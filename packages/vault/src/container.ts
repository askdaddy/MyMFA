import {
  AES_256_GCM,
  AeadAuthError,
  ARGON2ID_PARAMS,
  assertArgon2idParams,
  assertNotWeakerThanBaseline,
  Base64DecodeError,
  base64Decode,
  base64Encode,
  CompressError,
  utf8Decode,
  utf8Encode,
} from '@askdaddy/crypto'
import type { AeadSealed, Argon2idParams } from '@askdaddy/crypto'

import { VaultAuthError, VaultFormatError, VaultLockedError } from './errors.js'
import { assertVaultData } from './guard.js'
import { assertContainerVersion, migrateVaultData } from './migrate.js'
import {
  CONTAINER_FORMAT,
  CONTAINER_VERSION,
  DEFAULT_SETTINGS,
  SCHEMA_VERSION,
  type CipherHeader,
  type CreateVaultOptions,
  type CryptoHeader,
  type EncryptedContainer,
  type KdfHeader,
  type VaultData,
  type VaultHandle,
  type VaultProviders,
  type WrappedKeyHeader,
} from './types.js'

const DEK_LENGTH = AES_256_GCM.keyLength

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * §1.1.1：分隔符与十进制拼法是契约，**不得改回裸拼接**（裸拼接会让 version=1/schemaVersion=11
 * 与 version=11/schemaVersion=1 产生同一个 AAD）。三个值全部取自容器头部。
 */
function buildAad(version: number, schemaVersion: number): Uint8Array {
  return utf8Encode(`${CONTAINER_FORMAT}\n${version}\n${schemaVersion}`)
}

/**
 * §5.1 的归并表：这些失败与「主密码错误」必须不可区分。
 *
 * 用白名单而不是 `catch` 全吞——程序自身的 bug（TypeError 之类）应当照常抛出，
 * 否则一次实现错误会被伪装成「密码不对」，永远查不出来。
 */
function isMergedFailure(error: unknown): boolean {
  return (
    error instanceof AeadAuthError ||
    error instanceof Base64DecodeError ||
    error instanceof CompressError ||
    error instanceof SyntaxError
  )
}

function zeroAll(buffers: readonly Uint8Array[]): void {
  for (const buffer of buffers) buffer.fill(0)
}

function track(spent: Uint8Array[], bytes: Uint8Array): Uint8Array {
  spent.push(bytes)
  return bytes
}

// ── 头部字段解码 ────────────────────────────────────────────────────────────
//
// `kdf.*` 的问题报具体字段（§5.2：参数降级必须指名是哪个参数，用户据此判断文件是否被动手脚）；
// `cipher.*` / `wrappedMasterKey.*` / `data` 的问题一律归并进统一提示（§5.1），
// 因为它们都在认证路径上，单独报错就等于告诉攻击者「密码是对的，坏在别处」。

function decodeKdfField(value: unknown, path: string): Uint8Array {
  if (typeof value !== 'string') {
    throw new VaultFormatError(`${path} 必须是 base64 字符串，文件可能已损坏`)
  }
  try {
    return base64Decode(value)
  } catch {
    throw new VaultFormatError(`${path} 不是合法的 base64`)
  }
}

function decodeAuthField(value: unknown, length?: number): Uint8Array {
  if (typeof value !== 'string') throw new VaultAuthError()
  let bytes: Uint8Array
  try {
    bytes = base64Decode(value)
  } catch {
    throw new VaultAuthError()
  }
  if (length !== undefined && bytes.byteLength !== length) throw new VaultAuthError()
  return bytes
}

function headerInt(value: unknown, path: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new VaultFormatError(`${path} 必须是正整数，文件可能已损坏`)
  }
  return value
}

// ── 写入 ────────────────────────────────────────────────────────────────────

/**
 * 用 KEK 包裹 DEK。**不带 AAD**：KEK 由 `crypto.kdf` 的全部参数派生，篡改其中任一字段
 * 都会得到不同的 KEK、解包必然认证失败，该字段已经自保护（§1.1.1）。
 */
async function wrapDek(
  password: string,
  salt: Uint8Array,
  dek: Uint8Array,
  providers: VaultProviders,
): Promise<WrappedKeyHeader> {
  const passwordBytes = utf8Encode(password)
  const spent: Uint8Array[] = [passwordBytes]

  try {
    const kek = await providers.kdf.deriveKey(passwordBytes, salt, ARGON2ID_PARAMS)
    spent.push(kek)

    const sealed = await providers.aead.encrypt(kek, dek)
    spent.push(sealed.nonce, sealed.ciphertext, sealed.tag)

    return {
      nonce: base64Encode(sealed.nonce),
      tag: base64Encode(sealed.tag),
      data: base64Encode(sealed.ciphertext),
    }
  } finally {
    // KEK 用完即清零，句柄**不持有**它（Plan 修订 #2 R2-1）。
    zeroAll(spent)
  }
}

/**
 * DEK 只以闭包变量存在，不是任何对象的属性——`JSON.stringify(句柄)`、`Object.keys`、
 * 调试器展开与误打日志都拿不到它（design 方案 A / C1）。
 */
function createHandle(
  providers: VaultProviders,
  dek: Uint8Array,
  initialData: VaultData,
  initialKdf: KdfHeader,
  initialWrapped: WrappedKeyHeader,
): VaultHandle {
  let kdf = initialKdf
  let wrappedMasterKey = initialWrapped
  let data = initialData
  let locked = false

  function assertUnlocked(action: string): void {
    if (locked) throw new VaultLockedError(`密钥库已锁定，无法${action}`)
  }

  return {
    get data(): VaultData {
      assertUnlocked('读取数据')
      return data
    },

    replaceData(next: VaultData): void {
      assertUnlocked('修改数据')
      data = assertVaultData(next)
    },

    sessionDek(): Uint8Array {
      assertUnlocked('读取会话密钥')
      return new Uint8Array(dek)
    },

    async serialize(): Promise<Uint8Array> {
      assertUnlocked('写入')

      const spent: Uint8Array[] = []
      try {
        const plaintext = track(spent, utf8Encode(JSON.stringify(data)))
        const gzipped = track(spent, await providers.compress.compress(plaintext))
        // 每次写入都用全新 cipher.nonce：明文会变，GCM 下 nonce 复用是灾难（§1.1 写入流程）。
        const aad = track(spent, buildAad(CONTAINER_VERSION, SCHEMA_VERSION))
        const sealed = await providers.aead.encrypt(dek, gzipped, aad)
        track(spent, sealed.nonce)
        track(spent, sealed.ciphertext)
        track(spent, sealed.tag)

        const cipher: CipherHeader = {
          name: providers.aead.name,
          nonce: base64Encode(sealed.nonce),
          tag: base64Encode(sealed.tag),
        }
        const crypto: CryptoHeader = { kdf, cipher, wrappedMasterKey }
        const container: EncryptedContainer = {
          format: CONTAINER_FORMAT,
          version: CONTAINER_VERSION,
          schemaVersion: SCHEMA_VERSION,
          encrypted: true,
          crypto,
          data: base64Encode(sealed.ciphertext),
        }

        return utf8Encode(JSON.stringify(container))
      } finally {
        zeroAll(spent)
      }
    },

    async changeMasterPassword(nextPassword: string): Promise<void> {
      assertUnlocked('修改主密码')

      // 只重新生成 salt、重新派生 KEK、重新包裹 DEK；payload 一律不碰（B7 / 意向 10）。
      const salt = providers.random.randomBytes(ARGON2ID_PARAMS.saltLength)
      try {
        const nextWrapped = await wrapDek(nextPassword, salt, dek, providers)
        wrappedMasterKey = nextWrapped
        kdf = { ...kdf, salt: base64Encode(salt) }
      } finally {
        salt.fill(0)
      }
    },

    lock(): void {
      if (locked) return
      dek.fill(0)
      locked = true
    },
  }
}

export async function createVault(
  password: string,
  providers: VaultProviders,
  options: CreateVaultOptions,
): Promise<VaultHandle> {
  const now = options.now?.() ?? Date.now()
  const dek = providers.random.randomBytes(DEK_LENGTH)
  const salt = providers.random.randomBytes(ARGON2ID_PARAMS.saltLength)

  try {
    const kdf: KdfHeader = {
      name: providers.kdf.name,
      memoryKiB: ARGON2ID_PARAMS.memoryKiB,
      iterations: ARGON2ID_PARAMS.iterations,
      parallelism: ARGON2ID_PARAMS.parallelism,
      salt: base64Encode(salt),
      keyLength: ARGON2ID_PARAMS.keyLength,
    }
    const wrappedMasterKey = await wrapDek(password, salt, dek, providers)

    const data: VaultData = {
      schemaVersion: SCHEMA_VERSION,
      meta: { createdAt: now, updatedAt: now, appVersion: options.appVersion },
      entries: [],
      tags: [],
      settings: { ...DEFAULT_SETTINGS },
    }

    return createHandle(providers, dek, data, kdf, wrappedMasterKey)
  } catch (error) {
    dek.fill(0)
    throw error
  } finally {
    // salt 不是秘密（它就明文写在文件头里），但缓冲区没有理由留着。
    salt.fill(0)
  }
}

// ── 读取 ────────────────────────────────────────────────────────────────────

interface ParsedHeader {
  readonly version: number
  readonly schemaVersion: number
  readonly kdf: KdfHeader
  readonly wrappedMasterKey: WrappedKeyHeader
  readonly params: Argon2idParams
  /** 已解码的 `crypto.kdf.salt`，派生 KEK 用；清零由 `spent` 统一负责 */
  readonly salt: Uint8Array
  readonly wrapped: AeadSealed
  readonly payload: AeadSealed
  /** 已解码、由 `openVault` 负责清零（含异常路径）的缓冲区 */
  readonly spent: Uint8Array[]
}

/** §1.1 读取流程步骤 1–3。 */
function parseContainer(bytes: Uint8Array): Record<string, unknown> {
  let parsed: unknown
  try {
    parsed = JSON.parse(utf8Decode(bytes))
  } catch {
    throw new VaultFormatError('密钥库文件已损坏：不是合法的 UTF-8 JSON 文本')
  }

  if (!isRecord(parsed)) {
    throw new VaultFormatError('密钥库文件已损坏：顶层不是 JSON 对象')
  }
  if (parsed.format !== CONTAINER_FORMAT) {
    throw new VaultFormatError('这不是本 App 的密钥库文件')
  }
  // 明文容器由 packages/transfer 封装与解封。这里明确拒绝而不是静默按明文读取，
  // 否则 AGENTS.md §5.4 要求的「明文导出须二次确认 + 显著风险提示」会被绕过。
  if (parsed.encrypted !== true) {
    throw new VaultFormatError('这是未加密的明文备份，请改用导入功能读取')
  }

  return parsed
}

/** §1.1 读取流程步骤 4–5：版本闸门与参数降级检查，**全程不触碰 KDF / AEAD / Compress**。 */
function readHeader(bytes: Uint8Array, providers: VaultProviders): ParsedHeader {
  const container = parseContainer(bytes)
  assertContainerVersion(container)

  const spent: Uint8Array[] = []
  try {
    const crypto = container.crypto
    const rawKdf = isRecord(crypto) ? crypto.kdf : undefined
    const rawCipher = isRecord(crypto) ? crypto.cipher : undefined
    const rawWrapped = isRecord(crypto) ? crypto.wrappedMasterKey : undefined
    if (!isRecord(crypto) || !isRecord(rawKdf) || !isRecord(rawCipher) || !isRecord(rawWrapped)) {
      throw new VaultFormatError('密钥库文件已损坏：crypto 头部不完整')
    }

    // C10：名称与注入的 Provider 不符时直接拒绝，绝不调用 deriveKey。
    if (rawKdf.name !== providers.kdf.name) {
      throw new VaultFormatError(
        `密钥库用 ${String(rawKdf.name)} 派生密钥，本端注入的是 ${providers.kdf.name}，无法打开`,
      )
    }
    if (rawCipher.name !== providers.aead.name) {
      throw new VaultFormatError(
        `密钥库用 ${String(rawCipher.name)} 加密，本端注入的是 ${providers.aead.name}，无法打开`,
      )
    }

    const memoryKiB = headerInt(rawKdf.memoryKiB, 'crypto.kdf.memoryKiB')
    const iterations = headerInt(rawKdf.iterations, 'crypto.kdf.iterations')
    const parallelism = headerInt(rawKdf.parallelism, 'crypto.kdf.parallelism')
    const keyLength = headerInt(rawKdf.keyLength, 'crypto.kdf.keyLength')

    const salt = track(spent, decodeKdfField(rawKdf.salt, 'crypto.kdf.salt'))
    // C9/D3：`assertNotWeakerThanBaseline` 不比较 saltLength（它对写入路径是正确的排除），
    // 所以「salt 被改短」这一降级攻击面必须由 vault 层自己拦住。
    if (salt.byteLength < ARGON2ID_PARAMS.saltLength) {
      throw new VaultFormatError(
        `crypto.kdf.salt 只有 ${salt.byteLength} 字节，低于基线 ${ARGON2ID_PARAMS.saltLength} 字节`,
      )
    }
    if (keyLength !== AES_256_GCM.keyLength) {
      throw new VaultFormatError(
        `crypto.kdf.keyLength 必须是 ${AES_256_GCM.keyLength}，实际为 ${keyLength}`,
      )
    }

    const params: Argon2idParams = {
      memoryKiB,
      iterations,
      parallelism,
      saltLength: salt.byteLength,
      keyLength,
    }
    // 先比基线再查结构：降级攻击要看到「哪个参数低于基线」，而不是被 8*p 的结构性约束盖过去。
    assertNotWeakerThanBaseline(params)
    assertArgon2idParams(params)

    const wrapped: AeadSealed = {
      nonce: track(spent, decodeAuthField(rawWrapped.nonce, AES_256_GCM.nonceLength)),
      ciphertext: track(spent, decodeAuthField(rawWrapped.data)),
      tag: track(spent, decodeAuthField(rawWrapped.tag, AES_256_GCM.tagLength)),
    }
    const payload: AeadSealed = {
      nonce: track(spent, decodeAuthField(rawCipher.nonce, AES_256_GCM.nonceLength)),
      ciphertext: track(spent, decodeAuthField(container.data)),
      tag: track(spent, decodeAuthField(rawCipher.tag, AES_256_GCM.tagLength)),
    }

    const version = container.version as number
    const schemaVersion = container.schemaVersion as number

    return {
      version,
      schemaVersion,
      // salt 重新编码成规范 base64：文件里可能写的是 base64url 或省略了 padding。
      kdf: { ...rawKdf, name: providers.kdf.name, salt: base64Encode(salt) } as KdfHeader,
      wrappedMasterKey: {
        nonce: rawWrapped.nonce,
        tag: rawWrapped.tag,
        data: rawWrapped.data,
      } as WrappedKeyHeader,
      params,
      salt,
      wrapped,
      payload,
      spent,
    }
  } catch (error) {
    zeroAll(spent)
    throw error
  }
}

/** §1.1 读取流程步骤 6–7。 */
async function unwrapDek(
  password: string,
  header: ParsedHeader,
  providers: VaultProviders,
): Promise<Uint8Array> {
  const passwordBytes = utf8Encode(password)
  const spent: Uint8Array[] = [passwordBytes]

  try {
    // 按**文件头参数**派生，不是硬编码值——否则读不出参数被上调过的旧文件。
    const kek = await providers.kdf.deriveKey(passwordBytes, header.salt, header.params)
    spent.push(kek)

    try {
      return await providers.aead.decrypt(kek, header.wrapped)
    } catch (error) {
      if (isMergedFailure(error)) throw new VaultAuthError()
      throw error
    }
  } finally {
    zeroAll(spent)
  }
}

/** §1.1 读取流程步骤 8。 */
async function readPayload(
  dek: Uint8Array,
  header: ParsedHeader,
  providers: VaultProviders,
): Promise<Record<string, unknown>> {
  const spent: Uint8Array[] = []

  try {
    const aad = track(spent, buildAad(header.version, header.schemaVersion))
    const gzipped = track(spent, await providers.aead.decrypt(dek, header.payload, aad))
    // 能走到解压说明密码已经对了，解压失败也不得单独提示「压缩格式错误」（§5.1）。
    const jsonBytes = track(spent, await providers.compress.decompress(gzipped))

    const parsed: unknown = JSON.parse(utf8Decode(jsonBytes))
    if (!isRecord(parsed)) throw new VaultAuthError()
    return parsed
  } catch (error) {
    if (isMergedFailure(error)) throw new VaultAuthError()
    throw error
  } finally {
    zeroAll(spent)
  }
}

export async function openVault(
  bytes: Uint8Array,
  password: string,
  providers: VaultProviders,
): Promise<VaultHandle> {
  const header = readHeader(bytes, providers)

  try {
    const dek = await unwrapDek(password, header, providers)
    try {
      const plaintext = await readPayload(dek, header, providers)

      // ADR-017 的纵深防御。AAD 已覆盖头部 schemaVersion，真实 Provider 下不一致会先让
      // GCM 认证失败，本分支不可达；留着是因为 AAD 布局将来若变动，它是唯一的兜底。
      if (plaintext.schemaVersion !== header.schemaVersion) throw new VaultAuthError()

      const data = migrateVaultData(plaintext)
      return createHandle(providers, dek, data, header.kdf, header.wrappedMasterKey)
    } catch (error) {
      // 异常路径同样要清掉 DEK（C12），否则一次失败的解锁会把密钥留在堆上。
      dek.fill(0)
      throw error
    }
  } finally {
    zeroAll(header.spent)
  }
}

export async function openVaultWithDek(
  bytes: Uint8Array,
  sessionDek: Uint8Array,
  providers: VaultProviders,
): Promise<VaultHandle> {
  if (!(sessionDek instanceof Uint8Array) || sessionDek.byteLength !== DEK_LENGTH) {
    throw new VaultAuthError()
  }
  const header = readHeader(bytes, providers)
  const dek = new Uint8Array(sessionDek)
  try {
    const plaintext = await readPayload(dek, header, providers)
    if (plaintext.schemaVersion !== header.schemaVersion) throw new VaultAuthError()
    const data = migrateVaultData(plaintext)
    return createHandle(providers, dek, data, header.kdf, header.wrappedMasterKey)
  } catch (error) {
    dek.fill(0)
    throw error
  } finally {
    zeroAll(header.spent)
  }
}
