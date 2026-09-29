import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto'
import { gunzipSync, gzipSync } from 'node:zlib'

import {
  AeadAuthError,
  CompressError,
  utf8Encode,
  type AeadProvider,
  type AeadSealed,
  type Argon2idParams,
  type CompressProvider,
  type KdfProvider,
  type RandomProvider,
} from '@askdaddy/crypto'

import {
  DEFAULT_SETTINGS,
  SCHEMA_VERSION,
  type Entry,
  type Tag,
  type VaultData,
  type VaultProviders,
} from '../types.js'

/**
 * 夹具 Provider，全部基于 Node 内置模块（测试目录豁免平台禁令，与
 * `packages/otp/src/__tests__/helpers.ts` 同一模式）。
 *
 * **为什么不用 `@askdaddy/crypto-web` 的真实 Provider**：`AGENTS.md` §3 规定
 * `crypto-web` 禁止被任何核心包依赖，`packages/vault` 是核心包，devDependency 也算。
 * 代价是这些单测只能证明 vault 遵守 Provider 契约，不能证明它与真实 Argon2id / WebCrypto
 * 协同正确——那一层由 QA 在根级 `test/` 的端到端测试覆盖（docs/testing.md §4.1）。
 */

/** AGENTS.md §5.3：夹具中的 secret 必须是假值。这是 RFC 4226 附录 D 用的 base32 串。 */
export const FAKE_SECRET_BASE32 = 'JBSWY3DPEHPK3PXP'

/** 同一个假 secret 的原始字节 base64 形式——`Entry.secret` 存的是字节而非 base32。 */
export const FAKE_SECRET_BASE64 = 'SkJTV1kzRFBFSFBLM1BYUA=='

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

/** HKDF-Expand 风格的 SHA-256 计数器展开。只作夹具，不是 KDF，不用于任何生产路径。 */
function expand(seed: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length)
  let previous = new Uint8Array(0)
  let offset = 0
  let counter = 1

  while (offset < length) {
    const hmac = createHmac('sha256', seed)
    hmac.update(previous)
    hmac.update(Uint8Array.from([counter]))
    previous = new Uint8Array(hmac.digest())
    out.set(previous.subarray(0, Math.min(32, length - offset)), offset)
    offset += 32
    counter += 1
  }

  return out
}

/**
 * 夹具 KDF。声明 `name: 'argon2id'` 是因为 `KdfProvider` 把该字段钉成了字面量类型——
 * 夹具顶替的是**契约**，不是算法。输出对 password / salt / memoryKiB / iterations /
 * parallelism / keyLength 六者中任一变化都敏感，否则 C3 / C9 的降级拒绝测不出效果。
 */
export const fixtureKdf: KdfProvider = {
  name: 'argon2id',

  async deriveKey(
    password: Uint8Array,
    salt: Uint8Array,
    params: Argon2idParams,
  ): Promise<Uint8Array> {
    const label = utf8Encode(
      `${params.memoryKiB}|${params.iterations}|${params.parallelism}|${params.keyLength}`,
    )
    return expand(concatBytes(password, salt, label), params.keyLength)
  },
}

export const fixtureAead: AeadProvider = {
  name: 'aes-256-gcm',

  async encrypt(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<AeadSealed> {
    const nonce = new Uint8Array(randomBytes(12))
    const cipher = createCipheriv('aes-256-gcm', key, nonce)
    if (aad !== undefined) cipher.setAAD(aad)

    const ciphertext = concatBytes(
      new Uint8Array(cipher.update(plaintext)),
      new Uint8Array(cipher.final()),
    )
    return { nonce, ciphertext, tag: new Uint8Array(cipher.getAuthTag()) }
  },

  async decrypt(key: Uint8Array, sealed: AeadSealed, aad?: Uint8Array): Promise<Uint8Array> {
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, sealed.nonce)
      if (aad !== undefined) decipher.setAAD(aad)
      decipher.setAuthTag(sealed.tag)

      return concatBytes(
        new Uint8Array(decipher.update(sealed.ciphertext)),
        new Uint8Array(decipher.final()),
      )
    } catch {
      // 与真实 Provider 的契约一致：认证失败一律 AeadAuthError，vault 才能把它归并进统一提示。
      throw new AeadAuthError('AES-256-GCM 认证失败：密钥不正确或数据已被篡改')
    }
  },
}

export const fixtureCompress: CompressProvider = {
  name: 'gzip',

  async compress(bytes: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(gzipSync(bytes))
  },

  async decompress(bytes: Uint8Array): Promise<Uint8Array> {
    try {
      return new Uint8Array(gunzipSync(bytes))
    } catch {
      throw new CompressError('gzip 解压失败：输入不是合法的 gzip 字节流')
    }
  },
}

export const fixtureRandom: RandomProvider = {
  randomBytes: (length: number) => new Uint8Array(randomBytes(length)),
}

/**
 * 记录型随机源：留存每一个交出去的 `Uint8Array` 引用，供测试断言它们事后被 `fill(0)`。
 * 这是 C12 / D5 的唯一可验证手段——生产代码不得为此暴露 DEK。
 */
export function createRecordingRandom(): {
  provider: RandomProvider
  issued: Uint8Array[]
} {
  const issued: Uint8Array[] = []
  return {
    issued,
    provider: {
      randomBytes(length: number): Uint8Array {
        const bytes = new Uint8Array(randomBytes(length))
        issued.push(bytes)
        return bytes
      },
    },
  }
}

/** 记录调用情况的 Provider 包装，用于断言某条路径**没有**触碰 kdf / aead / compress。 */
export function createProbe(
  providers: {
    kdf?: KdfProvider
    aead?: AeadProvider
    compress?: CompressProvider
    random?: RandomProvider
  } = {},
): {
  providers: {
    kdf: KdfProvider
    aead: AeadProvider
    compress: CompressProvider
    random: RandomProvider
  }
  calls: string[]
} {
  const calls: string[] = []
  const kdf = providers.kdf ?? fixtureKdf
  const aead = providers.aead ?? fixtureAead
  const compress = providers.compress ?? fixtureCompress

  return {
    calls,
    providers: {
      random: providers.random ?? fixtureRandom,
      kdf: {
        name: kdf.name,
        deriveKey: (password, salt, params) => {
          calls.push('kdf.deriveKey')
          return kdf.deriveKey(password, salt, params)
        },
      },
      aead: {
        name: aead.name,
        encrypt: (key, plaintext, aad) => {
          calls.push('aead.encrypt')
          return aead.encrypt(key, plaintext, aad)
        },
        decrypt: (key, sealed, aad) => {
          calls.push('aead.decrypt')
          return aead.decrypt(key, sealed, aad)
        },
      },
      compress: {
        name: compress.name,
        compress: (bytes) => {
          calls.push('compress.compress')
          return compress.compress(bytes)
        },
        decompress: (bytes) => {
          calls.push('compress.decompress')
          return compress.decompress(bytes)
        },
      },
    },
  }
}

/** 所有方法一被调用就抛错的 Provider，用于证明高版本拒绝路径完全没碰加密能力。 */
export const explodingProviders = (() => {
  const boom = (): never => {
    throw new Error('探针 Provider 被调用，说明拒绝路径没有停在解密之前')
  }
  return {
    kdf: { name: 'argon2id' as const, deriveKey: boom },
    aead: { name: 'aes-256-gcm' as const, encrypt: boom, decrypt: boom },
    compress: { name: 'gzip' as const, compress: boom, decompress: boom },
    random: { randomBytes: boom },
  }
})()

export function makeEntry(overrides: Partial<Entry> = {}): Entry {
  return {
    id: '019c0f6a-0000-7000-8000-000000000001',
    kind: 'totp',
    issuer: 'GitHub',
    account: 'alice@example.com',
    secret: FAKE_SECRET_BASE64,
    algo: 'SHA1',
    digits: 6,
    period: 30,
    tagIds: [],
    note: '',
    sites: [],
    usageCount: 0,
    lastUsedAt: null,
    position: 'a0',
    favorite: false,
    createdAt: 1_737_000_000_000,
    updatedAt: 1_737_000_000_000,
    ...overrides,
  }
}

export function makeTag(overrides: Partial<Tag> = {}): Tag {
  return {
    id: '019c0f6a-0000-7000-8000-00000000000a',
    name: '工作',
    color: '#5B8DEF',
    position: 'a0',
    ...overrides,
  }
}

export function makeVaultData(overrides: Partial<VaultData> = {}): VaultData {
  return {
    schemaVersion: SCHEMA_VERSION,
    meta: { createdAt: 1_737_000_000_000, updatedAt: 1_737_000_000_000, appVersion: '1.0.0' },
    entries: [makeEntry()],
    tags: [makeTag()],
    settings: { ...DEFAULT_SETTINGS },
    ...overrides,
  }
}

export const fixtureProviders = {
  kdf: fixtureKdf,
  aead: fixtureAead,
  random: fixtureRandom,
  compress: fixtureCompress,
}

/**
 * 忽略 AAD 的桩 AEAD，**只允许出现在 `src/__tests__/`**。
 *
 * 存在的唯一理由：ADR-017 让 AAD 覆盖头部 `schemaVersion`，任何遵守契约的 AEAD 下
 * 「头部与明文 `schemaVersion` 不一致」都会先触发 GCM 认证失败，`openVault` 里那道
 * 纵深防御分支永不可达。去掉 AAD 绑定才能走到它，从而证明它确实在（Plan 修订 #2 R2-4）。
 */
export const aadBlindAead: AeadProvider = {
  name: 'aes-256-gcm',
  encrypt: (key, plaintext) => fixtureAead.encrypt(key, plaintext),
  decrypt: (key, sealed) => fixtureAead.decrypt(key, sealed),
}

export interface Recording {
  /** 被调用的 Provider 方法，如 `kdf.deriveKey` */
  readonly call: string
  /** 缓冲区的角色，如 `kek` / `aad` / `plaintext` */
  readonly role: string
  /** 交给 Provider 的原始引用——生产代码用完应当 `fill(0)`，事后可据此断言 */
  readonly ref: Uint8Array
  /** 调用当下的拷贝——`ref` 被清零后仍可用于内容比对 */
  readonly copy: Uint8Array
}

/**
 * 记录型 Provider：留存每个进出缓冲区的引用与拷贝。
 *
 * **刻意不记录 `aead.*` 的 `key` 参数**：那是 DEK，它必须活到 `lock()` 才被清零，
 * 把它纳入「事后必须全零」的断言会与设计直接冲突。DEK 的清零由
 * `createRecordingRandom().issued` 观测（它是 DEK 的唯一来源）。
 */
export function createRecordingProviders(base: VaultProviders = fixtureProviders): {
  providers: VaultProviders
  recordings: Recording[]
} {
  const recordings: Recording[] = []

  function record(call: string, role: string, ref: Uint8Array): Uint8Array {
    recordings.push({ call, role, ref, copy: Uint8Array.from(ref) })
    return ref
  }

  return {
    recordings,
    providers: {
      random: base.random,
      kdf: {
        name: base.kdf.name,
        async deriveKey(password, salt, params) {
          record('kdf.deriveKey', 'password', password)
          record('kdf.deriveKey', 'salt', salt)
          return record('kdf.deriveKey', 'kek', await base.kdf.deriveKey(password, salt, params))
        },
      },
      aead: {
        name: base.aead.name,
        async encrypt(key, plaintext, aad) {
          record('aead.encrypt', 'plaintext', plaintext)
          if (aad !== undefined) record('aead.encrypt', 'aad', aad)
          const sealed = await base.aead.encrypt(key, plaintext, aad)
          record('aead.encrypt', 'nonce', sealed.nonce)
          record('aead.encrypt', 'ciphertext', sealed.ciphertext)
          record('aead.encrypt', 'tag', sealed.tag)
          return sealed
        },
        async decrypt(key, sealed, aad) {
          record('aead.decrypt', 'nonce', sealed.nonce)
          record('aead.decrypt', 'ciphertext', sealed.ciphertext)
          record('aead.decrypt', 'tag', sealed.tag)
          if (aad !== undefined) record('aead.decrypt', 'aad', aad)
          return record('aead.decrypt', 'plaintext', await base.aead.decrypt(key, sealed, aad))
        },
      },
      compress: {
        name: base.compress.name,
        async compress(bytes) {
          record('compress.compress', 'json', bytes)
          return record('compress.compress', 'gzip', await base.compress.compress(bytes))
        },
        async decompress(bytes) {
          record('compress.decompress', 'gzip', bytes)
          return record('compress.decompress', 'json', await base.compress.decompress(bytes))
        },
      },
    },
  }
}
