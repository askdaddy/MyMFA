import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import {
  AES_256_GCM,
  ARGON2ID_PARAMS,
  base64Decode,
  base64Encode,
  CompressError,
  utf8Decode,
  utf8Encode,
  type AeadProvider,
  type CompressProvider,
} from '@askdaddy/crypto'

import { createVault, openVault } from '../container.js'
import { VaultAuthError, VaultFormatError, VaultLockedError, VaultVersionError } from '../errors.js'
import {
  CONTAINER_FORMAT,
  CONTAINER_VERSION,
  DEFAULT_SETTINGS,
  SCHEMA_VERSION,
  type EncryptedContainer,
  type Entry,
  type Tag,
  type VaultHandle,
  type VaultProviders,
} from '../types.js'
import {
  aadBlindAead,
  concatBytes,
  createProbe,
  createRecordingProviders,
  createRecordingRandom,
  explodingProviders,
  fixtureCompress,
  fixtureProviders,
  makeEntry,
  makeTag,
  type Recording,
} from './helpers.js'

const PASSWORD = 'correct horse battery staple'
const NEXT_PASSWORD = 'Tr0ub4dor&3-新主密码'
const WRONG_PASSWORD = 'not-the-master-password'
const APP_VERSION = '1.0.0'
const NOW = 1_737_000_000_000
const fixedNow = (): number => NOW

/** `VaultAuthError` 的 message 是常量，任何失败来源都不得改写它（docs/vault-format.md §5.1）。 */
const AUTH_MESSAGE = '密钥库文件已损坏，或主密码不正确'

const CONTAINER_V99 = '../__fixtures__/container-schema-v99.json'

// ── 测试工具 ────────────────────────────────────────────────────────────────

function decodeContainer(bytes: Uint8Array): EncryptedContainer {
  return JSON.parse(utf8Decode(bytes)) as EncryptedContainer
}

function patchContainer(
  bytes: Uint8Array,
  patch: (container: Record<string, unknown>) => void,
): Uint8Array {
  const container = JSON.parse(utf8Decode(bytes)) as Record<string, unknown>
  patch(container)
  return utf8Encode(JSON.stringify(container))
}

/** 翻转 payload 密文的一个字节：模拟「文件在传输或落盘途中被改动」。 */
function tamperData(bytes: Uint8Array): Uint8Array {
  return patchContainer(bytes, (container) => {
    const raw = base64Decode(container.data as string)
    raw[0] = (raw[0]! + 1) & 0xff
    container.data = base64Encode(raw)
  })
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

function isZeroed(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0)
}

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer
    }
    return true
  }
  return false
}

function sortedKeys(value: object): string[] {
  return Object.keys(value).sort()
}

type CryptoSection = 'kdf' | 'cipher' | 'wrappedMasterKey'

function section(container: Record<string, unknown>, name: CryptoSection): Record<string, unknown> {
  return (container.crypto as Record<string, Record<string, unknown>>)[name]!
}

async function captureError(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise
  } catch (error) {
    return error as Error
  }
  throw new Error('预期抛出异常，调用却成功返回了')
}

async function newHandle(providers: VaultProviders = fixtureProviders): Promise<VaultHandle> {
  return createVault(PASSWORD, providers, { appVersion: APP_VERSION, now: fixedNow })
}

async function sampleContainer(providers: VaultProviders = fixtureProviders): Promise<Uint8Array> {
  return (await newHandle(providers)).serialize()
}

/**
 * `VaultData` 的字段在类型上是 `readonly`——那是给调用方的只读视图，不是运行时不可变。
 * 测试需要往新库里塞条目，故在此解开；生产代码不得这样写。
 */
function entriesOf(handle: VaultHandle): Entry[] {
  return handle.data.entries as Entry[]
}

function tagsOf(handle: VaultHandle): Tag[] {
  return handle.data.tags as Tag[]
}

/**
 * 统计某次 Provider 方法被调用了几趟。
 *
 * 不能直接数 `recordings` 里 `call` 相同的条数——一趟 `kdf.deriveKey` 会留下 password /
 * salt / kek 三条记录。这里按「每趟恰好记录一次」的角色计数。
 */
function countInvocations(recordings: readonly Recording[], call: string, role: string): number {
  return recordings.filter((r) => r.call === call && r.role === role).length
}

function snapshots(
  recordings: readonly Recording[],
  call: string,
  role: string,
): readonly Uint8Array[] {
  return recordings.filter((r) => r.call === call && r.role === role).map((r) => r.copy)
}

const brokenDecompress: CompressProvider = {
  name: 'gzip',
  compress: (bytes) => fixtureCompress.compress(bytes),
  async decompress() {
    throw new CompressError('夹具：解压失败')
  },
}

const nonJsonDecompress: CompressProvider = {
  name: 'gzip',
  compress: (bytes) => fixtureCompress.compress(bytes),
  async decompress() {
    return utf8Encode('{ 这不是合法的 JSON')
  },
}

// ── 步骤 14：createVault 与 serialize ───────────────────────────────────────

describe('步骤 14：createVault 产出的空库', () => {
  it('data 是空库，带上注入的 appVersion 与时间戳', async () => {
    const handle = await newHandle()

    expect(handle.data).toEqual({
      schemaVersion: SCHEMA_VERSION,
      meta: { createdAt: NOW, updatedAt: NOW, appVersion: APP_VERSION },
      entries: [],
      tags: [],
      settings: { ...DEFAULT_SETTINGS },
    })
  })

  it('settings 是 DEFAULT_SETTINGS 的副本，不是同一引用', async () => {
    // 共用引用会让「某个库改了设置」污染常量，进而污染之后新建的每一个库。
    const handle = await newHandle()

    expect(handle.data.settings).not.toBe(DEFAULT_SETTINGS)
    expect((await newHandle()).data.settings).not.toBe(handle.data.settings)
  })

  it('未注入 now 时回落到 Date.now()', async () => {
    const before = Date.now()
    const handle = await createVault(PASSWORD, fixtureProviders, { appVersion: APP_VERSION })

    expect(handle.data.meta.createdAt).toBeGreaterThanOrEqual(before)
    expect(handle.data.meta.updatedAt).toBe(handle.data.meta.createdAt)
  })
})

describe('步骤 14：容器结构', () => {
  it('头部字段集合与 §1.1 一致，没有多也没有少', async () => {
    const container = decodeContainer(await sampleContainer())

    expect(sortedKeys(container)).toEqual(
      ['crypto', 'data', 'encrypted', 'format', 'schemaVersion', 'version'].sort(),
    )
    expect(sortedKeys(container.crypto)).toEqual(['cipher', 'kdf', 'wrappedMasterKey'].sort())
    expect(sortedKeys(container.crypto.kdf)).toEqual(
      ['iterations', 'keyLength', 'memoryKiB', 'name', 'parallelism', 'salt'].sort(),
    )
    expect(sortedKeys(container.crypto.cipher)).toEqual(['name', 'nonce', 'tag'].sort())
    expect(sortedKeys(container.crypto.wrappedMasterKey)).toEqual(['data', 'nonce', 'tag'].sort())
  })

  it('固定字段逐项等于常量', async () => {
    const container = decodeContainer(await sampleContainer())

    expect(container.format).toBe(CONTAINER_FORMAT)
    expect(container.version).toBe(CONTAINER_VERSION)
    // ADR-017：schemaVersion 必须在头部明文可见，读取端才能在派生 KEK 之前拒绝未来版本。
    expect(container.schemaVersion).toBe(SCHEMA_VERSION)
    expect(container.encrypted).toBe(true)
    expect(container.crypto.kdf.name).toBe('argon2id')
    expect(container.crypto.cipher.name).toBe('aes-256-gcm')
  })

  it('kdf 头部逐项等于 ARGON2ID_PARAMS 基线', async () => {
    const { kdf } = decodeContainer(await sampleContainer()).crypto

    expect(kdf.memoryKiB).toBe(ARGON2ID_PARAMS.memoryKiB)
    expect(kdf.iterations).toBe(ARGON2ID_PARAMS.iterations)
    expect(kdf.parallelism).toBe(ARGON2ID_PARAMS.parallelism)
    expect(kdf.keyLength).toBe(ARGON2ID_PARAMS.keyLength)
  })

  it('各 base64 字段解码后的字节长度符合参数常量', async () => {
    const { crypto } = decodeContainer(await sampleContainer())

    expect(base64Decode(crypto.kdf.salt)).toHaveLength(ARGON2ID_PARAMS.saltLength)
    expect(base64Decode(crypto.cipher.nonce)).toHaveLength(AES_256_GCM.nonceLength)
    expect(base64Decode(crypto.cipher.tag)).toHaveLength(AES_256_GCM.tagLength)
    expect(base64Decode(crypto.wrappedMasterKey.nonce)).toHaveLength(AES_256_GCM.nonceLength)
    expect(base64Decode(crypto.wrappedMasterKey.tag)).toHaveLength(AES_256_GCM.tagLength)
    // 被包裹的就是 32 字节 DEK，密文与明文等长（GCM 是流式模式）。
    expect(base64Decode(crypto.wrappedMasterKey.data)).toHaveLength(AES_256_GCM.keyLength)
  })

  it('salt 是真随机值，不是全零占位', async () => {
    const { crypto } = decodeContainer(await sampleContainer())
    const first = base64Decode(crypto.kdf.salt)
    const second = base64Decode(decodeContainer(await sampleContainer()).crypto.kdf.salt)

    expect(isZeroed(first)).toBe(false)
    expect(first).not.toEqual(second)
  })

  it('data 字段是密文，其明文形态以 gzip 魔数 1f 8b 开头', async () => {
    const { providers, recordings } = createRecordingProviders()
    const handle = await newHandle(providers)
    const container = decodeContainer(await handle.serialize())

    // 容器里的 data 是密文，不该有 gzip 头；有头说明压缩结果没被加密就写出去了。
    expect([...base64Decode(container.data).subarray(0, 2)]).not.toEqual([0x1f, 0x8b])

    const gzipped = snapshots(recordings, 'compress.compress', 'gzip')
    expect(gzipped).toHaveLength(1)
    expect([...gzipped[0]!.subarray(0, 2)]).toEqual([0x1f, 0x8b])
    // 交给 AEAD 的正是压缩输出，中间没有被换掉。
    expect(snapshots(recordings, 'aead.encrypt', 'plaintext').at(-1)).toEqual(gzipped[0])
  })
})

describe('步骤 14：C1 容器不泄露任何秘密', () => {
  it('DEK / KEK / 主密码的原始字节、hex、base64 均不出现在容器里', async () => {
    const { provider: random, issued } = createRecordingRandom()
    const { providers, recordings } = createRecordingProviders({ ...fixtureProviders, random })
    const handle = await createVault(PASSWORD, providers, {
      appVersion: APP_VERSION,
      now: fixedNow,
    })
    const bytes = await handle.serialize()
    const container = decodeContainer(bytes)
    const text = utf8Decode(bytes)

    const dek = issued.find((buffer) => buffer.length === AES_256_GCM.keyLength)!
    const kek = snapshots(recordings, 'kdf.deriveKey', 'kek')[0]!
    const passwordBytes = snapshots(recordings, 'kdf.deriveKey', 'password')[0]!
    expect(dek).toBeDefined()

    // 每个 base64 字段都解码回原始字节再搜一遍：只在 JSON 文本里搜会漏掉「密文其实就是明文」这种情况。
    const decodedFields = [
      container.data,
      container.crypto.kdf.salt,
      container.crypto.cipher.nonce,
      container.crypto.cipher.tag,
      container.crypto.wrappedMasterKey.nonce,
      container.crypto.wrappedMasterKey.tag,
      container.crypto.wrappedMasterKey.data,
    ].map((field) => base64Decode(field))

    for (const secret of [dek, kek, passwordBytes]) {
      expect(isZeroed(secret)).toBe(false)
      expect(text).not.toContain(toHex(secret))
      expect(text).not.toContain(base64Encode(secret))
      expect(containsBytes(bytes, secret)).toBe(false)
      for (const field of decodedFields) {
        expect(containsBytes(field, secret)).toBe(false)
      }
    }

    expect(text).not.toContain(PASSWORD)
  })

  it('serialize 之后 DEK 仍然可用（没有被过早清零）', async () => {
    const { provider: random, issued } = createRecordingRandom()
    const handle = await createVault(
      PASSWORD,
      { ...fixtureProviders, random },
      {
        appVersion: APP_VERSION,
        now: fixedNow,
      },
    )
    const dek = issued.find((buffer) => buffer.length === AES_256_GCM.keyLength)!

    await handle.serialize()
    await handle.serialize()

    expect(isZeroed(dek)).toBe(false)
  })
})

describe('步骤 14：R2-2 连续写入的 nonce 策略', () => {
  it('payload 三件套每次全新，wrappedMasterKey 与 salt 逐字节不变', async () => {
    const handle = await newHandle()
    const bytesA = await handle.serialize()
    const bytesB = await handle.serialize()
    const a = decodeContainer(bytesA)
    const b = decodeContainer(bytesB)

    expect(b.crypto.cipher.nonce).not.toBe(a.crypto.cipher.nonce)
    expect(b.crypto.cipher.tag).not.toBe(a.crypto.cipher.tag)
    expect(b.data).not.toBe(a.data)

    // R2-1：句柄生命周期内 DEK 恒定，重新包裹它没有安全收益，却要求 KEK 常驻内存。
    expect(b.crypto.kdf.salt).toBe(a.crypto.kdf.salt)
    expect(b.crypto.wrappedMasterKey).toEqual(a.crypto.wrappedMasterKey)
  })

  it('两次写出的容器都能打开，且 data 深度相等', async () => {
    const handle = await newHandle()
    entriesOf(handle).push(makeEntry())
    tagsOf(handle).push(makeTag())

    const bytesA = await handle.serialize()
    const bytesB = await handle.serialize()

    const openedA = await openVault(bytesA, PASSWORD, fixtureProviders)
    const openedB = await openVault(bytesB, PASSWORD, fixtureProviders)

    expect(openedA.data).toEqual(handle.data)
    expect(openedB.data).toEqual(handle.data)
    expect(openedA.data).toEqual(openedB.data)
  })
})

describe('步骤 14：AAD', () => {
  it('payload 用 utf8Encode("mfavault\\n1\\n1") 作 AAD，包裹 DEK 不带 AAD', async () => {
    const { providers, recordings } = createRecordingProviders()
    const handle = await newHandle(providers)
    await handle.serialize()

    const aads = snapshots(recordings, 'aead.encrypt', 'aad')
    expect(aads).toHaveLength(1)
    expect(aads[0]).toEqual(
      utf8Encode(`${CONTAINER_FORMAT}\n${CONTAINER_VERSION}\n${SCHEMA_VERSION}`),
    )
    expect(utf8Decode(aads[0]!)).toBe('mfavault\n1\n1')
  })

  it('写入时用了错误 AAD 的容器，读取时认证失败', async () => {
    // §1.1.1 的 AAD 拼法一旦被改动（例如退回裸拼接），这条测试就会失败。
    const tamperedAad: AeadProvider = {
      name: 'aes-256-gcm',
      encrypt: (key, plaintext, aad) =>
        fixtureProviders.aead.encrypt(
          key,
          plaintext,
          aad === undefined ? undefined : concatBytes(aad, utf8Encode('!')),
        ),
      decrypt: (key, sealed, aad) => fixtureProviders.aead.decrypt(key, sealed, aad),
    }

    const bytes = await sampleContainer({ ...fixtureProviders, aead: tamperedAad })
    const error = await captureError(openVault(bytes, PASSWORD, fixtureProviders))

    expect(error).toBeInstanceOf(VaultAuthError)
    expect(error.message).toBe(AUTH_MESSAGE)
  })
})

describe('步骤 14：C12 中间缓冲区清零', () => {
  it('createVault 与 serialize 之后，除 DEK 外所有缓冲区都被 fill(0)', async () => {
    const { provider: random, issued } = createRecordingRandom()
    const { providers, recordings } = createRecordingProviders({ ...fixtureProviders, random })
    const handle = await createVault(PASSWORD, providers, {
      appVersion: APP_VERSION,
      now: fixedNow,
    })
    const afterCreate = recordings.length
    await handle.serialize()

    expect(afterCreate).toBeGreaterThan(0)
    expect(recordings.length).toBeGreaterThan(afterCreate)

    const dek = issued.find((buffer) => buffer.length === AES_256_GCM.keyLength)!
    for (const recording of recordings) {
      // DEK 必须活到 lock()，把它一起清零会让句柄当场失效。
      if (recording.ref === dek) continue
      expect(isZeroed(recording.ref), `${recording.call} 的 ${recording.role} 未被清零`).toBe(true)
    }
  })

  it('serialize 期间产生的每一个缓冲区都被清零（这一段不涉及 DEK）', async () => {
    const { providers, recordings } = createRecordingProviders()
    const handle = await newHandle(providers)
    const mark = recordings.length

    await handle.serialize()

    const window = recordings.slice(mark)
    expect(window.length).toBeGreaterThan(0)
    for (const recording of window) {
      expect(isZeroed(recording.ref), `${recording.call} 的 ${recording.role} 未被清零`).toBe(true)
    }
  })
})

// ── 步骤 15：openVault ──────────────────────────────────────────────────────

describe('步骤 15：往返', () => {
  it('写入再读出，data 深度相等（含中文、emoji、换行与全部字段）', async () => {
    const handle = await newHandle()
    entriesOf(handle).push(
      makeEntry({
        issuer: '阿里云',
        account: '张三@例子.中国',
        note: '备注：中文 + emoji 🔐\n第二行',
        sites: ['console.aliyun.com', 'github.com'],
        tagIds: ['019c0f6a-0000-7000-8000-00000000000a'],
        favorite: true,
        usageCount: 17,
        lastUsedAt: NOW,
      }),
      makeEntry({
        id: '019c0f6a-0000-7000-8000-000000000002',
        kind: 'hotp',
        issuer: 'GitLab',
        algo: 'SHA512',
        digits: 8,
        period: undefined,
        counter: 42,
        position: 'a1',
      }),
    )
    tagsOf(handle).push(makeTag({ name: '工作 🏢' }))

    const bytes = await handle.serialize()
    const opened = await openVault(bytes, PASSWORD, fixtureProviders)

    expect(opened.data).toEqual(handle.data)
    expect(opened.data.entries).toHaveLength(2)
    expect(opened.data.entries[0]!.note).toContain('🔐')
    expect(opened.data.entries[1]!.counter).toBe(42)
    expect(opened.data.entries[1]!.period).toBeUndefined()
  })

  it('读出的是一个可继续写入的活句柄', async () => {
    const bytes = await sampleContainer()
    const opened = await openVault(bytes, PASSWORD, fixtureProviders)
    entriesOf(opened).push(makeEntry())

    const reopened = await openVault(await opened.serialize(), PASSWORD, fixtureProviders)

    expect(reopened.data.entries).toHaveLength(1)
  })

  it('空库也能往返', async () => {
    const handle = await newHandle()
    const opened = await openVault(await handle.serialize(), PASSWORD, fixtureProviders)

    expect(opened.data).toEqual(handle.data)
  })
})

describe('步骤 15：C1 失败原因不可区分', () => {
  it('主密码错误与密文被篡改抛出完全相同的 name 与 message', async () => {
    const bytes = await sampleContainer()

    const wrongPassword = await captureError(openVault(bytes, WRONG_PASSWORD, fixtureProviders))
    const tampered = await captureError(openVault(tamperData(bytes), PASSWORD, fixtureProviders))

    expect(wrongPassword).toBeInstanceOf(VaultAuthError)
    expect(tampered).toBeInstanceOf(VaultAuthError)
    expect(tampered.name).toBe(wrongPassword.name)
    expect(tampered.message).toBe(wrongPassword.message)
    expect(wrongPassword.message).toBe(AUTH_MESSAGE)
  })

  it('六个失败来源全部归并为同一个 VaultAuthError', async () => {
    const cases: { label: string; run: () => Promise<unknown> }[] = [
      {
        label: 'wrappedMasterKey 解包失败（主密码错误）',
        run: async () => openVault(await sampleContainer(), WRONG_PASSWORD, fixtureProviders),
      },
      {
        label: 'payload 解密失败（data 被篡改）',
        run: async () => openVault(tamperData(await sampleContainer()), PASSWORD, fixtureProviders),
      },
      {
        label: 'data 不是合法 base64',
        run: async () =>
          openVault(
            patchContainer(await sampleContainer(), (container) => {
              container.data = '!!!not-base64!!!'
            }),
            PASSWORD,
            fixtureProviders,
          ),
      },
      {
        label: 'gzip 解压失败',
        run: async () =>
          openVault(await sampleContainer(), PASSWORD, {
            ...fixtureProviders,
            compress: brokenDecompress,
          }),
      },
      {
        label: 'JSON 解析失败',
        run: async () =>
          openVault(await sampleContainer(), PASSWORD, {
            ...fixtureProviders,
            compress: nonJsonDecompress,
          }),
      },
      {
        // R2-4：真实 AEAD 下 AAD 已覆盖头部 schemaVersion，本分支不可达，只能用忽略 AAD 的桩走到它。
        label: '头部与明文 schemaVersion 不一致（纵深防御）',
        run: async () =>
          openVault(
            patchContainer(await sampleContainer(), (container) => {
              container.schemaVersion = 0
            }),
            PASSWORD,
            { ...fixtureProviders, aead: aadBlindAead },
          ),
      },
    ]

    expect(cases).toHaveLength(6)
    for (const { label, run } of cases) {
      const error = await captureError(run())
      expect(error, label).toBeInstanceOf(VaultAuthError)
      expect(error.message, label).toBe(AUTH_MESSAGE)
    }
  })

  it('明文根节点不是对象时同样归并', async () => {
    // 走到这一步说明密码已经对了，但明文结构坏掉；仍不得给出比统一提示更细的信息。
    const notAnObject: CompressProvider = {
      name: 'gzip',
      compress: (bytes) => fixtureCompress.compress(bytes),
      async decompress() {
        return utf8Encode('42')
      },
    }

    const error = await captureError(
      openVault(await sampleContainer(), PASSWORD, { ...fixtureProviders, compress: notAnObject }),
    )

    expect(error).toBeInstanceOf(VaultAuthError)
    expect(error.message).toBe(AUTH_MESSAGE)
  })
})

describe('步骤 15：AAD 覆盖的头部字段被篡改', () => {
  // 必须**改小**：改大会先被 C11 的版本闸门拦成 VaultVersionError，测不到 AAD。
  // 用的是遵守 AAD 契约的夹具，与 R2-4 那条（靠 aadBlindAead 桩走到纵深防御分支）是两回事：
  // 这两条证明的是 GCM 认证本身覆盖了头部 version 与 schemaVersion。
  const cases: { label: string; patch: (container: Record<string, unknown>) => void }[] = [
    {
      label: '头部 version 改小',
      patch: (container) => {
        container.version = CONTAINER_VERSION - 1
      },
    },
    {
      label: '头部 schemaVersion 改小',
      patch: (container) => {
        container.schemaVersion = SCHEMA_VERSION - 1
      },
    },
  ]

  it.each(cases)('$label → 与错误密码全等的 VaultAuthError', async ({ patch }) => {
    const wrongPassword = await captureError(
      openVault(await sampleContainer(), WRONG_PASSWORD, fixtureProviders),
    )
    const error = await captureError(
      openVault(patchContainer(await sampleContainer(), patch), PASSWORD, fixtureProviders),
    )

    expect(error).toBeInstanceOf(VaultAuthError)
    expect(error.name).toBe(wrongPassword.name)
    expect(error.message).toBe(wrongPassword.message)
    expect(error.message).toBe(AUTH_MESSAGE)
  })
})

describe('步骤 15：结构性损坏报 VaultFormatError', () => {
  const cases: { label: string; bytes: () => Uint8Array }[] = [
    { label: '不是合法的 UTF-8 JSON 文本', bytes: () => utf8Encode('这根本不是 JSON') },
    { label: '顶层是数组', bytes: () => utf8Encode('[]') },
    { label: '顶层是字符串', bytes: () => utf8Encode('"mfavault"') },
    { label: '顶层是 null', bytes: () => utf8Encode('null') },
  ]

  it.each(cases)('$label', async ({ bytes }) => {
    const { providers, calls } = createProbe()
    const error = await captureError(openVault(bytes(), WRONG_PASSWORD, providers))

    expect(error).toBeInstanceOf(VaultFormatError)
    expect(calls).not.toContain('kdf.deriveKey')
  })

  const patched: { label: string; patch: (container: Record<string, unknown>) => void }[] = [
    {
      // `format` 虽然也在 AAD 覆盖范围内，但它被篡改时走的是**预期不同**的这条提示：
      // docs/vault-format.md §1.1 步骤 1 要求「不是本 App 的密钥库文件」独立成一条，
      // 因为这是文件格式识别，发生在派生 KEK 之前，与主密码正确与否无关，
      // 因此**不参与** C7 的归并（与上面那组 AAD 用例刻意分开列）。
      label: 'format 不是 mfavault',
      patch: (container) => {
        container.format = 'aegis'
      },
    },
    {
      label: 'encrypted 为 false',
      patch: (container) => {
        container.encrypted = false
      },
    },
    {
      label: 'encrypted 字段缺失',
      patch: (container) => {
        delete container.encrypted
      },
    },
    {
      label: 'crypto 头部缺 wrappedMasterKey',
      patch: (container) => {
        delete (container.crypto as Record<string, unknown>).wrappedMasterKey
      },
    },
    {
      label: 'kdf.salt 不是合法 base64',
      patch: (container) => {
        section(container, 'kdf').salt = '!!!'
      },
    },
    {
      label: 'kdf.memoryKiB 不是整数',
      patch: (container) => {
        section(container, 'kdf').memoryKiB = '65536'
      },
    },
  ]

  it.each(patched)('$label', async ({ patch }) => {
    const { providers, calls } = createProbe()
    const bytes = patchContainer(await sampleContainer(), patch)
    const error = await captureError(openVault(bytes, WRONG_PASSWORD, providers))

    expect(error).toBeInstanceOf(VaultFormatError)
    expect(calls).not.toContain('kdf.deriveKey')
  })

  it('明文容器（encrypted 缺失）被明确拒绝，不会被当成加密库硬解', async () => {
    // AGENTS.md §5.4 要求明文导出必须二次确认；静默按明文读取会绕过那道提示。
    const bytes = utf8Encode(
      JSON.stringify({
        format: CONTAINER_FORMAT,
        version: CONTAINER_VERSION,
        schemaVersion: SCHEMA_VERSION,
        data: { schemaVersion: SCHEMA_VERSION },
      }),
    )
    const error = await captureError(openVault(bytes, PASSWORD, fixtureProviders))

    expect(error).toBeInstanceOf(VaultFormatError)
    expect(error.message).toContain('明文')
  })
})

describe('步骤 15：C9/C10 在派生 KEK 之前就拒绝', () => {
  const cases: {
    label: string
    field: CryptoSection
    key: string
    value: unknown
    message?: RegExp
  }[] = [
    {
      label: 'memoryKiB 低于基线（降级攻击）',
      field: 'kdf',
      key: 'memoryKiB',
      value: 1024,
      message: /memoryKiB/,
    },
    {
      label: 'iterations 低于基线',
      field: 'kdf',
      key: 'iterations',
      value: 1,
      message: /iterations/,
    },
    {
      label: 'parallelism 低于基线',
      field: 'kdf',
      key: 'parallelism',
      value: 1,
      message: /parallelism/,
    },
    {
      label: 'salt 短于 16 字节',
      field: 'kdf',
      key: 'salt',
      value: base64Encode(new Uint8Array(8)),
      message: /salt/,
    },
    {
      label: 'keyLength 不是 32',
      field: 'kdf',
      key: 'keyLength',
      value: 16,
      message: /keyLength/,
    },
    {
      label: 'kdf.name 与注入的 Provider 不符',
      field: 'kdf',
      key: 'name',
      value: 'scrypt',
      message: /scrypt/,
    },
    {
      label: 'cipher.nonce 长度不是 12',
      field: 'cipher',
      key: 'nonce',
      value: base64Encode(new Uint8Array(AES_256_GCM.nonceLength - 1)),
    },
    {
      label: 'cipher.tag 长度不是 16',
      field: 'cipher',
      key: 'tag',
      value: base64Encode(new Uint8Array(AES_256_GCM.tagLength + 1)),
    },
    {
      label: 'cipher.name 与注入的 Provider 不符',
      field: 'cipher',
      key: 'name',
      value: 'chacha20-poly1305',
      message: /chacha20-poly1305/,
    },
    {
      label: 'wrappedMasterKey.nonce 长度不是 12',
      field: 'wrappedMasterKey',
      key: 'nonce',
      value: base64Encode(new Uint8Array(AES_256_GCM.nonceLength + 1)),
    },
    {
      label: 'wrappedMasterKey.tag 长度不是 16',
      field: 'wrappedMasterKey',
      key: 'tag',
      value: base64Encode(new Uint8Array(AES_256_GCM.tagLength - 1)),
    },
  ]

  it.each(cases)('$label', async ({ field, key, value, message }) => {
    const { providers, calls } = createProbe()
    const bytes = patchContainer(await sampleContainer(), (container) => {
      section(container, field)[key] = value
    })

    const error = await captureError(openVault(bytes, PASSWORD, providers))

    // 关键断言：一次 Argon2id 派生都没发生，攻击者无法用「响应快慢」探测参数是否被接受。
    expect(calls).not.toContain('kdf.deriveKey')
    expect(calls).not.toContain('aead.decrypt')
    expect(calls).not.toContain('compress.decompress')
    if (message !== undefined) expect(error.message).toMatch(message)
  })

  it('降级报错先于结构性报错，消息指名是哪个参数', async () => {
    const { providers } = createProbe()
    const bytes = patchContainer(await sampleContainer(), (container) => {
      // memoryKiB=1 同时违反基线与 8*parallelism 的结构约束；必须报「低于基线」。
      section(container, 'kdf').memoryKiB = 1
    })

    const error = await captureError(openVault(bytes, PASSWORD, providers))

    expect(error.message).toContain('低于基线')
    expect(error.message).toContain('memoryKiB')
  })
})

describe('步骤 15：C4 高版本容器在解密之前被拒', () => {
  function v99Bytes(): Uint8Array {
    return readFileSync(fileURLToPath(new URL(CONTAINER_V99, import.meta.url)))
  }

  it('schemaVersion=99 的夹具抛 VaultVersionError，且完全没有触碰加密能力', async () => {
    const error = await captureError(openVault(v99Bytes(), PASSWORD, explodingProviders))

    expect(error).toBeInstanceOf(VaultVersionError)
    expect(error.message).toContain('schemaVersion=99')
    expect(error.message).toContain('请升级 App')
  })

  it('容器 version 过高同样在解密之前被拒', async () => {
    const bytes = patchContainer(await sampleContainer(), (container) => {
      container.version = CONTAINER_VERSION + 1
    })

    const error = await captureError(openVault(bytes, PASSWORD, explodingProviders))

    expect(error).toBeInstanceOf(VaultVersionError)
    expect(error.message).toContain(`version=${CONTAINER_VERSION + 1}`)
  })

  it('高版本拒绝路径连随机数都不取', async () => {
    // explodingProviders 的每个方法一被调用就抛错；能拿到 VaultVersionError 就证明一个都没被调用。
    await expect(openVault(v99Bytes(), PASSWORD, explodingProviders)).rejects.toThrow(
      VaultVersionError,
    )
  })
})

describe('步骤 15：C12 读取路径的清零', () => {
  it('成功解锁后，含明文 JSON 在内的所有中间缓冲区都被清零', async () => {
    const { provider: random, issued } = createRecordingRandom()
    const { providers, recordings } = createRecordingProviders({ ...fixtureProviders, random })
    const bytes = await sampleContainer(providers)
    const dek = Uint8Array.from(issued.find((b) => b.length === AES_256_GCM.keyLength)!)
    const mark = recordings.length

    const handle = await openVault(bytes, PASSWORD, providers)

    const window = recordings.slice(mark)
    expect(countInvocations(window, 'compress.decompress', 'json')).toBe(1)

    // 解包出来的 DEK 是唯一的例外：它要活到 lock()，否则句柄根本无法再次写入。
    const unwrapped = window.filter(
      (item) => item.call === 'aead.decrypt' && item.role === 'plaintext',
    )
    expect(unwrapped).toHaveLength(2)
    const unwrappedDek = unwrapped.find((item) => item.copy.length === AES_256_GCM.keyLength)!
    expect(unwrappedDek.copy).toEqual(dek)

    for (const item of window) {
      if (item === unwrappedDek) continue
      expect(isZeroed(item.ref), `${item.call} 的 ${item.role} 未被清零`).toBe(true)
    }

    handle.lock()
    expect(isZeroed(unwrappedDek.ref)).toBe(true)
  })

  it('解锁失败（主密码错误）时，密码字节与 KEK 同样被清零', async () => {
    const { providers, recordings } = createRecordingProviders()
    const bytes = await sampleContainer(providers)
    const mark = recordings.length

    await expect(openVault(bytes, WRONG_PASSWORD, providers)).rejects.toThrow(VaultAuthError)

    const window = recordings.slice(mark)
    expect(countInvocations(window, 'kdf.deriveKey', 'password')).toBe(1)
    for (const recording of window) {
      expect(isZeroed(recording.ref), `${recording.call} 的 ${recording.role} 未被清零`).toBe(true)
    }
  })

  it('结构性拒绝路径不产生任何需要清零的秘密缓冲区', async () => {
    const { providers, recordings } = createRecordingProviders()
    const bytes = patchContainer(await sampleContainer(providers), (container) => {
      section(container, 'kdf').memoryKiB = 1024
    })
    const mark = recordings.length

    await expect(openVault(bytes, PASSWORD, providers)).rejects.toThrow()

    expect(countInvocations(recordings.slice(mark), 'kdf.deriveKey', 'password')).toBe(0)
  })
})

describe('步骤 15：C8 无模块级可变状态', () => {
  it('container.ts 没有顶层 let / var', () => {
    const source = readFileSync(fileURLToPath(new URL('../container.ts', import.meta.url)), 'utf8')

    // 模块级可变变量会被跨调用共享，解锁尝试计数之类的旁路就是从这儿长出来的。
    expect(source).not.toMatch(/^(?:export\s+)?(?:let|var)\s/m)
  })
})

// ── 步骤 16：changeMasterPassword 与 lock ───────────────────────────────────

describe('步骤 16：changeMasterPassword', () => {
  async function populated(providers: VaultProviders): Promise<VaultHandle> {
    const handle = await createVault(PASSWORD, providers, {
      appVersion: APP_VERSION,
      now: fixedNow,
    })
    // 塞几条数据，让「改密码是 O(1)」这个断言有实际分量。
    entriesOf(handle).push(makeEntry(), makeEntry({ id: '019c0f6a-0000-7000-8000-000000000002' }))
    tagsOf(handle).push(makeTag())
    return handle
  }

  it('改密码后新密码可开、旧密码不可开，data 不变', async () => {
    const handle = await populated(fixtureProviders)
    const before = handle.data

    await handle.changeMasterPassword(NEXT_PASSWORD)
    const bytes = await handle.serialize()

    const opened = await openVault(bytes, NEXT_PASSWORD, fixtureProviders)
    expect(opened.data).toEqual(before)

    const error = await captureError(openVault(bytes, PASSWORD, fixtureProviders))
    expect(error).toBeInstanceOf(VaultAuthError)
    expect(error.message).toBe(AUTH_MESSAGE)
  })

  it('R2-3：期间的 Provider 轨迹是 encrypt×1 / deriveKey×1，其余全 0', async () => {
    const { providers, recordings } = createRecordingProviders()
    const handle = await populated(providers)
    await handle.serialize()
    const mark = recordings.length

    await handle.changeMasterPassword(NEXT_PASSWORD)

    const window = recordings.slice(mark)
    expect(countInvocations(window, 'aead.encrypt', 'plaintext')).toBe(1)
    expect(countInvocations(window, 'aead.decrypt', 'ciphertext')).toBe(0)
    expect(countInvocations(window, 'compress.compress', 'json')).toBe(0)
    expect(countInvocations(window, 'compress.decompress', 'gzip')).toBe(0)
    expect(countInvocations(window, 'kdf.deriveKey', 'password')).toBe(1)
  })

  it('R2-3：改密码前后交给 aead.encrypt 的明文字节快照逐字节相同', async () => {
    const { providers, recordings } = createRecordingProviders()
    const handle = await populated(providers)

    const m0 = recordings.length
    await handle.serialize()
    const firstWindow = recordings.slice(m0)

    const m1 = recordings.length
    await handle.changeMasterPassword(NEXT_PASSWORD)
    const changeWindow = recordings.slice(m1)

    const m2 = recordings.length
    await handle.serialize()
    const secondWindow = recordings.slice(m2)

    const firstJson = snapshots(firstWindow, 'compress.compress', 'json')
    const secondJson = snapshots(secondWindow, 'compress.compress', 'json')
    expect(firstJson).toHaveLength(1)
    expect(secondJson).toHaveLength(1)
    expect(secondJson[0]).toEqual(firstJson[0])
    expect(firstJson[0]!.length).toBeGreaterThan(0)

    // 交给 AEAD 的压缩输出同样逐字节相同——payload 从头到尾没被碰过，只是换了包裹。
    expect(snapshots(secondWindow, 'aead.encrypt', 'plaintext')).toEqual(
      snapshots(firstWindow, 'aead.encrypt', 'plaintext'),
    )

    // 改密码那一趟确实重新包裹了 DEK：唯一一次 encrypt 的明文就是 DEK 本身（32 字节）。
    expect(snapshots(changeWindow, 'aead.encrypt', 'plaintext')[0]).toHaveLength(
      AES_256_GCM.keyLength,
    )
  })

  it('salt 与 wrappedMasterKey 三字段全换，kdf 参数保持不变', async () => {
    const handle = await populated(fixtureProviders)
    const before = decodeContainer(await handle.serialize())

    await handle.changeMasterPassword(NEXT_PASSWORD)
    const after = decodeContainer(await handle.serialize())

    expect(after.crypto.kdf.salt).not.toBe(before.crypto.kdf.salt)
    expect(base64Decode(after.crypto.kdf.salt)).toHaveLength(ARGON2ID_PARAMS.saltLength)
    expect(after.crypto.wrappedMasterKey.nonce).not.toBe(before.crypto.wrappedMasterKey.nonce)
    expect(after.crypto.wrappedMasterKey.tag).not.toBe(before.crypto.wrappedMasterKey.tag)
    expect(after.crypto.wrappedMasterKey.data).not.toBe(before.crypto.wrappedMasterKey.data)

    expect(after.crypto.kdf.name).toBe(before.crypto.kdf.name)
    expect(after.crypto.kdf.memoryKiB).toBe(before.crypto.kdf.memoryKiB)
    expect(after.crypto.kdf.iterations).toBe(before.crypto.kdf.iterations)
    expect(after.crypto.kdf.parallelism).toBe(before.crypto.kdf.parallelism)
    expect(after.crypto.kdf.keyLength).toBe(before.crypto.kdf.keyLength)
  })

  it('R2-3：改密码后 payload 三件套会变，这不是回归', async () => {
    // 写入流程每次都换新 cipher.nonce，所以 data / nonce / tag 必然不同。
    // 这条测试把该行为钉住，避免有人误把「密文不变」当成改密码的验收标准又改回去。
    const handle = await populated(fixtureProviders)
    const before = decodeContainer(await handle.serialize())

    await handle.changeMasterPassword(NEXT_PASSWORD)
    const after = decodeContainer(await handle.serialize())

    expect(after.data).not.toBe(before.data)
    expect(after.crypto.cipher.nonce).not.toBe(before.crypto.cipher.nonce)
    expect(after.crypto.cipher.tag).not.toBe(before.crypto.cipher.tag)
  })

  it('改密码期间的 KEK / 密码字节 / 新 salt 被清零，DEK 保留', async () => {
    const { provider: random, issued } = createRecordingRandom()
    const { providers, recordings } = createRecordingProviders({ ...fixtureProviders, random })
    const handle = await populated(providers)
    const mark = recordings.length

    await handle.changeMasterPassword(NEXT_PASSWORD)

    const dek = issued.find((buffer) => buffer.length === AES_256_GCM.keyLength)!
    const window = recordings.slice(mark)
    expect(countInvocations(window, 'kdf.deriveKey', 'kek')).toBe(1)
    for (const item of window) {
      if (item.ref === dek) continue
      expect(isZeroed(item.ref), `${item.call} 的 ${item.role} 未被清零`).toBe(true)
    }
    expect(isZeroed(dek)).toBe(false)
  })

  it('改密码不影响此前已经写出的文件——那份仍然只认旧密码', async () => {
    // 已落盘的容器是历史快照，wrappedMasterKey 早就固化在里面了。
    const handle = await populated(fixtureProviders)
    const before = await handle.serialize()

    await handle.changeMasterPassword(NEXT_PASSWORD)
    const after = await handle.serialize()

    await expect(openVault(before, PASSWORD, fixtureProviders)).resolves.toBeDefined()
    await expect(openVault(before, NEXT_PASSWORD, fixtureProviders)).rejects.toThrow(VaultAuthError)
    await expect(openVault(after, NEXT_PASSWORD, fixtureProviders)).resolves.toBeDefined()
    expect(before).not.toEqual(after)
  })
})

describe('步骤 16：lock', () => {
  it('lock 之后 data / serialize / changeMasterPassword 全部抛 VaultLockedError', async () => {
    const handle = await newHandle()
    handle.lock()

    expect(() => handle.data).toThrow(VaultLockedError)
    await expect(handle.serialize()).rejects.toThrow(VaultLockedError)
    await expect(handle.changeMasterPassword(NEXT_PASSWORD)).rejects.toThrow(VaultLockedError)
  })

  it('lock 幂等，且 DEK 缓冲区被清零', async () => {
    const { provider: random, issued } = createRecordingRandom()
    const handle = await createVault(
      PASSWORD,
      { ...fixtureProviders, random },
      {
        appVersion: APP_VERSION,
        now: fixedNow,
      },
    )
    const dek = issued.find((buffer) => buffer.length === AES_256_GCM.keyLength)!

    expect(isZeroed(dek)).toBe(false)
    handle.lock()
    expect(isZeroed(dek)).toBe(true)

    expect(() => handle.lock()).not.toThrow()
    expect(isZeroed(dek)).toBe(true)
    expect(() => handle.data).toThrow(VaultLockedError)
  })

  it('openVault 得到的句柄同样可以 lock，且锁定后文件本身没被破坏', async () => {
    const handle = await newHandle()
    entriesOf(handle).push(makeEntry())
    const bytes = await handle.serialize()

    const opened = await openVault(bytes, PASSWORD, fixtureProviders)
    opened.lock()

    expect(() => opened.data).toThrow(VaultLockedError)
    const reopened = await openVault(bytes, PASSWORD, fixtureProviders)
    expect(reopened.data.entries).toHaveLength(1)
  })
})

// ── 步骤 14/15/16 共用：平台无关性 ─────────────────────────────────────────

describe('平台无关性（AGENTS.md §3）', () => {
  const source = readFileSync(fileURLToPath(new URL('../container.ts', import.meta.url)), 'utf8')

  it('只 import 相对模块与 @askdaddy 内部包', () => {
    const specifiers = [...source.matchAll(/from '([^']+)'/g)].map((match) => match[1]!)
    const external = specifiers.filter(
      (specifier) => !specifier.startsWith('.') && !specifier.startsWith('@askdaddy/'),
    )

    expect(external).toEqual([])
  })

  it('不依赖 @askdaddy/crypto-web（核心包禁止依赖平台适配包）', () => {
    expect(source).not.toContain('@askdaddy/crypto-web')
  })

  it('不触碰 window / chrome / process / Buffer / require', () => {
    for (const banned of ['window', 'chrome', 'process', 'Buffer', 'require(']) {
      expect(source, banned).not.toContain(banned)
    }
  })

  it('运行时依赖全部是 workspace 内部包', () => {
    const manifest = JSON.parse(
      readFileSync(fileURLToPath(new URL('../../package.json', import.meta.url)), 'utf8'),
    ) as { dependencies?: Record<string, string> }

    expect(
      Object.values(manifest.dependencies ?? {}).every((version) =>
        version.startsWith('workspace:'),
      ),
    ).toBe(true)
  })
})
