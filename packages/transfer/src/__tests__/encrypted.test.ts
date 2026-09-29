import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes, scryptSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { AeadAuthError, utf8Decode, utf8Encode } from '@askdaddy/crypto'
import type { AeadProvider, Pbkdf2Provider, ScryptProvider } from '@askdaddy/crypto'
import { assertVaultData } from '@askdaddy/vault'
import { generateAegis, parseAegis } from '../aegis.js'
import { parseTwoFas } from '../twofas.js'
import { detect } from '../detect.js'
import { generateAegisEncrypted, parseAegisEncrypted, parseTwoFasEncrypted } from '../encrypted.js'
import { TransferAuthError, TransferFormatError } from '../errors.js'

const text = (name: string) =>
  readFileSync(new URL(`../__fixtures__/${name}`, import.meta.url), 'utf8')
const fakePassword = () => utf8Encode('test')
const edgePassword = () => utf8Encode('test-测试')
const params = { costFactor: 1024, blockSize: 8, parallelism: 1, keyLength: 32 }
const vault = assertVaultData(
  (JSON.parse(text('mfavault_plaintext.json')) as { data: unknown }).data,
)
const message = new TransferAuthError().message

function providers(fault?: 'kdf' | 'encrypt' | 'decrypt', failAt = 1) {
  const issued: Uint8Array[] = []
  const keys: Uint8Array[] = []
  let operations = 0
  let kdfCalls = 0
  const keep = (bytes: Uint8Array) => {
    issued.push(bytes)
    return bytes
  }
  const key = (bytes: Uint8Array) => {
    keys.push(bytes)
    return keep(bytes)
  }
  const scrypt: ScryptProvider = {
    name: 'scrypt',
    async deriveKey(password, salt, p) {
      kdfCalls += 1
      if (fault === 'kdf') throw new Error('injected-provider-failure')
      return key(
        scryptSync(password, salt, p.keyLength, {
          N: p.costFactor,
          r: p.blockSize,
          p: p.parallelism,
          maxmem: 128 * 1024 * 1024,
        }),
      )
    },
  }
  const pbkdf2: Pbkdf2Provider = {
    name: 'pbkdf2',
    async deriveKey(password, salt, p) {
      kdfCalls += 1
      if (fault === 'kdf') throw new Error('injected-provider-failure')
      expect(p).toEqual({ hash: 'SHA-256', iterations: 10000, keyLength: 32 })
      return key(pbkdf2Sync(password, salt, p.iterations, p.keyLength, 'sha256'))
    },
  }
  const aead: AeadProvider = {
    name: 'aes-256-gcm',
    async decrypt(k, sealed) {
      operations += 1
      if (fault === 'decrypt' && operations === failAt)
        throw new AeadAuthError('injected-provider-failure')
      try {
        const decipher = createDecipheriv('aes-256-gcm', k, sealed.nonce)
        decipher.setAuthTag(sealed.tag)
        return keep(Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]))
      } catch {
        throw new AeadAuthError('independent-auth-failure')
      }
    },
    async encrypt(k, plain) {
      issued.push(plain)
      operations += 1
      if (fault === 'encrypt' && operations === failAt) throw new Error('injected-provider-failure')
      const nonce = keep(randomBytes(12))
      const cipher = createCipheriv('aes-256-gcm', k, nonce)
      return {
        nonce,
        ciphertext: keep(Buffer.concat([cipher.update(plain), cipher.final()])),
        tag: keep(cipher.getAuthTag()),
      }
    },
  }
  const random = { randomBytes: (length: number) => keep(randomBytes(length)) }
  return { scrypt, pbkdf2, aead, random, issued, keys, calls: () => kdfCalls }
}

const allZero = (bytes: readonly Uint8Array[]) => bytes.every((b) => b.every((v) => v === 0))

interface AegisFile {
  version: number
  db: string
  header: {
    slots: {
      type: number
      uuid?: string
      n?: number
      r?: number
      p?: number
      salt?: string
      key?: string
      key_params?: { nonce: string; tag: string }
    }[]
    params: { nonce: string; tag: string }
  }
}

function independentAegis(input: Uint8Array, password: Uint8Array) {
  const file = JSON.parse(utf8Decode(input)) as AegisFile
  expect(file.version).toBe(1)
  const slot = file.header.slots[0]!
  expect(slot.type).toBe(1)
  expect(slot.uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  expect([slot.n, slot.r, slot.p]).toEqual([1024, 8, 1])
  const key = scryptSync(password, Buffer.from(slot.salt!, 'hex'), 32, {
    N: slot.n!,
    r: slot.r!,
    p: slot.p!,
    maxmem: 128 * 1024 * 1024,
  })
  const open = (key: Uint8Array, ciphertext: Uint8Array, p: { nonce: string; tag: string }) => {
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(p.nonce, 'hex'))
    d.setAuthTag(Buffer.from(p.tag, 'hex'))
    return Buffer.concat([d.update(ciphertext), d.final()])
  }
  const master = open(key, Buffer.from(slot.key!, 'hex'), slot.key_params!)
  const db = open(master, Buffer.from(file.db, 'base64'), file.header.params)
  try {
    expect(master.length).toBe(32)
    expect(Buffer.compare(master, key)).not.toBe(0)
    return JSON.parse(db.toString()) as unknown
  } finally {
    key.fill(0)
    master.fill(0)
    db.fill(0)
  }
}

describe('加密 golden 与字段保留', () => {
  it('上游 Aegis 夹具解密：6 成功、1 非标准条目失败', async () => {
    const p = providers()
    const input = text('aegis_encrypted.json')
    expect(detect(input)).toBe('aegis')
    const result = await parseAegisEncrypted(input, fakePassword(), p)
    expect(result.entries.length).toBe(6)
    expect(result.failures.length).toBe(1)
    expect(result.entries.map((e) => e.account)).toEqual(
      parseAegis(text('aegis_plain.json')).entries.map((e) => e.account),
    )
    expect(allZero(p.issued)).toBe(true)
    expect(result.entries.every((e) => e.secret.some((v) => v !== 0))).toBe(true)
  })

  it('Aegis 多槽、Unicode 密码、分组与顺序 golden', async () => {
    const p = providers()
    const result = await parseAegisEncrypted(text('aegis_encrypted_edge.json'), edgePassword(), p)
    expect(result).toEqual(parseAegis(text('aegis_grouped_v3.json')))
    expect(p.calls()).toBe(2)
    expect(allZero(p.issued)).toBe(true)
  })

  it('上游 2FAS v4 正常 golden', async () => {
    const p = providers()
    const input = text('twofas_encrypted.2fas')
    expect(detect(input)).toBe('2fas')
    const result = await parseTwoFasEncrypted(input, fakePassword(), p)
    expect(result.entries.length).toBe(4)
    expect(result.failures.length).toBe(1)
    expect(result.entries.map((e) => e.account)).toEqual(
      parseTwoFas(text('2fas_authenticator_plain_v4.2fas')).entries.map((e) => e.account),
    )
    expect(p.calls()).toBe(2)
    expect(allZero(p.issued)).toBe(true)
  })

  it('2FAS 独立盐、分组、部分失败、伪造 iterations golden', async () => {
    const p = providers()
    const result = await parseTwoFasEncrypted(text('twofas_encrypted_edge.2fas'), edgePassword(), p)
    expect(result).toEqual(parseTwoFas(text('twofas_edge.json')))
    expect(result.tags.length).toBe(2)
    expect(result.failures.length).toBe(5)
    expect(allZero(p.issued)).toBe(true)
  })

  it.each(['twofas_encrypted_v2.2fas', 'twofas_encrypted_v3.2fas'])(
    '明确拒绝旧版 %s',
    async (name) => {
      const p = providers()
      await expect(parseTwoFasEncrypted(text(name), fakePassword(), p)).rejects.toThrow(
        TransferAuthError,
      )
      expect(p.calls()).toBe(0)
    },
  )
})

describe('加密导出独立反向校验', () => {
  it('独立 Node 原语解密等于明文生成器，保留标签、顺序与 counter', async () => {
    const p = providers()
    const password = edgePassword()
    const output = await generateAegisEncrypted(vault, password, params, p)
    const expected = JSON.parse(utf8Decode(generateAegis(vault))) as { db: unknown }
    expect(independentAegis(output, password)).toEqual(expected.db)
    const parsed = await parseAegisEncrypted(output, password, providers())
    expect(parsed).toEqual(parseAegis(generateAegis(vault)))
    expect(password.some((v) => v !== 0)).toBe(true)
    expect(allZero(p.issued)).toBe(true)
  })

  it('两次导出 salt、两层 nonce、UUID 不复用', async () => {
    const files: AegisFile[] = []
    for (let i = 0; i < 2; i += 1)
      files.push(
        JSON.parse(
          utf8Decode(await generateAegisEncrypted(vault, fakePassword(), params, providers())),
        ) as AegisFile,
      )
    expect(files[0]!.header.slots[0]!.salt).not.toBe(files[1]!.header.slots[0]!.salt)
    expect(files[0]!.header.params.nonce).not.toBe(files[1]!.header.params.nonce)
    expect(files[0]!.header.slots[0]!.key_params!.nonce).not.toBe(
      files[1]!.header.slots[0]!.key_params!.nonce,
    )
    expect(files[0]!.header.slots[0]!.uuid).not.toBe(files[1]!.header.slots[0]!.uuid)
  })

  it('非法输出密钥长度拒绝，不能生成非 AES256 文件', async () => {
    await expect(
      generateAegisEncrypted(vault, fakePassword(), { ...params, keyLength: 16 }, providers()),
    ).rejects.toThrow(TransferFormatError)
  })

  it.each([1, 2])('encrypt 第 %i 次故障清零已生成的密钥和缓冲', async (at) => {
    const p = providers('encrypt', at)
    await expect(generateAegisEncrypted(vault, fakePassword(), params, p)).rejects.toThrow()
    expect(p.issued.length).toBeGreaterThan(0)
    expect(allZero(p.issued)).toBe(true)
  })

  it('KDF 故障也清零随机 master/salt', async () => {
    const p = providers('kdf')
    await expect(generateAegisEncrypted(vault, fakePassword(), params, p)).rejects.toThrow()
    expect(allZero(p.issued)).toBe(true)
  })
})

describe('不可区分错误与资源限制', () => {
  it.each(['aegis', 'twofas'] as const)('%s 密码错误、篡改与畸形错误完全相同', async (format) => {
    const parser = format === 'aegis' ? parseAegisEncrypted : parseTwoFasEncrypted
    const name = format === 'aegis' ? 'aegis_encrypted.json' : 'twofas_encrypted.2fas'
    const json = JSON.parse(text(name)) as Record<string, unknown>
    if (format === 'aegis') json.db = 'AAAA'
    else json.servicesEncrypted = 'AAAA:AAAA:AAAA'
    for (const [input, password] of [
      [text(name), utf8Encode('wrong')],
      [JSON.stringify(json), fakePassword()],
      ['{bad', fakePassword()],
    ] as const) {
      const p = providers()
      await expect(parser(input, password, p)).rejects.toMatchObject({
        name: 'TransferAuthError',
        message,
      })
      expect(allZero(p.issued)).toBe(true)
      expect(password.some((v) => v !== 0)).toBe(true)
    }
  })

  it.each(['aegis_encrypted_malformed.json', 'twofas_encrypted_malformed.2fas'])(
    '%s 在派生之前拒绝',
    async (name) => {
      const p = providers()
      const parser = name.startsWith('aegis') ? parseAegisEncrypted : parseTwoFasEncrypted
      await expect(parser(text(name), edgePassword(), p)).rejects.toMatchObject({
        name: 'TransferAuthError',
        message,
      })
      expect(p.calls()).toBe(0)
    },
  )

  it('槽数量上限与无密码槽在 KDF 前拒绝', async () => {
    for (const count of [0, 33]) {
      const json = JSON.parse(text('aegis_encrypted.json')) as AegisFile
      json.header.slots = Array.from({ length: count }, () => ({ type: 2 }))
      const p = providers()
      await expect(parseAegisEncrypted(JSON.stringify(json), fakePassword(), p)).rejects.toThrow(
        TransferAuthError,
      )
      expect(p.calls()).toBe(0)
    }
  })

  it('超深嵌套与超长输入不调用 KDF', async () => {
    const p = providers()
    for (const input of [
      '['.repeat(65) + '0' + ']'.repeat(65),
      new Uint8Array(16 * 1024 * 1024 + 1),
    ]) {
      await expect(parseAegisEncrypted(input, fakePassword(), p)).rejects.toThrow(TransferAuthError)
      await expect(parseTwoFasEncrypted(input, fakePassword(), p)).rejects.toThrow(
        TransferAuthError,
      )
    }
    expect(p.calls()).toBe(0)
  })

  it.each([1, 2])('2FAS decrypt 第 %i 次故障清零临时值', async (at) => {
    const p = providers('decrypt', at)
    await expect(
      parseTwoFasEncrypted(text('twofas_encrypted.2fas'), fakePassword(), p),
    ).rejects.toThrow(TransferAuthError)
    expect(allZero(p.issued)).toBe(true)
  })

  it('Aegis 解 db 故障时清零 master 与 KEK', async () => {
    const p = providers('decrypt', 2)
    await expect(
      parseAegisEncrypted(text('aegis_encrypted.json'), fakePassword(), p),
    ).rejects.toThrow(TransferAuthError)
    expect(p.keys.length).toBe(1)
    expect(allZero(p.issued)).toBe(true)
  })

  it('2FAS reference 损坏不得只凭 services 解密成功', async () => {
    const json = JSON.parse(text('twofas_encrypted.2fas')) as Record<string, unknown>
    const ref = (json.reference as string).split(':')
    const bytes = Buffer.from(ref[0]!, 'base64')
    bytes[0] = bytes[0]! ^ 1
    ref[0] = bytes.toString('base64')
    json.reference = ref.join(':')
    await expect(
      parseTwoFasEncrypted(JSON.stringify(json), fakePassword(), providers()),
    ).rejects.toMatchObject({ name: 'TransferAuthError', message })
  })
})
