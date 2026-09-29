import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { utf8Decode, utf8Encode } from '@askdaddy/crypto'
import {
  assertVaultData,
  SCHEMA_VERSION,
  VaultSchemaError,
  VaultVersionError,
  type VaultData,
} from '@askdaddy/vault'
import { openPlaintext, sealPlaintext } from '../container.js'
import { TransferFormatError } from '../errors.js'
import { TRANSFER_LIMITS } from '../input.js'

const fixture = (name: string): string =>
  readFileSync(new URL(`../__fixtures__/${name}`, import.meta.url), 'utf8')

const vaultFixture = (name = 'mfavault_plaintext.json'): VaultData =>
  assertVaultData((JSON.parse(fixture(name)) as { data: unknown }).data)

const containerFixture = (name: string): Record<string, unknown> =>
  JSON.parse(fixture(name)) as Record<string, unknown>

const bytesOf = (input: unknown): Uint8Array =>
  input instanceof Uint8Array ? input : utf8Encode(JSON.stringify(input))

const unseal = (bytes: Uint8Array): unknown => JSON.parse(utf8Decode(bytes)) as unknown

/** 夹具里的假 secret（同一批字节在文本夹具里写作 base32 `4SJHB4GSD43FZBAI7C2HLRJGPQ`）。 */
const SECRET_FORMS = [
  '5JJw8NIfNlyECPi0dcUmfA==',
  '5JJw8NIfNlyECPi0dcUmfA',
  'e49270f0d21f365c8408f8b475c5267c',
  '4SJHB4GSD43FZBAI7C2HLRJGPQ',
]

const messageOf = (run: () => unknown): string => {
  try {
    run()
  } catch (error) {
    return (error as Error).message
  }
  throw new Error('预期抛错，实际没有')
}

describe('sealPlaintext', () => {
  it('顶层恰为五个键，encrypted 为 false，data 是对象而非字符串', () => {
    const sealed = unseal(sealPlaintext(vaultFixture())) as Record<string, unknown>
    expect(Object.keys(sealed)).toEqual(['format', 'version', 'schemaVersion', 'encrypted', 'data'])
    expect(sealed.format).toBe('mfavault')
    expect(sealed.version).toBe(1)
    expect(sealed.encrypted).toBe(false)
    expect(typeof sealed.data).toBe('object')
    expect(sealed.data).not.toBeNull()
  })

  it('头部 schemaVersion 恒等于明文里的值', () => {
    const sealed = unseal(sealPlaintext(vaultFixture())) as {
      schemaVersion: number
      data: { schemaVersion: number }
    }
    expect(sealed.schemaVersion).toBe(sealed.data.schemaVersion)
    expect(sealed.schemaVersion).toBe(SCHEMA_VERSION)
  })

  it('对非法 VaultData 抛错而不是产出文件', () => {
    const data = vaultFixture()
    const invalid = {
      ...data,
      entries: [{ ...data.entries[0]!, digits: 9 }],
    } as unknown as VaultData
    expect(() => sealPlaintext(invalid)).toThrow(VaultSchemaError)
  })

  it('纯函数：同一输入连续两次产出逐字节相同', () => {
    const data = vaultFixture()
    expect(sealPlaintext(data)).toEqual(sealPlaintext(data))
  })

  it('空 entries 与空 tags 也能封装', () => {
    const data = vaultFixture()
    expect(() => sealPlaintext({ ...data, entries: [], tags: [] })).not.toThrow()
  })
})

describe('openPlaintext：往返', () => {
  it('seal → open 往返无损，且返回值通过 assertVaultData', () => {
    const data = vaultFixture()
    const opened = openPlaintext(sealPlaintext(data))
    expect(opened).toEqual(data)
    expect(() => assertVaultData(opened)).not.toThrow()
  })

  it('真实夹具解封出 3 条目 1 标签', () => {
    const opened = openPlaintext(utf8Encode(fixture('mfavault_plaintext.json')))
    expect(opened.entries).toHaveLength(3)
    expect(opened.tags).toHaveLength(1)
    expect(opened.entries[0]).toMatchObject({ issuer: 'Deno', account: 'Mason', digits: 6 })
    expect(opened.settings.clipboardClearSeconds).toBeGreaterThan(0)
  })

  it('schemaVersion 0 的老文件经迁移链升到当前版本', () => {
    const opened = openPlaintext(utf8Encode(fixture('mfavault_plaintext_v0.json')))
    expect(opened.schemaVersion).toBe(SCHEMA_VERSION)
    expect(opened.entries).toHaveLength(2)
    // 迁移只补字段，不清理未知字段。
    expect(opened).toHaveProperty('legacyFieldFromV0')
    expect(() => assertVaultData(opened)).not.toThrow()
  })

  it('迁移前的 v0 明文本身过不了 assertVaultData，证明确实走了迁移链', () => {
    const raw = containerFixture('mfavault_plaintext_v0.json').data
    expect(() => assertVaultData(raw)).toThrow(VaultSchemaError)
  })
})

describe('openPlaintext：C3 上限闸门先于解析', () => {
  it('超过字节上限的**合法** JSON 也在 parse 之前被拒', () => {
    const huge = `{"format":"mfavault","version":1,"schemaVersion":1,"encrypted":false,"data":{"pad":"${'x'.repeat(
      TRANSFER_LIMITS.maxInputBytes,
    )}"}}`
    const bytes = utf8Encode(huge)
    expect(bytes.length).toBeGreaterThan(TRANSFER_LIMITS.maxInputBytes)
    // 前提自证：这份输入本身是合法 JSON，若 parse 先跑就不会得到「超过上限」的文案。
    expect(() => JSON.parse(huge)).not.toThrow()
    expect(messageOf(() => openPlaintext(bytes))).toContain('超过上限')
  })

  it('刚好在上限内的输入不因体积被拒', () => {
    const pad = TRANSFER_LIMITS.maxInputBytes - 200
    const huge = `{"format":"mfavault","pad":"${'x'.repeat(pad)}"}`
    const bytes = utf8Encode(huge)
    expect(bytes.length).toBeLessThanOrEqual(TRANSFER_LIMITS.maxInputBytes)
    expect(messageOf(() => openPlaintext(bytes))).not.toContain('超过上限')
  })
})

describe('openPlaintext：版本类错误', () => {
  it('version 高于支持值时抛版本类错误并提示升级 App', () => {
    const container = { ...containerFixture('mfavault_plaintext.json'), version: 2 }
    const message = messageOf(() => openPlaintext(bytesOf(container)))
    expect(message).toContain('升级 App')
    expect(message).toContain('version=2')
    expect(() => openPlaintext(bytesOf(container))).toThrow(VaultVersionError)
  })

  it('schemaVersion 高于支持值时同样抛版本类错误', () => {
    const container = { ...containerFixture('mfavault_plaintext.json'), schemaVersion: 9 }
    expect(() => openPlaintext(bytesOf(container))).toThrow(VaultVersionError)
    expect(messageOf(() => openPlaintext(bytesOf(container)))).toContain('升级 App')
  })

  it('version 不是整数时判为文件损坏', () => {
    const container = { ...containerFixture('mfavault_plaintext.json'), version: '1' }
    expect(() => openPlaintext(bytesOf(container))).toThrow(/必须是整数/)
  })
})

describe('openPlaintext：外壳损坏', () => {
  const cases: [string, unknown, string | RegExp][] = [
    // 直接给原始字节：经 `JSON.stringify` 包装会变成合法的 JSON 字符串字面量，测不到 parse 失败路径。
    ['非 JSON', utf8Encode('this is not json at all'), /不是合法的 JSON/],
    ['顶层是数组', [1, 2, 3], /顶层不是 JSON 对象/],
    ['顶层是字符串', '"mfavault"', /顶层不是 JSON 对象/],
    ['顶层是 null', null, /顶层不是 JSON 对象/],
    ['缺 format', { version: 1, schemaVersion: 1, encrypted: false, data: {} }, /不是本 App/],
    ['format 不对', { format: 'aegis', encrypted: false, data: {} }, /不是本 App/],
    ['encrypted 缺失', { format: 'mfavault', version: 1, schemaVersion: 1, data: {} }, /encrypted/],
    [
      'encrypted 非布尔',
      { format: 'mfavault', version: 1, schemaVersion: 1, encrypted: 'false', data: {} },
      /encrypted/,
    ],
    [
      'data 是字符串',
      { format: 'mfavault', version: 1, schemaVersion: 1, encrypted: false, data: 'aaaa' },
      /而不是字符串/,
    ],
    [
      'data 是数组',
      { format: 'mfavault', version: 1, schemaVersion: 1, encrypted: false, data: [] },
      /不是 JSON 对象/,
    ],
    [
      'data 缺失',
      { format: 'mfavault', version: 1, schemaVersion: 1, encrypted: false },
      /不是 JSON 对象/,
    ],
  ]

  for (const [name, input, expected] of cases) {
    it(`${name} 抛 TransferFormatError`, () => {
      expect(() => openPlaintext(bytesOf(input))).toThrow(TransferFormatError)
      expect(messageOf(() => openPlaintext(bytesOf(input)))).toMatch(expected)
    })
  }

  it('encrypted: true 的文案指向加密容器路径，而不是笼统的格式错误', () => {
    const message = messageOf(() => openPlaintext(utf8Encode(fixture('mfavault_malformed.json'))))
    expect(message).toContain('加密')
    expect(message).toContain('主密码')
    expect(message).not.toContain('不是合法的 JSON')
    expect(message).not.toContain('顶层不是 JSON 对象')
    expect(() => openPlaintext(utf8Encode(fixture('mfavault_malformed.json')))).toThrow(
      TransferFormatError,
    )
  })

  it('头部与明文的 schemaVersion 不一致时拒绝，不猜按哪一处迁移', () => {
    const container = containerFixture('mfavault_plaintext.json')
    const tampered = { ...container, schemaVersion: 0 }
    expect(messageOf(() => openPlaintext(bytesOf(tampered)))).toContain('schemaVersion 不一致')
  })

  it('明文 schema 非法时透传 VaultSchemaError，不压成 TransferFormatError', () => {
    const container = containerFixture('mfavault_plaintext.json')
    const data = container.data as { entries: Record<string, unknown>[] }
    const tampered = {
      ...container,
      data: { ...data, entries: [{ ...data.entries[0]!, digits: 9 }] },
    }
    expect(() => openPlaintext(bytesOf(tampered))).toThrow(VaultSchemaError)
  })
})

describe('C4：错误文案不泄露 secret', () => {
  const failures: [string, () => unknown][] = [
    ['encrypted: true 夹具', () => openPlaintext(utf8Encode(fixture('mfavault_malformed.json')))],
    [
      '明文 schema 非法',
      () => {
        const container = containerFixture('mfavault_plaintext.json')
        const data = container.data as { entries: Record<string, unknown>[] }
        return openPlaintext(
          bytesOf({
            ...container,
            data: { ...data, entries: [{ ...data.entries[0]!, digits: 9 }] },
          }),
        )
      },
    ],
    [
      '封装非法数据',
      () => {
        const data = vaultFixture()
        return sealPlaintext({
          ...data,
          entries: [{ ...data.entries[0]!, digits: 9 }],
        } as unknown as VaultData)
      },
    ],
    [
      '头部与明文版本不一致',
      () =>
        openPlaintext(
          bytesOf({ ...containerFixture('mfavault_plaintext.json'), schemaVersion: 0 }),
        ),
    ],
  ]

  for (const [name, run] of failures) {
    it(`${name} 的文案不含 secret 的任何编码形式`, () => {
      const message = messageOf(run)
      // `docs/vault-format.md` §5.2：错误消息绝不回显 secret 的值、其 base64 或 hex 形式。
      // 这里连 base32 形态与 issuer 一并断言，覆盖四种编码路径。
      for (const form of SECRET_FORMS) {
        expect(message).not.toContain(form)
      }
      expect(message).not.toContain('Deno')
    })
  }
})
