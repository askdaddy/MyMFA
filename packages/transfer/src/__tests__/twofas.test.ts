import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { utf8Encode } from '@askdaddy/crypto'
import { parseAegis } from '../aegis.js'
import { TransferFormatError } from '../errors.js'
import { TRANSFER_LIMITS } from '../input.js'
import { parseTwoFas } from '../twofas.js'
import type { ParsedEntry } from '../types.js'

const url = (name: string): URL => new URL(`../__fixtures__/${name}`, import.meta.url)
const fileBytes = (name: string): Uint8Array => new Uint8Array(readFileSync(url(name)))
const fileText = (name: string): string => readFileSync(url(name), 'utf8')

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

/** secret 的 hex 由 node 对 `packages/otp/dist` 独立算出后硬编码，不是用被测代码再推一次。 */
const golden = (entries: readonly ParsedEntry[]): unknown[] =>
  entries.map((entry) => ({
    sourceIndex: entry.sourceIndex,
    issuer: entry.issuer,
    account: entry.account,
    kind: entry.kind,
    algo: entry.algo,
    digits: entry.digits,
    secret: hex(entry.secret),
    note: entry.note,
    tagNames: entry.tagNames,
    favorite: entry.favorite,
    ...(entry.kind === 'totp' ? { period: entry.period } : { counter: entry.counter }),
  }))

const wrap = (services: unknown[], groups?: unknown, schemaVersion = 4): string =>
  JSON.stringify({
    services,
    groups: groups ?? [],
    updatedAt: 1702934732299,
    schemaVersion,
    appVersionCode: 5000009,
    appVersionName: '5.1.0',
    appOrigin: 'android',
  })

/** 上游 `BackupService.Otp` 的全部键都可空，这里给一份「手工添加的 TOTP」最小可用值。 */
const DEFAULT_OTP: Record<string, unknown> = {
  link: null,
  label: 'Mason',
  account: 'Mason',
  issuer: 'Deno',
  digits: 6,
  period: 30,
  algorithm: 'SHA1',
  tokenType: 'TOTP',
  source: 'Manual',
}

const service = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  name: 'Deno',
  secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ',
  updatedAt: 1702934567518,
  otp: { ...DEFAULT_OTP },
  order: { position: 0 },
  ...overrides,
})

/** 把 `otp` 的部分键覆盖到默认值上，避免每处都重复抄一遍完整的 otp 对象。 */
const withOtp = (otp: Record<string, unknown>, rest: Record<string, unknown> = {}) =>
  service({ ...rest, otp: { ...DEFAULT_OTP, ...otp } })

describe('parseTwoFas：golden 快照', () => {
  it('schemaVersion 4 的 vendored 样本解出 4 条，1 条 STEAM 判为单条失败', () => {
    const result = parseTwoFas(fileBytes('2fas_authenticator_plain_v4.2fas'))
    expect(result.format).toBe('2fas')
    expect(result.tags).toEqual([])
    expect(result.skipped).toBe(0)
    expect(result.warnings).toEqual([])
    expect(golden(result.entries)).toEqual([
      {
        sourceIndex: 0,
        issuer: 'Deno',
        account: 'Mason',
        kind: 'totp',
        algo: 'SHA1',
        digits: 6,
        secret: 'e49270f0d21f365c8408f8b475c5267c',
        note: '',
        tagNames: [],
        favorite: false,
        period: 30,
      },
      {
        sourceIndex: 1,
        issuer: 'Issuu',
        account: 'James',
        kind: 'hotp',
        algo: 'SHA1',
        digits: 6,
        secret: 'c39cc45ed2e99be8cc2fa14b654edd67',
        note: '',
        tagNames: [],
        favorite: false,
        counter: 1,
      },
      {
        sourceIndex: 2,
        issuer: 'Air Canada',
        account: 'Benjamin',
        kind: 'hotp',
        algo: 'SHA256',
        digits: 7,
        secret: '552a94b99feed079b472cd44d52fe642',
        note: '',
        tagNames: [],
        favorite: false,
        counter: 50,
      },
      {
        sourceIndex: 3,
        issuer: 'WWE',
        account: 'Mason',
        kind: 'hotp',
        algo: 'SHA512',
        digits: 8,
        secret: 'ed40c5eefbecce2206b15d75c1182a76',
        note: '',
        tagNames: [],
        favorite: false,
        counter: 10300,
      },
    ])

    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]).toMatchObject({ sourceIndex: 4, path: 'services[4]' })
    expect(result.failures[0]!.reason).toContain('不受支持')
    expect(result.failures[0]!.reason).toContain('steam')
  })

  it('字节与字符串两种入参结果一致', () => {
    expect(golden(parseTwoFas(fileText('2fas_authenticator_plain_v4.2fas')).entries)).toEqual(
      golden(parseTwoFas(fileBytes('2fas_authenticator_plain_v4.2fas')).entries),
    )
  })

  it('C10：与 Aegis 解出的同名条目 secret **字节相同**（counter 系统性差 1，故不比 counter）', () => {
    const twofas = parseTwoFas(fileBytes('2fas_authenticator_plain_v4.2fas')).entries
    const aegis = parseAegis(fileBytes('aegis_plain.json')).entries
    const byIdentity = new Map(aegis.map((e) => [`${e.issuer}:${e.account}`, hex(e.secret)]))
    for (const entry of twofas) {
      const expected = byIdentity.get(`${entry.issuer}:${entry.account}`)
      expect(expected, `${entry.issuer}:${entry.account} 应同时存在于 Aegis 夹具`).toBeDefined()
      expect(hex(entry.secret)).toBe(expected)
    }
  })
})

describe('parseTwoFas：两处字段位置陷阱', () => {
  it('secret 取自 services[].secret 顶层，otp 内同名的另一个值被忽略', () => {
    // `otp.secret` 不是 2FAS 的字段；这里刻意塞一个**合法但不同**的 base32，
    // 若实现误从 otp 内取值，解出的字节就会是 5OM4… 而不是 4SJH…。
    const result = parseTwoFas(wrap([withOtp({ secret: '5OM4WOOGPLQEF6UGN3CPEOOLWU' })]))
    expect(hex(result.entries[0]!.secret)).toBe('e49270f0d21f365c8408f8b475c5267c')
    expect(hex(result.entries[0]!.secret)).not.toBe('eb99cb39c67ae042fa866ec4f239cbb5')
  })

  it('kind 只由 otp.tokenType 决定；services[].type 的品牌图标枚举不影响判定', () => {
    // `type` 是 `ServiceType` 枚举（PascalCase 品牌名），上游只拿它做 legacy 图标匹配。
    const hotp = parseTwoFas(wrap([withOtp({ tokenType: 'HOTP', counter: 7 }, { type: 'Google' })]))
    expect(hotp.entries[0]).toMatchObject({ kind: 'hotp', counter: 7 })

    const totp = parseTwoFas(wrap([withOtp({}, { type: 'Google' })]))
    expect(totp.entries[0]).toMatchObject({ kind: 'totp', period: 30 })
  })

  it('tokenType 大小写不敏感（上游 legacyEnumValueOrNull 按小写比较）', () => {
    expect(parseTwoFas(wrap([withOtp({ tokenType: 'totp' })])).entries[0]!.kind).toBe('totp')
    expect(parseTwoFas(wrap([withOtp({ tokenType: 'hotp', counter: 3 })])).entries[0]!.kind).toBe(
      'hotp',
    )
  })

  it('account 取 otp.account，缺失时退回 otp.label（照抄上游 `?:`）', () => {
    expect(
      parseTwoFas(wrap([withOtp({ account: null, label: '来自 label' })])).entries[0]!.account,
    ).toBe('来自 label')
    // 显式空串**不**触发回退：Kotlin 的 `?:` 只判 null。
    expect(
      parseTwoFas(wrap([withOtp({ account: '', label: '来自 label' })])).entries[0]!.account,
    ).toBe('')
  })

  it('issuer 取 otp.issuer，缺失时退回顶层 name，两者都无则为空串', () => {
    expect(
      parseTwoFas(wrap([withOtp({ issuer: null }, { name: '顶层名字' })])).entries[0]!.issuer,
    ).toBe('顶层名字')
    const noName = withOtp({ issuer: null })
    delete noName.name
    expect(parseTwoFas(wrap([noName])).entries[0]!.issuer).toBe('')
  })

  it('结构化字段与 otp.link 矛盾时以结构化字段为准', () => {
    // `twofas_edge.json` 的 LinkDisagrees：link 写 digits=6&period=30&algorithm=SHA1，
    // 结构化字段写 8 / 50 / SHA512。上游 `ServiceMapper.asDomain` 用的是后者。
    const entry = parseTwoFas(fileBytes('twofas_edge.json')).entries.find(
      (e) => e.issuer === 'LinkDisagrees',
    )
    expect(entry).toMatchObject({ algo: 'SHA512', digits: 8, period: 50 })
  })

  it('icon / badge / link / source / serviceTypeID / order 都不映射到 ParsedEntry', () => {
    const result = parseTwoFas(
      wrap([
        withOtp(
          { link: 'otpauth://totp/x', source: 'Link' },
          {
            serviceTypeID: 'abc',
            badge: { color: 'Red' },
            icon: { selected: 'Label', label: { text: 'DE', backgroundColor: 'Yellow' } },
          },
        ),
      ]),
    )
    expect(Object.keys(result.entries[0]!).sort()).toEqual([
      'account',
      'algo',
      'digits',
      'favorite',
      'issuer',
      'kind',
      'note',
      'period',
      'secret',
      'sourceIndex',
      'tagNames',
    ])
    expect(result.warnings).toEqual([])
  })
})

describe('parseTwoFas：不受支持的令牌类型（ADR-004 + C5）', () => {
  it('tokenType 为 STEAM 判为单条失败，原因是「不受支持」而不是先抱怨 digits=5', () => {
    const result = parseTwoFas(
      wrap([
        service(),
        withOtp(
          { tokenType: 'STEAM', digits: 5 },
          { name: 'Boeing', secret: 'JRZCL47CMXVOQMNPZR2F7J4RGI' },
        ),
        service(),
      ]),
    )
    expect(result.entries.map((e) => e.sourceIndex)).toEqual([0, 2])
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]).toMatchObject({ sourceIndex: 1, path: 'services[1]' })
    expect(result.failures[0]!.reason).toContain('不受支持')
    expect(result.failures[0]!.reason).not.toContain('digits')
  })

  it('tokenType 缺失判为失败，不复制上游「补 TOTP」的静默默认值（C8）', () => {
    // 上游 `ServiceMapper.kt:136` 是 `otp.tokenType?.let { … } ?: Service.AuthType.TOTP`。
    const result = parseTwoFas(wrap([withOtp({ tokenType: null })]))
    expect(result.entries).toEqual([])
    expect(result.failures[0]!.reason).toContain('令牌类型')
  })

  it('tokenType 是无法识别的值判为失败', () => {
    expect(parseTwoFas(wrap([withOtp({ tokenType: 'MOTP' })])).failures[0]!.reason).toContain(
      '不受支持',
    )
    expect(parseTwoFas(wrap([withOtp({ tokenType: 'UNKNOWN' })])).failures[0]!.reason).toContain(
      '无法识别',
    )
  })
})

describe('parseTwoFas：kotlinx explicitNulls=false 的省略语义（C8）', () => {
  it('otp 整体缺失判为单条失败，不整包失败', () => {
    const noOtp = service({ name: 'NoOtp' })
    delete noOtp.otp
    const result = parseTwoFas(wrap([service(), noOtp]))
    expect(result.entries).toHaveLength(1)
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]!.reason).toContain('otp')
  })

  it('totp 缺 period 判为失败，不静默补 30', () => {
    const result = parseTwoFas(wrap([withOtp({ period: undefined })]))
    expect(result.entries).toEqual([])
    expect(result.failures[0]!.reason).toContain('period')
  })

  it('hotp 缺 counter 判为失败，不静默补 0', () => {
    const result = parseTwoFas(wrap([withOtp({ tokenType: 'HOTP' })]))
    expect(result.entries).toEqual([])
    expect(result.failures[0]!.reason).toContain('counter')
  })

  it('digits 缺失判为失败：本格式没有 Aegis 那样的默认值授权', () => {
    const result = parseTwoFas(wrap([withOtp({ digits: null })]))
    expect(result.entries).toEqual([])
    expect(result.failures[0]!.reason).toContain('digits')
  })

  it('totp 携带 counter / hotp 携带 period 时按 kind 取用，另一个忽略', () => {
    expect(parseTwoFas(wrap([withOtp({ counter: 99 })])).entries[0]).toMatchObject({
      kind: 'totp',
      period: 30,
    })
    expect(
      parseTwoFas(wrap([withOtp({ tokenType: 'HOTP', counter: 99, period: 45 })])).entries[0],
    ).toMatchObject({ kind: 'hotp', counter: 99 })
  })

  it('counter 为 -1 判为失败', () => {
    expect(
      parseTwoFas(wrap([withOtp({ tokenType: 'HOTP', counter: -1 })])).failures[0]!.reason,
    ).toContain('counter')
  })
})

describe('parseTwoFas：算法（C8 不回落）', () => {
  it.each(['SHA224', 'SHA384'])('%s 判为单条失败，不回落 SHA1', (algorithm) => {
    const result = parseTwoFas(wrap([withOtp({ algorithm })]))
    expect(result.entries).toEqual([])
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]!.reason).toContain('algorithm')
    expect(result.failures[0]!.reason).toContain('SHA1 / SHA256 / SHA512')
  })

  it('algorithm 缺失判为失败，不复制上游「落成 null 由下游取 SHA1」', () => {
    expect(parseTwoFas(wrap([withOtp({ algorithm: null })])).failures[0]!.reason).toContain(
      'algorithm',
    )
  })

  it.each(['SHA1', 'SHA256', 'SHA512'])('%s 正常通过', (algorithm) => {
    expect(parseTwoFas(wrap([withOtp({ algorithm })])).entries[0]!.algo).toBe(algorithm)
  })
})

describe('parseTwoFas：分组 → tagNames', () => {
  it('groups 与 services[].groupId 还原为 tagNames，未被引用的分组也进 tags', () => {
    const result = parseTwoFas(fileBytes('twofas_edge.json'))
    expect(result.tags).toEqual([
      { name: '工作', sourceIndex: 0 },
      { name: '个人', sourceIndex: 1 },
    ])
    expect(result.entries.map((e) => e.tagNames)).toEqual([['工作'], [], ['个人']])
  })

  it('悬空 groupId 记 warning 而非失败', () => {
    const result = parseTwoFas(fileBytes('twofas_edge.json'))
    // `services[5]` 引用了 groups 里不存在的 id，条目本身仍须产出（C5）。
    const entry = result.entries.find((e) => e.sourceIndex === 5)
    expect(entry).toBeDefined()
    expect(entry!.tagNames).toEqual([])
    expect(result.failures.map((f) => f.sourceIndex)).not.toContain(5)

    const warning = result.warnings.find((w) => w.sourceIndex === 5)
    expect(warning).toMatchObject({ sourceIndex: 5, field: 'services[5].groupId' })
    expect(warning!.message).toContain('不存在')
  })

  it('groups 缺失是合法形态（kotlinx 默认 emptyList），不记 warning', () => {
    const json = JSON.parse(wrap([service()])) as Record<string, unknown>
    delete json.groups
    const result = parseTwoFas(JSON.stringify(json))
    expect(result.entries).toHaveLength(1)
    expect(result.tags).toEqual([])
    expect(result.warnings).toEqual([])
  })

  it('groups 不是数组时整包警告并忽略分组，条目照常产出', () => {
    const json = JSON.parse(wrap([service({ groupId: 'g' })])) as Record<string, unknown>
    json.groups = { '0': { id: 'g', name: '工作' } }
    const result = parseTwoFas(JSON.stringify(json))
    expect(result.entries).toHaveLength(1)
    expect(result.entries[0]!.tagNames).toEqual([])
    expect(result.warnings[0]).toMatchObject({ sourceIndex: null, field: 'groups' })
  })

  it('分组元素缺 id 或 name 时忽略该分组并记 warning', () => {
    const result = parseTwoFas(wrap([service()], [{ name: '没有 id' }]))
    expect(result.tags).toEqual([])
    expect(result.warnings[0]).toMatchObject({ sourceIndex: 0, field: 'groups[0]' })
  })

  it('isExpanded / updatedAt 不映射', () => {
    const result = parseTwoFas(
      wrap(
        [service({ groupId: 'g' })],
        [{ id: 'g', name: '工作', isExpanded: false, updatedAt: 1 }],
      ),
    )
    expect(result.tags).toEqual([{ name: '工作', sourceIndex: 0 }])
  })
})

describe('parseTwoFas：schemaVersion（前向兼容）', () => {
  it('vendored 的 schemaVersion 1 样本整包失败，文案是版本类提示而非静默产出错乱条目', () => {
    const message = (() => {
      try {
        parseTwoFas(fileBytes('2fas_authenticator.json'))
      } catch (error) {
        return (error as Error).message
      }
      throw new Error('预期抛错，实际没有')
    })()
    expect(message).toContain('schemaVersion=1')
    expect(message).toContain('过旧')
    // v1 的 otp 只有 account / issuer / label，结构上凑不出可计算验证码的条目。
    expect(message).toContain('tokenType')
  })

  it('schemaVersion 高于当前值时提示升级 App', () => {
    expect(() => parseTwoFas(wrap([service()], [], 5))).toThrow(/schemaVersion=5/)
    expect(() => parseTwoFas(wrap([service()], [], 5))).toThrow(/请升级 App/)
  })

  it('schemaVersion 缺失或非整数时判为损坏', () => {
    const absent = JSON.parse(wrap([service()])) as Record<string, unknown>
    delete absent.schemaVersion
    expect(() => parseTwoFas(JSON.stringify(absent))).toThrow(/缺少 schemaVersion/)
    expect(() => parseTwoFas(wrap([service()], [], 4.5))).toThrow(/必须是整数/)
    expect(() =>
      parseTwoFas(JSON.stringify({ ...JSON.parse(wrap([])), schemaVersion: '4' })),
    ).toThrow(/必须是整数/)
  })
})

describe('parseTwoFas：整包结构性缺失抛 TransferFormatError（C5）', () => {
  const cases: [string, string][] = [
    ['不是 JSON', 'this is not json'],
    ['顶层是数组', '[1,2,3]'],
    ['顶层是字符串', '"2fas"'],
    ['services 不是数组', fileText('twofas_malformed.json')],
    ['services 缺失', JSON.stringify({ schemaVersion: 4, groups: [] })],
  ]

  for (const [name, text] of cases) {
    it(`${name} 抛 TransferFormatError`, () => {
      expect(() => parseTwoFas(text)).toThrow(TransferFormatError)
    })
  }

  it('servicesEncrypted 非空（加密备份）时文案指向加密路径，而不是「成功导入 0 条」', () => {
    const encrypted = JSON.stringify({
      schemaVersion: 4,
      services: [],
      servicesEncrypted: 'Y2lwaGVyOnNhbHQ6aXY=',
      groups: [],
    })
    expect(() => parseTwoFas(encrypted)).toThrow(TransferFormatError)
    try {
      parseTwoFas(encrypted)
    } catch (error) {
      expect((error as Error).message).toContain('加密')
      expect((error as Error).message).toContain('主密码')
      // C4：只回显字段名，不回显密文。
      expect((error as Error).message).not.toContain('Y2lwaGVy')
    }
  })

  it('reference 非空（上游 isEncrypted 的判据）同样指向加密路径', () => {
    expect(() =>
      parseTwoFas(JSON.stringify({ schemaVersion: 4, services: [], reference: 'not-blank' })),
    ).toThrow(/加密/)
  })

  it('单条不是对象只记 failure', () => {
    const result = parseTwoFas(wrap([service(), 42, null]))
    expect(result.entries).toHaveLength(1)
    expect(result.failures.map((f) => f.sourceIndex)).toEqual([1, 2])
  })

  it('超过字节上限抛 TransferFormatError', () => {
    const huge = new Uint8Array(TRANSFER_LIMITS.maxInputBytes + 1)
    expect(() => parseTwoFas(huge)).toThrow(/超过上限/)
  })

  it('超过条目上限抛 TransferFormatError', () => {
    const services = Array.from({ length: TRANSFER_LIMITS.maxEntries + 1 }, () => null)
    expect(() => parseTwoFas(wrap(services))).toThrow(/超过上限/)
  })

  it('非 UTF-8 字节与空输入都按损坏处理', () => {
    expect(() => parseTwoFas(Uint8Array.from([0xff, 0xfe, 0x7b, 0x7d]))).toThrow(
      TransferFormatError,
    )
    expect(() => parseTwoFas(utf8Encode(''))).toThrow(TransferFormatError)
  })
})

describe('parseTwoFas：边界夹具', () => {
  it('twofas_edge.json：3 条成功、5 条失败、1 条悬空分组 warning', () => {
    const result = parseTwoFas(fileBytes('twofas_edge.json'))
    expect(result.entries.map((e) => e.sourceIndex)).toEqual([0, 5, 6])
    expect(result.entries[1]).toMatchObject({
      issuer: '航空 Air Canada',
      account: '张三@example.com',
      kind: 'totp',
      algo: 'SHA256',
      digits: 7,
      period: 30,
    })

    expect(result.failures.map((f) => f.sourceIndex)).toEqual([1, 2, 3, 4, 7])
    expect(result.failures[0]!.reason).toContain('不受支持')
    expect(result.failures[1]!.reason).toContain('algorithm')
    expect(result.failures[2]!.reason).toContain('period')
    expect(result.failures[3]!.reason).toContain('otp')
    expect(result.failures[4]!.reason).toContain('counter')

    // order.position 与数组下标一致，故不该有排序 warning。
    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]!.sourceIndex).toBe(5)
  })

  it('order.position 与数组顺序不一致时补一条整包 warning，但仍按数组顺序导入', () => {
    // 上游导出恒写 `position = index`（`ServiceMapper.kt:108`），故真实文件不会触发；
    // 手工改过顺序的文件不该让自定义排序被静默丢弃。
    const result = parseTwoFas(
      wrap([service({ order: { position: 9 } }), service({ order: { position: 0 } })]),
    )
    expect(result.entries.map((e) => e.sourceIndex)).toEqual([0, 1])
    const warning = result.warnings.find((w) => w.field === 'services[].order.position')
    expect(warning).toMatchObject({ sourceIndex: null })
    expect(warning!.message).toContain('自定义排序未保留')
  })

  it('order 缺失或非整数 position 不记 warning（无从比较）', () => {
    const noOrder = service()
    delete noOrder.order
    expect(parseTwoFas(wrap([noOrder])).warnings).toEqual([])
    expect(parseTwoFas(wrap([service({ order: { position: 'x' } })])).warnings).toEqual([])
  })

  it('空 services 数组不抛错', () => {
    expect(parseTwoFas(wrap([]))).toMatchObject({
      format: '2fas',
      entries: [],
      tags: [],
      failures: [],
      warnings: [],
      skipped: 0,
    })
  })

  it('失败条目的局部 warning 不会残留', () => {
    // MD5 会先产出「已归一化」warning，随后因缺 period 失败；warning 必须一起丢弃。
    const result = parseTwoFas(
      wrap([withOtp({ algorithm: 'MD5', period: undefined, groupId: 'g-missing' })]),
    )
    expect(result.entries).toEqual([])
    expect(result.failures).toHaveLength(1)
    expect(result.warnings).toEqual([])
  })
})

describe('C4：错误文案不泄露 secret', () => {
  const SECRET_FORMS = [
    '4SJHB4GSD43FZBAI7C2HLRJGPQ',
    '4sjhb4gsd43fzbai7c2hlrjgpq',
    'e49270f0d21f365c8408f8b475c5267c',
    '5JJw8NIfNlyECPi0dcUmfA==',
    // `otp.link` 里也带着 secret，而 `services[1]`（STEAM）确实会失败——它的文案最有机会
    // 顺手回显 link。这两条把「失败条目不泄露 link」钉住，不是空跑。
    'JRZCL47CMXVOQMNPZR2F7J4RGI',
    'otpauth://steam/Boeing',
  ]

  it('两份夹具的全部 failure / warning 文案都不含 secret 的任何编码形式', () => {
    const edge = parseTwoFas(fileBytes('twofas_edge.json'))
    const plain = parseTwoFas(fileBytes('2fas_authenticator_plain_v4.2fas'))
    const all = [
      ...edge.failures.map((f) => f.reason),
      ...edge.warnings.map((w) => w.message),
      ...plain.failures.map((f) => f.reason),
      ...plain.warnings.map((w) => w.message),
    ]
    expect(all.length).toBeGreaterThan(0)
    for (const message of all) {
      for (const form of SECRET_FORMS) {
        expect(message).not.toContain(form)
      }
    }
  })

  it('secret 非法时的文案只说「不合法」，不回显内容', () => {
    const result = parseTwoFas(wrap([service({ secret: '!!!not-base32!!!' })]))
    expect(result.failures[0]!.reason).toContain('base32')
    for (const form of ['!!!not-base32!!!', 'not-base32']) {
      expect(result.failures[0]!.reason).not.toContain(form)
    }
  })

  it('整包失败抛出的异常也不含 secret', () => {
    const text = fileText('twofas_malformed.json')
    try {
      parseTwoFas(text)
      expect.unreachable('应当抛错')
    } catch (error) {
      for (const form of ['4SJHB4GSD43FZBAI7C2HLRJGPQ', 'e49270f0d21f365c8408f8b475c5267c']) {
        expect((error as Error).message).not.toContain(form)
      }
    }
  })
})

describe('parseTwoFas：纯函数', () => {
  it('同一输入连续两次结果相同，且不修改入参', () => {
    const bytes = fileBytes('twofas_edge.json')
    const snapshot = Uint8Array.from(bytes)
    const first = parseTwoFas(bytes)
    const second = parseTwoFas(bytes)
    expect(golden(first.entries)).toEqual(golden(second.entries))
    expect(first.tags).toEqual(second.tags)
    expect(first.failures).toEqual(second.failures)
    expect(first.warnings).toEqual(second.warnings)
    expect(bytes).toEqual(snapshot)
  })

  it('返回值不与入参共享结构', () => {
    const text = fileText('twofas_edge.json')
    const first = parseTwoFas(text)
    ;(first.entries[0]!.tagNames as string[]).push('污染')
    expect(parseTwoFas(text).entries[0]!.tagNames).toEqual(['工作'])
  })
})
