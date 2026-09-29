import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { utf8Encode } from '@askdaddy/crypto'
import { parseAegis } from '../aegis.js'
import { TransferFormatError } from '../errors.js'
import { parseFreeOtpPlus } from '../freeotp-plus.js'
import { TRANSFER_LIMITS } from '../input.js'
import type { ParsedEntry } from '../types.js'

const url = (name: string): URL => new URL(`../__fixtures__/${name}`, import.meta.url)
const fileBytes = (name: string): Uint8Array => new Uint8Array(readFileSync(url(name)))
const fileText = (name: string): string => readFileSync(url(name), 'utf8')

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

/** secret 的 hex 由 node 独立算出后硬编码，不是用被测代码再推一次。 */
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

/** `4SJHB4GSD43FZBAI7C2HLRJGPQ` 的有符号 int 数组形态，与 Aegis / 2FAS 夹具里是同一把密钥。 */
const DEFAULT_SECRET: number[] = [
  -28, -110, 112, -16, -46, 31, 54, 92, -124, 8, -8, -76, 117, -59, 38, 124,
]
const DEFAULT_SECRET_HEX = 'e49270f0d21f365c8408f8b475c5267c'

/**
 * 上游 `Token` 的 `digits` / `counter` / `period` 是 Java 基本类型，Gson 无条件写出，
 * 故默认值刻意让 TOTP 也带 `counter`——这是本格式最大的陷阱。
 */
const token = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  algo: 'SHA1',
  counter: 0,
  digits: 6,
  issuerExt: 'Deno',
  issuerInt: 'Deno',
  label: 'Mason',
  period: 30,
  secret: [...DEFAULT_SECRET],
  type: 'TOTP',
  ...overrides,
})

/** `tokenOrder` 省略时不写该键（区别于显式 `null`），用于覆盖探测器判不出、解析器仍要能吃的情形。 */
const wrap = (tokens: readonly unknown[], tokenOrder?: unknown): string =>
  JSON.stringify(tokenOrder === undefined ? { tokens } : { tokens, tokenOrder })

describe('parseFreeOtpPlus：golden 快照', () => {
  it('vendored 样本解出 6 条，顺序即 tokenOrder', () => {
    const result = parseFreeOtpPlus(fileBytes('freeotp_plus.json'))
    expect(result.format).toBe('freeotp-plus')
    expect(result.tags).toEqual([])
    expect(result.skipped).toBe(0)
    expect(result.failures).toEqual([])
    expect(result.warnings).toEqual([])
    expect(golden(result.entries)).toEqual([
      {
        sourceIndex: 0,
        issuer: 'WWE',
        account: 'Mason',
        kind: 'hotp',
        algo: 'SHA512',
        digits: 8,
        secret: 'ed40c5eefbecce2206b15d75c1182a76',
        note: '',
        tagNames: [],
        favorite: false,
        counter: 10299,
      },
      {
        sourceIndex: 1,
        issuer: 'Air Canada',
        account: 'Benjamin',
        kind: 'hotp',
        algo: 'SHA256',
        digits: 7,
        secret: '552a94b99feed079b472cd44d52fe642',
        note: '',
        tagNames: [],
        favorite: false,
        counter: 49,
      },
      {
        sourceIndex: 2,
        issuer: 'Issuu',
        account: 'James',
        kind: 'hotp',
        algo: 'SHA1',
        digits: 6,
        secret: 'c39cc45ed2e99be8cc2fa14b654edd67',
        note: '',
        tagNames: [],
        favorite: false,
        counter: 0,
      },
      {
        sourceIndex: 3,
        issuer: 'Airbnb',
        account: 'Elijah',
        kind: 'totp',
        algo: 'SHA512',
        digits: 8,
        secret: 'f91664c8d768853aedde5a936c16ba88',
        note: '',
        tagNames: [],
        favorite: false,
        period: 50,
      },
      {
        sourceIndex: 4,
        issuer: 'SPDX',
        account: 'James',
        kind: 'totp',
        algo: 'SHA256',
        digits: 7,
        secret: 'eb99cb39c67ae042fa866ec4f239cbb5',
        note: '',
        tagNames: [],
        favorite: false,
        period: 20,
      },
      {
        sourceIndex: 5,
        issuer: 'Deno',
        account: 'Mason',
        kind: 'totp',
        algo: 'SHA1',
        digits: 6,
        secret: DEFAULT_SECRET_HEX,
        note: '',
        tagNames: [],
        favorite: false,
        period: 30,
      },
    ])
  })

  it('C10：同一把密钥与 Aegis 的 base32 解出**字节相同**', () => {
    const aegis = parseAegis(fileBytes('aegis_plain.json'))
    const freeotp = parseFreeOtpPlus(fileBytes('freeotp_plus.json'))
    const byAegis = new Map(
      aegis.entries.map((entry) => [`${entry.issuer}:${entry.account}`, entry]),
    )

    expect(freeotp.entries).toHaveLength(6)
    for (const entry of freeotp.entries) {
      const other = byAegis.get(`${entry.issuer}:${entry.account}`)
      expect(other, `${entry.issuer}:${entry.account} 在 Aegis 夹具中不存在`).toBeDefined()
      expect(hex(entry.secret)).toBe(hex(other!.secret))
    }
  })

  it('counter **不做 ±1 调整**：与 Aegis 系统性差 1 是上游 URI 约定造成的，不是存储语义', () => {
    const aegis = parseAegis(fileBytes('aegis_plain.json'))
    const freeotp = parseFreeOtpPlus(fileBytes('freeotp_plus.json'))
    const counterOf = (entries: readonly ParsedEntry[], issuer: string): number => {
      const entry = entries.find((candidate) => candidate.issuer === issuer)
      return entry?.kind === 'hotp' ? entry.counter : -1
    }

    for (const issuer of ['WWE', 'Air Canada', 'Issuu']) {
      expect(counterOf(freeotp.entries, issuer)).toBe(counterOf(aegis.entries, issuer) - 1)
    }
  })

  it('边界夹具：缺 tokenOrder、issuerAlt / labelAlt 生效、无 issuer 字段、-128 下界', () => {
    const result = parseFreeOtpPlus(fileBytes('freeotp_plus_edge.json'))
    expect(golden(result.entries)).toEqual([
      {
        sourceIndex: 0,
        issuer: 'Deno Alt',
        account: 'Mason Alt',
        kind: 'totp',
        algo: 'SHA1',
        digits: 6,
        secret: 'e49270f0d21f365c8408f8b475c52680',
        note: '',
        tagNames: ['工作'],
        favorite: false,
        period: 30,
      },
      {
        sourceIndex: 1,
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
      {
        sourceIndex: 2,
        issuer: '',
        account: 'Benjamin',
        kind: 'hotp',
        algo: 'SHA256',
        digits: 7,
        secret: '552a94b99feed079b472cd44d52fe642',
        note: '',
        tagNames: ['个人'],
        favorite: false,
        counter: 50,
      },
    ])
    expect(result.failures).toEqual([])
    expect(result.warnings).toEqual([
      {
        sourceIndex: null,
        field: 'tokenOrder',
        message: '缺少 tokenOrder，已按 tokens 数组顺序导入（可能与 FreeOTP+ 中看到的顺序不同）',
      },
    ])
  })
})

describe('parseFreeOtpPlus：kind 只由 type 决定', () => {
  it("type 为 'TOTP'（大写）即使带 counter 也判为 totp，counter 不进条目", () => {
    const result = parseFreeOtpPlus(wrap([token({ counter: 999 })], ['Deno:Mason']))
    const [entry] = result.entries
    expect(entry).toMatchObject({ kind: 'totp', period: 30 })
    expect(entry && 'counter' in entry).toBe(false)
    expect(result.failures).toEqual([])
  })

  it("type 为 'HOTP' 即使带 period 也判为 hotp，period 不进条目", () => {
    const result = parseFreeOtpPlus(
      wrap([token({ type: 'HOTP', period: 99, counter: 7 })], ['Deno:Mason']),
    )
    const [entry] = result.entries
    expect(entry).toMatchObject({ kind: 'hotp', counter: 7 })
    expect(entry && 'period' in entry).toBe(false)
  })

  it('type 缺失时判为单条失败，即使只剩 counter 也不猜成 hotp', () => {
    const onlyCounter = token()
    delete onlyCounter.type
    delete onlyCounter.period
    const result = parseFreeOtpPlus(wrap([onlyCounter]))
    expect(result.entries).toEqual([])
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]).toMatchObject({ sourceIndex: 0, path: 'tokens[0]' })
    expect(result.failures[0]?.reason).toContain('令牌类型必须是字符串')
  })

  it('type 为其他值时判为单条失败，即使 period 齐全也不猜成 totp', () => {
    const result = parseFreeOtpPlus(wrap([token({ type: 'MOTP' })]))
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toContain('不受支持')
  })

  it("type 为 'STEAM' 时报「不受支持」而非「文件损坏」", () => {
    const result = parseFreeOtpPlus(wrap([token({ type: 'STEAM' })]))
    expect(result.failures[0]?.reason).toContain('该令牌类型不受支持')
    expect(result.failures[0]?.reason).toContain('steam')
  })

  it('小写 totp / hotp 同样可识别（上游写大写，容忍来自手工编辑的文件）', () => {
    const result = parseFreeOtpPlus(wrap([token({ type: 'totp' }), token({ type: ' hotp ' })]))
    expect(result.entries.map((entry) => entry.kind)).toEqual(['totp', 'hotp'])
  })

  it('C8：totp 缺 period 判为单条失败，不补 30', () => {
    const noPeriod = token()
    delete noPeriod.period
    const result = parseFreeOtpPlus(wrap([noPeriod]))
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toContain('period 必须是整数')
  })

  it('C8：hotp 缺 counter 判为单条失败，不补 0', () => {
    const noCounter = token({ type: 'HOTP' })
    delete noCounter.counter
    const result = parseFreeOtpPlus(wrap([noCounter]))
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toContain('counter 必须是整数')
  })
})

describe('parseFreeOtpPlus：secret 是有符号 int 数组', () => {
  it('越界值判为单条失败，且**不发生** `& 0xFF` 截断', () => {
    const result = parseFreeOtpPlus(wrap([token({ secret: [-1, 128] })]))
    expect(result.entries).toEqual([])
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]?.reason).toContain('第 1 项')
    // 截断会得到 [255, 0]；这里必须一条都解不出来。
    expect(result.failures[0]?.reason).not.toContain('255')
  })

  it('-129 同样失败，失败消息只写下标不写字节值', () => {
    const result = parseFreeOtpPlus(wrap([token({ secret: [-129, 1] })]))
    expect(result.failures[0]?.reason).toContain('第 0 项')
    expect(result.failures[0]?.reason).not.toContain('-129')
  })

  it('-128 与 127 两个边界值都合法', () => {
    const result = parseFreeOtpPlus(wrap([token({ secret: [-128, 127] })]))
    expect(result.failures).toEqual([])
    expect(hex(result.entries[0]!.secret)).toBe('807f')
  })

  it('负值按 v + 256 转换', () => {
    const result = parseFreeOtpPlus(wrap([token({ secret: [-1, -2, -128] })]))
    expect(hex(result.entries[0]!.secret)).toBe('fffe80')
  })

  it('secret 是字符串（base32）时判为单条失败，不走 base32 路径', () => {
    const result = parseFreeOtpPlus(wrap([token({ secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ' })]))
    expect(result.failures[0]?.reason).toContain('secret 必须是数组')
  })

  it('secret 是空数组 / 缺失 / 含小数时判为单条失败', () => {
    const missing = token()
    delete missing.secret
    const result = parseFreeOtpPlus(
      wrap([token({ secret: [] }), missing, token({ secret: [1.5] }), token({ secret: [1e30] })]),
    )
    expect(result.entries).toEqual([])
    expect(result.failures.map((failure) => failure.reason)).toEqual([
      'secret 数组为空',
      'secret 必须是数组，实际收到的类型是 undefined',
      'secret 数组的第 0 项不是 [-128,127] 范围内的整数',
      'secret 数组的第 0 项不是 [-128,127] 范围内的整数',
    ])
  })
})

describe('parseFreeOtpPlus：tokenOrder 决定输出顺序', () => {
  const three = (): Record<string, unknown>[] => [
    token({ issuerExt: 'A', issuerInt: 'A', label: 'x' }),
    token({ issuerExt: 'B', issuerInt: 'B', label: 'y' }),
    token({ issuerExt: 'C', issuerInt: 'C', label: 'z' }),
  ]

  it('按 tokenOrder 重排输出，但 sourceIndex 仍是 tokens 数组下标', () => {
    const result = parseFreeOtpPlus(wrap(three(), ['C:z', 'A:x', 'B:y']))
    expect(result.entries.map((entry) => entry.issuer)).toEqual(['C', 'A', 'B'])
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([2, 0, 1])
    expect(result.warnings).toEqual([])
  })

  it('重排后 failures 的 path 仍指向文件里真实的那个元素', () => {
    const tokens = three()
    tokens[1] = token({ issuerExt: 'B', issuerInt: 'B', label: 'y', secret: [128] })
    const result = parseFreeOtpPlus(wrap(tokens, ['C:z', 'B:y', 'A:x']))
    expect(result.entries.map((entry) => entry.issuer)).toEqual(['C', 'A'])
    expect(result.failures).toEqual([
      expect.objectContaining({ sourceIndex: 1, path: 'tokens[1]' }),
    ])
  })

  it('tokenOrder 缺失时退回数组顺序并记 warning', () => {
    const result = parseFreeOtpPlus(wrap(three()))
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([0, 1, 2])
    expect(result.warnings).toEqual([
      expect.objectContaining({ sourceIndex: null, field: 'tokenOrder' }),
    ])
  })

  it('tokenOrder 显式为 null 时同样退回数组顺序并记 warning', () => {
    const result = parseFreeOtpPlus(wrap(three(), null))
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([0, 1, 2])
    expect(result.warnings[0]?.message).toContain('缺少 tokenOrder')
  })

  it('tokenOrder 不是数组时退回数组顺序并记 warning，不整包失败', () => {
    const result = parseFreeOtpPlus(wrap(three(), 'C:z'))
    expect(result.entries).toHaveLength(3)
    expect(result.warnings[0]?.message).toContain('tokenOrder 不是数组')
  })

  it('悬空的排序项记 warning 并忽略', () => {
    const result = parseFreeOtpPlus(wrap(three(), ['Nope:x', 'A:x']))
    expect(result.entries.map((entry) => entry.issuer)).toEqual(['A', 'B', 'C'])
    expect(result.warnings).toHaveLength(2)
    expect(result.warnings[0]).toMatchObject({ field: 'tokenOrder[0]' })
    expect(result.warnings[0]?.message).toContain('找不到对应条目')
    expect(result.warnings[1]?.message).toContain('有 2 个条目未被 tokenOrder 引用')
  })

  it('非字符串的排序项记 warning 并忽略', () => {
    const result = parseFreeOtpPlus(wrap(three(), [42, 'B:y']))
    expect(result.entries.map((entry) => entry.issuer)).toEqual(['B', 'A', 'C'])
    expect(result.warnings[0]).toMatchObject({ field: 'tokenOrder[0]' })
    expect(result.warnings[0]?.message).toContain('排序项不是字符串')
  })

  it('上游会丢弃未被 tokenOrder 引用的 token，本 App 追加到末尾并记 warning', () => {
    const result = parseFreeOtpPlus(wrap(three(), ['B:y']))
    expect(result.entries.map((entry) => entry.issuer)).toEqual(['B', 'A', 'C'])
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([1, 0, 2])
    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]?.message).toContain('有 2 个条目未被 tokenOrder 引用')
  })

  it('id 重复时两个 token 都保留（上游 associateBy 只留最后一个）', () => {
    const tokens = [
      token({ issuerExt: 'A', issuerInt: 'A', label: 'x', digits: 6 }),
      token({ issuerExt: 'A', issuerInt: 'A', label: 'x', digits: 7 }),
    ]
    const result = parseFreeOtpPlus(wrap(tokens, ['A:x', 'A:x']))
    expect(result.entries.map((entry) => entry.digits)).toEqual([6, 7])
    expect(result.warnings).toEqual([])
  })

  it('tokenOrder 只列一次时，重复 id 的第二个成为孤儿并追加到末尾', () => {
    const tokens = [
      token({ issuerExt: 'A', issuerInt: 'A', label: 'x', digits: 6 }),
      token({ issuerExt: 'A', issuerInt: 'A', label: 'x', digits: 7 }),
    ]
    const result = parseFreeOtpPlus(wrap(tokens, ['A:x']))
    expect(result.entries.map((entry) => entry.digits)).toEqual([6, 7])
    expect(result.warnings).toHaveLength(1)
  })

  it('匹配用的是 getID()：issuerInt 优先于 issuerExt', () => {
    const result = parseFreeOtpPlus(
      wrap([token({ issuerInt: 'Inner', issuerExt: 'Outer' })], ['Inner:Mason']),
    )
    expect(result.entries).toHaveLength(1)
    expect(result.warnings).toEqual([])
  })

  it('issuerInt 为空串时 getID() 退到 issuerExt', () => {
    const result = parseFreeOtpPlus(wrap([token({ issuerInt: '' })], ['Deno:Mason']))
    expect(result.entries).toHaveLength(1)
    expect(result.warnings).toEqual([])
  })

  it('两个 issuer 都缺失时 getID() 就是裸 label', () => {
    const bare = token()
    delete bare.issuerInt
    delete bare.issuerExt
    const result = parseFreeOtpPlus(wrap([bare], ['Mason']))
    expect(result.entries).toHaveLength(1)
    expect(result.entries[0]?.issuer).toBe('')
    expect(result.warnings).toEqual([])
  })

  it('结构损坏、算不出 id 的条目也会作为孤儿进入 failures，不会凭空消失', () => {
    const result = parseFreeOtpPlus(wrap([null, token()], ['Deno:Mason']))
    expect(result.entries).toHaveLength(1)
    expect(result.entries[0]?.sourceIndex).toBe(1)
    expect(result.failures).toEqual([
      expect.objectContaining({ sourceIndex: 0, path: 'tokens[0]', reason: '条目不是 JSON 对象' }),
    ])
    expect(result.warnings[0]?.message).toContain('有 1 个条目未被 tokenOrder 引用')
  })
})

describe('parseFreeOtpPlus：issuer / label 的三级优先级', () => {
  it('getIssuer() 是 issuerAlt → issuerExt → issuerInt，与 getID() 的优先级不同', () => {
    const result = parseFreeOtpPlus(
      wrap([token({ issuerInt: 'Inner', issuerExt: 'Outer', issuerAlt: 'Alt' })], ['Inner:Mason']),
    )
    expect(result.entries[0]?.issuer).toBe('Alt')
  })

  it('issuerAlt 为空串时退到 issuerExt（getIssuer 同时判 null 与空串）', () => {
    const result = parseFreeOtpPlus(wrap([token({ issuerAlt: '' })]))
    expect(result.entries[0]?.issuer).toBe('Deno')
  })

  it('issuerAlt / issuerExt 都空时退到 issuerInt', () => {
    const result = parseFreeOtpPlus(
      wrap([token({ issuerAlt: null, issuerExt: '', issuerInt: 'Inner' })]),
    )
    expect(result.entries[0]?.issuer).toBe('Inner')
  })

  it('getLabel() 只判 null：labelAlt 为空串时账户名就是空串，不被 label 顶掉', () => {
    const result = parseFreeOtpPlus(wrap([token({ labelAlt: '' })]))
    expect(result.entries[0]?.account).toBe('')
  })

  it('labelAlt 非空时优先于 label', () => {
    const result = parseFreeOtpPlus(wrap([token({ label: 'Raw', labelAlt: 'Shown' })]))
    expect(result.entries[0]?.account).toBe('Shown')
  })

  it('label 缺失时账户名为空串（getLabel 的兜底）', () => {
    const noLabel = token()
    delete noLabel.label
    const result = parseFreeOtpPlus(wrap([noLabel], ['Deno:']))
    expect(result.entries[0]?.account).toBe('')
  })

  it('issuer 字段是非字符串时判为单条失败', () => {
    const result = parseFreeOtpPlus(wrap([token({ issuerExt: 7 })]))
    expect(result.failures[0]?.reason).toContain('tokens[0].issuerExt 必须是字符串')
  })

  it('issuer / account 超长时判为单条失败', () => {
    const long = 'a'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    const result = parseFreeOtpPlus(wrap([token({ labelAlt: long })]))
    expect(result.failures[0]?.reason).toContain('tokens[0].labelAlt 长度为')
  })
})

describe('parseFreeOtpPlus：category → tagNames', () => {
  it('category 字符串还原为单元素数组', () => {
    const result = parseFreeOtpPlus(wrap([token({ category: '工作' })]))
    expect(result.entries[0]?.tagNames).toEqual(['工作'])
  })

  it('category 缺失 / null / 空串都得到空数组', () => {
    const missing = token()
    delete missing.category
    const result = parseFreeOtpPlus(
      wrap([missing, token({ category: null }), token({ category: '' })]),
    )
    expect(result.entries.map((entry) => entry.tagNames)).toEqual([[], [], []])
    expect(result.failures).toEqual([])
  })

  it('category 是非字符串时判为单条失败', () => {
    const result = parseFreeOtpPlus(wrap([token({ category: 42 })]))
    expect(result.failures[0]?.reason).toContain('tokens[0].category 必须是字符串')
  })

  it('FreeOTP+ 没有独立的分组表，故 tags 恒为空数组', () => {
    const result = parseFreeOtpPlus(
      wrap([token({ category: '工作' }), token({ category: '个人' })]),
    )
    expect(result.tags).toEqual([])
    expect(result.entries.map((entry) => entry.tagNames)).toEqual([['工作'], ['个人']])
  })
})

describe('parseFreeOtpPlus：算法归一化', () => {
  it('SHA1 / SHA256 / SHA512 原样保留，小写与 Hmac 前缀也接受', () => {
    const order = ['Deno:Mason', 'Deno:Mason', 'Deno:Mason']
    const result = parseFreeOtpPlus(
      wrap(
        [token({ algo: 'SHA1' }), token({ algo: 'sha256' }), token({ algo: 'HmacSHA512' })],
        order,
      ),
    )
    expect(result.entries.map((entry) => entry.algo)).toEqual(['SHA1', 'SHA256', 'SHA512'])
    expect(result.warnings).toEqual([])
  })

  it('MD5 降级为 SHA1 并记 warning（HmacMD5 在 JCE 合法，故这条路径在 FreeOTP+ 上可达）', () => {
    const result = parseFreeOtpPlus(wrap([token({ algo: 'MD5' })], ['Deno:Mason']))
    expect(result.entries[0]?.algo).toBe('SHA1')
    expect(result.warnings).toEqual([
      { sourceIndex: 0, field: 'tokens[0].algo', message: '原文是 MD5，已归一化为 SHA1' },
    ])
  })

  it('SHA224 / SHA384 判为单条失败，不回落 SHA1', () => {
    const result = parseFreeOtpPlus(wrap([token({ algo: 'SHA224' }), token({ algo: 'SHA384' })]))
    expect(result.entries).toEqual([])
    expect(result.failures.map((failure) => failure.reason)).toEqual([
      '无法识别的 algorithm，仅支持 SHA1 / SHA256 / SHA512',
      '无法识别的 algorithm，仅支持 SHA1 / SHA256 / SHA512',
    ])
  })

  it('上游的 `algorithm ?: "sha1"` 兜底是 bug，本 App 不复制：algo 缺失即失败', () => {
    const noAlgo = token()
    delete noAlgo.algo
    const result = parseFreeOtpPlus(wrap([noAlgo]))
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toContain('algorithm 必须是字符串')
  })

  it('digits 越界判为单条失败（上游 Steam 令牌的 digits=5 就落在这里）', () => {
    const result = parseFreeOtpPlus(wrap([token({ digits: 5 }), token({ digits: 9 })]))
    expect(result.entries).toEqual([])
    expect(result.failures).toHaveLength(2)
    expect(result.failures[0]?.reason).toContain('digits')
  })
})

describe('parseFreeOtpPlus：整包结构性缺失', () => {
  const cases: readonly (readonly [string, string, string])[] = [
    ['顶层不是对象', '[]', '顶层不是 JSON 对象'],
    ['tokens 缺失', '{}', 'tokens 不是数组'],
    ['tokens 不是数组', '{"tokens":{}}', 'tokens 不是数组'],
    ['不是 JSON', 'not json', '不是合法的 JSON'],
  ]
  for (const [title, input, message] of cases) {
    it(`${title}时抛 TransferFormatError`, () => {
      expect(() => parseFreeOtpPlus(input)).toThrow(TransferFormatError)
      expect(() => parseFreeOtpPlus(input)).toThrow(message)
    })
  }

  it('tokens 为空数组时返回空结果而不抛', () => {
    const result = parseFreeOtpPlus(wrap([], []))
    expect(result).toMatchObject({
      format: 'freeotp-plus',
      entries: [],
      tags: [],
      failures: [],
      skipped: 0,
    })
    expect(result.warnings).toEqual([])
  })

  it('条目数超上限时抛 TransferFormatError', () => {
    const many = Array.from({ length: TRANSFER_LIMITS.maxEntries + 1 }, () => token())
    expect(() => parseFreeOtpPlus(wrap(many))).toThrow(/超过上限/)
  })

  it('输入字节超上限时抛 TransferFormatError', () => {
    const huge = `{"tokens":[],"pad":"${'a'.repeat(TRANSFER_LIMITS.maxInputBytes)}"}`
    expect(() => parseFreeOtpPlus(utf8Encode(huge))).toThrow(/超过上限/)
  })

  it('接受字符串输入，与字节输入结果一致', () => {
    const text = fileText('freeotp_plus.json')
    expect(golden(parseFreeOtpPlus(text).entries)).toEqual(
      golden(parseFreeOtpPlus(utf8Encode(text)).entries),
    )
  })

  it('畸形夹具：两条都失败，sourceIndex 与 path 一一对应', () => {
    const result = parseFreeOtpPlus(fileBytes('freeotp_plus_malformed.json'))
    expect(result.entries).toEqual([])
    expect(result.failures.map((failure) => [failure.sourceIndex, failure.path])).toEqual([
      [0, 'tokens[0]'],
      [1, 'tokens[1]'],
    ])
    // 夹具的 tokenOrder 只列了第一条，第二条是孤儿：上游会静默丢弃它，本 App 必须报出来。
    expect(result.warnings).toEqual([
      {
        sourceIndex: null,
        field: 'tokenOrder',
        message: '有 1 个条目未被 tokenOrder 引用，已追加到末尾（FreeOTP+ 自身会丢弃它们）',
      },
    ])
  })
})

describe('parseFreeOtpPlus：C4 与纯函数', () => {
  it('失败与警告消息里不含 secret 的原文、base32 或 hex 形式', () => {
    const result = parseFreeOtpPlus(fileBytes('freeotp_plus_malformed.json'))
    const leaked = [...result.failures, ...result.warnings].map((item) =>
      'reason' in item ? `${item.path} ${item.reason}` : `${item.field} ${item.message}`,
    )
    expect(result.failures).toHaveLength(2)
    for (const text of leaked) {
      expect(text).not.toContain('4SJHB4GSD43FZBAI7C2HLRJGPQ')
      expect(text).not.toContain(DEFAULT_SECRET_HEX)
    }
  })

  it('未映射的字段（image / imageAlt / issuerInt / label）既不进入条目也不产生 warning', () => {
    const result = parseFreeOtpPlus(
      wrap(
        [token({ image: 'file:///sdcard/a.png', imageAlt: null, label: 'Raw', labelAlt: 'Shown' })],
        ['Deno:Raw'],
      ),
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

  it('不修改入参字节，且两次调用结果一致', () => {
    const bytes = fileBytes('freeotp_plus.json')
    const copy = new Uint8Array(bytes)
    const first = parseFreeOtpPlus(bytes)
    const second = parseFreeOtpPlus(bytes)
    expect(bytes).toEqual(copy)
    expect(golden(second.entries)).toEqual(golden(first.entries))
    expect(second.warnings).toEqual(first.warnings)
  })
})
