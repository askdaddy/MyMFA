import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { utf8Encode } from '@askdaddy/crypto'
import { parseEnte } from '../ente.js'
import { TransferFormatError } from '../errors.js'
import { DEFAULT_TAG_SEPARATOR, parseGenericCsv, type GenericCsvMapping } from '../generic-csv.js'
import { TRANSFER_LIMITS } from '../input.js'
import type { ParsedEntry } from '../types.js'

const url = (name: string): URL => new URL(`../__fixtures__/${name}`, import.meta.url)
const fileBytes = (name: string): Uint8Array => new Uint8Array(readFileSync(url(name)))
const fileText = (name: string): string => readFileSync(url(name), 'utf8')

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

/** secret 的 hex 由 node 对 `@askdaddy/otp` 独立算出后硬编码，不是用被测代码再推一次。 */
const HEX_DENO = 'e49270f0d21f365c8408f8b475c5267c'
const HEX_WWE = 'ed40c5eefbecce2206b15d75c1182a76'
const HEX_AIR_CANADA = '552a94b99feed079b472cd44d52fe642'
const HEX_SPDX = 'eb99cb39c67ae042fa866ec4f239cbb5'

const SECRET_DENO = '4SJHB4GSD43FZBAI7C2HLRJGPQ'
const SECRET_WWE = '5VAML3X35THCEBVRLV24CGBKOY'
const SECRET_SPDX = '5OM4WOOGPLQEF6UGN3CPEOOLWU'

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

const keys = (warnings: readonly { sourceIndex: number | null; field: string }[]): string[] =>
  warnings.map((warning) => `${warning.sourceIndex}:${warning.field}`)

/** `generic_csv.csv` 的 10 个中文列名全部映射到位——这是「4 条全成功」golden 的前提。 */
const FULL: GenericCsvMapping = {
  secret: '密钥',
  issuer: '服务商',
  account: '账户',
  algo: '算法',
  digits: '位数',
  period: '周期',
  kind: '类型',
  counter: '计数器',
  tagNames: '标签',
  note: '备注',
}

/** R2 修订 6 冻结的 edge 夹具映射：不含 `备注`（5000 字符）与 `计数器`（该夹具没有这一列）。 */
const EDGE: GenericCsvMapping = {
  secret: '密钥',
  issuer: '服务商',
  account: '账户',
  algo: '算法',
  digits: '位数',
  period: '周期',
  kind: '类型',
}

/**
 * 构造样本一律用 `c_` 前缀的中性列名：任何被实现硬编码的列名都会在这里立刻暴露为
 * 「映射的列在表头中不存在」。
 */
const COLUMNS = [
  'c_name',
  'c_user',
  'c_secret',
  'c_algo',
  'c_digits',
  'c_period',
  'c_kind',
  'c_counter',
  'c_tags',
  'c_note',
] as const

type Column = (typeof COLUMNS)[number]

const MAPPING: GenericCsvMapping = {
  secret: 'c_secret',
  issuer: 'c_name',
  account: 'c_user',
  algo: 'c_algo',
  digits: 'c_digits',
  period: 'c_period',
  kind: 'c_kind',
  counter: 'c_counter',
  tagNames: 'c_tags',
  note: 'c_note',
}

const escapeCell = (value: string): string =>
  /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value

const cells = (overrides: Partial<Record<Column, string>> = {}): string[] =>
  COLUMNS.map((name) => overrides[name] ?? '')

/** 一行 TOTP 的最小合法形态：裸 base32 + 三个必填参数 + `kind`。 */
const totpRow = (overrides: Partial<Record<Column, string>> = {}): string[] =>
  cells({
    c_secret: SECRET_DENO,
    c_algo: 'SHA1',
    c_digits: '6',
    c_period: '30',
    c_kind: 'totp',
    ...overrides,
  })

/** 一行 `otpauth://` URI 形态：除 secret 外的其余单元格由 overrides 决定是否填。 */
const uriRow = (secretUri: string, overrides: Partial<Record<Column, string>> = {}): string[] =>
  cells({ c_secret: secretUri, ...overrides })

const table = (
  rows: readonly (readonly string[])[],
  header: readonly string[] = COLUMNS,
  trailingNewline = false,
): string => {
  const text = [header, ...rows].map((row) => row.map(escapeCell).join(',')).join('\n')
  return trailingNewline ? `${text}\n` : text
}

const uri = (
  issuer: string,
  account: string,
  secret: string,
  params = 'algorithm=SHA1&digits=6&period=30',
  kind = 'totp',
): string => `otpauth://${kind}/${issuer}:${account}?secret=${secret}&issuer=${issuer}&${params}`

/** 只映射 secret 一列——URI 形态最常见的用法。 */
const SECRET_ONLY: GenericCsvMapping = { secret: 'c_secret' }

describe('parseGenericCsv：三份 vendored 夹具的 golden', () => {
  it('generic_csv.csv 在完整映射下 4 条全成功（混合 kind + 分号多标签 + 引用单元格）', () => {
    const result = parseGenericCsv(fileBytes('generic_csv.csv'), FULL)
    expect(result.format).toBe('generic-csv')
    expect(result.tags).toEqual([])
    expect(result.failures).toEqual([])
    expect(result.warnings).toEqual([])
    expect(result.skipped).toBe(0)
    expect(golden(result.entries)).toEqual([
      {
        sourceIndex: 0,
        issuer: 'Deno',
        account: 'Mason',
        kind: 'totp',
        algo: 'SHA1',
        digits: 6,
        secret: HEX_DENO,
        note: '自定义列名的通用 CSV',
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
        secret: HEX_WWE,
        note: '',
        tagNames: ['工作', '个人'],
        favorite: false,
        counter: 10300,
      },
      {
        sourceIndex: 2,
        issuer: '航空 Air Canada',
        account: 'Benjamin',
        kind: 'hotp',
        algo: 'SHA256',
        digits: 7,
        secret: HEX_AIR_CANADA,
        note: '含 "引号" 与, 逗号',
        tagNames: [],
        favorite: false,
        counter: 50,
      },
      {
        sourceIndex: 3,
        issuer: 'SPDX',
        account: 'James',
        kind: 'totp',
        algo: 'SHA256',
        digits: 7,
        secret: HEX_SPDX,
        note: '备注含\n换行',
        tagNames: [],
        favorite: false,
        period: 20,
      },
    ])
  })

  it('同一份 generic_csv.csv 换一套映射（issuer/account 对调）得到不同结果', () => {
    const swapped: GenericCsvMapping = { ...FULL, issuer: '账户', account: '服务商' }
    const result = parseGenericCsv(fileText('generic_csv.csv'), swapped)
    expect(result.failures).toEqual([])
    expect(result.entries.map((entry) => [entry.issuer, entry.account])).toEqual([
      ['Mason', 'Deno'],
      ['Mason', 'WWE'],
      ['Benjamin', '航空 Air Canada'],
      ['James', 'SPDX'],
    ])
  })

  it('generic_csv.csv 少映射标签与备注两列时，条目数不变但两个字段一律为空', () => {
    const partial: GenericCsvMapping = {
      secret: '密钥',
      issuer: '服务商',
      account: '账户',
      algo: '算法',
      digits: '位数',
      period: '周期',
      kind: '类型',
      counter: '计数器',
    }
    const result = parseGenericCsv(fileBytes('generic_csv.csv'), partial)
    expect(result.failures).toEqual([])
    expect(result.entries).toHaveLength(4)
    expect(result.entries.every((entry) => entry.note === '')).toBe(true)
    expect(result.entries.every((entry) => entry.tagNames.length === 0)).toBe(true)
    // 未映射的列一律忽略且不记 warning（R2 修订 4）。
    expect(result.warnings).toEqual([])
  })

  it('generic_csv_edge.csv 在 R2 修订 6 冻结的映射下得 1 条成功 + 2 条失败', () => {
    const result = parseGenericCsv(fileBytes('generic_csv_edge.csv'), EDGE)
    expect(golden(result.entries)).toEqual([
      {
        sourceIndex: 0,
        issuer: 'Deno',
        account: 'Mason',
        kind: 'totp',
        algo: 'SHA1',
        digits: 6,
        secret: HEX_DENO,
        note: '',
        tagNames: [],
        favorite: false,
        period: 30,
      },
    ])
    // 第 2 行 digits=10 越界；第 3 行 period=0 非正整数。两条都点名对应字段。
    expect(result.failures.map((failure) => failure.sourceIndex)).toEqual([1, 2])
    expect(result.failures.map((failure) => failure.path)).toEqual([
      '通用 CSV 第 3 行',
      '通用 CSV 第 4 行',
    ])
    expect(result.failures[0]?.reason).toContain('digits')
    expect(result.failures[1]?.reason).toContain('period')
    expect(result.skipped).toBe(0)
    // `sha1`→`SHA1` 这一种归一化由本夹具钉住；另两种在构造样本里覆盖。
    expect(result.entries[0]?.algo).toBe('SHA1')
  })

  it('edge 夹具的 BOM / CRLF / 空列名 / 未知多余列四项都不构成错误', () => {
    const text = fileText('generic_csv_edge.csv')
    expect(text.charCodeAt(0)).toBe(0xfeff)
    expect(text).toContain('\r\n')
    const result = parseGenericCsv(text, EDGE)
    // 表头第 9 列 `未知多余列` 与第 10 列空列名都没被映射：既不该失败也不该告警，
    // 失败只应来自 digits / period 两道闸门。
    expect(result.failures.map((failure) => failure.reason)).toEqual([
      expect.stringContaining('digits'),
      expect.stringContaining('period'),
    ])
    expect(result.warnings).toEqual([])
  })

  it('edge 夹具一旦把 5000 字符的备注列映射进来，第 1 行也被长度闸门拦下', () => {
    const result = parseGenericCsv(fileBytes('generic_csv_edge.csv'), { ...EDGE, note: '备注' })
    expect(result.entries).toEqual([])
    expect(result.failures).toHaveLength(3)
    expect(result.failures[0]?.reason).toContain('备注 长度为')
    expect(result.failures[0]?.reason).toContain(`超过上限 ${TRANSFER_LIMITS.maxFieldLength}`)
  })

  it('generic_csv_malformed.csv：secret 单元格引号未闭合 → 整包抛 TransferFormatError', () => {
    const bytes = fileBytes('generic_csv_malformed.csv')
    expect(() => parseGenericCsv(bytes, { secret: '密钥' })).toThrow(TransferFormatError)
    expect(() => parseGenericCsv(bytes, { secret: '密钥' })).toThrow(/引号未闭合/)
  })

  it('C10：与 Ente 明文导出对撞，同身份的 secret 字节相等', () => {
    const ente = parseEnte(fileBytes('ente_auth.txt'))
    const generic = parseGenericCsv(fileBytes('generic_csv.csv'), FULL)
    const enteSecrets = new Map(
      ente.entries.map((entry) => [`${entry.issuer}:${entry.account}`, hex(entry.secret)]),
    )
    // `航空 Air Canada` 在 Ente 夹具里写作 `Air Canada`，身份不同故不参与对撞。
    const compared = generic.entries
      .map((entry) => [
        `${entry.issuer}:${entry.account}`,
        hex(entry.secret),
        enteSecrets.get(`${entry.issuer}:${entry.account}`),
      ])
      .filter((tuple): tuple is [string, string, string] => tuple[2] !== undefined)
    expect(compared.length).toBe(3)
    for (const [identity, actual, expected] of compared) {
      expect(actual, identity).toBe(expected)
    }
  })
})

describe('parseGenericCsv：映射由调用方给出，实现内无硬编码列名', () => {
  /** `generic_csv.csv` 的 10 个中文列名 + 具体产品的列名，一个都不许出现在实现里。 */
  const FORBIDDEN = [
    '服务商',
    '账户',
    '密钥',
    '算法',
    '位数',
    '周期',
    '类型',
    '计数器',
    '标签',
    '备注',
    '1password',
    'lastpass',
    'totp secret',
    'totpsecret',
    'issuervalue',
    'login_totp',
    'login_username',
    'notes',
    'folder',
    'collections',
    'favorite',
  ]

  /** 单引号、双引号与反引号三种字面量。转义过的字面量不在扫描范围内（实现里没有）。 */
  const literalsOf = (source: string): string[] =>
    [...source.matchAll(/'([^'\n]*)'|"([^"\n]*)"|`([^`\n]*)`/g)]
      .map((match) => (match[1] ?? match[2] ?? match[3] ?? '').toLowerCase())
      .filter((literal) => literal !== '')

  it('实现文件里不存在任何夹具中文列名或产品列名的字面量', () => {
    const source = readFileSync(new URL('../generic-csv.ts', import.meta.url), 'utf8')
    const literals = literalsOf(source)
    // 扫描本身有效：一个都没匹配到就等于这条断言在空跑。
    expect(literals.length).toBeGreaterThan(5)

    for (const forbidden of FORBIDDEN) {
      expect(literals, forbidden).not.toContain(forbidden)
    }

    // 更强的判据：任何**不含空白与中文标点**的字面量（即长得像列名的那种）都不得含上述子串。
    // 散文式的告警文案（如 R2 修订 2 指定的「未提供类型列，已按 TOTP 处理」）带逗号与空格，
    // 天然被这条排除——它是 PM 冻结的文案，不是列名。
    const bare = literals.filter((literal) => !/[\s，。：；]/.test(literal))
    expect(bare.length).toBeGreaterThan(5)
    for (const literal of bare) {
      for (const forbidden of FORBIDDEN) {
        expect(literal, `${literal} ⊃ ${forbidden}`).not.toContain(forbidden)
      }
    }
  })

  it('换一套完全陌生的列名照常解析', () => {
    const result = parseGenericCsv(table([totpRow({ c_name: 'Deno', c_user: 'Mason' })]), MAPPING)
    expect(result.failures).toEqual([])
    expect(result.entries[0]).toMatchObject({ issuer: 'Deno', account: 'Mason', digits: 6 })
  })

  it('列名带首尾空格时仍能命中（与 detect / bitwarden 的 trim 口径一致）', () => {
    const header = COLUMNS.map((name) => ` ${name} `)
    const result = parseGenericCsv(table([totpRow({ c_name: 'Deno' })], header), MAPPING)
    expect(result.failures).toEqual([])
    expect(result.entries[0]?.issuer).toBe('Deno')
  })

  it('映射指向不存在的列 → TransferFormatError，文案只点名映射目标与可用列数', () => {
    const text = table([totpRow()])
    const mapping = { ...MAPPING, issuer: '不存在的列' }
    expect(() => parseGenericCsv(text, mapping)).toThrow(TransferFormatError)
    try {
      parseGenericCsv(text, mapping)
    } catch (error) {
      const message = (error as Error).message
      expect(message).toContain('issuer')
      expect(message).toContain(`${COLUMNS.length} 列`)
      // 不回显调用方给的列名：残留映射可能来自另一份文件（R2 修订 1）。
      expect(message).not.toContain('不存在的列')
      // 不回显任何表头单元格。
      for (const name of COLUMNS) {
        expect(message, name).not.toContain(name)
      }
    }
  })

  it('C4：无表头行的 CSV 其表头就是第一条数据的 secret，缺失列的文案不得回显它', () => {
    // parseCsv 无条件把第 1 行当表头，于是 header[0] === SECRET_DENO。
    const headerless = `${SECRET_DENO},Mason\n${SECRET_SPDX},James`
    expect(() => parseGenericCsv(headerless, { secret: 'secret' })).toThrow(TransferFormatError)
    try {
      parseGenericCsv(headerless, { secret: 'secret' })
    } catch (error) {
      const message = (error as Error).message
      expect(message).toContain('secret')
      expect(message).toContain('2 列')
      expect(message).not.toContain(SECRET_DENO)
      expect(message).not.toContain(SECRET_DENO.toLowerCase())
      expect(message).not.toContain(SECRET_SPDX)
    }
  })

  it('secret 列未指定（空串或纯空白）→ TransferFormatError 点名 secret', () => {
    const text = table([totpRow()])
    expect(() => parseGenericCsv(text, { secret: '' })).toThrow(TransferFormatError)
    expect(() => parseGenericCsv(text, { secret: '' })).toThrow(/secret/)
    expect(() => parseGenericCsv(text, { secret: '   ' })).toThrow(/secret/)
  })

  it('重复列名不致命：后一列覆盖前一列', () => {
    const header = ['c_secret', 'c_algo', 'c_digits', 'c_period', 'c_kind', 'c_name', 'c_name']
    const row = [SECRET_DENO, 'SHA1', '6', '30', 'totp', '前者', '后者']
    const result = parseGenericCsv(`${header.join(',')}\n${row.join(',')}`, {
      secret: 'c_secret',
      algo: 'c_algo',
      digits: 'c_digits',
      period: 'c_period',
      kind: 'c_kind',
      issuer: 'c_name',
    })
    expect(result.failures).toEqual([])
    expect(result.entries[0]?.issuer).toBe('后者')
  })

  it('未映射的列一律忽略且不记 warning', () => {
    const result = parseGenericCsv(table([totpRow({ c_tags: 'a;b', c_note: '一条备注' })]), {
      secret: 'c_secret',
      algo: 'c_algo',
      digits: 'c_digits',
      period: 'c_period',
      kind: 'c_kind',
    })
    expect(result.failures).toEqual([])
    // c_name / c_user / c_tags / c_note / c_counter 五列都没被映射：既不该失败也不该告警。
    expect(result.warnings).toEqual([])
    expect(result.entries[0]).toMatchObject({
      issuer: '',
      account: '',
      note: '',
      tagNames: [],
    })
    expect(result.entries[0] && 'counter' in result.entries[0]).toBe(false)
  })
})

describe('parseGenericCsv：secret 列的两种形态', () => {
  it('裸 base32：小写与带 padding 都能解出同一份字节', () => {
    const result = parseGenericCsv(
      table([
        totpRow({ c_secret: SECRET_DENO.toLowerCase() }),
        totpRow({ c_secret: `${SECRET_DENO}====`, c_algo: 'SHA1' }),
      ]),
      MAPPING,
    )
    expect(result.failures).toEqual([])
    expect(hex(result.entries[0]!.secret)).toBe(HEX_DENO)
    expect(hex(result.entries[1]!.secret)).toBe(HEX_DENO)
    expect(result.entries[0]!.secret).toHaveLength(16)
  })

  it('otpauth:// URI：只映射 secret 一列也能取到全部参数，且不记 kind 告警', () => {
    const result = parseGenericCsv(table([uriRow(uri('Deno', 'Mason', SECRET_DENO))]), SECRET_ONLY)
    expect(result.failures).toEqual([])
    expect(result.skipped).toBe(0)
    // R2 补遗：URI 形态下 kind 未映射不记 warning——类型由 host 确定，不存在猜测。
    expect(result.warnings).toEqual([])
    expect(golden(result.entries)).toEqual([
      {
        sourceIndex: 0,
        issuer: 'Deno',
        account: 'Mason',
        kind: 'totp',
        algo: 'SHA1',
        digits: 6,
        secret: HEX_DENO,
        note: '',
        tagNames: [],
        favorite: false,
        period: 30,
      },
    ])
  })

  it('URI 的 hotp 形态：counter 取自 URI，且不产出 period', () => {
    const result = parseGenericCsv(
      table([
        uriRow(uri('WWE', 'Mason', SECRET_WWE, 'algorithm=SHA1&digits=6&counter=10300', 'hotp')),
      ]),
      SECRET_ONLY,
    )
    const entry = result.entries[0]
    expect(result.failures).toEqual([])
    expect(entry).toMatchObject({ kind: 'hotp', counter: 10300 })
    expect(entry && 'period' in entry).toBe(false)
  })

  it('scheme 大小写不敏感：OTPAUTH:// 同样走 URI 分支', () => {
    // RFC 3986 §3.1：只有 scheme 与 host 大小写不敏感，故只把 scheme 大写。
    const upper = `OTPAUTH${uri('Deno', 'Mason', SECRET_DENO).slice('otpauth'.length)}`
    const result = parseGenericCsv(table([uriRow(upper)]), SECRET_ONLY)
    expect(result.failures).toEqual([])
    expect(result.entries[0]?.algo).toBe('SHA1')
    expect(result.entries[0]?.kind).toBe('totp')
  })

  it('同一列里 URI 与裸 base32 混合出现是合法的，逐行各自处理', () => {
    // 裸 base32 行必须自带 algo / digits / period（修订 5），故这里映射这四列。
    const mapping: GenericCsvMapping = {
      secret: 'c_secret',
      algo: 'c_algo',
      digits: 'c_digits',
      period: 'c_period',
    }
    const result = parseGenericCsv(
      table([
        uriRow(uri('Deno', 'Mason', SECRET_DENO)),
        totpRow({ c_secret: SECRET_SPDX }),
        uriRow(uri('WWE', 'Mason', SECRET_WWE, 'algorithm=SHA1&digits=6&counter=7', 'hotp')),
      ]),
      mapping,
    )
    expect(result.failures).toEqual([])
    expect(result.entries.map((entry) => entry.kind)).toEqual(['totp', 'totp', 'hotp'])
    expect(hex(result.entries[1]!.secret)).toBe(HEX_SPDX)
    // 只有第 2 行是裸 base32，故 kind 告警只有一条，sourceIndex 指向它。
    expect(keys(result.warnings)).toEqual(['1:kind'])
    expect(result.warnings[0]?.message).toBe('未提供类型列，已按 TOTP 处理')
  })

  it('裸值不是合法 base32 时判为单条失败，其余行照常产出', () => {
    const result = parseGenericCsv(
      table([totpRow({ c_secret: 'not!base32' }), totpRow({ c_secret: SECRET_SPDX })]),
      MAPPING,
    )
    expect(result.failures).toEqual([
      expect.objectContaining({ sourceIndex: 0, path: '通用 CSV 第 2 行' }),
    ])
    expect(result.failures[0]?.reason).toBe('secret 不是合法的 base32 字符串')
    expect(result.entries).toHaveLength(1)
    expect(result.entries[0]?.sourceIndex).toBe(1)
  })

  it('secret 为空或纯空白 → 计入 skipped 而非 failures', () => {
    const result = parseGenericCsv(
      table([totpRow({ c_secret: '' }), totpRow({ c_secret: '   ' }), totpRow()]),
      MAPPING,
    )
    expect(result.failures).toEqual([])
    expect(result.skipped).toBe(2)
    expect(result.entries).toHaveLength(1)
    expect(result.entries[0]?.sourceIndex).toBe(2)
  })
})

describe('parseGenericCsv：三级取值优先级（R2 补遗）', () => {
  const URI_MAPPING: GenericCsvMapping = {
    secret: 'c_secret',
    issuer: 'c_name',
    account: 'c_user',
    algo: 'c_algo',
    digits: 'c_digits',
    period: 'c_period',
    kind: 'c_kind',
  }

  it('issuer / account 以 URI 为准，冲突时记 warning 且 field 是实际列名', () => {
    const result = parseGenericCsv(
      table([
        uriRow(uri('Deno', 'Mason', SECRET_DENO), { c_name: '别的名字', c_user: '别的账户' }),
      ]),
      URI_MAPPING,
    )
    expect(result.failures).toEqual([])
    expect(result.entries[0]).toMatchObject({ issuer: 'Deno', account: 'Mason' })
    expect(keys(result.warnings)).toEqual(['0:c_name', '0:c_user'])
    expect(result.warnings[0]?.message).toBe(
      'c_name 列与 secret 中 URI 的 issuer 不一致，已采用 URI 的值',
    )
    expect(result.warnings[1]?.message).toBe(
      'c_user 列与 secret 中 URI 的 account 不一致，已采用 URI 的值',
    )
    // C4：文案不回显任何一侧的值。
    for (const warning of result.warnings) {
      expect(warning.message).not.toContain('别的名字')
      expect(warning.message).not.toContain('别的账户')
      expect(warning.message).not.toContain('Deno')
      expect(warning.message).not.toContain('Mason')
    }
  })

  it('issuer / account 与 URI 一致时不记冲突 warning', () => {
    const result = parseGenericCsv(
      table([uriRow(uri('Deno', 'Mason', SECRET_DENO), { c_name: 'Deno', c_user: 'Mason' })]),
      URI_MAPPING,
    )
    expect(result.failures).toEqual([])
    expect(result.warnings).toEqual([])
  })

  it('URI 形态下映射列为空时身份仍取 URI 的值，不记冲突 warning', () => {
    const result = parseGenericCsv(table([uriRow(uri('Deno', 'Mason', SECRET_DENO))]), URI_MAPPING)
    expect(result.failures).toEqual([])
    expect(result.warnings).toEqual([])
    expect(result.entries[0]).toMatchObject({ issuer: 'Deno', account: 'Mason' })
  })

  it('裸 base32 形态下 issuer / account 只来自映射列，缺失则为空串且不记 warning', () => {
    const result = parseGenericCsv(table([totpRow()]), MAPPING)
    expect(result.failures).toEqual([])
    expect(result.entries[0]).toMatchObject({ issuer: '', account: '' })
    expect(result.warnings).toEqual([])
  })

  it('kind / algo / digits / period 以映射列为准，覆盖 URI 内嵌值', () => {
    const result = parseGenericCsv(
      table([
        uriRow(uri('Deno', 'Mason', SECRET_DENO, 'algorithm=SHA1&digits=6&period=30'), {
          c_algo: 'SHA512',
          c_digits: '8',
          c_period: '60',
          c_kind: 'totp',
        }),
      ]),
      URI_MAPPING,
    )
    expect(result.failures).toEqual([])
    expect(result.warnings).toEqual([])
    expect(result.entries[0]).toMatchObject({ algo: 'SHA512', digits: 8, period: 60 })
  })

  it('映射了但该行为空时回落到 URI 的值', () => {
    const result = parseGenericCsv(
      table([uriRow(uri('Deno', 'Mason', SECRET_DENO, 'algorithm=SHA256&digits=7&period=45'))]),
      { secret: 'c_secret', algo: 'c_algo', digits: 'c_digits', period: 'c_period' },
    )
    expect(result.failures).toEqual([])
    expect(result.entries[0]).toMatchObject({ algo: 'SHA256', digits: 7, period: 45 })
  })

  it('映射列把 URI 的 totp 改成 hotp 后，缺 counter 判单条失败而非静默置 0', () => {
    const result = parseGenericCsv(
      table([uriRow(uri('Deno', 'Mason', SECRET_DENO), { c_kind: 'hotp' })]),
      URI_MAPPING,
    )
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toBe('缺少 counter')
  })

  it('映射列把 URI 的 hotp 改成 totp 后，缺 period 判单条失败而非静默补 30', () => {
    const result = parseGenericCsv(
      table([
        uriRow(uri('WWE', 'Mason', SECRET_WWE, 'algorithm=SHA1&digits=6&counter=7', 'hotp'), {
          c_kind: 'totp',
        }),
      ]),
      URI_MAPPING,
    )
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toBe('缺少 period')
  })

  it('note / tagNames 只来自映射列：URI 没有这两个语义', () => {
    const result = parseGenericCsv(
      table([uriRow(uri('Deno', 'Mason', SECRET_DENO), { c_note: '一条备注', c_tags: 'a;b' })]),
      { secret: 'c_secret', note: 'c_note', tagNames: 'c_tags' },
    )
    expect(result.failures).toEqual([])
    expect(result.entries[0]).toMatchObject({ note: '一条备注', tagNames: ['a', 'b'] })
  })
})

describe('parseGenericCsv：kind 的分支', () => {
  it('未映射 kind + 裸 base32 → 按 totp 处理，每个裸 base32 行各记一条行级 warning', () => {
    const result = parseGenericCsv(
      table([totpRow({ c_kind: '' }), totpRow({ c_secret: SECRET_SPDX, c_kind: '' })]),
      { ...MAPPING, kind: undefined },
    )
    expect(result.failures).toEqual([])
    expect(result.entries.every((entry) => entry.kind === 'totp')).toBe(true)
    expect(keys(result.warnings)).toEqual(['0:kind', '1:kind'])
    expect(new Set(result.warnings.map((warning) => warning.message))).toEqual(
      new Set(['未提供类型列，已按 TOTP 处理']),
    )
  })

  it('已映射 kind 但某行为空 → 按 totp 处理，warning 的 field 是实际列名', () => {
    const result = parseGenericCsv(table([totpRow({ c_kind: '' })]), MAPPING)
    expect(result.failures).toEqual([])
    expect(keys(result.warnings)).toEqual(['0:c_kind'])
    expect(result.warnings[0]?.message).toBe('c_kind 为空，已按 TOTP 处理')
  })

  it('kind 为 hotp 而 counter 未映射 → 单条失败，绝不产出 counter 为 0 的条目', () => {
    const result = parseGenericCsv(table([totpRow({ c_kind: 'hotp', c_period: '' })]), {
      ...MAPPING,
      counter: undefined,
    })
    expect(result.entries).toEqual([])
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]?.reason).toBe('缺少 counter')
  })

  it('kind 为 totp 而 period 未映射 → 单条失败，绝不静默补 30', () => {
    const result = parseGenericCsv(table([totpRow({ c_period: '' })]), {
      ...MAPPING,
      period: undefined,
    })
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toBe('缺少 period')
  })

  it('kind 大小写不敏感：TOTP / HotP 都能识别', () => {
    const result = parseGenericCsv(
      table([
        totpRow({ c_kind: 'TOTP' }),
        totpRow({ c_kind: 'HotP', c_secret: SECRET_WWE, c_period: '', c_counter: '7' }),
      ]),
      MAPPING,
    )
    expect(result.failures).toEqual([])
    expect(result.warnings).toEqual([])
    expect(result.entries.map((entry) => entry.kind)).toEqual(['totp', 'hotp'])
  })

  it('kind 是 ADR-004 放弃的类型 → 单条失败，文案含「不受支持」', () => {
    for (const kind of ['steam', 'motp', 'yandex']) {
      const result = parseGenericCsv(table([totpRow({ c_kind: kind })]), MAPPING)
      expect(result.entries, kind).toEqual([])
      expect(result.failures[0]?.reason, kind).toContain('该令牌类型不受支持')
    }
  })

  it('kind 无法识别 → 单条失败', () => {
    const result = parseGenericCsv(table([totpRow({ c_kind: 'timed' })]), MAPPING)
    expect(result.failures[0]?.reason).toBe('无法识别的令牌类型，仅支持 totp / hotp')
  })

  it('某行失败时不留下指向它的 warning（行级缓冲）', () => {
    // 第 1 行：kind 为空 → 先记一条行级 warning，随后 digits 越界抛错，warning 必须被丢弃。
    const result = parseGenericCsv(
      table([
        totpRow({ c_kind: '', c_digits: '99' }),
        totpRow({ c_secret: SECRET_SPDX, c_kind: '' }),
      ]),
      MAPPING,
    )
    expect(result.failures.map((failure) => failure.sourceIndex)).toEqual([0])
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([1])
    expect(keys(result.warnings)).toEqual(['1:c_kind'])
  })
})

describe('parseGenericCsv：digits 与 algo 必填（R2 修订 5，只适用于裸 base32）', () => {
  it('digits 未映射 → 单条失败并点名 digits', () => {
    const result = parseGenericCsv(table([totpRow()]), { ...MAPPING, digits: undefined })
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toBe('缺少 digits')
  })

  it('digits 已映射但该行为空 → 同样单条失败', () => {
    const result = parseGenericCsv(table([totpRow({ c_digits: '' })]), MAPPING)
    expect(result.failures[0]?.reason).toBe('缺少 digits')
  })

  it('algo 未映射 → 单条失败并点名 algorithm', () => {
    const result = parseGenericCsv(table([totpRow()]), { ...MAPPING, algo: undefined })
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toBe('缺少 algorithm')
  })

  it('algo 已映射但该行为空 → 同样单条失败', () => {
    const result = parseGenericCsv(table([totpRow({ c_algo: '  ' })]), MAPPING)
    expect(result.failures[0]?.reason).toBe('缺少 algorithm')
  })

  it('digits 越界 → 单条失败，沿用 normalizeDigits 的既有文案', () => {
    for (const digits of ['5', '9', '10', '0', '-1']) {
      const result = parseGenericCsv(table([totpRow({ c_digits: digits })]), MAPPING)
      expect(result.entries, digits).toEqual([])
      expect(result.failures[0]?.reason, digits).toContain('digits 必须是 6–8 的整数')
    }
  })

  it('digits 非整数 → 单条失败', () => {
    for (const digits of ['6.0', 'abc', 'NaN']) {
      const result = parseGenericCsv(table([totpRow({ c_digits: digits })]), MAPPING)
      expect(result.failures[0]?.reason, digits).toContain('digits')
      expect(result.entries, digits).toEqual([])
    }
  })

  it('algo 归一化：SHA-512→SHA512、HmacSHA256→SHA256、sha1→SHA1（构造样本）', () => {
    const cases: readonly [string, string][] = [
      ['sha1', 'SHA1'],
      ['SHA-512', 'SHA512'],
      ['HmacSHA256', 'SHA256'],
      [' hmac-sha512 ', 'SHA512'],
      ['Algorithm.SHA256', 'SHA256'],
    ]
    for (const [raw, expected] of cases) {
      const result = parseGenericCsv(table([totpRow({ c_algo: raw })]), MAPPING)
      expect(result.failures, raw).toEqual([])
      expect(result.entries[0]?.algo, raw).toBe(expected)
    }
  })

  it('algo 为 md5 → 降级 SHA1 并记一条 warning，field 是实际列名', () => {
    const result = parseGenericCsv(table([totpRow({ c_algo: 'MD5' })]), MAPPING)
    expect(result.failures).toEqual([])
    expect(result.entries[0]?.algo).toBe('SHA1')
    expect(keys(result.warnings)).toEqual(['0:c_algo'])
    expect(result.warnings[0]?.message).toBe('原文是 MD5，已归一化为 SHA1')
  })

  it('URI 形态下 algo 为 MD5 时只有一条告警，不被重复记录', () => {
    const result = parseGenericCsv(
      table([uriRow(uri('Deno', 'Mason', SECRET_DENO, 'algorithm=MD5&digits=6&period=30'))]),
      SECRET_ONLY,
    )
    expect(result.failures).toEqual([])
    expect(result.entries[0]?.algo).toBe('SHA1')
    expect(keys(result.warnings)).toEqual(['0:algorithm'])
  })

  it('algo 无法识别 → 单条失败，绝不回落 SHA1', () => {
    const result = parseGenericCsv(table([totpRow({ c_algo: 'SHA0' })]), MAPPING)
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toBe('无法识别的 algorithm，仅支持 SHA1 / SHA256 / SHA512')
  })

  it('URI 形态下 digits / algo 未映射不会失败（修订 5 只适用于裸 base32）', () => {
    const result = parseGenericCsv(
      table([uriRow(uri('Deno', 'Mason', SECRET_DENO, 'algorithm=SHA256&digits=8&period=30'))]),
      SECRET_ONLY,
    )
    expect(result.failures).toEqual([])
    expect(result.entries[0]).toMatchObject({ algo: 'SHA256', digits: 8 })
  })
})

describe('parseGenericCsv：tagNames 的分隔符', () => {
  const rowOf = (tags: string): readonly (readonly string[])[] => [totpRow({ c_tags: tags })]

  it('默认分隔符是分号', () => {
    expect(DEFAULT_TAG_SEPARATOR).toBe(';')
    const result = parseGenericCsv(table(rowOf('工作;个人;服务器')), MAPPING)
    expect(result.entries[0]?.tagNames).toEqual(['工作', '个人', '服务器'])
  })

  it('逗号不是默认分隔符：含逗号的标签不会被切成两半', () => {
    const result = parseGenericCsv(table(rowOf('Deno, Inc')), MAPPING)
    expect(result.failures).toEqual([])
    expect(result.entries[0]?.tagNames).toEqual(['Deno, Inc'])
  })

  it('分隔符由调用方给出后可以就是逗号', () => {
    const result = parseGenericCsv(table(rowOf('a,b,c')), MAPPING, ',')
    expect(result.entries[0]?.tagNames).toEqual(['a', 'b', 'c'])
  })

  it('分隔符为空串时不拆分，整格作为一个标签', () => {
    const result = parseGenericCsv(table(rowOf('a;b')), MAPPING, '')
    expect(result.entries[0]?.tagNames).toEqual(['a;b'])
  })

  it('多字符分隔符同样生效', () => {
    const result = parseGenericCsv(table(rowOf('a||b||c')), MAPPING, '||')
    expect(result.entries[0]?.tagNames).toEqual(['a', 'b', 'c'])
  })

  it('逐项 trim、丢弃空项、跨项去重', () => {
    const result = parseGenericCsv(table(rowOf(' a ;; b ;a;  ')), MAPPING)
    expect(result.entries[0]?.tagNames).toEqual(['a', 'b'])
  })

  it('整格为空或纯空白时 tagNames 为空', () => {
    for (const tags of ['', '   ']) {
      const result = parseGenericCsv(table(rowOf(tags)), MAPPING)
      expect(result.failures, tags).toEqual([])
      expect(result.entries[0]?.tagNames, tags).toEqual([])
    }
  })

  it('未映射标签列时 tagNames 为空', () => {
    const result = parseGenericCsv(table(rowOf('a;b')), { ...MAPPING, tagNames: undefined })
    expect(result.entries[0]?.tagNames).toEqual([])
  })

  it('单个标签超长 → 单条失败，文案点名实际列名', () => {
    const long = 'a'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    const result = parseGenericCsv(table([totpRow({ c_tags: `x;${long}` })]), MAPPING)
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toContain('c_tags 长度为')
  })

  it('标签的首尾空白被 trim，但 note 的不被 trim', () => {
    const result = parseGenericCsv(
      table([totpRow({ c_tags: '  a  ', c_note: '  留白  ' })]),
      MAPPING,
    )
    expect(result.entries[0]?.tagNames).toEqual(['a'])
    expect(result.entries[0]?.note).toBe('  留白  ')
  })
})

describe('parseGenericCsv：ImportResult 固定形态与空单元格语义', () => {
  it('format / tags / favorite / sourceIndex 四项固定', () => {
    const result = parseGenericCsv(
      table([totpRow(), totpRow({ c_secret: SECRET_SPDX }), totpRow({ c_secret: '' })]),
      MAPPING,
    )
    expect(result.format).toBe('generic-csv')
    expect(result.tags).toEqual([])
    expect(result.entries.every((entry) => entry.favorite === false)).toBe(true)
    // sourceIndex 取 rowIndex（0 基数据行序号），跳过的行照样占号。
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([0, 1])
    expect(result.skipped).toBe(1)
  })

  it('条目形状是 ParsedEntry 的 11 个键，不含 id / position / createdAt / tagIds', () => {
    const entry = parseGenericCsv(table([totpRow()]), MAPPING).entries[0]!
    expect(Object.keys(entry).sort()).toEqual(
      [
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
      ].sort(),
    )
  })

  it('issuer / account / note 为空或纯空白时留空且不记 warning', () => {
    const result = parseGenericCsv(
      table([totpRow({ c_name: '   ', c_user: '', c_note: ' \t ' })]),
      MAPPING,
    )
    expect(result.failures).toEqual([])
    expect(result.entries[0]).toMatchObject({ issuer: '', account: '', note: '' })
    expect(result.warnings).toEqual([])
  })

  it('note 含引号、逗号与换行时原样还原（引用单元格）', () => {
    const note = '备注含 "引号"、逗号, 和\n换行'
    const text = table([totpRow({ c_note: note })])
    expect(text).toContain('"备注含 ""引号""')
    expect(parseGenericCsv(text, MAPPING).entries[0]?.note).toBe(note)
  })

  it('note 超长 → 单条失败，path 带行号', () => {
    const long = 'a'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    const result = parseGenericCsv(
      table([totpRow({ c_note: long }), totpRow({ c_secret: SECRET_SPDX })]),
      MAPPING,
    )
    expect(result.entries).toHaveLength(1)
    expect(result.failures).toEqual([
      expect.objectContaining({ sourceIndex: 0, path: '通用 CSV 第 2 行' }),
    ])
    expect(result.failures[0]?.reason).toContain('c_note 长度为')
  })

  it('字段数与表头不符的行走 C5 单条失败，合法行照常产出', () => {
    const text = [
      COLUMNS.join(','),
      totpRow().join(','),
      '只有,三个,字段',
      totpRow({ c_secret: SECRET_SPDX }).join(','),
    ].join('\n')
    const result = parseGenericCsv(text, MAPPING)
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([0, 2])
    expect(result.failures).toEqual([
      {
        sourceIndex: 1,
        path: '通用 CSV 第 3 行',
        reason: `该行有 3 个字段，与表头的 ${COLUMNS.length} 列不符`,
      },
    ])
  })

  it('只有表头没有数据行时得到空结果而非异常', () => {
    const result = parseGenericCsv(table([]), MAPPING)
    expect(result).toMatchObject({ format: 'generic-csv', entries: [], failures: [], skipped: 0 })
    expect(result.warnings).toEqual([])
  })

  it('没有表头行时抛 TransferFormatError', () => {
    expect(() => parseGenericCsv('', MAPPING)).toThrow(/不含表头行/)
    expect(() => parseGenericCsv('\n\n\n', MAPPING)).toThrow(TransferFormatError)
  })
})

describe('parseGenericCsv：整包闸门、C4 与纯函数', () => {
  it('字节数超上限时在解码之前就抛 TransferFormatError', () => {
    const bytes = new Uint8Array(TRANSFER_LIMITS.maxInputBytes + 1).fill(0x61)
    expect(() => parseGenericCsv(bytes, MAPPING)).toThrow(TransferFormatError)
    expect(() => parseGenericCsv(bytes, MAPPING)).toThrow(/超过上限/)
  })

  it('刚好在上限内的输入不因体积被拒', () => {
    // 单元格与行数都在各自上限内，只把总体积顶到 maxInputBytes。
    const pad = Math.floor(
      (TRANSFER_LIMITS.maxInputBytes - 32) / (TRANSFER_LIMITS.maxFieldLength + 8),
    )
    const rows = Array.from(
      { length: pad },
      () => `${'x'.repeat(TRANSFER_LIMITS.maxFieldLength)},y`,
    )
    const text = `c_pad,c_secret\n${rows.join('\n')}`
    const bytes = utf8Encode(text)
    expect(bytes.length).toBeLessThanOrEqual(TRANSFER_LIMITS.maxInputBytes)
    expect(rows.length).toBeLessThanOrEqual(TRANSFER_LIMITS.maxEntries)
    const result = parseGenericCsv(bytes, { secret: 'c_secret' })
    expect(result.entries).toEqual([])
    expect(result.failures.every((failure) => !failure.reason.includes('超过上限'))).toBe(true)
  })

  it('单元格长度超上限时抛 TransferFormatError', () => {
    const text = table([totpRow({ c_note: 'a'.repeat(TRANSFER_LIMITS.maxCsvCellLength + 1) })])
    expect(() => parseGenericCsv(text, MAPPING)).toThrow(/超过上限/)
  })

  it('数据行数超上限时抛 TransferFormatError', () => {
    const rows = (count: number) => Array.from({ length: count }, () => 'x').join('\n')
    // 恰好 maxEntries 行不超限，放行；有无尾换行结果相同（无尾换行时最后一行走 `scan()`
    // 循环之后的收尾分支，闸门在那里同样生效）。
    for (const text of [
      `c_secret\n${rows(TRANSFER_LIMITS.maxEntries)}\n`,
      `c_secret\n${rows(TRANSFER_LIMITS.maxEntries)}`,
    ]) {
      expect(() => parseGenericCsv(text, SECRET_ONLY)).not.toThrow()
    }
    for (const text of [
      `c_secret\n${rows(TRANSFER_LIMITS.maxEntries + 1)}\n`,
      `c_secret\n${rows(TRANSFER_LIMITS.maxEntries + 1)}`,
    ]) {
      expect(() => parseGenericCsv(text, SECRET_ONLY)).toThrow(/超过上限/)
    }
  })

  it('C4：任何 failure / warning / 异常文案都不含 secret 的原文、小写形态或 hex', () => {
    const collected: string[] = []
    const collect = (run: () => void): void => {
      try {
        run()
      } catch (error) {
        collected.push((error as Error).message)
      }
    }
    const collectResult = (
      run: () => {
        failures: readonly { reason: string }[]
        warnings: readonly { message: string }[]
      },
    ): void => {
      const result = run()
      collected.push(
        ...result.failures.map((failure) => failure.reason),
        ...result.warnings.map((warning) => warning.message),
      )
    }

    collectResult(() => parseGenericCsv(table([totpRow({ c_secret: 'not!base32' })]), MAPPING))
    collectResult(() => parseGenericCsv(table([totpRow({ c_digits: '99' })]), MAPPING))
    collectResult(() => parseGenericCsv(table([totpRow({ c_algo: 'SHA0' })]), MAPPING))
    collectResult(() => parseGenericCsv(table([totpRow({ c_kind: 'steam' })]), MAPPING))
    collectResult(() => parseGenericCsv(table([totpRow({ c_period: '' })]), MAPPING))
    collectResult(() => parseGenericCsv(table([totpRow({ c_note: 'a'.repeat(5000) })]), MAPPING))
    collectResult(() =>
      parseGenericCsv(
        table([
          uriRow(uri('Deno', 'Mason', SECRET_DENO).replace('issuer=Deno', 'issuer=别的'), {
            c_name: 'Deno',
          }),
        ]),
        { secret: 'c_secret', issuer: 'c_name' },
      ),
    )
    collect(() =>
      parseGenericCsv(`${SECRET_DENO},Mason\n${SECRET_SPDX},James`, { secret: 'secret' }),
    )
    collect(() =>
      parseGenericCsv(`${SECRET_DENO},Mason\n${SECRET_SPDX},James`, {
        secret: SECRET_DENO,
        issuer: '不存在',
      }),
    )
    collectResult(() => parseGenericCsv(table([totpRow(), ['只有', '两个']]), MAPPING))

    expect(collected.length).toBeGreaterThan(5)
    for (const message of collected) {
      expect(message).not.toContain(SECRET_DENO)
      expect(message).not.toContain(SECRET_DENO.toLowerCase())
      expect(message).not.toContain(HEX_DENO)
      expect(message).not.toContain(SECRET_SPDX)
    }
  })

  it('纯函数：不修改入参字节', () => {
    const bytes = fileBytes('generic_csv.csv')
    const before = Uint8Array.from(bytes)
    parseGenericCsv(bytes, FULL)
    expect(bytes).toEqual(before)
  })

  it('纯函数：同一输入与同一映射两次调用结果全等', () => {
    const bytes = fileBytes('generic_csv.csv')
    const first = parseGenericCsv(bytes, FULL)
    const second = parseGenericCsv(bytes, FULL)
    expect(golden(second.entries)).toEqual(golden(first.entries))
    expect(second.failures).toEqual(first.failures)
    expect(second.warnings).toEqual(first.warnings)
    expect(second.skipped).toBe(first.skipped)
  })

  it('字符串入参与等值字节入参结果全等', () => {
    const text = fileText('generic_csv.csv')
    const fromString = parseGenericCsv(text, FULL)
    const fromBytes = parseGenericCsv(utf8Encode(text), FULL)
    expect(golden(fromBytes.entries)).toEqual(golden(fromString.entries))
    expect(fromBytes.failures).toEqual(fromString.failures)
    expect(fromBytes.warnings).toEqual(fromString.warnings)
    expect(fromBytes.skipped).toBe(fromString.skipped)
  })

  it('非 TransferError 的异常不被吞掉', () => {
    // `mapping` 不是对象时读 `mapping.secret` 抛 TypeError，解析器不得把它转成格式错误。
    expect(() =>
      parseGenericCsv(table([totpRow()]), undefined as unknown as GenericCsvMapping),
    ).toThrow(TypeError)
  })
})
