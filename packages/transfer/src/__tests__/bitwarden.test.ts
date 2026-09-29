import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { utf8Encode } from '@askdaddy/crypto'
import { parseAegis } from '../aegis.js'
import { parseBitwarden } from '../bitwarden.js'
import { detect } from '../detect.js'
import { parseEnte } from '../ente.js'
import { TransferFormatError } from '../errors.js'
import { TRANSFER_LIMITS } from '../input.js'
import type { ParsedEntry } from '../types.js'

const url = (name: string): URL => new URL(`../__fixtures__/${name}`, import.meta.url)
const fileBytes = (name: string): Uint8Array => new Uint8Array(readFileSync(url(name)))
const fileText = (name: string): string => readFileSync(url(name), 'utf8')

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

/** secret 的 hex 由 node 对 `@askdaddy/otp` 独立算出后硬编码，不是用被测代码再推一次。 */
const HEX_DENO = 'e49270f0d21f365c8408f8b475c5267c'
const HEX_SPDX = 'eb99cb39c67ae042fa866ec4f239cbb5'
const HEX_AIRBNB = 'f91664c8d768853aedde5a936c16ba88'
const HEX_WWE = 'ed40c5eefbecce2206b15d75c1182a76'

const SECRET_DENO = '4SJHB4GSD43FZBAI7C2HLRJGPQ'
const SECRET_SPDX = '5OM4WOOGPLQEF6UGN3CPEOOLWU'
const SECRET_STEAM = 'JRZCL47CMXVOQMNPZR2F7J4RGI'

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

/** Bitwarden 个人导出的完整表头（vendored `bitwarden.csv` 用的就是这 10 列）。 */
const HEADER = [
  'folder',
  'favorite',
  'type',
  'name',
  'notes',
  'fields',
  'login_uri',
  'login_username',
  'login_password',
  'login_totp',
] as const

type Column = (typeof HEADER)[number]

const escapeCell = (value: string): string =>
  /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value

const cells = (overrides: Partial<Record<Column, string>> = {}): string[] =>
  HEADER.map((name) => overrides[name] ?? (name === 'type' ? 'login' : ''))

const table = (rows: readonly (readonly string[])[], header: readonly string[] = HEADER): string =>
  [header, ...rows].map((row) => row.map(escapeCell).join(',')).join('\n')

const uri = (
  issuer: string,
  account: string,
  secret: string,
  params = 'algorithm=SHA1&digits=6&period=30',
): string => `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&${params}`

const STEAM_FAILURE = 'Steam 令牌不受支持：本 App 只支持 TOTP 与 HOTP'

describe('parseBitwarden：golden 快照', () => {
  it('vendored 的 bitwarden.csv 解出 3 条，steam:// 行判为单条失败', () => {
    const result = parseBitwarden(fileBytes('bitwarden.csv'))
    expect(result.format).toBe('bitwarden')
    expect(result.tags).toEqual([])
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
        note: '',
        tagNames: [],
        favorite: false,
        period: 30,
      },
      {
        sourceIndex: 1,
        issuer: 'SPDX',
        account: 'James',
        kind: 'totp',
        algo: 'SHA256',
        digits: 7,
        secret: HEX_SPDX,
        note: '',
        tagNames: [],
        favorite: false,
        period: 20,
      },
      {
        sourceIndex: 2,
        issuer: 'Airbnb',
        account: 'Elijah',
        kind: 'totp',
        algo: 'SHA512',
        digits: 8,
        secret: HEX_AIRBNB,
        note: '',
        tagNames: [],
        favorite: false,
        period: 50,
      },
    ])
    expect(result.failures).toEqual([
      { sourceIndex: 3, path: 'Bitwarden CSV 第 5 行', reason: STEAM_FAILURE },
    ])
    // name 列写的是 "Test 1..3"，与 URI 的 issuer 全不一致，故每行一条冲突告警。
    expect(keys(result.warnings)).toEqual(['0:name', '1:name', '2:name'])
    expect(new Set(result.warnings.map((warning) => warning.message))).toEqual(
      new Set(['name 列与 login_totp 中 URI 的 issuer 不一致，已采用 URI 的值']),
    )
  })

  it('vendored 的 bitwarden_edge.csv（别名列名形态）解出 4 条 + 2 失败 + 2 跳过', () => {
    const result = parseBitwarden(fileBytes('bitwarden_edge.csv'))
    expect(golden(result.entries)).toEqual([
      {
        sourceIndex: 0,
        issuer: 'Deno',
        account: 'alice@example.com',
        kind: 'totp',
        algo: 'SHA1',
        digits: 6,
        secret: HEX_DENO,
        note: '备注含 "引号"、逗号, 和\n换行',
        tagNames: ['Work/Servers'],
        favorite: true,
        period: 30,
      },
      {
        sourceIndex: 1,
        issuer: 'Airbnb',
        account: 'Elijah',
        kind: 'totp',
        algo: 'SHA512',
        digits: 8,
        secret: HEX_AIRBNB,
        note: '',
        tagNames: [],
        favorite: false,
        period: 50,
      },
      {
        sourceIndex: 3,
        issuer: 'WWE',
        account: 'Mason',
        kind: 'hotp',
        algo: 'SHA512',
        digits: 8,
        secret: HEX_WWE,
        note: '',
        tagNames: [],
        favorite: false,
        counter: 10300,
      },
      {
        sourceIndex: 7,
        issuer: 'SPDX',
        account: 'James',
        kind: 'totp',
        algo: 'SHA256',
        digits: 7,
        secret: HEX_SPDX,
        note: '含 # 与 %',
        tagNames: ['Personal'],
        favorite: true,
        period: 20,
      },
    ])
    // 第 5 行是 `otpauth://hotp/...` 但**缺 counter**（不可恢复，禁止补 0）；第 7 行是 steam://。
    expect(result.failures).toEqual([
      { sourceIndex: 2, path: 'Bitwarden CSV 第 5 行', reason: 'URI 缺少 counter 参数' },
      { sourceIndex: 4, path: 'Bitwarden CSV 第 7 行', reason: STEAM_FAILURE },
    ])
    // 第 8 行（航空 张三）与第 9 行（type:note）的 totp 为空 → 跳过。
    expect(result.skipped).toBe(2)
    expect(keys(result.warnings)).toEqual([
      '0:digits',
      '0:period',
      '0:algorithm',
      '1:username',
      '3:username',
      '7:username',
    ])
    // 别名文件里的告警文案必须报**实际**列名，不能指向不存在的 login_totp / login_username。
    expect(result.warnings[0]?.message).toBe(
      'totp 是裸 base32，不含 digits，已按 Bitwarden 的默认值 6 补齐',
    )
    expect(result.warnings[3]?.message).toBe(
      'username 列与 totp 中 URI 的 account 不一致，已采用 URI 的值',
    )
  })

  it('vendored 的 bitwarden_malformed.csv：字段数不符的行走 C5 单条失败，合法行照常产出', () => {
    const result = parseBitwarden(fileBytes('bitwarden_malformed.csv'))
    expect(golden(result.entries)).toEqual([
      {
        sourceIndex: 2,
        issuer: 'Ok',
        account: '',
        kind: 'totp',
        algo: 'SHA1',
        digits: 6,
        secret: HEX_SPDX,
        note: '',
        tagNames: [],
        favorite: false,
        period: 30,
      },
    ])
    expect(result.failures).toEqual([
      {
        sourceIndex: 0,
        path: 'Bitwarden CSV 第 2 行',
        reason: '该行有 4 个字段，与表头的 5 列不符',
      },
      {
        sourceIndex: 1,
        path: 'Bitwarden CSV 第 3 行',
        reason: '该行有 7 个字段，与表头的 5 列不符',
      },
    ])
    expect(result.skipped).toBe(0)
    expect(keys(result.warnings)).toEqual(['2:digits', '2:period', '2:algorithm'])
  })

  it('C10：与 Ente 明文导出对撞，同身份的 secret 字节相等', () => {
    const ente = parseEnte(fileBytes('ente_auth.txt'))
    const bitwarden = parseBitwarden(fileBytes('bitwarden_edge.csv'))
    const enteSecrets = new Map(
      ente.entries.map((entry) => [`${entry.issuer}:${entry.account}`, hex(entry.secret)]),
    )
    // edge 夹具的 4 条里有 3 条身份（Airbnb:Elijah / WWE:Mason / SPDX:James）在 Ente 夹具中也存在，
    // 第 4 条 `Deno:alice@example.com` 是 Bitwarden 独有的账户名。写死 3 是为了让这条断言不空跑。
    const compared = bitwarden.entries
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

describe('parseBitwarden：按列名取值', () => {
  const rows = [
    cells({ name: 'Deno', login_username: 'alice', login_totp: SECRET_DENO, folder: 'Work' }),
    cells({ name: 'SPDX', login_totp: uri('SPDX', 'James', SECRET_SPDX), favorite: '1' }),
  ]

  it('列顺序整体调换后解析结果不变', () => {
    const permuted = [4, 0, 9, 1, 7, 3, 2, 5, 6, 8]
    const shuffled = table(
      rows.map((row) => permuted.map((index) => row[index]!)),
      permuted.map((index) => HEADER[index]!),
    )
    expect(shuffled.split('\n')[0]).not.toBe(HEADER.join(','))
    expect(golden(parseBitwarden(shuffled).entries)).toEqual(
      golden(parseBitwarden(table(rows)).entries),
    )
  })

  it('缺 totp 列时抛 TransferFormatError，且文案不回显表头内容（C4）', () => {
    // secret 特意写进 name 列：这样「文案不含 secret」才是真断言，
    // 而不是因为文件里压根就没有 secret（那种写法是空跑）。
    const full = cells({ name: SECRET_DENO, login_username: SECRET_SPDX })
    const header = HEADER.filter((name) => name !== 'login_totp')
    const row = HEADER.map((name, index) => [name, full[index]!] as const)
      .filter(([name]) => name !== 'login_totp')
      .map(([, value]) => value)
    const text = table([row], header)
    expect(text).toContain(SECRET_DENO)

    expect(() => parseBitwarden(text)).toThrow(TransferFormatError)
    expect(() => parseBitwarden(text)).toThrow(/不含 login_totp 或 totp 列/)
    try {
      parseBitwarden(text)
    } catch (error) {
      const message = (error as Error).message
      expect(message).not.toContain(SECRET_DENO)
      expect(message).not.toContain(SECRET_SPDX)
      expect(message).not.toContain('name')
    }
  })

  it('只有别名 totp 列时照常解析，warning 用实际列名', () => {
    const header = ['name', 'totp'] as const
    const text = table([['Deno', SECRET_DENO]], [...header])
    const result = parseBitwarden(text)
    expect(result.entries[0]).toMatchObject({ issuer: 'Deno', account: '', digits: 6, period: 30 })
    expect(keys(result.warnings)).toEqual(['0:digits', '0:period', '0:algorithm'])
    for (const warning of result.warnings) {
      expect(warning.message).toContain('totp 是裸 base32')
      expect(warning.message).not.toContain('login_totp')
    }
  })

  it('username 别名同样被读取', () => {
    const text = table([['Deno', 'alice', SECRET_DENO]], ['name', 'username', 'totp'])
    expect(parseBitwarden(text).entries[0]?.account).toBe('alice')
  })

  it('探测器判据不变：只有裸 totp 列的 CSV 被判为 generic-csv', () => {
    const aliased = table([['Deno', SECRET_DENO]], ['name', 'totp'])
    expect(detect(aliased)).toBe('generic-csv')
    expect(detect(fileBytes('bitwarden.csv'))).toBe('bitwarden')
    expect(detect(fileBytes('bitwarden_edge.csv'))).toBe('generic-csv')
  })

  it('表头单元格带空格时仍能找到列（与 detect 的 trim 口径一致）', () => {
    const text = table([['Deno', SECRET_DENO]], ['name ', ' login_totp'])
    expect(parseBitwarden(text).entries[0]?.issuer).toBe('Deno')
  })
})

describe('parseBitwarden：login_totp 的三种形态', () => {
  it('完整 URI 形态：algo / digits / period 全部取自 URI，不被默认值覆盖', () => {
    const text = table([
      cells({
        login_totp: uri('Airbnb', 'Elijah', SECRET_SPDX, 'algorithm=SHA512&digits=8&period=50'),
      }),
    ])
    const result = parseBitwarden(text)
    expect(result.entries[0]).toMatchObject({ kind: 'totp', algo: 'SHA512', digits: 8, period: 50 })
    // URI 形态自带全部参数，故一条默认值告警都不该有。
    expect(result.warnings).toEqual([])
  })

  it('hotp URI 形态：counter 取自 URI，且不产出 period', () => {
    const text = table([
      cells({
        login_totp: `otpauth://hotp/WWE:Mason?secret=${SECRET_DENO}&issuer=WWE&algorithm=SHA1&digits=6&counter=10300`,
      }),
    ])
    const entry = parseBitwarden(text).entries[0]
    expect(entry).toMatchObject({ kind: 'hotp', counter: 10300 })
    expect(entry && 'period' in entry).toBe(false)
  })

  it('scheme 大小写不敏感：OTPAUTH:// 同样走 URI 分支', () => {
    // 只大写 scheme。RFC 3986 §3.1 里只有 scheme 与 host 大小写不敏感，
    // query 的**参数名**大小写敏感，整条 URI 大写会因认不出 `SECRET=` 而正当失败。
    const text = table([
      cells({ login_totp: `OTPAUTH${uri('Deno', 'Mason', SECRET_DENO).slice('otpauth'.length)}` }),
    ])
    const result = parseBitwarden(text)
    expect(result.failures).toEqual([])
    expect(result.entries[0]?.algo).toBe('SHA1')
    expect(hex(result.entries[0]!.secret)).toBe(HEX_DENO)
  })

  it('裸 base32 形态：补 digits=6 / period=30 / SHA1，且每个默认值各记一条 warning', () => {
    const result = parseBitwarden(table([cells({ login_totp: SECRET_DENO })]))
    expect(result.entries[0]).toMatchObject({ kind: 'totp', algo: 'SHA1', digits: 6, period: 30 })
    // 26 个 base32 字符 → floor(26*5/8) = 16 字节；hex 与 golden 快照里的是同一份常量。
    expect(result.entries[0]!.secret).toHaveLength(16)
    expect(hex(result.entries[0]!.secret)).toBe(HEX_DENO)
    expect(keys(result.warnings)).toEqual(['0:digits', '0:period', '0:algorithm'])
    expect(result.warnings.map((warning) => warning.message)).toEqual([
      'login_totp 是裸 base32，不含 digits，已按 Bitwarden 的默认值 6 补齐',
      'login_totp 是裸 base32，不含 period，已按 Bitwarden 的默认值 30 补齐',
      'login_totp 是裸 base32，不含 algorithm，已按 Bitwarden 的默认值 SHA1 补齐',
    ])
  })

  it('裸 base32 一律按 TOTP 处理，绝不产出 counter 为 0 的 HOTP 条目', () => {
    const entry = parseBitwarden(table([cells({ login_totp: SECRET_DENO })])).entries[0]
    expect(entry?.kind).toBe('totp')
    expect(entry && 'counter' in entry).toBe(false)
  })

  it('裸 base32 带 padding 与小写也能解', () => {
    const result = parseBitwarden(
      table([
        cells({ login_totp: `${SECRET_DENO.toLowerCase()}====` }),
        cells({ login_totp: '4SJHB4GSD43FZBAI7C2HLRJGPQ' }),
      ]),
    )
    expect(result.failures).toEqual([])
    expect(hex(result.entries[0]!.secret)).toBe(HEX_DENO)
    expect(hex(result.entries[1]!.secret)).toBe(HEX_DENO)
  })

  it('裸值不是合法 base32 时判为单条失败', () => {
    const result = parseBitwarden(
      table([cells({ login_totp: 'not!base32' }), cells({ login_totp: SECRET_SPDX })]),
    )
    expect(result.failures).toEqual([
      expect.objectContaining({ sourceIndex: 0, path: 'Bitwarden CSV 第 2 行' }),
    ])
    expect(result.failures[0]?.reason).toBe('secret 不是合法的 base32 字符串')
    expect(result.entries).toHaveLength(1)
  })

  it('steam:// 形态判为单条失败，原因同时含「Steam」与「不受支持」', () => {
    const result = parseBitwarden(table([cells({ login_totp: `steam://${SECRET_STEAM}` })]))
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toContain('Steam')
    expect(result.failures[0]?.reason).toContain('不受支持')
  })

  it('STEAM:// 大写同样失败，且绝不用 Steam 专用字母表尝试解码', () => {
    const result = parseBitwarden(table([cells({ login_totp: `STEAM://${SECRET_STEAM}` })]))
    expect(result.failures[0]?.reason).toBe(STEAM_FAILURE)
  })

  it('URI 缺 secret 时判为单条失败', () => {
    const result = parseBitwarden(
      table([
        cells({
          login_totp: 'otpauth://totp/Deno:Mason?issuer=Deno&algorithm=SHA1&digits=6&period=30',
        }),
      ]),
    )
    expect(result.failures[0]?.reason).toBe('URI 缺少 secret 参数')
  })
})

describe('parseBitwarden：login_totp 是单值，不做逗号拆分', () => {
  it('单格内两个裸 base32 逗号相连 → 一行只产出一个结果，不是两条', () => {
    const result = parseBitwarden(
      table([
        cells({ login_totp: `${SECRET_DENO},${SECRET_SPDX}` }),
        cells({ login_totp: SECRET_DENO }),
      ]),
    )
    // 拆分会让第 1 行产出 2 条；不拆分则它整格不是合法 base32，判为 1 条失败。
    expect(result.entries).toHaveLength(1)
    expect(result.entries[0]?.sourceIndex).toBe(1)
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]?.sourceIndex).toBe(0)
  })

  it('单格内两个完整 URI 逗号相连 → 同样不拆成两条', () => {
    const result = parseBitwarden(
      table([cells({ login_totp: `${uri('A', 'a', SECRET_DENO)},${uri('B', 'b', SECRET_SPDX)}` })]),
    )
    expect(result.entries.length + result.failures.length).toBe(1)
    expect(result.entries.length).not.toBe(2)
  })

  it('label 含未编码逗号的 URI 不会被切成两半', () => {
    const result = parseBitwarden(
      table([
        cells({
          login_totp: `otpauth://totp/Deno:Mason, Jr.?secret=${SECRET_DENO}&issuer=Deno&algorithm=SHA1&digits=6&period=30`,
        }),
      ]),
    )
    expect(result.failures).toEqual([])
    expect(result.entries[0]).toMatchObject({ issuer: 'Deno', account: 'Mason, Jr.' })
  })

  it('collections 才是逗号多值：一格拆成多个标签', () => {
    const header = ['name', 'collections', 'login_totp']
    const result = parseBitwarden(table([['Deno', 'Work,Servers,Work', SECRET_DENO]], header))
    expect(result.entries[0]?.tagNames).toEqual(['Work', 'Servers'])
  })
})

describe('parseBitwarden：身份列映射', () => {
  it('裸 base32 形态下 name→issuer、login_username→account、notes→note', () => {
    const result = parseBitwarden(
      table([
        cells({
          name: 'Deno',
          login_username: 'alice@example.com',
          notes: '一条备注',
          login_totp: SECRET_DENO,
        }),
      ]),
    )
    expect(result.entries[0]).toMatchObject({
      issuer: 'Deno',
      account: 'alice@example.com',
      note: '一条备注',
    })
  })

  it('URI 形态下身份以 URI 为准，与 name 冲突时记 warning', () => {
    const result = parseBitwarden(
      table([cells({ name: 'Test 1', login_totp: uri('Deno', 'Mason', SECRET_DENO) })]),
    )
    expect(result.entries[0]).toMatchObject({ issuer: 'Deno', account: 'Mason' })
    expect(keys(result.warnings)).toEqual(['0:name'])
    expect(result.warnings[0]?.message).toContain('已采用 URI 的值')
  })

  it('name 与 URI 的 issuer 一致时不记冲突 warning', () => {
    const result = parseBitwarden(
      table([
        cells({
          name: 'Deno',
          login_username: 'Mason',
          login_totp: uri('Deno', 'Mason', SECRET_DENO),
        }),
      ]),
    )
    expect(result.warnings).toEqual([])
  })

  it('login_username 与 URI 的 account 冲突时记 warning，field 是该列名', () => {
    const result = parseBitwarden(
      table([
        cells({
          name: 'Deno',
          login_username: 'bob',
          login_totp: uri('Deno', 'Mason', SECRET_DENO),
        }),
      ]),
    )
    expect(keys(result.warnings)).toEqual(['0:login_username'])
    expect(result.entries[0]?.account).toBe('Mason')
  })

  it('三列都缺失（表头没有）时留空且不记 warning', () => {
    const result = parseBitwarden(table([['x', SECRET_DENO]], ['type', 'login_totp']))
    expect(result.entries[0]).toMatchObject({ issuer: '', account: '', note: '' })
    expect(keys(result.warnings)).toEqual(['0:digits', '0:period', '0:algorithm'])
  })

  it('三列为空串或纯空白时同样留空且不记 warning', () => {
    const result = parseBitwarden(
      table([cells({ name: '   ', login_username: '', notes: ' \t ', login_totp: SECRET_DENO })]),
    )
    expect(result.entries[0]).toMatchObject({ issuer: '', account: '', note: '' })
  })

  it('notes 里用户故意留的首尾空白不被 trim 掉', () => {
    const result = parseBitwarden(table([cells({ notes: '  留白  ', login_totp: SECRET_DENO })]))
    expect(result.entries[0]?.note).toBe('  留白  ')
  })

  it('notes 含引号、逗号与换行时原样还原（引用单元格）', () => {
    const note = '备注含 "引号"、逗号, 和\n换行'
    const text = table([cells({ notes: note, login_totp: SECRET_DENO })])
    expect(text).toContain('"备注含 ""引号""')
    expect(parseBitwarden(text).entries[0]?.note).toBe(note)
  })

  it('notes 超长判为单条失败，path 带行号', () => {
    const long = 'a'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    const result = parseBitwarden(
      table([cells({ notes: long, login_totp: SECRET_DENO }), cells({ login_totp: SECRET_SPDX })]),
    )
    expect(result.entries).toHaveLength(1)
    expect(result.failures).toEqual([
      expect.objectContaining({ sourceIndex: 0, path: 'Bitwarden CSV 第 2 行' }),
    ])
    expect(result.failures[0]?.reason).toContain('notes 长度为')
  })

  it('name 超长同样判为单条失败', () => {
    const long = 'a'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    const result = parseBitwarden(table([cells({ name: long, login_totp: SECRET_DENO })]))
    expect(result.failures[0]?.reason).toContain('name 长度为')
  })
})

describe('parseBitwarden：folder / favorite / collections', () => {
  it('folder 还原为单元素 tagNames，多级路径原样保留', () => {
    const result = parseBitwarden(
      table([cells({ folder: 'Work/Servers/DB', login_totp: SECRET_DENO })]),
    )
    expect(result.entries[0]?.tagNames).toEqual(['Work/Servers/DB'])
  })

  it('folder 为空或纯空白时 tagNames 为空', () => {
    for (const folder of ['', '   ']) {
      const result = parseBitwarden(table([cells({ folder, login_totp: SECRET_DENO })]))
      expect(result.entries[0]?.tagNames, folder).toEqual([])
    }
  })

  it('folder 超长判为单条失败', () => {
    const long = 'a'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    const result = parseBitwarden(table([cells({ folder: long, login_totp: SECRET_DENO })]))
    expect(result.failures[0]?.reason).toContain('folder 长度为')
  })

  it('favorite 的判据是「非空且 !== "0"」', () => {
    const cases: [string, boolean][] = [
      ['1', true],
      ['0', false],
      ['', false],
      ['   ', false],
      ['true', true],
      ['false', true],
      ['no', true],
    ]
    for (const [value, expected] of cases) {
      const result = parseBitwarden(table([cells({ favorite: value, login_totp: SECRET_DENO })]))
      expect(result.entries[0]?.favorite, JSON.stringify(value)).toBe(expected)
    }
  })

  it('collections 列存在时记一条 sourceIndex 为 null 的整包 warning', () => {
    const header = [...HEADER.slice(0, 9), 'collections', 'login_totp']
    // 行必须与 11 列表头同宽，否则这一行走的是「字段数不符」失败路径，断言就成了空跑。
    const row = [...cells({ name: 'Deno' }).slice(0, 9), 'Work,Servers', SECRET_DENO]
    const result = parseBitwarden(table([row], header))
    expect(result.failures).toEqual([])
    expect(result.warnings[0]).toEqual({
      sourceIndex: null,
      field: 'collections',
      message: '检测到组织导出的 collections 列，已按逗号拆分并入各条目的标签',
    })
    expect(result.entries[0]?.tagNames).toEqual(['Work', 'Servers'])
  })

  it('collections 列不存在时不记整包 warning', () => {
    const result = parseBitwarden(table([cells({ login_totp: SECRET_DENO })]))
    expect(result.warnings.filter((warning) => warning.sourceIndex === null)).toEqual([])
  })

  it('collections 排在 folder 之后，与 folder 重名时去重', () => {
    const header = ['folder', 'collections', 'login_totp']
    const result = parseBitwarden(table([['Work', 'Servers,Work,Work', SECRET_DENO]], header))
    expect(result.entries[0]?.tagNames).toEqual(['Work', 'Servers'])
  })

  it('collections 单元格为空时不并入任何标签，仍只有那一条整包 warning', () => {
    const header = ['folder', 'collections', 'login_totp']
    const result = parseBitwarden(table([['Work', '', SECRET_DENO]], header))
    expect(result.entries[0]?.tagNames).toEqual(['Work'])
    expect(result.warnings.filter((warning) => warning.field === 'collections')).toHaveLength(1)
  })

  it('collections 的某个元素超长时判为单条失败', () => {
    const long = 'a'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    const header = ['collections', 'login_totp']
    const result = parseBitwarden(table([[`ok,${long}`, SECRET_DENO]], header))
    expect(result.failures[0]?.reason).toContain('collections 长度为')
  })
})

describe('parseBitwarden：跳过与失败', () => {
  it('login_totp 为空或纯空白的行计入 skipped，不计入 failures', () => {
    const result = parseBitwarden(
      table([
        cells({ name: 'A', login_totp: '' }),
        cells({ name: 'B', login_totp: '   ' }),
        cells({ name: 'C', login_totp: SECRET_DENO }),
      ]),
    )
    expect(result.skipped).toBe(2)
    expect(result.failures).toEqual([])
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([2])
  })

  it('type 为 note 的行（无 totp）同样计入 skipped', () => {
    const result = parseBitwarden(
      table([cells({ type: 'note', name: 'Secure Note', notes: '没有 totp 的备注行' })]),
    )
    expect(result.skipped).toBe(1)
    expect(result.entries).toEqual([])
    expect(result.failures).toEqual([])
  })

  it('被跳过的行不产生任何 warning', () => {
    const result = parseBitwarden(table([cells({ name: 'A', notes: 'x', folder: 'F' })]))
    expect(result.skipped).toBe(1)
    expect(result.warnings).toEqual([])
  })

  it('失败行不会留下指向自己的 warning', () => {
    // name 超长会让该行失败。它排在所有会 push warning 的读取之前（见 parseRow 的说明），
    // 故该行只可能一条 warning 都不产生——剩下的 4 条全部来自成功的第 2 行与整包的 collections。
    const long = 'a'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    const header = ['folder', 'collections', 'name', 'login_totp']
    const result = parseBitwarden(
      table(
        [
          ['Work', 'Servers', long, SECRET_DENO],
          ['Work', 'Servers', 'Ok', SECRET_SPDX],
        ],
        header,
      ),
    )
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]?.sourceIndex).toBe(0)
    expect(result.entries).toHaveLength(1)
    expect(keys(result.warnings)).toEqual([
      'null:collections',
      '1:digits',
      '1:period',
      '1:algorithm',
    ])
    expect(result.warnings.some((warning) => warning.sourceIndex === 0)).toBe(false)
  })

  it('只有表头没有数据行时返回空结果而不抛', () => {
    const result = parseBitwarden(table([]))
    expect(result).toMatchObject({ format: 'bitwarden', entries: [], failures: [], skipped: 0 })
    expect(result.warnings).toEqual([])
  })

  it('完全空的输入抛 TransferFormatError（没有表头行）', () => {
    expect(() => parseBitwarden('')).toThrow(/不含表头行/)
    // 只有换行也算「没有表头行」：`scan` 会丢掉纯空行。
    expect(() => parseBitwarden('\n\n\n')).toThrow(/不含表头行/)
    // 而「有内容但没有 totp 列」是另一条路径：表头存在，只是认不出 Bitwarden。
    expect(() => parseBitwarden('   \n\n ')).toThrow(/不含 login_totp 或 totp 列/)
  })

  it('引号未闭合时抛 TransferFormatError', () => {
    expect(() => parseBitwarden(`${HEADER.join(',')}\n"未闭合,${SECRET_DENO}`)).toThrow(
      /引号未闭合/,
    )
  })
})

describe('parseBitwarden：闸门、C4 与纯函数', () => {
  it('单元格超上限时抛 TransferFormatError', () => {
    const huge = `otpauth://totp/Deno:Mason?secret=${SECRET_DENO}&issuer=${'a'.repeat(TRANSFER_LIMITS.maxCsvCellLength)}`
    expect(() => parseBitwarden(table([cells({ login_totp: huge })]))).toThrow(/超过上限/)
  })

  it('数据行数超上限时抛 TransferFormatError', () => {
    const rows = Array.from({ length: TRANSFER_LIMITS.maxEntries + 1 }, () =>
      cells({ login_totp: SECRET_DENO }),
    )
    // 闸门实现在 `csv.ts`，边界口径（`maxEntries` 放行 / `maxEntries + 1` 抛错，与有无尾换行
    // 无关）由 `csv.test.ts` 的四组用例覆盖，这里只验证 Bitwarden 侧确实把闸门透传出来。
    expect(() => parseBitwarden(`${table(rows)}\n`)).toThrow(/超过上限/)
    expect(() =>
      parseBitwarden(`${table(rows.slice(0, TRANSFER_LIMITS.maxEntries))}\n`),
    ).not.toThrow()
  })

  it('输入字节超上限时抛 TransferFormatError', () => {
    const huge = `${table([cells({ login_totp: SECRET_DENO })])}\n${'#'.repeat(TRANSFER_LIMITS.maxInputBytes)}`
    expect(() => parseBitwarden(utf8Encode(huge))).toThrow(/超过上限/)
  })

  it('C4：失败与告警文案里不含 secret 的原文、小写形态或 hex', () => {
    const secretHex = HEX_DENO
    const result = parseBitwarden(
      table([
        // name 里写着 secret 原文，而该行因 digits 越界失败。
        cells({
          name: SECRET_DENO,
          login_totp: uri('Deno', 'Mason', SECRET_DENO, 'algorithm=SHA1&digits=99&period=30'),
        }),
        // notes 里写着 secret，且 totp 是 steam://（必失败）。
        cells({ notes: SECRET_DENO, login_totp: `steam://${SECRET_DENO}` }),
        // 裸 base32 成功，产生 3 条默认值告警。
        cells({ login_totp: SECRET_DENO }),
      ]),
    )
    expect(result.failures).toHaveLength(2)
    const texts = [
      ...result.failures.map((failure) => `${failure.path} ${failure.reason}`),
      ...result.warnings.map((warning) => `${warning.field} ${warning.message}`),
    ]
    expect(texts.length).toBeGreaterThan(3)
    for (const text of texts) {
      expect(text).not.toContain(SECRET_DENO)
      expect(text).not.toContain(SECRET_DENO.toLowerCase())
      expect(text).not.toContain(secretHex)
    }
  })

  it('不修改入参字节，且两次调用结果一致', () => {
    const bytes = fileBytes('bitwarden_edge.csv')
    const copy = new Uint8Array(bytes)
    const first = parseBitwarden(bytes)
    const second = parseBitwarden(bytes)
    expect(bytes).toEqual(copy)
    expect(golden(second.entries)).toEqual(golden(first.entries))
    expect(second.warnings).toEqual(first.warnings)
    expect(second.failures).toEqual(first.failures)
    expect(second.skipped).toBe(first.skipped)
  })

  it('接受字符串输入，与字节输入结果一致', () => {
    const text = fileText('bitwarden.csv')
    expect(golden(parseBitwarden(text).entries)).toEqual(
      golden(parseBitwarden(utf8Encode(text)).entries),
    )
  })

  it('ParsedEntry 的键集恰好是 11 个，没有多余字段', () => {
    const result = parseBitwarden(fileBytes('bitwarden_edge.csv'))
    // 夹具里 totp 与 hotp 两种条目都有，故两条分支的键集都被覆盖到。
    expect(new Set(result.entries.map((entry) => entry.kind))).toEqual(new Set(['totp', 'hotp']))
    for (const entry of result.entries) {
      expect(Object.keys(entry).sort()).toEqual(
        [
          'account',
          'algo',
          'digits',
          'favorite',
          'issuer',
          'kind',
          'note',
          'secret',
          'sourceIndex',
          'tagNames',
          entry.kind === 'totp' ? 'period' : 'counter',
        ].sort(),
      )
    }
  })

  it('与 Aegis 的同身份条目 secret 字节相等（C10，跨 JSON 与 CSV 两条路径）', () => {
    const aegis = parseAegis(fileBytes('aegis_plain.json'))
    const bitwarden = parseBitwarden(fileBytes('bitwarden.csv'))
    const byIdentity = new Map(
      aegis.entries.map((entry) => [`${entry.issuer}:${entry.account}`, hex(entry.secret)]),
    )
    let compared = 0
    for (const entry of bitwarden.entries) {
      const expected = byIdentity.get(`${entry.issuer}:${entry.account}`)
      if (expected === undefined) continue
      expect(hex(entry.secret), entry.issuer).toBe(expected)
      compared += 1
    }
    expect(compared).toBeGreaterThan(0)
  })
})
