import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { TransferError, TransferFormatError, TransferValueError } from '../errors.js'
import { TRANSFER_LIMITS } from '../input.js'
import { generateOtpAuthUri, parseOtpAuthLines, parseOtpAuthUri } from '../otpauth.js'
import { decodeBase32Secret } from '../secret.js'
import type { ParsedEntry } from '../types.js'

const fixture = (name: string): string =>
  readFileSync(new URL(`../__fixtures__/${name}`, import.meta.url), 'utf8')

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')

/** RFC 6238 风格的假密钥：`Hello!` + `DEADBEEF`。AGENTS.md §5.3 要求夹具用假值。 */
const SECRET = 'JBSWY3DPEHPK3PXP'
const SECRET_HEX = '48656c6c6f21deadbeef'

const CANONICAL = `otpauth://totp/GitHub:alice@example.com?secret=${SECRET}&issuer=GitHub&algorithm=SHA1&digits=6&period=30`

const parse = (uri: string): ParsedEntry => parseOtpAuthUri(uri, 0).entry

const tail = (overrides: string): string => `?secret=${SECRET}&algorithm=SHA1&digits=6${overrides}`

describe('parseOtpAuthUri：字段解析', () => {
  it('解析规范样例的全部字段', () => {
    const entry = parse(CANONICAL)
    expect(entry.kind).toBe('totp')
    expect(entry.issuer).toBe('GitHub')
    expect(entry.account).toBe('alice@example.com')
    expect(hex(entry.secret)).toBe(SECRET_HEX)
    expect(entry.algo).toBe('SHA1')
    expect(entry.digits).toBe(6)
    expect(entry).toMatchObject({ period: 30, note: '', tagNames: [], favorite: false })
  })

  it('sourceIndex 由调用方给定，而不是固定为 0', () => {
    expect(parseOtpAuthUri(CANONICAL, 7).entry.sourceIndex).toBe(7)
  })

  it('hotp 解析出 counter，且不带 period', () => {
    const entry = parse(`otpauth://hotp/GitHub:alice${tail('&issuer=GitHub&counter=42')}`)
    expect(entry.kind).toBe('hotp')
    expect(entry).toMatchObject({ counter: 42 })
    expect('period' in entry).toBe(false)
  })

  it('kind 只由 host 决定：totp 携带 counter 时忽略 counter', () => {
    const entry = parse(`otpauth://totp/GitHub:alice${tail('&issuer=GitHub&period=30&counter=99')}`)
    expect(entry.kind).toBe('totp')
    expect(entry).toMatchObject({ period: 30 })
    expect('counter' in entry).toBe(false)
  })

  it('kind 只由 host 决定：hotp 携带 period 时忽略 period', () => {
    const entry = parse(`otpauth://hotp/GitHub:alice${tail('&issuer=GitHub&period=30&counter=9')}`)
    expect(entry).toMatchObject({ kind: 'hotp', counter: 9 })
  })

  it('algorithm 走归一化链：小写、连字符、Hmac 前缀、Dart 枚举泄漏形式', () => {
    const algos = ['sha1', 'SHA-256', 'HmacSHA512', 'algorithm.sha256', ' Algorithm.SHA1 ']
    expect(
      algos.map(
        (value) => parse(`otpauth://totp/A:b${tail(`&algorithm=${value.trim()}&period=30`)}`).algo,
      ),
    ).toEqual(['SHA1', 'SHA256', 'SHA512', 'SHA256', 'SHA1'])
  })

  it('query 参数以 Map 暴露，供 Ente 读取 codeDisplay', () => {
    const { query } = parseOtpAuthUri(
      `otpauth://totp/A:b${tail('&period=30')}&codeDisplay=%7B%22trashed%22%3Afalse%7D`,
      0,
    )
    expect(query.get('codeDisplay')).toBe('{"trashed":false}')
  })
})

describe('parseOtpAuthUri：secret 的百分号编码', () => {
  it('Android Uri.encode 把 = 编成 %3D，解码后与不带 padding 时字节相同', () => {
    const bare = parse(`otpauth://totp/A:b${tail('&period=30')}`)
    const padded = parse(
      `otpauth://totp/A:b?secret=${SECRET}%3D%3D&algorithm=SHA1&digits=6&period=30`,
    )
    const full = parse(
      `otpauth://totp/A:b?secret=${SECRET}%3D%3D%3D%3D%3D%3D&algorithm=SHA1&digits=6&period=30`,
    )
    expect(hex(padded.secret)).toBe(hex(bare.secret))
    expect(hex(full.secret)).toBe(SECRET_HEX)
  })

  it('错误长度的 padding 不影响解码结果', () => {
    const entry = parse(
      `otpauth://totp/A:b?secret=4SJHB4GSD43FZBAI7C2HLRJGPQ%3D%3D&algorithm=SHA1&digits=6&period=30`,
    )
    expect(hex(entry.secret)).toBe(hex(decodeBase32Secret('4SJHB4GSD43FZBAI7C2HLRJGPQ')))
  })
})

describe('parseOtpAuthUri：label', () => {
  it('label 未编码（含裸空格）时仍能解析', () => {
    const entry = parse(
      `otpauth://hotp/Air Canada:Benjamin?secret=${SECRET}&issuer=Air Canada&algorithm=SHA1&digits=6&counter=1`,
    )
    expect(entry).toMatchObject({ issuer: 'Air Canada', account: 'Benjamin' })
  })

  it('issuer 前缀匹配时按前缀切除，account 内的裸冒号被完整保留', () => {
    const entry = parse(
      `otpauth://totp/Issuer:Account:extra?secret=${SECRET}&issuer=Issuer&algorithm=SHA1&digits=6&period=30`,
    )
    expect(entry).toMatchObject({ issuer: 'Issuer', account: 'Account:extra' })
  })

  it('query 缺 issuer 时从 label 补齐', () => {
    const entry = parse(
      `otpauth://totp/Deno:Mason?secret=${SECRET}&algorithm=SHA1&digits=6&period=30`,
    )
    expect(entry).toMatchObject({ issuer: 'Deno', account: 'Mason' })
  })

  it('label 只有 account 时 issuer 为空字符串', () => {
    const entry = parse(`otpauth://totp/Mason?secret=${SECRET}&algorithm=SHA1&digits=6&period=30`)
    expect(entry).toMatchObject({ issuer: '', account: 'Mason' })
  })

  it('label 已编码时先解码再切分', () => {
    const entry = parse(
      `otpauth://hotp/Air%20Canada:Benjamin?secret=${SECRET}&issuer=Air+Canada&algorithm=SHA1&digits=6&counter=1`,
    )
    expect(entry).toMatchObject({ issuer: 'Air Canada', account: 'Benjamin' })
  })

  it('label 含非法百分号转义时整体按字面保留，不判整条失败', () => {
    const entry = parse(
      `otpauth://totp/50%25off%zz:alice?secret=${SECRET}&algorithm=SHA1&digits=6&period=30`,
    )
    expect(entry.issuer).toBe('50%25off%zz')
    expect(entry.account).toBe('alice')
  })

  it('query 里的 + 表示空格，与 %20 等价', () => {
    const plus = parse(
      `otpauth://totp/A:b?secret=${SECRET}&issuer=Air+Canada&algorithm=SHA1&digits=6&period=30`,
    )
    const escaped = parse(
      `otpauth://totp/A:b?secret=${SECRET}&issuer=Air%20Canada&algorithm=SHA1&digits=6&period=30`,
    )
    expect(plus.issuer).toBe('Air Canada')
    expect(escaped.issuer).toBe(plus.issuer)
  })

  it('query 里的 %2B 是字面加号，不被误解成空格', () => {
    const entry = parse(
      `otpauth://totp/A:b?secret=${SECRET}&issuer=C%2B%2BD&algorithm=SHA1&digits=6&period=30`,
    )
    expect(entry.issuer).toBe('C++D')
  })
})

describe('parseOtpAuthUri：issuer 冲突', () => {
  it('两处都有且不一致时以 query 为准并记 warning', () => {
    const { entry, warnings } = parseOtpAuthUri(
      `otpauth://totp/Deno:Mason?secret=${SECRET}&issuer=WWE&algorithm=SHA1&digits=6&period=30`,
      3,
    )
    expect(entry).toMatchObject({ issuer: 'WWE', account: 'Mason' })
    expect(warnings).toEqual([
      {
        sourceIndex: 3,
        field: 'issuer',
        message: 'label 与 query 的 issuer 不一致，已采用 query 的值',
      },
    ])
  })

  it('C4：冲突 warning 不回显任何一侧的 issuer 值', () => {
    const { warnings } = parseOtpAuthUri(
      `otpauth://totp/${SECRET}:Mason?secret=${SECRET}&issuer=WWE&algorithm=SHA1&digits=6&period=30`,
      0,
    )
    expect(warnings).toHaveLength(1)
    expect(warnings[0]!.message).not.toContain(SECRET)
    expect(warnings[0]!.message).not.toContain('WWE')
  })

  it('一致时不产生 warning', () => {
    expect(parseOtpAuthUri(CANONICAL, 0).warnings).toEqual([])
  })

  it('Ente PR#77：只在第一个 = 处切分，issuer 值内的 period= 不被当成参数', () => {
    const { entry, warnings } = parseOtpAuthUri(
      `otpauth://totp/Weird:Mason?issuer=Weird.period=99&algorithm=SHA1&digits=6&period=30&secret=${SECRET}`,
      0,
    )
    expect(entry).toMatchObject({ issuer: 'Weird.period=99', account: 'Mason' })
    expect(entry.kind === 'totp' && entry.period).toBe(30)
    expect(warnings).toHaveLength(1)
  })
})

describe('parseOtpAuthUri：缺失与越界一律报错（C8）', () => {
  const cases: [string, string, string][] = [
    ['totp 缺 period', `otpauth://totp/A:b?secret=${SECRET}&algorithm=SHA1&digits=6`, 'period'],
    ['hotp 缺 counter', `otpauth://hotp/A:b?secret=${SECRET}&algorithm=SHA1&digits=6`, 'counter'],
    ['缺 secret', 'otpauth://totp/A:b?algorithm=SHA1&digits=6&period=30', 'secret'],
    ['缺 algorithm', `otpauth://totp/A:b?secret=${SECRET}&digits=6&period=30`, 'algorithm'],
    ['缺 digits', `otpauth://totp/A:b?secret=${SECRET}&algorithm=SHA1&period=30`, 'digits'],
    ['secret 为空', `otpauth://totp/A:b?secret=&algorithm=SHA1&digits=6&period=30`, ''],
  ]

  for (const [name, uri, keyword] of cases) {
    it(`${name} 判为失败，不补默认值`, () => {
      expect(() => parse(uri)).toThrow(TransferValueError)
      if (keyword !== '') {
        expect(() => parse(uri)).toThrow(new RegExp(keyword))
      }
    })
  }

  it('缺 period 的错误文案不暗示 30 这个默认值', () => {
    expect(() => parse(`otpauth://totp/A:b?secret=${SECRET}&algorithm=SHA1&digits=6`)).toThrow(
      /缺少 period/,
    )
  })

  const outOfRange: [string, string][] = [
    ['digits 越界', `otpauth://totp/A:b?secret=${SECRET}&algorithm=SHA1&digits=10&period=30`],
    ['period 为 0', `otpauth://totp/A:b?secret=${SECRET}&algorithm=SHA1&digits=6&period=0`],
    ['counter 为负', `otpauth://hotp/A:b?secret=${SECRET}&algorithm=SHA1&digits=6&counter=-1`],
    ['algorithm 不支持', `otpauth://totp/A:b?secret=${SECRET}&algorithm=SHA224&digits=6&period=30`],
    [
      'secret 不是 base32',
      `otpauth://totp/A:b?secret=%2A%2A%2A%2A&algorithm=SHA1&digits=6&period=30`,
    ],
  ]

  for (const [name, uri] of outOfRange) {
    it(`${name} 判为失败`, () => {
      expect(() => parse(uri)).toThrow(TransferValueError)
    })
  }

  it('steam host 报「不受支持」而不是先抱怨 digits=5', () => {
    expect(() =>
      parse(`otpauth://steam/A:b?secret=${SECRET}&algorithm=SHA1&digits=5&period=30`),
    ).toThrow(/该令牌类型不受支持/)
  })

  it('C4：全部错误文案不含 secret 的任何形式', () => {
    for (const [, uri] of outOfRange) {
      let message = ''
      try {
        parse(uri)
      } catch (error) {
        message = (error as Error).message
      }
      expect(message).not.toContain(SECRET)
      expect(message).not.toContain(SECRET_HEX)
      expect(message.toLowerCase()).not.toContain('****')
    }
  })

  it('query 百分号编码非法时报错且不回显原值', () => {
    let message = ''
    try {
      parse(`otpauth://totp/A:b?secret=${SECRET}&algorithm=SHA1&digits=6&period=30&issuer=%zz`)
    } catch (error) {
      message = (error as Error).message
    }
    expect(message).toContain('百分号编码')
    expect(message).not.toContain(SECRET)
  })
})

describe('parseOtpAuthUri：scheme', () => {
  it('非 otpauth scheme 判为失败', () => {
    expect(() =>
      parse(`https://example.com/totp/A:b?secret=${SECRET}&algorithm=SHA1&digits=6&period=30`),
    ).toThrow(TransferValueError)
  })

  it('otpauth-migration:// 不由本函数处理', () => {
    expect(() => parse(`otpauth-migration://offline?data=AAAA`)).toThrow(/scheme 不是 otpauth/)
  })

  it('scheme 大小写不敏感（RFC 3986 §3.1）', () => {
    expect(parse(CANONICAL.replace('otpauth', 'OTPAUTH')).issuer).toBe('GitHub')
  })

  it('单斜杠判为失败', () => {
    expect(() => parse(`otpauth:/totp/A:b?secret=${SECRET}&issuer=A`)).toThrow(TransferValueError)
  })

  it('完全没有 scheme 判为失败', () => {
    expect(() => parse(`totp/A:b?secret=${SECRET}&algorithm=SHA1&digits=6&period=30`)).toThrow(
      TransferValueError,
    )
  })

  it('# 之后是片段，被丢弃而不进入 query', () => {
    const entry = parse(`${CANONICAL}#notes-here`)
    expect(entry).toMatchObject({ issuer: 'GitHub', period: 30 })
    expect(parseOtpAuthUri(`${CANONICAL}#notes-here`, 0).query.has('notes-here')).toBe(false)
  })

  it('前后空白被忽略', () => {
    expect(parse(`  ${CANONICAL}\t`)).toMatchObject({ issuer: 'GitHub' })
  })
})

describe('parseOtpAuthLines：行式批量', () => {
  it('返回完整的 ImportResult，format 为 otpauth-lines', () => {
    const result = parseOtpAuthLines(`${CANONICAL}\n`)
    expect(result.format).toBe('otpauth-lines')
    expect(result.tags).toEqual([])
    expect(result.skipped).toBe(0)
    expect(result.entries).toHaveLength(1)
    expect(result.failures).toEqual([])
  })

  it('空行与纯空白行被跳过，sourceIndex 按非空行连续编号', () => {
    const result = parseOtpAuthLines(`\n${CANONICAL}\n   \n\n${CANONICAL}\n`)
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([0, 1])
    expect(result.failures).toEqual([])
  })

  it('C5：某一行非法只记 failures 并带行号，其余行照常产出', () => {
    const result = parseOtpAuthLines(
      [`otpauth://totp/A:a?secret=${SECRET}&algorithm=SHA1&digits=6`, CANONICAL, 'garbage'].join(
        '\n',
      ),
      'URI 文本',
    )
    expect(result.entries).toHaveLength(1)
    expect(result.entries[0]!.issuer).toBe('GitHub')
    expect(result.failures).toEqual([
      {
        sourceIndex: 0,
        path: 'URI 文本 第 1 行',
        reason: expect.stringContaining('period'),
      },
      {
        sourceIndex: 2,
        path: 'URI 文本 第 3 行',
        reason: expect.stringContaining('scheme'),
      },
    ])
  })

  it('失败行的行号是源文本行号，跳过的空行也计入', () => {
    const result = parseOtpAuthLines(`\n\n${CANONICAL}\n\ngarbage\n`)
    expect(result.failures).toEqual([
      expect.objectContaining({ path: 'otpauth 文本 第 5 行', sourceIndex: 1 }),
    ])
  })

  it('CRLF 与 LF 等价', () => {
    const lf = parseOtpAuthLines(`${CANONICAL}\n${CANONICAL}\n`)
    const crlf = parseOtpAuthLines(`${CANONICAL}\r\n${CANONICAL}\r\n`)
    expect(crlf.entries).toEqual(lf.entries)
  })

  it('C3：单行超长按整包失败处理，而不是逐行失败', () => {
    const long = `otpauth://totp/A:b?secret=${SECRET}&algorithm=SHA1&digits=6&period=30&issuer=${'x'.repeat(TRANSFER_LIMITS.maxLineLength)}`
    expect(() => parseOtpAuthLines(`${CANONICAL}\n${long}\n`)).toThrow(TransferFormatError)
  })

  it('C3：行数超上限时整包失败', () => {
    const text = `${Array.from({ length: TRANSFER_LIMITS.maxEntries + 1 }, () => CANONICAL).join('\n')}\n`
    expect(() => parseOtpAuthLines(text)).toThrow(TransferFormatError)
  })

  it('空输入返回空结果而非抛错', () => {
    expect(parseOtpAuthLines('')).toMatchObject({ entries: [], failures: [], warnings: [] })
    expect(parseOtpAuthLines('\n\n  \n')).toMatchObject({ entries: [], failures: [] })
  })
})

describe('parseOtpAuthLines：真实夹具', () => {
  it('plain.txt：6 条成功，1 条 steam 失败并带行号', () => {
    const result = parseOtpAuthLines(fixture('plain.txt'), 'plain.txt')
    expect(result.entries).toHaveLength(6)
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]).toMatchObject({ sourceIndex: 6, path: 'plain.txt 第 7 行' })
    expect(result.failures[0]!.reason).toContain('不受支持')
    expect(result.entries.map((entry) => entry.issuer)).toEqual([
      'Deno',
      'SPDX',
      'Airbnb',
      'Issuu',
      'Air Canada',
      'WWE',
    ])
    expect(result.entries[4]!.account).toBe('Benjamin')
    expect(result.warnings).toEqual([])
  })

  it('plain.txt 的 hotp 行带 counter、totp 行带 period', () => {
    const result = parseOtpAuthLines(fixture('plain.txt'), 'plain.txt')
    expect(result.entries[3]).toMatchObject({ kind: 'hotp', counter: 1 })
    expect(result.entries[5]).toMatchObject({
      kind: 'hotp',
      counter: 10300,
      algo: 'SHA512',
      digits: 8,
    })
    expect(result.entries[2]).toMatchObject({ kind: 'totp', period: 50, algo: 'SHA512', digits: 8 })
  })

  it('plain.txt 与 otpauth_edge.txt 解出的同一密钥字节相同（C10）', () => {
    const plain = parseOtpAuthLines(fixture('plain.txt'), 'plain.txt')
    const edge = parseOtpAuthLines(fixture('otpauth_edge.txt'), 'otpauth_edge.txt')
    const fromEdge = edge.entries.find((entry) => entry.issuer === 'Air Canada')
    expect(fromEdge).toBeDefined()
    expect(hex(fromEdge!.secret)).toBe(hex(plain.entries[4]!.secret))
  })

  it('otpauth_edge.txt：9 条成功、9 条失败、2 条空行跳过', () => {
    const result = parseOtpAuthLines(fixture('otpauth_edge.txt'), 'otpauth_edge.txt')
    expect(result.entries).toHaveLength(9)
    expect(result.failures).toHaveLength(9)
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([0, 1, 2, 3, 4, 5, 9, 16, 17])
    expect(result.failures.map((failure) => failure.sourceIndex)).toEqual([
      6, 7, 8, 10, 11, 12, 13, 14, 15,
    ])
  })

  it('otpauth_edge.txt：失败原因逐条对应其缺陷', () => {
    const reasons = parseOtpAuthLines(fixture('otpauth_edge.txt'), 'e').failures.map(
      (failure) => failure.path,
    )
    expect(reasons).toEqual([
      'e 第 7 行',
      'e 第 8 行',
      'e 第 9 行',
      'e 第 13 行',
      'e 第 14 行',
      'e 第 15 行',
      'e 第 16 行',
      'e 第 17 行',
      'e 第 18 行',
    ])
  })

  it('otpauth_edge.txt：两条 issuer 冲突各记一条 warning', () => {
    const result = parseOtpAuthLines(fixture('otpauth_edge.txt'), 'otpauth_edge.txt')
    expect(result.warnings).toEqual([
      expect.objectContaining({ sourceIndex: 4, field: 'issuer' }),
      expect.objectContaining({ sourceIndex: 17, field: 'issuer' }),
    ])
  })

  it('otpauth_edge.txt：带 padding 与错误长度 padding 的 secret 解出同一批字节', () => {
    const entries = parseOtpAuthLines(fixture('otpauth_edge.txt'), 'e').entries
    expect(hex(entries[0]!.secret)).toBe(hex(decodeBase32Secret('4SJHB4GSD43FZBAI7C2HLRJGPQ')))
    expect(hex(entries[1]!.secret)).toBe(hex(decodeBase32Secret('5OM4WOOGPLQEF6UGN3CPEOOLWU')))
  })

  it('otpauth_edge.txt：第 20 行的 issuer 值内含 period= 而未被截断', () => {
    const entry = parseOtpAuthLines(fixture('otpauth_edge.txt'), 'e').entries.at(-1)!
    expect(entry.issuer).toBe('Weird.period=99')
    expect(entry).toMatchObject({ account: 'Mason' })
    expect(entry.kind === 'totp' && entry.period).toBe(30)
  })

  it('otpauth_malformed.txt：5 行全部失败，无一条产出', () => {
    const result = parseOtpAuthLines(fixture('otpauth_malformed.txt'), 'm')
    expect(result.entries).toEqual([])
    expect(result.failures).toHaveLength(5)
    expect(result.failures.map((failure) => failure.path)).toEqual([
      'm 第 1 行',
      'm 第 2 行',
      'm 第 3 行',
      'm 第 4 行',
      'm 第 5 行',
    ])
  })

  it('C4：真实夹具的全部失败文案不含任何 secret', () => {
    const secrets = [
      '4SJHB4GSD43FZBAI7C2HLRJGPQ',
      '5OM4WOOGPLQEF6UGN3CPEOOLWU',
      'JRZCL47CMXVOQMNPZR2F7J4RGI',
    ]
    for (const name of ['plain.txt', 'otpauth_edge.txt', 'otpauth_malformed.txt']) {
      for (const failure of parseOtpAuthLines(fixture(name), name).failures) {
        for (const secret of secrets) {
          expect(failure.reason).not.toContain(secret)
        }
      }
    }
  })
})

describe('generateOtpAuthUri', () => {
  const source = {
    kind: 'totp' as const,
    issuer: 'GitHub',
    account: 'alice@example.com',
    secret: decodeBase32Secret(SECRET),
    algo: 'SHA1' as const,
    digits: 6 as const,
    period: 30,
  }

  it('产出与 docs/transfer.md §3.2 示例同形，参数全部显式写出', () => {
    expect(generateOtpAuthUri(source)).toBe(
      `otpauth://totp/GitHub:alice%40example.com?secret=${SECRET}&issuer=GitHub&algorithm=SHA1&digits=6&period=30`,
    )
  })

  it('secret 不带 = padding（base32Encode 总是补，必须显式去掉）', () => {
    const secretOf = (uri: string): string => /(?:[?&])secret=([^&]*)/.exec(uri)![1]!
    expect(secretOf(generateOtpAuthUri(source))).toBe(SECRET)
    expect(
      secretOf(
        generateOtpAuthUri({ ...source, secret: decodeBase32Secret('4SJHB4GSD43FZBAI7C2HLRJGPQ') }),
      ),
    ).toBe('4SJHB4GSD43FZBAI7C2HLRJGPQ')
  })

  it('label 经 percent-encode，issuer 在 label 与 query 两处都写', () => {
    expect(generateOtpAuthUri({ ...source, issuer: 'Air Canada' })).toBe(
      `otpauth://totp/Air%20Canada:alice%40example.com?secret=${SECRET}&issuer=Air%20Canada&algorithm=SHA1&digits=6&period=30`,
    )
  })

  it('hotp 带 counter 而不带 period', () => {
    expect(
      generateOtpAuthUri({ ...source, kind: 'hotp' as const, period: undefined, counter: 42 }),
    ).toBe(
      `otpauth://hotp/GitHub:alice%40example.com?secret=${SECRET}&issuer=GitHub&algorithm=SHA1&digits=6&counter=42`,
    )
  })

  it('issuer 为空时仍写出 issuer=，且 label 不含冒号', () => {
    expect(generateOtpAuthUri({ ...source, issuer: '' })).toBe(
      `otpauth://totp/alice%40example.com?secret=${SECRET}&issuer=&algorithm=SHA1&digits=6&period=30`,
    )
  })

  it('参数顺序固定，同一输入连续两次产出逐字节相同（纯函数）', () => {
    const first = generateOtpAuthUri(source)
    expect(generateOtpAuthUri(source)).toBe(first)
    expect(
      first
        .split('?')[1]!
        .split('&')
        .map((pair) => pair.split('=')[0]),
    ).toEqual(['secret', 'issuer', 'algorithm', 'digits', 'period'])
  })

  it('totp 缺 period / hotp 缺 counter 时抛错而不是省略参数', () => {
    expect(() => generateOtpAuthUri({ ...source, period: undefined })).toThrow(TransferValueError)
    expect(() =>
      generateOtpAuthUri({ ...source, kind: 'hotp' as const, period: undefined }),
    ).toThrow(TransferValueError)
  })
})

describe('生成 → 解析往返无损', () => {
  const roundTrip = (source: Parameters<typeof generateOtpAuthUri>[0]): ParsedEntry =>
    parse(generateOtpAuthUri(source))

  const base = {
    secret: decodeBase32Secret(SECRET),
    algo: 'SHA256' as const,
    digits: 7 as const,
  }

  const labels: [string, string, string][] = [
    ['普通', 'GitHub', 'alice@example.com'],
    ['含空格', 'Air Canada', 'Benjamin Mason'],
    ['account 含冒号', 'Deno', 'Ma:son'],
    ['issuer 含冒号', 'Foo:Bar', 'Baz'],
    ['两侧都含冒号', 'Foo:Bar', 'Ma:son'],
    ['issuer 为空', '', 'Mason'],
    ['issuer 为空且 account 含冒号', '', 'Ma:son'],
    ['含斜杠与百分号', 'a/b%c', 'd/e%f'],
    ['含加号', 'C++', 'a+b'],
    ['含 & = ? #', 'a&b=c?d#e', 'f&g=h?i#j'],
    ['非 ASCII', '航空 Air Canada', '李 Mason'],
    ['含 emoji', '🔐 vault', '👤 user'],
  ]

  for (const [name, issuer, account] of labels) {
    it(`${name}：issuer=${JSON.stringify(issuer)} account=${JSON.stringify(account)}`, () => {
      const entry = roundTrip({ ...base, kind: 'totp', issuer, account, period: 30 })
      expect(entry).toMatchObject({
        kind: 'totp',
        issuer,
        account,
        algo: 'SHA256',
        digits: 7,
        period: 30,
      })
      expect(hex(entry.secret)).toBe(SECRET_HEX)
    })
  }

  it('hotp 往返保留 counter', () => {
    const entry = roundTrip({
      ...base,
      kind: 'hotp',
      issuer: 'WWE',
      account: 'Mason',
      counter: 10300,
    })
    expect(entry).toMatchObject({ kind: 'hotp', counter: 10300 })
  })

  it('全部三种算法与三种位数往返一致', () => {
    for (const algo of ['SHA1', 'SHA256', 'SHA512'] as const) {
      for (const digits of [6, 7, 8] as const) {
        const entry = roundTrip({
          ...base,
          algo,
          digits,
          kind: 'totp',
          issuer: 'A',
          account: 'b',
          period: 45,
        })
        expect(entry).toMatchObject({ algo, digits, period: 45 })
      }
    }
  })

  it('往返不产生 issuer 冲突 warning', () => {
    for (const [, issuer, account] of labels) {
      const uri = generateOtpAuthUri({ ...base, kind: 'totp', issuer, account, period: 30 })
      expect(parseOtpAuthUri(uri, 0).warnings).toEqual([])
    }
  })

  it('plain.txt 解析 → 生成 → 再解析，字段完全一致', () => {
    const first = parseOtpAuthLines(fixture('plain.txt'), 'plain.txt').entries
    const second = parseOtpAuthLines(
      first.map((entry) => generateOtpAuthUri(entry)).join('\n'),
      'regenerated',
    )
    expect(second.failures).toEqual([])
    expect(second.entries).toEqual(first.map((entry, index) => ({ ...entry, sourceIndex: index })))
  })

  it('generateOtpAuthUri 直接接受 ParsedEntry，无需字段转换', () => {
    const entry = parse(CANONICAL)
    expect(parse(generateOtpAuthUri(entry))).toEqual(entry)
  })
})

describe('错误层级', () => {
  it('单条解析抛 TransferValueError，批量解析不向外抛', () => {
    expect(() => parse('garbage')).toThrow(TransferValueError)
    expect(() => parseOtpAuthLines('garbage\n')).not.toThrow()
    expect(new TransferValueError('x')).toBeInstanceOf(TransferError)
    expect(new TransferFormatError('x')).toBeInstanceOf(TransferError)
  })
})
