import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { utf8Encode } from '@askdaddy/crypto'
import { parseAegis } from '../aegis.js'
import { TransferFormatError } from '../errors.js'
import { TRANSFER_LIMITS } from '../input.js'
import { parseOtpAuthLines } from '../otpauth.js'
import { decodeBase64Secret } from '../secret.js'
import type { ParsedEntry } from '../types.js'

const url = (name: string): URL => new URL(`../__fixtures__/${name}`, import.meta.url)
const fileBytes = (name: string): Uint8Array => new Uint8Array(readFileSync(url(name)))
const fileText = (name: string): string => readFileSync(url(name), 'utf8')

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

/** 只保留 golden 关心的字段：secret 用 hex 表示，便于跨格式做字节相等断言（C10）。 */
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

/** 用最小可用条目做构造样本，避免每处都重复写 Aegis 的完整外壳。 */
const wrap = (entries: unknown[], groups?: unknown): string =>
  JSON.stringify({
    version: 1,
    header: { slots: null, params: null },
    db: groups === undefined ? { version: 3, entries } : { version: 3, groups, entries },
  })

const entry = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  type: 'totp',
  uuid: 'aaaaaaaa-0000-4000-8000-000000000001',
  name: 'Mason',
  issuer: 'Deno',
  icon: null,
  note: '',
  info: { secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ', algo: 'SHA1', digits: 6, period: 30 },
  ...overrides,
})

describe('parseAegis：golden 快照', () => {
  it('aegis_plain.json 解出 6 条，1 条 steam 判为单条失败', () => {
    const result = parseAegis(fileBytes('aegis_plain.json'))
    expect(result.format).toBe('aegis')
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
        secret: 'e49270f0d21f365c8408f8b475c5267c',
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
        secret: 'eb99cb39c67ae042fa866ec4f239cbb5',
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
        secret: 'f91664c8d768853aedde5a936c16ba88',
        note: '',
        tagNames: [],
        favorite: false,
        period: 50,
      },
      {
        sourceIndex: 3,
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
        sourceIndex: 4,
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
        sourceIndex: 5,
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
    expect(result.failures[0]).toMatchObject({ sourceIndex: 6, path: 'db.entries[6]' })
    expect(result.failures[0]!.reason).toContain('不受支持')
    expect(result.failures[0]!.reason).toContain('steam')
    expect(result.warnings).toEqual([])
  })

  it('C10：同一批身份与通用 otpauth 文本解出的 secret **字节相同**', () => {
    const aegis = parseAegis(fileBytes('aegis_plain.json')).entries
    const otpauth = parseOtpAuthLines(fileText('plain.txt'), 'plain.txt').entries
    expect(aegis).toHaveLength(otpauth.length)
    for (let i = 0; i < aegis.length; i += 1) {
      expect(aegis[i]!.issuer, `第 ${i} 条 issuer`).toBe(otpauth[i]!.issuer)
      expect(aegis[i]!.account, `第 ${i} 条 account`).toBe(otpauth[i]!.account)
      expect(hex(aegis[i]!.secret), `第 ${i} 条 secret`).toBe(hex(otpauth[i]!.secret))
    }
  })

  it('字节与字符串两种入参结果一致', () => {
    expect(golden(parseAegis(fileText('aegis_plain.json')).entries)).toEqual(
      golden(parseAegis(fileBytes('aegis_plain.json')).entries),
    )
  })
})

describe('parseAegis：字段名映射', () => {
  it('Aegis 的 name 映射为 account，issuer 映射为 issuer（两者与本 App 相反，不得弄反）', () => {
    const result = parseAegis(wrap([entry({ name: ' alice@corp ', issuer: 'GitHub' })]))
    expect(result.entries[0]).toMatchObject({ account: ' alice@corp ', issuer: 'GitHub' })
  })

  it('info.secret 解码为字节；大写无 padding 与带 padding 两种写法结果相同', () => {
    const bare = parseAegis(wrap([entry()])).entries[0]!
    const padded = parseAegis(
      wrap([
        entry({
          info: { secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ======', algo: 'SHA1', digits: 6, period: 30 },
        }),
      ]),
    ).entries[0]!
    const lower = parseAegis(
      wrap([
        entry({
          info: { secret: '4sjhb4gsd43fzbai7c2hlrjgpq', algo: 'SHA1', digits: 6, period: 30 },
        }),
      ]),
    ).entries[0]!
    expect(hex(bare.secret)).toBe('e49270f0d21f365c8408f8b475c5267c')
    expect(hex(padded.secret)).toBe(hex(bare.secret))
    expect(hex(lower.secret)).toBe(hex(bare.secret))
  })

  it('note 映射到 ParsedEntry.note；缺失或 null 时为空串', () => {
    expect(parseAegis(wrap([entry({ note: '备注文本' })])).entries[0]!.note).toBe('备注文本')
    expect(parseAegis(wrap([entry({ note: null })])).entries[0]!.note).toBe('')
    const absent = entry()
    delete absent.note
    expect(parseAegis(wrap([absent])).entries[0]!.note).toBe('')
  })

  it('issuer 缺失或 null 时为空串，不判失败', () => {
    expect(parseAegis(wrap([entry({ issuer: null })])).entries[0]!.issuer).toBe('')
    const absent = entry()
    delete absent.issuer
    expect(parseAegis(wrap([absent])).entries[0]!.issuer).toBe('')
  })

  it('_usageCount / _lastUsedTimestamp 即使出现也不映射', () => {
    const result = parseAegis(wrap([entry({ _usageCount: 99, _lastUsedTimestamp: 1737000000000 })]))
    expect(result.entries).toHaveLength(1)
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
  })

  it('favorite 恒为 false：Aegis 没有收藏概念', () => {
    expect(
      parseAegis(fileBytes('aegis_plain.json')).entries.every((e) => e.favorite === false),
    ).toBe(true)
  })
})

describe('parseAegis：标签', () => {
  it('v3 的 db.groups + entries[].groups 还原为 tagNames，未被引用的分组也进 tags', () => {
    const result = parseAegis(fileBytes('aegis_grouped_v3.json'))
    expect(result.tags).toEqual([
      { name: '工作', sourceIndex: 0 },
      { name: '个人', sourceIndex: 1 },
    ])
    expect(result.entries[0]!.tagNames).toEqual(['工作', '个人'])
    expect(result.entries[2]!.tagNames).toEqual([])
    expect(result.failures).toEqual([])
  })

  it('引用的 uuid 在 db.groups 中不存在时记 warning 而非失败', () => {
    const result = parseAegis(fileBytes('aegis_grouped_v3.json'))
    expect(result.entries).toHaveLength(3)
    expect(result.entries[1]!.tagNames).toEqual([])
    expect(result.failures).toEqual([])
    const warning = result.warnings.find((w) => w.sourceIndex === 1)
    expect(warning).toBeDefined()
    expect(warning!.field).toBe('db.entries[1].groups')
    expect(warning!.message).toContain('不存在')
  })

  it('legacy 的 entries[].group 字符串也还原为 tagNames；null 时为空数组', () => {
    const result = parseAegis(fileBytes('aegis_plain_grouped_v2.json'))
    expect(result.tags).toEqual([])
    expect(result.entries.map((e) => e.tagNames)).toEqual([
      ['group1'],
      [],
      ['group1'],
      ['group2'],
      [],
      [],
    ])
    expect(result.failures).toHaveLength(1)
  })

  it('db.groups 不是数组时整包警告并忽略分组，条目照常产出', () => {
    const result = parseAegis(
      wrap([entry({ groups: ['whatever'] })], { uuid: 'whatever', name: '工作' }),
    )
    expect(result.entries).toHaveLength(1)
    expect(result.failures).toEqual([])

    const broken = JSON.parse(wrap([entry()], [])) as Record<string, unknown>
    ;(broken.db as Record<string, unknown>).groups = { '0': { uuid: 'a', name: '工作' } }
    const parsed = parseAegis(JSON.stringify(broken))
    expect(parsed.entries).toHaveLength(1)
    expect(parsed.warnings[0]).toMatchObject({ sourceIndex: null, field: 'db.groups' })
  })

  it('分组元素缺 uuid 或 name 时忽略该分组并记 warning', () => {
    const result = parseAegis(wrap([entry()], [{ name: '没有 uuid' }]))
    expect(result.tags).toEqual([])
    expect(result.warnings[0]).toMatchObject({ sourceIndex: 0, field: 'db.groups[0]' })
  })
})

describe('parseAegis：不受支持的令牌类型（ADR-004 + C5）', () => {
  it.each(['steam', 'motp', 'yandex'])('%s 判为单条失败，其余条目照常产出', (type) => {
    const result = parseAegis(wrap([entry(), entry({ type, uuid: 'x' }), entry()]))
    expect(result.entries).toHaveLength(2)
    expect(result.entries.map((e) => e.sourceIndex)).toEqual([0, 2])
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]).toMatchObject({ sourceIndex: 1, path: 'db.entries[1]' })
    expect(result.failures[0]!.reason).toContain('不受支持')
  })

  it('steam 的失败原因是「不受支持」而不是先抱怨 digits=5', () => {
    const result = parseAegis(
      wrap([
        entry({
          type: 'steam',
          info: { secret: 'JRZCL47CMXVOQMNPZR2F7J4RGI', algo: 'SHA1', digits: 5, period: 30 },
        }),
      ]),
    )
    expect(result.failures[0]!.reason).toContain('不受支持')
    expect(result.failures[0]!.reason).not.toContain('digits')
  })
})

describe('parseAegis：算法归一化与默认值', () => {
  it('info.algo 为 MD5 时归一化为 SHA1 并记 warning', () => {
    const result = parseAegis(
      wrap([
        entry({
          info: { secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ', algo: 'MD5', digits: 6, period: 30 },
        }),
      ]),
    )
    expect(result.entries[0]!.algo).toBe('SHA1')
    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]).toMatchObject({ sourceIndex: 0, field: 'db.entries[0].info.algo' })
    expect(result.warnings[0]!.message).toContain('MD5')
    expect(result.warnings[0]!.message).toContain('SHA1')
  })

  it('HmacSHA256 归一化为 SHA256，且不记「已归一化」warning（§2.1 只要求 MD5 报出）', () => {
    const result = parseAegis(
      wrap([
        entry({
          info: { secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ', algo: 'HmacSHA256', digits: 6, period: 30 },
        }),
      ]),
    )
    expect(result.entries[0]!.algo).toBe('SHA256')
    expect(result.warnings).toEqual([])
  })

  it('无法识别的算法判为单条失败，绝不回落 SHA1（C8）', () => {
    const result = parseAegis(
      wrap([
        entry({
          info: { secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ', algo: 'SHA224', digits: 6, period: 30 },
        }),
      ]),
    )
    expect(result.entries).toEqual([])
    expect(result.failures[0]!.reason).toContain('algorithm')
  })

  it('info.digits 缺失时按 Aegis 默认值 6 补齐并记 warning', () => {
    const result = parseAegis(
      wrap([entry({ info: { secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ', algo: 'SHA1', period: 30 } })]),
    )
    expect(result.entries[0]!.digits).toBe(6)
    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]!.field).toBe('db.entries[0].info.digits')
    expect(result.warnings[0]!.message).toContain('默认值')
  })

  it('digits 越界判为失败，不夹取（§2.1）', () => {
    const result = parseAegis(
      wrap([
        entry({
          info: { secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ', algo: 'SHA1', digits: 10, period: 30 },
        }),
      ]),
    )
    expect(result.entries).toEqual([])
    expect(result.failures[0]!.reason).toContain('digits')
  })

  it('period（totp）缺失判为失败，不静默补 30（C8）', () => {
    const result = parseAegis(
      wrap([entry({ info: { secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ', algo: 'SHA1', digits: 6 } })]),
    )
    expect(result.entries).toEqual([])
    expect(result.failures[0]!.reason).toContain('period')
  })

  it('counter（hotp）缺失判为失败，不静默补 0（C8）', () => {
    const result = parseAegis(
      wrap([
        entry({
          type: 'hotp',
          info: { secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ', algo: 'SHA1', digits: 6 },
        }),
      ]),
    )
    expect(result.entries).toEqual([])
    expect(result.failures[0]!.reason).toContain('counter')
  })

  it('失败条目的局部 warning 不会残留（不留下指向不存在条目的警告）', () => {
    const result = parseAegis(
      wrap([
        entry({
          info: { secret: '4SJHB4GSD43FZBAI7C2HLRJGPQ', algo: 'MD5', digits: 6 },
        }),
      ]),
    )
    expect(result.entries).toEqual([])
    expect(result.failures).toHaveLength(1)
    expect(result.warnings).toEqual([])
  })
})

describe('parseAegis：边界夹具', () => {
  it('aegis_edge.json：3 条成功、6 条失败、1 条 MD5 warning', () => {
    const result = parseAegis(fileBytes('aegis_edge.json'))
    expect(result.entries.map((e) => e.sourceIndex)).toEqual([0, 2, 3])
    expect(result.entries[0]).toMatchObject({
      issuer: '航空 Air Canada',
      account: '张三 a:b/c%d+e f',
    })
    expect(result.entries[1]!.algo).toBe('SHA1')
    expect(result.entries[2]!.algo).toBe('SHA256')

    expect(result.failures.map((f) => f.sourceIndex)).toEqual([1, 4, 5, 6, 7, 8])
    expect(result.failures[0]!.reason).toContain('note')
    expect(result.failures[0]!.reason).toContain('超过上限')
    expect(result.failures[1]!.reason).toContain('digits')
    expect(result.failures[2]!.reason).toContain('period')
    expect(result.failures[3]!.reason).toContain('counter')
    expect(result.failures[4]!.reason).toContain('不受支持')
    expect(result.failures[5]!.reason).toContain('name')

    expect(result.warnings).toHaveLength(1)
    expect(result.warnings[0]!.sourceIndex).toBe(2)
  })

  it('legacy 分组夹具 aegis_plain_grouped_v2.json 解析成功', () => {
    const result = parseAegis(fileBytes('aegis_plain_grouped_v2.json'))
    expect(result.entries).toHaveLength(6)
    expect(result.failures).toHaveLength(1)
  })

  it('空 entries 数组不抛错', () => {
    const result = parseAegis(wrap([]))
    expect(result).toMatchObject({
      format: 'aegis',
      entries: [],
      tags: [],
      failures: [],
      skipped: 0,
    })
  })
})

describe('parseAegis：整包结构性缺失抛 TransferFormatError（C5）', () => {
  const cases: [string, string][] = [
    ['不是 JSON', 'this is not json'],
    ['顶层是数组', '[1,2,3]'],
    ['顶层是字符串', '"aegis"'],
    ['缺 db', JSON.stringify({ version: 1, header: { slots: null } })],
    ['db 不是对象', JSON.stringify({ version: 1, db: 42 })],
    ['db.entries 不是数组', fileText('aegis_malformed.json')],
  ]

  for (const [name, text] of cases) {
    it(`${name} 抛 TransferFormatError`, () => {
      expect(() => parseAegis(text)).toThrow(TransferFormatError)
    })
  }

  it('db 为字符串（加密形态）时文案指向加密路径，而不是笼统的格式错误', () => {
    const encrypted = JSON.stringify({ version: 1, header: { slots: [{}] }, db: 'QUJDRA==' })
    expect(() => parseAegis(encrypted)).toThrow(TransferFormatError)
    try {
      parseAegis(encrypted)
    } catch (error) {
      expect((error as Error).message).toContain('加密')
      expect((error as Error).message).toContain('主密码')
      expect((error as Error).message).not.toContain('不是合法的 JSON')
    }
  })

  it('单条缺 info 只记 failure，不整包失败', () => {
    const broken = entry()
    delete broken.info
    const result = parseAegis(wrap([entry(), broken]))
    expect(result.entries).toHaveLength(1)
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0]!.reason).toContain('info')
  })

  it('单条不是对象只记 failure', () => {
    const result = parseAegis(wrap([entry(), 42, null]))
    expect(result.entries).toHaveLength(1)
    expect(result.failures.map((f) => f.sourceIndex)).toEqual([1, 2])
  })

  it('超过字节上限抛 TransferFormatError', () => {
    const huge = new Uint8Array(TRANSFER_LIMITS.maxInputBytes + 1)
    expect(() => parseAegis(huge)).toThrow(TransferFormatError)
    expect(() => parseAegis(huge)).toThrow(/超过上限/)
  })

  it('超过条目上限抛 TransferFormatError', () => {
    const entries = Array.from({ length: TRANSFER_LIMITS.maxEntries + 1 }, () => null)
    expect(() => parseAegis(wrap(entries))).toThrow(/超过上限/)
  })
})

describe('C4：错误文案不泄露 secret', () => {
  const SECRET_FORMS = [
    '4SJHB4GSD43FZBAI7C2HLRJGPQ',
    '4sjhb4gsd43fzbai7c2hlrjgpq',
    'e49270f0d21f365c8408f8b475c5267c',
    '5JJw8NIfNlyECPi0dcUmfA==',
  ]

  const messages = (name: string): string[] => {
    const result = parseAegis(fileBytes(name))
    return [...result.failures.map((f) => f.reason), ...result.warnings.map((w) => w.message)]
  }

  it('边界夹具的全部 failure / warning 文案都不含 secret 的任何编码形式', () => {
    const all = [...messages('aegis_edge.json'), ...messages('aegis_plain.json')]
    expect(all.length).toBeGreaterThan(0)
    for (const message of all) {
      for (const form of SECRET_FORMS) {
        expect(message).not.toContain(form)
      }
    }
  })

  it('secret 非法时的文案只说「不合法」，不回显内容', () => {
    const result = parseAegis(
      wrap([entry({ info: { secret: '!!!not-base32!!!', algo: 'SHA1', digits: 6, period: 30 } })]),
    )
    expect(result.failures[0]!.reason).toContain('base32')
    for (const form of ['!!!not-base32!!!', 'not-base32']) {
      expect(result.failures[0]!.reason).not.toContain(form)
    }
  })

  it('整包失败抛出的异常也不含 secret', () => {
    const text = fileText('aegis_malformed.json')
    try {
      parseAegis(text)
      expect.unreachable('应当抛错')
    } catch (error) {
      for (const form of ['4SJHB4GSD43FZBAI7C2HLRJGPQ', 'e49270f0d21f365c8408f8b475c5267c']) {
        expect((error as Error).message).not.toContain(form)
      }
    }
  })
})

describe('parseAegis：纯函数', () => {
  it('同一输入连续两次结果相同，且不修改入参', () => {
    const bytes = fileBytes('aegis_grouped_v3.json')
    const snapshot = Uint8Array.from(bytes)
    const first = parseAegis(bytes)
    const second = parseAegis(bytes)
    expect(golden(first.entries)).toEqual(golden(second.entries))
    expect(first.tags).toEqual(second.tags)
    expect(first.failures).toEqual(second.failures)
    expect(first.warnings).toEqual(second.warnings)
    expect(bytes).toEqual(snapshot)
  })

  it('返回值不与入参共享结构：改动结果不影响下一次解析', () => {
    const text = fileText('aegis_plain_grouped_v2.json')
    const first = parseAegis(text)
    ;(first.entries[0]!.tagNames as string[]).push('污染')
    expect(parseAegis(text).entries[0]!.tagNames).toEqual(['group1'])
  })

  it('非 UTF-8 字节不抛异常，按损坏处理', () => {
    expect(() => parseAegis(Uint8Array.from([0xff, 0xfe, 0x7b, 0x7d]))).toThrow(TransferFormatError)
    expect(() => parseAegis(utf8Encode(''))).toThrow(TransferFormatError)
  })
})

describe('parseAegis：跨编码的字节相等（C10）', () => {
  it('同一密钥的 base32（Aegis）与 base64（本 App 明文容器）解码结果字节相同', () => {
    // `aegis_plain.json` 的 WWE:Mason 与 `mfavault_plaintext.json` 的第 2 条是同一个假密钥，
    // 一个写作 base32 `5VAML3X35THCEBVRLV24CGBKOY`，一个写作 base64 `7UDF7vvsziIGsV11wRgqdg==`。
    const fromAegis = parseAegis(fileBytes('aegis_plain.json')).entries[5]!
    expect(fromAegis).toMatchObject({ issuer: 'WWE', account: 'Mason' })
    expect(hex(fromAegis.secret)).toBe(hex(decodeBase64Secret('7UDF7vvsziIGsV11wRgqdg==')))
  })
})
