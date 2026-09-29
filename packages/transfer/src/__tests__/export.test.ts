import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { utf8Decode } from '@askdaddy/crypto'
import { base32Encode } from '@askdaddy/otp'
import { assertVaultData, VaultSchemaError, type Entry, type VaultData } from '@askdaddy/vault'
import { generateAegis, parseAegis } from '../aegis.js'
import { detect } from '../detect.js'
import { generateOtpAuthLines, parseOtpAuthLines } from '../otpauth.js'
import { decodeBase64Secret } from '../secret.js'
import { EXPORT_DEGRADATIONS } from '../types.js'
import type { ParsedEntry } from '../types.js'

/**
 * 步骤 17 的两个导出生成器与 §3.1 降级数据。
 *
 * 放在一个文件里而不是拆进 `aegis.test.ts` / `otpauth.test.ts`：两个生成器的往返断言共用同一套
 * 「从 vault 算出期望值」的推导（含 tagIds → tagNames 的解析），拆开会抄两遍。
 */

const fileText = (name: string): string =>
  readFileSync(new URL(`../__fixtures__/${name}`, import.meta.url), 'utf8')

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

const unseal = (bytes: Uint8Array): unknown => JSON.parse(utf8Decode(bytes)) as unknown

/** 已实测过 vault 真实守卫的合法数据：3 条目（1 totp + 2 hotp）、1 tag、含中文与空格。 */
const FIXTURE: VaultData = assertVaultData(
  (JSON.parse(fileText('mfavault_plaintext.json')) as { data: unknown }).data,
)

/** 夹具里的假 secret（AGENTS.md §5.3）在文本夹具中写作 base32 `4SJHB4GSD43FZBAI7C2HLRJGPQ`。 */
const DENO_BASE32 = '4SJHB4GSD43FZBAI7C2HLRJGPQ'

const vault = (patch: Record<string, unknown> = {}): VaultData =>
  assertVaultData({ ...FIXTURE, ...patch })

const entry = (patch: Record<string, unknown> = {}): Record<string, unknown> => ({
  ...FIXTURE.entries[0]!,
  ...patch,
})

/** 显示顺序：`position` 的字典序，与 `generateAegis` 的写出口径一致（§3.1 的 ⚠️ 数组顺序）。 */
const inDisplayOrder = <T extends { readonly position: string }>(items: readonly T[]): T[] =>
  [...items].sort((a, b) => (a.position < b.position ? -1 : a.position > b.position ? 1 : 0))

const tagNamesOf = (data: VaultData, tagIds: readonly string[]): string[] =>
  tagIds.flatMap((id) => {
    const tag = data.tags.find((candidate) => candidate.id === id)
    return tag === undefined ? [] : [tag.name]
  })

/** 从 vault 侧独立算出往返后应当看到的条目，避免「拿实现的输出当期望值」的自证。 */
const expected = (data: VaultData, source: Entry): Record<string, unknown> => ({
  issuer: source.issuer,
  account: source.account,
  secret: hex(decodeBase64Secret(source.secret)),
  algo: source.algo,
  digits: source.digits,
  kind: source.kind,
  note: source.note,
  tagNames: tagNamesOf(data, source.tagIds),
  ...(source.kind === 'totp' ? { period: source.period } : { counter: source.counter }),
})

const actual = (entries: readonly ParsedEntry[]): Record<string, unknown>[] =>
  entries.map((parsed) => ({
    issuer: parsed.issuer,
    account: parsed.account,
    secret: hex(parsed.secret),
    algo: parsed.algo,
    digits: parsed.digits,
    kind: parsed.kind,
    note: parsed.note,
    tagNames: [...parsed.tagNames],
    ...(parsed.kind === 'totp' ? { period: parsed.period } : { counter: parsed.counter }),
  }))

/** 递归收集 JSON 里出现过的**全部键名**，用于「不该出现的字段一个都没出现」这类断言。 */
const allKeys = (value: unknown, out = new Set<string>()): Set<string> => {
  if (Array.isArray(value)) {
    for (const item of value) allKeys(item, out)
    return out
  }
  if (typeof value === 'object' && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      out.add(key)
      allKeys(item, out)
    }
  }
  return out
}

interface AegisFile {
  version: number
  header: { slots: unknown; params: unknown }
  db: {
    version: number
    groups: { uuid: string; name: string }[]
    entries: {
      type: string
      uuid: string
      name: string
      issuer: string
      note: string
      groups: unknown[]
      info: { secret: string; algo: string; digits: number }
    }[]
  }
}

const aegisFile = (data: VaultData = FIXTURE): AegisFile => unseal(generateAegis(data)) as AegisFile

describe('generateAegis：外壳形态', () => {
  it('顶层为 version / header / db，明文的 slots 与 params 恒为 null', () => {
    const file = aegisFile()
    expect(Object.keys(file)).toEqual(['version', 'header', 'db'])
    expect(file.version).toBe(1)
    expect(file.header).toEqual({ slots: null, params: null })
  })

  it('db.version 写 3：分组表自 v3 起才存在', () => {
    expect(Object.keys(aegisFile().db)).toEqual(['version', 'groups', 'entries'])
    expect(aegisFile().db.version).toBe(3)
  })

  it('name 是账户、issuer 是服务商——与本 App 相反的字段名没有写反', () => {
    const first = FIXTURE.entries[0]!
    const written = aegisFile().db.entries[0]!
    expect(written.name).toBe(first.account)
    expect(written.issuer).toBe(first.issuer)
    expect(written.name).not.toBe(first.issuer)
  })

  it('uuid 沿用 Entry.id / Tag.id，不另造随机值', () => {
    const file = aegisFile()
    expect(file.db.groups.map((group) => group.uuid)).toEqual(FIXTURE.tags.map((tag) => tag.id))
    expect(file.db.entries.map((item) => item.uuid)).toEqual(
      inDisplayOrder(FIXTURE.entries).map((item) => item.id),
    )
  })
})

describe('generateAegis：secret 编码', () => {
  it('写 base32 大写且不带 padding', () => {
    for (const written of aegisFile().db.entries) {
      expect(written.info.secret, written.info.secret).toMatch(/^[A-Z2-7]+$/)
      expect(written.info.secret).not.toContain('=')
    }
  })

  it('与 base32Encode 去掉 padding 的结果逐字符相同', () => {
    const sources = inDisplayOrder(FIXTURE.entries)
    aegisFile().db.entries.forEach((written, index) => {
      const source = sources[index]!
      expect(written.info.secret).toBe(
        base32Encode(decodeBase64Secret(source.secret)).replaceAll('=', ''),
      )
    })
  })

  it('夹具里那条 Deno 的 secret 写成已知的 base32 字面量', () => {
    expect(aegisFile().db.entries[0]!.info.secret).toBe(DENO_BASE32)
  })
})

describe('generateAegis：标签形态', () => {
  it('db.groups 是 {uuid,name} 对象数组，不是字符串数组', () => {
    const groups = aegisFile().db.groups
    expect(groups.length).toBeGreaterThan(0)
    for (const group of groups) {
      expect(typeof group).toBe('object')
      expect(Object.keys(group).sort()).toEqual(['name', 'uuid'])
    }
    expect(groups[0]).toEqual({ uuid: FIXTURE.tags[0]!.id, name: FIXTURE.tags[0]!.name })
  })

  it('entries[].groups 是 uuid 引用，不是标签名', () => {
    const file = aegisFile()
    const names = new Set(file.db.groups.map((group) => group.name))
    const referenced = file.db.entries.flatMap((item) => item.groups)
    expect(referenced.length).toBeGreaterThan(0)
    for (const ref of referenced) {
      expect(typeof ref).toBe('string')
      expect(names.has(ref as string), String(ref)).toBe(false)
      expect(file.db.groups.map((group) => group.uuid)).toContain(ref)
    }
  })

  it('未被任何条目引用的标签也要写进 db.groups', () => {
    const data = vault({
      tags: [
        ...FIXTURE.tags,
        {
          ...FIXTURE.tags[0]!,
          id: '019c0f6a-0000-7000-8000-0000000000ff',
          name: '空分组',
          position: 'a9',
        },
      ],
    })
    const file = aegisFile(data)
    expect(file.db.groups.map((group) => group.name)).toEqual(['工作', '空分组'])
    expect(file.db.entries.flatMap((item) => item.groups)).not.toContain(
      '019c0f6a-0000-7000-8000-0000000000ff',
    )
    expect(parseAegis(generateAegis(data)).tags.map((tag) => tag.name)).toEqual(['工作', '空分组'])
  })

  it('指向不存在标签的 tagIds 被丢掉，条目本身照常导出', () => {
    const data = vault({
      entries: [
        entry({
          tagIds: [FIXTURE.tags[0]!.id, 'no-such-tag'],
          id: '019c0f6a-0000-7000-8000-000000000009',
        }),
      ],
    })
    const file = aegisFile(data)
    expect(file.db.entries[0]!.groups).toEqual([FIXTURE.tags[0]!.id])
    const result = parseAegis(generateAegis(data))
    expect(result.failures).toEqual([])
    expect(result.entries[0]!.tagNames).toEqual(['工作'])
  })
})

describe('generateAegis：丢弃字段', () => {
  it('§3.1 判 ❌ 的字段与上游不导出的下划线字段一个都不出现', () => {
    const keys = allKeys(aegisFile())
    for (const forbidden of [
      'sites',
      'position',
      'usageCount',
      'lastUsedAt',
      'favorite',
      '_usageCount',
      '_lastUsedTimestamp',
      'id',
      'tagIds',
      'createdAt',
      'updatedAt',
      'color',
    ]) {
      expect(keys, forbidden).not.toContain(forbidden)
    }
  })

  it('产物的键集合恰好是 Aegis 的那一套（钉住 icon / icon_mime 与上游样本同形）', () => {
    expect([...allKeys(aegisFile())].sort()).toEqual(
      [
        'algo',
        'counter',
        'db',
        'digits',
        'entries',
        'groups',
        'header',
        'icon',
        'icon_mime',
        'info',
        'issuer',
        'name',
        'note',
        'params',
        'period',
        'secret',
        'slots',
        'type',
        'uuid',
        'version',
      ].sort(),
    )
  })
})

describe('generateAegis：顺序与纯函数', () => {
  it('按 position 的字典序写出，而不是照抄 entries 的数组顺序', () => {
    const shuffled = vault({
      entries: [
        entry({ id: '019c0f6a-0000-7000-8000-000000000001', position: 'a2', issuer: '第三' }),
        entry({ id: '019c0f6a-0000-7000-8000-000000000002', position: 'a0', issuer: '第一' }),
        entry({ id: '019c0f6a-0000-7000-8000-000000000003', position: 'a1', issuer: '第二' }),
      ],
    })
    expect(aegisFile(shuffled).db.entries.map((item) => item.issuer)).toEqual([
      '第一',
      '第二',
      '第三',
    ])
  })

  it('标签也按 position 排序', () => {
    const data = vault({
      tags: [
        {
          ...FIXTURE.tags[0]!,
          id: '019c0f6a-0000-7000-8000-00000000000b',
          name: '乙',
          position: 'a1',
        },
        {
          ...FIXTURE.tags[0]!,
          id: '019c0f6a-0000-7000-8000-00000000000a',
          name: '甲',
          position: 'a0',
        },
      ],
    })
    expect(aegisFile(data).db.groups.map((group) => group.name)).toEqual(['甲', '乙'])
  })

  it('同一 VaultData 连续调用两次产出逐字节相同', () => {
    expect(generateAegis(FIXTURE)).toEqual(generateAegis(FIXTURE))
  })

  it('不改动传入的 vault', () => {
    const before = JSON.stringify(FIXTURE)
    generateAegis(FIXTURE)
    expect(JSON.stringify(FIXTURE)).toBe(before)
  })
})

describe('generateAegis：边界', () => {
  it('空 entries 与空 tags 产出合法的空调用结果，不抛错', () => {
    const data = vault({ entries: [], tags: [] })
    const file = aegisFile(data)
    expect(file.db.entries).toEqual([])
    expect(file.db.groups).toEqual([])
    const result = parseAegis(generateAegis(data))
    expect(result.entries).toEqual([])
    expect(result.tags).toEqual([])
    expect(result.failures).toEqual([])
  })

  it('对非法 VaultData 抛错而不是产出文件', () => {
    expect(() => generateAegis(vault({ entries: [entry({ digits: 9 })] }))).toThrow(
      VaultSchemaError,
    )
  })

  it('issuer / account / note 为空串时照样写出，往返后仍是空串', () => {
    const data = vault({ entries: [entry({ issuer: '', account: '', note: '', tagIds: [] })] })
    const written = aegisFile(data).db.entries[0]!
    expect([written.issuer, written.name, written.note]).toEqual(['', '', ''])
    const result = parseAegis(generateAegis(data))
    expect(result.failures).toEqual([])
    expect([
      result.entries[0]!.issuer,
      result.entries[0]!.account,
      result.entries[0]!.note,
    ]).toEqual(['', '', ''])
  })
})

describe('generateAegis → parseAegis：双向迁移往返', () => {
  it('夹具的 9 个字段全部一致', () => {
    const result = parseAegis(generateAegis(FIXTURE))
    expect(result.failures).toEqual([])
    expect(result.warnings).toEqual([])
    expect(result.skipped).toBe(0)
    expect(result.format).toBe('aegis')
    expect(actual(result.entries)).toEqual(
      inDisplayOrder(FIXTURE.entries).map((source) => expected(FIXTURE, source)),
    )
  })

  it('标签名往返一致，顺序也一致', () => {
    const result = parseAegis(generateAegis(FIXTURE))
    expect(result.tags.map((tag) => tag.name)).toEqual(FIXTURE.tags.map((tag) => tag.name))
  })

  it('构造出来的边界 vault（中文 issuer、含冒号账户、7/8 位、SHA256/512、period 50）同样往返', () => {
    const data = vault({
      tags: [
        {
          id: '019c0f6a-0000-7000-8000-00000000000a',
          name: '工作',
          color: '#5B8DEF',
          position: 'a0',
        },
        {
          id: '019c0f6a-0000-7000-8000-00000000000b',
          name: 'a:b',
          color: '#000000',
          position: 'a1',
        },
      ],
      entries: [
        entry({
          id: '019c0f6a-0000-7000-8000-000000000011',
          kind: 'totp',
          issuer: '航空 Air Canada',
          account: 'ben:jamín@example.com',
          secret: '5JJw8NIfNlyECPi0dcUmfA==',
          algo: 'SHA256',
          digits: 7,
          period: 50,
          counter: undefined,
          note: '含 "引号" 与\n换行',
          tagIds: ['019c0f6a-0000-7000-8000-00000000000a', '019c0f6a-0000-7000-8000-00000000000b'],
          position: 'a0',
        }),
        entry({
          id: '019c0f6a-0000-7000-8000-000000000012',
          kind: 'hotp',
          issuer: '',
          account: '',
          algo: 'SHA512',
          digits: 8,
          counter: 0,
          period: undefined,
          note: '',
          tagIds: [],
          position: 'a1',
        }),
      ],
    })
    const result = parseAegis(generateAegis(data))
    expect(result.failures).toEqual([])
    expect(actual(result.entries)).toEqual(data.entries.map((source) => expected(data, source)))
    expect(result.tags.map((tag) => tag.name)).toEqual(['工作', 'a:b'])
  })

  it('生成的文件能被格式探测器认成 aegis', () => {
    expect(detect(generateAegis(FIXTURE))).toBe('aegis')
  })
})

describe('generateOtpAuthLines', () => {
  const lines = (data: VaultData = FIXTURE): string[] => generateOtpAuthLines(data).split('\n')

  it('每行一个 URI，行数等于条目数', () => {
    const text = generateOtpAuthLines(FIXTURE)
    expect(text.split('\n')).toHaveLength(FIXTURE.entries.length)
    expect(text.endsWith('\n')).toBe(false)
    for (const line of lines()) expect(line.startsWith('otpauth://')).toBe(true)
  })

  it('host 就是 kind，totp 带 period、hotp 带 counter', () => {
    const [totp, hotp] = lines()
    expect(totp!.startsWith('otpauth://totp/')).toBe(true)
    expect(hotp!.startsWith('otpauth://hotp/')).toBe(true)
    expect(totp).toContain('&period=30')
    expect(totp).not.toContain('counter=')
    expect(hotp).toContain('&counter=10300')
    expect(hotp).not.toContain('period=')
  })

  it('secret 无 = padding，其余参数全部显式写出', () => {
    for (const line of lines()) {
      const query = new Map(
        line
          .slice(line.indexOf('?') + 1)
          .split('&')
          .map((pair) => {
            const at = pair.indexOf('=')
            return [pair.slice(0, at), pair.slice(at + 1)] as const
          }),
      )
      expect(query.get('secret')).toMatch(/^[A-Z2-7]+$/)
      for (const key of ['secret', 'issuer', 'algorithm', 'digits']) {
        expect(query.has(key), key).toBe(true)
      }
      expect(query.has('period') || query.has('counter')).toBe(true)
    }
  })

  it('secret 与第一条的已知 base32 字面量一致', () => {
    expect(lines()[0]).toContain(`secret=${DENO_BASE32}`)
  })

  it('label 经 percent-encode：空格、冒号与非 ASCII 都不是裸字符', () => {
    const data = vault({
      entries: [
        entry({
          issuer: '航空 Air Canada',
          account: 'ben:jamín@example.com',
          tagIds: [],
        }),
      ],
    })
    const line = lines(data)[0]!
    const label = line.slice('otpauth://totp/'.length, line.indexOf('?'))
    expect(label).toBe(
      `${encodeURIComponent('航空 Air Canada')}:${encodeURIComponent('ben:jamín@example.com')}`,
    )
    expect(label).toContain('%3A')
    expect(label).toContain('%20')
    expect(label).not.toContain(' ')
    expect(line).toContain(`issuer=${encodeURIComponent('航空 Air Canada')}`)
  })

  it('issuer 在 label 与 query 两处都写；空 issuer 也显式写出 issuer=', () => {
    expect(lines()[0]).toContain('otpauth://totp/Deno:Mason?')
    const empty = lines(vault({ entries: [entry({ issuer: '', account: 'a:b', tagIds: [] })] }))[0]!
    expect(empty).toContain('issuer=&')
    expect(empty).toContain(`otpauth://totp/${encodeURIComponent('a:b')}?`)
  })

  it('行序就是 entries 的数组顺序：§3.1 对本格式把 position 判为 ❌', () => {
    const data = vault({
      entries: [
        entry({ position: 'a2', issuer: 'third' }),
        entry({ position: 'a0', issuer: 'first' }),
      ],
    })
    // label 里就带着 issuer 前缀，且整行第一个 ':' 属 `otpauth://`，故只在 label 内部找分隔符。
    const issuers = lines(data).map((line) => {
      const label = line.slice('otpauth://totp/'.length, line.indexOf('?'))
      return decodeURIComponent(label.slice(0, label.indexOf(':')))
    })
    expect(issuers).toEqual(['third', 'first'])
  })

  it('纯函数：同一 VaultData 连续调用两次逐字符相同', () => {
    expect(generateOtpAuthLines(FIXTURE)).toBe(generateOtpAuthLines(FIXTURE))
  })

  it('不改动传入的 vault', () => {
    const before = JSON.stringify(FIXTURE)
    generateOtpAuthLines(FIXTURE)
    expect(JSON.stringify(FIXTURE)).toBe(before)
  })

  it('空 entries 产出空串，行式解析给出 0 条目且不抛错', () => {
    const text = generateOtpAuthLines(vault({ entries: [] }))
    expect(text).toBe('')
    const result = parseOtpAuthLines(text)
    expect(result.entries).toEqual([])
    expect(result.failures).toEqual([])
  })

  it('对非法 VaultData 抛错而不是产出文本', () => {
    expect(() => generateOtpAuthLines(vault({ entries: [entry({ digits: 9 })] }))).toThrow(
      VaultSchemaError,
    )
  })
})

describe('generateOtpAuthLines → parseOtpAuthLines：往返无损', () => {
  const roundTrip = (data: VaultData): Record<string, unknown>[] => {
    const result = parseOtpAuthLines(generateOtpAuthLines(data))
    expect(result.failures).toEqual([])
    expect(result.warnings).toEqual([])
    expect(result.format).toBe('otpauth-lines')
    return actual(result.entries)
  }

  it('夹具的 7 个字段全部还原', () => {
    // §3.1：note 与 tags 对本格式是 ❌，故往返后必然是空值——这正是 EXPORT_DEGRADATIONS 登记的两项。
    expect(roundTrip(FIXTURE)).toEqual(
      FIXTURE.entries.map((source) => ({ ...expected(FIXTURE, source), note: '', tagNames: [] })),
    )
  })

  it('中文 issuer、含冒号账户、空 issuer、7/8 位与 SHA256/512 同样还原', () => {
    const data = vault({
      entries: [
        entry({
          id: '019c0f6a-0000-7000-8000-000000000021',
          kind: 'totp',
          issuer: '航空 Air Canada',
          account: 'ben:jamín@example.com',
          algo: 'SHA256',
          digits: 7,
          period: 50,
          counter: undefined,
          position: 'a0',
        }),
        entry({
          id: '019c0f6a-0000-7000-8000-000000000022',
          kind: 'hotp',
          issuer: '',
          account: 'a:b:c',
          algo: 'SHA512',
          digits: 8,
          counter: 0,
          period: undefined,
          position: 'a1',
        }),
      ],
    })
    expect(roundTrip(data)).toEqual(
      data.entries.map((source) => ({
        ...expected(data, source),
        note: '',
        tagNames: [],
      })),
    )
  })
})

describe('EXPORT_DEGRADATIONS：§3.1 降级表的数据形态', () => {
  it('aegis 行与 §3.1 逐格对应', () => {
    expect([...EXPORT_DEGRADATIONS.aegis.dropped]).toEqual([
      'sites',
      'usageCount',
      'lastUsedAt',
      'favorite',
    ])
    expect([...EXPORT_DEGRADATIONS.aegis.degraded]).toEqual(['position'])
  })

  it('otpauth-lines 行与 §3.1 逐格对应', () => {
    expect([...EXPORT_DEGRADATIONS['otpauth-lines'].dropped].sort()).toEqual(
      ['note', 'tagIds', 'sites', 'usageCount', 'lastUsedAt', 'position', 'favorite'].sort(),
    )
    expect(EXPORT_DEGRADATIONS['otpauth-lines'].degraded).toEqual([])
  })

  it('Aegis 判 ✅ 的字段不在 dropped 里', () => {
    const dropped = new Set<string>(EXPORT_DEGRADATIONS.aegis.dropped)
    for (const kept of ['issuer', 'account', 'secret', 'algo', 'digits', 'note', 'tagIds']) {
      expect(dropped.has(kept), kept).toBe(false)
    }
  })

  it('每个字段名都是 Entry 上真实存在的键，dropped 与 degraded 不重叠', () => {
    const real = new Set(Object.keys(FIXTURE.entries[0]!))
    for (const degradation of Object.values(EXPORT_DEGRADATIONS)) {
      const dropped = new Set<string>(degradation.dropped)
      const degraded = new Set<string>(degradation.degraded)
      for (const field of [...dropped, ...degraded]) {
        expect(real.has(field), field).toBe(true)
        expect(dropped.has(field) && degraded.has(field), field).toBe(false)
      }
    }
  })
})
