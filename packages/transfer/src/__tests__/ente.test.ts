import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { utf8Encode } from '@askdaddy/crypto'
import { parseEnte } from '../ente.js'
import { TransferFormatError } from '../errors.js'
import { TRANSFER_LIMITS } from '../input.js'
import { parseOtpAuthLines } from '../otpauth.js'
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

/** 上游 `CodeDisplay.toJson()` 的 9 个字段（`code_display.dart:112-124`）。 */
const FULL_DISPLAY: Record<string, unknown> = {
  pinned: false,
  trashed: false,
  lastUsedAt: 0,
  tapCount: 0,
  tags: [],
  note: '',
  position: 0,
  iconSrc: 'ente',
  iconID: '',
}

/** `ente_auth.txt` 用的旧形态：只有前 5 个字段，没有 note / position / iconSrc / iconID。 */
const LEGACY_DISPLAY: Record<string, unknown> = {
  pinned: false,
  trashed: false,
  lastUsedAt: 0,
  tapCount: 0,
  tags: [],
}

const displayParam = (fields: Record<string, unknown>): string =>
  `codeDisplay=${encodeURIComponent(JSON.stringify(fields))}`

const BASE_QUERY = 'algorithm=SHA1&digits=6&period=30&issuer=Deno&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ'

const totpLine = (query = BASE_QUERY, fields?: Record<string, unknown>): string =>
  `otpauth://totp/Deno:Mason?${query}${fields === undefined ? '' : `&${displayParam(fields)}`}`

/** 把若干行拼成一份导出文本，顺带覆盖「空行要被跳过」。 */
const file = (...lines: readonly string[]): string => lines.join('\n')

/** `pinned` / `tapCount` / `lastUsedAt` / `iconSrc` / `iconID` 的 warning 文案是同一句。 */
const UNMAPPED_MESSAGE = '该字段未导入（本 App 暂不保留这项信息）'

const unmapped = (sourceIndex: number, fields: readonly string[]): string[] =>
  fields.map((field) => `${sourceIndex}:codeDisplay.${field}`)

const keys = (warnings: readonly { sourceIndex: number | null; field: string }[]): string[] =>
  warnings.map((warning) => `${warning.sourceIndex}:${warning.field}`)

describe('parseEnte：golden 快照', () => {
  it('vendored 的 ente_auth.txt（旧 5 字段 codeDisplay）解出 6 条，steam 行判为单条失败', () => {
    const result = parseEnte(fileBytes('ente_auth.txt'))
    expect(result.format).toBe('ente')
    expect(result.tags).toEqual([])
    expect(result.skipped).toBe(0)
    expect(golden(result.entries)).toEqual([
      {
        sourceIndex: 0,
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
        sourceIndex: 1,
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
        sourceIndex: 4,
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
        sourceIndex: 5,
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
        sourceIndex: 6,
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
    expect(result.failures).toEqual([
      {
        sourceIndex: 2,
        path: 'Ente 明文导出 第 3 行',
        reason: '该令牌类型不受支持："steam"，本 App 只支持 TOTP 与 HOTP',
      },
    ])
    // 旧形态没有 iconSrc / iconID，故每条只有 3 条未导入告警。
    expect(keys(result.warnings)).toEqual(
      [0, 1, 3, 4, 5, 6].flatMap((index) => unmapped(index, ['pinned', 'tapCount', 'lastUsedAt'])),
    )
    expect(new Set(result.warnings.map((warning) => warning.message))).toEqual(
      new Set([UNMAPPED_MESSAGE]),
    )
  })

  it('末行 algorithm=sha512 小写：同一文件内大小写混用也全部正确归一化', () => {
    const result = parseEnte(fileBytes('ente_auth.txt'))
    expect(result.entries.map((entry) => entry.algo)).toEqual([
      'SHA256',
      'SHA512',
      'SHA1',
      'SHA1',
      'SHA256',
      'SHA512',
    ])
  })

  it('ente_jsonlines.txt：整行是带引号的 JSON 字符串，按 position 排序后解出 3 条', () => {
    const result = parseEnte(fileBytes('ente_jsonlines.txt'))
    expect(result.failures).toEqual([])
    expect(result.skipped).toBe(0)
    expect(golden(result.entries)).toEqual([
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
        issuer: 'Air Canada',
        account: 'Benjamin',
        kind: 'hotp',
        algo: 'SHA256',
        digits: 7,
        secret: '552a94b99feed079b472cd44d52fe642',
        note: 'label 里是裸空格',
        tagNames: [],
        favorite: false,
        counter: 50,
      },
      {
        sourceIndex: 0,
        issuer: 'Deno',
        account: 'Mason',
        kind: 'totp',
        algo: 'SHA1',
        digits: 6,
        secret: 'e49270f0d21f365c8408f8b475c5267c',
        note: '',
        tagNames: ['工作'],
        favorite: false,
        period: 30,
      },
    ])
    // 9 字段全量形态：5 个未映射字段各一条，共 3 × 5。
    expect(keys(result.warnings)).toEqual(
      [0, 1, 2].flatMap((index) =>
        unmapped(index, ['pinned', 'tapCount', 'lastUsedAt', 'iconSrc', 'iconID']),
      ),
    )
  })

  it('ente_edge.txt：11 行 → 8 条成功 + 1 跳过 + 2 失败，顺序由 position 决定', () => {
    const result = parseEnte(fileBytes('ente_edge.txt'))
    expect(result.skipped).toBe(1)
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([2, 3, 4, 6, 7, 8, 10, 0])
    expect(result.failures).toEqual([
      expect.objectContaining({ sourceIndex: 5, path: 'Ente 明文导出 第 6 行' }),
      expect.objectContaining({ sourceIndex: 9, path: 'Ente 明文导出 第 10 行' }),
    ])
    expect(result.failures[0]?.reason).toContain('不受支持')
    expect(result.failures[1]?.reason).toBe('URI 缺少 secret 参数')
    // 唯一一条 position 非 0 的（第 1 行，position=3）被排到末尾，note / tags 完整还原。
    expect(golden(result.entries.slice(-1))).toEqual([
      {
        sourceIndex: 0,
        issuer: 'Deno',
        account: 'Mason',
        kind: 'totp',
        algo: 'SHA1',
        digits: 6,
        secret: 'e49270f0d21f365c8408f8b475c5267c',
        note: '九字段 codeDisplay',
        tagNames: ['工作', '个人'],
        favorite: false,
        period: 30,
      },
    ])
    expect(keys(result.warnings)).toEqual([
      ...unmapped(0, ['pinned', 'tapCount', 'lastUsedAt', 'iconSrc', 'iconID']),
      '1:codeDisplay.trashed',
      ...unmapped(2, ['pinned', 'tapCount', 'lastUsedAt', 'iconSrc', 'iconID']),
      ...unmapped(3, ['pinned', 'tapCount', 'lastUsedAt', 'iconSrc', 'iconID']),
      ...unmapped(4, ['pinned', 'tapCount', 'lastUsedAt', 'iconSrc', 'iconID']),
      '6:codeDisplay',
      '7:codeDisplay.pinned',
      '8:codeDisplay.pinned',
    ])
  })

  it('ente_edge.txt 覆盖上游的四种 algorithm 泄漏/大小写形态', () => {
    const result = parseEnte(fileBytes('ente_edge.txt'))
    const algoOf = (issuer: string): string | undefined =>
      result.entries.find((entry) => entry.issuer === issuer)?.algo
    expect(algoOf('WWE')).toBe('SHA512') // algorithm=sha512
    expect(algoOf('SPDX')).toBe('SHA256') // algorithm=algorithm.sha256（Dart 枚举泄漏）
    expect(algoOf('Air Canada')).toBe('SHA256') // algorithm=Algorithm.SHA256
    expect(algoOf('Fragment')).toBe('SHA1')
  })
})

describe('parseEnte：两条导出路径', () => {
  it('裸 URI 行与带引号的 JSON 行可以混在同一份文件里', () => {
    const quoted = JSON.stringify(totpLine(BASE_QUERY, { ...FULL_DISPLAY, note: '带引号' }))
    const result = parseEnte(file(totpLine(BASE_QUERY, { ...FULL_DISPLAY, note: '裸行' }), quoted))
    expect(result.entries.map((entry) => entry.note)).toEqual(['裸行', '带引号'])
    expect(result.failures).toEqual([])
  })

  it('带引号的行不会被当成 URI 而静默失败（与 parseOtpAuthLines 对照）', () => {
    const quoted = JSON.stringify(totpLine(BASE_QUERY, LEGACY_DISPLAY))
    expect(parseOtpAuthLines(quoted).failures).toHaveLength(1)
    const result = parseEnte(quoted)
    expect(result.failures).toEqual([])
    expect(result.entries).toHaveLength(1)
  })

  it('引号行内的转义与非 ASCII 都能还原', () => {
    const quoted = JSON.stringify(
      totpLine(BASE_QUERY, { ...FULL_DISPLAY, note: 'A&B=C 中文 "引号" \\反斜杠' }),
    )
    // note 是百分号编码后才进 query 的，故外层 JSON 里不会出现转义引号；
    // 这里要钉住的是「整行被一对引号包住」这个上游 `jsonEncode` 的外壳形态。
    expect(quoted.startsWith('"') && quoted.endsWith('"')).toBe(true)
    expect(quoted).not.toContain('\\"')
    const result = parseEnte(quoted)
    expect(result.entries[0]?.note).toBe('A&B=C 中文 "引号" \\反斜杠')
  })

  it('以引号开头但不是合法 JSON 的行判为单条失败，不牵连其他行', () => {
    const result = parseEnte(file('"otpauth://broken', totpLine()))
    expect(result.entries).toHaveLength(1)
    expect(result.failures).toEqual([
      expect.objectContaining({ sourceIndex: 0, path: 'Ente 明文导出 第 1 行' }),
    ])
  })

  it('不带引号的行原样按 URI 解析，其中的字面引号不会被 JSON 解析器吃掉', () => {
    // label 段是路径而非 query，`"` 在其中是字面字符；`unwrapJsonLine` 只看行首，
    // 故这一行绝不会进 JSON.parse。
    const result = parseEnte(
      'otpauth://totp/Den:"b"?algorithm=SHA1&digits=6&period=30&issuer=Den&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ',
    )
    expect(result.failures).toEqual([])
    expect(result.entries[0]?.account).toBe('"b"')
  })
})

describe('parseEnte：codeDisplay 的映射', () => {
  it('note → ParsedEntry.note，tags → tagNames', () => {
    const result = parseEnte(
      totpLine(BASE_QUERY, { ...FULL_DISPLAY, note: '一条备注', tags: ['工作', '个人'] }),
    )
    expect(result.entries[0]).toMatchObject({ note: '一条备注', tagNames: ['工作', '个人'] })
  })

  it('codeDisplay 缺失是合法形态，不产生任何 codeDisplay 相关 warning', () => {
    const result = parseEnte(totpLine())
    expect(result.entries).toHaveLength(1)
    expect(result.entries[0]).toMatchObject({ note: '', tagNames: [] })
    expect(result.warnings).toEqual([])
  })

  it('旧 5 字段形态不因缺 note / position / iconSrc / iconID 而失败', () => {
    const result = parseEnte(totpLine(BASE_QUERY, LEGACY_DISPLAY))
    expect(result.failures).toEqual([])
    expect(result.entries[0]).toMatchObject({ note: '', tagNames: [] })
    expect(keys(result.warnings)).toEqual(unmapped(0, ['pinned', 'tapCount', 'lastUsedAt']))
  })

  it('只有 pinned 一个字段时也只报那一条', () => {
    const result = parseEnte(totpLine(BASE_QUERY, { pinned: true }))
    expect(keys(result.warnings)).toEqual(['0:codeDisplay.pinned'])
  })

  it('5 个未映射字段各产生一条 warning，且 pinned 不进 favorite', () => {
    const result = parseEnte(totpLine(BASE_QUERY, { ...FULL_DISPLAY, pinned: true, tapCount: 9 }))
    expect(keys(result.warnings)).toEqual(
      unmapped(0, ['pinned', 'tapCount', 'lastUsedAt', 'iconSrc', 'iconID']),
    )
    expect(result.entries[0]?.favorite).toBe(false)
  })

  it('未知字段（上游没有的键）不报 warning，只有已知的 5 个才报', () => {
    const result = parseEnte(totpLine(BASE_QUERY, { ...LEGACY_DISPLAY, somethingNew: 1 }))
    expect(keys(result.warnings)).toEqual(unmapped(0, ['pinned', 'tapCount', 'lastUsedAt']))
  })

  it("照抄上游的 replaceAll('%2C', ',')：双重编码残留仍能解出 tags", () => {
    // URI 里写 %252C，query 解码一遍后剩下字面量 %2C —— 正是上游 `code_display.dart:84-87`
    // 要处理的老导出形态；不替换掉 jsonDecode 就会失败。
    const raw = 'codeDisplay=%7B%22pinned%22%3Afalse%252C%22tags%22%3A%5B%22x%22%5D%7D'
    const result = parseEnte(`otpauth://totp/Deno:Mason?${BASE_QUERY}&${raw}`)
    expect(result.failures).toEqual([])
    expect(result.entries[0]?.tagNames).toEqual(['x'])
    expect(result.warnings.filter((warning) => warning.field === 'codeDisplay')).toEqual([])
  })

  it('codeDisplay 后跟未转义的 # 片段时照常解析（片段已在 URI 层被切掉）', () => {
    const result = parseEnte(fileText('ente_edge.txt').split('\n')[8]!)
    expect(result.failures).toEqual([])
    expect(result.entries[0]?.issuer).toBe('Fragment')
  })
})

describe('parseEnte：trashed 跳过', () => {
  it('trashed 为 true 的条目被跳过并记 warning，计入 skipped 而非 failures', () => {
    const result = parseEnte(
      file(
        totpLine(BASE_QUERY, { ...FULL_DISPLAY, trashed: true }),
        totpLine(BASE_QUERY, { ...FULL_DISPLAY, trashed: false }),
      ),
    )
    expect(result.skipped).toBe(1)
    expect(result.entries).toHaveLength(1)
    expect(result.entries[0]?.sourceIndex).toBe(1)
    expect(result.failures).toEqual([])
    expect(
      keys(result.warnings.filter((warning) => warning.field === 'codeDisplay.trashed')),
    ).toEqual(['0:codeDisplay.trashed'])
  })

  it('被跳过的条目不再刷 5 条未映射告警（它根本没被导入）', () => {
    const result = parseEnte(totpLine(BASE_QUERY, { ...FULL_DISPLAY, trashed: true }))
    expect(keys(result.warnings)).toEqual(['0:codeDisplay.trashed'])
  })

  it('trashed 不是布尔值时按默认值处理（不跳过）并记 warning', () => {
    const result = parseEnte(totpLine(BASE_QUERY, { ...FULL_DISPLAY, trashed: 'true' }))
    expect(result.skipped).toBe(0)
    expect(result.entries).toHaveLength(1)
    expect(result.warnings[0]).toMatchObject({ sourceIndex: 0, field: 'codeDisplay' })
    expect(result.warnings[0]?.message).toContain('trashed')
  })
})

describe('parseEnte：position 只用于排序', () => {
  const at = (position: number, issuer: string): string =>
    `otpauth://totp/${issuer}:Mason?algorithm=SHA1&digits=6&period=30&issuer=${issuer}&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ&${displayParam({ position })}`

  it('按 position 升序输出，sourceIndex 仍是行序号', () => {
    const result = parseEnte(file(at(2, 'Two'), at(0, 'Zero'), at(1, 'One')))
    expect(result.entries.map((entry) => entry.issuer)).toEqual(['Zero', 'One', 'Two'])
    expect(result.entries.map((entry) => entry.sourceIndex)).toEqual([1, 2, 0])
  })

  it('position 的值不出现在 ParsedEntry 的任何字段里', () => {
    const result = parseEnte(file(at(7, 'Seven'), at(0, 'Zero')))
    for (const entry of result.entries) {
      expect(Object.keys(entry).sort()).toEqual([
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
    }
    // 改动 position 只改变顺序，不改变任何字段值：把两份结果按 sourceIndex 排回来后必须全等。
    const other = parseEnte(file(at(0, 'Seven'), at(7, 'Zero')))
    const byIndex = (entries: readonly ParsedEntry[]): unknown[] =>
      golden([...entries].sort((left, right) => left.sourceIndex - right.sourceIndex))
    expect(byIndex(result.entries)).toEqual(byIndex(other.entries))
  })

  it('position 相同时保持文件原序（稳定排序）', () => {
    const result = parseEnte(file(at(0, 'First'), at(0, 'Second'), at(0, 'Third')))
    expect(result.entries.map((entry) => entry.issuer)).toEqual(['First', 'Second', 'Third'])
  })

  it('没有 codeDisplay 的条目按 position=0 参与排序，不会被甩到最后', () => {
    const result = parseEnte(file(at(3, 'Placed'), totpLine()))
    expect(result.entries.map((entry) => entry.issuer)).toEqual(['Deno', 'Placed'])
  })

  it('负 position 排到最前（上游不校验符号，排序自然处理）', () => {
    const result = parseEnte(file(at(0, 'Zero'), at(-1, 'Negative')))
    expect(result.entries.map((entry) => entry.issuer)).toEqual(['Negative', 'Zero'])
  })

  it('position 不是整数时按默认值 0 处理并记 warning', () => {
    const result = parseEnte(
      file(
        totpLine(BASE_QUERY, { position: 3.5 }),
        totpLine(
          'algorithm=SHA1&digits=6&period=30&issuer=Other&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ',
          {
            position: 1,
          },
        ),
      ),
    )
    expect(result.entries.map((entry) => entry.issuer)).toEqual(['Deno', 'Other'])
    expect(result.warnings[0]?.message).toContain('position')
  })
})

describe('parseEnte：codeDisplay 非法时不丢弃可用密钥', () => {
  const broken = (value: string): string =>
    `otpauth://totp/Deno:Mason?${BASE_QUERY}&codeDisplay=${encodeURIComponent(value)}`

  it('不是合法 JSON 时条目仍解析成功并记一条 warning', () => {
    const result = parseEnte(broken('{"pinned":'))
    expect(result.failures).toEqual([])
    expect(result.entries).toHaveLength(1)
    expect(golden(result.entries)[0]).toMatchObject({ issuer: 'Deno', note: '', tagNames: [] })
    expect(keys(result.warnings)).toEqual(['0:codeDisplay'])
    expect(result.warnings[0]?.message).toContain('不是合法的 JSON')
  })

  it('解出来不是对象（数组 / 字符串 / null）时同样退回默认值 + warning', () => {
    for (const value of ['[]', '"text"', 'null', '7']) {
      const result = parseEnte(broken(value))
      expect(result.entries, value).toHaveLength(1)
      expect(keys(result.warnings), value).toEqual(['0:codeDisplay'])
      expect(result.warnings[0]?.message, value).toContain('不是 JSON 对象')
    }
  })

  it('超深嵌套的 codeDisplay 触发深度闸门，转成 warning 而不是崩溃', () => {
    const deep = `[${'['.repeat(TRANSFER_LIMITS.maxNestingDepth + 1)}]`
    const result = parseEnte(broken(deep))
    expect(result.entries).toHaveLength(1)
    expect(keys(result.warnings)).toEqual(['0:codeDisplay'])
  })

  it('note 类型不对时整个 codeDisplay 退回默认值（全有或全无，与上游 fromJson 抛错一致）', () => {
    const result = parseEnte(broken('{"note":7,"tags":["工作"],"position":2}'))
    expect(result.entries).toHaveLength(1)
    expect(result.entries[0]).toMatchObject({ note: '', tagNames: [] })
    expect(result.warnings[0]?.message).toContain('note')
    expect(result.warnings[0]?.message).toContain('全部丢失')
  })

  it('tags 不是数组、或元素不是字符串时同样退回默认值', () => {
    for (const value of ['{"tags":"工作"}', '{"tags":[1]}', '{"tags":{}}']) {
      const result = parseEnte(broken(value))
      expect(result.entries[0]?.tagNames, value).toEqual([])
      expect(result.warnings[0]?.message, value).toContain('tags')
    }
  })

  it('note 或 tag 超长时判为**单条失败**（maxFieldLength 是 vault 的硬约束，不降级成 warning）', () => {
    const long = 'a'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    const result = parseEnte(file(broken(JSON.stringify({ note: long })), totpLine()))
    expect(result.entries).toHaveLength(1)
    expect(result.entries[0]?.sourceIndex).toBe(1)
    expect(result.failures).toEqual([
      expect.objectContaining({ sourceIndex: 0, path: 'Ente 明文导出 第 1 行' }),
    ])
    expect(result.failures[0]?.reason).toContain('codeDisplay.note 长度为')
  })

  it('tags 里有一个超长元素时判为单条失败', () => {
    const long = 'a'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    const result = parseEnte(broken(JSON.stringify({ tags: ['ok', long] })))
    expect(result.failures[0]?.reason).toContain('codeDisplay.tags 长度为')
  })

  it('失败条目不会留下指向自己的 codeDisplay warning', () => {
    // 必须先产生 warning 再抛错，才走得到「局部 warning 随该条一起丢弃」这条路径：
    // `pinned` 触发未映射告警，随后 note 超长抛 TransferFormatError。
    const long = 'a'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    const result = parseEnte(
      file(
        broken(JSON.stringify({ pinned: true, note: long })),
        totpLine(BASE_QUERY, {
          pinned: true,
        }),
      ),
    )
    expect(result.entries).toHaveLength(1)
    expect(result.failures).toHaveLength(1)
    expect(keys(result.warnings)).toEqual(['1:codeDisplay.pinned'])
  })
})

describe('parseEnte：不复制上游的静默降级（C8）', () => {
  it('_getDigits 的 defaultDigits 兜底不复制：digits 缺失即单条失败', () => {
    const result = parseEnte(
      totpLine('algorithm=SHA1&period=30&issuer=Deno&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ'),
    )
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toBe('URI 缺少 digits 参数')
  })

  it('_getPeriod 的 defaultPeriod 兜底不复制：period 缺失即单条失败', () => {
    const result = parseEnte(
      totpLine('algorithm=SHA1&digits=6&issuer=Deno&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ'),
    )
    expect(result.failures[0]?.reason).toBe('URI 缺少 period 参数')
  })

  it('_getCounter 的「无 key 返回 0」不复制：counter 缺失即单条失败', () => {
    const result = parseEnte(
      'otpauth://hotp/Deno:Mason?algorithm=SHA1&digits=6&issuer=Deno&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ',
    )
    expect(result.failures[0]?.reason).toBe('URI 缺少 counter 参数')
  })

  it('_getCounter 解析失败返回 defaultPeriod(30) 的上游 bug 不复制', () => {
    const result = parseEnte(
      'otpauth://hotp/Deno:Mason?algorithm=SHA1&digits=6&counter=abc&issuer=Deno&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ',
    )
    expect(result.entries).toEqual([])
    expect(result.failures[0]?.reason).toContain('counter 必须是整数')
    expect(result.failures[0]?.reason).not.toContain('30')
  })

  it('_getAlgorithm 的 SHA1 兜底不复制：algorithm 缺失或无法识别都失败', () => {
    const missing = parseEnte(
      totpLine('digits=6&period=30&issuer=Deno&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ'),
    )
    expect(missing.failures[0]?.reason).toBe('URI 缺少 algorithm 参数')

    const unknown = parseEnte(
      totpLine('algorithm=SHA224&digits=6&period=30&issuer=Deno&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ'),
    )
    expect(unknown.entries).toEqual([])
    expect(unknown.failures[0]?.reason).toContain('无法识别的 algorithm')
  })

  it('steam host 报「不受支持」而非 digits 越界（normalizeKind 排在 digits 之前）', () => {
    const result = parseEnte(
      'otpauth://steam/Deno:Mason?algorithm=SHA1&digits=5&period=30&issuer=Deno&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ',
    )
    expect(result.failures[0]?.reason).toContain('该令牌类型不受支持')
    expect(result.failures[0]?.reason).not.toContain('digits')
  })
})

describe('parseEnte：算法归一化补充', () => {
  const withAlgo = (algo: string): string =>
    totpLine(`algorithm=${algo}&digits=6&period=30&issuer=Deno&secret=4SJHB4GSD43FZBAI7C2HLRJGPQ`)

  it('Hmac 前缀、连字符、大小写混写都能归一化', () => {
    const result = parseEnte(
      file(withAlgo('HmacSHA256'), withAlgo('SHA-512'), withAlgo('algorithm.sha1')),
    )
    expect(result.entries.map((entry) => entry.algo)).toEqual(['SHA256', 'SHA512', 'SHA1'])
  })

  it('MD5 降级为 SHA1 并记 warning', () => {
    const result = parseEnte(withAlgo('MD5'))
    expect(result.entries[0]?.algo).toBe('SHA1')
    expect(keys(result.warnings)).toEqual(['0:algorithm'])
    expect(result.warnings[0]?.message).toBe('原文是 MD5，已归一化为 SHA1')
  })
})

describe('parseEnte：整包闸门、C4 与纯函数', () => {
  it('空输入与纯空白输入返回空结果而不抛', () => {
    for (const text of ['', '   \n\n  ']) {
      const result = parseEnte(text)
      expect(result, text).toMatchObject({ format: 'ente', entries: [], failures: [], skipped: 0 })
      expect(result.warnings, text).toEqual([])
    }
  })

  it('单行超长时抛 TransferFormatError', () => {
    const long = totpLine(BASE_QUERY, { note: 'a'.repeat(TRANSFER_LIMITS.maxLineLength) })
    expect(long.length).toBeGreaterThan(TRANSFER_LIMITS.maxLineLength)
    expect(() => parseEnte(long)).toThrow(TransferFormatError)
    expect(() => parseEnte(long)).toThrow(/超过上限/)
  })

  it('行数超上限时抛 TransferFormatError', () => {
    const many = Array.from({ length: TRANSFER_LIMITS.maxEntries + 1 }, () => totpLine()).join('\n')
    expect(() => parseEnte(many)).toThrow(/超过上限/)
  })

  it('输入字节超上限时抛 TransferFormatError', () => {
    const huge = `${totpLine()}\n${'#'.repeat(TRANSFER_LIMITS.maxInputBytes)}`
    expect(() => parseEnte(utf8Encode(huge))).toThrow(/超过上限/)
  })

  it('接受字符串输入，与字节输入结果一致', () => {
    const text = fileText('ente_auth.txt')
    expect(golden(parseEnte(text).entries)).toEqual(golden(parseEnte(utf8Encode(text)).entries))
  })

  it('C4：失败与告警文案里不含 secret 的原文或 hex', () => {
    const secret = '4SJHB4GSD43FZBAI7C2HLRJGPQ'
    const secretHex = 'e49270f0d21f365c8408f8b475c5267c'
    const result = parseEnte(
      file(
        // digits 越界让这条失败，而它的 note 里恰好写着 secret 原文。
        `otpauth://totp/Deno:Mason?algorithm=SHA1&digits=99&period=30&issuer=Deno&secret=${secret}&${displayParam({ note: secret })}`,
        // codeDisplay 非法，raw 里同样有 secret。
        `otpauth://totp/Deno:Mason?${BASE_QUERY}&codeDisplay=%7B${encodeURIComponent(secret)}`,
      ),
    )
    expect(result.failures).toHaveLength(1)
    const texts = [
      ...result.failures.map((failure) => `${failure.path} ${failure.reason}`),
      ...result.warnings.map((warning) => `${warning.field} ${warning.message}`),
    ]
    expect(result.warnings).toHaveLength(1)
    for (const text of texts) {
      expect(text).not.toContain(secret)
      expect(text).not.toContain(secret.toLowerCase())
      expect(text).not.toContain(secretHex)
    }
  })

  it('不修改入参字节，且两次调用结果一致', () => {
    const bytes = fileBytes('ente_edge.txt')
    const copy = new Uint8Array(bytes)
    const first = parseEnte(bytes)
    const second = parseEnte(bytes)
    expect(bytes).toEqual(copy)
    expect(golden(second.entries)).toEqual(golden(first.entries))
    expect(second.warnings).toEqual(first.warnings)
    expect(second.skipped).toBe(first.skipped)
  })
})
