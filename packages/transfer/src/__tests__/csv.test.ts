import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { generateCsv, parseCsv } from '../csv.js'
import { TransferFormatError } from '../errors.js'
import { TRANSFER_LIMITS } from '../input.js'

const fixture = (name: string): string =>
  readFileSync(new URL(`../__fixtures__/${name}`, import.meta.url), 'utf8')

const values = (text: string): Record<string, string>[] =>
  parseCsv(text, 'CSV').records.map((record) => Object.fromEntries(record.values))

describe('parseCsv：基本形态', () => {
  it('表头 + 数据行解析为「列名 → 值」的记录数组', () => {
    const table = parseCsv('issuer,account,secret\nDeno,Mason,AAAA\nWWE,Mason,BBBB\n', 'CSV')
    expect(table.header).toEqual(['issuer', 'account', 'secret'])
    expect(table.records).toHaveLength(2)
    expect(table.failures).toEqual([])
    expect(table.records[0]!.values.get('secret')).toBe('AAAA')
    expect(table.records[1]!.values.get('issuer')).toBe('WWE')
  })

  it('按列名取值：把列顺序整体调换后结果不变', () => {
    const original = values('issuer,account,secret\nDeno,Mason,AAAA\n')
    const shuffled = values('secret,issuer,account\nAAAA,Deno,Mason\n')
    expect(shuffled).toEqual(original)
  })

  it('没有数据行时返回空记录数组而非抛错', () => {
    const table = parseCsv('issuer,account\n', 'CSV')
    expect(table.header).toEqual(['issuer', 'account'])
    expect(table.records).toEqual([])
    expect(table.failures).toEqual([])
  })

  it('文件末尾没有换行也能解析', () => {
    expect(parseCsv('a,b\n1,2', 'CSV').records).toHaveLength(1)
  })

  it('完全没有表头行时抛 TransferFormatError', () => {
    expect(() => parseCsv('', 'CSV')).toThrow(TransferFormatError)
    expect(() => parseCsv('\n\n', 'CSV')).toThrow(TransferFormatError)
  })

  it('空行被跳过，而「只有一个空字段的行」算数据行', () => {
    const table = parseCsv('a,b\n1,2\n\n\n3,4\n', 'CSV')
    expect(table.records).toHaveLength(2)
    // `""` 是一个显式的空字段，不是空行。
    expect(parseCsv('a\n""\n', 'CSV').records).toHaveLength(1)
  })

  it('剥掉 UTF-8 BOM，否则第一个列名匹配不上', () => {
    expect(parseCsv('\uFEFFissuer,account\nDeno,Mason\n', 'CSV').header).toEqual([
      'issuer',
      'account',
    ])
  })
})

describe('parseCsv：引号与转义（RFC 4180）', () => {
  it('"a,b",c 解析为两列 a,b 与 c', () => {
    expect(values('x,y\n"a,b",c\n')[0]).toEqual({ x: 'a,b', y: 'c' })
  })

  it('"he said ""hi""",x 解析为 he said "hi" 与 x', () => {
    expect(values('x,y\n"he said ""hi""",x\n')[0]).toEqual({ x: 'he said "hi"', y: 'x' })
  })

  it('引号内的换行被保留为单个字段', () => {
    const table = parseCsv('a,b\n"line1\nline2",x\n', 'CSV')
    expect(table.records).toHaveLength(1)
    expect(table.records[0]!.values.get('a')).toBe('line1\nline2')
  })

  it('引号内的 CRLF 原样保留，不当作行尾', () => {
    expect(parseCsv('a,b\n"line1\r\nline2",x\r\n', 'CSV').records[0]!.values.get('a')).toBe(
      'line1\r\nline2',
    )
  })

  it('CRLF 与 LF 行尾都能解析，且结果一致', () => {
    const lf = values('a,b\n1,2\n3,4\n')
    expect(values('a,b\r\n1,2\r\n3,4\r\n')).toEqual(lf)
    expect(values('a,b\r1,2\r3,4\r')).toEqual(lf)
  })

  it('只有字段起始处的引号才开启引用，中间的引号按字面处理', () => {
    expect(values('a,b\nx"y",z\n')[0]).toEqual({ a: 'x"y"', b: 'z' })
  })

  it('引号后紧跟内容时不吞掉后续字符', () => {
    expect(values('a,b\n"x"y,z\n')[0]).toEqual({ a: 'xy', b: 'z' })
  })

  it('引号未闭合时抛 TransferFormatError（整包）并带行号', () => {
    try {
      parseCsv('a,b\n1,"2\n', 'CSV')
      expect.unreachable('应当抛错')
    } catch (error) {
      expect(error).toBeInstanceOf(TransferFormatError)
      expect((error as Error).message).toContain('第 2 行')
      expect((error as Error).message).toContain('引号未闭合')
    }
  })

  it('错误消息不回显单元格内容（C4）', () => {
    const secretLike = 'JBSWY3DPEHPK3PXP'
    try {
      parseCsv(`a,b\n1,"${secretLike}\n`, 'CSV')
      expect.unreachable('应当抛错')
    } catch (error) {
      expect((error as Error).message).not.toContain(secretLike)
    }
  })
})

describe('parseCsv：列数不符（C5 部分成功）', () => {
  it('列数不符的行进入 failures 并带行号，不中止其余行', () => {
    const table = parseCsv('a,b,c\n1,2,3\nTooFew\n1,2,3,4\n5,6,7\n', 'CSV')
    expect(table.records).toHaveLength(2)
    expect(table.records.map((r) => r.values.get('a'))).toEqual(['1', '5'])
    expect(table.failures).toHaveLength(2)
    expect(table.failures[0]).toEqual({
      sourceIndex: 1,
      path: 'CSV 第 3 行',
      reason: '该行有 1 个字段，与表头的 3 列不符',
    })
    expect(table.failures[1]!.path).toBe('CSV 第 4 行')
    expect(table.failures[1]!.reason).toContain('4 个字段')
  })

  it('行号按源文本计，含引号内换行占用的行', () => {
    const table = parseCsv('a,b\n"multi\nline",x\nshort\n', 'CSV')
    expect(table.failures).toHaveLength(1)
    // 第 2–3 行是那条多行记录，第 4 行才是 short。
    expect(table.failures[0]!.path).toBe('CSV 第 4 行')
  })

  it('failure 的 reason 不回显单元格内容（C4）', () => {
    const secretLike = 'JBSWY3DPEHPK3PXP'
    const [failure] = parseCsv(`a,b\n${secretLike}\n`, 'CSV').failures
    expect(failure!.reason).not.toContain(secretLike)
    expect(failure!.path).not.toContain(secretLike)
  })
})

describe('parseCsv：上限闸门（C3）', () => {
  it('单元格超过 maxCsvCellLength 时抛 TransferFormatError', () => {
    const oversized = 'x'.repeat(TRANSFER_LIMITS.maxCsvCellLength + 1)
    expect(() => parseCsv(`a,b\n${oversized},y\n`, 'CSV')).toThrow(TransferFormatError)
    // 恰好等于上限不算超。
    const exact = 'x'.repeat(TRANSFER_LIMITS.maxCsvCellLength)
    expect(parseCsv(`a,b\n${exact},y\n`, 'CSV').records).toHaveLength(1)
  })

  it('引号内的超长单元格同样被拦下', () => {
    const oversized = 'x'.repeat(TRANSFER_LIMITS.maxCsvCellLength + 1)
    expect(() => parseCsv(`a,b\n"${oversized}",y\n`, 'CSV')).toThrow(TransferFormatError)
  })

  // 行数判定与「文件有无尾换行符」无关，不得有 ±1 容差：无尾换行时最后一行走的是
  // `scan()` 循环之后的收尾分支，闸门必须挂在那里同样生效。
  const dataRows = (count: number) => Array.from({ length: count }, (_v, i) => `${i},y`).join('\n')

  it('数据行数恰好等于 maxEntries 时放行，有无尾换行都放行', () => {
    const exact = dataRows(TRANSFER_LIMITS.maxEntries)
    for (const text of [`${exact}\n`, exact]) {
      expect(parseCsv(`a,b\n${text}`, 'CSV').records).toHaveLength(TRANSFER_LIMITS.maxEntries)
    }
  })

  it('数据行数为 maxEntries + 1 时抛 TransferFormatError，有无尾换行都抛', () => {
    const over = dataRows(TRANSFER_LIMITS.maxEntries + 1)
    for (const text of [`${over}\n`, over]) {
      expect(() => parseCsv(`a,b\n${text}`, 'CSV')).toThrow(TransferFormatError)
    }
  })

  it('上限在逐行解析之前生效：整体抛错而不是降级为单行 failure', () => {
    const oversized = 'x'.repeat(TRANSFER_LIMITS.maxCsvCellLength + 1)
    // 第一行超限，第二行列数不符。若是「先解析再校验」，会得到一条 failure；
    // 实际必须整包抛错，说明闸门在扫描途中就生效了。
    expect(() => parseCsv(`a,b\n${oversized},y\nshort\n`, 'CSV')).toThrow(TransferFormatError)
  })
})

describe('parseCsv：真实夹具', () => {
  it('bitwarden.csv（10 列，末行无换行）全部解析成功', () => {
    const table = parseCsv(fixture('bitwarden.csv'), 'Bitwarden CSV')
    expect(table.header).toContain('login_totp')
    expect(table.records).toHaveLength(4)
    expect(table.failures).toEqual([])
    expect(table.records[3]!.values.get('login_totp')).toMatch(/^steam:\/\//)
  })

  it('bitwarden_edge.csv（alias 列名 + 引号内逗号与换行）全部解析成功', () => {
    const table = parseCsv(fixture('bitwarden_edge.csv'), 'Bitwarden CSV')
    expect(table.header).toEqual([
      'folder',
      'favorite',
      'type',
      'name',
      'notes',
      'uri',
      'username',
      'totp',
    ])
    expect(table.failures).toEqual([])
    expect(table.records).toHaveLength(8)
    expect(table.records[0]!.values.get('notes')).toContain('逗号')
    expect(table.records[0]!.values.get('notes')).toContain('\n')
    expect(table.records[0]!.values.get('folder')).toBe('Work/Servers')
    // 未加引号的 `/` 与空格不应被特殊处理。
    expect(table.records[1]!.values.get('username')).toBe('bob@ex ample.com')
  })

  it('generic_csv.csv（中文列名 + 引号内换行）按列名取值', () => {
    const table = parseCsv(fixture('generic_csv.csv'), '通用 CSV')
    expect(table.header).toContain('密钥')
    expect(table.failures).toEqual([])
    expect(table.records).toHaveLength(4)
    expect(table.records[1]!.values.get('标签')).toBe('工作;个人')
    expect(table.records[2]!.values.get('备注')).toBe('含 "引号" 与, 逗号')
    expect(table.records[3]!.values.get('备注')).toBe('备注含\n换行')
  })

  it('generic_csv_edge.csv（BOM + CRLF + 空表头单元格）解析成功', () => {
    const table = parseCsv(fixture('generic_csv_edge.csv'), '通用 CSV')
    // BOM 必须被剥掉，否则第一个列名是 "\uFEFF服务商"。
    expect(table.header[0]).toBe('服务商')
    expect(table.header.at(-1)).toBe('')
    expect(table.failures).toEqual([])
    expect(table.records).toHaveLength(3)
    expect(table.records[0]!.values.get('备注')).toHaveLength(5000)
    expect(table.records[1]!.values.get('账户')).toBe('Benjamin "B"')
  })

  it('bitwarden_malformed.csv（列数不符）产出带行号的 failures 且保留合法行', () => {
    const table = parseCsv(fixture('bitwarden_malformed.csv'), 'Bitwarden CSV')
    expect(table.records).toHaveLength(1)
    expect(table.records[0]!.values.get('name')).toBe('Ok')
    expect(table.failures).toHaveLength(2)
    expect(table.failures.map((f) => f.path)).toEqual([
      'Bitwarden CSV 第 2 行',
      'Bitwarden CSV 第 3 行',
    ])
    expect(table.failures[0]!.reason).toContain('4 个字段')
    expect(table.failures[1]!.reason).toContain('7 个字段')
  })

  it('generic_csv_malformed.csv（重复列名 + 未闭合引号）抛 TransferFormatError', () => {
    expect(() => parseCsv(fixture('generic_csv_malformed.csv'), '通用 CSV')).toThrow(
      TransferFormatError,
    )
  })

  it('重复列名本身不致命：后一列覆盖前一列，需要区分时看 header', () => {
    const table = parseCsv('密钥,账户,账户,算法\nAAAA,Mason,Davis,SHA1\n', '通用 CSV')
    expect(table.header).toEqual(['密钥', '账户', '账户', '算法'])
    expect(table.records).toHaveLength(1)
    expect(table.records[0]!.values.get('账户')).toBe('Davis')
  })

  it('列名是 __proto__ 或 constructor 时按普通列名处理，不污染原型', () => {
    const table = parseCsv('__proto__,constructor\nx,y\n', 'CSV')
    expect(table.records[0]!.values.get('__proto__')).toBe('x')
    expect(table.records[0]!.values.get('constructor')).toBe('y')
    expect({} as Record<string, unknown>).not.toHaveProperty('constructor', 'y')
  })
})

describe('generateCsv', () => {
  it('值含 , " \\n \\r 时被引号包裹并转义', () => {
    const csv = generateCsv(
      ['a', 'b'],
      [
        ['x,y', 'he said "hi"'],
        ['line1\nline2', 'plain'],
      ],
    )
    expect(csv).toBe('a,b\r\n"x,y","he said ""hi"""\r\n"line1\nline2",plain\r\n')
  })

  it('不含特殊字符的值不加引号', () => {
    expect(generateCsv(['a'], [['plain']])).toBe('a\r\nplain\r\n')
  })

  it('空输入产出只有表头的合法 CSV', () => {
    expect(generateCsv(['a', 'b'], [])).toBe('a,b\r\n')
    expect(parseCsv(generateCsv(['a', 'b'], []), 'CSV').records).toEqual([])
  })

  it('往返无损：含全部特殊字符的值生成后解析回原值', () => {
    const header = ['issuer', 'account', 'note', 'tags']
    const rows = [
      ['Deno', 'Mason', '备注, 含 "引号" 与\n换行', '标签A;标签B'],
      ['Issuu Air Canada', 'Benjamin "B"', '', 'x'],
      ['含 \r 的值', 'otpauth://totp/Deno:Mason?secret=AAAA&issuer=Deno', '# 与 %', ''],
    ]
    const table = parseCsv(generateCsv(header, rows), 'CSV')
    expect(table.header).toEqual(header)
    expect(table.failures).toEqual([])
    expect(table.records.map((r) => header.map((name) => r.values.get(name)))).toEqual(rows)
  })

  it('往返无损：BOM 与 CRLF 输入生成的产物同样可解析', () => {
    const source = fixture('generic_csv_edge.csv')
    const table = parseCsv(source, '通用 CSV')
    const regenerated = generateCsv(
      table.header,
      table.records.map((r) => table.header.map((name) => r.values.get(name) ?? '')),
    )
    const reparsed = parseCsv(regenerated, '通用 CSV')
    expect(reparsed.header).toEqual(table.header)
    expect(reparsed.records.map((r) => [...r.values.values()])).toEqual(
      table.records.map((r) => [...r.values.values()]),
    )
  })
})
