import { TransferFormatError } from './errors.js'
import { assertEntryCount, assertFieldLength, TRANSFER_LIMITS } from './input.js'
import type { ParseFailure } from './types.js'

const QUOTE = '"'
const COMMA = ','
const BOM = 0xfeff

/** 一行原始扫描结果。`lineNumber` 是该行**起始**处的 1 基源文本行号。 */
interface ScannedRow {
  readonly fields: readonly string[]
  readonly lineNumber: number
}

export interface CsvRecord {
  /**
   * 列名 → 值。用 `Map` 而非普通对象：表头来自不可信文件，若列名是 `__proto__` 或
   * `constructor`，`obj[name] = value` 会改原型或读到继承属性，而不是存一个普通字段。
   *
   * 重复列名时后一列覆盖前一列——重复表头本身就是畸形输入
   * （`__fixtures__/generic_csv_malformed.csv`），这里不做仲裁，需要区分时看 `CsvTable.header`。
   */
  readonly values: ReadonlyMap<string, string>
  /** 该行起始处的 1 基源文本行号，用于拼 `ParseFailure.path`。 */
  readonly lineNumber: number
  /** 0 基数据行序号（不含表头），即 `ParsedEntry.sourceIndex`。 */
  readonly rowIndex: number
}

export interface CsvTable {
  readonly header: readonly string[]
  readonly records: readonly CsvRecord[]
  /** 列数与表头不符的行。收进这里而不是抛异常，是 C5「部分成功优于全量失败」的要求。 */
  readonly failures: readonly ParseFailure[]
}

/** 读一个单元格的原文。列未映射（`undefined`）与列在该行缺值都收敛成空串。 */
export function cell(values: ReadonlyMap<string, string>, column: string | undefined): string {
  return column === undefined ? '' : (values.get(column) ?? '')
}

/**
 * 读一个**自由文本**单元格（issuer / account / note / 标签列）。
 *
 * 纯空白视作缺失（Bitwarden 上游 `getValueOrDefault` 的 `isNullOrWhitespace` 口径），但返回值
 * **不 trim**——`note` 里用户故意留的首尾空白不该被吃掉。`maxFieldLength` 闸门在这里跑：
 * 整格通过则从中拆出的任何子串也必然通过。
 */
export function cellText(values: ReadonlyMap<string, string>, column: string | undefined): string {
  if (column === undefined) return ''
  const raw = values.get(column) ?? ''
  if (raw.trim() === '') return ''
  assertFieldLength(raw, column)
  return raw
}

/**
 * RFC 4180 状态机。两道上限（单元格长度、数据行数）在扫描途中即时生效，而不是等全部行扫完
 * 再检查——一个百万行的 CSV 不该先被完整读进内存再被拒绝（C3）。
 */
function scan(text: string, what: string): ScannedRow[] {
  const rows: ScannedRow[] = []
  let fields: string[] = []
  let field = ''
  let inQuotes = false
  // 区分「空行」与「只有一个空字段的行」：后者由 `,` 或 `""` 产生，是有意义的数据行。
  let sawAnyChar = false
  let lineNumber = 1
  let rowLine = 1

  // 行数闸门挂在「推入一行」这个动作上，而不是挂在换行分支上：文件末尾没有换行符的最后一行
  // 走的是循环之后的收尾分支，两处都必须计数，否则上限会有 ±1 行的容差。
  const pushRow = (): void => {
    rows.push({ fields, lineNumber: rowLine })
    assertEntryCount(rows.length - 1, what) // 减 1 是表头行
  }

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]!

    if (inQuotes) {
      if (ch === QUOTE) {
        if (text[i + 1] === QUOTE) {
          field += QUOTE
          i += 1
        } else {
          inQuotes = false
        }
      } else {
        if (ch === '\n') lineNumber += 1
        else if (ch === '\r' && text[i + 1] !== '\n') lineNumber += 1
        field += ch
        if (field.length > TRANSFER_LIMITS.maxCsvCellLength) {
          throw new TransferFormatError(
            `${what} 第 ${rowLine} 行有一个单元格长度超过上限 ${TRANSFER_LIMITS.maxCsvCellLength}`,
          )
        }
      }
      continue
    }

    // 只有字段起始处的 `"` 才开启引用；`a"b` 里的引号按字面处理，避免把畸形输入吞成合法值。
    if (ch === QUOTE && field === '') {
      inQuotes = true
      sawAnyChar = true
      continue
    }

    if (ch === COMMA) {
      fields.push(field)
      field = ''
      sawAnyChar = true
      continue
    }

    if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i += 1
      fields.push(field)
      field = ''
      if (sawAnyChar || fields.length > 1) {
        pushRow()
      }
      fields = []
      sawAnyChar = false
      lineNumber += 1
      rowLine = lineNumber
      continue
    }

    field += ch
    sawAnyChar = true
    if (field.length > TRANSFER_LIMITS.maxCsvCellLength) {
      throw new TransferFormatError(
        `${what} 第 ${rowLine} 行有一个单元格长度超过上限 ${TRANSFER_LIMITS.maxCsvCellLength}`,
      )
    }
  }

  if (inQuotes) {
    throw new TransferFormatError(`${what} 第 ${rowLine} 行的引号未闭合，文件可能已损坏`)
  }
  if (sawAnyChar || fields.length > 0) {
    fields.push(field)
    pushRow()
  }

  return rows
}

export function parseCsv(text: string, what: string): CsvTable {
  // Excel 与 PowerShell 导出的 CSV 常带 UTF-8 BOM；不剥掉的话第一个列名会匹配不上。
  const source = text.charCodeAt(0) === BOM ? text.slice(1) : text
  const rows = scan(source, what)

  if (rows.length === 0) {
    throw new TransferFormatError(`${what} 不含表头行`)
  }

  const header = [...rows[0]!.fields]
  const records: CsvRecord[] = []
  const failures: ParseFailure[] = []

  for (let index = 0; index < rows.length - 1; index += 1) {
    const row = rows[index + 1]!
    if (row.fields.length !== header.length) {
      // 只报行号与列数，不回显单元格内容——CSV 的 secret 列就在这些单元格里（C4）。
      failures.push({
        sourceIndex: index,
        path: `${what} 第 ${row.lineNumber} 行`,
        reason: `该行有 ${row.fields.length} 个字段，与表头的 ${header.length} 列不符`,
      })
      continue
    }

    const values = new Map<string, string>()
    for (let column = 0; column < header.length; column += 1) {
      values.set(header[column]!, row.fields[column]!)
    }
    records.push({ values, lineNumber: row.lineNumber, rowIndex: index })
  }

  return { header, records, failures }
}

/** RFC 4180 §2.1 规定行尾是 CRLF；解析侧同时接受 LF，故往返无损。 */
const LINE_ENDING = '\r\n'

function escapeCell(value: string): string {
  if (/[",\r\n]/.test(value)) {
    return `${QUOTE}${value.replaceAll(QUOTE, QUOTE + QUOTE)}${QUOTE}`
  }
  return value
}

export function generateCsv(
  header: readonly string[],
  rows: readonly (readonly string[])[],
): string {
  const lines = [header, ...rows].map((fields) => fields.map(escapeCell).join(COMMA))
  return `${lines.join(LINE_ENDING)}${LINE_ENDING}`
}
