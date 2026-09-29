import { DEFAULT_DIGITS, DEFAULT_PERIOD } from '@askdaddy/otp'

import type { CsvRecord } from './csv.js'
import { cell, cellText, parseCsv } from './csv.js'
import { TransferError, TransferFormatError } from './errors.js'
import { assertFieldLength, readText } from './input.js'
import { parseOtpAuthUri } from './otpauth.js'
import { decodeBase32Secret } from './secret.js'
import type {
  DetectableInput,
  ImportResult,
  ParsedEntry,
  ParseFailure,
  ParseWarning,
} from './types.js'

/**
 * Bitwarden 的 CSV 导出（`docs/transfer.md` §2）。权威来源是上游
 * `libs/importer/src/importers/bitwarden/bitwarden-csv-importer.ts`（`bitwarden/clients`）。
 *
 * 三处**照抄上游而非按直觉写**的地方：
 *
 * 1. totp 列名有两个：`login_totp` 与历史别名 `totp`（上游 `:100` 是
 *    `value.login_totp || value.totp`）。探测器只认 `login_totp`，但解析器两个都要吃——
 *    只用别名的老导出会被探测成 `generic-csv`，用户手选 Bitwarden 后不能读不出密钥。
 * 2. `login_totp` 是**单值**。上游只对 `login_uri` 调 `parseSingleRowCsv`（`:103`），
 *    对 totp 没有（`:100`）。按逗号拆分会把 label 含未编码逗号的 URI 切成两半，两半都不是
 *    合法 URI。逗号多值语义只属于 `collections`（`:25`）。
 * 3. `favorite` 的判据是 `getValueOrDefault(value.favorite, "0") !== "0"`（`:39`）：
 *    任何非 `"0"` 的非空值都算 true，包括空串以外的任意文本。
 *
 * 上游 `:39` 还有 `!this.organization &&` 前缀（组织导出一律不收藏）。这里**不复制**：
 * 判定 organization 需要另一个信号，而 `favorite` 列本身已经写明意图，按计划冻结的
 * `favorite !== "0"` 处置。
 */

const OTPAUTH_PREFIX = 'otpauth://'

/** 上游 `:100` 与 `:101` 的双列名。顺序即优先级。 */
const TOTP_COLUMNS = ['login_totp', 'totp'] as const
const ACCOUNT_COLUMNS = ['login_username', 'username'] as const

interface Columns {
  readonly totp: string
  readonly account: string | undefined
  readonly name: string | undefined
  readonly notes: string | undefined
  readonly folder: string | undefined
  readonly favorite: string | undefined
  readonly collections: string | undefined
}

/**
 * 在表头里找列名，返回**原始**表头单元格（`CsvRecord.values` 的键是原样的，不能拿 trim 后的
 * 去查）。`detect.ts` 判表头时会 trim，故这里也必须 trim 后比较，否则 `"login_totp "` 这种
 * 带空格的表头会被探测成 Bitwarden 却在解析时找不到列。
 */
function findColumn(header: readonly string[], candidates: readonly string[]): string | undefined {
  return header.find((cell) => candidates.includes(cell.trim()))
}

function resolveColumns(header: readonly string[], what: string): Columns {
  const totp = findColumn(header, TOTP_COLUMNS)
  if (totp === undefined) {
    // 不回显表头内容：没有表头行的 CSV 会把第一条数据的 secret 当成列名（C4）。
    throw new TransferFormatError(`${what} 不含 login_totp 或 totp 列，不是 Bitwarden 的导出`)
  }
  return {
    totp,
    account: findColumn(header, ACCOUNT_COLUMNS),
    name: findColumn(header, ['name']),
    notes: findColumn(header, ['notes']),
    folder: findColumn(header, ['folder']),
    favorite: findColumn(header, ['favorite']),
    collections: findColumn(header, ['collections']),
  }
}

/** `folder` 单元素 + `collections` 逗号拆分（上游 `:25`），去重后合并。 */
function readTagNames(values: ReadonlyMap<string, string>, columns: Columns): readonly string[] {
  const tags: string[] = []
  const push = (name: string, path: string): void => {
    if (name === '' || tags.includes(name)) return
    assertFieldLength(name, path)
    tags.push(name)
  }

  const folder = cellText(values, columns.folder)
  if (folder !== '') push(folder, columns.folder!)

  const collections = cellText(values, columns.collections)
  if (collections !== '') {
    for (const collection of collections.split(',')) push(collection.trim(), columns.collections!)
  }

  return tags
}

/** 完整 URI 形态：algo / digits / period / counter 全部取自 URI，身份以 URI 为准。 */
function fromUri(
  totp: string,
  sourceIndex: number,
  columns: Columns,
  issuer: string,
  account: string,
  warnings: ParseWarning[],
): ParsedEntry {
  const parsed = parseOtpAuthUri(totp, sourceIndex)
  warnings.push(...parsed.warnings)

  // 冲突时以 URI 为准（步骤 8 的 label/query issuer 冲突同口径），但必须报出来。
  // 文案与 field 都用**实际命中**的列名（可能是别名 `totp` / `username`），否则导入摘要会
  // 指向一个文件里不存在的列。不回显任何一侧的值，`name` 里可能夹着 secret（C4）。
  if (issuer !== '' && issuer !== parsed.entry.issuer) {
    const column = columns.name ?? 'name'
    warnings.push({
      sourceIndex,
      field: column,
      message: `${column} 列与 ${columns.totp} 中 URI 的 issuer 不一致，已采用 URI 的值`,
    })
  }
  if (account !== '' && account !== parsed.entry.account) {
    const column = columns.account ?? 'login_username'
    warnings.push({
      sourceIndex,
      field: column,
      message: `${column} 列与 ${columns.totp} 中 URI 的 account 不一致，已采用 URI 的值`,
    })
  }

  return parsed.entry
}

/**
 * 裸 base32 形态：CSV **没有** `algorithm` / `digits` / `period` / `counter` 列，
 * 三个默认值由解析器**显式**补并逐个记 warning（`docs/transfer.md` §2.1 授权的唯一补默认值场景）。
 *
 * 类型一律按 TOTP：裸 base32 不携带任何类型信息，无从判定 HOTP，故 §2.1 的「裸 base32 且类型为
 * HOTP → counter 无法恢复」在本格式下不可达。这里**绝不**产出 `counter: 0` 的 HOTP 条目。
 */
function fromBareBase32(
  totp: string,
  sourceIndex: number,
  column: string,
  warnings: ParseWarning[],
): Uint8Array {
  // `steam://<BASE32>` 在 `decodeBase32Secret` 入口就被拒（`secret.ts`），文案含「Steam」与
  // 「不受支持」；判在那里而不是这里，是为了不让 Steam 专用字母表的 `:` 与 `/` 被误报成
  // 「不是合法的 base32 字符串」。
  const secret = decodeBase32Secret(totp)

  warnings.push(
    {
      sourceIndex,
      field: 'digits',
      message: `${column} 是裸 base32，不含 digits，已按 Bitwarden 的默认值 ${DEFAULT_DIGITS} 补齐`,
    },
    {
      sourceIndex,
      field: 'period',
      message: `${column} 是裸 base32，不含 period，已按 Bitwarden 的默认值 ${DEFAULT_PERIOD} 补齐`,
    },
    {
      sourceIndex,
      field: 'algorithm',
      message: `${column} 是裸 base32，不含 algorithm，已按 Bitwarden 的默认值 SHA1 补齐`,
    },
  )

  return secret
}

/**
 * 返回 `undefined` 表示该行没有 TOTP，计入 `skipped` 而非 `failures`。
 *
 * `warnings` 是**整包共享**的数组，不像 `aegis.ts` / `ente.ts` 那样先攒在行级局部再合并：
 * 本格式的所有可能抛错的读取（`cellText` 的超长判定、`readTagNames`、`decodeBase32Secret`、
 * `parseOtpAuthUri`）都排在 `fromUri` / `fromBareBase32` 之前，而 warning 只在这两个函数里产生，
 * 所以「先 push 后 throw」在本文件中不可达，失败行不可能留下指向自己的告警。
 */
function parseRow(
  record: CsvRecord,
  columns: Columns,
  warnings: ParseWarning[],
): ParsedEntry | undefined {
  const values = record.values
  const totp = (values.get(columns.totp) ?? '').trim()
  if (totp === '') return undefined

  const sourceIndex = record.rowIndex
  const issuer = cellText(values, columns.name)
  const account = cellText(values, columns.account)
  const note = cellText(values, columns.notes)
  const tagNames = readTagNames(values, columns)
  const favoriteRaw = cell(values, columns.favorite)
  const favorite = favoriteRaw.trim() !== '' && favoriteRaw.trim() !== '0'

  const base = { note, tagNames, favorite, sourceIndex }

  if (totp.toLowerCase().startsWith(OTPAUTH_PREFIX)) {
    // 身份以 URI 为准，故 `base` 里不含 issuer / account（`fromUri` 已把冲突报成 warning）。
    return { ...fromUri(totp, sourceIndex, columns, issuer, account, warnings), ...base }
  }

  return {
    ...base,
    issuer,
    account,
    secret: fromBareBase32(totp, sourceIndex, columns.totp, warnings),
    kind: 'totp',
    algo: 'SHA1',
    digits: DEFAULT_DIGITS,
    period: DEFAULT_PERIOD,
  }
}

export function parseBitwarden(input: DetectableInput, what = 'Bitwarden CSV'): ImportResult {
  const table = parseCsv(readText(input, what), what)
  const columns = resolveColumns(table.header, what)

  const warnings: ParseWarning[] = []
  if (columns.collections !== undefined) {
    warnings.push({
      sourceIndex: null,
      field: columns.collections,
      message: '检测到组织导出的 collections 列，已按逗号拆分并入各条目的标签',
    })
  }

  const entries: ParsedEntry[] = []
  const failures: ParseFailure[] = [...table.failures]
  let skipped = 0

  for (const record of table.records) {
    try {
      const entry = parseRow(record, columns, warnings)
      if (entry === undefined) {
        skipped += 1
        continue
      }
      entries.push(entry)
    } catch (error) {
      if (!(error instanceof TransferError)) throw error
      failures.push({
        sourceIndex: record.rowIndex,
        path: `${what} 第 ${record.lineNumber} 行`,
        reason: error.message,
      })
    }
  }

  return { format: 'bitwarden', entries, tags: [], failures, warnings, skipped }
}
