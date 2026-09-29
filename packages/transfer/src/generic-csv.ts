import type { EntryKind } from '@askdaddy/vault'

import type { CsvRecord } from './csv.js'
import { cell, cellText, parseCsv } from './csv.js'
import { TransferError, TransferFormatError, TransferValueError } from './errors.js'
import { assertFieldLength, readText } from './input.js'
import {
  normalizeAlgorithm,
  normalizeCounter,
  normalizeDigits,
  normalizeKind,
  normalizePeriod,
  type NormalizedAlgorithm,
} from './normalize.js'
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
 * **通用 CSV**（`docs/transfer.md` §2 的「通用 CSV」行）：1Password / LastPass 这类**没有权威
 * schema** 的来源的统一归宿（ADR-019 对 1Password 的判定即「不实现专用解析器」）。
 *
 * 因此本文件里**不存在任何具体产品的列名**——连 `generic_csv.csv` 夹具的中文列名也不出现。
 * 列名一律由调用方通过 `GenericCsvMapping` 给出；同一份 CSV 传两套映射就得到两套结果。
 */

const WHAT = '通用 CSV'
const OTPAUTH_PREFIX = 'otpauth://'

/**
 * 标签列的默认分隔符是**分号**而不是逗号：CSV 的字段分隔符就是逗号，含逗号的标签必然被写成
 * 引用单元格，再用逗号拆一次会把一个标签切成两半——与 Bitwarden 解析器对 totp 列不做逗号
 * 拆分是同一个道理（该处依据上游源码，这里依据 CSV 本身）。
 */
export const DEFAULT_TAG_SEPARATOR = ';'

/** 调用方给出的「哪个字段来自哪一列」。除 `secret` 外全部可选。 */
export interface GenericCsvMapping {
  readonly secret: string
  readonly issuer?: string
  readonly account?: string
  readonly kind?: string
  readonly algo?: string
  readonly digits?: string
  readonly period?: string
  readonly counter?: string
  readonly note?: string
  readonly tagNames?: string
}

/**
 * 映射解析后的形态：值是在表头中**实际命中**的那个单元格原文（可能带空格），未映射的字段是
 * `undefined`。只有 `secret` 必然有值——它在 `resolveColumns` 里就被卡住了。
 */
type Columns = {
  readonly [K in Exclude<keyof GenericCsvMapping, 'secret'>]: string | undefined
} & {
  readonly secret: string
}

/**
 * 把调用方给的列名对到表头上。
 *
 * 比较用 `trim()`（与 `detect` 和 `bitwarden.ts` 同口径），但**返回原始单元格**——
 * `CsvRecord.values` 是按原始表头单元格建键的，返回 trim 后的值会导致「找得到却取不出」。
 */
function findColumn(header: readonly string[], requested: string | undefined): string | undefined {
  if (requested === undefined || requested.trim() === '') return undefined
  const trimmed = requested.trim()
  return header.find((name) => name.trim() === trimmed)
}

/**
 * 未映射（`undefined` 或空串）→ `undefined`；映射了却在表头里找不到 → **整包**失败（这是配置
 * 错误，不是文件损坏）。
 *
 * 文案只点名映射目标与可用列数，**不回显表头单元格、也不回显调用方给的列名**（C4）：
 * `parseCsv` 无条件把第一行当表头，一份没有表头行的 CSV 会把第一条数据的 secret 变成列名；
 * 而残留的映射里那个列名可能来自另一份文件。调用方（列映射 UI）本来就持有这两样东西。
 */
function mapColumn(
  header: readonly string[],
  requested: string | undefined,
  field: string,
): string | undefined {
  if (requested === undefined || requested.trim() === '') return undefined
  const matched = findColumn(header, requested)
  if (matched === undefined) {
    throw new TransferFormatError(
      `${WHAT} 的表头有 ${header.length} 列，其中没有映射为 ${field} 的那一列`,
    )
  }
  return matched
}

function resolveColumns(header: readonly string[], mapping: GenericCsvMapping): Columns {
  const secret = mapColumn(header, mapping.secret, 'secret')
  if (secret === undefined) {
    throw new TransferFormatError(`${WHAT} 的映射没有指定 secret 列`)
  }
  return {
    secret,
    issuer: mapColumn(header, mapping.issuer, 'issuer'),
    account: mapColumn(header, mapping.account, 'account'),
    kind: mapColumn(header, mapping.kind, 'kind'),
    algo: mapColumn(header, mapping.algo, 'algo'),
    digits: mapColumn(header, mapping.digits, 'digits'),
    period: mapColumn(header, mapping.period, 'period'),
    counter: mapColumn(header, mapping.counter, 'counter'),
    note: mapColumn(header, mapping.note, 'note'),
    tagNames: mapColumn(header, mapping.tagNames, 'tagNames'),
  }
}

/**
 * 映射列优先（用户显式指定的参数覆盖文件内嵌值），未映射或该行为空时回落到 `otpauth://` URI
 * 自带的值；两者都没有就按 C8 判单条失败，**绝不补默认值**——补出来的验证码算得出但永远错。
 */
function resolveParam<T>(
  raw: string,
  parse: (value: string) => T,
  fromUri: T | undefined,
  what: string,
): T {
  if (raw !== '') return parse(raw)
  if (fromUri !== undefined) return fromUri
  throw new TransferValueError(`缺少 ${what}`)
}

/**
 * `kind` 是唯一允许猜的字段：猜成 `totp` 会连带要求 `period` 存在，真正的 HOTP 行要么因为没有
 * `period` 列而**大声失败**，要么确实带着 `period`（那正是调用方要的效果），两种结果都不会静默
 * 产出错码。`digits` / `algo` / `period` / `counter` 没有这个性质，故一律不猜。
 */
function resolveKind(
  raw: string,
  uri: ParsedEntry | undefined,
  column: string | undefined,
  sourceIndex: number,
  warnings: ParseWarning[],
): EntryKind {
  if (raw !== '') return normalizeKind(raw)
  if (uri !== undefined) return uri.kind

  const field = column ?? 'kind'
  warnings.push({
    sourceIndex,
    field,
    message:
      column === undefined ? '未提供类型列，已按 TOTP 处理' : `${field} 为空，已按 TOTP 处理`,
  })
  return 'totp'
}

function readTagNames(
  values: ReadonlyMap<string, string>,
  column: string | undefined,
  separator: string,
): readonly string[] {
  if (column === undefined) return []
  const raw = cellText(values, column)
  if (raw === '') return []

  const tags: string[] = []
  for (const part of separator === '' ? [raw] : raw.split(separator)) {
    const name = part.trim()
    if (name === '' || tags.includes(name)) continue
    assertFieldLength(name, column)
    tags.push(name)
  }
  return tags
}

/**
 * 返回 `undefined` 表示该行没有 secret，计入 `skipped` 而非 `failures`。
 *
 * `warnings` 形参是**调用方给的行级缓冲区**，不是整包数组：与 `bitwarden.ts` 不同，本文件的
 * URI 解析与类型告警都排在 `digits` / `period` / `counter` 的判定之前，「先 push 后 throw」
 * 是可达的，该行一旦失败就不能留下指向一个不存在条目的警告。
 */
function parseRow(
  record: CsvRecord,
  columns: Columns,
  tagSeparator: string,
  warnings: ParseWarning[],
): ParsedEntry | undefined {
  const values = record.values
  const rawSecret = cell(values, columns.secret).trim()
  if (rawSecret === '') return undefined

  const sourceIndex = record.rowIndex

  let uri: ParsedEntry | undefined
  if (rawSecret.toLowerCase().startsWith(OTPAUTH_PREFIX)) {
    const parsed = parseOtpAuthUri(rawSecret, sourceIndex)
    warnings.push(...parsed.warnings)
    uri = parsed.entry
  }
  const secret = uri?.secret ?? decodeBase32Secret(rawSecret)

  const issuerColumn = columns.issuer
  const accountColumn = columns.account
  const issuerText = cellText(values, issuerColumn)
  const accountText = cellText(values, accountColumn)

  // 身份以 URI 为准（与 `bitwarden.ts` 同口径），冲突要报出来但不回显任何一侧的值（C4）。
  if (
    uri !== undefined &&
    issuerColumn !== undefined &&
    issuerText !== '' &&
    issuerText !== uri.issuer
  ) {
    warnings.push({
      sourceIndex,
      field: issuerColumn,
      message: `${issuerColumn} 列与 secret 中 URI 的 issuer 不一致，已采用 URI 的值`,
    })
  }
  if (
    uri !== undefined &&
    accountColumn !== undefined &&
    accountText !== '' &&
    accountText !== uri.account
  ) {
    warnings.push({
      sourceIndex,
      field: accountColumn,
      message: `${accountColumn} 列与 secret 中 URI 的 account 不一致，已采用 URI 的值`,
    })
  }

  const kind = resolveKind(
    cell(values, columns.kind).trim(),
    uri,
    columns.kind,
    sourceIndex,
    warnings,
  )

  const normalized = resolveParam<NormalizedAlgorithm>(
    cell(values, columns.algo).trim(),
    normalizeAlgorithm,
    uri === undefined ? undefined : { algo: uri.algo, fromMd5: false },
    'algorithm',
  )
  if (normalized.fromMd5) {
    warnings.push({
      sourceIndex,
      field: columns.algo ?? 'algorithm',
      message: '原文是 MD5，已归一化为 SHA1',
    })
  }

  // `normalizeDigits` 返回 `number`，其内部复用的 `assertDigits` 已把取值收敛到 6..8，
  // 与 `Entry['digits']` 的字面量联合完全一致，故这里的断言是恒真的（同 `otpauth.ts`）。
  const digits = resolveParam(
    cell(values, columns.digits).trim(),
    normalizeDigits,
    uri?.digits,
    'digits',
  ) as ParsedEntry['digits']

  const base = {
    issuer: uri?.issuer ?? issuerText,
    account: uri?.account ?? accountText,
    secret,
    algo: normalized.algo,
    digits,
    note: cellText(values, columns.note),
    tagNames: readTagNames(values, columns.tagNames, tagSeparator),
    // 映射项里没有 favorite，通用 CSV 也没有这个语义（`docs/transfer.md` §3.1）。
    favorite: false,
    sourceIndex,
  }

  if (kind === 'totp') {
    const period = resolveParam(
      cell(values, columns.period).trim(),
      normalizePeriod,
      uri?.kind === 'totp' ? uri.period : undefined,
      'period',
    )
    return { ...base, kind, period }
  }

  const counter = resolveParam(
    cell(values, columns.counter).trim(),
    normalizeCounter,
    uri?.kind === 'hotp' ? uri.counter : undefined,
    'counter',
  )
  return { ...base, kind, counter }
}

export function parseGenericCsv(
  input: DetectableInput,
  mapping: GenericCsvMapping,
  tagSeparator = DEFAULT_TAG_SEPARATOR,
): ImportResult {
  const table = parseCsv(readText(input, WHAT), WHAT)
  const columns = resolveColumns(table.header, mapping)

  const entries: ParsedEntry[] = []
  const failures: ParseFailure[] = [...table.failures]
  const warnings: ParseWarning[] = []
  let skipped = 0

  for (const record of table.records) {
    const local: ParseWarning[] = []
    try {
      const entry = parseRow(record, columns, tagSeparator, local)
      if (entry === undefined) {
        skipped += 1
        continue
      }
      entries.push(entry)
      warnings.push(...local)
    } catch (error) {
      if (!(error instanceof TransferError)) throw error
      failures.push({
        sourceIndex: record.rowIndex,
        path: `${WHAT} 第 ${record.lineNumber} 行`,
        reason: error.message,
      })
    }
  }

  return { format: 'generic-csv', entries, tags: [], failures, warnings, skipped }
}
