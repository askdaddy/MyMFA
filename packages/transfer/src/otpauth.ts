import {
  assertVaultData,
  type EntryAlgorithm,
  type EntryKind,
  type VaultData,
} from '@askdaddy/vault'

import { TransferError, TransferFormatError, TransferValueError } from './errors.js'
import { assertEntryCount, TRANSFER_LIMITS } from './input.js'
import {
  normalizeAlgorithm,
  normalizeCounter,
  normalizeDigits,
  normalizeKind,
  normalizePeriod,
} from './normalize.js'
import { decodeBase32Secret, decodeBase64Secret, encodeBase32Secret } from './secret.js'
import type { ImportResult, ParsedEntry, ParseFailure, ParseWarning } from './types.js'

/**
 * RFC 3986 §3.1 的 scheme 产生式。必须整段匹配到 `://`，`otpauth:/totp/...`（单斜杠）因此被拒。
 *
 * **不使用 `URL` 全局**：Hermes 的支持不完整，且 `URL` 会自作主张地规范化 label，
 * 而 `docs/transfer.md` §2 的通用 otpauth 行明确要求「不得假定 label 已编码」
 * （FreeOTP 的 `appendEncodedPath` 就不做百分号编码）。
 */
const SCHEME_PATTERN = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([\s\S]*)$/

const OTPAUTH_SCHEME = 'otpauth'

export interface OtpAuthUri {
  readonly entry: ParsedEntry
  /**
   * 已解码的 query 参数。Ente 的 `codeDisplay` 就挂在这里（步骤 14），一并返回免得它重切一遍 URI。
   *
   * 用 `Map` 而非普通对象，理由与 `csv.ts` 相同：参数名来自不可信文件。
   */
  readonly query: ReadonlyMap<string, string>
  readonly warnings: readonly ParseWarning[]
}

/**
 * `application/x-www-form-urlencoded`：`+` 表示空格，且必须**先**替换再百分号解码，
 * 否则 `%2B`（字面加号）会被误解成空格。`issuer=Air+Canada` 与 `issuer=Air%20Canada` 因此等价。
 *
 * 解码失败时不回显原值——query 里就放着 `secret`（C4，见 `errors.ts`）。
 */
function decodeQueryComponent(raw: string): string {
  try {
    return decodeURIComponent(raw.replaceAll('+', ' '))
  } catch {
    throw new TransferValueError('URI 的 query 中存在非法的百分号编码')
  }
}

/**
 * label 是**路径段**而非 query，`+` 在其中是字面加号，故不做 `+` → 空格替换。
 * 解码失败时按字面保留而不是判整条失败：上游确实存在不编码 label 的实现。
 */
function decodeLabel(raw: string): string {
  try {
    return decodeURIComponent(raw)
  } catch {
    return raw
  }
}

/**
 * 按 `&` 切分，每对只在**第一个** `=` 处分开。
 *
 * 只切第一个是硬要求：`issuer=Weird.period=99&period=30`（`otpauth_edge.txt` 第 20 行，
 * 即 Ente PR#77 的截断陷阱）若按 `=` 全切或按正则抓 `period=(\d+)`，就会读出一个并不存在的
 * `period=99`。重复参数名后者覆盖前者——规范未定义重复语义，不做仲裁。
 */
function parseQuery(queryString: string): Map<string, string> {
  const query = new Map<string, string>()
  if (queryString === '') {
    return query
  }
  for (const pair of queryString.split('&')) {
    if (pair === '') {
      continue
    }
    const separator = pair.indexOf('=')
    const key = separator === -1 ? pair : pair.slice(0, separator)
    const value = separator === -1 ? '' : pair.slice(separator + 1)
    query.set(decodeQueryComponent(key), decodeQueryComponent(value))
  }
  return query
}

interface ResolvedLabel {
  readonly issuer: string
  readonly account: string
  readonly conflict: boolean
}

/**
 * label 的形态是 `issuer:account`，但 issuer 前缀可有可无，且 `account` 自身可能含 `:`。
 * 三条分支各自的依据：
 *
 * 1. query 的 `issuer` 是**显式空值** → 整个 label 都是 account。生成侧对空 issuer 也会写出
 *    `issuer=`，读到它才能区分「没有 issuer」与「issuer 未提供」；否则 account 里的 `:`
 *    会被当成分隔符，往返有损。
 * 2. query 有非空 `issuer` 且 label 以 `issuer:` 开头 → 按该前缀切除，而不是按第一个 `:` 切。
 *    这样 issuer 含 `:` 时 account 才不会被切错。
 * 3. 其余情况按第一个 `:` 切分；两处 issuer 不一致时以 query 为准（design 冻结的判定）。
 */
function resolveLabel(label: string, queryIssuer: string | undefined): ResolvedLabel {
  if (queryIssuer === '') {
    return { issuer: '', account: label, conflict: false }
  }

  if (queryIssuer !== undefined) {
    const prefix = `${queryIssuer}:`
    if (label.startsWith(prefix)) {
      return { issuer: queryIssuer, account: label.slice(prefix.length), conflict: false }
    }
  }

  const separator = label.indexOf(':')
  const labelIssuer = separator === -1 ? '' : label.slice(0, separator)
  const account = separator === -1 ? label : label.slice(separator + 1)
  return {
    issuer: queryIssuer ?? labelIssuer,
    account,
    conflict: queryIssuer !== undefined && labelIssuer !== '' && labelIssuer !== queryIssuer,
  }
}

function requiredParam(query: ReadonlyMap<string, string>, key: string): string {
  const value = query.get(key)
  // C8：`algorithm` / `digits` / `period` / `counter` 缺失一律报错，绝不补默认值。
  // 上游 Ente 的 `_getDigits` / `_getPeriod` / `_getAlgorithm` 在异常时静默回落，
  // 那份「算得出但永远错」的验证码比导入失败严重得多（`__fixtures__/README.md` §四.4）。
  if (value === undefined) {
    throw new TransferValueError(`URI 缺少 ${key} 参数`)
  }
  return value
}

/** 解析**单个** otpauth URI。畸形输入抛 `TransferError`，由批量侧转成 `ParseFailure`（C5）。 */
export function parseOtpAuthUri(uri: string, sourceIndex: number): OtpAuthUri {
  const text = uri.trim()

  // RFC 3986 §3.5：`#` 之后一律是片段。Ente 的导出里出现过未转义的 `#`（`ente_edge.txt` 第 9 行），
  // 不先切掉就会把片段当成 query 的一部分。
  const hash = text.indexOf('#')
  const withoutFragment = hash === -1 ? text : text.slice(0, hash)

  const matched = SCHEME_PATTERN.exec(withoutFragment)
  if (matched === null) {
    throw new TransferValueError('不是 otpauth URI：缺少 scheme 与 "//"')
  }
  // scheme 大小写不敏感（RFC 3986 §3.1），故 `OTPAUTH://` 同样接受。
  // `otpauth-migration://` 的 scheme 是另一个字面量，会在这里被拒——它属 #9，不由本函数处理。
  if (matched[1]!.toLowerCase() !== OTPAUTH_SCHEME) {
    throw new TransferValueError('scheme 不是 otpauth，无法按通用 otpauth URI 解析')
  }

  const remainder = matched[2]!
  const queryStart = remainder.indexOf('?')
  const authorityPath = queryStart === -1 ? remainder : remainder.slice(0, queryStart)
  const query = parseQuery(queryStart === -1 ? '' : remainder.slice(queryStart + 1))

  const slash = authorityPath.indexOf('/')
  const host = slash === -1 ? authorityPath : authorityPath.slice(0, slash)
  const label = decodeLabel(slash === -1 ? '' : authorityPath.slice(slash + 1))

  // 先判 kind：`otpauth://steam/...` 必须报「该令牌类型不受支持」，而不是先抱怨它的 `digits=5`。
  const kind: EntryKind = normalizeKind(host)
  const queryIssuer = query.get('issuer')
  const resolved = resolveLabel(label, queryIssuer)

  const warnings: ParseWarning[] = []
  if (resolved.conflict) {
    // 不回显任何一侧的值：畸形文件可能把 secret 写在 issuer 参数里（C4）。
    warnings.push({
      sourceIndex,
      field: 'issuer',
      message: 'label 与 query 的 issuer 不一致，已采用 query 的值',
    })
  }

  const secret = decodeBase32Secret(requiredParam(query, 'secret'))
  const normalized = normalizeAlgorithm(requiredParam(query, 'algorithm'))
  if (normalized.fromMd5) {
    warnings.push({
      sourceIndex,
      field: 'algorithm',
      message: '原文是 MD5，已归一化为 SHA1',
    })
  }
  // `normalizeDigits` 返回 `number`，其内部复用的 `assertDigits` 已把取值收敛到 6..8，
  // 与 `Entry['digits']` 的字面量联合完全一致，故这里的断言是恒真的。
  const digits = normalizeDigits(requiredParam(query, 'digits')) as ParsedEntry['digits']

  const base = {
    issuer: resolved.issuer,
    account: resolved.account,
    secret,
    algo: normalized.algo,
    digits,
    // 通用 otpauth URI 没有备注 / 标签 / 收藏语义，留空即可（`docs/transfer.md` §3.1）。
    note: '',
    tagNames: [] as readonly string[],
    favorite: false,
    sourceIndex,
  }

  const entry: ParsedEntry =
    kind === 'totp'
      ? { ...base, kind, period: normalizePeriod(requiredParam(query, 'period')) }
      : { ...base, kind, counter: normalizeCounter(requiredParam(query, 'counter')) }

  return { entry, query, warnings }
}

export interface SourceLine {
  readonly text: string
  readonly lineNumber: number
}

/**
 * 切行 + 去空白 + 两道上限闸门（单行长度、条目数），全部在解析**之前**完成（C3）。
 *
 * `lineNumber` 是 1 基的源文本行号，用于 `ParseFailure.path`；`sourceIndex` 另按非空行的序号计，
 * 与 `csv.ts` 的 `rowIndex` / `lineNumber` 分工一致。
 *
 * 导出是为了让 Ente（步骤 14）复用同一套闸门：它的行还要先脱掉 `jsonEncode` 的引号外壳，
 * 不能直接走 `scanOtpAuthLines`。**不进 `index.ts` 的公开出口**。
 */
export function collectOtpAuthLines(text: string, what: string): SourceLine[] {
  const raw = text.split(/\r?\n/)
  const lines: SourceLine[] = []

  for (let index = 0; index < raw.length; index += 1) {
    const line = raw[index]!.trim()
    if (line === '') {
      continue
    }
    if (line.length > TRANSFER_LIMITS.maxLineLength) {
      throw new TransferFormatError(
        `${what} 第 ${index + 1} 行的长度为 ${line.length}，超过上限 ${TRANSFER_LIMITS.maxLineLength}`,
      )
    }
    lines.push({ text: line, lineNumber: index + 1 })
  }

  assertEntryCount(lines.length, what)
  return lines
}

export type OtpAuthLinesResult = Omit<ImportResult, 'format'>

/**
 * 行式批量解析。空行跳过；单行非法只记入 `failures` 并带行号，其余行照常产出（C5）。
 *
 * 返回不含 `format` 的结果，好让 Ente（步骤 14）复用同一套行扫描后自己贴 `'ente'`。
 */
export function scanOtpAuthLines(text: string, what: string): OtpAuthLinesResult {
  const lines = collectOtpAuthLines(text, what)
  const entries: ParsedEntry[] = []
  const failures: ParseFailure[] = []
  const warnings: ParseWarning[] = []

  for (let ordinal = 0; ordinal < lines.length; ordinal += 1) {
    const line = lines[ordinal]!
    try {
      const parsed = parseOtpAuthUri(line.text, ordinal)
      entries.push(parsed.entry)
      warnings.push(...parsed.warnings)
    } catch (error) {
      if (!(error instanceof TransferError)) {
        throw error
      }
      failures.push({
        sourceIndex: ordinal,
        path: `${what} 第 ${line.lineNumber} 行`,
        reason: error.message,
      })
    }
  }

  return { entries, tags: [], failures, warnings, skipped: 0 }
}

export function parseOtpAuthLines(text: string, what = 'otpauth 文本'): ImportResult {
  return { format: 'otpauth-lines', ...scanOtpAuthLines(text, what) }
}

/**
 * 生成 URI 所需的最小字段集。刻意不直接用 `ParsedEntry` 或 vault 的 `Entry`：
 * 前者带 `sourceIndex`（生成侧无意义），后者的 `secret` 是 base64 字符串而非字节。
 * 两者都能结构化赋值进来，步骤 17 的 `generateOtpAuthLines(vault)` 因此无需重写编码逻辑。
 */
export interface OtpAuthSource {
  readonly kind: EntryKind
  readonly issuer: string
  readonly account: string
  /** **原始字节**，base32 编码在本函数内做。 */
  readonly secret: Uint8Array
  readonly algo: EntryAlgorithm
  readonly digits: ParsedEntry['digits']
  readonly period?: number
  readonly counter?: number
}

/**
 * `docs/transfer.md` §3.2：参数全部显式写出以求最大兼容，`issuer` 在 label 与 query 两处都写，
 * `secret` 为 base32 **大写无 padding**（去 padding 在 `secret.ts` 的 `encodeBase32Secret` 里）。
 *
 * 参数顺序固定为 `secret, issuer, algorithm, digits, period|counter`，与 §3.2 的示例一致，
 * 这样同一输入永远产出同一串字节（步骤 17 的纯函数要求）。
 */
export function generateOtpAuthUri(source: OtpAuthSource): string {
  // issuer 为空时也要写出 `issuer=`：解析侧靠这个显式空值判定「label 不含 issuer 前缀」。
  const label =
    source.issuer === ''
      ? encodeURIComponent(source.account)
      : `${encodeURIComponent(source.issuer)}:${encodeURIComponent(source.account)}`

  const params = [
    `secret=${encodeBase32Secret(source.secret)}`,
    `issuer=${encodeURIComponent(source.issuer)}`,
    `algorithm=${source.algo}`,
    `digits=${source.digits}`,
  ]

  if (source.kind === 'totp') {
    if (source.period === undefined) {
      throw new TransferValueError('totp 条目缺少 period，无法生成 otpauth URI')
    }
    params.push(`period=${source.period}`)
  } else {
    if (source.counter === undefined) {
      throw new TransferValueError('hotp 条目缺少 counter，无法生成 otpauth URI')
    }
    params.push(`counter=${source.counter}`)
  }

  return `otpauth://${source.kind}/${label}?${params.join('&')}`
}

/**
 * 整个 vault 导出为 otpauth URI 文本（`docs/transfer.md` §3 的「otpauth URI 文本」行）：
 * 每行一个 URI，行分隔符是 `\n`，**不带尾随换行**——`collectOtpAuthLines` 会跳过空行，
 * 带不带都能往返，但带上会让「逐字节相同」的比较里多一处无意义的差异来源。
 *
 * 行序就是 `vault.entries` 的数组顺序：§3.1 对本格式把 `position` 判为 ❌（完全丢弃），
 * 没有「顺序承载手动排序」的承诺，故不像 `generateAegis` 那样按 `position` 重排。
 *
 * 先 `assertVaultData` 再编码，与 `container.ts` 的 `sealPlaintext` 同口径：非法数据必须
 * **抛错而不是产出文件**。这也让 `decodeBase64Secret` 与 `generateOtpAuthUri` 的两处内部
 * 校验（secret 解码后为空、totp 缺 period）在本入口下都成为不可达路径。
 */
export function generateOtpAuthLines(vault: VaultData): string {
  const data = assertVaultData(vault)
  return data.entries
    .map((entry) =>
      generateOtpAuthUri({
        kind: entry.kind,
        issuer: entry.issuer,
        account: entry.account,
        secret: decodeBase64Secret(entry.secret),
        algo: entry.algo,
        digits: entry.digits,
        period: entry.period,
        counter: entry.counter,
      }),
    )
    .join('\n')
}
