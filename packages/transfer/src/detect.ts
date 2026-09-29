import { isRecord, parseJson, readText } from './input.js'
import type { DetectableInput, FormatId } from './types.js'

/**
 * 格式探测器（`docs/transfer.md` §4）。**纯函数**：畸形输入返回 `undefined`，绝不抛异常
 * （C6），也绝不修改入参。
 *
 * 探测顺序按成本从低到高：URI scheme 前缀 → JSON 特征字段 → 文本行形态 → CSV 表头 → 兜底不猜。
 * §4 的第 2 步「magic / 扩展名」在这里**无法实现**——`detect` 只拿到字节或字符串，拿不到文件名
 * （文件名属平台 API，C2 禁止）；本 App 的头部判据 `format === "mfavault"` 已覆盖同一意图。
 *
 * 兜底返回 `undefined` 是**有意义的结果**而不是失败：§4 第 6 步要求此时让用户手选格式，
 * 所以这里宁可少判也不猜——猜错会让用户的备份被按错误的解析器读成一批错乱条目。
 */

const OTPAUTH_PREFIX = 'otpauth://'
/** GA 迁移二维码的 scheme（#9）。它同样以 `otpauth-` 开头，必须先于通用前缀排除。 */
const GA_MIGRATION_PREFIX = 'otpauth-migration://'
/** Ente 独有的 query 参数；有它就是 Ente 的裸 URI 导出，没有就是通用 otpauth 文本。 */
const ENTE_MARKER = 'codeDisplay='

const WHAT = '待探测的输入'

function startsWithScheme(text: string, prefix: string): boolean {
  // scheme 大小写不敏感（RFC 3986 §3.1），与 `parseOtpAuthUri` 保持同一口径。
  return text.slice(0, prefix.length).toLowerCase() === prefix
}

/** 长度闸门 + UTF-8 解码。超限不是「无法识别」的理由，但探测器不许抛，故同样归为 `undefined`。 */
function toText(input: DetectableInput): string | undefined {
  try {
    return readText(input, WHAT)
  } catch {
    return undefined
  }
}

function toJsonObject(text: string): Record<string, unknown> | undefined {
  let parsed: unknown
  // `parseJson` 内含嵌套深度闸门，且吞掉了 SyntaxError 的源码片段（C4）。
  try {
    parsed = parseJson(text, WHAT)
  } catch {
    return undefined
  }
  return isRecord(parsed) ? parsed : undefined
}

/**
 * §4 第 3 步。两处判据是**照抄**而非凭直觉写的（design §要点 6）：
 *
 * - Aegis 不能用「含 `header.slots`」——明文导出的 `slots` 是 `null`，键存在值为 null，
 *   该判据恒真却对加密形态无效；也不能用 `db.entries`——加密时 `db` 是 base64 字符串，会漏判。
 *   故取 `typeof version === 'number' && 'header' in json && 'db' in json`，让加密文件也落进
 *   `aegis` 分支，#10 再在那里扩展加密判别。
 * - 2FAS 必须写成 `'servicesEncrypted' in json || ('services' in json && 'schemaVersion' in json)`：
 *   加密备份的 `services` 是**空数组**，只靠「`services` 非空」会漏判。
 */
function detectJson(json: Record<string, unknown>): FormatId | undefined {
  if (json.format === 'mfavault') {
    // `encrypted: true` 走的是主密码路径（#10），不是明文备份；此处刻意不给 `'mfavault-plaintext'`。
    return json.encrypted === false ? 'mfavault-plaintext' : undefined
  }

  if (typeof json.version === 'number' && 'header' in json && 'db' in json) return 'aegis'

  if ('servicesEncrypted' in json || ('services' in json && 'schemaVersion' in json)) return '2fas'

  // FreeOTP+ 的两个键都要在：只有 `tokens` 的话，任何未知格式的 `{tokens:[...]}` 都会被误判。
  // 上游 `SavedTokens.kt` 恒序列化 `tokenOrder`，真机文件不会缺；缺了就走 §4 第 6 步让用户手选，
  // 解析器（步骤 13）仍然能吃缺 `tokenOrder` 的输入——探测与解析是两件事。
  if (Array.isArray(json.tokens) && Array.isArray(json.tokenOrder)) return 'freeotp-plus'

  return undefined
}

/**
 * §4 第 4 步：`jsonEncode(uri)` 的产物——整行是一个**带引号**的 JSON 字符串，Ente 的第二条
 * 明文导出路径。带引号的行不以 `otpauth://` 开头，故与裸 URI 行天然分流，不会被当裸 URI 解析。
 */
function isQuotedOtpAuthLine(line: string): boolean {
  if (!line.startsWith('"')) return false
  let parsed: unknown
  try {
    parsed = JSON.parse(line)
  } catch {
    return false
  }
  return typeof parsed === 'string' && startsWithScheme(parsed, OTPAUTH_PREFIX)
}

/**
 * 随机二进制经 `utf8Decode` 会产出 U+FFFD，NUL 等控制字符则直接暴露非文本本质。
 * 两者都说明这不是一张表，按 §4 第 6 步兜底不猜——否则「含逗号的乱码」会被判成 generic CSV。
 */
function isPrintableText(text: string): boolean {
  if (text.includes('\uFFFD')) return false
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i)
    if (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) return false
  }
  return true
}

function collectLines(text: string): string[] {
  const lines: string[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (line !== '') lines.push(line)
  }
  return lines
}

/** §4 第 5 步。只用表头行判别，不解析数据行——探测的成本必须低于解析。 */
function detectCsv(headerLine: string): FormatId | undefined {
  const cells = headerLine.split(',').map((cell) => {
    const trimmed = cell.trim()
    // 全引号表头（`"folder","login_totp"`）也是合法 CSV，剥掉引号再比才不会漏判 Bitwarden。
    return trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')
      ? trimmed.slice(1, -1)
      : trimmed
  })

  // 判据是 `login_totp` 而**不是** `totp`：Bitwarden 的别名导出用 `totp`，1Password 的 CSV
  // 根本没有 TOTP 列（A3：无权威 schema），拿 `totp` 判别会同时误判这两家。
  if (cells.includes('login_totp')) return 'bitwarden'
  if (cells.filter((cell) => cell !== '').length >= 2) return 'generic-csv'
  return undefined
}

export function detect(input: DetectableInput): FormatId | undefined {
  const text = toText(input)
  if (text === undefined) return undefined

  // `trim()` 顺带吃掉 UTF-8 BOM（U+FEFF 属 ES 的 WhiteSpace 产生式），`generic_csv_edge.csv` 靠这条。
  const trimmed = text.trim()
  if (trimmed === '') return undefined

  // §4 第 1 步：成本最低的前缀判别。GA 的 scheme 是另一个字面量，必须先排除，
  // 绝不能把迁移二维码当成普通 URI 行（它属 #9）。
  if (startsWithScheme(trimmed, GA_MIGRATION_PREFIX)) return 'ga-migration'
  if (startsWithScheme(trimmed, OTPAUTH_PREFIX)) {
    // Ente 的裸 URI 导出与通用 otpauth 文本只差一个 `codeDisplay` 参数，但两者能还原的字段
    // 差很多（note / tags / trashed / position）。判成通用文本会让这些字段被静默丢弃，
    // 正是 `docs/transfer.md` §2.1 禁止的静默失败。
    return trimmed.includes(ENTE_MARKER) ? 'ente' : 'otpauth-lines'
  }

  // 看起来是 JSON 的输入只有两种结局：识别出格式，或 `undefined`。**不**回落到 CSV 分支，
  // 否则一份损坏的 JSON 备份会被当成一张表读。
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const json = toJsonObject(trimmed)
    return json === undefined ? undefined : detectJson(json)
  }

  // `trimmed` 非空且已去掉首尾空白，故首行必非空，`collectLines` 至少给出一行。
  const lines = collectLines(trimmed)

  // §4 第 4 步。裸 URI 行已在第 1 步按前缀分流，走不到这里。
  if (lines.every(isQuotedOtpAuthLine)) return 'ente'

  // §4 第 5 步。
  return isPrintableText(trimmed) ? detectCsv(lines[0]!) : undefined
}
