import { TransferError, TransferValueError } from './errors.js'
import { assertFieldLength, isRecord, parseJson, readText } from './input.js'
import { collectOtpAuthLines, parseOtpAuthUri } from './otpauth.js'
import type {
  DetectableInput,
  ImportResult,
  ParsedEntry,
  ParseFailure,
  ParseWarning,
} from './types.js'

/**
 * Ente 的**明文**导出（`docs/transfer.md` §2）。权威来源是上游 `mobile/apps/auth/lib/models/`
 * 下的 `code.dart` 与 `code_display.dart`（ente/ente）。加密形态（`.enteauth` / age+XChaCha20）
 * 属 #12，这里不碰。
 *
 * 上游有**两条**导出路径，本解析器两条都要吃：
 *
 * 1. 裸 `otpauth://` 行 —— 每行一个 URI，`codeDisplay` 是它的一个 query 参数。
 * 2. `toOTPAuthUrlFormat()`（`code.dart:199-206`）—— 末尾多一次 `jsonEncode(uri)`，
 *    于是**整行是一个带引号的 JSON 字符串**。不先脱壳就会被当成 URI 解析并报
 *    「不是 otpauth URI」，把一份完全正常的备份整包判死。
 *
 * `codeDisplay` 的 9 个字段里本 App 只映射 4 个（`note` / `tags` / `trashed` / `position`）。
 * 其余 5 个**逐个记 warning**：`pinned`（置顶）、`tapCount` / `lastUsedAt`（使用统计）在本 App
 * 的数据模型里都有对应位置（`Entry.favorite` / `usageCount` / `lastUsedAt`），只是 #8 不做映射；
 * `iconSrc` / `iconID` 是图标。这与 2FAS 的 `icon` / `badge`（纯外观，不告警）不同，
 * 故这里刻意更吵——漏掉的是用户能感知的行为，不是像素。
 */

/** 上游 `CodeDisplay` 的 9 个字段减去映射的 4 个（`code_display.dart:6-27`）。 */
const UNMAPPED_FIELDS = ['pinned', 'tapCount', 'lastUsedAt', 'iconSrc', 'iconID'] as const

/** 上游 `CodeDisplay()` 的默认构造参数（`code_display.dart:17-27`），逐字照抄。 */
interface CodeDisplay {
  readonly note: string
  readonly tagNames: readonly string[]
  readonly trashed: boolean
  readonly position: number
}

const DEFAULT_DISPLAY: CodeDisplay = { note: '', tagNames: [], trashed: false, position: 0 }

/** 排序用，**不进** `ParsedEntry`（验收标准明确要求 position 的值不出现在任何字段里）。 */
interface Placed {
  readonly entry: ParsedEntry
  readonly position: number
}

/**
 * 上游 `CodeDisplay.fromUri` 在 `jsonDecode` 之前先做一次 `replaceAll('%2C', ',')`
 * （`code_display.dart:84-87`）：Ente 的旧导出把 codeDisplay 编码了两次，URI 解码一遍后
 * 仍残留字面量 `%2C`，不替换掉 `jsonDecode` 就会失败。这条怪癖必须照抄，否则老备份的
 * note / tags 会全部丢失。
 */
function readCodeDisplay(
  raw: string | undefined,
  sourceIndex: number,
  warnings: ParseWarning[],
): CodeDisplay {
  // `codeDisplay` 是可选参数：上游 `fromUri` 在缺参数时返回 null 并由调用方兜底成默认值，
  // 既不报错也不告警。「没有附加信息」不等于「附加信息没导进来」，故这里同样保持安静。
  if (raw === undefined) return DEFAULT_DISPLAY

  let parsed: unknown
  try {
    parsed = parseJson(raw.replaceAll('%2C', ','), 'codeDisplay')
  } catch (error) {
    // 上游 `_parseCodeDisplayJson` 在 `safeParsing` 下 catch 住一切并返回默认值
    // （`code_display.dart:91-110`），但**一声不吭**——那是 §2.1 禁止的静默失败：
    // 用户的 note 与 tags 会凭空消失。这里照抄「不丢弃可用密钥」，但把事实报出来。
    if (!(error instanceof TransferError)) throw error
    warnings.push({
      sourceIndex,
      field: 'codeDisplay',
      message:
        '不是合法的 JSON，已按默认值处理，该条目的 note / tags / trashed / position 全部丢失',
    })
    return DEFAULT_DISPLAY
  }

  if (!isRecord(parsed)) {
    warnings.push({
      sourceIndex,
      field: 'codeDisplay',
      message: '不是 JSON 对象，已按默认值处理，该条目的 note / tags / trashed / position 全部丢失',
    })
    return DEFAULT_DISPLAY
  }

  // 上游 `fromJson` 把整个对象交给 Dart 的静态类型检查，任一字段类型不对就整体抛错、
  // 落回默认 `CodeDisplay()`。这里同样**全有或全无**：只丢 note 不丢 tags 会造成
  // 「一半字段是原文、一半是默认值」的混合体，比整体退回默认值更难向用户解释。
  const problems: string[] = []
  const { note, tagNames, trashed, position } = readFields(parsed, problems)
  if (problems.length > 0) {
    warnings.push({
      sourceIndex,
      field: 'codeDisplay',
      message: `字段类型不正确（${problems.join('、')}），已按默认值处理，该条目的 note / tags / trashed / position 全部丢失`,
    })
    return DEFAULT_DISPLAY
  }

  if (trashed) {
    // 已删除的条目根本不导入，「pinned 未导入」之类的提示对它没有意义，故只报跳过这一条。
    warnings.push({
      sourceIndex,
      field: 'codeDisplay.trashed',
      message: '该条目在 Ente 中已被删除，已跳过不导入',
    })
    return { ...DEFAULT_DISPLAY, trashed: true }
  }

  for (const field of UNMAPPED_FIELDS) {
    if (field in parsed) {
      warnings.push({
        sourceIndex,
        field: `codeDisplay.${field}`,
        message: '该字段未导入（本 App 暂不保留这项信息）',
      })
    }
  }

  // 长度闸门放在类型检查**之后**，且刻意让它抛出去变成单条失败：`maxFieldLength` 是
  // vault schema 的硬约束，与 Aegis / 2FAS 的 note 超长同判，不能在这里降级成 warning。
  assertFieldLength(note, 'codeDisplay.note')
  for (const tag of tagNames) assertFieldLength(tag, 'codeDisplay.tags')

  return { note, tagNames, trashed, position }
}

function readFields(
  json: Record<string, unknown>,
  problems: string[],
): { note: string; tagNames: string[]; trashed: boolean; position: number } {
  let note = ''
  let trashed = false
  let position = 0
  let tagNames: string[] = []

  const rawNote = json.note
  if (rawNote !== undefined && rawNote !== null) {
    if (typeof rawNote !== 'string') problems.push('note')
    else note = rawNote
  }

  const rawTrashed = json.trashed
  if (rawTrashed !== undefined && rawTrashed !== null) {
    if (typeof rawTrashed !== 'boolean') problems.push('trashed')
    else trashed = rawTrashed
  }

  const rawPosition = json.position
  if (rawPosition !== undefined && rawPosition !== null) {
    // 上游是 Dart `int`：`3.5` 会在赋值时抛错。负值上游不校验，排序时自然排到最前，故放行。
    if (typeof rawPosition !== 'number' || !Number.isSafeInteger(rawPosition)) {
      problems.push('position')
    } else position = rawPosition
  }

  const rawTags = json.tags
  if (rawTags !== undefined && rawTags !== null) {
    // 上游是 `List<String>.from(json['tags'] ?? [])`：非数组、或元素非字符串，都会抛错。
    if (!Array.isArray(rawTags) || rawTags.some((tag) => typeof tag !== 'string')) {
      problems.push('tags')
    } else tagNames = rawTags as string[]
  }

  return { note, tagNames, trashed, position }
}

/**
 * 脱掉 `jsonEncode(uri)` 的引号外壳（`code.dart:205`）。
 *
 * 只对**以引号开头**的行尝试：裸 URI 行不以引号开头，走原样返回，不会被 JSON 解析器
 * 意外吃掉（`otpauth://x?a="b"` 整行不是合法 JSON）。
 */
function unwrapJsonLine(line: string): string {
  if (!line.startsWith('"')) return line
  const parsed = parseJson(line, 'Ente 导出的 JSON 行')
  if (typeof parsed !== 'string') {
    throw new TransferValueError('带引号的行解出来不是字符串，无法按 otpauth URI 解析')
  }
  return parsed
}

export function parseEnte(input: DetectableInput, what = 'Ente 明文导出'): ImportResult {
  const lines = collectOtpAuthLines(readText(input, what), what)

  const placed: Placed[] = []
  const failures: ParseFailure[] = []
  const warnings: ParseWarning[] = []
  let skipped = 0

  for (let ordinal = 0; ordinal < lines.length; ordinal += 1) {
    const line = lines[ordinal]!
    // 条目级 warning 先攒在局部：该条目若随后失败，就不能留下指向一个不存在条目的警告。
    const local: ParseWarning[] = []
    try {
      const parsed = parseOtpAuthUri(unwrapJsonLine(line.text), ordinal)
      const display = readCodeDisplay(parsed.query.get('codeDisplay'), ordinal, local)
      if (display.trashed) {
        skipped += 1
        warnings.push(...local)
        continue
      }
      placed.push({
        entry: { ...parsed.entry, note: display.note, tagNames: display.tagNames },
        position: display.position,
      })
      warnings.push(...parsed.warnings, ...local)
    } catch (error) {
      if (!(error instanceof TransferError)) throw error
      failures.push({
        sourceIndex: ordinal,
        path: `${what} 第 ${line.lineNumber} 行`,
        reason: error.message,
      })
    }
  }

  // `position` 只决定**输出顺序**，不改写 `sourceIndex`（后者恒为非空行序号，
  // 这样 `ParseFailure.path` 的行号才对得上原文）。`Array.prototype.sort` 是稳定排序，
  // 故 position 相同的条目保持文件原序。
  placed.sort((left, right) => left.position - right.position)

  return {
    format: 'ente',
    entries: placed.map((item) => item.entry),
    // Ente 的导出没有独立的标签声明表，`tags` 只存在于 `codeDisplay` 内，故恒为空；
    // 标签由 app 层从 `entries[].tagNames` 汇总。
    tags: [],
    failures,
    warnings,
    skipped,
  }
}
