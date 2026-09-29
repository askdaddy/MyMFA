import { TransferError, TransferFormatError, TransferValueError } from './errors.js'
import { assertEntryCount, isRecord, parseJson, readText } from './input.js'
import {
  normalizeAlgorithm,
  normalizeCounter,
  normalizeDigits,
  normalizeKind,
  normalizePeriod,
} from './normalize.js'
import { decodeIntArraySecret } from './secret.js'
import { optionalText, requiredText } from './text.js'
import type {
  DetectableInput,
  ImportResult,
  ParsedEntry,
  ParseFailure,
  ParseWarning,
} from './types.js'

/**
 * FreeOTP+ 备份（`docs/transfer.md` §2）。权威来源是上游 `SavedTokens.kt` /
 * `Token.java` / `MigrationUtil.kt`（helloworld1/FreeOTPPlus），字段名即 Gson 序列化的
 * Java 私有字段名，**不是** getter 名——`issuerExt` 而非 `issuer`。
 *
 * 三处必须照抄上游而不是凭直觉写的地方：
 *
 * 1. `digits` / `counter` / `period` 是 Java **基本类型**，Gson 无条件序列化，故 TOTP 也带
 *    `counter`、HOTP 也带 `period`。**kind 只能由 `type` 决定**，用字段存在性推断必然读错。
 * 2. `getID()`（`issuerInt` → `issuerExt` → 裸 `label`）与 `getIssuer()`
 *    （`issuerAlt` → `issuerExt` → `issuerInt` → `""`）优先级**不同**，且 `getLabel()` 偏爱
 *    `labelAlt`。`tokenOrder` 里存的是 `getID()` 的结果，匹配必须用 `getID()`；而展示给用户、
 *    因而也是本 App 该导入的，是 `getIssuer()` / `getLabel()`。
 * 3. 上游 `MigrationUtil.kt:27` 用 `tokenOrder.mapNotNull { tokenMap[it] }` 迁移，**未被
 *    `tokenOrder` 引用的 token 会被静默丢弃**。本 App 不复制这条：那是 `docs/transfer.md` §2.1
 *    禁止的静默失败，用户会平白少掉一批密钥。这里把它们追加到末尾并记 warning。
 *
 * counter **不做 ±1 调整**：上游 `generateCodes()` 是 `getHOTP(counter++)`，本 App 的
 * `Entry.counter` 同样是「直接喂给 HMAC 的那个值」，语义已经一致。夹具里与 Aegis 差 1，
 * 差的是 otpauth URI 的 `counter` 参数约定（上游导入时 `-1`、导出时 `+1`），不是存储语义。
 */

/** 上游 `Token.getID()`，逐分支照抄（含「空串等同于不存在」这一判断）。 */
function tokenId(token: Record<string, unknown>): string {
  const issuerInt = typeof token.issuerInt === 'string' ? token.issuerInt : ''
  const issuerExt = typeof token.issuerExt === 'string' ? token.issuerExt : ''
  const label = typeof token.label === 'string' ? token.label : ''
  if (issuerInt !== '') return `${issuerInt}:${label}`
  if (issuerExt !== '') return `${issuerExt}:${label}`
  return label
}

/** 上游 `getIssuer()`：跳过 null **与空串**，与 `text.ts` 的 `firstText`（只跳 null）语义不同。 */
function firstNonEmpty(candidates: readonly (readonly [unknown, string])[]): string {
  for (const [value, path] of candidates) {
    const text = optionalText(value, path)
    if (text !== '') return text
  }
  return ''
}

/**
 * 把 `tokenOrder` 翻译成 `tokens` 的下标序列。
 *
 * 返回的下标**只决定输出顺序**，不改写 `sourceIndex`：`sourceIndex` 恒为 `tokens` 数组下标，
 * 这样 `ParseFailure.path` 始终指向文件里真实的那个元素（步骤 14 的 Ente `position` 同理）。
 */
function resolveOrder(
  rawTokens: readonly unknown[],
  tokenOrder: unknown,
  warnings: ParseWarning[],
): readonly number[] {
  const indices = rawTokens.map((_, index) => index)
  if (tokenOrder === undefined || tokenOrder === null) {
    warnings.push({
      sourceIndex: null,
      field: 'tokenOrder',
      message: '缺少 tokenOrder，已按 tokens 数组顺序导入（可能与 FreeOTP+ 中看到的顺序不同）',
    })
    return indices
  }
  if (!Array.isArray(tokenOrder)) {
    warnings.push({
      sourceIndex: null,
      field: 'tokenOrder',
      message: `tokenOrder 不是数组，已按 tokens 数组顺序导入（实际收到的类型是 ${typeof tokenOrder}）`,
    })
    return indices
  }

  // 上游 `associateBy` 在 id 重复时只保留最后一个；这里改成队列，重复 id 的 token 一个都不丢。
  const byId = new Map<string, number[]>()
  for (const index of indices) {
    const token = rawTokens[index]
    if (!isRecord(token)) continue
    const id = tokenId(token)
    byId.set(id, [...(byId.get(id) ?? []), index])
  }

  const ordered: number[] = []
  const used = new Set<number>()
  for (let position = 0; position < tokenOrder.length; position += 1) {
    const key: unknown = tokenOrder[position]
    if (typeof key !== 'string') {
      warnings.push({
        sourceIndex: null,
        field: `tokenOrder[${position}]`,
        message: `排序项不是字符串，已忽略（实际收到的类型是 ${typeof key}）`,
      })
      continue
    }
    const queue = byId.get(key)
    const index = queue?.shift()
    if (index === undefined) {
      warnings.push({
        sourceIndex: null,
        field: `tokenOrder[${position}]`,
        message: '排序项在 tokens 中找不到对应条目，已忽略',
      })
      continue
    }
    ordered.push(index)
    used.add(index)
  }

  // 未被引用的 token（含结构损坏、算不出 id 的那些）追加到末尾，保持数组原序。
  const orphaned = indices.filter((index) => !used.has(index))
  if (orphaned.length > 0) {
    warnings.push({
      sourceIndex: null,
      field: 'tokenOrder',
      message: `有 ${orphaned.length} 个条目未被 tokenOrder 引用，已追加到末尾（FreeOTP+ 自身会丢弃它们）`,
    })
  }

  return [...ordered, ...orphaned]
}

function parseEntry(raw: unknown, sourceIndex: number, warnings: ParseWarning[]): ParsedEntry {
  if (!isRecord(raw)) throw new TransferValueError('条目不是 JSON 对象')

  const prefix = `tokens[${sourceIndex}]`
  // 先判 kind：FreeOTP+ 的 Steam 令牌是 `issuerExt === "Steam"` 的 TOTP，没有独立类型，
  // 因此这里能拦下的只有上游 `TokenType` 之外的值；Steam 会在 `digits: 5` 那一步失败。
  const kind = normalizeKind(raw.type)
  const secret = decodeIntArraySecret(raw.secret)

  const normalized = normalizeAlgorithm(raw.algo)
  if (normalized.fromMd5) {
    // 上游只做 `Mac.getInstance("Hmac" + algo)` 校验，HmacMD5 在 JCE 里是合法的，
    // 所以这条降级路径在 FreeOTP+ 上**可达**（与 2FAS 不同）。
    warnings.push({ sourceIndex, field: `${prefix}.algo`, message: '原文是 MD5，已归一化为 SHA1' })
  }

  const digits = normalizeDigits(raw.digits) as ParsedEntry['digits']
  const issuer = firstNonEmpty([
    [raw.issuerAlt, `${prefix}.issuerAlt`],
    [raw.issuerExt, `${prefix}.issuerExt`],
    [raw.issuerInt, `${prefix}.issuerInt`],
  ])
  // `getLabel()` 只判 null 不判空串：显式的 `labelAlt: ""` 就该得到空账户名，不该被 `label` 顶掉。
  const account =
    raw.labelAlt !== undefined && raw.labelAlt !== null
      ? requiredText(raw.labelAlt, `${prefix}.labelAlt`)
      : optionalText(raw.label, `${prefix}.label`)

  const category = optionalText(raw.category, `${prefix}.category`)
  const tagNames = category === '' ? [] : [category]

  const base = {
    issuer,
    account,
    secret,
    algo: normalized.algo,
    digits,
    // FreeOTP+ 没有备注字段，也没有收藏概念（`Token.java` 无 note / favorite 字段）。
    // `image` / `imageAlt` 是图标路径，本 App 只做首字母色块，与 2FAS 的 icon 同样不映射、不告警。
    note: '',
    tagNames,
    favorite: false,
    sourceIndex,
  }

  // C8：period / counter 缺失一律失败。上游是基本类型故恒存在，缺失只可能来自手工编辑的文件，
  // 补 30 或 0 会产出一个「算得出但永远错」的验证码。
  if (kind === 'totp') {
    return { ...base, kind, period: normalizePeriod(raw.period) }
  }
  return { ...base, kind, counter: normalizeCounter(raw.counter) }
}

export function parseFreeOtpPlus(input: DetectableInput, what = 'FreeOTP+ 备份'): ImportResult {
  const json = parseJson(readText(input, what), what)
  if (!isRecord(json)) {
    throw new TransferFormatError(`${what} 已损坏：顶层不是 JSON 对象`)
  }

  const rawTokens = json.tokens
  if (!Array.isArray(rawTokens)) {
    throw new TransferFormatError(`${what} 已损坏：tokens 不是数组`)
  }
  assertEntryCount(rawTokens.length, what)

  const warnings: ParseWarning[] = []
  const order = resolveOrder(rawTokens, json.tokenOrder, warnings)

  const entries: ParsedEntry[] = []
  const failures: ParseFailure[] = []
  for (const index of order) {
    // 条目级 warning 先攒在局部：该条目若随后失败，就不能留下指向一个不存在条目的警告。
    const local: ParseWarning[] = []
    try {
      entries.push(parseEntry(rawTokens[index], index, local))
      warnings.push(...local)
    } catch (error) {
      if (!(error instanceof TransferError)) throw error
      failures.push({ sourceIndex: index, path: `tokens[${index}]`, reason: error.message })
    }
  }

  // FreeOTP+ 没有「声明了但没人用」的分组表：category 只存在于 token 上，故 tags 恒为空，
  // 标签由 app 层从 `entries[].tagNames` 汇总。
  return { format: 'freeotp-plus', entries, tags: [], failures, warnings, skipped: 0 }
}
