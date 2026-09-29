import { utf8Encode } from '@askdaddy/crypto'
import { DEFAULT_DIGITS } from '@askdaddy/otp'
import { assertVaultData, type Entry, type VaultData } from '@askdaddy/vault'

import { TransferError, TransferFormatError, TransferValueError } from './errors.js'
import { assertEntryCount, assertFieldLength, isRecord, parseJson, readText } from './input.js'
import {
  normalizeAlgorithm,
  normalizeCounter,
  normalizeDigits,
  normalizeKind,
  normalizePeriod,
} from './normalize.js'
import { decodeBase32Secret, decodeBase64Secret, encodeBase32Secret } from './secret.js'
import { optionalText, requiredText } from './text.js'
import type {
  DetectableInput,
  ImportResult,
  ParsedEntry,
  ParseFailure,
  ParseWarning,
  ParsedTag,
} from './types.js'

/**
 * Aegis **明文**备份（`docs/transfer.md` §2 第一行，权威来源为 Aegis 仓库的 `docs/vault.md`
 * 与 `vault/VaultEntry.java`）。加密形态的 `db` 是 base64 字符串、`header.slots` 非空，
 * 归 #10；这里遇到就明确指向加密路径，不按明文猜。
 *
 * 两处字段名**与本 App 相反**，是这一格式最容易写错的地方：Aegis 的 `name` 是账户，
 * `issuer` 才是服务商。
 */

/** Aegis `TokenInfo` 的 `_digits` 初值与本 App 的 `DEFAULT_DIGITS` 同为 6，故直接复用常量。 */
const AEGIS_DEFAULT_DIGITS = DEFAULT_DIGITS

/**
 * `db.groups:[{uuid,name}]`（v3 起）。分组表里可以存在**没有任何条目引用**的分组，
 * 所以要单独产出 `ParsedTag`，只看条目会把它们丢掉。
 */
function readGroups(
  db: Record<string, unknown>,
  tags: ParsedTag[],
  warnings: ParseWarning[],
): ReadonlyMap<string, string> {
  const names = new Map<string, string>()
  const raw = db.groups
  if (raw === undefined || raw === null) return names

  if (!Array.isArray(raw)) {
    warnings.push({
      sourceIndex: null,
      field: 'db.groups',
      message: 'db.groups 不是数组，已忽略全部分组',
    })
    return names
  }

  for (let index = 0; index < raw.length; index += 1) {
    const group: unknown = raw[index]
    const path = `db.groups[${index}]`
    if (!isRecord(group) || typeof group.uuid !== 'string' || typeof group.name !== 'string') {
      warnings.push({ sourceIndex: index, field: path, message: '缺少 uuid 或 name，已忽略该分组' })
      continue
    }
    try {
      assertFieldLength(group.name, `${path}.name`)
    } catch (error) {
      // 分组名过长只是丢掉一个标签，不该让整包失败，也不该牵连引用它的条目。
      warnings.push({
        sourceIndex: index,
        field: `${path}.name`,
        message: `${(error as Error).message}，已忽略该分组`,
      })
      continue
    }
    names.set(group.uuid, group.name)
    tags.push({ name: group.name, sourceIndex: index })
  }

  return names
}

/**
 * v3 的 `entries[].groups:[uuid]` 与 legacy 的 `entries[].group:"name"|null` 两种形态。
 * 悬空 uuid 记 warning 而非失败：分组表被裁剪过不该让用户丢掉条目本身。
 */
function readTagNames(
  entry: Record<string, unknown>,
  sourceIndex: number,
  names: ReadonlyMap<string, string>,
  warnings: ParseWarning[],
): readonly string[] {
  const field = `db.entries[${sourceIndex}].groups`
  const refs = entry.groups
  if (Array.isArray(refs)) {
    const resolved: string[] = []
    for (const ref of refs) {
      if (typeof ref !== 'string') {
        warnings.push({ sourceIndex, field, message: '分组引用不是字符串，已忽略' })
        continue
      }
      const name = names.get(ref)
      if (name === undefined) {
        warnings.push({
          sourceIndex,
          field,
          message: '引用的分组 uuid 在 db.groups 中不存在，已忽略该分组',
        })
        continue
      }
      resolved.push(name)
    }
    return resolved
  }

  const legacy = entry.group
  if (legacy === undefined || legacy === null) return []
  return [requiredText(legacy, `db.entries[${sourceIndex}].group`)]
}

function parseEntry(
  raw: unknown,
  sourceIndex: number,
  names: ReadonlyMap<string, string>,
  warnings: ParseWarning[],
): ParsedEntry {
  if (!isRecord(raw)) throw new TransferValueError('条目不是 JSON 对象')

  // 先判 kind：`type:"steam"` 必须报「不受支持」，而不是先抱怨它的 `digits:5`。
  const kind = normalizeKind(raw.type)

  const info = raw.info
  if (!isRecord(info)) throw new TransferValueError('缺少 info 对象')

  const prefix = `db.entries[${sourceIndex}]`
  const account = requiredText(raw.name, `${prefix}.name`)
  const issuer = optionalText(raw.issuer, `${prefix}.issuer`)
  const note = optionalText(raw.note, `${prefix}.note`)
  const secret = decodeBase32Secret(info.secret)

  const normalized = normalizeAlgorithm(info.algo)
  if (normalized.fromMd5) {
    warnings.push({
      sourceIndex,
      field: `${prefix}.info.algo`,
      message: '原文是 MD5，已归一化为 SHA1',
    })
  }

  let digits: ParsedEntry['digits']
  if (info.digits === undefined || info.digits === null) {
    warnings.push({
      sourceIndex,
      field: `${prefix}.info.digits`,
      message: `缺少 digits，已按 Aegis 的默认值 ${AEGIS_DEFAULT_DIGITS} 补齐`,
    })
    digits = AEGIS_DEFAULT_DIGITS
  } else {
    digits = normalizeDigits(info.digits) as ParsedEntry['digits']
  }

  const tagNames = readTagNames(raw, sourceIndex, names, warnings)

  const base = {
    issuer,
    account,
    secret,
    algo: normalized.algo,
    digits,
    note,
    tagNames,
    // Aegis 没有收藏概念，也没有 usageCount / lastUsedAt 的导出（design §要点 8），故一律不映射。
    favorite: false,
    sourceIndex,
  }

  // C8：period / counter 缺失一律失败。补 30 或 0 会产出一个「算得出但永远错」的验证码。
  if (kind === 'totp') {
    if (info.period === undefined || info.period === null) {
      throw new TransferValueError('totp 条目缺少 period')
    }
    return { ...base, kind, period: normalizePeriod(info.period) }
  }
  if (info.counter === undefined || info.counter === null) {
    throw new TransferValueError('hotp 条目缺少 counter')
  }
  return { ...base, kind, counter: normalizeCounter(info.counter) }
}

export function parseAegis(input: DetectableInput, what = 'Aegis 备份'): ImportResult {
  const json = parseJson(readText(input, what), what)
  if (!isRecord(json)) {
    throw new TransferFormatError(`${what} 已损坏：顶层不是 JSON 对象`)
  }

  const db = json.db
  if (typeof db === 'string') {
    throw new TransferFormatError(
      `${what} 是 Aegis 的**加密**备份，需要主密码才能打开，不能按明文备份读取（加密兼容路径属 #10）`,
    )
  }
  if (!isRecord(db)) {
    throw new TransferFormatError(`${what} 已损坏：缺少 db 对象`)
  }

  const rawEntries = db.entries
  if (!Array.isArray(rawEntries)) {
    throw new TransferFormatError(`${what} 已损坏：db.entries 不是数组`)
  }
  assertEntryCount(rawEntries.length, what)

  const tags: ParsedTag[] = []
  const warnings: ParseWarning[] = []
  const names = readGroups(db, tags, warnings)

  const entries: ParsedEntry[] = []
  const failures: ParseFailure[] = []
  for (let index = 0; index < rawEntries.length; index += 1) {
    // 条目级 warning 先攒在局部：该条目若随后失败，就不能留下指向一个不存在条目的警告。
    const local: ParseWarning[] = []
    try {
      entries.push(parseEntry(rawEntries[index], index, names, local))
      warnings.push(...local)
    } catch (error) {
      if (!(error instanceof TransferError)) throw error
      failures.push({
        sourceIndex: index,
        path: `db.entries[${index}]`,
        reason: error.message,
      })
    }
  }

  return { format: 'aegis', entries, tags, failures, warnings, skipped: 0 }
}

/** 顶层 `version` 与 `header`：明文备份的 `slots` / `params` 恒为 `null`（`aegis_plain.json`）。 */
const AEGIS_FILE_VERSION = 1

/**
 * 写 `db.version: 3` 而不是 1：分组表 `db.groups` 自 v3 起才存在（见文件头对 `readGroups` 的
 * 说明），要还原标签就必须是 v3。v1 只有 `entries[].group:"name"` 这种单分组形态，
 * 与本 App 的多标签模型对不上。
 */
const AEGIS_DB_VERSION = 3

/**
 * `docs/transfer.md` §3.1 对 `position` 的判定是 ⚠️「数组顺序」而**不是** ❌：Aegis 没有
 * position 字段，但它按 `db.entries` 的顺序显示条目。要让那一格成立，写出的数组顺序就必须是
 * 用户的显示顺序，即 fractional index 的**字典序**（`docs/vault-format.md` §2.1 对
 * `Entry.position` 的契约）。
 *
 * 用 `<` / `>` 而不是 `localeCompare`：后者随运行环境的 ICU locale 变化，会让「同一输入
 * 逐字节相同的输出」这条纯函数要求在不同机器上不成立。
 *
 * 只排序，不生成也不重排 fractional index——那属 `#5 domain`（AGENTS.md §2），
 * 且 `INTERNAL_DEPS` 也禁止 transfer 依赖 domain。
 */
function byPosition<T extends { readonly position: string }>(items: readonly T[]): T[] {
  return [...items].sort((a, b) => (a.position < b.position ? -1 : a.position > b.position ? 1 : 0))
}

function toAegisEntry(entry: Entry, uuidsOfTag: ReadonlySet<string>) {
  // 指向不存在标签的 `tagIds` 无法还原成分组名，只能丢掉：`assertVaultData` 不校验引用完整性
  // （`guard.ts:112` 只查「字符串数组」），既然它在闸门处合法，导出就不该为它整体失败。
  const groups = entry.tagIds.filter((id) => uuidsOfTag.has(id))

  const secret = encodeBase32Secret(decodeBase64Secret(entry.secret))
  // `assertVaultData` 已保证 totp 必带 period、hotp 必带 counter（`guard.ts:103-110`），故这两处
  // 非空断言恒真。必须显式取出来而不是直接展开 `entry`：`JSON.stringify` 会静默丢掉值为
  // `undefined` 的键，那会产出一个「能被 Aegis 打开、但周期是默认值」的错码文件。
  const timing = entry.kind === 'totp' ? { period: entry.period! } : { counter: entry.counter! }

  return {
    type: entry.kind,
    // Aegis 的 `uuid` 用它自己的分组/条目主键语义，本 App 的 `Entry.id` 已是 UUID v7，直接沿用：
    // 既省掉一次随机源（纯函数要求），也让同一 vault 的两次导出产物逐字节相同。
    uuid: entry.id,
    // 字段名与本 App **相反**（见文件头）：Aegis 的 `name` 是账户，`issuer` 才是服务商。
    name: entry.account,
    issuer: entry.issuer,
    // 本 App 不做图标（用户决策：只用首字母色块），写 `null` 与上游 vendored 样本同形。
    icon: null,
    icon_mime: null,
    note: entry.note,
    groups,
    info: { secret, algo: entry.algo, digits: entry.digits, ...timing },
  }
}

/**
 * 导出为 Aegis **明文** JSON（`docs/transfer.md` §3 的「Aegis 明文」行，双向迁移）。
 *
 * 丢弃 `sites` / `usageCount` / `lastUsedAt` / `favorite` 与 `_usageCount` /
 * `_lastUsedTimestamp`：前四个是 §3.1 降级表里的 ❌，后两个上游压根不导出（design §要点 8）。
 * 丢了什么由 `types.ts` 的 `EXPORT_DEGRADATIONS.aegis` 以数据形式给 UI；本函数不做二次确认
 * 与风险提示——那属 AGENTS.md §5.4 的 UI 职责，归 #6。
 *
 * 纯函数：不读时钟、不读随机源（uuid 沿用 `Entry.id` / `Tag.id`），同一 `VaultData` 连续调用
 * 两次产出逐字节相同的结果。
 */
export function generateAegis(vault: VaultData): Uint8Array {
  const data = assertVaultData(vault)

  const tags = byPosition(data.tags)
  const groups = tags.map((tag) => ({ uuid: tag.id, name: tag.name }))
  // `Tag.id` 已是 UUID v7，直接当 Aegis 的分组 uuid 用：既是合法的 RFC 4122 文本形态
  // （上游用 Gson 反序列化成 `java.util.UUID`，编造的字符串会让它整包打不开），又省掉一次随机源。
  const uuidsOfTag = new Set(groups.map((group) => group.uuid))
  const entries = byPosition(data.entries).map((entry) => toAegisEntry(entry, uuidsOfTag))

  const file = {
    version: AEGIS_FILE_VERSION,
    header: { slots: null, params: null },
    db: { version: AEGIS_DB_VERSION, groups, entries },
  }
  return utf8Encode(JSON.stringify(file))
}
