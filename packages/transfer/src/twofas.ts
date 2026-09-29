import { TransferError, TransferFormatError, TransferValueError } from './errors.js'
import { assertEntryCount, isRecord, parseJson, readText } from './input.js'
import {
  normalizeAlgorithm,
  normalizeCounter,
  normalizeDigits,
  normalizeKind,
  normalizePeriod,
} from './normalize.js'
import { decodeBase32Secret } from './secret.js'
import { firstText, requiredText } from './text.js'
import type {
  DetectableInput,
  ImportResult,
  ParsedEntry,
  ParseFailure,
  ParseWarning,
  ParsedTag,
} from './types.js'

/**
 * 2FAS **明文**备份（`docs/transfer.md` §2）。权威来源为 `twofas/2fas-android` 的
 * `data/services/.../domain/{BackupContent,BackupService,BackupGroup}.kt` 与
 * `mapper/ServiceMapper.kt`（ADR-019：以开源仓库 schema 为准，不猜字段名）。
 *
 * 两处最容易写错的字段位置：
 *
 * 1. **`secret` 在 `services[].secret` 顶层**，不在 `otp` 内。`BackupService.secret` 是
 *    非空必填，而 `otp` 里根本没有 secret 字段。
 * 2. **令牌类型是 `services[].otp.tokenType`**（`"TOTP" | "HOTP" | "STEAM"`）。
 *    `services[].type` 是 `ServiceType` 品牌图标枚举（PascalCase，如 `"Google"`），
 *    上游只拿它做 legacy 图标匹配（`BackupRepositoryImpl.kt` 的 `serviceTypeIdFromLegacy`），
 *    **与 kind 无关**。
 *
 * 四处**刻意不复制**上游的静默降级（`ServiceMapper.kt:136/139/140/143`，C8）：上游把
 * `tokenType` 缺失补成 `TOTP`、`algorithm` 无法识别时落成 `null`（下游再取 SHA1）、
 * `period` / `digits` / `counter` 原样透传 `null`。这些都会产出「算得出但永远是错的」验证码，
 * 本 App 一律判为单条失败。
 */

/**
 * 上游 `BackupContent.CurrentSchema`。**只实现这一版**，更早的版本整包失败而不是逐条降级：
 * `schemaVersion: 1` 的 `services[].otp` 只有 `account` / `issuer` / `label` 三个键，
 * 结构上就凑不出一个可计算验证码的条目（夹具 README §「2FAS schemaVersion: 1 的特殊性」）。
 */
const CURRENT_SCHEMA = 4

/**
 * 上游 `BackupContent.isEncrypted` 的判据是 `reference` 非空，`servicesEncrypted` 是密文载体本身。
 * 加密备份的 `services` 是**空数组**，按明文读会得到「成功导入 0 条」——那是最坏的静默失败，
 * 所以两者任一非空都直接指向加密路径。
 */
const ENCRYPTED_FIELDS = ['servicesEncrypted', 'reference'] as const

function assertSchemaVersion(raw: unknown, what: string): void {
  if (raw === undefined) {
    throw new TransferFormatError(
      `${what} 缺少 schemaVersion，无法判断 2FAS 的备份版本，请在 2FAS 中重新导出`,
    )
  }
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw)) {
    throw new TransferFormatError(
      `${what} 已损坏：schemaVersion 必须是整数，实际收到的类型是 ${typeof raw}`,
    )
  }
  if (raw < CURRENT_SCHEMA) {
    throw new TransferFormatError(
      `${what} 的 schemaVersion=${raw} 过旧，本 App 只实现了 2FAS 的 schemaVersion ${CURRENT_SCHEMA}。` +
        '更早的版本不携带 tokenType / digits / period / algorithm，结构上无法还原出可计算验证码的条目，' +
        '请先在 2FAS 中升级并重新导出（不补默认值：docs/transfer.md §2.1）',
    )
  }
  if (raw > CURRENT_SCHEMA) {
    throw new TransferFormatError(
      `${what} 的 schemaVersion=${raw} 高于本 App 支持的 ${CURRENT_SCHEMA}，请升级 App 后再导入`,
    )
  }
}

function assertNotEncrypted(json: Record<string, unknown>, what: string): void {
  for (const field of ENCRYPTED_FIELDS) {
    const value = json[field]
    if (typeof value === 'string' && value.trim() !== '') {
      // 只回显字段名，不回显值：`servicesEncrypted` 装的正是密文（C4）。
      throw new TransferFormatError(
        `${what} 是 2FAS 的**加密**备份（${field} 非空），需要 2FAS 的主密码才能打开，` +
          '不能按明文备份读取（加密兼容路径属 #10）',
      )
    }
  }
}

/** `groups:[{id,name,isExpanded,updatedAt}]`。`isExpanded` / `updatedAt` 是 UI 状态，不映射。 */
function readGroups(
  json: Record<string, unknown>,
  tags: ParsedTag[],
  warnings: ParseWarning[],
): ReadonlyMap<string, string> {
  const names = new Map<string, string>()
  const raw = json.groups
  // kotlinx 给了 `groups` 默认值 `emptyList()`，故「键缺失」是合法形态，不记 warning。
  if (raw === undefined || raw === null) return names

  if (!Array.isArray(raw)) {
    warnings.push({
      sourceIndex: null,
      field: 'groups',
      message: 'groups 不是数组，已忽略全部分组',
    })
    return names
  }

  for (let index = 0; index < raw.length; index += 1) {
    const group: unknown = raw[index]
    const path = `groups[${index}]`
    if (!isRecord(group) || typeof group.id !== 'string' || typeof group.name !== 'string') {
      warnings.push({ sourceIndex: index, field: path, message: '缺少 id 或 name，已忽略该分组' })
      continue
    }
    try {
      requiredText(group.name, `${path}.name`)
    } catch (error) {
      // 分组名过长只丢掉一个标签，不该牵连引用它的条目，更不该整包失败。
      warnings.push({
        sourceIndex: index,
        field: `${path}.name`,
        message: `${(error as Error).message}，已忽略该分组`,
      })
      continue
    }
    names.set(group.id, group.name)
    tags.push({ name: group.name, sourceIndex: index })
  }

  return names
}

/**
 * 上游导出时 `order.position` 恒等于数组下标（`ServiceMapper.kt:108` 用 `mapIndexed`），
 * 但导入时上游会 `sortedBy { order.position }`（`BackupRepositoryImpl.kt:193`）。
 *
 * 这里**保持数组顺序**：`ParsedEntry.sourceIndex` 的契约是「JSON 是数组下标」（`types.ts`），
 * 按 position 重排会让 sourceIndex 不再是下标，failure 的 `path` 也就对不上原文。
 * 代价是手工改过 position 的文件丢失自定义排序，故不一致时补一条整包 warning，不静默丢弃。
 */
function warnIfOrderDiverges(rawServices: readonly unknown[], warnings: ParseWarning[]): void {
  for (let index = 0; index < rawServices.length; index += 1) {
    const service: unknown = rawServices[index]
    if (!isRecord(service) || !isRecord(service.order)) continue
    const position: unknown = service.order.position
    if (typeof position === 'number' && Number.isSafeInteger(position) && position !== index) {
      warnings.push({
        sourceIndex: null,
        field: 'services[].order.position',
        message:
          `order.position 与数组顺序不一致（services[${index}] 的 position 是 ${position}），` +
          '已按数组顺序导入，来源里的自定义排序未保留',
      })
      return
    }
  }
}

/** `services[].groupId` 是单个字符串引用（不是数组），悬空 id 记 warning 而非失败。 */
function readTagNames(
  raw: Record<string, unknown>,
  sourceIndex: number,
  prefix: string,
  names: ReadonlyMap<string, string>,
  warnings: ParseWarning[],
): readonly string[] {
  const field = `${prefix}.groupId`
  const ref = raw.groupId
  if (ref === undefined || ref === null) return []
  if (typeof ref !== 'string') {
    throw new TransferValueError(`${field} 必须是字符串，实际收到的类型是 ${typeof ref}`)
  }
  const name = names.get(ref)
  if (name === undefined) {
    warnings.push({
      sourceIndex,
      field,
      message: '引用的分组 id 在 groups 中不存在，已忽略该分组',
    })
    return []
  }
  return [name]
}

function parseEntry(
  raw: unknown,
  sourceIndex: number,
  names: ReadonlyMap<string, string>,
  warnings: ParseWarning[],
): ParsedEntry {
  if (!isRecord(raw)) throw new TransferValueError('条目不是 JSON 对象')

  const prefix = `services[${sourceIndex}]`
  // `BackupService.otp` 在上游是非空必填（无默认值），缺了就是文件不符合 schema。
  const otp = raw.otp
  if (!isRecord(otp)) throw new TransferValueError('缺少 otp 对象')

  // 先判 kind：`tokenType:"STEAM"` 必须报「不受支持」，而不是先抱怨它的 `digits:5`。
  const kind = normalizeKind(otp.tokenType)

  // 顶层 `secret`，不是 `otp.secret`（本模块 JSDoc 陷阱 1）。

  // `ServiceMapper.kt:135` 的 `otp.account ?: otp.label` 与 `:138` 的 `otp.issuer`。
  // issuer 再退一级到顶层 `name`：`ParsedEntry` 只有一个服务商槽位，而手工添加的服务
  // `otp.issuer` 可以为 null 而 `name` 有值，直接留空等于把用户唯一填过的名字丢掉。
  const account = firstText([
    [otp.account, `${prefix}.otp.account`],
    [otp.label, `${prefix}.otp.label`],
  ])
  const issuer = firstText([
    [otp.issuer, `${prefix}.otp.issuer`],
    [raw.name, `${prefix}.name`],
  ])

  const normalized = normalizeAlgorithm(otp.algorithm)
  if (normalized.fromMd5) {
    // 上游 `Service.Algorithm` 枚举没有 MD5，正常文件走不到这里；留着是因为
    // `normalizeAlgorithm` 是各格式共用的，MD5 一旦被降级就必须报出（§2.1）。
    warnings.push({
      sourceIndex,
      field: `${prefix}.otp.algorithm`,
      message: '原文是 MD5，已归一化为 SHA1',
    })
  }

  // 2FAS 没有 Aegis 那样的「digits 缺失按默认值补齐」授权：`BackupService.Otp.digits` 可空，
  // 上游透传 null 由下游兜底，那正是 C8 禁止的静默默认值，故缺失即失败。
  const digits = normalizeDigits(otp.digits) as ParsedEntry['digits']

  const tagNames = readTagNames(raw, sourceIndex, prefix, names, warnings)

  const base = {
    issuer,
    account,
    algo: normalized.algo,
    digits,
    // 2FAS 的 `BackupService` 没有备注字段，也没有收藏概念（无 favorite / usageCount 键）。
    note: '',
    tagNames,
    favorite: false,
    sourceIndex,
  }

  // C8：period / counter 缺失一律失败。补 30 或 0 会产出一个「算得出但永远错」的验证码。
  if (kind === 'totp') {
    if (otp.period === undefined || otp.period === null) {
      throw new TransferValueError('totp 条目缺少 period')
    }
    return {
      ...base,
      kind,
      period: normalizePeriod(otp.period),
      secret: decodeBase32Secret(raw.secret),
    }
  }
  if (otp.counter === undefined || otp.counter === null) {
    throw new TransferValueError('hotp 条目缺少 counter')
  }
  return {
    ...base,
    kind,
    counter: normalizeCounter(otp.counter),
    secret: decodeBase32Secret(raw.secret),
  }
}

export function parseTwoFas(input: DetectableInput, what = '2FAS 备份'): ImportResult {
  const json = parseJson(readText(input, what), what)
  if (!isRecord(json)) {
    throw new TransferFormatError(`${what} 已损坏：顶层不是 JSON 对象`)
  }

  assertSchemaVersion(json.schemaVersion, what)
  assertNotEncrypted(json, what)

  const rawServices = json.services
  if (!Array.isArray(rawServices)) {
    throw new TransferFormatError(`${what} 已损坏：services 不是数组`)
  }
  assertEntryCount(rawServices.length, what)

  const tags: ParsedTag[] = []
  const warnings: ParseWarning[] = []
  const names = readGroups(json, tags, warnings)

  const entries: ParsedEntry[] = []
  const failures: ParseFailure[] = []
  for (let index = 0; index < rawServices.length; index += 1) {
    // 条目级 warning 先攒在局部：该条目若随后失败，就不能留下指向一个不存在条目的警告。
    const local: ParseWarning[] = []
    try {
      entries.push(parseEntry(rawServices[index], index, names, local))
      warnings.push(...local)
    } catch (error) {
      if (!(error instanceof TransferError)) throw error
      failures.push({
        sourceIndex: index,
        path: `services[${index}]`,
        reason: error.message,
      })
    }
  }

  warnIfOrderDiverges(rawServices, warnings)

  return { format: '2fas', entries, tags, failures, warnings, skipped: 0 }
}
