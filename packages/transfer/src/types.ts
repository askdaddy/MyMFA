import type { EncryptedContainer, Entry, EntryAlgorithm, VaultData } from '@askdaddy/vault'

/**
 * 草稿边界（design 方案 A）：`ParsedEntry` **只承载来源格式真正提供的信息**。
 *
 * `Entry` 的 `id` / `position` / `createdAt` / `updatedAt` 分别需要随机源、`#5 domain` 的
 * fractional index、时钟、时钟——引用其中任何一个都会让解析器不再是纯函数（C6），
 * golden test 也就无法稳定快照。因此这四个字段连同 `tagIds` / `sites` / `usageCount` /
 * `lastUsedAt` 一律不出现在草稿里，由 app 层在 #5 落地后补齐。
 */

export const FORMAT_IDS = [
  'mfavault-plaintext',
  'aegis',
  '2fas',
  'freeotp-plus',
  'ente',
  'bitwarden',
  'otpauth-lines',
  'generic-csv',
] as const

export type FormatId = (typeof FORMAT_IDS)[number]

/** 探测器接受文件字节，也接受粘贴框 / 二维码解码出来的字符串，避免调用方多做一次编码。 */
export type DetectableInput = Uint8Array | string

interface ParsedEntryBase {
  readonly issuer: string
  readonly account: string
  /** **原始字节**，不是编码字符串：判重必须按字节比（C10）。base64 编码推迟到组装 `Entry` 时。 */
  readonly secret: Uint8Array
  readonly algo: EntryAlgorithm
  readonly digits: Entry['digits']
  readonly note: string
  /** 标签**名称**。大小写不敏感去重属 `#5 domain`，本包不做。 */
  readonly tagNames: readonly string[]
  readonly favorite: boolean
  /**
   * 来源文件内的序号，从 0 开始：JSON 是数组下标，CSV 是数据行号，行式文本是行号。
   * app 层据此生成 `position`，因此它同时承担了「保留来源顺序」的职责。
   */
  readonly sourceIndex: number
}

export interface ParsedTotpEntry extends ParsedEntryBase {
  readonly kind: 'totp'
  /** 秒。判别联合保证 totp 必带 period——`guard.ts` 对 period 是条件必填且**无默认值**。 */
  readonly period: number
}

export interface ParsedHotpEntry extends ParsedEntryBase {
  readonly kind: 'hotp'
  readonly counter: number
}

export type ParsedEntry = ParsedTotpEntry | ParsedHotpEntry

/**
 * 来源格式声明的标签。与 `ParsedEntry.tagNames` 分开，是因为 Aegis 的 `db.groups` 与
 * 2FAS 的 `groups` 都允许存在**没有任何条目引用的空分组**，只看条目会丢掉它们。
 */
export interface ParsedTag {
  readonly name: string
  /** 该标签在来源中的声明序号，用于稳定排序。 */
  readonly sourceIndex: number
}

/**
 * **单条**不可用。不是异常——C5「部分成功优于全量失败」要求它被收集而不是抛出。
 * 整包不可用才抛 `TransferFormatError`。
 *
 * `reason` 遵守 C4：只写路径与原因，绝不回显 `secret` 的值或其 base32 / base64 / hex 形式。
 */
export interface ParseFailure {
  readonly sourceIndex: number
  readonly path: string
  readonly reason: string
}

/**
 * 已成功导入、但**处置方式需要让用户知道**的情形（`docs/transfer.md` §2.1）：
 * 已归一化的算法、已按来源默认值补齐的字段、未导入的字段、被跳过的条目。
 * `sourceIndex` 为 `null` 表示这是一条覆盖整个文件的警告。
 */
export interface ParseWarning {
  readonly sourceIndex: number | null
  readonly field: string
  readonly message: string
}

export interface ImportResult {
  readonly format: FormatId
  readonly entries: readonly ParsedEntry[]
  readonly tags: readonly ParsedTag[]
  readonly failures: readonly ParseFailure[]
  readonly warnings: readonly ParseWarning[]
  /** 既不算成功也不算失败的跳过数（如 Bitwarden 中 `login_totp` 为空的行）。 */
  readonly skipped: number
}

/**
 * 本 App 的**未加密**容器（`docs/vault-format.md` §1.2）。
 *
 * 与 vault 的 `EncryptedContainer` 的唯一结构差别是 `encrypted: false` 且 `data` 是
 * **明文对象**而非 base64 的 gzip 密文——因此不涉及 `CompressProvider`，读写全同步。
 */
export interface PlaintextContainer {
  /** 与加密容器同源：两者的 `format` 必须是同一个字面量，否则探测器无法用同一条判据。 */
  readonly format: EncryptedContainer['format']
  readonly version: number
  readonly schemaVersion: number
  readonly encrypted: false
  readonly data: VaultData
}

/**
 * `docs/transfer.md` §3.1 字段降级表的**数据形态**。
 *
 * 存在理由：§3.1 要求「导出前必须展示这张降级表」，而 AGENTS.md §5.4 的二次确认与风险提示
 * 属 UI（#6）。生成器本身不提供确认流程，但 UI 要读的数据必须由本包给出，否则那张表就会在
 * 前端再抄一遍——两处必然漂移。
 *
 * 键名一律取 vault `Entry` 的字段名（`keyof Entry`），于是降级表与数据模型在**编译期**绑定：
 * `Entry` 增删字段时这里会红，而不是等用户投诉「导出去标签没了」。
 */
export interface ExportDegradation {
  /** 该格式完全丢弃的字段（§3.1 的 ❌）。 */
  readonly dropped: readonly (keyof Entry)[]
  /** 语义被削弱的字段（§3.1 的 ⚠️），如 Aegis 的 `position` 退化为数组顺序。 */
  readonly degraded: readonly (keyof Entry)[]
}

/**
 * 只覆盖本 Issue 已实现的两个生成器。本 App 明文备份（`container.ts`）在 §3.1 里全是 ✅，
 * 无需登记；GA 迁移码属 #9，加密 Aegis 属 #10，等它们落地时再补各自的行。
 */
export const EXPORT_DEGRADATIONS = {
  aegis: {
    dropped: ['sites', 'usageCount', 'lastUsedAt', 'favorite'],
    degraded: ['position'],
  },
  'otpauth-lines': {
    dropped: ['note', 'tagIds', 'sites', 'usageCount', 'lastUsedAt', 'position', 'favorite'],
    degraded: [],
  },
} as const satisfies Readonly<Record<'aegis' | 'otpauth-lines', ExportDegradation>>
