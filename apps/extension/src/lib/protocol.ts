import type { Entry, EntryAlgorithm, EntryKind, Settings, Tag } from '@askdaddy/vault'

export interface DisplayEntry {
  id: string
  kind: EntryKind
  issuer: string
  account: string
  code: string
  nextCode: string
  remainingSeconds: number
  period: number
  counter?: number
  tagIds: readonly string[]
  sites: readonly string[]
  note: string
  algo: EntryAlgorithm
  digits: Entry['digits']
  favorite: boolean
  currentSite: boolean
}

export interface Snapshot {
  state: 'empty' | 'locked' | 'ready'
  entries: DisplayEntry[]
  tags: readonly Tag[]
  settings: Settings
  subdomainMatching: boolean
  /** 上一次后台剪贴板清理失败的提示；读取即清除，只在问题发生后的首次快照出现。 */
  clipboardNotice?: string
}

export interface EntryInput {
  id?: string
  kind: EntryKind
  issuer: string
  account: string
  /** base32；编辑时留空表示沿用原 secret。 */
  secret?: string
  algo: EntryAlgorithm
  digits: 6 | 7 | 8
  period?: number
  counter?: number
  tagIds: string[]
  note: string
  sites: string[]
}

/**
 * 单条条目的可编辑字段（含 secret 的 base32 形态）。popup 的 snapshot 刻意不含 secret；
 * options 的编辑表单通过这条受限消息按条获取，页面不持有整份 VaultData。
 */
export interface EntryDetail {
  id: string
  kind: EntryKind
  issuer: string
  account: string
  secretBase32: string
  algo: EntryAlgorithm
  digits: Entry['digits']
  period?: number
  counter?: number
  tagIds: string[]
  note: string
  sites: string[]
}

export interface SiteContext {
  protocol: string
  hostname: string
}

export interface ExportFile {
  filename: string
  /** 容器字节流的 base64；页面侧还原为 Blob 下载。 */
  base64: string
}

export type Request =
  | { type: 'snapshot'; site?: SiteContext; query?: string; tagIds?: string[] }
  | { type: 'create'; password: string }
  | { type: 'import'; base64: string; sourcePassword: string; newPassword: string }
  | { type: 'unlock'; password: string }
  | { type: 'lock' }
  | { type: 'saveEntry'; entry: EntryInput }
  | { type: 'entryDetail'; id: string }
  | { type: 'deleteEntry'; id: string }
  | { type: 'saveSettings'; settings: Partial<Settings>; subdomainMatching?: boolean }
  | { type: 'saveTag'; id?: string; name: string; color: string }
  | { type: 'deleteTag'; id: string }
  | { type: 'export'; plaintext: boolean }
  | { type: 'copied'; id: string; text: string }

export interface Reply<T = unknown> {
  ok: boolean
  value?: T
  error?: string
}

const REQUEST_TYPES = new Set<Request['type']>([
  'snapshot',
  'create',
  'import',
  'unlock',
  'lock',
  'saveEntry',
  'entryDetail',
  'deleteEntry',
  'saveSettings',
  'saveTag',
  'deleteTag',
  'export',
  'copied',
])

/** 消息边界的第一道闸门：结构不合法的输入一律拒绝，不进入任何处理分支。 */
export function parseRequest(value: unknown): Request | undefined {
  if (typeof value !== 'object' || value === null) return undefined
  const candidate = value as { type?: unknown }
  return typeof candidate.type === 'string' && REQUEST_TYPES.has(candidate.type as Request['type'])
    ? (candidate as Request)
    : undefined
}

export async function request<T>(message: Request): Promise<T> {
  const reply = (await browser.runtime.sendMessage(message)) as Reply<T>
  if (!reply?.ok) throw new Error(reply?.error ?? '操作失败')
  return reply.value as T
}
