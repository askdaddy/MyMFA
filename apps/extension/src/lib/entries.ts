import { base64Encode } from '@askdaddy/crypto'
import { appendEntry, normalizeHostname } from '@askdaddy/domain'
import { base32Decode } from '@askdaddy/otp'
import {
  ENTRY_ALGORITHMS,
  uuidV7,
  type Entry,
  type EntryAlgorithm,
  type VaultData,
} from '@askdaddy/vault'

import type { EntryInput } from './protocol.js'
import { vaultProviders } from './providers.js'

/**
 * EntryInput → Entry 的组装与校验。非法输入抛 `Error`（安全文案，不含 secret 值），
 * 调用方在写盘前捕获，旧数据保持不动——对应步骤 11「无效 secret/域名/OTP 参数被拒绝且旧值保留」。
 */

function text(value: string, label: string): string {
  const trimmed = value.trim()
  if (!trimmed) throw new Error(`${label}不能为空`)
  return trimmed
}

function encodeSecret(base32: string): string {
  try {
    const bytes = base32Decode(base32.trim().replaceAll(' ', ''))
    if (bytes.length === 0) throw new Error('secret 不能为空')
    return base64Encode(bytes)
  } catch (error) {
    if (error instanceof Error && error.message.includes('secret')) throw error
    throw new Error('secret 不是合法的 base32 文本', { cause: error })
  }
}

function encodeSites(sites: readonly string[]): string[] {
  const normalized: string[] = []
  for (const site of sites) {
    const host = normalizeHostname(site)
    if (host === undefined) throw new Error(`绑定域名不合法：${site.trim()}`)
    if (!normalized.includes(host)) normalized.push(host)
  }
  return normalized
}

function assertAlgorithm(algo: EntryAlgorithm): void {
  if (!ENTRY_ALGORITHMS.includes(algo)) throw new Error('摘要算法不受支持')
}

function assertKindParams(input: EntryInput): void {
  if (input.kind === 'totp') {
    if (!Number.isSafeInteger(input.period) || (input.period ?? 0) <= 0) {
      throw new Error('TOTP 周期必须是正整数（秒）')
    }
  } else if (input.kind === 'hotp') {
    if (!Number.isSafeInteger(input.counter) || (input.counter ?? -1) < 0) {
      throw new Error('HOTP 计数器必须是非负整数')
    }
  } else {
    throw new Error('令牌类型不受支持')
  }
}

function assertTagIds(data: VaultData, tagIds: readonly string[]): void {
  const known = new Set(data.tags.map((tag) => tag.id))
  for (const id of tagIds) {
    if (!known.has(id)) throw new Error('所选标签不存在')
  }
}

export function buildEntry(
  input: EntryInput,
  current: VaultData,
): { entry: Entry; append: boolean } {
  assertAlgorithm(input.algo)
  assertKindParams(input)
  assertTagIds(current, input.tagIds)

  const issuer = text(input.issuer, '服务商')
  const account = text(input.account, '账户')
  const sites = encodeSites(input.sites)
  const now = Date.now()

  const existing =
    input.id === undefined ? undefined : current.entries.find((e) => e.id === input.id)
  if (input.id !== undefined && existing === undefined) throw new Error('条目不存在')

  const secret =
    input.secret === undefined || input.secret.trim() === ''
      ? (existing?.secret ??
        (() => {
          throw new Error('secret 不能为空')
        })())
      : encodeSecret(input.secret)

  const base: Entry = {
    id: existing?.id ?? uuidV7(vaultProviders.random),
    kind: input.kind,
    issuer,
    account,
    secret,
    algo: input.algo,
    digits: input.digits,
    period: input.kind === 'totp' ? input.period : undefined,
    counter: input.kind === 'hotp' ? input.counter : undefined,
    tagIds: [...input.tagIds],
    note: input.note.trim(),
    sites,
    usageCount: existing?.usageCount ?? 0,
    lastUsedAt: existing?.lastUsedAt ?? null,
    position: existing?.position ?? '',
    favorite: existing?.favorite ?? false,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  }

  return existing === undefined ? { entry: base, append: true } : { entry: base, append: false }
}

/** `appendEntry` 给新条目生成 fractional index；编辑条目保持原 position。 */
export function withEntry(data: VaultData, input: EntryInput): VaultData {
  const { entry, append } = buildEntry(input, data)
  const entries = append
    ? appendEntry(data.entries, entry)
    : data.entries.map((existing) => (existing.id === entry.id ? entry : existing))
  return { ...data, entries, meta: { ...data.meta, updatedAt: Date.now() } }
}
