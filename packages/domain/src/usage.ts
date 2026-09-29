import type { Entry } from '@askdaddy/vault'
import { DomainError, assertNow } from './errors.js'

export type UsageEvent = 'copy' | 'expand' | 'visible'
export function recordUsage(entry: Entry, event: UsageEvent, now: number): Entry {
  assertNow(now)
  if (event === 'visible') return entry
  if (event !== 'copy' && event !== 'expand') throw new DomainError('使用事件不受支持')
  if (
    !Number.isSafeInteger(entry.usageCount) ||
    entry.usageCount < 0 ||
    entry.usageCount >= Number.MAX_SAFE_INTEGER
  )
    throw new DomainError('使用次数超出范围')
  return { ...entry, usageCount: entry.usageCount + 1, lastUsedAt: now, updatedAt: now }
}
export function setFavorite(entry: Entry, favorite: boolean, now: number): Entry {
  assertNow(now)
  return { ...entry, favorite, updatedAt: now }
}
