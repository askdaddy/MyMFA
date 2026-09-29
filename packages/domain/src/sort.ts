import type { Entry } from '@askdaddy/vault'
import { DomainError } from './errors.js'

export const SORT_MODES = [
  'manual',
  'issuer',
  'account',
  'usageCount',
  'lastUsedAt',
  'createdAt',
] as const
export type SortMode = (typeof SORT_MODES)[number]
export interface SortOptions {
  readonly mode: SortMode
  readonly direction?: 'asc' | 'desc'
}
export const compareText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0)
export const compareIdentity = (a: Entry, b: Entry): number =>
  compareText(a.issuer, b.issuer) || compareText(a.account, b.account)

export function sortEntries(entries: readonly Entry[], options: SortOptions): Entry[] {
  const { mode, direction } = options
  if (
    !SORT_MODES.includes(mode) ||
    (direction !== undefined && direction !== 'asc' && direction !== 'desc')
  ) {
    throw new DomainError('排序方式不受支持')
  }
  const descending =
    direction === 'desc' ||
    (direction === undefined && (mode === 'usageCount' || mode === 'lastUsedAt'))
  return [...entries].sort((a, b) => {
    const favorite = Number(b.favorite) - Number(a.favorite)
    if (favorite) return favorite
    let primary: number
    if (mode === 'lastUsedAt' && (a.lastUsedAt === null || b.lastUsedAt === null)) {
      const missing = Number(a.lastUsedAt === null) - Number(b.lastUsedAt === null)
      if (missing) return missing
      primary = 0
    } else {
      switch (mode) {
        case 'manual':
          primary = compareText(a.position, b.position)
          break
        case 'issuer':
          primary = compareText(a.issuer, b.issuer)
          break
        case 'account':
          primary = compareText(a.account, b.account)
          break
        case 'usageCount':
          primary = a.usageCount - b.usageCount
          break
        case 'lastUsedAt':
          primary = a.lastUsedAt! - b.lastUsedAt!
          break
        case 'createdAt':
          primary = a.createdAt - b.createdAt
          break
      }
    }
    return (descending ? -primary : primary) || compareIdentity(a, b)
  })
}
