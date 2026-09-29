import type { Entry } from '@askdaddy/vault'
import { DomainError } from './errors.js'

export interface FilterOptions {
  readonly match?: 'any' | 'all'
  readonly favoritesOnly?: boolean
}
export function filterEntries(
  entries: readonly Entry[],
  tagIds: readonly string[],
  options: FilterOptions = {},
): Entry[] {
  const match = options.match ?? 'any'
  if (match !== 'any' && match !== 'all') throw new DomainError('标签筛选方式不受支持')
  return entries.filter((entry) => {
    if (options.favoritesOnly && !entry.favorite) return false
    if (tagIds.length === 0) return true
    return match === 'all'
      ? tagIds.every((id) => entry.tagIds.includes(id))
      : tagIds.some((id) => entry.tagIds.includes(id))
  })
}
