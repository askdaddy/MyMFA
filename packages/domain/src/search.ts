import type { Entry, Tag } from '@askdaddy/vault'
import { compareIdentity } from './sort.js'

export interface SearchOptions {
  readonly searchPinyin?: boolean
}
export interface SearchResult {
  readonly entry: Entry
  readonly score: number
}

function score(text: string, query: string): number {
  const value = text.toLowerCase()
  const short = 1 / (1 + Array.from(value).length)
  if (value.startsWith(query)) return 3 + short
  if (value.split(/[^\p{L}\p{N}]+/u).some((word) => word.startsWith(query))) return 2 + short
  const chars = Array.from(query)
  let index = 0
  for (const char of value) if (char === chars[index]) index += 1
  return index === chars.length ? 1 + short : 0
}
export async function searchEntries(
  entries: readonly Entry[],
  tags: readonly Tag[],
  query: string,
  options: SearchOptions = {},
): Promise<SearchResult[]> {
  const needle = query.trim().toLowerCase()
  if (!needle)
    return [...entries]
      .sort((a, b) => Number(b.favorite) - Number(a.favorite))
      .map((entry) => ({ entry, score: 0 }))
  const tagNames = new Map(tags.map((tag) => [tag.id, tag.name]))
  const candidates = entries.map((entry) => ({
    entry,
    fields: [
      entry.issuer,
      entry.account,
      entry.note,
      ...entry.tagIds.map((id) => tagNames.get(id) ?? ''),
    ],
  }))
  const pinyin =
    (options.searchPinyin ?? true) &&
    candidates.some(({ fields }) => fields.some((field) => /\p{Script=Han}/u.test(field)))
      ? (await import('./pinyin.js')).initials
      : undefined
  return candidates
    .map(({ entry, fields }) => ({
      entry,
      score: Math.max(
        0,
        ...fields.map((field) =>
          Math.max(score(field, needle), pinyin ? score(pinyin(field), needle) : 0),
        ),
      ),
    }))
    .filter((result) => result.score > 0)
    .sort(
      (a, b) =>
        Number(b.entry.favorite) - Number(a.entry.favorite) ||
        b.score - a.score ||
        compareIdentity(a.entry, b.entry),
    )
}
