import { generateKeyBetween, generateNKeysBetween } from 'fractional-indexing'
import type { Entry, Tag } from '@askdaddy/vault'
import { DomainError } from './errors.js'
import { compareText } from './sort.js'
import type { SortMode } from './sort.js'

export const MAX_POSITION_LENGTH = 20
interface Positioned {
  readonly id: string
  readonly position: string
}
export function assertIds(items: readonly Positioned[]): void {
  const ids = new Set(items.map((item) => item.id))
  if (ids.has('') || ids.size !== items.length) throw new DomainError('记录标识为空或重复')
}
export function keyBetween(before: string | null, after: string | null): string {
  if (
    [before, after].some((key) => key !== null && !/^[A-Za-z][0-9A-Za-z]+$/.test(key)) ||
    (before !== null && after !== null && before >= after)
  )
    throw new DomainError('位置键或插入区间无效')
  try {
    return generateKeyBetween(before, after)
  } catch {
    throw new DomainError('位置键或插入区间无效')
  }
}
export function rebalancePositions<T extends Positioned>(items: readonly T[]): T[] {
  assertIds(items)
  const ordered = [...items].sort((a, b) => compareText(a.position, b.position))
  const keys = generateNKeysBetween(null, null, ordered.length)
  return ordered.map((item, i) => ({ ...item, position: keys[i]! }))
}
function prepare<T extends Positioned>(items: readonly T[]): T[] {
  assertIds(items)
  const ordered = [...items].sort((a, b) => compareText(a.position, b.position))
  let previous: string | undefined
  for (const item of ordered) {
    if (item.position.length > MAX_POSITION_LENGTH || item.position === previous)
      return rebalancePositions(ordered)
    try {
      keyBetween(item.position, null)
    } catch {
      return rebalancePositions(ordered)
    }
    previous = item.position
  }
  return ordered
}
export function appendPositioned<T extends Positioned>(items: readonly T[], item: T): T[] {
  assertIds([...items, item])
  const ordered = prepare(items)
  const position = keyBetween(ordered.at(-1)?.position ?? null, null)
  const result = [...ordered, { ...item, position }]
  return position.length > MAX_POSITION_LENGTH ? rebalancePositions(result) : result
}
function movePositioned<T extends Positioned>(
  items: readonly T[],
  id: string,
  beforeId: string | null,
): T[] {
  const ordered = prepare(items)
  const index = ordered.findIndex((item) => item.id === id)
  if (index < 0 || (beforeId !== null && !ordered.some((item) => item.id === beforeId))) {
    throw new DomainError('移动记录或目标不存在')
  }
  if (beforeId === id || (ordered[index + 1]?.id ?? null) === beforeId) return ordered
  const [moving] = ordered.splice(index, 1)
  const target =
    beforeId === null ? ordered.length : ordered.findIndex((item) => item.id === beforeId)
  const position = keyBetween(
    ordered[target - 1]?.position ?? null,
    ordered[target]?.position ?? null,
  )
  ordered.splice(target, 0, { ...moving!, position })
  return position.length > MAX_POSITION_LENGTH ? rebalancePositions(ordered) : ordered
}
export const appendEntry = (entries: readonly Entry[], entry: Entry): Entry[] =>
  appendPositioned(entries, entry)
export function moveEntry(
  entries: readonly Entry[],
  id: string,
  beforeId: string | null,
  mode: SortMode,
): Entry[] {
  if (mode !== 'manual') throw new DomainError('请先切换到手动排序')
  return movePositioned(entries, id, beforeId)
}
export function moveTag(tags: readonly Tag[], id: string, beforeId: string | null): Tag[] {
  return movePositioned(tags, id, beforeId)
}
