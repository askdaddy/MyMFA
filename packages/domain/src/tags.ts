import type { Entry, Tag } from '@askdaddy/vault'
import { DomainError, assertNow } from './errors.js'
import { appendPositioned, assertIds } from './positions.js'

function nameOf(value: string): string {
  const name = value.trim()
  if (!name) throw new DomainError('标签名不能为空')
  return name
}
function colorOf(value: string): string {
  const color = value.trim()
  if (!color) throw new DomainError('标签颜色不能为空')
  return color
}
function uniqueName(tags: readonly Tag[], name: string, except?: string): void {
  if (
    tags.some((tag) => tag.id !== except && tag.name.trim().toLowerCase() === name.toLowerCase())
  ) {
    throw new DomainError('标签名称已存在')
  }
}
export function addTag(tags: readonly Tag[], input: Omit<Tag, 'position'>): Tag[] {
  const name = nameOf(input.name)
  uniqueName(tags, name)
  return appendPositioned(tags, { ...input, name, color: colorOf(input.color), position: '' })
}
export function updateTag(
  tags: readonly Tag[],
  id: string,
  patch: { readonly name?: string; readonly color?: string },
): Tag[] {
  assertIds(tags)
  const existing = tags.find((tag) => tag.id === id)
  if (!existing) throw new DomainError('标签不存在')
  const name = nameOf(patch.name ?? existing.name)
  uniqueName(tags, name, id)
  const color = colorOf(patch.color ?? existing.color)
  return tags.map((tag) => (tag.id === id ? { ...tag, name, color } : tag))
}
export function deleteTag(
  entries: readonly Entry[],
  tags: readonly Tag[],
  id: string,
  now: number,
): { entries: Entry[]; tags: Tag[]; affectedCount: number } {
  assertNow(now)
  assertIds(tags)
  if (!tags.some((tag) => tag.id === id)) throw new DomainError('标签不存在')
  let affectedCount = 0
  const next = entries.map((entry) => {
    if (!entry.tagIds.includes(id)) return entry
    affectedCount += 1
    return { ...entry, tagIds: entry.tagIds.filter((tagId) => tagId !== id), updatedAt: now }
  })
  return { entries: next, tags: tags.filter((tag) => tag.id !== id), affectedCount }
}
