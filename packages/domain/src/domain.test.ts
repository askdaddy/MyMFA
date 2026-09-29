import { describe, expect, it } from 'vitest'
import type { Entry, Tag } from '@askdaddy/vault'
import {
  SORT_MODES,
  DomainError,
  sortEntries,
  keyBetween,
  rebalancePositions,
  appendEntry,
  moveEntry,
  moveTag,
  addTag,
  updateTag,
  deleteTag,
  filterEntries,
  searchEntries,
  recordUsage,
  setFavorite,
  normalizeHostname,
  matchesSite,
  matchingEntries,
} from './index.js'

const entry = (id: string, patch: Partial<Entry> = {}): Entry => ({
  id,
  kind: 'totp',
  issuer: '',
  account: '',
  secret: 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=',
  algo: 'SHA1',
  digits: 6,
  period: 30,
  tagIds: [],
  note: '',
  sites: [],
  usageCount: 0,
  lastUsedAt: null,
  position: 'a0',
  favorite: false,
  createdAt: 0,
  updatedAt: 0,
  ...patch,
})
const tag = (id: string, position = 'a0'): Tag => ({ id, name: id, color: '#123456', position })
const ids = (items: readonly { id: string }[]): string[] => items.map((item) => item.id)
const frozen = <T extends object>(value: T): T => {
  Object.values(value).forEach((child) => {
    if (child !== null && typeof child === 'object') frozen(child)
  })
  return Object.freeze(value)
}

describe('sorting', () => {
  it.each(SORT_MODES)('%s keeps favorites first in both directions', (mode) => {
    const items = frozen([entry('n'), entry('f', { favorite: true })])
    for (const direction of ['asc', 'desc'] as const)
      expect(ids(sortEntries(items, { mode, direction }))).toEqual(['f', 'n'])
  })
  it.each([
    ['manual', { position: 'a1' }, { position: 'a0' }],
    ['issuer', { issuer: 'B' }, { issuer: 'A' }],
    ['account', { account: 'B' }, { account: 'A' }],
    ['createdAt', { createdAt: 2 }, { createdAt: 1 }],
  ] as const)('%s asc and desc', (mode, a, b) => {
    const items = frozen([entry('a', a), entry('b', b)])
    expect(ids(sortEntries(items, { mode }))).toEqual(['b', 'a'])
    expect(ids(sortEntries(items, { mode, direction: 'desc' }))).toEqual(['a', 'b'])
  })
  it.each(['usageCount', 'lastUsedAt'] as const)('%s defaults descending', (mode) => {
    const items = [entry('a', { [mode]: 1 }), entry('b', { [mode]: 2 })]
    expect(ids(sortEntries(items, { mode }))).toEqual(['b', 'a'])
    expect(ids(sortEntries(items, { mode, direction: 'asc' }))).toEqual(['a', 'b'])
  })
  it.each(['asc', 'desc'] as const)('null recent times last under %s', (direction) => {
    expect(
      ids(
        sortEntries([entry('n'), entry('t', { lastUsedAt: 0 })], {
          mode: 'lastUsedAt',
          direction,
        }),
      ),
    ).toEqual(['t', 'n'])
  })
  it('uses raw position comparison, ascending secondary keys and stable ties', () => {
    expect(
      ids(
        sortEntries([entry('v', { position: 'a0V' }), entry('z', { position: 'a0Z' })], {
          mode: 'manual',
        }),
      ),
    ).toEqual(['v', 'z'])
    const items = [
      entry('b', { issuer: 'B' }),
      entry('a1', { issuer: 'A', account: 'a' }),
      entry('a2', { issuer: 'A', account: 'a' }),
    ]
    expect(ids(sortEntries(items, { mode: 'usageCount', direction: 'desc' }))).toEqual([
      'a1',
      'a2',
      'b',
    ])
  })
})

describe('fractional positions', () => {
  it('keeps equal historical positions stable during move recovery', () => {
    const items = frozen([
      entry('z', { issuer: 'Z' }),
      entry('a', { issuer: 'A' }),
      entry('c', { position: 'a1' }),
    ])
    expect(ids(moveEntry(items, 'c', null, 'manual'))).toEqual(['z', 'a', 'c'])
  })
  it('agrees with upstream examples and reports fixed errors', () => {
    expect(keyBetween(null, null)).toBe('a0')
    expect(keyBetween('a0', null)).toBe('a1')
    expect(keyBetween('a0', 'a1')).toBe('a0V')
    for (const [a, b] of [
      ['bad-private-value', null],
      ['a1', 'a0'],
    ] as const) {
      expect(() => keyBetween(a, b)).toThrow(DomainError)
      expect(() => keyBetween(a, b)).toThrow('位置键或插入区间无效')
    }
  })
  it('supports repeated interpolation at both ends and in the middle', () => {
    let a = 'a0'
    let b = 'a1'
    for (let i = 0; i < 200; i++) {
      const mid = keyBetween(a, b)
      expect(a < mid && mid < b).toBe(true)
      if (i % 2) a = mid
      else b = mid
    }
    expect(keyBetween(null, 'a0') < 'a0').toBe(true)
    expect(keyBetween('a0', null) > 'a0').toBe(true)
  })
  it('normal moves alter only the moved record; supports prepend, append and no-op', () => {
    const items = frozen([
      entry('a'),
      entry('b', { position: 'a1' }),
      entry('c', { position: 'a2' }),
    ])
    const moved = moveEntry(items, 'c', 'a', 'manual')
    expect(ids(moved)).toEqual(['c', 'a', 'b'])
    expect(moved[1]).toBe(items[0])
    expect(moved[2]).toBe(items[1])
    expect(ids(moveEntry(items, 'a', null, 'manual'))).toEqual(['b', 'c', 'a'])
    expect(moveEntry(items, 'a', 'b', 'manual')).toEqual(items)
    expect(moveEntry(items, 'a', 'a', 'manual')).toEqual(items)
    expect(appendEntry([], entry('first'))[0]?.position).toBe('a0')
    expect(ids(appendEntry(items, entry('d')))).toEqual(['a', 'b', 'c', 'd'])
  })
  it.each(['legacy', 'a0' + 'V'.repeat(22), 'a0'])('recovers historical %s keys', (position) => {
    const items = frozen([entry('a', { position }), entry('b', { position: 'a0' })])
    const before = [...items].sort((a, b) =>
      a.position < b.position ? -1 : a.position > b.position ? 1 : 0,
    )
    const result = appendEntry(items, entry('c'))
    expect(ids(result)).toEqual([...ids(before), 'c'])
    expect(new Set(result.map((item) => item.position)).size).toBe(3)
    result.forEach((item) => expect(item.position.length).toBeLessThanOrEqual(20))
  })
  it('recovers a newly generated key exceeding the limit', () => {
    const left = 'a0' + '0'.repeat(17) + '1'
    const right = 'a0' + '0'.repeat(17) + '2'
    expect(keyBetween(left, right).length).toBeGreaterThan(20)
    const items = [
      entry('a', { position: left }),
      entry('b', { position: right }),
      entry('c', { position: 'a1' }),
    ]
    const moved = moveEntry(items, 'c', 'b', 'manual')
    expect(ids(moved)).toEqual(['a', 'c', 'b'])
    moved.forEach((item) => expect(item.position.length).toBeLessThanOrEqual(20))
  })
  it('rejects unknown, duplicate and empty IDs and nonmanual moves', () => {
    expect(() => moveEntry([], 'x', null, 'manual')).toThrow(DomainError)
    expect(() => moveEntry([entry('a')], 'a', 'missing', 'manual')).toThrow(DomainError)
    expect(() => appendEntry([entry('a')], entry('a'))).toThrow(DomainError)
    expect(() => appendEntry([], entry(''))).toThrow(DomainError)
    expect(() => moveEntry([entry('a')], 'a', null, 'issuer')).toThrow(DomainError)
    expect(() => rebalancePositions([entry('a'), entry('a')])).toThrow(DomainError)
  })
  it('preserves unknown fields and stable order while rebalancing', () => {
    const items = frozen([
      { ...entry('b', { position: 'old-b' }), extra: { x: 1 } },
      { ...entry('a', { position: 'old-a' }), extra: { x: 2 } },
    ])
    const result = rebalancePositions(items)
    expect(ids(result)).toEqual(['a', 'b'])
    expect(result[0]?.extra).toBe(items[1]?.extra)
  })
  it('seeded drag sequence preserves IDs, ordering, length bounds and input', () => {
    let items = rebalancePositions(Array.from({ length: 20 }, (_, i) => entry(String(i))))
    let seed = 42
    const random = (): number => {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0
      return seed
    }
    for (let i = 0; i < 400; i++) {
      const before = frozen(items)
      const from = random() % items.length
      const target = random() % (items.length + 1)
      const beforeId = items[target]?.id ?? null
      const expected = ids(items)
      if (beforeId !== items[from]!.id) {
        const [id] = expected.splice(from, 1)
        expected.splice(beforeId === null ? expected.length : expected.indexOf(beforeId), 0, id!)
      }
      items = moveEntry(before, before[from]!.id, beforeId, 'manual')
      expect(ids(items)).toEqual(expected)
      expect(new Set(ids(items)).size).toBe(20)
      expect(
        items.every(
          (item, j) =>
            item.position.length <= 20 && (j === 0 || items[j - 1]!.position < item.position),
        ),
      ).toBe(true)
    }
  })
})

describe('tags and filters', () => {
  it('creates, renames, recolors and moves tags without changing IDs', () => {
    const tags = frozen([tag('a')])
    const added = addTag(tags, { id: 'b', name: ' Work ', color: ' red ' })
    expect(added[1]).toEqual({ id: 'b', name: 'Work', color: 'red', position: 'a1' })
    const updated = updateTag(added, 'b', { name: ' Personal ', color: ' blue ' })
    expect(updated[1]?.name).toBe('Personal')
    expect(updated[1]?.color).toBe('blue')
    expect(ids(moveTag(updated, 'b', 'a'))).toEqual(['b', 'a'])
    expect(tags).toEqual([tag('a')])
  })
  it('rejects case insensitive duplicates, blank values, IDs and missing targets', () => {
    const tags = [tag('Work'), tag('b', 'a1')]
    expect(() => addTag(tags, { id: 'c', name: ' work ', color: 'red' })).toThrow(DomainError)
    expect(() => updateTag(tags, 'b', { name: ' WORK ' })).toThrow(DomainError)
    expect(() => updateTag(tags, 'x', {})).toThrow(DomainError)
    expect(() => addTag([], { id: 'a', name: ' ', color: 'red' })).toThrow(DomainError)
    expect(() => updateTag(tags, 'b', { color: ' ' })).toThrow(DomainError)
    expect(() => moveTag(tags, 'x', null)).toThrow(DomainError)
  })
  it('delete counts affected entries, removes all references, preserves opaque fields', () => {
    const items = frozen([
      { ...entry('a', { tagIds: ['t', 't', 'u'] }), opaque: 123 },
      entry('b', { tagIds: ['u'] }),
    ])
    const result = deleteTag(items, [tag('t'), tag('u', 'a1')], 't', 100)
    expect(result.affectedCount).toBe(1)
    expect(ids(result.entries)).toEqual(['a', 'b'])
    expect(result.entries[0]).toEqual({ ...items[0], tagIds: ['u'], updatedAt: 100 })
    expect(result.entries[1]).toBe(items[1])
    expect(ids(result.tags)).toEqual(['u'])
    expect(() => deleteTag(items, [], 't', 100)).toThrow(DomainError)
  })
  it('combines default OR, AND, empty and favorites filtering', async () => {
    const items = frozen([
      entry('a', { issuer: 'Alpha', tagIds: ['a'], favorite: true }),
      entry('b', { issuer: 'Alpha', tagIds: ['b'] }),
      entry('c', { issuer: 'Alpha', tagIds: ['a', 'b'] }),
    ])
    expect(ids(filterEntries(items, ['a', 'b']))).toEqual(['a', 'b', 'c'])
    expect(ids(filterEntries(items, ['a', 'b'], { match: 'all' }))).toEqual(['c'])
    expect(ids(filterEntries(items, [], { match: 'all' }))).toEqual(['a', 'b', 'c'])
    expect(ids(filterEntries(items, ['a', 'b'], { favoritesOnly: true }))).toEqual(['a'])
    expect(filterEntries(items, ['unknown'])).toEqual([])
    expect(
      (await searchEntries(filterEntries(items, ['b']), [], 'alp')).map((r) => r.entry.id),
    ).toEqual(['b', 'c'])
  })
})

describe('search', () => {
  it('ranks prefix, word prefix and subsequence with shorter field preference', async () => {
    const items = frozen([
      entry('sub', { issuer: 'a-l-p-h' }),
      entry('word', { issuer: 'My Alpha' }),
      entry('long', { issuer: 'Alphabet' }),
      entry('short', { issuer: 'Alpha' }),
    ])
    expect((await searchEntries(items, [], ' ALPH ')).map((r) => r.entry.id)).toEqual([
      'short',
      'long',
      'word',
      'sub',
    ])
  })
  it.each(['issuer', 'account', 'note'] as const)('searches %s', async (field) => {
    expect((await searchEntries([entry('a', { [field]: 'needle' })], [], 'needle')).length).toBe(1)
  })
  it('searches tag names and favors favorites over score; maintains stable empty input', async () => {
    const items = [
      entry('n', { issuer: 'needle' }),
      entry('f', { favorite: true, tagIds: ['t'] }),
      entry('z'),
      entry('x'),
    ]
    expect(
      (await searchEntries(items, [{ ...tag('t'), name: 'a needle' }], 'needle')).map(
        (r) => r.entry.id,
      ),
    ).toEqual(['f', 'n'])
    expect((await searchEntries(items, [], ' ')).map((r) => r.entry.id)).toEqual([
      'f',
      'n',
      'z',
      'x',
    ])
  })
  it('breaks score ties by identity then stable input order', async () => {
    const items = [
      entry('b', { issuer: 'B', note: 'needle' }),
      entry('a1', { issuer: 'A', note: 'needle' }),
      entry('a2', { issuer: 'A', note: 'needle' }),
    ]
    expect((await searchEntries(items, [], 'needle')).map((r) => r.entry.id)).toEqual([
      'a1',
      'a2',
      'b',
    ])
  })
  it.each([
    ['支付宝', 'zfb'],
    ['微信', 'wx'],
    ['中国银行', 'zgyh'],
  ])('pinyin %s matches %s', async (issuer, query) => {
    const items = [entry('a', { issuer })]
    expect((await searchEntries(items, [], query)).length).toBe(1)
    expect(await searchEntries(items, [], query, { searchPinyin: false })).toEqual([])
  })
  it('never inspects secrets during read-only queries', async () => {
    const item = entry('a', { issuer: 'Alpha', sites: ['example.com'] })
    Object.defineProperty(item, 'secret', {
      get() {
        throw new Error('secret accessed')
      },
    })
    expect((await searchEntries([item], [], 'alph')).length).toBe(1)
    expect(sortEntries([item], { mode: 'manual' })).toEqual([item])
    expect(matchingEntries([item], { protocol: 'https:', hostname: 'example.com' })).toEqual([item])
  })
})

describe('usage and favorite', () => {
  it.each(['copy', 'expand'] as const)('%s records explicit time and increments count', (event) => {
    const item = frozen({ ...entry('a'), extra: 'preserved' })
    expect(recordUsage(item, event, 100)).toEqual({
      ...item,
      usageCount: 1,
      lastUsedAt: 100,
      updatedAt: 100,
    })
    expect(item.usageCount).toBe(0)
  })
  it('visible does not count and favorite injects time', () => {
    const item = frozen(entry('a'))
    expect(recordUsage(item, 'visible', 100)).toBe(item)
    expect(setFavorite(item, true, 100)).toEqual({ ...item, favorite: true, updatedAt: 100 })
  })
  it.each([-1, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1])('rejects time %s', (now) => {
    expect(() => recordUsage(entry('a'), 'copy', now)).toThrow(DomainError)
    expect(() => setFavorite(entry('a'), true, now)).toThrow(DomainError)
    expect(() => deleteTag([], [tag('t')], 't', now)).toThrow(DomainError)
  })
  it.each([-1, 1.5, Number.MAX_SAFE_INTEGER])(
    'rejects invalid or overflowing usage count %s',
    (usageCount) => {
      expect(() => recordUsage(entry('a', { usageCount }), 'copy', 1)).toThrow(DomainError)
    },
  )
})

describe('site matching', () => {
  it.each([
    ['example.com', 'example.com', true],
    ['example.com', 'sub.example.com', true],
    ['example.com', 'evil-example.com', false],
    ['example.com', 'example.com.evil.org', false],
    ['EXAMPLE.COM', 'example.com', true],
    ['example.com:443', 'example.com.', true],
    ['example.com', 'user@example.com', false],
    ['example.com', 'example.com/path', false],
    ['example.com', 'a..example.com', false],
    ['example.com', '-bad.example.com', false],
    ['example.com', 'example.com:65536', false],
    ['example.com', 'example.com:0', false],
    ['example.com', 'example.com:', false],
    ['example.com', '例子.example.com', false],
    ['127.0.0.1', '127.0.0.1', true],
    ['127.0.0.1', 'sub.127.0.0.1', false],
    ['256.0.0.1', '256.0.0.1', false],
    ['[::1]', '[::1]', false],
    ['xn--fsqu00a.xn--0zwm56d', 'xn--fsqu00a.xn--0zwm56d', true],
  ] as const)('%s -> %s = %s', (site, hostname, expected) => {
    expect(matchesSite(site, { protocol: 'https:', hostname })).toBe(expected)
  })
  it.each(['chrome:', 'file:', 'javascript:', 'data:', 'ftp:'])(
    'rejects protocol %s',
    (protocol) => {
      expect(matchesSite('example.com', { protocol, hostname: 'example.com' })).toBe(false)
    },
  )
  it('supports disabling subdomains, http, stable matching and label limits', () => {
    expect(matchesSite('example.com', { protocol: 'http:', hostname: 'example.com' })).toBe(true)
    expect(
      matchesSite('example.com', { protocol: 'https:', hostname: 'a.example.com' }, false),
    ).toBe(false)
    expect(normalizeHostname('a'.repeat(64) + '.com')).toBeUndefined()
    expect(normalizeHostname(Array(5).fill('a'.repeat(63)).join('.'))).toBeUndefined()
    expect(normalizeHostname(' EXAMPLE.COM.:443 ')).toBe('example.com')
    const items = frozen([
      entry('a', { sites: ['example.com'] }),
      entry('b'),
      entry('c', { sites: ['other.com', 'example.com'] }),
    ])
    expect(ids(matchingEntries(items, { protocol: 'https:', hostname: 'example.com' }))).toEqual([
      'a',
      'c',
    ])
  })
})
