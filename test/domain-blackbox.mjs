import assert from 'node:assert/strict'
import { registerHooks } from 'node:module'
import { readFile } from 'node:fs/promises'
import { log } from 'node:console'
import { URL } from 'node:url'

let dictionaryLoads = 0
const hook = registerHooks({
  resolve(specifier, context, next) {
    if (specifier === 'pinyin-pro') dictionaryLoads += 1
    return next(specifier, context)
  },
})
const d = await import('../packages/domain/dist/index.js')
let passed = 0
async function check(name, run) {
  await run()
  passed += 1
  log('PASS ' + name)
}
const entry = (id, patch = {}) => ({
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
const tag = (id, name = id, position = 'a0') => ({ id, name, color: '#123456', position })
const ids = (records) => records.map((record) => record.id)
const resultIds = (records) => records.map((record) => record.entry.id)
function freeze(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(freeze)
    Object.freeze(value)
  }
  return value
}
const invalid = (run) => assert.throws(run, d.DomainError)
const byPosition = (items) =>
  [...items].sort((a, b) => (a.position < b.position ? -1 : a.position > b.position ? 1 : 0))

await check('步骤1/10：dist公开入口、依赖/catalog与构建平台边界', async () => {
  for (const name of [
    'DomainError',
    'sortEntries',
    'keyBetween',
    'rebalancePositions',
    'appendEntry',
    'moveEntry',
    'moveTag',
    'addTag',
    'updateTag',
    'deleteTag',
    'filterEntries',
    'searchEntries',
    'recordUsage',
    'setFavorite',
    'normalizeHostname',
    'matchesSite',
    'matchingEntries',
  ])
    assert.equal(typeof d[name], 'function')
  assert.equal(d.MAX_POSITION_LENGTH, 20)
  const pkg = JSON.parse(
    await readFile(new URL('../packages/domain/package.json', import.meta.url)),
  )
  assert.deepEqual(pkg.dependencies, {
    '@askdaddy/vault': 'workspace:*',
    'fractional-indexing': 'catalog:',
    'pinyin-pro': 'catalog:',
  })
  const ts = JSON.parse(
    await readFile(new URL('../packages/domain/tsconfig.build.json', import.meta.url)),
  )
  assert.deepEqual(ts.compilerOptions.types, [])
  assert.equal(dictionaryLoads, 0)
})
await check('步骤7：字典在入口、空查询、ASCII候选、禁用时均不加载', async () => {
  const chinese = [entry('a', { issuer: '支付宝' })]
  assert.equal((await d.searchEntries(chinese, [], '')).length, 1)
  assert.deepEqual(await d.searchEntries(chinese, [], 'zfb', { searchPinyin: false }), [])
  assert.equal((await d.searchEntries([entry('b', { issuer: 'Alpha' })], [], 'alp')).length, 1)
  assert.equal(dictionaryLoads, 0)
})
await check('步骤7：启用汉字搜索才加载；支付宝/微信/中国银行首字母', async () => {
  for (const [issuer, query] of [
    ['支付宝', 'zfb'],
    ['微信', 'wx'],
    ['中国银行', 'zgyh'],
  ])
    assert.deepEqual(resultIds(await d.searchEntries([entry('a', { issuer })], [], query)), ['a'])
  assert.equal(dictionaryLoads, 1)
})
hook.deregister()

for (const [mode, small, big] of [
  ['manual', { position: 'a0V' }, { position: 'a0Z' }],
  ['issuer', { issuer: 'A' }, { issuer: 'B' }],
  ['account', { account: 'a' }, { account: 'b' }],
  ['usageCount', { usageCount: 0 }, { usageCount: 7 }],
  ['lastUsedAt', { lastUsedAt: 0 }, { lastUsedAt: 7 }],
  ['createdAt', { createdAt: 0 }, { createdAt: 7 }],
]) {
  await check('步骤2：' + mode + '方向、默认值、收藏覆盖及输入纯度', () => {
    const items = freeze([
      entry('big', big),
      entry('small', small),
      entry('favorite', { ...big, favorite: true }),
    ])
    const snapshot = JSON.stringify(items)
    assert.deepEqual(ids(d.sortEntries(items, { mode, direction: 'asc' })), [
      'favorite',
      'small',
      'big',
    ])
    assert.deepEqual(ids(d.sortEntries(items, { mode, direction: 'desc' })), [
      'favorite',
      'big',
      'small',
    ])
    const descending = ['usageCount', 'lastUsedAt'].includes(mode)
    assert.deepEqual(
      ids(d.sortEntries(items, { mode })),
      descending ? ['favorite', 'big', 'small'] : ['favorite', 'small', 'big'],
    )
    assert.equal(JSON.stringify(items), snapshot)
  })
}
await check('步骤2：null末尾、次级issuer/account升序、完全相同稳定', () => {
  for (const direction of ['asc', 'desc'])
    assert.deepEqual(
      ids(
        d.sortEntries([entry('null'), entry('t', { lastUsedAt: 1 })], {
          mode: 'lastUsedAt',
          direction,
        }),
      ),
      ['t', 'null'],
    )
  const items = [
    entry('b', { issuer: 'B' }),
    entry('az', { issuer: 'A', account: 'z' }),
    entry('aa1', { issuer: 'A', account: 'a' }),
    entry('aa2', { issuer: 'A', account: 'a' }),
  ]
  for (const mode of ['manual', 'usageCount', 'lastUsedAt', 'createdAt'])
    assert.deepEqual(ids(d.sortEntries(items, { mode, direction: 'desc' })), [
      'aa1',
      'aa2',
      'az',
      'b',
    ])
})
await check('步骤3：上游固定键与200次插值，畸形/逆序/相等区间不泄露输入', () => {
  assert.equal(d.keyBetween(null, null), 'a0')
  assert.equal(d.keyBetween('a0', null), 'a1')
  assert.equal(d.keyBetween('a0', 'a1'), 'a0V')
  let a = 'a0'
  let b = 'a1'
  for (let i = 0; i < 200; i++) {
    const middle = d.keyBetween(a, b)
    assert.ok(a < middle && middle < b)
    if (i % 2) a = middle
    else b = middle
  }
  assert.ok(d.keyBetween(null, 'a0') < 'a0')
  for (const [a, b] of [
    ['a1', 'a0'],
    ['a0', 'a0'],
    ['a0!', null],
    ['a0汉', null],
    ['', null],
    ['a0V0', null],
    ['untrusted-key', null],
  ]) {
    assert.throws(
      () => d.keyBetween(a, b),
      (error) => error instanceof d.DomainError && error.message === '位置键或插入区间无效',
    )
  }
})
await check('步骤3/4：正常单记录改位、前/后/相邻/同位/空表插入', () => {
  const items = freeze([entry('a'), entry('b', { position: 'a1' }), entry('c', { position: 'a2' })])
  const moved = d.moveEntry(items, 'c', 'a', 'manual')
  assert.deepEqual(ids(moved), ['c', 'a', 'b'])
  assert.strictEqual(moved[1], items[0])
  assert.strictEqual(moved[2], items[1])
  assert.deepEqual(ids(d.moveEntry(items, 'a', null, 'manual')), ['b', 'c', 'a'])
  assert.deepEqual(d.moveEntry(items, 'a', 'a', 'manual'), items)
  assert.deepEqual(d.moveEntry(items, 'a', 'b', 'manual'), items)
  assert.equal(d.appendEntry([], entry('a'))[0].position, 'a0')
  assert.deepEqual(ids(d.appendEntry(items, entry('d'))), ['a', 'b', 'c', 'd'])
})
await check('步骤3/4：重复/非法/长历史键恢复；新长键触发重排；未知字段保留', () => {
  for (const position of ['a0', 'legacy!', 'a0' + 'V'.repeat(25)]) {
    const items = freeze([{ ...entry('x', { position }), future: { x: 7 } }, entry('a')])
    const output = d.appendEntry(items, entry('new'))
    assert.deepEqual(ids(output), [...ids(byPosition(items)), 'new'])
    assert.equal(new Set(output.map((e) => e.position)).size, 3)
    assert.ok(output.every((e) => e.position.length <= 20))
    assert.equal(output.find((e) => e.id === 'x').future.x, 7)
  }
  const left = 'a0' + '0'.repeat(17) + '1'
  const right = 'a0' + '0'.repeat(17) + '2'
  assert.ok(d.keyBetween(left, right).length > 20)
  const output = d.moveEntry(
    [
      entry('a', { position: left }),
      entry('b', { position: right }),
      entry('c', { position: 'a1' }),
    ],
    'c',
    'b',
    'manual',
  )
  assert.deepEqual(ids(output), ['a', 'c', 'b'])
  assert.ok(output.every((e) => e.position.length <= 20))
})
await check('步骤4：缺失/重复/空ID及非手动拖动拒绝', () => {
  invalid(() => d.moveEntry([], 'x', null, 'manual'))
  invalid(() => d.moveEntry([entry('a')], 'a', 'x', 'manual'))
  invalid(() => d.appendEntry([entry('a')], entry('a')))
  invalid(() => d.appendEntry([], entry('')))
  invalid(() => d.rebalancePositions([entry('a'), entry('a')]))
  invalid(() => d.moveEntry([entry('a')], 'a', null, 'issuer'))
})
await check('步骤4/10：独立种子1000次拖动保序、纯度与位置上限', () => {
  let items = d.rebalancePositions(Array.from({ length: 30 }, (_, i) => entry(String(i))))
  let seed = 20260929
  const random = () => {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0
    return seed
  }
  for (let i = 0; i < 1000; i++) {
    const frozen = freeze(items)
    const snapshot = JSON.stringify(frozen)
    const id = frozen[random() % frozen.length].id
    const beforeId = frozen[random() % (frozen.length + 1)]?.id ?? null
    const expected = ids(frozen)
    if (beforeId !== id) {
      expected.splice(expected.indexOf(id), 1)
      expected.splice(beforeId === null ? expected.length : expected.indexOf(beforeId), 0, id)
    }
    items = d.moveEntry(frozen, id, beforeId, 'manual')
    assert.equal(JSON.stringify(frozen), snapshot)
    assert.deepEqual(ids(items), expected)
    assert.ok(
      items.every(
        (e, j) => e.position.length <= 20 && (j === 0 || items[j - 1].position < e.position),
      ),
    )
  }
})
await check('步骤5：标签增改色/名/移动、trim大小写唯一、未知字段保留', () => {
  const tags = freeze([{ ...tag('a', 'Work'), future: 7 }])
  invalid(() => d.addTag(tags, { id: 'b', name: ' work ', color: 'red' }))
  invalid(() => d.addTag(tags, { id: 'a', name: 'Other', color: 'red' }))
  invalid(() => d.addTag(tags, { id: 'b', name: ' ', color: 'red' }))
  const added = d.addTag(tags, { id: 'b', name: ' Other ', color: ' blue ' })
  assert.equal(added[1].name, 'Other')
  assert.equal(added[1].color, 'blue')
  invalid(() => d.updateTag(added, 'b', { name: ' WORK ' }))
  invalid(() => d.updateTag(added, 'b', { color: '' }))
  invalid(() => d.updateTag(added, 'missing', {}))
  const updated = d.updateTag(added, 'a', { name: ' Personal ', color: ' red ' })
  assert.equal(updated[0].future, 7)
  assert.equal(updated[0].name, 'Personal')
  assert.equal(updated[0].color, 'red')
  assert.deepEqual(ids(d.moveTag(updated, 'b', 'a')), ['b', 'a'])
})
await check('步骤5：删除仅解除关联，条目计数一次，secret及未知字段保持', () => {
  const items = freeze([
    { ...entry('a', { tagIds: ['t', 't', 'u'] }), future: 'kept' },
    entry('b', { tagIds: ['u'] }),
    entry('c', { tagIds: ['t'] }),
  ])
  const output = d.deleteTag(items, [tag('t'), tag('u', 'Other', 'a1')], 't', 123)
  assert.equal(output.affectedCount, 2)
  assert.deepEqual(ids(output.entries), ['a', 'b', 'c'])
  assert.deepEqual(output.entries[0], { ...items[0], tagIds: ['u'], updatedAt: 123 })
  assert.strictEqual(output.entries[1], items[1])
  assert.equal(output.entries[2].secret, items[2].secret)
  assert.deepEqual(ids(output.tags), ['u'])
  invalid(() => d.deleteTag(items, [], 't', 123))
})
await check('步骤6：OR/AND/空选择/未知标签/收藏及筛选再搜索', async () => {
  const items = freeze([
    entry('a', { issuer: 'Alpha', tagIds: ['a'], favorite: true }),
    entry('b', { issuer: 'Alpha', tagIds: ['b'] }),
    entry('c', { issuer: 'Alpha', tagIds: ['a', 'b'] }),
  ])
  assert.deepEqual(ids(d.filterEntries(items, ['a', 'b'])), ['a', 'b', 'c'])
  assert.deepEqual(ids(d.filterEntries(items, ['a', 'b'], { match: 'all' })), ['c'])
  assert.deepEqual(ids(d.filterEntries(items, [], { match: 'all' })), ['a', 'b', 'c'])
  assert.deepEqual(ids(d.filterEntries(items, ['a', 'b'], { favoritesOnly: true })), ['a'])
  assert.deepEqual(d.filterEntries(items, ['unknown']), [])
  assert.deepEqual(resultIds(await d.searchEntries(d.filterEntries(items, ['b']), [], 'alp')), [
    'b',
    'c',
  ])
})
await check('步骤7：四字段、评分层级、短字段、收藏、次级键与空查询稳定', async () => {
  const items = freeze([
    entry('sub', { issuer: 'a-l-p-h' }),
    entry('word', { issuer: 'My Alpha' }),
    entry('long', { issuer: 'Alphabet' }),
    entry('short', { issuer: 'Alpha' }),
  ])
  assert.deepEqual(resultIds(await d.searchEntries(items, [], ' ALPH ')), [
    'short',
    'long',
    'word',
    'sub',
  ])
  for (const field of ['issuer', 'account', 'note'])
    assert.equal(
      (await d.searchEntries([entry('x', { [field]: 'needle' })], [], 'needle')).length,
      1,
    )
  assert.deepEqual(
    resultIds(
      await d.searchEntries([entry('x', { tagIds: ['t'] })], [tag('t', 'Needle')], 'needle'),
    ),
    ['x'],
  )
  assert.deepEqual(
    resultIds(
      await d.searchEntries(
        [entry('n', { issuer: 'needle' }), entry('f', { favorite: true, note: 'a n e e d l e' })],
        [],
        'needle',
      ),
    ),
    ['f', 'n'],
  )
  const ties = [
    entry('b', { issuer: 'B', note: 'needle' }),
    entry('a1', { issuer: 'A', note: 'needle' }),
    entry('a2', { issuer: 'A', note: 'needle' }),
  ]
  assert.deepEqual(resultIds(await d.searchEntries(ties, [], 'needle')), ['a1', 'a2', 'b'])
  assert.deepEqual(
    resultIds(
      await d.searchEntries(
        [entry('z'), entry('f', { favorite: true }), entry('a'), entry('g', { favorite: true })],
        [],
        ' ',
      ),
    ),
    ['f', 'g', 'z', 'a'],
  )
})
await check('步骤7/9：查询不访问secret getter、不用secret做匹配', async () => {
  const item = entry('x', { issuer: 'Alpha', sites: ['example.com'] })
  Object.defineProperty(item, 'secret', {
    get() {
      throw new Error('Unexpected sensitive access')
    },
  })
  assert.equal((await d.searchEntries([item], [], 'alp')).length, 1)
  assert.equal((await d.searchEntries([item], [], 'MTIz')).length, 0)
  assert.strictEqual(d.sortEntries([item], { mode: 'manual' })[0], item)
  assert.strictEqual(d.filterEntries([item], [])[0], item)
  assert.strictEqual(
    d.matchingEntries([item], { protocol: 'https:', hostname: 'example.com' })[0],
    item,
  )
})
await check('步骤8：copy/expand计数，visible不计，时间注入及字段纯度', () => {
  const item = freeze({ ...entry('a', { usageCount: 8 }), future: 7 })
  for (const event of ['copy', 'expand'])
    assert.deepEqual(d.recordUsage(item, event, 123), {
      ...item,
      usageCount: 9,
      lastUsedAt: 123,
      updatedAt: 123,
    })
  assert.strictEqual(d.recordUsage(item, 'visible', 123), item)
  assert.deepEqual(d.setFavorite(item, true, 123), { ...item, favorite: true, updatedAt: 123 })
  for (const now of [-1, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    invalid(() => d.recordUsage(item, 'copy', now))
    invalid(() => d.setFavorite(item, true, now))
    invalid(() => d.deleteTag([], [tag('t')], 't', now))
  }
  for (const usageCount of [-1, 1.5, Number.MAX_SAFE_INTEGER])
    invalid(() => d.recordUsage(entry('a', { usageCount }), 'copy', 0))
})
await check('步骤9：testing.md八类域名匹配完整复现', () => {
  for (const [site, hostname, protocol, expected] of [
    ['github.com', 'github.com', 'https:', true],
    ['github.com', 'gist.github.com', 'https:', true],
    ['gist.github.com', 'github.com', 'https:', false],
    ['github.com', 'evil-github.com', 'https:', false],
    ['github.com', 'github.com.evil.com', 'https:', false],
    ['GitHub.COM', 'github.com', 'https:', true],
    ['github.com:8443', 'github.com', 'https:', true],
    ...['chrome:', 'file:', 'about:'].map((protocol) => [
      'github.com',
      'github.com',
      protocol,
      false,
    ]),
  ])
    assert.equal(d.matchesSite(site, { protocol, hostname }), expected)
})
await check('步骤9：子域开关/端口/根点/伪造/IPv4/IPv6/国际域名边界与匹配保序', () => {
  assert.equal(
    d.matchesSite('github.com', { protocol: 'https:', hostname: 'gist.github.com' }, false),
    false,
  )
  assert.equal(
    d.matchesSite('GitHub.COM.:443', { protocol: 'HTTP:', hostname: 'github.com:80' }),
    true,
  )
  for (const hostname of [
    'user@github.com',
    'github.com/path',
    'github.com?x=1',
    'a..github.com',
    '-bad.github.com',
    'github.com:0',
    'github.com:65536',
    'github.com:',
    '[::1]',
    '例子.github.com',
    'a'.repeat(64) + '.github.com',
  ])
    assert.equal(d.matchesSite('github.com', { protocol: 'https:', hostname }), false)
  assert.equal(d.matchesSite('127.0.0.1', { protocol: 'https:', hostname: '127.0.0.1' }), true)
  assert.equal(d.matchesSite('127.0.0.1', { protocol: 'https:', hostname: 'sub.127.0.0.1' }), false)
  assert.equal(d.normalizeHostname('256.0.0.1'), undefined)
  assert.equal(d.normalizeHostname(Array(5).fill('a'.repeat(63)).join('.')), undefined)
  assert.equal(
    d.matchesSite('xn--fsqu00a.xn--0zwm56d', {
      protocol: 'https:',
      hostname: 'xn--fsqu00a.xn--0zwm56d',
    }),
    true,
  )
  assert.deepEqual(
    ids(
      d.matchingEntries(
        [
          entry('z', { sites: ['github.com'] }),
          entry('no'),
          entry('a', { sites: ['other.com', 'github.com'] }),
        ],
        { protocol: 'https:', hostname: 'github.com' },
      ),
    ),
    ['z', 'a'],
  )
})
await check('步骤4：拖动恢复重复历史键时，同位记录保持原有稳定顺序', () => {
  const items = freeze([
    entry('z', { issuer: 'Z' }),
    entry('a', { issuer: 'A' }),
    entry('c', { position: 'a1' }),
  ])
  assert.deepEqual(ids(d.moveEntry(items, 'c', null, 'manual')), ['z', 'a', 'c'])
})
log('PASS ' + passed + '/' + passed + ' domain public-API black-box checks')
