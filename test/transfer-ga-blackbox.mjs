import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { URL } from 'node:url'
import { performance } from 'node:perf_hooks'
import * as T from '../packages/transfer/dist/index.js'

const tests = []
const check = (name, run) => tests.push({ name, run })
const fixture = (name) =>
  JSON.parse(
    readFileSync(
      new URL(`../packages/transfer/src/__fixtures__/ga_${name}.json`, import.meta.url),
      'utf8',
    ),
  )
const normal = fixture('normal').cases
const edge = fixture('edge').cases
const malformed = fixture('malformed').cases
const prefix = 'otpauth-migration://offline?data='
const syntheticSecret = Buffer.from('12345678901234567890')

// QA 的测试输入与输出检查均不调用被测 wire helper。
function unsigned(value) {
  let n = BigInt.asUintN(64, BigInt(value))
  const out = []
  do {
    const rest = n / 128n
    out.push(Number(n % 128n) + (rest ? 128 : 0))
    n = rest
  } while (n)
  return Buffer.from(out)
}
function scalar(key, n) {
  return Buffer.concat([unsigned(key * 8), unsigned(n)])
}
function bytes(key, value) {
  const data = Buffer.from(value)
  return Buffer.concat([unsigned(key * 8 + 2), unsigned(data.length), data])
}
function row({
  name = 'issuer:中文/+%:account',
  issuer = '发行方:issuer',
  algo = 1,
  digits = 1,
  kind = 2,
  counter,
  secret = syntheticSecret,
} = {}) {
  return Buffer.concat([
    bytes(1, secret),
    bytes(2, Buffer.from(name)),
    bytes(3, Buffer.from(issuer)),
    scalar(4, algo),
    scalar(5, digits),
    scalar(6, kind),
    ...(counter === undefined ? [] : [scalar(7, counter)]),
  ])
}
function payload(
  rows = [row()],
  { id = 42, size = 1, index = 0, version = 1 } = {},
  extra = Buffer.alloc(0),
) {
  return Buffer.concat([
    ...rows.map((item) => bytes(1, item)),
    scalar(2, version),
    scalar(3, size),
    scalar(4, index),
    scalar(5, id),
    extra,
  ])
}
const toUri = (data) => prefix + data.toString('base64')
const shard = (rows, options, extra) => toUri(payload(rows, options, extra))

function independentRead(data) {
  const fields = []
  let cursor = 0
  function number() {
    let result = 0n
    let multiplier = 1n
    while (true) {
      const byte = data[cursor++]
      assert.notEqual(byte, undefined)
      result += BigInt(byte % 128) * multiplier
      if (byte < 128) return result
      multiplier *= 128n
    }
  }
  while (cursor < data.length) {
    const tag = Number(number())
    const wire = tag % 8
    if (wire === 0) fields.push([Math.floor(tag / 8), number()])
    else {
      assert.equal(wire, 2)
      const length = Number(number())
      fields.push([Math.floor(tag / 8), data.subarray(cursor, cursor + length)])
      cursor += length
    }
  }
  return fields
}
const error = (run) => {
  try {
    run()
  } catch (caught) {
    assert.ok(caught instanceof T.TransferError, `unexpected ${caught.name}`)
    for (const encoding of [
      syntheticSecret.toString(),
      syntheticSecret.toString('hex'),
      syntheticSecret.toString('base64'),
    ])
      assert.ok(!caught.message.includes(encoding))
    return caught
  }
  assert.fail('expected TransferError')
}
function vault(count = 1) {
  const data = JSON.parse(
    readFileSync(
      new URL('../packages/transfer/src/__fixtures__/mfavault_plaintext.json', import.meta.url),
      'utf8',
    ),
  ).data
  const seed = data.entries[0]
  data.entries = Array.from({ length: count }, (_, index) => ({
    ...seed,
    id: `019c0f6a-0000-7000-8000-${(index + 1).toString(16).padStart(12, '0')}`,
    issuer: `发行方:${index}`,
    account: `issuer:account/${index}+%`,
    secret: syntheticSecret.toString('base64'),
    digits: 6,
    period: 30,
    algo: ['SHA1', 'SHA256', 'SHA512'][index % 3],
  }))
  return data
}

check('1 出口与GA探测/普通格式保持', () => {
  for (const name of ['parseGaMigration', 'parseGaMigrationBatch', 'generateGaMigration'])
    assert.equal(typeof T[name], 'function')
  assert.ok(T.FORMAT_IDS.includes('ga-migration'))
  assert.equal(T.detect(normal[0].uri.toUpperCase()), 'ga-migration')
  assert.equal(T.detect('otpauth://totp/account?secret=SYNTHETIC'), 'otpauth-lines')
  assert.deepEqual(
    [...T.EXPORT_DEGRADATIONS['ga-migration'].dropped].sort(),
    ['note', 'tagIds', 'sites', 'usageCount', 'lastUsedAt', 'position', 'favorite'].sort(),
  )
})
check('2 独立固定基线解码，不只做自往返', () => {
  for (const item of normal) {
    const raw = Buffer.from(item.uri.slice(prefix.length), 'base64')
    assert.equal(raw.toString('hex'), item.hex)
    const parsed = T.parseGaMigration(item.uri)
    assert.equal(parsed.entries.length, 1)
    assert.equal(parsed.failures.length, 0)
    assert.deepEqual(Buffer.from(parsed.entries[0].secret), syntheticSecret)
  }
  const parsed = T.parseGaMigration(normal[1].uri)
  assert.equal(parsed.entries[0].counter, 42)
  assert.equal(parsed.entries[0].algo, 'SHA256')
  assert.equal(parsed.entries[0].digits, 8)
})
check('2 截断/非法varint/key/wire/known错位/超声明长度', () => {
  for (const item of malformed) error(() => T.parseGaMigration(item.uri))
  for (const data of [
    Buffer.from([0]),
    Buffer.from([0x80]),
    Buffer.from([11]),
    Buffer.from([12]),
    Buffer.from([14]),
    Buffer.from([15]),
    Buffer.concat([unsigned(2n ** 32n), unsigned(0)]),
    Buffer.concat([Buffer.from([0x0a]), unsigned(2n ** 63n)]),
    Buffer.concat([Buffer.from([0x08]), Buffer.from(Array(9).fill(255)), Buffer.from([2])]),
  ])
    error(() => T.parseGaMigration(toUri(data)))
  error(() => T.parseGaMigration(shard([Buffer.concat([row(), bytes(4, [])])])))
  error(() => T.parseGaMigration(shard([], {}, bytes(2, []))))
})
check('2 unknown wire0/1/2/5跳过，不递归LEN', () => {
  const extra = Buffer.concat([
    scalar(101, 2n ** 64n - 1n),
    unsigned(102 * 8 + 1),
    Buffer.alloc(8),
    bytes(103, Buffer.from(Array(300).fill(0x0b))),
    unsigned(104 * 8 + 5),
    Buffer.alloc(4),
  ])
  const parsed = T.parseGaMigration(shard([Buffer.concat([row(), extra])], {}, extra))
  assert.equal(parsed.entries.length, 1)
  assert.deepEqual(Buffer.from(parsed.entries[0].secret), syntheticSecret)
})
check('2 重复单值最后值，重复消息作为多条目', () => {
  const parsed = T.parseGaMigration(
    shard([Buffer.concat([row(), scalar(4, 3)]), row()], {}, scalar(5, -1)),
  )
  assert.equal(parsed.batchId, -1)
  assert.equal(parsed.entries.length, 2)
  assert.equal(parsed.entries[0].algo, 'SHA512')
})
check('3 URI编码，raw+与百分号，空路径和fragment', () => {
  const input = shard([
    Buffer.concat([row(), bytes(100, Buffer.alloc(30, 251)), bytes(101, Buffer.alloc(30, 255))]),
  ])
  assert.ok(input.includes('+'))
  assert.ok(input.includes('/'))
  const decoded = T.parseGaMigration(input)
  assert.deepEqual(
    T.parseGaMigration(prefix + encodeURIComponent(input.slice(prefix.length))),
    decoded,
  )
  assert.deepEqual(
    T.parseGaMigration(input.replace('offline?', 'offline/?') + '#fragment'),
    decoded,
  )
})
check('3 URI拒绝错误主机/路径/重复data/非法base64与百分号', () => {
  for (const input of [
    normal[0].uri.replace('offline', 'evil'),
    normal[0].uri.replace('offline?', 'offline/evil?'),
    normal[0].uri + '&data=AA==',
    prefix + '%',
    prefix + '!',
    prefix + 'A',
    prefix + 'AAA===',
    prefix + 'AAAA=AAAA',
    prefix + '',
    prefix + 'A A A A',
  ])
    error(() => T.parseGaMigration(input))
})
check('3 version、batchSize/index和signedint32 id边界', () => {
  for (const id of [-2147483648, -1, 0, 2147483647])
    assert.equal(T.parseGaMigration(shard([], { id })).batchId, id)
  assert.equal(T.parseGaMigration(toUri(Buffer.concat([scalar(2, 1), scalar(3, 1)]))).batchIndex, 0)
  for (const version of [0, 2]) error(() => T.parseGaMigration(shard([], { version })))
  for (const size of [0, 1001, 2147483647]) error(() => T.parseGaMigration(shard([], { size })))
  for (const index of [-1, 1, 2147483647]) error(() => T.parseGaMigration(shard([], { index })))
  error(() => T.parseGaMigration(shard([], {}, scalar(5, 2n ** 40n))))
  assert.equal(T.parseGaMigration(shard([], { size: 1000, index: 999 })).batchSize, 1000)
})
check('3/4 URI字节输入不修改、独立secret与安全错误', () => {
  const input = Buffer.from(normal[0].uri)
  const copy = Buffer.from(input)
  const result = T.parseGaMigration(input)
  result.entries[0].secret.fill(0)
  assert.deepEqual(input, copy)
  assert.deepEqual(Buffer.from(T.parseGaMigration(input).entries[0].secret), syntheticSecret)
})
check('4 三算法/digits/type/name/issuer与TOTP默认警告', () => {
  for (const [algo, expected] of [
    [1, 'SHA1'],
    [2, 'SHA256'],
    [3, 'SHA512'],
    [4, 'SHA1'],
  ]) {
    for (const digits of [1, 2]) {
      const result = T.parseGaMigration(shard([row({ algo, digits })]))
      assert.equal(result.entries[0].algo, expected)
      assert.equal(result.entries[0].digits, digits === 1 ? 6 : 8)
      assert.equal(result.entries[0].account, 'issuer:中文/+%:account')
      assert.equal(result.entries[0].issuer, '发行方:issuer')
      assert.equal(result.entries[0].period, 30)
      assert.ok(result.warnings.some((item) => item.field === 'period'))
      assert.equal(
        result.warnings.some((item) => item.field === 'algorithm'),
        algo === 4,
      )
    }
  }
})
check('4 HOTP安全counter不截断，省略0显式警告', () => {
  for (const counter of [0n, 42n, 9007199254740991n])
    assert.equal(
      T.parseGaMigration(shard([row({ kind: 1, counter })])).entries[0].counter,
      Number(counter),
    )
  for (const counter of [-1n, 9007199254740992n, 9223372036854775807n])
    assert.equal(T.parseGaMigration(shard([row({ kind: 1, counter })])).failures.length, 1)
  const zero = T.parseGaMigration(shard([row({ kind: 1 })]))
  assert.equal(zero.entries[0].counter, 0)
  assert.equal(zero.warnings[0].field, 'counter')
})
check('4 空secret/未知枚举/非法UTF8/超长部分失败不影响其他条目', () => {
  const rows = [
    row(),
    row({ secret: [] }),
    row({ algo: 0 }),
    row({ digits: 0 }),
    row({ kind: 0 }),
    row({ algo: 99 }),
    Buffer.concat([row(), bytes(2, [0xc0, 0xaf])]),
    row({ issuer: 'x'.repeat(4097) }),
    row(),
  ]
  const result = T.parseGaMigration(shard(rows))
  assert.deepEqual(
    result.entries.map((item) => item.sourceIndex),
    [0, 8],
  )
  assert.equal(result.failures.length, 7)
  for (const item of result.failures)
    for (const encoding of [
      syntheticSecret.toString(),
      syntheticSecret.toString('hex'),
      syntheticSecret.toString('base64'),
    ])
      assert.ok(!item.reason.includes(encoding))
  assert.equal(
    T.parseGaMigration(shard([row({ issuer: 'x'.repeat(4096) })])).entries[0].issuer.length,
    4096,
  )
})
check('5 乱序相等/缺片明确/重复去重/混batch与冲突拒绝', () => {
  const a = edge[3].uri
  const b = edge[4].uri
  const result = T.parseGaMigrationBatch([a, b])
  assert.deepEqual(T.parseGaMigrationBatch([b, a]), result)
  assert.deepEqual(
    result.entries.map((item) => [item.account, item.sourceIndex]),
    [
      ['first', 0],
      ['second', 1],
    ],
  )
  assert.deepEqual(T.parseGaMigrationBatch([b]).missingIndices, [0])
  assert.equal(T.parseGaMigrationBatch([b]).complete, false)
  const dup = T.parseGaMigrationBatch([b, a, a])
  assert.equal(dup.duplicateCount, 1)
  assert.equal(dup.entries.length, 2)
  assert.equal(dup.complete, true)
  for (const bad of [
    shard([], { size: 2 }),
    shard([], { size: 2, index: 1, id: 43 }),
    shard([], { size: 3, index: 1 }),
    shard([], { size: 2, index: 1, version: 2 }),
  ])
    error(() => T.parseGaMigrationBatch([a, bad]))
  const failed = T.parseGaMigrationBatch([
    shard([row({ algo: 0 }), row()], { size: 2, index: 1 }),
    shard([row()], { size: 2 }),
  ])
  assert.deepEqual(
    failed.entries.map((item) => item.sourceIndex),
    [0, 2],
  )
  assert.equal(failed.failures[0].sourceIndex, 1)
})
check('3/5 全部资源边界两侧，不按声明预分配', () => {
  error(() => T.parseGaMigration(new Uint8Array(16 * 1024 * 1024 + 1)))
  error(() => T.parseGaMigration('x'.repeat(65537)))
  const atLimit = shard([], {}, bytes(100, Buffer.alloc(49000)))
  assert.ok(atLimit.length < 65536)
  assert.equal(T.parseGaMigration(atLimit).entries.length, 0)
  error(() => T.parseGaMigration(shard([], {}, bytes(100, Buffer.alloc(49200)))))
  const emptyRows = Array.from({ length: 10000 }, () => Buffer.alloc(0))
  assert.equal(T.parseGaMigration(shard(emptyRows)).failures.length, 10000)
  error(() => T.parseGaMigration(shard([...emptyRows, Buffer.alloc(0)])))
  const half = emptyRows.slice(0, 5000)
  assert.equal(
    T.parseGaMigrationBatch([shard(half, { size: 2 }), shard(half, { size: 2, index: 1 })]).failures
      .length,
    10000,
  )
  error(() =>
    T.parseGaMigrationBatch([
      shard(half, { size: 2 }),
      shard([...half, Buffer.alloc(0)], { size: 2, index: 1 }),
    ]),
  )
  error(() => T.parseGaMigrationBatch([]))
  assert.equal(T.parseGaMigrationBatch(Array(10000).fill(shard([]))).duplicateCount, 9999)
  error(() => T.parseGaMigrationBatch(Array(10001).fill(shard([]))))
  error(() => T.parseGaMigrationBatch(Array(300).fill(atLimit)))
  const missing = T.parseGaMigrationBatch([shard([], { size: 1000 })])
  assert.equal(missing.missingIndices.length, 999)
})
check('6 独立读取生成字节/分片metadata/可表示OTP往返', () => {
  const data = vault(11)
  data.entries[1] = { ...data.entries[1], kind: 'hotp', counter: Number.MAX_SAFE_INTEGER }
  const before = JSON.stringify(data)
  const output = T.generateGaMigration(data, { batchId: -2147483648 })
  assert.equal(output.uris.length, 2)
  assert.equal(output.verification, 'unverified')
  assert.equal(output.warning, '未经 Google Authenticator 真机扫描验证')
  for (let index = 0; index < output.uris.length; index++) {
    const raw = Buffer.from(decodeURIComponent(output.uris[index].slice(prefix.length)), 'base64')
    const fields = independentRead(raw)
    assert.equal(fields.filter(([key]) => key === 1).length, index === 0 ? 10 : 1)
    for (const [key, expected] of [
      [2, 1n],
      [3, 2n],
      [4, BigInt(index)],
      [5, -2147483648n],
    ])
      assert.equal(BigInt.asIntN(64, fields.find(([number]) => number === key)[1]), expected)
    for (const [offset, [, message]] of fields.filter(([key]) => key === 1).entries()) {
      const record = new Map(independentRead(message))
      const source = data.entries[index * 10 + offset]
      assert.deepEqual(record.get(1), syntheticSecret)
      assert.equal(record.get(2).toString(), source.account)
      assert.equal(record.get(3).toString(), source.issuer)
      assert.equal(record.get(4), BigInt(['SHA1', 'SHA256', 'SHA512'].indexOf(source.algo) + 1))
      assert.equal(record.get(5), 1n)
      assert.equal(record.get(6), source.kind === 'totp' ? 2n : 1n)
      if (source.kind === 'hotp') assert.equal(record.get(7), BigInt(source.counter))
    }
  }
  const result = T.parseGaMigrationBatch([...output.uris].reverse())
  assert.equal(result.complete, true)
  assert.equal(result.entries.length, 11)
  assert.equal(result.entries[1].counter, Number.MAX_SAFE_INTEGER)
  assert.equal(JSON.stringify(data), before)
})
check('6 配置/空vault/不可表示OTP与输出资源上限', () => {
  for (const options of [
    {},
    undefined,
    { batchId: 2147483648 },
    { batchId: -2147483649 },
    { batchId: NaN },
    { batchId: 1.5 },
    ...[0, -1, 1.5, NaN, 10001].map((entriesPerBatch) => ({ batchId: 1, entriesPerBatch })),
  ])
    error(() => T.generateGaMigration(vault(), options))
  for (const entriesPerBatch of [1, 10, 10000])
    assert.equal(T.generateGaMigration(vault(), { batchId: 0, entriesPerBatch }).uris.length, 1)
  assert.equal(T.generateGaMigration(vault(0), { batchId: 0 }).uris.length, 0)
  for (const modification of [
    { digits: 7 },
    { period: 60 },
    { account: '\ud800' },
    { issuer: 'x'.repeat(4097) },
    { secret: Buffer.alloc(60000).toString('base64') },
  ]) {
    const data = vault()
    Object.assign(data.entries[0], modification)
    error(() => T.generateGaMigration(data, { batchId: 1 }))
  }
  error(() => T.generateGaMigration(vault(1001), { batchId: 1, entriesPerBatch: 1 }))
  const large = vault(1000)
  for (const entry of large.entries) {
    entry.account = 'x'.repeat(4096)
    entry.issuer = 'x'.repeat(4096)
  }
  error(() => T.generateGaMigration(large, { batchId: 1, entriesPerBatch: 1000 }))
  const aggregate = vault(4000)
  for (const entry of aggregate.entries) {
    entry.account = 'x'.repeat(4096)
    entry.issuer = 'x'.repeat(4096)
  }
  assert.match(
    error(() => T.generateGaMigration(aggregate, { batchId: 1, entriesPerBatch: 4 })).message,
    /累计/,
  )
  error(() => T.generateGaMigration(vault(10001), { batchId: 1 }))
})
check('7/9 2000任意字节+500有效payload变异+截断，类型化错误且有界', () => {
  let seed = 0x9a6b7c8d
  const random = () => {
    seed ^= seed << 13
    seed ^= seed >>> 17
    seed ^= seed << 5
    return seed >>> 0
  }
  const probe = (data) => {
    try {
      const result = T.parseGaMigration(toUri(data))
      for (const entry of result.entries) entry.secret.fill(0)
    } catch (caught) {
      assert.ok(caught instanceof T.TransferError, `unexpected ${caught.name}`)
    }
  }
  const start = performance.now()
  for (let i = 0; i < 2000; i++)
    probe(Buffer.from(Array.from({ length: random() % 257 }, () => random() % 256)))
  const valid = payload()
  for (let i = 0; i < 500; i++) {
    const mutated = Buffer.from(valid)
    mutated[random() % mutated.length] = random() % 256
    probe(mutated)
  }
  for (let i = 0; i < valid.length; i++) probe(valid.subarray(0, i))
  console.log(
    `  fuzz completed: 2500 + ${valid.length} truncations, ${Math.round(performance.now() - start)} ms`,
  )
})

let failed = 0
for (const { name, run } of tests) {
  try {
    run()
    console.log(`PASS ${name}`)
  } catch (caught) {
    failed++
    console.error(`FAIL ${name}: ${caught.message}`)
  }
}
console.log(`GA blackbox: ${tests.length - failed}/${tests.length} PASS`)
if (failed) process.exitCode = 1
