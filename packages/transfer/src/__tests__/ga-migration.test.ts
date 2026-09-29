import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { utf8Encode } from '@askdaddy/crypto'
import type { VaultData } from '@askdaddy/vault'
import {
  detect,
  FORMAT_IDS,
  EXPORT_DEGRADATIONS,
  generateGaMigration,
  parseGaMigration,
  parseGaMigrationBatch,
  TransferError,
  TransferFormatError,
} from '../index.js'

const fixture = (name: string): { cases: { name: string; uri: string; hex: string }[] } =>
  JSON.parse(readFileSync(new URL(`../__fixtures__/ga_${name}.json`, import.meta.url), 'utf8')) as {
    cases: { name: string; uri: string; hex: string }[]
  }
const normal = fixture('normal').cases
const edge = fixture('edge').cases
const malformed = fixture('malformed').cases
const vault = (): VaultData =>
  JSON.parse(
    readFileSync(new URL('../__fixtures__/mfavault_plaintext.json', import.meta.url), 'utf8'),
  ).data as VaultData

// 独立夹具 writer，不使用被测 wire helper 或生成器。
function vi(value: bigint | number): number[] {
  let n = BigInt.asUintN(64, BigInt(value))
  const bytes: number[] = []
  while (n >= 128n) {
    bytes.push(Number(n & 127n) | 128)
    n >>= 7n
  }
  return [...bytes, Number(n)]
}
function field(key: number, value: number | bigint | readonly number[]): number[] {
  return Array.isArray(value)
    ? [...vi(key * 8 + 2), ...vi(value.length), ...value]
    : [...vi(key * 8), ...vi(value as number | bigint)]
}
function entry(algo = 1, digits = 1, kind = 2, counter?: bigint): number[] {
  return [
    ...field(1, [49, 50, 51]),
    ...field(2, [...utf8Encode('issuer:中文/+%')]),
    ...field(3, [...utf8Encode('发行方:synthetic')]),
    ...field(4, algo),
    ...field(5, digits),
    ...field(6, kind),
    ...(counter === undefined ? [] : field(7, counter)),
  ]
}
function uri(
  rows: readonly number[][],
  size = 1,
  index = 0,
  id = 42,
  extra: number[] = [],
): string {
  return fromBytes([
    ...rows.flatMap((row) => field(1, row)),
    ...field(2, 1),
    ...field(3, size),
    ...field(4, index),
    ...field(5, id),
    ...extra,
  ])
}
function fromBytes(bytes: readonly number[]): string {
  return `otpauth-migration://offline?data=${Buffer.from(bytes).toString('base64')}`
}

describe('GA 固定独立字节基线', () => {
  it.each(normal)('$name', ({ uri: input, hex }) => {
    expect(Buffer.from(input.split('data=')[1]!, 'base64').toString('hex')).toBe(hex)
    const result = parseGaMigration(input)
    expect(result.entries).toHaveLength(1)
    expect(result.failures).toHaveLength(0)
    expect(Buffer.from(result.entries[0]!.secret).toString()).toBe('12345678901234567890')
    expect(result).toMatchObject({ version: 1, batchId: 42, batchSize: 1, batchIndex: 0 })
  })
  it('Unicode 与冒号独立保留，signed int32 两端', () => {
    expect(parseGaMigration(edge[0]!.uri).entries[0]).toMatchObject({
      issuer: '中文:发行方',
      account: 'Synthetic:中文/+%:账户',
      algo: 'SHA512',
      digits: 8,
      period: 30,
    })
    expect(parseGaMigration(edge[0]!.uri).batchId).toBe(-2147483648)
    expect(parseGaMigration(edge[1]!.uri)).toMatchObject({ batchId: 2147483647 })
    expect(parseGaMigration(edge[1]!.uri).entries[0]).toMatchObject({
      counter: Number.MAX_SAFE_INTEGER,
    })
  })
  it.each(malformed)('整包错误 $name', ({ uri: input }) =>
    expect(() => parseGaMigration(input)).toThrow(TransferFormatError),
  )
})

describe('GA 协议/条目边界', () => {
  it.each([1, 2, 3, 4])('algorithm %s', (algo) => {
    const result = parseGaMigration(uri([entry(algo)]))
    expect(result.entries[0]!.algo).toBe(['SHA1', 'SHA256', 'SHA512', 'SHA1'][algo - 1])
    expect(result.warnings.some((warning) => warning.field === 'algorithm')).toBe(algo === 4)
  })
  it.each([0, 5, 127, 2147483647])('未知算法 %s 部分失败', (algo) => {
    const result = parseGaMigration(uri([entry(), entry(algo), entry()]))
    expect(result.entries.map((item) => item.sourceIndex)).toEqual([0, 2])
    expect(result.failures[0]!.sourceIndex).toBe(1)
  })
  it.each([0, 3, 99])('未知digits %s', (digits) =>
    expect(parseGaMigration(uri([entry(1, digits)])).failures).toHaveLength(1),
  )
  it.each([0, 3, 99])('未知kind %s', (kind) =>
    expect(parseGaMigration(uri([entry(1, 1, kind)])).failures).toHaveLength(1),
  )
  it.each([0n, 42n, BigInt(Number.MAX_SAFE_INTEGER)])('HOTP counter %s', (counter) =>
    expect(parseGaMigration(uri([entry(2, 2, 1, counter)])).entries[0]).toMatchObject({
      counter: Number(counter),
      digits: 8,
      kind: 'hotp',
    }),
  )
  it.each([-1n, 9007199254740992n, 9223372036854775807n])('非安全counter %s不截断', (counter) =>
    expect(parseGaMigration(uri([entry(1, 1, 1, counter)])).failures).toHaveLength(1),
  )
  it('来源固定period与proto3零counter有显式警告', () => {
    const result = parseGaMigration(uri([entry(), entry(1, 1, 1)]))
    expect(result.warnings.map((warning) => warning.field)).toEqual(['period', 'counter'])
    expect(result.entries[1]).toMatchObject({ counter: 0 })
  })
  it('空secret、非法UTF8、超长字符串单条失败', () => {
    const result = parseGaMigration(
      uri([
        [...entry(), ...field(1, [])],
        [...entry(), ...field(2, [255])],
        [...entry(), ...field(3, Array(4097).fill(65) as number[])],
        entry(),
      ]),
    )
    expect(result.entries).toHaveLength(1)
    expect(result.failures).toHaveLength(3)
  })
  it('4096长度、重复单值最后值、未知wire跳过', () => {
    const extra = [
      ...field(20, 999),
      ...vi(21 * 8 + 1),
      ...(Array(8).fill(0) as number[]),
      ...field(22, [255, 0]),
      ...vi(23 * 8 + 5),
      ...[0, 0, 0, 0],
    ]
    const result = parseGaMigration(
      uri(
        [[...entry(), ...field(2, Array(4096).fill(65) as number[]), ...field(4, 3), ...extra]],
        1,
        0,
        42,
        extra,
      ),
    )
    expect(result.entries[0]!.account.length).toBe(4096)
    expect(result.entries[0]!.algo).toBe('SHA512')
  })
  it.each([0, 3, 4, 6, 7])('非法key或wire %s', (wire) =>
    expect(() => parseGaMigration(fromBytes([wire === 0 ? 0 : 8 + wire]))).toThrow(TransferError),
  )
  it.each([0, 1001, 2147483647])('size %s', (size) =>
    expect(() => parseGaMigration(uri([], size))).toThrow(TransferError),
  )
  it.each([-1, 1, 2147483647])('index %s', (index) =>
    expect(() => parseGaMigration(uri([], 1, index))).toThrow(TransferError),
  )
  it('省略index与id为proto3零值', () =>
    expect(parseGaMigration(fromBytes([...field(2, 1), ...field(3, 1)]))).toMatchObject({
      batchIndex: 0,
      batchId: 0,
    }))
  it('known wire不允许被当成unknown跳过', () => {
    expect(() => parseGaMigration(uri([], 1, 0, 42, field(2, [])))).toThrow(TransferError)
    expect(() => parseGaMigration(uri([[...entry(), ...field(4, [])]]))).toThrow(TransferError)
  })
  it('URI字节输入不修改，返回secret独立', () => {
    const input = utf8Encode(normal[0]!.uri)
    const snapshot = input.slice()
    parseGaMigration(input).entries[0]!.secret.fill(0)
    expect(input).toEqual(snapshot)
    expect(parseGaMigration(input).entries[0]!.secret[0]).toBe(49)
  })
  it('百分号与raw+编码一致', () => {
    const input = uri([[...entry(), ...field(100, [255, 255, 255])]])
    expect(input).toContain('+')
    expect(parseGaMigration(input)).toEqual(
      parseGaMigration(
        'otpauth-migration://offline?data=' + encodeURIComponent(input.split('data=')[1]!),
      ),
    )
  })
  it.each([
    'otpauth://offline?data=AA==',
    'otpauth-migration://other?data=AA==',
    'otpauth-migration://offline/path?data=AA==',
    'otpauth-migration://offline?data=%',
    'otpauth-migration://offline?data=!',
    'otpauth-migration://offline?data=',
    'otpauth-migration://offline?data=AA==&data=AA==',
  ])('URI非法不回显', (input) => {
    expect(() => parseGaMigration(input)).toThrow(TransferError)
    try {
      parseGaMigration(input)
    } catch (error) {
      expect((error as Error).message).not.toContain(input)
    }
  })
  it('URI/总字节/条目数先限制', () => {
    expect(() => parseGaMigration('x'.repeat(65537))).toThrow(TransferError)
    expect(() => parseGaMigration(new Uint8Array(16 * 1024 * 1024 + 1))).toThrow(TransferError)
    expect(parseGaMigration(uri(Array.from({ length: 10000 }, () => []))).failures).toHaveLength(
      10000,
    )
    expect(() => parseGaMigration(uri(Array.from({ length: 10001 }, () => [])))).toThrow(
      TransferError,
    )
  })
})

describe('GA 分片与生成器', () => {
  const first = edge[3]!.uri
  const second = edge[4]!.uri
  it('乱序、缺片、重复去重与全局序号', () => {
    const complete = parseGaMigrationBatch([first, second])
    expect(parseGaMigrationBatch([second, first])).toEqual(complete)
    expect(complete.entries.map((item) => [item.account, item.sourceIndex])).toEqual([
      ['first', 0],
      ['second', 1],
    ])
    expect(parseGaMigrationBatch([second])).toMatchObject({ complete: false, missingIndices: [0] })
    expect(parseGaMigrationBatch([first, second, first])).toMatchObject({
      duplicateCount: 1,
      complete: true,
      entries: complete.entries,
    })
  })
  it('失败条目也占全局序号', () => {
    const result = parseGaMigrationBatch([uri([entry(0), entry()], 2, 1), uri([entry()], 2, 0)])
    expect(result.entries.map((item) => item.sourceIndex)).toEqual([0, 2])
    expect(result.failures[0]!.sourceIndex).toBe(1)
  })
  it.each([uri([entry()], 2, 0), uri([], 2, 1, 43), uri([], 3, 1)])(
    '内容冲突或不同批次拒绝',
    (input) => expect(() => parseGaMigrationBatch([first, input])).toThrow(TransferError),
  )
  it('空输入、输入数、累计字节、记录数受限', () => {
    expect(() => parseGaMigrationBatch([])).toThrow(TransferError)
    expect(() => parseGaMigrationBatch(Array(10001).fill(first) as string[])).toThrow(TransferError)
    expect(() => parseGaMigrationBatch(Array(300).fill('x'.repeat(60000)) as string[])).toThrow(
      TransferError,
    )
    const rows = Array.from({ length: 5000 }, () => [])
    expect(parseGaMigrationBatch([uri(rows, 2, 0), uri(rows, 2, 1)]).failures).toHaveLength(10000)
    expect(() => parseGaMigrationBatch([uri(rows, 2, 0), uri([...rows, []], 2, 1)])).toThrow(
      TransferError,
    )
  })
  it('生成配置/metadata/OTP字段往返与显式降级', () => {
    const originalVault = vault()
    const source: VaultData = {
      ...originalVault,
      entries: originalVault.entries.map((item) => ({
        ...item,
        digits: 6,
        ...(item.kind === 'totp' ? { period: 30 } : {}),
      })),
    }
    const snapshot = JSON.stringify(source)
    const output = generateGaMigration(source, { batchId: -123, entriesPerBatch: 1 })
    expect(output).toMatchObject({
      verification: 'unverified',
      warning: '未经 Google Authenticator 真机扫描验证',
    })
    const result = parseGaMigrationBatch(output.uris)
    expect(result).toMatchObject({
      complete: true,
      batchSize: source.entries.length,
      batchId: -123,
    })
    for (const [index, item] of result.entries.entries()) {
      const original = source.entries[index]!
      expect(item).toMatchObject({
        kind: original.kind,
        issuer: original.issuer,
        account: original.account,
        algo: original.algo,
        digits: original.digits,
      })
      expect(Buffer.from(item.secret).toString('base64')).toBe(original.secret)
      expect(item.note).toBe('')
      expect(item.tagNames).toEqual([])
      expect(item.favorite).toBe(false)
    }
    expect(JSON.stringify(source)).toBe(snapshot)
    expect(EXPORT_DEGRADATIONS['ga-migration'].dropped).toHaveLength(7)
  })
  it.each([NaN, Infinity, 1.5, -2147483649, 2147483648])('id %s拒绝', (batchId) =>
    expect(() => generateGaMigration(vault(), { batchId })).toThrow(TransferError),
  )
  it.each([0, -1, 1.5, NaN, 10001])('M %s拒绝', (entriesPerBatch) =>
    expect(() => generateGaMigration(vault(), { batchId: 1, entriesPerBatch })).toThrow(
      TransferError,
    ),
  )
  it.each([0, -2147483648, 2147483647])('合法batchId %s', (batchId) => {
    const source: VaultData = { ...vault(), entries: [] }
    expect(generateGaMigration(source, { batchId })).toMatchObject({
      uris: [],
      verification: 'unverified',
    })
  })
  it('无法表示OTP字段明确拒绝', () => {
    const original = vault()
    const source: VaultData = { ...original, entries: [{ ...original.entries[0]!, digits: 7 }] }
    expect(() => generateGaMigration(source, { batchId: 1 })).toThrow(TransferError)
    expect(() =>
      generateGaMigration(
        { ...source, entries: [{ ...source.entries[0]!, digits: 6, period: 60 }] },
        { batchId: 1 },
      ),
    ).toThrow(TransferError)
  })
  it('9格式出口与探测不把迁移当普通URI', () => {
    expect(FORMAT_IDS).toContain('ga-migration')
    expect(detect(normal[0]!.uri)).toBe('ga-migration')
    expect(detect(normal[0]!.uri.toUpperCase())).toBe('ga-migration')
  })
  it('seeded 500任意字节只产生TransferError或正常结果', () => {
    let seed = 9
    for (let count = 0; count < 500; count += 1) {
      const bytes = Array.from({ length: count % 127 }, () => {
        seed = (seed * 1664525 + 1013904223) >>> 0
        return seed & 255
      })
      try {
        parseGaMigration(fromBytes(bytes))
      } catch (error) {
        expect(error).toBeInstanceOf(TransferError)
      }
    }
  })
})
