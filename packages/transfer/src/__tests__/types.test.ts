import { describe, expect, it } from 'vitest'

import type {
  ImportResult,
  ParsedEntry,
  ParsedHotpEntry,
  ParsedTag,
  ParsedTotpEntry,
  ParseFailure,
  ParseWarning,
  PlaintextContainer,
} from '../types.js'
import { FORMAT_IDS } from '../types.js'

const FORBIDDEN = [
  'id',
  'position',
  'tagIds',
  'sites',
  'usageCount',
  'lastUsedAt',
  'createdAt',
  'updatedAt',
] as const

type ForbiddenKey = (typeof FORBIDDEN)[number]

/**
 * 编译期断言：`ParsedEntry` 一旦长出任何「需要随机源 / 时钟 / #5 fractional index」的字段，
 * `HasForbidden` 就变成 `true`，下面的 `const hasForbidden: HasForbidden = false` 立即编译失败。
 */
type HasForbidden = Extract<keyof ParsedEntry, ForbiddenKey> extends never ? false : true
const hasForbidden: HasForbidden = false

const BASE = {
  issuer: 'GitHub',
  account: 'alice@example.com',
  secret: new Uint8Array([1, 2, 3]),
  algo: 'SHA1',
  digits: 6,
  note: '',
  tagNames: [],
  favorite: false,
} as const

const TOTP: ParsedTotpEntry = { ...BASE, kind: 'totp', period: 30, sourceIndex: 0 }
const HOTP: ParsedHotpEntry = { ...BASE, kind: 'hotp', counter: 42, sourceIndex: 1 }

/** 判别联合的收窄必须在编译期成立，否则 app 层无法安全地按 kind 取 period / counter。 */
function periodOrCounter(entry: ParsedEntry): number {
  return entry.kind === 'totp' ? entry.period : entry.counter
}

describe('ParsedEntry 的草稿边界', () => {
  it('类型上不存在任何需要随机源、时钟或 #5 fractional index 的字段', () => {
    expect(hasForbidden).toBe(false)

    const present = Object.keys(TOTP).filter((key) =>
      (FORBIDDEN as readonly string[]).includes(key),
    )
    expect(present).toEqual([])
    expect(Object.keys(HOTP).filter((k) => (FORBIDDEN as readonly string[]).includes(k))).toEqual(
      [],
    )
  })

  it('判别联合保证 totp 必带 period、hotp 必带 counter', () => {
    expect(periodOrCounter(TOTP)).toBe(30)
    expect(periodOrCounter(HOTP)).toBe(42)
    expect('counter' in TOTP).toBe(false)
    expect('period' in HOTP).toBe(false)

    // @ts-expect-error totp 分支缺 period 必须编译失败
    const noPeriod: ParsedTotpEntry = { ...BASE, kind: 'totp', sourceIndex: 0 }
    // @ts-expect-error hotp 分支缺 counter 必须编译失败
    const noCounter: ParsedHotpEntry = { ...BASE, kind: 'hotp', sourceIndex: 0 }
    expect(noPeriod.kind).toBe('totp')
    expect(noCounter.kind).toBe('hotp')
  })

  it('含 spec 要求的全部字段，secret 是字节而非编码字符串', () => {
    expect(TOTP.secret).toBeInstanceOf(Uint8Array)
    for (const key of [
      'kind',
      'issuer',
      'account',
      'secret',
      'algo',
      'digits',
      'tagNames',
      'sourceIndex',
    ]) {
      expect(Object.keys(TOTP)).toContain(key)
    }
  })
})

describe('FORMAT_IDS', () => {
  it('覆盖 spec 要求的全部格式，且无重复', () => {
    for (const id of [
      'mfavault-plaintext',
      'aegis',
      '2fas',
      'freeotp-plus',
      'ente',
      'bitwarden',
      'otpauth-lines',
      'generic-csv',
    ]) {
      expect(FORMAT_IDS).toContain(id)
    }
    expect(new Set(FORMAT_IDS).size).toBe(FORMAT_IDS.length)
  })
})

describe('PlaintextContainer', () => {
  it('encrypted 是字面量 false，data 是明文对象而非字符串', () => {
    const data = { schemaVersion: 1 } as unknown as PlaintextContainer['data']
    const container: PlaintextContainer = {
      format: 'mfavault',
      version: 1,
      schemaVersion: 1,
      encrypted: false,
      data,
    }

    // @ts-expect-error encrypted 必须是字面量 false，不能是 true
    const wrong: PlaintextContainer = { ...container, encrypted: true }

    expect(container.encrypted).toBe(false)
    expect(wrong.encrypted).toBe(true)
    expect(container.data).toBe(data)
    expect(typeof container.data).toBe('object')
  })
})

describe('报告结构', () => {
  it('failures / warnings 是结构体而非异常，skipped 独立计数', () => {
    const failure: ParseFailure = {
      sourceIndex: 3,
      path: 'entries[3].secret',
      reason: '不是合法的 base32',
    }
    const globalWarning: ParseWarning = {
      sourceIndex: null,
      field: 'algorithm',
      message: '已从 MD5 归一化为 SHA1',
    }
    const entryWarning: ParseWarning = {
      sourceIndex: 1,
      field: 'period',
      message: '来源缺失，已按默认值 30 补齐',
    }
    const tag: ParsedTag = { name: 'work', sourceIndex: 0 }
    const result: ImportResult = {
      format: 'aegis',
      entries: [TOTP],
      tags: [tag],
      failures: [failure],
      warnings: [globalWarning, entryWarning],
      skipped: 2,
    }

    expect(result.failures).toHaveLength(1)
    expect(result.warnings.map((w) => w.sourceIndex)).toEqual([null, 1])
    expect(result.skipped).toBe(2)
    expect(result.tags[0]?.name).toBe('work')
  })

  it('C4：ParseFailure 只有路径与原因两个可写文本位，没有承载原始值的字段', () => {
    expect(Object.keys({ sourceIndex: 0, path: '', reason: '' } satisfies ParseFailure)).toEqual([
      'sourceIndex',
      'path',
      'reason',
    ])
  })
})
