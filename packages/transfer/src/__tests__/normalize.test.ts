import { describe, expect, it } from 'vitest'
import { TransferError, TransferValueError } from '../errors.js'
import {
  normalizeAlgorithm,
  normalizeCounter,
  normalizeDigits,
  normalizeKind,
  normalizePeriod,
} from '../normalize.js'

// 一个长得像 base32 密钥的字符串：畸形文件可能把它放错到 algorithm / type 字段，
// 错误消息一旦回显就等于把密钥写进崩溃上报（C4）。
const SECRET_LIKE = 'JBSWY3DPEHPK3PXP'

const sha1Spellings = [
  'SHA1',
  'sha1',
  'SHA-1',
  'sha-1',
  ' sha1 ',
  'HmacSHA1',
  'hmacsha1',
  'HmacSHA-1',
  'Algorithm.sha1',
  'algorithm.sha1',
]
const sha256Spellings = [
  'SHA256',
  'sha256',
  'sha-256',
  'SHA-256',
  'algorithm.sha256',
  'Algorithm.SHA256',
  'HmacSHA256',
  'HmacSHA-256',
]
const sha512Spellings = ['SHA512', 'sha512', 'sha-512', 'algorithm.sha512', 'HmacSHA512']

describe('normalizeAlgorithm', () => {
  it.each(sha1Spellings)('把 %j 归一化为 SHA1', (raw) => {
    expect(normalizeAlgorithm(raw)).toEqual({ algo: 'SHA1', fromMd5: false })
  })

  it.each(sha256Spellings)('把 %j 归一化为 SHA256', (raw) => {
    expect(normalizeAlgorithm(raw)).toEqual({ algo: 'SHA256', fromMd5: false })
  })

  it.each(sha512Spellings)('把 %j 归一化为 SHA512', (raw) => {
    expect(normalizeAlgorithm(raw)).toEqual({ algo: 'SHA512', fromMd5: false })
  })

  it('MD5 降级为 SHA1，并通过 fromMd5 让调用方区分「本来就是 SHA1」', () => {
    expect(normalizeAlgorithm('MD5')).toEqual({ algo: 'SHA1', fromMd5: true })
    expect(normalizeAlgorithm('md5')).toEqual({ algo: 'SHA1', fromMd5: true })
    expect(normalizeAlgorithm('HmacMD5')).toEqual({ algo: 'SHA1', fromMd5: true })
    expect(normalizeAlgorithm('SHA1').fromMd5).toBe(false)
  })

  it.each(['SHA224', 'sha224', 'SHA384', 'sha-384', 'MD4', '', '   ', 'SHA0', SECRET_LIKE])(
    '对无法识别的 %j 抛错，绝不回落 SHA1',
    (raw) => {
      expect(() => normalizeAlgorithm(raw)).toThrow(TransferValueError)
    },
  )

  it.each([undefined, null, 1, true, {}, ['SHA1']])('对非字符串 %j 抛错', (raw) => {
    expect(() => normalizeAlgorithm(raw)).toThrow(TransferValueError)
  })

  it('错误消息不回显收到的原值', () => {
    try {
      normalizeAlgorithm(SECRET_LIKE)
      expect.unreachable('应当抛错')
    } catch (error) {
      expect((error as Error).message).not.toContain(SECRET_LIKE)
      expect((error as Error).message).not.toContain(SECRET_LIKE.toLowerCase())
    }
  })

  it('抛出的错误可被解析器用单一 TransferError 捕获', () => {
    try {
      normalizeAlgorithm('SHA224')
      expect.unreachable('应当抛错')
    } catch (error) {
      expect(error).toBeInstanceOf(TransferValueError)
      expect(error).toBeInstanceOf(TransferError)
      expect((error as Error).name).toBe('TransferValueError')
    }
  })
})

describe('normalizeDigits', () => {
  it.each([6, 7, 8])('接受 %i', (digits) => {
    expect(normalizeDigits(digits)).toBe(digits)
  })

  it.each(['6', ' 7 ', '+8'])('接受纯整数文本 %j（CSV 全是字符串）', (digits) => {
    expect(normalizeDigits(digits)).toBe(Number(digits))
  })

  it.each([5, 9, 10, 0, -1, 6.5, Number.NaN, Number.POSITIVE_INFINITY])('拒绝 %s', (digits) => {
    expect(() => normalizeDigits(digits)).toThrow(TransferValueError)
  })

  it.each([undefined, null, true, '', '6.5', 'abc', '6px', {}])('拒绝非整数输入 %j', (digits) => {
    expect(() => normalizeDigits(digits)).toThrow(TransferValueError)
  })

  it('复用 @askdaddy/otp 的范围判定，错误消息沿用其措辞', () => {
    try {
      normalizeDigits(10)
      expect.unreachable('应当抛错')
    } catch (error) {
      expect((error as Error).message).toContain('6–8')
      expect((error as Error).cause).toBeInstanceOf(Error)
    }
  })
})

describe('normalizeCounter', () => {
  it.each([0, 1, 50, 10_300, '50'])('接受 %s', (counter) => {
    expect(normalizeCounter(counter)).toBe(Number(counter))
  })

  it.each([-1, -10_300, 1.5, Number.NaN, 'abc', undefined, null])('拒绝 %s', (counter) => {
    expect(() => normalizeCounter(counter)).toThrow(TransferValueError)
  })
})

describe('normalizePeriod', () => {
  it.each([20, 30, 50, 60, '30'])('接受 %s', (period) => {
    expect(normalizePeriod(period)).toBe(Number(period))
  })

  it.each([0, -30, 30.5, Number.NaN, '', 'abc', undefined, null, true])(
    '拒绝 %s，不补默认值 30',
    (period) => {
      expect(() => normalizePeriod(period)).toThrow(TransferValueError)
    },
  )
})

describe('normalizeKind', () => {
  it.each(['totp', 'TOTP', ' TOTP ', 'hotp', 'HOTP'])('接受 %j', (raw) => {
    expect(normalizeKind(raw)).toBe(raw.trim().toLowerCase())
  })

  it.each(['steam', 'STEAM', 'motp', 'MOTP', 'yandex', 'YANDEX'])(
    '拒绝 ADR-004 已放弃的 %j，并说明是不受支持而非文件损坏',
    (raw) => {
      try {
        normalizeKind(raw)
        expect.unreachable('应当抛错')
      } catch (error) {
        expect(error).toBeInstanceOf(TransferValueError)
        expect((error as Error).message).toContain('该令牌类型不受支持')
        expect((error as Error).message).toContain('TOTP 与 HOTP')
      }
    },
  )

  it.each(['', 'sha1', SECRET_LIKE, undefined, null, 1, {}])('拒绝无法识别的 %j', (raw) => {
    expect(() => normalizeKind(raw)).toThrow(TransferValueError)
  })

  it('未知类型的错误消息不回显原值', () => {
    try {
      normalizeKind(SECRET_LIKE)
      expect.unreachable('应当抛错')
    } catch (error) {
      expect((error as Error).message).not.toContain(SECRET_LIKE)
    }
  })
})
