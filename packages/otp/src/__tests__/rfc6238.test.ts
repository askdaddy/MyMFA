import { describe, expect, it } from 'vitest'

import type { DigestAlgorithm } from '../hmac.js'
import { createOtp } from '../otp.js'
import { nodeHmac, RFC_6238_SECRETS } from './helpers.js'

const otp = createOtp(nodeHmac)

/**
 * RFC 6238 附录 B：8 位，period = 30。
 * 三种算法各自使用不同长度的 secret（20 / 32 / 64 字节），混用会得到错误的期望值。
 */
const RFC_6238_VECTORS: ReadonlyArray<[number, string, string, string]> = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'],
  [2000000000, '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826'],
]

const BY_ALGORITHM: ReadonlyArray<[DigestAlgorithm, number]> = [
  ['SHA-1', 1],
  ['SHA-256', 2],
  ['SHA-512', 3],
]

describe('RFC 6238 附录 B TOTP 测试向量', () => {
  it.each(BY_ALGORITHM)('%s', async (algorithm, vectorIndex) => {
    for (const vector of RFC_6238_VECTORS) {
      const time = vector[0]!
      const expected = vector[vectorIndex]!
      await expect(
        otp.totpAt({ secret: RFC_6238_SECRETS[algorithm], algorithm, digits: 8, period: 30 }, time),
      ).resolves.toBe(expected)
    }
  })

  it('保留前导零：T=1111111109 的 SHA-1 码是 07081804 而不是 7081804', async () => {
    const code = await otp.totpAt(
      { secret: RFC_6238_SECRETS['SHA-1'], algorithm: 'SHA-1', digits: 8 },
      1111111109,
    )
    expect(code).toBe('07081804')
    expect(code).toHaveLength(8)
  })

  it('counterForTime 与 RFC 6238 附录 B 的 T / X 列一致', () => {
    const expected: ReadonlyArray<[number, number]> = [
      [59, 1],
      [1111111109, 37037036],
      [1111111111, 37037037],
      [1234567890, 41152263],
      [2000000000, 66666666],
      [20000000000, 666666666],
    ]
    for (const [time, counter] of expected) {
      expect(otp.counterForTime(time, 30)).toBe(counter)
    }
  })
})

describe('digits 截断', () => {
  it('6 / 7 / 8 位互为后缀，证明截断只做取模而非重新计算', async () => {
    const params = { secret: RFC_6238_SECRETS['SHA-1'] as Uint8Array, algorithm: 'SHA-1' as const }
    const eight = await otp.totpAt({ ...params, digits: 8 }, 1111111109)
    const seven = await otp.totpAt({ ...params, digits: 7 }, 1111111109)
    const six = await otp.totpAt({ ...params, digits: 6 }, 1111111109)

    expect(eight).toBe('07081804')
    expect(seven).toBe(eight.slice(1))
    expect(six).toBe(eight.slice(2))
    expect(seven).toHaveLength(7)
    expect(six).toHaveLength(6)
  })
})
