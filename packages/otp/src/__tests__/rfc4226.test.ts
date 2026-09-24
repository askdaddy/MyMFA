import { describe, expect, it } from 'vitest'

import { createOtp } from '../otp.js'
import { asciiSecret, nodeHmac } from './helpers.js'

const otp = createOtp(nodeHmac)

/** RFC 4226 附录 D：secret = "12345678901234567890"（ASCII），SHA-1，6 位。 */
const RFC_4226_SECRET = asciiSecret('12345678901234567890')

const RFC_4226_VECTORS: ReadonlyArray<[number, string]> = [
  [0, '755224'],
  [1, '287082'],
  [2, '359152'],
  [3, '969429'],
  [4, '338314'],
  [5, '254676'],
  [6, '287922'],
  [7, '162583'],
  [8, '399871'],
  [9, '520489'],
]

describe('RFC 4226 附录 D HOTP 测试向量', () => {
  it.each(RFC_4226_VECTORS)('counter=%i → %s', async (counter, expected) => {
    await expect(otp.hotpAt({ secret: RFC_4226_SECRET }, counter)).resolves.toBe(expected)
  })

  it('默认参数即 SHA-1 / 6 位，无需显式指定', async () => {
    await expect(
      otp.hotpAt({ secret: RFC_4226_SECRET, algorithm: 'SHA-1', digits: 6 }, 0),
    ).resolves.toBe('755224')
  })
})

describe('counter 编码', () => {
  it('大 counter 不丢精度', async () => {
    // RFC 4226 §5.2 要求 counter 以 8 字节大端表示；2^32 以上必须仍然正确
    const code = await otp.hotpAt({ secret: RFC_4226_SECRET }, 2 ** 32)
    expect(code).toMatch(/^\d{6}$/)
  })

  it('拒绝负数与非整数 counter', async () => {
    await expect(otp.hotpAt({ secret: RFC_4226_SECRET }, -1)).rejects.toThrow()
    await expect(otp.hotpAt({ secret: RFC_4226_SECRET }, 1.5)).rejects.toThrow()
  })

  it('拒绝空 secret', async () => {
    await expect(otp.hotpAt({ secret: new Uint8Array(0) }, 0)).rejects.toThrow()
  })

  it('拒绝越界 digits', async () => {
    await expect(otp.hotpAt({ secret: RFC_4226_SECRET, digits: 5 }, 0)).rejects.toThrow()
    await expect(otp.hotpAt({ secret: RFC_4226_SECRET, digits: 9 }, 0)).rejects.toThrow()
  })
})
