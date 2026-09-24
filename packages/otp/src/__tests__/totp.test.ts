import { describe, expect, it } from 'vitest'

import { base32Decode } from '../base32.js'
import { OtpConfigError } from '../errors.js'
import { DEFAULT_PERIOD, createOtp, type TotpParams } from '../otp.js'
import { asciiSecret, nodeHmac, RFC_6238_SECRETS } from './helpers.js'

const otp = createOtp(nodeHmac)

const RFC_4226_SECRET = asciiSecret('12345678901234567890')
const SIX_DIGIT: TotpParams = { secret: RFC_4226_SECRET }

describe('period', () => {
  it('默认为 30', () => {
    expect(DEFAULT_PERIOD).toBe(30)
    expect(otp.counterForTime(0)).toBe(0)
    expect(otp.counterForTime(29)).toBe(0)
    expect(otp.counterForTime(30)).toBe(1)
  })

  it('period = 60 时步长翻倍', async () => {
    expect(otp.counterForTime(59, 60)).toBe(0)
    expect(otp.counterForTime(60, 60)).toBe(1)

    const at59 = await otp.totpAt({ ...SIX_DIGIT, period: 60 }, 59)
    const at0 = await otp.totpAt({ ...SIX_DIGIT, period: 60 }, 0)
    const at60 = await otp.totpAt({ ...SIX_DIGIT, period: 60 }, 60)
    expect(at59).toBe(at0)
    expect(at60).not.toBe(at0)
  })

  it('拒绝非正整数 period', () => {
    expect(() => otp.counterForTime(0, 0)).toThrow(OtpConfigError)
    expect(() => otp.counterForTime(0, -30)).toThrow(OtpConfigError)
    expect(() => otp.counterForTime(0, 30.5)).toThrow(OtpConfigError)
  })
})

describe('周期边界', () => {
  it('t = 29.999 与 t = 30.000 落在不同步', () => {
    expect(otp.counterForTime(29.999)).toBe(0)
    expect(otp.counterForTime(30.0)).toBe(1)
  })

  it('remainingSeconds 在边界处从趋近 0 跳回 period', () => {
    expect(otp.remainingSeconds(29.999)).toBeCloseTo(0.001, 6)
    expect(otp.remainingSeconds(30.0)).toBe(30)
    expect(otp.remainingSeconds(0)).toBe(30)
    expect(otp.remainingSeconds(45)).toBe(15)
  })
})

describe('预提示', () => {
  it('nextCode 等于进入下一周期后的 code', async () => {
    for (const time of [0, 1, 29.999, 30, 59, 1111111109, 2000000000]) {
      const state = await otp.totpState(SIX_DIGIT, time)
      const afterBoundary = await otp.totpAt(SIX_DIGIT, (state.counter + 1) * state.period)
      expect(state.nextCode).toBe(afterBoundary)
    }
  })

  it('nextCode 在整个当前周期内保持不变，并在跨边界后无缝接续', async () => {
    const before = await otp.totpState(SIX_DIGIT, 29.999)
    const after = await otp.totpState(SIX_DIGIT, 30.0)

    expect(before.counter).toBe(0)
    expect(after.counter).toBe(1)
    expect(before.nextCode).toBe(after.code)
    expect(after.counter).toBe(before.counter + 1)
  })

  it('nextCode 与 code 在同一周期内不同', async () => {
    const state = await otp.totpState(SIX_DIGIT, 0)
    expect(state.nextCode).not.toBe(state.code)
  })

  it('HOTP 的预提示是 counter + 1，与时间无关', async () => {
    const current = await otp.hotpAt({ secret: RFC_4226_SECRET }, 7)
    const next = await otp.hotpAt({ secret: RFC_4226_SECRET }, 8)

    expect(current).toBe('162583')
    expect(next).toBe('399871')
  })

  it('totpState 一次调用即给出 UI 所需的全部字段', async () => {
    const state = await otp.totpState(
      { secret: RFC_6238_SECRETS['SHA-1'] as Uint8Array, algorithm: 'SHA-1', digits: 8 },
      59,
    )
    expect(state).toMatchObject({ code: '94287082', counter: 1, period: 30 })
    expect(state.remainingSeconds).toBe(1)
  })
})

describe('clockOffsetSeconds', () => {
  it('正偏移把本地时间往前推', async () => {
    const uncorrected = await otp.totpAt(SIX_DIGIT, 59)
    const corrected = await otp.totpAt(SIX_DIGIT, 29, 30)
    expect(corrected).toBe(uncorrected)
    expect(otp.counterForTime(29, 30, 30)).toBe(1)
  })

  it('负偏移把本地时间往回拉', async () => {
    expect(otp.counterForTime(59, 30, -30)).toBe(0)
    expect(await otp.totpAt(SIX_DIGIT, 59, -30)).toBe(await otp.totpAt(SIX_DIGIT, 29))
  })

  it('偏移同时作用于 remainingSeconds', () => {
    expect(otp.remainingSeconds(20)).toBe(10)
    expect(otp.remainingSeconds(20, 30, 15)).toBe(25)
    expect(otp.remainingSeconds(20, 30, -15)).toBe(25)
  })

  it('校准后早于 Unix 纪元时抛错，而不是返回一个看起来正常的错码', async () => {
    expect(() => otp.counterForTime(10, 30, -100)).toThrow(OtpConfigError)
    await expect(otp.totpAt(SIX_DIGIT, 10, -100)).rejects.toThrow(OtpConfigError)
  })
})

describe('secret 输入形态', () => {
  it('接受 base32 解码后的原始字节', async () => {
    const decoded = base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
    expect(decoded).toEqual(RFC_4226_SECRET)
    expect(await otp.hotpAt({ secret: decoded }, 0)).toBe('755224')
  })

  it('拒绝非 Uint8Array 的 secret', async () => {
    await expect(
      otp.hotpAt({ secret: 'JBSWY3DPEHPK3PXP' as unknown as Uint8Array }, 0),
    ).rejects.toThrow(OtpConfigError)
  })
})
