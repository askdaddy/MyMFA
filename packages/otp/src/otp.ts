import { OtpConfigError } from './errors.js'
import { DEFAULT_ALGORITHM, type DigestAlgorithm, type HmacProvider } from './hmac.js'
import {
  assertAlgorithm,
  assertDigits,
  counterToBytes,
  DEFAULT_DIGITS,
  formatCode,
  truncate,
} from './hotp.js'

export const DEFAULT_PERIOD = 30

export interface OtpParams {
  secret: Uint8Array
  algorithm?: DigestAlgorithm
  digits?: number
}

export interface TotpParams extends OtpParams {
  period?: number
}

export interface TotpState {
  /** 当前周期的验证码 */
  code: string
  /** 下一周期的验证码，即预提示要显示的那个（docs/features.md §2） */
  nextCode: string
  counter: number
  period: number
  /** 当前周期剩余秒数，可为小数，供进度环使用 */
  remainingSeconds: number
}

export interface Otp {
  hotpAt(params: OtpParams, counter: number): Promise<string>
  totpAt(params: TotpParams, unixSeconds: number, clockOffsetSeconds?: number): Promise<string>
  totpState(
    params: TotpParams,
    unixSeconds: number,
    clockOffsetSeconds?: number,
  ): Promise<TotpState>
  counterForTime(unixSeconds: number, period?: number, clockOffsetSeconds?: number): number
  remainingSeconds(unixSeconds: number, period?: number, clockOffsetSeconds?: number): number
}

function resolveBase(params: OtpParams): {
  secret: Uint8Array
  algorithm: DigestAlgorithm
  digits: number
} {
  if (!(params.secret instanceof Uint8Array) || params.secret.length === 0) {
    throw new OtpConfigError('secret 必须是非空的 Uint8Array')
  }

  const algorithm = params.algorithm ?? DEFAULT_ALGORITHM
  const digits = params.digits ?? DEFAULT_DIGITS
  assertAlgorithm(algorithm)
  assertDigits(digits)

  return { secret: params.secret, algorithm, digits }
}

function resolvePeriod(period: number | undefined): number {
  const resolved = period ?? DEFAULT_PERIOD
  if (!Number.isSafeInteger(resolved) || resolved <= 0) {
    throw new OtpConfigError(`period 必须是正整数，实际为 ${resolved}`)
  }
  return resolved
}

/**
 * 校准偏移的语义是 `服务端时间 - 本地时间`，所以补偿后的时间 = 本地时间 + 偏移。
 * 补偿后落到 1970 之前说明系统时钟或偏移量错得离谱，此时算出的验证码看起来正常却必然错误，
 * 因此直接抛错让 UI 走时钟告警分支，而不是给一个骗人的码。
 */
function correctedTime(unixSeconds: number, clockOffsetSeconds: number): number {
  if (!Number.isFinite(unixSeconds) || !Number.isFinite(clockOffsetSeconds)) {
    throw new OtpConfigError('时间或时钟偏移不是有限数值')
  }
  const corrected = unixSeconds + clockOffsetSeconds
  if (corrected < 0) {
    throw new OtpConfigError(
      `校准后的时间 ${corrected} 早于 Unix 纪元，系统时钟或 clockOffsetSeconds 有误`,
    )
  }
  return corrected
}

export function createOtp(hmacProvider: HmacProvider): Otp {
  async function hotpAt(params: OtpParams, counter: number): Promise<string> {
    const { secret, algorithm, digits } = resolveBase(params)
    const digest = await hmacProvider.hmac(algorithm, secret, counterToBytes(counter))
    return formatCode(truncate(digest, algorithm), digits)
  }

  function counterForTime(
    unixSeconds: number,
    period: number | undefined,
    clockOffsetSeconds: number | undefined,
  ): number {
    const resolvedPeriod = resolvePeriod(period)
    const corrected = correctedTime(unixSeconds, clockOffsetSeconds ?? 0)
    return Math.floor(corrected / resolvedPeriod)
  }

  function remainingSeconds(
    unixSeconds: number,
    period: number | undefined,
    clockOffsetSeconds: number | undefined,
  ): number {
    const resolvedPeriod = resolvePeriod(period)
    const corrected = correctedTime(unixSeconds, clockOffsetSeconds ?? 0)
    return resolvedPeriod - (corrected % resolvedPeriod)
  }

  async function totpAt(
    params: TotpParams,
    unixSeconds: number,
    clockOffsetSeconds?: number,
  ): Promise<string> {
    return hotpAt(params, counterForTime(unixSeconds, params.period, clockOffsetSeconds))
  }

  async function totpState(
    params: TotpParams,
    unixSeconds: number,
    clockOffsetSeconds?: number,
  ): Promise<TotpState> {
    const { secret, algorithm, digits } = resolveBase(params)
    const period = resolvePeriod(params.period)
    const counter = counterForTime(unixSeconds, period, clockOffsetSeconds)

    const [code, nextCode] = await Promise.all([
      hotpAt({ secret, algorithm, digits }, counter),
      hotpAt({ secret, algorithm, digits }, counter + 1),
    ])

    return {
      code,
      nextCode,
      counter,
      period,
      remainingSeconds: remainingSeconds(unixSeconds, period, clockOffsetSeconds),
    }
  }

  return { hotpAt, totpAt, totpState, counterForTime, remainingSeconds }
}
