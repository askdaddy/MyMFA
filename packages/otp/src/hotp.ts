import { OtpConfigError } from './errors.js'
import { DIGEST_ALGORITHMS, HMAC_OUTPUT_LENGTH, type DigestAlgorithm } from './hmac.js'

export const MIN_DIGITS = 6
export const MAX_DIGITS = 8
export const DEFAULT_DIGITS = 6

export function assertDigits(digits: number): void {
  if (!Number.isInteger(digits) || digits < MIN_DIGITS || digits > MAX_DIGITS) {
    throw new OtpConfigError(`digits 必须是 ${MIN_DIGITS}–${MAX_DIGITS} 的整数，实际为 ${digits}`)
  }
}

export function assertAlgorithm(algorithm: DigestAlgorithm): void {
  if (!DIGEST_ALGORITHMS.includes(algorithm)) {
    throw new OtpConfigError(
      `不支持的摘要算法 "${algorithm}"，仅支持 ${DIGEST_ALGORITHMS.join(' / ')}`,
    )
  }
}

/** RFC 4226 §5.3 动态截断。 */
export function truncate(digest: Uint8Array, algorithm: DigestAlgorithm): number {
  const expected = HMAC_OUTPUT_LENGTH[algorithm]
  if (digest.length !== expected) {
    throw new OtpConfigError(
      `${algorithm} 的 HMAC 输出应为 ${expected} 字节，实际为 ${digest.length} 字节——Provider 可能忽略了算法参数`,
    )
  }

  const offset = digest[digest.length - 1]! & 0x0f
  return (
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff)
  )
}

/**
 * 必须以字符串返回：`07081804` 这类含前导零的码一旦经过 Number 就会丢掉前导零，
 * 而 RFC 6238 附录 B 的测试向量里就有这一例。
 */
export function formatCode(truncated: number, digits: number): string {
  return String(truncated % 10 ** digits).padStart(digits, '0')
}

export function assertCounter(counter: number): void {
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new OtpConfigError(`counter 必须是非负安全整数，实际为 ${counter}`)
  }
}

export function counterToBytes(counter: number): Uint8Array {
  assertCounter(counter)
  const bytes = new Uint8Array(8)
  const view = new DataView(bytes.buffer)
  view.setBigUint64(0, BigInt(counter))
  return bytes
}
