import { CryptoParamsError } from './errors.js'

export interface ScryptParams {
  readonly costFactor: number
  readonly blockSize: number
  readonly parallelism: number
  readonly keyLength: number
}

export interface Pbkdf2Params {
  readonly iterations: number
  readonly hash: 'SHA-256' | 'SHA-1'
  readonly keyLength: number
}

export const COMPAT_KDF_LIMITS = {
  maxMemoryBytes: 128 * 1024 * 1024,
  maxWork: 2 ** 24,
  maxIterations: 1_000_000,
  maxKeyLength: 64,
  maxSaltLength: 1024,
} as const

function positive(value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new CryptoParamsError('兼容 KDF 参数必须是正整数')
  }
}

function assertLength(keyLength: number, salt: Uint8Array): void {
  positive(keyLength)
  if (
    keyLength > COMPAT_KDF_LIMITS.maxKeyLength ||
    salt.length === 0 ||
    salt.length > COMPAT_KDF_LIMITS.maxSaltLength
  ) {
    throw new CryptoParamsError('兼容 KDF 的输出或盐长度超出限制')
  }
}

export function assertScryptParams(params: ScryptParams, salt: Uint8Array): void {
  const { costFactor: n, blockSize: r, parallelism: p } = params
  for (const value of [n, r, p]) positive(value)
  assertLength(params.keyLength, salt)
  if (
    n <= 1 ||
    !Number.isInteger(Math.log2(n)) ||
    128 * n * r > COMPAT_KDF_LIMITS.maxMemoryBytes ||
    n * r * p > COMPAT_KDF_LIMITS.maxWork
  ) {
    throw new CryptoParamsError('scrypt 参数不合法或超出资源限制')
  }
}

export function assertPbkdf2Params(params: Pbkdf2Params, salt: Uint8Array): void {
  positive(params.iterations)
  assertLength(params.keyLength, salt)
  if (
    params.iterations > COMPAT_KDF_LIMITS.maxIterations ||
    (params.hash !== 'SHA-256' && params.hash !== 'SHA-1')
  ) {
    throw new CryptoParamsError('PBKDF2 参数不合法或超出资源限制')
  }
}
