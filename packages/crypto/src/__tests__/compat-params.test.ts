import { describe, expect, it } from 'vitest'
import { assertPbkdf2Params, assertScryptParams } from '../compat-params.js'
import type { Pbkdf2Params, ScryptParams } from '../compat-params.js'
import { CryptoParamsError } from '../errors.js'
import type { KdfProvider, Pbkdf2Provider, ScryptProvider } from '../providers.js'

const salt = new Uint8Array(32)
const scrypt: ScryptParams = { costFactor: 32768, blockSize: 8, parallelism: 1, keyLength: 32 }
const pbkdf2: Pbkdf2Params = { iterations: 10000, hash: 'SHA-256', keyLength: 32 }

describe('兼容 KDF 信任边界', () => {
  it('合法参数可表达，且不能赋给自有 vault 的 KDF', () => {
    expect(() => assertScryptParams(scrypt, salt)).not.toThrow()
    expect(() => assertPbkdf2Params(pbkdf2, salt)).not.toThrow()
    const s: ScryptProvider = { name: 'scrypt', deriveKey: async () => new Uint8Array(32) }
    const p: Pbkdf2Provider = { name: 'pbkdf2', deriveKey: async () => new Uint8Array(32) }
    // @ts-expect-error 自有 vault 必须在编译期拒绝兼容算法。
    const rejectedScrypt: KdfProvider = s
    // @ts-expect-error 自有 vault 必须在编译期拒绝兼容算法。
    const rejectedPbkdf2: KdfProvider = p
    expect(rejectedScrypt.name).not.toBe('argon2id')
    expect(rejectedPbkdf2.name).not.toBe('argon2id')
  })

  it.each([
    { costFactor: 1 },
    { costFactor: 3 },
    { costFactor: 2 ** 30 },
    { blockSize: 0 },
    { blockSize: 1.5 },
    { parallelism: -1 },
    { parallelism: 10000 },
    { costFactor: Number.NaN },
    { keyLength: 65 },
  ])('scrypt 拒绝畸形或超限参数 %j', (patch) => {
    expect(() => assertScryptParams({ ...scrypt, ...patch }, salt)).toThrow(CryptoParamsError)
  })

  it.each([
    { iterations: 0 },
    { iterations: 1.5 },
    { iterations: 1000001 },
    { iterations: Number.POSITIVE_INFINITY },
    { keyLength: 0 },
    { keyLength: 65 },
  ])('PBKDF2 拒绝畸形或超限参数 %j', (patch) => {
    expect(() => assertPbkdf2Params({ ...pbkdf2, ...patch }, salt)).toThrow(CryptoParamsError)
  })

  it('两种 KDF 都拒绝空盐与超长盐，允许边界输出和盐', () => {
    for (const salt of [new Uint8Array(0), new Uint8Array(1025)]) {
      expect(() => assertScryptParams(scrypt, salt)).toThrow(CryptoParamsError)
      expect(() => assertPbkdf2Params(pbkdf2, salt)).toThrow(CryptoParamsError)
    }
    expect(() =>
      assertPbkdf2Params({ ...pbkdf2, hash: 'SHA-1', keyLength: 64 }, new Uint8Array(1024)),
    ).not.toThrow()
    expect(() =>
      assertPbkdf2Params({ ...pbkdf2, hash: 'MD5' as Pbkdf2Params['hash'] }, salt),
    ).toThrow(CryptoParamsError)
  })
})
