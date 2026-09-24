import { describe, expect, it } from 'vitest'

import { CryptoParamsError } from '../errors.js'
import type { Argon2idParams } from '../params.js'
import {
  AES_256_GCM,
  ARGON2ID_PARAMS,
  ARGON2ID_VERSION,
  assertArgon2idParams,
  assertNotWeakerThanBaseline,
} from '../params.js'

/** RFC 9106 §5.3 官方向量使用的参数，m=32KiB 远低于生产基线。 */
const RFC_9106_PARAMS: Argon2idParams = {
  memoryKiB: 32,
  iterations: 3,
  parallelism: 4,
  saltLength: 16,
  keyLength: 32,
}

/**
 * 这些数字是 AGENTS.md §5.1 的红线，改小必须先在 docs/decisions.md 立 ADR。
 * 逐字写死断言，让任何无意中的改动在 CI 上直接失败。
 */
describe('Argon2id 基线参数', () => {
  it('memoryKiB = 65536（64 MiB），单位是 KiB 不是 MiB', () => {
    expect(ARGON2ID_PARAMS.memoryKiB).toBe(65536)
    expect(ARGON2ID_PARAMS.memoryKiB * 1024).toBe(64 * 1024 * 1024)
  })

  it('iterations = 3, parallelism = 4, saltLength = 16, keyLength = 32', () => {
    expect(ARGON2ID_PARAMS).toEqual({
      memoryKiB: 65536,
      iterations: 3,
      parallelism: 4,
      saltLength: 16,
      keyLength: 32,
    })
  })

  it('版本固定为 0x13（Argon2 1.3），与 RFC 9106 一致', () => {
    expect(ARGON2ID_VERSION).toBe(0x13)
  })

  it('AES-256-GCM 的 nonce 为 12 字节、tag 为 16 字节', () => {
    expect(AES_256_GCM).toEqual({ keyLength: 32, nonceLength: 12, tagLength: 16 })
  })
})

describe('assertArgon2idParams（结构性校验）', () => {
  it('接受基线参数', () => {
    expect(() => assertArgon2idParams(ARGON2ID_PARAMS)).not.toThrow()
  })

  it('接受 RFC 9106 官方向量的参数——跨端一致性测试必须能跑它', () => {
    expect(() => assertArgon2idParams(RFC_9106_PARAMS)).not.toThrow()
  })

  it('接受上调后的参数', () => {
    expect(() =>
      assertArgon2idParams({ ...ARGON2ID_PARAMS, memoryKiB: 131072, iterations: 4 }),
    ).not.toThrow()
  })

  it('拒绝非正整数与非整数', () => {
    expect(() => assertArgon2idParams({ ...ARGON2ID_PARAMS, iterations: 0 })).toThrow(
      CryptoParamsError,
    )
    expect(() => assertArgon2idParams({ ...ARGON2ID_PARAMS, keyLength: -1 })).toThrow(
      CryptoParamsError,
    )
    expect(() => assertArgon2idParams({ ...ARGON2ID_PARAMS, keyLength: 32.5 })).toThrow(
      CryptoParamsError,
    )
  })

  it('拒绝违反 Argon2 规范 memoryKiB >= 8 * parallelism 的组合', () => {
    expect(() => assertArgon2idParams({ ...ARGON2ID_PARAMS, parallelism: 65536 })).toThrow(
      CryptoParamsError,
    )
  })
})

describe('assertNotWeakerThanBaseline（策略性校验）', () => {
  it('接受基线与上调后的参数', () => {
    expect(() => assertNotWeakerThanBaseline(ARGON2ID_PARAMS)).not.toThrow()
    expect(() =>
      assertNotWeakerThanBaseline({ ...ARGON2ID_PARAMS, memoryKiB: 131072 }),
    ).not.toThrow()
  })

  it('拒绝任何一项下调', () => {
    expect(() => assertNotWeakerThanBaseline({ ...ARGON2ID_PARAMS, memoryKiB: 32768 })).toThrow(
      CryptoParamsError,
    )
    expect(() => assertNotWeakerThanBaseline({ ...ARGON2ID_PARAMS, iterations: 2 })).toThrow(
      CryptoParamsError,
    )
    expect(() => assertNotWeakerThanBaseline({ ...ARGON2ID_PARAMS, parallelism: 2 })).toThrow(
      CryptoParamsError,
    )
  })

  it('拒绝 RFC 9106 官方向量的参数——它不能被当成生产参数', () => {
    expect(() => assertNotWeakerThanBaseline(RFC_9106_PARAMS)).toThrow(CryptoParamsError)
  })

  it('saltLength 不参与比较，它只影响新文件的生成', () => {
    expect(() => assertNotWeakerThanBaseline({ ...ARGON2ID_PARAMS, saltLength: 8 })).not.toThrow()
  })

  it('错误信息指向 ADR 流程，而不是只说「参数非法」', () => {
    expect(() => assertNotWeakerThanBaseline({ ...ARGON2ID_PARAMS, memoryKiB: 1024 })).toThrow(
      /ADR/,
    )
  })
})
