import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import { base64Encode, CryptoParamsError, utf8Encode } from '@askdaddy/crypto'
import type { Argon2idParams, KdfProvider } from '@askdaddy/crypto'

import { webKdfProvider } from '../kdf.js'

const provider: KdfProvider = webKdfProvider

/** AGENTS.md §5.3：夹具一律用假值。 */
const PASSWORD = utf8Encode('JBSWY3DPEHPK3PXP')
const SALT = utf8Encode('0123456789abcdef')

/** 单元测试用小内存参数换取速度；生产参数下的比对见 consistency 测试。 */
const FAST_PARAMS: Argon2idParams = {
  memoryKiB: 32,
  iterations: 3,
  parallelism: 4,
  saltLength: 16,
  keyLength: 32,
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

describe('webKdfProvider', () => {
  it('name 为字面量 argon2id，供 vault 与文件头 crypto.kdf.name 比对', () => {
    expect(provider.name).toBe('argon2id')
  })

  it('输出长度恰为 params.keyLength', async () => {
    for (const keyLength of [16, 32, 64]) {
      const key = await provider.deriveKey(PASSWORD, SALT, { ...FAST_PARAMS, keyLength })
      expect(key).toBeInstanceOf(Uint8Array)
      expect(key).toHaveLength(keyLength)
    }
  })

  it('相同入参多次调用输出字节级一致', async () => {
    const a = await provider.deriveKey(PASSWORD, SALT, FAST_PARAMS)
    const b = await provider.deriveKey(PASSWORD, SALT, FAST_PARAMS)
    expect(hex(a)).toBe(hex(b))
  })

  it('相同 password、不同 salt 输出不同', async () => {
    const a = await provider.deriveKey(PASSWORD, SALT, FAST_PARAMS)
    const b = await provider.deriveKey(PASSWORD, utf8Encode('fedcba9876543210'), FAST_PARAMS)
    expect(hex(a)).not.toBe(hex(b))
  })

  it('相同 salt、不同 password 输出不同', async () => {
    const a = await provider.deriveKey(PASSWORD, SALT, FAST_PARAMS)
    const b = await provider.deriveKey(utf8Encode('JBSWY3DPEHPK3PXY'), SALT, FAST_PARAMS)
    expect(hex(a)).not.toBe(hex(b))
  })

  it('iterations 与 parallelism 都参与派生，不是被忽略的摆设', async () => {
    const base = await provider.deriveKey(PASSWORD, SALT, FAST_PARAMS)
    const moreIterations = await provider.deriveKey(PASSWORD, SALT, {
      ...FAST_PARAMS,
      iterations: 4,
    })
    const lessParallel = await provider.deriveKey(PASSWORD, SALT, {
      ...FAST_PARAMS,
      parallelism: 1,
    })

    expect(hex(moreIterations)).not.toBe(hex(base))
    expect(hex(lessParallel)).not.toBe(hex(base))
  })

  it('memoryKiB = 32 能正常派生——基线强度校验不在 Provider 层', async () => {
    const key = await provider.deriveKey(PASSWORD, SALT, FAST_PARAMS)
    expect(key).toHaveLength(FAST_PARAMS.keyLength)
  })

  it('结构性非法参数抛出 CryptoParamsError', async () => {
    const invalid: Argon2idParams[] = [
      { ...FAST_PARAMS, iterations: 0 },
      { ...FAST_PARAMS, keyLength: -1 },
      { ...FAST_PARAMS, memoryKiB: 8 }, // < 8 * parallelism
      { ...FAST_PARAMS, parallelism: 0 },
    ]

    for (const params of invalid) {
      await expect(provider.deriveKey(PASSWORD, SALT, params)).rejects.toThrow(CryptoParamsError)
    }
  })

  it('错误消息不泄露 password / salt 的字节值', async () => {
    const leakable = [
      'JBSWY3DPEHPK3PXP',
      '0123456789abcdef',
      hex(PASSWORD),
      hex(SALT),
      base64Encode(PASSWORD),
      base64Encode(SALT),
    ]

    const error = await provider
      .deriveKey(PASSWORD, SALT, { ...FAST_PARAMS, iterations: 0 })
      .then(() => undefined)
      .catch((e: unknown) => e as CryptoParamsError)

    expect(error).toBeInstanceOf(CryptoParamsError)
    for (const value of leakable) {
      expect(error!.message).not.toContain(value)
    }
  })

  it('实现不 import Node 内置模块，不使用 process / Buffer', () => {
    const source = readFileSync(fileURLToPath(new URL('../kdf.ts', import.meta.url)), 'utf8')
    const specifiers = [...source.matchAll(/from '([^']+)'/g)].map((m) => m[1]!)
    const external = specifiers.filter(
      (s) => !s.startsWith('.') && s !== '@askdaddy/crypto' && s !== 'hash-wasm',
    )

    expect(external).toEqual([])
    expect(source).not.toMatch(/\bprocess\b/)
    expect(source).not.toMatch(/\bBuffer\b/)
  })
})
