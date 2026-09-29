import { pbkdf2Sync, scryptSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { CryptoParamsError, utf8Encode } from '@askdaddy/crypto'
import type { Pbkdf2Params } from '@askdaddy/crypto'
import { webPbkdf2Provider, webScryptProvider } from '../index.js'

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex')

describe('兼容 KDF 独立一致性', () => {
  it('RFC7914 password/NaCl 官方向量', async () => {
    const key = await webScryptProvider.deriveKey(utf8Encode('password'), utf8Encode('NaCl'), {
      costFactor: 1024,
      blockSize: 8,
      parallelism: 16,
      keyLength: 64,
    })
    expect(hex(key)).toBe(
      'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
    )
    key.fill(0)
  })

  it.each([
    [1024, 1, 2],
    [32768, 8, 1],
    [2048, 8, 2],
  ])('scrypt N/r/p=%j/%j/%j 与 Node 相等', async (costFactor, blockSize, parallelism) => {
    const password = utf8Encode('test-测试-\u0000')
    const salt = utf8Encode('only-a-fake-test-salt')
    const key = await webScryptProvider.deriveKey(password, salt, {
      costFactor,
      blockSize,
      parallelism,
      keyLength: 32,
    })
    const expected = scryptSync(password, salt, 32, {
      N: costFactor,
      r: blockSize,
      p: parallelism,
      maxmem: 128 * 1024 * 1024,
    })
    expect(hex(key)).toBe(hex(expected))
    expect(hex(password)).toBe(hex(utf8Encode('test-测试-\u0000')))
    key.fill(0)
    expected.fill(0)
  })

  it.each(['SHA-256', 'SHA-1'] as const)('PBKDF2 %s 与 Node 相等', async (hash) => {
    for (const iterations of [1, 10000]) {
      const password = utf8Encode('test-测试-\u0000')
      const salt = utf8Encode('fake-salt')
      const params: Pbkdf2Params = { hash, iterations, keyLength: 32 }
      const key = await webPbkdf2Provider.deriveKey(password, salt, params)
      const expected = pbkdf2Sync(
        password,
        salt,
        iterations,
        32,
        hash === 'SHA-1' ? 'sha1' : 'sha256',
      )
      expect(hex(key)).toBe(hex(expected))
      expect(hex(salt)).toBe(hex(utf8Encode('fake-salt')))
      key.fill(0)
      expected.fill(0)
    }
  })

  it('资源限制在原语之前生效', async () => {
    await expect(
      webScryptProvider.deriveKey(new Uint8Array(1), new Uint8Array(1), {
        costFactor: 2 ** 30,
        blockSize: 8,
        parallelism: 1,
        keyLength: 32,
      }),
    ).rejects.toThrow(CryptoParamsError)
    await expect(
      webPbkdf2Provider.deriveKey(new Uint8Array(1), new Uint8Array(1), {
        hash: 'SHA-256',
        iterations: 1000001,
        keyLength: 32,
      }),
    ).rejects.toThrow(CryptoParamsError)
  })
})
