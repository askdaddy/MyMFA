import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import { CryptoParamsError } from '@askdaddy/crypto'
import type { RandomProvider } from '@askdaddy/crypto'

import { webRandomProvider } from '../random.js'

const provider: RandomProvider = webRandomProvider

describe('webRandomProvider', () => {
  it('请求 N 字节返回长度恰为 N 的 Uint8Array', () => {
    for (const length of [1, 12, 16, 32, 128]) {
      const bytes = provider.randomBytes(length)
      expect(bytes).toBeInstanceOf(Uint8Array)
      expect(bytes).toHaveLength(length)
    }
  })

  it('两次相同长度的调用结果不同', () => {
    const a = provider.randomBytes(32)
    const b = provider.randomBytes(32)
    expect(a).not.toEqual(b)
  })

  it('请求 0 字节返回空数组且不抛错', () => {
    expect(provider.randomBytes(0)).toEqual(new Uint8Array(0))
  })

  it('输出分布非退化——32 字节不全为同一字节值', () => {
    const bytes = provider.randomBytes(32)
    expect(new Set(bytes).size).toBeGreaterThan(1)
  })

  it('负数、非整数与 NaN 长度抛出 CryptoParamsError 而非裸字符串', () => {
    for (const length of [-1, -32, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => provider.randomBytes(length)).toThrow(CryptoParamsError)
    }
  })

  it('错误消息只回显长度，不含任何随机字节', () => {
    expect(() => provider.randomBytes(-1)).toThrow('长度必须是非负整数，实际为 -1')
  })

  it('实现只用 WebCrypto 全局，不引入任何第三方依赖', () => {
    const source = readFileSync(fileURLToPath(new URL('../random.ts', import.meta.url)), 'utf8')
    const specifiers = [...source.matchAll(/from '([^']+)'/g)].map((m) => m[1]!)
    const external = specifiers.filter((s) => !s.startsWith('.') && s !== '@askdaddy/crypto')

    expect(external).toEqual([])
    expect(source).toContain('crypto.getRandomValues')
  })
})
