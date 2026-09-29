import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import type { RandomProvider } from '@askdaddy/crypto'
import { describe, expect, it } from 'vitest'

import { uuidV7 } from '../id.js'
import { fixtureRandom } from './helpers.js'

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

/** 大于 2^32，能同时验到时间戳高 16 bit 与低 32 bit 的写入。 */
const NOW = 1_737_000_000_000

function timestampOf(id: string): number {
  return Number.parseInt(id.slice(0, 8) + id.slice(9, 13), 16)
}

describe('uuidV7 的格式', () => {
  it('输出 36 字符的标准连字符格式，version 位为 7、variant 位为 8/9/a/b', () => {
    for (let i = 0; i < 50; i += 1) {
      const id = uuidV7(fixtureRandom, NOW)
      expect(id, id).toHaveLength(36)
      expect(id, id).toMatch(UUID_V7)
      expect(id[14], id).toBe('7')
      expect(['8', '9', 'a', 'b'], id).toContain(id[19])
    }
  })
})

describe('uuidV7 的时间戳来自注入的 now', () => {
  it('前 48 bit 等于传入的 Unix 毫秒', () => {
    expect(timestampOf(uuidV7(fixtureRandom, NOW))).toBe(NOW)
  })

  it('毫秒以下的精度被截断而不是四舍五入', () => {
    expect(timestampOf(uuidV7(fixtureRandom, NOW + 0.9))).toBe(NOW)
  })

  it('省略 now 时回落到 Date.now()', () => {
    const before = Date.now()
    const timestamp = timestampOf(uuidV7(fixtureRandom))

    expect(timestamp).toBeGreaterThanOrEqual(before)
    expect(timestamp).toBeLessThanOrEqual(Date.now())
  })

  it('随机源确实来自注入的 Provider，不是全局 crypto', () => {
    // 固定字节 + 固定 now ⇒ 输出完全可预测。若实现偷读了全局随机源，这条会当场失败。
    const zeroes: RandomProvider = { randomBytes: (length) => new Uint8Array(length) }

    expect(uuidV7(zeroes, 0)).toBe('00000000-0000-7000-8000-000000000000')
  })
})

describe('uuidV7 的唯一性与有序性', () => {
  it('同一毫秒内连续生成 1000 个，无重复', () => {
    const ids = new Set<string>()
    for (let i = 0; i < 1000; i += 1) ids.add(uuidV7(fixtureRandom, NOW))

    expect(ids.size).toBe(1000)
  })

  it('时间推进后生成的 id 字典序更大', () => {
    const earlier = uuidV7(fixtureRandom, NOW)
    const later = uuidV7(fixtureRandom, NOW + 1)

    expect(later > earlier).toBe(true)
  })
})

describe('uuidV7 的平台无关性（AGENTS.md §3）', () => {
  const source = readFileSync(fileURLToPath(new URL('../id.ts', import.meta.url)), 'utf8')

  it('只 import 相对模块与 @askdaddy 内部包，且不依赖 crypto-web', () => {
    const specifiers = [...source.matchAll(/from '([^']+)'/g)].map((match) => match[1]!)
    const external = specifiers.filter(
      (specifier) => !specifier.startsWith('.') && !specifier.startsWith('@askdaddy/'),
    )

    expect(specifiers).not.toEqual([])
    expect(external).toEqual([])
    expect(source).not.toContain('@askdaddy/crypto-web')
  })

  it('不触碰全局随机源与 Node 内置模块', () => {
    for (const banned of ['getRandomValues', 'globalThis', 'node:', 'require(', 'Buffer']) {
      expect(source, banned).not.toContain(banned)
    }
  })

  it('不引入 uuid 依赖', () => {
    const manifest = JSON.parse(
      readFileSync(fileURLToPath(new URL('../../package.json', import.meta.url)), 'utf8'),
    ) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }

    expect(Object.keys(manifest.dependencies ?? {})).not.toContain('uuid')
    expect(Object.keys(manifest.devDependencies ?? {})).not.toContain('uuid')
  })
})
