import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { gzipSync, gunzipSync } from 'node:zlib'

import { describe, expect, it } from 'vitest'

import { CompressError, utf8Encode } from '@askdaddy/crypto'
import type { CompressProvider } from '@askdaddy/crypto'

import { webCompressProvider } from '../compress.js'

const provider: CompressProvider = webCompressProvider

const cases: ReadonlyArray<readonly [string, Uint8Array]> = [
  ['空输入', new Uint8Array(0)],
  ['单个字节', new Uint8Array([0x42])],
  ['纯 ASCII', utf8Encode('correct horse battery staple')],
  ['中文与 emoji', utf8Encode('密钥库🔐 MyMFA 双因素认证')],
  ['不可压缩的随机字节', new Uint8Array(randomBytes(4096))],
]

describe('webCompressProvider', () => {
  it('name 为字面量 gzip', () => {
    expect(provider.name).toBe('gzip')
  })

  it.each(cases)('往返还原字节级相等：%s', async (_label, input) => {
    expect(await provider.decompress(await provider.compress(input))).toEqual(input)
  })

  it('输出是真 gzip：魔数为 1f 8b，且能被 node:zlib 解开', async () => {
    const input = utf8Encode('跨实现可读')
    const compressed = await provider.compress(input)

    expect([compressed[0], compressed[1]]).toEqual([0x1f, 0x8b])
    expect(new Uint8Array(gunzipSync(compressed))).toEqual(input)
  })

  it('node:zlib 产出的 gzip 同样能被解开——只要求可互解，不要求输出字节一致', async () => {
    const input = utf8Encode('{"schemaVersion":1}')

    expect(await provider.decompress(new Uint8Array(gzipSync(input)))).toEqual(input)
  })

  it('大负载不死锁：256 KiB 输入往返成功', async () => {
    const input = utf8Encode('x'.repeat(256 * 1024))

    expect(await provider.decompress(await provider.compress(input))).toEqual(input)
  })

  it('非法 gzip 字节流抛 CompressError，不吞错误返回空数组', async () => {
    const truncated = (await provider.compress(utf8Encode('truncated'))).subarray(0, 12)

    for (const bytes of [new Uint8Array(0), utf8Encode('not gzip'), randomBytes(64), truncated]) {
      await expect(provider.decompress(bytes)).rejects.toThrow(CompressError)
    }
  })

  it('错误消息是固定文本，不回显输入字节', async () => {
    await expect(provider.decompress(utf8Encode('hunter2-secret-bytes'))).rejects.toThrow(
      'gzip 解压失败：输入不是合法的 gzip 字节流',
    )
  })

  it('实现不 import Node 内置模块，不使用 process / Buffer', () => {
    const source = readFileSync(fileURLToPath(new URL('../compress.ts', import.meta.url)), 'utf8')
    const specifiers = [...source.matchAll(/from '([^']+)'/g)].map((m) => m[1]!)

    expect(specifiers.filter((s) => !s.startsWith('.') && s !== '@askdaddy/crypto')).toEqual([])
    expect(source).not.toMatch(/\bprocess\b/)
    expect(source).not.toMatch(/\bBuffer\b/)
    expect(source).toContain("new CompressionStream('gzip')")
    expect(source).toContain("new DecompressionStream('gzip')")
  })
})
