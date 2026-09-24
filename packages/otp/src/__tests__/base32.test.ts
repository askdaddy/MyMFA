import { describe, expect, it } from 'vitest'

import { base32Decode, base32Encode } from '../base32.js'
import { Base32DecodeError } from '../errors.js'

/** RFC 4648 §10 官方测试向量。 */
const RFC_4648_VECTORS: ReadonlyArray<[string, string]> = [
  ['', ''],
  ['f', 'MY======'],
  ['fo', 'MZXQ===='],
  ['foo', 'MZXW6==='],
  ['foob', 'MZXW6YQ='],
  ['fooba', 'MZXW6YTB'],
  ['foobar', 'MZXW6YTBOI======'],
]

function ascii(text: string): Uint8Array {
  return new Uint8Array(text.split('').map((c) => c.charCodeAt(0)))
}

describe('base32Encode', () => {
  it.each(RFC_4648_VECTORS)('编码 %j', (plain, encoded) => {
    expect(base32Encode(ascii(plain))).toBe(encoded)
  })
})

describe('base32Decode', () => {
  it.each(RFC_4648_VECTORS)('解码 %j', (plain, encoded) => {
    expect(base32Decode(encoded)).toEqual(ascii(plain))
  })

  it('容忍小写、空格、连字符与缺失的 padding', () => {
    const expected = ascii('foobar')
    expect(base32Decode('mzxw6ytboi')).toEqual(expected)
    expect(base32Decode('MZXW 6YTB OI')).toEqual(expected)
    expect(base32Decode('MZXW-6YTB-OI')).toEqual(expected)
    expect(base32Decode('MZXW6YTBOI=')).toEqual(expected)
  })

  it('纠正 0/O 与 1/I 的手抄混淆', () => {
    const canonical = 'MZXW6YTBOI======'
    expect(base32Decode('MZXW6YTB01======')).toEqual(base32Decode(canonical))
    expect(base32Decode('mzxw6ytb01')).toEqual(base32Decode(canonical))
  })

  it('丢弃末尾不足 8 bit 的填充位', () => {
    // 7 个字符 = 35 bit，只够 4 字节，剩下 3 bit 是填充；写成非零值仍应解出同样的字节
    expect(base32Decode('MZXW6YQ')).toEqual(ascii('foob'))
    expect(base32Decode('MZXW6YR')).toEqual(ascii('foob'))
  })

  it('对非法字符抛 Base32DecodeError', () => {
    expect(() => base32Decode('MZXW6YT8')).toThrow(Base32DecodeError)
    expect(() => base32Decode('MZXW6YT9')).toThrow(Base32DecodeError)
    expect(() => base32Decode('MZXW!YTB')).toThrow(Base32DecodeError)
  })

  it('空输入与纯 padding 输入都解出空字节（RFC 4648 对称性）', () => {
    expect(base32Decode('')).toEqual(new Uint8Array(0))
    expect(base32Decode('====')).toEqual(new Uint8Array(0))
  })
})

describe('往返', () => {
  it('对任意字节序列保持往返一致', () => {
    for (const length of [0, 1, 2, 3, 4, 5, 10, 16, 20, 32, 64]) {
      const bytes = new Uint8Array(length)
      for (let i = 0; i < length; i += 1) bytes[i] = (i * 37 + 11) % 256
      expect(base32Decode(base32Encode(bytes))).toEqual(bytes)
    }
  })
})
