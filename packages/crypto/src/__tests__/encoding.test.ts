import { describe, expect, it } from 'vitest'

import { base64Decode, base64Encode, utf8Decode, utf8Encode } from '../encoding.js'
import { Base64DecodeError } from '../errors.js'

/** 确定性伪随机，避免测试结果随种子漂移。 */
function lcg(seed: number): () => number {
  let state = seed
  return () => {
    state = (state * 1103515245 + 12345) % 2147483648
    return state / 2147483648
  }
}

function randomBytes(length: number, seed: number): Uint8Array {
  const next = lcg(seed)
  const out = new Uint8Array(length)
  for (let i = 0; i < length; i += 1) out[i] = Math.floor(next() * 256)
  return out
}

const SAMPLE_BYTE_LENGTHS = [0, 1, 2, 3, 4, 5, 12, 16, 32, 33, 64, 100]

describe('base64', () => {
  it.each(SAMPLE_BYTE_LENGTHS)('与 Node Buffer 编码一致（%i 字节）', (length) => {
    const bytes = randomBytes(length, length + 1)
    expect(base64Encode(bytes)).toBe(Buffer.from(bytes).toString('base64'))
  })

  it.each(SAMPLE_BYTE_LENGTHS)('与 Node Buffer 解码一致（%i 字节）', (length) => {
    const bytes = randomBytes(length, length + 1)
    const encoded = Buffer.from(bytes).toString('base64')
    expect(base64Decode(encoded)).toEqual(bytes)
  })

  it('保持往返一致', () => {
    for (const length of SAMPLE_BYTE_LENGTHS) {
      const bytes = randomBytes(length, length * 7 + 3)
      expect(base64Decode(base64Encode(bytes))).toEqual(bytes)
    }
  })

  it('容忍缺失 padding、空白与 base64url 字母表', () => {
    const bytes = randomBytes(32, 99)
    const standard = base64Encode(bytes)
    expect(base64Decode(standard.replaceAll('=', ''))).toEqual(bytes)
    expect(base64Decode(standard.replaceAll('+', '-').replaceAll('/', '_'))).toEqual(bytes)
    expect(base64Decode(standard.replace(/(.{4})/g, '$1\n'))).toEqual(bytes)
  })

  it('对非法字符抛 Base64DecodeError', () => {
    expect(() => base64Decode('!!!!')).toThrow(Base64DecodeError)
    expect(() => base64Decode('abc*')).toThrow(Base64DecodeError)
  })

  it('空输入解出空字节', () => {
    expect(base64Decode('')).toEqual(new Uint8Array(0))
    expect(base64Encode(new Uint8Array(0))).toBe('')
  })
})

const UTF8_SAMPLES = [
  '',
  'ascii only',
  '中文服务商',
  '混合 mixed 中文 with émoji 🎉🔐',
  '𝄞 four byte',
  'zero\u0000null',
  'café',
  '　全角空格',
]

describe('utf8', () => {
  it.each(UTF8_SAMPLES)('编码与 Node Buffer 一致：%j', (text) => {
    expect(utf8Encode(text)).toEqual(new Uint8Array(Buffer.from(text, 'utf8')))
  })

  it.each(UTF8_SAMPLES)('解码与 Node Buffer 一致：%j', (text) => {
    const bytes = new Uint8Array(Buffer.from(text, 'utf8'))
    expect(utf8Decode(bytes)).toBe(Buffer.from(bytes).toString('utf8'))
  })

  it('保持往返一致', () => {
    for (const text of UTF8_SAMPLES) {
      expect(utf8Decode(utf8Encode(text))).toBe(text)
    }
  })

  it('孤立代理项替换为 U+FFFD，与 Node 一致', () => {
    const lone = '\ud800'
    expect(utf8Encode(lone)).toEqual(new Uint8Array(Buffer.from(lone, 'utf8')))
    expect(utf8Decode(utf8Encode(lone))).toBe('\ufffd')
  })

  it('畸形字节序列不抛错，且解出的字符串不含孤立代理项', () => {
    const malformed = [
      new Uint8Array([0xe4, 0xb8]), // 截断的 3 字节序列
      new Uint8Array([0xf0, 0x9f, 0x8e]), // 截断的 4 字节序列
      new Uint8Array([0x80, 0x41]), // 孤立续字节
      new Uint8Array([0xff, 0xfe]), // 非法前导字节
      new Uint8Array([0xf4, 0x90, 0x80, 0x80]), // 超出 U+10FFFF
      new Uint8Array([0xed, 0xa0, 0x80]), // 以 UTF-8 形式编码的代理项 U+D800
    ]
    for (const bytes of malformed) {
      const decoded = utf8Decode(bytes)
      for (const char of decoded) {
        const codePoint = char.codePointAt(0)!
        expect(codePoint < 0xd800 || codePoint > 0xdfff).toBe(true)
      }
    }
  })

  it('以 UTF-8 形式编码的代理项解不出代理项字符', () => {
    // U+D800 的（非法）UTF-8 编码
    const decoded = utf8Decode(new Uint8Array([0xed, 0xa0, 0x80]))
    expect(decoded).not.toBe('\ud800')
    expect(decoded.replaceAll('\ufffd', '')).toBe('')
  })

  it('过度编码不被接受：C0 80 解不出 NUL', () => {
    // 若过度编码被当作合法 NUL，就会被用来绕过以字符串比较为前提的校验
    expect(utf8Decode(new Uint8Array([0xc0, 0x80]))).not.toContain('\u0000')
  })
})
