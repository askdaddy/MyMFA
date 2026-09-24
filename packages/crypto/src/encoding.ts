import { Base64DecodeError } from './errors.js'

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

const BASE64_VALUES = new Int8Array(128).fill(-1)
for (let i = 0; i < BASE64_ALPHABET.length; i += 1) {
  BASE64_VALUES[BASE64_ALPHABET.charCodeAt(i)] = i
}

// base64url 与标准 base64 只差两个字符；导入他 App 的数据时两种都会遇到。
BASE64_VALUES['-'.charCodeAt(0)] = BASE64_VALUES['+'.charCodeAt(0)]!
BASE64_VALUES['_'.charCodeAt(0)] = BASE64_VALUES['/'.charCodeAt(0)]!

export function base64Encode(bytes: Uint8Array): string {
  let out = ''
  let i = 0

  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!
    out +=
      BASE64_ALPHABET.charAt((n >>> 18) & 0x3f) +
      BASE64_ALPHABET.charAt((n >>> 12) & 0x3f) +
      BASE64_ALPHABET.charAt((n >>> 6) & 0x3f) +
      BASE64_ALPHABET.charAt(n & 0x3f)
  }

  const remaining = bytes.length - i
  if (remaining === 1) {
    const n = bytes[i]! << 16
    out +=
      BASE64_ALPHABET.charAt((n >>> 18) & 0x3f) + BASE64_ALPHABET.charAt((n >>> 12) & 0x3f) + '=='
  } else if (remaining === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8)
    out +=
      BASE64_ALPHABET.charAt((n >>> 18) & 0x3f) +
      BASE64_ALPHABET.charAt((n >>> 12) & 0x3f) +
      BASE64_ALPHABET.charAt((n >>> 6) & 0x3f) +
      '='
  }

  return out
}

export function base64Decode(input: string): Uint8Array {
  const normalized = input.replaceAll('=', '').replaceAll(/\s/g, '')
  const out = new Uint8Array(Math.floor((normalized.length * 6) / 8))

  let bits = 0
  let value = 0
  let index = 0

  for (let i = 0; i < normalized.length; i += 1) {
    const code = normalized.charCodeAt(i)
    const decoded = code < 128 ? (BASE64_VALUES[code] ?? -1) : -1
    if (decoded === -1) {
      throw new Base64DecodeError(`位置 ${i} 处的字符不是合法 base64 字符`)
    }
    value = (value << 6) | decoded
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[index] = (value >>> bits) & 0xff
      index += 1
    }
  }

  return out
}

const REPLACEMENT = 0xfffd

function encodeCodePoint(codePoint: number, out: number[]): void {
  // 孤立代理项不是合法 Unicode 标量值；与 WHATWG 和 Node 的行为一致，替换为 U+FFFD。
  const cp = codePoint >= 0xd800 && codePoint <= 0xdfff ? REPLACEMENT : codePoint

  if (cp < 0x80) {
    out.push(cp)
  } else if (cp < 0x800) {
    out.push(0xc0 | (cp >>> 6), 0x80 | (cp & 0x3f))
  } else if (cp < 0x10000) {
    out.push(0xe0 | (cp >>> 12), 0x80 | ((cp >>> 6) & 0x3f), 0x80 | (cp & 0x3f))
  } else {
    out.push(
      0xf0 | (cp >>> 18),
      0x80 | ((cp >>> 12) & 0x3f),
      0x80 | ((cp >>> 6) & 0x3f),
      0x80 | (cp & 0x3f),
    )
  }
}

/**
 * 不用 `TextEncoder` / `TextDecoder`：Hermes 不保证提供这两个全局，
 * 而主密码的 UTF-8 字节序列只要有一端不同，派生出的 KEK 就完全不同、vault 直接打不开。
 * 自己实现并用 Node 的行为做对照测试，比依赖各端 polyfill 更可控。
 */
export function utf8Encode(text: string): Uint8Array {
  const out: number[] = []
  for (const char of text) {
    encodeCodePoint(char.codePointAt(0)!, out)
  }
  return Uint8Array.from(out)
}

export function utf8Decode(bytes: Uint8Array): string {
  let out = ''
  let i = 0

  while (i < bytes.length) {
    const lead = bytes[i]!

    if (lead < 0x80) {
      out += String.fromCharCode(lead)
      i += 1
      continue
    }

    const length = lead >= 0xf0 ? 4 : lead >= 0xe0 ? 3 : lead >= 0xc0 ? 2 : 0
    if (length === 0 || i + length > bytes.length) {
      out += String.fromCharCode(REPLACEMENT)
      i += 1
      continue
    }

    let codePoint = lead & ((1 << (7 - length)) - 1)
    let valid = true
    for (let j = 1; j < length; j += 1) {
      const continuation = bytes[i + j]!
      if ((continuation & 0xc0) !== 0x80) {
        valid = false
        break
      }
      codePoint = (codePoint << 6) | (continuation & 0x3f)
    }

    const minLength = codePoint < 0x80 ? 1 : codePoint < 0x800 ? 2 : codePoint < 0x10000 ? 3 : 4
    // 代理项区间的码点不允许以 UTF-8 形式出现（WHATWG 与 Node 都替换为 U+FFFD）。
    // 放过它会让解出的字符串带上孤立代理项，再编码时各端行为不一致。
    const isSurrogate = codePoint >= 0xd800 && codePoint <= 0xdfff
    if (!valid || isSurrogate || minLength !== length || codePoint > 0x10ffff) {
      out += String.fromCharCode(REPLACEMENT)
      i += 1
      continue
    }

    out += String.fromCodePoint(codePoint)
    i += length
  }

  return out
}
