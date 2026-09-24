import { Base32DecodeError } from './errors.js'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

const VALUES = new Int8Array(128).fill(-1)
for (let i = 0; i < ALPHABET.length; i += 1) {
  VALUES[ALPHABET.charCodeAt(i)] = i
}

/**
 * base32 字母表不含 `0` 和 `1`，而它们与 `O` / `I` 的混淆是手抄 secret 时最常见的错误，
 * 因此解码阶段直接纠正而不是报错——报错会让用户无法导入自己早已在用的条目。
 */
const CONFUSABLE = new Map([
  ['0', 'O'],
  ['1', 'I'],
])

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0
  let value = 0
  let out = ''

  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += ALPHABET.charAt((value >>> bits) & 0x1f)
    }
  }

  if (bits > 0) {
    out += ALPHABET.charAt((value << (5 - bits)) & 0x1f)
  }

  while (out.length % 8 !== 0) {
    out += '='
  }

  return out
}

export function base32Decode(input: string): Uint8Array {
  const normalized = input
    .toUpperCase()
    .replaceAll('=', '')
    .replaceAll(/\s|-/g, '')
    .replace(/[01]/g, (c) => CONFUSABLE.get(c) ?? c)

  const out = new Uint8Array(Math.floor((normalized.length * 5) / 8))
  let bits = 0
  let value = 0
  let index = 0

  for (let i = 0; i < normalized.length; i += 1) {
    const code = normalized.charCodeAt(i)
    const decoded = code < 128 ? (VALUES[code] ?? -1) : -1
    if (decoded === -1) {
      throw new Base32DecodeError(`位置 ${i} 处的字符不是合法 base32 字符（合法字符为 A-Z 与 2-7）`)
    }
    value = (value << 5) | decoded
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out[index] = (value >>> bits) & 0xff
      index += 1
    }
  }

  return out
}
