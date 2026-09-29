import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import { AeadAuthError, AES_256_GCM, CryptoParamsError, utf8Encode } from '@askdaddy/crypto'
import type { AeadProvider, AeadSealed } from '@askdaddy/crypto'

import { webAeadProvider } from '../aead.js'

const provider: AeadProvider = webAeadProvider

/** AGENTS.md §5.3：夹具一律用假值，且长度必须恰为 32 字节。 */
const KEY = utf8Encode('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')
const WRONG_KEY = utf8Encode('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXQ')
const PLAINTEXT = utf8Encode('otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP')
const AAD = utf8Encode('vault-header-v1')

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function copy(sealed: AeadSealed): AeadSealed {
  return {
    nonce: Uint8Array.from(sealed.nonce),
    ciphertext: Uint8Array.from(sealed.ciphertext),
    tag: Uint8Array.from(sealed.tag),
  }
}

describe('webAeadProvider', () => {
  it('name 为字面量 aes-256-gcm', () => {
    expect(provider.name).toBe('aes-256-gcm')
  })

  it('nonce 12 字节、tag 16 字节，ciphertext 不含 tag', async () => {
    const sealed = await provider.encrypt(KEY, PLAINTEXT)

    expect(sealed.nonce).toHaveLength(AES_256_GCM.nonceLength)
    expect(sealed.tag).toHaveLength(AES_256_GCM.tagLength)
    expect(sealed.ciphertext).toHaveLength(PLAINTEXT.length)
  })

  it('encrypt 的形参只有 key / plaintext / aad，没有 nonce', () => {
    // 真正的约束是上面的 `const provider: AeadProvider`——签名不符 typecheck 就过不去。
    // 这里再补一道运行时断言，防止有人给实现悄悄加上第四个形参。
    expect(provider.encrypt.length).toBe(3)
  })

  it('往返还原字节级相等', async () => {
    const sealed = await provider.encrypt(KEY, PLAINTEXT)
    expect(hex(await provider.decrypt(KEY, sealed))).toBe(hex(PLAINTEXT))
  })

  it('空明文与非 ASCII 明文同样可往返', async () => {
    for (const plaintext of [new Uint8Array(0), utf8Encode('验证码 🔐 中文与 emoji')]) {
      const sealed = await provider.encrypt(KEY, plaintext)
      expect(hex(await provider.decrypt(KEY, sealed))).toBe(hex(plaintext))
    }
  })

  it('同一明文加密两次，nonce 与 ciphertext 均不同', async () => {
    const a = await provider.encrypt(KEY, PLAINTEXT)
    const b = await provider.encrypt(KEY, PLAINTEXT)

    expect(hex(a.nonce)).not.toBe(hex(b.nonce))
    expect(hex(a.ciphertext)).not.toBe(hex(b.ciphertext))
  })

  it('aad 参与认证：相同 aad 解密成功，不同 aad 抛 AeadAuthError', async () => {
    const sealed = await provider.encrypt(KEY, PLAINTEXT, AAD)

    expect(hex(await provider.decrypt(KEY, sealed, AAD))).toBe(hex(PLAINTEXT))
    await expect(provider.decrypt(KEY, sealed, utf8Encode('vault-header-v2'))).rejects.toThrow(
      AeadAuthError,
    )
    await expect(provider.decrypt(KEY, sealed)).rejects.toThrow(AeadAuthError)
  })

  it('加密时不带 aad、解密时带 aad 同样失败', async () => {
    const sealed = await provider.encrypt(KEY, PLAINTEXT)
    await expect(provider.decrypt(KEY, sealed, AAD)).rejects.toThrow(AeadAuthError)
  })

  it('篡改 ciphertext / nonce / tag 中任一项均抛 AeadAuthError', async () => {
    for (const tamper of [
      (s: AeadSealed) => {
        s.ciphertext[0]! ^= 0xff
      },
      (s: AeadSealed) => {
        s.nonce[0]! ^= 0xff
      },
      (s: AeadSealed) => {
        s.tag[0]! ^= 0xff
      },
    ]) {
      const sealed = copy(await provider.encrypt(KEY, PLAINTEXT))
      tamper(sealed)
      await expect(provider.decrypt(KEY, sealed)).rejects.toThrow(AeadAuthError)
    }
  })

  it('密钥错误与数据被篡改在类型和消息上不可区分', async () => {
    const sealed = await provider.encrypt(KEY, PLAINTEXT)

    const wrongKey = await provider.decrypt(WRONG_KEY, copy(sealed)).catch((e: unknown) => e)
    const tampered = copy(sealed)
    tampered.ciphertext[0]! ^= 0xff
    const tamperedError = await provider.decrypt(KEY, tampered).catch((e: unknown) => e)

    expect(wrongKey).toBeInstanceOf(AeadAuthError)
    expect(tamperedError).toBeInstanceOf(AeadAuthError)
    expect((wrongKey as Error).name).toBe((tamperedError as Error).name)
    expect((wrongKey as Error).message).toBe((tamperedError as Error).message)
  })

  it('AeadAuthError 的消息不透传 WebCrypto 原始错误文本', async () => {
    const sealed = copy(await provider.encrypt(KEY, PLAINTEXT))
    sealed.tag[0]! ^= 0xff

    const error = (await provider.decrypt(KEY, sealed).catch((e: unknown) => e)) as AeadAuthError
    expect(error.message).not.toMatch(/OperationError|operation-specific|DOMException/i)
  })

  it('错误消息不泄露密钥、明文或 nonce 的字节值', async () => {
    const sealed = copy(await provider.encrypt(KEY, PLAINTEXT))
    sealed.ciphertext[0]! ^= 0xff

    // 用 thunk 而不是 promise 数组：一次性建好三个 promise 会让后两个在
    // catch 挂上之前就 reject，Node 会报 PromiseRejectionHandledWarning。
    const attempts = [
      () => provider.decrypt(KEY, sealed),
      () => provider.decrypt(WRONG_KEY, copy(sealed)),
      () => provider.decrypt(utf8Encode('too-short'), sealed),
    ]

    const messages: string[] = []
    for (const attempt of attempts) {
      await attempt().catch((e: unknown) => messages.push((e as Error).message))
    }

    const leakable = [
      hex(KEY),
      hex(PLAINTEXT),
      hex(sealed.nonce),
      'JBSWY3DPEHPK3PXP',
      'otpauth://totp',
    ]
    expect(messages).toHaveLength(attempts.length)
    for (const message of messages) {
      for (const value of leakable) {
        expect(message).not.toContain(value)
      }
    }
  })

  it('密钥长度非 32 字节抛 CryptoParamsError，不裸抛 WebCrypto 错误', async () => {
    for (const key of [
      new Uint8Array(0),
      new Uint8Array(16),
      new Uint8Array(31),
      new Uint8Array(33),
    ]) {
      await expect(provider.encrypt(key, PLAINTEXT)).rejects.toThrow(CryptoParamsError)
      await expect(
        provider.decrypt(key, {
          nonce: new Uint8Array(12),
          ciphertext: new Uint8Array(0),
          tag: new Uint8Array(16),
        }),
      ).rejects.toThrow(CryptoParamsError)
    }
  })

  it('实现不 import Node 内置模块，不使用 process / Buffer', () => {
    const source = readFileSync(fileURLToPath(new URL('../aead.ts', import.meta.url)), 'utf8')
    const specifiers = [...source.matchAll(/from '([^']+)'/g)].map((m) => m[1]!)
    const external = specifiers.filter((s) => !s.startsWith('.') && s !== '@askdaddy/crypto')

    expect(external).toEqual([])
    expect(source).not.toMatch(/\bprocess\b/)
    expect(source).not.toMatch(/\bBuffer\b/)
  })
})
