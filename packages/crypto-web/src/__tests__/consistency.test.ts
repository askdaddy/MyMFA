import { createCipheriv, createDecipheriv } from 'node:crypto'

import argon2 from 'argon2'
import { argon2id } from 'hash-wasm'
import { describe, expect, it } from 'vitest'

import {
  AES_256_GCM,
  ARGON2ID_PARAMS,
  ARGON2ID_PRODUCTION_VECTOR,
  ARGON2ID_RFC9106_VECTOR,
  ARGON2ID_VERSION,
  utf8Encode,
} from '@askdaddy/crypto'

import { webAeadProvider, webKdfProvider } from '../index.js'

/**
 * 跨端一致性基线（docs/testing.md §3）。
 *
 * `argon2` 是对照实现，绑定 P-H-C/phc-winner-argon2 官方参考实现，仅作 devDependency。
 * 它必须在模块顶层静态导入：包缺失时整个测试文件加载失败并报错，
 * 而不是被 skip 或 try/catch 吞掉——那等于变相跳过 KAT。
 */

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * node-argon2 的类型签名只接受 `Buffer`（运行时其实也吃 `Uint8Array`）。
 * 按类型走而不是断言绕过：测试文件本就豁免平台禁令，`Buffer` 在这里是合法工具。
 */
function buf(bytes: Uint8Array): Buffer {
  return Buffer.from(bytes)
}

/** 生产路径只用「主密码 + salt」，因此对照实现也不传 secret 与 associatedData。 */
function oracleDerive(password: Uint8Array, salt: Uint8Array, keyLength: number) {
  return argon2.hash(buf(password), {
    type: argon2.argon2id,
    version: ARGON2ID_VERSION,
    timeCost: ARGON2ID_PARAMS.iterations,
    memoryCost: ARGON2ID_PARAMS.memoryKiB,
    parallelism: ARGON2ID_PARAMS.parallelism,
    hashLength: keyLength,
    salt: buf(salt),
    raw: true,
  })
}

describe('Argon2id 一致性（KAT）', () => {
  it('KAT-1：对照实现在 RFC 9106 §5.3 完整入参下复现官方 tag', async () => {
    const vector = ARGON2ID_RFC9106_VECTOR

    const tag = await argon2.hash(buf(vector.password), {
      type: argon2.argon2id,
      version: vector.version,
      timeCost: vector.params.iterations,
      memoryCost: vector.params.memoryKiB,
      parallelism: vector.params.parallelism,
      hashLength: vector.params.keyLength,
      salt: buf(vector.salt),
      secret: buf(vector.secret),
      associatedData: buf(vector.associatedData),
      raw: true,
    })

    // 只比对 hex，避免断言失败时把 password / secret / salt 的字节打进输出。
    expect(hex(tag)).toBe(vector.expectedTagHex)
  })

  it('KAT-2：hash-wasm 与对照实现在生产参数下字节级相等，且等于固化基线', async () => {
    const vector = ARGON2ID_PRODUCTION_VECTOR

    const fromProvider = await webKdfProvider.deriveKey(vector.password, vector.salt, vector.params)
    const fromOracle = await oracleDerive(vector.password, vector.salt, vector.params.keyLength)

    expect(hex(fromProvider)).toBe(hex(fromOracle))
    expect(hex(fromOracle)).toBe(vector.expectedKeyHex)
  })

  it('固化基线未过期：实际派生输出等于参考向量中的期望密钥', async () => {
    const vector = ARGON2ID_PRODUCTION_VECTOR
    const key = await webKdfProvider.deriveKey(vector.password, vector.salt, vector.params)

    expect(hex(key)).toBe(vector.expectedKeyHex)
  })

  it('hash-wasm 的 PHC 串声明 v=19，且 m / t / p 与生产参数一致', async () => {
    const vector = ARGON2ID_PRODUCTION_VECTOR

    const encoded = await argon2id({
      password: vector.password,
      salt: vector.salt,
      iterations: ARGON2ID_PARAMS.iterations,
      parallelism: ARGON2ID_PARAMS.parallelism,
      memorySize: ARGON2ID_PARAMS.memoryKiB,
      hashLength: ARGON2ID_PARAMS.keyLength,
      outputType: 'encoded',
    })

    // hash-wasm 没有 version 入参，PHC 串是唯一能证明它跑的是 Argon2 1.3（0x13）的地方。
    expect(encoded.startsWith(`$argon2id$v=${ARGON2ID_VERSION}$`)).toBe(true)
    expect(ARGON2ID_VERSION).toBe(19)
    expect(encoded).toContain(
      `$m=${ARGON2ID_PARAMS.memoryKiB},t=${ARGON2ID_PARAMS.iterations},p=${ARGON2ID_PARAMS.parallelism}$`,
    )
  })
})

const AES_KEY = utf8Encode('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')
const AES_PLAINTEXT = utf8Encode('otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP')
const AES_AAD = utf8Encode('vault-header-v1')

function opensslEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
) {
  const cipher = createCipheriv('aes-256-gcm', key, nonce, {
    authTagLength: AES_256_GCM.tagLength,
  })
  if (aad !== undefined) {
    cipher.setAAD(aad)
  }

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return {
    ciphertext: new Uint8Array(ciphertext),
    tag: new Uint8Array(cipher.getAuthTag()),
  }
}

function opensslDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: tag.length })
  decipher.setAuthTag(tag)
  if (aad !== undefined) {
    decipher.setAAD(aad)
  }

  // final() 在认证失败时抛错，这正是「认证通过」的断言点。
  return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]))
}

describe('AES-256-GCM 一致性（对照 OpenSSL）', () => {
  it('相同 key / nonce / aad 下，Web Provider 的 ciphertext 与 tag 与 OpenSSL 逐字节相等', async () => {
    const sealed = await webAeadProvider.encrypt(AES_KEY, AES_PLAINTEXT, AES_AAD)
    const expected = opensslEncrypt(AES_KEY, sealed.nonce, AES_PLAINTEXT, AES_AAD)

    expect(hex(sealed.ciphertext)).toBe(hex(expected.ciphertext))
    expect(hex(sealed.tag)).toBe(hex(expected.tag))
  })

  it('OpenSSL 加密的结果能被 Web Provider 正确解密', async () => {
    const nonce = new Uint8Array(AES_256_GCM.nonceLength)
    crypto.getRandomValues(nonce)
    const { ciphertext, tag } = opensslEncrypt(AES_KEY, nonce, AES_PLAINTEXT, AES_AAD)

    const plaintext = await webAeadProvider.decrypt(AES_KEY, { nonce, ciphertext, tag }, AES_AAD)
    expect(hex(plaintext)).toBe(hex(AES_PLAINTEXT))
  })

  it('Web Provider 加密的结果能被 OpenSSL 解密并认证通过', async () => {
    const sealed = await webAeadProvider.encrypt(AES_KEY, AES_PLAINTEXT, AES_AAD)

    const plaintext = opensslDecrypt(AES_KEY, sealed.nonce, sealed.ciphertext, sealed.tag, AES_AAD)
    expect(hex(plaintext)).toBe(hex(AES_PLAINTEXT))
  })

  it('空明文的 tag 也与 OpenSSL 一致——tag 切分位置在零长度密文下最容易出错', async () => {
    const sealed = await webAeadProvider.encrypt(AES_KEY, new Uint8Array(0))
    const expected = opensslEncrypt(AES_KEY, sealed.nonce, new Uint8Array(0))

    expect(sealed.ciphertext).toHaveLength(0)
    expect(hex(sealed.tag)).toBe(hex(expected.tag))
    expect(hex(opensslDecrypt(AES_KEY, sealed.nonce, sealed.ciphertext, sealed.tag))).toBe('')
  })
})
