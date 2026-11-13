import { createRequire } from 'node:module'
import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto'
import { gzipSync, gunzipSync } from 'node:zlib'

import type { NativeCryptoBridge } from '../../apps/mobile/src/crypto/bridge.js'

/**
 * QA 侧的原生桥替身（#19 步骤 8）。
 *
 * 这不是「模拟原生实现」——Kotlin 无法在 Node 里跑，而原生字节级正确性已由 #17 的 Android
 * gate 覆盖。这里要验的是另一件事：**TS 适配层**（参数映射、nonce/tag 切分、错误映射）
 * 接上真实原语时，vault 的 185 项语义测试是否照旧成立。
 *
 * 因此每个原语都用仓库既有的真实实现，不用假算法：
 * - Argon2id：`argon2`（P-H-C 参考实现绑定，crypto-web 的一致性测试用它，
 *   见 docs/testing.md §3.2「Web 端的等价论证链」）
 * - scrypt / AES-GCM / 随机数 / gzip：Node 内置 OpenSSL / zlib
 *
 * `argon2` 只装在 `packages/crypto-web` 的 devDependencies 下，故用 createRequire 借它的解析根，
 * 而不是把依赖强行提到根 package（QA 不改业务包）。
 */
const requireFromCryptoWeb = createRequire(
  new URL('../../packages/crypto-web/package.json', import.meta.url),
)
const argon2 = requireFromCryptoWeb('argon2') as {
  hash(
    password: Buffer,
    options: {
      salt: Buffer
      type: unknown
      memoryCost: number
      timeCost: number
      parallelism: number
      hashLength: number
      raw: boolean
      version: number
    },
  ): Promise<Buffer>
  argon2id: unknown
}

/** `ILOOP_MOBILE_BRIDGE=broken` 时让 KDF 直接炸掉，用于负向对照：证明注入真的生效。 */
const BROKEN = process.env.ILOOP_MOBILE_BRIDGE === 'broken'

export const bridgeCallCounts = {
  argon2id: 0,
  scrypt: 0,
  aesGcmEncrypt: 0,
  aesGcmDecrypt: 0,
}

function coded(code: string, message: string): Error {
  const error = new Error(message) as Error & { code: string }
  error.code = code
  return error
}

export const nodeBridge: NativeCryptoBridge = {
  async argon2id(password, salt, memoryKiB, iterations, parallelism, keyLength, version) {
    bridgeCallCounts.argon2id += 1
    if (BROKEN) {
      throw new Error('ILOOP_MOBILE_BRIDGE=broken：注入点未生效或适配层未调用原生桥')
    }
    const key = await argon2.hash(Buffer.from(password), {
      salt: Buffer.from(salt),
      type: argon2.argon2id,
      memoryCost: memoryKiB,
      timeCost: iterations,
      parallelism,
      hashLength: keyLength,
      raw: true,
      version,
    })
    return new Uint8Array(key)
  },

  async scrypt(password, salt, costFactor, blockSize, parallelism, keyLength) {
    bridgeCallCounts.scrypt += 1
    const key = scryptSync(Buffer.from(password), Buffer.from(salt), keyLength, {
      N: costFactor,
      r: blockSize,
      p: parallelism,
      maxmem: 256 * 1024 * 1024,
    })
    return new Uint8Array(key)
  },

  async aesGcmEncrypt(key, plaintext, aad) {
    bridgeCallCounts.aesGcmEncrypt += 1
    const nonce = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), nonce)
    if (aad !== undefined) cipher.setAAD(Buffer.from(aad))
    // 与原生一致：nonce(12) ‖ ciphertext ‖ tag(16) 单段返回。
    return new Uint8Array(
      Buffer.concat([nonce, cipher.update(Buffer.from(plaintext)), cipher.final(), cipher.getAuthTag()]),
    )
  },

  async aesGcmDecrypt(key, nonce, ciphertext, tag, aad) {
    bridgeCallCounts.aesGcmDecrypt += 1
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce))
    if (aad !== undefined) decipher.setAAD(Buffer.from(aad))
    decipher.setAuthTag(Buffer.from(tag))
    try {
      return new Uint8Array(
        Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]),
      )
    } catch {
      throw coded('ERR_AEAD_AUTH', 'AES-256-GCM 认证失败')
    }
  },

  randomBytes(length) {
    return new Uint8Array(randomBytes(length))
  },

  async gzip(bytes) {
    return new Uint8Array(gzipSync(Buffer.from(bytes)))
  },

  async gunzip(bytes) {
    try {
      return new Uint8Array(gunzipSync(Buffer.from(bytes)))
    } catch {
      throw coded('ERR_GZIP', 'gzip 解压失败')
    }
  },

  // vault 契约不含 SecureStore；这里给一个内存实现，让 MobileProviders 的类型闭合。
  async secureStoreRead(name) {
    return memoryStore.get(name) ?? null
  },
  async secureStoreWrite(name, value) {
    memoryStore.set(name, value)
  },
  async secureStoreRemove(name) {
    memoryStore.delete(name)
  },
}

const memoryStore = new Map<string, Uint8Array>()

process.on('exit', () => {
  console.log(
    `[mobile-bridge] argon2id=${bridgeCallCounts.argon2id} aesGcmEncrypt=${bridgeCallCounts.aesGcmEncrypt} aesGcmDecrypt=${bridgeCallCounts.aesGcmDecrypt}`,
  )
})
