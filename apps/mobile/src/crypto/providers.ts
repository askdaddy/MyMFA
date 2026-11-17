import {
  AeadAuthError,
  AES_256_GCM,
  ARGON2ID_VERSION,
  assertArgon2idParams,
  assertScryptParams,
  CompressError,
  CryptoError,
  CryptoParamsError,
} from '@askdaddy/crypto'
import type {
  AeadProvider,
  AeadSealed,
  CompressProvider,
  CryptoProviders,
  KdfProvider,
  RandomProvider,
  ScryptProvider,
  SecureStore,
} from '@askdaddy/crypto'

import { NATIVE_ERROR_CODES, nativeErrorCode, type NativeCryptoBridge } from './bridge'

export interface MobileProviders extends CryptoProviders {
  /** ADR-018 兼容路径：**不得**赋给 vault 的 KDF（`VaultProviders.kdf` 只收 Argon2id）。 */
  scrypt: ScryptProvider
  secureStore: SecureStore
}

const AEAD_AUTH_MESSAGE = 'AES-256-GCM 认证失败：密钥不正确或数据已被篡改'

/**
 * 把原生 `CodedException` 映射回 `@askdaddy/crypto` 的错误类型。
 *
 * 认证失败必须变成 `AeadAuthError`，vault 才认得出这是「密码错或文件损坏」这一类、
 * 从而把它归并进统一提示；映射漏了会让 `openVault` 把一次认证失败当成程序 bug 抛出去，
 * 等于给用户一个「密码对不对」的旁路。
 */
function rethrowNative(error: unknown): never {
  switch (nativeErrorCode(error)) {
    case NATIVE_ERROR_CODES.aeadAuth:
      throw new AeadAuthError(AEAD_AUTH_MESSAGE)
    case NATIVE_ERROR_CODES.gzip:
      throw new CompressError('gzip 解压失败：输入不是合法的 gzip 字节流')
    case NATIVE_ERROR_CODES.cryptoParam: {
      const message = error instanceof Error ? error.message : '原生加密参数不合法'
      throw new CryptoParamsError(message)
    }
    case NATIVE_ERROR_CODES.secureStore:
      throw new CryptoError('设备安全存储操作失败')
    default:
      throw error instanceof Error ? error : new CryptoError('原生加密调用失败')
  }
}

function assertKey(key: Uint8Array): void {
  if (key.length !== AES_256_GCM.keyLength) {
    throw new CryptoParamsError(
      `AES-256-GCM 密钥必须是 ${AES_256_GCM.keyLength} 字节，实际为 ${key.length} 字节`,
    )
  }
}

/**
 * 用注入的原生桥构造移动端 Provider 栈。
 *
 * 不在这里 import `expo`：那会让本模块在 Node（QA 的 185 项复跑、适配层单测）里不可加载，
 * 而「同一份适配层在两端跑同一组契约」正是这套抽象的价值所在。
 */
export function createMobileProviders(bridge: NativeCryptoBridge): MobileProviders {
  const kdf: KdfProvider = {
    name: 'argon2id',

    async deriveKey(password, salt, params) {
      // 只做结构性校验：RFC 9106 的低内存向量必须能跑，基线降级检查属于 vault 层。
      assertArgon2idParams(params)
      return bridge.argon2id(
        password,
        salt,
        params.memoryKiB,
        params.iterations,
        params.parallelism,
        params.keyLength,
        // 版本必须显式传：各库默认值不一致，漏传会静默改变输出（docs/testing.md §3.4）。
        ARGON2ID_VERSION,
      )
    },
  }

  const scrypt: ScryptProvider = {
    name: 'scrypt',

    async deriveKey(password, salt, params) {
      assertScryptParams(params, salt)
      return bridge.scrypt(
        password,
        salt,
        params.costFactor,
        params.blockSize,
        params.parallelism,
        params.keyLength,
      )
    },
  }

  const aead: AeadProvider = {
    name: 'aes-256-gcm',

    async encrypt(key, plaintext, aad): Promise<AeadSealed> {
      assertKey(key)
      let sealed: Uint8Array
      try {
        sealed = await bridge.aesGcmEncrypt(key, plaintext, aad)
      } catch (error) {
        rethrowNative(error)
      }

      const minimum = AES_256_GCM.nonceLength + AES_256_GCM.tagLength
      if (sealed.length < minimum) {
        throw new CryptoError('原生 AEAD 返回的数据短于 nonce + tag 的固定长度')
      }

      const bodyEnd = sealed.length - AES_256_GCM.tagLength
      return {
        nonce: sealed.subarray(0, AES_256_GCM.nonceLength),
        ciphertext: sealed.subarray(AES_256_GCM.nonceLength, bodyEnd),
        tag: sealed.subarray(bodyEnd),
      }
    },

    async decrypt(key, sealed, aad) {
      assertKey(key)
      if (sealed.nonce.length !== AES_256_GCM.nonceLength) {
        throw new CryptoParamsError(
          `nonce 必须是 ${AES_256_GCM.nonceLength} 字节，实际为 ${sealed.nonce.length} 字节`,
        )
      }
      if (sealed.tag.length !== AES_256_GCM.tagLength) {
        throw new CryptoParamsError(
          `tag 必须是 ${AES_256_GCM.tagLength} 字节，实际为 ${sealed.tag.length} 字节`,
        )
      }

      try {
        return await bridge.aesGcmDecrypt(key, sealed.nonce, sealed.ciphertext, sealed.tag, aad)
      } catch (error) {
        rethrowNative(error)
      }
    },
  }

  const random: RandomProvider = {
    randomBytes(length: number): Uint8Array {
      if (!Number.isSafeInteger(length) || length < 0) {
        throw new CryptoParamsError(`randomBytes 的长度必须是非负整数，实际为 ${length}`)
      }
      return bridge.randomBytes(length)
    },
  }

  const compress: CompressProvider = {
    name: 'gzip',

    async compress(bytes) {
      try {
        return await bridge.gzip(bytes)
      } catch (error) {
        rethrowNative(error)
      }
    },

    async decompress(bytes) {
      try {
        return await bridge.gunzip(bytes)
      } catch (error) {
        rethrowNative(error)
      }
    },
  }

  const secureStore: SecureStore = {
    async read(name) {
      if (name === '') throw new CryptoParamsError('安全存储的键名不能为空')
      try {
        return await bridge.secureStoreRead(name)
      } catch (error) {
        rethrowNative(error)
      }
    },

    async write(name, value) {
      if (name === '') throw new CryptoParamsError('安全存储的键名不能为空')
      try {
        await bridge.secureStoreWrite(name, value)
      } catch (error) {
        rethrowNative(error)
      }
    },

    async remove(name) {
      if (name === '') throw new CryptoParamsError('安全存储的键名不能为空')
      try {
        await bridge.secureStoreRemove(name)
      } catch (error) {
        rethrowNative(error)
      }
    },
  }

  return { kdf, scrypt, aead, random, compress, secureStore }
}
