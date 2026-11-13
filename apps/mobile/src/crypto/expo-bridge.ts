import type { NativeCryptoBridge } from './bridge'
import MymfaNativeModule from '../../modules/mymfa-native/src/MymfaNativeModule'

/**
 * 真实的 Expo 原生桥。**这是 `apps/mobile/src/crypto` 里唯一 import 平台能力的文件**：
 * 适配层（`providers.ts`）因此能在 Node 里被实例化，QA 才能把同一份 Provider 栈注入 vault
 * 的 185 项语义测试（spec A2）。
 *
 * 二进制全程走 `Uint8Array` ↔ `ByteArray`，不经 base64 或字符串：字符串不可变、无法清零，
 * 把主密码或 DEK 编码进去会留下没人能擦的副本（AGENTS.md §5.4）。
 */
export const expoNativeBridge: NativeCryptoBridge = {
  argon2id: (password, salt, memoryKiB, iterations, parallelism, keyLength, version) =>
    MymfaNativeModule.argon2id(
      password,
      salt,
      memoryKiB,
      iterations,
      parallelism,
      keyLength,
      version,
    ),

  scrypt: (password, salt, costFactor, blockSize, parallelism, keyLength) =>
    MymfaNativeModule.scrypt(password, salt, costFactor, blockSize, parallelism, keyLength),

  aesGcmEncrypt: (key, plaintext, aad) =>
    aad === undefined
      ? MymfaNativeModule.aesGcmEncrypt(key, plaintext, null)
      : MymfaNativeModule.aesGcmEncrypt(key, plaintext, aad),

  aesGcmDecrypt: (key, nonce, ciphertext, tag, aad) =>
    aad === undefined
      ? MymfaNativeModule.aesGcmDecrypt(key, nonce, ciphertext, tag, null)
      : MymfaNativeModule.aesGcmDecrypt(key, nonce, ciphertext, tag, aad),

  randomBytes: (length) => MymfaNativeModule.randomBytes(length),

  gzip: (bytes) => MymfaNativeModule.gzip(bytes),
  gunzip: (bytes) => MymfaNativeModule.gunzip(bytes),

  secureStoreRead: (name) => MymfaNativeModule.secureStoreRead(name),
  secureStoreWrite: (name, value) => MymfaNativeModule.secureStoreWrite(name, value),
  secureStoreRemove: (name) => MymfaNativeModule.secureStoreRemove(name),
}
