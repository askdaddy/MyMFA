import type { Argon2idParams } from './params.js'

export interface KdfProvider {
  /**
   * 与 vault 文件头 `crypto.kdf.name` 比对用。
   * 文件声明 argon2id 而运行时注入的是别的实现时，必须拒绝打开而不是静默用错算法派生。
   */
  readonly name: 'argon2id'
  deriveKey(password: Uint8Array, salt: Uint8Array, params: Argon2idParams): Promise<Uint8Array>
}

/** AEAD 输出。`ciphertext` 不含 tag——WebCrypto 把两者拼在一起返回，Provider 负责切开。 */
export interface AeadSealed {
  nonce: Uint8Array
  ciphertext: Uint8Array
  tag: Uint8Array
}

export interface AeadProvider {
  readonly name: 'aes-256-gcm'
  encrypt(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<AeadSealed>
  decrypt(key: Uint8Array, sealed: AeadSealed, aad?: Uint8Array): Promise<Uint8Array>
}

export interface RandomProvider {
  randomBytes(length: number): Uint8Array
}

/**
 * 设备安全存储：iOS Keychain / Android Keystore / `chrome.storage.session`。
 * 只用于存放生物识别包裹的 DEK 与解锁态，**禁止**用它持久化任何可导出内容（AGENTS.md §5.1）。
 */
export interface SecureStore {
  read(key: string): Promise<Uint8Array | null>
  write(key: string, value: Uint8Array): Promise<void>
  remove(key: string): Promise<void>
}

export interface CryptoProviders {
  kdf: KdfProvider
  aead: AeadProvider
  random: RandomProvider
  secureStore: SecureStore
}
