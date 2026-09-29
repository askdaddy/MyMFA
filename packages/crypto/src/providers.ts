import type { Argon2idParams } from './params.js'
import type { Pbkdf2Params, ScryptParams } from './compat-params.js'

export interface ScryptProvider {
  readonly name: 'scrypt'
  deriveKey(password: Uint8Array, salt: Uint8Array, params: ScryptParams): Promise<Uint8Array>
}

export interface Pbkdf2Provider {
  readonly name: 'pbkdf2'
  deriveKey(password: Uint8Array, salt: Uint8Array, params: Pbkdf2Params): Promise<Uint8Array>
}

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
 * gzip 压缩。**不是加密原语**，放在这里只是因为它同样需要平台注入：
 * Web 用 `CompressionStream`，Hermes 不提供该 API，移动端必须走原生模块。
 *
 * 跨端一致性要求弱于 KDF / AEAD：只要求任何一端能解开其他端产出的 gzip 流，
 * **不要求**压缩输出字节级一致（压缩级别、OS 字节、mtime 均允许实现差异）。
 */
export interface CompressProvider {
  readonly name: 'gzip'
  compress(bytes: Uint8Array): Promise<Uint8Array>
  decompress(bytes: Uint8Array): Promise<Uint8Array>
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
  compress: CompressProvider
  secureStore: SecureStore
}
