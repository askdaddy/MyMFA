import { NativeModule, requireNativeModule } from 'expo'

/**
 * 原生模块的 JS 声明。二进制参数/返回值一律用 `Uint8Array`：Expo 在桥上把它们映射成
 * `ByteArray`，全程不经过字符串（AGENTS.md §5.4：秘密不能落在不可清零的不可变值里）。
 */
declare class MymfaNativeModule extends NativeModule<Record<string, never>> {
  moduleVersion(): string

  argon2id(
    password: Uint8Array,
    salt: Uint8Array,
    memoryKiB: number,
    iterations: number,
    parallelism: number,
    keyLength: number,
    version: number,
  ): Promise<Uint8Array>

  scrypt(
    password: Uint8Array,
    salt: Uint8Array,
    costFactor: number,
    blockSize: number,
    parallelism: number,
    keyLength: number,
  ): Promise<Uint8Array>

  /** 返回 `nonce(12) ‖ ciphertext ‖ tag(16)`。 */
  aesGcmEncrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array | null): Promise<Uint8Array>

  aesGcmDecrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    tag: Uint8Array,
    aad: Uint8Array | null,
  ): Promise<Uint8Array>

  randomBytes(length: number): Uint8Array

  gzip(bytes: Uint8Array): Promise<Uint8Array>
  gunzip(bytes: Uint8Array): Promise<Uint8Array>

  secureStoreRead(name: string): Promise<Uint8Array | null>
  secureStoreWrite(name: string, value: Uint8Array): Promise<void>
  secureStoreRemove(name: string): Promise<void>
}

export default requireNativeModule<MymfaNativeModule>('MymfaNative')
