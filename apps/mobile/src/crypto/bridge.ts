/**
 * 原生加密能力的 JS 侧契约（#19）。
 *
 * 这一层存在的唯一理由：`apps/mobile/src/crypto` 的适配层必须能在**没有原生环境**时被实例化，
 * 否则 vault 的 185 项语义测试无法在移动端 Provider 栈上复跑（spec A2）。因此这里只放类型，
 * 真实实现（`expo-bridge.ts`）与测试替身（Node 桥）都只是它的一个实现。
 *
 * 参数名与原生方法一一对应。`memoryKiB` 恒等映射到 Argon2Kt 的 `mCostInKibibyte`，
 * 任何一端做 KiB/MiB 换算都会让派生密钥不同（docs/testing.md §3.4）。
 */
export interface NativeCryptoBridge {
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

  /** 返回 `nonce(12) ‖ ciphertext ‖ tag(16)` 的单段字节，切分由适配层完成。 */
  aesGcmEncrypt(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>

  aesGcmDecrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    tag: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array>

  /** 同步：`RandomProvider.randomBytes` 在 `@askdaddy/crypto` 里就是同步方法。 */
  randomBytes(length: number): Uint8Array

  gzip(bytes: Uint8Array): Promise<Uint8Array>
  gunzip(bytes: Uint8Array): Promise<Uint8Array>

  secureStoreRead(name: string): Promise<Uint8Array | null>
  secureStoreWrite(name: string, value: Uint8Array): Promise<void>
  secureStoreRemove(name: string): Promise<void>
}

/** 原生 `CodedException` 暴露到 JS 的码值。改码等于改契约。 */
export const NATIVE_ERROR_CODES = {
  aeadAuth: 'ERR_AEAD_AUTH',
  gzip: 'ERR_GZIP',
  cryptoParam: 'ERR_CRYPTO_PARAM',
  secureStore: 'ERR_SECURE_STORE',
} as const

/**
 * Expo 的 `CodedException` 在 JS 侧就是一个带 `code` 的 `Error`。
 * 不假设 `instanceof` 关系：桥接边界上只信这个结构化字段。
 */
export function nativeErrorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const code = (error as { code?: unknown }).code
  return typeof code === 'string' ? code : undefined
}
