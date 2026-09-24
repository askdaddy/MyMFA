/**
 * 三端唯一都原生支持的摘要原语是 WebCrypto 的 HMAC，它是异步的；
 * 因此这里统一用异步接口，而不是为了同步而引入 WASM（AGENTS.md §5.2）。
 */
export type DigestAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512'

export interface HmacProvider {
  hmac(algorithm: DigestAlgorithm, key: Uint8Array, message: Uint8Array): Promise<Uint8Array>
}

export const DIGEST_ALGORITHMS: readonly DigestAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-512']

export const DEFAULT_ALGORITHM: DigestAlgorithm = 'SHA-1'

export const HMAC_OUTPUT_LENGTH: Record<DigestAlgorithm, number> = {
  'SHA-1': 20,
  'SHA-256': 32,
  'SHA-512': 64,
}
