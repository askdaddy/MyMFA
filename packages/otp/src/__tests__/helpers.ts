import { createHmac } from 'node:crypto'

import type { DigestAlgorithm, HmacProvider } from '../hmac.js'

const NODE_ALGORITHM: Record<DigestAlgorithm, string> = {
  'SHA-1': 'sha1',
  'SHA-256': 'sha256',
  'SHA-512': 'sha512',
}

/** 测试专用的参考实现，用来校验我们自己的算法；发布产物不包含它。 */
export const nodeHmac: HmacProvider = {
  async hmac(algorithm, key, message) {
    const digest = createHmac(NODE_ALGORITHM[algorithm], Buffer.from(key))
      .update(Buffer.from(message))
      .digest()
    return new Uint8Array(digest)
  },
}

export function asciiSecret(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, 'ascii'))
}

/** RFC 6238 附录 B 对三种算法使用**不同长度**的 secret，混用会得到错误的期望值。 */
export const RFC_6238_SECRETS = {
  'SHA-1': asciiSecret('12345678901234567890'),
  'SHA-256': asciiSecret('12345678901234567890123456789012'),
  'SHA-512': asciiSecret('1234567890123456789012345678901234567890123456789012345678901234'),
} as const satisfies Record<DigestAlgorithm, Uint8Array>
