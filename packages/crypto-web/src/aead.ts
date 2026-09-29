import { AeadAuthError, AES_256_GCM, CryptoParamsError } from '@askdaddy/crypto'
import type { AeadProvider, AeadSealed } from '@askdaddy/crypto'

const ALGORITHM = 'AES-GCM'

/**
 * TS 5.7 起 `Uint8Array` 的默认类型参数是 `ArrayBufferLike`，而 WebCrypto 的 `BufferSource`
 * 要求 `ArrayBuffer`，两者在类型层面不兼容。
 *
 * 这里做一次窄化断言而不是拷贝一份：拷贝明文会多出一份没人负责清零的秘密副本
 * （AGENTS.md §5.4）。真有人传进 SharedArrayBuffer 时 WebCrypto 会在运行时拒绝，
 * 不会静默算出错误结果。
 */
function bufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>
}

async function importKey(key: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  if (key.length !== AES_256_GCM.keyLength) {
    throw new CryptoParamsError(
      `AES-256-GCM 密钥必须是 ${AES_256_GCM.keyLength} 字节，实际为 ${key.length} 字节`,
    )
  }
  return crypto.subtle.importKey('raw', bufferSource(key), { name: ALGORITHM }, false, [usage])
}

function gcmParams(iv: Uint8Array, aad: Uint8Array | undefined): AesGcmParams {
  return {
    name: ALGORITHM,
    iv: bufferSource(iv),
    additionalData: aad === undefined ? undefined : bufferSource(aad),
    tagLength: AES_256_GCM.tagLength * 8,
  }
}

export const webAeadProvider: AeadProvider = {
  name: 'aes-256-gcm',

  async encrypt(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<AeadSealed> {
    const cryptoKey = await importKey(key, 'encrypt')

    // nonce 一律内部生成：GCM 在同一密钥下重用 nonce 会直接泄露明文与认证子密钥，
    // 因此接口层面就不给调用方传入的机会。
    const nonce = new Uint8Array(AES_256_GCM.nonceLength)
    crypto.getRandomValues(nonce)

    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(gcmParams(nonce, aad), cryptoKey, bufferSource(plaintext)),
    )

    // WebCrypto 返回 ciphertext || tag，tag 在**尾部**；按同样顺序拼回去才能解密。
    const split = sealed.length - AES_256_GCM.tagLength
    return {
      nonce,
      ciphertext: sealed.subarray(0, split),
      tag: sealed.subarray(split),
    }
  },

  async decrypt(key: Uint8Array, sealed: AeadSealed, aad?: Uint8Array): Promise<Uint8Array> {
    const cryptoKey = await importKey(key, 'decrypt')

    const combined = new Uint8Array(sealed.ciphertext.length + sealed.tag.length)
    combined.set(sealed.ciphertext, 0)
    combined.set(sealed.tag, sealed.ciphertext.length)

    try {
      return new Uint8Array(
        await crypto.subtle.decrypt(gcmParams(sealed.nonce, aad), cryptoKey, combined),
      )
    } catch {
      // 「密钥错误」与「密文被篡改」必须不可区分，否则 vault 解锁流程会留下密码探测旁路。
      // 原始 WebCrypto 错误文本不透传：它可能带上算法内部细节，对调用方没有价值。
      throw new AeadAuthError('AES-256-GCM 认证失败：密钥不正确或数据已被篡改')
    }
  },
}
