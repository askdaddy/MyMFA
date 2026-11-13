package expo.modules.mymfanative

import expo.modules.kotlin.exception.CodedException

/**
 * 错误码是 JS 侧把原生失败映射回 `@askdaddy/crypto` 错误类型的唯一依据，
 * 因此必须稳定：改码等于改契约。
 *
 * 消息里不得出现任何口令、密钥或明文片段（AGENTS.md §5.1）。
 */
internal class AeadAuthException :
  CodedException("ERR_AEAD_AUTH", "AES-256-GCM 认证失败：密钥不正确或数据已被篡改", null)

internal class GzipException(message: String, cause: Throwable?) :
  CodedException("ERR_GZIP", message, cause)

internal class CryptoParamException(message: String) :
  CodedException("ERR_CRYPTO_PARAM", message, null)

internal class SecureStoreException(message: String, cause: Throwable? = null) :
  CodedException("ERR_SECURE_STORE", message, cause)
