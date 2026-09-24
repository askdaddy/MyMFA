export class CryptoError extends Error {
  override name = 'CryptoError'
}

export class CryptoParamsError extends CryptoError {
  override name = 'CryptoParamsError'
}

/**
 * AEAD 认证失败。调用方**不得**据此区分「密码错误」与「文件损坏」——
 * vault 层必须把两者映射成同一条用户提示，否则会留下密码探测旁路（docs/vault-format.md §5）。
 */
export class AeadAuthError extends CryptoError {
  override name = 'AeadAuthError'
}

export class Base64DecodeError extends CryptoError {
  override name = 'Base64DecodeError'
}
