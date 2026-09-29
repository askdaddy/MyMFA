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

/**
 * gzip 解压失败。与 `AeadAuthError` 一样，调用方**不得**据此提示「压缩格式错误」——
 * 能走到解压这一步说明密码已经是对的，单独提示等于泄露该事实（docs/vault-format.md §5.1）。
 */
export class CompressError extends CryptoError {
  override name = 'CompressError'
}
