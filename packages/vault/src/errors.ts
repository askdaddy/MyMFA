export class VaultFormatError extends Error {
  override name = 'VaultFormatError'
}

/**
 * 主密码错误与文件损坏**必须**不可区分，否则解锁流程会留下密码探测旁路
 * （docs/vault-format.md §5.1）。因此 message 是常量，构造函数不接受任何入参——
 * 一旦允许调用方传入变体，三端就会各自写出不同的提示，攻击者可据此区分失败原因。
 */
export class VaultAuthError extends Error {
  override name = 'VaultAuthError'

  constructor() {
    super('密钥库文件已损坏，或主密码不正确')
  }
}

/**
 * schema 校验失败。发生在**成功解密之后**，此时"密码对不对"已不是秘密，
 * 因此可以给出字段级诊断；message 必须带字段路径（如 `entries[3].secret`），
 * 且**绝不回显** `secret` 的值、其 base64 或 hex 形式。
 */
export class VaultSchemaError extends Error {
  override name = 'VaultSchemaError'
}

/** 容器 `version` 或 `schemaVersion` 高于当前支持值（docs/vault-format.md §4）。 */
export class VaultVersionError extends Error {
  override name = 'VaultVersionError'
}

/** 句柄已 `lock()`，DEK 已清零，任何成员访问都必须失败而不是返回陈旧数据。 */
export class VaultLockedError extends Error {
  override name = 'VaultLockedError'
}
