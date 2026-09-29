export class TransferError extends Error {
  override name = 'TransferError'
}

export class TransferAuthError extends TransferError {
  override name = 'TransferAuthError'
  constructor() {
    super('无法打开加密备份：密码不正确或文件已损坏')
  }
}

/**
 * **整包不可用**：长度超限、JSON 解析失败、格式特征缺失、版本过高。
 *
 * 与 `ParseFailure` 的分工是 C5「部分成功优于全量失败」的类型化表达：
 * 一条都导不出来时才抛异常，单条目的问题一律收进 `ImportResult.failures` 继续走。
 *
 * message 遵守 C4：只写路径与原因，**绝不回显** `secret` 的值或其 base32 / base64 / hex 形式
 * （`docs/vault-format.md` §5.2）。错误消息会进崩溃上报，回显即泄露。
 */
export class TransferFormatError extends TransferError {
  override name = 'TransferFormatError'
}

/**
 * **单条目不可用**：字段类型错位、取值越界、`algorithm` / 令牌类型无法识别。
 *
 * 与 `TransferFormatError` 互斥：后者要求整包中止，本类型由解析器捕获后转成 `ParseFailure`
 * 并继续处理其余条目（C5）。解析器因此只需 `catch` 一处 `TransferError`——`@askdaddy/otp`
 * 抛出的 `OtpConfigError` 已在 `normalize.ts` 就地转译，不会漏到解析器外面。
 *
 * message 同样遵守 C4：只写「哪个字段、期望什么」，**不回显收到的原值**。畸形文件可能把
 * `secret` 放错字段，回显原值等于把密钥写进崩溃上报。定位靠 `ParseFailure.path`。
 */
export class TransferValueError extends TransferError {
  override name = 'TransferValueError'
}
