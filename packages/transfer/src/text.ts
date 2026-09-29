import { TransferValueError } from './errors.js'
import { assertFieldLength } from './input.js'

/**
 * 各 JSON 解析器共用的字符串字段读法：类型收敛 + `maxFieldLength` 闸门一次做完。
 *
 * 错误消息只带**路径**不带值（C4）——`note` / `label` 之类的字段里可能夹着 secret。
 */
export function requiredText(value: unknown, path: string): string {
  if (typeof value !== 'string') {
    throw new TransferValueError(`${path} 必须是字符串，实际收到的类型是 ${typeof value}`)
  }
  assertFieldLength(value, path)
  return value
}

/** 「键缺失」与「值为 null」等价：kotlinx `explicitNulls=false` 与 Gson 都会产出这两种形态。 */
export function optionalText(value: unknown, path: string): string {
  return value === undefined || value === null ? '' : requiredText(value, path)
}

/**
 * 按优先级取第一个非 null 值，全部缺失时给空串。
 *
 * 语义照抄 Kotlin 的 `?:`——只判 null，**不判空串**：`otp.account` 显式为 `""` 时不该被
 * `otp.label` 顶掉（上游 `ServiceMapper.kt` 的 `otp.account ?: otp.label` 同理）。
 */
export function firstText(candidates: readonly (readonly [unknown, string])[]): string {
  for (const [value, path] of candidates) {
    if (value !== undefined && value !== null) return requiredText(value, path)
  }
  return ''
}
