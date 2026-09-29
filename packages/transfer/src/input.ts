import { utf8Decode, utf8Encode } from '@askdaddy/crypto'

import { TransferFormatError } from './errors.js'
import type { DetectableInput } from './types.js'

/**
 * 不可信输入的入口闸门（`docs/security.md` §8：长度与嵌套深度上限必须在解析前生效）。
 *
 * 三道闸门的顺序是契约：**字节长度 → UTF-8 解码 → 嵌套深度 → JSON.parse**。
 * 字节长度必须在 `utf8Decode` 之前，否则一个 1 GiB 的文件会先被解成 1 GiB 字符串；
 * 嵌套深度必须在 `JSON.parse` 之前，V8 对超深嵌套抛 RangeError 而 Hermes 的行为未经确认，
 * 自己数一遍括号比依赖各引擎的栈保护更可控。
 */
export const TRANSFER_LIMITS = {
  /** 2FAS 上游的文件上限是 100 MiB；这里取更紧的值，因为解码 + parse 会放大数倍内存占用。 */
  maxInputBytes: 16 * 1024 * 1024,
  /** 自有格式与各第三方格式的实际嵌套都不超过 6 层，64 已是很宽的余量。 */
  maxNestingDepth: 64,
  maxEntries: 10_000,
  /** issuer / account / tag 名 / note 等单个已解码字符串字段的长度上限。 */
  maxFieldLength: 4_096,
  /** 行式格式（otpauth 文本、Ente）的单行长度上限。 */
  maxLineLength: 65_536,
  /** CSV 单元格上限。比行上限宽松：Bitwarden 的单格内可以塞多个逗号分隔的 URI。 */
  maxCsvCellLength: 65_536,
} as const

export function assertInputSize(bytes: Uint8Array, what: string): void {
  if (bytes.length > TRANSFER_LIMITS.maxInputBytes) {
    throw new TransferFormatError(
      `${what} 有 ${bytes.length} 字节，超过上限 ${TRANSFER_LIMITS.maxInputBytes} 字节`,
    )
  }
}

/** 字节长度闸门 + UTF-8 解码。`utf8Decode` 对非法字节序列替换为 U+FFFD 而不抛错。 */
export function decodeInput(bytes: Uint8Array, what: string): string {
  assertInputSize(bytes, what)
  return utf8Decode(bytes)
}

/**
 * 各格式解析器与 `detect` 共用的入口：`DetectableInput` 的两个分支都收敛成文本，
 * 闸门只跑一次（字符串入参也要过——粘贴框里的 20 MiB 文本与 20 MiB 文件同样危险）。
 */
export function readText(input: DetectableInput, what: string): string {
  return decodeInput(typeof input === 'string' ? utf8Encode(input) : input, what)
}

/** JSON 对象判据。数组与 `null` 在 `typeof` 下都是 `'object'`，必须显式排除。 */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function maxNestingDepth(text: string): number {
  let depth = 0
  let max = 0
  let inString = false
  let escaped = false

  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i)

    if (inString) {
      if (escaped) escaped = false
      else if (code === 0x5c) escaped = true
      else if (code === 0x22) inString = false
      continue
    }

    if (code === 0x22) inString = true
    else if (code === 0x7b || code === 0x5b) {
      depth += 1
      if (depth > max) max = depth
      // 提前退出：已经超限就不必数完剩下的几兆字节。
      if (max > TRANSFER_LIMITS.maxNestingDepth) return max
    } else if (code === 0x7d || code === 0x5d) depth -= 1
  }

  return max
}

/**
 * 吞掉 `JSON.parse` 的原始错误：SyntaxError 的 message 会带上出错位置附近的**源码片段**，
 * 而导入文件的片段可能正好含 secret（C4）。
 */
export function parseJson(text: string, what: string): unknown {
  const depth = maxNestingDepth(text)
  if (depth > TRANSFER_LIMITS.maxNestingDepth) {
    throw new TransferFormatError(
      `${what} 的嵌套深度达到 ${depth}，超过上限 ${TRANSFER_LIMITS.maxNestingDepth}，文件可能已损坏`,
    )
  }

  try {
    return JSON.parse(text) as unknown
  } catch {
    throw new TransferFormatError(`${what} 不是合法的 JSON，文件可能已损坏`)
  }
}

export function assertFieldLength(value: string, path: string): void {
  if (value.length > TRANSFER_LIMITS.maxFieldLength) {
    throw new TransferFormatError(
      `${path} 长度为 ${value.length}，超过上限 ${TRANSFER_LIMITS.maxFieldLength}`,
    )
  }
}

export function assertEntryCount(count: number, what: string): void {
  if (count > TRANSFER_LIMITS.maxEntries) {
    throw new TransferFormatError(
      `${what} 含 ${count} 个条目，超过上限 ${TRANSFER_LIMITS.maxEntries}，请分批导入`,
    )
  }
}
