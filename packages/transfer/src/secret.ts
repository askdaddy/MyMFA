import { base64Decode, Base64DecodeError } from '@askdaddy/crypto'
import { base32Decode, base32Encode, Base32DecodeError } from '@askdaddy/otp'
import { TransferValueError } from './errors.js'

const STEAM_PREFIX = 'steam://'

/**
 * 导出侧的 base32：`base32Encode` **总是补 `=`**（`packages/otp/src/base32.ts:37-41`），
 * 而 otpauth URI（`docs/transfer.md` §3.2）与 Aegis 的 `info.secret` 都要求**大写无 padding**。
 * 两个生成器共用，去 padding 这件事就只有一处可能写错。
 */
export function encodeBase32Secret(bytes: Uint8Array): string {
  return base32Encode(bytes).replaceAll('=', '')
}

/**
 * ADR-004 已放弃 Steam，`steam://<secret>` 一律拒绝，**绝不用 Steam 字母表
 * `23456789BCDFGHJKMNPQRTVWXY` 尝试解码**（design §要点 4 第四条）。
 *
 * 判在 base32 路径入口而非 Bitwarden 解析器里：`:` 与 `/` 本就不是合法 base32 字符，
 * 交给 `base32Decode` 会报「位置 5 处的字符不合法」，把「不受支持的令牌类型」误报成「文件损坏」。
 */
function assertNotSteam(raw: string): void {
  if (raw.trim().toLowerCase().startsWith(STEAM_PREFIX)) {
    throw new TransferValueError('Steam 令牌不受支持：本 App 只支持 TOTP 与 HOTP')
  }
}

function assertNonEmpty(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 0) {
    throw new TransferValueError('secret 解码后为空')
  }
  return bytes
}

/**
 * Aegis / 2FAS / otpauth URI / Bitwarden 裸 base32 共用这一条路径。
 * padding、大小写、空格、`0`↔`O` 与 `1`↔`I` 混淆字符的容忍度全部由
 * `@askdaddy/otp` 的 `base32Decode` 决定，transfer 不另写一份（C9）。
 */
export function decodeBase32Secret(raw: unknown): Uint8Array {
  if (typeof raw !== 'string') {
    throw new TransferValueError(`secret 必须是字符串，实际收到的类型是 ${typeof raw}`)
  }
  assertNotSteam(raw)

  try {
    return assertNonEmpty(base32Decode(raw))
  } catch (error) {
    if (error instanceof Base32DecodeError) {
      throw new TransferValueError('secret 不是合法的 base32 字符串', { cause: error })
    }
    throw error
  }
}

/** 本 App 明文容器的 `Entry.secret` 走这条路径（`docs/vault-format.md` §2.1）。 */
export function decodeBase64Secret(raw: unknown): Uint8Array {
  if (typeof raw !== 'string') {
    throw new TransferValueError(`secret 必须是字符串，实际收到的类型是 ${typeof raw}`)
  }

  try {
    return assertNonEmpty(base64Decode(raw))
  } catch (error) {
    if (error instanceof Base64DecodeError) {
      throw new TransferValueError('secret 不是合法的 base64 字符串', { cause: error })
    }
    throw error
  }
}

/**
 * FreeOTP+ 专用：上游是 Java `byte[]`，Gson 序列化成有符号 int 数组。
 *
 * 越界值一律失败，**禁止 `& 0xFF` 截断**——截断会静默产出一个「算得出但永远是错的」密钥
 * （`docs/transfer.md` §2.1）。失败消息只写**下标**不写值，避免密钥字节进崩溃上报（C4）。
 */
export function decodeIntArraySecret(raw: unknown): Uint8Array {
  if (!Array.isArray(raw)) {
    throw new TransferValueError(`secret 必须是数组，实际收到的类型是 ${typeof raw}`)
  }
  if (raw.length === 0) {
    throw new TransferValueError('secret 数组为空')
  }

  const bytes = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i += 1) {
    const value: unknown = raw[i]
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < -128 || value > 127) {
      throw new TransferValueError(`secret 数组的第 ${i} 项不是 [-128,127] 范围内的整数`)
    }
    bytes[i] = value < 0 ? value + 256 : value
  }
  return bytes
}
