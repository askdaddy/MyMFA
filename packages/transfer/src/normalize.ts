import { assertCounter, assertDigits, OtpConfigError } from '@askdaddy/otp'
import type { EntryAlgorithm, EntryKind } from '@askdaddy/vault'
import { TransferValueError } from './errors.js'

/**
 * `docs/transfer.md` §2.1 的归一化链末端查表。`md5` 刻意留在表里：它不是「支持 MD5」，
 * 而是「把上游已经产出的 MD5 条目降级为 SHA1」，降级事实由 `fromMd5` 交给调用方记 warning。
 */
const ALGORITHM_TABLE: Readonly<Record<string, EntryAlgorithm>> = {
  sha1: 'SHA1',
  sha256: 'SHA256',
  sha512: 'SHA512',
  md5: 'SHA1',
}

const KIND_TABLE: Readonly<Record<string, EntryKind>> = {
  totp: 'totp',
  hotp: 'hotp',
}

/** ADR-004 明确放弃的令牌类型。单独列出是为了给出「本 App 不支持」而非「文件坏了」的提示。 */
const DROPPED_KINDS: ReadonlySet<string> = new Set(['steam', 'motp', 'yandex'])

export interface NormalizedAlgorithm {
  readonly algo: EntryAlgorithm
  /**
   * 原文是 `md5`，值被降级为 `SHA1`。
   *
   * design §要点 3 把该规则限定在 `kind !== 'motp'`，这里不再判一次：mOTP 条目在
   * `normalizeKind` 就已被拒绝，能走到算法归一化的必然不是 motp。
   */
  readonly fromMd5: boolean
}

/**
 * 去空白 → 去连字符 → 去前缀 `Hmac` → 去前缀 `Algorithm.` / `algorithm.` → 小写 → 查表。
 *
 * 顺序是 design §要点 3 冻结的，不可调换：`HmacSHA-256` 先去连字符才能被 `^hmac` 命中。
 * 查不到即抛错，**绝不回落 SHA1**（C8）——回落会让用户拿到一个算得出但永远是错的验证码。
 */
export function normalizeAlgorithm(raw: unknown): NormalizedAlgorithm {
  if (typeof raw !== 'string') {
    throw new TransferValueError(`algorithm 必须是字符串，实际收到的类型是 ${typeof raw}`)
  }

  const key = raw
    .replaceAll(/\s/g, '')
    .replaceAll('-', '')
    .replace(/^hmac/i, '')
    .replace(/^algorithm\./i, '')
    .toLowerCase()

  const algo = ALGORITHM_TABLE[key]
  if (algo === undefined) {
    throw new TransferValueError('无法识别的 algorithm，仅支持 SHA1 / SHA256 / SHA512')
  }
  return { algo, fromMd5: key === 'md5' }
}

export function normalizeKind(raw: unknown): EntryKind {
  if (typeof raw !== 'string') {
    throw new TransferValueError(`令牌类型必须是字符串，实际收到的类型是 ${typeof raw}`)
  }

  const key = raw.trim().toLowerCase()
  const kind = KIND_TABLE[key]
  if (kind !== undefined) {
    return kind
  }
  if (DROPPED_KINDS.has(key)) {
    // 文案取自 `docs/transfer.md` §2.1：「原因写『该令牌类型不受支持』」。回显 key 是安全的：
    // 它已被 DROPPED_KINDS 收敛为三个固定字面量之一。
    throw new TransferValueError(`该令牌类型不受支持："${key}"，本 App 只支持 TOTP 与 HOTP`)
  }
  throw new TransferValueError('无法识别的令牌类型，仅支持 totp / hotp')
}

/**
 * CSV 与部分 JSON 把数字写成字符串（Bitwarden CSV 全是字符串），故接受纯整数文本。
 * 小数、`NaN`、空串一律不放行——交给下游的 `assert*` 判定，本函数只负责类型收敛。
 */
function toInteger(raw: unknown, what: string): number {
  if (typeof raw === 'number') {
    return raw
  }
  if (typeof raw === 'string') {
    const trimmed = raw.trim()
    if (/^[+-]?\d+$/.test(trimmed)) {
      return Number(trimmed)
    }
  }
  throw new TransferValueError(`${what} 必须是整数，实际收到的类型是 ${typeof raw}`)
}

/** 把 `@askdaddy/otp` 的错误就地转译，好让解析器只 catch 一种类型（见 errors.ts 的说明）。 */
function checked(raw: unknown, what: string, assert: (value: number) => void): number {
  const value = toInteger(raw, what)
  try {
    assert(value)
  } catch (error) {
    if (error instanceof OtpConfigError) {
      throw new TransferValueError(error.message, { cause: error })
    }
    throw error
  }
  return value
}

/** 范围判定复用 `@askdaddy/otp`，transfer 不另写一份（lazy-ladder rung 2）。 */
export function normalizeDigits(raw: unknown): number {
  return checked(raw, 'digits', assertDigits)
}

export function normalizeCounter(raw: unknown): number {
  return checked(raw, 'counter', assertCounter)
}

/**
 * `@askdaddy/otp` 没有导出的 period 断言，其内部 `resolvePeriod` 会把 `undefined`
 * 补成 `DEFAULT_PERIOD`——那正是 C8 禁止的静默默认值，故不能复用。
 * 「period 缺失」由解析器直接判失败，不调用本函数。
 */
export function normalizePeriod(raw: unknown): number {
  return checked(raw, 'period', (period) => {
    if (!Number.isSafeInteger(period) || period <= 0) {
      throw new TransferValueError(`period 必须是正整数，实际为 ${period}`)
    }
  })
}
