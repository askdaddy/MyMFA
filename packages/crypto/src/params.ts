import { CryptoParamsError } from './errors.js'

export interface Argon2idParams {
  /**
   * 内存开销，单位**统一为 KiB**。
   * 这是跨端不一致的头号来源：同一份文档里写 64 被一端理解成 64 MiB、另一端理解成 64 KiB，
   * 两边都能跑出结果，但派生密钥完全不同。禁止在任何一端使用 MiB 为单位的字段名。
   */
  readonly memoryKiB: number
  readonly iterations: number
  readonly parallelism: number
  readonly saltLength: number
  readonly keyLength: number
}

/**
 * Argon2id 基线参数（AGENTS.md §5.1）。
 * 只能上调，下调必须先在 docs/decisions.md 立 ADR。
 */
export const ARGON2ID_PARAMS = {
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 4,
  saltLength: 16,
  keyLength: 32,
} as const satisfies Argon2idParams

/** Argon2 版本 1.3，即 RFC 9106 的 0x13。三端必须显式传同一个值，不能依赖各自库的默认值。 */
export const ARGON2ID_VERSION = 0x13

export const AES_256_GCM = {
  keyLength: 32,
  nonceLength: 12,
  tagLength: 16,
} as const

/**
 * 结构性校验：只判断参数本身是否合法，**不**与生产基线比较。
 *
 * 基线检查放在 vault 层而不是这里，因为 Provider 必须能跑 RFC 9106 的官方向量
 * （m=32KiB，远低于生产值）来证明实现正确；把策略塞进原语会让这个验证无法进行。
 * 写入与读取 vault 时由 vault 调用 `assertNotWeakerThanBaseline` 拦截降级。
 */
export function assertArgon2idParams(params: Argon2idParams): void {
  for (const field of ['memoryKiB', 'iterations', 'parallelism', 'keyLength'] as const) {
    const value = params[field]
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new CryptoParamsError(`Argon2id 参数 ${field} 必须是正整数，实际为 ${value}`)
    }
  }

  if (params.memoryKiB < 8 * params.parallelism) {
    throw new CryptoParamsError(
      `Argon2id 要求 memoryKiB >= 8 * parallelism，实际为 ${params.memoryKiB} < ${8 * params.parallelism}`,
    )
  }
}

/**
 * §5.1 红线「Argon2id 参数只能上调不能下调」的运行时执行点。
 *
 * 读取既有 vault 时同样必须调用：攻击者把文件头里的 memoryKiB 改小是一次降级攻击，
 * 会让离线爆破成本骤降。saltLength 不参与比较，它只影响新文件的生成。
 */
export function assertNotWeakerThanBaseline(
  params: Argon2idParams,
  baseline: Argon2idParams = ARGON2ID_PARAMS,
): void {
  for (const field of ['memoryKiB', 'iterations', 'parallelism'] as const) {
    if (params[field] < baseline[field]) {
      throw new CryptoParamsError(
        `Argon2id 参数 ${field}=${params[field]} 低于基线 ${baseline[field]}，` +
          '红线禁止下调；确需调整必须先在 docs/decisions.md 立 ADR',
      )
    }
  }
}
