import { VaultFormatError, VaultSchemaError, VaultVersionError } from './errors.js'
import { assertVaultData } from './guard.js'
import { CONTAINER_VERSION, DEFAULT_SETTINGS, SCHEMA_VERSION, type VaultData } from './types.js'

/**
 * 版本策略与迁移链。两件事放在一个模块里，因为它们是同一条读取流程的两端：
 * 容器头部的版本闸门（解密前，§1.1 步骤 4）与明文 schema 的迁移入口（解密后，步骤 9）。
 */

export type MigrationFn = (data: Record<string, unknown>) => Record<string, unknown>

/**
 * v0 → v1：v1 引入了随 vault 一起加密的 `settings`（v0 时代偏好项硬编码在各端）。
 *
 * v0 是**人工构造**的历史版本——本 App 第一个真实发布的 schema 就是 v1。保留它是为了让
 * 迁移链有可测的输入：等真的要加 v2 时，链路机制已经被证明可用，而不是第一次被用到。
 */
function migrate_0_to_1(data: Record<string, unknown>): Record<string, unknown> {
  return {
    ...data,
    schemaVersion: 1,
    // 不覆盖已存在的 settings：迁移不得静默丢弃数据（docs/vault-format.md §5）。
    settings: data.settings ?? { ...DEFAULT_SETTINGS },
  }
}

/**
 * **按位置索引**：`MIGRATIONS[i]` 把 `schemaVersion` 从 `i` 升到 `i + 1`。
 *
 * 用数组而不是 `{ from, to }` 的映射表，是为了让「跳版本」在结构上不可能——
 * 映射表可以写出 `{ from: 0, to: 3 }`，而数组的第 0 项只能是 0 → 1。
 * 不变量 `MIGRATIONS.length === SCHEMA_VERSION` 由测试守住。
 */
export const MIGRATIONS: readonly MigrationFn[] = [migrate_0_to_1]

/**
 * 容器头部的版本闸门（`docs/vault-format.md` §1.1 步骤 4）。
 *
 * 必须在派生 KEK **之前**调用：高版本文件的解密尝试没有意义，还会白白消耗一次
 * Argon2id 派生（低端 Android 上 1–2 秒）。
 */
export function assertContainerVersion(container: Record<string, unknown>): void {
  const limits = { version: CONTAINER_VERSION, schemaVersion: SCHEMA_VERSION } as const

  for (const field of Object.keys(limits) as (keyof typeof limits)[]) {
    const value = container[field]
    if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
      throw new VaultFormatError(`容器头部 ${field} 必须是整数，文件可能已损坏`)
    }
    if (value > limits[field]) {
      throw new VaultVersionError(
        `密钥库文件的 ${field}=${value} 高于本 App 支持的 ${limits[field]}，请升级 App 后再打开`,
      )
    }
  }
}

/**
 * 把任意受支持版本的明文迁移到 `SCHEMA_VERSION`，随后交给守卫校验
 * （§4「迁移后必须通过 schema 校验才允许写回」）。
 *
 * @param trace 可选的调用记录。用出参而不是模块级变量，是因为 C8 禁止生产代码持有
 *   任何模块级可变状态；不传就是零开销。
 */
export function migrateVaultData(value: unknown, trace?: string[]): VaultData {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VaultSchemaError('明文必须是 JSON 对象')
  }

  const version = (value as Record<string, unknown>).schemaVersion
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 0) {
    throw new VaultSchemaError('schemaVersion 必须是非负整数，否则无法决定迁移路径')
  }
  if (version > SCHEMA_VERSION) {
    throw new VaultVersionError(
      `密钥库的 schemaVersion=${version} 高于本 App 支持的 ${SCHEMA_VERSION}，请升级 App 后再打开`,
    )
  }

  let current = value as Record<string, unknown>
  for (let from = version; from < SCHEMA_VERSION; from += 1) {
    const migration = MIGRATIONS[from]
    if (migration === undefined) {
      throw new VaultVersionError(`缺少 schemaVersion ${from} → ${from + 1} 的迁移函数`)
    }

    trace?.push(migration.name)
    current = migration(current)

    if (current.schemaVersion !== from + 1) {
      throw new VaultSchemaError(
        `迁移函数 ${migration.name} 必须把 schemaVersion 从 ${from} 升到 ${from + 1}，` +
          `实际为 ${String(current.schemaVersion)}`,
      )
    }
  }

  return assertVaultData(current)
}
