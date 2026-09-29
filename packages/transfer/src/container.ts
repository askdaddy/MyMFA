import { utf8Encode } from '@askdaddy/crypto'
import {
  assertContainerVersion,
  assertVaultData,
  CONTAINER_FORMAT,
  CONTAINER_VERSION,
  migrateVaultData,
  type VaultData,
} from '@askdaddy/vault'

import { TransferFormatError } from './errors.js'
import { decodeInput, isRecord, parseJson } from './input.js'
import type { PlaintextContainer } from './types.js'

/**
 * 本 App **未加密**容器的封装与解封（`docs/vault-format.md` §1.2）。
 *
 * 全程同步、零 Provider 注入：明文容器的 `data` 是**对象**而非 base64 的 gzip 密文，
 * 因此既不需要 `CompressProvider` 也不需要 `AeadProvider`——那两个只服务加密容器
 * （已由 `packages/vault` + `packages/crypto-web` 实现）。
 *
 * **抛出的错误分两族，刻意不合并**（design §要点 5：明文容器没有密码，不存在 vault 那条
 * 「密码错误与文件损坏不得区分」的防枚举约束，所以两类提示可以分开）：
 *
 * - `TransferFormatError` — 容器外壳坏了：超上限、不是 JSON、顶层不是对象、`format` 不对、
 *   `encrypted` 不是 `false`、头部与明文的 `schemaVersion` 不一致。
 * - `@askdaddy/vault` 的 `VaultVersionError` / `VaultFormatError` / `VaultSchemaError` —
 *   版本与明文 schema 问题。这些**就地透传**而不是包一层：包装会把「请升级 App」与
 *   「文件已损坏」两种处置方式完全不同的提示压成同一族，也会让 `assertContainerVersion`
 *   与 `migrateVaultData` 白写一遍（lazy-ladder rung 2：复用优于重写）。
 */

/**
 * 封装为明文容器字节。
 *
 * 先 `assertVaultData` 再序列化：非法数据必须**抛错而不是产出文件**，否则一个 `digits: 9`
 * 的条目会被写进备份，等到用户换设备导入时才发现——那时已经无法追溯是哪一步写坏的。
 */
export function sealPlaintext(vault: VaultData): Uint8Array {
  const data = assertVaultData(vault)
  const container: PlaintextContainer = {
    format: CONTAINER_FORMAT,
    version: CONTAINER_VERSION,
    // §1.1：头部的 `schemaVersion` 恒等于明文里的值。照抄而不是写死 `SCHEMA_VERSION`，
    // 是为了让这条不变量在传入旧版本数据时依然成立，而不是产出一个头部撒谎的文件。
    schemaVersion: data.schemaVersion,
    encrypted: false,
    data,
  }
  return utf8Encode(JSON.stringify(container))
}

/** 解封顺序是契约（design §要点 5）：字节长度闸门 → UTF-8 解码 → 嵌套深度 → `JSON.parse`。 */
export function openPlaintext(bytes: Uint8Array, what = '明文备份'): VaultData {
  const container = parseJson(decodeInput(bytes, what), what)

  if (!isRecord(container)) {
    throw new TransferFormatError(`${what} 已损坏：顶层不是 JSON 对象`)
  }

  if (container.format !== CONTAINER_FORMAT) {
    throw new TransferFormatError(`这不是本 App 的备份文件：format 不是 "${CONTAINER_FORMAT}"`)
  }

  // 与 `packages/vault` 的 `parseContainer` 互为镜像：vault 拒绝明文容器，这里拒绝加密容器。
  // 两侧都明确拒绝而不是静默按另一种读，否则 AGENTS.md §5.4 的明文风险提示会被绕过。
  if (container.encrypted === true) {
    throw new TransferFormatError(
      `${what} 是**加密**容器，需要主密码才能打开，不能按明文备份读取（加密容器的兼容路径属 #10）`,
    )
  }
  if (container.encrypted !== false) {
    throw new TransferFormatError(
      `${what} 已损坏：encrypted 必须是布尔值 false，实际收到的类型是 ${typeof container.encrypted}`,
    )
  }

  // 版本闸门在读取 `data` 之前：高版本文件不该先被迁移链猜一遍。
  assertContainerVersion(container)

  const data = container.data
  if (typeof data === 'string') {
    // 明文容器的 `data` 是对象；字符串形态只出现在加密容器里（base64 的 gzip 密文）。
    throw new TransferFormatError(`${what} 已损坏：明文容器的 data 必须是对象而不是字符串`)
  }
  if (!isRecord(data)) {
    throw new TransferFormatError(`${what} 已损坏：data 不是 JSON 对象`)
  }

  // §2：头部与明文的 `schemaVersion` 必须相等。不等说明写入端有 bug 或文件被手工编辑过，
  // 此时按哪一处迁移都是猜——与 §1.1 要求解密后校验两者相等是同一条纵深防御。
  if (data.schemaVersion !== container.schemaVersion) {
    throw new TransferFormatError(`${what} 已损坏：头部与明文的 schemaVersion 不一致`)
  }

  // 迁移链内含 `assertVaultData`，故返回值已是校验过的 `VaultData`；`schemaVersion: 0`
  // 的老文件在这里升到当前版本，transfer 不另写迁移。
  return migrateVaultData(data)
}
