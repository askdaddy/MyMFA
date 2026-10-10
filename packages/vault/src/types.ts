import type { AeadProvider, CompressProvider, KdfProvider, RandomProvider } from '@askdaddy/crypto'

/** 容器格式标识，`docs/vault-format.md` §1.1。 */
export const CONTAINER_FORMAT = 'mfavault'

/**
 * `Entry.algo` 用 otpauth URI 的无连字符拼写（`docs/vault-format.md` §2.1），
 * 而 `@askdaddy/otp` 的 `DigestAlgorithm` 用 WebCrypto 的 `'SHA-1'` 拼写。
 * 两者**刻意不合并**：vault 存的是导入导出格式里的既有拼写，改成 WebCrypto 形式会让
 * 从 Aegis / 2FAS 迁移来的数据全部失配；换算发生在计算验证码的那一层，不在本包。
 */
export type EntryAlgorithm = 'SHA1' | 'SHA256' | 'SHA512'

export const ENTRY_ALGORITHMS: readonly EntryAlgorithm[] = ['SHA1', 'SHA256', 'SHA512']

/** 容器封装版本。与 `schemaVersion` 独立：前者描述封装，后者描述明文结构。 */
export const CONTAINER_VERSION = 1

/** 明文 schema 版本。 */
export const SCHEMA_VERSION = 1

export type EntryKind = 'totp' | 'hotp'

/**
 * `docs/vault-format.md` §2.1 的全部字段。
 *
 * 刻意**不用**可辨识联合把 `period` / `counter` 拆成两个子类型：两者的条件必填性由
 * `guard.ts` 在运行时校验（外部导入的数据没有类型保证），类型层面拆成联合只会让
 * `#5 domain` 的排序与搜索到处做窄化，收益为零。
 */
export interface Entry {
  readonly id: string
  readonly kind: EntryKind
  readonly issuer: string
  readonly account: string
  /** base64 编码的**原始字节**，不是 base32 字符串（`docs/vault-format.md` §2.1）。 */
  readonly secret: string
  readonly algo: EntryAlgorithm
  readonly digits: 6 | 7 | 8
  /** 秒。`kind === 'totp'` 时必填。 */
  readonly period?: number
  /** `kind === 'hotp'` 时必填。 */
  readonly counter?: number
  readonly tagIds: readonly string[]
  readonly note: string
  readonly sites: readonly string[]
  readonly usageCount: number
  readonly lastUsedAt: number | null
  /** fractional index，字典序即显示顺序。生成与重排属 `#5 domain`，本包只校验非空字符串。 */
  readonly position: string
  readonly favorite: boolean
  readonly createdAt: number
  readonly updatedAt: number
}

export interface Tag {
  readonly id: string
  readonly name: string
  readonly color: string
  readonly position: string
}

export interface Settings {
  readonly defaultSort: string
  readonly previewNextCode: boolean
  readonly autoLockSeconds: number
  readonly clockOffsetSeconds: number
  readonly clipboardClearSeconds: number
  readonly searchPinyin: boolean
  readonly requireBiometric: boolean
}

/** `docs/vault-format.md` §2.3 的表格默认值，逐项对应。 */
export const DEFAULT_SETTINGS: Settings = {
  defaultSort: 'manual',
  previewNextCode: true,
  autoLockSeconds: 60,
  clockOffsetSeconds: 0,
  clipboardClearSeconds: 45,
  searchPinyin: true,
  requireBiometric: false,
}

export interface VaultMeta {
  readonly createdAt: number
  readonly updatedAt: number
  readonly appVersion: string
}

export interface VaultData {
  readonly schemaVersion: number
  readonly meta: VaultMeta
  readonly entries: readonly Entry[]
  readonly tags: readonly Tag[]
  readonly settings: Settings
}

export interface KdfHeader {
  readonly name: 'argon2id'
  readonly memoryKiB: number
  readonly iterations: number
  readonly parallelism: number
  readonly salt: string
  readonly keyLength: number
}

export interface CipherHeader {
  readonly name: 'aes-256-gcm'
  readonly nonce: string
  readonly tag: string
}

export interface WrappedKeyHeader {
  readonly nonce: string
  readonly tag: string
  readonly data: string
}

export interface CryptoHeader {
  readonly kdf: KdfHeader
  readonly cipher: CipherHeader
  readonly wrappedMasterKey: WrappedKeyHeader
}

/**
 * 加密容器。`schemaVersion` 在头部**明文可见**（ADR-017）：读取端必须在解密前就能
 * 重建 AAD，并且能在不消耗一次 Argon2id 派生的前提下拒绝来自未来版本的文件。
 *
 * **不含** `biometricWrappedDek`——生物识别包裹的 DEK 只能存于设备安全存储，
 * 绝不进入 vault 文件或任何可导出内容（AGENTS.md §5.1）。类型层面不存在该字段，
 * 而不是校验后丢弃。
 */
export interface EncryptedContainer {
  readonly format: typeof CONTAINER_FORMAT
  readonly version: number
  readonly schemaVersion: number
  readonly encrypted: true
  readonly crypto: CryptoHeader
  readonly data: string
}

/**
 * 刻意比 `CryptoProviders` 窄：`SecureStore` 属各 app 端职责（#6 / M3），
 * vault 不需要它，要求注入只会让核心包无法独立测试。
 */
export interface VaultProviders {
  readonly kdf: KdfProvider
  readonly aead: AeadProvider
  readonly random: RandomProvider
  readonly compress: CompressProvider
}

export interface CreateVaultOptions {
  readonly appVersion: string
  /** 注入以便测试；默认 `Date.now()`。 */
  readonly now?: () => number
}

export interface VaultHandle {
  /** 锁定后访问抛 `VaultLockedError`（`docs/vault-format.md` §1.1，B8）。 */
  readonly data: VaultData
  replaceData(next: VaultData): void
  sessionDek(): Uint8Array
  serialize(): Promise<Uint8Array>
  /**
   * 只重新派生 KEK 并重新包裹 DEK，payload 一概不碰——O(1) 而非 O(n)。
   * 因此**下一次** `serialize()` 的 `data` / `cipher.nonce` / `cipher.tag` 与改密码前不同
   * 属正常行为（写入流程每次都换新 nonce），不是回归（Plan 修订 #2 R2-3）。
   */
  changeMasterPassword(nextPassword: string): Promise<void>
  /** 清零 DEK，幂等。 */
  lock(): void
}
