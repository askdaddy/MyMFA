import { base64Decode } from '@askdaddy/crypto'
import { MAX_DIGITS, MIN_DIGITS } from '@askdaddy/otp'

import { VaultSchemaError } from './errors.js'
import { DEFAULT_SETTINGS, ENTRY_ALGORITHMS, type Settings, type VaultData } from './types.js'

/**
 * 守卫**只判定不重建**：校验通过后把入参原样返回（同一引用），未知字段因此得以保留
 * （`docs/vault-format.md` §5.3 的前向兼容规则）。这也是不用 zod 的原因——zod 默认剥除
 * 未知字段（`docs/architecture.md` §4.3）。
 *
 * 唯一的写入是 `settings` 的默认值回填：入参来自 `JSON.parse`，本就归本包所有，
 * 就地补齐比复制一份更能保住「同一引用」这条不变量。
 */

function fail(path: string, reason: string): never {
  // 只报路径与原因，绝不回显字段值：`secret` 一旦进 message 就等于进了崩溃上报（C1）。
  throw new VaultSchemaError(`${path} ${reason}`)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function asRecord(value: unknown, path: string): Record<string, unknown> {
  if (!isRecord(value)) fail(path, '必须是 JSON 对象')
  return value
}

function asArray(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) fail(path, '必须是数组')
  return value
}

function asString(value: unknown, path: string): string {
  if (typeof value !== 'string') fail(path, '必须是字符串')
  return value
}

function asNonEmptyString(value: unknown, path: string): string {
  const text = asString(value, path)
  if (text.length === 0) fail(path, '不能为空字符串')
  return text
}

function asInteger(value: unknown, path: string): number {
  // Number.isSafeInteger 一次性挡掉 NaN / Infinity / 小数 / 超出安全范围的值。
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    fail(path, '必须是整数，NaN / Infinity / 小数都不接受')
  }
  return value
}

function asBoolean(value: unknown, path: string): boolean {
  if (typeof value !== 'boolean') fail(path, '必须是布尔值')
  return value
}

function asStringArray(value: unknown, path: string): void {
  const items = asArray(value, path)
  for (let i = 0; i < items.length; i += 1) asString(items[i], `${path}[${i}]`)
}

/** base64 解码失败与「解码后为空」都算非法；返回 undefined 让调用方决定报错文案。 */
function tryBase64Decode(encoded: string): Uint8Array | undefined {
  try {
    return base64Decode(encoded)
  } catch {
    return undefined
  }
}

function asSecret(value: unknown, path: string): void {
  const encoded = asNonEmptyString(value, path)
  const decoded = tryBase64Decode(encoded)
  // 吞掉底层错误：Base64DecodeError 的 message 带出错位置，那是输入内容的间接泄露。
  if (decoded === undefined) fail(path, '不是合法的 base64')
  if (decoded.length === 0) fail(path, 'base64 解码后为空，密钥必须是正数字节')
}

function asOneOf<T extends string>(value: unknown, path: string, allowed: readonly T[]): void {
  const text = asString(value, path)
  if (!allowed.includes(text as T)) fail(path, `取值必须是 ${allowed.join(' / ')} 之一`)
}

const ENTRY_KINDS = ['totp', 'hotp'] as const

function guardEntry(value: unknown, path: string): void {
  const entry = asRecord(value, path)

  asNonEmptyString(entry.id, `${path}.id`)
  asOneOf(entry.kind, `${path}.kind`, ENTRY_KINDS)
  asString(entry.issuer, `${path}.issuer`)
  asString(entry.account, `${path}.account`)
  asSecret(entry.secret, `${path}.secret`)
  asOneOf(entry.algo, `${path}.algo`, ENTRY_ALGORITHMS)

  const digits = asInteger(entry.digits, `${path}.digits`)
  if (digits < MIN_DIGITS || digits > MAX_DIGITS) {
    fail(`${path}.digits`, `必须是 ${MIN_DIGITS}–${MAX_DIGITS} 的整数`)
  }

  if (entry.kind === 'totp') {
    // 条件必填而不给默认值：period 缺失若静默补 30，导入方写错的 60 秒令牌会永久算错码。
    const period = asInteger(entry.period, `${path}.period`)
    if (period <= 0) fail(`${path}.period`, '必须是正整数秒')
  } else {
    const counter = asInteger(entry.counter, `${path}.counter`)
    if (counter < 0) fail(`${path}.counter`, '必须是非负整数')
  }

  asStringArray(entry.tagIds, `${path}.tagIds`)
  asString(entry.note, `${path}.note`)
  asStringArray(entry.sites, `${path}.sites`)

  const usageCount = asInteger(entry.usageCount, `${path}.usageCount`)
  if (usageCount < 0) fail(`${path}.usageCount`, '必须是非负整数')

  if (entry.lastUsedAt !== null) asInteger(entry.lastUsedAt, `${path}.lastUsedAt`)

  // 只校验非空字符串：能否插值、如何生成新键属 #5 domain（A2）。
  asNonEmptyString(entry.position, `${path}.position`)
  asBoolean(entry.favorite, `${path}.favorite`)
  asInteger(entry.createdAt, `${path}.createdAt`)
  asInteger(entry.updatedAt, `${path}.updatedAt`)
}

function guardTag(value: unknown, path: string): void {
  const tag = asRecord(value, path)

  asNonEmptyString(tag.id, `${path}.id`)
  // 大小写不敏感去重是 #5 的领域逻辑，本包只保证它是非空字符串。
  asNonEmptyString(tag.name, `${path}.name`)
  asNonEmptyString(tag.color, `${path}.color`)
  asNonEmptyString(tag.position, `${path}.position`)
}

const SETTINGS_KIND = {
  defaultSort: 'string',
  previewNextCode: 'boolean',
  autoLockSeconds: 'number',
  clockOffsetSeconds: 'number',
  clipboardClearSeconds: 'number',
  searchPinyin: 'boolean',
  requireBiometric: 'boolean',
} as const satisfies Record<keyof Settings, 'string' | 'boolean' | 'number'>

/**
 * `settings` 宽松、`entries`/`tags` 严格（D4）：偏好项错了大不了回到默认体验，
 * 条目错了会算出错的验证码——后者必须让用户看见。
 */
function guardSettings(value: unknown, path: string): void {
  const settings = asRecord(value, path)

  for (const key of Object.keys(SETTINGS_KIND) as (keyof Settings)[]) {
    const current = settings[key]
    const ok =
      SETTINGS_KIND[key] === 'number'
        ? typeof current === 'number' && Number.isSafeInteger(current)
        : typeof current === SETTINGS_KIND[key]
    if (!ok) settings[key] = DEFAULT_SETTINGS[key]
  }
}

/**
 * 校验解密（并迁移）后的明文。返回的就是入参本身，调用方可以据此断言未发生重建。
 */
export function assertVaultData(value: unknown): VaultData {
  const data = asRecord(value, 'vault')

  const schemaVersion = asInteger(data.schemaVersion, 'schemaVersion')
  if (schemaVersion < 0) fail('schemaVersion', '必须是非负整数')

  const meta = asRecord(data.meta, 'meta')
  asInteger(meta.createdAt, 'meta.createdAt')
  asInteger(meta.updatedAt, 'meta.updatedAt')
  asNonEmptyString(meta.appVersion, 'meta.appVersion')

  // 空数组合法：新建 vault 就没有条目。
  const entries = asArray(data.entries, 'entries')
  for (let i = 0; i < entries.length; i += 1) guardEntry(entries[i], `entries[${i}]`)

  const tags = asArray(data.tags, 'tags')
  for (let i = 0; i < tags.length; i += 1) guardTag(tags[i], `tags[${i}]`)

  guardSettings(data.settings, 'settings')

  return data as unknown as VaultData
}
