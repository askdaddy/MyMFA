import { base64Decode, base64Encode, utf8Decode, utf8Encode } from '@askdaddy/crypto'
import { assertVaultData, type VaultData } from '@askdaddy/vault'

import { TransferFormatError, TransferValueError } from './errors.js'
import { int32, readFields, writeFields } from './ga-wire.js'
import { assertEntryCount, assertFieldLength, readText, TRANSFER_LIMITS } from './input.js'
import { decodeBase64Secret } from './secret.js'
import type { DetectableInput, ImportResult, ParsedEntry, ParseWarning } from './types.js'

export const GA_MIGRATION_LIMITS = {
  maxBatches: 1_000,
  defaultEntriesPerBatch: 10,
} as const

const VERIFICATION_WARNING = '未经 Google Authenticator 真机扫描验证'

export interface GaMigrationShard extends ImportResult {
  readonly version: number
  readonly batchSize: number
  readonly batchIndex: number
  readonly batchId: number
}

export interface GaMigrationBatchResult extends Omit<GaMigrationShard, 'batchIndex'> {
  readonly complete: boolean
  readonly missingIndices: readonly number[]
  readonly duplicateCount: number
}

export interface GaMigrationExportOptions {
  /** 由调用方的随机源生成，本包不引入平台随机数。 */
  readonly batchId: number
  readonly entriesPerBatch?: number
}

export interface GaMigrationExport {
  readonly uris: readonly string[]
  readonly verification: 'unverified'
  readonly warning: string
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index])
}

function clearEntries(result: ImportResult): void {
  for (const entry of result.entries) entry.secret.fill(0)
}

function uriPayload(text: string): Uint8Array {
  if (text.length > TRANSFER_LIMITS.maxLineLength) {
    throw new TransferFormatError('GA URI 超过长度上限')
  }
  const matched = /^otpauth-migration:\/\/offline\/?\?([^#]*)(?:#.*)?$/i.exec(text.trim())
  if (matched === null) throw new TransferFormatError('GA URI scheme、主机或路径非法')
  let data: string | undefined
  try {
    for (const pair of matched[1]!.split('&')) {
      const separator = pair.indexOf('=')
      const key = decodeURIComponent(separator === -1 ? pair : pair.slice(0, separator))
      if (key === 'data') {
        if (data !== undefined) throw new TransferFormatError('GA URI 重复 data 参数')
        // URI payload 是 base64；raw '+' 是数据而非表单空格。
        data = decodeURIComponent(separator === -1 ? '' : pair.slice(separator + 1))
      }
    }
    if (data === undefined || data === '') throw new TransferFormatError('GA URI 缺少 data')
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(data) || data.length % 4 === 1) {
      throw new TransferFormatError('GA data 不是合法 base64')
    }
    const bytes = base64Decode(data)
    if (
      (data.includes('=') && data.length % 4 !== 0) ||
      base64Encode(bytes).replace(/=+$/, '') !== data.replace(/=+$/, '')
    ) {
      bytes.fill(0)
      throw new TransferFormatError('GA data 不是合法 base64')
    }
    return bytes
  } catch {
    throw new TransferFormatError('GA URI 的 data 参数或编码非法')
  }
}

function checkedText(bytes: Uint8Array): string {
  const text = utf8Decode(bytes)
  const encoded = utf8Encode(text)
  const valid = sameBytes(encoded, bytes)
  encoded.fill(0)
  if (!valid) throw new TransferValueError('GA 文本字段不是合法 UTF-8')
  if (text.length > TRANSFER_LIMITS.maxFieldLength) {
    throw new TransferValueError('GA 文本字段超过长度上限')
  }
  return text
}

function parseEntry(
  bytes: Uint8Array,
  sourceIndex: number,
): {
  entry: ParsedEntry
  warnings: ParseWarning[]
} {
  const fields = new Map<number, bigint | Uint8Array>()
  for (const field of readFields(bytes)) {
    if (field.number > 7) continue
    const expected = field.number <= 3 ? 2 : 0
    if (field.wire !== expected) throw new TransferFormatError('GA 条目字段 wire 类型错误')
    fields.set(field.number, field.value)
  }
  const secret = fields.get(1)
  if (!(secret instanceof Uint8Array) || secret.length === 0) {
    throw new TransferValueError('GA secret 缺失或为空')
  }
  const name = fields.get(2)
  const issuer = fields.get(3)
  const accountText = name instanceof Uint8Array ? checkedText(name) : ''
  const issuerText = issuer instanceof Uint8Array ? checkedText(issuer) : ''
  const algorithm = fields.get(4)
  const digitCount = fields.get(5)
  const kind = fields.get(6)
  if (algorithm !== 1n && algorithm !== 2n && algorithm !== 3n && algorithm !== 4n) {
    throw new TransferValueError('GA algorithm 未指定或不受支持')
  }
  if (digitCount !== 1n && digitCount !== 2n) {
    throw new TransferValueError('GA digits 未指定或不受支持')
  }
  if (kind !== 1n && kind !== 2n) throw new TransferValueError('GA 令牌类型未指定或不受支持')
  const counter = fields.get(7) ?? 0n
  if (kind === 1n && (typeof counter !== 'bigint' || counter > BigInt(Number.MAX_SAFE_INTEGER))) {
    throw new TransferValueError('GA counter 必须是非负安全整数')
  }
  const warnings: ParseWarning[] = []
  function warn(field: string, message: string): void {
    warnings.push({ sourceIndex, field, message })
  }
  if (algorithm === 4n) warn('algorithm', '原文是 MD5，已归一化为 SHA1')
  if (kind === 2n) warn('period', 'GA 格式没有 period 字段，按来源格式恢复为 30 秒')
  if (kind === 1n && !fields.has(7)) warn('counter', 'GA counter 未编码，采用 proto3 的 0 值')
  const base = {
    secret: secret.slice(),
    issuer: issuerText,
    account: accountText,
    algo:
      algorithm === 2n
        ? ('SHA256' as const)
        : algorithm === 3n
          ? ('SHA512' as const)
          : ('SHA1' as const),
    digits: digitCount === 1n ? (6 as const) : (8 as const),
    note: '',
    tagNames: [],
    favorite: false,
    sourceIndex,
  }
  return {
    entry:
      kind === 2n
        ? { ...base, kind: 'totp', period: 30 }
        : { ...base, kind: 'hotp', counter: Number(counter) },
    warnings,
  }
}

function readShard(text: string): { result: GaMigrationShard; bytes: Uint8Array } {
  const bytes = uriPayload(text)
  const records: Uint8Array[] = []
  const metadata = new Map<number, number>()
  const entries: ParsedEntry[] = []
  try {
    for (const field of readFields(bytes)) {
      if (field.number === 1) {
        if (field.wire !== 2 || !(field.value instanceof Uint8Array)) {
          throw new TransferFormatError('GA payload 条目 wire 类型错误')
        }
        assertEntryCount(records.length + 1, 'GA 分片')
        records.push(field.value)
      } else if (field.number >= 2 && field.number <= 5) {
        if (field.wire !== 0 || typeof field.value !== 'bigint') {
          throw new TransferFormatError('GA 批次字段 wire 类型错误')
        }
        metadata.set(field.number, int32(field.value))
      }
    }
    const version = metadata.get(2) ?? 0
    const batchSize = metadata.get(3) ?? 0
    const batchIndex = metadata.get(4) ?? 0
    const batchId = metadata.get(5) ?? 0
    if (version !== 1) throw new TransferFormatError('GA 迁移版本不受支持，仅支持 1')
    if (batchSize < 1 || batchSize > GA_MIGRATION_LIMITS.maxBatches) {
      throw new TransferFormatError('GA batch_size 超出范围')
    }
    if (batchIndex < 0 || batchIndex >= batchSize)
      throw new TransferFormatError('GA batch_index 超出范围')
    const failures: ImportResult['failures'][number][] = []
    const warnings: ParseWarning[] = []
    for (let index = 0; index < records.length; index += 1) {
      try {
        const parsed = parseEntry(records[index]!, index)
        entries.push(parsed.entry)
        warnings.push(...parsed.warnings)
      } catch (error) {
        if (!(error instanceof TransferValueError)) throw error
        failures.push({ sourceIndex: index, path: `GA 条目 ${index}`, reason: error.message })
      }
    }
    return {
      bytes,
      result: {
        format: 'ga-migration',
        version,
        batchSize,
        batchIndex,
        batchId,
        entries,
        failures,
        warnings,
        tags: [],
        skipped: 0,
      },
    }
  } catch (error) {
    bytes.fill(0)
    for (const entry of entries) entry.secret.fill(0)
    throw error
  }
}

export function parseGaMigration(input: DetectableInput): GaMigrationShard {
  const shard = readShard(readText(input, 'GA 迁移'))
  try {
    return shard.result
  } finally {
    shard.bytes.fill(0)
  }
}

export function parseGaMigrationBatch(inputs: readonly DetectableInput[]): GaMigrationBatchResult {
  if (inputs.length === 0) throw new TransferFormatError('GA 分片输入为空')
  assertEntryCount(inputs.length, 'GA 输入分片')
  // 先检查全部输入的累计量，再解码第一个 payload；重复分片也消耗资源。
  let totalBytes = 0
  const texts: string[] = []
  for (const input of inputs) {
    const text = readText(input, 'GA 分片')
    const encoded = utf8Encode(text)
    totalBytes += encoded.length
    encoded.fill(0)
    if (totalBytes > TRANSFER_LIMITS.maxInputBytes)
      throw new TransferFormatError('GA 分片累计大小超过上限')
    if (text.length > TRANSFER_LIMITS.maxLineLength)
      throw new TransferFormatError('GA URI 超过长度上限')
    texts.push(text)
  }
  const shards: ReturnType<typeof readShard>[] = []
  const unique = new Map<number, ReturnType<typeof readShard>>()
  let success = false
  try {
    let duplicateCount = 0
    let count = 0
    for (const text of texts) {
      const shard = readShard(text)
      shards.push(shard)
      const first = shards[0]!.result
      const result = shard.result
      if (
        result.batchId !== first.batchId ||
        result.version !== first.version ||
        result.batchSize !== first.batchSize
      ) {
        throw new TransferFormatError('GA 分片不属于同一批次')
      }
      const previous = unique.get(result.batchIndex)
      if (previous !== undefined) {
        if (!sameBytes(previous.bytes, shard.bytes))
          throw new TransferFormatError('GA 同索引分片内容冲突')
        duplicateCount += 1
        clearEntries(result)
      } else {
        count += result.entries.length + result.failures.length
        assertEntryCount(count, 'GA 批次')
        unique.set(result.batchIndex, shard)
      }
    }
    const first = shards[0]!.result
    const missingIndices: number[] = []
    for (let index = 0; index < first.batchSize; index += 1) {
      if (!unique.has(index)) missingIndices.push(index)
    }
    const entries: ParsedEntry[] = []
    const failures: ImportResult['failures'][number][] = []
    const warnings: ParseWarning[] = []
    let offset = 0
    for (const [, shard] of [...unique].sort(([left], [right]) => left - right)) {
      const result = shard.result
      entries.push(
        ...result.entries.map((entry) => ({ ...entry, sourceIndex: entry.sourceIndex + offset })),
      )
      failures.push(
        ...result.failures.map((failure) => ({
          ...failure,
          sourceIndex: failure.sourceIndex + offset,
          path: `GA 分片 ${result.batchIndex} / ${failure.path}`,
        })),
      )
      warnings.push(
        ...result.warnings.map((warning) => ({
          ...warning,
          sourceIndex: warning.sourceIndex === null ? null : warning.sourceIndex + offset,
        })),
      )
      offset += result.entries.length + result.failures.length
    }
    success = true
    return {
      format: 'ga-migration',
      version: first.version,
      batchSize: first.batchSize,
      batchId: first.batchId,
      complete: missingIndices.length === 0,
      missingIndices,
      duplicateCount,
      entries,
      failures,
      warnings,
      tags: [],
      skipped: 0,
    }
  } finally {
    for (const shard of shards) {
      shard.bytes.fill(0)
      if (!success) clearEntries(shard.result)
    }
  }
}

export function generateGaMigration(
  vault: VaultData,
  options: GaMigrationExportOptions,
): GaMigrationExport {
  const data = assertVaultData(vault)
  const batchId = options?.batchId
  const perBatch = options?.entriesPerBatch ?? GA_MIGRATION_LIMITS.defaultEntriesPerBatch
  if (!Number.isInteger(batchId) || batchId < -0x8000_0000 || batchId > 0x7fff_ffff) {
    throw new TransferValueError('GA batchId 必须是 signed int32')
  }
  if (!Number.isSafeInteger(perBatch) || perBatch < 1 || perBatch > TRANSFER_LIMITS.maxEntries) {
    throw new TransferValueError('GA 每片条目数超出范围')
  }
  assertEntryCount(data.entries.length, 'GA 导出')
  const batchSize = Math.ceil(data.entries.length / perBatch)
  if (batchSize > GA_MIGRATION_LIMITS.maxBatches)
    throw new TransferValueError('GA 导出批次数超过上限')
  const uris: string[] = []
  let totalBytes = 0
  for (let batchIndex = 0; batchIndex < batchSize; batchIndex += 1) {
    const encodedEntries: Uint8Array[] = []
    let payload: Uint8Array | undefined
    try {
      for (const entry of data.entries.slice(batchIndex * perBatch, (batchIndex + 1) * perBatch)) {
        if (entry.digits === 7 || (entry.kind === 'totp' && entry.period !== 30)) {
          throw new TransferValueError('GA 格式不能表示 7 位验证码或非 30 秒 TOTP')
        }
        assertFieldLength(entry.issuer, 'GA issuer')
        assertFieldLength(entry.account, 'GA account')
        if (entry.secret.length > TRANSFER_LIMITS.maxLineLength) {
          throw new TransferValueError('GA secret 超过可导出长度')
        }
        const secret = decodeBase64Secret(entry.secret)
        const name = utf8Encode(entry.account)
        const issuer = utf8Encode(entry.issuer)
        try {
          if (utf8Decode(name) !== entry.account || utf8Decode(issuer) !== entry.issuer) {
            throw new TransferValueError('GA 文本字段含非法 Unicode')
          }
          encodedEntries.push(
            writeFields([
              [1, secret],
              [2, name],
              [3, issuer],
              [4, entry.algo === 'SHA1' ? 1n : entry.algo === 'SHA256' ? 2n : 3n],
              [5, entry.digits === 6 ? 1n : 2n],
              [6, entry.kind === 'hotp' ? 1n : 2n],
              ...(entry.kind === 'hotp' ? [[7, BigInt(entry.counter!)] as const] : []),
            ]),
          )
        } finally {
          secret.fill(0)
          name.fill(0)
          issuer.fill(0)
        }
      }
      payload = writeFields([
        ...encodedEntries.map((entry) => [1, entry] as const),
        [2, 1n],
        [3, BigInt(batchSize)],
        [4, BigInt(batchIndex)],
        [5, BigInt(batchId)],
      ])
      const uri = `otpauth-migration://offline?data=${encodeURIComponent(base64Encode(payload))}`
      if (uri.length > TRANSFER_LIMITS.maxLineLength)
        throw new TransferValueError('GA 导出 URI 超过长度上限')
      totalBytes += uri.length
      if (totalBytes > TRANSFER_LIMITS.maxInputBytes)
        throw new TransferValueError('GA 导出累计大小超过上限')
      uris.push(uri)
    } finally {
      payload?.fill(0)
      for (const entry of encodedEntries) entry.fill(0)
    }
  }
  return { uris, verification: 'unverified', warning: VERIFICATION_WARNING }
}
