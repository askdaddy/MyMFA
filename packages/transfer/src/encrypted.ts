import {
  assertScryptParams,
  base64Decode,
  base64Encode,
  utf8Decode,
  utf8Encode,
} from '@askdaddy/crypto'
import type {
  AeadProvider,
  AeadSealed,
  Pbkdf2Provider,
  RandomProvider,
  ScryptParams,
  ScryptProvider,
} from '@askdaddy/crypto'
import type { VaultData } from '@askdaddy/vault'

import { generateAegis, parseAegis } from './aegis.js'
import { TransferAuthError, TransferFormatError } from './errors.js'
import { assertInputSize, isRecord, parseJson } from './input.js'
import { parseTwoFas } from './twofas.js'
import type { DetectableInput, ImportResult } from './types.js'

export interface AegisImportProviders {
  readonly scrypt: ScryptProvider
  readonly aead: AeadProvider
}

export interface AegisExportProviders extends AegisImportProviders {
  readonly random: RandomProvider
}

export interface TwoFasImportProviders {
  readonly pbkdf2: Pbkdf2Provider
  readonly aead: AeadProvider
}

type Track = (bytes: Uint8Array) => Uint8Array

function tracker(spent: Uint8Array[]): Track {
  return (bytes) => {
    spent.push(bytes)
    return bytes
  }
}

function clear(spent: readonly Uint8Array[]): void {
  for (const bytes of spent) bytes.fill(0)
}

function readObject(input: DetectableInput, track: Track): Record<string, unknown> {
  const bytes = typeof input === 'string' ? track(utf8Encode(input)) : input
  assertInputSize(bytes, '加密备份')
  const json = parseJson(utf8Decode(bytes), '加密备份')
  if (!isRecord(json)) throw new TransferAuthError()
  return json
}

function hexDecode(value: unknown, length: number | undefined, track: Track): Uint8Array {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length % 2 !== 0 ||
    value.length > 2048 ||
    !/^[0-9a-f]+$/i.test(value) ||
    (length !== undefined && value.length !== length * 2)
  ) {
    throw new TransferAuthError()
  }
  const bytes = track(new Uint8Array(value.length / 2))
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function b64(value: unknown, track: Track): Uint8Array {
  if (typeof value !== 'string') throw new TransferAuthError()
  return track(base64Decode(value))
}

function aegisSealed(value: unknown, ciphertext: Uint8Array, track: Track): AeadSealed {
  if (!isRecord(value)) throw new TransferAuthError()
  return {
    nonce: hexDecode(value.nonce, 12, track),
    tag: hexDecode(value.tag, 16, track),
    ciphertext,
  }
}

function scryptParams(slot: Record<string, unknown>, salt: Uint8Array): ScryptParams {
  if (typeof slot.n !== 'number' || typeof slot.r !== 'number' || typeof slot.p !== 'number') {
    throw new TransferAuthError()
  }
  const params = { costFactor: slot.n, blockSize: slot.r, parallelism: slot.p, keyLength: 32 }
  assertScryptParams(params, salt)
  return params
}

export async function parseAegisEncrypted(
  input: DetectableInput,
  password: Uint8Array,
  providers: AegisImportProviders,
): Promise<ImportResult> {
  const spent: Uint8Array[] = []
  const track = tracker(spent)
  try {
    const json = readObject(input, track)
    if (json.version !== 1 || !isRecord(json.header)) throw new TransferAuthError()
    const slots = json.header.slots
    if (!Array.isArray(slots) || slots.length === 0 || slots.length > 32) {
      throw new TransferAuthError()
    }
    const sealed = aegisSealed(json.header.params, b64(json.db, track), track)
    // 在任何 KDF 执行前校验全部槽，避免前面可用的槽掩盖后面的超限参数。
    const candidates = slots.flatMap((raw: unknown) => {
      if (!isRecord(raw)) throw new TransferAuthError()
      if (raw.type !== 1) return []
      const salt = hexDecode(raw.salt, undefined, track)
      return [
        {
          salt,
          params: scryptParams(raw, salt),
          wrapped: aegisSealed(raw.key_params, hexDecode(raw.key, 32, track), track),
        },
      ]
    })
    for (const slot of candidates) {
      const key = track(await providers.scrypt.deriveKey(password, slot.salt, slot.params))
      let master: Uint8Array
      try {
        master = track(await providers.aead.decrypt(key, slot.wrapped))
      } catch {
        continue
      } finally {
        key.fill(0)
      }
      if (master.length !== 32) throw new TransferAuthError()
      const plaintext = track(await providers.aead.decrypt(master, sealed))
      assertInputSize(plaintext, '加密备份明文')
      const db = parseJson(utf8Decode(plaintext), '加密备份明文')
      const file = track(
        utf8Encode(JSON.stringify({ version: 1, header: { slots: null, params: null }, db })),
      )
      return parseAegis(file)
    }
    throw new TransferAuthError()
  } catch {
    throw new TransferAuthError()
  } finally {
    clear(spent)
  }
}

function uuid(random: RandomProvider, track: Track): string {
  const bytes = track(random.randomBytes(16))
  if (bytes.length !== 16) throw new TransferFormatError('随机源输出长度不正确')
  bytes[6] = (bytes[6]! & 0x0f) | 0x40
  bytes[8] = (bytes[8]! & 0x3f) | 0x80
  const text = hexEncode(bytes)
  return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}-${text.slice(16, 20)}-${text.slice(20)}`
}

function encodedParams(sealed: AeadSealed, track: Track) {
  track(sealed.nonce)
  track(sealed.tag)
  track(sealed.ciphertext)
  return { nonce: hexEncode(sealed.nonce), tag: hexEncode(sealed.tag) }
}

export async function generateAegisEncrypted(
  vault: VaultData,
  password: Uint8Array,
  params: ScryptParams,
  providers: AegisExportProviders,
): Promise<Uint8Array> {
  const spent: Uint8Array[] = []
  const track = tracker(spent)
  try {
    const { costFactor, blockSize, parallelism, keyLength } = params
    const selected = { costFactor, blockSize, parallelism, keyLength }
    if (keyLength !== 32) throw new TransferFormatError('Aegis 的密钥长度必须是 32 字节')
    const salt = track(providers.random.randomBytes(32))
    const master = track(providers.random.randomBytes(32))
    if (salt.length !== 32 || master.length !== 32) {
      throw new TransferFormatError('随机源输出长度不正确')
    }
    assertScryptParams(selected, salt)
    const key = track(await providers.scrypt.deriveKey(password, salt, selected))
    const plainFile = readObject(track(generateAegis(vault)), track)
    const plaintext = track(utf8Encode(JSON.stringify(plainFile.db)))
    const wrapped = await providers.aead.encrypt(key, master)
    const keyParams = encodedParams(wrapped, track)
    const sealed = await providers.aead.encrypt(master, plaintext)
    const dataParams = encodedParams(sealed, track)
    const file = {
      version: 1,
      header: {
        slots: [
          {
            type: 1,
            uuid: uuid(providers.random, track),
            key: hexEncode(wrapped.ciphertext),
            key_params: keyParams,
            n: costFactor,
            r: blockSize,
            p: parallelism,
            salt: hexEncode(salt),
          },
        ],
        params: dataParams,
      },
      db: base64Encode(sealed.ciphertext),
    }
    const output = utf8Encode(JSON.stringify(file))
    assertInputSize(output, 'Aegis 加密导出')
    return output
  } finally {
    clear(spent)
  }
}

function twoFasPart(value: unknown, track: Track) {
  if (typeof value !== 'string') throw new TransferAuthError()
  const parts = value.split(':')
  if (parts.length !== 3) throw new TransferAuthError()
  const data = b64(parts[0], track)
  const salt = b64(parts[1], track)
  const nonce = b64(parts[2], track)
  if (data.length < 16 || nonce.length !== 12 || salt.length === 0 || salt.length > 1024) {
    throw new TransferAuthError()
  }
  return { salt, sealed: { nonce, ciphertext: data.subarray(0, -16), tag: data.subarray(-16) } }
}

export async function parseTwoFasEncrypted(
  input: DetectableInput,
  password: Uint8Array,
  providers: TwoFasImportProviders,
): Promise<ImportResult> {
  const spent: Uint8Array[] = []
  const track = tracker(spent)
  try {
    const json = readObject(input, track)
    if (json.schemaVersion !== 4) {
      throw new TransferAuthError()
    }
    const reference = twoFasPart(json.reference, track)
    const services = twoFasPart(json.servicesEncrypted, track)
    let serviceBytes: Uint8Array | undefined
    for (const part of [reference, services]) {
      // 2FAS 不将这些参数写入文件；它们来自固定版本的一手格式定义，不能读取伪造覆盖值。
      const key = track(
        await providers.pbkdf2.deriveKey(password, part.salt, {
          hash: 'SHA-256',
          iterations: 10_000,
          keyLength: 32,
        }),
      )
      try {
        serviceBytes = track(await providers.aead.decrypt(key, part.sealed))
        assertInputSize(serviceBytes, '加密备份明文')
      } finally {
        key.fill(0)
      }
    }
    const raw = parseJson(utf8Decode(serviceBytes!), '加密备份明文')
    const file = track(
      utf8Encode(
        JSON.stringify({
          ...json,
          services: raw,
          servicesEncrypted: null,
          reference: null,
        }),
      ),
    )
    return parseTwoFas(file)
  } catch {
    throw new TransferAuthError()
  } finally {
    clear(spent)
  }
}
