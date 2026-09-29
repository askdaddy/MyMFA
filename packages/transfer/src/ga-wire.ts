import { TransferFormatError } from './errors.js'

export interface WireField {
  readonly number: number
  readonly wire: number
  readonly value: bigint | Uint8Array
}

export function* readFields(bytes: Uint8Array): Generator<WireField> {
  let offset = 0
  function varint(): bigint {
    let value = 0n
    for (let index = 0; index < 10; index += 1) {
      const byte = bytes[offset++]
      if (byte === undefined || (index === 9 && byte > 1)) {
        throw new TransferFormatError('GA protobuf varint 截断或溢出')
      }
      value |= BigInt(byte & 127) << BigInt(index * 7)
      if (byte < 128) return value
    }
    throw new TransferFormatError('GA protobuf varint 过长')
  }
  while (offset < bytes.length) {
    const key = varint()
    const number = Number(key >> 3n)
    const wire = Number(key & 7n)
    if (number < 1 || number > 0x1fff_ffff) {
      throw new TransferFormatError('GA protobuf 字段号非法')
    }
    if (wire === 0) {
      yield { number, wire, value: varint() }
      continue
    }
    // GA 的固定两层 schema 不含 groups；未知 LEN 不递归，避免嵌套炸弹。
    if (wire !== 1 && wire !== 2 && wire !== 5) {
      throw new TransferFormatError('GA protobuf wire 类型不受支持')
    }
    const length = wire === 2 ? varint() : BigInt(wire === 1 ? 8 : 4)
    if (length > BigInt(bytes.length - offset)) {
      throw new TransferFormatError('GA protobuf 字段长度超过剩余数据')
    }
    const end = offset + Number(length)
    yield { number, wire, value: bytes.subarray(offset, end) }
    offset = end
  }
}

export function int32(value: bigint): number {
  const signed = BigInt.asIntN(64, value)
  if (value > 0xffff_ffffn && (signed < -0x8000_0000n || signed > 0x7fff_ffffn)) {
    throw new TransferFormatError('GA protobuf int32 超出范围')
  }
  return Number(BigInt.asIntN(32, value))
}

function varintBytes(value: bigint): Uint8Array {
  let remaining = BigInt.asUintN(64, value)
  const bytes: number[] = []
  do {
    const byte = Number(remaining & 127n)
    remaining >>= 7n
    bytes.push(byte | (remaining === 0n ? 0 : 128))
  } while (remaining !== 0n)
  return Uint8Array.from(bytes)
}

export function writeFields(
  fields: readonly (readonly [number, bigint | Uint8Array])[],
): Uint8Array {
  const chunks: Uint8Array[] = []
  for (const [number, value] of fields) {
    chunks.push(varintBytes(BigInt(number * 8 + (typeof value === 'bigint' ? 0 : 2))))
    if (typeof value === 'bigint') chunks.push(varintBytes(value))
    else chunks.push(varintBytes(BigInt(value.length)), value)
  }
  const result = new Uint8Array(chunks.reduce((length, chunk) => length + chunk.length, 0))
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.length
  }
  return result
}
