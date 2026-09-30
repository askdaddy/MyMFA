import { describe, expect, it } from 'vitest'
import fc from 'fast-check'
import {
  decodeBase32Secret,
  parseAegis,
  parseBitwarden,
  parseCsv,
  parseEnte,
  parseFreeOtpPlus,
  parseGaMigration,
  parseTwoFas,
  TransferError,
  TRANSFER_LIMITS,
} from '../../index.js'

const seed = 20260930
const runs = 200

function controlled(run: () => unknown): void {
  try {
    run()
  } catch (error) {
    expect(error).toBeInstanceOf(TransferError)
  }
}

describe('固定种子模糊测试：不可信输入只返回结果或受控错误', () => {
  it('protobuf wire 数据', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 512 }), (bytes) => {
        const uri = `otpauth-migration://offline?data=${Buffer.from(bytes).toString('base64')}`
        controlled(() => parseGaMigration(uri))
      }),
      { seed, numRuns: runs },
    )
  })

  it('JSON 解析器', () => {
    const parsers = [parseAegis, parseTwoFas, parseFreeOtpPlus, parseEnte]
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 512 }), (bytes) => {
        for (const parser of parsers) controlled(() => parser(bytes))
      }),
      { seed: seed + 1, numRuns: runs },
    )
  })

  it('CSV 解析器', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 512 }), (value) => {
        controlled(() => parseCsv(value, '模糊测试 CSV'))
        controlled(() => parseBitwarden(value))
      }),
      { seed: seed + 2, numRuns: runs },
    )
  })

  it('base32 种子', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 512 }), (value) => {
        controlled(() => decodeBase32Secret(value))
      }),
      { seed: seed + 3, numRuns: runs },
    )
  })

  it('资源边界在解析前触发', () => {
    const tooDeep = '['.repeat(TRANSFER_LIMITS.maxNestingDepth + 1)
    expect(() => parseAegis(tooDeep)).toThrow(TransferError)
    const tooLarge = new Uint8Array(TRANSFER_LIMITS.maxInputBytes + 1)
    expect(() => parseTwoFas(tooLarge)).toThrow(TransferError)
    expect(() => parseCsv('a'.repeat(TRANSFER_LIMITS.maxCsvCellLength + 1), 'CSV')).toThrow(
      TransferError,
    )
  })
})
