import { describe, expect, it } from 'vitest'
import * as api from '../index.js'

/**
 * 步骤 18 冻结的公开出口契约：清单里的每一个名字都必须能从 `@askdaddy/transfer` 直接导入。
 *
 * 这条测试与 QA 从根级 `test/` 做的黑盒验证是同一份清单的两端——QA 那侧走**已构建的包**，
 * 本侧走源码，两者不一致时说明 `index.ts` 漏了转发。
 *
 * 只断言「存在且形态正确」，不断言行为：行为由各解析器自己的测试覆盖。
 */

const CONTRACT_FUNCTIONS = [
  'detect',
  'sealPlaintext',
  'openPlaintext',
  'parseAegis',
  'parseTwoFas',
  'parseFreeOtpPlus',
  'parseEnte',
  'parseBitwarden',
  'parseGenericCsv',
  'parseOtpAuthLines',
  'generateAegis',
  'generateOtpAuthLines',
  'normalizeAlgorithm',
  'decodeBase32Secret',
  'decodeIntArraySecret',
] as const

const CONTRACT_VALUES = ['FORMAT_IDS', 'TRANSFER_LIMITS'] as const

/**
 * 错误类必须是**可 `instanceof` 的构造函数**而不只是导出的名字：C5 的处置方式是让调用方
 * 区分「整包不可用」（`TransferFormatError`，抛出）与「单条不可用」（收进 `failures`），
 * 而区分只能靠 `instanceof`。
 */
const CONTRACT_ERRORS = ['TransferError', 'TransferFormatError'] as const

describe('公开出口契约', () => {
  it.each([...CONTRACT_FUNCTIONS])('%s 是导出的函数', (name) => {
    expect(typeof api[name]).toBe('function')
  })

  it.each([...CONTRACT_VALUES])('%s 是导出的常量', (name) => {
    expect(typeof api[name]).toBe('object')
    expect(api[name]).not.toBeNull()
  })

  it.each([...CONTRACT_ERRORS])('%s 是可 instanceof 的错误类，且继承自 TransferError', (name) => {
    const Ctor: new (message: string) => Error = api[name]
    expect(typeof Ctor).toBe('function')
    expect(new Ctor('x')).toBeInstanceOf(Error)
    expect(new Ctor('x')).toBeInstanceOf(api.TransferError)
  })

  it('FORMAT_IDS 覆盖全部 9 个格式，且是只读数组的字面量来源', () => {
    expect([...api.FORMAT_IDS].sort()).toEqual(
      [
        'ga-migration',
        '2fas',
        'aegis',
        'bitwarden',
        'ente',
        'freeotp-plus',
        'generic-csv',
        'mfavault-plaintext',
        'otpauth-lines',
      ].sort(),
    )
  })

  it('8 个类型名在编译期可见：任一缺失或改名都会让 pnpm typecheck 失败', () => {
    const result: api.ImportResult = api.parseOtpAuthLines('')
    const failure: api.ParseFailure | undefined = result.failures[0]
    const warning: api.ParseWarning | undefined = result.warnings[0]
    const tag: api.ParsedTag | undefined = result.tags[0]
    const entry: api.ParsedEntry | undefined = result.entries[0]
    const format: api.FormatId = result.format
    const input: api.DetectableInput = ''
    // `PlaintextContainer` 只钉类型不造值：造一个合法的 `VaultData` 是 `container.test.ts` 的事。
    const container: api.PlaintextContainer | undefined = undefined

    expect(format).toBe('otpauth-lines')
    expect(input).toBe('')
    expect([failure, warning, tag, entry, container]).toEqual([
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
    ])
  })
})
