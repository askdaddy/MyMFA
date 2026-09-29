import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { Base32DecodeError } from '@askdaddy/otp'
import { TransferError, TransferValueError } from '../errors.js'
import { decodeBase32Secret, decodeBase64Secret, decodeIntArraySecret } from '../secret.js'

// Air Canada:Benjamin 的密钥。选它是因为字面里同时含 `O` 与 `I`，
// 才能验证 `0`→`O` / `1`→`I` 的混淆字符纠正（`4SJHB...` 那批不含这两个字符）。
const BASE32 = 'KUVJJOM753IHTNDSZVCNKL7GII'
const EXPECTED_HEX = '552a94b99feed079b472cd44d52fe642'
const BASE64 = 'VSqUuZ/u0Hm0cs1E1S/mQg=='
const CONFUSABLE = BASE32.replaceAll('O', '0').replaceAll('I', '1')

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

describe('decodeBase32Secret', () => {
  it.each([
    ['不带 padding', BASE32],
    ['带完整 padding', `${BASE32}======`],
    ['小写', BASE32.toLowerCase()],
    ['含空格（每 4 字符一组）', 'KUVJ JO M7 53IH TNDS ZVCN KL7G II'],
    ['含连字符', 'KUVJJO-M753IH-TNDSZV-CNKL7G-II'],
    ['0/1 混淆字符', CONFUSABLE],
    ['小写 + 混淆字符 + padding', `${CONFUSABLE.toLowerCase()}======`],
    ['制表符与换行', `\t${BASE32}\n`],
  ])('对同一密钥的「%s」写法解出相同字节', (_label, raw) => {
    expect(hex(decodeBase32Secret(raw))).toBe(EXPECTED_HEX)
  })

  it('解出的字节与 base64 路径对同一密钥的结果一致（C10）', () => {
    expect(decodeBase32Secret(BASE32)).toEqual(decodeBase64Secret(BASE64))
  })

  it.each([
    ['空字符串', ''],
    ['只有 padding', '======'],
    ['只有空白', '   '],
    ['含 base64 专有字符（合法 base64 但非法 base32）', 'a+b/c='],
    ['含 base32 字母表外的数字 8', 'AAAAAAAA8A======'],
    ['含百分号转义残留', 'KUVJJO%3D%3D'],
  ])('拒绝「%s」', (_label, raw) => {
    expect(() => decodeBase32Secret(raw)).toThrow(TransferValueError)
  })

  it.each([undefined, null, 42, true, {}, [65, 66]])('拒绝非字符串输入 %j', (raw) => {
    expect(() => decodeBase32Secret(raw)).toThrow(TransferValueError)
  })

  it('失败消息不回显 secret 原文，只说明原因', () => {
    const bad = `${BASE32}$$`
    try {
      decodeBase32Secret(bad)
      expect.unreachable('应当抛错')
    } catch (error) {
      expect((error as Error).message).not.toContain(BASE32)
      expect((error as Error).message).toContain('base32')
      expect((error as Error).cause).toBeInstanceOf(Base32DecodeError)
    }
  })
})

describe('decodeBase64Secret', () => {
  it('解出与 base32 路径相同的字节', () => {
    expect(hex(decodeBase64Secret(BASE64))).toBe(EXPECTED_HEX)
  })

  it.each([
    ['不带 padding', 'VSqUuZ/u0Hm0cs1E1S/mQg'],
    ['base64url 字母表', 'VSqUuZ_u0Hm0cs1E1S_mQg=='],
    ['含空白', ` ${BASE64} `],
  ])('容忍「%s」写法', (_label, raw) => {
    expect(hex(decodeBase64Secret(raw))).toBe(EXPECTED_HEX)
  })

  it.each([
    ['空字符串', ''],
    ['含 `!` 等字母表外字符', 'not!base64!'],
    ['全是非法字符', '****'],
  ])('拒绝「%s」', (_label, raw) => {
    expect(() => decodeBase64Secret(raw)).toThrow(TransferValueError)
  })

  it('失败消息不回显 secret 原文', () => {
    try {
      decodeBase64Secret('@@invalid@@')
      expect.unreachable('应当抛错')
    } catch (error) {
      expect((error as Error).message).not.toContain('@@invalid@@')
      expect((error as Error).message).toContain('base64')
    }
  })
})

describe('decodeIntArraySecret', () => {
  it('把有符号 int 数组还原为字节：[72,-64,127,-128] → [72,192,127,128]', () => {
    expect(Array.from(decodeIntArraySecret([72, -64, 127, -128]))).toEqual([72, 192, 127, 128])
  })

  it('边界值 -128 与 127 都能还原', () => {
    expect(Array.from(decodeIntArraySecret([-128, -1, 0, 127]))).toEqual([128, 255, 0, 127])
  })

  it('与 base32 路径对同一密钥解出相同字节（对照 FreeOTP+ 夹具）', () => {
    const fixture = JSON.parse(
      readFileSync(new URL('../__fixtures__/freeotp_plus.json', import.meta.url), 'utf8'),
    ) as { tokens: { issuerExt: string; secret: number[] }[] }
    const token = fixture.tokens.find((t) => t.issuerExt === 'Air Canada')
    expect(token).toBeDefined()
    expect(decodeIntArraySecret(token!.secret)).toEqual(decodeBase32Secret(BASE32))
  })

  it('对空数组判为失败', () => {
    expect(() => decodeIntArraySecret([])).toThrow(TransferValueError)
  })

  it.each([
    ['128（超上界）', [128]],
    ['-129（超下界）', [-129]],
    ['255（未做有符号转换的原始字节）', [255]],
    ['1.5（非整数）', [1.5]],
    ['NaN', [Number.NaN]],
    ['越界值混在合法值中间', [1, 2, -129, 4]],
    ['字符串项', ['65']],
    ['null 项', [null]],
  ])('对含 %s 的数组判为失败', (_label, raw) => {
    expect(() => decodeIntArraySecret(raw)).toThrow(TransferValueError)
  })

  it.each([undefined, null, '65,66', 42, {}])('拒绝非数组输入 %j', (raw) => {
    expect(() => decodeIntArraySecret(raw)).toThrow(TransferValueError)
  })

  it('不做 & 0xFF 截断：越界值必须失败而不是被悄悄修正（C8）', () => {
    // 若实现是 `value & 0xFF`，[255] 会静默变成 [255]、[128] 变成 [128]，测试就会通过而非抛错。
    expect(() => decodeIntArraySecret([255, 128, 300])).toThrow(TransferValueError)
  })

  it('失败消息只写下标，不写数组内容（C4）', () => {
    try {
      decodeIntArraySecret([1, 2, -129, 4])
      expect.unreachable('应当抛错')
    } catch (error) {
      const message = (error as Error).message
      expect(message).toContain('第 2 项')
      expect(message).not.toContain('-129')
      expect(message).not.toContain('129')
    }
  })
})

describe('steam:// 拒绝分支', () => {
  // 取自 vendored 夹具 bitwarden.csv 的第 4 行，是上游真实会产出的形态。
  const steamRow = readFileSync(new URL('../__fixtures__/bitwarden.csv', import.meta.url), 'utf8')
    .split('\n')
    .find((line) => line.includes('steam://'))
  const steamUri = steamRow?.split(',').pop() ?? ''

  it('夹具里确实有一条 steam:// 记录', () => {
    expect(steamUri.startsWith('steam://')).toBe(true)
  })

  it.each([
    'steam://JRZCL47CMXVOQMNPZR2F7J4RGI',
    'STEAM://JRZCL47CMXVOQMNPZR2F7J4RGI',
    ' steam://JRZCL47CMXVOQMNPZR2F7J4RGI ',
  ])('对 %j 判为失败，文案含「Steam」与「不受支持」', (raw) => {
    try {
      decodeBase32Secret(raw)
      expect.unreachable('应当抛错')
    } catch (error) {
      expect(error).toBeInstanceOf(TransferValueError)
      expect((error as Error).message).toContain('Steam')
      expect((error as Error).message).toContain('不受支持')
    }
  })

  it('夹具里的那条 steam:// 记录同样被拒', () => {
    expect(() => decodeBase32Secret(steamUri)).toThrow(/Steam 令牌不受支持/)
  })

  it('不走 base32 报错路径——说明未尝试任何字母表解码（ADR-004）', () => {
    try {
      decodeBase32Secret(steamUri)
      expect.unreachable('应当抛错')
    } catch (error) {
      // 若真的尝试过解码，消息会是「不是合法的 base32 字符串」；这里是专用的不支持文案。
      expect((error as Error).message).not.toContain('base32')
      expect((error as Error).cause).toBeUndefined()
    }
  })
})

describe('三条路径互不试探', () => {
  it('非法 base32 不会被当作 base64 再试一次', () => {
    // `a+b/c=` 是合法 base64（解出 3 字节）但非法 base32。
    expect(decodeBase64Secret('a+b/c=').length).toBe(3)
    expect(() => decodeBase32Secret('a+b/c=')).toThrow(TransferValueError)
  })

  it('非法 base64 不会被当作 base32 再试一次', () => {
    // `$$$$` 两条路径都非法；base32 路径必须报 base32 的原因，base64 路径必须报 base64 的原因。
    try {
      decodeBase32Secret('$$$$')
      expect.unreachable('应当抛错')
    } catch (error) {
      expect((error as Error).message).toContain('base32')
    }
    try {
      decodeBase64Secret('$$$$')
      expect.unreachable('应当抛错')
    } catch (error) {
      expect((error as Error).message).toContain('base64')
    }
  })

  it('int 数组路径不接受字符串，字符串路径不接受数组', () => {
    expect(() => decodeIntArraySecret(BASE32)).toThrow(TransferValueError)
    expect(() => decodeBase32Secret([72, -64])).toThrow(TransferValueError)
    expect(() => decodeBase64Secret([72, -64])).toThrow(TransferValueError)
  })

  it('全部失败都是 TransferValueError，可被解析器单点捕获', () => {
    const failures = [
      () => decodeBase32Secret(''),
      () => decodeBase64Secret('!!'),
      () => decodeIntArraySecret([]),
      () => decodeBase32Secret('steam://AAAA'),
    ]
    for (const fail of failures) {
      expect(fail).toThrow(TransferValueError)
      try {
        fail()
      } catch (error) {
        expect(error).toBeInstanceOf(TransferError)
      }
    }
  })
})
