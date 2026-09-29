import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { utf8Encode } from '@askdaddy/crypto'
import { detect } from '../detect.js'
import { TRANSFER_LIMITS } from '../input.js'

const fileBytes = (name: string): Uint8Array =>
  new Uint8Array(readFileSync(new URL(`../__fixtures__/${name}`, import.meta.url)))

const fileText = (name: string): string =>
  readFileSync(new URL(`../__fixtures__/${name}`, import.meta.url), 'utf8')

const jsonBytes = (value: unknown): Uint8Array => utf8Encode(JSON.stringify(value))

/** 0x00–0xFF 全量循环：既含 NUL 与控制字符，也含大量非法 UTF-8 起始字节。确定性构造，不用随机源。 */
const binaryGarbage = (): Uint8Array => {
  const bytes = new Uint8Array(1024)
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = i % 256
  return bytes
}

describe('detect：§4 第 1 步 URI scheme 前缀', () => {
  it('otpauth:// 开头的文本判为 otpauth-lines', () => {
    const uri =
      'otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30'
    expect(detect(uri)).toBe('otpauth-lines')
    expect(detect(utf8Encode(uri))).toBe('otpauth-lines')
  })

  it('scheme 大小写不敏感（RFC 3986 §3.1）', () => {
    expect(detect('OTPAUTH://totp/X:a?secret=JBSWY3DPEHPK3PXP')).toBe('otpauth-lines')
  })

  it('前导空白与 BOM 不影响前缀判别', () => {
    expect(detect('\n  otpauth://totp/X:a?secret=AAAA\n')).toBe('otpauth-lines')
    expect(detect('\uFEFFotpauth://totp/X:a?secret=AAAA')).toBe('otpauth-lines')
  })

  it('otpauth-migration:// 不得被判为 otpauth-lines（属 #9）', () => {
    const migration = 'otpauth-migration://offline?data=CjQKDEhlbGxvIeW7uuaWsBIEVGVzdA%3D%3D'
    expect(detect(migration)).not.toBe('otpauth-lines')
    expect(detect(migration)).toBeUndefined()
    expect(detect(migration.toUpperCase())).toBeUndefined()
  })

  it('多行裸 URI 文本判为 otpauth-lines', () => {
    expect(detect(fileText('plain.txt'))).toBe('otpauth-lines')
    expect(detect(fileBytes('plain.txt'))).toBe('otpauth-lines')
  })
})

describe('detect：§4 第 3 步 JSON 特征字段', () => {
  it('format === "mfavault" 且 encrypted: false 判为 mfavault-plaintext', () => {
    expect(detect(fileBytes('mfavault_plaintext.json'))).toBe('mfavault-plaintext')
    expect(detect(fileText('mfavault_plaintext.json'))).toBe('mfavault-plaintext')
  })

  it('schemaVersion 0 的老明文容器同样判为 mfavault-plaintext', () => {
    expect(detect(fileBytes('mfavault_plaintext_v0.json'))).toBe('mfavault-plaintext')
  })

  it('encrypted: true 时不得判为 mfavault-plaintext（加密路径属 #10）', () => {
    expect(detect(fileBytes('mfavault_malformed.json'))).not.toBe('mfavault-plaintext')
    expect(detect(fileBytes('mfavault_malformed.json'))).toBeUndefined()
    expect(
      detect(jsonBytes({ format: 'mfavault', version: 1, schemaVersion: 1, data: {} })),
    ).toBeUndefined()
  })

  it('Aegis 明文样本判为 aegis', () => {
    for (const name of [
      'aegis_plain.json',
      'aegis_plain_grouped_v2.json',
      'aegis_grouped_v3.json',
    ]) {
      expect(detect(fileBytes(name)), name).toBe('aegis')
    }
  })

  it('陷阱一：header.slots 为 null 且 db 为对象仍须命中 aegis', () => {
    expect(detect(jsonBytes({ version: 1, header: { slots: null }, db: { entries: [] } }))).toBe(
      'aegis',
    )
  })

  it('陷阱一的另一半：db 为 base64 字符串（加密形态）也落在 aegis 分支，#10 再细分', () => {
    expect(detect(jsonBytes({ version: 1, header: { slots: null }, db: 'QUJDRA==' }))).toBe('aegis')
  })

  it('含 db.entries 但不是 Aegis 的 JSON 不被误判', () => {
    expect(detect(jsonBytes({ db: { entries: [] } }))).toBeUndefined()
    expect(detect(jsonBytes({ version: '1', header: {}, db: {} }))).toBeUndefined()
  })

  it('结构性畸形的 Aegis 样本仍判为 aegis（探测不负责校验内容）', () => {
    expect(detect(fileBytes('aegis_malformed.json'))).toBe('aegis')
    expect(detect(fileBytes('aegis_edge.json'))).toBe('aegis')
  })

  it('2FAS 明文样本判为 2fas', () => {
    expect(detect(fileBytes('2fas_authenticator.json'))).toBe('2fas')
    expect(detect(fileBytes('2fas_authenticator_plain_v4.2fas'))).toBe('2fas')
    expect(detect(fileBytes('twofas_edge.json'))).toBe('2fas')
  })

  it('陷阱二：services 为空数组 + schemaVersion 存在也判为 2fas', () => {
    expect(detect(jsonBytes({ schemaVersion: 4, services: [] }))).toBe('2fas')
  })

  it('含 servicesEncrypted 的 JSON 判为 2fas', () => {
    expect(detect(jsonBytes({ servicesEncrypted: 'QUJDRA==' }))).toBe('2fas')
    expect(detect(jsonBytes({ servicesEncrypted: 'QUJDRA==', services: [] }))).toBe('2fas')
  })

  it('FreeOTP+ 样本（tokens + tokenOrder）判为 freeotp-plus', () => {
    expect(detect(fileBytes('freeotp_plus.json'))).toBe('freeotp-plus')
    expect(detect(fileBytes('freeotp_plus_malformed.json'))).toBe('freeotp-plus')
  })

  it('只有 tokens 而无 tokenOrder 时不猜，交给用户手选（§4 第 6 步）', () => {
    expect(detect(jsonBytes({ tokens: [] }))).toBeUndefined()
    expect(detect(fileBytes('freeotp_plus_edge.json'))).toBeUndefined()
  })

  it('未知 JSON 与损坏 JSON 一律 undefined，且不回落到 CSV 分支', () => {
    expect(detect('{"a":1}')).toBeUndefined()
    expect(detect('[1,2,3]')).toBeUndefined()
    expect(detect('{"format":"mfavault",')).toBeUndefined()
    expect(detect('"just a json string"')).toBeUndefined()
    expect(detect('null')).toBeUndefined()
  })

  it('深层嵌套超过上限时不抛异常', () => {
    const deep = `${'['.repeat(TRANSFER_LIMITS.maxNestingDepth + 2)}${']'.repeat(
      TRANSFER_LIMITS.maxNestingDepth + 2,
    )}`
    expect(() => detect(deep)).not.toThrow()
    expect(detect(deep)).toBeUndefined()
  })
})

describe('detect：§4 第 4 步 文本行形态', () => {
  it('Ente 裸 URI 导出（带 codeDisplay）判为 ente 而非 otpauth-lines', () => {
    expect(detect(fileText('ente_auth.txt'))).toBe('ente')
    expect(detect(fileBytes('ente_auth.txt'))).toBe('ente')
    expect(detect(fileBytes('ente_edge.txt'))).toBe('ente')
  })

  it('不带 codeDisplay 的裸 URI 文本仍判为 otpauth-lines', () => {
    expect(
      detect('otpauth://totp/X:a?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30'),
    ).toBe('otpauth-lines')
  })

  it('jsonEncode 的带引号 JSON 行判为 ente，且不被当成裸 URI 行', () => {
    expect(detect(fileText('ente_jsonlines.txt'))).toBe('ente')
    expect(detect(fileBytes('ente_jsonlines.txt'))).toBe('ente')
    expect(detect(fileText('ente_jsonlines.txt'))).not.toBe('otpauth-lines')
  })

  it('单行带引号 JSON 字符串也算 ente 的 jsonlines 形态', () => {
    const line = JSON.stringify('otpauth://totp/X:a?secret=JBSWY3DPEHPK3PXP')
    expect(detect(line)).toBe('ente')
  })

  it('带引号但内容不是 otpauth URI 的行不判为 ente', () => {
    expect(detect('"this is not a uri"')).toBeUndefined()
    expect(detect('{"a":1}\n"otpauth://totp/X:a?secret=AAAA"')).toBeUndefined()
  })

  it('裸 URI 与带引号行混排时不猜', () => {
    const mixed = 'otpauth://totp/A:a?secret=AAAA\n"otpauth://totp/B:b?secret=BBBB"'
    // 首行是裸 URI，按第 1 步的前缀规则给出结果；这里钉住的是「不会走到 jsonlines 分支」。
    expect(detect(mixed)).toBe('otpauth-lines')
    const mixedReversed = '"otpauth://totp/B:b?secret=BBBB"\notpauth://totp/A:a?secret=AAAA'
    expect(detect(mixedReversed)).not.toBe('ente')
  })

  it('部分行不是 URI 的文本：首行是 URI 就按前缀规则给结果，逐行失败留给解析器（C5）', () => {
    // `otpauth_edge.txt` 混进了 `https://`、无 scheme、空行等坏行，但 §4 第 1 步是**前缀**规则：
    // 识别成行式文本后，坏行由 `parseOtpAuthLines` 逐行记 failure，而不是在探测阶段整包放弃。
    expect(detect(fileBytes('otpauth_edge.txt'))).toBe('otpauth-lines')
    // 首行就不是 URI 的才真的无法判定。
    expect(detect(fileBytes('otpauth_malformed.txt'))).toBeUndefined()
  })
})

describe('detect：§4 第 5 步 CSV 表头', () => {
  it('含 login_totp 表头判为 bitwarden', () => {
    expect(detect(fileText('bitwarden.csv'))).toBe('bitwarden')
    expect(detect(fileBytes('bitwarden.csv'))).toBe('bitwarden')
    expect(detect(fileBytes('bitwarden_malformed.csv'))).toBe('bitwarden')
  })

  it('全引号表头也判为 bitwarden', () => {
    expect(detect('"folder","name","login_totp"\n"","a","AAAA"')).toBe('bitwarden')
  })

  it('只含 totp 表头不得判为 bitwarden，也不得判为任何 1Password 专用格式', () => {
    const result = detect(fileBytes('bitwarden_edge.csv'))
    expect(result).not.toBe('bitwarden')
    expect(result === 'generic-csv' || result === undefined).toBe(true)
    expect(detect('name,totp\na,AAAA')).not.toBe('bitwarden')
  })

  it('其他表头的 CSV 判为 generic-csv', () => {
    expect(detect(fileText('generic_csv.csv'))).toBe('generic-csv')
    expect(detect(fileBytes('generic_csv_malformed.csv'))).toBe('generic-csv')
  })

  it('BOM + CRLF 的表头仍能判别', () => {
    expect(detect(fileBytes('generic_csv_edge.csv'))).toBe('generic-csv')
    expect(detect('\uFEFFa,b\r\n1,2\r\n')).toBe('generic-csv')
  })

  it('单列文本不判为 CSV', () => {
    expect(detect('just one line of prose')).toBeUndefined()
    expect(detect('a\nb\nc')).toBeUndefined()
  })
})

describe('detect：畸形输入一律 undefined 且不抛异常', () => {
  const cases: [string, () => Uint8Array | string][] = [
    ['随机二进制', binaryGarbage],
    ['空字节串', () => new Uint8Array(0)],
    ['空字符串', () => ''],
    ['纯空白', () => '   \n\t\r\n  '],
    ['只有 BOM', () => '\uFEFF'],
    ['NUL 字节', () => utf8Encode('a\0b\0c')],
    ['NUL 混在 CSV 里', () => utf8Encode('a,b\0\nc,d')],
    ['非法 UTF-8 序列', () => Uint8Array.from([0xff, 0xfe, 0x2c, 0x61, 0x80])],
    ['超长输入', () => new Uint8Array(TRANSFER_LIMITS.maxInputBytes + 1)],
  ]

  for (const [name, make] of cases) {
    it(`${name} 返回 undefined`, () => {
      const input = make()
      expect(() => detect(input)).not.toThrow()
      expect(detect(input)).toBeUndefined()
    })
  }

  it('刚好在上限内的合法输入不因体积被拒', () => {
    const head = '{"format":"mfavault","encrypted":false,"pad":"'
    const pad = TRANSFER_LIMITS.maxInputBytes - head.length - 2
    const input = `${head}${'x'.repeat(pad)}"}`
    expect(utf8Encode(input).length).toBe(TRANSFER_LIMITS.maxInputBytes)
    expect(detect(input)).toBe('mfavault-plaintext')
  })

  it('错误文案不泄露 secret：探测器根本不产出文案，但也不得把内容回显到异常里', () => {
    // C4 在探测器上的形态是「不抛异常」——没有异常就没有 message，也就不可能回显 secret。
    const input = 'otpauth://totp/X:a?secret=JBSWY3DPEHPK3PXP%zz'
    expect(() => detect(input)).not.toThrow()
  })
})

describe('detect：纯函数', () => {
  it('同一输入连续两次结果相同', () => {
    for (const name of [
      'aegis_plain.json',
      '2fas_authenticator.json',
      'freeotp_plus.json',
      'mfavault_plaintext.json',
      'ente_auth.txt',
      'ente_jsonlines.txt',
      'bitwarden.csv',
      'generic_csv.csv',
      'plain.txt',
      'otpauth_malformed.txt',
    ]) {
      const bytes = fileBytes(name)
      expect(detect(bytes), name).toBe(detect(bytes))
    }
  })

  it('字节入参与字符串入参结果一致', () => {
    for (const name of [
      'aegis_plain.json',
      '2fas_authenticator.json',
      'freeotp_plus.json',
      'mfavault_plaintext.json',
      'ente_auth.txt',
      'ente_jsonlines.txt',
      'bitwarden.csv',
      'generic_csv.csv',
      'generic_csv_edge.csv',
      'plain.txt',
    ]) {
      expect(detect(fileText(name)), name).toBe(detect(fileBytes(name)))
    }
  })

  it('不修改入参', () => {
    const bytes = fileBytes('mfavault_plaintext.json')
    const snapshot = Uint8Array.from(bytes)
    detect(bytes)
    expect(bytes).toEqual(snapshot)

    const garbage = binaryGarbage()
    const garbageSnapshot = Uint8Array.from(garbage)
    detect(garbage)
    expect(garbage).toEqual(garbageSnapshot)
  })
})
