/**
 * QA 黑盒验收脚本 —— Issue #8（packages/transfer），plan「公开出口契约」指定的落点。
 *
 * 为什么必须是根级 `test/`：QA 只对业务代码有只读权限（iloop T0），验收必须**独立复现**，
 * 不采信开发的自述。本脚本只 import **构建产物 `dist/`**，验证的是将要发布的那份字节；
 * 期望值一律从 `src/__fixtures__/` 的原始内容与 `docs/` 的冻结判据推导，不抄开发的单测。
 *
 * 运行：`pnpm build && node test/transfer-blackbox.mjs`
 * 退出码 0 = 全部 PASS。
 *
 * 覆盖：plan 步骤 1–18 中**可观测**的验收标准，含计划修订 R1（步骤 15）与 R2 / R2b（步骤 16）
 * 冻结后的完整标准。类型层不变量（步骤 3 的「八个字段不得存在」）由 `test/transfer-type-probe.ts`
 * 配合 `tsc --noEmit` 独立验证，不在本脚本内。纯结构性判据（README 溯源、.gitignore、
 * dist 无 json、lint / typecheck / format）由 shell 命令取证，见 verify-report。
 */

/* global console, process, URL, performance */
// 根级 `test/` 不在 eslint.config.js 的 Node globals 配置里（Issue #7 尚未落地），脚本要打印
// 结果、设置退出码、解析夹具路径与计时，只能就地声明这四个全局（QA 不得改 eslint.config.js）。

import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'

import {
  base64Decode,
  base64Encode,
  utf8Decode,
  utf8Encode,
} from '../packages/crypto/dist/index.js'
import { assertVaultData } from '../packages/vault/dist/index.js'
import * as T from '../packages/transfer/dist/index.js'

const FIXTURES = new URL('../packages/transfer/src/__fixtures__/', import.meta.url)
const fixture = (name) => readFileSync(new URL(name, FIXTURES), 'utf8')
const fixtureBytes = (name) => new Uint8Array(readFileSync(new URL(name, FIXTURES)))

const cases = []
const test = (name, fn) => cases.push({ name, fn })

/** 取异常对象；没有抛异常即判失败（「预期抛错」本身就是判据的一部分）。 */
const thrown = (fn) => {
  try {
    fn()
  } catch (error) {
    return error
  }
  assert.fail('预期抛错，实际正常返回')
}

const messageOf = (fn) => thrown(fn).message

/** 把 Uint8Array 转成可比较的十六进制串，用于「字节相同」类断言。 */
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')

/**
 * 同一份假 secret 在四类来源里的两种写法（C10「判重按字节比」的证据）。
 * base64 形态取自 `mfavault_plaintext.json`，base32 形态取自各第三方夹具。
 */
const SECRET_DENO = { base64: '5JJw8NIfNlyECPi0dcUmfA==', base32: '4SJHB4GSD43FZBAI7C2HLRJGPQ' }
const SECRET_WWE = { base64: '7UDF7vvsziIGsV11wRgqdg==', base32: '5VAML3X35THCEBVRLV24CGBKOY' }
const SECRET_AIRCANADA = {
  base64: 'VSqUuZ/u0Hm0cs1E1S/mQg==',
  base32: 'KUVJJOM753IHTNDSZVCNKL7GII',
}

/** C4 取证：把一段文案里所有可能泄露 secret 的形态都列出来。 */
const leakForms = (secretBase32) => {
  const bytes = T.decodeBase32Secret(secretBase32)
  return [
    secretBase32,
    secretBase32.toLowerCase(),
    base64Encode(bytes),
    base64Encode(bytes).replaceAll('=', ''),
    hex(bytes),
  ]
}
const assertNoSecretLeak = (texts, secretBase32, label) => {
  for (const text of texts) {
    for (const form of leakForms(secretBase32)) {
      assert.ok(
        !String(text).includes(form),
        `${label}：文案泄露了 secret 的某种编码形态（C4 / docs/vault-format.md §5.2）`,
      )
    }
  }
}

const VAULT = assertVaultData(JSON.parse(fixture('mfavault_plaintext.json')).data)

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 18 / 步骤 1 / 步骤 3：公开出口契约
// ─────────────────────────────────────────────────────────────────────────────

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
]
const CONTRACT_VALUES = ['FORMAT_IDS', 'TRANSFER_LIMITS']
const CONTRACT_ERRORS = ['TransferError', 'TransferFormatError']

test('步骤 18：契约清单的每个函数都能从包入口导入且为 function', () => {
  for (const name of CONTRACT_FUNCTIONS) {
    assert.equal(typeof T[name], 'function', `缺失函数出口 ${name}`)
  }
})

test('步骤 18：契约清单的每个常量都能导入', () => {
  for (const name of CONTRACT_VALUES) {
    assert.equal(typeof T[name], 'object', `缺失常量出口 ${name}`)
    assert.ok(T[name] !== null, `${name} 为 null`)
  }
})

test('步骤 18：契约清单的两个错误类可被 new 且是 Error 子类', () => {
  for (const name of CONTRACT_ERRORS) {
    const Ctor = T[name]
    assert.equal(typeof Ctor, 'function', `缺失错误出口 ${name}`)
    const error = new Ctor('probe')
    assert.ok(error instanceof Error, `${name} 不是 Error 子类`)
    assert.equal(error.message, 'probe')
  }
  assert.ok(
    new T.TransferFormatError('x') instanceof T.TransferError,
    'TransferFormatError 必须继承 TransferError（步骤 2）',
  )
})

test('步骤 3：FORMAT_IDS 含全部八个格式 id', () => {
  for (const id of [
    'mfavault-plaintext',
    'aegis',
    '2fas',
    'freeotp-plus',
    'ente',
    'bitwarden',
    'otpauth-lines',
    'generic-csv',
  ]) {
    assert.ok(T.FORMAT_IDS.includes(id), `FORMAT_IDS 缺 ${id}`)
  }
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 2：上限常量与 C4
// ─────────────────────────────────────────────────────────────────────────────

test('步骤 2：TRANSFER_LIMITS 每个值都是有限正整数', () => {
  assert.ok(Object.keys(T.TRANSFER_LIMITS).length >= 5, '上限常量少于 5 项')
  for (const [key, value] of Object.entries(T.TRANSFER_LIMITS)) {
    assert.ok(Number.isInteger(value), `${key} 不是整数：${value}`)
    assert.ok(Number.isFinite(value), `${key} 不是有限数`)
    assert.ok(value > 0, `${key} 不是正数：${value}`)
  }
})

test('步骤 2：secret / digits 非法时的文案不含 secret 的任何编码形态（C4）', () => {
  const bad = '!!!not-base32!!!'
  const message = messageOf(() => T.decodeBase32Secret(bad))
  assert.ok(!message.includes(bad), '文案回显了收到的原值（C4 禁止）')
  // 夹具共 7 条，末条是 steam（ADR-004 单条失败），故这里只留一条以隔离 digits 越界这一个变量
  const aegis = JSON.parse(fixture('aegis_plain.json'))
  aegis.db.entries = [aegis.db.entries[0]]
  aegis.db.entries[0].info.digits = 9
  const result = T.parseAegis(JSON.stringify(aegis))
  assert.equal(result.entries.length, 0)
  assert.equal(result.failures.length, 1)
  assertNoSecretLeak(
    [result.failures[0].reason, result.failures[0].path],
    SECRET_DENO.base32,
    'Aegis digits 越界的 failure',
  )
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 5：归一化
// ─────────────────────────────────────────────────────────────────────────────

test('步骤 5：SHA1 系列的七种写法全部归一化为 SHA1', () => {
  for (const raw of [
    'SHA1',
    'sha1',
    'SHA-1',
    ' sha1 ',
    'HmacSHA1',
    'Algorithm.sha1',
    'algorithm.sha1',
  ]) {
    const got = T.normalizeAlgorithm(raw)
    assert.equal(got.algo, 'SHA1', `${JSON.stringify(raw)} → ${got.algo}`)
    assert.equal(got.fromMd5, false, `${JSON.stringify(raw)} 被误判为来自 MD5`)
  }
})

test('步骤 5：SHA256 / SHA512 系列归一化正确', () => {
  assert.equal(T.normalizeAlgorithm('SHA256').algo, 'SHA256')
  assert.equal(T.normalizeAlgorithm('sha-256').algo, 'SHA256')
  assert.equal(T.normalizeAlgorithm('algorithm.sha256').algo, 'SHA256')
  assert.equal(T.normalizeAlgorithm('SHA512').algo, 'SHA512')
  assert.equal(T.normalizeAlgorithm('sha-512').algo, 'SHA512')
  assert.equal(T.normalizeAlgorithm('Algorithm.SHA512').algo, 'SHA512')
})

test('步骤 5：MD5 → SHA1 且调用方能区分「本来就是 SHA1」（fromMd5 信号）', () => {
  const got = T.normalizeAlgorithm('MD5')
  assert.equal(got.algo, 'SHA1')
  assert.equal(got.fromMd5, true, 'MD5 的归一化必须给出可区分的 warning 信号')
  assert.equal(T.normalizeAlgorithm('SHA1').fromMd5, false)
})

test('步骤 5：SHA224 / SHA384 / MD4 / 空串 / 乱码一律失败，绝不回落 SHA1（C8）', () => {
  for (const raw of [
    'SHA224',
    'SHA384',
    'MD4',
    '',
    'totally-unknown',
    'SHA0',
    undefined,
    1,
    null,
  ]) {
    assert.throws(() => T.normalizeAlgorithm(raw), undefined, `${JSON.stringify(raw)} 未被拒绝`)
  }
})

test('步骤 5：digits 5/9/10/0/-1/6.5/NaN 全部失败，6/7/8 通过', () => {
  for (const bad of [5, 9, 10, 0, -1, 6.5, NaN, '6.5', null, undefined, true]) {
    assert.throws(() => T.normalizeDigits(bad), undefined, `digits=${String(bad)} 未被拒绝`)
  }
  for (const good of [6, 7, 8]) {
    assert.equal(T.normalizeDigits(good), good)
  }
})

test('步骤 5：kind 归一化只接受 totp / hotp，其余一律失败（不静默补默认值）', () => {
  assert.equal(T.normalizeKind('totp'), 'totp')
  assert.equal(T.normalizeKind('TOTP'), 'totp')
  assert.equal(T.normalizeKind('hotp'), 'hotp')
  assert.equal(T.normalizeKind('HOTP'), 'hotp')
  for (const bad of ['steam', 'motp', 'yandex', '', undefined, 'time']) {
    assert.throws(() => T.normalizeKind(bad), undefined, `kind=${String(bad)} 未被拒绝`)
  }
})

// normalizePeriod / normalizeCounter 不在步骤 5 的冻结判据内（标题只列 algorithm / digits / kind），
// 属开发在偏差 11 里自报的计划外出口。按 reviewer.md「禁止引入计划外的验收项」，此处不设断言；
// period / counter 的缺失处置由各格式步骤（11 / 12 / 13 / 16 修订 2）的 C8 判据钉住。

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 6：secret 三条解码路径 + Steam 拒绝
// ─────────────────────────────────────────────────────────────────────────────

test('步骤 6：base32 的大小写 / 空格 / padding / 0-1 混淆字符写法解出相同字节', () => {
  const canonical = T.decodeBase32Secret(SECRET_DENO.base32)
  for (const variant of [
    SECRET_DENO.base32,
    SECRET_DENO.base32.toLowerCase(),
    `${SECRET_DENO.base32.slice(0, 8)} ${SECRET_DENO.base32.slice(8)}`,
    // 判据要求「含 0/1 混淆字符的**同一密钥**解出相同字节」，故 I→1 必须被接受而非判失败
    SECRET_DENO.base32.replace('BAI7', 'BA17'),
  ]) {
    assert.equal(hex(T.decodeBase32Secret(variant)), hex(canonical), `变体 ${variant} 解出不同字节`)
  }
  assert.equal(
    hex(T.decodeBase32Secret('JBSWY3DPEHPK3PXP======')),
    hex(T.decodeBase32Secret('JBSWY3DPEHPK3PXP')),
    '带 padding 与不带 padding 未解出相同字节',
  )
  // O→0 同理：SPDX 密钥含三个 O，全部换成 0 后必须解出同一份字节
  assert.equal(
    hex(T.decodeBase32Secret('50M4W00GPLQEF6UGN3CPE00LWU')),
    hex(T.decodeBase32Secret('5OM4WOOGPLQEF6UGN3CPEOOLWU')),
    'O→0 混淆字符未解出相同字节',
  )
  // 混淆字符之外的非法字符仍须判失败（C8：不得猜）
  assert.throws(() => T.decodeBase32Secret('JBSWY3DPEHPK3PXP8'))
  assert.throws(() => T.decodeBase32Secret('JBSWY3DPEHPK3PXP!'))
})

test('步骤 6：C10 —— 同一密钥的 base32 与 base64 形态解出逐字节相同', () => {
  for (const pair of [SECRET_DENO, SECRET_WWE, SECRET_AIRCANADA]) {
    assert.equal(
      hex(T.decodeBase32Secret(pair.base32)),
      hex(T.decodeBase64Secret(pair.base64)),
      `${pair.base32} 与 ${pair.base64} 不是同一份字节`,
    )
  }
})

test('步骤 6：decodeIntArraySecret 对有符号字节做 +256 归一', () => {
  assert.deepEqual([...T.decodeIntArraySecret([72, -64, 127, -128])], [72, 192, 127, 128])
})

test('步骤 6：int 数组越界 / 非整数 / 空数组判为失败，且不做 & 0xFF 截断', () => {
  for (const bad of [[128], [-129], [255], [1.5], [NaN], [], 'not-array', [null], [-1, 128]]) {
    assert.throws(
      () => T.decodeIntArraySecret(bad),
      undefined,
      `int 数组 ${JSON.stringify(bad)} 未被拒绝`,
    )
  }
})

test('步骤 6：int 数组失败文案不回显收到的数组内容（C4）', () => {
  const message = messageOf(() => T.decodeIntArraySecret([72, 200]))
  // 文案允许出现「第 N 项」这类位置信息与 [-128,127] 这类固定范围常量，
  // 但不得回显收到的数组本身或越界项的值——那是 secret 的推断材料
  assert.ok(!message.includes('200'), `文案回显了越界项的原值：${message}`)
  assert.ok(
    !message.includes('[72,200]') && !message.includes('72, 200'),
    `文案回显了数组内容：${message}`,
  )
})

test('步骤 6：steam:// 判为失败，文案含「Steam」与「不受支持」，不做 Steam 字母表解码', () => {
  const uri = `otpauth://totp/Boeing:Sophia?secret=steam://${SECRET_DENO.base32}&issuer=Boeing&algorithm=SHA1&digits=6&period=30`
  const error = thrown(() => T.parseOtpAuthUri(uri, 0))
  assert.match(error.message, /Steam/)
  assert.match(error.message, /不受支持/)
})

test('步骤 6：三条路径互不试探 —— 非法 base32 不会被当 base64 再试', () => {
  // SECRET_DENO.base64 含 `8` `9` `0` `=`，不在 base32 字母表内，故对 base32 入口是非法输入。
  // 判据要求它**不得**被回落到 base64 再解一次——若回落，就会静默解出正确字节而非报错。
  const error = thrown(() => T.decodeBase32Secret(SECRET_DENO.base64))
  assert.match(
    error.message,
    /base32/i,
    `抛的不是 base32 的错，疑似回落到了别的路径：${error.message}`,
  )
  // 反向不成立：base32 字母表 A-Z2-7 是 base64 字母表的子集，
  // 一份 26 字符的 base32 串对 base64 入口天然合法，无法用它证明「未试探」，故不设该方向断言。
  assert.equal(
    hex(T.decodeBase64Secret(SECRET_DENO.base64)),
    hex(T.decodeBase32Secret(SECRET_DENO.base32)),
  )
})

test('步骤 6：encodeBase32Secret 输出大写且无 padding', () => {
  const encoded = T.encodeBase32Secret(T.decodeBase64Secret(SECRET_DENO.base64))
  assert.equal(encoded, SECRET_DENO.base32)
  assert.ok(!encoded.includes('='), '仍带 padding')
  assert.equal(encoded, encoded.toUpperCase())
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 7：CSV
// ─────────────────────────────────────────────────────────────────────────────

test('步骤 7：按列名取值，不按列位置', () => {
  const table = T.parseCsv('b,a\n1,2\n', 'probe')
  assert.equal(table.records[0].values.get('a'), '2')
  assert.equal(table.records[0].values.get('b'), '1')
  assert.deepEqual(table.header, ['b', 'a'], '表头未保留原始顺序')
})

test('步骤 7：引号包裹、引号内 "" 转义、字段内换行', () => {
  const quoted = T.parseCsv('x,y\n"a,b",c\n', 'probe')
  assert.equal(quoted.records[0].values.get('x'), 'a,b')
  assert.equal(quoted.records[0].values.get('y'), 'c')
  assert.equal(
    T.parseCsv('x,y\n"he said ""hi""",z\n', 'probe').records[0].values.get('x'),
    'he said "hi"',
  )
  const multiline = T.parseCsv('x,y\n"line1\nline2",z\n', 'probe')
  assert.equal(multiline.records.length, 1, '字段内换行被切成了两行')
  assert.equal(multiline.records[0].values.get('x'), 'line1\nline2')
})

test('步骤 7：CRLF 与 LF 行尾都能解析', () => {
  assert.equal(T.parseCsv('a,b\n1,2\n3,4\n', 'probe').records.length, 2)
  const crlf = T.parseCsv('a,b\r\n1,2\r\n3,4\r\n', 'probe')
  assert.equal(crlf.records.length, 2)
  assert.equal(crlf.records[1].values.get('b'), '4', 'CRLF 的 \\r 泄漏进了值')
})

test('步骤 7：列数与表头不符的行判失败并带行号，不中止其余行（C5）', () => {
  const table = T.parseCsv('a,b\n1,2\n3\n4,5\n', 'probe')
  assert.equal(table.records.length, 2, '合法行没有照常产出')
  assert.equal(table.failures.length, 1)
  // ParseFailure 的形态是 {sourceIndex, path, reason}；行号落在 path 上
  assert.equal(table.failures[0].sourceIndex, 1, '第二条数据行的 sourceIndex 应为 1')
  assert.match(table.failures[0].path, /第 3 行/, `failure 未带来源行号：${table.failures[0].path}`)
  assert.deepEqual(
    table.records.map((r) => r.rowIndex),
    [0, 2],
    'rowIndex 应为源文件里的 0 基数据行序号（失败行也占号）',
  )
  assert.deepEqual(
    table.records.map((r) => r.lineNumber),
    [2, 4],
    'lineNumber 应为 1 基的源文本行号',
  )
})

test('步骤 7：超过上限的单元格长度在逐行解析之前抛 TransferFormatError（C3）', () => {
  const huge = `a,b\n1,${'x'.repeat(T.TRANSFER_LIMITS.maxCsvCellLength + 1)}\n`
  const error = thrown(() => T.parseCsv(huge, 'probe'))
  assert.ok(error instanceof T.TransferFormatError, `抛的不是 TransferFormatError：${error.name}`)
  assert.match(error.message, /超过上限/)
})

test('步骤 7：行数超过上限抛 TransferFormatError —— 带尾换行', () => {
  const rows = T.TRANSFER_LIMITS.maxEntries + 1
  const text = ['a,b', ...Array.from({ length: rows }, (_, i) => `${i},x`)].join('\n') + '\n'
  const error = thrown(() => T.parseCsv(text, 'probe'))
  assert.ok(error instanceof T.TransferFormatError, `抛的不是 TransferFormatError：${error.name}`)
  assert.match(error.message, /超过上限/)
  // 刚好在上限内不得被拒
  const exact =
    ['a,b', ...Array.from({ length: T.TRANSFER_LIMITS.maxEntries }, (_, i) => `${i},x`)].join(
      '\n',
    ) + '\n'
  assert.equal(T.parseCsv(exact, 'probe').records.length, T.TRANSFER_LIMITS.maxEntries)
})

test('步骤 7：行数超过上限抛 TransferFormatError —— 无尾换行', () => {
  const rows = T.TRANSFER_LIMITS.maxEntries + 1
  const text = ['a,b', ...Array.from({ length: rows }, (_, i) => `${i},x`)].join('\n')
  const error = thrown(() => T.parseCsv(text, 'probe'))
  assert.ok(error instanceof T.TransferFormatError, `抛的不是 TransferFormatError：${error.name}`)
  assert.match(error.message, /超过上限/)
})

test('步骤 7：生成侧对 , " 换行 正确引用转义，往返无损', () => {
  const text = T.generateCsv(['a', 'b', 'c'], [['x,y', 'he said "hi"', 'line1\nline2']])
  assert.match(text, /"x,y"/)
  assert.match(text, /"he said ""hi"""/)
  const back = T.parseCsv(text, 'probe')
  assert.equal(back.failures.length, 0, JSON.stringify(back.failures))
  assert.equal(back.records.length, 1)
  assert.equal(back.records[0].values.get('a'), 'x,y')
  assert.equal(back.records[0].values.get('b'), 'he said "hi"')
  assert.equal(back.records[0].values.get('c'), 'line1\nline2')
})

test('步骤 7：引号未闭合判整包失败', () => {
  assert.ok(
    thrown(() => T.parseCsv('a,b\n"unclosed,2\n', 'probe')) instanceof T.TransferFormatError,
  )
})

// cell / cellText 是开发在步骤 16 提升的计划外出口（偏差 11 已自报），不在步骤 7 的冻结判据内，此处不设断言。

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 8：otpauth URI
// ─────────────────────────────────────────────────────────────────────────────

const FULL_URI =
  'otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30'

test('步骤 8：完整 URI 解析出 kind/issuer/account/secret/algo/digits/period', () => {
  const { entry } = T.parseOtpAuthUri(FULL_URI, 0)
  assert.equal(entry.kind, 'totp')
  assert.equal(entry.issuer, 'GitHub')
  assert.equal(entry.account, 'alice@example.com')
  assert.equal(hex(entry.secret), hex(T.decodeBase32Secret('JBSWY3DPEHPK3PXP')))
  assert.equal(entry.algo, 'SHA1')
  assert.equal(entry.digits, 6)
  assert.equal(entry.period, 30)
})

test('步骤 8：secret 的 %3D%3D（Android Uri.encode 的 =）先 URL-decode 再 base32，字节相同', () => {
  const encoded = FULL_URI.replace('secret=JBSWY3DPEHPK3PXP', 'secret=JBSWY3DPEHPK3PXP%3D%3D')
  assert.equal(
    hex(T.parseOtpAuthUri(encoded, 0).entry.secret),
    hex(T.parseOtpAuthUri(FULL_URI, 0).entry.secret),
  )
})

test('步骤 8：label 未编码（裸空格与裸冒号）仍能解析', () => {
  const { entry } = T.parseOtpAuthUri(
    'otpauth://totp/Air Canada:Benjamin X?secret=JBSWY3DPEHPK3PXP&digits=6&period=30&algorithm=SHA1',
    0,
  )
  assert.equal(entry.issuer, 'Air Canada')
  assert.equal(entry.account, 'Benjamin X')
})

test('步骤 8：query 缺 issuer 时从 label 补齐；两处不一致时以 query 为准并记 warning', () => {
  const fromLabel = T.parseOtpAuthUri(
    'otpauth://totp/OnlyLabel:acct?secret=JBSWY3DPEHPK3PXP&digits=6&period=30&algorithm=SHA1',
    0,
  )
  assert.equal(fromLabel.entry.issuer, 'OnlyLabel')
  const conflict = T.parseOtpAuthUri(
    'otpauth://totp/LabelIssuer:acct?secret=JBSWY3DPEHPK3PXP&issuer=QueryIssuer&digits=6&period=30&algorithm=SHA1',
    0,
  )
  assert.equal(conflict.entry.issuer, 'QueryIssuer', '冲突时未以 query 的 issuer 为准')
  assert.ok(
    conflict.warnings.some((w) => w.field === 'issuer'),
    'issuer 冲突未记 warning',
  )
})

test('步骤 8：label 只有 account 无 issuer 时 issuer 为空字符串', () => {
  const { entry } = T.parseOtpAuthUri(
    'otpauth://totp/plainaccount?secret=JBSWY3DPEHPK3PXP&digits=6&period=30&algorithm=SHA1',
    0,
  )
  assert.equal(entry.issuer, '')
  assert.equal(entry.account, 'plainaccount')
})

test('步骤 8：hotp 带 counter 解析成功；缺 counter 判失败', () => {
  const ok = T.parseOtpAuthUri(
    'otpauth://hotp/X:y?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&counter=42',
    0,
  )
  assert.equal(ok.entry.kind, 'hotp')
  assert.equal(ok.entry.counter, 42)
  assert.throws(
    () =>
      T.parseOtpAuthUri('otpauth://hotp/X:y?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6', 0),
    undefined,
    'hotp 缺 counter 未被拒绝',
  )
})

test('步骤 8：totp 缺 period 判失败，不静默补 30（C8）', () => {
  assert.match(
    messageOf(() =>
      T.parseOtpAuthUri('otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6', 0),
    ),
    /period/,
  )
})

test('步骤 8：scheme 不是 otpauth 判失败；otpauth-migration:// 不由本函数处理', () => {
  for (const bad of [
    'https://totp/X:y?secret=JBSWY3DPEHPK3PXP',
    'totp/X:y?secret=JBSWY3DPEHPK3PXP',
    'otpauth-migration://offline?data=abc',
  ]) {
    assert.throws(() => T.parseOtpAuthUri(bad, 0), undefined, `${bad} 未被拒绝`)
  }
})

test('步骤 8：行式批量 —— 空行跳过，非法行只记 failure 并带行号，其余照常产出（C5）', () => {
  const text = [
    FULL_URI,
    '',
    'otpauth://totp/Broken:x?secret=!!!&digits=6&period=30&algorithm=SHA1',
    '   ',
    'otpauth://hotp/Second:y?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&counter=7',
  ].join('\n')
  const result = T.parseOtpAuthLines(text)
  assert.equal(result.format, 'otpauth-lines')
  assert.equal(result.entries.length, 2)
  assert.equal(result.failures.length, 1)
  // 空行被跳过后，sourceIndex 按**非空行序号**计（第 1、2、3 个非空行 = 0、1、2），
  // 1 基的源文本行号另由 path 承载——两者是不同语义，判据只要求「带行号」
  assert.equal(result.failures[0].sourceIndex, 1)
  assert.match(
    result.failures[0].path,
    /第 3 行/,
    `failure 未带来源行号：${result.failures[0].path}`,
  )
  assert.deepEqual(
    result.entries.map((e) => e.sourceIndex),
    [0, 2],
  )
  assert.deepEqual(
    result.entries.map((e) => e.issuer),
    ['GitHub', 'Second'],
  )
})

test('步骤 8：空输入与纯空白输入返回空结果而不抛', () => {
  for (const text of ['', '   ', '\n\n\n', ' \n \n']) {
    const result = T.parseOtpAuthLines(text)
    assert.deepEqual(result.entries, [], `${JSON.stringify(text)} 产出了条目`)
    assert.equal(result.failures.length, 0)
  }
})

test('步骤 8：生成侧 padding 去除 / label 编码 / 参数全写 / issuer 两处都写', () => {
  const uri = T.generateOtpAuthUri({
    kind: 'totp',
    issuer: '航空 Air Canada',
    account: 'bob@ex ample.com',
    secret: T.decodeBase32Secret(SECRET_AIRCANADA.base32),
    algo: 'SHA256',
    digits: 7,
    period: 30,
  })
  assert.ok(uri.startsWith('otpauth://totp/'), uri)
  assert.ok(uri.includes(`secret=${SECRET_AIRCANADA.base32}`), `secret 形态不对：${uri}`)
  assert.match(uri, /algorithm=SHA256/)
  assert.match(uri, /digits=7/)
  assert.match(uri, /period=30/)
  assert.match(uri, /issuer=/, 'query 里没写 issuer')
  const label = uri.slice('otpauth://totp/'.length, uri.indexOf('?'))
  assert.ok(label.includes('%'), `label 未经 percent-encode：${label}`)
  assert.ok(decodeURIComponent(label).startsWith('航空 Air Canada:'), label)
  assert.match(
    T.generateOtpAuthUri({
      kind: 'hotp',
      issuer: 'WWE',
      account: 'Mason',
      secret: T.decodeBase32Secret(SECRET_WWE.base32),
      algo: 'SHA512',
      digits: 8,
      counter: 10300,
    }),
    /counter=10300/,
  )
})

test('步骤 8：generateOtpAuthUri → parseOtpAuthUri 往返无损', () => {
  for (const source of [
    {
      kind: 'totp',
      issuer: '航空 Air Canada',
      account: 'bob@ex ample.com:with/colon%plus+space',
      secret: T.decodeBase32Secret(SECRET_AIRCANADA.base32),
      algo: 'SHA256',
      digits: 7,
      period: 45,
    },
    {
      kind: 'hotp',
      issuer: '',
      account: 'Mason',
      secret: T.decodeBase32Secret(SECRET_WWE.base32),
      algo: 'SHA512',
      digits: 8,
      counter: 10300,
    },
  ]) {
    const { entry: back } = T.parseOtpAuthUri(T.generateOtpAuthUri(source), 0)
    assert.equal(back.kind, source.kind)
    assert.equal(back.issuer, source.issuer)
    assert.equal(back.account, source.account)
    assert.equal(hex(back.secret), hex(source.secret))
    assert.equal(back.algo, source.algo)
    assert.equal(back.digits, source.digits)
    if (source.kind === 'totp') assert.equal(back.period, source.period)
    else assert.equal(back.counter, source.counter)
  }
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 9：本 App 明文容器
// ─────────────────────────────────────────────────────────────────────────────

test('步骤 9：sealPlaintext 顶层恰为五个键，encrypted=false，format=mfavault，data 是对象', () => {
  const sealed = JSON.parse(utf8Decode(T.sealPlaintext(VAULT)))
  assert.deepEqual(Object.keys(sealed), ['format', 'version', 'schemaVersion', 'encrypted', 'data'])
  assert.equal(sealed.format, 'mfavault')
  assert.equal(sealed.encrypted, false)
  assert.equal(typeof sealed.data, 'object')
  assert.ok(sealed.data !== null)
  assert.equal(sealed.schemaVersion, sealed.data.schemaVersion)
})

test('步骤 9：seal → open 往返无损，返回对象通过 assertVaultData', () => {
  const back = T.openPlaintext(T.sealPlaintext(VAULT))
  assert.deepEqual(back, VAULT)
  assert.doesNotThrow(() => assertVaultData(back))
})

test('步骤 9：非法 VaultData 抛错而非产出文件', () => {
  assert.throws(() => T.sealPlaintext({ ...VAULT, entries: [{ ...VAULT.entries[0], digits: 9 }] }))
})

test('步骤 9：超过字节上限在 JSON.parse 之前生效（C3）', () => {
  const bytes = utf8Encode(
    JSON.stringify({
      format: 'mfavault',
      version: 1,
      schemaVersion: 1,
      encrypted: false,
      data: 'x'.repeat(T.TRANSFER_LIMITS.maxInputBytes),
    }),
  )
  assert.ok(bytes.length > T.TRANSFER_LIMITS.maxInputBytes)
  const error = thrown(() => T.openPlaintext(bytes))
  assert.ok(error instanceof T.TransferFormatError)
  assert.match(error.message, /超过上限/)
})

test('步骤 9：version / schemaVersion 高于支持值抛版本类错误并提示升级 App', () => {
  for (const patch of [{ version: 99 }, { schemaVersion: 99 }]) {
    const sealed = JSON.parse(utf8Decode(T.sealPlaintext(VAULT)))
    Object.assign(sealed, patch)
    // 判据是「抛**版本类**错误，提示升级 App（复用 `assertContainerVersion`）」——
    // 复用 vault 的版本错误类即满足，不要求一定是 TransferFormatError
    const error = thrown(() => T.openPlaintext(utf8Encode(JSON.stringify(sealed))))
    assert.ok(error instanceof Error, `${JSON.stringify(patch)} 未抛错`)
    assert.match(
      error.name,
      /Version/i,
      `${JSON.stringify(patch)} 抛的不是版本类错误：${error.name}`,
    )
    assert.match(
      error.message,
      /升级/,
      `${JSON.stringify(patch)} 的文案未提示升级 App：${error.message}`,
    )
  }
})

test('步骤 9：非 JSON / JSON 非对象 / 缺 format / encrypted=true 四种输入分别抛 TransferFormatError', () => {
  const base = JSON.parse(utf8Decode(T.sealPlaintext(VAULT)))
  assert.ok(
    thrown(() => T.openPlaintext(utf8Encode('this is not json'))) instanceof T.TransferFormatError,
  )
  assert.ok(thrown(() => T.openPlaintext(utf8Encode('[1,2,3]'))) instanceof T.TransferFormatError)
  const noFormat = { ...base }
  delete noFormat.format
  assert.ok(
    thrown(() => T.openPlaintext(utf8Encode(JSON.stringify(noFormat)))) instanceof
      T.TransferFormatError,
  )
  const encryptedError = thrown(() =>
    T.openPlaintext(utf8Encode(JSON.stringify({ ...base, encrypted: true }))),
  )
  assert.ok(encryptedError instanceof T.TransferFormatError)
  assert.match(
    encryptedError.message,
    /加密/,
    `encrypted:true 的文案未指向加密容器路径：${encryptedError.message}`,
  )
})

test('步骤 9：schemaVersion 0 经迁移链升到当前版本', () => {
  const v0 = JSON.parse(fixture('mfavault_plaintext_v0.json'))
  assert.equal(v0.schemaVersion, 0, '夹具前提变了，本条需重取证据')
  const opened = T.openPlaintext(utf8Encode(JSON.stringify(v0)))
  assert.ok(opened.schemaVersion >= 1, `未升级：${opened.schemaVersion}`)
  assert.doesNotThrow(() => assertVaultData(opened))
})

test('步骤 9：容器路径的全部错误文案不含 secret（C4）', () => {
  const bad = JSON.parse(utf8Decode(T.sealPlaintext(VAULT)))
  bad.data.entries[0].digits = 99
  assertNoSecretLeak(
    [
      messageOf(() => T.openPlaintext(utf8Encode(JSON.stringify(bad)))),
      messageOf(() => T.openPlaintext(utf8Encode('nope'))),
    ],
    SECRET_DENO.base32,
    'openPlaintext',
  )
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 10：格式探测器
// ─────────────────────────────────────────────────────────────────────────────

test('步骤 10：otpauth:// 文本 → otpauth-lines；otpauth-migration:// 不得当成普通 URI 行', () => {
  assert.equal(T.detect(FULL_URI), 'otpauth-lines')
  assert.equal(T.detect(`${FULL_URI}\n${FULL_URI}`), 'otpauth-lines')
  assert.notEqual(
    T.detect('otpauth-migration://offline?data=Ci0KFXNvbWUtc2VjcmV0EgR0ZXN0'),
    'otpauth-lines',
  )
})

test('步骤 10：format=mfavault 且 encrypted=false → mfavault-plaintext；encrypted=true 不得返回该值', () => {
  assert.equal(T.detect(fixtureBytes('mfavault_plaintext.json')), 'mfavault-plaintext')
  const sealed = JSON.parse(utf8Decode(T.sealPlaintext(VAULT)))
  assert.notEqual(
    T.detect(JSON.stringify({ ...sealed, encrypted: true, data: 'x' })),
    'mfavault-plaintext',
  )
})

test('步骤 10：Aegis 明文判据 —— header.slots 为 null 且 db 为对象时必须命中（陷阱一）', () => {
  assert.equal(T.detect(fixtureBytes('aegis_plain.json')), 'aegis')
  assert.equal(T.detect(fixtureBytes('aegis_grouped_v3.json')), 'aegis')
  const db = JSON.parse(fixture('aegis_plain.json')).db
  assert.equal(typeof db, 'object')
  assert.ok(!Array.isArray(db), '夹具前提：db 是对象而非数组')
})

test('步骤 10：2FAS 判据 —— 空 services 与 servicesEncrypted 都命中（陷阱二）', () => {
  assert.equal(T.detect(fixtureBytes('2fas_authenticator.json')), '2fas')
  assert.equal(T.detect(JSON.stringify({ schemaVersion: 4, services: [] })), '2fas')
  assert.equal(T.detect(JSON.stringify({ schemaVersion: 4, servicesEncrypted: 'abc' })), '2fas')
})

test('步骤 10：FreeOTP+ 判据（tokens + tokenOrder）', () => {
  assert.equal(T.detect(fixtureBytes('freeotp_plus.json')), 'freeotp-plus')
})

test('步骤 10：Ente 裸 URI 行与带引号的 jsonEncode JSON 行区分对待', () => {
  assert.ok(['ente', 'otpauth-lines'].includes(T.detect(fixtureBytes('ente_auth.txt'))))
  assert.ok(fixture('ente_jsonlines.txt').startsWith('"'), '夹具前提：jsonEncode 行以引号开头')
  assert.notEqual(
    T.detect(fixtureBytes('ente_jsonlines.txt')),
    'otpauth-lines',
    '带引号的 JSON 行被当成裸 URI 行',
  )
})

test('步骤 10：login_totp 表头 → bitwarden；只有 totp 表头不得判为 bitwarden 或任何 1Password 专用格式', () => {
  assert.equal(T.detect(fixtureBytes('bitwarden.csv')), 'bitwarden')
  const totpOnly = `folder,name,totp\n,Deno,${SECRET_DENO.base32}\n`
  assert.notEqual(T.detect(totpOnly), 'bitwarden')
  for (const id of T.FORMAT_IDS) {
    assert.ok(
      !/1password|onepassword|lastpass/i.test(id),
      `出现了无权威 schema 的专用格式 id：${id}`,
    )
  }
})

test('步骤 10：其他表头 CSV → generic-csv 或 undefined', () => {
  const got = T.detect(fixtureBytes('generic_csv.csv'))
  assert.ok(got === 'generic-csv' || got === undefined, `其他表头 CSV 探测为 ${got}`)
})

test('步骤 10：随机二进制 / 空输入 / null 字节 / 超长 / 非法 UTF-8 一律 undefined 且不抛异常', () => {
  for (const input of [
    new Uint8Array(0),
    '',
    new Uint8Array([0, 1, 2, 255, 254, 128]),
    new Uint8Array([0xff, 0xfe, 0xfd, 0x80]),
    utf8Encode('x'.repeat(200000)),
    new Uint8Array(Array.from({ length: 64 }, (_, i) => (i * 37) % 256)),
  ]) {
    let got
    assert.doesNotThrow(() => {
      got = T.detect(input)
    })
    assert.equal(got, undefined, `非法输入被探测为 ${got}`)
  }
})

test('步骤 10：detect 是纯函数 —— 两次调用同结果，且不修改入参', () => {
  const bytes = fixtureBytes('aegis_plain.json')
  const snapshot = Uint8Array.from(bytes)
  assert.equal(T.detect(bytes), T.detect(bytes))
  assert.equal(T.detect(fixture('bitwarden.csv')), T.detect(fixture('bitwarden.csv')))
  assert.deepEqual([...bytes], [...snapshot], 'detect 修改了入参字节')
})

test('步骤 10：全部明文夹具都被正确探测（无遗漏的未知格式）', () => {
  for (const [name, id] of Object.entries({
    'aegis_plain.json': 'aegis',
    'aegis_grouped_v3.json': 'aegis',
    'aegis_plain_grouped_v2.json': 'aegis',
    '2fas_authenticator.json': '2fas',
    'freeotp_plus.json': 'freeotp-plus',
    'mfavault_plaintext.json': 'mfavault-plaintext',
    'bitwarden.csv': 'bitwarden',
    'ente_auth.txt': 'ente',
  })) {
    const got = T.detect(fixtureBytes(name))
    assert.ok(
      got === id || (name === 'ente_auth.txt' && got === 'otpauth-lines'),
      `${name} 探测为 ${got}`,
    )
  }
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 11：Aegis 明文解析
// ─────────────────────────────────────────────────────────────────────────────

const shapeOf = (entries) =>
  entries.map((e) => [
    e.issuer,
    e.account,
    e.kind,
    e.algo,
    e.digits,
    e.kind === 'totp' ? e.period : e.counter,
  ])

test('步骤 11：aegis_plain.json 解析成功，golden 与夹具一致', () => {
  const result = T.parseAegis(fixtureBytes('aegis_plain.json'))
  assert.equal(result.format, 'aegis')
  assert.equal(result.entries.length, 6, 'steam 条目应被单条剔除，其余 6 条照常产出')
  assert.equal(result.failures.length, 1)
  assert.deepEqual(shapeOf(result.entries), [
    ['Deno', 'Mason', 'totp', 'SHA1', 6, 30],
    ['SPDX', 'James', 'totp', 'SHA256', 7, 20],
    ['Airbnb', 'Elijah', 'totp', 'SHA512', 8, 50],
    ['Issuu', 'James', 'hotp', 'SHA1', 6, 1],
    ['Air Canada', 'Benjamin', 'hotp', 'SHA256', 7, 50],
    ['WWE', 'Mason', 'hotp', 'SHA512', 8, 10300],
  ])
  assert.deepEqual(
    result.entries.map((e) => e.sourceIndex),
    [0, 1, 2, 3, 4, 5],
  )
})

test('步骤 11：entries[].name → account，entries[].issuer → issuer（字段名与本 App 相反）', () => {
  const [first] = T.parseAegis(fixture('aegis_plain.json')).entries
  assert.equal(first.account, 'Mason', 'name 未映射为 account')
  assert.equal(first.issuer, 'Deno', 'issuer 未映射为 issuer')
})

test('步骤 11：info.secret 按 base32 解为字节；大写无 padding 与带 padding 都能解', () => {
  const noPad = T.parseAegis(fixture('aegis_plain.json')).entries[0]
  assert.equal(hex(noPad.secret), hex(base64Decode(SECRET_DENO.base64)), 'C10：与其他格式字节不同')
  const json = JSON.parse(fixture('aegis_plain.json'))
  json.db.entries = [json.db.entries[0]]
  json.db.entries[0].info.secret = `${SECRET_DENO.base32.toLowerCase()}==`
  const padded = T.parseAegis(JSON.stringify(json))
  assert.equal(
    padded.failures.length,
    0,
    `带 padding 小写形态解析失败：${padded.failures[0]?.reason}`,
  )
  assert.equal(hex(padded.entries[0].secret), hex(noPad.secret))
})

test('步骤 11：db.groups + entries[].groups 还原为 tagNames；悬空 uuid 记 warning 而非失败', () => {
  const result = T.parseAegis(fixture('aegis_grouped_v3.json'))
  assert.deepEqual(
    result.tags.map((t) => t.name),
    ['工作', '个人'],
  )
  assert.deepEqual(
    result.tags.map((t) => t.sourceIndex),
    [0, 1],
  )
  assert.deepEqual([...result.entries[0].tagNames].sort(), ['个人', '工作'])
  assert.equal(result.entries[1].tagNames.length, 0, '悬空 uuid 应被丢弃而非产出空名标签')
  assert.equal(result.failures.length, 0, '悬空 uuid 被判成了整条失败')
  assert.ok(
    result.warnings.some((w) => w.sourceIndex === 1),
    '悬空 uuid 未记 warning',
  )
  assert.deepEqual(result.entries[2].tagNames, [])
  assert.equal(result.entries[0].note, '两个分组都要挂上')
})

test('步骤 11：legacy entries[].group 字符串还原为 tagNames；null → 空数组', () => {
  const legacy = T.parseAegis(fixture('aegis_plain_grouped_v2.json'))
  assert.ok(
    legacy.entries.some((e) => e.tagNames.length > 0),
    'legacy group 字符串未还原',
  )
  const json = JSON.parse(fixture('aegis_plain_grouped_v2.json'))
  json.db.entries = json.db.entries.map((e) => ({ ...e, group: null }))
  const nulled = T.parseAegis(JSON.stringify(json))
  // 夹具含 steam 条目，ADR-004 下它恒为一条 failure，与 group 无关
  assert.deepEqual(
    nulled.failures.map((f) => f.reason).filter((r) => !/不受支持/.test(r)),
    [],
    'group:null 引入了 steam 之外的失败',
  )
  for (const entry of nulled.entries) assert.deepEqual(entry.tagNames, [])
})

test('步骤 11：type 为 steam / motp / yandex 判单条失败，文案含「不受支持」（ADR-004 + C5）', () => {
  const result = T.parseAegis(fixture('aegis_plain.json'))
  assert.equal(result.failures.length, 1)
  assert.equal(result.failures[0].sourceIndex, 6)
  assert.match(result.failures[0].reason, /不受支持/)
  assert.equal(result.entries.length, 6)
  for (const type of ['steam', 'motp', 'yandex']) {
    const json = JSON.parse(fixture('aegis_plain.json'))
    json.db.entries = [{ ...json.db.entries[0], type }]
    const single = T.parseAegis(JSON.stringify(json))
    assert.equal(single.entries.length, 0, `${type} 未被拒绝`)
    assert.equal(single.failures.length, 1)
    assert.match(single.failures[0].reason, /不受支持/, `${type} 的文案缺「不受支持」`)
  }
})

test('步骤 11：info.algo 为 MD5 归一化为 SHA1 并记 warning', () => {
  const json = JSON.parse(fixture('aegis_plain.json'))
  json.db.entries = [{ ...json.db.entries[0], info: { ...json.db.entries[0].info, algo: 'MD5' } }]
  const result = T.parseAegis(JSON.stringify(json))
  assert.equal(result.entries.length, 1, result.failures[0]?.reason)
  assert.equal(result.entries[0].algo, 'SHA1')
  assert.ok(
    result.warnings.some(
      (w) => /algo/i.test(w.field) && w.sourceIndex === 0 && /MD5/.test(w.message),
    ),
    `MD5 归一化未记 warning，实得 ${JSON.stringify(result.warnings)}`,
  )
})

test('步骤 11：digits 缺失按默认值补齐并记 warning；period/counter 缺失判失败（C8）', () => {
  const noDigits = JSON.parse(fixture('aegis_plain.json'))
  noDigits.db.entries = [{ ...noDigits.db.entries[0] }]
  delete noDigits.db.entries[0].info.digits
  const digitsResult = T.parseAegis(JSON.stringify(noDigits))
  assert.equal(
    digitsResult.entries.length,
    1,
    `digits 缺失未走补齐：${digitsResult.failures[0]?.reason}`,
  )
  assert.ok(
    digitsResult.warnings.some((w) => /digits/.test(w.field) && w.sourceIndex === 0),
    `digits 补齐未记 warning，实得 ${JSON.stringify(digitsResult.warnings)}`,
  )
  assert.equal(digitsResult.entries[0].digits, 6, '未按 Aegis 默认值 6 补齐')

  const noPeriod = JSON.parse(fixture('aegis_plain.json'))
  noPeriod.db.entries = [{ ...noPeriod.db.entries[0] }]
  delete noPeriod.db.entries[0].info.period
  const periodResult = T.parseAegis(JSON.stringify(noPeriod))
  assert.equal(periodResult.entries.length, 0, 'totp 缺 period 未被拒绝（C8）')
  assert.equal(periodResult.failures.length, 1)

  const noCounter = JSON.parse(fixture('aegis_plain.json'))
  noCounter.db.entries = [noCounter.db.entries[3]]
  delete noCounter.db.entries[0].info.counter
  assert.equal(
    T.parseAegis(JSON.stringify(noCounter)).entries.length,
    0,
    'hotp 缺 counter 未被拒绝（C8）',
  )
})

test('步骤 11：_usageCount / _lastUsedTimestamp 不映射', () => {
  const json = JSON.parse(fixture('aegis_plain.json'))
  json.db.entries = [{ ...json.db.entries[0], _usageCount: 42, _lastUsedTimestamp: 1700000000000 }]
  const keys = Object.keys(T.parseAegis(JSON.stringify(json)).entries[0])
  for (const forbidden of ['usageCount', 'lastUsedAt', '_usageCount', '_lastUsedTimestamp']) {
    assert.ok(!keys.includes(forbidden), `映射了上游不导出的字段 ${forbidden}`)
  }
})

test('步骤 11：畸形样本 —— 整包结构缺失抛 TransferFormatError，单条缺失记 failure（C5）', () => {
  assert.ok(thrown(() => T.parseAegis('{}')) instanceof T.TransferFormatError, '缺 db 未抛整包错')
  assert.ok(
    thrown(() =>
      T.parseAegis(JSON.stringify({ version: 1, header: {}, db: { entries: 'x' } })),
    ) instanceof T.TransferFormatError,
  )
  const json = JSON.parse(fixture('aegis_plain.json'))
  delete json.db.entries[1].info
  const result = T.parseAegis(JSON.stringify(json))
  // 夹具末条是 steam，恒为一条 failure；删掉 entries[1].info 再叠一条，故共 2 条、剩 5 条产出
  assert.equal(result.failures.length, 2, JSON.stringify(result.failures))
  assert.equal(result.entries.length, 5, '单条缺失中止了其余条目')
  const infoFailure = result.failures.find((f) => f.sourceIndex === 1)
  assert.ok(infoFailure, `缺 info 的那条未记 failure：${JSON.stringify(result.failures)}`)
  assert.match(infoFailure.reason, /info/, '文案未点名缺失的 info')
  assert.ok(
    thrown(() => T.parseAegis(fixture('aegis_malformed.json'))) instanceof T.TransferFormatError,
  )
})

test('步骤 11：全部 failure / warning 文案不含 secret（C4）', () => {
  const texts = []
  for (const name of ['aegis_plain.json', 'aegis_grouped_v3.json', 'aegis_malformed.json']) {
    try {
      const result = T.parseAegis(fixture(name))
      texts.push(...result.failures.map((f) => f.reason), ...result.warnings.map((w) => w.message))
    } catch (error) {
      texts.push(error.message)
    }
  }
  assertNoSecretLeak(texts, SECRET_DENO.base32, 'parseAegis')
  assertNoSecretLeak(texts, SECRET_WWE.base32, 'parseAegis')
})

test('步骤 11：parseAegis 是纯函数 —— 不修改入参，两次调用结果全等', () => {
  const text = fixture('aegis_grouped_v3.json')
  assert.deepEqual(T.parseAegis(text), T.parseAegis(text))
  const bytes = fixtureBytes('aegis_plain.json')
  const snapshot = Uint8Array.from(bytes)
  T.parseAegis(bytes)
  assert.deepEqual([...bytes], [...snapshot])
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 12：2FAS
// ─────────────────────────────────────────────────────────────────────────────

test('步骤 12：services[].secret 在顶层被读取（防回归：误读 otp.secret 必然失败）', () => {
  const wrongPlace = {
    schemaVersion: 4,
    services: [
      {
        name: 'Deno',
        type: 'Manual',
        otp: {
          account: 'Mason',
          issuer: 'Deno',
          tokenType: 'TOTP',
          algorithm: 'SHA1',
          digits: 6,
          period: 30,
          secret: SECRET_DENO.base32,
        },
      },
    ],
  }
  const result = T.parseTwoFas(JSON.stringify(wrongPlace))
  assert.equal(result.entries.length, 0, '实现从 otp.secret 取到了值——陷阱一未防住')
  assert.equal(result.failures.length, 1)
})

test('步骤 12：otp.tokenType 判别 kind；services[].type 的品牌枚举不影响 kind（陷阱二）', () => {
  const result = T.parseTwoFas(
    JSON.stringify({
      schemaVersion: 4,
      services: [
        {
          name: 'Deno',
          type: 'Google',
          secret: SECRET_DENO.base32,
          otp: {
            account: 'Mason',
            issuer: 'Deno',
            tokenType: 'TOTP',
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
          },
        },
        {
          name: 'WWE',
          type: 'Unknown',
          secret: SECRET_WWE.base32,
          otp: {
            account: 'Mason',
            issuer: 'WWE',
            tokenType: 'HOTP',
            algorithm: 'SHA512',
            digits: 8,
            counter: 10300,
          },
        },
      ],
    }),
  )
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.equal(result.entries.length, 2)
  assert.equal(result.entries[0].kind, 'totp', 'services[].type=Google 干扰了 kind 判定')
  assert.equal(result.entries[1].kind, 'hotp')
  assert.equal(result.entries[1].counter, 10300)
})

test('步骤 12：tokenType=STEAM 判单条失败，文案含「不受支持」', () => {
  const result = T.parseTwoFas(
    JSON.stringify({
      schemaVersion: 4,
      services: [
        {
          name: 'Boeing',
          secret: SECRET_DENO.base32,
          otp: { tokenType: 'STEAM', algorithm: 'SHA1', digits: 5, period: 30 },
        },
        {
          name: 'Deno',
          secret: SECRET_WWE.base32,
          otp: { tokenType: 'TOTP', algorithm: 'SHA1', digits: 6, period: 30 },
        },
      ],
    }),
  )
  assert.equal(result.entries.length, 1)
  assert.equal(result.failures.length, 1)
  assert.match(result.failures[0].reason, /不受支持/)
})

test('步骤 12：kotlinx explicitNulls=false —— otp 整体缺失 / period 缺失 / counter 缺失按 C8 判定', () => {
  const build = (otp) =>
    JSON.stringify({ schemaVersion: 4, services: [{ name: 'X', secret: SECRET_DENO.base32, otp }] })
  assert.equal(T.parseTwoFas(build(undefined)).entries.length, 0, 'otp 整体缺失未判失败')
  assert.equal(
    T.parseTwoFas(build({ tokenType: 'TOTP', algorithm: 'SHA1', digits: 6 })).entries.length,
    0,
    'totp 缺 period 未判失败（C8）',
  )
  assert.equal(
    T.parseTwoFas(build({ tokenType: 'HOTP', algorithm: 'SHA1', digits: 6 })).entries.length,
    0,
    'hotp 缺 counter 未判失败（C8）',
  )
})

test('步骤 12：algorithm 为 SHA224 / SHA384 判单条失败，不回落 SHA1（C8）', () => {
  for (const algorithm of ['SHA224', 'SHA384']) {
    const result = T.parseTwoFas(
      JSON.stringify({
        schemaVersion: 4,
        services: [
          {
            name: 'X',
            secret: SECRET_DENO.base32,
            otp: { tokenType: 'TOTP', algorithm, digits: 6, period: 30 },
          },
        ],
      }),
    )
    assert.equal(result.entries.length, 0, `${algorithm} 被回落接受了`)
    assert.equal(result.failures.length, 1)
  }
})

test('步骤 12：vendored schemaVersion:1 老样本 —— 不得静默产出错乱条目', () => {
  const text = fixture('2fas_authenticator.json')
  assert.equal(JSON.parse(text).schemaVersion, 1, '夹具前提变了')
  let result
  try {
    result = T.parseTwoFas(text)
  } catch (error) {
    assert.ok(error instanceof T.TransferFormatError, `抛的不是 TransferFormatError：${error.name}`)
    return
  }
  // 该样本没有 otp.tokenType，任何「产出条目」都意味着猜了 kind（C8 违规）
  if (result.entries.length > 0) {
    assert.fail(
      `schemaVersion:1 老样本静默产出了 ${result.entries.length} 条（该样本无 tokenType）`,
    )
  }
  assert.ok(result.failures.length > 0 || result.skipped > 0, '既没产出也没记录任何失败/跳过')
})

test('步骤 12：groups 还原为 tagNames', () => {
  const result = T.parseTwoFas(
    JSON.stringify({
      schemaVersion: 4,
      groups: [
        { id: 'g1', name: '工作' },
        { id: 'g2', name: '个人' },
      ],
      services: [
        {
          name: 'Deno',
          secret: SECRET_DENO.base32,
          groupId: 'g1',
          otp: { tokenType: 'TOTP', algorithm: 'SHA1', digits: 6, period: 30 },
        },
      ],
    }),
  )
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.deepEqual([...result.entries[0].tagNames], ['工作'])
  assert.deepEqual(result.tags.map((t) => t.name).sort(), ['个人', '工作'])
})

test('步骤 12：2FAS 三份夹具（v4 正常 / edge / malformed）', () => {
  const normal = T.parseTwoFas(fixtureBytes('2fas_authenticator_plain_v4.2fas'))
  assert.ok(normal.entries.length > 0, `v4 正常样本零条目：${normal.failures[0]?.reason}`)
  const edge = T.parseTwoFas(fixtureBytes('twofas_edge.json'))
  assert.ok(edge.entries.length + edge.failures.length > 0)
  assert.ok(
    thrown(() => T.parseTwoFas(fixture('twofas_malformed.json'))) instanceof T.TransferError,
  )
})

test('步骤 12：parseTwoFas 纯函数 + C4', () => {
  // 用 v4 正常样本：vendored 的 2fas_authenticator.json 是 schemaVersion:1，按判据必然抛错，
  // 抛错路径的纯度另由「同一输入两次抛同样的错」验证
  const bytes = fixtureBytes('2fas_authenticator_plain_v4.2fas')
  assert.deepEqual(T.parseTwoFas(bytes), T.parseTwoFas(bytes))
  const snapshot = Uint8Array.from(bytes)
  T.parseTwoFas(bytes)
  assert.deepEqual([...bytes], [...snapshot], 'parseTwoFas 修改了入参')
  const oldText = fixture('2fas_authenticator.json')
  assert.equal(
    messageOf(() => T.parseTwoFas(oldText)),
    messageOf(() => T.parseTwoFas(oldText)),
  )
  const result = T.parseTwoFas(fixture('twofas_edge.json'))
  assertNoSecretLeak(
    [...result.failures.map((f) => f.reason), ...result.warnings.map((w) => w.message)],
    SECRET_DENO.base32,
    'parseTwoFas',
  )
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 13：FreeOTP+
// ─────────────────────────────────────────────────────────────────────────────

test('步骤 13：freeotp_plus.json 解析成功，golden 与夹具一致（tokenOrder 决定顺序）', () => {
  const result = T.parseFreeOtpPlus(fixtureBytes('freeotp_plus.json'))
  assert.equal(result.format, 'freeotp-plus')
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.deepEqual(shapeOf(result.entries), [
    ['WWE', 'Mason', 'hotp', 'SHA512', 8, 10299],
    ['Air Canada', 'Benjamin', 'hotp', 'SHA256', 7, 49],
    ['Issuu', 'James', 'hotp', 'SHA1', 6, 0],
    ['Airbnb', 'Elijah', 'totp', 'SHA512', 8, 50],
    ['SPDX', 'James', 'totp', 'SHA256', 7, 20],
    ['Deno', 'Mason', 'totp', 'SHA1', 6, 30],
  ])
  assert.deepEqual(
    result.entries.map((e) => e.sourceIndex),
    [0, 1, 2, 3, 4, 5],
  )
})

test('步骤 13：int 数组 secret 与其他格式的 base32 解出同一份字节（C10）', () => {
  const byIssuer = new Map(
    T.parseFreeOtpPlus(fixture('freeotp_plus.json')).entries.map((e) => [e.issuer, e]),
  )
  assert.equal(hex(byIssuer.get('WWE').secret), hex(base64Decode(SECRET_WWE.base64)))
  assert.equal(hex(byIssuer.get('Air Canada').secret), hex(base64Decode(SECRET_AIRCANADA.base64)))
  assert.equal(hex(byIssuer.get('Deno').secret), hex(base64Decode(SECRET_DENO.base64)))
  assert.equal(
    hex(byIssuer.get('WWE').secret),
    hex(
      T.decodeIntArraySecret([
        -19, 64, -59, -18, -5, -20, -50, 34, 6, -79, 93, 117, -63, 24, 42, 118,
      ]),
    ),
  )
})

test('步骤 13：kind 只由 type 决定，禁止用字段存在性推断', () => {
  const build = (token) => JSON.stringify({ tokenOrder: ['X:y'], tokens: [token] })
  const base = {
    algo: 'SHA1',
    digits: 6,
    period: 30,
    counter: 99,
    issuerExt: 'X',
    label: 'y',
    secret: [-1, 2],
  }
  const totpWithCounter = T.parseFreeOtpPlus(build({ ...base, type: 'TOTP' }))
  assert.equal(totpWithCounter.entries[0].kind, 'totp', 'TOTP 携带 counter 却被判成 hotp')
  assert.equal(totpWithCounter.entries[0].period, 30)
  const hotpWithPeriod = T.parseFreeOtpPlus(build({ ...base, type: 'HOTP' }))
  assert.equal(hotpWithPeriod.entries[0].kind, 'hotp', 'HOTP 携带 period 却被判成 totp')
  assert.equal(hotpWithPeriod.entries[0].counter, 99)
})

test('步骤 13：type 缺失或为其他值判单条失败，不靠字段存在性猜测', () => {
  const base = {
    algo: 'SHA1',
    digits: 6,
    period: 30,
    counter: 0,
    issuerExt: 'X',
    label: 'y',
    secret: [-1, 2],
  }
  for (const type of [undefined, 'time', 'counter', 'STEAM', '']) {
    const token = type === undefined ? base : { ...base, type }
    const result = T.parseFreeOtpPlus(JSON.stringify({ tokenOrder: ['X:y'], tokens: [token] }))
    assert.equal(result.entries.length, 0, `type=${JSON.stringify(type)} 未被拒绝`)
    assert.equal(result.failures.length, 1)
  }
})

test('步骤 13：int 数组越界（128 / -129）判失败，不发生 & 0xFF 截断', () => {
  for (const secret of [[-1, 128], [128], [-129]]) {
    const result = T.parseFreeOtpPlus(
      JSON.stringify({
        tokenOrder: ['X:y'],
        tokens: [
          { type: 'TOTP', algo: 'SHA1', digits: 6, period: 30, issuerExt: 'X', label: 'y', secret },
        ],
      }),
    )
    assert.equal(
      result.entries.length,
      0,
      `${JSON.stringify(secret)} 未被拒绝（可能被 & 0xFF 截断了）`,
    )
    assert.equal(result.failures.length, 1)
  }
})

test('步骤 13：tokenOrder 缺失时退回 tokens 数组顺序并记 warning', () => {
  const json = JSON.parse(fixture('freeotp_plus.json'))
  delete json.tokenOrder
  const result = T.parseFreeOtpPlus(JSON.stringify(json))
  assert.equal(result.entries.length, 6)
  assert.deepEqual(
    result.entries.map((e) => e.issuer),
    ['WWE', 'Air Canada', 'Issuu', 'Airbnb', 'SPDX', 'Deno'],
    '未退回 tokens 数组顺序',
  )
  assert.ok(
    result.warnings.some((w) => w.sourceIndex === null),
    'tokenOrder 缺失未记整包 warning',
  )
})

test('步骤 13：category 还原为单元素 tagNames；缺失时为空数组', () => {
  const result = T.parseFreeOtpPlus(fixture('freeotp_plus_edge.json'))
  const withCategory = result.entries.filter((e) => e.tagNames.length > 0)
  assert.ok(withCategory.length > 0, 'edge 夹具里没有任何 category，本条失去证据')
  for (const entry of withCategory)
    assert.equal(entry.tagNames.length, 1, 'category 被拆成了多个标签')
  const json = JSON.parse(fixture('freeotp_plus.json'))
  for (const token of json.tokens) delete token.category
  const stripped = T.parseFreeOtpPlus(JSON.stringify(json))
  assert.equal(stripped.failures.length, 0, stripped.failures[0]?.reason)
  for (const entry of stripped.entries) assert.deepEqual(entry.tagNames, [])
})

test('步骤 13：malformed 夹具按 C5 处理 —— 收集部分结果而非整包抛错', () => {
  const result = T.parseFreeOtpPlus(fixture('freeotp_plus_malformed.json'))
  assert.ok(result.failures.length > 0, '畸形 token 没有被记录成 failure')
  for (const failure of result.failures) {
    assert.equal(typeof failure.sourceIndex, 'number')
    assert.ok(failure.path.length > 0, 'failure 缺来源定位')
    assert.ok(failure.reason.length > 0, 'failure 缺原因文案')
  }
})

test('步骤 13：parseFreeOtpPlus 纯函数 + C4', () => {
  const text = fixture('freeotp_plus.json')
  assert.deepEqual(T.parseFreeOtpPlus(text), T.parseFreeOtpPlus(text))
  const result = T.parseFreeOtpPlus(fixture('freeotp_plus_edge.json'))
  assertNoSecretLeak(
    [...result.failures.map((f) => f.reason), ...result.warnings.map((w) => w.message)],
    SECRET_DENO.base32,
    'parseFreeOtpPlus',
  )
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 14：Ente
// ─────────────────────────────────────────────────────────────────────────────

test('步骤 14：ente_auth.txt 裸 URI 行解析成功，golden 与夹具一致', () => {
  const result = T.parseEnte(fixtureBytes('ente_auth.txt'))
  assert.equal(result.format, 'ente')
  // 夹具共 7 行，第 3 行是 otpauth://steam/…，按 ADR-004 判单条失败，其余 6 条产出。
  // golden 由 QA 逐行读取夹具原文独立推导（含第 7 行 WWE 同时带 period 与 counter，
  // host 是 hotp 故取 counter=10300——「kind 只由来源类型决定，不按字段存在性推断」）
  assert.equal(result.failures.length, 1, JSON.stringify(result.failures))
  assert.equal(result.failures[0].sourceIndex, 2)
  assert.match(result.failures[0].reason, /不受支持/)
  assert.deepEqual(shapeOf(result.entries), [
    ['Air Canada', 'Benjamin', 'hotp', 'SHA256', 7, 50],
    ['Airbnb', 'Elijah', 'totp', 'SHA512', 8, 50],
    ['Deno', 'Mason', 'totp', 'SHA1', 6, 30],
    ['Issuu', 'James', 'hotp', 'SHA1', 6, 1],
    ['SPDX', 'James', 'totp', 'SHA256', 7, 20],
    ['WWE', 'Mason', 'hotp', 'SHA512', 8, 10300],
  ])
  assert.deepEqual(
    result.entries.map((e) => e.sourceIndex),
    [0, 1, 3, 4, 5, 6],
  )
  // 夹具的 codeDisplay 均无 position 字段，故全部取默认值、保持文件原序
  assert.ok(
    result.entries.every((e) => !('position' in e)),
    'ParsedEntry 出现了 position 字段',
  )
})

test('步骤 14：带引号的 jsonEncode JSON 行也能解析，且不被当裸 URI 静默失败', () => {
  const result = T.parseEnte(fixture('ente_jsonlines.txt'))
  assert.ok(result.entries.length > 0, `jsonEncode 行零条目产出：${result.failures[0]?.reason}`)
  assert.ok(result.entries.every((e) => e.secret.length > 0))
})

const enteLine = (codeDisplay, secret = SECRET_DENO.base32, issuer = 'Deno') =>
  `otpauth://totp/${issuer}:Mason?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30` +
  (codeDisplay === null ? '' : `&codeDisplay=${codeDisplay}`)

test('步骤 14：codeDisplay 百分号编码 JSON → note 与 tags', () => {
  const cd = encodeURIComponent(
    JSON.stringify({
      pinned: false,
      trashed: false,
      lastUsedAt: 0,
      tapCount: 0,
      tags: ['工作', '个人'],
      note: '来自 Ente 的备注',
    }),
  )
  const result = T.parseEnte(enteLine(cd))
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.deepEqual([...result.entries[0].tagNames], ['工作', '个人'])
  assert.equal(result.entries[0].note, '来自 Ente 的备注')
})

test('步骤 14：只有 5 个字段的旧 codeDisplay 同样能解析', () => {
  const old = encodeURIComponent(
    JSON.stringify({ pinned: false, trashed: false, lastUsedAt: 0, tapCount: 0, tags: [] }),
  )
  const result = T.parseEnte(enteLine(old))
  assert.equal(result.failures.length, 0, `旧形态被判失败：${result.failures[0]?.reason}`)
  assert.equal(result.entries.length, 1)
})

test('步骤 14：trashed=true 被跳过并记 warning，不产出 entry', () => {
  const cd = encodeURIComponent(
    JSON.stringify({ pinned: false, trashed: true, lastUsedAt: 0, tapCount: 0, tags: [] }),
  )
  const result = T.parseEnte(enteLine(cd))
  assert.equal(result.entries.length, 0, 'trashed 条目被产出了')
  assert.equal(result.failures.length, 0, 'trashed 是跳过不是失败')
  assert.ok(result.skipped >= 1 || result.warnings.length >= 1, 'trashed 既没计数也没告警')
  assert.ok(
    result.warnings.some((w) => /trashed/i.test(w.field + w.message)),
    '未记 trashed warning',
  )
})

test('步骤 14：codeDisplay.position 用于排序，但其值不出现在 ParsedEntry 任何字段', () => {
  // position 取 100/200/300，与 digits(6) / period(30) / sourceIndex(0..2) 均不碰撞，
  // 这样「值不出现在任何字段里」才可判定
  const mk = (position, issuer) => {
    const cd = encodeURIComponent(
      JSON.stringify({
        pinned: false,
        trashed: false,
        lastUsedAt: 0,
        tapCount: 0,
        tags: [],
        position,
      }),
    )
    return enteLine(cd, SECRET_DENO.base32, issuer)
  }
  const result = T.parseEnte(`${mk(300, 'third')}\n${mk(100, 'first')}\n${mk(200, 'second')}`)
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.deepEqual(
    result.entries.map((e) => e.issuer),
    ['first', 'second', 'third'],
    '输出未按 codeDisplay.position 升序排列',
  )
  // position 重排的是 sourceIndex 序列：它不再随输出递增，而是保留各自的源行序号
  assert.deepEqual(
    result.entries.map((e) => e.sourceIndex),
    [1, 2, 0],
    'sourceIndex 序列未被 position 重排',
  )
  for (const entry of result.entries) {
    assert.ok(!('position' in entry), 'ParsedEntry 出现了 position 字段（design 方案 A 不变量）')
    for (const [field, value] of Object.entries(entry)) {
      assert.ok(
        ![100, 200, 300].includes(value),
        `position 的值泄漏进了字段 ${field}（判据要求其值不出现在任何字段里）`,
      )
    }
  }
})

test('步骤 14：pinned/tapCount/lastUsedAt/iconSrc/iconID 不映射，各产生一条「未导入」warning', () => {
  const cd = encodeURIComponent(
    JSON.stringify({
      pinned: true,
      trashed: false,
      lastUsedAt: 1700000000,
      tapCount: 9,
      tags: [],
      iconSrc: 'http://x/y.png',
      iconID: 'abc',
    }),
  )
  const result = T.parseEnte(enteLine(cd))
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  const keys = Object.keys(result.entries[0])
  for (const forbidden of ['pinned', 'tapCount', 'lastUsedAt', 'iconSrc', 'iconID', 'usageCount']) {
    assert.ok(!keys.includes(forbidden), `映射了不该映射的字段 ${forbidden}`)
  }
  const fields = new Set(result.warnings.map((w) => w.field))
  for (const field of ['pinned', 'tapCount', 'lastUsedAt', 'iconSrc', 'iconID']) {
    // 实测 field 命名为 `codeDisplay.<原名>`（带路径前缀），故按后缀匹配
    assert.ok(
      [...fields].some((f) => f === field || f.endsWith(`.${field}`)),
      `缺 ${field} 的「字段未导入」warning，实得 ${[...fields].join(',')}`,
    )
  }
  for (const field of ['pinned', 'tapCount', 'lastUsedAt', 'iconSrc', 'iconID']) {
    const hit = result.warnings.find((w) => w.field === field || w.field.endsWith(`.${field}`))
    assert.match(
      hit.message,
      /未导入/,
      `${field} 的 warning 文案不是「字段未导入」：${hit.message}`,
    )
  }
  // trashed / note / tags 是**要**映射的三项，不得出现在未导入告警里
  for (const field of ['trashed', 'note', 'tags']) {
    assert.ok(
      !result.warnings.some((w) => w.field === field || w.field.endsWith(`.${field}`)),
      `${field} 是应映射字段，却被记成「未导入」`,
    )
  }
})

test('步骤 14：同文件内 algorithm 大小写混用全部归一化；Dart 枚举泄漏形式也接受', () => {
  const mk = (algorithm) =>
    `otpauth://totp/Deno:Mason?secret=${SECRET_DENO.base32}&issuer=Deno&algorithm=${encodeURIComponent(algorithm)}&digits=6&period=30`
  const result = T.parseEnte(
    [mk('sha1'), mk('SHA-256'), mk('algorithm.sha512'), mk('HmacSHA1')].join('\n'),
  )
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.deepEqual(
    result.entries.map((e) => e.algo),
    ['SHA1', 'SHA256', 'SHA512', 'SHA1'],
  )
})

test('步骤 14：codeDisplay 非法时该条仍按 URI 其余部分解析成功并记 warning', () => {
  const result = T.parseEnte(enteLine('%7Bnot-json'))
  assert.equal(result.entries.length, 1, '附加参数非法导致可用密钥被丢弃')
  assert.equal(result.failures.length, 0)
  assert.equal(hex(result.entries[0].secret), hex(base64Decode(SECRET_DENO.base64)))
  assert.ok(
    result.warnings.some((w) => /codeDisplay/i.test(w.field + w.message)),
    'codeDisplay 非法未记 warning',
  )
})

test('步骤 14：parseEnte 纯函数 + C4 + edge/malformed 夹具', () => {
  const text = fixture('ente_auth.txt')
  assert.deepEqual(T.parseEnte(text), T.parseEnte(text))
  const bytes = fixtureBytes('ente_auth.txt')
  const snapshot = Uint8Array.from(bytes)
  T.parseEnte(bytes)
  assert.deepEqual([...bytes], [...snapshot], 'parseEnte 修改了入参')
  const edge = T.parseEnte(fixtureBytes('ente_edge.txt'))
  assert.ok(edge.entries.length + edge.failures.length > 0)
  // malformed 夹具按 C5 收集部分结果，不是整包抛错
  const malformed = T.parseEnte(fixture('otpauth_malformed.txt'))
  assert.ok(malformed.failures.length > 0, '畸形行没有被记录成 failure')
  assertNoSecretLeak(
    [
      ...edge.failures.map((f) => f.reason),
      ...edge.warnings.map((w) => w.message),
      ...malformed.failures.map((f) => `${f.path} ${f.reason}`),
    ],
    SECRET_DENO.base32,
    'parseEnte',
  )
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 15（R1 冻结）：Bitwarden CSV
// ─────────────────────────────────────────────────────────────────────────────

test('步骤 15：bitwarden.csv golden —— URI 形态全取自 URI，steam 行单条失败', () => {
  const result = T.parseBitwarden(fixtureBytes('bitwarden.csv'))
  assert.equal(result.format, 'bitwarden')
  assert.deepEqual(shapeOf(result.entries), [
    ['Deno', 'Mason', 'totp', 'SHA1', 6, 30],
    ['SPDX', 'James', 'totp', 'SHA256', 7, 20],
    ['Airbnb', 'Elijah', 'totp', 'SHA512', 8, 50],
  ])
  // 夹具的 name 是 Test 1..4、login_username 全空；R1 修订 2 定为 URI 形态以 URI 为准
  assert.equal(result.failures.length, 1)
  assert.equal(result.failures[0].sourceIndex, 3)
  assert.match(result.failures[0].reason, /Steam/)
  assert.match(result.failures[0].reason, /不受支持/)
})

test('步骤 15：bitwarden_edge.csv（别名列名形态）golden', () => {
  const result = T.parseBitwarden(fixtureBytes('bitwarden_edge.csv'))
  // golden 由 QA 逐行读取夹具独立推导。夹具 8 个数据行：
  //   0 Deno（裸 base32 + 引号内换行的 notes + folder + favorite=1）→ 成功
  //   1 Airbnb（URI 形态，username 与 URI 的 account 冲突）→ 成功
  //   2 Issuu（otpauth://hotp 但缺 counter）→ 失败（C8：不得静默置 0）
  //   3 WWE（URI 形态 hotp counter=10300）→ 成功
  //   4 Boeing（steam://）→ 失败（ADR-004）
  //   5 航空 张三（totp 空）→ skipped
  //   6 Secure Note（type=note，totp 空）→ skipped
  //   7 SPDX（URI 形态 + folder=Personal + favorite=1 + notes 含 # 与 %）→ 成功
  assert.equal(result.failures.length, 2, `期望 2 条失败，实得 ${JSON.stringify(result.failures)}`)
  assert.deepEqual(
    result.failures.map((f) => f.sourceIndex),
    [2, 4],
  )
  assert.match(result.failures[0].reason, /counter/, '缺 counter 的文案未点名 counter')
  assert.match(result.failures[1].reason, /Steam/)
  assert.match(result.failures[1].reason, /不受支持/)
  assert.equal(result.skipped, 2, `空 totp 行的跳过数不对：${result.skipped}`)
  assert.deepEqual(shapeOf(result.entries), [
    ['Deno', 'alice@example.com', 'totp', 'SHA1', 6, 30],
    ['Airbnb', 'Elijah', 'totp', 'SHA512', 8, 50],
    ['WWE', 'Mason', 'hotp', 'SHA512', 8, 10300],
    ['SPDX', 'James', 'totp', 'SHA256', 7, 20],
  ])
  assert.deepEqual(
    result.entries.map((e) => e.sourceIndex),
    [0, 1, 3, 7],
  )
  assert.equal(
    result.entries[0].note,
    '备注含 "引号"、逗号, 和\n换行',
    'notes 未按原样保留（含换行与引号）',
  )
  assert.deepEqual(
    [...result.entries[0].tagNames],
    ['Work/Servers'],
    'folder 未还原为单元素 tagNames',
  )
  assert.equal(result.entries[0].favorite, true, 'favorite="1" 未判为 true')
  assert.equal(result.entries[1].favorite, false, 'favorite="0" 被判为 true')
  assert.equal(result.entries[3].note, '含 # 与 %', 'notes 里的 # 与 % 未原样保留')
  assert.deepEqual([...result.entries[3].tagNames], ['Personal'])
  assert.equal(result.entries[3].favorite, true)
})

test('步骤 15：读取的是 login_totp 列；缺失时回退 totp 别名列（R1 修订 3）', () => {
  assert.equal(
    T.parseBitwarden(fixture('bitwarden.csv')).entries.length,
    3,
    'login_totp 列未被读取',
  )
  const aliasOnly = `folder,favorite,type,name,notes,totp\n,,login,Deno,,${SECRET_DENO.base32}\n`
  const result = T.parseBitwarden(aliasOnly)
  assert.equal(result.entries.length, 1, 'totp 别名列未被接受')
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
})

test('步骤 15：探测器判据不变 —— 只有裸 totp 列的 CSV 被 detect 识别为 generic-csv 而非 bitwarden', () => {
  const aliasOnly = `folder,favorite,type,name,notes,totp\n,,login,Deno,,${SECRET_DENO.base32}\n`
  assert.notEqual(T.detect(aliasOnly), 'bitwarden')
  assert.equal(T.detect(aliasOnly), 'generic-csv')
})

test('步骤 15：按列名取值 —— 列顺序整体调换后解析结果不变', () => {
  const original = T.parseBitwarden(fixture('bitwarden.csv'))
  const lines = fixture('bitwarden.csv').trimEnd().split('\n')
  const reversed = T.parseBitwarden(
    lines.map((line) => line.split(',').reverse().join(',')).join('\n'),
  )
  assert.deepEqual(
    shapeOf(reversed.entries),
    shapeOf(original.entries),
    '列顺序调换改变了解析结果（说明按位置取值）',
  )
  assert.deepEqual(
    reversed.failures.map((f) => f.sourceIndex),
    original.failures.map((f) => f.sourceIndex),
  )
})

test('步骤 15：裸 base32 形态默认 digits=6/period=30/SHA1，且每个默认值各记一条 warning（C8）', () => {
  const result = T.parseBitwarden(
    `folder,favorite,type,name,notes,login_username,login_totp\n,,login,Deno,,mason,${SECRET_DENO.base32}\n`,
  )
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  const [entry] = result.entries
  assert.equal(entry.digits, 6)
  assert.equal(entry.algo, 'SHA1')
  assert.equal(entry.kind, 'totp')
  assert.equal(entry.period, 30)
  assert.equal(entry.counter, undefined, '裸 base32 被静默置了 counter=0（§2.1 禁止）')
  const fields = result.warnings.map((w) => w.field)
  for (const field of ['digits', 'period', 'algorithm']) {
    assert.ok(fields.includes(field), `缺 ${field} 的默认值 warning，实得 ${fields.join(',')}`)
  }
})

test('步骤 15：login_totp 为空的行跳过且不计入 failures，计入 skipped', () => {
  const result = T.parseBitwarden(`folder,name,login_totp\n,A,\n,B,${SECRET_DENO.base32}\n,C,\n`)
  assert.equal(result.entries.length, 1)
  assert.equal(result.failures.length, 0, '空 totp 行被当成了错误')
  assert.equal(result.skipped, 2)
})

test('步骤 15：login_totp 不做逗号拆分 —— 含逗号的单格原样交给 URI 解析器（R1 修订 1）', () => {
  const uri =
    'otpauth://totp/Air Canada:Benjamin X?secret=' +
    SECRET_DENO.base32 +
    '&issuer=Deno&algorithm=SHA1&digits=6&period=30'
  const result = T.parseBitwarden(`folder,name,login_totp\n,Deno,"${uri}"\n`)
  assert.equal(result.failures.length, 0, `含逗号的单格被拆坏了：${result.failures[0]?.reason}`)
  assert.equal(result.entries.length, 1, '含逗号的单格被拆成了多条')
  assert.equal(result.entries[0].account, 'Benjamin X')
  assert.equal(result.entries[0].issuer, 'Deno')
})

test('步骤 15：URI 形态下 issuer 以 URI 为准，与 name 冲突时记 warning（R1 修订 2）', () => {
  // 显式构造而非 replace：FULL_URI 里 `GitHub` 先出现在 label 上，
  // 直接 replace 会只改掉 label 而把 query 的 issuer=GitHub 留下，测不到「冲突时以 URI 为准」。
  // label 与 query 的 issuer 故意写成一致，隔离掉步骤 8 那条 label/query 冲突告警，
  // 使本条只观测「name 列 vs URI」这一个冲突
  const uri =
    'otpauth://totp/UriIssuer:uri@example.com?secret=JBSWY3DPEHPK3PXP' +
    '&issuer=UriIssuer&algorithm=SHA1&digits=6&period=30'
  const result = T.parseBitwarden(
    `folder,name,login_username,login_totp\n,Conflict Name,uri@example.com,"${uri}"\n`,
  )
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.equal(result.entries.length, 1)
  assert.equal(
    result.entries[0].issuer,
    'UriIssuer',
    'issuer 未以 URI 为准（被 name 列静默覆盖了）',
  )
  // R1 修订 2 未冻结 warning 的 field 取值（实测用源列名 name），只要求「记一条 warning，不得静默覆盖」
  const conflict = result.warnings.filter(
    (w) => /issuer/.test(w.message) && /name/.test(w.field + w.message),
  )
  assert.equal(
    conflict.length,
    1,
    `name 与 URI 的 issuer 冲突应记恰一条 warning，实得 ${JSON.stringify(result.warnings)}`,
  )
})

test('步骤 15：URI 形态下 account 以 URI 为准，与 login_username 冲突时记 warning（R1 修订 2）', () => {
  const uri =
    'otpauth://totp/UriIssuer:uri@example.com?secret=JBSWY3DPEHPK3PXP' +
    '&issuer=UriIssuer&algorithm=SHA1&digits=6&period=30'
  const result = T.parseBitwarden(
    `folder,name,login_username,login_totp\n,UriIssuer,conflict@example.com,"${uri}"\n`,
  )
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.equal(result.entries[0].account, 'uri@example.com', 'account 未以 URI 为准')
  const conflict = result.warnings.filter((w) => /account/.test(w.message))
  assert.equal(
    conflict.length,
    1,
    `login_username 与 URI 的 account 冲突应记恰一条 warning，实得 ${JSON.stringify(result.warnings)}`,
  )
  assert.equal(result.entries[0].issuer, 'UriIssuer', 'name 与 URI 一致时不应改变 issuer')
})

test('步骤 15：裸 base32 形态下 issuer/account 取自 name / login_username', () => {
  const [entry] = T.parseBitwarden(
    `folder,name,login_username,login_totp\n,Deno Name,mason@x.io,${SECRET_DENO.base32}\n`,
  ).entries
  assert.equal(entry.issuer, 'Deno Name')
  assert.equal(entry.account, 'mason@x.io')
})

test('步骤 15：notes → note；三个身份列缺失或为空时留空且不记 warning', () => {
  const [entry] = T.parseBitwarden(
    `name,login_username,notes,login_totp\nDeno,mason,一条备注,${SECRET_DENO.base32}\n`,
  ).entries
  assert.equal(entry.note, '一条备注')
  const bare = T.parseBitwarden(`login_totp\n${SECRET_DENO.base32}\n`)
  assert.equal(bare.failures.length, 0, bare.failures[0]?.reason)
  assert.equal(bare.entries[0].issuer, '')
  assert.equal(bare.entries[0].account, '')
  assert.equal(bare.entries[0].note, '')
  assert.ok(
    !bare.warnings.some((w) => ['issuer', 'account', 'note'].includes(w.field)),
    '身份列缺失记了 warning（R1 修订 2 要求不记）',
  )
})

test('步骤 15：collections 列存在 → 一条 sourceIndex:null 整包 warning，值按逗号拆分并入 tagNames（R1 修订 4）', () => {
  const result = T.parseBitwarden(
    `folder,name,collections,login_totp\nWork,Deno,"Org A,Org B",${SECRET_DENO.base32}\n`,
  )
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  const whole = result.warnings.filter(
    (w) => w.sourceIndex === null && /collections/i.test(w.field + w.message),
  )
  assert.equal(whole.length, 1, `collections 的整包 warning 应恰为一条，实得 ${whole.length}`)
  assert.deepEqual([...result.entries[0].tagNames].sort(), ['Org A', 'Org B', 'Work'])
})

test('步骤 15：无 collections 列时不发该整包 warning', () => {
  const result = T.parseBitwarden(`folder,name,login_totp\nWork,Deno,${SECRET_DENO.base32}\n`)
  assert.ok(
    !result.warnings.some((w) => /collections/i.test(w.field + w.message)),
    'CSV 里没有 collections 列却发了 warning',
  )
})

test('步骤 15：type 列不单独处理（R1 修订 5）—— note 行由空 totp 天然覆盖', () => {
  const result = T.parseBitwarden(
    'folder,favorite,type,name,notes,login_totp\n,,note,Secure Note,没有 totp 的备注行,\n',
  )
  assert.equal(result.entries.length, 0)
  assert.equal(result.failures.length, 0, 'note 行被判成了失败')
  assert.equal(result.skipped, 1)
})

test('步骤 15：bitwarden_malformed.csv —— 畸形行走 C5 单条失败并带行号，合法行照常', () => {
  const result = T.parseBitwarden(fixtureBytes('bitwarden_malformed.csv'))
  assert.ok(result.entries.length > 0, '合法行没有照常产出')
  assert.ok(result.failures.length > 0, '畸形行没有被记录')
  for (const failure of result.failures) {
    assert.equal(typeof failure.sourceIndex, 'number')
    assert.ok(failure.sourceIndex >= 0, '行号非法')
  }
})

test('步骤 15：整包闸门 —— 单元格长度 / 字节数超限抛 TransferFormatError，文案含「超过上限」', () => {
  const cellError = thrown(() =>
    T.parseBitwarden(
      `name,login_totp\nA,"${'x'.repeat(T.TRANSFER_LIMITS.maxCsvCellLength + 1)}"\n`,
    ),
  )
  assert.ok(cellError instanceof T.TransferFormatError)
  assert.match(cellError.message, /超过上限/)
  const bytesError = thrown(() =>
    T.parseBitwarden(
      utf8Encode(`name,login_totp\nA,${'y'.repeat(T.TRANSFER_LIMITS.maxInputBytes + 10)}\n`),
    ),
  )
  assert.ok(bytesError instanceof T.TransferFormatError)
  assert.match(bytesError.message, /超过上限/)
})

test('步骤 15：parseBitwarden 纯函数 + C4', () => {
  const text = fixture('bitwarden_edge.csv')
  assert.deepEqual(T.parseBitwarden(text), T.parseBitwarden(text))
  const bytes = fixtureBytes('bitwarden.csv')
  const snapshot = Uint8Array.from(bytes)
  T.parseBitwarden(bytes)
  assert.deepEqual([...bytes], [...snapshot], 'parseBitwarden 修改了入参')
  const result = T.parseBitwarden(text)
  assertNoSecretLeak(
    [...result.failures.map((f) => f.reason), ...result.warnings.map((w) => w.message)],
    SECRET_DENO.base32,
    'parseBitwarden',
  )
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 16（R2 / R2b 冻结）：通用 CSV 手动列映射
// ─────────────────────────────────────────────────────────────────────────────

/** R2 修订 6 为 generic_csv.csv 冻结的映射（列名由 QA 独立读取夹具表头得到）。 */
const GENERIC_MAPPING = {
  secret: '密钥',
  issuer: '服务商',
  account: '账户',
  algo: '算法',
  digits: '位数',
  period: '周期',
  kind: '类型',
  counter: '计数器',
  tagNames: '标签',
  note: '备注',
}

test('步骤 16：generic_csv.csv golden —— 4 条全成功（混合 kind + 分号多标签 + 引用单元格）', () => {
  const result = T.parseGenericCsv(fixtureBytes('generic_csv.csv'), GENERIC_MAPPING)
  assert.equal(result.format, 'generic-csv')
  assert.equal(result.failures.length, 0, JSON.stringify(result.failures))
  assert.equal(result.entries.length, 4)
  assert.deepEqual(shapeOf(result.entries), [
    ['Deno', 'Mason', 'totp', 'SHA1', 6, 30],
    ['WWE', 'Mason', 'hotp', 'SHA512', 8, 10300],
    ['航空 Air Canada', 'Benjamin', 'hotp', 'SHA256', 7, 50],
    ['SPDX', 'James', 'totp', 'SHA256', 7, 20],
  ])
  assert.deepEqual([...result.entries[0].tagNames], ['工作'])
  assert.deepEqual(
    [...result.entries[1].tagNames],
    ['工作', '个人'],
    '分号多标签未按默认分隔符拆分',
  )
  assert.equal(result.entries[0].note, '自定义列名的通用 CSV')
  assert.equal(result.entries[2].note, '含 "引号" 与, 逗号', '引用单元格内的引号与逗号未还原')
  assert.equal(result.entries[3].note, '备注含\n换行', '引用单元格内的换行未还原')
  assert.equal(result.entries[1].note, '', '空备注未留空')
  assert.deepEqual(
    result.entries.map((e) => e.sourceIndex),
    [0, 1, 2, 3],
    'sourceIndex 应等于 rowIndex',
  )
  assert.deepEqual(result.tags, [], 'ImportResult.tags 未固定为空数组')
  assert.ok(
    result.entries.every((e) => e.favorite === false),
    'favorite 未固定为 false',
  )
})

test('步骤 16：C10 —— 通用 CSV 解出的 secret 与其他格式字节相同', () => {
  const result = T.parseGenericCsv(fixture('generic_csv.csv'), GENERIC_MAPPING)
  assert.equal(hex(result.entries[0].secret), hex(base64Decode(SECRET_DENO.base64)))
  assert.equal(hex(result.entries[1].secret), hex(base64Decode(SECRET_WWE.base64)))
  assert.equal(hex(result.entries[2].secret), hex(base64Decode(SECRET_AIRCANADA.base64)))
})

test('步骤 16：映射由调用方参数提供 —— 同一 CSV 传两套映射得两套结果（A3）', () => {
  // 两套映射都必须映射齐 algo/digits/period：R2 修订 5 下裸 base32 行缺这三项一律单条失败，
  // 只映射 secret/issuer/account 会得到零条目，测不出「两套映射两套结果」
  const csv = 'colA,colB,secretCol,al,d,p\nIssuerOne,AcctOne,JBSWY3DPEHPK3PXP,SHA1,6,30\n'
  const resultA = T.parseGenericCsv(csv, {
    secret: 'secretCol',
    issuer: 'colA',
    account: 'colB',
    algo: 'al',
    digits: 'd',
    period: 'p',
  })
  const resultB = T.parseGenericCsv(csv, {
    secret: 'secretCol',
    issuer: 'colB',
    account: 'colA',
    algo: 'al',
    digits: 'd',
    period: 'p',
  })
  assert.equal(resultA.failures.length, 0, resultA.failures[0]?.reason)
  assert.equal(resultB.failures.length, 0, resultB.failures[0]?.reason)
  assert.equal(resultA.entries[0].issuer, 'IssuerOne')
  assert.equal(resultA.entries[0].account, 'AcctOne')
  assert.equal(resultB.entries[0].issuer, 'AcctOne')
  assert.equal(resultB.entries[0].account, 'IssuerOne')
  assert.notEqual(resultA.entries[0].issuer, resultB.entries[0].issuer, '两套映射得到同一结果')
})

test('步骤 16：实现内不存在硬编码的产品列名（A3）—— 未映射的 issuer/account 必须留空', () => {
  const csv =
    'issuer,account,secret,algorithm,digits,period\nDeno,Mason,JBSWY3DPEHPK3PXP,SHA1,6,30\n'
  const result = T.parseGenericCsv(csv, {
    secret: 'secret',
    algo: 'algorithm',
    digits: 'digits',
    period: 'period',
  })
  assert.equal(result.entries[0].issuer, '', '未映射 issuer 却拿到了值——实现内硬编码了列名')
  assert.equal(result.entries[0].account, '', '未映射 account 却拿到了值——实现内硬编码了列名')
})

test('步骤 16：secret 映射必填', () => {
  assert.throws(() => T.parseGenericCsv('a,b\n1,2\n', {}), undefined, 'secret 缺失未被拒绝')
})

test('步骤 16：映射列在表头中不存在 → TransferFormatError，文案只点名映射目标与可用列数量（R2 修订 1）', () => {
  const csv = 'colA,colB\nSECRETVALUE,other\n'
  const error = thrown(() => T.parseGenericCsv(csv, { secret: 'missingColumn' }))
  assert.ok(error instanceof T.TransferFormatError, `抛的不是 TransferFormatError：${error.name}`)
  assert.ok(!error.message.includes('colA'), '文案回显了表头单元格原文（R2 修订 1 / C4）')
  assert.ok(!error.message.includes('colB'), '文案回显了表头单元格原文')
  assert.ok(
    !error.message.includes('SECRETVALUE'),
    '文案可能回显了首行数据（无表头时那就是 secret）',
  )
  assert.match(error.message, /2/, '文案未给出可用列数量')
})

test('步骤 16：secret 列支持裸 base32 与 otpauth:// URI 两形态；解码失败按单条 failure；空白按 skipped', () => {
  // 裸 base32 不携带任何参数，R2 修订 5 下必须映射齐 algo/digits/period 才能成功
  const bareMapping = { secret: 's', algo: 'al', digits: 'd', period: 'p' }
  const rows = [
    's,al,d,p',
    'JBSWY3DPEHPK3PXP,SHA1,6,30',
    `"${FULL_URI}",SHA1,6,30`,
    '!!!not-base32!!!,SHA1,6,30',
    '   ,SHA1,6,30',
    ',SHA1,6,30',
  ]
  const result = T.parseGenericCsv(rows.join('\n') + '\n', bareMapping)
  assert.equal(
    result.entries.length,
    2,
    `期望 2 条成功，实得 ${result.entries.length}：${JSON.stringify(result.failures)}`,
  )
  assert.equal(
    hex(result.entries[0].secret),
    hex(result.entries[1].secret),
    '裸 base32 与 URI 两种形态未解出同一份字节（C10）',
  )
  assert.equal(result.failures.length, 1, JSON.stringify(result.failures))
  assert.equal(result.failures[0].sourceIndex, 2)
  assert.match(result.failures[0].reason, /base32/)
  assert.equal(result.skipped, 2, `空白与空单元格应按 skipped 处理，实得 ${result.skipped}`)
})

test('步骤 16（R2b）：URI 形态在「只映射 secret」这一最常见用法下仍然可用', () => {
  const result = T.parseGenericCsv(`s\n"${FULL_URI}"\nJBSWY3DPEHPK3PXP\n`, { secret: 's' })
  // 第 1 行是 URI，参数全在 URI 里 → 成功；第 2 行是裸 base32，缺 algo/digits/period → 单条失败
  assert.equal(result.entries.length, 1, JSON.stringify(result.failures))
  assert.equal(result.entries[0].issuer, 'GitHub')
  assert.equal(result.failures.length, 1)
  assert.equal(result.failures[0].sourceIndex, 1)
})

test('步骤 16（R2b）：URI 形态下 issuer/account 以 URI 为准并记冲突 warning；其余映射列以映射列为准', () => {
  const csv = `issuer,account,secret,algorithm,digits,period\nMappingIssuer,MappingAcct,"${FULL_URI}",SHA512,8,45\n`
  const result = T.parseGenericCsv(csv, {
    secret: 'secret',
    issuer: 'issuer',
    account: 'account',
    algo: 'algorithm',
    digits: 'digits',
    period: 'period',
  })
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  const [entry] = result.entries
  assert.equal(entry.issuer, 'GitHub', 'issuer 未以 URI 为准')
  assert.equal(entry.account, 'alice@example.com', 'account 未以 URI 为准')
  assert.equal(entry.algo, 'SHA512', 'algo 未以映射列为准（R2b 三级优先级）')
  assert.equal(entry.digits, 8, 'digits 未以映射列为准')
  assert.equal(entry.period, 45, 'period 未以映射列为准')
  assert.ok(
    result.warnings.some((w) => w.field === 'issuer'),
    'issuer 冲突未记 warning',
  )
})

test('步骤 16：七个可选映射项全部生效', () => {
  const hotp = T.parseGenericCsv(
    's,i,a,k,al,d,c,n,t\nJBSWY3DPEHPK3PXP,Iss,Acct,hotp,SHA256,7,99,一条备注,甲;乙\n',
    {
      secret: 's',
      issuer: 'i',
      account: 'a',
      kind: 'k',
      algo: 'al',
      digits: 'd',
      counter: 'c',
      note: 'n',
      tagNames: 't',
    },
  )
  assert.equal(hotp.failures.length, 0, hotp.failures[0]?.reason)
  const [entry] = hotp.entries
  assert.equal(entry.issuer, 'Iss')
  assert.equal(entry.account, 'Acct')
  assert.equal(entry.kind, 'hotp')
  assert.equal(entry.algo, 'SHA256')
  assert.equal(entry.digits, 7)
  assert.equal(entry.counter, 99)
  assert.equal(entry.note, '一条备注')
  assert.deepEqual([...entry.tagNames], ['甲', '乙'])
  const totp = T.parseGenericCsv(
    's,i,a,k,al,d,p,n,t\nJBSWY3DPEHPK3PXP,Iss,Acct,totp,SHA1,6,45,备注,单一\n',
    {
      secret: 's',
      issuer: 'i',
      account: 'a',
      kind: 'k',
      algo: 'al',
      digits: 'd',
      period: 'p',
      note: 'n',
      tagNames: 't',
    },
  )
  assert.equal(totp.failures.length, 0, totp.failures[0]?.reason)
  assert.equal(totp.entries[0].period, 45)
})

test('步骤 16（R2 修订 2 + R2b）：kind 未映射 → 按 totp，每个裸 base32 行一条行级 warning', () => {
  const result = T.parseGenericCsv(
    's,al,d,p\nJBSWY3DPEHPK3PXP,SHA1,6,30\nJBSWY3DPEHPK3PXP,SHA1,6,30\n',
    {
      secret: 's',
      algo: 'al',
      digits: 'd',
      period: 'p',
    },
  )
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.equal(result.entries.length, 2)
  assert.ok(result.entries.every((e) => e.kind === 'totp'))
  const kindWarnings = result.warnings.filter((w) => w.field === 'kind')
  assert.equal(
    kindWarnings.length,
    2,
    `每个裸 base32 行应各一条 kind warning，实得 ${kindWarnings.length}`,
  )
  assert.deepEqual(
    kindWarnings.map((w) => w.sourceIndex),
    [0, 1],
    'kind warning 不是行级（R2b）',
  )
})

test('步骤 16（R2b）：纯 URI 文件在 kind 未映射时不发无意义的 kind warning', () => {
  const result = T.parseGenericCsv(`s\n"${FULL_URI}"\n`, { secret: 's' })
  assert.equal(result.entries.length, 1)
  assert.equal(result.entries[0].kind, 'totp')
  assert.ok(
    !result.warnings.some((w) => w.field === 'kind'),
    'URI 自带 kind，仍发了行级 kind warning',
  )
})

test('步骤 16（R2 修订 2）：kind 已映射但该行空 → 按 totp + 一条行级 warning', () => {
  const result = T.parseGenericCsv('s,k,al,d,p\nJBSWY3DPEHPK3PXP,,SHA1,6,30\n', {
    secret: 's',
    kind: 'k',
    algo: 'al',
    digits: 'd',
    period: 'p',
  })
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.equal(result.entries[0].kind, 'totp')
  // 与「未映射」分支的 field 命名不同：已映射时 field 是调用方给的列名，未映射时是 'kind'。
  // 判据只要求「一条行级 warning」，未冻结 field 取值，故两种命名都接受
  const kindWarnings = result.warnings.filter((w) => w.sourceIndex === 0 && /TOTP/.test(w.message))
  assert.equal(
    kindWarnings.length,
    1,
    `空 kind 应记恰一条行级 warning，实得 ${JSON.stringify(result.warnings)}`,
  )
  assert.ok(
    ['k', 'kind'].includes(kindWarnings[0].field),
    `field 既不是映射列名也不是 'kind'：${kindWarnings[0].field}`,
  )
})

test('步骤 16（R2 修订 2）：hotp 缺 counter / totp 缺 period → 单条失败，绝不静默补默认值', () => {
  const mapping = { secret: 's', kind: 'k', algo: 'al', digits: 'd' }
  const hotp = T.parseGenericCsv('s,k,al,d\nJBSWY3DPEHPK3PXP,hotp,SHA1,6\n', mapping)
  assert.equal(hotp.entries.length, 0, 'hotp 缺 counter 未判失败')
  assert.equal(hotp.failures.length, 1)
  const totp = T.parseGenericCsv('s,k,al,d\nJBSWY3DPEHPK3PXP,totp,SHA1,6\n', mapping)
  assert.equal(totp.entries.length, 0, 'totp 缺 period 未判失败（C8）')
  assert.match(totp.failures[0].reason, /period/)
})

test('步骤 16（R2 修订 5）：digits / algo 未映射或该行为空 → 单条失败，文案分别点名 digits / algorithm', () => {
  const noDigits = T.parseGenericCsv('s,al,p\nJBSWY3DPEHPK3PXP,SHA1,30\n', {
    secret: 's',
    algo: 'al',
    period: 'p',
  })
  assert.equal(noDigits.entries.length, 0, 'digits 未映射未判失败')
  assert.match(noDigits.failures[0].reason, /digits/)
  const noAlgo = T.parseGenericCsv('s,d,p\nJBSWY3DPEHPK3PXP,6,30\n', {
    secret: 's',
    digits: 'd',
    period: 'p',
  })
  assert.equal(noAlgo.entries.length, 0, 'algo 未映射未判失败')
  assert.match(noAlgo.failures[0].reason, /algorithm/)
  const emptyDigits = T.parseGenericCsv('s,al,d,p\nJBSWY3DPEHPK3PXP,SHA1,,30\n', {
    secret: 's',
    algo: 'al',
    digits: 'd',
    period: 'p',
  })
  assert.equal(emptyDigits.entries.length, 0, 'digits 该行为空未判失败')
  const emptyAlgo = T.parseGenericCsv('s,al,d,p\nJBSWY3DPEHPK3PXP,,6,30\n', {
    secret: 's',
    algo: 'al',
    digits: 'd',
    period: 'p',
  })
  assert.equal(emptyAlgo.entries.length, 0, 'algo 该行为空未判失败')
})

test('步骤 16（R2b 收窄）：URI 形态下 digits / algo / period 未映射时从 URI 取值，不判失败', () => {
  const result = T.parseGenericCsv(`s\n"${FULL_URI}"\n`, { secret: 's' })
  assert.equal(
    result.failures.length,
    0,
    `R2b：URI 形态被误判失败 —— ${result.failures[0]?.reason}`,
  )
  assert.equal(result.entries[0].digits, 6)
  assert.equal(result.entries[0].algo, 'SHA1')
  assert.equal(result.entries[0].period, 30)
})

test('步骤 16（R2 修订 3）：tagNames 默认分号拆分；trim / 丢空项 / 去重；分隔符可自定义；空串不拆分', () => {
  assert.equal(T.DEFAULT_TAG_SEPARATOR, ';', '默认分隔符不是分号（R2 修订 3 禁止默认逗号）')
  const mapping = { secret: 's', tagNames: 't', algo: 'al', digits: 'd', period: 'p' }
  const result = T.parseGenericCsv(
    's,t,al,d,p\nJBSWY3DPEHPK3PXP," 甲 ; ; 乙 ;甲 ",SHA1,6,30\n',
    mapping,
  )
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.deepEqual([...result.entries[0].tagNames], ['甲', '乙'], '未 trim / 未丢空项 / 未去重')
  const custom = T.parseGenericCsv('s,t,al,d,p\nJBSWY3DPEHPK3PXP,甲|乙,SHA1,6,30\n', mapping, '|')
  assert.deepEqual([...custom.entries[0].tagNames], ['甲', '乙'])
  const noSplit = T.parseGenericCsv('s,t,al,d,p\nJBSWY3DPEHPK3PXP,"甲,乙",SHA1,6,30\n', mapping, '')
  assert.deepEqual([...noSplit.entries[0].tagNames], ['甲,乙'], '分隔符为空串时仍在拆分')
})

test('步骤 16：tag 长度闸门生效', () => {
  const long = 'x'.repeat(T.TRANSFER_LIMITS.maxFieldLength + 1)
  const result = T.parseGenericCsv(`s,t,al,d,p\nJBSWY3DPEHPK3PXP,${long},SHA1,6,30\n`, {
    secret: 's',
    tagNames: 't',
    algo: 'al',
    digits: 'd',
    period: 'p',
  })
  assert.equal(result.entries.length, 0, '超长 tag 未被长度闸门拦下')
  assert.ok(result.failures.length > 0)
})

test('步骤 16（R2 修订 4）：未映射的列一律忽略且不记 warning；空列名不构成错误', () => {
  const result = T.parseGenericCsv('s,,extra,al,d,p\nJBSWY3DPEHPK3PXP,ignored,junk,SHA1,6,30\n', {
    secret: 's',
    algo: 'al',
    digits: 'd',
    period: 'p',
  })
  assert.equal(result.failures.length, 0, `空列名被判成了错误：${result.failures[0]?.reason}`)
  assert.equal(result.entries.length, 1)
  assert.ok(
    !result.warnings.some((w) => /extra|junk|未映射|unknown/i.test(w.field + w.message)),
    '未映射的列记了 warning',
  )
})

test('步骤 16：generic_csv_edge.csv golden —— BOM / CRLF / 空列名 / 未知多余列 + 1 成功 2 失败（R2 修订 6）', () => {
  const raw = fixtureBytes('generic_csv_edge.csv')
  assert.equal(raw[0], 0xef, '夹具前提：BOM 存在')
  assert.ok(fixture('generic_csv_edge.csv').includes('\r\n'), '夹具前提：CRLF 存在')
  // R2 修订 6 冻结的映射：服务商 / 账户 / 密钥 / 算法 / 位数 / 周期 / 类型 —— **不含** 备注 与 计数器。
  // 理由（修订 6 原文）：夹具第 1 行的 备注 有 5000 字符，映射它就会撞 maxFieldLength=4096，
  // 使得该夹具唯一可成功的第 1 行也失败，golden 变成 0 成功 3 失败
  const result = T.parseGenericCsv(raw, {
    secret: '密钥',
    issuer: '服务商',
    account: '账户',
    algo: '算法',
    digits: '位数',
    period: '周期',
    kind: '类型',
  })
  assert.equal(
    result.entries.length,
    1,
    `期望 1 条成功，实得 ${result.entries.length}：${JSON.stringify(result.failures)}`,
  )
  assert.equal(result.failures.length, 2, `期望 2 条失败，实得 ${JSON.stringify(result.failures)}`)
  const [entry] = result.entries
  assert.equal(
    entry.issuer,
    'Deno',
    `BOM 未剥掉或列名不匹配，issuer=${JSON.stringify(entry.issuer)}`,
  )
  assert.equal(entry.account, 'Mason')
  assert.equal(entry.algo, 'SHA1', 'sha1 → SHA1 归一化（R2 修订 6 由本夹具钉住）')
  assert.equal(entry.digits, 6)
  assert.equal(entry.kind, 'totp')
  assert.equal(entry.period, 30)
  // 修订 6：失败两条的原因分别点名 digits（第 2 行的 10）与 period（第 3 行的 0）
  const reasons = result.failures.map((f) => f.reason).join(' | ')
  assert.match(reasons, /digits/, `未点名 digits 越界的那一行：${reasons}`)
  assert.match(reasons, /period/, `未点名 period 越界的那一行：${reasons}`)
  assert.deepEqual(
    result.failures.map((f) => f.sourceIndex),
    [1, 2],
  )
})

test('步骤 16（R2 修订 6）：SHA-512 → SHA512 与 HmacSHA256 → SHA256 由构造样本钉住', () => {
  const result = T.parseGenericCsv(
    [
      's,al,d,p',
      'JBSWY3DPEHPK3PXP,SHA-512,8,30',
      'JBSWY3DPEHPK3PXP,HmacSHA256,6,30',
      'JBSWY3DPEHPK3PXP,sha1,6,30',
    ].join('\n'),
    { secret: 's', algo: 'al', digits: 'd', period: 'p' },
  )
  assert.equal(result.failures.length, 0, result.failures[0]?.reason)
  assert.deepEqual(
    result.entries.map((e) => e.algo),
    ['SHA512', 'SHA256', 'SHA1'],
  )
})

test('步骤 16：generic_csv_malformed.csv 整包抛「引号未闭合」', () => {
  const error = thrown(() =>
    T.parseGenericCsv(fixture('generic_csv_malformed.csv'), GENERIC_MAPPING),
  )
  assert.ok(error instanceof T.TransferError, `抛的不是 TransferError：${error.name}`)
  assert.match(error.message, /引号|未闭合/, `文案不是引号未闭合：${error.message}`)
})

test('步骤 16：重复列名本身不致命（R2 修订 6 由构造样本单独覆盖）', () => {
  assert.doesNotThrow(() =>
    T.parseGenericCsv('s,s,al,d,p\nJBSWY3DPEHPK3PXP,other,SHA1,6,30\n', {
      secret: 's',
      algo: 'al',
      digits: 'd',
      period: 'p',
    }),
  )
})

test('步骤 16：整包闸门 —— 单元格长度超限抛 TransferFormatError，文案含「超过上限」', () => {
  const cellError = thrown(() =>
    T.parseGenericCsv(`s\n"${'x'.repeat(T.TRANSFER_LIMITS.maxCsvCellLength + 1)}"\n`, {
      secret: 's',
    }),
  )
  assert.ok(cellError instanceof T.TransferFormatError)
  assert.match(cellError.message, /超过上限/)
})

test('步骤 16：整包闸门 —— 字节数超限抛 TransferFormatError，文案含「超过上限」', () => {
  const error = thrown(() =>
    T.parseGenericCsv(utf8Encode(`s\n${'y'.repeat(T.TRANSFER_LIMITS.maxInputBytes + 10)}\n`), {
      secret: 's',
    }),
  )
  assert.ok(error instanceof T.TransferFormatError, `抛的不是 TransferFormatError：${error.name}`)
  assert.match(error.message, /超过上限/)
})

test('步骤 16：整包闸门 —— 条目数超限抛 TransferFormatError（带尾换行）', () => {
  const mapping = { secret: 's', algo: 'al', digits: 'd', period: 'p' }
  const text =
    [
      's,al,d,p',
      ...Array.from(
        { length: T.TRANSFER_LIMITS.maxEntries + 1 },
        () => 'JBSWY3DPEHPK3PXP,SHA1,6,30',
      ),
    ].join('\n') + '\n'
  const error = thrown(() => T.parseGenericCsv(text, mapping))
  assert.ok(error instanceof T.TransferFormatError, `抛的不是 TransferFormatError：${error.name}`)
  assert.match(error.message, /超过上限/)
  // 刚好在上限内不得被拒
  const exact =
    [
      's,al,d,p',
      ...Array.from({ length: T.TRANSFER_LIMITS.maxEntries }, () => 'JBSWY3DPEHPK3PXP,SHA1,6,30'),
    ].join('\n') + '\n'
  assert.equal(T.parseGenericCsv(exact, mapping).entries.length, T.TRANSFER_LIMITS.maxEntries)
})

test('步骤 16：整包闸门 —— 条目数超限抛 TransferFormatError（无尾换行）', () => {
  // 判据是绝对的：「条目数超限时抛 TransferFormatError」，未区分文件是否以换行结尾。
  // 一份 10001 个数据行且不带尾换行的 CSV 就是超限输入，必须被拒。
  const mapping = { secret: 's', algo: 'al', digits: 'd', period: 'p' }
  const text = [
    's,al,d,p',
    ...Array.from({ length: T.TRANSFER_LIMITS.maxEntries + 1 }, () => 'JBSWY3DPEHPK3PXP,SHA1,6,30'),
  ].join('\n')
  const error = thrown(() => T.parseGenericCsv(text, mapping))
  assert.ok(error instanceof T.TransferFormatError, `抛的不是 TransferFormatError：${error.name}`)
  assert.match(error.message, /超过上限/)
})

test('步骤 16：parseGenericCsv 纯函数 —— 不修改入参与映射，两次调用全等', () => {
  const csv = fixture('generic_csv.csv')
  const mapping = { ...GENERIC_MAPPING }
  assert.deepEqual(T.parseGenericCsv(csv, mapping), T.parseGenericCsv(csv, mapping))
  assert.deepEqual(mapping, GENERIC_MAPPING, 'parseGenericCsv 修改了调用方给的映射对象')
})

test('步骤 16：C4 —— 任何 failure / warning / 异常文案不含 secret', () => {
  const texts = []
  const mapping = {
    secret: '密钥',
    issuer: '服务商',
    account: '账户',
    algo: '算法',
    digits: '位数',
    period: '周期',
    kind: '类型',
  }
  for (const name of ['generic_csv.csv', 'generic_csv_edge.csv', 'generic_csv_malformed.csv']) {
    try {
      const result = T.parseGenericCsv(fixture(name), mapping)
      texts.push(
        ...result.failures.map((f) => `${f.path} ${f.reason}`),
        ...result.warnings.map((w) => `${w.field} ${w.message}`),
      )
    } catch (error) {
      texts.push(error.message)
    }
  }
  // 解码失败走单条 failure 而非抛错，故按 failure 收集其文案
  const bad = T.parseGenericCsv('s\n!!!bad-secret!!!\n', { secret: 's' })
  texts.push(...bad.failures.map((f) => `${f.path} ${f.reason}`))
  assert.ok(bad.failures.length > 0, '非法 secret 未被记为 failure')
  // 整包级错误（映射列不存在）的文案同样不得回显表头或数据
  texts.push(messageOf(() => T.parseGenericCsv('a,b\nSECRETVALUE,other\n', { secret: 'missing' })))
  assert.ok(texts.length > 3, `只收集到 ${texts.length} 条文案，取证面太窄`)
  assertNoSecretLeak(texts, SECRET_DENO.base32, 'parseGenericCsv')
  for (const text of texts) {
    assert.ok(!text.includes('SECRETVALUE'), `文案回显了首行数据（C4）：${text}`)
  }
})

test('步骤 16：复用步骤 7 的 CSV 解析（lazy-ladder rung 2）—— 同源错误形态一致', () => {
  const unclosed = thrown(() => T.parseCsv('a\n"unclosed\n', 'probe'))
  const viaGeneric = thrown(() => T.parseGenericCsv('s\n"unclosed\n', { secret: 's' }))
  assert.equal(unclosed.constructor, viaGeneric.constructor, '两处引号未闭合抛的不是同一错误类型')
  // 两处 `what` 标签本就不同（'probe' vs '通用 CSV'，后者自身含空格，故不能按首个空格切）；
  // 从第一个「第」起必须逐字相同——若各写了一份解析器，剥掉标签后的正文会漂移
  const strip = (message) => {
    const at = message.indexOf('第')
    assert.ok(at >= 0, `文案未含「第」，无法比对：${message}`)
    return message.slice(at)
  }
  assert.equal(
    strip(unclosed.message),
    strip(viaGeneric.message),
    '两处文案漂移，说明各写了一份解析器',
  )
  assert.match(unclosed.message, /引号未闭合/)
})

// ─────────────────────────────────────────────────────────────────────────────
// 步骤 17：导出生成器
// ─────────────────────────────────────────────────────────────────────────────

const collectKeys = (value, into = new Set()) => {
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, into)
  } else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      into.add(key)
      collectKeys(item, into)
    }
  }
  return into
}

test('步骤 17：generateAegis → parseAegis 双向迁移往返无损', () => {
  const bytes = T.generateAegis(VAULT)
  assert.equal(T.detect(bytes), 'aegis', '产物未被探测器识别为 aegis')
  const result = T.parseAegis(bytes)
  assert.equal(result.failures.length, 0, JSON.stringify(result.failures))
  assert.equal(result.entries.length, VAULT.entries.length)
  const byIssuer = new Map(result.entries.map((e) => [`${e.issuer}\u0000${e.account}`, e]))
  for (const entry of VAULT.entries) {
    const back = byIssuer.get(`${entry.issuer}\u0000${entry.account}`)
    assert.ok(back, `往返丢失了 ${entry.issuer}/${entry.account}`)
    assert.equal(back.kind, entry.kind)
    assert.equal(hex(back.secret), hex(base64Decode(entry.secret)), 'secret 字节往返不一致')
    assert.equal(back.algo, entry.algo)
    assert.equal(back.digits, entry.digits)
    if (entry.kind === 'totp') assert.equal(back.period, entry.period)
    else assert.equal(back.counter, entry.counter)
    assert.equal(back.note, entry.note)
    assert.deepEqual(
      [...back.tagNames].sort(),
      VAULT.tags
        .filter((t) => entry.tagIds.includes(t.id))
        .map((t) => t.name)
        .sort(),
    )
  }
})

test('步骤 17：Aegis 产物的 secret 是 base32 大写且无 padding', () => {
  const file = JSON.parse(utf8Decode(T.generateAegis(VAULT)))
  for (const entry of file.db.entries) {
    assert.equal(entry.info.secret, entry.info.secret.toUpperCase())
    assert.ok(!entry.info.secret.includes('='), `${entry.info.secret} 仍带 padding`)
    assert.match(entry.info.secret, /^[A-Z2-7]+$/)
  }
  assert.ok(file.db.entries.some((e) => e.info.secret === SECRET_DENO.base32))
})

test('步骤 17：标签形态是 db.groups:[{uuid,name}] + entries[].groups:[uuid]，不是字符串数组', () => {
  const file = JSON.parse(utf8Decode(T.generateAegis(VAULT)))
  assert.ok(Array.isArray(file.db.groups), 'db.groups 不是数组')
  assert.deepEqual(file.db.groups, [{ uuid: VAULT.tags[0].id, name: '工作' }])
  assert.equal(
    file.db.entries.filter((e) => e.groups.length > 0).length,
    2,
    'tagIds 引用未还原成分组 uuid',
  )
  for (const entry of file.db.entries) {
    assert.ok(Array.isArray(entry.groups))
    for (const group of entry.groups) {
      assert.equal(typeof group, 'string', 'groups 里出现了对象而非 uuid 字符串')
      assert.match(
        group,
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
        'uuid 形态非法（上游 Gson 反序列化成 java.util.UUID 会整包打不开）',
      )
    }
  }
})

test('步骤 17：sites / usageCount / lastUsedAt / favorite / position 与 _usageCount / _lastUsedTimestamp 均不出现', () => {
  const keys = collectKeys(JSON.parse(utf8Decode(T.generateAegis(VAULT))))
  for (const forbidden of [
    'sites',
    'usageCount',
    'lastUsedAt',
    'favorite',
    'position',
    '_usageCount',
    '_lastUsedTimestamp',
    'tagIds',
    'id',
    'createdAt',
    'updatedAt',
  ]) {
    assert.ok(!keys.has(forbidden), `产物出现了被 §3.1 丢弃的字段 ${forbidden}`)
  }
  for (const expected of [
    'version',
    'header',
    'db',
    'entries',
    'groups',
    'type',
    'uuid',
    'name',
    'issuer',
    'icon',
    'note',
    'info',
    'secret',
    'algo',
    'digits',
  ]) {
    assert.ok(keys.has(expected), `产物缺少 Aegis schema 必需的 ${expected}`)
  }
})

test('步骤 17：position 退化为数组顺序 —— 产物按 fractional index 字典序排列（§3.1 的 ⚠️）', () => {
  const shuffled = { ...VAULT, entries: [VAULT.entries[2], VAULT.entries[0], VAULT.entries[1]] }
  const file = JSON.parse(utf8Decode(T.generateAegis(shuffled)))
  assert.deepEqual(
    file.db.entries.map((e) => e.issuer),
    ['Deno', 'WWE', '航空 Air Canada'],
    '未按 position 字典序输出（position a0 < a1 < a2）',
  )
})

test('步骤 17：generateOtpAuthLines 每行一个 URI，无 padding，参数全写，label 编码，往返无损', () => {
  const text = T.generateOtpAuthLines(VAULT)
  const lines = text.split('\n')
  assert.equal(lines.length, VAULT.entries.length)
  assert.ok(!text.endsWith('\n'), '带尾随换行')
  for (const line of lines) {
    assert.ok(line.startsWith('otpauth://'), line)
    assert.match(line, /[?&]secret=[A-Z2-7]+(&|$)/, `secret 形态非法：${line}`)
    assert.match(line, /[?&]algorithm=SHA(1|256|512)(&|$)/, `algorithm 未显式写出：${line}`)
    assert.match(line, /[?&]digits=[678](&|$)/, `digits 未显式写出：${line}`)
    assert.match(line, /[?&](period=\d+|counter=\d+)(&|$)/, `period/counter 未显式写出：${line}`)
    assert.match(line, /[?&]issuer=/, `issuer 未写进 query：${line}`)
  }
  const roundTrip = T.parseOtpAuthLines(text)
  assert.equal(roundTrip.failures.length, 0, JSON.stringify(roundTrip.failures))
  assert.equal(roundTrip.entries.length, VAULT.entries.length)
  for (const [index, entry] of VAULT.entries.entries()) {
    assert.equal(roundTrip.entries[index].issuer, entry.issuer)
    assert.equal(roundTrip.entries[index].account, entry.account)
    assert.equal(hex(roundTrip.entries[index].secret), hex(base64Decode(entry.secret)))
    assert.equal(roundTrip.entries[index].algo, entry.algo)
    assert.equal(roundTrip.entries[index].digits, entry.digits)
    assert.equal(roundTrip.entries[index].kind, entry.kind)
  }
})

test('步骤 17：两个生成器都是纯函数 —— 不读时钟不读随机源，两次调用逐字节相同', () => {
  assert.deepEqual([...T.generateAegis(VAULT)], [...T.generateAegis(VAULT)])
  assert.equal(T.generateOtpAuthLines(VAULT), T.generateOtpAuthLines(VAULT))
  const before = Date.now()
  const a = T.generateAegis(VAULT)
  while (Date.now() === before) {
    /* 等到时钟走一格，若产物读时钟则两次必不同 */
  }
  assert.deepEqual([...a], [...T.generateAegis(VAULT)], '产物随时钟变化')
  const sealed = T.sealPlaintext(VAULT)
  T.generateAegis(VAULT)
  T.generateOtpAuthLines(VAULT)
  assert.deepEqual([...sealed], [...T.sealPlaintext(VAULT)], 'sealPlaintext 不纯')
})

test('步骤 17：空 entries 与空 tags 时两个生成器都产出合法空结果，不抛错', () => {
  const empty = { ...VAULT, entries: [], tags: [] }
  const aegis = JSON.parse(utf8Decode(T.generateAegis(empty)))
  assert.deepEqual(aegis.db.entries, [])
  assert.deepEqual(aegis.db.groups, [])
  assert.equal(aegis.version, 1)
  assert.equal(T.generateOtpAuthLines(empty), '')
  assert.doesNotThrow(() => T.parseAegis(T.generateAegis(empty)))
})

test('步骤 17：非法 VaultData 时生成器抛错而非产出文件（与 sealPlaintext 同口径）', () => {
  const bad = { ...VAULT, entries: [{ ...VAULT.entries[0], digits: 9 }] }
  assert.throws(() => T.generateAegis(bad))
  assert.throws(() => T.generateOtpAuthLines(bad))
})

test('步骤 17：降级信息以数据形式可被 UI 取得（§3.1），且登记表与产物一致', () => {
  const degradations = T.EXPORT_DEGRADATIONS
  assert.ok(degradations.aegis, '缺 aegis 行')
  assert.ok(degradations['otpauth-lines'], '缺 otpauth-lines 行')
  const entryFields = new Set(Object.keys(VAULT.entries[0]))
  for (const [format, degradation] of Object.entries(degradations)) {
    assert.ok(Array.isArray(degradation.dropped), `${format}.dropped 不是数组`)
    assert.ok(Array.isArray(degradation.degraded), `${format}.degraded 不是数组`)
    for (const field of [...degradation.dropped, ...degradation.degraded]) {
      assert.ok(entryFields.has(field), `${format} 登记了 vault Entry 上不存在的字段 ${field}`)
    }
  }
  assert.deepEqual([...degradations.aegis.dropped].sort(), [
    'favorite',
    'lastUsedAt',
    'sites',
    'usageCount',
  ])
  assert.deepEqual([...degradations.aegis.degraded], ['position'])
  for (const field of [
    'note',
    'tagIds',
    'sites',
    'usageCount',
    'lastUsedAt',
    'position',
    'favorite',
  ]) {
    assert.ok(
      degradations['otpauth-lines'].dropped.includes(field),
      `otpauth-lines 漏登记 ${field}`,
    )
  }
  const keys = collectKeys(JSON.parse(utf8Decode(T.generateAegis(VAULT))))
  for (const field of degradations.aegis.dropped) {
    assert.ok(!keys.has(field), `声明丢弃 ${field} 但产物里出现了`)
  }
  const line = T.generateOtpAuthLines(VAULT)
  assert.ok(!line.includes('明文容器夹具'), '声明丢弃 note 但 note 出现在 URI 里')
  assert.ok(!line.includes('deno.land'), '声明丢弃 sites 但 sites 出现在 URI 里')
})

test('步骤 17：生成器不实现任何二次确认 / 风险提示流程（AGENTS.md §5.4 属 UI，归 #6）', () => {
  assert.equal(T.generateAegis.length, 1, 'generateAegis 出现了确认相关的第二参数')
  assert.equal(T.generateOtpAuthLines.length, 1)
  assert.equal(typeof T.generateOtpAuthLines(VAULT), 'string')
  assert.ok(T.generateAegis(VAULT) instanceof Uint8Array)
})

// ─────────────────────────────────────────────────────────────────────────────
// 跨格式一致性（C10）、闸门顺序（C3）、纯函数（C6）
// ─────────────────────────────────────────────────────────────────────────────

test('C10：同一密钥跨 Aegis / FreeOTP+ / Ente / Bitwarden / 通用 CSV / 容器 / URI 文本字节一致', () => {
  const baseline = hex(base64Decode(SECRET_DENO.base64))
  const seen = new Map([
    ['aegis', T.parseAegis(fixture('aegis_plain.json')).entries[0].secret],
    [
      'freeotp-plus',
      T.parseFreeOtpPlus(fixture('freeotp_plus.json')).entries.find((e) => e.issuer === 'Deno')
        .secret,
    ],
    ['ente', T.parseEnte(fixture('ente_auth.txt')).entries.find((e) => e.issuer === 'Deno').secret],
    ['bitwarden', T.parseBitwarden(fixture('bitwarden.csv')).entries[0].secret],
    [
      'generic-csv',
      T.parseGenericCsv(fixture('generic_csv.csv'), GENERIC_MAPPING).entries[0].secret,
    ],
    ['otpauth-lines', T.parseOtpAuthLines(T.generateOtpAuthLines(VAULT)).entries[0].secret],
    ['mfavault-plaintext', base64Decode(T.openPlaintext(T.sealPlaintext(VAULT)).entries[0].secret)],
  ])
  assert.equal(seen.size, 7)
  for (const [format, bytes] of seen) {
    assert.equal(hex(bytes), baseline, `${format} 的 Deno 密钥字节与基线不符`)
  }
})

test('C3：整包闸门顺序 —— 字节长度在 JSON.parse 之前生效（超限但非法的 JSON 报「超过上限」）', () => {
  const oversized = utf8Encode(`{${' '.repeat(T.TRANSFER_LIMITS.maxInputBytes)}`)
  for (const parse of [
    T.parseAegis,
    T.parseTwoFas,
    T.parseFreeOtpPlus,
    T.parseBitwarden,
    T.parseEnte,
  ]) {
    const error = thrown(() => parse(oversized))
    assert.ok(error instanceof T.TransferFormatError, `${parse.name} 抛的不是 TransferFormatError`)
    assert.match(
      error.message,
      /超过上限/,
      `${parse.name} 未在 parse 之前拦住超限输入：${error.message}`,
    )
  }
  assert.equal(T.detect(oversized), undefined, 'detect 对超限输入未返回 undefined')
})

test('C6：全部解析器与生成器都是纯函数 —— 同一输入两次调用结果全等', () => {
  const twice = [
    ['parseAegis', () => T.parseAegis(fixture('aegis_grouped_v3.json'))],
    // 用 v4 正常样本：2fas_authenticator.json 是 schemaVersion:1，按判据必然抛错
    ['parseTwoFas', () => T.parseTwoFas(fixture('2fas_authenticator_plain_v4.2fas'))],
    ['parseFreeOtpPlus', () => T.parseFreeOtpPlus(fixture('freeotp_plus.json'))],
    ['parseEnte', () => T.parseEnte(fixture('ente_auth.txt'))],
    ['parseBitwarden', () => T.parseBitwarden(fixture('bitwarden.csv'))],
    ['parseGenericCsv', () => T.parseGenericCsv(fixture('generic_csv.csv'), GENERIC_MAPPING)],
    ['parseOtpAuthLines', () => T.parseOtpAuthLines(T.generateOtpAuthLines(VAULT))],
    ['openPlaintext', () => T.openPlaintext(fixtureBytes('mfavault_plaintext.json'))],
    ['detect', () => T.detect(fixtureBytes('aegis_plain.json'))],
  ]
  for (const [name, run] of twice) {
    assert.deepEqual(run(), run(), `${name} 不是纯函数`)
  }
  // 抛错路径的纯度：同一输入两次抛同样的错，且不修改入参
  for (const name of [
    '2fas_authenticator.json',
    'generic_csv_malformed.csv',
    'aegis_malformed.json',
  ]) {
    const text = fixture(name)
    const parse = name.startsWith('2fas')
      ? T.parseTwoFas
      : name.startsWith('generic')
        ? T.parseGenericCsv
        : T.parseAegis
    const args = name.startsWith('generic') ? [text, GENERIC_MAPPING] : [text]
    assert.equal(
      messageOf(() => parse(...args)),
      messageOf(() => parse(...args)),
      `${name} 的抛错路径不纯`,
    )
  }
})

test('C4：全部夹具跑一遍，收集到的文案不含任何夹具 secret 的编码形态', () => {
  const listed = [
    'aegis_plain.json',
    'aegis_grouped_v3.json',
    'aegis_plain_grouped_v2.json',
    'aegis_edge.json',
    'aegis_malformed.json',
    'aegis_encrypted.json',
    'aegis_encrypted_edge.json',
    'aegis_encrypted_malformed.json',
    '2fas_authenticator.json',
    '2fas_authenticator_plain_v4.2fas',
    'twofas_edge.json',
    'twofas_malformed.json',
    'twofas_encrypted.2fas',
    'twofas_encrypted_edge.2fas',
    'twofas_encrypted_malformed.2fas',
    'twofas_encrypted_v2.2fas',
    'twofas_encrypted_v3.2fas',
    'freeotp_plus.json',
    'freeotp_plus_edge.json',
    'freeotp_plus_malformed.json',
    'ente_auth.txt',
    'ente_edge.txt',
    'ente_jsonlines.txt',
    'bitwarden.csv',
    'bitwarden_edge.csv',
    'bitwarden_malformed.csv',
    'generic_csv.csv',
    'generic_csv_edge.csv',
    'generic_csv_malformed.csv',
    'plain.txt',
    'otpauth_edge.txt',
    'otpauth_malformed.txt',
    'mfavault_plaintext.json',
    'mfavault_plaintext_v0.json',
    'mfavault_malformed.json',
  ]
  // 防止漏夹具：清单必须与目录实际内容逐一对齐（README 不是夹具，排除）
  const actual = readdirSync(new URL('../packages/transfer/src/__fixtures__/', import.meta.url))
    .filter((name) => name !== 'README.md')
    .sort()
  assert.deepEqual(listed.slice().sort(), actual, 'C4 扫描的夹具清单与目录实际内容不一致')
  const texts = []
  const parsers = [T.parseAegis, T.parseTwoFas, T.parseFreeOtpPlus, T.parseEnte, T.parseBitwarden]
  for (const name of listed) {
    for (const parse of parsers) {
      try {
        const result = parse(fixture(name))
        texts.push(
          ...result.failures.map((f) => `${f.path} ${f.reason}`),
          ...result.warnings.map((w) => `${w.field} ${w.message}`),
        )
      } catch (error) {
        texts.push(error.message)
      }
    }
    // 通用 CSV 需要映射参数，单独跑一遍；otpauth-lines 与容器路径也各跑一遍
    try {
      const result = T.parseGenericCsv(fixture(name), GENERIC_MAPPING)
      texts.push(
        ...result.failures.map((f) => `${f.path} ${f.reason}`),
        ...result.warnings.map((w) => `${w.field} ${w.message}`),
      )
    } catch (error) {
      texts.push(error.message)
    }
    try {
      const result = T.parseOtpAuthLines(fixture(name))
      texts.push(...result.failures.map((f) => `${f.path} ${f.reason}`))
    } catch (error) {
      texts.push(error.message)
    }
    try {
      T.openPlaintext(fixtureBytes(name))
    } catch (error) {
      texts.push(error.message)
    }
    try {
      T.detect(fixtureBytes(name))
    } catch (error) {
      texts.push(error.message)
    }
  }
  assert.ok(texts.length > 100, `只收集到 ${texts.length} 条文案，取证面太窄`)
  for (const secret of [SECRET_DENO, SECRET_WWE, SECRET_AIRCANADA]) {
    assertNoSecretLeak(texts, secret.base32, '全夹具文案扫描')
  }
})

// ─────────────────────────────────────────────────────────────────────────────
// 运行器
// ─────────────────────────────────────────────────────────────────────────────

let failed = 0
for (const { name, fn } of cases) {
  const started = performance.now()
  try {
    fn()
    console.log(`PASS  ${name}  (${Math.round(performance.now() - started)}ms)`)
  } catch (error) {
    failed += 1
    console.log(`FAIL  ${name}`)
    console.log(`      ${String(error.message).split('\n').join('\n      ')}`)
  }
}

console.log('')
console.log(`${cases.length - failed}/${cases.length} passed`)
process.exit(failed === 0 ? 0 : 1)
