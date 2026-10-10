/* global URL, chrome, window, document, getComputedStyle, TextDecoder, navigator, setTimeout --
   浏览器/扩展全局存在于被驱动的页面与 SW 上下文（evaluate 回调）或 Node 宿主，
   与根级 test/ 只放开 console/process/Buffer 的策略相容，就地声明。 */

/**
 * QA 黑盒验收脚本 —— Issue #6（apps/extension Chrome MV3 扩展），Plan R1 步骤 14。
 *
 * 运行：`pnpm build && node test/extension-e2e.mjs`（脚本会自行重建扩展产物）。
 * 退出码 0 = 全部 PASS。约 4 分钟（含两段剪贴板 45s 清理与一段空闲锁定的真实等待）。
 *
 * 方法论：
 * - 真实 Chrome（Playwright Chromium channel）加载 unpacked MV3 产物，全部从 UI / 消息 /
 *   存储快照等外部可观测行为断言，不读业务源码内部状态。
 * - 验证码对照用本脚本内独立实现的 RFC 4226/6238（node:crypto HMAC），不采信开发自述；
 *   导出的加密备份与导入夹具均用 packages/vault 公开 API + 真实 Web Provider 在 Node
 *   侧独立生成 / 解开。
 * - 剪贴板：popup.html 以标签页方式打开（window.open 的扩展页拿不到 runtime 绑定，需
 *   reload 一次）；域名匹配因无头环境无「点击图标」手势、activeTab 不授予，按带 site
 *   参数的 snapshot 请求做消息级验证（Chrome 安全语义，非实现缺陷）。
 * - 全部 secret 为假值（JBSWY3DPEHPK3PXP 同源），无真实备份。
 */

import assert from 'node:assert/strict'
import { execSync } from 'node:child_process'
import { createHmac } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { chromium } from 'playwright'

import { base64Decode } from '../packages/crypto/dist/index.js'
import {
  webAeadProvider,
  webCompressProvider,
  webKdfProvider,
  webRandomProvider,
} from '../packages/crypto-web/dist/index.js'
import { createVault, openVault } from '../packages/vault/dist/index.js'

const ROOT = new URL('..', import.meta.url).pathname
const EXT_DIR = join(ROOT, 'apps/extension', '.output', 'chrome-mv3')
const PASSWORD = 'correct horse battery staple'
const SECOND_PASSWORD = 'qa-second-password-2'

const results = []
function check(name, ok, detail = '') {
  results.push({ name, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`)
}

// ── 独立 OTP 实现（node:crypto，不依赖被测代码） ─────────────────────────────

function base32DecodeLocal(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  const out = []
  for (const char of text.replaceAll('=', '')) {
    const index = alphabet.indexOf(char)
    assert.ok(index >= 0, `base32 字符 ${char}`)
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((value >>> bits) & 0xff)
    }
  }
  return Uint8Array.from(out)
}

function independentHotp(key, counter, digits, algo) {
  const buffer = Buffer.alloc(8)
  buffer.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac(algo, Buffer.from(key)).update(buffer).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3]
  return String(binary % 10 ** digits).padStart(digits, '0')
}

const SECRET_SHA1 = 'JBSWY3DPEHPK3PXP' // RFC 假值，10 字节
const SECRET_SHA256 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' // 20 字节假值
const SECRET_SHA512 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'

const QA_PROVIDERS = {
  kdf: webKdfProvider,
  aead: webAeadProvider,
  random: webRandomProvider,
  compress: webCompressProvider,
}

// ── 步骤 1/13：构建与 manifest ───────────────────────────────────────────────

execSync('pnpm --filter @askdaddy/extension build', { cwd: ROOT, stdio: 'pipe' })
check('步骤1：扩展构建 EXIT 0', true)

const manifest = JSON.parse(readFileSync(join(EXT_DIR, 'manifest.json'), 'utf8'))
check(
  '步骤1：manifest 权限恰为六项',
  JSON.stringify(manifest.permissions) ===
    JSON.stringify([
      'storage',
      'activeTab',
      'clipboardWrite',
      'clipboardRead',
      'alarms',
      'offscreen',
    ]),
  JSON.stringify(manifest.permissions),
)
check(
  '步骤1：host_permissions 为空',
  Array.isArray(manifest.host_permissions) && manifest.host_permissions.length === 0,
)
check('步骤1：无 content_scripts', manifest.content_scripts === undefined)
check(
  '步骤1：三入口齐备',
  manifest.action !== undefined &&
    manifest.options_ui !== undefined &&
    manifest.background !== undefined,
)

const rootPackage = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
check('步骤1：pnpm ext:dev 存在', rootPackage.scripts['ext:dev'] !== undefined)
check(
  '步骤1：offscreen.html 产物存在',
  readFileSync(join(EXT_DIR, 'offscreen.html'), 'utf8').includes('textarea'),
)

// ── 浏览器环境 ───────────────────────────────────────────────────────────────

const profileDir = mkdtempSync(join(tmpdir(), 'mymfa-qa-'))
const ctx = await chromium.launchPersistentContext(profileDir, {
  headless: true,
  channel: 'chromium',
  args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
})
const bg = ctx.serviceWorkers()[0] ?? (await new Promise((r) => ctx.once('serviceworker', r)))
const extId = new URL(bg.url()).host
check('环境：扩展已加载，background SW 存在', extId.length > 0)

const options = await ctx.newPage()
await options.goto(`chrome-extension://${extId}/options.html`)
await options.waitForSelector('.tabs')

async function send(message) {
  return options.evaluate(
    (msg) => chrome.runtime.sendMessage(msg).then((r) => r ?? { ok: false, error: 'no-reply' }),
    message,
  )
}

async function openPopup() {
  const promise = ctx.waitForEvent('page')
  await options.evaluate((url) => window.open(url), `chrome-extension://${extId}/popup.html`)
  const popup = await promise
  await popup.reload()
  return popup
}

// 步骤 6：创建 vault（含强度指示与不可找回警示的呈现检查）
const pwFields = options.locator('input[type=password]')
await pwFields.nth(0).fill(PASSWORD)
await pwFields.nth(1).fill(PASSWORD)
const setupText = await options.evaluate(() => document.body.innerText)
check(
  '步骤6：创建页含不可找回警示',
  setupText.includes('不可找回'),
  setupText.slice(0, 40).replaceAll('\n', ' '),
)
await options.click('button.primary')
await options.waitForSelector('.options-bar', { timeout: 20000 })
check('步骤6：创建成功进入面板', true)

async function addEntry(fields) {
  await options.click('.tabs button:has-text("条目")')
  await options.click('button:has-text("新增条目")')
  await options.fill('input[placeholder*="JBSWY"]', fields.secret)
  const grid = options.locator('.grid2 input')
  await grid.nth(0).fill(fields.issuer)
  await grid.nth(1).fill(fields.account)
  if (fields.kind === 'hotp') await options.selectOption('.grid2 select >> nth=0', 'hotp')
  if (fields.algo !== undefined) await options.selectOption('.grid2 select >> nth=1', fields.algo)
  if (fields.digits !== undefined)
    await options.selectOption('.grid2 select >> nth=2', fields.digits)
  if (fields.counter !== undefined) {
    await options.locator('label:has-text("计数器") input').fill(fields.counter)
  }
  if (fields.site !== undefined) {
    await options.fill('input[placeholder="example.com"]', fields.site)
    await options.click('button:has-text("添加")')
  }
  if (fields.tag !== undefined) await options.click(`.tags .chip:has-text("${fields.tag}")`)
  await options.click('.card .row.end button.primary')
  await options.waitForSelector(`.entry-admin li:has-text("${fields.issuer}")`, { timeout: 10000 })
}

await options.click('.tabs button:has-text("标签")')
await options.fill('input[placeholder="新标签名"]', '工作')
await options.click('button:has-text("添加")')
await options.waitForSelector('.entry-admin li:has-text("工作")')
check('步骤11：标签创建', true)

await addEntry({
  issuer: 'GitHub',
  account: 'alice@example.com',
  secret: SECRET_SHA1,
  site: 'github.com',
  tag: '工作',
})
await addEntry({
  issuer: 'Sha256',
  account: 'bob@example.com',
  secret: SECRET_SHA256,
  algo: 'SHA256',
})
await addEntry({
  issuer: 'Sha512',
  account: 'carol@example.com',
  secret: SECRET_SHA512,
  algo: 'SHA512',
  digits: '8',
})
await addEntry({
  issuer: 'HotpBank',
  account: 'dave@example.com',
  secret: SECRET_SHA1,
  kind: 'hotp',
  counter: '3',
})
check('步骤11：四类条目（SHA1/256/512 + HOTP）经 UI 创建', true)

// ── 步骤 2/7：验证码与预提示的独立对照 ──────────────────────────────────────

const popup = await openPopup()
await popup.waitForSelector('.entry', { timeout: 15000 })

function codesOf(popupPage) {
  return popupPage.evaluate(() =>
    Array.from(document.querySelectorAll('.entry')).map((row) => ({
      issuer: (row.querySelector('.identity')?.textContent ?? '').trim().split('\n')[0] ?? '',
      code: row.querySelector('.code')?.textContent?.trim() ?? '',
      next: row.querySelector('.next')?.textContent?.trim() ?? '',
      remaining: Number(row.querySelector('.ring-text')?.textContent ?? '-1'),
    })),
  )
}

let rows = await codesOf(popup)
if (rows.some((row) => row.remaining >= 0 && row.remaining <= 2)) {
  await popup.waitForTimeout(2500)
  rows = await codesOf(popup)
}
const sampledAt = Date.now()
const byIssuer = new Map(rows.map((row) => [row.issuer, row]))
const keySha1 = base32DecodeLocal(SECRET_SHA1)
/** 双窗口对照：取样瞬间可能恰逢周期翻转，当前窗口不中再比对上一窗口。 */
const matchTotp = (key, digits, algo, got) => {
  const counter = Math.floor(sampledAt / 1000 / 30)
  return (
    got === independentHotp(key, counter, digits, algo) ||
    got === independentHotp(key, counter - 1, digits, algo)
  )
}
const wantSha1 = independentHotp(keySha1, Math.floor(sampledAt / 1000 / 30), 6, 'sha1')
check(
  '步骤2：SHA-1 当前码与独立实现一致',
  matchTotp(keySha1, 6, 'sha1', byIssuer.get('GitHub')?.code),
  `got=${byIssuer.get('GitHub')?.code} want=${wantSha1}`,
)
check(
  '步骤2：SHA-1 预提示码为下一周期码',
  (() => {
    const counter = Math.floor(sampledAt / 1000 / 30)
    const next = byIssuer.get('GitHub')?.next ?? ''
    return (
      next === independentHotp(keySha1, counter + 1, 6, 'sha1') ||
      next === independentHotp(keySha1, counter, 6, 'sha1')
    )
  })(),
  `next=${byIssuer.get('GitHub')?.next}`,
)
check(
  '步骤2：SHA-256 当前码与独立实现一致',
  matchTotp(base32DecodeLocal(SECRET_SHA256), 6, 'sha256', byIssuer.get('Sha256')?.code),
  `got=${byIssuer.get('Sha256')?.code}`,
)
check(
  '步骤2：SHA-512 8 位当前码与独立实现一致',
  matchTotp(base32DecodeLocal(SECRET_SHA512), 8, 'sha512', byIssuer.get('Sha512')?.code),
  `got=${byIssuer.get('Sha512')?.code}`,
)
check(
  '步骤7：HOTP 当前码为 counter=3、预提示为 counter+1',
  byIssuer.get('HotpBank')?.code ===
    independentHotp(base32DecodeLocal(SECRET_SHA1), 3, 6, 'sha1') &&
    byIssuer.get('HotpBank')?.next ===
      independentHotp(base32DecodeLocal(SECRET_SHA1), 4, 6, 'sha1'),
  `got=${byIssuer.get('HotpBank')?.code}/${byIssuer.get('HotpBank')?.next}`,
)
const fontSizeSmall = await popup
  .locator('.entry .next')
  .first()
  .evaluate((el) => Number.parseFloat(getComputedStyle(el).fontSize))
const fontSizeBig = await popup
  .locator('.entry .code')
  .first()
  .evaluate((el) => Number.parseFloat(getComputedStyle(el).fontSize))
check(
  '步骤7：预提示码以小号显示在当前码下方',
  fontSizeSmall < fontSizeBig,
  `${fontSizeSmall} < ${fontSizeBig}`,
)

const ring = () =>
  popup.evaluate(() => Number(document.querySelector('.ring-text')?.textContent ?? '-1'))
const r1 = await ring()
await popup.waitForTimeout(2500)
const r2 = await ring()
check('步骤7：倒计时环每秒递减', r2 < r1 || r2 === 30, `r1=${r1} r2=${r2}`)

// ── 步骤 8：域名绑定与置顶（消息级） ────────────────────────────────────────

async function siteMatch(hostname, protocol = 'https:') {
  const reply = await send({ type: 'snapshot', site: { protocol, hostname } })
  return reply.value.entries.filter((e) => e.currentSite).map((e) => e.issuer)
}
check(
  '步骤8：github.com 命中置顶',
  JSON.stringify(await siteMatch('github.com')) === JSON.stringify(['GitHub']),
)
check(
  '步骤8：gist.github.com 子域命中',
  JSON.stringify(await siteMatch('gist.github.com')) === JSON.stringify(['GitHub']),
)
check('步骤8：evil-github.com 不命中', (await siteMatch('evil-github.com')).length === 0)
check('步骤8：github.com.evil.com 不命中', (await siteMatch('github.com.evil.com')).length === 0)
check('步骤8：chrome:// 页不命中', (await siteMatch('extensions', 'chrome:')).length === 0)
await send({ type: 'saveSettings', settings: {}, subdomainMatching: false })
check('步骤8：关闭子域匹配后 gist 不命中', (await siteMatch('gist.github.com')).length === 0)
await send({ type: 'saveSettings', settings: {}, subdomainMatching: true })
check('步骤8：恢复子域匹配后 gist 命中', (await siteMatch('gist.github.com')).length === 1)

// ── 步骤 9：搜索与标签筛选 ───────────────────────────────────────────────────

await popup.fill('.search', 'alice')
await popup.waitForTimeout(600)
let filteredRows = await codesOf(popup)
check(
  '步骤9：按账户搜索命中 GitHub',
  filteredRows.length === 1 && filteredRows[0].issuer === 'GitHub',
  JSON.stringify(filteredRows.map((r) => r.issuer)),
)
await popup.locator('.chip:has-text("工作")').click()
await popup.waitForTimeout(600)
filteredRows = await codesOf(popup)
check(
  '步骤9：搜索+标签组合仍命中 GitHub',
  filteredRows.length === 1 && filteredRows[0].issuer === 'GitHub',
)
await popup.fill('.search', '')
await popup.locator('.chip:has-text("工作")').click()
await popup.waitForTimeout(600)
filteredRows = await codesOf(popup)
check('步骤9：清除筛选后四条目全部返回', filteredRows.length === 4, `count=${filteredRows.length}`)
const emptyQuery = await send({ type: 'snapshot', query: '不存在的条目名xyz' })
check('步骤9：空结果可辨识', emptyQuery.value.entries.length === 0)

// ── 步骤 4：消息边界与存储 ───────────────────────────────────────────────────

const malformed = await send({ type: '不存在的请求类型' })
check(
  '步骤4：畸形消息被安全拒绝',
  malformed.ok === false && typeof malformed.error === 'string',
  JSON.stringify(malformed.error ?? ''),
)
const storageDump = await options.evaluate(() =>
  chrome.storage.local.get(null).then((all) => JSON.stringify(all)),
)
const localKeys = Object.keys(JSON.parse(storageDump))
check(
  '步骤4：storage.local 仅加密容器与偏好，无 secret/主密码',
  localKeys.every((key) => key === 'vault.container' || key === 'vault.prefs') &&
    !storageDump.includes('JBSWY3DPEHPK3PXP') &&
    !storageDump.includes(PASSWORD),
  `keys=${localKeys.join(',')}`,
)
const containerJson = JSON.parse(
  new TextDecoder().decode(base64Decode(JSON.parse(storageDump)['vault.container'])),
)
check(
  '步骤4：local 容器为加密形态',
  containerJson.encrypted === true && containerJson.format === 'mfavault',
)
const sessionKeys = await options.evaluate(() =>
  chrome.storage.session.get(null).then((all) => Object.keys(all)),
)
check('步骤4：session 含解锁态', sessionKeys.includes('vault.session'))

// ── 步骤 10：复制与剪贴板清理 ────────────────────────────────────────────────

const githubRow = popup.locator('.entry', { hasText: 'GitHub' }).first()
const copiedCode = (await githubRow.locator('.code').innerText()).trim()
await githubRow.click()
await popup.waitForSelector('.toast')
check('步骤10：复制回执提示', (await popup.locator('.toast').innerText()).includes('已复制'))
check(
  '步骤10：剪贴板内容等于所复制验证码',
  (await popup.evaluate(() => navigator.clipboard.readText())) === copiedCode,
)
await popup.close()

await new Promise((r) => setTimeout(r, 47000))
const afterClear = await options.evaluate(() => navigator.clipboard.readText())
check(
  '步骤10：popup 关闭后 45 秒验证码被清空',
  afterClear.trim() === '',
  `clipboard=${JSON.stringify(afterClear.slice(0, 8))}`,
)

const popup3 = await openPopup()
const row3 = popup3.locator('.entry', { hasText: 'GitHub' }).first()
await row3.click()
await popup3.waitForSelector('.toast')
await popup3.close()
await options.evaluate(() => navigator.clipboard.writeText('用户自己的内容-keepme'))
await new Promise((r) => setTimeout(r, 47000))
const protectedContent = await options.evaluate(() => navigator.clipboard.readText())
check(
  '步骤10：用户后来复制的内容不被清除',
  protectedContent === '用户自己的内容-keepme',
  protectedContent,
)

const popup4 = await openPopup()
await send({ type: 'saveSettings', settings: { clipboardClearSeconds: 0 } })
await popup4.locator('.entry').first().click()
await popup4.waitForSelector('.toast')
const disableState = await options.evaluate(async () => ({
  pending: (await chrome.storage.session.get('clipboard.pending'))['clipboard.pending'] ?? null,
  alarms: (await chrome.alarms.getAll()).map((a) => a.name),
}))
check(
  '步骤10：清理关闭后无 pending 与清理 alarm',
  disableState.pending === null && !disableState.alarms.includes('mymfa-clipboard-clear'),
  JSON.stringify(disableState.alarms),
)
await send({ type: 'saveSettings', settings: { clipboardClearSeconds: 45 } })
await popup4.close()

await options.evaluate(() =>
  chrome.storage.session.set({ 'clipboard.failed': '剪贴板清理失败，请手动清理' }),
)
const popup5 = await openPopup()
const notice = await popup5
  .locator('.notice')
  .innerText()
  .catch(() => '')
check('步骤10：清理失败状态向用户显示', notice.includes('剪贴板清理失败'), notice)
await popup5.close()

// ── 步骤 11：条目编辑/删除与非法输入 ────────────────────────────────────────

await options.click('.tabs button:has-text("条目")')
await options.click('.entry-admin li:has-text("Sha256") button:has-text("编辑")')
await options.waitForSelector('.grid2 input >> nth=2')
const secretPlaceholder =
  (await options.locator('.grid2 input >> nth=2').getAttribute('placeholder')) ?? ''
check('步骤11：编辑时 secret 留空沿用有明示', secretPlaceholder.includes('沿用'), secretPlaceholder)
await options.fill('.grid2 input >> nth=2', '!!!不是base32!!!')
await options.click('.card .row.end button.primary')
await options.waitForSelector('.error', { timeout: 5000 })
check('步骤11：非法 secret 被拒绝', true)
await options.click('.card .row.end button:has-text("取消")')

await options.click('.entry-admin li:has-text("Sha256") button:has-text("编辑")')
await options.waitForSelector('.grid2 input >> nth=2')
// entryDetail 异步加载，等提示脱离占位符再断言
await options.waitForFunction(
  () => !(document.querySelector('.card code')?.textContent ?? '').includes('…'),
  undefined,
  { timeout: 5000 },
)
const currentSecretHint = await options.locator('.card code').first().innerText()
check(
  '步骤11：拒绝后旧值保留（原 secret 仍显示）',
  currentSecretHint.includes('GEZD'),
  currentSecretHint.slice(0, 12),
)
await options.click('.card .row.end button:has-text("取消")')

await options.click('button:has-text("新增条目")')
await options.fill('input[placeholder*="JBSWY"]', SECRET_SHA1)
const gridNew = options.locator('.grid2 input')
await gridNew.nth(0).fill('BadSite')
await gridNew.nth(1).fill('x@example.com')
await options.fill('input[placeholder="example.com"]', 'not a domain!!')
await options.click('button:has-text("添加")')
await options.click('.card .row.end button.primary')
await options.waitForSelector('.error', { timeout: 5000 })
check('步骤11：非法域名被拒绝（保存时校验，旧值保留）', true)
await options.click('.card .row.end button:has-text("取消")')

options.once('dialog', (dialog) => void dialog.accept())
await options.click('.entry-admin li:has-text("Sha512") button:has-text("删除")')
await options.waitForTimeout(1500)
check(
  '步骤11：删除条目后列表减少',
  (await options.locator('.entry-admin li').count()) === 3,
  `count=${await options.locator('.entry-admin li').count()}`,
)

// ── 步骤 12：导出（独立解开验证）与明文二次确认 ─────────────────────────────

await options.click('.tabs button:has-text("导入 / 导出")')
const [encDownload] = await Promise.all([
  options.waitForEvent('download', { timeout: 10000 }),
  options.click('button:has-text("导出加密备份")'),
])
const encPath = join(profileDir, 'qa-export.mfavault')
await encDownload.saveAs(encPath)
const opened = await openVault(new Uint8Array(readFileSync(encPath)), PASSWORD, QA_PROVIDERS)
check(
  '步骤12：加密导出可被 vault API 独立打开且数据一致',
  opened.data.entries.length === 3 && opened.data.tags.some((t) => t.name === '工作'),
  `entries=${opened.data.entries.length}`,
)

await options.click('button:has-text("导出明文备份")')
await options.waitForSelector('.modal')
check(
  '步骤12：明文导出未确认前按钮禁用',
  await options.locator('.modal button.danger').isDisabled(),
)
const modalText = await options.locator('.modal').innerText()
check(
  '步骤12：明文导出有显著风险提示与二次确认',
  modalText.includes('风险') && modalText.includes('确认'),
)
await options.click('.modal label.check input')
const [plainDownload] = await Promise.all([
  options.waitForEvent('download', { timeout: 10000 }),
  options.click('.modal button.danger'),
])
const plainPath = join(profileDir, 'qa-export-plaintext.json')
await plainDownload.saveAs(plainPath)
check('步骤12：明文导出为未加密容器', readFileSync(plainPath, 'utf8').includes('"encrypted":false'))

// ── 步骤 6：导入（错误来源密码不覆盖 + 正确导入保留数据） ───────────────────

const fixtureVault = await createVault(SECOND_PASSWORD, QA_PROVIDERS, { appVersion: 'qa-fixture' })
const fixturePath = join(profileDir, 'fixture.mfavault')
writeFileSync(fixturePath, await fixtureVault.serialize())
const fixtureBase64 = readFileSync(fixturePath).toString('base64')

const wrongImport = await send({
  type: 'import',
  base64: fixtureBase64,
  sourcePassword: 'wrong-password',
  newPassword: 'x',
})
check(
  '步骤6：错误来源密码被拒绝',
  wrongImport.ok === false && /主密码/.test(wrongImport.error ?? ''),
  wrongImport.error ?? '',
)
const unchanged = await send({ type: 'snapshot' })
check(
  '步骤6：错误来源密码未覆盖现有 vault',
  unchanged.value.entries.length === 3,
  `entries=${unchanged.value.entries.length}`,
)

const goodImport = await send({
  type: 'import',
  base64: fixtureBase64,
  sourcePassword: SECOND_PASSWORD,
  newPassword: SECOND_PASSWORD,
})
check('步骤6：正确导入成功', goodImport.ok === true, goodImport.error ?? '')
await send({ type: 'lock' })
check('步骤6：导入后锁定，需主密码', (await send({ type: 'snapshot' })).value.state === 'locked')
check(
  '步骤6：导入设置的新密码可解锁',
  (await send({ type: 'unlock', password: SECOND_PASSWORD })).ok === true,
)

// ── 步骤 5：手动锁定 / 空闲锁定 / 浏览器重启 ────────────────────────────────

await send({ type: 'lock' })
check('步骤5：手动锁定立即生效', (await send({ type: 'snapshot' })).value.state === 'locked')
await send({ type: 'unlock', password: SECOND_PASSWORD })
await send({ type: 'saveSettings', settings: { autoLockSeconds: 15 } })
await new Promise((r) => setTimeout(r, 55000))
check('步骤5：空闲 15 秒后自动锁定', (await send({ type: 'snapshot' })).value.state === 'locked')
await send({ type: 'unlock', password: SECOND_PASSWORD })
check('步骤5：锁定后可重新解锁', (await send({ type: 'snapshot' })).value.state === 'ready')

await ctx.close()

const ctx2 = await chromium.launchPersistentContext(profileDir, {
  headless: true,
  channel: 'chromium',
  args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
})
const bg2 = ctx2.serviceWorkers()[0] ?? (await new Promise((r) => ctx2.once('serviceworker', r)))
const options2 = await ctx2.newPage()
await options2.goto(`chrome-extension://${new URL(bg2.url()).host}/options.html`)
await options2.waitForTimeout(1500)
const restartBody = await options2.evaluate(() => document.body.innerText)
check(
  '步骤5：浏览器重启后要求主密码（DEK 未落盘）',
  restartBody.includes('解锁密钥库'),
  restartBody.slice(0, 24).replaceAll('\n', ' '),
)
await ctx2.close()

// ── 汇总 ─────────────────────────────────────────────────────────────────────

rmSync(profileDir, { recursive: true, force: true })
const failed = results.filter((r) => !r.ok)
console.log(
  `\n${failed.length === 0 ? 'ALL PASS' : 'HAS FAIL'}：${results.length - failed.length}/${results.length}`,
)
process.exit(failed.length ? 1 : 0)
