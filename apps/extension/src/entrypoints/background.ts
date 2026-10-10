import {
  addTag,
  deleteTag as domainDeleteTag,
  recordUsage,
  SORT_MODES,
  updateTag,
} from '@askdaddy/domain'
import { base64Decode, base64Encode, Base64DecodeError } from '@askdaddy/crypto'
import { base32Encode } from '@askdaddy/otp'
import { sealPlaintext } from '@askdaddy/transfer'
import {
  createVault,
  DEFAULT_SETTINGS,
  openVault,
  openVaultWithDek,
  uuidV7,
  VaultAuthError,
  VaultFormatError,
  VaultLockedError,
  VaultSchemaError,
  VaultVersionError,
  type Settings,
  type VaultData,
  type VaultHandle,
} from '@askdaddy/vault'
import { browser } from 'wxt/browser'

import { buildDisplayList } from '../lib/display.js'
import { withEntry } from '../lib/entries.js'
import {
  parseRequest,
  type EntryDetail,
  type ExportFile,
  type Reply,
  type Request,
  type Snapshot,
} from '../lib/protocol.js'
import { vaultProviders } from '../lib/providers.js'
import * as store from '../lib/storage.js'

const IDLE_ALARM = 'mymfa-idle-check'
const CLIPBOARD_ALARM = 'mymfa-clipboard-clear'

const APP_VERSION = browser.runtime.getManifest().version

/** SW 内存态：句柄随 SW 回收消失，凭 storage.session 的 DEK 在下一条消息到达时重建。 */
let handle: VaultHandle | null = null

/** 单一串行队列（design 方案 A）：所有请求排队执行，避免并发修改丢数据。 */
let queue: Promise<unknown> = Promise.resolve()

function enqueue<T>(work: () => Promise<T>): Promise<T> {
  const run = queue.then(work, work)
  queue = run.catch(() => undefined)
  return run
}

// ── 安全错误文案 ─────────────────────────────────────────────────────────────
//
// 回给页面的错误只允许已知类型的具体文案；未知异常一律泛化，防止实现细节或敏感材料外泄。

function safeError(error: unknown): string {
  if (error instanceof VaultAuthError) return '主密码不正确，或密钥库已损坏'
  if (error instanceof VaultLockedError) return '密钥库已锁定，请先解锁'
  if (
    error instanceof VaultFormatError ||
    error instanceof VaultVersionError ||
    error instanceof VaultSchemaError ||
    error instanceof Base64DecodeError
  ) {
    return error.message
  }
  if (error instanceof Error && error.message) return error.message
  return '操作失败'
}

// ── 解锁态管理 ───────────────────────────────────────────────────────────────

async function ensureUnlocked(): Promise<VaultHandle | null> {
  if (handle) return handle
  const [bytes, session] = await Promise.all([store.readContainer(), store.readSession()])
  if (!bytes || !session) return null
  const dek = Uint8Array.from(session.dek)
  try {
    handle = await openVaultWithDek(bytes, dek, vaultProviders)
    return handle
  } catch {
    // 容器已更换（如导入覆盖）而 session DEK 还是旧的：视为锁定，等待主密码。
    await store.clearSession()
    return null
  } finally {
    dek.fill(0)
  }
}

async function adoptHandle(next: VaultHandle): Promise<void> {
  handle = next
  await store.writeSession({ dek: Array.from(next.sessionDek()), lastActiveAt: Date.now() })
}

async function lockNow(): Promise<void> {
  handle?.lock()
  handle = null
  await store.clearSession()
}

// ── 持久化 ───────────────────────────────────────────────────────────────────

/**
 * 校验 → 序列化 → 写 local，成功才返回；写失败回滚内存，保证「写入失败不会让已有 vault 丢失」。
 */
async function persist(next: VaultData): Promise<void> {
  if (!handle) throw new Error('密钥库未解锁')
  const previous = handle.data
  handle.replaceData(next)
  try {
    await store.writeContainer(await handle.serialize())
  } catch (error) {
    handle.replaceData(previous)
    throw error
  }
}

// ── 请求处理 ─────────────────────────────────────────────────────────────────

async function snapshot(request: Extract<Request, { type: 'snapshot' }>): Promise<Snapshot> {
  const notice = await store.consumeClipboardFailure()
  const prefs = await store.readPrefs()
  const unlocked = await ensureUnlocked()
  if (!unlocked) {
    const bytes = await store.readContainer()
    return {
      state: bytes ? 'locked' : 'empty',
      entries: [],
      tags: [],
      settings: { ...DEFAULT_SETTINGS },
      subdomainMatching: prefs.subdomainMatching,
      clipboardNotice: notice,
    }
  }
  const entries = await buildDisplayList(unlocked.data, {
    site: request.site,
    query: request.query,
    tagIds: request.tagIds,
    subdomainMatching: prefs.subdomainMatching,
  })
  return {
    state: 'ready',
    entries,
    tags: unlocked.data.tags,
    settings: unlocked.data.settings,
    subdomainMatching: prefs.subdomainMatching,
    clipboardNotice: notice,
  }
}

async function create(request: Extract<Request, { type: 'create' }>): Promise<void> {
  if (await store.readContainer()) throw new Error('已存在密钥库；请改用导入或先清除扩展数据')
  const created = await createVault(request.password, vaultProviders, { appVersion: APP_VERSION })
  await store.writeContainer(await created.serialize())
  await adoptHandle(created)
}

async function importVault(request: Extract<Request, { type: 'import' }>): Promise<void> {
  const bytes = base64Decode(request.base64)
  // 来源密码错误在这一步抛出，现有 vault 不会被触碰（步骤 6 验收）。
  const source = await openVault(bytes, request.sourcePassword, vaultProviders)
  const data = source.data
  source.lock()

  const created = await createVault(request.newPassword, vaultProviders, {
    appVersion: APP_VERSION,
  })
  created.replaceData({
    ...data,
    meta: { ...data.meta, updatedAt: Date.now(), appVersion: APP_VERSION },
  })
  await store.writeContainer(await created.serialize())
  await adoptHandle(created)
}

async function unlock(request: Extract<Request, { type: 'unlock' }>): Promise<void> {
  const bytes = await store.readContainer()
  if (!bytes) throw new Error('尚未创建密钥库')
  await adoptHandle(await openVault(bytes, request.password, vaultProviders))
}

function requireHandle(): VaultHandle {
  if (!handle) throw new VaultLockedError()
  return handle
}

function assertSettingsPatch(patch: Partial<Settings>): void {
  if (
    patch.autoLockSeconds !== undefined &&
    (!Number.isSafeInteger(patch.autoLockSeconds) || patch.autoLockSeconds < 15)
  ) {
    throw new Error('自动锁定时长不能少于 15 秒')
  }
  if (
    patch.clipboardClearSeconds !== undefined &&
    (!Number.isSafeInteger(patch.clipboardClearSeconds) || patch.clipboardClearSeconds < 0)
  ) {
    throw new Error('剪贴板清理时间不合法')
  }
  if (patch.defaultSort !== undefined && !SORT_MODES.includes(patch.defaultSort as never)) {
    throw new Error('排序方式不受支持')
  }
}

async function saveSettings(request: Extract<Request, { type: 'saveSettings' }>): Promise<void> {
  assertSettingsPatch(request.settings)
  const current = requireHandle()
  await persist({
    ...current.data,
    settings: { ...current.data.settings, ...request.settings },
    meta: { ...current.data.meta, updatedAt: Date.now() },
  })
  if (request.subdomainMatching !== undefined) {
    await store.writePrefs({ subdomainMatching: request.subdomainMatching })
  }
}

async function saveTag(request: Extract<Request, { type: 'saveTag' }>): Promise<void> {
  const current = requireHandle()
  const now = Date.now()
  const tags =
    request.id === undefined
      ? addTag(current.data.tags, {
          id: uuidV7(vaultProviders.random),
          name: request.name,
          color: request.color,
        })
      : updateTag(current.data.tags, request.id, { name: request.name, color: request.color })
  await persist({ ...current.data, tags, meta: { ...current.data.meta, updatedAt: now } })
}

async function deleteTag(request: Extract<Request, { type: 'deleteTag' }>): Promise<void> {
  const current = requireHandle()
  const { entries, tags } = domainDeleteTag(
    current.data.entries,
    current.data.tags,
    request.id,
    Date.now(),
  )
  await persist({
    ...current.data,
    entries,
    tags,
    meta: { ...current.data.meta, updatedAt: Date.now() },
  })
}

async function exportVault(request: Extract<Request, { type: 'export' }>): Promise<ExportFile> {
  const current = requireHandle()
  const stamp = new Date().toISOString().slice(0, 10)
  if (request.plaintext) {
    return {
      filename: `mymfa-backup-${stamp}-plaintext.json`,
      base64: base64Encode(sealPlaintext(current.data)),
    }
  }
  return {
    filename: `mymfa-backup-${stamp}.mfavault`,
    base64: base64Encode(await current.serialize()),
  }
}

/**
 * 复制回执：记录使用计数（best-effort，失败不阻断复制），并调度剪贴板到期清理。
 * 比对基准直接采用页面刚写入剪贴板的文本——验证码本就随每份快照下发到页面，
 * 这里只是同一 trusted context 内回传一次；换成在 SW 重算会踩中周期边界竞态。
 */
async function copied(request: Extract<Request, { type: 'copied' }>): Promise<void> {
  const current = await ensureUnlocked()
  if (!current) throw new VaultLockedError()
  const entry = current.data.entries.find((item) => item.id === request.id)
  if (!entry) throw new Error('条目不存在')

  const now = Date.now()
  const seconds = current.data.settings.clipboardClearSeconds
  if (seconds > 0) {
    await store.writePendingClear({ expected: request.text, at: now })
    await browser.alarms.create(CLIPBOARD_ALARM, { when: now + seconds * 1000 })
  } else {
    await store.clearPendingClear()
    await browser.alarms.clear(CLIPBOARD_ALARM)
  }

  try {
    const entries = current.data.entries.map((item) =>
      item.id === request.id ? recordUsage(item, 'copy', now) : item,
    )
    await persist({ ...current.data, entries, meta: { ...current.data.meta, updatedAt: now } })
  } catch {
    // 使用计数是附带数据：写失败不影响复制与清理本身。
  }
}

async function entryDetail(id: string): Promise<EntryDetail> {
  const current = await ensureUnlocked()
  if (!current) throw new VaultLockedError()
  const entry = current.data.entries.find((item) => item.id === id)
  if (!entry) throw new Error('条目不存在')
  const secret = base64Decode(entry.secret)
  try {
    return {
      id: entry.id,
      kind: entry.kind,
      issuer: entry.issuer,
      account: entry.account,
      secretBase32: base32Encode(secret).replaceAll('=', ''),
      algo: entry.algo,
      digits: entry.digits,
      period: entry.period,
      counter: entry.counter,
      tagIds: [...entry.tagIds],
      note: entry.note,
      sites: [...entry.sites],
    }
  } finally {
    secret.fill(0)
  }
}

async function handleRequest(request: Request): Promise<unknown> {
  switch (request.type) {
    case 'snapshot':
      return snapshot(request)
    case 'create':
      return create(request)
    case 'import':
      return importVault(request)
    case 'unlock':
      return unlock(request)
    case 'lock':
      return lockNow()
    case 'saveEntry':
      return persist(withEntry(requireHandle().data, request.entry))
    case 'entryDetail':
      return entryDetail(request.id)
    case 'deleteEntry': {
      const data = requireHandle().data
      return persist({
        ...data,
        entries: data.entries.filter((entry) => entry.id !== request.id),
        meta: { ...data.meta, updatedAt: Date.now() },
      })
    }
    case 'saveSettings':
      return saveSettings(request)
    case 'saveTag':
      return saveTag(request)
    case 'deleteTag':
      return deleteTag(request)
    case 'export':
      return exportVault(request)
    case 'copied':
      return copied(request)
  }
}

// ── 剪贴板 offscreen 编排（步骤 10） ────────────────────────────────────────

interface OffscreenResult {
  pasted: boolean
  matched: boolean
  cleared: boolean
}

async function hasOffscreen(): Promise<boolean> {
  const contexts = await browser.runtime.getContexts({
    contextTypes: ['OFFSCREEN_DOCUMENT' as never],
  })
  return contexts.length > 0
}

async function runClipboardClear(expected: string): Promise<OffscreenResult> {
  if (!(await hasOffscreen())) {
    await browser.offscreen.createDocument({
      url: browser.runtime.getURL('/offscreen.html'),
      reasons: ['CLIPBOARD' as never],
      justification: '验证码到期清理：仅当剪贴板仍为本次复制的验证码时清空',
    })
  }
  try {
    return (await browser.runtime.sendMessage({
      type: 'offscreen-clipboard-clear',
      expected,
    })) as OffscreenResult
  } finally {
    if (await hasOffscreen()) await browser.offscreen.closeDocument()
  }
}

async function onClipboardAlarm(): Promise<void> {
  const pending = await store.readPendingClear()
  await store.clearPendingClear()
  if (!pending) return
  try {
    const result = await runClipboardClear(pending.expected)
    // pasted && !matched 是正确保护（用户后来复制了别的内容），不算失败。
    if (!result.pasted || (result.matched && !result.cleared)) {
      await store.recordClipboardFailure('剪贴板清理失败，请手动清理')
    }
  } catch {
    await store.recordClipboardFailure('剪贴板清理失败，请手动清理')
  }
}

// ── 空闲锁定（步骤 5） ───────────────────────────────────────────────────────

async function onIdleAlarm(): Promise<void> {
  const session = await store.readSession()
  if (!session) return
  const idleMs = Date.now() - session.lastActiveAt
  if (idleMs <= 0) return
  const current = handle ?? (await ensureUnlocked())
  if (!current) return
  const limit = current.data.settings.autoLockSeconds * 1000
  if (idleMs > limit) await lockNow()
}

// ── 入口 ─────────────────────────────────────────────────────────────────────

export default defineBackground(() => {
  // alarms 的最小周期是 0.5 分钟；60 秒级 autoLock 的实际触发粒度即 ±30 秒。
  void browser.alarms.create(IDLE_ALARM, { periodInMinutes: 0.5 })

  browser.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
    const request = parseRequest(message)
    if (request === undefined) {
      sendResponse({ ok: false, error: '无法识别的请求' } satisfies Reply)
      return false
    }
    void store.touchActivity()
    enqueue(() => handleRequest(request)).then(
      (value) => sendResponse({ ok: true, value } satisfies Reply),
      (error: unknown) => sendResponse({ ok: false, error: safeError(error) } satisfies Reply),
    )
    return true
  })

  browser.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === IDLE_ALARM) void enqueue(onIdleAlarm)
    else if (alarm.name === CLIPBOARD_ALARM) void onClipboardAlarm()
  })
})
