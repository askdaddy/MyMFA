import { base64Decode, base64Encode } from '@askdaddy/crypto'
import { browser } from 'wxt/browser'

/**
 * chrome.storage 封装（docs/chrome-extension.md §5）。
 *
 * local 只存加密容器与非敏感偏好；session 只存内存态（DEK、活动时间、待清理验证码）。
 * session 的访问级别保持默认 TRUSTED_CONTEXTS，不改成 ALL_CONTEXTS。
 */

const CONTAINER_KEY = 'vault.container'
const PREFS_KEY = 'vault.prefs'
const SESSION_KEY = 'vault.session'
const CLIPBOARD_PENDING_KEY = 'clipboard.pending'
const CLIPBOARD_FAILED_KEY = 'clipboard.failed'

export interface Prefs {
  subdomainMatching: boolean
}

export interface SessionState {
  dek: number[]
  lastActiveAt: number
}

export interface PendingClipboardClear {
  expected: string
  at: number
}

export const DEFAULT_PREFS: Prefs = { subdomainMatching: true }

async function readKey(key: string): Promise<unknown> {
  return (await browser.storage.local.get(key))[key]
}

async function readSessionKey(key: string): Promise<unknown> {
  return (await browser.storage.session.get(key))[key]
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)
    : undefined
}

export async function readContainer(): Promise<Uint8Array | undefined> {
  const value = await readKey(CONTAINER_KEY)
  if (typeof value !== 'string' || value.length === 0) return undefined
  return base64Decode(value)
}

export async function writeContainer(bytes: Uint8Array): Promise<void> {
  await browser.storage.local.set({ [CONTAINER_KEY]: base64Encode(bytes) })
}

export async function readPrefs(): Promise<Prefs> {
  const value = asRecord(await readKey(PREFS_KEY))
  return typeof value?.subdomainMatching === 'boolean'
    ? { subdomainMatching: value.subdomainMatching }
    : { ...DEFAULT_PREFS }
}

export async function writePrefs(prefs: Prefs): Promise<void> {
  await browser.storage.local.set({ [PREFS_KEY]: prefs })
}

export async function readSession(): Promise<SessionState | undefined> {
  const value = asRecord(await readSessionKey(SESSION_KEY))
  if (value === undefined || !Array.isArray(value.dek) || typeof value.lastActiveAt !== 'number') {
    return undefined
  }
  return { dek: value.dek as number[], lastActiveAt: value.lastActiveAt }
}

export async function writeSession(state: SessionState): Promise<void> {
  await browser.storage.session.set({ [SESSION_KEY]: state })
}

export async function touchActivity(now = Date.now()): Promise<void> {
  const current = await readSession()
  if (current) await writeSession({ ...current, lastActiveAt: now })
}

export async function clearSession(): Promise<void> {
  await browser.storage.session.remove(SESSION_KEY)
}

export async function readPendingClear(): Promise<PendingClipboardClear | undefined> {
  const value = asRecord(await readSessionKey(CLIPBOARD_PENDING_KEY))
  if (value === undefined || typeof value.expected !== 'string' || typeof value.at !== 'number') {
    return undefined
  }
  return { expected: value.expected, at: value.at }
}

export async function writePendingClear(pending: PendingClipboardClear): Promise<void> {
  await browser.storage.session.set({ [CLIPBOARD_PENDING_KEY]: pending })
}

export async function clearPendingClear(): Promise<void> {
  await browser.storage.session.remove(CLIPBOARD_PENDING_KEY)
}

export async function consumeClipboardFailure(): Promise<string | undefined> {
  const value = await readSessionKey(CLIPBOARD_FAILED_KEY)
  if (typeof value !== 'string') return undefined
  await browser.storage.session.remove(CLIPBOARD_FAILED_KEY)
  return value
}

export async function recordClipboardFailure(message: string): Promise<void> {
  await browser.storage.session.set({ [CLIPBOARD_FAILED_KEY]: message })
}
