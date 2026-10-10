import { base64Decode } from '@askdaddy/crypto'
import {
  filterEntries,
  matchingEntries,
  searchEntries,
  sortEntries,
  type SortMode,
} from '@askdaddy/domain'
import type { DigestAlgorithm } from '@askdaddy/otp'
import type { Entry, VaultData } from '@askdaddy/vault'

import type { DisplayEntry, SiteContext } from './protocol.js'
import { otp } from './providers.js'

/** vault 存 otpauth 无连字符拼写，`@askdaddy/otp` 用 WebCrypto 拼写（types.ts 的刻意不合并）。 */
const ALGO_TO_DIGEST: Record<Entry['algo'], DigestAlgorithm> = {
  SHA1: 'SHA-1',
  SHA256: 'SHA-256',
  SHA512: 'SHA-512',
}

/**
 * 计算单个条目的当前码与预提示码。解码出的 secret 用后即清零（AGENTS.md §5.4），
 * 不依赖 GC。HOTP 的预提示是 counter+1 的码（Issue 正文验收 4）。
 */
export async function computeCodes(
  entry: Entry,
  now: number,
  clockOffsetSeconds: number,
): Promise<{ code: string; nextCode: string; remainingSeconds: number; period: number }> {
  const secret = base64Decode(entry.secret)
  try {
    const params = {
      secret,
      algorithm: ALGO_TO_DIGEST[entry.algo],
      digits: entry.digits,
      period: entry.period,
    }
    if (entry.kind === 'totp') {
      const state = await otp.totpState(params, now, clockOffsetSeconds)
      return {
        code: state.code,
        nextCode: state.nextCode,
        remainingSeconds: state.remainingSeconds,
        period: state.period,
      }
    }
    const counter = entry.counter ?? 0
    const code = await otp.hotpAt(params, counter)
    const nextCode = await otp.hotpAt(params, counter + 1)
    return { code, nextCode, remainingSeconds: -1, period: 0 }
  } finally {
    secret.fill(0)
  }
}

export interface ListOptions {
  site?: SiteContext
  query?: string
  tagIds?: string[]
  subdomainMatching: boolean
}

/** 搜索 / tag 筛选 / 排序 / 站点置顶的组合管道；secret 不离开本模块。 */
export async function buildDisplayList(
  data: VaultData,
  options: ListOptions,
): Promise<DisplayEntry[]> {
  let entries: Entry[] = [...data.entries]

  if (options.tagIds !== undefined && options.tagIds.length > 0) {
    entries = filterEntries(entries, options.tagIds)
  }

  const query = options.query?.trim() ?? ''
  if (query) {
    const results = await searchEntries(entries, data.tags, query, {
      searchPinyin: data.settings.searchPinyin,
    })
    entries = results.map((result) => result.entry)
  } else {
    entries = sortEntries(entries, { mode: data.settings.defaultSort as SortMode })
  }

  let matchedIds = new Set<string>()
  if (options.site !== undefined) {
    matchedIds = new Set(
      matchingEntries(entries, options.site, options.subdomainMatching).map((entry) => entry.id),
    )
    if (matchedIds.size > 0) {
      entries = [
        ...entries.filter((entry) => matchedIds.has(entry.id)),
        ...entries.filter((entry) => !matchedIds.has(entry.id)),
      ]
    }
  }

  const now = Date.now()
  return Promise.all(
    entries.map(async (entry): Promise<DisplayEntry> => {
      const codes = await computeCodes(entry, now, data.settings.clockOffsetSeconds)
      return {
        id: entry.id,
        kind: entry.kind,
        issuer: entry.issuer,
        account: entry.account,
        tagIds: [...entry.tagIds],
        sites: [...entry.sites],
        note: entry.note,
        algo: entry.algo,
        digits: entry.digits,
        favorite: entry.favorite,
        currentSite: matchedIds.has(entry.id),
        ...codes,
      }
    }),
  )
}
