import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { browser } from 'wxt/browser'

import { request, type DisplayEntry, type SiteContext, type Snapshot } from '../../lib/protocol.js'
import '../../styles/shared.css'
import './style.css'

/** 首字母色块：issuer+account 稳定散列到色相，同一肉眼辨识（无需存图标）。 */
function blockHue(seed: string): number {
  let hash = 0
  for (let i = 0; i < seed.length; i++) hash = (hash * 31 + seed.charCodeAt(i)) % 360
  return hash
}

async function currentSite(): Promise<SiteContext | undefined> {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true })
  let candidate = tab
  if (candidate?.url?.startsWith('chrome-extension:')) {
    // popup.html 被当作普通标签页打开（调试 / QA 场景）：活跃标签是 popup 自身，
    // 退而取其他窗口里活跃的非扩展页。真实 popup 不走这条分支。
    const actives = await browser.tabs.query({ active: true })
    candidate = [...actives].reverse().find((item) => !item.url?.startsWith('chrome-extension:'))
  }
  if (candidate?.url === undefined) return undefined
  try {
    const url = new URL(candidate.url)
    return { protocol: url.protocol, hostname: url.hostname }
  } catch {
    return undefined
  }
}

function Countdown({ entry, elapsed }: { entry: DisplayEntry; elapsed: number }) {
  if (entry.kind === 'hotp') {
    return <span className="hotp-badge">HOTP #{entry.counter ?? 0}</span>
  }
  const remaining = Math.max(0, entry.remainingSeconds - elapsed)
  const fraction = Math.min(1, remaining / entry.period)
  const radius = 9
  const circumference = 2 * Math.PI * radius
  return (
    <svg className="ring" viewBox="0 0 24 24" role="img" aria-label={`${Math.ceil(remaining)} 秒`}>
      <circle className="ring-track" cx="12" cy="12" r={radius} />
      <circle
        className={remaining <= 5 ? 'ring-arc urgent' : 'ring-arc'}
        cx="12"
        cy="12"
        r={radius}
        strokeDasharray={circumference}
        strokeDashoffset={circumference * (1 - fraction)}
      />
      <text className="ring-text" x="12" y="16">
        {Math.ceil(remaining)}
      </text>
    </svg>
  )
}

function App() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [seconds, setSeconds] = useState(0)
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>()
  const [toast, setToast] = useState<string | undefined>()
  const [query, setQuery] = useState('')
  const [activeTags, setActiveTags] = useState<string[]>([])
  const siteRef = useRef<SiteContext | undefined>(undefined)
  const refreshRef = useRef<() => void>(() => undefined)
  const bootedRef = useRef(false)

  const refresh = useCallback(async () => {
    try {
      const next = await request<Snapshot>({
        type: 'snapshot',
        site: siteRef.current,
        query: query.trim() || undefined,
        tagIds: activeTags.length > 0 ? activeTags : undefined,
      })
      setSnapshot(next)
      setSeconds(0)
      setError(undefined)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '加载失败')
    }
  }, [query, activeTags])

  refreshRef.current = () => void refresh()

  useEffect(() => {
    void currentSite().then((site) => {
      siteRef.current = site
      bootedRef.current = true
      refreshRef.current()
    })
  }, [])

  // 搜索 / 筛选变化后防抖刷新；站点在打开时固定（activeTab 语义即「打开那一刻的页」）。
  useEffect(() => {
    if (!bootedRef.current) return
    const timer = setTimeout(() => refreshRef.current(), 150)
    return () => clearTimeout(timer)
  }, [query, activeTags])

  // 秒级心跳：倒计时归零的瞬间重新拉快照换码。
  useEffect(() => {
    const timer = setInterval(() => {
      setSeconds((value) => value + 1)
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    if (
      snapshot?.state === 'ready' &&
      snapshot.entries.some(
        (entry) => entry.kind === 'totp' && entry.remainingSeconds - seconds <= 0.2,
      )
    ) {
      refreshRef.current()
    }
  }, [seconds, snapshot])

  const elapsed = useMemo(() => seconds, [seconds])

  const unlock = async () => {
    setBusy(true)
    setError(undefined)
    try {
      await request({ type: 'unlock', password })
      setPassword('')
      await refresh()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '解锁失败')
    } finally {
      setBusy(false)
    }
  }

  const copy = async (entry: DisplayEntry) => {
    try {
      await navigator.clipboard.writeText(entry.code)
      const seconds_ = snapshot?.settings.clipboardClearSeconds ?? 0
      setToast(seconds_ > 0 ? `已复制，${seconds_} 秒后自动清理` : '已复制')
      // 比对基准用刚写入剪贴板的同一份文本：周期边界附近重算会得到下一周期的码。
      void request({ type: 'copied', id: entry.id, text: entry.code }).catch(() => undefined)
    } catch {
      setError('复制失败：浏览器未授予剪贴板权限')
    }
  }

  const lock = async () => {
    await request({ type: 'lock' })
    await refresh()
  }

  if (snapshot === null) {
    return <main className="popup loading">加载中…</main>
  }

  if (snapshot.state === 'empty') {
    return (
      <main className="popup">
        <header className="bar">
          <span className="brand">MyMFA</span>
        </header>
        <section className="center">
          <p>还没有密钥库。</p>
          <button className="primary" onClick={() => void browser.runtime.openOptionsPage()}>
            创建或导入密钥库
          </button>
        </section>
      </main>
    )
  }

  if (snapshot.state === 'locked') {
    return (
      <main className="popup">
        <header className="bar">
          <span className="brand">MyMFA</span>
        </header>
        <section className="center">
          <p className="hint">输入主密码解锁</p>
          <input
            type="password"
            autoFocus
            placeholder="主密码"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && password !== '' && !busy) void unlock()
            }}
          />
          <button
            className="primary"
            disabled={password === '' || busy}
            onClick={() => void unlock()}
          >
            {busy ? '解锁中…' : '解锁'}
          </button>
          {error !== undefined && <p className="error">{error}</p>}
        </section>
      </main>
    )
  }

  return (
    <main className="popup">
      <header className="bar">
        <span className="brand">MyMFA</span>
        <span className="bar-actions">
          <button
            className="ghost"
            title="设置"
            onClick={() => void browser.runtime.openOptionsPage()}
          >
            ⚙
          </button>
          <button className="ghost" title="立即锁定" onClick={() => void lock()}>
            锁定
          </button>
        </span>
      </header>

      {snapshot.clipboardNotice !== undefined && (
        <p className="notice">{snapshot.clipboardNotice}</p>
      )}

      <input
        className="search"
        placeholder="搜索服务商 / 账户…"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
      />

      {snapshot.tags.length > 0 && (
        <div className="tags">
          {snapshot.tags.map((tag) => {
            const active = activeTags.includes(tag.id)
            return (
              <button
                key={tag.id}
                className={active ? 'chip on' : 'chip'}
                style={{ borderColor: tag.color }}
                onClick={() =>
                  setActiveTags(
                    active ? activeTags.filter((id) => id !== tag.id) : [...activeTags, tag.id],
                  )
                }
              >
                {tag.name}
              </button>
            )
          })}
        </div>
      )}

      {error !== undefined && <p className="error">{error}</p>}

      <ul className="entries">
        {snapshot.entries.map((entry) => (
          <li
            key={entry.id}
            className={entry.currentSite ? 'entry pinned' : 'entry'}
            onClick={() => void copy(entry)}
          >
            <span
              className="block"
              style={{ background: `hsl(${blockHue(entry.issuer + entry.account)} 55% 45%)` }}
            >
              {entry.issuer.slice(0, 1).toUpperCase() || '?'}
            </span>
            <span className="meta">
              <span className="identity">
                {entry.issuer}
                {entry.currentSite && <em className="site-badge">当前网站</em>}
              </span>
              <span className="account">{entry.account}</span>
              <span className="codes">
                <b className="code">{entry.code}</b>
                {snapshot.settings.previewNextCode && (
                  <small className="next">{entry.nextCode}</small>
                )}
              </span>
            </span>
            <Countdown entry={entry} elapsed={elapsed} />
          </li>
        ))}
        {snapshot.entries.length === 0 && <li className="no-result">没有匹配的条目</li>}
      </ul>

      {toast !== undefined && (
        <p className="toast" onClick={() => setToast(undefined)}>
          {toast}
        </p>
      )}
    </main>
  )
}

createRoot(document.getElementById('root')!).render(<App />)
