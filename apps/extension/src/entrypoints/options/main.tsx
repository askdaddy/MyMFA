import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { createRoot } from 'react-dom/client'

import { SORT_MODES } from '@askdaddy/domain'
import type { EntryAlgorithm, EntryKind, Tag } from '@askdaddy/vault'

import {
  request,
  type DisplayEntry,
  type EntryDetail,
  type EntryInput,
  type ExportFile,
  type Snapshot,
} from '../../lib/protocol.js'
import { passwordStrength } from '../../lib/strength.js'
import '../../styles/shared.css'
import './style.css'

const SORT_LABELS: Record<string, string> = {
  manual: '手动排序',
  issuer: '按服务商',
  account: '按账户',
  usageCount: '按使用次数',
  lastUsedAt: '按最近使用',
  createdAt: '按创建时间',
}

async function fileToBase64(selected: File): Promise<string> {
  const buffer = new Uint8Array(await selected.arrayBuffer())
  let base64 = ''
  for (let offset = 0; offset < buffer.length; offset += 0x8000) {
    const chunk = buffer.subarray(offset, offset + 0x8000)
    base64 += btoa(String.fromCharCode(...Array.from(chunk)))
  }
  return base64
}

function download(file: ExportFile): void {
  const bytes = Uint8Array.from(atob(file.base64), (char) => char.charCodeAt(0))
  const blob = new Blob([bytes], { type: 'application/octet-stream' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = file.filename
  anchor.click()
  URL.revokeObjectURL(url)
}

/** 不可找回告知 + 强度指示是创建 / 导入两个流程共同的硬性呈现（步骤 6 验收）。 */
function PasswordFields({
  value,
  confirm,
  onChange,
  onConfirmChange,
}: {
  value: string
  confirm: string
  onChange: (next: string) => void
  onConfirmChange: (next: string) => void
}) {
  const strength = passwordStrength(value)
  const mismatch = confirm !== '' && confirm !== value
  return (
    <>
      <label>
        主密码
        <input
          type="password"
          autoComplete="new-password"
          value={value}
          onChange={(event) => onChange(event.target.value)}
        />
      </label>
      <div className="strength" aria-label={`密码强度：${strength.label}`}>
        <span className="strength-bars">
          {[1, 2, 3, 4].map((level) => (
            <i
              key={level}
              className={level <= strength.score ? `bar-${strength.score}` : undefined}
            />
          ))}
        </span>
        <span className="strength-label">{value === '' ? '' : strength.label}</span>
      </div>
      <label>
        确认主密码
        <input
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(event) => onConfirmChange(event.target.value)}
        />
      </label>
      {mismatch && <p className="error">两次输入的主密码不一致</p>}
      <p className="warning">
        主密码 <b>不可找回</b>
        ：它不发送到任何服务器，也没有重置途径。遗忘即永久失去全部验证码，请务必牢记或安全保管。
      </p>
    </>
  )
}

// ── 初始化（创建 / 导入）与解锁 ─────────────────────────────────────────────

function SetupScreen({ onDone }: { onDone: () => void }) {
  const [mode, setMode] = useState<'create' | 'import'>('create')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [sourcePassword, setSourcePassword] = useState('')
  const [file, setFile] = useState<{ name: string; base64: string } | undefined>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>()

  const submit = async () => {
    if (password === '' || password !== confirm) return
    if (mode === 'import' && (file === undefined || sourcePassword === '')) return
    setBusy(true)
    setError(undefined)
    try {
      if (mode === 'create') {
        await request({ type: 'create', password })
      } else {
        await request({
          type: 'import',
          base64: file!.base64,
          sourcePassword,
          newPassword: password,
        })
      }
      onDone()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '操作失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="options narrow">
      <h1>初始化 MyMFA 密钥库</h1>
      <div className="tabs">
        <button className={mode === 'create' ? 'tab on' : 'tab'} onClick={() => setMode('create')}>
          创建密钥库
        </button>
        <button className={mode === 'import' ? 'tab on' : 'tab'} onClick={() => setMode('import')}>
          导入 .mfavault 备份
        </button>
      </div>

      {mode === 'import' && (
        <>
          <label>
            备份文件（.mfavault）
            <input
              type="file"
              accept=".mfavault,.json"
              onChange={(event) => {
                const selected = event.target.files?.[0]
                if (selected === undefined) {
                  setFile(undefined)
                  return
                }
                void fileToBase64(selected).then((base64) =>
                  setFile({ name: selected.name, base64 }),
                )
              }}
            />
          </label>
          <label>
            来源主密码（打开该备份文件的密码）
            <input
              type="password"
              autoComplete="current-password"
              value={sourcePassword}
              onChange={(event) => setSourcePassword(event.target.value)}
            />
          </label>
          <p className="hint">来源密码错误时不会覆盖任何现有数据。</p>
        </>
      )}

      <PasswordFields
        value={password}
        confirm={confirm}
        onChange={setPassword}
        onConfirmChange={setConfirm}
      />

      <button
        className="primary"
        disabled={
          busy ||
          password === '' ||
          password !== confirm ||
          (mode === 'import' && (file === undefined || sourcePassword === ''))
        }
        onClick={() => void submit()}
      >
        {busy ? '处理中…' : mode === 'create' ? '创建密钥库' : '导入并重新加密'}
      </button>
      {error !== undefined && <p className="error">{error}</p>}
    </main>
  )
}

function UnlockScreen({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>()

  const unlock = async () => {
    setBusy(true)
    setError(undefined)
    try {
      await request({ type: 'unlock', password })
      onDone()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '解锁失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="options narrow">
      <h1>解锁密钥库</h1>
      <label>
        主密码
        <input
          type="password"
          autoFocus
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && password !== '' && !busy) void unlock()
          }}
        />
      </label>
      <button className="primary" disabled={password === '' || busy} onClick={() => void unlock()}>
        {busy ? '解锁中…' : '解锁'}
      </button>
      {error !== undefined && <p className="error">{error}</p>}
    </main>
  )
}

// ── 条目编辑 ─────────────────────────────────────────────────────────────────

const EMPTY_FORM: Omit<EntryInput, 'secret'> = {
  kind: 'totp',
  issuer: '',
  account: '',
  algo: 'SHA1',
  digits: 6,
  period: 30,
  counter: 0,
  tagIds: [],
  note: '',
  sites: [],
}

function EntryForm({
  entryId,
  tags,
  onSaved,
  onCancel,
}: {
  entryId: string | undefined
  tags: readonly Tag[]
  onSaved: () => void
  onCancel: () => void
}) {
  const [form, setForm] = useState<Omit<EntryInput, 'secret'>>({ ...EMPTY_FORM })
  const [secretRetyped, setSecretRetyped] = useState('')
  const [secretBase32, setSecretBase32] = useState<string | undefined>(undefined)
  const [siteDraft, setSiteDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>()

  useEffect(() => {
    if (entryId === undefined) return
    let cancelled = false
    void request<EntryDetail>({ type: 'entryDetail', id: entryId })
      .then((detail) => {
        if (cancelled) return
        setForm({
          id: detail.id,
          kind: detail.kind,
          issuer: detail.issuer,
          account: detail.account,
          algo: detail.algo,
          digits: detail.digits,
          period: detail.period,
          counter: detail.counter,
          tagIds: detail.tagIds,
          note: detail.note,
          sites: detail.sites,
        })
        setSecretBase32(detail.secretBase32)
      })
      .catch((caught: unknown) => {
        if (!cancelled) setError(caught instanceof Error ? caught.message : '读取条目失败')
      })
    return () => {
      cancelled = true
    }
  }, [entryId])

  const patch = (next: Partial<Omit<EntryInput, 'secret'>>) =>
    setForm((current) => ({ ...current, ...next }))

  const submit = async () => {
    setBusy(true)
    setError(undefined)
    try {
      await request({
        type: 'saveEntry',
        entry: {
          ...form,
          // 编辑时只有重新输入了 secret 才覆盖；留空表示沿用原值。
          secret: secretRetyped.trim() === '' ? undefined : secretRetyped,
        },
      })
      onSaved()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '保存失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h2>{entryId === undefined ? '新增条目' : `编辑：${form.issuer}`}</h2>
      {entryId !== undefined && (
        <p className="hint">
          secret 留空表示沿用原值（当前：<code>{secretBase32 ?? '…'}</code>）
        </p>
      )}
      <div className="grid2">
        <label>
          服务商
          <input value={form.issuer} onChange={(e) => patch({ issuer: e.target.value })} />
        </label>
        <label>
          账户
          <input value={form.account} onChange={(e) => patch({ account: e.target.value })} />
        </label>
        <label>
          Secret（base32{entryId !== undefined ? '，留空保持不变' : ''}）
          <input
            value={secretRetyped}
            placeholder={entryId !== undefined ? '留空 = 沿用原 secret' : '如 JBSWY3DPEHPK3PXP'}
            onChange={(e) => setSecretRetyped(e.target.value)}
          />
        </label>
        <label>
          类型
          <select value={form.kind} onChange={(e) => patch({ kind: e.target.value as EntryKind })}>
            <option value="totp">TOTP（基于时间）</option>
            <option value="hotp">HOTP（基于计数器）</option>
          </select>
        </label>
        <label>
          摘要算法
          <select
            value={form.algo}
            onChange={(e) => patch({ algo: e.target.value as EntryAlgorithm })}
          >
            <option value="SHA1">SHA-1</option>
            <option value="SHA256">SHA-256</option>
            <option value="SHA512">SHA-512</option>
          </select>
        </label>
        <label>
          位数
          <select
            value={form.digits}
            onChange={(e) => patch({ digits: Number(e.target.value) as 6 | 7 | 8 })}
          >
            <option value={6}>6</option>
            <option value={7}>7</option>
            <option value={8}>8</option>
          </select>
        </label>
        {form.kind === 'totp' ? (
          <label>
            周期（秒）
            <input
              type="number"
              min={1}
              value={form.period}
              onChange={(e) => patch({ period: Number(e.target.value) })}
            />
          </label>
        ) : (
          <label>
            计数器
            <input
              type="number"
              min={0}
              value={form.counter}
              onChange={(e) => patch({ counter: Number(e.target.value) })}
            />
          </label>
        )}
      </div>

      <label>标签</label>
      <div className="tags">
        {tags.map((tag) => {
          const on = form.tagIds.includes(tag.id)
          return (
            <button
              key={tag.id}
              className={on ? 'chip on' : 'chip'}
              style={{ borderColor: tag.color }}
              onClick={() =>
                patch({
                  tagIds: on ? form.tagIds.filter((id) => id !== tag.id) : [...form.tagIds, tag.id],
                })
              }
            >
              {tag.name}
            </button>
          )
        })}
        {tags.length === 0 && <span className="hint">还没有标签，可在「标签」页创建</span>}
      </div>

      <label>
        备注
        <textarea rows={2} value={form.note} onChange={(e) => patch({ note: e.target.value })} />
      </label>

      <label>绑定域名（popup 打开对应网站时自动置顶）</label>
      <ul className="site-list">
        {form.sites.map((site) => (
          <li key={site}>
            <code>{site}</code>
            <button
              className="ghost"
              onClick={() => patch({ sites: form.sites.filter((item) => item !== site) })}
            >
              移除
            </button>
          </li>
        ))}
      </ul>
      <div className="row">
        <input
          placeholder="example.com"
          value={siteDraft}
          onChange={(e) => setSiteDraft(e.target.value)}
        />
        <button
          onClick={() => {
            if (siteDraft.trim() !== '') {
              patch({ sites: [...form.sites, siteDraft.trim()] })
              setSiteDraft('')
            }
          }}
        >
          添加
        </button>
      </div>

      {error !== undefined && <p className="error">{error}</p>}
      <div className="row end">
        <button onClick={onCancel}>取消</button>
        <button
          className="primary"
          disabled={busy || form.issuer.trim() === '' || form.account.trim() === ''}
          onClick={() => void submit()}
        >
          {busy ? '保存中…' : '保存'}
        </button>
      </div>
    </section>
  )
}

// ── 各功能区 ─────────────────────────────────────────────────────────────────

function EntriesSection({
  entries,
  tags,
  reload,
}: {
  entries: readonly DisplayEntry[]
  tags: readonly Tag[]
  reload: () => void
}) {
  const [editing, setEditing] = useState<string | 'new' | undefined>(undefined)
  const [error, setError] = useState<string | undefined>()

  const remove = async (entry: DisplayEntry) => {
    if (!window.confirm(`删除条目「${entry.issuer} / ${entry.account}」？此操作不可撤销。`)) return
    try {
      await request({ type: 'deleteEntry', id: entry.id })
      reload()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '删除失败')
    }
  }

  if (editing !== undefined) {
    return (
      <EntryForm
        entryId={editing === 'new' ? undefined : editing}
        tags={tags}
        onSaved={() => {
          setEditing(undefined)
          reload()
        }}
        onCancel={() => setEditing(undefined)}
      />
    )
  }

  return (
    <section className="card">
      <div className="row space">
        <h2>条目（{entries.length}）</h2>
        <button className="primary" onClick={() => setEditing('new')}>
          新增条目
        </button>
      </div>
      {error !== undefined && <p className="error">{error}</p>}
      <ul className="entry-admin">
        {entries.map((entry) => (
          <li key={entry.id}>
            <span className="entry-admin-meta">
              <b>{entry.issuer}</b>
              <span className="hint">{entry.account}</span>
              <span className="hint">
                {entry.kind.toUpperCase()} · {entry.algo} · {entry.digits} 位
                {entry.sites.length > 0 && ` · ${entry.sites.join(', ')}`}
              </span>
            </span>
            <span className="row">
              <button onClick={() => setEditing(entry.id)}>编辑</button>
              <button className="danger" onClick={() => void remove(entry)}>
                删除
              </button>
            </span>
          </li>
        ))}
        {entries.length === 0 && <li className="hint">还没有条目</li>}
      </ul>
    </section>
  )
}

function TagsSection({ tags, reload }: { tags: readonly Tag[]; reload: () => void }) {
  const [name, setName] = useState('')
  const [color, setColor] = useState('#5b8def')
  const [editing, setEditing] = useState<Tag | undefined>()
  const [error, setError] = useState<string | undefined>()

  const save = async () => {
    try {
      await request({
        type: 'saveTag',
        id: editing?.id,
        name: editing === undefined ? name : editing.name,
        color,
      })
      setName('')
      setEditing(undefined)
      reload()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '保存失败')
    }
  }

  const remove = async (tag: Tag) => {
    if (!window.confirm(`删除标签「${tag.name}」？引用它的条目会同时移除该标签。`)) return
    try {
      await request({ type: 'deleteTag', id: tag.id })
      reload()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '删除失败')
    }
  }

  return (
    <section className="card">
      <h2>标签</h2>
      {error !== undefined && <p className="error">{error}</p>}
      <ul className="entry-admin">
        {tags.map((tag) => (
          <li key={tag.id}>
            <span className="entry-admin-meta">
              <span className="swatch" style={{ background: tag.color }} />
              {editing?.id === tag.id ? (
                <input
                  value={editing.name}
                  onChange={(e) => setEditing({ ...editing, name: e.target.value })}
                />
              ) : (
                <b>{tag.name}</b>
              )}
            </span>
            <span className="row">
              {editing?.id === tag.id ? (
                <button className="primary" onClick={() => void save()}>
                  保存
                </button>
              ) : (
                <button
                  onClick={() => {
                    setEditing(tag)
                    setColor(tag.color)
                  }}
                >
                  编辑
                </button>
              )}
              <button className="danger" onClick={() => void remove(tag)}>
                删除
              </button>
            </span>
          </li>
        ))}
        {tags.length === 0 && <li className="hint">还没有标签</li>}
      </ul>
      <div className="row">
        <input placeholder="新标签名" value={name} onChange={(e) => setName(e.target.value)} />
        <input
          type="color"
          value={color}
          onChange={(e) => setColor(e.target.value)}
          aria-label="标签颜色"
        />
        <button className="primary" disabled={name.trim() === ''} onClick={() => void save()}>
          添加
        </button>
      </div>
    </section>
  )
}

function SettingsSection({ snapshot, reload }: { snapshot: Snapshot; reload: () => void }) {
  const [error, setError] = useState<string | undefined>()
  const settings = snapshot.settings
  const clipboardOn = settings.clipboardClearSeconds > 0

  const save = async (patch: Partial<typeof settings>, subdomainMatching?: boolean) => {
    try {
      await request({ type: 'saveSettings', settings: patch, subdomainMatching })
      reload()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '保存失败')
    }
  }

  return (
    <section className="card">
      <h2>设置</h2>
      {error !== undefined && <p className="error">{error}</p>}
      <label className="check">
        <input
          type="checkbox"
          checked={settings.previewNextCode}
          onChange={(e) => void save({ previewNextCode: e.target.checked })}
        />
        预提示：在当前验证码下方缩小显示下一周期的码
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={snapshot.subdomainMatching}
          onChange={(e) => void save({}, e.target.checked)}
        />
        域名子域匹配（绑定 github.com 时 gist.github.com 也置顶）
      </label>
      <label>
        默认排序
        <select
          value={settings.defaultSort}
          onChange={(e) => void save({ defaultSort: e.target.value })}
        >
          {SORT_MODES.map((mode) => (
            <option key={mode} value={mode}>
              {SORT_LABELS[mode] ?? mode}
            </option>
          ))}
        </select>
      </label>
      <label>
        空闲自动锁定（秒，最少 15）
        <input
          type="number"
          min={15}
          defaultValue={settings.autoLockSeconds}
          onBlur={(e) => {
            const value = Number(e.target.value)
            if (value !== settings.autoLockSeconds) void save({ autoLockSeconds: value })
          }}
        />
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={clipboardOn}
          onChange={(e) => void save({ clipboardClearSeconds: e.target.checked ? 45 : 0 })}
        />
        复制后自动清理剪贴板
      </label>
      {clipboardOn && (
        <label>
          清理延时（秒）
          <input
            type="number"
            min={30}
            max={300}
            defaultValue={settings.clipboardClearSeconds}
            onBlur={(e) => {
              const value = Number(e.target.value)
              if (value !== settings.clipboardClearSeconds) {
                void save({ clipboardClearSeconds: value })
              }
            }}
          />
        </label>
      )}
      <p className="hint">
        清理只会在剪贴板内容仍是本次复制的验证码时执行，不会碰你后来复制的其他内容。
      </p>
    </section>
  )
}

function TransferSection({ hasVault, reload }: { hasVault: boolean; reload: () => void }) {
  const [importFile, setImportFile] = useState<File | undefined>()
  const [sourcePassword, setSourcePassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [confirmReplace, setConfirmReplace] = useState(false)
  const [plaintextOpen, setPlaintextOpen] = useState(false)
  const [plaintextChecked, setPlaintextChecked] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | undefined>()
  const [message, setMessage] = useState<string | undefined>()

  const runImport = async () => {
    if (
      importFile === undefined ||
      sourcePassword === '' ||
      newPassword === '' ||
      newPassword !== confirm
    ) {
      return
    }
    setBusy(true)
    setError(undefined)
    try {
      await request({
        type: 'import',
        base64: await fileToBase64(importFile),
        sourcePassword,
        newPassword,
      })
      setMessage(`已导入 ${importFile.name} 并用新主密码重新加密`)
      setImportFile(undefined)
      setSourcePassword('')
      setNewPassword('')
      setConfirm('')
      setConfirmReplace(false)
      reload()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '导入失败')
    } finally {
      setBusy(false)
    }
  }

  const exportVault = async (plaintext: boolean) => {
    setBusy(true)
    setError(undefined)
    try {
      download(await request<ExportFile>({ type: 'export', plaintext }))
      setMessage(plaintext ? '明文备份已导出，请妥善保管并尽快删除' : '加密备份已导出')
      setPlaintextOpen(false)
      setPlaintextChecked(false)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '导出失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h2>导入 / 导出</h2>
      {error !== undefined && <p className="error">{error}</p>}
      {message !== undefined && <p className="ok">{message}</p>}

      <h3>导入 .mfavault 备份{hasVault ? '（将覆盖当前数据）' : ''}</h3>
      {hasVault && !confirmReplace ? (
        <button className="danger" onClick={() => setConfirmReplace(true)}>
          当前已有密钥库，点此开始覆盖导入
        </button>
      ) : (
        <>
          <label>
            备份文件
            <input
              type="file"
              accept=".mfavault,.json"
              onChange={(e) => {
                setImportFile(e.target.files?.[0])
                setMessage(undefined)
              }}
            />
          </label>
          <label>
            来源主密码
            <input
              type="password"
              value={sourcePassword}
              onChange={(e) => setSourcePassword(e.target.value)}
            />
          </label>
          <PasswordFields
            value={newPassword}
            confirm={confirm}
            onChange={setNewPassword}
            onConfirmChange={setConfirm}
          />
          <button
            className="primary"
            disabled={
              busy ||
              importFile === undefined ||
              sourcePassword === '' ||
              newPassword === '' ||
              newPassword !== confirm
            }
            onClick={() => void runImport()}
          >
            {busy ? '导入中…' : '导入并重新加密'}
          </button>
        </>
      )}

      <h3>导出</h3>
      <div className="row">
        <button
          className="primary"
          disabled={busy || !hasVault}
          onClick={() => void exportVault(false)}
        >
          导出加密备份（.mfavault）
        </button>
        <button
          className="danger"
          disabled={busy || !hasVault}
          onClick={() => setPlaintextOpen(true)}
        >
          导出明文备份…
        </button>
      </div>

      {plaintextOpen && (
        <div className="modal">
          <div className="modal-body">
            <h3>导出明文备份</h3>
            <p className="warning">
              明文备份 <b>不做任何加密</b>：任何拿到该文件的人都能直接读出你的全部验证码 secret。
              仅应在受信任的迁移场景使用，导出后请尽快删除。
            </p>
            <label className="check">
              <input
                type="checkbox"
                checked={plaintextChecked}
                onChange={(e) => setPlaintextChecked(e.target.checked)}
              />
              我已了解上述风险，确认继续
            </label>
            <div className="row end">
              <button
                onClick={() => {
                  setPlaintextOpen(false)
                  setPlaintextChecked(false)
                }}
              >
                取消
              </button>
              <button
                className="danger"
                disabled={!plaintextChecked}
                onClick={() => void exportVault(true)}
              >
                仍然导出明文
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

// ── 主框架 ───────────────────────────────────────────────────────────────────

function Dashboard({ initial, onGone }: { initial: Snapshot; onGone: () => void }) {
  const [snapshot, setSnapshot] = useState(initial)
  const [tab, setTab] = useState<'entries' | 'tags' | 'settings' | 'transfer'>('entries')

  const reload = useCallback(async () => {
    const next = await request<Snapshot>({ type: 'snapshot' })
    if (next.state !== 'ready') {
      onGone()
      return
    }
    setSnapshot(next)
  }, [onGone])

  const lock = async () => {
    await request({ type: 'lock' })
    onGone()
  }

  const sections: Record<typeof tab, ReactNode> = {
    entries: (
      <EntriesSection
        entries={snapshot.entries}
        tags={snapshot.tags}
        reload={() => void reload()}
      />
    ),
    tags: <TagsSection tags={snapshot.tags} reload={() => void reload()} />,
    settings: <SettingsSection snapshot={snapshot} reload={() => void reload()} />,
    transfer: <TransferSection hasVault reload={() => void reload()} />,
  }

  return (
    <main className="options">
      <header className="options-bar">
        <h1>MyMFA</h1>
        <span className="hint">{snapshot.entries.length} 个条目 · 已解锁</span>
        <button onClick={() => void lock()}>立即锁定</button>
      </header>
      <nav className="tabs">
        {(
          [
            ['entries', '条目'],
            ['tags', '标签'],
            ['settings', '设置'],
            ['transfer', '导入 / 导出'],
          ] as const
        ).map(([key, label]) => (
          <button key={key} className={tab === key ? 'tab on' : 'tab'} onClick={() => setTab(key)}>
            {label}
          </button>
        ))}
      </nav>
      {sections[tab]}
    </main>
  )
}

function App() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => {
    void request<Snapshot>({ type: 'snapshot' }).then(setSnapshot, () => setSnapshot(null))
  }, [reloadKey])

  const refresh = () => setReloadKey((key) => key + 1)

  if (snapshot === null) return <main className="options narrow">加载中…</main>
  if (snapshot.state === 'empty') return <SetupScreen onDone={refresh} />
  if (snapshot.state === 'locked') return <UnlockScreen onDone={refresh} />
  return <Dashboard initial={snapshot} onGone={refresh} />
}

createRoot(document.getElementById('root')!).render(<App />)
