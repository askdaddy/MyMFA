import { describe, expect, it } from 'vitest'

import { AES_256_GCM } from '@askdaddy/crypto'

import { createVault, openVault, openVaultWithDek } from '../container.js'
import { VaultAuthError, VaultFormatError, VaultLockedError } from '../errors.js'
import { assertVaultData } from '../guard.js'
import type { VaultHandle, VaultProviders } from '../types.js'
import { fixtureProviders, makeEntry, makeTag } from './helpers.js'

const PASSWORD = 'correct horse battery staple'
const APP_VERSION = '1.0.0'
const NOW = 1_737_000_000_000
const fixedNow = (): number => NOW

/**
 * 步骤 3 的场景骨架：解锁 → 序列化落盘 → SW 内存丢失 → 凭 session DEK 重新打开。
 * 对应 `docs/chrome-extension.md` §5「Argon2id 派生中间态随 SW 回收失效，可从 DEK 恢复」。
 */
async function unlockAndPersist(
  providers: VaultProviders,
): Promise<{ bytes: Uint8Array; dek: Uint8Array; handle: VaultHandle }> {
  const created = await createVault(PASSWORD, providers, { appVersion: APP_VERSION, now: fixedNow })
  created.replaceData({
    ...created.data,
    entries: [makeEntry({ id: 'entry-1', issuer: 'Example' })],
    tags: [makeTag({ id: 'tag-1', name: '工作' })],
  })
  const bytes = await created.serialize()
  return { bytes, dek: created.sessionDek(), handle: created }
}

describe('openVaultWithDek', () => {
  it('SW 内存丢失后凭 session DEK 重新打开同一容器，数据一致', async () => {
    const { bytes, dek } = await unlockAndPersist(fixtureProviders)

    const reopened = await openVaultWithDek(bytes, dek, fixtureProviders)
    expect(reopened.data.entries.map((entry) => entry.id)).toEqual(['entry-1'])
    expect(reopened.data.tags.map((tag) => tag.id)).toEqual(['tag-1'])
  })

  it('会话恢复后可修改数据，且能用主密码再次打开并看到修改', async () => {
    const { bytes, dek } = await unlockAndPersist(fixtureProviders)

    const reopened = await openVaultWithDek(bytes, dek, fixtureProviders)
    reopened.replaceData({
      ...reopened.data,
      entries: [...reopened.data.entries, makeEntry({ id: 'entry-2', issuer: 'Added' })],
    })
    const next = await reopened.serialize()

    const byPassword = await openVault(next, PASSWORD, fixtureProviders)
    expect(byPassword.data.entries.map((entry) => entry.id)).toEqual(['entry-1', 'entry-2'])
  })

  it('错误的 DEK 被拒绝（认证失败归并为主密码类错误）', async () => {
    const { bytes } = await unlockAndPersist(fixtureProviders)

    const wrongDek = new Uint8Array(AES_256_GCM.keyLength).fill(0xab)
    await expect(openVaultWithDek(bytes, wrongDek, fixtureProviders)).rejects.toThrow(
      VaultAuthError,
    )
  })

  it('长度不合规的 DEK 在触碰任何 Provider 之前被拒绝', async () => {
    const { bytes } = await unlockAndPersist(fixtureProviders)

    await expect(
      openVaultWithDek(bytes, new Uint8Array(AES_256_GCM.keyLength - 1), fixtureProviders),
    ).rejects.toThrow(VaultAuthError)
    await expect(
      openVaultWithDek(bytes, 'not-bytes' as unknown as Uint8Array, fixtureProviders),
    ).rejects.toThrow(VaultAuthError)
  })

  it('非加密容器与畸形字节走既有格式错误路径', async () => {
    const dek = new Uint8Array(AES_256_GCM.keyLength)

    await expect(openVaultWithDek(new Uint8Array([0x7b]), dek, fixtureProviders)).rejects.toThrow(
      VaultFormatError,
    )
    await expect(
      openVaultWithDek(new TextEncoder().encode('{"format":"nope"}'), dek, fixtureProviders),
    ).rejects.toThrow(VaultFormatError)
  })
})

describe('VaultHandle 会话扩展（#6 步骤 3）', () => {
  it('sessionDek 返回拷贝：改写返回值不影响句柄继续工作', async () => {
    const providers = fixtureProviders
    const { dek, handle, bytes } = await unlockAndPersist(providers)

    dek.fill(0xff)

    const again = await handle.serialize()
    const reopened = await openVaultWithDek(again, handle.sessionDek(), providers)
    expect(reopened.data.entries).toHaveLength(1)
    await expect(openVault(bytes, PASSWORD, providers)).resolves.toBeTruthy()
  })

  it('replaceData 拒绝无效数据，句柄保持原数据可用', async () => {
    const { handle } = await unlockAndPersist(fixtureProviders)

    expect(() =>
      handle.replaceData({
        ...handle.data,
        entries: [{ ...makeEntry({ id: 'bad' }), digits: 9 as 6 }],
      }),
    ).toThrow()
    expect(handle.data.entries).toHaveLength(1)
    expect(() => handle.replaceData(assertVaultData(handle.data))).not.toThrow()
  })

  it('锁定后旧句柄不可用：data / replaceData / sessionDek / serialize 全部拒绝', async () => {
    const { handle } = await unlockAndPersist(fixtureProviders)

    handle.lock()
    handle.lock()

    expect(() => handle.data).toThrow(VaultLockedError)
    expect(() => handle.replaceData(handle.data)).toThrow(VaultLockedError)
    expect(() => handle.sessionDek()).toThrow(VaultLockedError)
    await expect(handle.serialize()).rejects.toThrow(VaultLockedError)
  })
})
