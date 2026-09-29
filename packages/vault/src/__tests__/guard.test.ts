import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import { base64Encode, utf8Encode } from '@askdaddy/crypto'

import { VaultSchemaError } from '../errors.js'
import { assertVaultData } from '../guard.js'
import { DEFAULT_SETTINGS, type Settings } from '../types.js'
import { FAKE_SECRET_BASE64, makeEntry, makeTag, makeVaultData } from './helpers.js'

/** 模拟解密后的明文：可变、无类原型方法，与 `JSON.parse` 的产物形状一致。 */
function looseVault(): Record<string, unknown> {
  return JSON.parse(JSON.stringify(makeVaultData())) as Record<string, unknown>
}

function entryAt(vault: Record<string, unknown>, index = 0): Record<string, unknown> {
  return (vault.entries as Record<string, unknown>[])[index]!
}

function tagAt(vault: Record<string, unknown>, index = 0): Record<string, unknown> {
  return (vault.tags as Record<string, unknown>[])[index]!
}

function settingsOf(vault: Record<string, unknown>): Record<string, unknown> {
  return vault.settings as Record<string, unknown>
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

describe('合法输入', () => {
  it('返回的对象与输入是同一引用——守卫只判定不重建', () => {
    const vault = looseVault()
    const result = assertVaultData(vault)

    expect(result).toBe(vault)
    expect(result.meta).toBe(vault.meta)
    expect(result.entries).toBe(vault.entries)
    expect(result.entries[0]).toBe(entryAt(vault))
    expect(result.tags).toBe(vault.tags)
    expect(result.tags[0]).toBe(tagAt(vault))
    expect(result.settings).toBe(vault.settings)
  })

  it('空 entries 与空 tags 合法（新建 vault 就是空的）', () => {
    const vault = looseVault()
    vault.entries = []
    vault.tags = []

    expect(assertVaultData(vault).entries).toEqual([])
  })

  it('hotp 条目只需 counter，不需要 period', () => {
    const vault = looseVault()
    const hotp = entryAt(vault)
    hotp.kind = 'hotp'
    hotp.counter = 0
    delete hotp.period

    expect(() => assertVaultData(vault)).not.toThrow()
  })

  it('digits 取 6/7/8、algo 取三种摘要都合法', () => {
    for (const digits of [6, 7, 8]) {
      for (const algo of ['SHA1', 'SHA256', 'SHA512']) {
        const vault = looseVault()
        Object.assign(entryAt(vault), { digits, algo })
        expect(() => assertVaultData(vault)).not.toThrow()
      }
    }
  })

  it('lastUsedAt 为 null 合法', () => {
    const vault = looseVault()
    entryAt(vault).lastUsedAt = null

    expect(() => assertVaultData(vault)).not.toThrow()
  })

  it('position 只要求非空字符串，不要求可插值', () => {
    for (const position of ['a0', 'zzzz', '0', ' ', 'a'.repeat(200)]) {
      const vault = looseVault()
      entryAt(vault).position = position
      expect(() => assertVaultData(vault)).not.toThrow()
    }
  })

  it('tag 名不做大小写不敏感去重——那是 #5 的领域逻辑', () => {
    const vault = looseVault()
    vault.tags = [
      JSON.parse(JSON.stringify(makeTag({ name: 'Work' }))),
      JSON.parse(
        JSON.stringify(makeTag({ id: '019c0f6a-0000-7000-8000-00000000000b', name: 'work' })),
      ),
      JSON.parse(
        JSON.stringify(makeTag({ id: '019c0f6a-0000-7000-8000-00000000000c', name: 'WORK' })),
      ),
    ]

    expect(assertVaultData(vault).tags).toHaveLength(3)
  })

  it('校验后的返回值可直接按 VaultData / Entry 类型使用', () => {
    const result = assertVaultData(looseVault())

    expect(result.schemaVersion).toBe(1)
    expect(result.entries[0]!.secret).toBe(FAKE_SECRET_BASE64)
    expect(result.entries[0]!.digits).toBe(6)
    expect(result.tags[0]!.name).toBe('工作')
  })
})

describe('未知字段原样保留', () => {
  it('五层各放一个未知键，校验通过且键仍在对象上', () => {
    const vault = looseVault()
    vault.futureRootField = { nested: true }
    ;(vault.meta as Record<string, unknown>).futureMetaField = 'x'
    entryAt(vault).futureEntryField = 42
    tagAt(vault).futureTagField = null
    settingsOf(vault).futureSettingField = [1, 2, 3]

    const result = assertVaultData(vault) as unknown as Record<string, unknown>

    expect(result.futureRootField).toEqual({ nested: true })
    expect((result.meta as Record<string, unknown>).futureMetaField).toBe('x')
    expect((result.entries as Record<string, unknown>[])[0]!.futureEntryField).toBe(42)
    expect((result.tags as Record<string, unknown>[])[0]!.futureTagField).toBeNull()
    expect((result.settings as Record<string, unknown>).futureSettingField).toEqual([1, 2, 3])
  })
})

interface BadCase {
  readonly label: string
  readonly path: string
  readonly patch: (vault: Record<string, unknown>) => void
}

const drop =
  (target: (v: Record<string, unknown>) => Record<string, unknown>, key: string) =>
  (vault: Record<string, unknown>): void => {
    delete target(vault)[key]
  }

const set =
  (target: (v: Record<string, unknown>) => Record<string, unknown>, key: string, value: unknown) =>
  (vault: Record<string, unknown>): void => {
    target(vault)[key] = value
  }

const BAD_CASES: readonly BadCase[] = [
  { label: 'schemaVersion 缺失', path: 'schemaVersion', patch: drop((v) => v, 'schemaVersion') },
  {
    label: 'schemaVersion 是小数',
    path: 'schemaVersion',
    patch: set((v) => v, 'schemaVersion', 1.5),
  },
  {
    label: 'schemaVersion 是 NaN',
    path: 'schemaVersion',
    patch: set((v) => v, 'schemaVersion', Number.NaN),
  },
  { label: 'meta 缺失', path: 'meta', patch: drop((v) => v, 'meta') },
  {
    label: 'meta.createdAt 是字符串',
    path: 'meta.createdAt',
    patch: set((v) => v.meta as Record<string, unknown>, 'createdAt', '1737000000000'),
  },
  {
    label: 'meta.appVersion 是空串',
    path: 'meta.appVersion',
    patch: set((v) => v.meta as Record<string, unknown>, 'appVersion', ''),
  },
  { label: 'entries 缺失', path: 'entries', patch: drop((v) => v, 'entries') },
  { label: 'entries 不是数组', path: 'entries', patch: set((v) => v, 'entries', {}) },
  { label: 'entries 是字符串', path: 'entries', patch: set((v) => v, 'entries', 'none') },
  { label: 'tags 不是数组', path: 'tags', patch: set((v) => v, 'tags', null) },
  { label: 'settings 缺失', path: 'settings', patch: drop((v) => v, 'settings') },
  { label: 'settings 不是对象', path: 'settings', patch: set((v) => v, 'settings', []) },
  { label: '条目不是对象', path: 'entries[0]', patch: set((v) => v, 'entries', [null]) },
  { label: 'entry.id 缺失', path: 'entries[0].id', patch: drop(entryAt, 'id') },
  { label: 'entry.id 是空串', path: 'entries[0].id', patch: set(entryAt, 'id', '') },
  { label: 'entry.kind 缺失', path: 'entries[0].kind', patch: drop(entryAt, 'kind') },
  { label: 'entry.kind 取值越界', path: 'entries[0].kind', patch: set(entryAt, 'kind', 'xotp') },
  { label: 'entry.issuer 是数字', path: 'entries[0].issuer', patch: set(entryAt, 'issuer', 7) },
  { label: 'entry.account 缺失', path: 'entries[0].account', patch: drop(entryAt, 'account') },
  { label: 'entry.secret 缺失', path: 'entries[0].secret', patch: drop(entryAt, 'secret') },
  { label: 'entry.secret 是空串', path: 'entries[0].secret', patch: set(entryAt, 'secret', '') },
  {
    label: 'entry.secret 不是合法 base64',
    path: 'entries[0].secret',
    patch: set(entryAt, 'secret', '!!!!not-base64!!!!'),
  },
  {
    label: 'entry.secret 解码后为空',
    path: 'entries[0].secret',
    patch: set(entryAt, 'secret', '===='),
  },
  { label: 'entry.algo 取值越界', path: 'entries[0].algo', patch: set(entryAt, 'algo', 'MD5') },
  { label: 'entry.digits 过小', path: 'entries[0].digits', patch: set(entryAt, 'digits', 5) },
  { label: 'entry.digits 过大', path: 'entries[0].digits', patch: set(entryAt, 'digits', 9) },
  { label: 'entry.digits 是小数', path: 'entries[0].digits', patch: set(entryAt, 'digits', 6.5) },
  {
    label: 'entry.digits 是 NaN',
    path: 'entries[0].digits',
    patch: set(entryAt, 'digits', Number.NaN),
  },
  {
    label: 'entry.digits 是 Infinity',
    path: 'entries[0].digits',
    patch: set(entryAt, 'digits', Number.POSITIVE_INFINITY),
  },
  { label: 'entry.digits 是字符串', path: 'entries[0].digits', patch: set(entryAt, 'digits', '6') },
  { label: 'totp 缺 period', path: 'entries[0].period', patch: drop(entryAt, 'period') },
  { label: 'totp 的 period 为 0', path: 'entries[0].period', patch: set(entryAt, 'period', 0) },
  { label: 'totp 的 period 是负数', path: 'entries[0].period', patch: set(entryAt, 'period', -30) },
  { label: 'entry.tagIds 不是数组', path: 'entries[0].tagIds', patch: set(entryAt, 'tagIds', 'a') },
  {
    label: 'entry.tagIds 元素不是字符串',
    path: 'entries[0].tagIds[1]',
    patch: set(entryAt, 'tagIds', ['a', 2]),
  },
  { label: 'entry.note 缺失', path: 'entries[0].note', patch: drop(entryAt, 'note') },
  {
    label: 'entry.sites 不是数组',
    path: 'entries[0].sites',
    patch: set(entryAt, 'sites', 'github.com'),
  },
  {
    label: 'entry.usageCount 是负数',
    path: 'entries[0].usageCount',
    patch: set(entryAt, 'usageCount', -1),
  },
  {
    label: 'entry.usageCount 是小数',
    path: 'entries[0].usageCount',
    patch: set(entryAt, 'usageCount', 1.5),
  },
  {
    label: 'entry.lastUsedAt 是字符串',
    path: 'entries[0].lastUsedAt',
    patch: set(entryAt, 'lastUsedAt', 'never'),
  },
  {
    label: 'entry.position 是空串',
    path: 'entries[0].position',
    patch: set(entryAt, 'position', ''),
  },
  {
    label: 'entry.position 是数字',
    path: 'entries[0].position',
    patch: set(entryAt, 'position', 3),
  },
  {
    label: 'entry.favorite 是字符串',
    path: 'entries[0].favorite',
    patch: set(entryAt, 'favorite', 'yes'),
  },
  {
    label: 'entry.createdAt 是 Infinity',
    path: 'entries[0].createdAt',
    patch: set(entryAt, 'createdAt', Number.POSITIVE_INFINITY),
  },
  {
    label: 'entry.updatedAt 缺失',
    path: 'entries[0].updatedAt',
    patch: drop(entryAt, 'updatedAt'),
  },
  {
    label: 'hotp 缺 counter',
    path: 'entries[0].counter',
    patch: (v) => {
      entryAt(v).kind = 'hotp'
      delete entryAt(v).period
    },
  },
  {
    label: 'hotp 的 counter 是负数',
    path: 'entries[0].counter',
    patch: (v) => {
      entryAt(v).kind = 'hotp'
      entryAt(v).counter = -1
    },
  },
  { label: 'tag 不是对象', path: 'tags[0]', patch: set((v) => v, 'tags', ['工作']) },
  { label: 'tag.id 是空串', path: 'tags[0].id', patch: set(tagAt, 'id', '') },
  { label: 'tag.name 是空串', path: 'tags[0].name', patch: set(tagAt, 'name', '') },
  { label: 'tag.name 缺失', path: 'tags[0].name', patch: drop(tagAt, 'name') },
  { label: 'tag.color 缺失', path: 'tags[0].color', patch: drop(tagAt, 'color') },
  { label: 'tag.position 是空串', path: 'tags[0].position', patch: set(tagAt, 'position', '') },
]

describe('非法输入', () => {
  it('根是数组、null、字符串或 undefined 时抛 VaultSchemaError 且路径为 vault', () => {
    for (const root of [[], null, 'vault', 42, undefined]) {
      expect(() => assertVaultData(root)).toThrow(VaultSchemaError)
      expect(() => assertVaultData(root)).toThrow('vault')
    }
  })

  for (const { label, path, patch } of BAD_CASES) {
    it(`${label} → message 含字段路径 ${path}`, () => {
      const vault = looseVault()
      patch(vault)

      expect(() => assertVaultData(vault)).toThrow(VaultSchemaError)
      expect(() => assertVaultData(vault)).toThrow(path)
    })
  }

  it('字段路径带上出错的数组下标（entries[3]）', () => {
    const vault = looseVault()
    vault.entries = [makeEntry(), makeEntry(), makeEntry(), makeEntry()].map(
      (e) => JSON.parse(JSON.stringify(e)) as Record<string, unknown>,
    )
    entryAt(vault, 3).secret = '!!!!'

    expect(() => assertVaultData(vault)).toThrow('entries[3].secret')
  })

  it('algo 用 WebCrypto 的连字符拼写会被拒绝——vault 存的是 otpauth 拼写', () => {
    const vault = looseVault()
    entryAt(vault).algo = 'SHA-1'

    expect(() => assertVaultData(vault)).toThrow(VaultSchemaError)
    expect(() => assertVaultData(vault)).toThrow('entries[0].algo')
  })
})

describe('C1：错误消息不泄露 secret', () => {
  for (const offending of ['!!!!not-base64!!!!', '====', 'JBSWY3DPEHPK3PXP!']) {
    it(`"${offending}" 的原文、base64 与 hex 形式都不出现在 message 中`, () => {
      const vault = looseVault()
      entryAt(vault).secret = offending

      let message = ''
      try {
        assertVaultData(vault)
      } catch (error) {
        message = (error as Error).message
      }

      expect(message).not.toBe('')
      expect(message).not.toContain(offending)
      expect(message).not.toContain(base64Encode(utf8Encode(offending)))
      expect(message).not.toContain(toHex(utf8Encode(offending)))
      expect(message).toContain('entries[0].secret')
    })
  }

  it('合法 secret 通过校验，且它的 base64 与 hex 形式不出现在任何错误里', () => {
    const vault = looseVault()
    entryAt(vault).secret = FAKE_SECRET_BASE64

    expect(() => assertVaultData(vault)).not.toThrow()
    expect(FAKE_SECRET_BASE64).toBe(base64Encode(utf8Encode('JBSWY3DPEHPK3PXP')))
    expect(toHex(utf8Encode('JBSWY3DPEHPK3PXP'))).toBe('4a425357593344504548504b33505850')
  })
})

describe('D4：settings 宽松', () => {
  it('缺失的字段按 DEFAULT_SETTINGS 填充，且对象仍是同一引用', () => {
    const vault = looseVault()
    vault.settings = {}
    const before = settingsOf(vault)

    const result = assertVaultData(vault)

    expect(result.settings).toBe(before)
    expect(result.settings).toEqual(DEFAULT_SETTINGS)
  })

  it('类型不符的已知字段回落默认值而不抛错', () => {
    const bad: Record<keyof Settings, unknown> = {
      defaultSort: 42,
      previewNextCode: 'yes',
      autoLockSeconds: '60',
      clockOffsetSeconds: Number.NaN,
      clipboardClearSeconds: 30.5,
      searchPinyin: 1,
      requireBiometric: null,
    }

    for (const key of Object.keys(bad) as (keyof Settings)[]) {
      const vault = looseVault()
      settingsOf(vault)[key] = bad[key]

      expect(() => assertVaultData(vault)).not.toThrow()
      expect(assertVaultData(vault).settings[key]).toBe(DEFAULT_SETTINGS[key])
    }
  })

  it('合法的 settings 值原样保留，不被默认值覆盖', () => {
    const vault = looseVault()
    Object.assign(settingsOf(vault), {
      defaultSort: 'issuer',
      previewNextCode: false,
      autoLockSeconds: 0,
      clockOffsetSeconds: -12,
      clipboardClearSeconds: 0,
      searchPinyin: false,
      requireBiometric: true,
    })

    expect(assertVaultData(vault).settings).toEqual({
      defaultSort: 'issuer',
      previewNextCode: false,
      autoLockSeconds: 0,
      clockOffsetSeconds: -12,
      clipboardClearSeconds: 0,
      searchPinyin: false,
      requireBiometric: true,
    })
  })
})

describe('C17：不引入三方校验库', () => {
  it('guard.ts 只 import 相对模块与 @askdaddy 内部包', () => {
    const source = readFileSync(fileURLToPath(new URL('../guard.ts', import.meta.url)), 'utf8')
    const specifiers = [...source.matchAll(/from '([^']+)'/g)].map((m) => m[1]!)
    const external = specifiers.filter((s) => !s.startsWith('.') && !s.startsWith('@askdaddy/'))

    expect(external).toEqual([])
  })

  it('package.json 的运行时依赖全部是 workspace 内部包', () => {
    const manifest = JSON.parse(
      readFileSync(fileURLToPath(new URL('../../package.json', import.meta.url)), 'utf8'),
    ) as { dependencies?: Record<string, string> }

    expect(
      Object.values(manifest.dependencies ?? {}).every((v) => v.startsWith('workspace:')),
    ).toBe(true)
  })
})
