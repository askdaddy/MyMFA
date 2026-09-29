import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import { VaultFormatError, VaultSchemaError, VaultVersionError } from '../errors.js'
import { assertContainerVersion, MIGRATIONS, migrateVaultData } from '../migrate.js'
import { CONTAINER_VERSION, DEFAULT_SETTINGS, SCHEMA_VERSION } from '../types.js'
import { FAKE_SECRET_BASE64 } from './helpers.js'

const FIXTURE_DIR = new URL('../__fixtures__/', import.meta.url)

function loadFixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(fileURLToPath(new URL(name, FIXTURE_DIR)), 'utf8')) as Record<
    string,
    unknown
  >
}

/** 夹具是「另一个版本的 App 写出来的文件」，必须从磁盘读，不能在测试里现造。 */
const V0 = 'schema-v0.json'
const CONTAINER_V99 = 'container-schema-v99.json'

function entriesOf(data: Record<string, unknown>): Record<string, unknown>[] {
  return data.entries as Record<string, unknown>[]
}

describe('迁移链的结构', () => {
  it('MIGRATIONS 按位置索引，长度恰为 SCHEMA_VERSION', () => {
    expect(MIGRATIONS).toHaveLength(SCHEMA_VERSION)
  })

  it('第 i 项的函数名就是 migrate_i_to_i+1，不存在跳版本入口', () => {
    expect(MIGRATIONS.map((m) => m.name)).toEqual(['migrate_0_to_1'])
  })
})

describe('schemaVersion 0 的夹具', () => {
  it('迁移后 schemaVersion === 1 且通过守卫', () => {
    const result = migrateVaultData(loadFixture(V0))

    expect(result.schemaVersion).toBe(1)
    expect(result.entries).toHaveLength(2)
    expect(result.tags).toHaveLength(1)
  })

  it('迁移是逐级的，被调用的函数依次为 migrate_0_to_1', () => {
    const trace: string[] = []
    migrateVaultData(loadFixture(V0), trace)

    expect(trace).toEqual(['migrate_0_to_1'])
  })

  it('v0 缺失的 settings 被填成 DEFAULT_SETTINGS', () => {
    expect(loadFixture(V0).settings).toBeUndefined()
    expect(migrateVaultData(loadFixture(V0)).settings).toEqual(DEFAULT_SETTINGS)
  })

  it('条目内容逐项保持不变，迁移没有顺手改数据', () => {
    const before = entriesOf(loadFixture(V0))
    const after = migrateVaultData(loadFixture(V0)).entries as unknown as Record<string, unknown>[]

    expect(after).toEqual(before)
  })

  it('v0 的未知根字段迁移后仍在（前向兼容）', () => {
    const result = migrateVaultData(loadFixture(V0)) as unknown as Record<string, unknown>

    expect(result.legacyFieldFromV0).toBe('v0 时代的字段，迁移后必须原样保留')
  })

  it('夹具里的 secret 全是假值（AGENTS.md §5.3）', () => {
    for (const entry of entriesOf(loadFixture(V0))) {
      expect(entry.secret).toBe(FAKE_SECRET_BASE64)
    }
  })
})

describe('迁移函数的纯度', () => {
  it('不修改入参对象', () => {
    const input = loadFixture(V0)
    const snapshot = JSON.stringify(input)

    migrateVaultData(input)

    expect(JSON.stringify(input)).toBe(snapshot)
  })

  it('同一输入两次调用产出深度相等的结果', () => {
    expect(migrateVaultData(loadFixture(V0))).toEqual(migrateVaultData(loadFixture(V0)))
  })

  it('schemaVersion 已等于当前值时不执行任何迁移函数', () => {
    const current = migrateVaultData(loadFixture(V0))
    const trace: string[] = []

    const result = migrateVaultData(current, trace)

    expect(trace).toEqual([])
    expect(result).toBe(current)
  })

  it('已是当前版本时返回同一引用，不重建对象', () => {
    const input = migrateVaultData(loadFixture(V0))

    expect(migrateVaultData(input)).toBe(input)
  })
})

describe('schemaVersion 校验', () => {
  it('高于当前值时抛 VaultVersionError 并提示升级', () => {
    for (const version of [2, 99, SCHEMA_VERSION + 1]) {
      const data = { ...migrateVaultData(loadFixture(V0)), schemaVersion: version }

      expect(() => migrateVaultData(data)).toThrow(VaultVersionError)
      expect(() => migrateVaultData(data)).toThrow('请升级 App')
    }
  })

  it('不是非负整数时抛 VaultSchemaError', () => {
    const base = migrateVaultData(loadFixture(V0)) as unknown as Record<string, unknown>

    for (const version of [undefined, null, '1', 1.5, Number.NaN, -1]) {
      expect(() => migrateVaultData({ ...base, schemaVersion: version })).toThrow(VaultSchemaError)
    }
  })

  it('根不是对象时抛 VaultSchemaError', () => {
    for (const root of [null, [], 'vault', 42, undefined]) {
      expect(() => migrateVaultData(root)).toThrow(VaultSchemaError)
    }
  })

  it('迁移后仍不合法的数据被守卫拦下，不会被写回', () => {
    const data = loadFixture(V0)
    delete entriesOf(data)[0]!.secret

    expect(() => migrateVaultData(data)).toThrow(VaultSchemaError)
    expect(() => migrateVaultData(data)).toThrow('entries[0].secret')
  })
})

describe('容器头部的版本闸门', () => {
  it('schemaVersion 99 的容器夹具被拒绝，抛 VaultVersionError', () => {
    expect(() => assertContainerVersion(loadFixture(CONTAINER_V99))).toThrow(VaultVersionError)
    expect(() => assertContainerVersion(loadFixture(CONTAINER_V99))).toThrow('schemaVersion=99')
  })

  it('闸门只看头部两个整数字段，不接受任何 Provider——结构上无法触发解密', () => {
    expect(assertContainerVersion).toHaveLength(1)
  })

  it('容器 version 高于当前值时同样拒绝', () => {
    const container = loadFixture(CONTAINER_V99)
    container.schemaVersion = SCHEMA_VERSION
    container.version = CONTAINER_VERSION + 1

    expect(() => assertContainerVersion(container)).toThrow(VaultVersionError)
    expect(() => assertContainerVersion(container)).toThrow('version=2')
  })

  it('两个版本号都等于当前值时放行', () => {
    const container = loadFixture(CONTAINER_V99)
    container.schemaVersion = SCHEMA_VERSION
    container.version = CONTAINER_VERSION

    expect(() => assertContainerVersion(container)).not.toThrow()
  })

  it('头部版本号不是整数时抛 VaultFormatError（文件已损坏）', () => {
    for (const field of ['version', 'schemaVersion']) {
      for (const value of ['1', 1.5, null, undefined]) {
        const container = loadFixture(CONTAINER_V99)
        container[field] = value

        expect(() => assertContainerVersion(container)).toThrow(VaultFormatError)
      }
    }
  })
})

describe('夹具本身的安全性', () => {
  it('文件名不含 .mfavault，也不会被 .gitignore 的备份模式命中', () => {
    const names = readdirSync(fileURLToPath(FIXTURE_DIR))

    expect(names.length).toBeGreaterThan(0)
    for (const name of names) {
      expect(name).not.toContain('mfavault')
      expect(name).toMatch(/\.json$/)
      expect(name).not.toMatch(/backup|aegis|2fas|authenticator|secrets|credentials|qr-/i)
    }
  })

  it('v99 容器夹具的 data 不是真密文，而是可读的占位串', () => {
    const container = loadFixture(CONTAINER_V99)
    const decoded = Buffer.from(container.data as string, 'base64').toString('utf8')

    expect(decoded).toBe('FIXTURE-NOT-REAL-CIPHERTEXT')
  })

  it('v99 容器夹具的字段字节长度与真实容器一致，只是版本号来自未来', () => {
    const { crypto } = loadFixture(CONTAINER_V99) as {
      crypto: {
        kdf: { salt: string }
        cipher: { nonce: string; tag: string }
        wrappedMasterKey: { nonce: string; tag: string; data: string }
      }
    }
    const len = (b64: string) => Buffer.from(b64, 'base64').byteLength

    expect(len(crypto.kdf.salt)).toBe(16)
    expect(len(crypto.cipher.nonce)).toBe(12)
    expect(len(crypto.cipher.tag)).toBe(16)
    expect(len(crypto.wrappedMasterKey.nonce)).toBe(12)
    expect(len(crypto.wrappedMasterKey.tag)).toBe(16)
    expect(len(crypto.wrappedMasterKey.data)).toBe(32)
  })
})
