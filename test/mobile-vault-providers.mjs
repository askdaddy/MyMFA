#!/usr/bin/env node
/**
 * #19 步骤 8：让 `packages/vault` 的 185 项语义测试在**移动端 Provider 栈**上复跑。
 *
 * 口径说明（与 spec A2 一致）：原生 Kotlin 无法在 Node 进程里执行，所以这里注入的是
 * `createMobileProviders()` + Node 真实原语桥（argon2 / OpenSSL AES-GCM / zlib）。
 * 它证明 TS 适配层与 vault 契约相容；原生字节级正确性由 #17 的 Android gate 与
 * `NativeCryptoKATTest` 负责，两者不可互相替代。
 *
 * 用法：
 *   node test/mobile-vault-providers.mjs            正跑：要求 185 passed 且 KDF 真被调用
 *   node test/mobile-vault-providers.mjs --broken   负向对照：KDF 注入点必须让测试失败
 */
import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const broken = process.argv.includes('--broken')
const config = 'test/mobile/vitest.config.mts'
// vitest 是各 package 的 devDependency，不提升到根 node_modules；直接借 vault 的解析结果，
// 避免为一条 QA 脚本改动根 package.json。
const vitestBin = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../packages/vault/node_modules/vitest/vitest.mjs',
)

const result = spawnSync(
  process.execPath,
  [vitestBin, 'run', '--config', config, '--reporter=default'],
  {
    encoding: 'utf8',
    env: { ...process.env, ILOOP_MOBILE_BRIDGE: broken ? 'broken' : 'real' },
    maxBuffer: 32 * 1024 * 1024,
  },
)

const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`

if (broken) {
  const injected = output.includes('ILOOP_MOBILE_BRIDGE=broken')
  if (result.status === 0 || !injected) {
    console.error('[FAIL] 负向对照没有生效：移动 Provider 栈没有真正接到 vault 的测试路径上')
    console.error(output.slice(-4000))
    process.exit(1)
  }
  console.log('[PASS] 负向对照：注入点生效，KDF 被打桩后 185 项必然失败')
  process.exit(0)
}

const counts = /Tests\s+(\d+) failed \|\s*(\d+) passed|Tests\s+(\d+) passed/.exec(output)
const passed = counts ? Number(counts[2] ?? counts[3]) : 0
const failed = counts && counts[1] !== undefined ? Number(counts[1]) : 0
const injected = output.includes('[mobile-bridge] mobile provider stack injected')

if (result.status !== 0 || failed !== 0 || passed !== 185) {
  console.error(`[FAIL] 期望 185 passed / 0 failed，实际 ${passed} passed / ${failed} failed`)
  console.error(output.slice(-6000))
  process.exit(1)
}

if (!injected) {
  console.error('[FAIL] 185 项跑完了，但移动 Provider 栈没有被加载——注入没有生效')
  console.error(output.slice(-2000))
  process.exit(1)
}

console.log('[PASS] 185 项 vault 语义测试在移动端 Provider 栈（真实 Argon2id/AES-GCM/zlib）上通过')
