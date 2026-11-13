import { createMobileProviders } from '../../apps/mobile/src/crypto/providers.js'
import { nodeBridge } from './node-bridge.js'

/**
 * 把 `packages/vault/src/__tests__/helpers.ts` 里的夹具 Provider 换成移动端 Provider 栈
 * （#19 步骤 8）。夹具的其余部分（`makeEntry`、探针 Provider、记录型 Provider 等）原样复用
 * ——只换「加密能力从哪来」，这正是本项验收要证明的注入路径。
 */
export * from '../../packages/vault/src/__tests__/helpers.js'

const mobile = createMobileProviders(nodeBridge)

// 加载标记：驱动脚本据此确认「这 185 项确实跑在移动端 Provider 栈上」，
// 而不是默默退回 Node 夹具（那种情况下 185 也会全绿，但什么都没证明）。
console.log('[mobile-bridge] mobile provider stack injected into vault fixtures')

export const fixtureKdf = mobile.kdf
export const fixtureAead = mobile.aead
export const fixtureCompress = mobile.compress
export const fixtureRandom = mobile.random

export const fixtureProviders = {
  kdf: mobile.kdf,
  aead: mobile.aead,
  random: mobile.random,
  compress: mobile.compress,
}
