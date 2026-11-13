import { fileURLToPath } from 'node:url'

const repoRoot = fileURLToPath(new URL('../..', import.meta.url))
const mobileHelpers = fileURLToPath(new URL('./vault-helpers-mobile.ts', import.meta.url))

/**
 * 用别名把 vault 单测的夹具 Provider 换成移动端 Provider 栈（#19 步骤 8）。
 *
 * 只在 `packages/vault/src/__tests__/*` 里把 `./helpers.js` 换成替换模块：被测代码、
 * 被测代码与该模块的相对导入都不动，因此 185 项测试本体一个字没改。
 *
 * 刻意不 import `defineConfig`：vitest 是各 package 的 devDependency、不提升到根，
 * 根目录的配置文件解析不到它。返回普通对象同样被 vitest 接受。
 */
export default {
  root: repoRoot,
  plugins: [
    {
      name: 'iloop-mobile-provider-swap',
      enforce: 'pre',
      resolveId(source, importer) {
        if (
          source === './helpers.js' &&
          importer !== undefined &&
          importer.includes('/packages/vault/src/__tests__/')
        ) {
          return mobileHelpers
        }
        return null
      },
    },
  ],
  test: {
    include: ['packages/vault/src/__tests__/*.test.ts'],
    environment: 'node',
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
}
