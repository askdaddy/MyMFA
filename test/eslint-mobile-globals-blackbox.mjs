import assert from 'node:assert/strict'
import { ESLint } from 'eslint'

const eslint = new ESLint()
const bannedProbe =
  'process.cwd(); Buffer.from("synthetic"); window.alert("x"); document.title; navigator.userAgent; localStorage.getItem("x"); chrome.storage;'
let passed = 0
async function check(name, run) {
  await run()
  passed += 1
  console.log('PASS ' + name)
}
async function lint(code, filePath) {
  const [result] = await eslint.lintText(code, { filePath })
  return result
}

await check('apps/mobile 源文件禁 Node/浏览器全局（#18 步骤 6 验收②）', async () => {
  for (const filePath of [
    'apps/mobile/probe.ts',
    'apps/mobile/modules/mymfa-native/src/probe.ts',
  ]) {
    const result = await lint(bannedProbe, filePath)
    const hit = result.messages.filter((m) => m.ruleId === 'no-restricted-globals')
    assert.ok(hit.length >= 6, `预期至少 6 个全局违例，实际 ${hit.length}（${filePath}）`)
  }
})

await check(
  'apps/mobile 放行 react-native / expo import（验收「react-native 放行」侧）',
  async () => {
    const code =
      "import { Text } from 'react-native';\nimport * as Expo from 'expo';\nexport { Text, Expo };\n"
    for (const filePath of ['apps/mobile/probe.tsx', 'apps/mobile/probe.ts']) {
      const result = await lint(code, filePath)
      assert.equal(
        result.messages.filter((m) => m.ruleId === 'no-restricted-imports').length,
        0,
        `react-native/expo import 不应被拦截（${filePath}）`,
      )
    }
  },
)

await check('packages/* 平台禁令零回归：RN import 在核心包仍被拦截', async () => {
  const result = await lint(
    "import { Text } from 'react-native';\nexport { Text };\n",
    'packages/otp/src/probe.ts',
  )
  assert.ok(result.messages.some((m) => m.ruleId === 'no-restricted-imports'))
})

await check('apps/mobile 配置文件豁免有据（app.config.ts 可用 process）', async () => {
  const result = await lint(
    'export default { extra: process.env.EXPO_PUBLIC_X };',
    'apps/mobile/app.config.ts',
  )
  assert.equal(
    result.messages.filter((m) => m.ruleId === 'no-restricted-globals').length,
    0,
    '配置文件在 Node 运行，不应受运行时全局禁令约束',
  )
})

console.log(passed + '/' + passed + ' apps/mobile ESLint boundary checks passed')
