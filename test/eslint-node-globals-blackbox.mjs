import assert from 'node:assert/strict'
import { ESLint } from 'eslint'

const eslint = new ESLint()
const probe = 'console.log("synthetic"); process.cwd(); Buffer.from("synthetic");'
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

await check('根级最小Node脚本runtime与真实文件lint', async () => {
  assert.equal(Buffer.from('synthetic').length, 9)
  assert.equal(typeof process.version, 'string')
  const [result] = await eslint.lintFiles('test/eslint-node-globals-blackbox.mjs')
  assert.equal(result.errorCount, 0)
})
await check('根级嵌套test路径三全局可用，未知名称仍拒绝', async () => {
  for (const filePath of ['test/probe.mjs', 'test/nested/probe.mjs'])
    assert.equal((await lint(probe, filePath)).errorCount, 0)
  const result = await lint('unknownQaName();', 'test/probe.mjs')
  assert.ok(result.messages.some((m) => m.ruleId === 'no-undef'))
})
await check('根级三全局readonly，不允许赋值', async () => {
  for (const name of ['console', 'process', 'Buffer']) {
    const result = await lint(name + ' = null;', 'test/probe.mjs')
    assert.ok(result.messages.some((m) => m.ruleId === 'no-global-assign'))
  }
})
for (const pkg of ['otp', 'crypto', 'crypto-web', 'vault', 'transfer', 'domain']) {
  await check(pkg + '生产/包内测试未获新增globals，平台与Node导入禁令有效', async () => {
    const filePath = 'packages/' + pkg + '/src/probe.ts'
    const result = await lint(probe, filePath)
    assert.ok(result.messages.some((m) => m.ruleId === 'no-console'))
    for (const name of ['process', 'Buffer'])
      assert.ok(
        result.messages.some(
          (m) => m.ruleId === 'no-restricted-globals' && m.message.includes(name),
        ),
      )
    const imported = await lint(
      "import { readFile } from 'node:fs'; export { readFile };",
      filePath,
    )
    assert.ok(imported.messages.some((m) => m.ruleId === 'no-restricted-imports'))
    for (const suffix of ['src/probe.ts', 'src/__tests__/probe.test.ts']) {
      const config = await eslint.calculateConfigForFile('packages/' + pkg + '/' + suffix)
      for (const name of ['console', 'process', 'Buffer'])
        assert.equal(Object.hasOwn(config.languageOptions.globals ?? {}, name), false)
    }
  })
}
await check('内部依赖与非法动态执行规则保持', async () => {
  const result = await lint(
    "import { x } from '@askdaddy/domain'; export { x };",
    'packages/vault/src/probe.ts',
  )
  assert.ok(result.messages.some((m) => m.ruleId === 'no-restricted-imports'))
  const dynamic = await lint('eval("synthetic");', 'test/probe.mjs')
  assert.ok(dynamic.messages.some((m) => m.ruleId === 'no-eval'))
})
console.log(passed + '/' + passed + ' ESLint boundary checks passed')
