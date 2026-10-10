import { defineConfig } from 'wxt'

export default defineConfig({
  srcDir: 'src',
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'MyMFA',
    description: '纯本地验证码与预提示',
    permissions: ['storage', 'activeTab', 'clipboardWrite', 'clipboardRead', 'alarms', 'offscreen'],
    host_permissions: [],
    // hash-wasm 的 Argon2id（ADR-009 选定的唯一 WASM 依赖）在 MV3 下必须声明
    // wasm-unsafe-eval 才能编译 WebAssembly；这不是 unsafe-eval，不放开任何脚本执行面。
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
  },
})
