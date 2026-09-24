import js from '@eslint/js'
import tseslint from 'typescript-eslint'

const INTERNAL_PACKAGES = ['otp', 'crypto', 'vault', 'transfer', 'domain']
const APP_PACKAGES = ['mobile', 'extension', 'desktop']

/**
 * 依赖方向白名单（docs/architecture.md §3）。
 * 用白名单而非黑名单：新增内部包时不会漏掉规则。
 */
const INTERNAL_DEPS = {
  otp: [],
  crypto: [],
  vault: ['crypto', 'otp'],
  transfer: ['vault', 'crypto', 'otp'],
  domain: ['vault'],
}

const NODE_BUILTINS = [
  'assert',
  'async_hooks',
  'buffer',
  'child_process',
  'cluster',
  'console',
  'constants',
  'crypto',
  'dgram',
  'diagnostics_channel',
  'dns',
  'domain',
  'events',
  'fs',
  'http',
  'http2',
  'https',
  'inspector',
  'module',
  'net',
  'os',
  'path',
  'perf_hooks',
  'process',
  'punycode',
  'querystring',
  'readline',
  'repl',
  'stream',
  'string_decoder',
  'timers',
  'tls',
  'trace_events',
  'tty',
  'url',
  'util',
  'v8',
  'vm',
  'wasi',
  'worker_threads',
  'zlib',
]

const NODE_MESSAGE =
  'packages/* 禁止 Node 内置模块：Hermes 与 MV3 service worker 都没有，平台能力必须通过注入的 Provider 提供（AGENTS.md §3）'

/**
 * 裸模块名一律走 `paths` 精确匹配，不走 `patterns`。
 * patterns 是 gitignore 风格、只按 basename 匹配，`crypto` 会连带命中 `@askdaddy/crypto`，
 * 从而让 vault 无法合法依赖 crypto——这是必须避免的误报。
 */
const NODE_BUILTIN_PATHS = NODE_BUILTINS.map((name) => ({ name, message: NODE_MESSAGE }))

// 与内部包重名的内置模块（crypto、domain）不能生成 `name/*` 子路径 pattern，理由同上。
const NODE_SUBPATH_PATTERNS = NODE_BUILTINS.filter((name) => !INTERNAL_PACKAGES.includes(name)).map(
  (name) => `${name}/*`,
)

const PLATFORM_PATTERNS = [
  {
    group: ['react-native', 'react-native-*', '@react-native-*/*', '@react-native-community/*'],
    message: 'packages/* 禁止 React Native API，改用注入的 Provider（AGENTS.md §3）',
  },
  {
    group: ['expo', 'expo-*'],
    message: 'packages/* 禁止 Expo API，改用注入的 Provider（AGENTS.md §3）',
  },
  {
    group: ['wxt', 'wxt/*', '@wxt-dev/*'],
    message: 'packages/* 禁止扩展框架 API，改用注入的 Provider（AGENTS.md §3）',
  },
  {
    group: ['@tauri-apps/*'],
    message: 'packages/* 禁止 Tauri API，改用注入的 Provider（AGENTS.md §3）',
  },
  {
    group: ['hash-wasm', 'argon2-*', 'libsodium*'],
    message:
      '平台相关的加密实现只能放在 apps/* 的 Provider 里；packages/crypto 只定义接口与参数常量（AGENTS.md §5.1）',
  },
  {
    group: ['node:*', ...NODE_SUBPATH_PATTERNS],
    message: NODE_MESSAGE,
  },
  {
    group: APP_PACKAGES.map((app) => `@askdaddy/${app}`),
    message: 'packages/* 禁止反向依赖 apps/*（docs/architecture.md §3）',
  },
]

const PLATFORM_GLOBALS = [
  'window',
  'document',
  'navigator',
  'location',
  'localStorage',
  'sessionStorage',
  'indexedDB',
  'chrome',
  'browser',
  'process',
  'global',
  'globalThis',
  'self',
  'Buffer',
  'require',
]

function internalDepMessage(pkg, allowed) {
  if (allowed.length === 0) {
    return `packages/${pkg} 是叶子包，不允许依赖任何内部包（docs/architecture.md §3）`
  }
  return `packages/${pkg} 只允许依赖 ${allowed.map((p) => `@askdaddy/${p}`).join('、')}（docs/architecture.md §3）`
}

const internalDepRules = Object.entries(INTERNAL_DEPS).map(([pkg, allowed]) => ({
  files: [`packages/${pkg}/**/*.{ts,tsx,mts,cts}`],
  rules: {
    'no-restricted-imports': [
      'error',
      {
        paths: NODE_BUILTIN_PATHS,
        patterns: [
          ...PLATFORM_PATTERNS,
          {
            group: INTERNAL_PACKAGES.filter((p) => !allowed.includes(p)).map(
              (p) => `@askdaddy/${p}`,
            ),
            message: internalDepMessage(pkg, allowed),
          },
        ],
      },
    ],
    'no-restricted-globals': ['error', ...PLATFORM_GLOBALS],
  },
}))

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/coverage/**',
      '**/.turbo/**',
      '**/.output/**',
      '**/.wxt/**',
      'apps/mobile/android/**',
      'apps/mobile/ios/**',
      'apps/desktop/src-tauri/target/**',
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    rules: {
      // AGENTS.md §5.2：解析不可信输入必须是纯数据处理
      'no-eval': 'error',
      'no-new-func': 'error',
      'no-implied-eval': 'error',
      // AGENTS.md §6：禁止 any，确需时用 unknown + 类型守卫
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'separate-type-imports' },
      ],
      'no-console': 'warn',
    },
  },

  ...internalDepRules,

  {
    files: ['packages/**/*.{ts,tsx,mts,cts}'],
    rules: {
      // AGENTS.md §5.1：核心包不得输出任何内容，防止密钥或明文经日志外泄
      'no-console': 'error',
    },
  },

  {
    // 测试夹具需要一个真实的 HMAC / 随机数实现充当被测代码的对照，只能用 Node 内置模块。
    // 测试不进入发布产物（tsconfig.build.json 已排除），发布代码的平台无关性由
    // build 配置的 types:[] 与 packages/* 的受限规则共同保证。
    files: ['**/*.test.ts', '**/*.spec.ts', '**/__tests__/**', 'test/**'],
    rules: {
      'no-restricted-imports': 'off',
      'no-restricted-globals': 'off',
      'no-console': 'off',
    },
  },

  {
    files: ['**/*.config.{js,mjs,cjs,ts}', 'eslint.config.js'],
    rules: {
      'no-restricted-imports': 'off',
      'no-restricted-globals': 'off',
      'no-console': 'off',
    },
  },
)
