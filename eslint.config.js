import js from '@eslint/js'
import tseslint from 'typescript-eslint'

const INTERNAL_PACKAGES = ['otp', 'crypto', 'crypto-web', 'vault', 'transfer', 'domain']
const APP_PACKAGES = ['mobile', 'extension', 'desktop']

/**
 * 依赖方向白名单（docs/architecture.md §3）。
 * 用白名单而非黑名单：新增内部包时不会漏掉规则。
 */
const INTERNAL_DEPS = {
  otp: [],
  crypto: [],
  'crypto-web': ['crypto'],
  vault: ['crypto', 'otp'],
  transfer: ['vault', 'crypto', 'otp'],
  domain: ['vault'],
}

/** 平台适配包，是平台禁令的唯一例外（docs/architecture.md §3.1）。 */
const WEB_ADAPTER_PACKAGE = 'crypto-web'

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

const PLATFORM_SDK_PATTERNS = [
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
    group: ['node:*', ...NODE_SUBPATH_PATTERNS],
    message: NODE_MESSAGE,
  },
  {
    group: APP_PACKAGES.map((app) => `@askdaddy/${app}`),
    message: 'packages/* 禁止反向依赖 apps/*（docs/architecture.md §3）',
  },
]

// 加密实现库单独一条，因为 packages/crypto-web 是唯一被允许使用它的地方。
// 裸名 `argon2` 必须与 `argon2-*` 并列：patterns 是 gitignore 风格，后者匹配不到前者。
const CRYPTO_IMPL_PATTERN = {
  group: ['hash-wasm', 'argon2', 'argon2-*', 'libsodium*', '@noble/*'],
  message:
    '加密原语的实现库只允许出现在 packages/crypto-web 或 apps/* 的原生模块里；' +
    'packages/crypto 只定义接口与参数常量（AGENTS.md §5.1）',
}

const CORE_PACKAGE_PATTERNS = [...PLATFORM_SDK_PATTERNS, CRYPTO_IMPL_PATTERN]

/**
 * crypto-web 的例外只到 hash-wasm 为止：其余实现库是测试对照（devDependency），
 * 只能在测试文件里出现——文件末尾针对测试目录的 override 已为其关闭本规则。
 */
const ORACLE_IMPL_PATTERN = {
  group: CRYPTO_IMPL_PATTERN.group.filter((name) => name !== 'hash-wasm'),
  message:
    '对照实现（node-argon2 / libsodium / @noble）只允许出现在测试文件里；' +
    'packages/crypto-web 的生产代码只能用 hash-wasm 与 WebCrypto（docs/testing.md §3.2）',
}

const WEB_ADAPTER_PATTERNS = [...PLATFORM_SDK_PATTERNS, ORACLE_IMPL_PATTERN]

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
  // 核心包必须走注入的 Provider，直接摸 WebCrypto 会绕过 §5.1「加密原语只在 Provider 内调用」
  'crypto',
]

// crypto-web 可以用 WebCrypto 全局，其余禁令与核心包完全一致。
const WEB_ADAPTER_GLOBALS = PLATFORM_GLOBALS.filter((name) => name !== 'crypto')

function internalDepMessage(pkg, allowed) {
  if (allowed.length === 0) {
    return `packages/${pkg} 是叶子包，不允许依赖任何内部包（docs/architecture.md §3）`
  }
  return `packages/${pkg} 只允许依赖 ${allowed.map((p) => `@askdaddy/${p}`).join('、')}（docs/architecture.md §3）`
}

const internalDepRules = Object.entries(INTERNAL_DEPS).map(([pkg, allowed]) => {
  const isWebAdapter = pkg === WEB_ADAPTER_PACKAGE
  return {
    files: [`packages/${pkg}/**/*.{ts,tsx,mts,cts}`],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: NODE_BUILTIN_PATHS,
          patterns: [
            ...(isWebAdapter ? WEB_ADAPTER_PATTERNS : CORE_PACKAGE_PATTERNS),
            {
              group: INTERNAL_PACKAGES.filter((p) => !allowed.includes(p)).map(
                (p) => `@askdaddy/${p}`,
              ),
              message: internalDepMessage(pkg, allowed),
            },
          ],
        },
      ],
      'no-restricted-globals': [
        'error',
        ...(isWebAdapter ? WEB_ADAPTER_GLOBALS : PLATFORM_GLOBALS),
      ],
    },
  }
})

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
    files: ['test/**'],
    languageOptions: {
      globals: { console: 'readonly', process: 'readonly', Buffer: 'readonly' },
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
