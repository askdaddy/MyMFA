# 架构设计

> 关联决策：[ADR-001 技术栈](decisions.md#adr-001) ｜ 状态：设计基线，尚未实现

## 1. 设计原则

1. **安全敏感逻辑只实现一次**。OTP 算法、加密、vault 序列化、导入导出解析全部收敛到无平台依赖的 TypeScript 核心包，三端复用同一份经过审计的实现。这是选择 TypeScript 全家桶的根本原因。
2. **核心包零平台依赖**。平台差异（加密原语、安全存储、文件系统、扫码）通过 Provider 接口由宿主注入，核心包不认识 `react-native`、`chrome.*` 或 Node 内置模块。
3. **格式即契约**。vault 文件格式与导入导出格式是跨端、跨版本的兼容边界，必须有显式版本号和迁移路径，不允许隐式变更。
4. **不建后端**。无账号体系、无云同步服务，所有数据始终留在用户设备上。

## 2. Monorepo 结构

pnpm workspaces + Turborepo。

```
packages/
  otp/          RFC 4226 HOTP、RFC 6238 TOTP、base32、摘要抽象
  crypto/       KdfProvider / AeadProvider 接口 + 各端实现
  vault/        数据模型、加解密、序列化、schema 迁移、完整性校验
  transfer/     导入导出：每格式一个模块 + 统一格式探测器
  domain/       排序、搜索、tag、使用统计、域名匹配、时钟偏移
apps/
  mobile/       React Native（Expo prebuild + 自定义原生模块）
  extension/    Chrome MV3（WXT 脚手架 + React popup）
  desktop/      Tauri（后期阶段）
docs/
test/           QA 黑盒测试脚本
```

## 3. 依赖方向

严格单向，禁止反向或跨层引用。依赖只能从上层指向下层：

```
第 4 层   apps/mobile      apps/extension      apps/desktop
第 3 层   domain
第 2 层   vault            transfer
第 1 层   crypto    otp          （叶子，无内部依赖）
适配层    crypto-web ──→ crypto  （Web Provider，只被 apps/* 与跨端测试引用）
```

具体到包，允许的内部依赖是一份**白名单**（`eslint.config.js` 中的 `INTERNAL_DEPS`）：

| 包           | 允许依赖                 | 用途                                                            |
| ------------ | ------------------------ | --------------------------------------------------------------- |
| `otp`        | —                        | 叶子                                                            |
| `crypto`     | —                        | 叶子，只有接口与参数常量                                        |
| `crypto-web` | `crypto`                 | Web/WebCrypto 侧的 KDF、AEAD、随机数 Provider 实现              |
| `vault`      | `crypto`、`otp`          | 加解密；校验条目参数合法性                                      |
| `transfer`   | `vault`、`crypto`、`otp` | 构造 Entry；解密他 App 的加密备份；otpauth URI 的 base32 编解码 |
| `domain`     | `vault`                  | 读取条目                                                        |
| `apps/*`     | 全部 packages            | 并负责**注入平台 Provider**                                     |

核心包（`otp`、`crypto`、`vault`、`transfer`、`domain`）一律禁止 import `apps/*` 与任何平台 SDK。

### 3.1 为什么 `crypto-web` 是例外

`packages/crypto` 只有接口，那么 Web 侧的实现（`hash-wasm` 的 Argon2id + WebCrypto 的 AES-GCM）必须有个落脚处。它同时被 `apps/extension`、`apps/desktop` 与跨端一致性测试使用——若各写一份，就违背了「安全敏感代码只实现一次」（见 `README.md`），而这三处任何一处写错都会导致 vault 在另一端打不开。

因此 `crypto-web` 作为**平台适配包**存在，是 `packages/*` 平台禁令的唯一例外：

- 允许 `hash-wasm`（AGENTS.md §5.2 许可的唯一 WASM 用途）、WebCrypto 全局（`crypto.subtle`、`crypto.getRandomValues`）与 `CompressionStream` / `DecompressionStream`（gzip，同为浏览器与 MV3 service worker 原生具备）
- **仍然禁止** Node 内置模块与 `process` / `Buffer` / `require` / `chrome.*`，保证它能在浏览器与 MV3 service worker 里原样运行
- 仍然禁止被任何核心包依赖，方向只能是 `apps/* → crypto-web → crypto`

移动端原生 Provider（argon2-jvm、libsodium）不进 `packages/*`，直接放在 `apps/mobile` 的原生模块里——它们必然 import `react-native`，与浏览器无法共用一行代码，独立成包没有收益。

`SecureStore` 的各端实现同理留在 `apps/*`：扩展端要用 `chrome.storage.session`，移动端要用 Keychain / Keystore，没有共用面。

### 3.2 强制方式

ESLint `no-restricted-imports`（内部包白名单 + 平台模块）与 `no-restricted-globals`（`window`/`chrome`/`process` 等）按 `packages/*` 逐包配置，在 CI 阻断，不靠人工审查。`crypto-web` 有自己的一份规则，允许 WebCrypto 与 `hash-wasm`，其余禁令与核心包一致。

发布产物另有一道类型层保障：`packages/*/tsconfig.build.json` 设 `types: []`，构建时拿不到 Node / DOM 的类型声明。

未声明的第三方依赖不需要额外规则拦截：pnpm 的 `node_modules` 严格隔离，包只能解析到自己 `package.json` 里声明的依赖，漏声明会直接在构建期失败。

## 4. 包职责详述

### 4.1 `packages/otp`

- base32 编解码（RFC 4648），容忍缺失 padding、大小写、空格与 `0/O`、`1/I` 混淆字符
- HOTP：`counter` + `secret` → `digits` 位数字码
- TOTP：在 HOTP 之上按 `period` 计算时间步，支持 `clockOffsetSeconds` 补偿系统时钟偏差
- 摘要算法：SHA-1 / SHA-256 / SHA-512，通过注入的 `Hmac` 接口调用（WebCrypto 三端都支持，无需 WASM）
- 下一周期码：`nextCode()` 即 `period` 步长 +1 的结果；HOTP 则为 `counter + 1`

**不做**：Steam、Yandex、mOTP 等非标准变体（见 [ADR-004](decisions.md#adr-004)）。

### 4.2 `packages/crypto`

只定义接口与参数常量，不含平台实现：

- `KdfProvider`：`deriveKey(password, salt, params) → Uint8Array`。`name` 当前被钉成字面量 `'argon2id'`；容纳 [ADR-018](decisions.md#adr-018) 豁免的 scrypt / PBKDF2 需要扩展这个接口，属跨包契约变更，须先改文档再改代码
- `AeadProvider`：`encrypt(key, plaintext, aad?) → {nonce, ciphertext, tag}` / `decrypt(...)`
- `RandomProvider`：密码学安全随机数
- `SecureStore`：平台安全存储（Keychain / Keystore / `chrome.storage.session`）
- `CompressProvider`：`compress(bytes) → Uint8Array` / `decompress(bytes) → Uint8Array`，`name` 恒为 `'gzip'`

**`CompressProvider` 与前四个不同，它不是加密原语**。放进 `packages/crypto` 是因为它同样需要平台注入（Web 用 `CompressionStream`，Hermes 不提供该 API，移动端必须走原生模块），而不是因为它涉及安全。相应地它的跨端一致性要求**弱于** KDF / AEAD：只要求任何一端能解开其他端产出的 gzip 流，**不要求**压缩输出字节级一致，理由与陷阱见 [testing.md §4.2](testing.md#42-gzip-的跨端一致性是弱要求)。

各端实现位置：

| 端                      | KDF 实现                              | AEAD 实现                    | 代码位置                      |
| ----------------------- | ------------------------------------- | ---------------------------- | ----------------------------- |
| Web / 扩展 / Tauri 前端 | `hash-wasm` 的 argon2id               | WebCrypto `crypto.subtle`    | `packages/crypto-web`（共用） |
| Android                 | argon2-jvm（原生模块）                | Android Keystore / Conscrypt | `apps/mobile` 原生模块        |
| iOS                     | libsodium `crypto_pwhash`（原生模块） | CryptoKit                    | `apps/mobile` 原生模块        |

Web 侧之所以独立成 `packages/crypto-web` 而不是放进各 app，见 [§3.1](#31-为什么-crypto-web-是例外)。`SecureStore` 不设共用包——三端实现毫无重叠（Keychain / Keystore / `chrome.storage.session`），各自留在 `apps/*`。

`CompressProvider` 的实现位置：Web / 扩展 / Tauri 前端在 `packages/crypto-web`（平台原生 `CompressionStream('gzip')`，无新依赖）；Android / iOS 在 `apps/mobile` 原生模块——**Hermes 不提供 `CompressionStream`**，与 Argon2id 一样无法复用 Web 实现。

`packages/crypto` 还负责定义 Argon2id 参数常量（`memoryKiB` / `iterations` / `parallelism` / `saltLength` / `keyLength`）与统一的错误类型。**参数常量只能放在这里**：三端实现各自硬编码数字，是单位混淆（MiB vs KiB）导致跨端不一致的头号来源（见 [testing.md §3](testing.md#3-跨端加密一致性测试最高优先级)）。

三端实现必须通过 [跨端一致性测试](testing.md#3-跨端加密一致性测试最高优先级) 验证字节级一致。

### 4.3 `packages/vault`

- 数据模型类型定义与运行时校验（**手写类型守卫**，不引入 zod——zod 默认剥除未知字段，与"未知字段原样保留"的前向兼容规则冲突，见 [vault-format.md §5.3](vault-format.md#53-未知字段)）
- 序列化 / 反序列化：gzip 压缩能力**通过注入的 `CompressProvider` 获得**，vault 自己不实现压缩、也不直接调用任何平台 API（`zlib` 被平台禁令拦截，`CompressionStream` 在 Hermes 上不存在）。校验函数**只判定不重建**，直接返回入参对象，这是未知字段得以保留的机制保证
- 加密容器封装与解封（只处理 `encrypted: true`；明文容器属 `packages/transfer`）
- `schemaVersion` 迁移链：`v0 → v1 → ...`，每步一个纯函数，禁止跳版本迁移
- 双层密钥管理：DEK 生成、KEK 派生、包裹与解包

### 4.4 `packages/transfer`

- 每个外部格式一个模块，统一暴露 `detect(input)` / `parse(input, options)` / `generate(vault, options)`
- 格式探测器：JSON 按特征字段判别，文本按 `otpauth://` / `otpauth-migration://` 前缀判别
- 解析失败必须给出**行级/条目级**错误，支持"部分成功导入"而非全量回滚
- **明文容器**（`encrypted: false`）的封装与解封归本包，`packages/vault` 只处理加密容器并显式拒绝明文（[vault-format.md §1.2](vault-format.md#12-未加密容器)）
- 第三方**加密**备份的兼容路径（Aegis scrypt、2FAS / Raivio PBKDF2）走 [ADR-018](decisions.md#adr-018) 的豁免，四个边界条件必须全部满足；`packages/vault` 不得依赖该路径
- 详细矩阵见 [transfer.md](transfer.md)

### 4.5 `packages/domain`

- 排序策略：手动（fractional indexing）、issuer、account、usageCount、lastUsedAt、createdAt；二级排序恒为 `issuer + account` 以保证稳定
- 搜索：子序列模糊匹配 + 评分；可选拼音首字母匹配
- 域名匹配：`entry.sites` 与当前 hostname 比对，含子域规则
- 使用统计：`usageCount` 与 `lastUsedAt` 的递增时机
- 时钟偏移：从 HTTP `Date` 头计算 `clockOffsetSeconds`

## 5. 平台适配层

### 5.1 移动端（React Native）

- Expo prebuild 工作流，通过 config plugin 注入自定义原生模块
- 原生模块职责：Argon2id、SecureStore（Keychain/Keystore）、生物识别、防截屏、二维码扫描与生成、局域网 HTTP 服务
- **Hermes 不支持 WASM**，因此 Argon2id 必须走原生模块，不能复用 `hash-wasm`；Hermes 同样不提供 `CompressionStream`，gzip 也必须走原生模块。这两处是移动端与 Web 端无法共享实现的部分
- 推荐 `react-native-quick-crypto` 提供 node-compatible crypto API（依赖新架构，需在 M0 验证兼容性）

### 5.2 Chrome 扩展

详见 [chrome-extension.md](chrome-extension.md)。关键点：MV3 service worker 会被回收，解锁态必须放 `chrome.storage.session`。

### 5.3 桌面端（后期）

Tauri 2.x，前端复用 `apps/extension` 的 React 组件层，Rust 侧提供 Argon2id 与文件系统访问。不排期，但架构上不设障碍。

## 6. 构建与工具链

| 项         | 选型                                         |
| ---------- | -------------------------------------------- |
| 包管理     | pnpm workspaces                              |
| 任务编排   | Turborepo（增量构建 + 远程缓存可选）         |
| 语言       | TypeScript `strict: true`，全仓 ESM          |
| 测试       | Vitest                                       |
| Lint       | ESLint（含依赖方向规则）+ Prettier           |
| 提交规范   | Conventional Commits，引用 Issue 编号        |
| 移动端构建 | Expo prebuild → EAS Build（或本地 fastlane） |
| 扩展构建   | WXT（Vite 底座，MV3 原生支持）               |

## 7. 关键架构风险

| 风险                       | 缓解措施                                                                                                                                          | 验证阶段               |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| Argon2id 三端输出不一致    | 官方测试向量 + 跨端字节比对 CI                                                                                                                    | **M0（必须最早验证）** |
| RN 加密生态与新架构兼容性  | M0 做最小可运行原型，验证 quick-crypto 可用                                                                                                       | M0                     |
| MV3 SW 回收导致解锁态丢失  | `chrome.storage.session` + 早期原型验证                                                                                                           | M4 前                  |
| 导入格式字段名与文档不符   | 以一手来源（各 App 开源仓库 schema / 官方文档）为准建立 golden test，不信任社区逆向资料，见 [ADR-019](decisions.md#adr-019)；真机校准为后续跟进项 | M2                     |
| 恶意导入文件导致崩溃或注入 | 解析器纯函数化 + 模糊测试 + 禁用动态执行                                                                                                          | M2                     |
