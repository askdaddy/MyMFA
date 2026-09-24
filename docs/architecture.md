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

严格单向，禁止反向或跨层引用：

```
apps/mobile ─┐
apps/extension ─┼─→ domain ─→ vault ─→ transfer
apps/desktop ─┘              ↓            ↓
                          crypto ←──── otp
```

规则：

- `otp` 与 `crypto` 是叶子，不依赖任何内部包。
- `vault` 依赖 `crypto`（加解密）与 `otp`（校验条目参数合法性）。
- `transfer` 依赖 `vault`（构造 Entry）与 `crypto`（解密他 App 的加密备份）。
- `domain` 依赖 `vault`（读取条目）。
- `apps/*` 依赖全部 packages，并负责**注入平台 Provider**。
- 任何 `packages/*` 禁止 import `apps/*` 或平台 SDK。

这条规则由 ESLint 的 `no-restricted-imports` + `import/no-extraneous-dependencies` 在 CI 强制，不靠人工审查。

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

- `KdfProvider`：`deriveKey(password, salt, params) → Uint8Array`
- `AeadProvider`：`encrypt(key, plaintext, aad?) → {nonce, ciphertext, tag}` / `decrypt(...)`
- `RandomProvider`：密码学安全随机数
- `SecureStore`：平台安全存储（Keychain / Keystore / `chrome.storage.session`）

各端实现位置：

| 端 | KDF 实现 | AEAD 实现 |
|---|---|---|
| Web / 扩展 / Tauri 前端 | `hash-wasm` 的 argon2id | WebCrypto `crypto.subtle` |
| Android | argon2-jvm（原生模块） | Android Keystore / Conscrypt |
| iOS | libsodium `crypto_pwhash`（原生模块） | CryptoKit |

三端实现必须通过 [跨端一致性测试](testing.md#3-跨端加密一致性测试最高优先级) 验证字节级一致。

### 4.3 `packages/vault`

- 数据模型类型定义与运行时校验（zod 或手写守卫）
- 序列化 / 反序列化（含 gzip 压缩）
- 加密容器封装与解封
- `schemaVersion` 迁移链：`v0 → v1 → ...`，每步一个纯函数，禁止跳版本迁移
- 双层密钥管理：DEK 生成、KEK 派生、包裹与解包

### 4.4 `packages/transfer`

- 每个外部格式一个模块，统一暴露 `detect(input)` / `parse(input, options)` / `generate(vault, options)`
- 格式探测器：JSON 按特征字段判别，文本按 `otpauth://` / `otpauth-migration://` 前缀判别
- 解析失败必须给出**行级/条目级**错误，支持"部分成功导入"而非全量回滚
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
- **Hermes 不支持 WASM**，因此 Argon2id 必须走原生模块，不能复用 `hash-wasm`。这是移动端与 Web 端唯一无法共享实现的部分
- 推荐 `react-native-quick-crypto` 提供 node-compatible crypto API（依赖新架构，需在 M0 验证兼容性）

### 5.2 Chrome 扩展

详见 [chrome-extension.md](chrome-extension.md)。关键点：MV3 service worker 会被回收，解锁态必须放 `chrome.storage.session`。

### 5.3 桌面端（后期）

Tauri 2.x，前端复用 `apps/extension` 的 React 组件层，Rust 侧提供 Argon2id 与文件系统访问。不排期，但架构上不设障碍。

## 6. 构建与工具链

| 项 | 选型 |
|---|---|
| 包管理 | pnpm workspaces |
| 任务编排 | Turborepo（增量构建 + 远程缓存可选） |
| 语言 | TypeScript `strict: true`，全仓 ESM |
| 测试 | Vitest |
| Lint | ESLint（含依赖方向规则）+ Prettier |
| 提交规范 | Conventional Commits，引用 Issue 编号 |
| 移动端构建 | Expo prebuild → EAS Build（或本地 fastlane） |
| 扩展构建 | WXT（Vite 底座，MV3 原生支持） |

## 7. 关键架构风险

| 风险 | 缓解措施 | 验证阶段 |
|---|---|---|
| Argon2id 三端输出不一致 | 官方测试向量 + 跨端字节比对 CI | **M0（必须最早验证）** |
| RN 加密生态与新架构兼容性 | M0 做最小可运行原型，验证 quick-crypto 可用 | M0 |
| MV3 SW 回收导致解锁态丢失 | `chrome.storage.session` + 早期原型验证 | M4 前 |
| 导入格式字段名与文档不符 | 以真实样本为准建立 golden test，不信任二手资料 | M2 |
| 恶意导入文件导致崩溃或注入 | 解析器纯函数化 + 模糊测试 + 禁用动态执行 | M2 |
