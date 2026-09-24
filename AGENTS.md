# AGENTS.md

本文件是 AI Agent 与本仓库协作的**作业契约**。开始任何工作前先完整读取本文件。
与用户临时指令冲突时，以用户当次显式指令为准；与 `docs/` 冲突时，以本文件的**安全红线**为准。

## 1. 项目定位

**MyMFA** — 跨平台 MFA（多因素认证）客户端，产品形态对标 Android 上的 Aegis。

- 支持的令牌类型：**TOTP（RFC 6238）+ HOTP（RFC 4226）**
- 目标平台：Android / iOS（React Native）、Chrome 扩展（MV3）；桌面端（Tauri）为后期阶段
- 差异化功能：**预提示**（当前码为主，下一周期的码缩小显示在其下方）
- 数据策略：**纯本地**，无自建后端，跨设备靠导入导出与局域网配对迁移
- 包命名空间：**`@askdaddy`**；代码托管 **GitHub**，Issue 操作走 `gh` CLI

## 2. 当前仓库状态

git 已初始化，分支 `main`，远端 `git@github.com:askdaddy/MyMFA.git`。
**仓库可见性（public / private）与开源许可证尚未确定，未经用户显式确认不得 `git push`。**

工具链已安装：pnpm workspaces + Turborepo + TypeScript strict + ESLint + Prettier + Vitest。
依赖版本统一由 `pnpm-workspace.yaml` 的 `catalog:` 管理，各包一律写 `"catalog:"`，不要写死版本号。

进度：

- ✅ `docs/` 设计基线（16 条 ADR 全部确认，无阻塞性待决策项，见 `docs/decisions.md`）
- ✅ monorepo 脚手架与平台禁令强制机制
- ✅ `packages/otp`：base32 / HOTP / TOTP / 预提示 / 时钟偏移，通过 RFC 4226 附录 D 与 RFC 6238 附录 B 全部官方测试向量
- ⬜ `packages/crypto`、三端 Argon2id 一致性验证、`vault` / `transfer` / `domain`、全部 apps

`docs/` 是唯一的设计基线，实现必须与之一致；若实现中发现设计有误，先改文档再改代码。

**M0 出口标准未达成前，禁止开始 vault 层实现**（见 `docs/security.md` §4）。

## 3. 目录结构

标注 ✅ 的已存在，⬜ 为规划中。新增代码必须落在对应位置，不要在根目录散放文件。

```
packages/
  otp/        ✅ @askdaddy/otp      TOTP/HOTP 算法、base32、摘要算法抽象（零平台依赖）
  crypto/     ⬜ @askdaddy/crypto   KDF 与 AEAD 抽象层 + 各端 Provider（零平台依赖，原语注入）
  vault/      ⬜ @askdaddy/vault    数据模型、加解密、序列化、schema 版本迁移（零平台依赖）
  transfer/   ⬜ @askdaddy/transfer 导入导出格式解析器与生成器、格式探测器（零平台依赖）
  domain/     ⬜ @askdaddy/domain   排序、搜索、tag、使用统计、域名匹配（零平台依赖）
apps/
  mobile/     ⬜ React Native（Expo prebuild + 自定义原生模块）
  extension/  ⬜ Chrome MV3 扩展（WXT 脚手架）
  desktop/    ⬜ Tauri（后期阶段，暂不创建）
docs/         ✅ 设计文档
test/         ⬜ QA 黑盒测试脚本
```

`packages/*` 一律**禁止** import 任何平台 API（`react-native`、`chrome.*`、`window`、`process`、Node 内置模块）。平台差异通过依赖注入的 Provider 接口解决。强制方式见 §4.1。

## 4. 命令

已落地：

| 命令                           | 作用                                        |
| ------------------------------ | ------------------------------------------- |
| `pnpm install`                 | 安装依赖                                    |
| `pnpm build`                   | 构建全部 package（`tsc` → `dist`）          |
| `pnpm typecheck`               | 全仓 TypeScript 严格类型检查                |
| `pnpm lint`                    | 根级 `eslint .`，含平台禁令与依赖方向白名单 |
| `pnpm format` / `format:check` | Prettier 写入 / 校验                        |
| `pnpm test`                    | Vitest 单元测试（含 RFC 官方测试向量）      |

规划中，尚未实现：

| 命令                | 作用                                                  |
| ------------------- | ----------------------------------------------------- |
| `pnpm test:cross`   | **跨端加密一致性测试**（Argon2id/AES-GCM 字节级比对） |
| `pnpm mobile:start` | 启动 RN 开发服务                                      |
| `pnpm ext:dev`      | 启动扩展开发构建（watch）                             |

`pnpm lint` 只在根级运行：ESLint flat config 集中在 `eslint.config.js`，规则按路径分域，分包运行反而会漏掉跨包规则。

### 4.1 平台禁令的强制方式

`packages/*` 的平台无关性不靠人工审查，由两道机制保证：

1. **ESLint**（`eslint.config.js`）：`no-restricted-imports` 拦截平台 SDK、Node 内置模块与白名单外的内部包；`no-restricted-globals` 拦截 `window` / `chrome` / `process` / `Buffer` 等；`packages/*` 内 `no-console` 为 error（§5.1）。内部包依赖是**白名单** `INTERNAL_DEPS`，新增包必须同步这张表与 `docs/architecture.md` §3。
2. **TypeScript**：`packages/*/tsconfig.build.json` 设 `types: []`，发布产物在类型层面就拿不到 Node / DOM 全局。

因此每个 `packages/*` 有两份 tsconfig，新包照抄这个结构：

- `tsconfig.json` — 含 `types: ["node"]`，覆盖 `src` 与测试，供 typecheck 与编辑器使用
- `tsconfig.build.json` — `types: []`、只含 `src`、排除测试、输出到 `dist`

`moduleResolution` 为 `NodeNext`，**相对导入必须显式写 `.js` 扩展名**（`import { x } from './x.js'`）。

测试文件（`*.test.ts`、`__tests__/**`）豁免平台禁令，因为夹具需要一个真实的 HMAC / 随机数实现充当被测代码的对照；测试不进入发布产物。

## 5. 安全红线（不可协商）

这是一个持有用户第二因素的 App，安全缺陷等同产品失败。以下任何一条被违反都视为 T0 事故。

### 5.1 密钥与明文

- **禁止**将主密码、DEK、KEK、条目 `secret` 明文写入日志、`console.*`、错误消息、崩溃上报、URL 参数或注释。
- **禁止**在 `packages/crypto` 的 Provider 之外的任何位置直接调用加密原语。所有加解密必须走统一接口，便于审计。
- **禁止**下调 Argon2id 参数（`m=64MiB, t=3, p=4`）。只能上调，且必须通过 ADR 记录（见 `docs/decisions.md`）。
- **禁止**自研加密算法、自研 KDF、自研 AEAD。只允许使用 Argon2id + AES-256-GCM，实现库见 `docs/security.md`。
- 生物识别包裹的 DEK **只能**存于设备安全存储（iOS Keychain / Android Keystore），**禁止**写入 vault 文件或任何可导出内容。

### 5.2 依赖

- **禁止**引入新的加密相关依赖而不先在 Issue/ADR 中说明理由与许可证。
- 导入解析器（protobuf、各 App 的 JSON/CSV）**禁止**使用 `eval`、`new Function`、动态 `require`。解析不可信输入必须是纯数据处理。
- 优先使用平台原生能力（WebCrypto、`crypto.subtle`），不轻易引入 WASM；必需的 WASM 仅限 Argon2id 一处。

### 5.3 测试与提交

- 测试夹具中的 `secret` 必须使用**假值**（如 RFC 测试向量、`JBSWY3DPEHPK3PXP`），**禁止**提交任何真实 vault 备份、真实种子、真实二维码图片。
- **禁止**提交 `.mfavault`、`*-backup.json`、`2fas-backup.json`、`aegis*.json` 等备份文件，除非它是显式标注的脱敏测试夹具。
- `.gitignore` 必须包含备份文件模式后，才允许开始任何导入导出功能的开发。

### 5.4 运行时防护

- 写入剪贴板的验证码必须设置延时清理（默认 30–60 秒），并提供关闭选项。
- 明文 vault 在内存中使用后应主动清零引用（`Uint8Array.fill(0)`），不得依赖 GC。
- 导出**明文**备份时必须二次确认 + 显著风险提示，不得默认选中。

## 6. 编码约定

- TypeScript `strict: true`，禁止 `any`（确需时用 `unknown` + 类型守卫）。
- 全仓 ESM，禁止 CommonJS 混用。
- 运行时错误用具体错误类型，不抛裸字符串；解析外部输入必须处理畸形数据而非崩溃。
- 单元测试框架 Vitest；每个格式解析器都必须有基于真实样本的 golden test。
- 命名：`issuer`（服务商）、`account`（账户）、`entry`（条目）、`vault`（密钥库）。UI 文案中不要出现 "token" 与 "code" 混用，统一「验证码」。
- 注释只写 WHY，不写 WHAT。默认不写注释。
- 不添加需求外的功能、抽象与兼容层。三个相似实现优于一个过早的抽象。

## 7. 多角色协作边界

若通过 `iloop` Skill 推进 Issue，遵守其权限矩阵：

- **PM**：只读业务代码，产出写回 Issue（远程不可用时降级 `docs/`）。
- **开发**：唯一可改业务代码者，且仅限已冻结 `plan` 覆盖的范围。
- **QA**：只写 `test/`，不改被测代码，独享关闭 Issue 权限。

## 8. 文档索引

| 文档                       | 内容                                         |
| -------------------------- | -------------------------------------------- |
| `docs/README.md`           | 文档导航                                     |
| `docs/decisions.md`        | ADR：全部已确认决策与待确认默认值            |
| `docs/architecture.md`     | monorepo 结构、包职责、依赖方向              |
| `docs/security.md`         | 双层密钥模型、KDF/AEAD、生物识别、跨端一致性 |
| `docs/vault-format.md`     | vault 文件格式与数据模型 schema              |
| `docs/features.md`         | 预提示、排序、搜索、tag、图标、时钟校准      |
| `docs/transfer.md`         | 导入导出格式矩阵与探测策略                   |
| `docs/chrome-extension.md` | MV3 架构、权限最小化、域名绑定               |
| `docs/testing.md`          | 测试策略、测试向量来源、golden test          |
| `docs/roadmap.md`          | M0–M6 里程碑与风险清单                       |
