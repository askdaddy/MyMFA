# 里程碑与风险

> 状态：规划基线。工期未估算——单人开发节奏未知，且 M0 的技术验证结果会显著影响后续排期。

## 1. 里程碑

### M0 — 基础设施与技术验证 🔴 关键路径

**目标**：把最大的技术风险在写业务代码之前消掉。

- monorepo 搭建（pnpm workspaces + Turborepo + TS strict + Vitest + ESLint 依赖方向规则）
- `packages/otp`：base32、HOTP、TOTP，跑通 RFC 4226 / 6238 全部官方测试向量
- `packages/crypto`：`KdfProvider` / `AeadProvider` / `RandomProvider` / `SecureStore` 接口定义
- **三端 Argon2id + AES-256-GCM 实现与字节级一致性验证**（Web `hash-wasm`、Android argon2-jvm、iOS libsodium）
- RN 加密生态验证：`react-native-quick-crypto` 在目标 RN 版本 + 新架构下可用性原型
- `.gitignore` 覆盖备份文件模式（必须在任何导入导出开发前就位）

**出口标准**分两部分（[跨端一致性测试](testing.md#3-跨端加密一致性测试最高优先级)）：

| 部分       | 内容                                                                                                      | 何时必须达成   |
| ---------- | --------------------------------------------------------------------------------------------------------- | -------------- |
| **Web 端** | Web Provider 通过 Argon2id KAT；生产参数下与参考实现字节级一致；对照向量固化为跨端比对基线                | **进入 M1 前** |
| **移动端** | Android（argon2-jvm）与 iOS（libsodium）的输出与上述固化基线字节级一致；真实 `.mfavault` 样本三端互相解密 | **进入 M3 前** |

**Web 端部分未通过不得进入 M1**；移动端部分未通过不得进入 M3。

拆分的理由是三端比对依赖真机或模拟器，在纯 Web 迭代中无法执行；若不拆分，vault 层会被一条当前范围内不可能满足的标准永久阻塞。两部分之间的契约是**同一份固化基线**——移动端后续比对的就是 Web 端产出的那份向量，因此拆分不会削弱 R1 的防护，只是把验证时点后移到具备设备条件时。此拆分对应用户于 2026-09-24 确认的 **Web 端 MVP** 迭代范围（见 Issue #1）。

> M0 是本项目的成败关键。若三端 Argon2id 无法达成一致，需要在此阶段就推翻 [ADR-009](decisions.md#adr-009) 改用 PBKDF2（WebCrypto 三端原生支持，无 WASM 问题，代价是抗 GPU 能力较弱），而不是拖到集成阶段再返工。

### M1 — Vault 核心

- 数据模型 + 运行时校验（Entry / Tag / Settings，见 [vault-format.md](vault-format.md)）
- 双层密钥模型：DEK 生成、KEK 派生、包裹与解包
- 加密容器读写、gzip、AAD 校验
- `schemaVersion` 迁移链框架
- 自动备份滚动（仅加密态）
- 生物识别包裹：iOS Keychain（`kSecAccessControlBiometryCurrentSet`）、Android Keystore + BiometricPrompt、`KeyPermanentlyInvalidatedException` 回退
- 主密码修改（仅重新包裹 DEK）

**出口标准**：vault 往返测试全绿；三端能互相打开对方加密的 vault。

### M2 — 导入导出

- `packages/transfer`：格式探测器 + 各格式解析器
- 导入：Aegis（明文 + scrypt 加密）、GA 迁移二维码（protobuf + 分片重组）、2FAS、Raivio、FreeOTP、Ente、Bitwarden / 1Password CSV、通用 otpauth URI、通用 CSV（手动列映射）
- **LastPass 不做专用解析器**（无权威来源可用，见 [ADR-019](decisions.md#adr-019)），走通用 CSV 的手动列映射
- M2 已拆为三个 Issue 推进：#8 探测器与明文/文本格式、#10 第三方加密备份兼容（含 `AGENTS.md` §5.1/§5.2 按 [ADR-018](decisions.md#adr-018) 修订）、#9 GA 迁移二维码 protobuf；#4 转为跟踪 Issue
- 导出：自有加密/明文、Aegis 明文/加密、otpauth URI、批量二维码、GA 迁移二维码
- 重复与冲突处理策略
- 导入预览与部分成功报告 UI
- 字段降级表展示

**出口标准**：全部格式 golden test 通过（**字段名以一手来源校准——各 App 开源仓库的 schema 定义与官方文档，不以社区逆向资料为准**，见 [ADR-019](decisions.md#adr-019) 与 [testing.md §5.1](testing.md#51-字段名的权威来源adr-019)）；解析器模糊测试无崩溃。

真实样本回归校验与 GA 迁移二维码的真机扫描验证**不在本里程碑出口标准内**，按 ADR-019 降级为 #11 跟踪；在完成前，GA 导出 UI 必须标注「未经 Google Authenticator 真机验证」。

### M3 — 移动端 MVP

- 创建 vault 流程（强制主密码 + 强度指示 + 不可找回告知）
- 解锁页（主密码 + 生物识别）
- 条目列表：首字母色块、当前码、环形倒计时、**预提示码**、虚拟化滚动
- 添加条目：扫码、手动、从图片识别二维码
- 条目详情与编辑
- 搜索（含拼音首字母）、tag 管理与筛选、备注
- 排序：手动拖拽（fractional indexing）+ 六种排序方式
- 收藏置顶、使用计数
- 安全设置：自动锁定、剪贴板清理、防截屏、后台遮罩
- 时钟校准
- 深色模式、无障碍、中英双语、空状态引导

**出口标准**：Maestro E2E 全绿；200 条目列表滚动流畅（掉帧率达标）；低端 Android 设备上 Argon2id 派生耗时实测并记录。

### M4 — Chrome 扩展

- WXT 脚手架 + MV3 三入口（background / popup / options）
- Provider 注入：`hash-wasm` Argon2id、WebCrypto、`chrome.storage` 封装
- 导入 `.mfavault` + 设置扩展主密码
- **解锁态管理**：DEK 存 `storage.session`，`alarms` 空闲锁定，验证浏览器重启后需重新输密码
- popup 列表：当前码 + 预提示码 + 倒计时 + 搜索 + tag 筛选 + 点击复制
- **域名绑定与自动置顶**（`activeTab` 读当前页 hostname，含子域规则与后缀伪造防护）
- options：条目管理、导入导出、设置
- 零 `host_permissions`，不注入 content script

**出口标准**：Playwright E2E 全绿；域名匹配安全用例（`evil-github.com`、`github.com.evil.com`）全部通过；跨端一致性 E2E（移动端导出 → 扩展导入，数据完整）。

### M5 — 局域网配对迁移

- 移动端：一次性 X25519 密钥对、临时局域网 HTTP 服务、配对二维码、传输后立即关闭
- 扩展：扫码/手输连接、ECDH 协商、配对码认证、接收并导入加密 blob
- **前置技术验证**：Chrome 对私有网段请求的 PNA 策略、`optional_host_permissions` 按需授权流程（见 [ADR-015 后果](decisions.md#adr-015)）

**出口标准**：同一局域网内手机 → 扩展迁移成功率验证；配对码错误时拒绝连接；传输完成即销毁全部会话密钥。

> 若 PNA 验证失败，回退方案为"移动端展示分片二维码 + 扩展摄像头扫描"（`getUserMedia`，无需网络权限），代价是大 vault 需扫多张码。

### M6 — 发布打磨

- 双端商店上架：App Store / Google Play / Chrome Web Store
- **加密合规声明**（App Store Connect 要求）
- 权限说明文案（扩展商店审核重点）
- 备份提醒（长期未备份时提示）
- 崩溃上报接入 + 敏感字段过滤
- 用户文档：迁移指南（明确告知 Authy / Microsoft Authenticator 不支持）、常见问题
- 时间校准端点最终选定

## 2. 里程碑依赖关系

```
M0 ──→ M1 ──→ M2 ──┬──→ M3 ──┐
                   │         ├──→ M5 ──→ M6
                   └──→ M4 ──┘
```

M3 与 M4 可并行（都只依赖 M2）。M5 需要 M3 与 M4 都完成。

## 3. 风险清单

| #   | 风险                              | 影响                         | 概率   | 缓解                                                                                                                                                                                     | 验证点   |
| --- | --------------------------------- | ---------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| R1  | **三端 Argon2id 输出不一致**      | 致命：跨端 vault 无法互开    | 中     | 官方测试向量 + 字节比对 CI + 单位统一为 `memoryKiB`；失败则推翻 ADR-009 改 PBKDF2                                                                                                        | **M0**   |
| R2  | RN 加密生态与新架构不兼容         | 高：移动端无法派生密钥       | 中     | M0 做最小原型；备选 Expo config plugin 自写原生模块                                                                                                                                      | M0       |
| R3  | MV3 SW 回收导致解锁态丢失         | 中：用户体验差，频繁重输密码 | 中     | `storage.session` + `alarms`，早期原型验证                                                                                                                                               | M4 前    |
| R4  | 第三方格式字段名与文档不符        | 中：导入静默丢数据           | **高** | 一律以一手来源（各 App 开源仓库 schema / 官方文档）为准建 golden test，不信任社区逆向资料，见 [ADR-019](decisions.md#adr-019)；真实样本回归校验为 #11 跟进项，风险**未被消除、只是后移** | M2 / #11 |
| R5  | GA 迁移 protobuf 编码不被真机接受 | 中：导出到 GA 失败           | 中     | 真机扫描验证，不靠自解析往返；按 [ADR-019](decisions.md#adr-019) 降级为 #11 跟进，完成前导出 UI 必须标注「未经真机验证」                                                                 | #11      |
| R6  | Chrome PNA 阻止扩展访问局域网     | 中：M5 无法实现              | **高** | 前置原型验证；回退到二维码扫描方案                                                                                                                                                       | M5 前    |
| R7  | 低端 Android 上 Argon2id 派生过慢 | 中：解锁等待 1–2 秒          | 中     | M3 实测；必要时提供高性能模式（默认关闭 + 显著警告）                                                                                                                                     | M3       |
| R8  | 恶意导入文件导致崩溃/内存耗尽     | 中：可用性与安全             | 低     | 纯函数解析 + 长度/深度上限 + 模糊测试                                                                                                                                                    | M2       |
| R9  | 用户忘记主密码导致数据永久丢失    | 高（对用户）                 | **高** | 创建流程强告知 + 定期备份提醒 + 导出备份引导。**不提供后门**                                                                                                                             | M3 / M6  |
| R10 | App Store 加密合规审查            | 低：上架延迟                 | 中     | 提前准备加密声明，说明仅使用标准豁免算法                                                                                                                                                 | M6       |

## 4. 明确的非目标

以下内容在 V1 及可预见的迭代中**不做**，避免范围蔓延：

- 云同步、账号体系、自建后端
- 多用户 / 共享密钥库 / 团队版
- Steam / Yandex / mOTP 等非标准令牌变体
- 企业级 SSO / SAML / OIDC 集成
- 扩展端自动填充到网页
- 服务商品牌图标库
- 硬件密钥（YubiKey / WebAuthn PRF）派生 — 架构预留，不实现
- 桌面端（Tauri）— 架构不设障碍，不排期
- 密码管理功能（本项目只管第二因素，不存密码）
