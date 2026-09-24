# MyMFA

跨平台多因素认证（MFA）客户端，产品形态对标 Android 上的 [Aegis](https://github.com/beemdevelopment/Aegis)。

> **当前状态**：M0 进行中。设计基线见 [`docs/`](docs/README.md)，Agent 作业契约见 [`AGENTS.md`](AGENTS.md)。
> 已完成 monorepo 脚手架与 `packages/otp`（通过 RFC 4226 / RFC 6238 全部官方测试向量）；`packages/crypto` 与三端 Argon2id 一致性验证尚未开始，vault 层在此之前禁止动工。

## 这是什么

一个本地优先的 TOTP / HOTP 验证码管理器。所有密钥保存在端到端加密的 vault 文件中，不经过任何服务端。

## 核心特性

| 特性           | 说明                                                                                                                     |
| -------------- | ------------------------------------------------------------------------------------------------------------------------ |
| **预提示**     | 当前周期的验证码作为主体大字显示，下一周期的码缩小显示在正下方，提前可用                                                 |
| **标签与备注** | 每个条目可打多个 tag、写自由文本备注                                                                                     |
| **多维排序**   | 手动拖拽、按账户名、按服务商名、按使用次数、按最近使用                                                                   |
| **搜索**       | 对服务商 / 账户 / 备注 / 标签做模糊匹配，支持拼音首字母                                                                  |
| **广泛迁移**   | 导入兼容 Aegis、Google Authenticator、2FAS、Raivio、Ente、FreeOTP、1Password、Bitwarden 等主流格式；导出同样覆盖上述格式 |
| **本地优先**   | 无账号、无后端、无云同步。跨设备通过导出文件或局域网配对迁移                                                             |
| **域名绑定**   | Chrome 扩展中，条目可绑定网站域名，打开对应站点时自动置顶                                                                |

## 平台

| 平台                    | 技术         | 阶段           |
| ----------------------- | ------------ | -------------- |
| Android / iOS           | React Native | M3             |
| Chrome 扩展             | MV3 + WXT    | M4             |
| macOS / Windows / Linux | Tauri        | 后期，暂不排期 |

三端共用同一套 TypeScript 核心包（算法、加密、vault、导入导出、领域逻辑），安全敏感代码只实现一次。

## 文档

- [`docs/decisions.md`](docs/decisions.md) — 全部架构决策记录（ADR），先看这个
- [`docs/architecture.md`](docs/architecture.md) — monorepo 结构与包职责
- [`docs/security.md`](docs/security.md) — 密钥模型与加密规范
- [`docs/vault-format.md`](docs/vault-format.md) — vault 文件格式
- [`docs/features.md`](docs/features.md) — 功能规格
- [`docs/transfer.md`](docs/transfer.md) — 导入导出矩阵
- [`docs/chrome-extension.md`](docs/chrome-extension.md) — 扩展设计
- [`docs/testing.md`](docs/testing.md) — 测试策略
- [`docs/roadmap.md`](docs/roadmap.md) — 里程碑与风险

## 已确认的关键决策

| 决策                  | 结论                                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------------- |
| 技术栈                | TypeScript 全家桶：React Native + Chrome MV3 + 后期 Tauri（[ADR-001](docs/decisions.md#adr-001)） |
| 数据同步              | 纯本地，无后端（[ADR-002](docs/decisions.md#adr-002)）                                            |
| KDF                   | Argon2id `m=64MiB, t=3, p=4`（[ADR-009](docs/decisions.md#adr-009)）                              |
| 时钟校准              | 采纳（[ADR-010](docs/decisions.md#adr-010)）                                                      |
| 产品名 / scope / 托管 | MyMFA / `@askdaddy` / GitHub（[ADR-016](docs/decisions.md#adr-016)）                              |

全部 16 条 ADR 见 [`docs/decisions.md`](docs/decisions.md)。剩余待决策项见该文件的[待决策清单](docs/decisions.md#待决策清单)。

## 许可证

未定（见 [待决策清单](docs/decisions.md#待决策清单)）。当前方案不使用品牌图标库，只用首字母色块，因此不存在图标资源的许可证兼容性问题。
