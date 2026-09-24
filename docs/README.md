# 文档索引

本目录是项目的**设计基线**。实现必须与这些文档一致；若实现中发现设计有误，先改文档再改代码。当前进度见 [`AGENTS.md` §2](../AGENTS.md)。

## 先读什么

| 你的目的           | 从这里开始                                                            |
| ------------------ | --------------------------------------------------------------------- |
| 快速了解这是什么   | [`../README.md`](../README.md)                                        |
| 了解为什么这么设计 | [`decisions.md`](decisions.md)                                        |
| 开始写代码         | [`../AGENTS.md`](../AGENTS.md) → [`architecture.md`](architecture.md) |
| 实现加密/vault     | [`security.md`](security.md) → [`vault-format.md`](vault-format.md)   |
| 实现导入导出       | [`transfer.md`](transfer.md)                                          |
| 实现扩展           | [`chrome-extension.md`](chrome-extension.md)                          |
| 写测试             | [`testing.md`](testing.md)                                            |
| 了解排期与风险     | [`roadmap.md`](roadmap.md)                                            |

## 文档清单

| 文档                                         | 内容                                                                                                                                                                                                             | 状态                                             |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| [`decisions.md`](decisions.md)               | 16 条 ADR：技术栈、同步策略、预提示形态、令牌范围、扩展范围、安全模型、导出兼容、图标、KDF 选型、时钟校准、双层密钥、fractional indexing、Tag 全局实体、secret 存原始字节、扩展零 host_permissions、产品名与托管 | ✅ 基线（16 条全部已确认或技术推导，无待确认项） |
| [`architecture.md`](architecture.md)         | monorepo 结构、5 个核心包职责、依赖方向规则、平台适配层、工具链选型                                                                                                                                              | ✅ 基线                                          |
| [`security.md`](security.md)                 | 威胁模型、DEK/KEK 双层密钥、加密算法与参数、跨端一致性风险、MV3 解锁态、局域网迁移安全、运行时防护                                                                                                               | ✅ 基线                                          |
| [`vault-format.md`](vault-format.md)         | 容器格式（加密/明文）、Entry/Tag/Settings schema、fractional indexing、schema 迁移链、完整性与容错、自动备份                                                                                                     | ✅ 基线 v1                                       |
| [`features.md`](features.md)                 | 列表与预提示、时钟校准、条目管理、排序、搜索、tag 与备注、首字母色块、安全 UI 要求、无障碍与国际化                                                                                                               | ✅ 基线                                          |
| [`transfer.md`](transfer.md)                 | 导入矩阵（13 种来源）、导出矩阵（7 种目标）、字段降级表、otpauth URI 编码、GA 迁移码分片、格式探测器、重复处理                                                                                                   | ⚠️ 字段名待真实样本校准                          |
| [`chrome-extension.md`](chrome-extension.md) | MV3 三入口架构、权限最小化、域名绑定匹配规则、解锁态与 SW 生命周期、数据导入路径、V2 局域网配对的权限冲突                                                                                                        | ✅ 基线                                          |
| [`testing.md`](testing.md)                   | 测试分层、RFC 官方测试向量、跨端加密一致性验证方法、golden test、域名匹配安全用例、模糊测试、E2E、安全审查清单                                                                                                   | ✅ 基线                                          |
| [`roadmap.md`](roadmap.md)                   | M0–M6 里程碑与出口标准、依赖关系图、10 项风险清单、明确的非目标                                                                                                                                                  | ✅ 基线（工期未估算）                            |

## 关键约束速查

这几条最容易被忽略，违反会造成返工或安全事故：

1. **`packages/*` 禁止 import 任何平台 API**。平台差异通过 Provider 注入。（[architecture.md §3](architecture.md#3-依赖方向)）
2. **M0 未通过跨端加密一致性验证，不得开始 vault 层实现**。（[security.md §4](security.md#4-跨端实现一致性本项目最大技术风险)）
3. **`secret` 存原始字节的 base64，不存 base32 字符串**。（[ADR-014](decisions.md#adr-014)）
4. **Argon2id 参数只能上调不能下调**。（`AGENTS.md` §5.1）
5. **`biometricWrappedDek` 绝不进入 vault 文件或导出内容**。（[security.md §2](security.md#2-双层密钥模型)）
6. **DEK 只存 `chrome.storage.session`，禁止存 `local`**。（[chrome-extension.md §5](chrome-extension.md#5-解锁态与生命周期)）
7. **域名匹配必须用 `hostname === site || hostname.endsWith("." + site)`**，裸 `endsWith` 会被 `evil-github.com` 绕过。（[chrome-extension.md §4.3](chrome-extension.md#43-匹配规则)）
8. **主密码错误与文件损坏必须给出同一条提示**，防止密码探测旁路。（[vault-format.md §5](vault-format.md#5-完整性与容错)）
9. **第三方格式的字段名以真实样本为准**，`transfer.md` 只是设计参考。（[transfer.md 顶部警告](transfer.md)）
10. **测试夹具只用假 secret**，禁止提交任何真实备份文件。（`AGENTS.md` §5.3）

## 待确认事项

方案中留白、需在对应阶段前确认的项，完整清单见 [`decisions.md` 待决策清单](decisions.md#待决策清单)。

2026-09-24 已解决三项关键决策：产品名 **MyMFA** / scope **`@askdaddy`** / 托管 **GitHub**（[ADR-016](decisions.md#adr-016)）、**Argon2id** 采纳（[ADR-009](decisions.md#adr-009)）、**时钟校准**采纳（[ADR-010](decisions.md#adr-010)）。M0 阶段 0–4 因此全部解除阻塞。

剩余待决策中影响最近的一项是 **仓库可见性（public / private）**，它决定许可证选择与 CI 配置，需在创建 GitHub 远端前确定。
