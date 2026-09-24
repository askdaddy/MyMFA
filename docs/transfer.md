# 导入导出格式规范

> 关联决策：[ADR-007 导出兼容范围](decisions.md#adr-007)
> 状态：设计基线，尚未实现
>
> ⚠️ **本文档中标注的第三方格式字段名基于公开资料与社区逆向，属于设计参考而非权威规范。**
> M2 阶段必须用**真实导出样本**逐一校准字段名与编码细节，并固化为 golden test。
> 任何解析器的实现都不得只依据本文档就认为完成。

## 1. 总体原则

1. **每个格式一个独立模块**，统一接口：`detect(input)` / `parse(input, options)` / `generate(vault, options)`。
2. **格式自动探测**优先于让用户手选格式。JSON 按特征字段判别，文本按 URI scheme 前缀判别，二维码按解码后的前缀判别。
3. **部分成功优于全量失败**。单条目解析失败不中止整体导入，收集错误后输出报告。
4. **导入是不可信输入路径**，全部解析器必须纯函数、无动态代码执行、有长度与嵌套深度上限（见 [security.md §8](security.md#8-导入路径的输入信任边界)）。
5. **导入前必须展示摘要**（来源格式、成功条目数、失败数与原因、重复数），用户确认后才写入 vault。

## 2. 导入矩阵

| 来源                     | 载体                                              | 加密                    | 解析要点                                                                              | 置信度   |
| ------------------------ | ------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------- | -------- |
| **Aegis**                | `aegis.json`                                      | 明文                    | `db.entries[]`，`info.secret` 为 base32                                               | 高       |
| **Aegis**                | `aegis-encrypted.json`                            | scrypt + AES-256-GCM    | 需实现 **scrypt** 解密（本项目自有 vault 用 Argon2id，scrypt 只在此只读兼容路径出现） | 高       |
| **Google Authenticator** | `otpauth-migration://offline?data=<b64 protobuf>` | 无                      | 解 protobuf `MigrationPayload`，需处理**分片**（`batch_index` / `batch_size`）        | 中       |
| **2FAS**                 | `2fas-backup.json`                                | 明文                    | `services[].otp{secret, issuer, account, period, digits, algorithm, counter}`         | 中       |
| **2FAS**                 | 加密备份                                          | PBKDF2 + AES-GCM        | 头部含 salt 与 KDF 参数                                                               | 中       |
| **Raivio Authenticator** | JSON                                              | PBKDF2-SHA256 + AES-GCM | `payload` 为 base64 密文                                                              | 中       |
| **FreeOTP / FreeOTP+**   | JSON                                              | 明文                    | token 数组，`secret` 可能是 **int 数组**而非 base32，需特殊处理                       | 中       |
| **Ente Auth**            | `ente-auth-codes.txt`                             | 明文                    | 每行一个 `otpauth://` URI                                                             | 高       |
| **Bitwarden**            | CSV                                               | 明文                    | `totp` 列，值为 `otpauth://` URI 或裸 base32                                          | 高       |
| **1Password**            | CSV                                               | 明文                    | `totp` 列为 `otpauth://` URI                                                          | 高       |
| **LastPass**             | CSV                                               | 明文                    | 专有列结构                                                                            | 低       |
| **通用 otpauth**         | `.txt` / `.csv`                                   | 明文                    | 每行一个 `otpauth://` URI                                                             | 高       |
| **通用 CSV**             | `.csv`                                            | 明文                    | 需支持列名映射（用户手动指定哪列是 secret / issuer / account）                        | 高       |
| **本 App**               | `.mfavault`                                       | Argon2id + AES-256-GCM  | 见 [vault-format.md](vault-format.md)                                                 | 完全可控 |

**明确不支持**：

| 来源                    | 原因                                                                                           |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| Authy                   | 无官方导出格式，密钥存于服务端且绑定设备。社区方案依赖抓取 Twilio 私有 API，不稳定且有账号风险 |
| Microsoft Authenticator | 无标准导出格式，仅云端备份且绑定微软账号                                                       |

这两项需在导入界面的说明文案与用户文档中明确告知，避免用户误以为功能坏了。

## 3. 导出矩阵

按用户决策，导出侧覆盖到 **Google Authenticator 迁移二维码**：

| 目标格式              | 载体                              | 说明                                                                 |
| --------------------- | --------------------------------- | -------------------------------------------------------------------- |
| **本 App 加密 vault** | `.mfavault`                       | 首选，完整保留 tag / note / sites / 使用统计 / position              |
| **本 App 明文备份**   | `.mfavault`（`encrypted: false`） | 需显著风险提示 + 二次确认                                            |
| **Aegis 明文**        | `aegis.json`                      | 双向迁移，丢弃本 App 独有字段（`sites` / `position` / `usageCount`） |
| **Aegis 加密**        | `aegis-encrypted.json`            | 需实现 **scrypt 加密**路径                                           |
| **otpauth URI 文本**  | `.txt`                            | 每行一个 URI，通用性最好                                             |
| **批量二维码**        | 屏幕显示                          | 分屏多张，适配无文件传输通道的场景                                   |
| **GA 迁移二维码**     | 屏幕显示                          | protobuf 编码，需自动分片                                            |

### 3.1 字段降级表

导出到通用格式时必然丢失信息，必须在 UI 上明确告知用户丢了什么：

| 字段                             | 本 App | Aegis            | otpauth URI | GA 迁移码 |
| -------------------------------- | ------ | ---------------- | ----------- | --------- |
| issuer / account / secret        | ✅     | ✅               | ✅          | ✅        |
| algo / digits / period / counter | ✅     | ✅               | ✅          | ✅        |
| note                             | ✅     | ✅               | ❌          | ❌        |
| tags                             | ✅     | ✅（字符串形式） | ❌          | ❌        |
| sites（域名绑定）                | ✅     | ❌               | ❌          | ❌        |
| usageCount / lastUsedAt          | ✅     | ❌               | ❌          | ❌        |
| position（手动排序）             | ✅     | ⚠️ 数组顺序      | ❌          | ❌        |
| favorite                         | ✅     | ❌               | ❌          | ❌        |

**导出前必须展示这张降级表**（或其精简版），让用户知道选了某个格式会失去哪些数据。这是防止"导出到别的 App 再导回来发现标签全没了"这类数据丢失投诉的关键。

### 3.2 otpauth URI 编码细节

```
otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30
```

- label 部分为 `issuer:account`，需 **percent-encode**；`issuer` 与 `account` 中的 `:` 必须转义
- `issuer` 既在 label 中也在 query 参数中（这是各 App 的实际惯例，两处都要写）
- `secret` 为 base32（**不带 padding**），这是 URI 格式的规定，与 vault 内存原始字节不同
- 非默认值才写 query 参数（`algorithm=SHA1` / `digits=6` / `period=30` 可省略），但为了最大兼容性建议**全部显式写出**
- HOTP 额外带 `counter=<n>`

### 3.3 GA 迁移二维码分片

Google Authenticator 的 `MigrationPayload` 单个二维码有实际条数上限（超出后 GA 无法扫描）。导出时：

- 按每批 N 条分片（N 需在 M2 用真机实测确定，社区经验约 10 条左右）
- 填充 `batch_size`（总批数）、`batch_index`（当前批次，从 0 开始）、`batch_id`（同一次导出的唯一标识）
- UI 上显示"第 X / Y 张"，支持前后翻页
- protobuf 无官方规范，编码实现需对照 GA 真机扫描结果验证，不能只靠自解析往返测试

## 4. 格式探测器

探测顺序（成本从低到高）：

1. **URI scheme 前缀**：`otpauth-migration://` → GA；`otpauth://` → 通用 URI
2. **magic / 扩展名**：`.mfavault` → 本 App
3. **JSON 特征字段**：
   - 含 `format === "mfavault"` → 本 App
   - 含 `header.slots` + `db.entries` → Aegis
   - 含 `services[]` + `schemaVersion` → 2FAS
   - 含 `payload`（base64 字符串）+ `version` → Raivio
4. **CSV 表头**：含 `totp` 列 → Bitwarden / 1Password；否则走手动列映射
5. **兜底**：无法判定时让用户手选格式，不猜

探测器必须是纯函数，对畸形输入返回"无法识别"而非抛异常。

## 5. 加密备份的密钥输入

导入他 App 的加密备份时需要用户输入**该 App 的主密码**（不是本 App 的）。UI 上必须清楚区分这两个密码，否则用户会困惑并反复输错。

KDF 参数来自备份文件自身头部，不使用本 App 默认值。Aegis 用 scrypt、2FAS/Raivio 用 PBKDF2，因此 `packages/crypto` 必须同时提供 Argon2id（自有）、scrypt（Aegis 只读兼容 + 加密导出）、PBKDF2（2FAS/Raivio 只读兼容）三种 KDF 能力。

## 6. 重复处理策略

导入时按 `(issuer, account, secret)` 三元组判重：

| 情况                                | 处理                                                 |
| ----------------------------------- | ---------------------------------------------------- |
| 完全相同                            | 跳过，计入"已存在"                                   |
| issuer + account 相同但 secret 不同 | **不自动覆盖**，作为冲突列出，让用户逐条选择保留哪个 |
| secret 相同但 issuer / account 不同 | 视为新条目导入（同一密钥可能在多处登记）             |

冲突条目在导入预览界面单独成组展示，默认不导入。

## 7. 测试要求

- 每个格式至少 3 个真实脱敏样本：正常、边界（超长字段 / 非 ASCII / 特殊字符）、畸形
- 全部样本固化为 golden test，解析结果快照比对
- protobuf 与 JSON 解析器纳入模糊测试
- 加密备份的解密路径需覆盖"密码错误"与"文件损坏"两种失败，且二者提示信息不得区分（见 [vault-format.md §5](vault-format.md#5-完整性与容错)）
