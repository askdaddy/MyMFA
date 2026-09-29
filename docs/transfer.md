# 导入导出格式规范

> 关联决策：[ADR-007 导出兼容范围](decisions.md#adr-007)、[ADR-018 兼容 KDF 豁免](decisions.md#adr-018)、[ADR-019 golden test 权威来源](decisions.md#adr-019)
> 状态：设计基线，尚未实现
>
> §2 矩阵已于 2026-09-28 按 [ADR-019](decisions.md#adr-019) 的一手来源校准（各 App 开源仓库的 schema 定义与官方文档），
> 「权威来源」列即为校准依据。仍标注为**低**置信度的行表示一手来源缺失，实现前必须再确认，不得照本表直接编码。
> 权威来源的优先级与夹具标注要求见 [testing.md §5.1](testing.md#51-字段名的权威来源adr-019)。

## 1. 总体原则

1. **每个格式一个独立模块**，统一接口：`detect(input)` / `parse(input, options)` / `generate(vault, options)`。
2. **格式自动探测**优先于让用户手选格式。JSON 按特征字段判别，文本按 URI scheme 前缀判别，二维码按解码后的前缀判别。
3. **部分成功优于全量失败**。单条目解析失败不中止整体导入，收集错误后输出报告。
4. **导入是不可信输入路径**，全部解析器必须纯函数、无动态代码执行、有长度与嵌套深度上限（见 [security.md §8](security.md#8-导入路径的输入信任边界)）。
5. **导入前必须展示摘要**（来源格式、成功条目数、失败数与原因、重复数），用户确认后才写入 vault。
6. **报错优于静默降级**。凡是「猜一个默认值就能继续」的地方，都会让用户拿到一个**算得出但永远是错的**验证码——比导入失败严重得多。§2.1 列出了必须报错的具体情形。

## 2. 导入矩阵

| 来源                     | 载体                                                                       | 加密                                                 | 解析要点（一手校准）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | 权威来源                                                                                              | 置信度             |
| ------------------------ | -------------------------------------------------------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------ |
| **Aegis**                | `aegis*.json`                                                              | 明文                                                 | 外层 `version=1`、`header.slots === null`、`db` 为**对象**（内层 `db.version=3`，与外层是两个版本号）；`db.entries[]` 每项 `{type, uuid, name(=account), issuer, note, info, group}`；`info.secret` 为 base32 **大写无 padding**；`info` 另含 `algo`（`SHA1\|SHA256\|SHA512\|MD5`，大写无连字符）、`digits`、`period`/`counter`；`type` 小写 `totp\|hotp\|steam\|motp\|yandex`；标签是 `db.groups:[{uuid,name}]` + `entries[].groups:[uuid]`，**不是字符串数组**（另有 legacy 的 `entries[].group:"name"\|null`）；`_usageCount` / `_lastUsedTimestamp` **不导出**                                                                                                                                                                                                                                                                                                                                                                                                               | Aegis 仓库 `docs/vault.md`、`vault/VaultFile.java`、`vault/Vault.java`                                | 高（一手）         |
| **Aegis**                | 同上                                                                       | scrypt + AES-256-GCM                                 | scrypt 的 `n/r/p/salt` 在 **`header.slots[]`** 逐密码槽存放（Hex 编码），**不在** `header.params`；`header.params` 只有 `{nonce, tag}`——**GCM tag 与密文分开存**；`db` 是 **base64 字符串**；官方参考实现 `docs/decrypt.py`，其测试夹具口令为 `test`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | 同上 + `docs/decrypt.py`                                                                              | 高（一手）→ 归 #10 |
| **Google Authenticator** | `otpauth-migration://offline?data=<b64 protobuf>`                          | 无                                                   | protobuf `MigrationPayload`，分片字段 `batch_index` / `batch_size` / `batch_id`；编码侧必须真机验证                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | 无一手规范（ADR-019 第 3 级以下）                                                                     | 中 → 归 #9         |
| **2FAS**                 | `2fas-backup-<yyyyMMddHHmmss>.2fas`                                        | 明文                                                 | `schemaVersion` 当前为 **4**；**`secret` 在 `services[].secret` 顶层，不在 `otp` 内**；类型判别字段是 **`services[].otp.tokenType`** = `"TOTP"\|"HOTP"\|"STEAM"`（大写），而 `services[].type` 是 PascalCase 的**品牌图标**枚举、不可当令牌类型用；kotlinx `explicitNulls=false` → **null 字段整体省略**；`otp` 内为 `{issuer, account, period, digits, algorithm, counter}`；**唯一会产出 `SHA224` / `SHA384` 的来源**（见 §2.1）；上游有 100 MiB 体积上限                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | 2FAS 仓库 `backup/` 模块（`CurrentSchema = 4`）                                                       | 高（一手）         |
| **2FAS**                 | 同上                                                                       | PBKDF2-HMAC-SHA256 + AES-GCM                         | `ITERATIONS = 10_000`、`KEY_LENGTH = 256` bit；载体是单字符串 `"b64data:b64salt:b64iv"`；**GCM tag 追加在密文末尾**（与 Aegis 的分离存放相反）；`groups` 即使在加密备份中也**保持明文**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | 同上                                                                                                  | 高（一手）→ 归 #10 |
| **Raivo OTP**            | 加密 ZIP                                                                   | WinZip AES（PBKDF2-HMAC-SHA1 + AES-CTR + HMAC-SHA1） | 官方 `DataExportFeature.swift` 使用 SSZipArchive；不属于本轮 #10 的 AES-GCM 兼容范围，算法与 ZIP 依赖须独立决策                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `raivo-otp/ios-application` @ `8ea4901b`，ZipArchive @ `b56f8c60`                                     | 一手；独立跟进     |
| **FreeOTP+**             | JSON                                                                       | 明文                                                 | `{tokens:[], tokenOrder:["issuer:label"]}`；**`secret` 是有符号 int 数组**（含负值）；`type` 大写；`digits`/`counter`/`period` 是 Java 基本类型故**恒存在**——TOTP 行也带 `counter`、HOTP 行也带 `period`，**禁止用字段存在性推断类型**；int→byte 需先校验 `[-128,127]`；分组是每 token 的 `category` 字符串                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | FreeOTP+ 仓库 `Token.java` + Aegis 夹具 `importers/freeotp_plus.json`                                 | 高（一手）         |
| **Ente Auth**            | `ente-auth-codes-plaintext-<yyyyMMdd-HHmmss UTC>.txt` / `-plainhtml-.html` | 明文                                                 | **两条导出路径**：裸 `otpauth://` URI 行，与 `jsonEncode` 后的**带引号 JSON 字符串**行；URI 携带 `codeDisplay` 百分号编码 JSON 参数（当前 9 字段 `pinned/trashed/lastUsedAt/tapCount/tags/note/position/iconSrc/iconID`，旧夹具只有 5 个）；`algorithm` 在**同一真实文件内大小写混用**；host 严格按小写匹配；`hasError` 的码被上游静默跳过                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Ente 仓库 `auth/lib/` 导出模块 + Aegis 夹具 `importers/ente_auth.txt`                                 | 高（一手）         |
| **Ente Auth**            | `ente-auth-codes-encrypted-<ts>.json`                                      | Argon2id + **XChaCha20-Poly1305**                    | `{version:1, kdfParams:{memLimit, opsLimit, salt}, encryptedData, encryptionNonce}`；文件里**没有 `parallelism`**（libsodium 固定 p=1，须实测确认而非假定）；⚠️ `hash-wasm` 不提供 XChaCha20-Poly1305，属未解的**依赖缺口**，按 `AGENTS.md` §5.2 须先立 Issue/ADR                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | 同上                                                                                                  | 中（依赖缺口未解） |
| **Bitwarden**            | CSV                                                                        | 明文                                                 | 列名是 **`login_totp`**，导入侧同时接受历史别名 **`totp`**（上游是 `value.login_totp \|\| value.totp`，见 `bitwarden-csv-importer.ts:100`）；`login_totp` 有**三种**合法形态：完整 `otpauth://` URI、`steam://<BASE32>`（字母表 `23456789BCDFGHJKMNPQRTVWXY`，digits 强制 5）、裸 base32（默认 digits 6 / period 30 / SHA1）；**不存在 `algorithm`/`digits`/`period`/`counter` 列**；个人导出含 `folder`+`favorite`，组织导出含 `collections`；**多值语义只适用于 `login_uri` 与 `collections`（单格内逗号分隔），`login_totp` 是单值**——上游只对 `login_uri` 调 `parseSingleRowCsv`（`:103`），对 `login_totp` 没有（`:100`），对 totp 套用多值语义会把 label 含未编码逗号的 URI 切成两半；身份列映射为 `name`→issuer、`login_username`（别名 `username`）→account、`notes`→note，完整 URI 自带 issuer/account 时**以 URI 为准**并记 warning（与 label/query issuer 冲突同口径）；上游只导出 Login+SecureNote 且跳过 `organizationId != null`；**必须按列名解析，禁止按列位置** | `bitwarden/clients` @ `45eb0013` 的 `libs/importer/src/importers/bitwarden/bitwarden-csv-importer.ts` | 高（一手）         |
| **1Password**            | CSV                                                                        | 明文                                                 | ⚠️ **不存在权威 CSV schema**：6 份真实夹具 + 3 个第三方导入器 + 官方措辞「limited set of fields」共同表明其 CSV **不含 TOTP 列** → **禁止硬编码 `totp` 列**。改走 1PUX（`field.id.startsWith("TOTP_")` / `value.totp`，值可能是裸 base32）或下方「通用 CSV」手动列映射                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | 无权威 schema（ADR-019 判定为不实现专用解析器）                                                       | 低                 |
| **LastPass**             | CSV                                                                        | 明文                                                 | **不实现专用解析器**：无权威来源可用（[ADR-019](decisions.md#adr-019)），改走下方「通用 CSV」的手动列映射                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | 无                                                                                                    | 低                 |
| **通用 otpauth**         | `.txt` / `.csv`                                                            | 明文                                                 | 每行一个 `otpauth://` URI。规范只定义 `hotp` / `totp`（`steam` 是私有扩展）；规范**从未声明 `algorithm` 大小写敏感**；padding「should be omitted」但现实中带 padding 的 secret 大量存在；`digits` 范围四种实现各不相同（规范 6/8、FreeOTP 6–9、Aegis 1–10、Bitwarden 夹取 1–10）；Android `Uri.encode` 会把 `=` 编成 `%3D`，而 FreeOTP 的 `appendEncodedPath` **不**对 label 做百分号编码 → **解析必须先 URL-decode `secret`，且不得假定 label 已编码**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Google Authenticator wiki 的 Key URI Format（raw markdown）                                           | 高（一手）         |
| **通用 CSV**             | `.csv`                                                                     | 明文                                                 | 需支持列名映射（用户手动指定哪列是 secret / issuer / account）；这是 1Password / LastPass 等无权威 schema 来源的统一归宿                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | 自有规范                                                                                              | 完全可控           |
| **本 App**               | `.mfavault`                                                                | Argon2id + AES-256-GCM                               | 见 [vault-format.md](vault-format.md)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | 自有规范                                                                                              | 完全可控           |

**明确不支持**：

| 来源                    | 原因                                                                                                           |
| ----------------------- | -------------------------------------------------------------------------------------------------------------- |
| Authy                   | 无官方导出格式，密钥存于服务端且绑定设备。社区方案依赖抓取 Twilio 私有 API，不稳定且有账号风险                 |
| Microsoft Authenticator | 无标准导出格式，仅云端备份且绑定微软账号                                                                       |
| FreeOTP（Red Hat）      | 导出物是 Java `ObjectOutputStream` 二进制 blob，无明文 JSON 路径；与 **FreeOTP+** 是两个不同项目，不可混为一行 |

这三项需在导入界面的说明文案与用户文档中明确告知，避免用户误以为功能坏了。

### 2.1 静默失败清单

以下情形一律**报错并计入导入摘要**，禁止「补个默认值继续」——静默降级的结果是用户拿到一个能显示但永远错误的验证码，比导入失败严重得多。

| 情形                                                                                               | 处理                                                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `algorithm` 无法归一化到本 App 支持的算法                                                          | 归一化链：去空白 → 去连字符 → 去前缀 `Hmac` → 去前缀 `Algorithm.` / `algorithm.` → `toLowerCase()` → 查表。**查不到即报错，禁止回落 SHA1**                                                                                      |
| `SHA224` / `SHA384`（仅 2FAS 会产出）                                                              | 本 App 不支持 → 报错                                                                                                                                                                                                            |
| 非 motp 条目的 `MD5`（Aegis 会产出）                                                               | 上游是静默转 SHA1；本 App 必须在导入摘要中列为「已归一化」，不得无声处理                                                                                                                                                        |
| FreeOTP+ 的 int 数组越界（超出 `[-128,127]`）                                                      | 报错，**禁止 `& 0xFF` 截断**；合法负值按 `v + 256` 转换                                                                                                                                                                         |
| Bitwarden 裸 base32 且类型为 HOTP                                                                  | `counter` 无法恢复（CSV 无该列）→ 在摘要中报出，**禁止静默置 0**                                                                                                                                                                |
| `period` 缺失                                                                                      | **不得静默补 30**。`packages/vault` 的守卫对 `period` 是条件必填且无默认值；来源格式自带默认值的（Bitwarden 裸 base32、1Password URI）由**解析器显式补**并在摘要中标注                                                          |
| 不支持的令牌类型（Aegis 的 `steam` / `motp` / `yandex`、2FAS 的 `STEAM`、Bitwarden 的 `steam://`） | 报错跳过，原因写「该令牌类型不受支持」。[ADR-004](decisions.md#adr-004) 已明确放弃这些非标准变体，`docs/vault-format.md` 也把 `digits` 冻结为 `6 \| 7 \| 8`；放宽需同时改 `packages/otp` 与 `packages/vault` 的类型，属独立决策 |
| `digits` 超范围                                                                                    | 各来源范围不一，统一按 `packages/otp` 的 `MIN_DIGITS`–`MAX_DIGITS` 判定，越界报错                                                                                                                                               |
| secret 解码失败                                                                                    | 四条解码路径（base32 字符串 / base64 原始字节 / 有符号 int 数组 / `steam://` 专用字母表）**互不兼容**，一律报错，禁止跨路径试探                                                                                                 |

## 3. 导出矩阵

按用户决策，导出侧覆盖到 **Google Authenticator 迁移二维码**：

| 目标格式              | 载体                              | 说明                                                                              |
| --------------------- | --------------------------------- | --------------------------------------------------------------------------------- |
| **本 App 加密 vault** | `.mfavault`                       | 首选，完整保留 tag / note / sites / 使用统计 / position                           |
| **本 App 明文备份**   | `.mfavault`（`encrypted: false`） | 需显著风险提示 + 二次确认                                                         |
| **Aegis 明文**        | `aegis.json`                      | 双向迁移，丢弃本 App 独有字段（`sites` / `position` / `usageCount`）              |
| **Aegis 加密**        | `aegis-encrypted.json`            | 需实现 **scrypt 加密**路径（归 #10，受 [ADR-018](decisions.md#adr-018) 边界约束） |
| **otpauth URI 文本**  | `.txt`                            | 每行一个 URI，通用性最好                                                          |
| **批量二维码**        | 屏幕显示                          | 分屏多张，适配无文件传输通道的场景                                                |
| **GA 迁移二维码**     | 屏幕显示                          | protobuf 编码，需自动分片（归 #9）                                                |

### 3.1 字段降级表

导出到通用格式时必然丢失信息，必须在 UI 上明确告知用户丢了什么：

| 字段                             | 本 App | Aegis                      | otpauth URI | GA 迁移码 |
| -------------------------------- | ------ | -------------------------- | ----------- | --------- |
| issuer / account / secret        | ✅     | ✅                         | ✅          | ✅        |
| algo / digits / period / counter | ✅     | ✅                         | ✅          | ✅        |
| note                             | ✅     | ✅                         | ❌          | ❌        |
| tags                             | ✅     | ✅（`groups` + uuid 引用） | ❌          | ❌        |
| sites（域名绑定）                | ✅     | ❌                         | ❌          | ❌        |
| usageCount / lastUsedAt          | ✅     | ❌（上游不导出）           | ❌          | ❌        |
| position（手动排序）             | ✅     | ⚠️ 数组顺序                | ❌          | ❌        |
| favorite                         | ✅     | ❌                         | ❌          | ❌        |

**导出前必须展示这张降级表**（或其精简版），让用户知道选了某个格式会失去哪些数据。这是防止"导出到别的 App 再导回来发现标签全没了"这类数据丢失投诉的关键。

### 3.2 otpauth URI 编码细节

```
otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30
```

- label 部分为 `issuer:account`，需 **percent-encode**；`issuer` 与 `account` 中的 `:` 必须转义
- `issuer` 既在 label 中也在 query 参数中（这是各 App 的实际惯例，两处都要写）
- `secret` 为 base32（**不带 padding**），这是 URI 格式的规定，与 vault 内存原始字节不同。⚠️ `packages/otp` 的 `base32Encode` **总是补 `=`**，生成 URI 时必须显式 `.replaceAll('=', '')`
- 非默认值才写 query 参数（`algorithm=SHA1` / `digits=6` / `period=30` 可省略），但为了最大兼容性建议**全部显式写出**
- HOTP 额外带 `counter=<n>`

### 3.3 GA 迁移二维码分片

Google Authenticator 的 `MigrationPayload` 单个二维码有实际条数上限（超出后 GA 无法扫描）。导出时：

- 按每批 N 条分片。N 无一手规范可依，按 [ADR-019](decisions.md#adr-019) 降级为**可配置常量**，先取社区经验值（约 10 条），真机实测归 #11
- 填充 `batch_size`（总批数）、`batch_index`（当前批次，从 0 开始）、`batch_id`（同一次导出的唯一标识）
- UI 上显示"第 X / Y 张"，支持前后翻页
- protobuf 无官方规范，编码实现需对照 GA 真机扫描结果验证，不能只靠自解析往返测试

## 4. 格式探测器

探测顺序（成本从低到高）：

1. **URI scheme 前缀**：`otpauth-migration://` → GA；`otpauth://` → 通用 URI
2. **magic / 扩展名**：`.mfavault` → 本 App
3. **JSON 特征字段**：
   - 含 `format === "mfavault"` → 本 App
   - **Aegis**：`typeof version === 'number' && 'header' in json && 'db' in json`。**不能**用「含 `header.slots`」判别——明文导出的 `header.slots` 是 `null`（键存在、值为 null）；也**不能**用 `db.entries`——加密时 `db` 是 base64 字符串而非对象
   - **2FAS**：`'servicesEncrypted' in json || ('services' in json && 'schemaVersion' in json)`。加密备份的 `services` 是**空数组**，只靠「`services[]` 非空」会漏判
   - **Ente 加密**：`kdfParams.memLimit` + `encryptedData` + `encryptionNonce`
   - **FreeOTP+**：`tokens[]` + `tokenOrder[]`
   - **Raivo**：加密 ZIP（独立跟进）；不按 JSON `payload` 猜测，不在 #10 探测范围
4. **文本行形态**：先区分「裸 `otpauth://` URI 行」与「`jsonEncode` 后的带引号 JSON 行」——Ente 的两条明文导出路径都可能落在 `.txt` 里
5. **CSV 表头**：含 `login_totp` 列 → Bitwarden；**不得**用 `totp` 列判别 1Password（其 CSV 无 TOTP 列）；否则走手动列映射。探测只认 `login_totp`，但**解析器仍须接受 `totp` 别名**（上游导入侧读 `login_totp || totp`）——只用别名的老导出会被探测成 `generic-csv`，此时由用户手选 Bitwarden，解析器不能因为列名是别名就读不出密钥
6. **兜底**：无法判定时让用户手选格式，不猜

探测器必须是纯函数，对畸形输入返回"无法识别"而非抛异常。

## 5. 加密备份的密钥输入

导入他 App 的加密备份时需要用户输入**该 App 的主密码**（不是本 App 的）。UI 上必须清楚区分这两个密码，否则用户会困惑并反复输错。

文件携带的 KDF 参数严格读取文件；未携带参数只采用受支持版本的一手定义常量。Aegis 用 scrypt，2FAS 用 PBKDF2-SHA256（固定 10000 次、32 字节）；禁止套用自有 vault 默认值或降级猜测。Aegis 加密导出由调用方显式提供 scrypt 参数并写入槽。自有 Argon2id-only 接口保持不变，scrypt/PBKDF2 通过独立兼容 Provider 注入。

scrypt 与 PBKDF2 触碰了 `AGENTS.md` §5.1 / §5.2 的字面禁令，其豁免边界由 [ADR-018](decisions.md#adr-018) 规定，四个条件全部必须满足：

1. 文件携带参数严格读取文件；未携带参数只允许一手格式常量；第三方导出显式提供参数并写入文件，禁止套用自有 vault 默认值
2. 派生出的密钥只用于解开该第三方容器，禁止参与自有 vault 的任何密钥派生、包裹或认证
3. 兼容路径禁止被自有 vault 的读写路径调用（`packages/vault` 不得依赖它）
4. 实现必须来自既有依赖或平台原生能力（scrypt 用 hash-wasm，PBKDF2 优先 WebCrypto），不得手写

Web 端的 scrypt 走 `hash-wasm`（WebCrypto 不提供 scrypt）；PBKDF2 优先用 WebCrypto 原生能力。移动端 M3 需另找 scrypt 的原生实现，这是一条新增的跨端一致性风险（ADR-018 后果一节）。

**Ente 加密导出是例外中的例外**：它的 AEAD 是 XChaCha20-Poly1305，既不在自有白名单（Argon2id + AES-256-GCM）内，`hash-wasm` 也不提供该算法。这构成一个未解的依赖缺口，按 `AGENTS.md` §5.2 必须先有 Issue/ADR 说明理由与许可证才允许引入新加密依赖；在此之前 Ente 只实现明文导入路径。

## 6. 重复处理策略

导入时按 `(issuer, account, secret)` 三元组判重：

| 情况                                | 处理                                                 |
| ----------------------------------- | ---------------------------------------------------- |
| 完全相同                            | 跳过，计入"已存在"                                   |
| issuer + account 相同但 secret 不同 | **不自动覆盖**，作为冲突列出，让用户逐条选择保留哪个 |
| secret 相同但 issuer / account 不同 | 视为新条目导入（同一密钥可能在多处登记）             |

判重用的 `secret` 必须是**解码后的原始字节**，不能拿编码字符串比：同一密钥在 Aegis 里是无 padding base32、在本 App 里是 base64、在 FreeOTP+ 里是 int 数组，字符串比对会把完全相同的条目判成三条。

冲突条目在导入预览界面单独成组展示，默认不导入。

## 7. 测试要求

- 每个格式至少 3 个脱敏样本：正常、边界（超长字段 / 非 ASCII / 特殊字符）、畸形；字段名权威来源与夹具标注要求见 [ADR-019](decisions.md#adr-019) 与 [testing.md §5.1](testing.md#51-字段名的权威来源adr-019)
- 全部样本固化为 golden test，解析结果快照比对；夹具目录 `packages/transfer/src/__fixtures__/`
- **可直接复用的真实夹具**：Aegis 仓库 `app/src/test/resources/com/beemdevelopment/aegis/` 下的 `importers/aegis_plain.json`、`importers/aegis_encrypted.json`（口令 `test`）、`vault/aegis_plain_grouped_v2.json`、`importers/2fas_authenticator.json`（schemaVersion 1，用于前向兼容）、`importers/freeotp_plus.json`、`importers/ente_auth.txt`、`importers/bitwarden.json`、`importers/plain.txt`，以及参考实现 `docs/decrypt.py`。这些均为上游自带的**假密钥**，符合 `AGENTS.md` §5.3，vendored 时必须附来源 URL + commit SHA
- protobuf 与 JSON 解析器纳入模糊测试
- 加密备份的解密路径需覆盖"密码错误"与"文件损坏"两种失败，且二者提示信息不得区分（见 [vault-format.md §5](vault-format.md#5-完整性与容错)）
