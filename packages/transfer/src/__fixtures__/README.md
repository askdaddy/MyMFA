# golden 夹具来源标注

## #10 加密夹具（非真实用户备份）

`aegis_encrypted.json`、`twofas_encrypted_v2.2fas`、`twofas_encrypted_v3.2fas`、
`twofas_encrypted.2fas` 逐字节取自下方 Aegis commit 的 `importers/` 测试资源。
其中后者上游文件名为 `2fas_authenticator_encrypted_v4.2fas`；v2 上游文件名无版本后缀。
上游 `DatabaseImporterTest.java` 明确使用假密码 `test`，secret 与已有明文测试资源同源。

`aegis_encrypted_edge.json` / `aegis_encrypted_malformed.json`、
`twofas_encrypted_edge.2fas` / `twofas_encrypted_malformed.2fas`
是按上述一手 schema 定义构造，非真实 App 导出，假密码 `test-测试`，种子来自既有
`aegis_grouped_v3.json` / `twofas_edge.json`；独立 Node crypto 生成密文。
Aegis 边界覆盖非密码槽、错误密码槽、正确密码槽与分组，畸形覆盖超限 N；
2FAS 边界覆盖独立 salt、明文分组、部分失败、伪造 iterations 字段，畸形覆盖多余载体段。
固定 salt / nonce 仅用于可复现的假值夹具，生产生成器使用注入的密码学随机源。

2FAS 固定加密参数依据 `twofas/2fas-android` @ `0a6b4a87d4eafc38aabc9721be59bd06e88c7e54`
的 `core/cipher/.../backup/internal/BackupKeyGeneratorPbkdf.kt`、`backup/DataEncrypted.kt`
与 `internal/CipherAes.kt`；Aegis 密码槽依据同 commit 来源表中的 `docs/vault.md`。

本目录下的夹具分两类。**非真实 App 导出**——全部 secret 均为上游仓库自带的假密钥或 RFC 测试向量，
符合 `AGENTS.md` §5.3「测试夹具中的 secret 必须使用假值」。

来源权威性与标注要求见 [ADR-019](../../../../docs/decisions.md#adr-019) 与
[testing.md §5.1](../../../../docs/testing.md#51-字段名的权威来源adr-019)。

## 一、vendored：逐字节取自 Aegis 仓库

来源仓库：<https://github.com/beemdevelopment/Aegis>
commit SHA：`d6f4e5925a97e4e91593f1542085eae03432a759`（`master`，2026-09-28 取得）
上游路径前缀：`app/src/test/resources/com/beemdevelopment/aegis/`

| 本目录文件              | 上游路径                                  | 用途                                                                    |
| ----------------------- | ----------------------------------------- | ----------------------------------------------------------------------- |
| `aegis_plain.json`      | `importers/aegis_plain.json`              | Aegis 明文**正常**样本；`db.version=1`，无分组，含 1 条 `type: steam`   |
| `aegis_plain_grouped_v2.json` | `vault/aegis_plain_grouped_v2.json` | Aegis 明文分组样本；`db.version=2`，用 **legacy** `entries[].group` 字符串 |
| `2fas_authenticator.json` | `importers/2fas_authenticator.json`     | 2FAS **`schemaVersion: 1`** 前向兼容样本，见下方「v1 的特殊性」         |
| `2fas_authenticator_plain_v4.2fas` | `importers/2fas_authenticator_plain_v4.2fas` | 2FAS **`schemaVersion: 4`**（当前）明文正常样本                    |
| `freeotp_plus.json`     | `importers/freeotp_plus.json`             | FreeOTP+ **正常**样本；`secret` 为有符号 int 数组                        |
| `ente_auth.txt`         | `importers/ente_auth.txt`                 | Ente 明文**正常**样本；`codeDisplay` 为**旧 5 字段**形态，末行 `algorithm=sha512` 小写 |
| `bitwarden.csv`         | `importers/bitwarden.csv`                 | Bitwarden **正常**样本；列为 `login_totp`，含 1 行 `steam://`            |
| `plain.txt`             | `importers/plain.txt`                     | 通用 otpauth URI 文本**正常**样本；含 `issuer=Air+Canada`（`+` 表空格）与 `%20` |

### 2FAS `schemaVersion: 1` 的特殊性

v1 的 `services[].otp` **只有** `account` / `issuer` / `label` 三个键——没有 `tokenType`、
没有 `digits`、没有 `period`、没有 `algorithm`。也就是说 v1 备份**在结构上无法**还原出一个
可计算验证码的条目。按 C8「报错优于静默降级」，解析器必须整包失败并给出版本相关的提示，
**不得**补默认值蒙过去。这份夹具就是该行为的 golden 输入。

### Aegis `db.version` 与分组形态

两份 vendored 夹具分别是 `db.version` 1 与 2，**都不含** v3 引入的
`db.groups:[{uuid,name}]` + `entries[].groups:[uuid]` uuid 引用式分组，只有 v2 的 legacy
`entries[].group:"name"|null`。因此 uuid 形态由下方自构造夹具 `aegis_grouped_v3.json` 覆盖。

## 二、自构造：按一手 schema 手工编写

`_edge` 为**边界**样本（超长字段 / 非 ASCII / 特殊字符 `:` `/` `%` `+` 空格 / 越界取值），
`_malformed` 为**畸形**样本（结构性错误）。**非真实 App 导出**——全部 secret 取自上表
vendored 夹具里的同一批上游假密钥，因此可以做跨格式字节相等断言（C10）。

字段名的权威来源（2026-09-28 逐一读取核对，非推测）：

| 上游仓库 | 分支 | commit SHA | 权威文件 |
| --- | --- | --- | --- |
| `beemdevelopment/Aegis` | `master` | `d6f4e5925a97e4e91593f1542085eae03432a759` | `app/src/main/java/com/beemdevelopment/aegis/vault/VaultEntry.java` |
| `twofas/2fas-android` | `develop` | `0a6b4a87d4eafc38aabc9721be59bd06e88c7e54` | `data/services/src/main/java/com/twofasapp/data/services/domain/{BackupContent,BackupService,BackupGroup}.kt` |
| `helloworld1/FreeOTPPlus` | `master` | `1e1e26552212e1c706fdcae08079cf0cc69655d8` | `token-data/src/main/java/org/fedorahosted/freeotp/data/legacy/{Token.java,SavedTokens.kt}` |
| `ente/ente` | `main` | `23201f1bbb215a955962118df476951723069fcb` | `mobile/apps/auth/lib/models/{code.dart,code_display.dart}` |
| `bitwarden/clients` | `main` | `45eb0013dc413dab78932c418d209d89371febf6` | `libs/importer/src/importers/bitwarden/bitwarden-csv-importer.ts` |
| 本仓库 `packages/vault` | — | — | `src/{types,guard,migrate}.ts` 与 `src/__fixtures__/schema-v0.json` |

通用 `otpauth://` 语法参照 Google Authenticator wiki 的 *Key URI Format*（无版本化 SHA，
故 `plain.txt` 这份 vendored 夹具才是本仓库的本地权威）。

### 各文件覆盖点

| 文件 | 覆盖的边界 / 畸形点 |
| --- | --- |
| `aegis_grouped_v3.json` | `db.version=3` 的 `db.groups:[{uuid,name}]` + `entries[].groups:[uuid]` 引用式分组；一条挂在**多个**分组、一条引用**不存在**的 uuid、一条 `groups:[]` |
| `aegis_edge.json` | 非 ASCII 与特殊字符 `:` `/` `%` `+` 空格；5000 字符超长 `note`（超 `maxFieldLength=4096`）；`algo:"MD5"`；`algo:"HmacSHA256"`；`digits:10`；totp 缺 `period`；hotp 缺 `counter`；`type:"steam"`；缺 `name`（上游用 `getString`，为必填） |
| `aegis_malformed.json` | `db.entries` 是对象而非数组 |
| `twofas_edge.json` | `tokenType:"STEAM"`；`algorithm:"SHA224"`；totp 缺 `period`；`otp` 整体缺失（违反 schema：`BackupService.otp` 非空）；非 ASCII；非空 `groups:[{id,name,isExpanded,updatedAt}]` 与悬空 `groupId`；`link` 与结构化字段**互相矛盾**（判定优先级）；`counter:-1` |
| `twofas_malformed.json` | `services` 不是数组 |
| `freeotp_plus_edge.json` | `secret` 含有符号下界 `-128`；`category`；**缺 `tokenOrder`**；`issuerInt:""` 而 `issuerExt` 有值（上游 `getID()` 的回退顺序）；`issuerAlt`/`labelAlt`/`image`/`imageAlt` 应被忽略；第三条**完全没有** `issuerInt`/`issuerExt` |
| `freeotp_plus_malformed.json` | `secret` 含越界值 `128` 与 `-129`；另一条 `secret` 是 base32 **字符串**而非 int 数组 |
| `ente_edge.txt` | 11 行：九字段 `codeDisplay` 全量非默认值 / `trashed:true` / `algorithm` 小写 / `algorithm.sha256` 泄漏形式 / `Algorithm.SHA256` 大写前缀 / `steam` host / `codeDisplay` 坏 JSON / `%2C` 双重编码残留 / `codeDisplay` 后跟未转义 `#` 片段 / 缺 `secret` / 无 `codeDisplay` 参数 |
| `ente_jsonlines.txt` | `toOTPAuthUrlFormat()` 的 `jsonEncode(uri)` 产物——每行是**带引号的 JSON 字符串**，其中一行 label 含裸空格 |
| `bitwarden_edge.csv` | alias 列名（`totp`/`uri`/`username`，非 `login_*`）；`folder` 多级路径；`favorite` 取 `1`/`0`/空；裸 base32；`otpauth://hotp/...` **缺 counter**（不可恢复）；`steam://`；`login_totp` 为空；`type:note` 整行；非 ASCII；含 `"`、`,`、换行的引用单元格 |
| `bitwarden_malformed.csv` | 数据行字段数少于 / 多于表头，外加一条合法行——**只**含这一种缺陷，用于验证 C5 的单行失败路径（失败行进 `failures` 且带行号，合法行仍须导出）。未闭合引号属整包中止，混在同一份文件里会让这条路径永远走不到 |
| `otpauth_edge.txt` | 20 行：`secret` 带完整 `%3D%3D%3D%3D%3D%3D` padding 与**错误长度**的 `%3D%3D`；label 裸空格；`issuer=Air+Canada`；label 无 issuer；label 与 query 的 issuer 冲突；label 多冒号；hotp 缺 counter；totp 缺 period；非 `otpauth` scheme；scheme 大写；空行与纯空白行；`steam`；`digits=10`；`period=0`；`counter=-1`；缺 secret；缺 scheme 与 host；`#` 片段；`issuer` 内含 `period=`（Ente PR#77 的截断问题） |
| `otpauth_malformed.txt` | 整行不是 URI；单斜杠；`%%%%` 非法百分号转义；空 host 空 secret；NUL 字节 |
| `generic_csv.csv` | 自定义中文列名的通用 CSV（需调用方给映射）；分号分隔的多标签；含 `"`、`,` 与换行的引用单元格 |
| `generic_csv_edge.csv` | UTF-8 **BOM**；**CRLF** 行尾；5000 字符超长单元格（超 `maxFieldLength=4096`）；未知多余列与**空表头单元格**；`digits:10` 越界；`period:0`；算法写作 `sha1`/`SHA-512`/`HmacSHA256` 三种待归一化形式 |
| `generic_csv_malformed.csv` | 表头有**重复列名**（本身不致命：后一列覆盖前一列，需要区分时看 `header`）；`secret` 单元格**未闭合引号**——这才是整包中止的原因 |
| `mfavault_plaintext.json` | 本 App 明文容器（`encrypted:false`）；`data` 已通过 `assertVaultData` 实测（3 条目 / 1 tag / secret 为 16 字节 base64） |
| `mfavault_plaintext_v0.json` | `schemaVersion:0` 且 `data` 无 `settings`、带 `legacyFieldFromV0`；实测经 `migrateVaultData` 走 `migrate_0_to_1` 后保留遗留字段并补上 `settings`，迁移前则被 `assertVaultData` 拒绝 |
| `mfavault_malformed.json` | `encrypted:true` 但 `data` 是明文对象且无 `crypto` 块——必须报"这是加密容器"而非笼统的格式错误 |

## 三、机械变形的约定

截断、字节级损坏、类型错位（字符串写成数字等）这类**可由正常样本机械派生**的畸形输入，
不单独存文件，而是在测试里对 vendored 夹具做变形。理由：这些变形的价值在于覆盖面而非内容，
存成文件只会让夹具目录膨胀且难以维护（lazy-ladder：删优于加）。

## 四、上游怪癖（写测试前必读）

以下四条都是核对上游源码时发现的、**与直觉相反**的事实，直接影响断言怎么写：

1. **FreeOTP+ 的 counter 与 Aegis 系统性差 1。** 同一批身份在上游两份夹具里：
   `WWE:Mason` Aegis=10300 / FreeOTP+=10299，`Air Canada:Benjamin` 50 / 49，
   `Issuu:James` 1 / 0。因此**跨格式相等断言只能针对 `secret` 的解码字节**，
   不能针对 counter。
2. **FreeOTP+ 每个 token 都同时带 `counter` 与 `period`**，与 `type` 无关——Gson 把
   `Token` 的全部字段无条件序列化。所以「TOTP 携带 counter」在 FreeOTP+ 里是**常态**
   而非边界；解析器取哪个由 `type` 决定，另一个直接忽略。
3. **Bitwarden 的 `login_totp` 是单值**，逗号分隔的多值只出现在 `login_uri`
   （上游对后者调 `parseSingleRowCsv`，对 `login_totp` 没有）。别把多值语义套到 totp 上。
   另外 `favorite` 的判定是 `!== "0"`——任何非 `"0"` 的非空值都算 true。
4. **Ente 的 `_getCounter()` 解析失败时返回 `defaultPeriod`（30）**，这是上游的 bug，
   把「周期」当成了「计数器」的兜底值。本 App **不得复制**该行为：counter 不可恢复就报错
   （C8）。同理 Ente 的 `_getDigits`/`_getPeriod`/`_getAlgorithm` 在异常时静默回落到
   `defaultDigits`/`defaultPeriod`/`sha1`，而 `docs/transfer.md` §2.1 明确要求**查不到即报错**。
   夹具里的 `algorithm.sha256` / `Algorithm.SHA256` 就是用来钉住这条差异的。
