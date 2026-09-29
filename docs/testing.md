# 测试策略

> 状态：设计基线，尚未实现。框架选型 Vitest。

本项目的测试重心与普通 App 不同：**密码学正确性**与**格式兼容性**的缺陷是致命的且用户无法自行诊断（验证码对不上、备份打不开），而 UI 缺陷只是难用。因此测试投入按此优先级分配。

## 1. 测试分层

| 层               | 范围                                                         | 位置                                                                                                                      | 优先级   |
| ---------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- | -------- |
| 跨端加密一致性   | Argon2id / AES-GCM 三端字节比对                              | Web：`packages/crypto-web/src/__tests__`；Android/iOS：`apps/mobile` 原生模块测试。**共用参考向量置于 `packages/crypto`** | **最高** |
| 算法正确性       | RFC 4226 / 6238 官方测试向量                                 | `packages/otp/__tests__`                                                                                                  | 最高     |
| 格式往返         | vault 加解密 + schema 迁移                                   | `packages/vault/__tests__`                                                                                                | 高       |
| 导入 golden test | 每个第三方格式的样本快照（来源见 [§5](#5-导入-golden-test)） | `packages/transfer/src/__fixtures__`                                                                                      | 高       |
| 领域逻辑         | 排序稳定性、搜索评分、域名匹配                               | `packages/domain/__tests__`                                                                                               | 中       |
| 模糊测试         | 解析器对畸形输入的健壮性                                     | `packages/transfer/src/__tests__/fuzz`                                                                                    | 中       |
| 端到端           | App / 扩展的用户流程                                         | `test/`                                                                                                                   | 中       |

**覆盖率目标**：`packages/otp`、`packages/crypto`、`packages/vault` 要求 100% 分支覆盖；其余包不设硬性指标，但关键路径必须有测试。

## 2. OTP 算法测试

使用 RFC 官方测试向量，不自己造数据。下表已用 Node `crypto` 实算复核（2026-09-24），与 RFC 原文一致。

**RFC 4226（HOTP）附录 D** — secret = `"12345678901234567890"`（ASCII，20 字节），SHA-1，6 位：

| counter | 期望码 | counter | 期望码 |
| ------- | ------ | ------- | ------ |
| 0       | 755224 | 5       | 254676 |
| 1       | 287082 | 6       | 287922 |
| 2       | 359152 | 7       | 162583 |
| 3       | 969429 | 8       | 399871 |
| 4       | 338314 | 9       | 520489 |

**RFC 6238（TOTP）附录 B** — 8 位，`period = 30`，三种摘要算法各用**不同长度的 secret**：

| 时间（秒）  | SHA-1    | SHA-256  | SHA-512  |
| ----------- | -------- | -------- | -------- |
| 59          | 94287082 | 46119246 | 90693936 |
| 1111111109  | 07081804 | 68084774 | 25091201 |
| 1111111111  | 14050471 | 67062674 | 99943326 |
| 1234567890  | 89005924 | 91819424 | 93441116 |
| 2000000000  | 69279037 | 90698825 | 38618901 |
| 20000000000 | 65353130 | 77737706 | 47863826 |

对应 secret（均为 `"1234567890"` 模式重复至指定长度的 ASCII 字节）：

| 算法    | secret 长度 | secret（ASCII）                                                    |
| ------- | ----------- | ------------------------------------------------------------------ |
| SHA-1   | 20 字节     | `12345678901234567890`                                             |
| SHA-256 | 32 字节     | `12345678901234567890123456789012`                                 |
| SHA-512 | 64 字节     | `1234567890123456789012345678901234567890123456789012345678901234` |

⚠️ 三个算法的 secret **长度不同**，测试时不要混用同一个 secret——这是最常见的错误，会导致 SHA-256/512 全部对不上。

**额外必测用例**：

- `digits` 为 6 / 7 / 8 的截断正确性，含前导零（`07081804` 不能被当作数字丢掉前导零）
- `period` 非 30（如 60）
- 周期边界：`t = 29.999s` 与 `t = 30.000s` 必须落在不同步
- **预提示码**：`nextCode()` 必须等于下一秒进入周期后的 `currentCode()`，且在周期边界处连续
- HOTP 的 `counter + 1` 预提示
- `clockOffsetSeconds` 正负偏移补偿

**base32 测试**：padding 缺失、小写、内含空格、`0/O` 与 `1/I` 混淆字符、非法字符拒绝、空输入。

## 3. 跨端加密一致性测试（最高优先级）

这是本项目最大的技术风险，**必须在 M0 完成，未通过不得开始 vault 层实现**（见 [ADR-009](decisions.md#adr-009)）。

出口标准按端拆分（Web 端部分进入 M1 前必须达成，移动端部分进入 M3 前必须达成），拆分依据与两部分的契约见 [roadmap.md M0](roadmap.md#m0--基础设施与技术验证--关键路径)。

**当前进度**：Web 端部分已于 2026-09-24 达成（GitHub Issue #2），Android / iOS 部分待 M3。固化的生产比对基线是 `packages/crypto/src/vectors.ts` 的 `ARGON2ID_PRODUCTION_VECTOR`，移动端后续比对的正是同一份向量。`pnpm test:cross` 当前只覆盖 Web 端。

### 3.1 三端实现

| 端         | Argon2id 实现             | AEAD                 | 代码位置                      | 一致性验证 |
| ---------- | ------------------------- | -------------------- | ----------------------------- | ---------- |
| Web / 扩展 | `hash-wasm`               | WebCrypto            | `packages/crypto-web`（共用） | ✅ 已达成  |
| Android    | argon2-jvm                | Conscrypt / Keystore | `apps/mobile` 原生模块        | ⬜ 待 M3   |
| iOS        | libsodium `crypto_pwhash` | CryptoKit            | `apps/mobile` 原生模块        | ⬜ 待 M3   |

`version` 必须是 `0x13`（Argon2 1.3），不能依赖各库默认值。三端的满足方式不同：

| 端         | 如何保证 version = `0x13`                                                                |
| ---------- | ---------------------------------------------------------------------------------------- |
| Android    | argon2-jvm 显式传入版本参数                                                              |
| iOS        | libsodium `crypto_pwhash` 显式传 `crypto_pwhash_ARGON2ID_VERSION`                        |
| Web / 扩展 | `hash-wasm` **无 `version` 入参**，改为断言其 `outputType: 'encoded'` 的 PHC 串含 `v=19` |

### 3.2 已知答案测试（KAT）先行

三端交叉比对之前，每端实现必须先独立通过 **RFC 9106 §5.3** 的 Argon2id 官方向量。这是唯一能证明「实现本身正确」的手段——只靠三端互相一致，可能是三端一起错。

```
password          = 32 字节，全部为 0x01
salt              = 16 字节，全部为 0x02
secret (keyed)    =  8 字节，全部为 0x03
associated data   = 12 字节，全部为 0x04
memoryKiB         = 32
iterations        = 3
parallelism       = 4
version           = 0x13
tagLength         = 32

期望 tag =
0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9
d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59
```

注意三点：

- 该向量**带 `secret` 与 `associated data`**，而 `hash-wasm@4.12.0` 的 `IArgon2Options` 实测字段为 `password / salt / secret? / iterations / parallelism / memorySize / hashLength / outputType?`——**没有 `associatedData`**（2026-09-24 核查其已发布的 `.d.ts` 确认）。因此 Web 端**无法用 `hash-wasm` 直接复现官方向量**，必须按下方「Web 端的等价论证链」处理，**不得跳过 KAT**。
- `memoryKiB = 32` 远低于生产基线 65536，因此 `assertArgon2idParams` 只做结构性校验、不比对基线；基线降级检查在 vault 层执行（见 `packages/crypto/src/params.ts`）。
- 好消息：`hash-wasm` 的 `memorySize` 文档明确为 kibibytes，与本项目统一的 `memoryKiB` 语义一致，**恒等传递、无需换算**——这消除了 §3.4 的头号失败模式。换算仍需独立测试断言，因为「看起来不用换算所以没测」正是单位混淆的温床。

#### Web 端的等价论证链

`hash-wasm` 跑不了带 AD 的官方向量，改用 `argon2@0.45.1`（node-argon2，绑定 P-H-C/phc-winner-argon2 **官方参考实现**）作 **devDependency 测试对照**。它的 `HashOptions` 同时支持 `secret`、`associatedData` 与显式 `version`（默认 `0x13`），正好补上 `hash-wasm` 的两个缺口。三段论证：

| 环节  | 断言                                                                                                    | 证明了什么                                 |
| ----- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| KAT-1 | 对照实现在 RFC 9106 §5.3 完整入参（含 `secret` 与 AD）下输出**逐字节等于**官方期望 tag                  | 对照实现可信，且本项目对该向量的解读正确   |
| KAT-2 | `hash-wasm` 与对照实现在**生产配置**下输出字节级相等                                                    | `hash-wasm` 的实现正确                     |
| 版本  | `hash-wasm` 的 `outputType: 'encoded'` PHC 串含 `v=19`，且 `m=` / `t=` / `p=` 与 `ARGON2ID_PARAMS` 一致 | 版本为 `0x13`，且 `memoryKiB` 换算未被弄错 |

KAT-2 的「生产配置」指 vault 实际使用的配置——**无 `secret`、无 `associated data`**（双层密钥模型只用 `主密码 + salt`，见 [security.md §2](security.md#2-双层密钥模型)）。因此 `hash-wasm` 缺这两个入参**对本项目的实际用途无影响**，KAT-1 → KAT-2 的传递论证在本项目用途范围内是完备的。

已排除的对照路径：本机 OpenSSL 3.6.4 虽提供 ARGON2ID KDF，但线程池不可配置——`threads=1` 可用、`threads=4` 报 `invalid thread pool size ... requested 4 threads, available: 0`，`OPENSSL_CONF` 的 `[openssl_init] threads` 亦无效（2026-09-24 实测），而生产参数 `parallelism=4` 必须能跑，故不可用作对照。

对照实现缺失时相关测试必须**失败**，不得 skip 或用 `try/catch` 吞掉——那等于变相跳过 KAT。

Web 端三段论证已落地于 `packages/crypto-web/src/__tests__/consistency.test.ts`：对照实现以模块顶层静态导入（缺失即整个测试文件加载失败），并用「移走 `node_modules/argon2` → vitest 退出码 1、0 个测试被执行」实测验证过不会被静默跳过。

### 3.3 生产参数下的三端比对

KAT 通过后，再用生产参数做三端字节级比对：

```
password    = "correct horse battery staple"
salt        = <16 字节固定值，base64 常量>
memoryKiB   = 65536
iterations  = 3
parallelism = 4
version     = 0x13
keyLength   = 32
```

验证步骤：

1. **KAT 先行**：每端先通过 §3.2 的 RFC 9106 向量。（Web ✅ / Android ⬜ / iOS ⬜）
2. **三端交叉比对**：三端在生产参数下的输出必须与**同一份共用参考向量**字节级一致。该向量置于 `packages/crypto`（typed 常量，随代码版本化），**不得**各端私存一份——各端各自硬编码期望值同样会漂移，理由与 [architecture.md §4.2](architecture.md#42-packagescrypto)「参数常量只能放在这里」完全相同。（向量已固化 ✅；Web 与之比对通过 ✅ / Android ⬜ / iOS ⬜）
3. **真实文件往返**：用一个真实加密的 `.mfavault` 样本，三端互相解密（A 端加密 → B/C 端解密），全部必须成功。（⬜ 依赖 vault 层，属 M1 验收范围，不在 M0 出口标准内）
   - **Web 端部分的落点是根级 `test/`**，由 QA 编写，使用 `@askdaddy/crypto-web` 的真实 Provider（真实 Argon2id + WebCrypto AES-GCM + `CompressionStream`），而非夹具。理由见 [§4.1](#41-不属于-packagesvault-的测试项)。
   - Android / iOS 部分仍待 M3。
   - 样本文件必须在测试运行时**生成于临时目录**，不得提交进仓库：`.gitignore` 无条件忽略 `*.mfavault`，且 `AGENTS.md` §5.3 禁止提交任何真实 vault 备份。
4. **单位陷阱专项检查**：内存参数在 KiB / MiB / 字节之间的换算是最常见的不一致来源。本项目统一以 **`memoryKiB`** 为准，各端 Provider 负责换算，换算逻辑必须有独立测试。（Web ✅，由 §3.2 的版本环节断言 PHC 串 `m=65536` 覆盖 / Android ⬜ / iOS ⬜）

### 3.3.1 AES-256-GCM 的对照

AEAD 在各端都由平台原生实现提供（WebCrypto / Conscrypt / CryptoKit），三者同为 AES-GCM 标准实现，跨端不一致的风险远低于 Argon2id。真正的风险在**封装层**而非算法层，即 §3.4 列出的 tag 拼接位置与 nonce 长度。因此各端的 AEAD 一致性测试以一个**独立第三方实现**作对照即可，不必等其他端就绪：

| 端         | 被测实现  | 对照实现                                       | 状态      |
| ---------- | --------- | ---------------------------------------------- | --------- |
| Web / 扩展 | WebCrypto | OpenSSL（Node 内置 `crypto` 的 `aes-256-gcm`） | ✅ 已达成 |
| Android    | Conscrypt | 同上（JVM 侧）                                 | ⬜ 待 M3  |
| iOS        | CryptoKit | CommonCrypto                                   | ⬜ 待 M3  |

必须双向验证：被测实现加密 → 对照实现解密认证通过；对照实现加密 → 被测实现解密认证通过。单向通过不足以证明 tag 切分位置一致。

Web 端的双向验证已落地（含带 AAD 与空明文两组），断言点在 tag 从**尾部**切分这一封装约定上。

### 3.4 常见失败模式（测试须覆盖）

| 失败模式                             | 症状                                                     |
| ------------------------------------ | -------------------------------------------------------- |
| 内存单位混淆                         | 派生出的密钥完全不同，vault 无法解密                     |
| 并行度参数被忽略                     | 输出不同                                                 |
| Argon2 版本未显式指定（1.0 vs 1.3）  | 输出不同，且不报错                                       |
| salt 编码差异（hex vs base64）       | 输出不同                                                 |
| 主密码的 UTF-8 编码差异              | 输出不同（本项目用 `@askdaddy/crypto` 的纯 TS 实现规避） |
| GCM tag 拼接位置不同（前置 vs 后置） | 解密失败或 tag 校验失败                                  |
| nonce 长度不一致（12 vs 16 字节）    | 解密失败                                                 |

## 4. Vault 格式测试

下列 6 项是 `packages/vault` 的**必测项**（单元测试用夹具 Provider，见下方说明）：

- **往返测试**：`encrypt(decrypt(x)) === x` 语义等价（注意 nonce 每次不同，需比对解密后的明文而非密文）
- **AAD 校验**：篡改 `format` / `version` / `schemaVersion` 后必须解密失败
- **schema 迁移链**：每一级迁移都有独立的 fixture（旧版本真实文件）与期望输出；禁止只测"最新版 → 最新版"
- **高版本拒绝**：读取 `schemaVersion` 高于当前 App 支持值的文件必须明确拒绝，不得尝试解析
- **未知字段保留**：写入带未知字段的文件 → 读取 → 再写入，未知字段必须原样保留（前向兼容）
- **错误提示不可区分**：主密码错误与文件损坏必须给出**同一条**提示信息，且不泄露尝试次数（防密码探测旁路）

### 4.1 不属于 `packages/vault` 的测试项

| 项                           | 归属             | 理由                                                                                              |
| ---------------------------- | ---------------- | ------------------------------------------------------------------------------------------------- |
| 自动备份滚动                 | **app 端**       | 需要访问应用私有目录并做文件滚动淘汰，零平台依赖的核心包无法实现（`AGENTS.md` §3）                |
| 明文备份的二次确认与风险提示 | **app 端**       | 属 UI 行为；vault 层只负责拒绝解析明文容器（[vault-format.md §1.1](vault-format.md#11-加密容器)） |
| 真实 Provider 端到端往返     | **根级 `test/`** | 见下                                                                                              |

**关于真实 Provider 往返**：`AGENTS.md` §3 规定 `packages/crypto-web` **禁止被任何核心包依赖**，`packages/vault` 是核心包，因此它的单元测试只能用夹具 Provider（基于 Node 内置模块，测试文件豁免平台禁令），**只能证明 vault 遵守 Provider 契约**，不能证明它与真实 Argon2id / WebCrypto / `CompressionStream` 协同正确。这一缺口由 QA 在根级 `test/` 编写的端到端测试补齐——根级 `test/` 不属于任何 package，不受依赖方向白名单约束。

### 4.2 gzip 的跨端一致性是**弱**要求

Argon2id 与 AES-GCM 要求三端**字节级**一致，gzip **不要求**：

- 一致性要求仅为 `decompress(任意合法 gzip(x)) === x`——即任何一端产出的 gzip 流，其他端都能正确还原
- **不要求**压缩输出字节级一致

理由：gzip 头部与输出允许实现差异——压缩级别（`CompressionStream` 不暴露该选项，各端默认值不同）、OS 字节（第 10 字节，`0xFF` unknown / `0x03` Unix / `0x0B` macOS）、`mtime` 字段（通常写 0，但实现可写入实际时间）。这些差异**不影响解压结果**，而密文是"压缩后再加密"的，解密方只要能解压即可。

⚠️ 因此 M3 做三端比对时，**不得**把 gzip 输出纳入 Argon2id 级别的字节比对，否则会误判为一致性缺陷。真正需要字节级一致的只有 KDF 与 AEAD（§3）。

## 5. 导入 golden test

每个第三方格式至少 3 个脱敏样本：

| 样本类型 | 覆盖内容                                                                                                                  |
| -------- | ------------------------------------------------------------------------------------------------------------------------- |
| 正常     | 5–10 个典型条目，TOTP 与 HOTP 混合                                                                                        |
| 边界     | 超长 issuer/account、非 ASCII（中文/日文/emoji）、特殊字符（`:`, `/`, `%`, `+`, 空格）、`digits=8`、`period=60`、`SHA512` |
| 畸形     | 缺失必填字段、类型错误、截断的 JSON、非法 base32、深层嵌套、超大文件                                                      |

测试方式：解析结果与快照文件比对（`toMatchSnapshot`），快照纳入版本控制。样本文件必须**全部使用假 secret**（如 RFC 测试向量或 `JBSWY3DPEHPK3PXP`），并在文件头注释标明为测试夹具。夹具目录为 `packages/transfer/src/__fixtures__/`（`.gitignore` 已为该路径开好备份文件模式的例外）。

### 5.1 字段名的权威来源（ADR-019）

> ⚠️ [transfer.md](transfer.md) 表格中标注的第三方格式字段名基于公开资料与社区逆向，**不可直接作为实现依据**。

按 [ADR-019](decisions.md#adr-019)，字段名的权威来源按下列优先级取用：

| 优先级 | 来源                                                               | 适用格式                                           |
| ------ | ------------------------------------------------------------------ | -------------------------------------------------- |
| 1      | 该 App **开源仓库中的 schema 定义**（序列化/反序列化那段代码本身） | Aegis、2FAS、FreeOTP / FreeOTP+、Ente Auth         |
| 2      | 该 App 的**官方文档**                                              | Bitwarden / 1Password 的 CSV 列结构                |
| 3      | 本项目**自有规范**                                                 | `.mfavault`（加密与明文两种变体）                  |
| 4      | 社区公认的事实标准（`otpauth` Key URI Format）                     | 通用 otpauth URI 文本                              |
| —      | **无权威来源可用** → 不实现专用解析器，走通用 CSV 手动列映射       | LastPass（`transfer.md` 矩阵中置信度标注为「低」） |

每个夹具文件必须在文件头注明其来源（仓库路径 + commit / tag，或文档 URL），并显式标注「依据 schema 定义构造，**非**真实 App 导出」。

真机校准（用真实 App 导出样本回归校验已实现的解析器）由独立 Issue 跟踪，**不阻塞 M2**。这条风险没有被消除，只是后移——ADR-019 的后果一节记录了它无法覆盖的缺陷类型（App 实际写出与其 schema 定义不一致）。

**加密备份路径额外测试**：

- Aegis scrypt 解密（scrypt 的豁免边界见 [ADR-018](decisions.md#adr-018)）
- 2FAS / Raivio 的 PBKDF2 解密
- 密码错误 vs 文件损坏的提示不可区分
- KDF 参数取自备份文件头部，不使用本 App 默认值

**GA 迁移二维码**：

- protobuf 解码正确性（对照公开的 `MigrationPayload` 结构定义）
- **分片重组**：`batch_index` / `batch_size` / `batch_id` 的多批合并，乱序输入、缺批检测、重复批去重
- 导出侧分片生成后，**必须用 Google Authenticator 真机扫描验证**，不能只靠自解析往返测试（protobuf 无官方规范，自解析往返可能双端都错）。按 [ADR-019](decisions.md#adr-019)，该验证降级为后续跟进项；**在完成之前，导出 UI 必须标注「未经 Google Authenticator 真机验证」**

## 6. 域名匹配测试（安全相关）

[chrome-extension.md §4.3](chrome-extension.md#43-匹配规则) 的规则必须有完整用例，尤其：

| 用例                                          | 期望                      |
| --------------------------------------------- | ------------------------- |
| 绑定 `github.com`，访问 `github.com`          | 匹配                      |
| 绑定 `github.com`，访问 `gist.github.com`     | 匹配（子域）              |
| 绑定 `gist.github.com`，访问 `github.com`     | **不**匹配                |
| 绑定 `github.com`，访问 `evil-github.com`     | **不**匹配 ← 关键安全用例 |
| 绑定 `github.com`，访问 `github.com.evil.com` | **不**匹配 ← 关键安全用例 |
| 大小写混合 `GitHub.COM`                       | 匹配                      |
| 带端口 `github.com:8443`                      | 匹配                      |
| `chrome://` / `file://` / `about:` 页面       | 不匹配任何条目            |

`evil-github.com` 与 `github.com.evil.com` 这两条是裸 `endsWith` 实现的典型漏洞，必须有对应测试锁死。

## 7. 模糊测试

对导入解析器（protobuf / JSON / CSV / base32）做模糊测试：

- 工具：`fast-check`（属性测试 + 随机生成）或 `jsfuzz`
- 目标：解析器对任意字节输入**不得抛出未捕获异常、不得进入死循环、不得内存耗尽**
- 输入约束：长度上限、嵌套深度上限必须在解析前生效
- 纳入 CI，每次运行固定种子以保证可复现

## 8. 端到端测试

放 `test/`（QA 黑盒测试脚本目录）。

**移动端**：Maestro（YAML 描述，RN 支持好，无需写测试代码）覆盖：

- 创建 vault → 设置主密码 → 添加条目 → 列表显示当前码与预提示码
- 锁定 → 主密码解锁 / 生物识别解锁
- 搜索、按 tag 筛选、切换排序、拖拽手动排序
- 导出加密 vault → 卸载重装 → 导入恢复 → 条目与 tag 完整
- 时钟校准流程

**扩展**：Playwright（支持加载 MV3 扩展）覆盖：

- 导入 `.mfavault` → 解锁 → popup 显示列表
- 打开绑定域名的标签页 → 相关条目自动置顶并显示「当前网站」标记
- 点击复制 → 剪贴板内容正确
- 关闭浏览器重开 → 需重新输入主密码（验证 DEK 未落盘）
- 空闲超时 → 自动锁定

**跨端一致性 E2E**：移动端导出的 vault 在扩展中导入，条目数、tag、note、sites、排序全部一致。

## 9. 安全审查清单（非自动化）

发布前人工核对：

- [ ] 全仓 grep 确认无 secret / DEK / 主密码 / 验证码出现在日志、`console.*`、错误消息、崩溃上报中
- [ ] `packages/crypto` 之外无任何直接加密原语调用
- [ ] Argon2id 参数未被下调
- [ ] 无 `eval` / `new Function` / 动态 `require`
- [ ] DEK 未写入 `chrome.storage.local` 或任何落盘位置
- [ ] `biometricWrappedDek` 未出现在 vault 文件或导出内容中
- [ ] `.gitignore` 覆盖全部备份文件模式
- [ ] 仓库中无真实 vault / 真实 secret / 真实二维码
- [ ] 剪贴板自动清理生效
- [ ] 明文导出有二次确认与风险警告
- [ ] 崩溃上报（若接入）已做敏感字段过滤
- [ ] 依赖许可证审计通过
- [ ] 无未申报的网络请求（扩展尤其重要，商店会审查）
