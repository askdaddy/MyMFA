# Vault 文件格式与数据模型

> 状态：设计基线 v1，尚未实现。本文件是跨端与跨版本的**兼容契约**，变更需走 ADR 并递增版本号。

## 1. 容器格式

JSON 文本文件，UTF-8 编码，扩展名 `.mfavault`。同时提供未加密备份变体。

### 1.1 加密容器

```json
{
  "format": "mfavault",
  "version": 1,
  "schemaVersion": 1,
  "encrypted": true,
  "crypto": {
    "kdf": {
      "name": "argon2id",
      "memoryKiB": 65536,
      "iterations": 3,
      "parallelism": 4,
      "salt": "<base64, 16 字节>",
      "keyLength": 32
    },
    "cipher": {
      "name": "aes-256-gcm",
      "nonce": "<base64, 12 字节>",
      "tag": "<base64, 16 字节>"
    },
    "wrappedMasterKey": {
      "nonce": "<base64, 12 字节>",
      "tag": "<base64, 16 字节>",
      "data": "<base64, DEK 的 KEK 包裹密文>"
    }
  },
  "data": "<base64, gzip(明文 JSON) 的 AES-256-GCM 密文>"
}
```

**头部的 `schemaVersion` 与明文里的 `schemaVersion` 同时存在，职责不同**：

- **头部**（明文可见）用于**解密前**的决策——高版本拒绝、构造 AAD。没有它，读取端无法在解密前重建写入端用过的 AAD，也无法在不浪费一次 Argon2id 派生的前提下拒绝未来版本的文件。
- **明文内**（§2）用于**解密后**的迁移链入口。
- 两者都受 GCM 认证保护。解密后必须校验**头部值 === 明文值**，不等即拒绝（纵深防御，防止两处分头演化）。

**读取流程**（顺序是契约的一部分，前四步失败时**不得**调用 KDF 或 AEAD）：

1. 容器必须是合法 JSON 且顶层为对象（不是数组、不是 `null`），否则报"文件已损坏"
2. 校验 `format === "mfavault"`，否则拒绝并提示"不是本 App 的密钥库文件"
3. 校验 `encrypted === true`。明文容器不由 vault 层解析（其封装与解封属 `packages/transfer`），遇到时明确拒绝，**不得**静默当作明文读取——否则 `AGENTS.md` §5.4 要求的明文导出风险提示会被绕过
4. 校验版本：`version` 与 `schemaVersion` 任一**高于**当前支持值即拒绝打开并提示升级 App，且**不尝试解密**（§4）
5. 校验文件头的加密参数未被降级：`kdf.memoryKiB` / `iterations` / `parallelism` 不低于基线，`kdf.salt` 不短于 16 字节，`kdf.keyLength === 32`，两处 `nonce` 均为 12 字节、两处 `tag` 均为 16 字节；`kdf.name` 与 `cipher.name` 必须与运行时注入的 Provider 一致
6. 按 `crypto.kdf` 中的**文件头参数**（而非硬编码值）派生 KEK
7. 用 KEK 解开 `wrappedMasterKey` 得到 DEK
8. 用 DEK 解密 `data`（带 §1.1.1 的 AAD），解压 gzip，得到明文 JSON
9. 校验头部与明文的 `schemaVersion` 相等，必要时执行迁移链

**写入流程**：每次写入都生成**全新的** `cipher.nonce`——明文每次都可能不同，GCM 下 nonce 复用是灾难。`wrappedMasterKey` 与 `kdf.salt` 在同一个已解锁句柄内**保持不变**，只在改主密码时整体重新生成（此时 salt 也换）。理由：句柄生命周期内 DEK 恒定，用同一个 KEK 重新包裹同一个 DEK 只是换个 nonce，没有安全收益，却要求 KEK 常驻内存；「KEK 用完即清零」比「包裹密文每次不同」重要得多（见 [security.md §2.2](security.md#22-明文清零的能力边界不要过度承诺)）。头部的 `schemaVersion` 恒等于明文里的值。

> lazy-ladder: 同一句柄并发调用 `serialize()` 不加锁。当前三个 app 端都是单用户单线程交互，不存在并发写入场景；若将来引入后台自动保存，需改为写入队列或句柄级互斥。

### 1.1.1 AAD 的字节布局

`data` 加密时携带 AAD，防止头部字段被篡改后仍能解密。**布局是契约的一部分，不得改回裸拼接**：

```
aad = utf8Encode(`${format}\n${version}\n${schemaVersion}`)
```

- 分隔符固定为 `\n`（0x0A）
- `version` 与 `schemaVersion` 以**十进制字符串**参与，不含前导零
- 三个值**全部取自容器头部**（明文可见），因此读取端在解密前就能重建出与写入端逐字节相同的 AAD
- 当前值下 `aad` 的实际字节内容为 `"mfavault\n1\n1"`，共 12 字节

**为什么必须带分隔符**：裸拼接会让 `version=1, schemaVersion=11` 与 `version=11, schemaVersion=1` 产生**同一个** AAD（都是 `mfavault111`），头部篡改保护形同虚设。

`wrappedMasterKey` **不带 AAD**。理由：它的密钥是 KEK，而 KEK 由 `crypto.kdf` 的全部参数派生——篡改 `crypto.kdf` 中任何字段都会导致派生出不同的 KEK，解包必然认证失败，该字段已经自保护。

### 1.2 未加密容器

```json
{
  "format": "mfavault",
  "version": 1,
  "schemaVersion": 1,
  "encrypted": false,
  "data": { "...明文 schema..." }
}
```

头部同样携带 `schemaVersion`（与加密容器对称），`data` 为明文对象而非 base64 字符串。本变体由 `packages/transfer` 负责封装与解封，`packages/vault` 只处理加密容器。

明文备份导出时必须：显著风险提示 + 二次确认 + 不默认选中（见 `AGENTS.md` §5.4）。

## 2. 明文 Schema

```json
{
  "schemaVersion": 1,
  "meta": {
    "createdAt": 1737000000000,
    "updatedAt": 1737000000000,
    "appVersion": "1.0.0"
  },
  "entries": [/* Entry[] */],
  "tags": [/* Tag[] */],
  "settings": {/* Settings */}
}
```

时间戳统一为 Unix 毫秒（number）。

`schemaVersion` 必须与容器头部的同名字段**相等**（§1.1）；本字段是迁移链的入口，头部字段是解密前的决策依据。

### 2.1 Entry

| 字段         | 类型                                 | 必填 | 说明                                            |
| ------------ | ------------------------------------ | ---- | ----------------------------------------------- |
| `id`         | string                               | ✅   | UUID v7，全局唯一，导入时冲突则重新生成         |
| `kind`       | `"totp"` \| `"hotp"`                 | ✅   | 令牌类型                                        |
| `issuer`     | string                               | ✅   | 服务商名，如 `GitHub`                           |
| `account`    | string                               | ✅   | 账户名，如 `alice@example.com`                  |
| `secret`     | string                               | ✅   | base64 编码的**原始字节**（不是 base32 字符串） |
| `algo`       | `"SHA1"` \| `"SHA256"` \| `"SHA512"` | ✅   | 默认 `SHA1`                                     |
| `digits`     | 6 \| 7 \| 8                          | ✅   | 默认 6                                          |
| `period`     | number                               | TOTP | 秒，默认 30                                     |
| `counter`    | number                               | HOTP | 初始 0                                          |
| `tagIds`     | string[]                             | ✅   | 引用 `Tag.id`，默认 `[]`                        |
| `note`       | string                               | ✅   | 自由文本备注，默认 `""`                         |
| `sites`      | string[]                             | ✅   | 绑定的域名，供扩展自动置顶，默认 `[]`           |
| `usageCount` | number                               | ✅   | 使用次数，默认 0                                |
| `lastUsedAt` | number \| null                       | ✅   | 最近使用时间戳，默认 `null`                     |
| `position`   | string                               | ✅   | fractional index，手动排序用                    |
| `favorite`   | boolean                              | ✅   | 是否置顶收藏，默认 `false`                      |
| `createdAt`  | number                               | ✅   |                                                 |
| `updatedAt`  | number                               | ✅   |                                                 |

**关于 `secret` 存原始字节而非 base32**：base32 是传输编码，不是密钥本体。存原始字节避免各端 base32 解码实现差异（padding、大小写、混淆字符处理）导致同一个 secret 在不同设备上算出不同验证码。base32 只在导入解析和用户手动输入时出现。

### 2.2 Tag

| 字段       | 类型   | 说明                                     |
| ---------- | ------ | ---------------------------------------- |
| `id`       | string | UUID v7                                  |
| `name`     | string | 标签名，vault 内唯一（大小写不敏感去重） |
| `color`    | string | 十六进制色值，如 `#5B8DEF`               |
| `position` | string | fractional index，控制标签栏顺序         |

Tag 是**全局实体**而非 Entry 上的字符串数组。这样重命名或删除标签只需改一处，不必遍历全部条目——Aegis 的 tag 是字符串形式，重命名需要批量改写，我们要避免这个设计。

### 2.3 Settings

| 字段                    | 类型    | 默认       | 说明                                      |
| ----------------------- | ------- | ---------- | ----------------------------------------- |
| `defaultSort`           | string  | `"manual"` | 见 [features.md 排序](features.md#3-排序) |
| `previewNextCode`       | boolean | `true`     | 预提示开关                                |
| `autoLockSeconds`       | number  | `60`       | 空闲自动锁定，0 表示不锁定                |
| `clockOffsetSeconds`    | number  | `0`        | 时钟校准偏移量                            |
| `clipboardClearSeconds` | number  | `45`       | 剪贴板自动清理，0 表示不清理              |
| `searchPinyin`          | boolean | `true`     | 拼音首字母匹配                            |
| `requireBiometric`      | boolean | `false`    | 是否优先走生物识别解锁                    |

`settings` 随 vault 一起加密，因此跨设备迁移时用户偏好一并带走。

## 3. Fractional Indexing（手动排序）

手动排序不重排整张表，用可插值的位置键：

- 位置键为字符串，字典序即显示顺序（如 `"a0"`、`"a1"`、`"a0V"`）
- 在 A 与 B 之间插入 → 生成介于两者字典序之间的新键，无需改动其他条目
- 键长度退化到阈值时（如 > 20 字符）触发一次该列表的整体重排
- 新增条目默认追加到末尾

**为什么不用数组下标或整数 position**：数组下标在插入时需要重写后续全部条目，产生巨大的 vault 差异与不必要的重加密；整数 position 会耗尽间隙。fractional index 让单次拖动只改一个条目。

## 4. Schema 版本迁移

- `schemaVersion` 独立于容器 `version`：前者描述明文结构，后者描述容器封装
- 迁移链为**逐级纯函数**：`migrate_1_to_2(vault)`、`migrate_2_to_3(vault)`……禁止跨版本跳跃迁移
- 迁移后必须通过 schema 校验才允许写回
- `version` 与 `schemaVersion` **任一**高于当前 App 支持值时拒绝打开并提示升级 App，绝不尝试降级或猜测字段含义。两者都在容器头部明文可见，因此拒绝发生在**解密之前**——连 KEK 都不派生。高版本可能使用了本版本不认识的封装或字段含义，解密尝试本身没有意义，且会白白消耗一次 Argon2id 派生（低端设备上 1–2 秒）
- 每次 schema 变更必须同时：递增版本号、编写迁移函数、补迁移测试、更新本文件、更新容器头部的 `schemaVersion`

## 5. 完整性与容错

错误提示分成**三类**，归类本身就是安全属性：

### 5.1 归并为同一条提示的失败源（防密码探测旁路）

下列 5 类失败**必须**给出完全相同的错误类型与完全相同的 message，用户与攻击者都无法从中区分"密码错了"与"文件坏了"：

| 失败源                          | 为什么必须归并                                                   |
| ------------------------------- | ---------------------------------------------------------------- |
| `wrappedMasterKey` 解包失败     | 直接对应主密码错误                                               |
| `data` 解密失败（GCM tag 不符） | 密钥错误或密文被篡改，两者在密码学上不可区分                     |
| `data` 的 base64 非法           | 若单独提示"编码错误"，就等于告诉攻击者密码是对的                 |
| gzip 解压失败（含魔数不对）     | 同上。**禁止**单独提示"压缩格式错误"——能走到解压说明密码已经对了 |
| 解压后 JSON 解析失败            | 同上                                                             |

统一提示：`密钥库文件已损坏，或主密码不正确`。

**不携带任何尝试次数信息**，vault 层也**不存在**任何计数器字段、模块级可变变量或解锁历史记录——计数属于 app 端的 UI 策略，落到数据层就变成了可被绕过的状态。

### 5.2 独立提示的失败源

| 场景                                  | 处理                                                                                                                    |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `format` 不是 `"mfavault"`            | **独立**提示"不是本 App 的密钥库文件"。这是文件格式识别，与密码无关，归并反而会让用户误以为密码错了                     |
| 容器 JSON 非法 / 顶层非对象           | 报文件损坏（读不到 `format`，无法做格式识别）                                                                           |
| 容器 `version` / `schemaVersion` 过高 | 提示升级 App，不尝试解密（§4）                                                                                          |
| 加密参数被降级                        | 指明是哪个参数低于基线，拒绝打开（§1.1 读取流程第 5 步）                                                                |
| schema 校验失败                       | 报**具体字段路径**（如 `entries[3].secret`），不静默丢弃数据。错误消息**绝不回显** `secret` 的值、其 base64 或 hex 形式 |

schema 校验失败发生在成功解密**之后**，此时"密码对不对"已经不再是秘密，因此可以给出精确的字段级诊断。

### 5.3 未知字段

**保留但不使用**，写回时原样带回（前向兼容）。这是一条重要的规则：新版本 App 写入的字段被旧版本读取时不应丢失，否则用户降级 App 会损坏数据。实现上要求校验函数**只判定不重建**——在入参对象上校验并原样返回，而不是逐字段拷贝出一个新对象（后者会静默剥掉未知键）。

## 6. 自动备份

- 每次成功修改 vault 后，在应用私有目录保留最近 N 份（默认 5）自动备份副本，加密态
- 备份文件命名含时间戳，滚动淘汰
- 提供"从自动备份恢复"入口
- 自动备份**只保留加密态**，绝不生成明文副本

## 7. 待确认项

| 项                          | 说明                                                                                |
| --------------------------- | ----------------------------------------------------------------------------------- |
| `usageCount` 是否随导出携带 | 跨设备迁移时统计口径不一致（手机点了 50 次，插件从 0 开始）。建议导出时可选是否包含 |
| `note` 是否支持 Markdown    | 当前设计为纯文本。若要支持富文本需考虑渲染安全（禁止 HTML）                         |
| 条目软删除 / 回收站         | 当前设计为直接删除 + 自动备份兜底。是否需要回收站待定                               |
