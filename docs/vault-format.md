# Vault 文件格式与数据模型

> 状态：设计基线 v1，尚未实现。本文件是跨端与跨版本的**兼容契约**，变更需走 ADR 并递增版本号。

## 1. 容器格式

JSON 文本文件，UTF-8 编码，扩展名 `.mfavault`。同时提供未加密备份变体。

### 1.1 加密容器

```json
{
  "format": "mfavault",
  "version": 1,
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

**读取流程**：

1. 校验 `format === "mfavault"`，否则拒绝并提示"不是本 App 的密钥库文件"
2. 按 `crypto.kdf` 中的**文件头参数**（而非硬编码值）派生 KEK
3. 用 KEK 解开 `wrappedMasterKey` 得到 DEK
4. 用 DEK 解密 `data`，解压 gzip，得到明文 JSON
5. 校验 `schemaVersion`，必要时执行迁移链

**写入流程**：每次写入都生成**全新的** `cipher.nonce`；DEK 与 salt 保持不变（除非用户改主密码，此时 salt 也重新生成）。

**AAD**：`data` 加密时将 `format`、`version`、`schemaVersion` 拼接作为 GCM 的 AAD，防止头部被篡改后仍能解密。

### 1.2 未加密容器

```json
{
  "format": "mfavault",
  "version": 1,
  "encrypted": false,
  "data": { "...明文 schema..." }
}
```

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
- 读取比当前 App 支持的更高 `schemaVersion` 的文件时，**拒绝打开并提示升级 App**，绝不尝试降级或猜测字段含义
- 每次 schema 变更必须同时：递增版本号、编写迁移函数、补迁移测试、更新本文件

## 5. 完整性与容错

| 场景             | 处理                                                         |
| ---------------- | ------------------------------------------------------------ |
| GCM tag 校验失败 | 报"文件已损坏或密码错误"，不区分具体原因（避免密码探测旁路） |
| gzip 解压失败    | 报文件损坏，提示从备份恢复                                   |
| schema 校验失败  | 报具体字段路径，不静默丢弃数据                               |
| 未知字段         | **保留但不使用**，写回时原样带回（前向兼容）                 |
| 主密码错误       | 与文件损坏给出同一提示，且不泄露尝试次数                     |

**未知字段保留**是一条重要的前向兼容规则：新版本 App 写入的字段被旧版本读取时不应丢失，否则用户降级 App 会损坏数据。

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
