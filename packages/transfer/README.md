# @askdaddy/transfer

GA 迁移格式由 `parseGaMigration(input)` 解析单片，由 `parseGaMigrationBatch(inputs)` 合并同一批次的 URI。输入可为字符串或 UTF-8 字节，输出沿用 `ImportResult`，secret 是独立的原始字节。调用方使用后应逐条 `entry.secret.fill(0)`；解析器不会修改或清零调用方输入。

多片按 `batchIndex` 排序；重复索引仅在 payload 字节相同的情况下去重。混合批次和内容冲突抛 `TransferFormatError`。缺片返回 `complete: false` 和 `missingIndices`，调用方必须展示缺片摘要后再决定是否继续。`sourceIndex` 是收到的唯一分片中记录的连续编号，包含失败记录；缺片不虚构记录数。

`generateGaMigration(vault, { batchId, entriesPerBatch })` 返回 `{ uris, verification, warning }`。`batchId` 由调用方随机源生成 signed int32；默认每片 10 条，可配置 1..10000，最多 1000 片。条数与 URI 长度不等同于二维码容量，实际可扫描阈值等待 #11 校准。空 vault 返回空 URI 数组。

支持版本 1、TOTP/HOTP、SHA1/SHA256/SHA512、6/8 位。GA 没有 period 字段：TOTP 导入明确警告并恢复为 30 秒，非 30 秒 TOTP 与 7 位验证码导出直接拒绝。未知/零枚举不猜默认值；MD5 按既有兼容规则映射 SHA1 并警告。HOTP counter 是非负安全整数，省略时按 proto3 的 0 值并警告。账户名与发行方独立保留，不猜测冒号前缀。`EXPORT_DEGRADATIONS['ga-migration']` 列出非 OTP 字段丢失项。

URI ≤65536 字符、总输入 ≤16MiB、总记录（含失败）≤10000；输入分片数≤10000。批次元数据在解析条目前校验，不按声明长度预分配。仅解析固定两层消息，跳过未知 varint/fixed64/length-delimited/fixed32，拒绝 groups 和损坏的 wire；完整边界内的条目错误可部分成功导入。报错不包含输入或密钥值。

依据 Aegis 固定 schema 和独立 wire 字节测试实现，**未经 Google Authenticator 真机扫描验证**。导出结果始终包含 `verification: 'unverified'` 和同一风险文案，扩展 #6 必须展示并实施明文导出的二次确认。真机校准由 #11 跟踪；自解析往返和跨实现字节对照不能代替设备验证。导出 URI 含明文密钥，仅用于受控迁移，不写日志或附到 Issue。
