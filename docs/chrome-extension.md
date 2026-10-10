# Chrome 扩展设计

> 关联决策：[ADR-005 插件范围](decisions.md#adr-005)、[ADR-002 纯本地](decisions.md#adr-002)
> 状态：设计基线，尚未实现（M4）

## 1. 范围界定

按用户决策，扩展做 **显示 + 域名绑定自动置顶**，**不做**自动填充。

**做**：

- popup 列表显示当前码 + 预提示码（与移动端一致的形态）
- 搜索、按 tag 筛选
- 点击复制验证码到剪贴板
- 读取当前标签页域名，自动把绑定该域名的条目置顶
- 导入 / 导出 `.mfavault` 文件
- 条目基础编辑（issuer / account / tags / note / sites 绑定）
- 主密码解锁，浏览器会话内保持解锁态

**不做**（V1）：

- content script 自动填充到网页输入框
- 与移动端实时同步
- 扫码添加（浏览器摄像头体验差，且移动端已覆盖）

不做自动填充是刻意的收敛：自动填充需要处理各站点千差万别的 DOM 结构、要申请更宽的权限、安全审查面显著变大，而收益（省一次粘贴）相对有限。若未来要做，见 §7。

## 2. MV3 架构

```
apps/extension/
  src/
    entrypoints/
      background.ts      # service worker：解锁态管理、定时清理
      offscreen.html      # 剪贴板清理所需的隐藏文档；仅处理剪贴板消息
      popup/             # React，主界面
      options/           # React，导入导出与设置
    lib/                 # 仅 Web 侧适配：Provider 注入、storage 封装
```

脚手架用 **WXT**（Vite 底座，MV3 原生支持，HMR 体验好）。

| 组件                          | 职责                                                                                  |
| ----------------------------- | ------------------------------------------------------------------------------------- |
| **background service worker** | 持有解锁态、响应 popup 的加解密请求、`chrome.alarms` 空闲锁定、导入导出时的重计算任务 |
| **popup**                     | 列表 UI、搜索、复制、倒计时刷新。生命周期短，打开即渲染、关闭即销毁                   |
| **options page**              | 导入导出、主密码修改、设置、条目管理（popup 空间太小，重操作放这里）                  |
| **offscreen document**        | 接收定时清理请求，仅在剪贴板仍为本次复制的验证码时清空；可行性须经真实 Chrome 验证    |

**为什么把加解密放 background**：Argon2id 派生在 WASM 下耗时可达数百毫秒至 1 秒，放 popup 会阻塞渲染且 popup 随时可能被销毁。放 SW 中执行，popup 通过 `chrome.runtime.sendMessage` 请求，SW 保持 DEK 与派生结果。

## 3. 权限最小化

```jsonc
{
  "manifest_version": 3,
  "permissions": ["storage", "activeTab", "clipboardWrite", "clipboardRead", "alarms", "offscreen"],
  "host_permissions": [], // 刻意留空
}
```

| 权限               | 用途                                              | 是否必需                                     |
| ------------------ | ------------------------------------------------- | -------------------------------------------- |
| `storage`          | `local` 存加密 vault blob，`session` 存解锁态 DEK | ✅                                           |
| `activeTab`        | popup 打开时读取当前标签页 URL 做域名匹配         | ✅                                           |
| `clipboardWrite`   | 点击复制验证码                                    | ✅                                           |
| `clipboardRead`    | 到期前比对剪贴板，避免清除用户后来复制的内容      | ✅；会显示读取剪贴板数据的安装警示           |
| `alarms`           | 空闲自动锁定                                      | 可选（不用则退化为 SW 内计时，会被回收打断） |
| `offscreen`        | popup 关闭后创建隐藏文档处理剪贴板                | ✅；不承载 vault 或 OTP 逻辑                 |
| `host_permissions` | —                                                 | ❌ **不申请**                                |

**关键设计**：用 `activeTab` 而不是 `<all_urls>` 读取当前页域名。`activeTab` 只在用户主动点击扩展图标时授予当前标签页的一次性访问权，正好匹配我们的场景（用户点开 popup 时才需要知道当前站点）。这样既不申请宽权限，也能通过 Chrome Web Store 的权限审查——**权限申请越少，商店审核越快，用户安装转化率越高**。

**不注入 content script**。V1 完全不碰页面 DOM，这既降低安全风险，也避免与页面脚本冲突。

点击复制后默认在 45 秒后尝试清理，可在设置中关闭。alarm 到期时由 background 请求 offscreen 文档读取当前剪贴板；仅当文本仍等于本次复制的验证码时才清空。读取失败时不得盲清，也不得改写用户后来复制的内容。offscreen 文档只为这次剪贴板操作短时存在，不持有 vault、DEK 或主密码。MV3 service worker 没有 DOM，且非聚焦的 offscreen 文档可能无法使用 `navigator.clipboard.readText()`；开发须先用假验证码在真实 Chrome 验证读取、比对与清理路径，再把该路径用于正式功能。若实机验证失败，回到 Issue #6 的计划阶段修订方案，不降低本节的安全保证。

## 4. 域名绑定与自动置顶

### 4.1 数据

条目的 `sites: string[]` 字段存绑定的域名（不带协议、不带路径），如 `["github.com", "gist.github.com"]`。

### 4.2 匹配流程

```
popup 打开
  → chrome.tabs.query({active: true, currentWindow: true})
  → 解析 hostname
  → 与所有 entry.sites 比对
  → 命中的条目置顶，并显示「当前网站」标记
  → 未命中则按 defaultSort 正常排序
```

### 4.3 匹配规则

| 规则       | 说明                                                                           |
| ---------- | ------------------------------------------------------------------------------ |
| 精确匹配   | `github.com` 匹配 `github.com`                                                 |
| 子域匹配   | 绑定 `github.com` 时，`gist.github.com` **也匹配**（默认开启，可在设置中关闭） |
| 反向不匹配 | 绑定 `gist.github.com` 时，`github.com` **不匹配**                             |
| 大小写     | 域名统一小写后比对                                                             |
| 端口       | 忽略                                                                           |
| 协议       | 只接受 `https:` 与 `http:`，其他协议（`chrome:`、`about:`、`file:`）一律不匹配 |

子域匹配需防**后缀伪造**：判断 `hostname === site || hostname.endsWith("." + site)`，不能用裸 `endsWith(site)`，否则 `evil-github.com` 会错误匹配 `github.com`。这是一个真实的安全陷阱，必须有对应测试用例。

### 4.4 绑定 UI

在条目详情页提供域名输入框 + 从当前标签页一键绑定按钮（借助 `activeTab` 读取）。支持多个域名，可逐条删除。

## 5. 解锁态与生命周期

MV3 的 service worker 在空闲约 30 秒后被回收，这是扩展设计中最容易踩坑的地方。

| 数据                | 存储位置                 | 生命周期                                               |
| ------------------- | ------------------------ | ------------------------------------------------------ |
| 加密 vault blob     | `chrome.storage.local`   | 持久（落盘）                                           |
| 解锁后的 DEK        | `chrome.storage.session` | 浏览器会话内，**不落盘**                               |
| Argon2id 派生中间态 | SW 内存                  | SW 存活期间，回收即失效（可从 DEK 恢复，无需重新派生） |
| 主密码              | **不存储**               | 仅在派生 DEK 的瞬间存在于内存                          |

**流程**：

```
popup 打开 → 读 storage.session 的 DEK
  ├─ 命中 → 直接用 DEK 解密 vault，渲染列表（无需用户操作）
  └─ 未命中 → 显示主密码输入框 → Argon2id 派生 KEK → 解开 wrappedMasterKey → 写入 storage.session
```

**注意事项**：

- `chrome.storage.session` 默认访问级别为 `TRUSTED_CONTEXTS`（扩展页面可访问，content script 不可）。**不得**改成 `ALL_CONTEXTS`。
- **禁止**把 DEK 或主密码写入 `storage.local`（会落盘，等于绕过全部加密保护）。
- 浏览器重启后 DEK 失效，需重新输入主密码——这是符合预期的行为，不是 bug。
- 空闲锁定：`chrome.alarms` 定期检查 `lastInteractionAt`，超过 `autoLockSeconds` 则清除 `storage.session` 中的 DEK。不能依赖 `setTimeout`，SW 被回收后定时器不会执行。

## 6. 数据如何进入扩展

### 6.1 V1：文件导入

options page 中用 `<input type="file">` 选择 `.mfavault` 文件 → 输入该文件的主密码 → 解密 → 用**扩展自己的新主密码**重新加密 → 存入 `storage.local`。

两个密码必须清楚区分（来源 vault 的密码 vs 扩展要设置的新密码），UI 上分两步走，不要放在同一屏。

### 6.2 V2：局域网配对

手机 App 起临时 HTTP 服务，扩展通过二维码获取 `IP:port + 公钥 + 配对码`，ECDH 协商后传输加密 vault blob。详见 [security.md §6](security.md#6-迁移通道安全局域网配对)。

**约束**：浏览器无法做 mDNS 服务发现，必须靠二维码或手输 IP。且扩展发起 `fetch` 到局域网地址会遇到**混合内容限制**——从 `chrome-extension://` 页面请求 `http://192.168.x.x` 需要在 manifest 中申请对应的 `host_permissions`，这会与 §3 的"零 host_permissions"设计冲突。

**因此 V2 需要重新评估权限模型**，可选路径：

1. 仅在配对时申请 `http://192.168.0.0/16` 等私有网段权限（可选权限 `optional_host_permissions`，用户按需授予）
2. 改用移动端展示二维码 + 扩展摄像头扫描（扩展页可用 `getUserMedia`，无需网络权限），但二维码容量有限，大 vault 需分片
3. 配对走 `localhost`：移动端无法在 PC 上监听 localhost，不可行

**推荐路径 1**（`optional_host_permissions`），既不污染默认安装权限，又能实现自动配对。此项在 M5 前需做原型验证，因为 Chrome 对私有网段请求还有 PNA（Private Network Access）策略限制，可能触发预检失败。

## 7. 若未来要做自动填充

不在 V1 范围，但架构上应保留可能性。届时需要：

- 新增 content script（`matches: ["<all_urls>"]`）——权限模型大幅收紧，商店审查难度上升
- TOTP 输入框识别启发式（`autocomplete="one-time-code"`、`inputmode="numeric"`、`maxlength=6/8`、name/id 含 `otp|totp|code|2fa`）
- 填充动作需用户显式触发（点击页面上的悬浮按钮），**不做自动填充**，避免在错误时机写入错误码
- 安全考量：content script 能接触 DEK 就等于全站密钥暴露，因此填充值必须由 background 计算后单条传递，content script 永不持有 DEK

## 8. 与移动端的 UI 复用

popup 的列表组件（条目行、预提示、倒计时环、搜索框）与移动端形态一致，但**不共享组件代码**：RN 与 Web 的组件层无法直接复用。

可复用的是：

- `packages/domain` 的排序、搜索、域名匹配逻辑（纯 TS）
- `packages/vault`、`packages/otp`、`packages/transfer`（纯 TS）
- 设计 token（色板、间距、字号）可以抽成常量包共享

不强求 UI 组件跨端复用。React Native Web 理论上可行，但会同时拖累两端的体验质量，不值得。
