/**
 * QA 黑盒验收脚本 —— Issue #3（packages/vault），design D7 指定的落点。
 *
 * 为什么必须是根级 `test/`：`AGENTS.md` §3 规定 `packages/crypto-web` 禁止被任何核心包依赖，
 * 所以 `packages/vault` 的单测只能用 Node 内置夹具 Provider，无法证明「vault 与真实
 * Argon2id / WebCrypto / CompressionStream 协同正确」。本脚本补上这一层，且**只跑构建产物
 * `dist/`**（不是源码），验证的是将要发布的那份字节。
 *
 * 运行：`pnpm build && node test/vault-web-e2e.mjs`
 * 退出码 0 = 全部 PASS。
 *
 * 覆盖：docs/testing.md §3.3 步骤 3「真实文件往返」的 Web 端部分、
 * docs/roadmap.md M1 出口标准「vault 往返测试全绿」、§4 的 AAD 校验 / 高版本拒绝 /
 * 错误提示不可区分，以及 C5「任何一端能解开其他端产出的 gzip 流」。
 */

import assert from 'node:assert/strict'
import { gunzipSync } from 'node:zlib'

import {
  AES_256_GCM,
  ARGON2ID_PARAMS,
  base64Decode,
  base64Encode,
  utf8Decode,
  utf8Encode,
} from '../packages/crypto/dist/index.js'
import {
  webAeadProvider,
  webCompressProvider,
  webKdfProvider,
  webRandomProvider,
} from '../packages/crypto-web/dist/index.js'
import {
  CONTAINER_FORMAT,
  CONTAINER_VERSION,
  createVault,
  DEFAULT_SETTINGS,
  openVault,
  SCHEMA_VERSION,
  VaultAuthError,
  VaultFormatError,
  VaultLockedError,
  VaultVersionError,
  uuidV7,
} from '../packages/vault/dist/index.js'

const PASSWORD = 'correct horse battery staple'
const NEXT_PASSWORD = 'Tr0ub4dor&3-新主密码'
const WRONG_PASSWORD = 'not-the-master-password'
const AUTH_MESSAGE = '密钥库文件已损坏，或主密码不正确'
const APP_VERSION = '1.0.0-qa'

const providers = {
  kdf: webKdfProvider,
  aead: webAeadProvider,
  random: webRandomProvider,
  compress: webCompressProvider,
}

// ── 极简 runner ──────────────────────────────────────────────────────────────

const cases = []
const test = (name, fn) => cases.push({ name, fn })

// ── 工具 ─────────────────────────────────────────────────────────────────────

const decodeContainer = (bytes) => JSON.parse(utf8Decode(bytes))

const HEX = '0123456789abcdef'

function toHex(bytes) {
  let out = ''
  for (const byte of bytes) out += HEX[byte >> 4] + HEX[byte & 0x0f]
  return out
}

/** 子串搜索。`Uint8Array.prototype.includes` 只比单个字节值，不能用来找字节序列。 */
function containsBytes(haystack, needle) {
  if (needle.length === 0 || needle.length > haystack.length) return false
  outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer
    }
    return true
  }
  return false
}

function patchContainer(bytes, patch) {
  const container = decodeContainer(bytes)
  patch(container)
  return utf8Encode(JSON.stringify(container))
}

function tamperData(bytes) {
  return patchContainer(bytes, (container) => {
    const raw = base64Decode(container.data)
    raw[0] ^= 0xff
    container.data = base64Encode(raw)
  })
}

async function captureError(promise) {
  try {
    await promise
  } catch (error) {
    return error
  }
  throw new assert.AssertionError({ message: '期望抛错，实际正常返回' })
}

/** 假 secret（AGENTS.md §5.3）：文档里公开示例用的那一串，不是任何真实种子。 */
const FAKE_SECRET_BASE64 = base64Encode(utf8Encode('JBSWY3DPEHPK3PXP'))

function makeEntry(overrides = {}) {
  const now = 1_737_000_000_000
  const entry = {
    id: uuidV7(webRandomProvider, now),
    kind: 'totp',
    issuer: 'GitHub',
    account: 'alice@example.com',
    secret: FAKE_SECRET_BASE64,
    algo: 'SHA1',
    digits: 6,
    period: 30,
    tagIds: [],
    note: '',
    sites: ['github.com'],
    usageCount: 0,
    lastUsedAt: null,
    position: 'a0',
    favorite: false,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  }
  // HOTP 条目不该带 period 键：显式的 `period: undefined` 会被 JSON 往返自然丢掉，
  // 留着只会让「写入前的对象」与「读回的对象」在 deepStrictEqual 下假性不等。
  if (entry.kind === 'hotp') delete entry.period
  else delete entry.counter
  return entry
}

/** 记录型包装：只为观测 Provider 调用轨迹与明文快照，密码学行为完全委托给真实 Provider。 */
function recording(base = providers) {
  const calls = []
  const snapshot = (bytes) => Uint8Array.from(bytes)
  return {
    calls,
    providers: {
      kdf: {
        name: base.kdf.name,
        async deriveKey(password, salt, params) {
          calls.push('kdf.deriveKey')
          return base.kdf.deriveKey(password, salt, params)
        },
      },
      aead: {
        name: base.aead.name,
        async encrypt(key, plaintext, aad) {
          calls.push('aead.encrypt')
          if (aad === undefined) {
            // D1：包裹 DEK 不带 AAD，payload 加密必带 AAD——据此区分两类明文快照。
            calls.push('aead.encrypt:wrap')
          } else {
            calls.push(`aad:${utf8Decode(aad)}`)
            calls.push({ role: 'payload', bytes: snapshot(plaintext) })
          }
          return base.aead.encrypt(key, plaintext, aad)
        },
        async decrypt(key, sealed, aad) {
          calls.push('aead.decrypt')
          if (aad !== undefined) calls.push(`aad:${utf8Decode(aad)}`)
          return base.aead.decrypt(key, sealed, aad)
        },
      },
      random: {
        randomBytes: (length) => {
          calls.push('random.randomBytes')
          return base.random.randomBytes(length)
        },
      },
      compress: {
        name: base.compress.name,
        async compress(bytes) {
          calls.push('compress.compress')
          return base.compress.compress(bytes)
        },
        async decompress(bytes) {
          calls.push('compress.decompress')
          return base.compress.decompress(bytes)
        },
      },
    },
  }
}

const countCalls = (calls, name) => calls.filter((call) => call === name).length

// ── 共享样本（真实 Argon2id 派生昂贵，全流程只建一次库） ─────────────────────

const sample = await (async () => {
  const handle = await createVault(PASSWORD, providers, {
    appVersion: APP_VERSION,
    now: () => 1_737_000_000_000,
  })
  handle.data.entries.push(
    makeEntry(),
    makeEntry({
      kind: 'hotp',
      issuer: '阿里云·控制台',
      account: 'bob@example.com',
      counter: 42,
      period: undefined,
      note: '备注含中文与 emoji 🔐\n以及换行',
      algo: 'SHA256',
      digits: 8,
      tagIds: ['tag-1'],
    }),
  )
  handle.data.tags.push({ id: 'tag-1', name: '工作', color: '#FF5733', position: 'a0' })
  return { handle, bytes: await handle.serialize() }
})()

// ── 用例 ─────────────────────────────────────────────────────────────────────

test('真实 Provider 端到端往返：写入再读出，data 深度相等（含中文与 emoji）', async () => {
  const opened = await openVault(sample.bytes, PASSWORD, providers)
  assert.deepEqual(opened.data, sample.handle.data)
  assert.equal(opened.data.entries[1].note, '备注含中文与 emoji 🔐\n以及换行')
  assert.equal(opened.data.tags[0].name, '工作')
  opened.lock()
})

test('空库同样可往返，settings 等于 DEFAULT_SETTINGS', async () => {
  const empty = await createVault(PASSWORD, providers, { appVersion: APP_VERSION })
  assert.deepEqual(empty.data.settings, DEFAULT_SETTINGS)
  assert.deepEqual(empty.data.entries, [])
  const opened = await openVault(await empty.serialize(), PASSWORD, providers)
  assert.deepEqual(opened.data, empty.data)
  empty.lock()
  opened.lock()
})

test('容器结构与 §1.1 一致，各 base64 字段字节长度符合参数常量', () => {
  const container = decodeContainer(sample.bytes)
  assert.deepEqual(Object.keys(container).sort(), [
    'crypto',
    'data',
    'encrypted',
    'format',
    'schemaVersion',
    'version',
  ])
  assert.equal(container.format, CONTAINER_FORMAT)
  assert.equal(container.version, CONTAINER_VERSION)
  assert.equal(container.schemaVersion, SCHEMA_VERSION)
  assert.equal(container.encrypted, true)

  const { kdf, cipher, wrappedMasterKey } = container.crypto
  assert.equal(kdf.name, 'argon2id')
  assert.equal(cipher.name, 'aes-256-gcm')
  assert.equal(kdf.memoryKiB, ARGON2ID_PARAMS.memoryKiB)
  assert.equal(kdf.iterations, ARGON2ID_PARAMS.iterations)
  assert.equal(kdf.parallelism, ARGON2ID_PARAMS.parallelism)
  assert.equal(kdf.keyLength, ARGON2ID_PARAMS.keyLength)

  assert.equal(base64Decode(kdf.salt).byteLength, ARGON2ID_PARAMS.saltLength)
  assert.equal(base64Decode(cipher.nonce).byteLength, AES_256_GCM.nonceLength)
  assert.equal(base64Decode(cipher.tag).byteLength, AES_256_GCM.tagLength)
  assert.equal(base64Decode(wrappedMasterKey.nonce).byteLength, AES_256_GCM.nonceLength)
  assert.equal(base64Decode(wrappedMasterKey.tag).byteLength, AES_256_GCM.tagLength)
  assert.equal(base64Decode(wrappedMasterKey.data).byteLength, AES_256_GCM.keyLength)
})

test('C1：容器全文不含主密码、KEK 与 DEK 的字节', async () => {
  const container = decodeContainer(sample.bytes)
  const text = utf8Decode(sample.bytes)
  const fields = [
    container.data,
    container.crypto.kdf.salt,
    container.crypto.cipher.nonce,
    container.crypto.cipher.tag,
    container.crypto.wrappedMasterKey.nonce,
    container.crypto.wrappedMasterKey.tag,
    container.crypto.wrappedMasterKey.data,
  ].map((field) => base64Decode(field))

  assert.equal(text.includes(PASSWORD), false)

  // KEK 用真实 Argon2id 按文件头参数独立重算，再在容器的每一处搜它的字节。
  const salt = base64Decode(container.crypto.kdf.salt)
  const kek = await webKdfProvider.deriveKey(utf8Encode(PASSWORD), salt, {
    memoryKiB: container.crypto.kdf.memoryKiB,
    iterations: container.crypto.kdf.iterations,
    parallelism: container.crypto.kdf.parallelism,
    saltLength: salt.byteLength,
    keyLength: container.crypto.kdf.keyLength,
  })
  const kekHex = toHex(kek)
  assert.equal(text.includes(kekHex), false)
  for (const field of fields) {
    assert.equal(containsBytes(field, kek), false, 'KEK 字节出现在容器字段里')
  }
  assert.equal(text.includes(FAKE_SECRET_BASE64), false, '条目 secret 泄露进了容器明文')

  // DEK 不是秘密：它就是 wrappedMasterKey 的明文，用刚重算的 KEK 独立解出来再搜一遍，
  // 这样「容器里找不到 DEK 字节」才是真断言而不是空断言。
  const wrapped = container.crypto.wrappedMasterKey
  const dek = await webAeadProvider.decrypt(kek, {
    nonce: base64Decode(wrapped.nonce),
    ciphertext: base64Decode(wrapped.data),
    tag: base64Decode(wrapped.tag),
  })
  const dekHex = toHex(dek)
  assert.equal(text.includes(dekHex), false)
  for (const field of fields) {
    assert.equal(containsBytes(field, dek), false, 'DEK 字节出现在容器字段里')
  }

  kek.fill(0)
  dek.fill(0)
})

test('C5：真实 CompressionStream 的产出是合法 gzip，node:zlib 能解开（跨端互通）', async () => {
  const recorder = recording()
  const handle = await createVault(PASSWORD, recorder.providers, { appVersion: APP_VERSION })
  handle.data.entries.push(makeEntry())
  const bytes = await handle.serialize()

  const payloads = recorder.calls.filter((call) => typeof call === 'object')
  assert.equal(payloads.length, 1)
  const gzipped = payloads[0].bytes

  // gzip 魔数
  assert.deepEqual([...gzipped.subarray(0, 2)], [0x1f, 0x8b])
  // 另一端的实现（node:zlib）能解开 Web 端产出的 gzip 流
  const parsed = JSON.parse(utf8Decode(gunzipSync(gzipped)))
  assert.equal(parsed.schemaVersion, SCHEMA_VERSION)
  assert.equal(parsed.entries.length, 1)
  assert.equal(parsed.entries[0].secret, FAKE_SECRET_BASE64)

  // 容器里的 data 是密文，不该带 gzip 头（带了说明压缩结果没被加密就写出去了）
  assert.notDeepEqual([...base64Decode(decodeContainer(bytes).data).subarray(0, 2)], [0x1f, 0x8b])
  handle.lock()
})

test('D1：payload 的 AAD 是 utf8Encode("mfavault\\n1\\n1")，包裹 DEK 不带 AAD', async () => {
  const recorder = recording()
  const handle = await createVault(PASSWORD, recorder.providers, { appVersion: APP_VERSION })
  await handle.serialize()

  const aads = recorder.calls.filter((call) => typeof call === 'string' && call.startsWith('aad:'))
  assert.deepEqual(aads, [`aad:${CONTAINER_FORMAT}\n${CONTAINER_VERSION}\n${SCHEMA_VERSION}`])
  handle.lock()
})

test('C7：主密码错误与密文被篡改抛出全等的 name 与 message', async () => {
  const wrongPassword = await captureError(openVault(sample.bytes, WRONG_PASSWORD, providers))
  const tampered = await captureError(openVault(tamperData(sample.bytes), PASSWORD, providers))

  assert.ok(wrongPassword instanceof VaultAuthError)
  assert.ok(tampered instanceof VaultAuthError)
  assert.equal(wrongPassword.name, 'VaultAuthError')
  assert.equal(tampered.name, wrongPassword.name)
  assert.equal(tampered.message, wrongPassword.message)
  assert.equal(wrongPassword.message, AUTH_MESSAGE)
})

test('步骤 15：篡改 AAD 覆盖的头部 version（改小）→ VaultAuthError', async () => {
  // 改小才能通过版本闸门；随后 AAD 与写入端不一致，GCM 认证失败并归并（R2-4 的括注）。
  const bytes = patchContainer(sample.bytes, (container) => {
    container.version = 0
  })
  const error = await captureError(openVault(bytes, PASSWORD, providers))
  assert.ok(error instanceof VaultAuthError, `实际抛出 ${error.name}: ${error.message}`)
  assert.equal(error.message, AUTH_MESSAGE)
})

test('步骤 15：篡改 AAD 覆盖的头部 schemaVersion（改小）→ VaultAuthError', async () => {
  const bytes = patchContainer(sample.bytes, (container) => {
    container.schemaVersion = 0
  })
  const error = await captureError(openVault(bytes, PASSWORD, providers))
  assert.ok(error instanceof VaultAuthError, `实际抛出 ${error.name}: ${error.message}`)
  assert.equal(error.message, AUTH_MESSAGE)
})

test('步骤 15：篡改 format 走的是 VaultFormatError 分支（预期的不同提示，与密码无关）', async () => {
  // docs/vault-format.md §1.1 步骤 1 要求「不是本 App 的密钥库文件」是独立提示：
  // 这是文件格式识别，在派生 KEK 之前就失败，不泄露任何密码相关信息。
  const bytes = patchContainer(sample.bytes, (container) => {
    container.format = 'aegis'
  })
  const recorder = recording()
  const error = await captureError(openVault(bytes, WRONG_PASSWORD, recorder.providers))
  assert.ok(error instanceof VaultFormatError, `实际抛出 ${error.name}`)
  assert.match(error.message, /不是本 App 的密钥库文件/)
  assert.equal(countCalls(recorder.calls, 'kdf.deriveKey'), 0)
})

test('C11：容器 version 高于支持值 → VaultVersionError，且完全不派生 KEK', async () => {
  const bytes = patchContainer(sample.bytes, (container) => {
    container.version = CONTAINER_VERSION + 1
  })
  const recorder = recording()
  const error = await captureError(openVault(bytes, PASSWORD, recorder.providers))
  assert.ok(error instanceof VaultVersionError, `实际抛出 ${error.name}`)
  assert.equal(countCalls(recorder.calls, 'kdf.deriveKey'), 0)
  assert.equal(countCalls(recorder.calls, 'aead.decrypt'), 0)
  assert.equal(countCalls(recorder.calls, 'random.randomBytes'), 0)
})

test('C11：schemaVersion 高于支持值 → VaultVersionError，且完全不派生 KEK', async () => {
  const bytes = patchContainer(sample.bytes, (container) => {
    container.schemaVersion = 99
  })
  const recorder = recording()
  const error = await captureError(openVault(bytes, PASSWORD, recorder.providers))
  assert.ok(error instanceof VaultVersionError, `实际抛出 ${error.name}`)
  assert.equal(countCalls(recorder.calls, 'kdf.deriveKey'), 0)
})

test('C3：文件头 memoryKiB 被下调 → 拒绝打开，且 message 指名是哪个参数', async () => {
  const bytes = patchContainer(sample.bytes, (container) => {
    container.crypto.kdf.memoryKiB = ARGON2ID_PARAMS.memoryKiB - 1
  })
  const recorder = recording()
  const error = await captureError(openVault(bytes, PASSWORD, recorder.providers))
  assert.match(error.message, /memoryKiB/)
  assert.equal(countCalls(recorder.calls, 'kdf.deriveKey'), 0)
})

test('C9：文件头 kdf.salt 被改短 → 拒绝打开，且不派生 KEK', async () => {
  const bytes = patchContainer(sample.bytes, (container) => {
    container.crypto.kdf.salt = base64Encode(new Uint8Array(4))
  })
  const recorder = recording()
  const error = await captureError(openVault(bytes, PASSWORD, recorder.providers))
  assert.equal(error.name !== 'VaultAuthError', true, '短 salt 不得伪装成密码错误')
  assert.match(error.message, /crypto\.kdf\.salt/)
  assert.equal(countCalls(recorder.calls, 'kdf.deriveKey'), 0)
})

test('C10：文件头 kdf.name 与注入的 Provider 不符 → 拒绝打开，且不派生 KEK', async () => {
  const bytes = patchContainer(sample.bytes, (container) => {
    container.crypto.kdf.name = 'scrypt'
  })
  const recorder = recording()
  const error = await captureError(openVault(bytes, PASSWORD, recorder.providers))
  assert.equal(error.name !== 'VaultAuthError', true)
  assert.equal(countCalls(recorder.calls, 'kdf.deriveKey'), 0)
})

test('B2：encrypted 为 false 的明文容器被拒绝，不会被当成加密库硬解', async () => {
  const bytes = patchContainer(sample.bytes, (container) => {
    container.encrypted = false
  })
  const error = await captureError(openVault(bytes, PASSWORD, providers))
  assert.ok(error instanceof VaultFormatError, `实际抛出 ${error.name}`)
  assert.match(error.message, /明文/)
})

test('意向 10 / R2-3：changeMasterPassword 是 O(1)，payload 一律不碰', async () => {
  const recorder = recording()
  const handle = await openVault(sample.bytes, PASSWORD, recorder.providers)

  // 改密码前先写一次，拿到交给 AEAD 的 payload 明文快照（该缓冲区事后会被清零，必须当场拷贝）
  await handle.serialize()
  const before = recorder.calls.filter((call) => typeof call === 'object').at(-1).bytes
  recorder.calls.length = 0

  await handle.changeMasterPassword(NEXT_PASSWORD)
  const during = [...recorder.calls]
  assert.equal(countCalls(during, 'aead.encrypt'), 1, '只重新包裹 DEK 一次')
  assert.equal(countCalls(during, 'aead.decrypt'), 0, 'payload 不得被解密')
  assert.equal(countCalls(during, 'compress.compress'), 0)
  assert.equal(countCalls(during, 'compress.decompress'), 0)
  assert.equal(countCalls(during, 'kdf.deriveKey'), 1)
  assert.equal(
    during.filter((call) => typeof call === 'object').length,
    0,
    '改密码期间不得触碰 payload 明文',
  )

  // 改密码后再写一次，交给 AEAD 的明文字节必须逐字节相同
  await handle.serialize()
  const after = recorder.calls.filter((call) => typeof call === 'object').at(-1).bytes
  assert.deepEqual(after, before, 'payload 内容被改动了，不是 O(1)')

  const changed = await handle.serialize()
  handle.lock()

  const reopened = await openVault(changed, NEXT_PASSWORD, providers)
  assert.deepEqual(reopened.data, sample.handle.data)
  reopened.lock()
})

test('改密码后旧密码失效，抛的是同一条 VaultAuthError', async () => {
  const handle = await openVault(sample.bytes, PASSWORD, providers)
  await handle.changeMasterPassword(NEXT_PASSWORD)
  const bytes = await handle.serialize()
  handle.lock()

  const error = await captureError(openVault(bytes, PASSWORD, providers))
  assert.ok(error instanceof VaultAuthError)
  assert.equal(error.message, AUTH_MESSAGE)
})

test('R2-2：连续 serialize 两次，payload 三件套全新，wrappedMasterKey 与 salt 逐字节不变', async () => {
  const handle = await openVault(sample.bytes, PASSWORD, providers)
  const a = decodeContainer(await handle.serialize())
  const b = decodeContainer(await handle.serialize())

  assert.notEqual(b.crypto.cipher.nonce, a.crypto.cipher.nonce)
  assert.notEqual(b.crypto.cipher.tag, a.crypto.cipher.tag)
  assert.notEqual(b.data, a.data)
  assert.equal(b.crypto.kdf.salt, a.crypto.kdf.salt)
  assert.deepEqual(b.crypto.wrappedMasterKey, a.crypto.wrappedMasterKey)

  const openedA = await openVault(utf8Encode(JSON.stringify(a)), PASSWORD, providers)
  assert.deepEqual(openedA.data, handle.data)
  openedA.lock()
  handle.lock()
})

test('B8：lock 之后 data / serialize / changeMasterPassword 全部抛 VaultLockedError，且幂等', async () => {
  const handle = await openVault(sample.bytes, PASSWORD, providers)
  handle.lock()
  handle.lock()

  assert.throws(() => handle.data, VaultLockedError)
  await assert.rejects(() => handle.serialize(), VaultLockedError)
  await assert.rejects(() => handle.changeMasterPassword(NEXT_PASSWORD), VaultLockedError)
})

test('lock 之后文件本身没被破坏，仍可重新解锁', async () => {
  const handle = await openVault(sample.bytes, PASSWORD, providers)
  handle.lock()
  const reopened = await openVault(sample.bytes, PASSWORD, providers)
  assert.deepEqual(reopened.data, sample.handle.data)
  reopened.lock()
})

// 步骤 11 的 6 条验收标准。`packages/vault/src/__tests__/` 里**没有** uuidV7 的测试
// （全仓 grep 只命中 index.ts 的再导出与 id.ts 的定义），故 QA 在黑盒层补上这组断言。
test('步骤 11：uuidV7 的格式、时间戳、唯一性与时间有序性', async () => {
  const NOW = 1_737_000_000_000
  const id = uuidV7(webRandomProvider, NOW)

  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  assert.equal(id.length, 36)
  assert.equal(id[14], '7', 'version 位必须是 7')
  assert.ok(['8', '9', 'a', 'b'].includes(id[19]), 'variant 位必须是 8/9/a/b')

  // 前 48 bit 是注入的 now（固定 now 时可预测 → 证明没有偷偷调用 Date.now()）
  const ms = Number.parseInt(id.slice(0, 8) + id.slice(9, 13), 16)
  assert.equal(ms, NOW)

  // 同一毫秒 1000 个不重复
  const same = new Set()
  for (let i = 0; i < 1000; i += 1) same.add(uuidV7(webRandomProvider, NOW))
  assert.equal(same.size, 1000)

  // 时间推进后字典序更大
  assert.ok(uuidV7(webRandomProvider, NOW + 1) > id)

  // 默认参数回落到 Date.now()：前后夹住即可，不必精确相等
  const before = Date.now()
  const autoId = uuidV7(webRandomProvider)
  const autoMs = Number.parseInt(autoId.slice(0, 8) + autoId.slice(9, 13), 16)
  assert.ok(autoMs >= before && autoMs <= Date.now())
})

// ── 执行 ─────────────────────────────────────────────────────────────────────

let failed = 0
for (const { name, fn } of cases) {
  const started = Date.now()
  try {
    await fn()
    console.log(`PASS  ${name}  (${Date.now() - started}ms)`)
  } catch (error) {
    failed += 1
    console.log(`FAIL  ${name}`)
    console.log(`      ${error.name}: ${error.message}`)
  }
}

sample.handle.lock()
console.log(`\n${cases.length - failed}/${cases.length} passed`)
process.exit(failed === 0 ? 0 : 1)
