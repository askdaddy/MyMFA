// Issue #10：仅通过 dist 公开入口和真实 Web Provider 验收，独立 Node 原语作为对照。
import assert from 'node:assert/strict'
import { Buffer } from 'node:buffer'
import { createCipheriv, createDecipheriv, pbkdf2Sync, scryptSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { URL } from 'node:url'
import { utf8Encode, utf8Decode } from '../packages/crypto/dist/index.js'
import {
  webAeadProvider,
  webScryptProvider,
  webPbkdf2Provider,
  webRandomProvider,
} from '../packages/crypto-web/dist/index.js'
import {
  detect,
  generateAegis,
  generateAegisEncrypted,
  parseAegis,
  parseAegisEncrypted,
  parseTwoFas,
  parseTwoFasEncrypted,
  TransferAuthError,
} from '../packages/transfer/dist/index.js'
import { assertVaultData } from '../packages/vault/dist/index.js'

const fixture = (name) =>
  readFileSync(new URL(`../packages/transfer/src/__fixtures__/${name}`, import.meta.url), 'utf8')
const password = utf8Encode('test-测试')
const providers = {
  scrypt: webScryptProvider,
  pbkdf2: webPbkdf2Provider,
  aead: webAeadProvider,
  random: webRandomProvider,
}
const params = { costFactor: 1024, blockSize: 8, parallelism: 1, keyLength: 32 }
const vault = assertVaultData(JSON.parse(fixture('mfavault_plaintext.json')).data)
let passed = 0
async function check(name, fn) {
  await fn()
  passed += 1
  console.log(`PASS ${name}`)
}
const hex = (value) => Buffer.from(value, 'hex')
const b64 = (value) => Buffer.from(value, 'base64')
const auth = (operation) =>
  assert.rejects(
    operation,
    (e) => e instanceof TransferAuthError && e.message === new TransferAuthError().message,
  )

function independentAegis(bytes) {
  const file = JSON.parse(utf8Decode(bytes))
  assert.equal(file.version, 1)
  const slot = file.header.slots[0]
  assert.equal(slot.type, 1)
  assert.deepEqual([slot.n, slot.r, slot.p], [1024, 8, 1])
  assert.match(slot.uuid, /^[\da-f]{8}-[\da-f]{4}-4[\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/)
  const key = scryptSync(password, hex(slot.salt), 32, { N: slot.n, r: slot.r, p: slot.p })
  const decrypt = (k, data, p) => {
    const cipher = createDecipheriv('aes-256-gcm', k, hex(p.nonce))
    cipher.setAuthTag(hex(p.tag))
    return Buffer.concat([cipher.update(data), cipher.final()])
  }
  const master = decrypt(key, hex(slot.key), slot.key_params)
  assert.equal(master.length, 32)
  assert.notDeepEqual(master, key)
  const plaintext = decrypt(master, b64(file.db), file.header.params)
  try {
    return JSON.parse(plaintext.toString('utf8'))
  } finally {
    key.fill(0)
    master.fill(0)
    plaintext.fill(0)
  }
}

function independentTwoFas() {
  const plain = JSON.parse(fixture('twofas_edge.json'))
  const encrypt = (text, byte) => {
    const salt = Buffer.alloc(32, byte)
    const nonce = Buffer.alloc(12, byte + 1)
    const key = pbkdf2Sync(password, salt, 10000, 32, 'sha256')
    const cipher = createCipheriv('aes-256-gcm', key, nonce)
    const encrypted = Buffer.concat([
      cipher.update(text, 'utf8'),
      cipher.final(),
      cipher.getAuthTag(),
    ])
    key.fill(0)
    return [encrypted, salt, nonce].map((v) => v.toString('base64')).join(':')
  }
  return {
    ...plain,
    services: null,
    servicesEncrypted: encrypt(JSON.stringify(plain.services), 7),
    reference: encrypt('reference', 11),
    iterations: 1,
  }
}

await check('Aegis 导出经独立 scrypt/AES 反解，字段保留与真实 Web 往返', async () => {
  const bytes = await generateAegisEncrypted(vault, password, params, providers)
  assert.deepEqual(independentAegis(bytes), JSON.parse(utf8Decode(generateAegis(vault))).db)
  assert.deepEqual(
    await parseAegisEncrypted(bytes, password, providers),
    parseAegis(generateAegis(vault)),
  )
  assert.equal(detect(bytes), 'aegis')
  const again = JSON.parse(
    utf8Decode(await generateAegisEncrypted(vault, password, params, providers)),
  )
  const first = JSON.parse(utf8Decode(bytes))
  for (const field of ['salt', 'uuid'])
    assert.notEqual(first.header.slots[0][field], again.header.slots[0][field])
  assert.notEqual(first.header.params.nonce, again.header.params.nonce)
  assert.notEqual(first.header.slots[0].key_params.nonce, again.header.slots[0].key_params.nonce)
})

await check('独立 2FAS v4 输入，各段盐/IV 与 groups/部分失败保留', async () => {
  const file = JSON.stringify(independentTwoFas())
  assert.deepEqual(
    await parseTwoFasEncrypted(file, password, providers),
    parseTwoFas(fixture('twofas_edge.json')),
  )
  assert.equal(detect(file), '2fas')
})

await check('一手上游 Aegis/2FAS 正常 golden 用真实 Web 解密', async () => {
  const fake = utf8Encode('test')
  const a = await parseAegisEncrypted(fixture('aegis_encrypted.json'), fake, providers)
  const b = await parseTwoFasEncrypted(fixture('twofas_encrypted.2fas'), fake, providers)
  assert.deepEqual(
    [a.entries.length, a.failures.length, b.entries.length, b.failures.length],
    [6, 1, 4, 1],
  )
  fake.fill(0)
})

await check('错误密码、篡改、畸形、旧版和超大输入同一错误', async () => {
  await auth(() =>
    parseAegisEncrypted(fixture('aegis_encrypted_edge.json'), utf8Encode('wrong'), providers),
  )
  await auth(() =>
    parseTwoFasEncrypted(JSON.stringify(independentTwoFas()), utf8Encode('wrong'), providers),
  )
  const file = independentTwoFas()
  file.reference = file.reference.slice(1)
  await auth(() => parseTwoFasEncrypted(JSON.stringify(file), password, providers))
  for (const input of ['{', 'x'.repeat(16 * 1024 * 1024 + 1)]) {
    await auth(() => parseAegisEncrypted(input, password, providers))
    await auth(() => parseTwoFasEncrypted(input, password, providers))
  }
  for (const version of [1, 2, 3, 5]) {
    await auth(() =>
      parseTwoFasEncrypted(
        JSON.stringify({ ...independentTwoFas(), schemaVersion: version }),
        password,
        providers,
      ),
    )
  }
})

await check('畸形/超限在派生前拒绝，不调用 KDF', async () => {
  let calls = 0
  const fail = {
    async deriveKey() {
      calls += 1
      throw new Error('unexpected KDF')
    },
  }
  const p = { ...providers, scrypt: fail, pbkdf2: fail }
  await auth(() => parseAegisEncrypted(fixture('aegis_encrypted_malformed.json'), password, p))
  await auth(() => parseTwoFasEncrypted(fixture('twofas_encrypted_malformed.2fas'), password, p))
  const file = JSON.parse(fixture('aegis_encrypted_edge.json'))
  file.header.slots = Array.from({ length: 33 }, () => file.header.slots[0])
  await auth(() => parseAegisEncrypted(JSON.stringify(file), password, p))
  assert.equal(calls, 0)
})

await check('Provider 边界观察正常/故障临时字节清零，调用方数据有效', async () => {
  for (const failAt of [0, 1, 2]) {
    const seen = []
    let calls = 0
    const keep = (bytes) => {
      seen.push(bytes)
      return bytes
    }
    const p = {
      ...providers,
      scrypt: {
        name: 'scrypt',
        async deriveKey(...args) {
          return keep(await webScryptProvider.deriveKey(...args))
        },
      },
      random: {
        randomBytes(n) {
          return keep(webRandomProvider.randomBytes(n))
        },
      },
      aead: {
        name: 'aes-256-gcm',
        async encrypt(key, plain) {
          seen.push(plain)
          if (++calls === failAt) throw new Error('injected failure')
          const sealed = await webAeadProvider.encrypt(key, plain)
          Object.values(sealed).forEach(keep)
          return sealed
        },
        async decrypt(...args) {
          return keep(await webAeadProvider.decrypt(...args))
        },
      },
    }
    if (failAt)
      await assert.rejects(
        () => generateAegisEncrypted(vault, password, params, p),
        /injected failure/,
      )
    else {
      const result = await parseAegisEncrypted(
        await generateAegisEncrypted(vault, password, params, p),
        password,
        p,
      )
      assert.ok(result.entries.every((entry) => entry.secret.some((byte) => byte !== 0)))
    }
    assert.ok(seen.length > 0 && seen.every((bytes) => bytes.every((byte) => byte === 0)))
    assert.equal(utf8Decode(password), 'test-测试')
  }
})

await check('2FAS 正常及两次 AEAD 故障的派生密钥/明文字节清零', async () => {
  for (const failAt of [0, 1, 2]) {
    const seen = []
    let calls = 0
    const keep = (bytes) => {
      seen.push(bytes)
      return bytes
    }
    const p = {
      ...providers,
      pbkdf2: {
        name: 'pbkdf2',
        async deriveKey(...args) {
          return keep(await webPbkdf2Provider.deriveKey(...args))
        },
      },
      aead: {
        ...webAeadProvider,
        async decrypt(...args) {
          if (++calls === failAt) throw new Error('injected failure')
          return keep(await webAeadProvider.decrypt(...args))
        },
      },
    }
    const open = () => parseTwoFasEncrypted(JSON.stringify(independentTwoFas()), password, p)
    if (failAt) await auth(open)
    else assert.deepEqual(await open(), parseTwoFas(fixture('twofas_edge.json')))
    assert.ok(seen.length > 0 && seen.every((bytes) => bytes.every((byte) => byte === 0)))
    assert.equal(utf8Decode(password), 'test-测试')
  }
})

password.fill(0)
console.log(`PASS ${passed}/${passed} encrypted transfer Web black-box checks`)
