import { useEffect, useState } from 'react'
import { StyleSheet, Text, View } from 'react-native'

import { ARGON2ID_PRODUCTION_VECTOR, AES_256_GCM, utf8Encode } from '@askdaddy/crypto'

import MymfaNativeModule from './modules/mymfa-native/src/MymfaNativeModule'
import { createMobileProviders, expoNativeBridge } from './src/crypto'

type SmokeState =
  | { status: 'running' }
  | { status: 'done'; lines: string[] }
  | { status: 'failed'; message: string }

const providers = createMobileProviders(expoNativeBridge)

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

/**
 * 开发期自检（#19 步骤 9a）：验证 Expo 模块注册与 `Uint8Array`↔`ByteArray` 桥接在真机上可用。
 *
 * 为什么必须在 App 里而不是 instrumentation：KAT 打的是 Kotlin 本体，跨 JS↔原生这一层
 * （typed array 转换、Promise 回传、错误码透出）只有真实 JS 运行时能证明。
 * 结果同时写 logcat，供 QA 用 `adb logcat` 取证；#20 落地真实 UI 时本文件会被替换。
 */
async function runSmoke(): Promise<string[]> {
  const lines: string[] = []

  const version = MymfaNativeModule.moduleVersion()
  lines.push(`moduleVersion=${version}`)

  const vector = ARGON2ID_PRODUCTION_VECTOR
  const started = Date.now()
  const key = await providers.kdf.deriveKey(vector.password, vector.salt, vector.params)
  const elapsed = Date.now() - started
  if (hex(key) !== vector.expectedKeyHex) {
    throw new Error(`argon2id 与固化基线不一致：${hex(key)}`)
  }
  lines.push(`argon2id=PASS ${elapsed}ms`)

  const aeadKey = providers.random.randomBytes(AES_256_GCM.keyLength)
  const plaintext = utf8Encode('预提示码: 123456')
  const aad = utf8Encode('mfavault\n1\n1')
  const sealed = await providers.aead.encrypt(aeadKey, plaintext, aad)
  const opened = await providers.aead.decrypt(aeadKey, sealed, aad)
  if (hex(opened) !== hex(plaintext)) throw new Error('AES-GCM 往返结果与明文不一致')
  lines.push('aead=PASS')

  const packed = await providers.compress.compress(plaintext)
  const unpacked = await providers.compress.decompress(packed)
  if (hex(unpacked) !== hex(plaintext)) throw new Error('gzip 往返结果与原文不一致')
  lines.push('gzip=PASS')

  return lines
}

export default function App() {
  const [smoke, setSmoke] = useState<SmokeState>({ status: 'running' })

  useEffect(() => {
    let cancelled = false

    runSmoke()
      .then((lines) => {
        if (cancelled) return
        for (const line of lines) {
          // eslint-disable-next-line no-console -- 冒烟结果必须进 logcat 供 QA 取证
          console.log(`[mfa-smoke] ${line}`)
        }
        setSmoke({ status: 'done', lines })
      })
      .catch((error: unknown) => {
        if (cancelled) return
        const message = error instanceof Error ? error.message : String(error)
        // eslint-disable-next-line no-console -- 失败同样要进 logcat
        console.log(`[mfa-smoke] FAIL ${message}`)
        setSmoke({ status: 'failed', message })
      })

    return () => {
      cancelled = true
    }
  }, [])

  return (
    <View style={styles.container}>
      <Text style={styles.title}>MyMFA</Text>
      <Text style={styles.subtitle}>Provider 自检</Text>
      {smoke.status === 'running' && <Text>检查中…</Text>}
      {smoke.status === 'failed' && <Text style={styles.failed}>FAIL {smoke.message}</Text>}
      {smoke.status === 'done' &&
        smoke.lines.map((line) => (
          <Text key={line} style={styles.line}>
            {line}
          </Text>
        ))}
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
    gap: 8,
  },
  title: { fontSize: 24, fontWeight: '600' },
  subtitle: { fontSize: 14, color: '#666' },
  line: { fontSize: 13, fontFamily: 'monospace' },
  failed: { fontSize: 13, color: '#b00020' },
})
