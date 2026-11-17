package expo.modules.mymfanative

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 原生原语的 known-answer 测试（#19 步骤 6）。
 *
 * 打的是 `NativeCrypto` / `SecureStore` 本身（模块门面只是转发），因此这里绿了才有资格说
 * 「原生实现可用」。全部输入是公开向量与假值，不含任何真实 secret（AGENTS.md §5.3）。
 *
 * 期望值来源：
 * - Argon2id 生产向量 / scrypt 摘要：`packages/crypto/src/vectors.ts` 与 #17 Android gate
 *   （同一份跨端基线，不在各端私存一份新值）
 * - AES-GCM 向量：Node 内置 OpenSSL 现场生成后固化（独立实现，满足 docs/testing.md §3.3.1
 *   「必须有第三方对照」的要求）
 */
@RunWith(AndroidJUnit4::class)
class NativeCryptoKATTest {
  private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

  private fun bytes(hex: String): ByteArray =
    hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

  // ── Argon2id：生产基线（跨端一致性的唯一硬标准） ─────────────────────────

  @Test
  fun argon2idMatchesProductionBaseline() {
    val key = NativeCrypto.argon2id(
      password = "correct horse battery staple".toByteArray(Charsets.UTF_8),
      salt = Base64.getDecoder().decode("TXlNRkFzYWx0Zml4dHVyZQ=="),
      memoryKiB = 65536,
      iterations = 3,
      parallelism = 4,
      keyLength = 32,
      version = 0x13,
    )

    assertEquals(
      "a08af7c53183770da615468c7cace51b2b9c2e9ee0324524f4e4d10bae86e873",
      hex(key),
    )
  }

  @Test
  fun argon2idRejectsUnknownVersion() {
    assertThrows(CryptoParamException::class.java) {
      NativeCrypto.argon2id(
        "pw".toByteArray(),
        ByteArray(16),
        65536,
        3,
        4,
        32,
        0x10,
      )
    }
  }

  // ── scrypt：ADR-018 兼容路径，与 Web/Node 同源期望摘要 ────────────────────

  @Test
  fun scryptMatchesCrossPlatformDigests() {
    val password = "test-测试-\u0000".toByteArray(Charsets.UTF_8)
    val salt = "only-a-fake-test-salt".toByteArray(Charsets.UTF_8)

    assertEquals(
      "c96af047ea44af8869150300880141518bd8c8f62aa4927fe23fe5304e215e98",
      hex(NativeCrypto.scrypt(password, salt, 32768, 8, 1, 32)),
    )
    assertEquals(
      "39580ff466f6b82582af475ac57658e6aa9df2970f0dba119dd01cf2152a458a",
      hex(NativeCrypto.scrypt(password, salt, 2048, 8, 2, 32)),
    )
  }

  // ── AES-256-GCM：与独立实现（OpenSSL）双向对齐 ───────────────────────────

  private val nodeKey = bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  private val nodeNonce = ByteArray(12) { 0xa0.toByte() }
  private val nodeAad = "mfavault\n1\n1".toByteArray(Charsets.UTF_8)
  private val nodePlaintext = bytes(
    "7b22656e7472696573223a5b7b22697373756572223a22476974487562222c226163636f756e74223a22616c696365406578616d706c652e636f6d222c22736563726574223a224a425357593344504548504b33505850227d5d7d",
  )
  private val nodeCiphertext = bytes(
    "5e93078dcab627b8ca73b4d9961d99ddb6cdfc9790d70b5c607a0d470036214f09c11b44ba5ba2ea374e36ca58cc1ff5d32ff7c22bafa5b80c3a8d1845aff8e59c212ce348a66efc08a27b95328cacfc3b4bb9d8697a0c22aaa7ae",
  )
  private val nodeTag = bytes("8506c0d6036f14fec0c27271b95aba71")

  @Test
  fun decryptsIndependentImplementationCiphertext() {
    val plaintext = NativeCrypto.aesGcmDecrypt(
      nodeKey,
      nodeNonce,
      nodeCiphertext,
      nodeTag,
      nodeAad,
    )

    assertEquals(hex(nodePlaintext), hex(plaintext))
  }

  @Test
  fun rejectsTamperedTagWithAuthError() {
    val tampered = nodeTag.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }

    assertThrows(AeadAuthException::class.java) {
      NativeCrypto.aesGcmDecrypt(nodeKey, nodeNonce, nodeCiphertext, tampered, nodeAad)
    }
  }

  @Test
  fun roundTripsItsOwnCiphertextAndSplitsNonceTag() {
    val plaintext = "预提示码: 123456".toByteArray(Charsets.UTF_8)

    val sealed = NativeCrypto.aesGcmEncrypt(nodeKey, plaintext, nodeAad)

    // 输出布局是 nonce(12) ‖ ciphertext ‖ tag(16)，与 TS 适配层的切分约定一致。
    assertEquals(12 + plaintext.size + 16, sealed.size)
    val nonce = sealed.copyOfRange(0, 12)
    val ciphertext = sealed.copyOfRange(12, sealed.size - 16)
    val tag = sealed.copyOfRange(sealed.size - 16, sealed.size)

    assertArrayEquals(
      plaintext,
      NativeCrypto.aesGcmDecrypt(nodeKey, nonce, ciphertext, tag, nodeAad),
    )
  }

  @Test
  fun encryptsEmptyPlaintext() {
    val sealed = NativeCrypto.aesGcmEncrypt(nodeKey, ByteArray(0), null)
    assertEquals(12 + 16, sealed.size)

    val nonce = sealed.copyOfRange(0, 12)
    val tag = sealed.copyOfRange(sealed.size - 16, sealed.size)
    assertEquals(
      0,
      NativeCrypto.aesGcmDecrypt(nodeKey, nonce, ByteArray(0), tag, null).size,
    )
  }

  // ── Keystore 包裹的安全存储 ───────────────────────────────────────────────

  @Test
  fun secureStoreRoundTripThroughKeystore() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val store = SecureStore(context)
    val name = "kat.dek"

    store.remove(name)
    assertNull(store.read(name))

    val dek = ByteArray(32) { (it * 7).toByte() }
    store.write(name, dek)
    val restored = store.read(name)
    assertNotNull(restored)
    assertArrayEquals(dek, restored)

    store.remove(name)
    assertNull(store.read(name))
  }

  @Test
  fun secureStoreRejectsOversizedValue() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val store = SecureStore(context)

    assertThrows(SecureStoreException::class.java) {
      store.write("kat.oversized", ByteArray(4097))
    }
  }

  // ── gzip / 随机数 ─────────────────────────────────────────────────────────

  @Test
  fun gzipRoundTripsAndRejectsGarbage() {
    val payload = "{\"entries\":[]}".toByteArray(Charsets.UTF_8)

    assertArrayEquals(payload, NativeCrypto.gunzip(NativeCrypto.gzip(payload)))
    assertTrue(NativeCrypto.gzip(payload).size >= 18)

    assertThrows(GzipException::class.java) {
      NativeCrypto.gunzip("not gzip".toByteArray(Charsets.UTF_8))
    }
  }

  @Test
  fun randomBytesHonoursLengthAndRejectsNegative() {
    assertEquals(32, NativeCrypto.randomBytes(32).size)
    assertEquals(0, NativeCrypto.randomBytes(0).size)
    assertThrows(CryptoParamException::class.java) { NativeCrypto.randomBytes(-1) }
  }
}
