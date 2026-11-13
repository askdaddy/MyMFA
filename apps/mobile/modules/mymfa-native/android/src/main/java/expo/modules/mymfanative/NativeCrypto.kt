package expo.modules.mymfanative

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import com.lambdapioneer.argon2kt.Argon2Version
import org.bouncycastle.crypto.generators.SCrypt
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.SecureRandom
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 加密原语的真正实现，与 Expo 门面分开，好让 instrumentation KAT 打到**同一份代码**
 * 而不是测试里的一份复制（复制的测试只能证明复制品正确）。
 *
 * 这里只做「参数校验 + 调原语 + 出错映射」，不做业务策略：基线下限、参数默认值属于
 * `@askdaddy/crypto` 与 TS 适配层。理由同 `packages/crypto/src/params.ts`——vault 必须在
 * RFC 9106 的低内存向量上跑通，把基线策略塞进原生层会让「验证实现正确」无法进行。
 */
internal object NativeCrypto {
  private const val ARGON2_VERSION_13 = 0x13
  private const val AES_KEY_BYTES = 32
  private const val GCM_NONCE_BYTES = 12
  private const val GCM_TAG_BYTES = 16
  private const val GCM_TAG_BITS = GCM_TAG_BYTES * 8

  // Argon2Kt 的 native 库是进程级单例，重复构造只是复用同一个 so。
  private val argon2 = Argon2Kt()
  private val secureRandom = SecureRandom()

  fun argon2id(
    password: ByteArray,
    salt: ByteArray,
    memoryKiB: Int,
    iterations: Int,
    parallelism: Int,
    keyLength: Int,
    version: Int,
  ): ByteArray {
    if (version != ARGON2_VERSION_13) {
      throw CryptoParamException("只支持 Argon2 版本 0x13，收到 $version")
    }
    requirePositive("memoryKiB", memoryKiB)
    requirePositive("iterations", iterations)
    requirePositive("parallelism", parallelism)
    requirePositive("keyLength", keyLength)
    requirePositive("salt.length", salt.size)

    return argon2.hash(
      mode = Argon2Mode.ARGON2_ID,
      password = password,
      salt = salt,
      // 单位恒等：契约里就是 KiB，Argon2Kt 收的也是 KiB。任何换算都会让跨端密钥不同。
      tCostInIterations = iterations,
      mCostInKibibyte = memoryKiB,
      parallelism = parallelism,
      hashLengthInBytes = keyLength,
      version = Argon2Version.V13,
    ).rawHashAsByteArray()
  }

  fun scrypt(
    password: ByteArray,
    salt: ByteArray,
    costFactor: Int,
    blockSize: Int,
    parallelism: Int,
    keyLength: Int,
  ): ByteArray {
    requirePositive("costFactor", costFactor)
    requirePositive("blockSize", blockSize)
    requirePositive("parallelism", parallelism)
    requirePositive("keyLength", keyLength)
    requirePositive("salt.length", salt.size)
    return try {
      SCrypt.generate(password, salt, costFactor, blockSize, parallelism, keyLength)
    } catch (error: IllegalArgumentException) {
      throw CryptoParamException("scrypt 参数不合法：${error.message}")
    }
  }

  /**
   * 返回 `nonce(12) ‖ ciphertext ‖ tag(16)` 的单段字节：跨桥只搬一个 buffer，
   * 避免 Map 里嵌套 typed array 带来的转换不确定性；切分由 TS 侧按固定偏移完成。
   */
  fun aesGcmEncrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray?): ByteArray {
    requireAesKey(key)
    val nonce = ByteArray(GCM_NONCE_BYTES)
    secureRandom.nextBytes(nonce)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(
      Cipher.ENCRYPT_MODE,
      SecretKeySpec(key, "AES"),
      GCMParameterSpec(GCM_TAG_BITS, nonce),
    )
    if (aad != null) cipher.updateAAD(aad)
    // JCE 把 tag 拼在密文尾部，与 WebCrypto 的行为一致，因此整段返回即可。
    return nonce + cipher.doFinal(plaintext)
  }

  fun aesGcmDecrypt(
    key: ByteArray,
    nonce: ByteArray,
    ciphertext: ByteArray,
    tag: ByteArray,
    aad: ByteArray?,
  ): ByteArray {
    requireAesKey(key)
    if (nonce.size != GCM_NONCE_BYTES) {
      throw CryptoParamException("nonce 必须是 $GCM_NONCE_BYTES 字节，收到 ${nonce.size}")
    }
    if (tag.size != GCM_TAG_BYTES) {
      throw CryptoParamException("tag 必须是 $GCM_TAG_BYTES 字节，收到 ${tag.size}")
    }

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(
      Cipher.DECRYPT_MODE,
      SecretKeySpec(key, "AES"),
      GCMParameterSpec(GCM_TAG_BITS, nonce),
    )
    if (aad != null) cipher.updateAAD(aad)
    return try {
      cipher.doFinal(ciphertext + tag)
    } catch (error: AEADBadTagException) {
      // 错误文本不透传：与 Web 端一致，调用方不得区分「密钥错」与「被篡改」。
      throw AeadAuthException()
    }
  }

  fun randomBytes(length: Int): ByteArray {
    // 上限只防误用（一次性申请几百 MB 会把 App 打死）；DEK/nonce/salt 都在几十字节量级。
    if (length < 0 || length > 1 shl 20) {
      throw CryptoParamException("randomBytes 的长度必须在 0..1048576 之间，收到 $length")
    }
    return ByteArray(length).also { secureRandom.nextBytes(it) }
  }

  fun gzip(bytes: ByteArray): ByteArray =
    ByteArrayOutputStream().use { out ->
      try {
        GZIPOutputStream(out).use { it.write(bytes) }
      } catch (error: IOException) {
        throw GzipException("gzip 压缩失败", error)
      }
      out.toByteArray()
    }

  fun gunzip(bytes: ByteArray): ByteArray =
    try {
      GZIPInputStream(ByteArrayInputStream(bytes)).use { it.readBytes() }
    } catch (error: IOException) {
      throw GzipException("gzip 解压失败：输入不是合法的 gzip 字节流", error)
    }

  private fun requirePositive(field: String, value: Int) {
    if (value <= 0) throw CryptoParamException("$field 必须是正整数，收到 $value")
  }

  private fun requireAesKey(key: ByteArray) {
    if (key.size != AES_KEY_BYTES) {
      throw CryptoParamException("AES-256-GCM 密钥必须是 $AES_KEY_BYTES 字节，收到 ${key.size}")
    }
  }
}
