package expo.modules.mymfanative

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 设备安全存储（AGENTS.md §5.1）：只在**设备内**保存生物识别包裹的 DEK 与解锁态。
 *
 * 落盘形态是「Keystore 非导出 AES 密钥包裹后的密文」，明文永不进 SharedPreferences、
 * 不进日志、不进任何可导出内容。密钥离开设备即不可用，因此这里的数据天然不可迁移。
 *
 * #22 会在此基础上加 `setUserAuthenticationRequired` 与
 * `KeyPermanentlyInvalidatedException` 回退；那属于生物识别的策略，不是本文件的职责。
 */
internal class SecureStore(private val context: Context) {
  companion object {
    private const val ALIAS = "mymfa-securestore-v1"
    private const val PREFS = "mymfa-secure-store"
    private const val NONCE_BYTES = 12
    private const val TAG_BITS = 128
    private const val MAX_VALUE_BYTES = 4096
    private const val MAX_NAME_LENGTH = 128
  }

  private fun prefs() = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  private fun key(): SecretKey {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (keyStore.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    generator.init(
      KeyGenParameterSpec.Builder(
        ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
      )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        // 关闭调用方自带 IV 的路径，避免 nonce 复用（与 JS 侧 AEAD 的约束同源）。
        .setRandomizedEncryptionRequired(true)
        .build(),
    )
    return generator.generateKey()
  }

  private fun assertName(name: String) {
    if (name.isBlank() || name.length > MAX_NAME_LENGTH) {
      throw SecureStoreException("安全存储的键名必须是 1–$MAX_NAME_LENGTH 个非空白字符")
    }
  }

  fun write(name: String, value: ByteArray) {
    assertName(name)
    // 上限是刻意切的角：这里只该放 DEK（32 字节级）这类小对象。放大后会变成「安全存储当数据库用」，
    // 那需要的是本地加密文件 + 轮换策略，不是 Keystore 包裹。
    if (value.size > MAX_VALUE_BYTES) {
      throw SecureStoreException("安全存储单条上限为 $MAX_VALUE_BYTES 字节")
    }

    try {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.ENCRYPT_MODE, key())
      // 键名进 AAD：把 A 条目的密文挪到 B 条目会被认证拒绝，而不是静默解出别人的 DEK。
      cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
      val sealed = cipher.doFinal(value)
      val blob = cipher.iv + sealed
      if (!prefs().edit().putString(name, Base64.encodeToString(blob, Base64.NO_WRAP)).commit()) {
        throw SecureStoreException("安全存储写入失败")
      }
    } catch (error: SecureStoreException) {
      throw error
    } catch (error: Exception) {
      throw SecureStoreException("安全存储写入失败", error)
    }
  }

  fun read(name: String): ByteArray? {
    assertName(name)
    val encoded = prefs().getString(name, null) ?: return null

    val blob = try {
      Base64.decode(encoded, Base64.NO_WRAP)
    } catch (error: IllegalArgumentException) {
      throw SecureStoreException("安全存储内容损坏", error)
    }
    if (blob.size <= NONCE_BYTES) throw SecureStoreException("安全存储内容损坏")

    try {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, blob, 0, NONCE_BYTES))
      cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
      return cipher.doFinal(blob, NONCE_BYTES, blob.size - NONCE_BYTES)
    } catch (error: AEADBadTagException) {
      // 密钥被系统作废（如用户清除凭据）与内容被篡改在这里不可区分，提示按「读不到」处理，
      // 调用方据此清空并回退主密码路径，而不是把它当成「从未写入」。
      throw SecureStoreException("安全存储内容损坏或密钥已失效", error)
    } catch (error: Exception) {
      throw SecureStoreException("安全存储读取失败", error)
    }
  }

  fun remove(name: String) {
    assertName(name)
    prefs().edit().remove(name).apply()
  }
}
