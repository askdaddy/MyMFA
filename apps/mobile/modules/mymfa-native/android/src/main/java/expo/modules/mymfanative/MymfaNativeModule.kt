package expo.modules.mymfanative

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * 移动端加密原语的唯一原生入口（#19）。
 *
 * 本文件只做 Expo 门面：把 JS 参数转成 `NativeCrypto` 的调用、把结果原样交回。
 * 所有算法与错误映射都在 `NativeCrypto`（因此 instrumentation KAT 打的是同一份实现），
 * 安全存储在 `SecureStore`。
 */
class MymfaNativeModule : Module() {
  private val secureStore by lazy {
    val context = appContext.reactContext
      ?: throw SecureStoreException("React context 不可用，无法访问设备安全存储")
    SecureStore(context.applicationContext)
  }

  override fun definition() = ModuleDefinition {
    Name("MymfaNative")

    // 骨架探针：验证 JS→原生桥接端到端可用。保持本函数不变，作为原生层在位的烟雾信号。
    Function("moduleVersion") {
      "0.1.0"
    }

    AsyncFunction("argon2id") {
        password: ByteArray,
        salt: ByteArray,
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        keyLength: Int,
        version: Int,
      ->
      NativeCrypto.argon2id(password, salt, memoryKiB, iterations, parallelism, keyLength, version)
    }

    AsyncFunction("scrypt") {
        password: ByteArray,
        salt: ByteArray,
        costFactor: Int,
        blockSize: Int,
        parallelism: Int,
        keyLength: Int,
      ->
      NativeCrypto.scrypt(password, salt, costFactor, blockSize, parallelism, keyLength)
    }

    AsyncFunction("aesGcmEncrypt") { key: ByteArray, plaintext: ByteArray, aad: ByteArray? ->
      NativeCrypto.aesGcmEncrypt(key, plaintext, aad)
    }

    AsyncFunction("aesGcmDecrypt") {
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        tag: ByteArray,
        aad: ByteArray?,
      ->
      NativeCrypto.aesGcmDecrypt(key, nonce, ciphertext, tag, aad)
    }

    // RandomProvider 在契约里是同步方法，这里必须保持同步。
    Function("randomBytes") { length: Int ->
      NativeCrypto.randomBytes(length)
    }

    AsyncFunction("gzip") { bytes: ByteArray ->
      NativeCrypto.gzip(bytes)
    }

    AsyncFunction("gunzip") { bytes: ByteArray ->
      NativeCrypto.gunzip(bytes)
    }

    AsyncFunction("secureStoreWrite") { name: String, value: ByteArray ->
      secureStore.write(name, value)
    }

    AsyncFunction("secureStoreRead") { name: String ->
      secureStore.read(name)
    }

    AsyncFunction("secureStoreRemove") { name: String ->
      secureStore.remove(name)
    }
  }
}
