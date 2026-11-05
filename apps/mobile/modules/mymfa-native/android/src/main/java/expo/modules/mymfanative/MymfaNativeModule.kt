package expo.modules.mymfanative

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class MymfaNativeModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("MymfaNative")

    // 骨架探针：验证 JS→原生桥接端到端可用。#19 落地 Argon2id/scrypt/SecureStore 时
    // 保持本函数不变，作为原生层在位的烟雾信号。
    Function("moduleVersion") {
      "0.1.0"
    }
  }
}
