import { argon2id } from 'hash-wasm'

import { assertArgon2idParams } from '@askdaddy/crypto'
import type { Argon2idParams, KdfProvider } from '@askdaddy/crypto'

export const webKdfProvider: KdfProvider = {
  name: 'argon2id',

  async deriveKey(
    password: Uint8Array,
    salt: Uint8Array,
    params: Argon2idParams,
  ): Promise<Uint8Array> {
    // 只做结构性校验：官方向量的 m=32KiB 必须能跑，基线降级检查属于 vault 层。
    assertArgon2idParams(params)

    return argon2id({
      password,
      salt,
      iterations: params.iterations,
      parallelism: params.parallelism,
      // hash-wasm 的 memorySize 单位就是 kibibytes，与 memoryKiB 恒等，不做任何换算。
      memorySize: params.memoryKiB,
      hashLength: params.keyLength,
      outputType: 'binary',
    })
  },
}
