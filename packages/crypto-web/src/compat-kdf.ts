import { scrypt } from 'hash-wasm'

import { assertPbkdf2Params, assertScryptParams } from '@askdaddy/crypto'
import type { Pbkdf2Provider, ScryptProvider } from '@askdaddy/crypto'

export const webScryptProvider: ScryptProvider = {
  name: 'scrypt',
  async deriveKey(password, salt, params) {
    assertScryptParams(params, salt)
    return scrypt({
      password,
      salt,
      costFactor: params.costFactor,
      blockSize: params.blockSize,
      parallelism: params.parallelism,
      hashLength: params.keyLength,
      outputType: 'binary',
    })
  },
}

export const webPbkdf2Provider: Pbkdf2Provider = {
  name: 'pbkdf2',
  async deriveKey(password, salt, params) {
    assertPbkdf2Params(params, salt)
    const { iterations, hash, keyLength } = params
    const key = await crypto.subtle.importKey(
      'raw',
      password as Uint8Array<ArrayBuffer>,
      'PBKDF2',
      false,
      ['deriveBits'],
    )
    return new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: salt as Uint8Array<ArrayBuffer>, iterations, hash },
        key,
        keyLength * 8,
      ),
    )
  },
}
