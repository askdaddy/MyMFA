import { CryptoParamsError } from '@askdaddy/crypto'
import type { RandomProvider } from '@askdaddy/crypto'

export const webRandomProvider: RandomProvider = {
  randomBytes(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new CryptoParamsError(`randomBytes 的长度必须是非负整数，实际为 ${length}`)
    }

    const out = new Uint8Array(length)
    crypto.getRandomValues(out)
    return out
  },
}
