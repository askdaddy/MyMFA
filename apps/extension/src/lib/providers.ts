import { createOtp } from '@askdaddy/otp'
import {
  webAeadProvider,
  webCompressProvider,
  webHmacProvider,
  webKdfProvider,
  webRandomProvider,
} from '@askdaddy/crypto-web'
import type { VaultProviders } from '@askdaddy/vault'

/** background 是唯一的数据边界（design 方案 A）：Provider 只在这一层组装。 */
export const vaultProviders: VaultProviders = {
  kdf: webKdfProvider,
  aead: webAeadProvider,
  random: webRandomProvider,
  compress: webCompressProvider,
}

export const otp = createOtp(webHmacProvider)
