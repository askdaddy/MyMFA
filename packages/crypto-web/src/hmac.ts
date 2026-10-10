export const webHmacProvider = {
  async hmac(algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512', key: Uint8Array, data: Uint8Array) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(key),
      { name: 'HMAC', hash: algorithm },
      false,
      ['sign'],
    )
    return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, new Uint8Array(data)))
  },
}
