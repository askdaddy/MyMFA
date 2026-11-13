import { describe, expect, it } from 'vitest'

import {
  AeadAuthError,
  ARGON2ID_PARAMS,
  ARGON2ID_VERSION,
  AES_256_GCM,
  CompressError,
  CryptoError,
  CryptoParamsError,
} from '@askdaddy/crypto'

import { NATIVE_ERROR_CODES, nativeErrorCode, type NativeCryptoBridge } from '../bridge'
import { createMobileProviders } from '../providers'

function codedError(code: string): Error {
  const error = new Error('native failure') as Error & { code: string }
  error.code = code
  return error
}

interface Calls {
  argon2id: unknown[][]
  scrypt: unknown[][]
  encrypt: unknown[][]
  decrypt: unknown[][]
  random: number[]
  gzip: Uint8Array[]
  gunzip: Uint8Array[]
  storeWrite: Array<[string, Uint8Array]>
  storeRead: string[]
  storeRemove: string[]
}

/**
 * 记录型假桥：断言的是**适配层交给原生的到底是什么**。
 * 真实算法的字节级一致性由 #17 的 Android gate 与原生 KAT 负责，这里不重复实现加密。
 */
function fakeBridge(overrides: Partial<NativeCryptoBridge> = {}): {
  bridge: NativeCryptoBridge
  calls: Calls
} {
  const calls: Calls = {
    argon2id: [],
    scrypt: [],
    encrypt: [],
    decrypt: [],
    random: [],
    gzip: [],
    gunzip: [],
    storeWrite: [],
    storeRead: [],
    storeRemove: [],
  }

  const bridge: NativeCryptoBridge = {
    async argon2id(password, salt, memoryKiB, iterations, parallelism, keyLength, version) {
      calls.argon2id.push([password, salt, memoryKiB, iterations, parallelism, keyLength, version])
      return new Uint8Array(keyLength).fill(7)
    },
    async scrypt(password, salt, costFactor, blockSize, parallelism, keyLength) {
      calls.scrypt.push([password, salt, costFactor, blockSize, parallelism, keyLength])
      return new Uint8Array(keyLength).fill(9)
    },
    async aesGcmEncrypt(key, plaintext, aad) {
      calls.encrypt.push([key, plaintext, aad])
      return Uint8Array.from([
        ...new Uint8Array(AES_256_GCM.nonceLength).fill(1),
        ...plaintext,
        ...new Uint8Array(AES_256_GCM.tagLength).fill(2),
      ])
    },
    async aesGcmDecrypt(key, nonce, ciphertext, tag, aad) {
      calls.decrypt.push([key, nonce, ciphertext, tag, aad])
      return Uint8Array.from(ciphertext)
    },
    randomBytes(length) {
      calls.random.push(length)
      return new Uint8Array(length).fill(3)
    },
    async gzip(bytes) {
      calls.gzip.push(bytes)
      return Uint8Array.from([0x1f, 0x8b])
    },
    async gunzip(bytes) {
      calls.gunzip.push(bytes)
      return Uint8Array.from([0x7b, 0x7d])
    },
    async secureStoreRead(name) {
      calls.storeRead.push(name)
      return new Uint8Array([4, 5])
    },
    async secureStoreWrite(name, value) {
      calls.storeWrite.push([name, value])
    },
    async secureStoreRemove(name) {
      calls.storeRemove.push(name)
    },
    ...overrides,
  }

  return { bridge, calls }
}

const password = new Uint8Array([1, 2, 3])
const salt = new Uint8Array(16).fill(0xaa)

describe('mobile KDF provider', () => {
  it('把 memoryKiB 原值交给原生（不做 KiB/MiB 换算）', async () => {
    const { bridge, calls } = fakeBridge()

    await createMobileProviders(bridge).kdf.deriveKey(password, salt, ARGON2ID_PARAMS)

    expect(calls.argon2id).toHaveLength(1)
    expect(calls.argon2id[0]![2]).toBe(65536)
  })

  it('显式传 Argon2 版本 0x13，不依赖原生库默认值', async () => {
    const { bridge, calls } = fakeBridge()

    await createMobileProviders(bridge).kdf.deriveKey(password, salt, ARGON2ID_PARAMS)

    expect(calls.argon2id[0]![6]).toBe(ARGON2ID_VERSION)
    expect(ARGON2ID_VERSION).toBe(0x13)
  })

  it('按契约顺序传递 password/salt/iterations/parallelism/keyLength', async () => {
    const { bridge, calls } = fakeBridge()

    await createMobileProviders(bridge).kdf.deriveKey(password, salt, ARGON2ID_PARAMS)

    const [sentPassword, sentSalt, , iterations, parallelism, keyLength] = calls.argon2id[0]!
    expect(sentPassword).toBe(password)
    expect(sentSalt).toBe(salt)
    expect(iterations).toBe(ARGON2ID_PARAMS.iterations)
    expect(parallelism).toBe(ARGON2ID_PARAMS.parallelism)
    expect(keyLength).toBe(ARGON2ID_PARAMS.keyLength)
  })

  it('参数不合法时在跨桥之前就抛 CryptoParamsError', async () => {
    const { bridge, calls } = fakeBridge()

    await expect(
      createMobileProviders(bridge).kdf.deriveKey(password, salt, {
        ...ARGON2ID_PARAMS,
        memoryKiB: 0,
      }),
    ).rejects.toBeInstanceOf(CryptoParamsError)
    expect(calls.argon2id).toEqual([])
  })
})

describe('mobile scrypt provider', () => {
  it('原样透传 N/r/p/keyLength', async () => {
    const { bridge, calls } = fakeBridge()

    const key = await createMobileProviders(bridge).scrypt.deriveKey(password, salt, {
      costFactor: 32768,
      blockSize: 8,
      parallelism: 1,
      keyLength: 32,
    })

    expect(key).toHaveLength(32)
    expect(calls.scrypt[0]!.slice(2)).toEqual([32768, 8, 1, 32])
  })

  it('拒绝非 2 的幂的 N', async () => {
    const { bridge, calls } = fakeBridge()

    await expect(
      createMobileProviders(bridge).scrypt.deriveKey(password, salt, {
        costFactor: 1000,
        blockSize: 8,
        parallelism: 1,
        keyLength: 32,
      }),
    ).rejects.toBeInstanceOf(CryptoParamsError)
    expect(calls.scrypt).toEqual([])
  })
})

describe('mobile AEAD provider', () => {
  const key = new Uint8Array(AES_256_GCM.keyLength).fill(5)

  it('把原生单段字节切成 nonce / ciphertext / tag', async () => {
    const { bridge } = fakeBridge()
    const plaintext = Uint8Array.from([10, 11, 12])

    const sealed = await createMobileProviders(bridge).aead.encrypt(key, plaintext)

    expect(sealed.nonce).toHaveLength(AES_256_GCM.nonceLength)
    expect(sealed.tag).toHaveLength(AES_256_GCM.tagLength)
    expect(Array.from(sealed.ciphertext)).toEqual([10, 11, 12])
    expect(sealed.nonce[0]).toBe(1)
    expect(sealed.tag[0]).toBe(2)
  })

  it('空明文的密文段为空，tag 不被吞进 ciphertext', async () => {
    const { bridge } = fakeBridge()

    const sealed = await createMobileProviders(bridge).aead.encrypt(key, new Uint8Array(0))

    expect(sealed.ciphertext).toHaveLength(0)
    expect(sealed.tag).toHaveLength(AES_256_GCM.tagLength)
  })

  it('把 AAD 透传给原生', async () => {
    const { bridge, calls } = fakeBridge()
    const aad = new Uint8Array([1, 2])

    await createMobileProviders(bridge).aead.encrypt(key, new Uint8Array(0), aad)

    expect(calls.encrypt[0]![2]).toBe(aad)
  })

  it('短于 nonce+tag 的原生返回值被拒绝，而不是静默切出错位数据', async () => {
    const { bridge } = fakeBridge({
      aesGcmEncrypt: async () => new Uint8Array(4),
    })

    await expect(
      createMobileProviders(bridge).aead.encrypt(key, new Uint8Array(0)),
    ).rejects.toBeInstanceOf(CryptoError)
  })

  it('认证失败码映射为 AeadAuthError（vault 依赖它做统一提示）', async () => {
    const { bridge } = fakeBridge({
      aesGcmDecrypt: async () => {
        throw codedError(NATIVE_ERROR_CODES.aeadAuth)
      },
    })

    await expect(
      createMobileProviders(bridge).aead.decrypt(key, {
        nonce: new Uint8Array(AES_256_GCM.nonceLength),
        ciphertext: new Uint8Array(1),
        tag: new Uint8Array(AES_256_GCM.tagLength),
      }),
    ).rejects.toBeInstanceOf(AeadAuthError)
  })

  it('密钥长度不对时在跨桥之前拒绝', async () => {
    const { bridge, calls } = fakeBridge()

    await expect(
      createMobileProviders(bridge).aead.encrypt(new Uint8Array(16), new Uint8Array(0)),
    ).rejects.toBeInstanceOf(CryptoParamsError)
    expect(calls.encrypt).toEqual([])
  })

  it('nonce/tag 长度不对时拒绝解密', async () => {
    const { bridge, calls } = fakeBridge()
    const providers = createMobileProviders(bridge)

    await expect(
      providers.aead.decrypt(key, {
        nonce: new Uint8Array(16),
        ciphertext: new Uint8Array(0),
        tag: new Uint8Array(AES_256_GCM.tagLength),
      }),
    ).rejects.toBeInstanceOf(CryptoParamsError)

    await expect(
      providers.aead.decrypt(key, {
        nonce: new Uint8Array(AES_256_GCM.nonceLength),
        ciphertext: new Uint8Array(0),
        tag: new Uint8Array(8),
      }),
    ).rejects.toBeInstanceOf(CryptoParamsError)

    expect(calls.decrypt).toEqual([])
  })
})

describe('mobile random provider', () => {
  it('长度为 0 合法，长度非负整数直传原生', () => {
    const { bridge, calls } = fakeBridge()
    const { random } = createMobileProviders(bridge)

    expect(random.randomBytes(0)).toHaveLength(0)
    expect(random.randomBytes(32)).toHaveLength(32)
    expect(calls.random).toEqual([0, 32])
  })

  it('负数与非整数长度被拒绝', () => {
    const { bridge } = fakeBridge()
    const { random } = createMobileProviders(bridge)

    expect(() => random.randomBytes(-1)).toThrow(CryptoParamsError)
    expect(() => random.randomBytes(1.5)).toThrow(CryptoParamsError)
  })
})

describe('mobile compress provider', () => {
  it('压缩/解压都走原生，解压失败映射为 CompressError', async () => {
    const { bridge, calls } = fakeBridge({
      gunzip: async () => {
        throw codedError(NATIVE_ERROR_CODES.gzip)
      },
    })
    const { compress } = createMobileProviders(bridge)

    const gz = await compress.compress(Uint8Array.from([1]))
    expect(gz).toEqual(Uint8Array.from([0x1f, 0x8b]))
    expect(calls.gzip).toHaveLength(1)

    await expect(compress.decompress(gz)).rejects.toBeInstanceOf(CompressError)
  })
})

describe('mobile secure store', () => {
  it('读写删直通原生，未写入时返回 null', async () => {
    const { bridge, calls } = fakeBridge()
    const { secureStore } = createMobileProviders(bridge)

    await secureStore.write('mymfa.dek', Uint8Array.from([1, 2]))
    const read = await secureStore.read('mymfa.dek')
    expect(read === null ? null : Array.from(read)).toEqual([4, 5])
    await secureStore.remove('mymfa.dek')

    expect(calls.storeWrite[0]![0]).toBe('mymfa.dek')
    expect(calls.storeRead).toEqual(['mymfa.dek'])
    expect(calls.storeRemove).toEqual(['mymfa.dek'])
  })

  it('空键名在跨桥之前被拒绝', async () => {
    const { bridge, calls } = fakeBridge()
    const { secureStore } = createMobileProviders(bridge)

    await expect(secureStore.read('')).rejects.toBeInstanceOf(CryptoParamsError)
    await expect(secureStore.write('', new Uint8Array(1))).rejects.toBeInstanceOf(CryptoParamsError)
    await expect(secureStore.remove('')).rejects.toBeInstanceOf(CryptoParamsError)
    expect(calls.storeRead).toEqual([])
    expect(calls.storeWrite).toEqual([])
  })

  it('原生安全存储失败映射为 CryptoError，不把原生异常直接抛给上层', async () => {
    const { bridge } = fakeBridge({
      secureStoreRead: async () => {
        throw codedError(NATIVE_ERROR_CODES.secureStore)
      },
    })

    await expect(createMobileProviders(bridge).secureStore.read('k')).rejects.toBeInstanceOf(
      CryptoError,
    )
  })
})

describe('bridge error decoding', () => {
  it('只认结构化 code 字段，不依赖 instanceof', () => {
    expect(nativeErrorCode(codedError('ERR_X'))).toBe('ERR_X')
    expect(nativeErrorCode(new Error('plain'))).toBeUndefined()
    expect(nativeErrorCode('ERR_X')).toBeUndefined()
    expect(nativeErrorCode(null)).toBeUndefined()
  })
})
