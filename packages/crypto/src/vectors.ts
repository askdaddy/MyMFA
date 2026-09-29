import { base64Decode, utf8Encode } from './encoding.js'
import type { Argon2idParams } from './params.js'
import { ARGON2ID_PARAMS, ARGON2ID_VERSION } from './params.js'

/**
 * 三端共用的参考向量（docs/testing.md §3.3 步骤 2）。
 *
 * 放在这里而不是各端私存一份，理由与参数常量完全相同：期望值一旦分叉，
 * 两端会各自「通过」自己的向量而互相打不开对方的 vault，这正是本项目最大的技术风险。
 */

/** RFC 9106 §5.3 的 Argon2id 官方向量，唯一能证明「实现本身正确」的输入。 */
export interface Argon2idRfc9106Vector {
  readonly password: Uint8Array
  readonly salt: Uint8Array
  /** 官方向量是 keyed 模式，生产路径不用；`hash-wasm` 无 `associatedData` 入参，故只能由对照实现跑。 */
  readonly secret: Uint8Array
  readonly associatedData: Uint8Array
  readonly params: Argon2idParams
  readonly version: number
  readonly expectedTagHex: string
}

export interface Argon2idProductionVector {
  readonly password: Uint8Array
  readonly salt: Uint8Array
  readonly params: Argon2idParams
  readonly version: number
  readonly expectedKeyHex: string
}

const RFC9106_EXPECTED_TAG_HEX = '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659'

/**
 * `memoryKiB = 32` 远低于生产基线，这是官方向量自带的值。
 * Provider 必须能跑它，所以 `assertArgon2idParams` 只做结构性校验、不比对基线。
 */
export const ARGON2ID_RFC9106_VECTOR = {
  password: new Uint8Array(32).fill(0x01),
  salt: new Uint8Array(16).fill(0x02),
  secret: new Uint8Array(8).fill(0x03),
  associatedData: new Uint8Array(12).fill(0x04),
  params: { memoryKiB: 32, iterations: 3, parallelism: 4, saltLength: 16, keyLength: 32 },
  version: ARGON2ID_VERSION,
  expectedTagHex: RFC9106_EXPECTED_TAG_HEX,
} as const satisfies Argon2idRfc9106Vector

/**
 * 由 P-H-C/phc-winner-argon2 官方参考实现（经 node-argon2）在生产参数下派生，
 * 是移动端 M3 比对时的同一份基线（docs/testing.md §3.3 步骤 2）。
 */
const PRODUCTION_EXPECTED_KEY_HEX =
  'a08af7c53183770da615468c7cace51b2b9c2e9ee0324524f4e4d10bae86e873'

/**
 * 生产参数下的比对向量（docs/testing.md §3.3）。
 *
 * 密码取自公开的 xkcd 口令梗，salt 是固定的可读 ASCII 常量（base64 为 `MyMFAsaltfixture`）——
 * 两者都不是秘密，AGENTS.md §5.3 禁止在夹具中出现真实种子。
 * vault 实际派生走双层密钥模型，只用「主密码 + salt」，因此这里没有 secret 与 associatedData。
 */
export const ARGON2ID_PRODUCTION_VECTOR = {
  password: utf8Encode('correct horse battery staple'),
  salt: base64Decode('TXlNRkFzYWx0Zml4dHVyZQ=='),
  params: ARGON2ID_PARAMS,
  version: ARGON2ID_VERSION,
  expectedKeyHex: PRODUCTION_EXPECTED_KEY_HEX,
} as const satisfies Argon2idProductionVector
