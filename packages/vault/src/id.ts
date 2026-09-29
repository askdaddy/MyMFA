import type { RandomProvider } from '@askdaddy/crypto'

const HEX = '0123456789abcdef'

/**
 * RFC 9562 的 UUID v7。不用 `uuid` 包（AGENTS.md §6 不引入需求外依赖），
 * 也不读 `crypto` 全局——随机源一律来自注入的 Provider，与仓库其余部分一致。
 *
 * 同一毫秒内的唯一性靠 74 位随机（`rand_a` 12 位 + `rand_b` 62 位）保证，不做单调计数器：
 * 计数器需要模块级可变状态，而 vault 层明确禁止任何模块级可变变量（C8，防解锁尝试计数）。
 * 1000 个同毫秒 id 的碰撞概率约 2.7e-17。
 */
export function uuidV7(random: RandomProvider, now: number = Date.now()): string {
  const bytes = random.randomBytes(16)
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)

  // 前 48 bit 是大端 Unix 毫秒。
  view.setUint16(0, Math.floor(now / 2 ** 32))
  view.setUint32(2, now >>> 0)

  bytes[6] = (bytes[6]! & 0x0f) | 0x70 // version 7
  bytes[8] = (bytes[8]! & 0x3f) | 0x80 // variant RFC 4122

  let hex = ''
  for (let i = 0; i < 16; i += 1) {
    const byte = bytes[i]!
    hex += HEX[byte >> 4]! + HEX[byte & 0x0f]!
  }

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}
