import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import { TransferError, TransferFormatError } from '../errors.js'
import {
  assertEntryCount,
  assertFieldLength,
  assertInputSize,
  decodeInput,
  parseJson,
  TRANSFER_LIMITS,
} from '../input.js'

const SRC_DIR = fileURLToPath(new URL('../', import.meta.url))

function sourceFiles(dir: string = SRC_DIR): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      // C6 只约束生产代码；测试自身需要可变局部状态。
      if (name === '__tests__' || name === '__fixtures__') continue
      out.push(...sourceFiles(full))
    } else if (name.endsWith('.ts')) {
      out.push(full)
    }
  }
  return out
}

describe('TRANSFER_LIMITS', () => {
  it('每个上限都是有限的正整数', () => {
    for (const [key, value] of Object.entries(TRANSFER_LIMITS)) {
      expect(Number.isSafeInteger(value), `${key} 应为安全整数`).toBe(true)
      expect(value, `${key} 应为正数`).toBeGreaterThan(0)
    }
  })

  it('嵌套深度上限远小于会触发引擎栈溢出的量级', () => {
    expect(TRANSFER_LIMITS.maxNestingDepth).toBeLessThan(1000)
  })
})

describe('C6：生产代码不得持有模块级可变状态', () => {
  it('src/ 下没有任何模块级 let / var 声明', () => {
    const offenders: string[] = []

    for (const file of sourceFiles()) {
      const lines = readFileSync(file, 'utf8').split('\n')
      lines.forEach((line, i) => {
        // 只匹配零缩进的声明：函数体内的 let 是局部状态，不违反 C6。
        if (/^(let|var)\s/.test(line)) offenders.push(`${file}:${i + 1}`)
      })
    }

    expect(offenders).toEqual([])
  })
})

describe('assertInputSize / decodeInput', () => {
  it('超过字节上限时抛 TransferFormatError，且报错发生在解码之前', () => {
    const oversized = new Uint8Array(TRANSFER_LIMITS.maxInputBytes + 1)
    expect(() => assertInputSize(oversized, '备份文件')).toThrow(TransferFormatError)

    // 全 0xFF 不是合法 UTF-8；若闸门在解码之后才生效，这里会先产出一个巨大字符串。
    oversized.fill(0xff)
    expect(() => decodeInput(oversized, '备份文件')).toThrow(/超过上限/)
  })

  it('恰好等于上限时放行', () => {
    expect(() => assertInputSize(new Uint8Array(TRANSFER_LIMITS.maxInputBytes), 'x')).not.toThrow()
  })

  it('非法 UTF-8 序列被替换为 U+FFFD 而不抛错', () => {
    expect(decodeInput(new Uint8Array([0x61, 0xff, 0x62]), 'x')).toBe('a\ufffdb')
  })
})

describe('parseJson', () => {
  it('C4：语法错误的报错不回显输入内容', () => {
    const secret = 'JBSWY3DPEHPK3PXP'
    const broken = `{"secret":"${secret}",}`

    let message = ''
    try {
      parseJson(broken, '备份文件')
    } catch (error) {
      message = (error as Error).message
    }

    expect(message).toContain('不是合法的 JSON')
    expect(message).not.toContain(secret)
    expect(message).not.toContain('JBSWY')
  })

  it('嵌套深度超限时抛错，且不进入 JSON.parse', () => {
    const deep = `${'['.repeat(TRANSFER_LIMITS.maxNestingDepth + 1)}${']'.repeat(
      TRANSFER_LIMITS.maxNestingDepth + 1,
    )}`
    expect(() => parseJson(deep, '备份文件')).toThrow(/嵌套深度/)
  })

  it('字符串字面量里的括号不计入嵌套深度', () => {
    const text = JSON.stringify({ note: `${'['.repeat(500)}${']'.repeat(500)}` })
    expect(parseJson(text, '备份文件')).toEqual({ note: '['.repeat(500) + ']'.repeat(500) })
  })

  it('字符串里被转义的引号不会提前结束字符串状态', () => {
    const text = '{"a":"say \\"hi\\" [[[","b":1}'
    expect(parseJson(text, '备份文件')).toEqual({ a: 'say "hi" [[[', b: 1 })
  })

  it('恰好等于深度上限时放行', () => {
    const atLimit = `${'['.repeat(TRANSFER_LIMITS.maxNestingDepth)}${']'.repeat(
      TRANSFER_LIMITS.maxNestingDepth,
    )}`
    expect(Array.isArray(parseJson(atLimit, 'x'))).toBe(true)
  })
})

describe('assertFieldLength / assertEntryCount', () => {
  it('字段超长时报路径与长度，不报内容', () => {
    const long = 'x'.repeat(TRANSFER_LIMITS.maxFieldLength + 1)
    expect(() => assertFieldLength(long, 'entries[3].note')).toThrow(/entries\[3\]\.note/)
    expect(() => assertFieldLength(long.slice(0, -1), 'x')).not.toThrow()
  })

  it('条目数超限时提示分批导入', () => {
    expect(() => assertEntryCount(TRANSFER_LIMITS.maxEntries + 1, '备份文件')).toThrow(/分批导入/)
    expect(() => assertEntryCount(TRANSFER_LIMITS.maxEntries, '备份文件')).not.toThrow()
  })
})

describe('错误层级', () => {
  it('TransferFormatError 是 TransferError 的子类，且 name 正确', () => {
    const error = new TransferFormatError('x')
    expect(error).toBeInstanceOf(TransferError)
    expect(error).toBeInstanceOf(Error)
    expect(error.name).toBe('TransferFormatError')
  })
})
