import { CompressError } from '@askdaddy/crypto'
import type { CompressProvider } from '@askdaddy/crypto'

/**
 * 走 `Blob#stream()` 而不是 `getWriter().write()`：后者在负载超过流的内部队列时，
 * 写入端会在读取端开始消费之前就被背压阻塞，形成死锁。Blob 的流由平台负责分段供给。
 */
function pipeThrough(
  bytes: Uint8Array,
  transform: CompressionStream | DecompressionStream,
): Promise<Uint8Array> {
  // 窄化断言而非拷贝，理由同 aead.ts 的 bufferSource：拷贝会多出一份没人负责清零的副本。
  const part = bytes as Uint8Array<ArrayBuffer>
  return new Response(new Blob([part]).stream().pipeThrough(transform))
    .arrayBuffer()
    .then((buffer) => new Uint8Array(buffer))
}

export const webCompressProvider: CompressProvider = {
  name: 'gzip',

  compress(bytes: Uint8Array): Promise<Uint8Array> {
    return pipeThrough(bytes, new CompressionStream('gzip'))
  },

  async decompress(bytes: Uint8Array): Promise<Uint8Array> {
    try {
      return await pipeThrough(bytes, new DecompressionStream('gzip'))
    } catch {
      // 平台抛出的 TypeError 文本在各端不一致，且可能带上输入片段；统一成一条固定提示。
      // 调用方（vault）会把它归并进「文件已损坏，或主密码不正确」，此处不得泄露更多。
      throw new CompressError('gzip 解压失败：输入不是合法的 gzip 字节流')
    }
  },
}
