import { browser } from 'wxt/browser'

/**
 * 剪贴板到期清理（步骤 10，读取路径已在步骤 0 于 Chrome for Testing 151 实测通过）。
 *
 * MV3 service worker 没有 DOM，非聚焦文档的 `navigator.clipboard` 不可靠，
 * 因此沿用官方示例的 `execCommand` 路径：paste 读取 → 仅当内容仍等于本次复制的验证码
 * 时才用 copy 清空。读取失败（pasted=false）时不动剪贴板，由 background 记失败提示。
 *
 * 本文档不承载 vault / OTP 逻辑，也不接收 DEK、主密码或条目 secret。
 */

interface ClearRequest {
  type: 'offscreen-clipboard-clear'
  expected: string
}

interface ClearResult {
  pasted: boolean
  matched: boolean
  cleared: boolean
}

browser.runtime.onMessage.addListener((message: unknown) => {
  if (
    typeof message !== 'object' ||
    message === null ||
    (message as { type?: unknown }).type !== 'offscreen-clipboard-clear'
  ) {
    return undefined
  }
  const expected = String((message as ClearRequest).expected ?? '')

  const workbench = document.querySelector<HTMLTextAreaElement>('#clipboard-workbench')
  if (workbench === null) {
    return Promise.resolve({ pasted: false, matched: false, cleared: false } satisfies ClearResult)
  }

  workbench.value = ''
  workbench.focus()
  workbench.select()
  const pasted = document.execCommand('paste')
  const matched = pasted && workbench.value === expected

  let cleared = false
  if (matched) {
    // Chrome 对空选区的 execCommand('copy') 返回 true 却**不写剪贴板**（实测 153），
    // 验证码会原样留存；写一个空格才是可观测的清空。
    workbench.value = ' '
    workbench.select()
    cleared = document.execCommand('copy')
  }
  workbench.value = ''

  return Promise.resolve({ pasted, matched, cleared } satisfies ClearResult)
})
