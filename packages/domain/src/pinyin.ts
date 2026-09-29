import { pinyin } from 'pinyin-pro'

export const initials = (text: string): string =>
  pinyin(text, { pattern: 'first', toneType: 'none', type: 'array' }).join('')
