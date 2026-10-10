/** 创建/导入页的密码强度指示（步骤 6 验收：弱密码仍明确标示强度）。纯启发式，不做字典。 */
export interface Strength {
  score: 0 | 1 | 2 | 3 | 4
  label: string
}

const LABELS: Record<Strength['score'], string> = {
  0: '太短',
  1: '弱',
  2: '一般',
  3: '强',
  4: '很强',
}

export function passwordStrength(password: string): Strength {
  if (password.length < 8) return { score: 0, label: LABELS[0] }
  let score = 1
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z0-9]/].filter((pattern) =>
    pattern.test(password),
  ).length
  if (password.length >= 12 && classes >= 2) score = 2
  if (password.length >= 12 && classes >= 3) score = 3
  if (password.length >= 16 && classes === 4) score = 4
  return { score: score as Strength['score'], label: LABELS[score as Strength['score']] }
}
