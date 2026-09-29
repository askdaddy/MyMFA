export class DomainError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DomainError'
  }
}

export function assertNow(now: number): void {
  if (!Number.isSafeInteger(now) || now < 0) throw new DomainError('时间必须是非负安全整数')
}
