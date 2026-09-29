import type { Entry } from '@askdaddy/vault'

export interface SiteContext {
  readonly protocol: string
  readonly hostname: string
}
const ipv4 = (host: string): boolean => /^\d+(?:\.\d+){3}$/.test(host)
export function normalizeHostname(value: string): string | undefined {
  let host = value.trim().toLowerCase()
  if (host.includes(':')) {
    const parts = host.split(':')
    if (
      parts.length !== 2 ||
      !/^\d+$/.test(parts[1]!) ||
      Number(parts[1]) < 1 ||
      Number(parts[1]) > 65535
    )
      return undefined
    host = parts[0]!
  }
  if (host.endsWith('.')) host = host.slice(0, -1)
  if (!host || host.length > 253) return undefined
  const labels = host.split('.')
  if (labels.some((label) => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)))
    return undefined
  if (ipv4(host) && labels.some((label) => label.length > 3 || Number(label) > 255))
    return undefined
  return host
}
export function matchesSite(site: string, context: SiteContext, subdomains = true): boolean {
  if (!['https:', 'http:'].includes(context.protocol.toLowerCase())) return false
  const bound = normalizeHostname(site)
  const host = normalizeHostname(context.hostname)
  if (bound === undefined || host === undefined) return false
  return host === bound || (subdomains && !ipv4(bound) && !ipv4(host) && host.endsWith('.' + bound))
}
export function matchingEntries(
  entries: readonly Entry[],
  context: SiteContext,
  subdomains = true,
): Entry[] {
  return entries.filter((entry) =>
    entry.sites.some((site) => matchesSite(site, context, subdomains)),
  )
}
