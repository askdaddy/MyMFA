import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  parseAegis,
  parseBitwarden,
  parseEnte,
  parseFreeOtpPlus,
  parseGaMigration,
  parseTwoFas,
  type ImportResult,
} from '../index.js'

const file = (name: string): Uint8Array =>
  new Uint8Array(readFileSync(new URL(`../__fixtures__/${name}`, import.meta.url)))
const ga = (name: string): string =>
  (
    JSON.parse(
      readFileSync(new URL(`../__fixtures__/ga_${name}.json`, import.meta.url), 'utf8'),
    ) as { cases: { uri: string }[] }
  ).cases[0]!.uri

function expected(run: () => ImportResult): unknown {
  try {
    const result = run()
    return {
      format: result.format,
      entries: result.entries.map((entry) => ({
        issuer: entry.issuer,
        account: entry.account,
        kind: entry.kind,
        algo: entry.algo,
        digits: entry.digits,
        value: entry.kind === 'totp' ? entry.period : entry.counter,
        tagNames: entry.tagNames,
        sourceIndex: entry.sourceIndex,
      })),
      tags: result.tags,
      failures: result.failures,
      warnings: result.warnings,
      skipped: result.skipped,
    }
  } catch (error) {
    if (!(error instanceof Error)) throw error
    return { error: error.name, message: error.message }
  }
}

describe('一手夹具的版本化 golden 快照（不记录 secret）', () => {
  const cases: readonly [string, () => ImportResult][] = [
    ['aegis-normal', () => parseAegis(file('aegis_plain.json'))],
    ['aegis-edge', () => parseAegis(file('aegis_edge.json'))],
    ['aegis-malformed', () => parseAegis(file('aegis_malformed.json'))],
    ['2fas-normal', () => parseTwoFas(file('2fas_authenticator_plain_v4.2fas'))],
    ['2fas-edge', () => parseTwoFas(file('twofas_edge.json'))],
    ['2fas-malformed', () => parseTwoFas(file('twofas_malformed.json'))],
    ['freeotp-normal', () => parseFreeOtpPlus(file('freeotp_plus.json'))],
    ['freeotp-edge', () => parseFreeOtpPlus(file('freeotp_plus_edge.json'))],
    ['freeotp-malformed', () => parseFreeOtpPlus(file('freeotp_plus_malformed.json'))],
    ['ente-normal', () => parseEnte(file('ente_auth.txt'))],
    ['ente-edge', () => parseEnte(file('ente_edge.txt'))],
    ['ente-malformed', () => parseEnte(new Uint8Array([0]))],
    ['bitwarden-normal', () => parseBitwarden(file('bitwarden.csv'))],
    ['bitwarden-edge', () => parseBitwarden(file('bitwarden_edge.csv'))],
    ['bitwarden-malformed', () => parseBitwarden(file('bitwarden_malformed.csv'))],
    ['ga-normal', () => parseGaMigration(ga('normal'))],
    ['ga-edge', () => parseGaMigration(ga('edge'))],
    ['ga-malformed', () => parseGaMigration(ga('malformed'))],
  ]
  it.each(cases)('%s', (name, run) => {
    expect(expected(run)).toMatchSnapshot(name)
  })
})
