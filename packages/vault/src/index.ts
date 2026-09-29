export { createVault, openVault } from './container.js'
export {
  VaultAuthError,
  VaultFormatError,
  VaultLockedError,
  VaultSchemaError,
  VaultVersionError,
} from './errors.js'
export { assertVaultData } from './guard.js'
export { uuidV7 } from './id.js'
export { assertContainerVersion, migrateVaultData } from './migrate.js'
export {
  CONTAINER_FORMAT,
  CONTAINER_VERSION,
  DEFAULT_SETTINGS,
  ENTRY_ALGORITHMS,
  SCHEMA_VERSION,
  type CipherHeader,
  type CreateVaultOptions,
  type CryptoHeader,
  type EncryptedContainer,
  type Entry,
  type EntryAlgorithm,
  type EntryKind,
  type KdfHeader,
  type Settings,
  type Tag,
  type VaultData,
  type VaultHandle,
  type VaultMeta,
  type VaultProviders,
  type WrappedKeyHeader,
} from './types.js'
