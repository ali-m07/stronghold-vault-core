/**
 * @ali-m07/stronghold-vault-core — the crypto heart of Stronghold.
 *
 * Public API. Importers should only need this entry point.
 */
export {
  UnlockedVault,
  WrongPasswordError,
  type LockedVault,
} from "./vault.js";
export {
  createKdfParams,
  deriveKey,
  generateSalt,
  DEFAULT_KDF_PARAMS,
  KEY_BYTES,
  type KdfParams,
} from "./kdf.js";
export {
  encryptVault,
  decryptVault,
  VAULT_FILE_FORMAT,
  type VaultFile,
} from "./vaultFile.js";
export {
  createEmptyVault,
  newEntryId,
  VAULT_SCHEMA_VERSION,
  type Vault,
  type VaultEntry,
} from "./types.js";
