/**
 * Key derivation: master password → 32-byte vault key, via Argon2id.
 *
 * KDF params are a security-vs-usability trade-off:
 *  - Higher memory/iterations = harder to brute-force, but slower to unlock.
 *  - These defaults (64 MB, 3 iterations, 4 lanes) are chosen to take roughly
 *    300-600ms on a modern laptop — acceptable for an unlock action, painful
 *    for an attacker brute-forcing millions of guesses.
 *
 * Params are stored in the vault file header (see types.ts / vaultFile.ts) so
 * that old files keep opening if we raise them later — no migration needed.
 */
import { getSodium } from "./sodium.js";

/** Tunable Argon2id parameters, persisted in the vault file header. */
export interface KdfParams {
  algorithm: "argon2id";
  /** 16-byte random salt, base64. Prevents rainbow-table / cross-vault attacks. */
  salt: string;
  /** Time cost (number of passes). */
  iterations: number;
  /** Memory cost in KiB. 65536 = 64 MB. */
  memorySize: number;
  /** Parallelism (lanes). */
  parallelism: number;
}

/** The output key length, in bytes. XChaCha20 wants a 32-byte key. */
export const KEY_BYTES = 32;

/** Sane defaults for a modern laptop unlock (~300-600ms). */
export const DEFAULT_KDF_PARAMS: Omit<KdfParams, "salt"> = {
  algorithm: "argon2id",
  iterations: 3,
  memorySize: 65536, // 64 MB
  parallelism: 4,
};

/** Generate a fresh 16-byte salt, base64-encoded. */
export async function generateSalt(): Promise<string> {
  const sodium = await getSodium();
  return sodium.to_base64(sodium.randombytes_buf(16));
}

/**
 * Derive a 32-byte vault key from a master password and KDF params.
 * Returns the key as a Uint8Array. The caller is responsible for not
 * persisting it (keep it in memory only, wipe when done).
 */
export async function deriveKey(
  masterPassword: string,
  params: KdfParams,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  const salt = sodium.from_base64(params.salt);
  return sodium.crypto_pwhash(
    KEY_BYTES,
    masterPassword,
    salt,
    params.iterations,
    params.memorySize,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

/** Build a full KdfParams (defaults + a fresh salt). Used when creating a new vault. */
export async function createKdfParams(): Promise<KdfParams> {
  return { ...DEFAULT_KDF_PARAMS, salt: await generateSalt() };
}
