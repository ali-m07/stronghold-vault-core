/**
 * Key derivation: master password → 32-byte vault key, via Argon2id.
 *
 * KDF params are a security-vs-usability trade-off:
 *  - Higher memory/iterations = harder to brute-force, but slower to unlock.
 *  - These defaults (64 MiB, 3 iterations) are chosen to take roughly
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
  /** Memory cost. New files use KiB; legacy files without memoryUnit use bytes. */
  memorySize: number;
  /** Unit marker added after v0.1.0 fixed the libsodium byte/KiB mismatch. */
  memoryUnit?: "kib";
  /** Reserved metadata. libsodium.js does not expose lane control. */
  parallelism: number;
}

/** The output key length, in bytes. XChaCha20 wants a 32-byte key. */
export const KEY_BYTES = 32;
const MIN_MEMORY_BYTES = 8 * 1024;
const MAX_MEMORY_BYTES = 1024 * 1024 * 1024;
const MAX_ITERATIONS = 10;

/** Sane defaults for a modern laptop unlock (~300-600ms). */
export const DEFAULT_KDF_PARAMS: Omit<KdfParams, "salt"> = {
  algorithm: "argon2id",
  iterations: 3,
  memorySize: 65536, // 64 MB
  memoryUnit: "kib",
  parallelism: 1,
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
  if (salt.length !== sodium.crypto_pwhash_SALTBYTES) {
    throw new Error("Invalid Argon2id salt length.");
  }
  if (!Number.isSafeInteger(params.iterations) || params.iterations < 1 || params.iterations > MAX_ITERATIONS) {
    throw new Error("Argon2id iterations are outside the supported range.");
  }
  const memoryBytes = kdfMemoryBytes(params);
  return sodium.crypto_pwhash(
    KEY_BYTES,
    masterPassword,
    salt,
    params.iterations,
    memoryBytes,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

/** Normalize persisted KDF memory metadata to libsodium's required byte unit. */
export function kdfMemoryBytes(params: Pick<KdfParams, "memorySize" | "memoryUnit">): number {
  if (!Number.isSafeInteger(params.memorySize) || params.memorySize <= 0) {
    throw new Error("Invalid Argon2id memory size.");
  }
  // v0.1.0 accidentally stored this numeric value as bytes while documenting
  // KiB, so an absent unit retains that legacy meaning for compatibility.
  const bytes = params.memoryUnit === "kib" ? params.memorySize * 1024 : params.memorySize;
  if (!Number.isSafeInteger(bytes) || bytes < MIN_MEMORY_BYTES || bytes > MAX_MEMORY_BYTES) {
    throw new Error("Argon2id memory size is outside the supported range.");
  }
  return bytes;
}

/** Build a full KdfParams (defaults + a fresh salt). Used when creating a new vault. */
export async function createKdfParams(): Promise<KdfParams> {
  return { ...DEFAULT_KDF_PARAMS, salt: await generateSalt() };
}
