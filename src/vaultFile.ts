/**
 * The vault file format — the on-disk/on-storage envelope.
 *
 * Structure (all binary fields are base64-encoded for portability):
 *
 *   kdf:        Argon2id parameters used to derive the key
 *   cipher:     algorithm name + 24-byte nonce
 *   ciphertext: the encrypted vault JSON, with the 16-byte AEAD auth tag
 *               appended (libsodium returns ciphertext||tag as one buffer)
 *
 * The auth tag doubles as password verification: an incorrect master password
 * produces a different key, which yields an invalid tag on decrypt — we surface
 * that as a clear "wrong password" error rather than a vague failure.
 *
 * Note on libsodium's API: crypto_aead_xchacha20poly1305_ietf_encrypt returns a
 * single Uint8Array of `ciphertext || tag` (tag is the last MACBYTES bytes). We
 * store them concatenated and split on decrypt only if we need the parts — but
 * since we always use them together, we keep them as one field.
 */
import { getSodium } from "./sodium.js";
import type { KdfParams } from "./kdf.js";

export interface VaultFile {
  /** File format version, independent of the vault schema version. */
  format: 1;
  kdf: KdfParams;
  cipher: {
    algorithm: "xchacha20-poly1305";
    /** 24-byte nonce, base64. New random nonce on every encrypt. */
    nonce: string;
  };
  /** Encrypted vault payload with auth tag appended, base64. */
  ciphertext: string;
}

export const VAULT_FILE_FORMAT = 1 as const;
/** Length of the Poly1305 auth tag, in bytes. */
export const TAG_BYTES = 16;

/** Encrypt a serialized vault payload (already JSON-stringified bytes). */
export async function encryptVault(
  plaintext: Uint8Array,
  key: Uint8Array,
  kdf: KdfParams,
): Promise<VaultFile> {
  const sodium = await getSodium();
  // 24-byte nonce — large enough that random nonces are collision-free in practice.
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  );
  // libsodium returns ciphertext || tag as a single Uint8Array.
  const combined = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    null, // no additional authenticated data
    null, // no secret nonce
    nonce,
    key,
  );
  return {
    format: VAULT_FILE_FORMAT,
    kdf,
    cipher: {
      algorithm: "xchacha20-poly1305",
      nonce: sodium.to_base64(nonce),
    },
    ciphertext: sodium.to_base64(combined),
  };
}

/** Decrypt a vault file. Throws `WrongPasswordError` if the auth tag is invalid. */
export async function decryptVault(
  file: VaultFile,
  key: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, // no secret nonce
      sodium.from_base64(file.ciphertext), // ciphertext || tag
      null, // no additional authenticated data
      sodium.from_base64(file.cipher.nonce),
      key,
    );
  } catch {
    // libsodium throws a generic error on auth failure; we make the cause explicit.
    // An invalid tag means the key was wrong, which means the password was wrong.
    throw new WrongPasswordError();
  }
}

/** Thrown when decryption's auth tag check fails — i.e. the password is incorrect. */
export class WrongPasswordError extends Error {
  constructor() {
    super("Wrong password (auth tag verification failed).");
    this.name = "WrongPasswordError";
  }
}