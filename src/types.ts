/**
 * Vault data model.
 *
 * This is the plaintext shape that gets encrypted into the vault file.
 * The encrypted envelope wraps a `Vault`.
 */

/** A single stored credential (or other sensitive item). */
export interface VaultEntry {
  /** Stable unique id (UUID v4). Used as the sync key in Phase 3. */
  id: string;
  /** Target site URL. Used for anti-phishing domain matching in the extension. */
  url: string;
  username: string;
  password: string;
  notes?: string;
  /** Optional TOTP secret for 2FA code generation (base32). */
  totpSecret?: string;
  /** Unix epoch ms. */
  createdAt: number;
  /** Unix epoch ms. Last-write-wins uses this field. */
  updatedAt: number;
}

/** The full plaintext vault. Serialized to JSON before encryption. */
export interface Vault {
  /** Schema version, for future migrations. Bump when the shape changes. */
  version: number;
  entries: VaultEntry[];
}

export const VAULT_SCHEMA_VERSION = 1;

/** Create an empty vault. */
export function createEmptyVault(): Vault {
  return { version: VAULT_SCHEMA_VERSION, entries: [] };
}

/** Generate a new entry id. Uses crypto.randomUUID where available (Node ≥ 19, modern browsers). */
export function newEntryId(): string {
  const c = globalThis.crypto as Crypto | undefined;
  if (c && typeof c.randomUUID === "function") {
    return c.randomUUID();
  }
  // Fallback for older runtimes: build a v4 UUID from random bytes.
  const bytes = new Uint8Array(16);
  if (c) {
    c.getRandomValues(bytes);
  } else {
    throw new Error("A cryptographically secure random number generator is required.");
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`;
}
