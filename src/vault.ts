/**
 * High-level vault API.
 *
 * `LockedVault` is an encrypted file you can store safely. `UnlockedVault`
 * holds the decrypted vault in memory plus the derived key, and lets you
 * mutate entries. Call `lock()` to re-encrypt and get back a `LockedVault`,
 * after which the in-memory key and plaintext should be dropped.
 *
 * This boundary is what the extension's service worker and the Node CLI both
 * consume — keeping crypto logic in one place.
 */
import { getSodium } from "./sodium.js";
import { createKdfParams, deriveKey, type KdfParams } from "./kdf.js";
import {
  decryptVault,
  encryptVault,
  type VaultFile,
  WrongPasswordError,
} from "./vaultFile.js";
import {
  createEmptyVault,
  newEntryId,
  type Vault,
  type VaultEntry,
} from "./types.js";

/** An encrypted vault file — safe to persist to disk or chrome.storage. */
export type LockedVault = VaultFile;

/** A vault held in memory with its derived key, ready for read/write. */
export class UnlockedVault {
  private constructor(
    private vault: Vault,
    private key: Uint8Array,
    private kdf: KdfParams,
  ) {}

  /** Create a brand-new empty vault with a fresh salt and key. */
  static async create(masterPassword: string): Promise<UnlockedVault> {
    const kdf = await createKdfParams();
    const key = await deriveKey(masterPassword, kdf);
    return new UnlockedVault(createEmptyVault(), key, kdf);
  }

  /** Unlock an existing encrypted vault file with the master password. */
  static async unlock(
    locked: LockedVault,
    masterPassword: string,
  ): Promise<UnlockedVault> {
    const key = await deriveKey(masterPassword, locked.kdf);
    const plaintext = await decryptVault(locked, key);
    const sodium = await getSodium();
    const json = sodium.to_string(plaintext);
    const vault = JSON.parse(json) as Vault;
    return new UnlockedVault(vault, key, locked.kdf);
  }

  /** Re-encrypt and return a safe-to-persist file. Drop the returned key afterwards. */
  async lock(): Promise<LockedVault> {
    const sodium = await getSodium();
    const plaintext = sodium.from_string(JSON.stringify(this.vault));
    return encryptVault(plaintext, this.key, this.kdf);
  }

  /** List all entries (no secret fields redacted — caller is trusted). */
  list(): readonly VaultEntry[] {
    return this.vault.entries;
  }

  /** Find an entry by id. */
  get(id: string): VaultEntry | undefined {
    return this.vault.entries.find((e) => e.id === id);
  }

  /** Add a new entry. Returns the created entry (with generated id + timestamps). */
  add(input: Omit<VaultEntry, "id" | "createdAt" | "updatedAt">): VaultEntry {
    const now = Date.now();
    const entry: VaultEntry = {
      ...input,
      id: newEntryId(),
      createdAt: now,
      updatedAt: now,
    };
    this.vault.entries.push(entry);
    return entry;
  }

  /** Update an existing entry by id. Bumps `updatedAt` (used by LWW sync). */
  update(id: string, patch: Partial<Omit<VaultEntry, "id" | "createdAt">>): VaultEntry | undefined {
    const idx = this.vault.entries.findIndex((e) => e.id === id);
    if (idx === -1) return undefined;
    this.vault.entries[idx] = {
      ...this.vault.entries[idx],
      ...patch,
      id,
      updatedAt: Date.now(),
    };
    return this.vault.entries[idx];
  }

  /** Delete an entry by id. Returns true if something was removed. */
  remove(id: string): boolean {
    const before = this.vault.entries.length;
    this.vault.entries = this.vault.entries.filter((e) => e.id !== id);
    return this.vault.entries.length < before;
  }

  /** Best-effort wipe of the in-memory key. Call after `lock()` if keeping the process alive. */
  wipeKey(): void {
    this.key.fill(0);
  }
}

export { WrongPasswordError };
export type { Vault, VaultEntry, KdfParams };