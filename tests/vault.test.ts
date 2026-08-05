/**
 * Vault core tests — round-trip crypto and the security invariants that matter.
 *
 * These are the tests that catch the catastrophic bugs: a wrong password must
 * be detected, round-trip must be lossless, and the file must not leak the key.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  UnlockedVault,
  WrongPasswordError,
  encryptVault,
  decryptVault,
  createKdfParams,
  deriveKey,
  newEntryId,
  createEmptyVault,
} from "../src/index.js";
import { kdfMemoryBytes } from "../src/kdf.js";

const MASTER = "correct horse battery staple";

test("new KDF parameters allocate the documented 64 MiB", async () => {
  const params = await createKdfParams();
  assert.equal(params.memoryUnit, "kib");
  assert.equal(kdfMemoryBytes(params), 64 * 1024 * 1024);
  // v0.1.0 envelopes omitted the marker and retain their legacy byte meaning.
  assert.equal(kdfMemoryBytes({ memorySize: 65536 }), 65536);
});

test("round-trip: create → lock → unlock preserves entries", async () => {
  const vault = await UnlockedVault.create(MASTER);
  vault.add({
    url: "https://example.com",
    username: "alice",
    password: "s3cret",
    notes: "personal",
  });
  const locked = await vault.lock();
  vault.wipeKey();

  const reopened = await UnlockedVault.unlock(locked, MASTER);
  const entries = reopened.list();
  assert.equal(entries.length, 1);
  assert.equal(entries[0].url, "https://example.com");
  assert.equal(entries[0].username, "alice");
  assert.equal(entries[0].password, "s3cret");
  assert.equal(entries[0].notes, "personal");
  reopened.wipeKey();
});

test("wrong master password is detected, not a silent corrupt decrypt", async () => {
  const vault = await UnlockedVault.create(MASTER);
  vault.add({ url: "https://x.io", username: "u", password: "p" });
  const locked = await vault.lock();
  vault.wipeKey();

  await assert.rejects(
    () => UnlockedVault.unlock(locked, "totally wrong password"),
    (err: unknown) => err instanceof WrongPasswordError,
  );
});

test("two vaults get different salts (no cross-vault key reuse)", async () => {
  const a = await createKdfParams();
  const b = await createKdfParams();
  assert.notEqual(a.salt, b.salt);
  const keyA = await deriveKey(MASTER, a);
  const keyB = await deriveKey(MASTER, b);
  // Same password, different salts → different keys.
  assert.notDeepEqual(Array.from(keyA), Array.from(keyB));
});

test("locking twice produces different nonces (no nonce reuse)", async () => {
  const vault = await UnlockedVault.create(MASTER);
  vault.add({ url: "https://a.io", username: "u", password: "p" });
  const l1 = await vault.lock();
  const l2 = await vault.lock();
  assert.notEqual(l1.cipher.nonce, l2.cipher.nonce);
  vault.wipeKey();
});

test("decrypt with a tampered ciphertext fails (auth tag integrity)", async () => {
  const vault = await UnlockedVault.create(MASTER);
  vault.add({ url: "https://t.io", username: "u", password: "p" });
  const locked = await vault.lock();
  vault.wipeKey();

  // Flip a byte in the base64 ciphertext → auth tag must catch it.
  const tampered = { ...locked, ciphertext: locked.ciphertext.slice(0, -2) + "AA" };
  const key = await deriveKey(MASTER, locked.kdf);
  await assert.rejects(() => decryptVault(tampered, key));
});

test("update bumps updatedAt and preserves id/createdAt", async () => {
  const vault = await UnlockedVault.create(MASTER);
  const entry = vault.add({ url: "https://u.io", username: "u", password: "p" });
  const updated = vault.update(entry.id, { password: "newpass" });
  assert.ok(updated);
  assert.equal(updated!.id, entry.id);
  assert.equal(updated!.createdAt, entry.createdAt);
  assert.equal(updated!.password, "newpass");
  assert.ok(updated!.updatedAt >= entry.updatedAt);
  vault.wipeKey();
});

test("remove actually removes", async () => {
  const vault = await UnlockedVault.create(MASTER);
  const entry = vault.add({ url: "https://r.io", username: "u", password: "p" });
  assert.equal(vault.list().length, 1);
  assert.equal(vault.remove(entry.id), true);
  assert.equal(vault.list().length, 0);
  assert.equal(vault.remove(entry.id), false); // already gone
  vault.wipeKey();
});

test("newEntryId produces unique ids", () => {
  const ids = new Set<string>();
  for (let i = 0; i < 1000; i++) ids.add(newEntryId());
  assert.equal(ids.size, 1000);
});

test("empty vault round-trips cleanly", async () => {
  const vault = await UnlockedVault.create(MASTER);
  const locked = await vault.lock();
  vault.wipeKey();
  const reopened = await UnlockedVault.unlock(locked, MASTER);
  assert.equal(reopened.list().length, 0);
  reopened.wipeKey();
});

test("encryptVault/decryptVault directly: plaintext bytes are preserved", async () => {
  const { getSodium } = await import("../src/sodium.js");
  const sodium = await getSodium();
  const kdf = await createKdfParams();
  const key = await deriveKey(MASTER, kdf);
  const message = sodium.from_string(JSON.stringify(createEmptyVault()));
  const file = await encryptVault(message, key, kdf);
  const out = await decryptVault(file, key);
  assert.deepEqual(Array.from(out), Array.from(message));
});
