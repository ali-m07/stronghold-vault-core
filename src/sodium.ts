/**
 * libsodium loader.
 *
 * libsodium-wrappers-sumo ships a WASM bundle (Argon2id included) that works in
 * both Node and the browser. We expose a single `getSodium()` so callers don't
 * repeat the `await sodium.ready` dance.
 *
 * libsodium-wrappers-sumo >= 0.8 ships working ESM artifacts for both Node and
 * browser bundlers, so one static import keeps the public package isomorphic.
 */
import sodium from "libsodium-wrappers-sumo";

export type Sodium = typeof sodium;

let sodiumReady: Promise<Sodium> | null = null;

/** Returns the libsodium API, ensuring the WASM module is loaded exactly once. */
export async function getSodium(): Promise<Sodium> {
  if (!sodiumReady) {
    sodiumReady = (async () => {
      await sodium.ready;
      return sodium;
    })();
  }
  return sodiumReady;
}
