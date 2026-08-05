/**
 * Local type shim for libsodium-wrappers-sumo.
 *
 * The package ships no .d.ts files of its own and its `exports` map points TS at
 * an ESM `.mjs` entry with no types, so TS reports `any`. The API surface of the
 * `-sumo` build is a strict superset of the non-sumo `libsodium-wrappers` (same
 * functions, plus the extra crypto aead aegis/secretstream/etc. routines). So we
 * reuse the community `@types/libsodium-wrappers` types for the bare specifier.
 */
declare module "libsodium-wrappers-sumo" {
  export * from "libsodium-wrappers";
  import sodium from "libsodium-wrappers";
  export default sodium;
}