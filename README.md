# @ali-m07/stronghold-vault-core

The isomorphic encryption core used by Stronghold. It derives 256-bit keys with Argon2id and encrypts versioned vault files with XChaCha20-Poly1305.

The default Argon2id cost is three passes over 64 MiB. KDF parameters and their memory unit are stored in every encrypted envelope.

> Security notice: this package has not received an independent security audit. Do not use it as the sole protection for production credentials yet.

## Install

```sh
npm install @ali-m07/stronghold-vault-core --registry=https://npm.pkg.github.com
```

GitHub Packages requires a GitHub token with `read:packages`. You can configure the scope once in `.npmrc`:

```ini
@ali-m07:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

## Usage

```ts
import { UnlockedVault } from "@ali-m07/stronghold-vault-core";

const vault = await UnlockedVault.create("a long master password");
vault.add({
  url: "https://example.com",
  username: "person@example.com",
  password: "secret",
});

const encrypted = await vault.lock();
vault.wipeKey();
```

Only the encrypted `LockedVault` value should be persisted. Master passwords, derived keys, and decrypted entries must remain in memory.

## Development

```sh
npm ci
npm test
npm run build
npm pack --dry-run
```

MIT licensed. See `LICENSE`.
