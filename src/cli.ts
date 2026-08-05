#!/usr/bin/env node
/**
 * stronghold CLI — a small manual interface to the vault core.
 *
 * Usage:
 *   stronghold init                    create a new empty vault (prompts for master password)
 *   stronghold add <url> <username>    add an entry (prompts for password + master)
 *   stronghold list                    list entry titles/ids (requires master password)
 *   stronghold get <id>                reveal an entry (requires master password)
 *
 * The vault file path defaults to ./vault.json but can be set with STRONGHOLD_VAULT.
 * The vault file is gitignored — never commit it.
 */
import { promises as fs } from "node:fs";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import {
  UnlockedVault,
  type LockedVault,
  type VaultEntry,
} from "./index.js";

const VAULT_PATH = process.env.STRONGHOLD_VAULT ?? "./vault.json";

function question(prompt: string): Promise<string> {
  const rl = createInterface({ input, output });
  return rl.question(prompt).finally(() => rl.close());
}

/** Read a password from a TTY without echoing secret characters. */
async function readPassword(prompt: string): Promise<string> {
  if (!input.isTTY || typeof input.setRawMode !== "function") {
    // Piped input is already controlled by the caller and has no terminal echo.
    return question(prompt);
  }

  output.write(prompt);
  return new Promise((resolve, reject) => {
    let password = "";
    const wasRaw = input.isRaw;

    const cleanup = (): void => {
      input.off("data", onData);
      input.setRawMode(Boolean(wasRaw));
      input.pause();
      output.write("\n");
    };

    const onData = (chunk: Buffer): void => {
      const value = chunk.toString("utf8");
      if (value === "\r" || value === "\n") {
        cleanup();
        resolve(password);
      } else if (value === "\u0003") {
        cleanup();
        reject(new Error("Password entry cancelled."));
      } else if (value === "\u007f" || value === "\b") {
        password = password.slice(0, -1);
      } else if (!value.startsWith("\u001b")) {
        password += value;
      }
    };

    input.setRawMode(true);
    input.resume();
    input.on("data", onData);
  });
}

async function readVaultFile(): Promise<LockedVault> {
  const raw = await fs.readFile(VAULT_PATH, "utf8");
  return JSON.parse(raw) as LockedVault;
}

async function writeVaultFile(locked: LockedVault): Promise<void> {
  await fs.writeFile(VAULT_PATH, JSON.stringify(locked, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
  await fs.chmod(VAULT_PATH, 0o600).catch(() => undefined);
}

async function cmdInit(): Promise<void> {
  const master = await readPassword("Choose a master password: ");
  const confirm = await readPassword("Confirm master password: ");
  if (master !== confirm) {
    console.error("Passwords do not match.");
    process.exit(1);
  }
  if (master.length < 12) {
    console.error("Master password must be at least 12 characters.");
    process.exit(1);
  }
  const vault = await UnlockedVault.create(master);
  const locked = await vault.lock();
  vault.wipeKey();
  await writeVaultFile(locked);
  console.log(`Created empty vault at ${VAULT_PATH}`);
}

async function cmdAdd(url: string, username: string): Promise<void> {
  const secret = await readPassword(`Password for ${username} at ${url}: `);
  const master = await readPassword("Master password: ");
  const locked = await readVaultFile();
  const vault = await UnlockedVault.unlock(locked, master);
  const entry = vault.add({ url, username, password: secret });
  const newLocked = await vault.lock();
  vault.wipeKey();
  await writeVaultFile(newLocked);
  console.log(`Added entry ${entry.id} for ${url}`);
}

async function cmdList(): Promise<void> {
  const master = await readPassword("Master password: ");
  const locked = await readVaultFile();
  const vault = await UnlockedVault.unlock(locked, master);
  vault.wipeKey();
  const entries = vault.list();
  if (entries.length === 0) {
    console.log("(empty vault)");
    return;
  }
  for (const e of entries) {
    console.log(`${e.id}  ${e.username}@${e.url}`);
  }
}

async function cmdGet(id: string): Promise<void> {
  const master = await readPassword("Master password: ");
  const locked = await readVaultFile();
  const vault = await UnlockedVault.unlock(locked, master);
  vault.wipeKey();
  const entry: VaultEntry | undefined = vault.get(id);
  if (!entry) {
    console.error(`No entry with id ${id}`);
    process.exit(1);
  }
  console.log(`url:      ${entry.url}`);
  console.log(`username: ${entry.username}`);
  console.log(`password: ${entry.password}`);
  if (entry.notes) console.log(`notes:    ${entry.notes}`);
}

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2);
  try {
    switch (cmd) {
      case "init":
        return await cmdInit();
      case "add":
        if (args.length < 2) {
          console.error("usage: stronghold add <url> <username>");
          process.exit(1);
        }
        return await cmdAdd(args[0], args[1]);
      case "list":
        return await cmdList();
      case "get":
        if (args.length < 1) {
          console.error("usage: stronghold get <id>");
          process.exit(1);
        }
        return await cmdGet(args[0]);
      default:
        console.error(
          "usage: stronghold <init|add <url> <user>|list|get <id>>",
        );
        process.exit(1);
    }
  } catch (err) {
    if (err instanceof Error && err.name === "WrongPasswordError") {
      console.error("Wrong master password.");
    } else {
      console.error(err);
    }
    process.exit(1);
  }
}

main();
