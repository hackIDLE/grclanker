#!/usr/bin/env node
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const binDir = dirname(fileURLToPath(import.meta.url));
const distEntry = resolve(binDir, "../dist/cli.js");
const srcEntry = resolve(binDir, "../src/cli.ts");

async function importEntry(entryPath) {
  await import(pathToFileURL(entryPath).href);
}

async function run() {
  if (existsSync(distEntry)) {
    await importEntry(distEntry);
    return;
  }

  if (existsSync(srcEntry)) {
    try {
      const { register } = await import("tsx/esm/api");
      register();
      await importEntry(srcEntry);
      return;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`Unable to start grclanker from source: ${message}`);
      process.exit(1);
    }
  }

  console.error("Unable to locate grclanker runtime. Expected dist/cli.js or src/cli.ts next to the package.");
  process.exit(1);
}

run();
