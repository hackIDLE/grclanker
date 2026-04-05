import { resolve } from "node:path";
import { launchCompanion } from "./pi/launch.js";

const appRoot = resolve(import.meta.dirname, "..");

const commands: Record<string, () => Promise<void>> = {
  investigate: () => launchCompanion(appRoot, "investigate"),
  audit: () => launchCompanion(appRoot, "audit"),
  assess: () => launchCompanion(appRoot, "assess"),
  validate: () => launchCompanion(appRoot, "validate"),
};

async function main() {
  const command = process.argv[2];

  if (command === "--help" || command === "-h") {
    console.log(`
grclanker — GRC companion built on Pi

Usage:
  grclanker                     Interactive GRC agent
  grclanker investigate         Vulnerability investigation workflow
  grclanker audit               Compliance audit workflow
  grclanker assess              Posture assessment workflow
  grclanker validate            FIPS validation workflow

Options:
  --help, -h                    Show this help
`);
    return;
  }

  const handler = command ? commands[command] : undefined;
  if (command && !handler) {
    console.error(`Unknown command: ${command}`);
    console.error(`Run 'grclanker --help' for usage`);
    process.exit(1);
  }

  await (handler ?? (() => launchCompanion(appRoot)))();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
