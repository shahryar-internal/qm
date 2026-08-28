import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const layerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const installedTemplate = resolve(layerRoot, "node_modules/@yc-software/qm/templates/aws/microvm-agent/Dockerfile");
const replacementTemplate = resolve(layerRoot, "aws/microvm-agent/Dockerfile");
const original = readFileSync(installedTemplate);
const replacement = readFileSync(replacementTemplate);

if (!original.includes(Buffer.from("dnf install -y gh-2.97.0-1"))) {
  throw new Error("The pinned QM package no longer has the expected MicroVM image defect");
}

let result;
try {
  writeFileSync(installedTemplate, replacement);
  result = spawnSync("npm", ["run", "qm", "--", "infra", "build-image"], {
    cwd: layerRoot,
    env: process.env,
    stdio: "inherit",
  });
} finally {
  writeFileSync(installedTemplate, original);
}

if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
