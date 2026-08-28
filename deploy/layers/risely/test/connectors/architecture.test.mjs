import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const layerRoot = fileURLToPath(new URL("../..", import.meta.url));
const repositoryRoot = resolve(layerRoot, "../../..");
const connectorRoot = join(layerRoot, "canary", "connectors");
const connectorTestRoot = join(layerRoot, "test", "connectors");
const sourceExtensions = new Set([".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"]);
const scanRoots = Object.freeze([
  join(layerRoot, "canary"),
  join(layerRoot, "test"),
  join(layerRoot, "sandbox"),
  join(layerRoot, "plugins"),
  join(layerRoot, "scripts"),
  join(repositoryRoot, "src"),
  join(repositoryRoot, "plugins"),
  join(repositoryRoot, "scripts"),
  join(repositoryRoot, "cli", "src"),
]);
const indexFiles = new Set([
  "index",
  "index.cjs",
  "index.cts",
  "index.js",
  "index.jsx",
  "index.mjs",
  "index.mts",
  "index.ts",
  "index.tsx",
]);
const trivia = "(?:\\s|/\\*[\\s\\S]*?\\*/|//[^\\r\\n]*(?:\\r?\\n|$))*";
const literalImport = new RegExp(
  `\\b(?:from${trivia}|require${trivia}\\(${trivia}|import${trivia}(?:\\(${trivia})?)([\"'])([^\"']*)\\1`,
  "g",
);

const files = async (directory) => {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        return files(path);
      }
      return entry.isFile() && sourceExtensions.has(extname(entry.name)) ? [path] : [];
    }),
  );
  return nested.flat();
};

const inside = (path, root) => {
  const pathRelative = relative(root, path);
  return (
    pathRelative === "" || (!pathRelative.startsWith(`..${sep}`) && pathRelative !== ".." && !isAbsolute(pathRelative))
  );
};

const literalSpecifiers = (source) => {
  const specifiers = [];
  for (const match of source.matchAll(literalImport)) {
    specifiers.push(match[2]);
  }
  return specifiers;
};

const modulePath = (path, specifier) => {
  if (specifier.startsWith(".")) return resolve(dirname(path), specifier);
  if (specifier.startsWith("/")) return resolve(specifier);
  if (!specifier.startsWith("file:")) return null;
  try {
    return fileURLToPath(specifier);
  } catch {
    return null;
  }
};

const internalConnectorSpecifier = (path, specifier) => {
  const target = modulePath(path, specifier);
  if (!target || !inside(target, connectorRoot)) return false;
  return !indexFiles.has(relative(connectorRoot, target));
};

test("architecture guard recognizes literal static and dynamic connector-internal imports", () => {
  const path = join(layerRoot, "canary", "workflows", "example.mjs");
  const blockTrivia = `/${"*"} literal ${"*"}/`;
  const source = `
    import value from "../connectors/providers.mjs";
    const later = import(${blockTrivia} "../connectors/types.mjs");
    const publicApi = require("../connectors/index.mjs");
  `;
  assert.deepEqual(
    literalSpecifiers(source).map((specifier) => internalConnectorSpecifier(path, specifier)),
    [true, true, false],
  );
});

test("literal connector-internal imports are absent from deployment, plugin, script, and sandbox sources", async () => {
  const candidates = (await Promise.all(scanRoots.map((root) => files(root))))
    .flat()
    .filter((path) => !inside(path, connectorRoot) && !inside(path, connectorTestRoot));
  const violations = [];
  for (const path of candidates) {
    const source = await readFile(path, "utf8");
    for (const specifier of literalSpecifiers(source)) {
      if (internalConnectorSpecifier(path, specifier)) {
        violations.push(`${path}:${specifier}`);
      }
    }
  }
  assert.deepEqual(violations, []);
});
