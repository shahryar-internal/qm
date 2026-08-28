import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const sourceRoot = fileURLToPath(new URL("../../canary/google-broker/", import.meta.url));

const sourceFiles = async (root) => {
  const output = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = resolve(root, entry.name);
    if (entry.isDirectory()) output.push(...(await sourceFiles(path)));
    else if (entry.isFile() && entry.name.endsWith(".mjs")) output.push(path);
  }
  return output.sort();
};

const importGraph = async (entry) => {
  const reached = new Set();
  const visit = async (path) => {
    if (reached.has(path)) return;
    reached.add(path);
    const source = await readFile(path, "utf8");
    const matches = source.matchAll(/(?:from\s+|export\s+\*\s+from\s+)["'](\.\.?\/[^"']+\.mjs)["']/g);
    for (const match of matches) await visit(resolve(dirname(path), match[1]));
  };
  await visit(entry);
  return [...reached].sort();
};

test("index import graph enumerates every provider-free source module", async () => {
  const files = await sourceFiles(sourceRoot);
  const reached = await importGraph(resolve(sourceRoot, "index.mjs"));
  assert.deepEqual(
    reached.map((path) => relative(sourceRoot, path)),
    files.map((path) => relative(sourceRoot, path)),
  );
});

test("every source module excludes provider transport, effects, signing, private-key creation, and comments", async () => {
  for (const file of await sourceFiles(sourceRoot)) {
    const source = await readFile(file, "utf8");
    assert.doesNotMatch(source, /from\s+["']node:(?:http|https|net|tls|child_process)["']/);
    assert.doesNotMatch(source, /\bfetch\s*\(/);
    assert.doesNotMatch(source, /\bcreatePrivateKey\b/);
    assert.doesNotMatch(source, /import\s*\{[^}]*\bsign\b/s);
    assert.doesNotMatch(source, /\bexecute\s*\(/);
    assert.doesNotMatch(source, /(?:^|\n)\s*(?:\/\/|\/\*)/);
    assert.doesNotMatch(source, /\b(?:TODO|FIXME)\b/);
  }
});

test("source exports no authority brand mint, trusted-clock override, executor, or signer", async () => {
  const sources = await Promise.all((await sourceFiles(sourceRoot)).map((file) => readFile(file, "utf8")));
  const source = sources.join("\n");
  assert.doesNotMatch(
    source,
    /export\s+(?:const|function)\s+(?:bindReadAuthority|assertBoundReadAuthority|mintAuthority)/,
  );
  assert.doesNotMatch(source, /maximumReceiptAgeMs|verificationNow|callerNow/);
  assert.doesNotMatch(source, /export\s+(?:const|function)\s+.*(?:Executor|Signer)/);
});
