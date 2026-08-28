import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const evalRoot = fileURLToPath(new URL("../../canary/evals/", import.meta.url));

const files = async (directory) => {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) paths.push(...(await files(path)));
    else paths.push(path);
  }
  return paths;
};

test("eval foundation has no provider, legacy, or secret dependency", async () => {
  const sources = await Promise.all((await files(evalRoot)).map((path) => readFile(path, "utf8")));
  const text = sources.join("\n");
  assert.doesNotMatch(text, /risely-(?:ops-staging|agentic-os)|legacy runtime/i);
  assert.doesNotMatch(text, /\bfetch\s*\(|process\.env|AWS_SECRET|GEMINI_API_KEY|SLACK_BOT_TOKEN/);
});
