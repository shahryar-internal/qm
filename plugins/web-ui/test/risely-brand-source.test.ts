import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../src/shell.css", import.meta.url), "utf8");
const ui = readFileSync(new URL("../src/ui.ts", import.meta.url), "utf8");

test("the Risely preset maps the Command Center light and dark design tokens", () => {
  assert.match(css, /html\[data-brand-preset="risely"\][\s\S]*--background: oklch\(0\.985 0 0\)/);
  assert.match(css, /--brand-accent: #5533e2/i);
  assert.match(css, /html\.dark\[data-brand-preset="risely"\][\s\S]*--background: oklch\(0\.08 0 0\)/);
  assert.match(css, /--brand-accent: #a78bfa/i);
  assert.match(css, /Inter, ui-sans-serif, system-ui/);
  assert.match(css, /\.signin-panel[\s\S]*border-radius: 16px/);
  assert.match(css, /\.composer-wrap:focus-within[\s\S]*var\(--brand-accent\)/);
});

test("the browser lockup can render only the chassis-owned fixed logo", () => {
  assert.match(ui, /brandLogoSvg\(preset\)/);
  assert.match(ui, /unsafeHTML\(logo\)/);
  assert.doesNotMatch(ui, /https?:\/\//);
});
