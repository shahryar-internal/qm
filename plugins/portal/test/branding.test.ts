import test from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";

process.env.PORTAL_BRAND_NAME = "Risely";
process.env.PORTAL_BRAND_PRESET = "risely";
process.env.PORTAL_PUBLIC_URL = "http://portal.test";

const { connectErrorHtml, server, signInErrorHtml } = await import("../src/index.ts");

test.after(async () => {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

test("portal cards use the Risely lockup, palette, title, and responsive system theme on first render", () => {
  for (const html of [signInErrorHtml("temporary"), connectErrorHtml("temporary")]) {
    assert.match(html, /<html lang="en" data-brand-preset="risely">/);
    assert.match(html, /<title>[^<]+ · Risely<\/title>/);
    assert.match(html, /<div class="brand-lockup">[\s\S]*<svg class="brand-logo"/);
    assert.match(html, /#5533E2/);
    assert.match(html, /font-family:Inter, ui-sans-serif, system-ui/);
    assert.match(html, /prefers-color-scheme:dark/);
    assert.match(html, /#A78BFA/);
  }
});

test("portal serves the exact preset rocket instead of an emoji favicon", async () => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const response = await fetch(`${base}/favicon.svg`);
  assert.equal(response.status, 200);
  const svg = await response.text();
  assert.match(svg, /viewBox="0 0 49 48"/);
  assert.match(svg, /#5533E2/);
  assert.match(svg, /M20\.328 33\.3886/);
  assert.doesNotMatch(svg, /<text/);
});
