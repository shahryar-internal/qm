import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { JSDOM } from "jsdom";

const core = createServer((req: IncomingMessage, res) => {
  if ((req.url ?? "").startsWith("/v1/surface-config")) {
    res.writeHead(200, { "content-type": "application/json" });
    return void res.end(
      JSON.stringify({ branding: { accent: "#5533E2", mark: "R", selfLabel: "Risely", preset: "risely" } }),
    );
  }
  res.writeHead(200, { "content-type": "application/json" });
  res.end("{}");
});
await new Promise<void>((r) => core.listen(0, r));

process.env.CORE_API_URL = `http://localhost:${(core.address() as AddressInfo).port}`;
process.env.CORE_SIGNING_SECRET = "web-ui-branding-test";
process.env.WEB_UI_PRINCIPALS = "alice";

const distDir = join(dirname(fileURLToPath(import.meta.url)), "..", "dist-web");
const distIndex = join(distDir, "index.html");
if (!existsSync(distIndex)) {
  mkdirSync(distDir, { recursive: true });
  writeFileSync(
    distIndex,
    '<!doctype html><html><head><title>QM · Web</title><meta name="brand-self-label" content="Agent" /><meta name="brand-preset" content="" /></head><body></body></html>',
  );
}

const { handler } = await import("../server/index.ts");
const surface = createServer((req, res) => void handler(req, res));
await new Promise<void>((r) => surface.listen(0, r));
const base = `http://localhost:${(surface.address() as AddressInfo).port}`;

test.after(() => {
  surface.close();
  core.close();
});

test("cold start: the FIRST shell render already carries the complete safe preset", async () => {
  const r = await fetch(`${base}/`, { headers: { cookie: "webuiuser=alice" } });
  assert.equal(r.status, 200);
  const html = await r.text();
  assert.match(html, /--brand-accent:#5533E2/, "accent injected on the first render");
  assert.match(html, /--brand-mark:"R"/, "mark injected on the first render");
  assert.match(
    html,
    /<meta name="brand-self-label" content="Risely"\s*\/?>/,
    "self-label meta injected regardless of template formatting",
  );
  assert.match(html, /<html data-brand-preset="risely"/);
  assert.match(html, /<meta name="brand-preset" content="risely"\s*\/?>/);
  assert.match(html, /<title>Risely · Web<\/title>/);
});

test("the vite template carries the self-label anchor the server injects into", () => {
  const template = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  assert.match(template, /<meta name="brand-self-label" content="QM"\s*\/?>/);
  assert.match(template, /<meta name="brand-preset" content=""\s*\/?>/);
});

test("injectBranding rewrites the tab title with the escaped label when a suffix is given", async () => {
  const { injectBranding } = await import("../../chassis/src/branding.ts");
  const shell =
    '<!doctype html><html><head><title>QM · Web</title><meta name="brand-self-label" content="Agent" /></head><body></body></html>';
  const branded = injectBranding(shell, { selfLabel: "straylight" }, { titleSuffix: "· Web" });
  assert.match(branded, /<title>straylight · Web<\/title>/);
  assert.match(injectBranding(shell, {}, { titleSuffix: "· Web" }), /<title>QM · Web<\/title>/);
  const hostile = injectBranding(shell, { selfLabel: "x</title><script>alert(1)</script>" }, { titleSuffix: "· Web" });
  assert.doesNotMatch(hostile, /<script>/i);
  assert.match(hostile, /<title>x&lt;\/title&gt;/);
  const unsafePreset = injectBranding(shell, {
    preset: "https://evil.test/logo.svg" as "risely",
    accent: "red}</style><script>alert(1)</script>",
  });
  assert.doesNotMatch(unsafePreset, /evil\.test|<script>|data-brand-preset/);
});

test("the preset favicon is the authoritative fixed Risely rocket", async () => {
  const r = await fetch(`${base}/favicon.svg`);
  assert.equal(r.status, 200);
  const svg = await r.text();
  assert.match(svg, /viewBox="0 0 49 48"/);
  assert.match(svg, /#5533E2/);
  assert.match(svg, /#2F1E7F/);
  assert.match(svg, /#FF707E/);
  assert.match(svg, /M18\.1746 18\.3541H22\.1289/);
  assert.doesNotMatch(svg, /<text/);
});

test("brandName() reads the injected self-label and falls back to the product name", async () => {
  const ui = await import("../src/ui.ts");
  const brandName = (ui as { brandName?: () => string }).brandName;
  assert.equal(typeof brandName, "function", "ui.ts exports brandName()");
  const dom = new JSDOM('<head><meta name="brand-self-label" content="Acme"></head>');
  (globalThis as { document?: Document }).document = dom.window.document;
  try {
    assert.equal(brandName!(), "Acme");
  } finally {
    delete (globalThis as { document?: Document }).document;
  }
  assert.equal(brandName!(), "QM");
});

test("brandMark uses only the fixed preset logo and neutral fallback", async () => {
  const { brandLogoSvg, brandPreset } = await import("../../chassis/src/branding.ts");
  assert.equal(brandPreset("risely"), "risely");
  assert.equal(brandPreset("https://evil.test/logo.svg"), undefined);
  const logo = brandLogoSvg(brandPreset("risely"));
  assert.match(logo, /class="brand-logo"/);
  assert.match(logo, /M20\.328 33\.3886/);
  assert.match(logo, /x1="46\.823" y1="2\.83764e-06" x2="2\.19791" y2="46\.3463"/);
  assert.match(logo, /stop-opacity="0\.909804"/);
  assert.equal(brandLogoSvg(brandPreset("<svg onload=alert(1)>")), "");
});
