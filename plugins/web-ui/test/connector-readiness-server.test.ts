import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

const providerPayload = {
  providers: {
    google: { connected: true, available: true },
    slack: { connected: true, needsReconnect: true, available: true },
    notion: { connected: false, available: true },
    github: { connected: false, available: false },
  },
};
const connectorRequests: string[] = [];
const core = createServer((req, res) => {
  const url = req.url ?? "";
  res.setHeader("content-type", "application/json");
  if (url.startsWith("/v1/surface-config")) return void res.end(JSON.stringify({}));
  if (url.startsWith("/v1/connectors/oauth/status")) {
    connectorRequests.push(url);
    return void res.end(JSON.stringify(providerPayload));
  }
  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not_found" }));
});
await new Promise<void>((resolve) => core.listen(0, resolve));

process.env.CORE_API_URL = `http://127.0.0.1:${(core.address() as AddressInfo).port}`;
process.env.CORE_SIGNING_SECRET = "connector-readiness-server-test-secret";
process.env.ALLOW_UNSIGNED_TEST_IDENTITY = "1";
process.env.NODE_ENV = "test";
process.env.WEB_UI_PRINCIPALS = "alice";

const { handler } = await import("../server/index.ts");
const surface = createServer((req, res) => void handler(req, res));
await new Promise<void>((resolve) => surface.listen(0, resolve));
const base = `http://127.0.0.1:${(surface.address() as AddressInfo).port}`;

test.after(() => {
  surface.close();
  core.close();
});

test("connector readiness is relayed from the authenticated principal's core status contract", async () => {
  const response = await fetch(`${base}/api/connectors`, { headers: { cookie: "webuiuser=alice" } });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), providerPayload);
  assert.equal(connectorRequests.length, 1);
  const path = new URL(connectorRequests[0]!, "http://core.test");
  assert.equal(path.pathname, "/v1/connectors/oauth/status");
  assert.equal(path.searchParams.get("principalId"), "alice");
});

test("connector readiness never reaches core without an authenticated surface principal", async () => {
  const response = await fetch(`${base}/api/connectors`);
  assert.equal(response.status, 401);
  assert.equal(connectorRequests.length, 1);
});
