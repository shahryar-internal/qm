import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  ConnectorReadinessController,
  connectorReadinessSummary,
  connectorUiState,
  parseConnectorProviders,
} from "../src/connector-readiness.ts";

const chat = readFileSync(new URL("../src/chat.ts", import.meta.url), "utf8");
const shell = readFileSync(new URL("../src/shell.ts", import.meta.url), "utf8");

test("connector presentation derives every state from the current status payload", () => {
  assert.equal(connectorUiState({ connected: true, available: true }), "connected");
  assert.equal(connectorUiState({ connected: true, needsReconnect: true, available: true }), "blocked");
  assert.equal(connectorUiState({ connected: false, available: true }), "disconnected");
  assert.equal(connectorUiState({ connected: false, available: false }), "disabled");
  assert.deepEqual(
    connectorReadinessSummary({
      google: { connected: true, available: true },
      slack: { connected: true, needsReconnect: true, available: true },
      notion: { available: true },
      github: { available: false },
    }),
    { connected: 1, blocked: 1, disconnected: 1, disabled: 1, total: 4 },
  );
});

test("connector payload parsing rejects malformed or unbounded provider records", () => {
  assert.deepEqual(
    parseConnectorProviders({
      google: {
        connected: true,
        available: true,
        hosts: ["calendar.google.com", { host: "drive.google.com" }],
        ignored: "not retained",
      },
    }),
    {
      google: {
        connected: true,
        needsReconnect: undefined,
        available: true,
        hosts: ["calendar.google.com", { host: "drive.google.com" }],
      },
    },
  );
  assert.deepEqual(parseConnectorProviders({}), {});
  assert.throws(() => parseConnectorProviders([]), /invalid connector readiness/);
  assert.throws(() => parseConnectorProviders({ google: {} }), /invalid connector readiness/);
  assert.throws(
    () => parseConnectorProviders({ slack: { connected: "yes", available: true } }),
    /invalid connector readiness/,
  );
  assert.throws(() => parseConnectorProviders({ notion: null }), /invalid connector readiness/);
  assert.throws(
    () => parseConnectorProviders({ "bad key": { connected: true, available: true } }),
    /invalid connector readiness/,
  );
  assert.throws(
    () => parseConnectorProviders({ google: { connected: false, available: true, hosts: ["bad host"] } }),
    /invalid connector readiness/,
  );
  assert.throws(
    () =>
      parseConnectorProviders(
        Object.fromEntries(
          Array.from({ length: 10_000 }, (_, index) => [`provider-${index}`, { connected: false, available: false }]),
        ),
      ),
    /invalid connector readiness/,
  );
  assert.throws(
    () => parseConnectorProviders({ google: { connected: false, available: false, ignored: "x".repeat(20_000) } }),
    /invalid connector readiness/,
  );
});

test("malformed readiness becomes unavailable while an exact empty map remains authoritative", async () => {
  for (const response of [null, false, 0, "", "unavailable", [], {}, { providers: { google: {} } }]) {
    const invalid = new ConnectorReadinessController();
    await invalid.refresh(async () => response);
    assert.deepEqual(invalid.state, { kind: "error" });
  }

  const empty = new ConnectorReadinessController();
  await empty.refresh(async () => ({ providers: {} }));
  assert.deepEqual(empty.state, { kind: "ready", providers: {} });
});

test("an auth transition fences a late response and permits only the new principal result", async () => {
  const controller = new ConnectorReadinessController();
  let finish!: (value: unknown) => void;
  const priorRequest = controller.refresh(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  controller.reset();
  await controller.refresh(async () => ({ providers: { google: { connected: false, available: true } } }));
  finish({ providers: { google: { connected: true, available: true } } });
  await priorRequest;
  assert.deepEqual(controller.state, {
    kind: "ready",
    providers: { google: { connected: false, needsReconnect: undefined, available: true, hosts: undefined } },
  });
});

test("chat connection claims require the authenticated status endpoint", () => {
  assert.match(chat, /connectorReadiness\.refresh\(\s*\(\) => api\("\/api\/connectors"\)/);
  assert.match(chat, /state === "connected"/);
  assert.match(chat, /state === "disabled"/);
  assert.match(chat, /state === "blocked"/);
  assert.doesNotMatch(chat, /connectedConnectors|markConnectorConnected/);
  assert.match(shell, /void refreshConnectorReadiness\(\)/);
});

test("new-user readiness is explicit about unavailable status and configured access", () => {
  assert.match(chat, /Workspace readiness/);
  assert.match(chat, /Only tools your workspace has configured and you have connected can be used/);
  assert.match(chat, /Tool status is unavailable/);
  assert.doesNotMatch(chat, /work across your connected tools/);
});
