import assert from "node:assert/strict";
import test from "node:test";
import { parseKeychainOverview } from "../src/keychain-overview.ts";

const empty = {
  credentials: [],
  connectorCredentials: [],
  grants: [],
  asks: [],
  usage: [],
  scopeNames: {},
};

test("an exact empty keychain overview remains an authoritative empty state", () => {
  assert.deepEqual(parseKeychainOverview(empty), empty);
});

test("malformed or oversized keychain overview collections fail closed", () => {
  assert.throws(() => parseKeychainOverview({ ...empty, credentials: null }), /invalid keychain overview/);
  assert.throws(() => parseKeychainOverview({ ...empty, credentials: [{}] }), /invalid keychain overview/);
  assert.throws(
    () =>
      parseKeychainOverview({ ...empty, credentials: Array.from({ length: 501 }, () => ({ id: "x", service: "x" })) }),
    /invalid keychain overview/,
  );
  assert.throws(
    () =>
      parseKeychainOverview({ ...empty, connectorCredentials: [{ credentialId: "x", host: "x", connected: "yes" }] }),
    /invalid keychain overview/,
  );
  assert.throws(() => parseKeychainOverview({ ...empty, scopeNames: [] }), /invalid keychain overview/);
  assert.throws(() => parseKeychainOverview({ ...empty, ignored: "x".repeat(262_145) }), /invalid keychain overview/);
  for (const createdAt of [-1, 1.5, 1e308, 8_640_000_000_000_001]) {
    assert.throws(
      () => parseKeychainOverview({ ...empty, credentials: [{ id: "x", service: "x", createdAt }] }),
      /invalid keychain overview/,
    );
  }
});

test("the overview parser retains only the bounded fields the Keychain renders", () => {
  assert.deepEqual(
    parseKeychainOverview({
      ...empty,
      credentials: [{ id: "cred-1", service: "GitHub", kind: "token", ignored: "not retained" }],
      connectorCredentials: [{ credentialId: "connector-1", host: "github.com", connected: true }],
      scopeNames: { "personal:alice": "Alice" },
    }),
    {
      ...empty,
      credentials: [
        {
          id: "cred-1",
          service: "GitHub",
          kind: "token",
          envKey: undefined,
          accountLabel: undefined,
          host: undefined,
          fingerprint: undefined,
          expiresAt: undefined,
          createdAt: undefined,
        },
      ],
      connectorCredentials: [
        {
          credentialId: "connector-1",
          host: "github.com",
          connected: true,
          needsReconnect: undefined,
          accountType: undefined,
          expiresAt: undefined,
        },
      ],
      scopeNames: { "personal:alice": "Alice" },
    },
  );
});
