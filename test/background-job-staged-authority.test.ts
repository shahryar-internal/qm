import assert from "node:assert/strict";
import { test } from "node:test";
import { createStagedBackgroundJobAuthority } from "../src/background-jobs/staged-authority.ts";
import type { BackgroundJobAuthoritySigner } from "../src/background-jobs/types.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import type { BackgroundJobAuthorityStageRecord } from "../src/background-jobs/staged-authority.ts";

function authority(kid: string): BackgroundJobAuthoritySigner {
  const token = async () => kid;
  return Object.freeze({
    ready: async () => undefined,
    signPrepare: token,
    signStart: token,
    signStatus: token,
    signCancel: token,
    jwks: () => ({
      keys: [
        Object.freeze({
          kty: "RSA",
          alg: "RS256",
          use: "sig",
          kid,
          n: `modulus-${kid}`,
          e: "AQAB",
        }),
      ],
    }),
  });
}

test("staged authority publishes next before activation, survives restart, and retires previous after overlap", async () => {
  const backing = createMemoryMap<BackgroundJobAuthorityStageRecord>();
  let now = 1_000;
  const build = () =>
    createStagedBackgroundJobAuthority({
      backing,
      recordId: "authority-stage-1",
      durable: true,
      active: { kid: "key-old", signer: authority("key-old") },
      next: { kid: "key-new", signer: authority("key-new") },
      cacheOverlapMs: 60_000,
      tokenLifetimeMs: 10_000,
      now: () => now,
    });
  const staged = build();
  await staged.ready();
  assert.deepEqual(
    staged.jwks().keys.map((key) => key.kid),
    ["key-old", "key-new"],
  );
  assert.equal(
    await staged.signPrepare(
      Buffer.from("{}"),
      { messageTs: "1788030001.000000", threadTs: "1788030001.000000" },
      "request-1",
    ),
    "key-old",
  );
  now += 59_999;
  assert.equal(
    await staged.signPrepare(
      Buffer.from("{}"),
      { messageTs: "1788030001.000000", threadTs: "1788030001.000000" },
      "request-2",
    ),
    "key-old",
  );
  now += 1;
  assert.equal(
    await staged.signPrepare(
      Buffer.from("{}"),
      { messageTs: "1788030001.000000", threadTs: "1788030001.000000" },
      "request-3",
    ),
    "key-new",
  );
  assert.deepEqual(
    staged.jwks().keys.map((key) => key.kid),
    ["key-new", "key-old"],
  );
  const restarted = build();
  await restarted.ready();
  assert.equal(
    await restarted.signPrepare(
      Buffer.from("{}"),
      { messageTs: "1788030001.000000", threadTs: "1788030001.000000" },
      "request-4",
    ),
    "key-new",
  );
  now += 70_000;
  await restarted.ready();
  assert.deepEqual(
    restarted.jwks().keys.map((key) => key.kid),
    ["key-new"],
  );
});

test("staged authority rejects non-durable rotation state", () => {
  assert.throws(() =>
    createStagedBackgroundJobAuthority({
      backing: createMemoryMap<BackgroundJobAuthorityStageRecord>(),
      recordId: "authority-stage-1",
      durable: false,
      active: { kid: "key-old", signer: authority("key-old") },
    }),
  );
});
