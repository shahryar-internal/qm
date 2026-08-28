import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalPayload, signRequest } from "../src/auth/source-auth-sign.ts";
import { createSignedPrivateTurnObserver } from "../src/api/signed-private-turn-observer.ts";
import type { PrivateTurnObservation } from "../src/api/private-turn-observer.ts";

const secret = "private-turn-observer-signing-secret-0123456789";
const observation: PrivateTurnObservation = {
  source: "web_chat",
  eventRef: `qm-private-turn:${"a".repeat(64)}`,
  conversationRef: "web:owner:private",
  principalRef: "internal:owner",
  audienceRef: "personal:internal:owner",
  workspaceRef: "org:default-org",
  observedAt: "2026-08-28T00:00:00.000Z",
  inputSha256: "b".repeat(64),
};

test("signed private-turn observer sends a redirect-refusing idempotent canonical request", async () => {
  let captured: { url: string; init: RequestInit } | undefined;
  const observer = createSignedPrivateTurnObserver({
    endpoint: "https://observer.example.test/v1/private-turns?tenant=default",
    signingSecret: secret,
    now: () => 1_777_593_600_000,
    fetch: async (input, init) => {
      captured = { url: String(input), init: init ?? {} };
      return new Response(null, { status: 202 });
    },
  });
  assert.equal(await observer.observe(observation), "accepted");
  assert.equal(captured?.url, "https://observer.example.test/v1/private-turns?tenant=default");
  assert.equal(captured?.init.method, "POST");
  assert.equal(captured?.init.redirect, "error");
  const body = captured?.init.body as string;
  assert.equal(body.includes("private secret"), false);
  const headers = captured?.init.headers as Record<string, string>;
  assert.equal(headers["x-idempotency-key"], observation.eventRef);
  assert.equal(headers["x-timestamp"], "1777593600");
  assert.equal(
    headers["x-signature"],
    signRequest(secret, 1_777_593_600, canonicalPayload("POST", "/v1/private-turns?tenant=default", body)),
  );
});

test("signed private-turn observer maps duplicate and retry-safe status classes", async () => {
  for (const [status, expected] of [
    [208, "duplicate"],
    [409, "duplicate"],
    [429, "unconfirmed"],
    [500, "unconfirmed"],
  ] as const) {
    const observer = createSignedPrivateTurnObserver({
      endpoint: "https://observer.example.test/private-turns",
      signingSecret: secret,
      fetch: async () => new Response(null, { status }),
    });
    assert.equal(await observer.observe(observation), expected);
  }
});

test("signed private-turn observer rejects unsafe endpoints and weak secrets", () => {
  for (const endpoint of [
    "http://observer.example.test/private-turns",
    "https://user:pass@observer.example.test/private-turns",
    "https://observer.example.test/private-turns#fragment",
    "https://observer.example.test./private-turns",
  ]) {
    assert.throws(
      () => createSignedPrivateTurnObserver({ endpoint, signingSecret: secret }),
      /endpoint must be an HTTPS URL/u,
    );
  }
  assert.throws(
    () =>
      createSignedPrivateTurnObserver({
        endpoint: "https://observer.example.test/private-turns",
        signingSecret: "short",
      }),
    /at least 32 characters/u,
  );
});
