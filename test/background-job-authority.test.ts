import { test } from "node:test";
import assert from "node:assert/strict";
import { constants, createHash, generateKeyPairSync, privateEncrypt, type JsonWebKey } from "node:crypto";
import {
  GetPublicKeyCommand,
  KeyUsageType,
  MessageType,
  SignCommand,
  SigningAlgorithmSpec,
  type KMSClient,
} from "@aws-sdk/client-kms";
import { createBackgroundJobAuthoritySigner } from "../src/background-jobs/kms-signer.ts";
import { createFixedBackgroundJobClient } from "../src/background-jobs/fixed-client.ts";
import type { BackgroundJobDefinition, BackgroundJobReceipt } from "../src/background-jobs/types.ts";

const DEFINITION: Readonly<BackgroundJobDefinition> = Object.freeze({
  id: "report-preview",
  operation: "report_preview",
  capability: "reports.preview",
  scope: "jobs:submit",
  tokenType: "job-authority+jwt",
  authorityHeader: "x-job-authority",
  prepare: Object.freeze({ path: "/api/jobs/report-preview/prepare", maxRequestBytes: 512 }),
  start: Object.freeze({ path: "/api/jobs/report-preview", maxRequestBytes: 1024 }),
  status: Object.freeze({ path: "/api/jobs/report-preview/status", maxRequestBytes: 512 }),
  cancel: Object.freeze({ path: "/api/jobs/report-preview/cancel", maxRequestBytes: 512 }),
});

const PROFILE = Object.freeze({
  organizationId: "org_example",
  actorPrincipalId: "principal_owner",
  actorSlackId: "UOWNER1",
  audienceScopeId: "personal:principal_owner",
  slackTeamId: "TTEAM01",
  channelId: "DOWNER1",
});

function material() {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const raw = pair.publicKey.export({ format: "jwk" });
  return {
    privateKey: pair.privateKey,
    spki: pair.publicKey.export({ format: "der", type: "spki" }),
    jwk: { kty: "RSA", alg: "RS256", use: "sig", kid: "key-1", n: raw.n, e: raw.e } satisfies JsonWebKey,
  };
}

function fakeKms(value: ReturnType<typeof material>, mode: "ok" | "get-fail" | "sign-fail" | "bad-sign" = "ok") {
  const prefix = Buffer.from("3031300d060960864801650304020105000420", "hex");
  return {
    async send(command: unknown) {
      if (command instanceof GetPublicKeyCommand) {
        if (mode === "get-fail") throw new Error("private-get-detail");
        return {
          PublicKey: value.spki,
          KeyUsage: KeyUsageType.SIGN_VERIFY,
          SigningAlgorithms: [SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256],
        };
      }
      assert.ok(command instanceof SignCommand);
      if (mode === "sign-fail") throw new Error("private-sign-detail");
      assert.equal(command.input.MessageType, MessageType.DIGEST);
      const signature = privateEncrypt(
        { key: value.privateKey, padding: constants.RSA_PKCS1_PADDING },
        Buffer.concat([prefix, Buffer.from(command.input.Message!)]),
      );
      if (mode === "bad-sign") signature[0] = signature[0]! ^ 1;
      return { Signature: signature, SigningAlgorithm: SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256 };
    },
  } as unknown as KMSClient;
}

function makeSigner(value = material(), mode: "ok" | "get-fail" | "sign-fail" | "bad-sign" = "ok") {
  let nonce = 0;
  return createBackgroundJobAuthoritySigner(
    {
      issuer: "https://gateway.example/authority",
      audience: "https://jobs.example/authority",
      keyId: "kms-key-1",
      tokenKid: "key-1",
      publicJwk: value.jwk,
      profile: PROFILE,
      definition: DEFINITION,
      lifetimeSeconds: 300,
    },
    { kms: fakeKms(value, mode), now: () => 1_788_030_000_000, randomId: () => `nonce_${++nonce}` },
  );
}

function decode(token: string) {
  const [header, claims, signature, extra] = token.split(".");
  assert.ok(header && claims && signature);
  assert.equal(extra, undefined);
  return {
    header: JSON.parse(Buffer.from(header, "base64url").toString("utf8")) as Record<string, unknown>,
    claims: JSON.parse(Buffer.from(claims, "base64url").toString("utf8")) as Record<string, unknown>,
  };
}

test("generic KMS authority signs exact configured claims and exposes only the configured public JWK", async () => {
  const signer = makeSigner();
  const body = Buffer.from('{"report":"weekly"}');
  const { header, claims } = decode(await signer.signStart(body, "1788030000.123456", "decision-123"));
  assert.deepEqual(header, { alg: "RS256", kid: "key-1", typ: DEFINITION.tokenType });
  assert.deepEqual(claims, {
    actorPrincipalId: PROFILE.actorPrincipalId,
    actorSlackId: PROFILE.actorSlackId,
    aud: "https://jobs.example/authority",
    audienceScopeId: PROFILE.audienceScopeId,
    capability: DEFINITION.capability,
    channelId: PROFILE.channelId,
    exp: 1_788_030_300,
    httpMethod: "POST",
    httpPath: DEFINITION.start.path,
    iat: 1_788_030_000,
    idempotencyKey: "decision-123",
    iss: "https://gateway.example/authority",
    jti: "nonce_1",
    operation: DEFINITION.operation,
    organizationId: PROFILE.organizationId,
    payloadSha256: createHash("sha256").update(body).digest("hex"),
    requestId: "nonce_2",
    scope: DEFINITION.scope,
    slackTeamId: PROFILE.slackTeamId,
    sub: PROFILE.actorPrincipalId,
    threadTs: "1788030000.123456",
  });
  assert.equal(typeof claims.aud, "string");
  assert.deepEqual(Object.keys(signer.jwks().keys[0]!).sort(), ["alg", "e", "kid", "kty", "n", "use"]);
});

test("status and cancel use fixed configured paths, stable control idempotency, and fresh request nonces", async () => {
  const signer = makeSigner();
  const body = Buffer.from('{"authorityId":"authority-1","runId":"run-0000001"}');
  const prepare = decode(await signer.signPrepare(Buffer.from("{}"), "1788030000.123456", "decision-123")).claims;
  const first = decode(await signer.signStatus(body, "1788030000.123456")).claims;
  const second = decode(await signer.signStatus(body, "1788030000.123456")).claims;
  const cancel = decode(await signer.signCancel(body, "1788030000.123456")).claims;
  assert.equal(prepare.httpPath, DEFINITION.prepare!.path);
  assert.equal(first.httpPath, DEFINITION.status.path);
  assert.equal(second.idempotencyKey, first.idempotencyKey);
  assert.equal(cancel.httpPath, DEFINITION.cancel.path);
  assert.notEqual(cancel.idempotencyKey, first.idempotencyKey);
  assert.notEqual(first.jti, second.jti);
  assert.notEqual(first.requestId, second.requestId);
});

test("generic signer fails closed on KMS outages, JWKS mismatch, bad signatures, caps, and lifetime", async () => {
  await assert.rejects(() => makeSigner(material(), "get-fail").ready(), /private-get-detail/);
  await assert.rejects(
    () => makeSigner(material(), "sign-fail").signStatus(Buffer.from("{}"), "1788030000.123456"),
    /private-sign-detail/,
  );
  await assert.rejects(
    () => makeSigner(material(), "bad-sign").signStatus(Buffer.from("{}"), "1788030000.123456"),
    /mismatched/,
  );
  const configured = material();
  const actual = material();
  const mismatch = createBackgroundJobAuthoritySigner(
    {
      issuer: "https://gateway.example/authority",
      audience: "https://jobs.example/authority",
      keyId: "kms-key-1",
      tokenKid: "key-1",
      publicJwk: configured.jwk,
      profile: PROFILE,
      definition: DEFINITION,
    },
    { kms: fakeKms(actual) },
  );
  await assert.rejects(() => mismatch.ready(), /does not match/);
  await assert.rejects(
    () => makeSigner().signStart(new Uint8Array(1025), "1788030000.123456", "decision-123"),
    /payload/,
  );
});

const RECEIPT: Readonly<BackgroundJobReceipt> = Object.freeze({
  jobId: DEFINITION.id,
  authorityId: "authority-1",
  runId: "run-0000001",
  ...PROFILE,
  threadTs: "1788030000.123456",
  idempotencyKey: "decision-123",
  createdAt: 1,
});

function json(value: unknown, url = "") {
  const body = JSON.stringify(value);
  const response = new Response(body, {
    headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
  });
  if (url) Object.defineProperty(response, "url", { value: url });
  return response;
}

test("fixed client uses only configured HTTPS paths, exact canonical control bytes, no redirects, and bounded responses", async () => {
  const calls: { url: string; init: RequestInit; body: string }[] = [];
  const signed: string[] = [];
  const signer = {
    ready: async () => undefined,
    jwks: () => ({ keys: [] }),
    signStart: async () => {
      signed.push("start");
      return "token-start";
    },
    signPrepare: async () => "token-prepare",
    signStatus: async () => {
      signed.push("status");
      return "token-status";
    },
    signCancel: async () => {
      signed.push("cancel");
      return "token-cancel";
    },
  };
  const fetcher = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init: init!, body: Buffer.from(init!.body as Uint8Array).toString("utf8") });
    if (url.endsWith(DEFINITION.start.path))
      return json({ authorityId: RECEIPT.authorityId, runId: RECEIPT.runId }, url);
    if (url.endsWith(DEFINITION.status.path)) return json({ runId: RECEIPT.runId, state: "complete" }, url);
    return json({ runId: RECEIPT.runId, state: "cancelling" }, url);
  }) as typeof fetch;
  const strict = (value: unknown) => {
    assert.ok(value && typeof value === "object" && !Array.isArray(value));
    return value as { runId: string; state: string };
  };
  const client = createFixedBackgroundJobClient(
    {
      origin: "https://jobs.example",
      definition: DEFINITION,
      fetch: fetcher,
      parsers: {
        admission: (value) => {
          const item = value as { authorityId: string; runId: string };
          return { authorityId: item.authorityId, runId: item.runId };
        },
        status: strict,
        cancellation: strict,
        statusRunId: (value) => value.runId,
        cancellationRunId: (value) => value.runId,
      },
    },
    signer,
  );
  await client.start(Buffer.from("{}"), RECEIPT.threadTs, RECEIPT.idempotencyKey);
  await client.status(RECEIPT);
  await client.status(RECEIPT);
  await client.cancel(RECEIPT);
  assert.deepEqual(signed, ["start", "status", "status", "cancel"]);
  assert.deepEqual(
    calls.map((call) => call.url),
    [
      `https://jobs.example${DEFINITION.start.path}`,
      `https://jobs.example${DEFINITION.status.path}`,
      `https://jobs.example${DEFINITION.status.path}`,
      `https://jobs.example${DEFINITION.cancel.path}`,
    ],
  );
  assert.equal(calls[1]!.body, '{"authorityId":"authority-1","runId":"run-0000001"}');
  for (const call of calls) {
    assert.equal(call.init.redirect, "error");
    assert.equal((call.init.headers as Record<string, string>)[DEFINITION.authorityHeader]?.startsWith("token-"), true);
    assert.equal((call.init.headers as Record<string, string>)["content-length"], String(Buffer.byteLength(call.body)));
  }
});

test("fixed client sanitizes redirect, timeout, oversize, origin, and server body failures", async () => {
  const base = {
    origin: "https://jobs.example",
    definition: DEFINITION,
    parsers: {
      admission: () => ({ authorityId: "authority-1", runId: "run-0000001" }),
      status: (value: unknown) => value as { runId: string },
      cancellation: (value: unknown) => value as { runId: string },
      statusRunId: (value: { runId: string }) => value.runId,
      cancellationRunId: (value: { runId: string }) => value.runId,
    },
  };
  const signer = {
    ready: async () => undefined,
    jwks: () => ({ keys: [] }),
    signPrepare: async () => "private-token",
    signStart: async () => "private-token",
    signStatus: async () => "private-token",
    signCancel: async () => "private-token",
  };
  const rejected = createFixedBackgroundJobClient(
    {
      ...base,
      fetch: (async () =>
        new Response("private-body", { status: 503, headers: { "content-type": "text/plain" } })) as typeof fetch,
    },
    signer,
  );
  await assert.rejects(
    () => rejected.status(RECEIPT),
    (error: Error) => error.message === "background job server rejected the request (503)",
  );
  const changed = createFixedBackgroundJobClient(
    { ...base, fetch: (async () => json({ runId: RECEIPT.runId }, "https://evil.example/status")) as typeof fetch },
    signer,
  );
  await assert.rejects(() => changed.status(RECEIPT), /origin/);
  const oversize = createFixedBackgroundJobClient(
    {
      ...base,
      fetch: (async () =>
        new Response("{}", {
          headers: { "content-type": "application/json", "content-length": String(256 * 1024 + 1) },
        })) as typeof fetch,
    },
    signer,
  );
  await assert.rejects(() => oversize.status(RECEIPT), /invalid/);
  const redirect = createFixedBackgroundJobClient(
    {
      ...base,
      fetch: (async (_input, init) => {
        assert.equal(init?.redirect, "error");
        throw new Error("redirect-private");
      }) as typeof fetch,
    },
    signer,
  );
  await assert.rejects(() => redirect.status(RECEIPT), /^Error: background job request failed$/);
});
