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
import {
  createFixedBackgroundJobClient,
  type BackgroundJobHttpResponse,
  type BackgroundJobPinnedRequest,
} from "../src/background-jobs/fixed-client.ts";
import { exactPublicRsaJwks, validateDefinition } from "../src/background-jobs/validation.ts";
import { canonicalJson } from "../src/cron/schedule-authority.ts";
import type {
  BackgroundJobApprovalGrant,
  BackgroundJobDefinition,
  BackgroundJobReceipt,
} from "../src/background-jobs/types.ts";

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

const BINDING = Object.freeze({
  descriptorSha256: "a".repeat(64),
  profileSha256: "b".repeat(64),
  schemaSha256: "c".repeat(64),
});

const SLACK = Object.freeze({ messageTs: "1788030001.123456", threadTs: "1788030000.123456" });

const RECEIPT: Readonly<BackgroundJobReceipt> = Object.freeze({
  jobId: DEFINITION.id,
  authorityId: "authority-1",
  runId: "run-0000001",
  ...PROFILE,
  ...BINDING,
  ...SLACK,
  payloadSha256: "d".repeat(64),
  approvalId: "approval-start",
  approvalDigest: "e".repeat(64),
  approvalEffect: "background_job_start",
  approvalMessageTs: SLACK.messageTs,
  approvalThreadTs: SLACK.threadTs,
  idempotencyKey: "decision-123",
  createdAt: 1,
});

const START_GRANT: Readonly<BackgroundJobApprovalGrant> = Object.freeze({
  ...PROFILE,
  ...BINDING,
  threadTs: SLACK.threadTs,
  messageTs: SLACK.messageTs,
  approvalId: "approval-start",
  digest: "e".repeat(64),
  effect: "background_job_start",
  jobId: DEFINITION.id,
  payloadSha256: RECEIPT.payloadSha256,
  idempotencyKey: RECEIPT.idempotencyKey,
  issuedAt: 1_788_030_000_000,
  expiresAt: 1_788_030_300_000,
});

const CANCEL_GRANT: Readonly<BackgroundJobApprovalGrant> = Object.freeze({
  ...START_GRANT,
  approvalId: "approval-cancel",
  digest: "f".repeat(64),
  effect: "background_job_cancel",
  messageTs: "1788030002.123456",
});

function approvalGrant(
  body: Uint8Array,
  effect: "background_job_start" | "background_job_cancel",
  idempotencyKey: string,
  approvalId: string,
  messageTs: string = SLACK.messageTs,
): Readonly<BackgroundJobApprovalGrant> {
  const unsigned = {
    ...PROFILE,
    ...BINDING,
    threadTs: SLACK.threadTs,
    messageTs,
    approvalId,
    effect,
    jobId: DEFINITION.id,
    payloadSha256: createHash("sha256").update(body).digest("hex"),
    idempotencyKey,
    issuedAt: 1_788_030_000_000,
    expiresAt: 1_788_030_300_000,
  } as const;
  return Object.freeze({
    ...unsigned,
    digest: createHash("sha256").update(canonicalJson(unsigned)).digest("hex"),
  });
}

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

function makeSigner(
  value = material(),
  mode: "ok" | "get-fail" | "sign-fail" | "bad-sign" = "ok",
  definition: Readonly<BackgroundJobDefinition> = DEFINITION,
) {
  let nonce = 0;
  return createBackgroundJobAuthoritySigner(
    {
      issuer: "https://gateway.example.com/authority",
      audience: "https://jobs.example.com/authority",
      keyId: "kms-key-1",
      tokenKid: "key-1",
      publicJwk: value.jwk,
      profile: PROFILE,
      definition,
      binding: BINDING,
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
  const grant = approvalGrant(body, "background_job_start", "decision-123", "approval-start");
  const { header, claims } = decode(await signer.signStart(body, grant, "decision-123"));
  assert.deepEqual(header, { alg: "RS256", kid: "key-1", typ: DEFINITION.tokenType });
  assert.deepEqual(claims, {
    actorPrincipalId: PROFILE.actorPrincipalId,
    actorSlackId: PROFILE.actorSlackId,
    approvalDigest: grant.digest,
    approvalEffect: "background_job_start",
    approvalId: grant.approvalId,
    aud: "https://jobs.example.com/authority",
    audienceScopeId: PROFILE.audienceScopeId,
    capability: DEFINITION.capability,
    channelId: PROFILE.channelId,
    exp: 1_788_030_300,
    httpMethod: "POST",
    httpPath: DEFINITION.start.path,
    iat: 1_788_030_000,
    idempotencyKey: "decision-123",
    iss: "https://gateway.example.com/authority",
    jti: "nonce_1",
    descriptorSha256: BINDING.descriptorSha256,
    messageTs: SLACK.messageTs,
    operation: DEFINITION.operation,
    organizationId: PROFILE.organizationId,
    payloadSha256: createHash("sha256").update(body).digest("hex"),
    profileSha256: BINDING.profileSha256,
    requestId: "nonce_2",
    schemaSha256: BINDING.schemaSha256,
    scope: DEFINITION.scope,
    slackTeamId: PROFILE.slackTeamId,
    sub: PROFILE.actorPrincipalId,
    threadTs: "1788030000.123456",
  });
  assert.equal(typeof claims.aud, "string");
  assert.deepEqual(Object.keys(signer.jwks().keys[0]!).sort(), ["alg", "e", "kid", "kty", "n", "use"]);
  const mutableDefinition = structuredClone(DEFINITION);
  const snapshotted = makeSigner(material(), "ok", mutableDefinition);
  (mutableDefinition.start as { path: string }).path = "/api/jobs/report-preview/tampered";
  assert.equal(
    decode(
      await snapshotted.signStart(
        body,
        approvalGrant(body, "background_job_start", "decision-456", "approval-start-2"),
        "decision-456",
      ),
    ).claims.httpPath,
    DEFINITION.start.path,
  );
});

test("status and cancel use fixed configured paths, stable control idempotency, and fresh request nonces", async () => {
  const signer = makeSigner();
  const body = Buffer.from('{"authorityId":"authority-1","runId":"run-0000001"}');
  const prepare = decode(await signer.signPrepare(Buffer.from("{}"), SLACK, "decision-123")).claims;
  const controlReceipt = { ...RECEIPT, descriptorSha256: "f".repeat(64) };
  const first = decode(await signer.signStatus(body, controlReceipt)).claims;
  const second = decode(await signer.signStatus(body, RECEIPT)).claims;
  const cancelGrant = approvalGrant(
    body,
    "background_job_cancel",
    `${DEFINITION.id}-cancel:${createHash("sha256").update(body).digest("hex")}`,
    "approval-cancel",
    CANCEL_GRANT.messageTs,
  );
  const cancel = decode(await signer.signCancel(body, RECEIPT, cancelGrant)).claims;
  assert.equal(prepare.httpPath, DEFINITION.prepare!.path);
  assert.equal(first.httpPath, DEFINITION.status.path);
  assert.equal(first.descriptorSha256, controlReceipt.descriptorSha256);
  assert.equal(first.messageTs, RECEIPT.messageTs);
  assert.equal(second.idempotencyKey, first.idempotencyKey);
  assert.equal(cancel.httpPath, DEFINITION.cancel.path);
  assert.equal(cancel.approvalId, cancelGrant.approvalId);
  assert.equal(cancel.approvalEffect, "background_job_cancel");
  assert.equal(cancel.messageTs, cancelGrant.messageTs);
  assert.notEqual(cancel.approvalId, RECEIPT.approvalId);
  assert.notEqual(cancel.idempotencyKey, first.idempotencyKey);
  assert.notEqual(first.jti, second.jti);
  assert.notEqual(first.requestId, second.requestId);
});

test("generic signer fails closed on KMS outages, JWKS mismatch, bad signatures, caps, and lifetime", async () => {
  await assert.rejects(() => makeSigner(material(), "get-fail").ready(), /private-get-detail/);
  await assert.rejects(
    () => makeSigner(material(), "sign-fail").signStatus(Buffer.from("{}"), RECEIPT),
    /private-sign-detail/,
  );
  await assert.rejects(() => makeSigner(material(), "bad-sign").signStatus(Buffer.from("{}"), RECEIPT), /mismatched/);
  const configured = material();
  const actual = material();
  const mismatch = createBackgroundJobAuthoritySigner(
    {
      issuer: "https://gateway.example.com/authority",
      audience: "https://jobs.example.com/authority",
      keyId: "kms-key-1",
      tokenKid: "key-1",
      publicJwk: configured.jwk,
      profile: PROFILE,
      definition: DEFINITION,
      binding: BINDING,
    },
    { kms: fakeKms(actual) },
  );
  await assert.rejects(() => mismatch.ready(), /does not match/);
  const oversized = new Uint8Array(1025);
  await assert.rejects(
    () =>
      makeSigner().signStart(
        oversized,
        approvalGrant(oversized, "background_job_start", "decision-123", "approval-oversize"),
        "decision-123",
      ),
    /payload/,
  );
  const exactBody = Buffer.from("{}");
  const exactGrant = approvalGrant(exactBody, "background_job_start", "decision-123", "approval-exact");
  assert.throws(
    () => makeSigner().signStart(exactBody, { ...exactGrant, digest: "0".repeat(64) }, "decision-123"),
    /approval grant/,
  );
  assert.throws(
    () => makeSigner().signStart(exactBody, { ...exactGrant, effect: "background_job_cancel" }, "decision-123"),
    /approval grant/,
  );
  assert.throws(() =>
    createBackgroundJobAuthoritySigner(
      {
        issuer: "https://gateway.example.com/authority",
        audience: "https://jobs.example.com/authority",
        keyId: "kms-key-1",
        tokenKid: "key-1",
        publicJwk: { ...material().jwk, x: "extra" } as JsonWebKey,
        profile: PROFILE,
        definition: DEFINITION,
        binding: BINDING,
      },
      { kms: fakeKms(material()) },
    ),
  );
  assert.throws(() => exactPublicRsaJwks({ keys: [{ ...material().jwk, d: "private" }] }));
  assert.throws(() => exactPublicRsaJwks({ keys: [material().jwk, material().jwk] }));
  assert.throws(() =>
    validateDefinition({ ...DEFINITION, start: { ...DEFINITION.start, path: "/api/jobs/../private" } }),
  );
  const local = material();
  assert.throws(() =>
    createBackgroundJobAuthoritySigner(
      {
        issuer: "https://localhost/authority",
        audience: "https://jobs.example.com/authority",
        keyId: "kms-key-1",
        tokenKid: "key-1",
        publicJwk: local.jwk,
        profile: PROFILE,
        definition: DEFINITION,
        binding: BINDING,
      },
      { kms: fakeKms(local) },
    ),
  );
});

test("JWKS rotation exposes a bounded unique overlap and retires the old key only after token and cache windows", async () => {
  const current = material();
  const previous = material();
  let now = 1_788_030_000_000;
  const retireAt = now + 900_000;
  const signer = createBackgroundJobAuthoritySigner(
    {
      issuer: "https://gateway.example.com/authority",
      audience: "https://jobs.example.com/authority",
      keyId: "kms-key-1",
      tokenKid: "key-1",
      publicJwk: current.jwk,
      previousPublicJwk: { ...previous.jwk, kid: "key-0" },
      previousKeyRetireAt: retireAt,
      profile: PROFILE,
      definition: DEFINITION,
      binding: BINDING,
      lifetimeSeconds: 300,
    },
    {
      kms: fakeKms(current),
      now: () => now,
      randomId: (() => {
        let id = 0;
        return () => `rotation_${++id}`;
      })(),
    },
  );
  assert.deepEqual(
    signer.jwks().keys.map((key) => key.kid),
    ["key-1", "key-0"],
  );
  const body = Buffer.from("{}");
  assert.equal(
    decode(
      await signer.signStart(
        body,
        approvalGrant(body, "background_job_start", "decision-123", "approval-rotation"),
        "decision-123",
      ),
    ).header.kid,
    "key-1",
  );
  now = retireAt - 1;
  assert.equal(signer.jwks().keys.length, 2);
  now = retireAt;
  assert.deepEqual(
    signer.jwks().keys.map((key) => key.kid),
    ["key-1"],
  );
  now = retireAt - 1;
  assert.deepEqual(
    signer.jwks().keys.map((key) => key.kid),
    ["key-1"],
  );
  assert.throws(() =>
    createBackgroundJobAuthoritySigner(
      {
        issuer: "https://gateway.example.com/authority",
        audience: "https://jobs.example.com/authority",
        keyId: "kms-key-1",
        tokenKid: "key-1",
        publicJwk: current.jwk,
        previousPublicJwk: { ...previous.jwk, kid: "key-0" },
        previousKeyRetireAt: 1_788_030_899_999,
        profile: PROFILE,
        definition: DEFINITION,
        binding: BINDING,
        lifetimeSeconds: 300,
      },
      { kms: fakeKms(current), now: () => 1_788_030_000_000 },
    ),
  );
  assert.throws(() => exactPublicRsaJwks({ keys: [current.jwk, previous.jwk, material().jwk] }));
});

function httpResponse(
  value: unknown,
  url: string,
  options: Readonly<{
    status?: number;
    contentType?: string;
    contentLength?: string;
    contentEncoding?: string;
    stalled?: boolean;
  }> = {},
) {
  const body = Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  let cancelled = 0;
  const headers = new Map<string, string>([
    ["content-type", options.contentType ?? "application/json"],
    ["content-length", options.contentLength ?? String(body.byteLength)],
  ]);
  if (options.contentEncoding) headers.set("content-encoding", options.contentEncoding);
  const response: BackgroundJobHttpResponse = {
    status: options.status ?? 200,
    url,
    headers: { get: (name) => headers.get(name.toLowerCase()) ?? null },
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(body);
        if (!options.stalled) controller.close();
      },
    }),
    cancel: async () => {
      cancelled += 1;
    },
  };
  return { response, cancelled: () => cancelled };
}

test("fixed client pins public DNS on every exact request with SNI, no proxy, and no redirects", async () => {
  const calls: { url: string; init: Parameters<BackgroundJobPinnedRequest>[1]; body: string }[] = [];
  let resolves = 0;
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
  const request: BackgroundJobPinnedRequest = async (url, init) => {
    calls.push({ url, init, body: Buffer.from(init.body).toString("utf8") });
    if (url.endsWith(DEFINITION.start.path))
      return httpResponse({ authorityId: RECEIPT.authorityId, runId: RECEIPT.runId }, url).response;
    if (url.endsWith(DEFINITION.status.path))
      return httpResponse({ runId: RECEIPT.runId, state: "complete" }, url).response;
    return httpResponse({ runId: RECEIPT.runId, state: "cancelling" }, url).response;
  };
  const strict = (value: unknown) => {
    assert.ok(value && typeof value === "object" && !Array.isArray(value));
    return value as { runId: string; state: string };
  };
  const client = createFixedBackgroundJobClient(
    {
      origin: "https://jobs.example.com",
      definition: DEFINITION,
      resolveHost: async () => {
        resolves += 1;
        return ["2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34"];
      },
      request,
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
  await client.start(Buffer.from("{}"), START_GRANT, RECEIPT.idempotencyKey);
  await client.status(RECEIPT);
  await client.status(RECEIPT);
  await client.cancel(RECEIPT, CANCEL_GRANT);
  assert.deepEqual(signed, ["start", "status", "status", "cancel"]);
  assert.deepEqual(
    calls.map((call) => call.url),
    [
      `https://jobs.example.com${DEFINITION.start.path}`,
      `https://jobs.example.com${DEFINITION.status.path}`,
      `https://jobs.example.com${DEFINITION.status.path}`,
      `https://jobs.example.com${DEFINITION.cancel.path}`,
    ],
  );
  assert.equal(calls[1]!.body, '{"authorityId":"authority-1","runId":"run-0000001"}');
  assert.equal(resolves, 4);
  for (const call of calls) {
    assert.equal(call.init.redirect, "error");
    assert.equal(call.init.proxy, "disabled");
    assert.equal(call.init.servername, "jobs.example.com");
    assert.equal(call.init.resolvedAddress, "93.184.216.34");
    assert.deepEqual(call.init.resolvedAddresses, ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]);
    assert.equal(call.init.headers[DEFINITION.authorityHeader]?.startsWith("token-"), true);
    assert.equal(call.init.headers["content-length"], String(Buffer.byteLength(call.body)));
  }
  const mutableDefinition = structuredClone(DEFINITION);
  const fixedCalls: string[] = [];
  const snapshotted = createFixedBackgroundJobClient(
    {
      origin: "https://jobs.example.com",
      definition: mutableDefinition,
      resolveHost: async () => ["93.184.216.34"],
      request: async (url) => {
        fixedCalls.push(url);
        return httpResponse({ authorityId: RECEIPT.authorityId, runId: RECEIPT.runId }, url).response;
      },
      parsers: {
        admission: () => ({ authorityId: RECEIPT.authorityId, runId: RECEIPT.runId }),
        status: strict,
        cancellation: strict,
        statusRunId: (value) => value.runId,
        cancellationRunId: (value) => value.runId,
      },
    },
    signer,
  );
  (mutableDefinition.start as { path: string }).path = "/api/jobs/report-preview/tampered";
  await snapshotted.start(Buffer.from("{}"), START_GRANT, RECEIPT.idempotencyKey);
  assert.deepEqual(fixedCalls, [`https://jobs.example.com${DEFINITION.start.path}`]);
});

test("fixed client sanitizes redirect, timeout, oversize, origin, and server body failures", async () => {
  const base = {
    origin: "https://jobs.example.com",
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
  assert.throws(() => createFixedBackgroundJobClient({ ...base, origin: "https://127.0.0.1" }, signer));
  const resolution = async () => ["93.184.216.34"];
  const rejectedResponse = httpResponse("private-body", `https://jobs.example.com${DEFINITION.status.path}`, {
    status: 503,
    contentType: "text/plain",
  });
  const rejected = createFixedBackgroundJobClient(
    {
      ...base,
      resolveHost: resolution,
      request: async () => rejectedResponse.response,
    },
    signer,
  );
  await assert.rejects(
    () => rejected.status(RECEIPT),
    (error: Error) => error.message === "background job server rejected the request (503)",
  );
  assert.equal(rejectedResponse.cancelled(), 1);
  const changedResponse = httpResponse({ runId: RECEIPT.runId }, "https://evil.example/status");
  const changed = createFixedBackgroundJobClient(
    { ...base, resolveHost: resolution, request: async () => changedResponse.response },
    signer,
  );
  await assert.rejects(() => changed.status(RECEIPT), /origin/);
  assert.equal(changedResponse.cancelled(), 1);
  const oversizeResponse = httpResponse("{}", `https://jobs.example.com${DEFINITION.status.path}`, {
    contentLength: String(256 * 1024 + 1),
  });
  const oversize = createFixedBackgroundJobClient(
    {
      ...base,
      resolveHost: resolution,
      request: async () => oversizeResponse.response,
    },
    signer,
  );
  await assert.rejects(() => oversize.status(RECEIPT), /invalid/);
  assert.equal(oversizeResponse.cancelled(), 1);
  const encodedResponse = httpResponse("{}", `https://jobs.example.com${DEFINITION.status.path}`, {
    contentEncoding: "gzip",
  });
  const encoded = createFixedBackgroundJobClient(
    { ...base, resolveHost: resolution, request: async () => encodedResponse.response },
    signer,
  );
  await assert.rejects(() => encoded.status(RECEIPT), /invalid/);
  assert.equal(encodedResponse.cancelled(), 1);
  const redirect = createFixedBackgroundJobClient(
    {
      ...base,
      resolveHost: resolution,
      request: async (_url, init) => {
        assert.equal(init.redirect, "error");
        assert.equal(init.proxy, "disabled");
        throw new Error("redirect-private");
      },
    },
    signer,
  );
  await assert.rejects(() => redirect.status(RECEIPT), /^Error: background job request failed$/);
  const stalled = createFixedBackgroundJobClient(
    {
      ...base,
      timeoutMs: 100,
      resolveHost: resolution,
      request: async () =>
        httpResponse("{", `https://jobs.example.com${DEFINITION.status.path}`, {
          contentLength: "1",
          stalled: true,
        }).response,
    },
    signer,
  );
  await assert.rejects(() => stalled.status(RECEIPT), /^Error: background job request failed$/);
  let dnsCalls = 0;
  const rebinding = createFixedBackgroundJobClient(
    {
      ...base,
      resolveHost: async () => (++dnsCalls === 1 ? ["93.184.216.34"] : ["93.184.216.34", "127.0.0.1"]),
      request: async (url) => httpResponse({ runId: RECEIPT.runId }, url).response,
    },
    signer,
  );
  await rebinding.status(RECEIPT);
  await assert.rejects(() => rebinding.status(RECEIPT), /did not resolve only to public addresses/);
  const mixed = createFixedBackgroundJobClient(
    {
      ...base,
      resolveHost: async () => ["93.184.216.34", "224.0.0.1"],
      request: async (url) => httpResponse({ runId: RECEIPT.runId }, url).response,
    },
    signer,
  );
  await assert.rejects(() => mixed.status(RECEIPT), /did not resolve only to public addresses/);
});
