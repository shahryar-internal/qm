import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { request as httpRequest } from "node:http";
import { test } from "node:test";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { syntheticDeploymentProfile } from "../../canary/deployment-profiles/testing.mjs";
import {
  createQmShadowIngress,
  qmShadowActivationBlockers,
  qmShadowIngressPolicy,
  validateQmShadowObservation,
} from "../../canary/qm-shadow-ingress/index.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import {
  assertIngressConfig,
  bodySignature,
  canonicalIngressMetadata,
  headerSignature,
} from "../../canary/service/ceo-canary/src/auth.mjs";
import { createRuntimeDomain } from "../../canary/service/ceo-canary/src/domain.mjs";
import { createCanaryHttpServer } from "../../canary/service/ceo-canary/src/http.mjs";

const NOW = Date.parse("2026-08-27T12:00:00.000Z");
const REQUEST_HASH = "a".repeat(64);
const SECRET = "qm-shadow-ingress-test-secret-at-least-thirty-two-characters";
const INGRESS_CONFIG = assertIngressConfig({
  secret: SECRET,
  issuer: "qm-surface-bridge-v1",
  audience: "ceo-canary",
  keyId: "qm-surface-key-v1",
});

class DurableRunStore {
  constructor(scope) {
    this.runtimeScope = scope;
    this.domain = createRuntimeDomain(scope);
    this.records = new Map();
    this.nonces = new Set();
    this.providerCalls = 0;
    this.createRunCalls = 0;
  }

  async health() {
    return true;
  }

  async claimIngress({ nonce }) {
    if (this.nonces.has(nonce)) return false;
    this.nonces.add(nonce);
    return true;
  }

  async createRun(run, payloadHash, context) {
    this.createRunCalls += 1;
    const checked = this.domain.assertRun(run);
    assert.equal(this.runtimeScope.contracts.PrincipalBinding.hash(checked), payloadHash);
    assert.equal(context.principalRef, this.runtimeScope.domainAuthority.principalRef);
    if (this.records.has(checked.runId)) {
      const error = new Error("duplicate");
      error.code = "run_already_exists";
      throw error;
    }
    const row = Object.freeze({ payload: checked, payload_hash: payloadHash });
    this.records.set(checked.runId, row);
    return row;
  }

  async readRun(runId, context) {
    assert.equal(context.principalRef, this.runtimeScope.domainAuthority.principalRef);
    return this.records.get(runId) ?? null;
  }
}

function observation(scope, source = "slack_dm", overrides = {}) {
  const slack = source === "slack_dm";
  return {
    contractType: "qm-shadow-observation",
    contractVersion: 1,
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    source,
    eventRef: slack ? "slack-event:Ev0123456789" : "qm-turn:0198f27c",
    conversationRef: slack ? "slack-dm:D0123456789" : "qm-session:0198f27c",
    humanPrincipalRef: scope.profile.identity.humanPrincipalRef,
    qmPrincipalRef: scope.profile.identity.qmPrincipalRef,
    surfacePrincipalRef: slack ? scope.profile.audiences.slack.principalRef : scope.profile.audiences.qm.principalRef,
    audienceRef: slack ? scope.profile.audiences.slack.audienceRef : scope.profile.audiences.qm.audienceRef,
    workspaceRef: slack ? scope.profile.anchors.slackTeamRef : scope.profile.anchors.workspaceRef,
    observedAt: new Date(NOW).toISOString(),
    inputSha256: "b".repeat(64),
    ...overrides,
  };
}

function signed(path, body, nonce) {
  const bytes = Buffer.from(body, "utf8");
  const fields = {
    issuer: INGRESS_CONFIG.issuer,
    audience: INGRESS_CONFIG.audience,
    keyId: INGRESS_CONFIG.keyId,
    method: "POST",
    pathWithQuery: path,
    timestamp: String(Math.floor(NOW / 1000)),
    nonce,
    contentType: "application/json",
    contentLength: String(bytes.length),
    contentSha256: createHash("sha256").update(bytes).digest("hex"),
  };
  const metadata = canonicalIngressMetadata(fields);
  return {
    path,
    method: "POST",
    body: bytes,
    headers: {
      "content-type": fields.contentType,
      "content-length": fields.contentLength,
      "x-canary-issuer": fields.issuer,
      "x-canary-audience": fields.audience,
      "x-canary-key-id": fields.keyId,
      "x-canary-timestamp": fields.timestamp,
      "x-canary-nonce": fields.nonce,
      "x-canary-content-type": fields.contentType,
      "x-canary-content-length": fields.contentLength,
      "x-canary-content-sha256": fields.contentSha256,
      "x-canary-header-signature": headerSignature(SECRET, metadata),
      "x-canary-body-signature": bodySignature(SECRET, metadata, bytes),
    },
  };
}

async function rawRequest(port, input) {
  return new Promise((resolve, reject) => {
    const request = httpRequest({ host: "127.0.0.1", port, ...input });
    request.once("error", reject);
    request.once("response", (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () =>
        resolve({ status: response.statusCode, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) }),
      );
    });
    request.end(input.body);
  });
}

test("Slack DM and authenticated web observations become profile-scoped digest-only durable runs", async () => {
  const scope = createRuntimeScope(ceoDeploymentProfile);
  const store = new DurableRunStore(scope);
  let acceptedAt = NOW + 86_400_000;
  const ingress = createQmShadowIngress({ store, scope, now: () => acceptedAt });
  const delayedObservation = observation(scope, "slack_dm", {
    observedAt: new Date(NOW - 86_400_000).toISOString(),
  });
  const slackReceipt = await ingress.observe(delayedObservation, REQUEST_HASH);
  const webReceipt = await ingress.observe(observation(scope, "web_chat"), "c".repeat(64));
  assert.equal(slackReceipt.status, "accepted");
  assert.equal(webReceipt.status, "accepted");
  assert.equal(store.records.size, 2);
  assert.equal(store.records.get(slackReceipt.runId).payload.actor.surface, "slack");
  assert.equal(store.records.get(webReceipt.runId).payload.actor.surface, "web");
  assert.equal(
    store.records.get(slackReceipt.runId).payload.actor.audienceRef,
    scope.profile.audiences.slack.audienceRef,
  );
  assert.equal(store.records.get(webReceipt.runId).payload.actor.audienceRef, scope.profile.audiences.qm.audienceRef);
  assert.equal(store.records.get(slackReceipt.runId).payload.inputHash, "b".repeat(64));
  assert.equal(store.records.get(slackReceipt.runId).payload.startedAt, new Date(acceptedAt).toISOString());
  acceptedAt += 1_000;
  assert.equal((await ingress.observe(delayedObservation, "d".repeat(64))).status, "duplicate");
  assert.equal(slackReceipt.profileSha256, scope.profileSha256);
  assert.equal(slackReceipt.retainedContent, "digest_only");
  assert.equal(slackReceipt.providerInvocationAllowed, false);
  assert.equal(slackReceipt.providerEffectBudget, 0);
  assert.equal(store.providerCalls, 0);
  assert.doesNotMatch(JSON.stringify([...store.records.values()]), /customer message|rawText|plaintext/iu);
  assert.deepEqual(qmShadowIngressPolicy.allowedSources, ["slack_dm", "web_chat"]);
  assert.ok(qmShadowActivationBlockers.includes("upstream_qm_turn_observer_deployment_binding_unavailable"));
});

test("profile, surface principal, audience, and workspace substitutions fail before durable access", () => {
  const scope = createRuntimeScope(ceoDeploymentProfile);
  const changes = [
    { profileSha256: "0".repeat(64) },
    { humanPrincipalRef: "principal:other" },
    { qmPrincipalRef: "qm:principal:other" },
    { surfacePrincipalRef: "slack-user:other" },
    { audienceRef: "slack-audience:other" },
    { workspaceRef: "slack-team:other" },
  ];
  for (const change of changes) {
    assert.throws(
      () => validateQmShadowObservation(observation(scope, "slack_dm", change), scope),
      (error) => error.code === "shadow_identity_mismatch",
    );
  }
  assert.throws(
    () => validateQmShadowObservation(observation(scope, "channel"), scope),
    (error) => error.code === "unsupported_shadow_source",
  );
  assert.throws(
    () => validateQmShadowObservation({ ...observation(scope), rawText: "secret" }, scope),
    (error) => error.code === "invalid_shadow_observation",
  );
});

test("event identity is idempotent across new signed nonces and conflicts on changed content", async () => {
  const scope = createRuntimeScope(ceoDeploymentProfile);
  const store = new DurableRunStore(scope);
  const ingress = createQmShadowIngress({ store, scope });
  const value = observation(scope);
  const accepted = await ingress.observe(value, REQUEST_HASH);
  const duplicate = await ingress.observe(value, "c".repeat(64));
  assert.equal(duplicate.status, "duplicate");
  assert.equal(duplicate.runId, accepted.runId);
  assert.equal(store.records.size, 1);
  assert.equal(store.createRunCalls, 1);
  await assert.rejects(
    () => ingress.observe({ ...value, inputSha256: "d".repeat(64) }, "e".repeat(64)),
    (error) => error.code === "shadow_observation_conflict",
  );
  assert.equal(store.records.size, 1);
  assert.equal(store.createRunCalls, 1);
});

test("concurrent redelivery converges on one durable record", async () => {
  const scope = createRuntimeScope(ceoDeploymentProfile);
  const store = new DurableRunStore(scope);
  const ingress = createQmShadowIngress({ store, scope });
  const receipts = await Promise.all([
    ingress.observe(observation(scope), REQUEST_HASH),
    ingress.observe(observation(scope), "c".repeat(64)),
  ]);
  assert.deepEqual(receipts.map((receipt) => receipt.status).sort(), ["accepted", "duplicate"]);
  assert.equal(store.records.size, 1);
});

test("factory authority options reject proxies, accessors, and cross-scope stores without trap execution", () => {
  const scope = createRuntimeScope(ceoDeploymentProfile);
  const store = new DurableRunStore(scope);
  assert.throws(() => createQmShadowIngress(new Proxy({ store, scope }, {})));
  let accessed = false;
  const options = { store };
  Object.defineProperty(options, "scope", {
    enumerable: true,
    get() {
      accessed = true;
      throw new Error("accessed");
    },
  });
  assert.throws(() => createQmShadowIngress(options));
  assert.equal(accessed, false);
  const otherScope = createRuntimeScope(syntheticDeploymentProfile);
  assert.throws(() => createQmShadowIngress({ store, scope: otherScope }));
  let storeGetterCalls = 0;
  const accessorStore = new DurableRunStore(scope);
  Object.defineProperty(accessorStore, "readRun", {
    configurable: true,
    get() {
      storeGetterCalls += 1;
      return async () => null;
    },
  });
  assert.throws(() => createQmShadowIngress({ store: accessorStore, scope }));
  assert.equal(storeGetterCalls, 0);
  const shadowedStore = new DurableRunStore(scope);
  shadowedStore.createRun = async () => {
    throw new Error("own shadow invoked");
  };
  assert.throws(() => createQmShadowIngress({ store: shadowedStore, scope }));
});

test("the factory preserves isolation when the same raw QM identifiers appear under another role profile", async () => {
  const ceoScope = createRuntimeScope(ceoDeploymentProfile);
  const roleScope = createRuntimeScope(syntheticDeploymentProfile);
  const ceoIngress = createQmShadowIngress({ store: new DurableRunStore(ceoScope), scope: ceoScope });
  const roleIngress = createQmShadowIngress({ store: new DurableRunStore(roleScope), scope: roleScope });
  const ceoReceipt = await ceoIngress.observe(observation(ceoScope), REQUEST_HASH);
  const roleReceipt = await roleIngress.observe(observation(roleScope), REQUEST_HASH);
  assert.notEqual(ceoReceipt.runId, roleReceipt.runId);
  assert.notEqual(ceoReceipt.sessionId, roleReceipt.sessionId);
  assert.notEqual(ceoReceipt.profileSha256, roleReceipt.profileSha256);
  assert.throws(() => createQmShadowIngress({ store: new DurableRunStore(ceoScope), scope: roleScope }));
});

test("the signed internal route persists once, rejects nonce replay, and deduplicates QM redelivery", async (t) => {
  const scope = createRuntimeScope(ceoDeploymentProfile);
  const store = new DurableRunStore(scope);
  const shadowIngress = createQmShadowIngress({ store, scope });
  const server = createCanaryHttpServer({
    service: {},
    shadowIngress,
    store,
    ingressConfig: INGRESS_CONFIG,
    now: () => NOW,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const port = server.address().port;
  const path = "/internal/v1/qm-shadow/observations";
  const body = JSON.stringify(observation(scope));
  const firstRequest = signed(path, body, "nonce-qm-shadow-000000000000000001");
  const first = await rawRequest(port, firstRequest);
  assert.equal(first.status, 201);
  assert.equal(first.body.status, "accepted");
  const replay = await rawRequest(port, firstRequest);
  assert.equal(replay.status, 401);
  assert.equal(replay.body.error, "replayed_request");
  const redelivery = await rawRequest(port, signed(path, body, "nonce-qm-shadow-000000000000000002"));
  assert.equal(redelivery.status, 200);
  assert.equal(redelivery.body.status, "duplicate");
  assert.equal(redelivery.body.runId, first.body.runId);
  assert.equal(store.records.size, 1);
});
