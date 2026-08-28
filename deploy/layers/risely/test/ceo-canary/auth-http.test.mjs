import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { request as httpRequest } from "node:http";
import { test } from "node:test";
import {
  assertIngressConfig,
  bodySignature,
  canonicalIngressMetadata,
  completeIngressAuthentication,
  headerSignature,
  verifyIngressHeaders,
} from "../../canary/service/ceo-canary/src/auth.mjs";
import { createCanaryHttpServer } from "../../canary/service/ceo-canary/src/http.mjs";
import { parseStrictJson } from "../../canary/service/ceo-canary/src/json.mjs";
import {
  deploymentProfileFromEnv,
  migrationPoolConfig,
  runtimePoolConfig,
} from "../../canary/service/ceo-canary/src/postgres-store.mjs";

const SECRET = "dedicated-canary-ingress-secret-at-least-thirty-two-characters";
const NOW = Date.parse("2026-08-26T12:00:00Z");
const INGRESS_CONFIG = assertIngressConfig({
  secret: SECRET,
  issuer: "canary-caller-v1",
  audience: "ceo-canary",
  keyId: "canary-key-v1",
});

class ReplayStore {
  constructor() {
    this.nonces = new Set();
  }

  async claimIngress({ nonce }) {
    if (this.nonces.has(nonce)) return false;
    this.nonces.add(nonce);
    return true;
  }

  async health() {
    return true;
  }
}

function signed(path, method = "GET", input = "", nonce = "nonce-0000000000000000000000000001") {
  const body = Buffer.isBuffer(input) ? input : Buffer.from(input, "utf8");
  const contentType = method === "POST" ? "application/json" : "";
  const timestamp = String(Math.floor(NOW / 1000));
  const contentSha256 = createHash("sha256").update(body).digest("hex");
  const fields = {
    issuer: INGRESS_CONFIG.issuer,
    audience: INGRESS_CONFIG.audience,
    keyId: INGRESS_CONFIG.keyId,
    method,
    pathWithQuery: path,
    timestamp,
    nonce,
    contentType,
    contentLength: String(body.length),
    contentSha256,
  };
  const metadata = canonicalIngressMetadata(fields);
  return {
    path,
    body,
    headers: {
      "content-length": String(body.length),
      ...(contentType ? { "content-type": contentType } : {}),
      "x-canary-issuer": fields.issuer,
      "x-canary-audience": fields.audience,
      "x-canary-key-id": fields.keyId,
      "x-canary-timestamp": fields.timestamp,
      "x-canary-nonce": fields.nonce,
      "x-canary-content-type": fields.contentType,
      "x-canary-content-length": fields.contentLength,
      "x-canary-content-sha256": fields.contentSha256,
      "x-canary-header-signature": headerSignature(SECRET, metadata),
      "x-canary-body-signature": bodySignature(SECRET, metadata, body),
    },
  };
}

async function rawRequest({ port, path, method, headers, body }) {
  return new Promise((resolve, reject) => {
    const request = httpRequest({ host: "127.0.0.1", port, path, method, headers });
    request.once("error", reject);
    request.once("response", (incoming) => {
      const chunks = [];
      incoming.on("data", (chunk) => chunks.push(chunk));
      incoming.on("end", () => resolve({ status: incoming.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
    });
    if (body?.length) request.end(body);
    else request.end();
  });
}

test("dedicated ingress binds issuer, audience, key id, transport metadata, digest, and raw body", async () => {
  const store = new ReplayStore();
  const request = signed("/internal/v1/runs", "POST", "{}", "nonce-0000000000000000000000000002");
  const verified = verifyIngressHeaders({
    method: "POST",
    pathWithQuery: request.path,
    headers: request.headers,
    config: INGRESS_CONFIG,
    now: NOW,
  });
  const authenticated = await completeIngressAuthentication({
    verified,
    bodyDigest: createHash("sha256").update(request.body).digest("hex"),
    computedBodySignature: request.headers["x-canary-body-signature"],
    store,
  });
  assert.match(authenticated.requestHash, /^[0-9a-f]{64}$/);
  await assert.rejects(
    () =>
      completeIngressAuthentication({
        verified,
        bodyDigest: createHash("sha256").update(request.body).digest("hex"),
        computedBodySignature: request.headers["x-canary-body-signature"],
        store,
      }),
    (error) => error.code === "replayed_request",
  );
  assert.throws(
    () =>
      verifyIngressHeaders({
        method: "POST",
        pathWithQuery: request.path,
        headers: { ...request.headers, "x-canary-audience": "other" },
        config: INGRESS_CONFIG,
        now: NOW,
      }),
    (error) => error.code === "authority_mismatch",
  );
});

test("only database-backed health is unsigned and internal reads require dedicated ingress", async (t) => {
  const store = new ReplayStore();
  const service = {
    async readRun(id) {
      return { runId: id };
    },
  };
  const server = createCanaryHttpServer({ service, store, ingressConfig: INGRESS_CONFIG, now: () => NOW });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  assert.equal((await fetch(`${base}/livez`)).status, 200);
  assert.equal((await fetch(`${base}/healthz`)).status, 200);
  assert.equal((await fetch(`${base}/readyz`)).status, 200);
  assert.equal((await fetch(`${base}/internal/v1/runs/run%3A1`)).status, 401);
  const request = signed("/internal/v1/runs/run%3A1", "GET", "", "nonce-0000000000000000000000000003");
  const read = await rawRequest({
    port: address.port,
    path: request.path,
    method: "GET",
    headers: request.headers,
  });
  assert.equal(read.status, 200);
  assert.deepEqual(JSON.parse(read.body), { runId: "run:1" });
});

test("duplicate JSON keys and excessive depth fail before JSON.parse contract use", () => {
  assert.throws(
    () => parseStrictJson('{"event":{"type":"approve","type":"reject"}}'),
    (error) => error.code === "duplicate_json_key",
  );
  assert.throws(
    () => parseStrictJson(`${"[".repeat(49)}null${"]".repeat(49)}`),
    (error) => error.code === "json_complexity_exceeded",
  );
});

test("fatal UTF-8 and signed oversized bodies are rejected without consuming a replay nonce", async (t) => {
  const store = new ReplayStore();
  const server = createCanaryHttpServer({ service: {}, store, ingressConfig: INGRESS_CONFIG, now: () => NOW });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  const invalidUtf8 = signed(
    "/internal/v1/runs",
    "POST",
    Buffer.from([0xc3, 0x28]),
    "nonce-0000000000000000000000000004",
  );
  const invalid = await rawRequest({
    port: address.port,
    path: invalidUtf8.path,
    method: "POST",
    headers: invalidUtf8.headers,
    body: invalidUtf8.body,
  });
  assert.equal(invalid.status, 401);
  assert.equal(store.nonces.size, 0);
  const oversized = signed("/internal/v1/runs", "POST", "{}", "nonce-0000000000000000000000000005");
  oversized.headers["content-length"] = String(256 * 1024 + 1);
  oversized.headers["x-canary-content-length"] = String(256 * 1024 + 1);
  const fields = {
    issuer: INGRESS_CONFIG.issuer,
    audience: INGRESS_CONFIG.audience,
    keyId: INGRESS_CONFIG.keyId,
    method: "POST",
    pathWithQuery: oversized.path,
    timestamp: oversized.headers["x-canary-timestamp"],
    nonce: oversized.headers["x-canary-nonce"],
    contentType: "application/json",
    contentLength: String(256 * 1024 + 1),
    contentSha256: oversized.headers["x-canary-content-sha256"],
  };
  const metadata = canonicalIngressMetadata(fields);
  oversized.headers["x-canary-header-signature"] = headerSignature(SECRET, metadata);
  oversized.headers["x-canary-body-signature"] = bodySignature(SECRET, metadata, oversized.body);
  const tooLarge = await rawRequest({
    port: address.port,
    path: oversized.path,
    method: "POST",
    headers: oversized.headers,
  });
  assert.equal(tooLarge.status, 413);
  assert.equal(store.nonces.size, 0);
});

test("runtime database configuration rejects master identity and URL TLS overrides", () => {
  const base = {
    CANARY_BOOTSTRAP_ADMIN_ROLE: "qm",
    CANARY_DATABASE_NAME: "qm",
    CANARY_DATABASE_HOST: "risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com",
    CANARY_DATABASE_PORT: "5432",
    CANARY_DATABASE_SCHEMA: "risely_agent_runtime",
    CANARY_OWNER_DATABASE_USER: "risely_agent_runtime_owner",
    CANARY_RUNTIME_DATABASE_USER: "risely_agent_runtime_runtime",
    CANARY_MIGRATION_DATABASE_USER: "risely_agent_runtime_migrator",
    DATABASE_CA_CERT: "-----BEGIN CERTIFICATE-----\ntrusted\n-----END CERTIFICATE-----",
  };
  assert.throws(() => runtimePoolConfig(base), /CANARY_DATABASE_URL/);
  assert.throws(
    () =>
      runtimePoolConfig({
        ...base,
        CANARY_DATABASE_URL:
          "postgresql://risely_agent_runtime_runtime:secret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com:5432/qm?sslmode=disable",
      }),
    /cannot override TLS/,
  );
  assert.throws(
    () =>
      runtimePoolConfig({
        ...base,
        CANARY_DATABASE_URL:
          "postgresql://postgres:secret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com:5432/qm",
      }),
    /must authenticate as/,
  );
  const config = runtimePoolConfig({
    ...base,
    CANARY_DATABASE_URL:
      "postgresql://risely_agent_runtime_runtime:secret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com:5432/qm",
  });
  assert.deepEqual(config.ssl, { ca: base.DATABASE_CA_CERT, rejectUnauthorized: true });
  const migrationConfig = migrationPoolConfig({
    ...base,
    CANARY_MIGRATION_DATABASE_URL:
      "postgresql://risely_agent_runtime_migrator:secret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com:5432/qm",
  });
  assert.deepEqual(migrationConfig.ssl, { ca: base.DATABASE_CA_CERT, rejectUnauthorized: true });
  for (const override of [
    { CANARY_BOOTSTRAP_ADMIN_ROLE: "command_center_admin" },
    { CANARY_DATABASE_NAME: "risely_agent_runtime" },
    { CANARY_DATABASE_NAME: "postgres" },
    { CANARY_DATABASE_SCHEMA: "public" },
    { CANARY_RUNTIME_DATABASE_USER: "postgres" },
    { CANARY_MIGRATION_DATABASE_USER: "postgres" },
  ]) {
    const hostile = {
      ...base,
      CANARY_DATABASE_URL:
        "postgresql://risely_agent_runtime_runtime:secret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com:5432/qm",
      CANARY_MIGRATION_DATABASE_URL:
        "postgresql://risely_agent_runtime_migrator:secret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com:5432/qm",
      ...override,
    };
    assert.throws(() => runtimePoolConfig(hostile), /compiled CEO canary database contract/);
    assert.throws(() => migrationPoolConfig(hostile), /compiled CEO canary database contract/);
  }
  for (const database of ["risely_agent_runtime", "postgres", "qm_shadow"]) {
    assert.throws(
      () =>
        runtimePoolConfig({
          ...base,
          CANARY_DATABASE_URL: `postgresql://risely_agent_runtime_runtime:secret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com:5432/${database}`,
        }),
      /must target only qm/,
    );
  }
  for (const host of [
    "risely-prod-cluster.example.us-west-2.rds.amazonaws.com",
    "risely-dev-cluster.example.us-west-2.rds.amazonaws.com",
    "database.internal",
  ]) {
    assert.throws(
      () =>
        runtimePoolConfig({
          ...base,
          CANARY_DATABASE_URL: `postgresql://risely_agent_runtime_runtime:secret@${host}:5432/qm`,
        }),
      /must target only qm/,
    );
  }
  for (const port of ["5433", "6432", "15432"]) {
    assert.throws(
      () =>
        runtimePoolConfig({
          ...base,
          CANARY_DATABASE_URL: `postgresql://risely_agent_runtime_runtime:secret@${base.CANARY_DATABASE_HOST}:${port}/qm`,
        }),
      /must target only qm/,
    );
  }
  assert.throws(
    () =>
      migrationPoolConfig({
        ...base,
        CANARY_MIGRATION_DATABASE_URL:
          "postgresql://risely_agent_runtime_migrator:secret@risely-prod-cluster.example.us-west-2.rds.amazonaws.com:5432/qm",
      }),
    /must target only qm/,
  );
  assert.throws(
    () =>
      migrationPoolConfig({
        ...base,
        DATABASE_URL:
          "postgresql://risely_agent_runtime_migrator:secret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com:5432/qm",
        CANARY_MIGRATION_DATABASE_URL:
          "postgresql://risely_agent_runtime_migrator:secret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com:5432/qm",
      }),
    /must not reuse DATABASE_URL/,
  );
  for (const databaseUrl of [
    "postgres://risely_agent_runtime_migrator:secret@RISELY-QM-PILOT-CORE.EXAMPLE.US-WEST-2.RDS.AMAZONAWS.COM/qm",
    "postgresql://%72isely_agent_runtime_migrator:%73ecret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com:5432/%71m",
    "postgres://risely_agent_runtime_migrator:secret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com/qm?application_name=qm",
  ]) {
    assert.throws(
      () =>
        migrationPoolConfig({
          ...base,
          DATABASE_URL: databaseUrl,
          CANARY_MIGRATION_DATABASE_URL:
            "postgresql://risely_agent_runtime_migrator:secret@risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com:5432/qm",
        }),
      /must not reuse DATABASE_URL/,
    );
  }
});

test("fixed deployment profile reference is the sole runtime identity input", () => {
  const profile = {
    CANARY_DEPLOYMENT_PROFILE_REF: "deployment-profile:risely:ceo:v1",
  };
  const resolved = deploymentProfileFromEnv(profile);
  assert.equal(resolved.anchors.tenantRef, "tenant:risely");
  assert.equal(resolved.anchors.principalBindingRef, "principal-binding:risely:ceo:v1");
  assert.equal(resolved.agent.agentId, "agent:risely:ceo-team");
  assert.equal(
    deploymentProfileFromEnv({
      ...profile,
      CANARY_TENANT_REF: "tenant:other",
      CANARY_AUTHORITY_PRINCIPAL_REF: "principal:employee",
      CANARY_AUDIENCE_REF: "audience:company",
    }),
    resolved,
  );
  for (const profileRef of [
    undefined,
    "deployment-profile:risely:synthetic:v1",
    "deployment-profile:risely:unknown:v1",
  ]) {
    assert.throws(
      () => deploymentProfileFromEnv({ CANARY_DEPLOYMENT_PROFILE_REF: profileRef }),
      /unsupported_deployment_profile/,
    );
  }
});
