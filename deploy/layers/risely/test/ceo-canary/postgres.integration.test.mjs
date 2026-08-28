import assert from "node:assert/strict";
import { test } from "node:test";
import pg from "pg";
import { sha256, sha256Canonical } from "../../canary/service/ceo-canary/src/canonical.mjs";
import { PostgresCanaryStore } from "../../canary/service/ceo-canary/src/postgres-store.mjs";
import { migrate } from "../../canary/service/ceo-canary/src/migrate.mjs";
import { applyRetention } from "../../canary/service/ceo-canary/src/retention.mjs";
import {
  CANARY_BOOTSTRAP_ADMIN_ROLE,
  CANARY_DATABASE_NAME,
  CANARY_EVALUATION_WRITER_DATABASE_USER,
  CANARY_MIGRATION_DATABASE_USER,
  CANARY_OWNER_DATABASE_USER,
  CANARY_RUNTIME_DATABASE_USER,
  CANARY_SCHEMA_NAME,
} from "../../canary/service/ceo-canary/src/schema.mjs";
import { actionProposal, approval, receipt, run } from "../contracts/fixtures.mjs";
import { validateArtifact } from "../../canary/presentation/index.mjs";
import { PostgresCeoSurfaceStore } from "../../canary/service/ceo-surface/src/postgres-adapter.mjs";
import {
  compileDeploymentBinding,
  deriveSurfaceOutboxEventId,
  evalReleaseReceiptHash,
  identityResolutionHash,
  outboxPayloadHash,
} from "../../canary/service/ceo-surface/src/contracts.mjs";
import { deliveryReceiptHash } from "../../canary/service/ceo-surface/src/durability.mjs";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import {
  compileShadowPublication,
  reconstructShadowPublication,
} from "../../canary/service/ceo-surface/src/publisher.mjs";

const { Pool } = pg;
const RUNTIME_SCOPE = createRuntimeScope(ceoDeploymentProfile);
const MIGRATION_DATABASE_URL = process.env.TEST_CANARY_MIGRATION_DATABASE_URL;
const RUNTIME_DATABASE_URL = process.env.TEST_CANARY_RUNTIME_DATABASE_URL;
const DATABASE_CA_CERT = process.env.TEST_DATABASE_CA_CERT;
const DISPOSABLE_DATABASE_MARKER = process.env.TEST_CANARY_DISPOSABLE_DATABASE_MARKER;
const BOOTSTRAP_CREATOR_USER = process.env.TEST_CANARY_BOOTSTRAP_CREATOR_USER;
const PRODUCTION_DATABASE_HOST = process.env.CANARY_DATABASE_HOST;
const skip =
  "external URL execution is permanently disabled; use lifecycle.pg16.integration.test.mjs with its self-created loopback Docker database";
const SURFACE_DEPLOYMENT = Object.freeze({
  contractType: "ceo-surface-deployment",
  contractVersion: 1,
  ceoUserRef: "slack-user:ceo",
  ceoEmail: "shahryar@risely.ai",
  qmPrincipalRef: "qm:principal:ceo-canary",
  credentialOwnerRef: "credential-owner:ceo",
  slackTeamId: "T123456789",
  evalAuthorityRef: "evaluator:risely:shadow-gate",
  evalPolicySha256: "a".repeat(64),
  identityResolverAuthorityRef: "resolver:risely:slack-identity",
});

export function disposablePostgresContract(env) {
  if (!/^risely-agent-runtime-disposable-v1:[0-9a-f]{64}$/.test(env.TEST_CANARY_DISPOSABLE_DATABASE_MARKER ?? "")) {
    throw new Error("Disposable PostgreSQL marker is invalid");
  }
  if (
    env.TEST_CANARY_BOOTSTRAP_CREATOR_USER !== CANARY_BOOTSTRAP_ADMIN_ROLE ||
    env.CANARY_BOOTSTRAP_ADMIN_ROLE !== CANARY_BOOTSTRAP_ADMIN_ROLE
  )
    throw new Error("Disposable PostgreSQL bootstrap creator is invalid");
  if (typeof env.TEST_DATABASE_CA_CERT !== "string" || !env.TEST_DATABASE_CA_CERT.includes("BEGIN CERTIFICATE")) {
    throw new Error("Disposable PostgreSQL CA is required");
  }
  const parsed = [
    ["TEST_CANARY_MIGRATION_DATABASE_URL", env.TEST_CANARY_MIGRATION_DATABASE_URL, CANARY_MIGRATION_DATABASE_USER],
    ["TEST_CANARY_RUNTIME_DATABASE_URL", env.TEST_CANARY_RUNTIME_DATABASE_URL, CANARY_RUNTIME_DATABASE_USER],
  ].map(([label, value, expectedUser]) => {
    let url;
    try {
      url = new URL(value);
    } catch {
      throw new Error(`${label} must be an absolute PostgreSQL URL`);
    }
    if (
      !["postgres:", "postgresql:"].includes(url.protocol) ||
      url.search ||
      url.hash ||
      decodeURIComponent(url.username) !== expectedUser ||
      decodeURIComponent(url.pathname.slice(1)) !== CANARY_DATABASE_NAME ||
      url.port !== "55439" ||
      url.hostname !== "127.0.0.1"
    )
      throw new Error(`${label} does not match the disposable PostgreSQL contract`);
    return {
      connectionString: url.toString(),
      host: url.hostname.toLowerCase(),
      port: url.port || "5432",
      database: decodeURIComponent(url.pathname.slice(1)),
    };
  });
  if (
    parsed[0].host !== parsed[1].host ||
    parsed[0].port !== parsed[1].port ||
    parsed[0].database !== parsed[1].database
  )
    throw new Error("Disposable PostgreSQL URLs do not identify the same server database");
  return Object.freeze({
    host: parsed[0].host,
    port: parsed[0].port,
    migrationDatabaseUrl: parsed[0].connectionString,
    runtimeDatabaseUrl: parsed[1].connectionString,
    marker: env.TEST_CANARY_DISPOSABLE_DATABASE_MARKER,
    bootstrapCreatorUser: env.TEST_CANARY_BOOTSTRAP_CREATOR_USER,
  });
}

function disposableEnvironment(contract, env) {
  return {
    CANARY_BOOTSTRAP_ADMIN_ROLE,
    CANARY_DATABASE_NAME,
    CANARY_DATABASE_SCHEMA: CANARY_SCHEMA_NAME,
    CANARY_OWNER_DATABASE_USER,
    CANARY_RUNTIME_DATABASE_USER,
    CANARY_MIGRATION_DATABASE_USER,
    CANARY_DATABASE_HOST: contract.host,
    CANARY_DATABASE_PORT: contract.port,
    CANARY_MIGRATION_DATABASE_URL: contract.migrationDatabaseUrl,
    CANARY_DATABASE_URL: contract.runtimeDatabaseUrl,
    DATABASE_CA_CERT: env.TEST_DATABASE_CA_CERT,
  };
}

function disposableUrl(user, host = "127.0.0.1", suffix = "", port = "55439") {
  const scheme = "postgresql:";
  return `${scheme}//${encodeURIComponent(user)}:fixture@${host}:${port}/qm${suffix}`;
}

function disposableContractFixture(overrides = {}) {
  return {
    TEST_CANARY_MIGRATION_DATABASE_URL: disposableUrl(CANARY_MIGRATION_DATABASE_USER),
    TEST_CANARY_RUNTIME_DATABASE_URL: disposableUrl(CANARY_RUNTIME_DATABASE_USER),
    TEST_DATABASE_CA_CERT: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
    TEST_CANARY_DISPOSABLE_DATABASE_MARKER: `risely-agent-runtime-disposable-v1:${"a".repeat(64)}`,
    TEST_CANARY_BOOTSTRAP_CREATOR_USER: CANARY_BOOTSTRAP_ADMIN_ROLE,
    CANARY_BOOTSTRAP_ADMIN_ROLE,
    ...overrides,
  };
}

test("disposable PostgreSQL contract rejects URL query fragment and options substitution", () => {
  for (const suffix of ["?sslmode=disable", "#shadow", "?options=-csearch_path%3Dpublic"]) {
    assert.throws(() =>
      disposablePostgresContract(
        disposableContractFixture({
          TEST_CANARY_RUNTIME_DATABASE_URL: disposableUrl(CANARY_RUNTIME_DATABASE_USER, undefined, suffix),
        }),
      ),
    );
  }
});

test("disposable PostgreSQL contract rejects production simulated Command Center and mismatched hosts", () => {
  for (const overrides of [
    {
      TEST_CANARY_MIGRATION_DATABASE_URL: disposableUrl(
        CANARY_MIGRATION_DATABASE_USER,
        "risely-qm-production.rds.amazonaws.com",
      ),
      TEST_CANARY_RUNTIME_DATABASE_URL: disposableUrl(
        CANARY_RUNTIME_DATABASE_USER,
        "risely-qm-production.rds.amazonaws.com",
      ),
    },
    {
      TEST_CANARY_RUNTIME_DATABASE_URL: disposableUrl(
        CANARY_RUNTIME_DATABASE_USER,
        "risely-prod-cluster.rds.amazonaws.com",
      ),
    },
    {
      TEST_CANARY_RUNTIME_DATABASE_URL: disposableUrl(
        CANARY_RUNTIME_DATABASE_USER,
        "command-center-staging-cluster.rds.amazonaws.com",
      ),
    },
  ])
    assert.throws(() => disposablePostgresContract(disposableContractFixture(overrides)));
});

test("disposable PostgreSQL contract requires deployment host provenance and owner-provisioned marker", () => {
  for (const overrides of [
    { TEST_CANARY_RUNTIME_DATABASE_URL: disposableUrl(CANARY_RUNTIME_DATABASE_USER, "localhost") },
    { TEST_CANARY_RUNTIME_DATABASE_URL: disposableUrl(CANARY_RUNTIME_DATABASE_USER, "127.0.0.1", "", "5432") },
    { TEST_CANARY_DISPOSABLE_DATABASE_MARKER: "confirmed" },
    { TEST_CANARY_BOOTSTRAP_CREATOR_USER: undefined },
    { TEST_CANARY_BOOTSTRAP_CREATOR_USER: CANARY_OWNER_DATABASE_USER },
    { TEST_CANARY_BOOTSTRAP_CREATOR_USER: "creator;SET ROLE attacker" },
  ])
    assert.throws(() => disposablePostgresContract(disposableContractFixture(overrides)));
});

function context(label) {
  return { principalRef: AUTHORITY.principalRef, requestHash: sha256(`request:${label}`) };
}

function expected(action) {
  return {
    expectedRevision: action.revision,
    expectedStateHash: action.stateHash,
    proposalHash: action.proposal.proposalHash,
    effectKey: action.proposal.effectKey,
  };
}

function iso(milliseconds) {
  return new Date(milliseconds).toISOString();
}

function surfaceFixture(suffix, baseTime = Date.now(), historicalAuthorityTime = null) {
  const deployment = compileDeploymentBinding(SURFACE_DEPLOYMENT);
  const artifact = validateArtifact({
    version: 1,
    id: `artifact:${sha256Canonical({ suffix })}`,
    revision: sha256Canonical({ suffix, revision: 1 }),
    kind: "meeting_prep",
    state: "ready",
    title: `Meeting prep ${suffix}`,
    summary: "Confirm the decision owner and implementation timeline.",
    facts: [{ label: "Outcome", value: "Confirm the executive sponsor." }],
    evidence: [{ label: "Calendar", source: "Google Calendar", occurredAt: iso(baseTime - 600_000) }],
    links: [],
    actions: [],
    updatedAt: iso(baseTime - 500_000),
  });
  const artifactSha256 = sha256Canonical(artifact);
  const evalRelease = {
    contractType: "eval-release",
    contractVersion: 1,
    evalRunId: `eval:meeting:${suffix}`,
    evalAuthorityRef: deployment.evalAuthorityRef,
    deploymentBindingSha256: deployment.bindingSha256,
    artifactId: artifact.id,
    artifactRevision: artifact.revision,
    artifactSha256,
    mode: "shadow",
    passed: true,
    release: true,
    sideEffects: 0,
    deterministicCheckIds: ["check:grounding"],
    judgeIds: ["judge:luna:quality", "judge:luna:safety"],
    judgeIndependenceKeys: ["origin:luna:quality", "origin:luna:safety"],
    policySha256: deployment.evalPolicySha256,
    rubricVersion: "rubric:2026-08-26:v1",
    evaluatedAt: iso(baseTime - 400_000),
    expiresAt: iso(baseTime + 1_800_000),
  };
  evalRelease.receiptSha256 = evalReleaseReceiptHash(evalRelease);
  const outboxItem = {
    contractType: "ceo-surface-outbox",
    contractVersion: 1,
    eventId: deriveSurfaceOutboxEventId(artifact, deployment),
    deploymentBindingSha256: deployment.bindingSha256,
    artifact,
    artifactSha256,
    evalRelease,
    queuedAt: iso(baseTime - 300_000),
  };
  outboxItem.payloadSha256 = outboxPayloadHash(outboxItem);
  const identityResolution = {
    contractType: "ceo-surface-identity-resolution",
    contractVersion: 1,
    resolverReceiptRef: `identity-receipt:${suffix}`,
    resolverAuthorityRef: deployment.identityResolverAuthorityRef,
    deploymentBindingSha256: deployment.bindingSha256,
    teamRef: deployment.teamRef,
    ceoUserRef: deployment.ceoUserRef,
    ceoEmail: deployment.ceoEmail,
    qmPrincipalRef: deployment.qmPrincipalRef,
    credentialOwnerRef: deployment.credentialOwnerRef,
    slackTeamId: deployment.slackTeamId,
    slackUserId: "U123456789",
    slackDirectMessageId: "D123456789",
    resolvedAt: iso(baseTime - 200_000),
    expiresAt: iso(baseTime + 1_800_000),
  };
  identityResolution.resolutionSha256 = identityResolutionHash(identityResolution);
  const publicationInput = {
    deploymentBinding: SURFACE_DEPLOYMENT,
    outboxItem,
    identityResolution,
  };
  const publication = historicalAuthorityTime
    ? reconstructShadowPublication(publicationInput, iso(historicalAuthorityTime))
    : compileShadowPublication(publicationInput);
  return { outboxItem, identityResolution, publication };
}

function surfaceReceipt(publication, attemptRef, attemptedAt, status, completedAt, providerReceiptRef) {
  const value = {
    contractType: "ceo-surface-delivery-receipt",
    contractVersion: 1,
    deliveryKey: publication.deliveryKey,
    outboxEventId: publication.outboxEventId,
    outboxPayloadSha256: publication.outboxPayloadSha256,
    artifactId: publication.artifactId,
    artifactRevision: publication.artifactRevision,
    artifactSha256: publication.artifactSha256,
    deploymentBindingSha256: publication.deploymentBindingSha256,
    identityResolutionSha256: publication.identityResolutionSha256,
    targetBindingSha256: publication.targetBindingSha256,
    messageSha256: publication.messageSha256,
    attemptRef,
    status,
    attemptedAt,
    completedAt,
  };
  if (providerReceiptRef) value.providerReceiptRef = providerReceiptRef;
  value.receiptSha256 = deliveryReceiptHash(value);
  return value;
}

function rehashPublication(value) {
  value.messageSha256 = sha256Canonical(value.message);
  value.targetBindingSha256 = sha256Canonical({
    deploymentBindingSha256: value.deploymentBindingSha256,
    target: value.target,
  });
  return value;
}

test(
  "Postgres atomically reserves effects, applies revision CAS, and recovers reconciliation leases",
  { skip },
  async (t) => {
    const disposableContract = disposablePostgresContract(process.env);
    const canaryEnvironment = disposableEnvironment(disposableContract, process.env);
    const ssl = { ssl: { ca: DATABASE_CA_CERT, rejectUnauthorized: true } };
    const migrationPool = new Pool({
      connectionString: disposableContract.migrationDatabaseUrl,
      ...ssl,
      max: 2,
    });
    const runtimePool = new Pool({
      connectionString: disposableContract.runtimeDatabaseUrl,
      ...ssl,
      max: 8,
    });
    const migrationIdentity = await migrationPool.query("SELECT current_user, current_database()");
    assert.deepEqual(migrationIdentity.rows[0], {
      current_user: CANARY_MIGRATION_DATABASE_USER,
      current_database: CANARY_DATABASE_NAME,
    });
    const runtimeIdentity = await runtimePool.query("SELECT current_user, current_database()");
    assert.deepEqual(runtimeIdentity.rows[0], {
      current_user: CANARY_RUNTIME_DATABASE_USER,
      current_database: CANARY_DATABASE_NAME,
    });
    const disposable = await migrationPool.query(
      `SELECT shobj_description(database_record.oid, 'pg_database') AS marker,
              owner.rolname AS database_owner,
              inet_server_addr()::text AS server_address,
              inet_server_port() AS server_port
       FROM pg_catalog.pg_database database_record
       JOIN pg_catalog.pg_roles owner ON owner.oid = database_record.datdba
       WHERE database_record.datname = current_database()`,
    );
    assert.equal(disposable.rows[0]?.marker, disposableContract.marker);
    assert.equal(disposable.rows[0]?.server_port, 5432);
    assert.ok(disposable.rows[0]?.server_address);
    assert.ok(
      ![
        CANARY_OWNER_DATABASE_USER,
        CANARY_MIGRATION_DATABASE_USER,
        CANARY_RUNTIME_DATABASE_USER,
        CANARY_EVALUATION_WRITER_DATABASE_USER,
      ].includes(disposable.rows[0]?.database_owner),
    );
    const bootstrapCreator = await migrationPool.query(
      `SELECT rolname, rolcanlogin, rolcreaterole, rolsuper
       FROM pg_catalog.pg_roles
       WHERE rolname = $1`,
      [disposableContract.bootstrapCreatorUser],
    );
    assert.deepEqual(bootstrapCreator.rows, [
      {
        rolname: disposableContract.bootstrapCreatorUser,
        rolcanlogin: true,
        rolcreaterole: true,
        rolsuper: false,
      },
    ]);
    const canaryRoleEdges = await migrationPool.query(
      `SELECT granted_role.rolname AS granted_role,
              member_role.rolname AS member_role,
              grantor_role.rolname AS grantor_role,
              membership.inherit_option,
              membership.set_option,
              membership.admin_option,
              grantor_role.rolsuper AS grantor_is_superuser
       FROM pg_catalog.pg_auth_members membership
       JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
       JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
       JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
       WHERE granted_role.rolname = ANY ($1::text[])
          OR member_role.rolname = ANY ($1::text[])
       ORDER BY granted_role.rolname, member_role.rolname`,
      [
        [
          CANARY_OWNER_DATABASE_USER,
          CANARY_MIGRATION_DATABASE_USER,
          CANARY_RUNTIME_DATABASE_USER,
          CANARY_EVALUATION_WRITER_DATABASE_USER,
        ],
      ],
    );
    assert.equal(canaryRoleEdges.rows.length, 5);
    assert.deepEqual(
      canaryRoleEdges.rows.filter((edge) => edge.member_role === CANARY_BOOTSTRAP_ADMIN_ROLE),
      [
        CANARY_EVALUATION_WRITER_DATABASE_USER,
        CANARY_MIGRATION_DATABASE_USER,
        CANARY_OWNER_DATABASE_USER,
        CANARY_RUNTIME_DATABASE_USER,
      ]
        .sort()
        .map((grantedRole) => ({
          granted_role: grantedRole,
          member_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
          grantor_role: canaryRoleEdges.rows.find((edge) => edge.member_role === CANARY_BOOTSTRAP_ADMIN_ROLE)
            ?.grantor_role,
          inherit_option: false,
          set_option: false,
          admin_option: true,
          grantor_is_superuser: true,
        })),
    );
    assert.equal(
      new Set(
        canaryRoleEdges.rows
          .filter((edge) => edge.member_role === CANARY_BOOTSTRAP_ADMIN_ROLE)
          .map((edge) => edge.grantor_role),
      ).size,
      1,
    );
    assert.deepEqual(
      canaryRoleEdges.rows.filter((edge) => edge.member_role === CANARY_MIGRATION_DATABASE_USER),
      [
        {
          granted_role: CANARY_OWNER_DATABASE_USER,
          member_role: CANARY_MIGRATION_DATABASE_USER,
          grantor_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
          inherit_option: false,
          set_option: true,
          admin_option: false,
          grantor_is_superuser: false,
        },
      ],
    );
    const emptySchema = await migrationPool.query(
      `SELECT namespace_owner.rolname AS schema_owner,
              count(relation.oid)::integer AS relation_count
       FROM pg_catalog.pg_namespace namespace
       JOIN pg_catalog.pg_roles namespace_owner ON namespace_owner.oid = namespace.nspowner
       LEFT JOIN pg_catalog.pg_class relation ON relation.relnamespace = namespace.oid
       WHERE namespace.nspname = $1
       GROUP BY namespace_owner.rolname`,
      [CANARY_SCHEMA_NAME],
    );
    assert.deepEqual(emptySchema.rows[0], { schema_owner: CANARY_OWNER_DATABASE_USER, relation_count: 0 });
    await migrate(canaryEnvironment);
    const migrationClient = await migrationPool.connect();
    await migrationClient.query(`SET ROLE ${CANARY_OWNER_DATABASE_USER}`);
    await migrationClient.query("SET search_path = pg_catalog");
    const store = new PostgresCanaryStore({
      pool: runtimePool,
      scope: RUNTIME_SCOPE,
    });
    t.after(async () => {
      await store.close();
      await migrationClient.query("RESET ROLE").catch(() => {});
      migrationClient.release();
      await migrationPool.end();
    });
    await store.initialize();
    await store.initialize();
    const surfaceStore = new PostgresCeoSurfaceStore({
      pool: runtimePool,
      scope: RUNTIME_SCOPE,
      deploymentBinding: SURFACE_DEPLOYMENT,
    });
    await surfaceStore.initialize();
    const surfaceAdapters = surfaceStore.adapters();
    const historicalAuthorityTime = Date.now() - 200 * 24 * 60 * 60 * 1000;
    const historicalSurface = surfaceFixture("historical", historicalAuthorityTime, historicalAuthorityTime);
    const historicalAttemptRef = "attempt:surface:historical";
    const historicalAttemptedAt = iso(historicalAuthorityTime + 1000);
    const historicalUnknown = surfaceReceipt(
      historicalSurface.publication,
      historicalAttemptRef,
      historicalAttemptedAt,
      "outcome_unknown",
      iso(historicalAuthorityTime + 2000),
    );
    const historicalSeed = await runtimePool.connect();
    try {
      await historicalSeed.query("BEGIN");
      await historicalSeed.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_outbox_events
           (event_id, deployment_binding_sha256, outbox_payload_sha256, artifact_id, artifact_revision,
            artifact_sha256, eval_receipt_sha256, outbox_item, queued_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::timestamptz, $9::timestamptz)`,
        [
          historicalSurface.outboxItem.eventId,
          historicalSurface.outboxItem.deploymentBindingSha256,
          historicalSurface.outboxItem.payloadSha256,
          historicalSurface.outboxItem.artifact.id,
          historicalSurface.outboxItem.artifact.revision,
          historicalSurface.outboxItem.artifactSha256,
          historicalSurface.outboxItem.evalRelease.receiptSha256,
          JSON.stringify(historicalSurface.outboxItem),
          historicalSurface.outboxItem.queuedAt,
        ],
      );
      await historicalSeed.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_outbox_states
           (event_id, status, revision, updated_at)
         VALUES ($1, 'outcome_unknown', 2, $2::timestamptz)`,
        [historicalSurface.outboxItem.eventId, iso(historicalAuthorityTime + 2000)],
      );
      await historicalSeed.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_delivery_reservations
           (delivery_key, outbox_event_id, outbox_payload_sha256, artifact_sha256,
            deployment_binding_sha256, identity_resolution_sha256, target_binding_sha256,
            message_sha256, attempt_ref, identity_resolution, publication, status, revision,
            reserved_at, attempted_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb,
                 'outcome_unknown', 2, $12::timestamptz, $13::timestamptz, $14::timestamptz)`,
        [
          historicalSurface.publication.deliveryKey,
          historicalSurface.outboxItem.eventId,
          historicalSurface.outboxItem.payloadSha256,
          historicalSurface.outboxItem.artifactSha256,
          historicalSurface.publication.deploymentBindingSha256,
          historicalSurface.identityResolution.resolutionSha256,
          historicalSurface.publication.targetBindingSha256,
          historicalSurface.publication.messageSha256,
          historicalAttemptRef,
          JSON.stringify(historicalSurface.identityResolution),
          JSON.stringify(historicalSurface.publication),
          iso(historicalAuthorityTime),
          historicalAttemptedAt,
          iso(historicalAuthorityTime + 2000),
        ],
      );
      await historicalSeed.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_delivery_receipts
           (delivery_key, revision, status, receipt_sha256, receipt, recorded_at)
         VALUES ($1, 1, 'outcome_unknown', $2, $3::jsonb, $4::timestamptz)`,
        [
          historicalSurface.publication.deliveryKey,
          historicalUnknown.receiptSha256,
          JSON.stringify(historicalUnknown),
          iso(historicalAuthorityTime + 3000),
        ],
      );
      await historicalSeed.query("COMMIT");
    } catch (error) {
      await historicalSeed.query("ROLLBACK");
      throw error;
    } finally {
      historicalSeed.release();
    }
    const historicalBeforeReconciliation = await surfaceAdapters.receipts.readDeliveryReceipt(
      historicalSurface.publication.deliveryKey,
    );
    assert.equal(historicalBeforeReconciliation.reservation.reservedAt, iso(historicalAuthorityTime));
    const historicalLease = await surfaceAdapters.receipts.reserveDeliveryReconciliation({
      deliveryKey: historicalSurface.publication.deliveryKey,
      reconciliationRef: "reconcile:surface:historical",
      reconciliationOwnerRef: "worker:surface:historical",
      leaseSeconds: 120,
      expectedRevision: 2,
    });
    const historicalVerified = surfaceReceipt(
      historicalSurface.publication,
      historicalAttemptRef,
      historicalAttemptedAt,
      "verified",
      new Date().toISOString(),
      "slack:message:historical",
    );
    await surfaceAdapters.receipts.commitReconciliationReceipt({
      receipt: historicalVerified,
      expectedRevision: historicalLease.revision,
      reconciliationRef: historicalLease.reconciliationRef,
      reconciliationOwnerRef: historicalLease.reconciliationOwnerRef,
    });
    assert.equal(
      (await surfaceAdapters.receipts.readDeliveryReceipt(historicalSurface.publication.deliveryKey)).receipts.length,
      2,
    );
    const firstSurface = surfaceFixture("delivery");
    const firstQueued = await surfaceAdapters.outbox.enqueueEvaluatedArtifactRevision(firstSurface.outboxItem);
    const duplicateQueued = await surfaceAdapters.outbox.enqueueEvaluatedArtifactRevision(firstSurface.outboxItem);
    assert.equal(firstQueued.outboxItem.payloadSha256, duplicateQueued.outboxItem.payloadSha256);
    const competingClaims = await Promise.all([
      surfaceAdapters.outbox.claimEvaluatedArtifactRevision({
        claimRef: "claim:surface:delivery",
        claimOwnerRef: "worker:surface:one",
        leaseSeconds: 120,
      }),
      surfaceAdapters.outbox.claimEvaluatedArtifactRevision({
        claimRef: "claim:surface:competitor",
        claimOwnerRef: "worker:surface:two",
        leaseSeconds: 120,
      }),
    ]);
    assert.equal(competingClaims.filter(Boolean).length, 1);
    const firstClaim = competingClaims.find(Boolean);
    assert.equal(firstClaim.outboxItem.eventId, firstSurface.outboxItem.eventId);
    const renewedClaim = await surfaceAdapters.outbox.renewClaim({
      eventId: firstClaim.outboxItem.eventId,
      claimRef: firstClaim.claimRef,
      expectedRevision: firstClaim.revision,
      leaseSeconds: 120,
    });
    await assert.rejects(
      () =>
        surfaceAdapters.outbox.renewClaim({
          eventId: firstClaim.outboxItem.eventId,
          claimRef: firstClaim.claimRef,
          expectedRevision: firstClaim.revision,
          leaseSeconds: 120,
        }),
      (error) => error.code === "claim_conflict",
    );
    const forgedPublications = [
      rehashPublication({
        ...structuredClone(firstSurface.publication),
        message: { ...structuredClone(firstSurface.publication.message), text: "Changed self-consistent text" },
      }),
      rehashPublication({
        ...structuredClone(firstSurface.publication),
        message: {
          ...structuredClone(firstSurface.publication.message),
          blocks: [
            ...structuredClone(firstSurface.publication.message.blocks),
            { type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "Send" } }] },
          ],
        },
      }),
      rehashPublication({
        ...structuredClone(firstSurface.publication),
        message: { ...structuredClone(firstSurface.publication.message), text: "Open https://attacker.example" },
      }),
      rehashPublication({
        ...structuredClone(firstSurface.publication),
        target: { ...structuredClone(firstSurface.publication.target), audienceRef: "audience:attacker" },
      }),
      {
        ...structuredClone(firstSurface.publication),
        receiptContract: { ...structuredClone(firstSurface.publication.receiptContract), durability: "memory" },
      },
    ];
    for (const [index, publication] of forgedPublications.entries())
      await assert.rejects(
        () =>
          surfaceAdapters.receipts.reserveDeliveryKey({
            publication,
            identityResolution: firstSurface.identityResolution,
            attemptRef: `attempt:surface:forged:${index}`,
            claimRef: renewedClaim.claimRef,
            expectedOutboxRevision: renewedClaim.revision,
          }),
        (error) => error.code === "publication_conflict" || error instanceof TypeError,
      );
    const concurrentReservations = await Promise.all([
      surfaceAdapters.receipts.reserveDeliveryKey({
        publication: firstSurface.publication,
        identityResolution: firstSurface.identityResolution,
        attemptRef: "attempt:surface:delivery",
        claimRef: renewedClaim.claimRef,
        expectedOutboxRevision: renewedClaim.revision,
      }),
      surfaceAdapters.receipts.reserveDeliveryKey({
        publication: firstSurface.publication,
        identityResolution: firstSurface.identityResolution,
        attemptRef: "attempt:surface:delivery",
        claimRef: renewedClaim.claimRef,
        expectedOutboxRevision: renewedClaim.revision,
      }),
    ]);
    assert.equal(concurrentReservations[0].deliveryKey, concurrentReservations[1].deliveryKey);
    const firstReservation = concurrentReservations[0];
    await assert.rejects(
      () =>
        surfaceAdapters.outbox.releaseClaim({
          eventId: firstClaim.outboxItem.eventId,
          claimRef: renewedClaim.claimRef,
          expectedRevision: renewedClaim.revision,
        }),
      (error) => error.code === "claim_conflict",
    );
    const firstAttempt = await surfaceAdapters.receipts.beginDeliveryAttempt({
      deliveryKey: firstReservation.deliveryKey,
      attemptRef: firstReservation.attemptRef,
      claimRef: renewedClaim.claimRef,
      expectedRevision: firstReservation.revision,
    });
    const unknownReceipt = surfaceReceipt(
      firstSurface.publication,
      firstAttempt.attemptRef,
      firstAttempt.attemptedAt,
      "outcome_unknown",
      new Date().toISOString(),
    );
    const unknownReservation = await surfaceAdapters.receipts.commitDeliveryReceipt({
      receipt: unknownReceipt,
      expectedRevision: firstAttempt.revision,
    });
    assert.equal(unknownReservation.status, "outcome_unknown");
    const reconciliation = await surfaceAdapters.receipts.reserveDeliveryReconciliation({
      deliveryKey: unknownReservation.deliveryKey,
      reconciliationRef: "reconcile:surface:delivery",
      reconciliationOwnerRef: "worker:surface:reconcile",
      leaseSeconds: 120,
      expectedRevision: unknownReservation.revision,
    });
    const verifiedReceipt = surfaceReceipt(
      firstSurface.publication,
      firstAttempt.attemptRef,
      firstAttempt.attemptedAt,
      "verified",
      new Date().toISOString(),
      "slack:message:verified",
    );
    await assert.rejects(
      () =>
        surfaceAdapters.receipts.commitReconciliationReceipt({
          receipt: verifiedReceipt,
          expectedRevision: reconciliation.revision,
          reconciliationRef: reconciliation.reconciliationRef,
          reconciliationOwnerRef: "worker:surface:attacker",
        }),
      (error) => error.code === "reconciliation_conflict",
    );
    const verifiedReservation = await surfaceAdapters.receipts.commitReconciliationReceipt({
      receipt: verifiedReceipt,
      expectedRevision: reconciliation.revision,
      reconciliationRef: reconciliation.reconciliationRef,
      reconciliationOwnerRef: reconciliation.reconciliationOwnerRef,
    });
    assert.equal(verifiedReservation.status, "verified");
    const deliveredOutbox = await surfaceAdapters.outbox.readOutboxEvent(firstSurface.outboxItem.eventId);
    assert.equal(deliveredOutbox.status, "delivered");
    const receiptHistory = await surfaceAdapters.receipts.readDeliveryReceipt(firstSurface.publication.deliveryKey);
    assert.deepEqual(
      receiptHistory.receipts.map((entry) => entry.status),
      ["outcome_unknown", "verified"],
    );
    await assert.rejects(
      () =>
        runtimePool.query(`UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_events SET artifact_id = 'artifact:tampered'`),
      /permission denied|runtime_immutable_relation/,
    );
    await assert.rejects(
      () =>
        runtimePool.query(`DELETE FROM ${CANARY_SCHEMA_NAME}.surface_delivery_receipts WHERE delivery_key = $1`, [
          firstSurface.publication.deliveryKey,
        ]),
      /permission denied|runtime_immutable_relation/,
    );
    const unresolvedSurface = surfaceFixture("unresolved", Date.now() + 1);
    await surfaceAdapters.outbox.enqueueEvaluatedArtifactRevision(unresolvedSurface.outboxItem);
    const unresolvedClaim = await surfaceAdapters.outbox.claimEvaluatedArtifactRevision({
      claimRef: "claim:surface:unresolved",
      claimOwnerRef: "worker:surface:two",
      leaseSeconds: 120,
    });
    const unresolvedReservation = await surfaceAdapters.receipts.reserveDeliveryKey({
      publication: unresolvedSurface.publication,
      identityResolution: unresolvedSurface.identityResolution,
      attemptRef: "attempt:surface:unresolved",
      claimRef: unresolvedClaim.claimRef,
      expectedOutboxRevision: unresolvedClaim.revision,
    });
    const unresolvedAttempt = await surfaceAdapters.receipts.beginDeliveryAttempt({
      deliveryKey: unresolvedReservation.deliveryKey,
      attemptRef: unresolvedReservation.attemptRef,
      claimRef: unresolvedClaim.claimRef,
      expectedRevision: unresolvedReservation.revision,
    });
    await surfaceAdapters.receipts.commitDeliveryReceipt({
      receipt: surfaceReceipt(
        unresolvedSurface.publication,
        unresolvedAttempt.attemptRef,
        unresolvedAttempt.attemptedAt,
        "outcome_unknown",
        new Date().toISOString(),
      ),
      expectedRevision: unresolvedAttempt.revision,
    });
    const attemptingSurface = surfaceFixture("attempting", Date.now() + 2);
    await surfaceAdapters.outbox.enqueueEvaluatedArtifactRevision(attemptingSurface.outboxItem);
    const attemptingClaim = await surfaceAdapters.outbox.claimEvaluatedArtifactRevision({
      claimRef: "claim:surface:attempting",
      claimOwnerRef: "worker:surface:three",
      leaseSeconds: 120,
    });
    const attemptingReservation = await surfaceAdapters.receipts.reserveDeliveryKey({
      publication: attemptingSurface.publication,
      identityResolution: attemptingSurface.identityResolution,
      attemptRef: "attempt:surface:attempting",
      claimRef: attemptingClaim.claimRef,
      expectedOutboxRevision: attemptingClaim.revision,
    });
    await surfaceAdapters.receipts.beginDeliveryAttempt({
      deliveryKey: attemptingReservation.deliveryKey,
      attemptRef: attemptingReservation.attemptRef,
      claimRef: attemptingClaim.claimRef,
      expectedRevision: attemptingReservation.revision,
    });
    await migrationClient.query(
      `ALTER TABLE ${CANARY_SCHEMA_NAME}.surface_outbox_events DISABLE TRIGGER surface_outbox_events_immutable`,
    );
    await migrationClient.query(
      `UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_events
       SET outbox_item = jsonb_set(outbox_item, '{evalRelease,expiresAt}', to_jsonb((clock_timestamp() - interval '1 hour')::text))
       WHERE event_id = $1`,
      [attemptingSurface.outboxItem.eventId],
    );
    await migrationClient.query(
      `ALTER TABLE ${CANARY_SCHEMA_NAME}.surface_outbox_events ENABLE TRIGGER surface_outbox_events_immutable`,
    );
    await migrationClient.query(
      `UPDATE ${CANARY_SCHEMA_NAME}.surface_delivery_reservations
       SET identity_resolution = jsonb_set(identity_resolution, '{expiresAt}', to_jsonb((clock_timestamp() - interval '1 hour')::text))
       WHERE delivery_key = $1`,
      [attemptingSurface.publication.deliveryKey],
    );
    await migrationClient.query(
      `UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_states
       SET claim_acquired_at = clock_timestamp() - interval '2 hours',
           claim_expires_at = clock_timestamp() - interval '1 hour'
       WHERE event_id = $1`,
      [attemptingSurface.outboxItem.eventId],
    );
    await surfaceAdapters.outbox.claimEvaluatedArtifactRevision({
      claimRef: "claim:surface:expiry-sweep",
      claimOwnerRef: "worker:surface:sweeper",
      leaseSeconds: 30,
    });
    const attemptingAfterSweep = await migrationClient.query(
      `SELECT states.status AS outbox_status, reservations.status AS delivery_status
       FROM ${CANARY_SCHEMA_NAME}.surface_outbox_states states
       JOIN ${CANARY_SCHEMA_NAME}.surface_delivery_reservations reservations
         ON reservations.outbox_event_id = states.event_id
       WHERE states.event_id = $1`,
      [attemptingSurface.outboxItem.eventId],
    );
    assert.deepEqual(attemptingAfterSweep.rows[0], {
      outbox_status: "claimed",
      delivery_status: "attempting",
    });
    await runtimePool.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.ingress_requests (nonce, request_hash, expires_at)
     VALUES ('nonce-expired-0000000001', $1, clock_timestamp() - interval '2 hours')`,
      [sha256("expired")],
    );
    assert.equal(
      await store.claimIngress({
        nonce: "nonce-current-0000000001",
        requestHash: sha256("current"),
        expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      }),
      true,
    );
    const retainedNonces = await runtimePool.query(
      `SELECT nonce FROM ${CANARY_SCHEMA_NAME}.ingress_requests ORDER BY nonce`,
    );
    assert.deepEqual(
      retainedNonces.rows.map((row) => row.nonce),
      ["nonce-current-0000000001"],
    );
    const now = Date.now();
    const workflowRun = run({ startedAt: iso(now - 1000) });
    await store.createRun(workflowRun, sha256Canonical(workflowRun), context("run"));
    const proposal = actionProposal({
      actor: workflowRun.actor,
      createdAt: iso(now - 500),
      expiresAt: iso(now + 60 * 60 * 1000),
    });
    const created = await store.createAction(proposal, context("action-create"));
    const duplicateEffect = actionProposal({
      proposalId: "proposal:duplicate-effect",
      actor: workflowRun.actor,
      createdAt: proposal.createdAt,
      expiresAt: proposal.expiresAt,
    });
    await assert.rejects(
      () => store.createAction(duplicateEffect, context("duplicate-effect")),
      (error) => error.code === "effect_already_reserved",
    );
    const approvalEvent = {
      type: "approve",
      approval: approval(proposal, "approve_once", {
        decidedAt: iso(now),
        expiresAt: iso(now + 30 * 60 * 1000),
      }),
    };
    const attempts = await Promise.allSettled([
      store.transitionAction(proposal.proposalId, expected(created), approvalEvent, undefined, context("approve-1")),
      store.transitionAction(proposal.proposalId, expected(created), approvalEvent, undefined, context("approve-2")),
    ]);
    assert.equal(attempts.filter((entry) => entry.status === "fulfilled").length, 1);
    assert.equal(attempts.filter((entry) => entry.status === "rejected").length, 1);
    assert.equal(attempts.find((entry) => entry.status === "rejected").reason.code, "revision_conflict");
    const approved = await store.readAction(proposal.proposalId, context("read-approved"));
    const executing = await store.reserveExecution(
      proposal.proposalId,
      expected(approved),
      "lease:execution-1",
      30,
      context("execute"),
    );
    const attemptedAt = iso(Date.parse(executing.state.claim.at) + 1);
    const unknown = await store.transitionAction(
      proposal.proposalId,
      expected(executing),
      {
        type: "record_receipt",
        receipt: receipt(proposal, "outcome_unknown", {
          claimId: "lease:execution-1",
          attemptedAt,
        }),
      },
      undefined,
      context("outcome-unknown"),
    );
    const firstReconciliation = await store.reserveReconciliation(
      proposal.proposalId,
      expected(unknown),
      "lease:reconcile-1",
      60,
      context("reconcile-1"),
    );
    assert.equal(firstReconciliation.lease_id, "lease:reconcile-1");
    await assert.rejects(
      () =>
        store.reserveReconciliation(
          proposal.proposalId,
          expected(unknown),
          "lease:reconcile-active-conflict",
          60,
          context("reconcile-conflict"),
        ),
      (error) => error.code === "lease_conflict",
    );
    await runtimePool.query(
      `UPDATE ${CANARY_SCHEMA_NAME}.reconciliation_leases
     SET acquired_at = clock_timestamp() - interval '2 minutes',
         expires_at = clock_timestamp() - interval '1 minute'
     WHERE proposal_id = $1`,
      [proposal.proposalId],
    );
    const recoveredReconciliation = await store.reserveReconciliation(
      proposal.proposalId,
      expected(unknown),
      "lease:reconcile-recovered",
      60,
      context("reconcile-recovered"),
    );
    assert.equal(recoveredReconciliation.lease_id, "lease:reconcile-recovered");
    const completedAt = iso(Date.now());
    const verified = await store.transitionAction(
      proposal.proposalId,
      expected(unknown),
      {
        type: "record_receipt",
        receipt: receipt(proposal, "verified", {
          claimId: "lease:execution-1",
          attemptedAt,
          completedAt,
        }),
      },
      "lease:reconcile-recovered",
      context("receipt"),
    );
    assert.equal(verified.state.status, "verified");
    assert.equal(verified.state.attempts, 1);
    assert.equal(
      (await runtimePool.query(`SELECT count(*)::integer AS count FROM ${CANARY_SCHEMA_NAME}.reconciliation_leases`))
        .rows[0].count,
      0,
    );
    await assert.rejects(
      () => runtimePool.query(`UPDATE ${CANARY_SCHEMA_NAME}.action_events SET event_type = 'tampered'`),
      /permission denied|runtime_immutable_relation/,
    );
    await assert.rejects(
      () => runtimePool.query(`DELETE FROM ${CANARY_SCHEMA_NAME}.action_effect_reservations`),
      /permission denied|runtime_immutable_relation/,
    );
    const audit = await migrationClient.query(
      `SELECT count(*)::integer AS count FROM ${CANARY_SCHEMA_NAME}.audit_events`,
    );
    assert.ok(audit.rows[0].count >= 10);
    const lineageStartedAt = Date.now();
    const lineageRoot = run({ runId: "run:retention-root", startedAt: iso(lineageStartedAt) });
    const lineageParent = run({
      runId: "run:retention-parent",
      parentRunId: lineageRoot.runId,
      startedAt: iso(lineageStartedAt + 1),
    });
    const lineageChild = run({
      runId: "run:retention-child",
      parentRunId: lineageParent.runId,
      startedAt: iso(lineageStartedAt + 2),
    });
    for (const lineageRun of [lineageRoot, lineageParent, lineageChild]) {
      await store.createRun(lineageRun, sha256Canonical(lineageRun), context(`lineage:${lineageRun.runId}`));
    }
    await migrationClient.query(
      `ALTER TABLE ${CANARY_SCHEMA_NAME}.workflow_runs DISABLE TRIGGER workflow_runs_immutable`,
    );
    await migrationClient.query(
      `UPDATE ${CANARY_SCHEMA_NAME}.workflow_runs
       SET created_at = clock_timestamp() - interval '366 days'
       WHERE run_id IN ($1, $2)`,
      [lineageRoot.runId, lineageParent.runId],
    );
    await migrationClient.query(
      `ALTER TABLE ${CANARY_SCHEMA_NAME}.workflow_runs ENABLE TRIGGER workflow_runs_immutable`,
    );
    await runtimePool.query(
      `UPDATE ${CANARY_SCHEMA_NAME}.action_states
       SET updated_at = clock_timestamp() - interval '181 days'
       WHERE proposal_id = $1`,
      [proposal.proposalId],
    );
    await runtimePool.query(
      `UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_states
       SET updated_at = clock_timestamp() - interval '181 days'
       WHERE event_id IN ($1, $2, $3, $4)`,
      [
        firstSurface.outboxItem.eventId,
        unresolvedSurface.outboxItem.eventId,
        attemptingSurface.outboxItem.eventId,
        historicalSurface.outboxItem.eventId,
      ],
    );
    await applyRetention(canaryEnvironment);
    assert.equal(
      (await migrationClient.query(`SELECT count(*)::integer AS count FROM ${CANARY_SCHEMA_NAME}.action_states`))
        .rows[0].count,
      0,
    );
    assert.equal(
      (
        await migrationClient.query(
          `SELECT count(*)::integer AS count FROM ${CANARY_SCHEMA_NAME}.action_effect_reservations`,
        )
      ).rows[0].count,
      1,
    );
    const retainedLineage = await migrationClient.query(
      `SELECT run_id FROM ${CANARY_SCHEMA_NAME}.workflow_runs
       WHERE run_id IN ($1, $2, $3)
       ORDER BY run_id`,
      [lineageRoot.runId, lineageParent.runId, lineageChild.runId],
    );
    assert.deepEqual(
      retainedLineage.rows.map((row) => row.run_id),
      [lineageChild.runId, lineageParent.runId, lineageRoot.runId].sort(),
    );
    assert.equal(await surfaceAdapters.outbox.readOutboxEvent(firstSurface.outboxItem.eventId), null);
    await assert.rejects(
      () => surfaceAdapters.outbox.enqueueEvaluatedArtifactRevision(firstSurface.outboxItem),
      (error) => error.code === "delivery_already_terminal",
    );
    const retiredHistory = await surfaceAdapters.receipts.readDeliveryReceipt(firstSurface.publication.deliveryKey);
    assert.equal(retiredHistory.retired, true);
    assert.equal(retiredHistory.terminalStatus, "verified");
    assert.deepEqual(
      retiredHistory.receipts.map((entry) => entry.status),
      ["outcome_unknown", "verified"],
    );
    assert.equal(
      (await surfaceAdapters.outbox.readOutboxEvent(unresolvedSurface.outboxItem.eventId)).status,
      "outcome_unknown",
    );
    const retainedAttempting = await migrationClient.query(
      `SELECT states.status AS outbox_status, reservations.status AS delivery_status
       FROM ${CANARY_SCHEMA_NAME}.surface_outbox_states states
       JOIN ${CANARY_SCHEMA_NAME}.surface_delivery_reservations reservations
         ON reservations.outbox_event_id = states.event_id
       WHERE states.event_id = $1`,
      [attemptingSurface.outboxItem.eventId],
    );
    assert.deepEqual(retainedAttempting.rows[0], {
      outbox_status: "claimed",
      delivery_status: "attempting",
    });
    const historicalRetired = await surfaceAdapters.receipts.readDeliveryReceipt(
      historicalSurface.publication.deliveryKey,
    );
    assert.equal(historicalRetired.retired, true);
    assert.equal(historicalRetired.record.reservedAt, iso(historicalAuthorityTime));
  },
);
