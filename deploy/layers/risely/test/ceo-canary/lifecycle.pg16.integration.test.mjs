import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { syntheticDeploymentProfile } from "../../canary/deployment-profiles/testing.mjs";
import {
  CANARY_DATABASE_NAME,
  CANARY_EVALUATION_WRITER_DATABASE_USER,
  CANARY_MIGRATION_DATABASE_USER,
  CANARY_RUNTIME_DATABASE_USER,
  CANARY_SCHEMA_NAME,
  SCHEMA_VERSION,
  catalogFingerprintSql,
  migrationChecksum,
} from "../../canary/service/ceo-canary/src/schema.mjs";

const { Client } = pg;
const enabled = process.env.TEST_CANARY_PG16_DOCKER_LIFECYCLE === "1";
const skip = enabled ? false : "set TEST_CANARY_PG16_DOCKER_LIFECYCLE=1 to run the isolated PostgreSQL 16 lifecycle";
const suffix = `${process.pid}-${Date.now()}`;
const databaseContainer = `risely-agent-runtime-db-${suffix}`;
const helperContainer = `risely-agent-runtime-helper-${suffix}`;
const networkName = `risely-agent-runtime-network-${suffix}`;
const certificateVolume = `risely-agent-runtime-cert-${suffix}`;
const secretVolume = `risely-agent-runtime-secrets-${suffix}`;
const hostPort = 56000 + (process.pid % 500);
const databaseAlias = `risely-qm-isolated-${suffix}.rds.amazonaws.com`;
const postgresImage = "postgres:16-alpine";
const runtimeImage = `risely-ceo-canary-runtime-${suffix}`;
const testImage = `risely-ceo-canary-test-${suffix}`;
const operatorImage = `risely-ceo-canary-operator-${suffix}`;
const layerDirectory = fileURLToPath(new URL("../../canary/", import.meta.url));
const dockerfilePath = fileURLToPath(new URL("../../canary/service/ceo-canary/Dockerfile", import.meta.url));
const postgresPassword = "postgres-isolated-lifecycle-fixture";
const bootstrapPassword = "qm-isolated-lifecycle-fixture";
const migrationPassword = Buffer.alloc(32, 0x41).toString("base64url");
const runtimePassword = Buffer.alloc(32, 0x42).toString("base64url");
const rotatedMigrationPassword = Buffer.alloc(32, 0x43).toString("base64url");
const rotatedRuntimePassword = Buffer.alloc(32, 0x44).toString("base64url");
const evaluationWriterPassword = Buffer.alloc(32, 0x45).toString("base64url");

function run(executable, args, input = null) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (exitCode) => resolve({ exitCode, stderr, stdout }));
    child.stdin.on("error", () => {});
    child.stdin.end(input ?? undefined);
  });
}

async function requireRun(executable, args, input = null) {
  const result = await run(executable, args, input);
  assert.equal(result.exitCode, 0, result.stderr || result.stdout);
  return result;
}

async function docker(args, input = null) {
  return run("docker", args, input);
}

async function requireDocker(args, input = null) {
  return requireRun("docker", args, input);
}

async function waitForDatabase() {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const result = await docker([
      "exec",
      databaseContainer,
      "pg_isready",
      "-U",
      "postgres",
      "-d",
      CANARY_DATABASE_NAME,
    ]);
    if (result.exitCode === 0) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  assert.fail("isolated PostgreSQL 16 lifecycle database did not become ready");
}

async function adminClient() {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const client = new Client({
      host: "127.0.0.1",
      port: hostPort,
      database: CANARY_DATABASE_NAME,
      user: "postgres",
      ["pass" + "word"]: postgresPassword,
    });
    try {
      await client.connect();
      return client;
    } catch {
      await client.end().catch(() => {});
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  assert.fail("isolated PostgreSQL 16 lifecycle host port did not become ready");
}

async function verifyEntityLockConcurrency() {
  const first = await adminClient();
  const second = await adminClient();
  const maintenance = await adminClient();
  try {
    await first.query("BEGIN");
    await second.query("BEGIN");
    await maintenance.query("BEGIN");
    await first.query("SELECT pg_advisory_xact_lock_shared(hashtext($1))", ["risely_agent_runtime:maintenance:v1"]);
    await second.query("SELECT pg_advisory_xact_lock_shared(hashtext($1))", ["risely_agent_runtime:maintenance:v1"]);
    const profileLock = `${ceoDeploymentProfile.profileRef}:${ceoDeploymentProfile.profileSha256}`;
    await first.query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))", [profileLock, "run:concurrency-a"]);
    const startedAt = performance.now();
    await second.query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))", [profileLock, "run:concurrency-b"]);
    assert.ok(performance.now() - startedAt < 1_000);
    assert.equal(
      (
        await second.query("SELECT pg_try_advisory_xact_lock(hashtext($1), hashtext($2)) AS acquired", [
          profileLock,
          "run:concurrency-a",
        ])
      ).rows[0].acquired,
      false,
    );
    let maintenanceAcquired = false;
    const maintenanceWait = maintenance
      .query("SELECT pg_advisory_xact_lock(hashtext($1))", ["risely_agent_runtime:maintenance:v1"])
      .then(() => {
        maintenanceAcquired = true;
      });
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(maintenanceAcquired, false);
    await first.query("COMMIT");
    await second.query("COMMIT");
    await maintenanceWait;
    assert.equal(maintenanceAcquired, true);
    await maintenance.query("COMMIT");
  } finally {
    await Promise.all([first.end(), second.end(), maintenance.end()]);
  }
}

async function copyVolumeFiles(volume, entries, owner) {
  await requireDocker(["create", "--name", helperContainer, "--volume", `${volume}:/payload`, postgresImage, "true"]);
  for (const [source, target] of entries) await requireDocker(["cp", source, `${helperContainer}:/payload/${target}`]);
  await requireDocker(["rm", helperContainer]);
  await requireDocker([
    "run",
    "--rm",
    "--volume",
    `${volume}:/payload`,
    postgresImage,
    "sh",
    "-c",
    `chown -R ${owner} /payload && chmod 0400 /payload/*`,
  ]);
}

function fixedEnvironment(ca) {
  return [
    "--env",
    `CANARY_DATABASE_HOST=${databaseAlias}`,
    "--env",
    "CANARY_DATABASE_PORT=5432",
    "--env",
    "CANARY_DATABASE_NAME=qm",
    "--env",
    "CANARY_DATABASE_SCHEMA=risely_agent_runtime",
    "--env",
    "CANARY_BOOTSTRAP_ADMIN_ROLE=qm",
    "--env",
    "CANARY_OWNER_DATABASE_USER=risely_agent_runtime_owner",
    "--env",
    "CANARY_MIGRATION_DATABASE_USER=risely_agent_runtime_migrator",
    "--env",
    "CANARY_RUNTIME_DATABASE_USER=risely_agent_runtime_runtime",
    "--env",
    "CANARY_DEPLOYMENT_PROFILE_REF=deployment-profile:risely:ceo:v1",
    "--env",
    "CANARY_MUTATIONS_ENABLED=0",
    "--env",
    "CANARY_PROVIDER_EXECUTION_ENABLED=0",
    "--env",
    `DATABASE_CA_CERT=${ca}`,
  ];
}

function databaseUrl(user, credential, host) {
  const url = new URL(`postgresql://${host}:5432/${CANARY_DATABASE_NAME}`);
  url.username = user;
  url["pass" + "word"] = credential;
  return url.toString();
}

async function verifyCompositeProfileIsolation(admin) {
  const ceo = ceoDeploymentProfile;
  const synthetic = syntheticDeploymentProfile;
  const hash = (character) => character.repeat(64);
  await admin.query(`SET ROLE risely_agent_runtime_owner`);
  try {
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.deployment_profiles
         (profile_ref, profile_sha256, profile)
       VALUES ($1, $2, $3::jsonb)
       ON CONFLICT (profile_ref, profile_sha256) DO NOTHING`,
      [synthetic.profileRef, synthetic.profileSha256, synthetic],
    );
  } finally {
    await admin.query(`RESET ROLE`);
  }
  const profiles = await admin.query(
    `SELECT profile_ref, profile_sha256 FROM ${CANARY_SCHEMA_NAME}.deployment_profiles ORDER BY profile_ref`,
  );
  assert.deepEqual(profiles.rows, [
    { profile_ref: ceo.profileRef, profile_sha256: ceo.profileSha256 },
    { profile_ref: synthetic.profileRef, profile_sha256: synthetic.profileSha256 },
  ]);
  await admin.query(`SET ROLE risely_agent_runtime_owner`);
  try {
    for (const profile of [ceo, synthetic]) {
      await admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.workflow_runs
           (profile_ref, profile_sha256, run_id, principal_ref, payload_hash, payload)
         VALUES ($1, $2, 'run:shared', $3, $4, '{}'::jsonb)`,
        [profile.profileRef, profile.profileSha256, profile.identity.humanPrincipalRef, hash("a")],
      );
      await admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.workflow_runs
           (profile_ref, profile_sha256, run_id, principal_ref, payload_hash, payload, created_at)
         VALUES ($1, $2, 'run:retention-scope', $3, $4, '{}'::jsonb,
                 clock_timestamp() - CASE WHEN $5::boolean THEN interval '366 days' ELSE interval '0 days' END)`,
        [profile.profileRef, profile.profileSha256, profile.identity.humanPrincipalRef, hash("7"), profile === ceo],
      );
      await admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.action_states
           (profile_ref, profile_sha256, proposal_id, run_id, principal_ref, proposal_hash, effect_key,
            proposal, state, state_hash, revision)
         VALUES ($1, $2, 'proposal:shared', 'run:shared', $3, $4, $5, '{}'::jsonb, '{}'::jsonb, $6, 0)`,
        [
          profile.profileRef,
          profile.profileSha256,
          profile.identity.humanPrincipalRef,
          hash("b"),
          hash("c"),
          hash("d"),
        ],
      );
      await admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.evaluation_candidates
           (profile_ref, profile_sha256, candidate_id, artifact_id, artifact_revision, artifact_sha256,
            evaluation_profile_sha256, evaluation_policy_sha256, candidate_sha256, candidate, policy_snapshot)
         VALUES ($1, $2, 'candidate:shared', 'artifact:shared', '1', $3, $4, $5, $6, '{}'::jsonb, '{}'::jsonb)`,
        [profile.profileRef, profile.profileSha256, hash("e"), hash("a"), hash("1"), hash("f")],
      );
      await admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.evaluation_releases
           (profile_ref, profile_sha256, release_id, candidate_id, evaluation_policy_ref,
            evaluation_policy_sha256, release_sha256, mode, passed, release,
            provider_release_eligible, release_record, policy_snapshot, evaluated_at, expires_at)
         VALUES ($1, $2, 'release:shared', 'candidate:shared', 'eval-policy:shared', $3, $4,
                 'synthetic_shadow', true, true, false, '{}'::jsonb, '{}'::jsonb, clock_timestamp(),
                 clock_timestamp() + interval '1 hour')`,
        [profile.profileRef, profile.profileSha256, hash("1"), hash("2")],
      );
      await admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.evaluation_replay_tombstones
           (profile_ref, profile_sha256, replay_ref, release_id, release_sha256, record_sha256, terminal_record)
         VALUES ($1, $2, 'replay:shared', 'release:shared', $3, $4, '{}'::jsonb)`,
        [profile.profileRef, profile.profileSha256, hash("2"), hash("3")],
      );
      await admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_outbox_events
           (profile_ref, profile_sha256, event_id, deployment_binding_sha256, outbox_payload_sha256,
            artifact_id, artifact_revision, artifact_sha256, eval_receipt_sha256,
            evaluation_release_id, outbox_item, queued_at)
         VALUES ($1, $2, 'event:shared', $3, $4, 'artifact:shared', '1', $5, $6,
                 'release:shared', '{}'::jsonb, clock_timestamp())`,
        [profile.profileRef, profile.profileSha256, hash("4"), hash("5"), hash("e"), hash("2")],
      );
      await admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_outbox_states
           (profile_ref, profile_sha256, event_id, status)
         VALUES ($1, $2, 'event:shared', 'pending')`,
        [profile.profileRef, profile.profileSha256],
      );
      await admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_delivery_reservations
           (profile_ref, profile_sha256, delivery_key, outbox_event_id, outbox_payload_sha256,
            artifact_sha256, deployment_binding_sha256, identity_resolution_sha256,
            target_binding_sha256, message_sha256, attempt_ref, identity_resolution, publication,
            status, revision, attempted_at, completed_at)
         VALUES ($1, $2, $3, 'event:shared', $4, $5, $6, $7, $8, $9, 'attempt:shared',
                 '{}'::jsonb, '{}'::jsonb, 'verified', 1, clock_timestamp(), clock_timestamp())`,
        [
          profile.profileRef,
          profile.profileSha256,
          hash("6"),
          hash("5"),
          hash("e"),
          hash("4"),
          hash("8"),
          hash("9"),
          hash("a"),
        ],
      );
      await admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_delivery_receipts
           (profile_ref, profile_sha256, delivery_key, revision, status, receipt_sha256, receipt)
         VALUES ($1, $2, $3, 1, 'verified', $4, '{}'::jsonb)`,
        [profile.profileRef, profile.profileSha256, hash("6"), hash("7")],
      );
      await admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_delivery_tombstones
           (profile_ref, profile_sha256, delivery_key, outbox_event_id, outbox_payload_sha256,
            deployment_binding_sha256, artifact_sha256, identity_resolution_sha256,
            target_binding_sha256, message_sha256, terminal_status, record_sha256,
            terminal_record, completed_at)
         VALUES ($1, $2, $3, 'event:shared', $4, $5, $6, $7, $8, $9,
                 'verified', $10, '{}'::jsonb, clock_timestamp())`,
        [
          profile.profileRef,
          profile.profileSha256,
          hash("6"),
          hash("5"),
          hash("4"),
          hash("e"),
          hash("8"),
          hash("9"),
          hash("a"),
          hash("b"),
        ],
      );
    }
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.workflow_runs
         (profile_ref, profile_sha256, run_id, principal_ref, payload_hash, payload)
       VALUES ($1, $2, 'run:ceo-only', $3, $4, '{}'::jsonb)`,
      [ceo.profileRef, ceo.profileSha256, ceo.identity.humanPrincipalRef, hash("6")],
    );
    await assert.rejects(
      admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.action_states
           (profile_ref, profile_sha256, proposal_id, run_id, principal_ref, proposal_hash, effect_key,
            proposal, state, state_hash, revision)
         VALUES ($1, $2, 'proposal:cross-profile', 'run:ceo-only', $3, $4, $5,
                 '{}'::jsonb, '{}'::jsonb, $6, 0)`,
        [
          synthetic.profileRef,
          synthetic.profileSha256,
          synthetic.identity.humanPrincipalRef,
          hash("7"),
          hash("8"),
          hash("9"),
        ],
      ),
      (error) => error?.code === "23503",
    );
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.evaluation_candidates
         (profile_ref, profile_sha256, candidate_id, artifact_id, artifact_revision, artifact_sha256,
          evaluation_profile_sha256, evaluation_policy_sha256, candidate_sha256, candidate, policy_snapshot)
       VALUES ($1, $2, 'candidate:ceo-only', 'artifact:ceo-only', '1', $3, $4, $5, $6, '{}'::jsonb, '{}'::jsonb)`,
      [ceo.profileRef, ceo.profileSha256, hash("a"), hash("2"), hash("3"), hash("b")],
    );
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.evaluation_releases
         (profile_ref, profile_sha256, release_id, candidate_id, evaluation_policy_ref,
          evaluation_policy_sha256, release_sha256, mode, passed, release,
          provider_release_eligible, release_record, policy_snapshot, evaluated_at, expires_at)
       VALUES ($1, $2, 'release:ceo-only', 'candidate:ceo-only', 'eval-policy:shared', $3, $4,
               'synthetic_shadow', true, true, false, '{}'::jsonb, '{}'::jsonb, clock_timestamp(),
               clock_timestamp() + interval '1 hour')`,
      [ceo.profileRef, ceo.profileSha256, hash("c"), hash("d")],
    );
    await assert.rejects(
      admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.evaluation_releases
           (profile_ref, profile_sha256, release_id, candidate_id, evaluation_policy_ref,
            evaluation_policy_sha256, release_sha256, mode, passed, release,
            provider_release_eligible, release_record, policy_snapshot, evaluated_at, expires_at)
         VALUES ($1, $2, 'release:cross-profile', 'candidate:ceo-only', 'eval-policy:shared', $3, $4,
                 'synthetic_shadow', true, true, false, '{}'::jsonb, '{}'::jsonb, clock_timestamp(),
                 clock_timestamp() + interval '1 hour')`,
        [synthetic.profileRef, synthetic.profileSha256, hash("c"), hash("d")],
      ),
      (error) => error?.code === "23503",
    );
    await assert.rejects(
      admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_outbox_events
           (profile_ref, profile_sha256, event_id, deployment_binding_sha256, outbox_payload_sha256,
            artifact_id, artifact_revision, artifact_sha256, eval_receipt_sha256,
            evaluation_release_id, outbox_item, queued_at)
         VALUES ($1, $2, 'event:cross-profile', $3, $4, 'artifact:shared', '1', $5, $6,
                 'release:ceo-only', '{}'::jsonb, clock_timestamp())`,
        [synthetic.profileRef, synthetic.profileSha256, hash("e"), hash("f"), hash("1"), hash("2")],
      ),
      (error) => error?.code === "23503",
    );
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.action_states
         (profile_ref, profile_sha256, proposal_id, run_id, principal_ref, proposal_hash, effect_key,
          proposal, state, state_hash, revision)
       VALUES ($1, $2, 'proposal:ceo-only', 'run:ceo-only', $3, $4, $5,
               '{}'::jsonb, '{}'::jsonb, $6, 0)`,
      [ceo.profileRef, ceo.profileSha256, ceo.identity.humanPrincipalRef, hash("7"), hash("8"), hash("9")],
    );
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.evaluation_candidates
         (profile_ref, profile_sha256, candidate_id, artifact_id, artifact_revision, artifact_sha256,
          evaluation_profile_sha256, evaluation_policy_sha256, candidate_sha256, candidate, policy_snapshot)
       VALUES ($1, $2, 'candidate:synthetic-only', 'artifact:ceo-only', '1', $3, $4, $5, $6, '{}'::jsonb, '{}'::jsonb)`,
      [synthetic.profileRef, synthetic.profileSha256, hash("9"), hash("4"), hash("5"), hash("0")],
    );
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.evaluation_releases
         (profile_ref, profile_sha256, release_id, candidate_id, evaluation_policy_ref,
          evaluation_policy_sha256, release_sha256, mode, passed, release,
          provider_release_eligible, release_record, policy_snapshot, evaluated_at, expires_at)
       VALUES ($1, $2, 'release:ceo-only', 'candidate:synthetic-only', 'eval-policy:shared', $3, $4,
               'synthetic_shadow', true, true, false, '{}'::jsonb, '{}'::jsonb, clock_timestamp(),
               clock_timestamp() + interval '1 hour')`,
      [synthetic.profileRef, synthetic.profileSha256, hash("c"), hash("d")],
    );
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.evaluation_replay_tombstones
         (profile_ref, profile_sha256, replay_ref, release_id, release_sha256, record_sha256, terminal_record)
       VALUES ($1, $2, 'replay:ceo-only', 'release:ceo-only', $3, $4, '{}'::jsonb)`,
      [ceo.profileRef, ceo.profileSha256, hash("d"), hash("e")],
    );
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_outbox_events
         (profile_ref, profile_sha256, event_id, deployment_binding_sha256, outbox_payload_sha256,
          artifact_id, artifact_revision, artifact_sha256, eval_receipt_sha256,
          evaluation_release_id, outbox_item, queued_at)
       VALUES ($1, $2, 'event:ceo-only', $3, $4, 'artifact:ceo-only', '1', $5, $6,
               'release:ceo-only', '{}'::jsonb, clock_timestamp())`,
      [ceo.profileRef, ceo.profileSha256, hash("d"), hash("c"), hash("a"), hash("d")],
    );
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_outbox_states
         (profile_ref, profile_sha256, event_id, status)
       VALUES ($1, $2, 'event:ceo-only', 'pending')`,
      [ceo.profileRef, ceo.profileSha256],
    );
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_delivery_reservations
         (profile_ref, profile_sha256, delivery_key, outbox_event_id, outbox_payload_sha256,
          artifact_sha256, deployment_binding_sha256, identity_resolution_sha256,
          target_binding_sha256, message_sha256, attempt_ref, identity_resolution, publication,
          status, revision)
       VALUES ($1, $2, $3, 'event:ceo-only', $4, $5, $6, $7, $8, $9,
               'attempt:ceo-only', '{}'::jsonb, '{}'::jsonb, 'reserved', 0)`,
      [ceo.profileRef, ceo.profileSha256, hash("f"), hash("c"), hash("a"), hash("d"), hash("1"), hash("2"), hash("3")],
    );
    await assert.rejects(
      admin.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_delivery_receipts
           (profile_ref, profile_sha256, delivery_key, revision, status, receipt_sha256, receipt)
         VALUES ($1, $2, $3, 1, 'verified', $4, '{}'::jsonb)`,
        [synthetic.profileRef, synthetic.profileSha256, hash("f"), hash("0")],
      ),
      (error) => error?.code === "23503",
    );
    await admin.query(
      `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_event_tombstones
         (profile_ref, profile_sha256, event_id, deployment_binding_sha256, outbox_payload_sha256,
          artifact_id, artifact_revision, artifact_sha256, eval_receipt_sha256, failure_code,
          event_identity_sha256, record_sha256, terminal_record, completed_at)
       VALUES ($1, $2, 'event:shared', $3, $4, 'artifact:shared', '1', $5, $6,
               'eval_release_expired', $7, $8, '{}'::jsonb, clock_timestamp())`,
      [ceo.profileRef, ceo.profileSha256, hash("4"), hash("5"), hash("e"), hash("2"), hash("c"), hash("d")],
    );
    const wrongProfileCas = await admin.query(
      `UPDATE ${CANARY_SCHEMA_NAME}.action_states
       SET revision = revision + 1
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND proposal_id = 'proposal:ceo-only' AND revision = 0`,
      [synthetic.profileRef, synthetic.profileSha256],
    );
    assert.equal(wrongProfileCas.rowCount, 0);
    const wrongProfileClaim = await admin.query(
      `UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_states
       SET status = 'claimed', claim_ref = 'claim:wrong-profile', claim_owner_ref = 'owner:wrong-profile',
           claim_acquired_at = clock_timestamp(), claim_expires_at = clock_timestamp() + interval '1 minute',
           revision = revision + 1
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND event_id = 'event:ceo-only' AND revision = 0`,
      [synthetic.profileRef, synthetic.profileSha256],
    );
    assert.equal(wrongProfileClaim.rowCount, 0);
    const cas = await admin.query(
      `UPDATE ${CANARY_SCHEMA_NAME}.action_states
       SET revision = revision + 1, state_hash = $4
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND proposal_id = $3 AND revision = 0`,
      [ceo.profileRef, ceo.profileSha256, "proposal:shared", hash("e")],
    );
    assert.equal(cas.rowCount, 1);
    await admin.query(
      `UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_states
       SET status = 'claimed', claim_ref = 'claim:ceo', claim_owner_ref = 'owner:ceo',
           claim_acquired_at = clock_timestamp(), claim_expires_at = clock_timestamp() + interval '1 minute',
           revision = revision + 1
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND event_id = 'event:shared' AND revision = 0`,
      [ceo.profileRef, ceo.profileSha256],
    );
    const isolated = await admin.query(
      `SELECT profile_ref,
              (SELECT revision FROM ${CANARY_SCHEMA_NAME}.action_states actions
               WHERE actions.profile_ref = profiles.profile_ref AND actions.profile_sha256 = profiles.profile_sha256
                 AND proposal_id = 'proposal:shared')::integer AS action_revision,
              (SELECT status FROM ${CANARY_SCHEMA_NAME}.surface_outbox_states states
               WHERE states.profile_ref = profiles.profile_ref AND states.profile_sha256 = profiles.profile_sha256
                 AND event_id = 'event:shared') AS outbox_status,
              (SELECT count(*)::integer FROM ${CANARY_SCHEMA_NAME}.surface_delivery_reservations reservations
               WHERE reservations.profile_ref = profiles.profile_ref AND reservations.profile_sha256 = profiles.profile_sha256
                 AND delivery_key = $1) AS delivery_rows,
              (SELECT count(*)::integer FROM ${CANARY_SCHEMA_NAME}.surface_delivery_receipts receipts
               WHERE receipts.profile_ref = profiles.profile_ref AND receipts.profile_sha256 = profiles.profile_sha256
                 AND delivery_key = $1) AS receipt_rows,
              (SELECT count(*)::integer FROM ${CANARY_SCHEMA_NAME}.surface_delivery_tombstones tombstones
               WHERE tombstones.profile_ref = profiles.profile_ref AND tombstones.profile_sha256 = profiles.profile_sha256
                 AND delivery_key = $1) AS delivery_tombstone_rows,
              (SELECT count(*)::integer FROM ${CANARY_SCHEMA_NAME}.evaluation_replay_tombstones replay
               WHERE replay.profile_ref = profiles.profile_ref AND replay.profile_sha256 = profiles.profile_sha256
                 AND replay_ref = 'replay:ceo-only') AS ceo_replay_tombstone_rows,
              (SELECT count(*)::integer FROM ${CANARY_SCHEMA_NAME}.surface_event_tombstones event_tombstones
               WHERE event_tombstones.profile_ref = profiles.profile_ref
                 AND event_tombstones.profile_sha256 = profiles.profile_sha256
                 AND event_id = 'event:shared') AS ceo_event_tombstone_rows,
              (SELECT status FROM ${CANARY_SCHEMA_NAME}.surface_outbox_states ceo_state
               WHERE ceo_state.profile_ref = profiles.profile_ref AND ceo_state.profile_sha256 = profiles.profile_sha256
                 AND event_id = 'event:ceo-only') AS ceo_only_outbox_status,
              (SELECT revision::integer FROM ${CANARY_SCHEMA_NAME}.action_states ceo_action
               WHERE ceo_action.profile_ref = profiles.profile_ref AND ceo_action.profile_sha256 = profiles.profile_sha256
                 AND proposal_id = 'proposal:ceo-only') AS ceo_only_action_revision
       FROM ${CANARY_SCHEMA_NAME}.deployment_profiles profiles
       ORDER BY profile_ref`,
      [hash("6")],
    );
    assert.deepEqual(isolated.rows, [
      {
        profile_ref: ceo.profileRef,
        action_revision: 1,
        outbox_status: "claimed",
        delivery_rows: 1,
        receipt_rows: 1,
        delivery_tombstone_rows: 1,
        ceo_replay_tombstone_rows: 1,
        ceo_event_tombstone_rows: 1,
        ceo_only_outbox_status: "pending",
        ceo_only_action_revision: 0,
      },
      {
        profile_ref: synthetic.profileRef,
        action_revision: 0,
        outbox_status: "pending",
        delivery_rows: 1,
        receipt_rows: 1,
        delivery_tombstone_rows: 1,
        ceo_replay_tombstone_rows: 0,
        ceo_event_tombstone_rows: 0,
        ceo_only_outbox_status: null,
        ceo_only_action_revision: null,
      },
    ]);
  } finally {
    await admin.query("RESET ROLE");
  }
}

test(
  "isolated PostgreSQL 16 provisions credentials then runs migrate and retention wrappers safely",
  { skip, timeout: 300000 },
  async (t) => {
    const temporaryDirectory = await mkdtemp(join(tmpdir(), "risely-agent-runtime-pg16-"));
    const certificatePath = join(temporaryDirectory, "server.crt");
    const privateKeyPath = join(temporaryDirectory, "server.key");
    const migrationCredentialPath = join(temporaryDirectory, "migration.password");
    const runtimeCredentialPath = join(temporaryDirectory, "runtime.password");
    const rotatedMigrationCredentialPath = join(temporaryDirectory, "rotated-migration.password");
    const rotatedRuntimeCredentialPath = join(temporaryDirectory, "rotated-runtime.password");
    const passfilePath = join(temporaryDirectory, "admin.pgpass");
    let admin;
    t.after(async () => {
      await admin?.end().catch(() => {});
      await docker(["rm", "--force", databaseContainer]);
      await docker(["rm", "--force", helperContainer]);
      await docker(["network", "rm", networkName]);
      await docker(["volume", "rm", "--force", certificateVolume]);
      await docker(["volume", "rm", "--force", secretVolume]);
      await docker(["image", "rm", "--force", runtimeImage, testImage, operatorImage]);
      await rm(temporaryDirectory, { force: true, recursive: true });
    });
    await requireRun("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "1",
      "-subj",
      `/CN=${databaseAlias}`,
      "-addext",
      `subjectAltName=DNS:${databaseAlias}`,
      "-keyout",
      privateKeyPath,
      "-out",
      certificatePath,
    ]);
    await Promise.all([
      writeFile(migrationCredentialPath, migrationPassword, { mode: 0o400 }),
      writeFile(runtimeCredentialPath, runtimePassword, { mode: 0o400 }),
      writeFile(rotatedMigrationCredentialPath, rotatedMigrationPassword, { mode: 0o400 }),
      writeFile(rotatedRuntimeCredentialPath, rotatedRuntimePassword, { mode: 0o400 }),
      writeFile(passfilePath, `${databaseAlias}:5432:${CANARY_DATABASE_NAME}:qm:${bootstrapPassword}\n`, {
        mode: 0o400,
      }),
    ]);
    await Promise.all([chmod(certificatePath, 0o400), chmod(privateKeyPath, 0o400)]);
    await requireDocker(["network", "create", networkName]);
    await requireDocker(["volume", "create", certificateVolume]);
    await requireDocker(["volume", "create", secretVolume]);
    await copyVolumeFiles(
      certificateVolume,
      [
        [certificatePath, "server.crt"],
        [privateKeyPath, "server.key"],
      ],
      "70:70",
    );
    await copyVolumeFiles(
      secretVolume,
      [
        [certificatePath, "ca.crt"],
        [migrationCredentialPath, "migration.password"],
        [runtimeCredentialPath, "runtime.password"],
        [passfilePath, "admin.pgpass"],
      ],
      "1000:1000",
    );
    await requireDocker([
      "run",
      "--detach",
      "--name",
      databaseContainer,
      "--network",
      networkName,
      "--network-alias",
      databaseAlias,
      "--publish",
      `127.0.0.1:${hostPort}:5432`,
      "--volume",
      `${certificateVolume}:/certificates:ro`,
      "--env",
      `POSTGRES_PASSWORD=${postgresPassword}`,
      "--env",
      `POSTGRES_DB=${CANARY_DATABASE_NAME}`,
      postgresImage,
      "postgres",
      "-c",
      "ssl=on",
      "-c",
      "ssl_cert_file=/certificates/server.crt",
      "-c",
      "ssl_key_file=/certificates/server.key",
    ]);
    await waitForDatabase();
    admin = await adminClient();
    await admin.query(
      `CREATE ROLE qm LOGIN CREATEROLE NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS PASSWORD '${bootstrapPassword}';
     ALTER DATABASE qm OWNER TO qm;`,
    );
    await requireDocker([
      "build",
      "--tag",
      operatorImage,
      "--target",
      "credential-operator",
      "--file",
      dockerfilePath,
      layerDirectory,
    ]);
    const ca = await readFile(certificatePath, "utf8");
    const adminUrl = databaseUrl("qm", bootstrapPassword, databaseAlias);
    const dbOperatorArgs = (phase, secretEnvironment = []) => [
      "run",
      "--rm",
      "--network",
      networkName,
      ...fixedEnvironment(ca),
      ...secretEnvironment.flatMap(([name, value]) => ["--env", `${name}=${value}`]),
      "--entrypoint",
      "node",
      operatorImage,
      "/app/canary/service/ceo-canary/src/db-operator.mjs",
      phase,
    ];
    const inventoryArgs = dbOperatorArgs("inventory", [["CANARY_BOOTSTRAP_DATABASE_URL", adminUrl]]);
    const initialInventory = await requireDocker(inventoryArgs);
    assert.match(initialInventory.stdout, /"schema":null/);
    assert.match(initialInventory.stdout, /risely_agent_runtime_operator_inventory_complete_v1/);
    assert.notEqual((await docker([...inventoryArgs, "caller-command-override"])).exitCode, 0);
    const bootstrapArgs = dbOperatorArgs("bootstrap", [["CANARY_BOOTSTRAP_DATABASE_URL", adminUrl]]);
    await requireDocker(bootstrapArgs);
    assert.notEqual((await docker(bootstrapArgs)).exitCode, 0);
    const structural = await admin.query(
      `SELECT rolname, rolcanlogin
     FROM pg_catalog.pg_roles
     WHERE rolname = ANY ($1::text[])
     ORDER BY rolname`,
      [[CANARY_MIGRATION_DATABASE_USER, CANARY_RUNTIME_DATABASE_USER]],
    );
    assert.deepEqual(structural.rows, [
      { rolname: CANARY_MIGRATION_DATABASE_USER, rolcanlogin: false },
      { rolname: CANARY_RUNTIME_DATABASE_USER, rolcanlogin: false },
    ]);
    await requireDocker([
      "build",
      "--tag",
      runtimeImage,
      "--target",
      "runtime",
      "--file",
      dockerfilePath,
      layerDirectory,
    ]);
    await requireDocker(["build", "--tag", testImage, "--target", "test", "--file", dockerfilePath, layerDirectory]);
    const initialMigrationUrl = databaseUrl(CANARY_MIGRATION_DATABASE_USER, migrationPassword, databaseAlias);
    const initialRuntimeUrl = databaseUrl(CANARY_RUNTIME_DATABASE_USER, runtimePassword, databaseAlias);
    await requireDocker(
      dbOperatorArgs("provision", [
        ["CANARY_BOOTSTRAP_DATABASE_URL", adminUrl],
        ["CANARY_MIGRATION_DATABASE_URL", initialMigrationUrl],
        ["CANARY_DATABASE_URL", initialRuntimeUrl],
      ]),
    );
    const operatorArgs = [
      "run",
      "--rm",
      "--network",
      networkName,
      "--volume",
      `${secretVolume}:/run/canary:ro`,
      ...fixedEnvironment(ca),
      "--env",
      "CANARY_MIGRATION_PASSWORD_FILE=/run/canary/migration.password",
      "--env",
      "CANARY_RUNTIME_PASSWORD_FILE=/run/canary/runtime.password",
      "--env",
      "CANARY_BOOTSTRAP_ADMIN_PASSFILE=/run/canary/admin.pgpass",
      "--env",
      "CANARY_DATABASE_CA_FILE=/run/canary/ca.crt",
      operatorImage,
    ];
    const provisioning = await docker(operatorArgs);
    if (provisioning.exitCode !== 0) {
      const state = await admin.query(
        `SELECT rolname, rolcanlogin FROM pg_catalog.pg_roles
       WHERE rolname = ANY ($1::text[]) ORDER BY rolname`,
        [[CANARY_MIGRATION_DATABASE_USER, CANARY_RUNTIME_DATABASE_USER]],
      );
      assert.fail(`credential provisioning failed with login state ${JSON.stringify(state.rows)}`);
    }
    const authenticated = await admin.query(
      `SELECT rolname, rolcanlogin
     FROM pg_catalog.pg_roles
     WHERE rolname = ANY ($1::text[])
     ORDER BY rolname`,
      [[CANARY_MIGRATION_DATABASE_USER, CANARY_RUNTIME_DATABASE_USER]],
    );
    assert.deepEqual(authenticated.rows, [
      { rolname: CANARY_MIGRATION_DATABASE_USER, rolcanlogin: true },
      { rolname: CANARY_RUNTIME_DATABASE_USER, rolcanlogin: true },
    ]);
    await requireDocker(operatorArgs);
    const refusedCredentialReuse = await docker(
      operatorArgs.map((argument) =>
        argument === "CANARY_RUNTIME_PASSWORD_FILE=/run/canary/runtime.password"
          ? "CANARY_RUNTIME_PASSWORD_FILE=/run/canary/migration.password"
          : argument,
      ),
    );
    assert.notEqual(refusedCredentialReuse.exitCode, 0);
    const probeAuthentication = async (user, password) =>
      docker([
        "run",
        "--rm",
        "--network",
        networkName,
        ...fixedEnvironment(ca),
        "--env",
        `TEST_DATABASE_USER=${user}`,
        "--env",
        `TEST_DATABASE_PASSWORD=${password}`,
        runtimeImage,
        "node",
        "--input-type=module",
        "--eval",
        "const pg = (await import('pg')).default; const client = new pg.Client({host: process.env.CANARY_DATABASE_HOST, port: 5432, database: 'qm', user: process.env.TEST_DATABASE_USER, ['pass' + 'word']: process.env.TEST_DATABASE_PASSWORD, ssl: {ca: process.env.DATABASE_CA_CERT, rejectUnauthorized: true}}); await client.connect(); await client.query('SELECT 1'); await client.end()",
      ]);
    assert.equal((await probeAuthentication(CANARY_MIGRATION_DATABASE_USER, migrationPassword)).exitCode, 0);
    assert.equal((await probeAuthentication(CANARY_RUNTIME_DATABASE_USER, runtimePassword)).exitCode, 0);
    await copyVolumeFiles(
      secretVolume,
      [
        [rotatedMigrationCredentialPath, "migration.password"],
        [rotatedRuntimeCredentialPath, "runtime.password"],
      ],
      "1000:1000",
    );
    await requireDocker(operatorArgs);
    assert.notEqual((await probeAuthentication(CANARY_MIGRATION_DATABASE_USER, migrationPassword)).exitCode, 0);
    assert.notEqual((await probeAuthentication(CANARY_RUNTIME_DATABASE_USER, runtimePassword)).exitCode, 0);
    assert.equal((await probeAuthentication(CANARY_MIGRATION_DATABASE_USER, rotatedMigrationPassword)).exitCode, 0);
    assert.equal((await probeAuthentication(CANARY_RUNTIME_DATABASE_USER, rotatedRuntimePassword)).exitCode, 0);
    const topology = await admin.query(
      `SELECT count(*)::integer AS edges,
            count(*) FILTER (WHERE membership.grantor = 10)::integer AS bootstrap_edges
     FROM pg_catalog.pg_auth_members membership
     JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
     JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
     WHERE granted_role.rolname = ANY ($1::text[])
        OR member_role.rolname = ANY ($1::text[])`,
      [
        [
          "risely_agent_runtime_owner",
          CANARY_EVALUATION_WRITER_DATABASE_USER,
          CANARY_MIGRATION_DATABASE_USER,
          CANARY_RUNTIME_DATABASE_USER,
        ],
      ],
    );
    assert.deepEqual(topology.rows, [{ edges: 5, bootstrap_edges: 4 }]);
    const migrationUrl = databaseUrl(CANARY_MIGRATION_DATABASE_USER, rotatedMigrationPassword, databaseAlias);
    const migrationArgs = [
      "run",
      "--rm",
      "--network",
      networkName,
      ...fixedEnvironment(ca),
      "--env",
      `CANARY_MIGRATION_DATABASE_URL=${migrationUrl}`,
      runtimeImage,
      "node",
      "--input-type=module",
      "--eval",
      "const { migrate } = await import('/app/canary/service/ceo-canary/src/migrate.mjs'); await migrate(process.env)",
    ];
    await admin.query("CREATE EXTENSION file_fdw; GRANT USAGE ON FOREIGN DATA WRAPPER file_fdw TO PUBLIC");
    assert.notEqual(
      (await docker(dbOperatorArgs("migrate", [["CANARY_MIGRATION_DATABASE_URL", migrationUrl]]))).exitCode,
      0,
    );
    assert.equal(
      (
        await admin.query(
          `SELECT count(*)::integer AS count FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace WHERE namespace.nspname = '${CANARY_SCHEMA_NAME}'`,
        )
      ).rows[0].count,
      0,
    );
    assert.equal(
      (await admin.query("SELECT count(*)::integer AS count FROM pg_catalog.pg_foreign_server")).rows[0].count,
      0,
    );
    await admin.query("REVOKE USAGE ON FOREIGN DATA WRAPPER file_fdw FROM PUBLIC; DROP EXTENSION file_fdw");
    await admin.query(
      `CREATE SCHEMA migration_event_escape;
     CREATE TABLE migration_event_escape.effects (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
     CREATE FUNCTION migration_event_escape.capture_ddl() RETURNS event_trigger
       LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
       AS 'BEGIN INSERT INTO migration_event_escape.effects DEFAULT VALUES; END';
     REVOKE EXECUTE ON FUNCTION migration_event_escape.capture_ddl() FROM PUBLIC;
     CREATE EVENT TRIGGER migration_escape_enabled
       ON ddl_command_start EXECUTE FUNCTION migration_event_escape.capture_ddl();
     TRUNCATE migration_event_escape.effects`,
    );
    assert.notEqual((await docker(migrationArgs)).exitCode, 0);
    assert.equal(
      (await admin.query("SELECT count(*)::integer AS count FROM migration_event_escape.effects")).rows[0].count,
      0,
    );
    assert.equal(
      (
        await admin.query(
          `SELECT count(*)::integer AS count FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace WHERE namespace.nspname = '${CANARY_SCHEMA_NAME}'`,
        )
      ).rows[0].count,
      0,
    );
    await admin.query("DROP EVENT TRIGGER migration_escape_enabled; DROP SCHEMA migration_event_escape CASCADE");
    await requireDocker(dbOperatorArgs("migrate", [["CANARY_MIGRATION_DATABASE_URL", migrationUrl]]));
    const migration = await admin.query(`SELECT version, checksum FROM ${CANARY_SCHEMA_NAME}.schema_migrations`);
    assert.deepEqual(migration.rows, [{ version: SCHEMA_VERSION, checksum: migrationChecksum() }]);
    const runtimeUrl = databaseUrl(CANARY_RUNTIME_DATABASE_USER, rotatedRuntimePassword, databaseAlias);
    await requireDocker(dbOperatorArgs("readiness", [["CANARY_DATABASE_URL", runtimeUrl]]));
    await requireDocker(
      dbOperatorArgs("provision", [
        ["CANARY_BOOTSTRAP_DATABASE_URL", adminUrl],
        ["CANARY_MIGRATION_DATABASE_URL", migrationUrl],
        ["CANARY_DATABASE_URL", runtimeUrl],
      ]),
    );
    await requireDocker(dbOperatorArgs("readiness", [["CANARY_DATABASE_URL", runtimeUrl]]));
    await admin.query(
      `ALTER ROLE ${CANARY_EVALUATION_WRITER_DATABASE_USER} LOGIN PASSWORD '${evaluationWriterPassword}'`,
    );
    await verifyEntityLockConcurrency();
    const evaluationWriterUrl = databaseUrl(
      CANARY_EVALUATION_WRITER_DATABASE_USER,
      evaluationWriterPassword,
      databaseAlias,
    );
    await requireDocker([
      "run",
      "--rm",
      runtimeImage,
      "node",
      "--input-type=module",
      "--eval",
      `for (const testOnlyModule of ['/app/canary/deployment-profiles/testing.mjs', '/app/canary/evals/testing.mjs', '/app/canary/evals/testing-result-store.mjs']) {
       let absent = false;
       try { await import(testOnlyModule); }
       catch (error) { if (error?.code === 'ERR_MODULE_NOT_FOUND') absent = true; else throw error; }
       if (!absent) throw new Error('production_testing_module_present:' + testOnlyModule);
     }`,
    ]);
    const runtimeVerificationArgs = [
      "run",
      "--rm",
      "--network",
      networkName,
      ...fixedEnvironment(ca),
      "--env",
      `CANARY_DATABASE_URL=${runtimeUrl}`,
      "--env",
      `CANARY_EVALUATION_WRITER_DATABASE_URL=${evaluationWriterUrl}`,
      testImage,
      "node",
      "--input-type=module",
      "--eval",
      `const pg = (await import('pg')).default;
     const { syntheticDeploymentProfile, syntheticTestJudgePrivateKeys } = await import('/app/canary/deployment-profiles/testing.mjs');
     const { ceoDeploymentProfile } = await import('/app/canary/deployment-profiles/index.mjs');
     await import('/app/canary/evals/testing.mjs');
     await import('/app/canary/evals/testing-result-store.mjs');
     const { PostgresCanaryStore, evaluationWriterPoolConfig, runtimePoolConfig, verifyCanaryDatabase } = await import('/app/canary/service/ceo-canary/src/postgres-store.mjs');
     const { PostgresEvaluationWriter } = await import('/app/canary/service/ceo-canary/src/evaluation-writer.mjs');
     const { createRuntimeScope } = await import('/app/canary/runtime-scope/index.mjs');
     const { createPrivateKey, sign } = await import('node:crypto');
     const { normalizeMeetingDossier } = await import('/app/canary/chief-of-staff/index.mjs');
     const { createProviderFreeEvaluationAuthority, mintEvaluationRelease, prepareEvaluationCandidate } = await import('/app/canary/evals/index.mjs');
     const { judgeResultSigningPayload } = await import('/app/canary/evals/release-authority.mjs');
     const { CanonicalCeoSurfaceStore } = await import('/app/canary/service/ceo-surface/src/index.mjs');
     const pool = new pg.Pool(runtimePoolConfig(process.env));
     const writerPool = new pg.Pool(evaluationWriterPoolConfig(process.env));
     await verifyCanaryDatabase(pool);
     const ceoScope = createRuntimeScope(ceoDeploymentProfile);
     const ceoStore = new PostgresCanaryStore({pool, scope: ceoScope});
     await ceoStore.initialize();
     const scope = createRuntimeScope(syntheticDeploymentProfile);
     const store = new PostgresCanaryStore({pool, scope});
     await store.initialize();
     try { await store.readRun('run:missing', {principalRef: scope.profile.identity.humanPrincipalRef, requestHash: '${"d".repeat(64)}'}); }
     catch (error) { if (error.code !== 'run_not_found') throw error; }
     let runtimeCallDenied = false;
     try {
       await pool.query(
         'SELECT risely_agent_runtime.persist_authorized_evaluation($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7::jsonb)',
         [scope.profileRef, scope.profileSha256, '${"f".repeat(64)}', {}, [], 'evaluation-release:${"f".repeat(64)}', {}],
       );
     } catch (error) { if (error?.code === '42501') runtimeCallDenied = true; else throw error; }
     if (!runtimeCallDenied) throw new Error('runtime_evaluation_write_not_denied');
     const evidence = scope.contracts.EvidenceBundle.create({
       principalBinding: scope.principalBinding,
       evidence: [{source: 'calendar', sourceRecordRef: 'source-record:${"1".repeat(64)}', contentSha256: '${"1".repeat(64)}',
         relatedContentSha256: ['${"2".repeat(64)}'], observedAt: '2026-08-26T16:55:00.000Z',
         fetchedAt: '2026-08-26T16:56:00.000Z', status: 'available', trust: 'untrusted_source_data',
         availability: 'available', sourceTrust: 'untrusted_source_data', sourceAvailability: 'available',
         claimRefs: ['claim:${"2".repeat(64)}']}],
     });
     const artifact = scope.contracts.WorkflowArtifact.create({
       principalBinding: scope.principalBinding, sourceLane: 'chief_of_staff', sourceArtifactRef: 'source:${"3".repeat(64)}',
       sourceArtifactSha256: '${"3".repeat(64)}', sourceRevision: '${"4".repeat(64)}', workflowKind: 'meeting_prep',
       state: 'ready', evidenceBundle: evidence, updatedAt: '2026-08-26T17:00:00.000Z',
     });
     for (const method of ['appendEvaluationCandidate', 'appendEvaluationJudgeResult', 'appendEvaluationRelease', 'readEvaluationRelease']) {
       if (typeof store[method] !== 'undefined') throw new Error('public_low_level_evaluation_method');
     }
     const dossier = normalizeMeetingDossier({
       meetingKey: '${"8".repeat(64)}',
       generatedAt: '2026-08-26T17:00:00.000Z',
       calendarEvidenceHash: '${"1".repeat(64)}',
       sources: [
         {source: 'calendar', availability: 'available'},
         {source: 'clarify', availability: 'unavailable'},
         {source: 'command_center_brain', availability: 'available'},
         {source: 'gmail', availability: 'available'},
         {source: 'notion', availability: 'not_connected'}],
       evidence: [
         {evidenceRef: 'evidence:calendar', source: 'calendar', evidenceHash: '${"1".repeat(64)}', capturedAt: '2026-08-26T16:55:00.000Z'},
         {evidenceRef: 'evidence:brain', source: 'command_center_brain', evidenceHash: '${"2".repeat(64)}', capturedAt: '2026-08-26T16:55:00.000Z'},
         {evidenceRef: 'evidence:gmail', source: 'gmail', evidenceHash: '${"3".repeat(64)}', capturedAt: '2026-08-26T16:55:00.000Z'}],
       sections: {
         accountOverview: [{claimId: 'claim:account', text: 'Account context is ready for review.', citations: ['evidence:brain']}],
         contactBackground: [{claimId: 'claim:contact', text: 'Contact context is ready for review.', citations: ['evidence:gmail']}],
         recommendedPositioning: [{claimId: 'claim:positioning', text: 'Positioning is ready for review.', citations: ['evidence:calendar']}]},
     });
     const evalEvidence = scope.contracts.EvidenceBundle.create({
       principalBinding: scope.principalBinding,
       evidence: dossier.evidence.map((entry, index) => ({
         source: entry.source,
         sourceRecordRef: 'source-record:' + String(index + 5).repeat(64),
         contentSha256: entry.evidenceHash,
         relatedContentSha256: [],
         observedAt: entry.capturedAt,
         fetchedAt: entry.capturedAt,
         status: 'cited',
         trust: 'untrusted_source_data',
         availability: 'available',
         sourceTrust: 'untrusted_source_data',
         sourceAvailability: 'available',
         claimRefs: Object.values(dossier.sections).flat()
           .filter((claim) => claim.citations.includes(entry.evidenceRef))
           .map((claim) => 'claim:' + scope.contracts.PrincipalBinding.hash({claimId: claim.claimId, text: claim.text, trust: claim.trust})),
       })),
     });
     const evalArtifact = scope.contracts.WorkflowArtifact.create({
       principalBinding: scope.principalBinding,
       sourceLane: 'chief_of_staff',
       sourceArtifactRef: 'source:${"7".repeat(64)}',
       sourceArtifactSha256: dossier.artifactHash,
       sourceRevision: '${"8".repeat(64)}',
       workflowKind: 'meeting_prep',
       state: 'ready',
       evidenceBundle: evalEvidence,
       updatedAt: '2026-08-26T17:00:00.000Z',
     });
     const fixtureJudges = scope.profile.evalPolicy.trustedJudgeRoots.map((root) => ({
       ...root,
       privateKey: createPrivateKey({key: syntheticTestJudgePrivateKeys[root.keyId], format: 'jwk'}),
     }));
     const writer = new PostgresEvaluationWriter({pool: writerPool, scope});
     await writer.initialize();
     const resultStore = writer.evaluationResultStore();
     if (!Object.isFrozen(resultStore) || resultStore !== writer.evaluationResultStore()) throw new Error('evaluation_port_not_stable');
     const evaluationStartedAt = '${new Date(Date.now() - 30_000).toISOString()}';
     const decisionAt = '${new Date().toISOString()}';
     const evalExpiresAt = '${new Date(Date.now() + 3_600_000).toISOString()}';
     const authority = createProviderFreeEvaluationAuthority({
       runtimeScope: scope,
       resultStore,
       readAuthorityTime: () => decisionAt,
     });
     let clonedPortRejected = false;
     try {
       createProviderFreeEvaluationAuthority({
         runtimeScope: scope,
         resultStore: {...resultStore},
         readAuthorityTime: () => decisionAt,
       });
     } catch { clonedPortRejected = true; }
     if (!clonedPortRejected) throw new Error('cloned_evaluation_port_accepted');
     const candidateInput = {
       artifact: evalArtifact,
       evaluationPayload: dossier,
       evaluationStartedAt,
       expiresAt: evalExpiresAt,
     };
     const candidate = prepareEvaluationCandidate(authority, {...candidateInput, runNonce: '${"9".repeat(64)}'});
     const issueQuorum = (subject) => fixtureJudges.map((judge) => {
       const projection = {
         schemaVersion: 1,
         receiptType: 'ProviderFreeJudgeResult',
         keyId: judge.keyId,
         judgeRef: judge.judgeRef,
         judgeClass: judge.judgeClass,
         originRef: judge.originRef,
         runRef: subject.runRef,
         artifactSha256: subject.artifactSha256,
         evidenceSha256: subject.evidenceSha256,
         evaluationPayloadSha256: subject.evaluationPayloadSha256,
         deploymentProfileSha256: subject.deploymentProfileSha256,
         evaluationProfileSha256: subject.evaluationProfileSha256,
         policySha256: subject.policySha256,
         deterministicResultsSha256: subject.deterministicResultsSha256,
         sideEffectCount: 0,
         scores: {accuracy: 5, grounding: 5, safety: 5, voice: 4, usefulness: 4},
         gateResults: Object.fromEntries(subject.policySnapshot.requiredGates.map((gate) => [gate, true])),
         passed: true,
         failures: [],
         evidenceRefs: [
           'artifact:' + subject.artifactSha256,
           'evidence:' + subject.evidenceSha256,
           'payload:' + subject.evaluationPayloadSha256],
         issuedAt: decisionAt,
         expiresAt: subject.expiresAt,
         nonce: scope.contracts.PrincipalBinding.hash({runRef: subject.runRef, judgeRef: judge.judgeRef}),
       };
       const receiptSha256 = scope.contracts.PrincipalBinding.hash(projection);
       const pending = {...projection, receiptSha256, signature: 'A'.repeat(86)};
       return {...projection, receiptSha256, signature: sign(null, judgeResultSigningPayload(pending), judge.privateKey).toString('base64url')};
     });
     const judgeResults = issueQuorum(candidate);
     const release = await mintEvaluationRelease(authority, {candidate, judgeResults});
     await mintEvaluationRelease(authority, {candidate, judgeResults});
     const durableRelease = {releaseId: 'evaluation-release:' + release.releaseSha256};
     const reloadedRelease = await resultStore.readRelease(durableRelease.releaseId);
     if (reloadedRelease?.releaseSha256 !== release.releaseSha256) throw new Error('durable_release_mismatch');
     const contractHash = scope.contracts.PrincipalBinding.hash;
     const candidateStoreSha256 = (candidateValue) => contractHash({
       digestRevision: 'EvaluationCandidate.store.sha256.v1',
       profileRef: scope.profileRef,
       profileSha256: scope.profileSha256,
       candidate: candidateValue,
     });
     const resealJudge = (judgeValue) => {
       const projection = structuredClone(judgeValue);
       delete projection.receiptSha256;
       delete projection.signature;
       return {...projection, receiptSha256: contractHash(projection), signature: 'A'.repeat(86)};
     };
     const resealRelease = (releaseValue, judgeValues) => {
       const projection = structuredClone(releaseValue);
       delete projection.releaseSha256;
       projection.judges = judgeValues.map((judge) => ({
         judgeRef: judge.judgeRef,
         independenceKey: judge.originRef,
         receiptSha256: judge.receiptSha256,
       })).sort((left, right) => left.judgeRef.localeCompare(right.judgeRef));
       return {...projection, releaseSha256: contractHash(projection)};
     };
     const expectDatabaseEvaluationReject = async (
       candidateValue,
       judgeValues,
       releaseValue,
       expected,
       candidateSha256 = candidateStoreSha256(candidateValue),
     ) => {
       let rejection = null;
       try {
         await writerPool.query(
           'SELECT risely_agent_runtime.persist_authorized_evaluation($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7::jsonb)',
           [scope.profileRef, scope.profileSha256, candidateSha256, JSON.stringify(candidateValue), JSON.stringify(judgeValues),
             'evaluation-release:' + releaseValue.releaseSha256, JSON.stringify(releaseValue)],
         );
       } catch (error) { rejection = error; }
       if (!rejection || !rejection.message.includes(expected)) {
         throw rejection ?? new Error('database_evaluation_forgery_accepted:' + expected);
       }
     };
     const gateSubstitution = structuredClone(judgeResults);
     gateSubstitution[0].gateResults[Object.keys(gateSubstitution[0].gateResults)[0]] = false;
     gateSubstitution[0] = resealJudge(gateSubstitution[0]);
     const gateRelease = resealRelease(release, gateSubstitution);
     await expectDatabaseEvaluationReject(candidate, gateSubstitution, gateRelease, 'invalid_authorized_evaluation_gate');
     const invalidSignature = structuredClone(judgeResults);
     invalidSignature[0].signature = '*';
     await expectDatabaseEvaluationReject(candidate, invalidSignature, release, 'invalid_authorized_evaluation_judge_linkage');
     const lowScores = structuredClone(judgeResults);
     lowScores[0].scores.accuracy = 1;
     lowScores[0] = resealJudge(lowScores[0]);
     const lowScoreRelease = resealRelease(release, lowScores);
     await expectDatabaseEvaluationReject(candidate, lowScores, lowScoreRelease, 'invalid_authorized_evaluation_scores');
     const spreadScores = structuredClone(judgeResults);
     spreadScores[1].scores.accuracy = 3;
     spreadScores[1] = resealJudge(spreadScores[1]);
     const spreadRelease = resealRelease(release, spreadScores);
     await expectDatabaseEvaluationReject(candidate, spreadScores, spreadRelease, 'invalid_authorized_evaluation_scores');
     const policySubstitution = structuredClone(candidate);
     policySubstitution.policySnapshot.minimumScore = 1;
     await expectDatabaseEvaluationReject(policySubstitution, judgeResults, release, 'invalid_authorized_evaluation');
     await expectDatabaseEvaluationReject(candidate, judgeResults, release, 'invalid_authorized_evaluation', '${"f".repeat(64)}');
     const alternateCandidate = prepareEvaluationCandidate(authority, {...candidateInput, runNonce: '${"a".repeat(64)}'});
     await expectDatabaseEvaluationReject(alternateCandidate, judgeResults, release, 'invalid_authorized_evaluation');
     const deploymentBinding = {
       contractType: 'ceo-surface-deployment',
       contractVersion: 1,
       ceoUserRef: scope.profile.audiences.slack.principalRef,
       ceoEmail: scope.profile.identity.humanEmail,
       qmPrincipalRef: scope.profile.identity.qmPrincipalRef,
       credentialOwnerRef: scope.profile.identity.credentialOwnerRef,
       slackTeamId: 'T123456789',
       evalAuthorityRef: release.evalAuthorityRef,
       evalPolicySha256: release.policySha256,
       identityResolverAuthorityRef: 'resolver:risely:slack-identity',
     };
     const outboxEvent = scope.contracts.OutboxEvent.create({
       principalBinding: scope.principalBinding,
       artifact: evalArtifact,
       evalRelease: release,
       surface: 'slack',
       queuedAt: decisionAt,
     });
     const publicationEnvelope = scope.contracts.PublicationEnvelope.create({outboxEvent});
     const surfaceStore = new CanonicalCeoSurfaceStore({pool, scope, deploymentBinding});
     await surfaceStore.initialize();
     const accepted = await surfaceStore.enqueuePublication({outboxEvent, publicationEnvelope});
     if (accepted?.outboxEvent?.eventId !== outboxEvent.eventId || accepted?.publicationEnvelope?.envelopeSha256 !== publicationEnvelope.envelopeSha256) {
       throw new Error('canonical_outbox_acceptance_mismatch');
     }
     try { await resultStore.appendReplayTombstone({releaseId: durableRelease.releaseId, replayRef: 'replay:lifecycle', terminalRecord: {z: 1, a: 2}}); }
     catch (error) { if (error.code !== 'evaluation_replay_retired') throw error; }
     try { await resultStore.appendReplayTombstone({releaseId: durableRelease.releaseId, replayRef: 'replay:lifecycle', terminalRecord: {z: 1, a: 2}}); }
     catch (error) { if (error.code !== 'evaluation_replay_retired') throw error; }
     await writer.close();
     await store.close();`,
    ];
    await requireDocker(runtimeVerificationArgs);
    await verifyCompositeProfileIsolation(admin);
    await admin.query(
      `SET ROLE risely_agent_runtime_owner;
     ALTER TABLE ${CANARY_SCHEMA_NAME}.ingress_requests DROP CONSTRAINT ingress_requests_request_hash_check;
     ALTER TABLE ${CANARY_SCHEMA_NAME}.ingress_requests ADD CONSTRAINT ingress_requests_request_hash_check CHECK (true);
     UPDATE ${CANARY_SCHEMA_NAME}.schema_migrations
       SET catalog_fingerprint = (SELECT catalog_fingerprint FROM (${catalogFingerprintSql()}) AS catalog_snapshot);
     RESET ROLE`,
    );
    assert.notEqual((await docker(runtimeVerificationArgs)).exitCode, 0);
    await admin.query(
      `SET ROLE risely_agent_runtime_owner;
     ALTER TABLE ${CANARY_SCHEMA_NAME}.ingress_requests DROP CONSTRAINT ingress_requests_request_hash_check;
     ALTER TABLE ${CANARY_SCHEMA_NAME}.ingress_requests ADD CONSTRAINT ingress_requests_request_hash_check
       CHECK (request_hash ~ '^[0-9a-f]{64}$'::text);
     UPDATE ${CANARY_SCHEMA_NAME}.schema_migrations
       SET catalog_fingerprint = (SELECT catalog_fingerprint FROM (${catalogFingerprintSql()}) AS catalog_snapshot);
     RESET ROLE`,
    );
    await requireDocker(runtimeVerificationArgs);
    await admin.query(
      `SET ROLE risely_agent_runtime_owner;
     ALTER SEQUENCE ${CANARY_SCHEMA_NAME}.action_events_event_sequence_seq MAXVALUE 9223372036854775806;
     RESET ROLE`,
    );
    assert.notEqual((await docker(runtimeVerificationArgs)).exitCode, 0);
    await admin.query(
      `SET ROLE risely_agent_runtime_owner;
     ALTER SEQUENCE ${CANARY_SCHEMA_NAME}.action_events_event_sequence_seq NO MAXVALUE;
     RESET ROLE`,
    );
    await requireDocker(runtimeVerificationArgs);
    await admin.query(
      `SET ROLE risely_agent_runtime_owner;
     ALTER TABLE ${CANARY_SCHEMA_NAME}.workflow_runs SET (toast.autovacuum_enabled = false);
     RESET ROLE`,
    );
    assert.notEqual((await docker(runtimeVerificationArgs)).exitCode, 0);
    await admin.query(
      `SET ROLE risely_agent_runtime_owner;
     ALTER TABLE ${CANARY_SCHEMA_NAME}.workflow_runs RESET (toast.autovacuum_enabled);
     RESET ROLE`,
    );
    await requireDocker(runtimeVerificationArgs);
    await admin.query(`ALTER EXTENSION plpgsql ADD SCHEMA ${CANARY_SCHEMA_NAME}`);
    assert.notEqual((await docker(runtimeVerificationArgs)).exitCode, 0);
    await admin.query(`ALTER EXTENSION plpgsql DROP SCHEMA ${CANARY_SCHEMA_NAME}`);
    await admin.query(`CREATE EXTENSION file_fdw; GRANT USAGE ON FOREIGN DATA WRAPPER file_fdw TO PUBLIC`);
    assert.notEqual((await docker(runtimeVerificationArgs)).exitCode, 0);
    await admin.query(`REVOKE USAGE ON FOREIGN DATA WRAPPER file_fdw FROM PUBLIC`);
    await requireDocker(runtimeVerificationArgs);
    await admin.query(
      `CREATE SERVER canary_escape_server FOREIGN DATA WRAPPER file_fdw; GRANT USAGE ON FOREIGN SERVER canary_escape_server TO PUBLIC`,
    );
    assert.notEqual((await docker(runtimeVerificationArgs)).exitCode, 0);
    await admin.query(
      `REVOKE USAGE ON FOREIGN SERVER canary_escape_server FROM PUBLIC; CREATE USER MAPPING FOR PUBLIC SERVER canary_escape_server`,
    );
    assert.notEqual((await docker(runtimeVerificationArgs)).exitCode, 0);
    await admin.query(
      `DROP USER MAPPING FOR PUBLIC SERVER canary_escape_server; DROP SERVER canary_escape_server; DROP EXTENSION file_fdw`,
    );
    await requireDocker(runtimeVerificationArgs);
    await admin.query(
      `SET ROLE risely_agent_runtime_owner;
     INSERT INTO ${CANARY_SCHEMA_NAME}.workflow_runs
       (profile_ref, profile_sha256, run_id, principal_ref, payload_hash, payload, created_at)
     VALUES ('${ceoDeploymentProfile.profileRef}', '${ceoDeploymentProfile.profileSha256}',
             'retention-proof', 'principal:proof', '${"0".repeat(64)}', '{}'::jsonb,
             clock_timestamp() - interval '366 days');
     RESET ROLE;
     CREATE SCHEMA retention_exploit;
     CREATE TABLE retention_exploit.effects (run_id text);
     CREATE FUNCTION retention_exploit.capture_delete() RETURNS trigger
       LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
       AS $$BEGIN INSERT INTO retention_exploit.effects(run_id) VALUES (OLD.run_id); RETURN OLD; END$$;
     CREATE TRIGGER retention_exploit_trigger
       AFTER DELETE ON ${CANARY_SCHEMA_NAME}.workflow_runs
       FOR EACH ROW EXECUTE FUNCTION retention_exploit.capture_delete();`,
    );
    const attackedRetention = await docker([
      "run",
      "--rm",
      "--network",
      networkName,
      ...fixedEnvironment(ca),
      "--env",
      `CANARY_MIGRATION_DATABASE_URL=${migrationUrl}`,
      runtimeImage,
      "node",
      "--input-type=module",
      "--eval",
      "const { applyRetention } = await import('/app/canary/service/ceo-canary/src/retention.mjs'); await applyRetention(process.env)",
    ]);
    assert.notEqual(attackedRetention.exitCode, 0);
    const blocked = await admin.query(
      `SELECT
       (SELECT count(*)::integer FROM ${CANARY_SCHEMA_NAME}.workflow_runs WHERE run_id = 'retention-proof') AS canary_rows,
       (SELECT count(*)::integer FROM retention_exploit.effects) AS external_effects`,
    );
    assert.deepEqual(blocked.rows, [{ canary_rows: 1, external_effects: 0 }]);
    await admin.query(
      `DROP TRIGGER retention_exploit_trigger ON ${CANARY_SCHEMA_NAME}.workflow_runs;
     DROP SCHEMA retention_exploit CASCADE;`,
    );
    const retentionArgs = [
      "run",
      "--rm",
      "--network",
      networkName,
      ...fixedEnvironment(ca),
      "--env",
      `CANARY_MIGRATION_DATABASE_URL=${migrationUrl}`,
      runtimeImage,
      "node",
      "--input-type=module",
      "--eval",
      "const { applyRetention } = await import('/app/canary/service/ceo-canary/src/retention.mjs'); await applyRetention(process.env)",
    ];
    await admin.query(
      `CREATE SCHEMA retention_event_escape;
     CREATE TABLE retention_event_escape.effects (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
     CREATE FUNCTION retention_event_escape.capture_ddl() RETURNS event_trigger
       LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
       AS 'BEGIN INSERT INTO retention_event_escape.effects DEFAULT VALUES; END';
     REVOKE EXECUTE ON FUNCTION retention_event_escape.capture_ddl() FROM PUBLIC;
     CREATE EVENT TRIGGER retention_escape_enabled
       ON ddl_command_start EXECUTE FUNCTION retention_event_escape.capture_ddl();
     TRUNCATE retention_event_escape.effects`,
    );
    assert.notEqual((await docker(retentionArgs)).exitCode, 0);
    assert.equal(
      (await admin.query("SELECT count(*)::integer AS count FROM retention_event_escape.effects")).rows[0].count,
      0,
    );
    assert.equal(
      (
        await admin.query(
          `SELECT count(*)::integer AS count FROM ${CANARY_SCHEMA_NAME}.workflow_runs WHERE run_id = 'retention-proof'`,
        )
      ).rows[0].count,
      1,
    );
    await admin.query("DROP EVENT TRIGGER retention_escape_enabled; DROP SCHEMA retention_event_escape CASCADE");
    await requireDocker(retentionArgs);
    assert.equal(
      (
        await admin.query(
          `SELECT count(*)::integer AS rows FROM ${CANARY_SCHEMA_NAME}.workflow_runs WHERE run_id = 'retention-proof'`,
        )
      ).rows[0].rows,
      0,
    );
    const retainedByProfile = await admin.query(
      `SELECT profile_ref FROM ${CANARY_SCHEMA_NAME}.workflow_runs
     WHERE run_id = 'run:retention-scope' ORDER BY profile_ref`,
    );
    assert.deepEqual(retainedByProfile.rows, [{ profile_ref: syntheticDeploymentProfile.profileRef }]);
  },
);
