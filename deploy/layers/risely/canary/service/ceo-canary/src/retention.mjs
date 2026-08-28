import pg from "pg";
import { fileURLToPath } from "node:url";
import {
  assertFixedDatabaseContract,
  assertMigrationDatabaseBoundary,
  assertOwnerDatabaseBoundary,
  migrationPoolConfig,
} from "./postgres-store.mjs";
import { assertPostMigrationDatabaseContract } from "./database-security.mjs";
import { CANARY_MAINTENANCE_LOCK_KEY, CANARY_OWNER_DATABASE_USER, CANARY_SCHEMA_NAME } from "./schema.mjs";

const { Pool } = pg;

export function retentionSql() {
  const schema = CANARY_SCHEMA_NAME;
  return `
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
ALTER TABLE ${schema}.action_events DISABLE TRIGGER action_events_append_only;
ALTER TABLE ${schema}.audit_events DISABLE TRIGGER audit_events_append_only;
ALTER TABLE ${schema}.surface_delivery_receipts DISABLE TRIGGER surface_delivery_receipts_append_only;
ALTER TABLE ${schema}.surface_outbox_events DISABLE TRIGGER surface_outbox_events_immutable;
ALTER TABLE ${schema}.workflow_runs DISABLE TRIGGER workflow_runs_immutable;
DO $retention$
DECLARE
  surface_candidate record;
  terminal_candidate record;
BEGIN
  FOR surface_candidate IN
    SELECT states.profile_ref, states.profile_sha256, states.event_id
    FROM ${schema}.surface_outbox_states states
    JOIN ${schema}.surface_outbox_events events
      ON events.profile_ref = states.profile_ref
     AND events.profile_sha256 = states.profile_sha256
     AND events.event_id = states.event_id
    LEFT JOIN ${schema}.surface_delivery_reservations reservations
      ON reservations.profile_ref = states.profile_ref
     AND reservations.profile_sha256 = states.profile_sha256
     AND reservations.outbox_event_id = states.event_id
    LEFT JOIN ${schema}.surface_delivery_tombstones tombstones
      ON tombstones.profile_ref = states.profile_ref
     AND tombstones.profile_sha256 = states.profile_sha256
     AND tombstones.delivery_key = reservations.delivery_key
     AND tombstones.outbox_event_id = states.event_id
    LEFT JOIN ${schema}.surface_event_tombstones event_tombstones
      ON event_tombstones.profile_ref = states.profile_ref
     AND event_tombstones.profile_sha256 = states.profile_sha256
     AND event_tombstones.event_id = states.event_id
    WHERE states.updated_at < clock_timestamp() - interval '180 days'
      AND (
        (
          states.status = 'failed'
          AND states.failure_code = 'eval_release_expired'
          AND reservations.delivery_key IS NULL
          AND event_tombstones.failure_code = states.failure_code
          AND event_tombstones.deployment_binding_sha256 = events.deployment_binding_sha256
          AND event_tombstones.outbox_payload_sha256 = events.outbox_payload_sha256
          AND event_tombstones.artifact_id = events.artifact_id
          AND event_tombstones.artifact_revision = events.artifact_revision
          AND event_tombstones.artifact_sha256 = events.artifact_sha256
          AND event_tombstones.eval_receipt_sha256 = events.eval_receipt_sha256
          AND event_tombstones.identity_resolution_sha256 IS NULL
          AND event_tombstones.target_binding_sha256 IS NULL
          AND event_tombstones.message_sha256 IS NULL
          AND event_tombstones.completed_at = states.updated_at
        )
        OR (
          states.status = 'failed'
          AND states.failure_code = 'identity_resolution_expired'
          AND reservations.status = 'reserved'
          AND event_tombstones.failure_code = states.failure_code
          AND event_tombstones.deployment_binding_sha256 = events.deployment_binding_sha256
          AND event_tombstones.outbox_payload_sha256 = events.outbox_payload_sha256
          AND event_tombstones.artifact_id = events.artifact_id
          AND event_tombstones.artifact_revision = events.artifact_revision
          AND event_tombstones.artifact_sha256 = events.artifact_sha256
          AND event_tombstones.eval_receipt_sha256 = events.eval_receipt_sha256
          AND event_tombstones.identity_resolution_sha256 = reservations.identity_resolution_sha256
          AND event_tombstones.target_binding_sha256 = reservations.target_binding_sha256
          AND event_tombstones.message_sha256 = reservations.message_sha256
          AND event_tombstones.completed_at = states.updated_at
        )
        OR (
          ((states.status = 'delivered' AND reservations.status = 'verified')
            OR (states.status = 'failed' AND states.failure_code = 'provider_refused' AND reservations.status = 'failed'))
          AND tombstones.terminal_status = reservations.status
          AND tombstones.outbox_payload_sha256 = reservations.outbox_payload_sha256
          AND tombstones.deployment_binding_sha256 = reservations.deployment_binding_sha256
          AND tombstones.artifact_sha256 = reservations.artifact_sha256
          AND tombstones.identity_resolution_sha256 = reservations.identity_resolution_sha256
          AND tombstones.target_binding_sha256 = reservations.target_binding_sha256
          AND tombstones.message_sha256 = reservations.message_sha256
          AND tombstones.completed_at = reservations.completed_at
        )
      )
  LOOP
    DELETE FROM ${schema}.surface_delivery_receipts receipts
    USING ${schema}.surface_delivery_reservations reservations
    WHERE receipts.profile_ref = surface_candidate.profile_ref
      AND receipts.profile_sha256 = surface_candidate.profile_sha256
      AND reservations.profile_ref = surface_candidate.profile_ref
      AND reservations.profile_sha256 = surface_candidate.profile_sha256
      AND receipts.profile_ref = reservations.profile_ref
      AND receipts.profile_sha256 = reservations.profile_sha256
      AND receipts.delivery_key = reservations.delivery_key
      AND reservations.outbox_event_id = surface_candidate.event_id;
    DELETE FROM ${schema}.surface_delivery_reservations reservations
    WHERE reservations.profile_ref = surface_candidate.profile_ref
      AND reservations.profile_sha256 = surface_candidate.profile_sha256
      AND reservations.outbox_event_id = surface_candidate.event_id;
    DELETE FROM ${schema}.surface_outbox_states states
    WHERE states.profile_ref = surface_candidate.profile_ref
      AND states.profile_sha256 = surface_candidate.profile_sha256
      AND states.event_id = surface_candidate.event_id;
    DELETE FROM ${schema}.surface_outbox_events events
    WHERE events.profile_ref = surface_candidate.profile_ref
      AND events.profile_sha256 = surface_candidate.profile_sha256
      AND events.event_id = surface_candidate.event_id;
  END LOOP;

  FOR terminal_candidate IN
    SELECT profile_ref, profile_sha256, proposal_id
    FROM ${schema}.action_states
    WHERE state->>'status' IN ('verified', 'refused', 'rejected', 'expired', 'stale', 'failed')
      AND updated_at < clock_timestamp() - interval '180 days'
  LOOP
    DELETE FROM ${schema}.reconciliation_leases leases
    WHERE leases.profile_ref = terminal_candidate.profile_ref
      AND leases.profile_sha256 = terminal_candidate.profile_sha256
      AND leases.proposal_id = terminal_candidate.proposal_id;
    DELETE FROM ${schema}.action_events events
    WHERE events.profile_ref = terminal_candidate.profile_ref
      AND events.profile_sha256 = terminal_candidate.profile_sha256
      AND events.proposal_id = terminal_candidate.proposal_id;
    DELETE FROM ${schema}.audit_events audit
    WHERE audit.profile_ref = terminal_candidate.profile_ref
      AND audit.profile_sha256 = terminal_candidate.profile_sha256
      AND audit.entity_type = 'action'
      AND audit.entity_id = terminal_candidate.proposal_id;
    DELETE FROM ${schema}.action_states states
    WHERE states.profile_ref = terminal_candidate.profile_ref
      AND states.profile_sha256 = terminal_candidate.profile_sha256
      AND states.proposal_id = terminal_candidate.proposal_id;
  END LOOP;
END;
$retention$;
WITH RECURSIVE protected_runs(profile_ref, profile_sha256, run_id) AS (
  SELECT runs.profile_ref, runs.profile_sha256, runs.run_id
  FROM ${schema}.workflow_runs runs
  WHERE runs.created_at >= clock_timestamp() - interval '365 days'
     OR EXISTS (
       SELECT 1 FROM ${schema}.action_states states
       WHERE states.profile_ref = runs.profile_ref
         AND states.profile_sha256 = runs.profile_sha256
         AND states.run_id = runs.run_id
     )
  UNION
  SELECT parent.profile_ref, parent.profile_sha256, parent.run_id
  FROM protected_runs child
  JOIN ${schema}.workflow_runs retained_child
    ON retained_child.profile_ref = child.profile_ref
   AND retained_child.profile_sha256 = child.profile_sha256
   AND retained_child.run_id = child.run_id
  JOIN ${schema}.workflow_runs parent
    ON parent.profile_ref = retained_child.profile_ref
   AND parent.profile_sha256 = retained_child.profile_sha256
   AND parent.run_id = retained_child.payload->>'parentRunId'
)
DELETE FROM ${schema}.workflow_runs runs
WHERE runs.created_at < clock_timestamp() - interval '365 days'
  AND NOT EXISTS (
    SELECT 1 FROM protected_runs protected
    WHERE protected.profile_ref = runs.profile_ref
      AND protected.profile_sha256 = runs.profile_sha256
      AND protected.run_id = runs.run_id
  )
  AND NOT EXISTS (
    SELECT 1 FROM ${schema}.workflow_runs child
    WHERE child.profile_ref = runs.profile_ref
      AND child.profile_sha256 = runs.profile_sha256
      AND child.payload->>'parentRunId' = runs.run_id
      AND EXISTS (
        SELECT 1 FROM protected_runs protected
        WHERE protected.profile_ref = child.profile_ref
          AND protected.profile_sha256 = child.profile_sha256
          AND protected.run_id = child.run_id
      )
  );
DELETE FROM ${schema}.audit_events audit
WHERE audit.recorded_at < clock_timestamp() - interval '400 days'
  AND NOT EXISTS (
    SELECT 1 FROM ${schema}.action_states states
    WHERE states.profile_ref = audit.profile_ref
      AND states.profile_sha256 = audit.profile_sha256
      AND audit.entity_type = 'action'
      AND audit.entity_id = states.proposal_id
      AND states.state->>'status' NOT IN ('verified', 'refused', 'rejected', 'expired', 'stale', 'failed')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM ${schema}.workflow_runs runs
    JOIN ${schema}.action_states states
      ON states.profile_ref = runs.profile_ref
     AND states.profile_sha256 = runs.profile_sha256
     AND states.run_id = runs.run_id
    WHERE runs.profile_ref = audit.profile_ref
      AND runs.profile_sha256 = audit.profile_sha256
      AND audit.entity_type = 'workflow_run'
      AND audit.entity_id = runs.run_id
      AND states.state->>'status' NOT IN ('verified', 'refused', 'rejected', 'expired', 'stale', 'failed')
  );
ALTER TABLE ${schema}.action_events ENABLE TRIGGER action_events_append_only;
ALTER TABLE ${schema}.audit_events ENABLE TRIGGER audit_events_append_only;
ALTER TABLE ${schema}.surface_delivery_receipts ENABLE TRIGGER surface_delivery_receipts_append_only;
ALTER TABLE ${schema}.surface_outbox_events ENABLE TRIGGER surface_outbox_events_immutable;
ALTER TABLE ${schema}.workflow_runs ENABLE TRIGGER workflow_runs_immutable;
`;
}

export async function applyRetention(env = process.env) {
  assertFixedDatabaseContract(env);
  const pool = new Pool(migrationPoolConfig(env));
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL search_path = pg_catalog");
    await assertMigrationDatabaseBoundary(client);
    await client.query(`SET LOCAL ROLE ${CANARY_OWNER_DATABASE_USER}`);
    await client.query("SET LOCAL search_path = pg_catalog");
    await assertOwnerDatabaseBoundary(client);
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [CANARY_MAINTENANCE_LOCK_KEY]);
    await assertPostMigrationDatabaseContract(client);
    await client.query(retentionSql());
    await assertPostMigrationDatabaseContract(client);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  applyRetention().catch(() => {
    process.exitCode = 1;
  });
}
