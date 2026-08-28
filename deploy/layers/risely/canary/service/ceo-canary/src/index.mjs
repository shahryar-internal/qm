import {
  CANARY_BOOTSTRAP_ADMIN_ROLE,
  CANARY_DATABASE_NAME,
  CANARY_EVALUATION_WRITER_DATABASE_USER,
  CANARY_MAINTENANCE_LOCK_KEY,
  CANARY_MIGRATION_DATABASE_USER,
  CANARY_OWNER_DATABASE_USER,
  CANARY_RUNTIME_DATABASE_USER,
  CANARY_SCHEMA_NAME,
  SCHEMA_VERSION,
} from "./schema.mjs";
import { verifyCanaryDatabase, verifyCanaryDatabaseClient, verifyCanaryDatabaseSentinel } from "./postgres-store.mjs";
export { assertDormantGmailDraftProposal, CANARY_PROVIDER_EXECUTION_AVAILABLE } from "./domain.mjs";

export const ceoCanaryDatabaseIdentity = Object.freeze({
  bootstrapAdminRole: CANARY_BOOTSTRAP_ADMIN_ROLE,
  databaseName: CANARY_DATABASE_NAME,
  schemaName: CANARY_SCHEMA_NAME,
  runtimeDatabaseUser: CANARY_RUNTIME_DATABASE_USER,
  evaluationWriterDatabaseUser: CANARY_EVALUATION_WRITER_DATABASE_USER,
  migrationDatabaseUser: CANARY_MIGRATION_DATABASE_USER,
  ownerDatabaseUser: CANARY_OWNER_DATABASE_USER,
  maintenanceLockKey: CANARY_MAINTENANCE_LOCK_KEY,
  schemaVersion: SCHEMA_VERSION,
});

export { EvaluationWriterError, PostgresEvaluationWriter } from "./evaluation-writer.mjs";
export { evaluationWriterPoolConfig } from "./postgres-store.mjs";

export async function verifyCeoCanaryDatabaseBoundary(pool) {
  return verifyCanaryDatabase(pool);
}

export async function verifyCeoCanaryDatabaseClientBoundary(client, transactionOpen = false) {
  if (!client || typeof client.query !== "function" || typeof transactionOpen !== "boolean") {
    throw new TypeError("Fixed client verification requires a PostgreSQL client and transaction state");
  }
  if (transactionOpen) {
    await client.query("SET LOCAL search_path = pg_catalog");
    return verifyCanaryDatabaseClient(client, true);
  }
  try {
    await client.query("BEGIN READ ONLY");
    await client.query("SET LOCAL search_path = pg_catalog");
    await client.query("SET LOCAL statement_timeout = '10s'");
    const result = await verifyCanaryDatabaseClient(client, true);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  }
}

export async function verifyCeoCanaryDatabaseClientSentinel(client, runtimeScope, requireProfile = true) {
  return verifyCanaryDatabaseSentinel(client, runtimeScope, requireProfile);
}
