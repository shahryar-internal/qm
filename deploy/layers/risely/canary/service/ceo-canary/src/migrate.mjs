import pg from "pg";
import { fileURLToPath } from "node:url";
import { assertFixedDatabaseContract, migrationPoolConfig } from "./database-connection.mjs";
import {
  assertMigrationDatabaseBoundary,
  assertOwnerDatabaseBoundary,
  assertPostMigrationDatabaseContract,
} from "./database-security.mjs";
import { CANARY_MAINTENANCE_LOCK_KEY, CANARY_OWNER_DATABASE_USER, migrationSql } from "./schema.mjs";

const { Pool } = pg;

export async function migrate(env = process.env) {
  assertFixedDatabaseContract(env);
  const pool = new Pool(migrationPoolConfig(env));
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL search_path = pg_catalog");
    await client.query("SET LOCAL statement_timeout = '30s'");
    await assertMigrationDatabaseBoundary(client);
    await client.query(`SET LOCAL ROLE ${CANARY_OWNER_DATABASE_USER}`);
    await client.query("SET LOCAL search_path = pg_catalog");
    await assertOwnerDatabaseBoundary(client);
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [CANARY_MAINTENANCE_LOCK_KEY]);
    await client.query(migrationSql());
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
  migrate().catch(() => {
    process.exitCode = 1;
  });
}
