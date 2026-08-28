import pg from "pg";
import { PrincipalBinding } from "../../../shared-contracts/index.mjs";
import {
  assertRuntimeScope,
  createRuntimeScope,
  productionRuntimeScopeFromEnv,
} from "../../../runtime-scope/index.mjs";
import { ceoDeploymentProfile } from "../../../deployment-profiles/index.mjs";
import { assertActionState, createActionState, createRuntimeDomain } from "./domain.mjs";
import {
  CANARY_BOOTSTRAP_ADMIN_ROLE,
  CANARY_DATABASE_NAME,
  CANARY_EVALUATION_WRITER_DATABASE_USER,
  CANARY_MAINTENANCE_LOCK_KEY,
  CANARY_MIGRATION_DATABASE_USER,
  CANARY_OWNER_DATABASE_USER,
  CANARY_RUNTIME_DATABASE_USER,
  CANARY_SCHEMA_NAME,
  EXPECTED_CATALOG_AUTHORITY_SHA256,
  SCHEMA_VERSION,
  migrationChecksum,
} from "./schema.mjs";
import {
  assertExactCanaryCatalog,
  assertMigrationDatabaseBoundary,
  assertOwnerDatabaseBoundary,
  assertRuntimeDatabaseBoundary,
  sameStructure,
} from "./database-security.mjs";

export { assertMigrationDatabaseBoundary, assertOwnerDatabaseBoundary };

const { Pool } = pg;
const canonicalSnapshot = PrincipalBinding.snapshot;
const sha256Canonical = PrincipalBinding.hash;
const HASH = /^[0-9a-f]{64}$/;
const LEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_PROPOSAL_LIFETIME_MS = 24 * 60 * 60 * 1000;
const READINESS_SCOPE = createRuntimeScope(ceoDeploymentProfile);
const EXPECTED_MIGRATION_CHECKSUM = migrationChecksum();

export class CanaryStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CanaryStoreError";
    this.code = code;
  }
}

function storeError(code, message) {
  throw new CanaryStoreError(code, message);
}

function assertContext(value) {
  const context = canonicalSnapshot(value, "request context");
  if (!context || typeof context.principalRef !== "string" || !HASH.test(context.requestHash)) {
    storeError("invalid_context", "Authenticated request context is invalid");
  }
  return context;
}

function asAction(row, domain) {
  if (!row) return null;
  let proposal;
  try {
    proposal = domain.assertProposal(row.proposal);
  } catch {
    storeError("stored_state_corrupt", "Stored action proposal is invalid");
  }
  let state;
  try {
    state = assertActionState(row.state);
  } catch {
    storeError("stored_state_corrupt", "Stored action state is invalid");
  }
  if (
    proposal.proposalId !== row.proposal_id ||
    proposal.runId !== row.run_id ||
    proposal.actor.principalRef !== row.principal_ref ||
    proposal.proposalHash !== row.proposal_hash ||
    proposal.effectKey !== row.effect_key ||
    state.proposalId !== proposal.proposalId ||
    state.proposalHash !== proposal.proposalHash ||
    state.effectKey !== proposal.effectKey ||
    state.actorPrincipalRef !== proposal.actor.principalRef ||
    state.credentialOwnerRef !== proposal.actor.credentialOwnerRef ||
    state.credentialRef !== proposal.credentialRef ||
    state.expectedProvider !== proposal.provider ||
    state.expiresAt !== proposal.expiresAt ||
    sha256Canonical(state) !== row.state_hash ||
    state.revision !== Number(row.revision)
  ) {
    storeError("stored_state_corrupt", "Stored action hashes or revision do not match their content");
  }
  return {
    proposal,
    state,
    stateHash: row.state_hash,
    revision: Number(row.revision),
  };
}

function databaseConnectionIdentity(value, label, strict) {
  if (typeof value !== "string") throw new Error(`${label} must be a PostgreSQL connection string`);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a PostgreSQL connection string`);
  }
  if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.hostname || !url.username || !url.password) {
    throw new Error(`${label} must contain a complete PostgreSQL authority`);
  }
  let username;
  let credentialValue;
  let database;
  try {
    username = decodeURIComponent(url.username);
    credentialValue = decodeURIComponent(url.password);
    database = decodeURIComponent(url.pathname.slice(1));
  } catch {
    throw new Error(`${label} contains invalid percent encoding`);
  }
  if (strict && (url.search || url.hash || !database || url.pathname.slice(1).includes("/"))) {
    throw new Error(`${label} cannot override TLS options`);
  }
  return {
    connectionString: value,
    credentialValue,
    database,
    host: url.hostname.toLowerCase(),
    port: url.port || "5432",
    username,
  };
}

function checkedDatabaseUrl(value, expectedDatabase, expectedUser, expectedHost, expectedPort, label) {
  const checked = databaseConnectionIdentity(value, label, true);
  if (checked.database !== expectedDatabase || checked.host !== expectedHost || checked.port !== expectedPort) {
    throw new Error(`${label} cannot override TLS options and must target only ${expectedDatabase}`);
  }
  if (checked.username !== expectedUser) {
    throw new Error(`${label} must authenticate as ${expectedUser}`);
  }
  if (/^(?:postgres|admin|administrator|master|root|qm)$/i.test(expectedUser)) {
    throw new Error(`${label} cannot use a database owner or administrative identity`);
  }
  return checked;
}

function assertDistinctDatabaseCredentials(env, checked, label) {
  for (const otherLabel of [
    "DATABASE_URL",
    "CANARY_DATABASE_URL",
    "CANARY_MIGRATION_DATABASE_URL",
    "CANARY_EVALUATION_WRITER_DATABASE_URL",
  ]) {
    const value = env[otherLabel];
    if (otherLabel === label || !value) continue;
    if (databaseConnectionIdentity(value, otherLabel, false).credentialValue === checked.credentialValue) {
      throw new Error(`${label} must not reuse ${otherLabel} credentials`);
    }
  }
}

function tlsPoolConfig(connectionString, ca, applicationName) {
  if (typeof ca !== "string" || !ca.includes("BEGIN CERTIFICATE")) {
    throw new Error("DATABASE_CA_CERT must contain the trusted PostgreSQL CA bundle");
  }
  return {
    connectionString,
    ssl: { ca, rejectUnauthorized: true },
    max: 8,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    query_timeout: 10000,
    application_name: applicationName,
  };
}

export function runtimePoolConfig(env = process.env) {
  assertFixedDatabaseContract(env);
  const checked = checkedDatabaseUrl(
    env.CANARY_DATABASE_URL,
    CANARY_DATABASE_NAME,
    CANARY_RUNTIME_DATABASE_USER,
    env.CANARY_DATABASE_HOST,
    env.CANARY_DATABASE_PORT,
    "CANARY_DATABASE_URL",
  );
  assertDistinctDatabaseCredentials(env, checked, "CANARY_DATABASE_URL");
  return tlsPoolConfig(checked.connectionString, env.DATABASE_CA_CERT, "risely-ceo-canary-runtime");
}

export function migrationPoolConfig(env = process.env) {
  assertFixedDatabaseContract(env);
  const checked = checkedDatabaseUrl(
    env.CANARY_MIGRATION_DATABASE_URL,
    CANARY_DATABASE_NAME,
    CANARY_MIGRATION_DATABASE_USER,
    env.CANARY_DATABASE_HOST,
    env.CANARY_DATABASE_PORT,
    "CANARY_MIGRATION_DATABASE_URL",
  );
  assertDistinctDatabaseCredentials(env, checked, "CANARY_MIGRATION_DATABASE_URL");
  return tlsPoolConfig(checked.connectionString, env.DATABASE_CA_CERT, "risely-ceo-canary-migration");
}

export function evaluationWriterPoolConfig(env = process.env) {
  assertFixedDatabaseContract(env);
  const checked = checkedDatabaseUrl(
    env.CANARY_EVALUATION_WRITER_DATABASE_URL,
    CANARY_DATABASE_NAME,
    CANARY_EVALUATION_WRITER_DATABASE_USER,
    env.CANARY_DATABASE_HOST,
    env.CANARY_DATABASE_PORT,
    "CANARY_EVALUATION_WRITER_DATABASE_URL",
  );
  assertDistinctDatabaseCredentials(env, checked, "CANARY_EVALUATION_WRITER_DATABASE_URL");
  return tlsPoolConfig(checked.connectionString, env.DATABASE_CA_CERT, "risely-ceo-canary-evaluation-writer");
}

export const postgresPoolConfig = runtimePoolConfig;

export function assertFixedDatabaseContract(env = process.env) {
  const expected = {
    CANARY_BOOTSTRAP_ADMIN_ROLE,
    CANARY_DATABASE_NAME,
    CANARY_DATABASE_SCHEMA: CANARY_SCHEMA_NAME,
    CANARY_OWNER_DATABASE_USER,
    CANARY_RUNTIME_DATABASE_USER,
    CANARY_MIGRATION_DATABASE_USER,
  };
  for (const [name, value] of Object.entries(expected)) {
    if (env[name] !== value) throw new Error(`${name} must equal the compiled CEO canary database contract`);
  }
  if (
    typeof env.CANARY_DATABASE_HOST !== "string" ||
    !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(env.CANARY_DATABASE_HOST) ||
    !env.CANARY_DATABASE_HOST.endsWith(".rds.amazonaws.com")
  ) {
    throw new Error("CANARY_DATABASE_HOST must be the deployment-owned Risely QM RDS endpoint");
  }
  if (env.CANARY_DATABASE_PORT !== "5432") throw new Error("CANARY_DATABASE_PORT must equal 5432");
  return { ...expected, CANARY_DATABASE_HOST: env.CANARY_DATABASE_HOST, CANARY_DATABASE_PORT: "5432" };
}

export function deploymentProfileFromEnv(env) {
  return productionRuntimeScopeFromEnv(env).profile;
}

export function authorityFromEnv(env) {
  return productionRuntimeScopeFromEnv(env).domainAuthority;
}

export async function verifyCanaryDatabaseSentinel(client, runtimeScope, requireProfile = true) {
  if (!client || typeof client.query !== "function" || typeof requireProfile !== "boolean") {
    throw new TypeError("Runtime database sentinel requires a PostgreSQL client and profile mode");
  }
  const scope = assertRuntimeScope(runtimeScope);
  const result = await client.query(
    `SELECT current_user,
            current_database(),
            pg_catalog.to_regnamespace($1)::text AS schema_name,
            migration.version,
            migration.checksum,
            migration.catalog_authority_sha256,
            profile.profile_sha256 AS stored_profile_sha256,
            profile.profile AS stored_profile,
            pg_catalog.has_table_privilege(current_user, pg_catalog.format('%I.evaluation_candidates', $1), 'INSERT') AS candidate_insert,
            pg_catalog.has_table_privilege(current_user, pg_catalog.format('%I.evaluation_judge_results', $1), 'INSERT') AS judge_insert,
            pg_catalog.has_table_privilege(current_user, pg_catalog.format('%I.evaluation_releases', $1), 'INSERT') AS release_insert,
            pg_catalog.has_function_privilege(current_user, pg_catalog.format('%I.persist_authorized_evaluation(text, character, character, jsonb, jsonb, text, jsonb)', $1), 'EXECUTE') AS evaluation_persist_execute
     FROM ${CANARY_SCHEMA_NAME}.schema_migrations migration
     LEFT JOIN ${CANARY_SCHEMA_NAME}.deployment_profiles profile
       ON profile.profile_ref = $2 AND profile.profile_sha256 = $3
     WHERE migration.version = $4`,
    [CANARY_SCHEMA_NAME, scope.profileRef, scope.profileSha256, SCHEMA_VERSION],
  );
  const sentinel = result.rows[0];
  if (
    result.rows.length !== 1 ||
    sentinel.current_user !== CANARY_RUNTIME_DATABASE_USER ||
    sentinel.current_database !== CANARY_DATABASE_NAME ||
    sentinel.schema_name !== CANARY_SCHEMA_NAME ||
    sentinel.version !== SCHEMA_VERSION ||
    sentinel.checksum !== EXPECTED_MIGRATION_CHECKSUM ||
    sentinel.catalog_authority_sha256 !== EXPECTED_CATALOG_AUTHORITY_SHA256 ||
    sentinel.candidate_insert ||
    sentinel.judge_insert ||
    sentinel.release_insert ||
    sentinel.evaluation_persist_execute !== false ||
    (requireProfile &&
      (sentinel.stored_profile_sha256 !== scope.profileSha256 ||
        sha256Canonical(sentinel.stored_profile) !== sha256Canonical(scope.profile)))
  ) {
    storeError("schema_unhealthy", "Runtime database sentinel drift detected");
  }
  return true;
}

export class PostgresCanaryStore {
  #initialized = false;
  #pool;

  constructor(options = {}) {
    if (Object.keys(options).some((name) => !["pool", "scope"].includes(name))) {
      throw new TypeError("CEO canary database security settings cannot be supplied by a caller");
    }
    const { pool, scope: scopeValue } = options;
    if (!pool || typeof pool.connect !== "function" || typeof pool.query !== "function") {
      throw new TypeError("PostgresCanaryStore requires a PostgreSQL pool");
    }
    const scope = assertRuntimeScope(scopeValue);
    this.#pool = pool;
    Object.defineProperties(this, {
      schema: { value: CANARY_SCHEMA_NAME, enumerable: true },
      runtimeScope: { value: scope, enumerable: false },
      authority: { value: scope.domainAuthority, enumerable: false },
      domain: { value: createRuntimeDomain(scope), enumerable: false },
      expectedRuntimeUser: { value: CANARY_RUNTIME_DATABASE_USER, enumerable: false },
      expectedMigrationUser: { value: CANARY_MIGRATION_DATABASE_USER, enumerable: false },
      expectedOwnerUser: { value: CANARY_OWNER_DATABASE_USER, enumerable: false },
      expectedDatabaseName: { value: CANARY_DATABASE_NAME, enumerable: false },
      maxClockSkewMs: { value: MAX_CLOCK_SKEW_MS, enumerable: false },
      maxProposalLifetimeMs: { value: MAX_PROPOSAL_LIFETIME_MS, enumerable: false },
    });
    Object.preventExtensions(this);
  }

  static fromEnv(env = process.env, runtimeScope = productionRuntimeScopeFromEnv(env)) {
    assertFixedDatabaseContract(env);
    const scope = assertRuntimeScope(runtimeScope);
    return new PostgresCanaryStore({
      pool: new Pool(runtimePoolConfig(env)),
      scope,
    });
  }

  async initialize() {
    if (this.#initialized) return true;
    await this.#verifySchema();
    this.#initialized = true;
    try {
      await this.#transaction(
        async (client) => {
          const profile = this.runtimeScope.profile;
          await client.query(
            `INSERT INTO ${this.schema}.deployment_profiles (profile_ref, profile_sha256, profile)
           VALUES ($1, $2, $3::jsonb)
           ON CONFLICT (profile_ref, profile_sha256) DO NOTHING`,
            [profile.profileRef, profile.profileSha256, JSON.stringify(profile)],
          );
          const stored = await client.query(
            `SELECT profile FROM ${this.schema}.deployment_profiles
           WHERE profile_ref = $1 AND profile_sha256 = $2`,
            [profile.profileRef, profile.profileSha256],
          );
          if (stored.rows.length !== 1 || sha256Canonical(stored.rows[0].profile) !== sha256Canonical(profile)) {
            storeError("schema_unhealthy", "Deployment profile registration does not match runtime authority");
          }
        },
        "deployment-profile-registration",
        false,
      );
      return true;
    } catch (error) {
      this.#initialized = false;
      throw error;
    }
  }

  async verifySchema(acquiredClient = null, transactionOpen = false) {
    return this.#verifySchema(acquiredClient, transactionOpen);
  }

  async #verifySchema(acquiredClient = null, transactionOpen = false) {
    const ownsClient = acquiredClient === null;
    if (ownsClient && transactionOpen)
      throw new TypeError("An open readiness transaction requires its acquired client");
    const client = ownsClient ? await this.#pool.connect() : acquiredClient;
    try {
      if (!transactionOpen) {
        await client.query("BEGIN READ ONLY");
        await client.query("SET LOCAL search_path = pg_catalog");
        await client.query("SET LOCAL statement_timeout = '10s'");
      }
      const identity = await client.query(
        `SELECT current_user,
          current_database(),
          rolname,
          rolcanlogin,
          rolinherit,
          rolsuper,
          rolcreaterole,
          rolcreatedb,
          rolreplication,
          rolbypassrls,
          pg_roles.oid = (SELECT datdba FROM pg_catalog.pg_database WHERE datname = current_database()) AS owns_database,
          EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member = pg_roles.oid) AS has_role_membership,
          (SELECT setconfig FROM pg_catalog.pg_db_role_setting
           WHERE setrole = pg_roles.oid
             AND setdatabase = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())) AS database_settings
   FROM pg_catalog.pg_roles WHERE rolname = current_user`,
      );
      const role = identity.rows[0];
      if (!role || role.current_database !== this.expectedDatabaseName)
        storeError("schema_unhealthy", "Database identity mismatch");
      if (
        role.current_user !== this.expectedRuntimeUser ||
        !role.rolcanlogin ||
        role.rolinherit ||
        role.rolsuper ||
        role.rolcreaterole ||
        role.rolcreatedb ||
        role.rolreplication ||
        role.rolbypassrls ||
        role.owns_database ||
        role.has_role_membership ||
        !sameStructure(role.database_settings, ["search_path=pg_catalog"])
      ) {
        storeError("schema_unhealthy", "Runtime role exceeds its authority");
      }
      await assertRuntimeDatabaseBoundary(client);
      await assertExactCanaryCatalog(client);
      const ownership = await client.query(
        `SELECT
     (SELECT schema_owner.rolname
      FROM pg_catalog.pg_namespace namespace
      JOIN pg_catalog.pg_roles schema_owner ON schema_owner.oid = namespace.nspowner
      WHERE namespace.nspname = $1) AS schema_owner,
     (SELECT array_agg(DISTINCT tableowner::text ORDER BY tableowner::text)::text[]
      FROM pg_catalog.pg_tables WHERE schemaname = $1) AS table_owners,
     (SELECT array_agg(DISTINCT sequenceowner::text ORDER BY sequenceowner::text)::text[]
      FROM pg_catalog.pg_sequences WHERE schemaname = $1) AS sequence_owners`,
        [this.schema],
      );
      if (
        ownership.rows[0]?.schema_owner !== this.expectedOwnerUser ||
        !sameStructure(ownership.rows[0]?.table_owners, [this.expectedOwnerUser]) ||
        !sameStructure(ownership.rows[0]?.sequence_owners, [this.expectedOwnerUser])
      ) {
        storeError("schema_unhealthy", "Canary schema ownership drift detected");
      }
      const privileges = await client.query(
        `SELECT
       has_database_privilege(current_user, current_database(), 'CONNECT') AS database_connect,
       has_database_privilege(current_user, current_database(), 'CREATE') AS database_create,
       has_database_privilege(current_user, current_database(), 'TEMP') AS database_temp,
       has_schema_privilege(current_user, $1, 'CREATE') AS schema_create,
       EXISTS (
         SELECT 1
         FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname <> $1
           AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND namespace.nspname <> 'information_schema'
           AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
           AND (
             has_table_privilege(current_user, relation.oid, 'SELECT') OR
             has_table_privilege(current_user, relation.oid, 'INSERT') OR
             has_table_privilege(current_user, relation.oid, 'UPDATE') OR
             has_table_privilege(current_user, relation.oid, 'DELETE') OR
             has_table_privilege(current_user, relation.oid, 'TRUNCATE') OR
             has_table_privilege(current_user, relation.oid, 'REFERENCES') OR
             has_table_privilege(current_user, relation.oid, 'TRIGGER')
           )
       ) AS cross_schema_table_access,
       EXISTS (
         SELECT 1
         FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname <> $1
           AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND namespace.nspname <> 'information_schema'
           AND relation.relkind = 'S'
           AND (
             has_sequence_privilege(current_user, relation.oid, 'SELECT') OR
             has_sequence_privilege(current_user, relation.oid, 'UPDATE') OR
             has_sequence_privilege(current_user, relation.oid, 'USAGE')
           )
       ) AS cross_schema_sequence_access,
       EXISTS (
         SELECT 1 FROM information_schema.tables relation
         WHERE relation.table_schema = $1
           AND has_table_privilege(
             current_user,
             format('%I.%I', relation.table_schema, relation.table_name),
             'TRUNCATE'
           )
       ) AS table_truncate,
       EXISTS (
         SELECT 1 FROM information_schema.tables relation
         WHERE relation.table_schema = $1
           AND relation.table_name IN (
             'action_effect_reservations',
             'action_events',
             'audit_events',
             'deployment_profiles',
             'evaluation_candidates',
             'evaluation_judge_results',
             'evaluation_release_judge_results',
             'evaluation_releases',
             'evaluation_replay_tombstones',
             'surface_delivery_receipts',
             'surface_delivery_tombstones',
             'surface_event_tombstones',
             'surface_outbox_events',
             'workflow_runs'
           )
           AND (
             has_table_privilege(
               current_user,
               format('%I.%I', relation.table_schema, relation.table_name),
               'UPDATE'
             ) OR
             has_table_privilege(
               current_user,
               format('%I.%I', relation.table_schema, relation.table_name),
               'DELETE'
             )
           )
       ) AS immutable_mutation,
       EXISTS (
         SELECT 1 FROM information_schema.columns column_record
         WHERE column_record.table_schema = $1
           AND column_record.table_name = 'action_states'
           AND column_record.column_name IN (
             'proposal_id',
             'run_id',
             'principal_ref',
             'proposal_hash',
             'effect_key',
             'proposal',
             'created_at'
           )
           AND has_column_privilege(
             current_user,
             format('%I.%I', column_record.table_schema, column_record.table_name),
             column_record.column_name,
             'UPDATE'
           )
       ) AS action_identity_update,
       has_column_privilege(
         current_user,
         format('%I.%I', $1, 'reconciliation_leases'),
         'proposal_id',
         'UPDATE'
       ) AS reconciliation_identity_update,
       has_table_privilege(
         current_user,
         format('%I.%I', $1, 'action_states'),
         'DELETE'
       ) AS action_state_delete,
       (
         has_table_privilege(current_user, format('%I.%I', $1, 'schema_migrations'), 'INSERT') OR
         has_table_privilege(current_user, format('%I.%I', $1, 'schema_migrations'), 'UPDATE') OR
         has_table_privilege(current_user, format('%I.%I', $1, 'schema_migrations'), 'DELETE') OR
         has_table_privilege(current_user, format('%I.%I', $1, 'schema_migrations'), 'TRUNCATE')
       ) AS schema_migration_write,
       has_table_privilege(
         current_user,
         format('%I.%I', $1, 'audit_events'),
         'SELECT'
       ) AS audit_select,
       EXISTS (
         SELECT 1 FROM information_schema.tables relation
         WHERE relation.table_schema = $1
           AND has_table_privilege(
             current_user,
             format('%I.%I', relation.table_schema, relation.table_name),
             'TRIGGER'
           )
       ) AS table_trigger,
       EXISTS (
         SELECT 1 FROM information_schema.tables relation
         WHERE relation.table_schema = $1
           AND has_table_privilege(
             current_user,
             format('%I.%I', relation.table_schema, relation.table_name),
             'REFERENCES'
           )
       ) AS table_references,
       EXISTS (
         SELECT 1
         FROM pg_catalog.pg_proc procedure
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname = $1
           AND (procedure.proname <> 'persist_authorized_evaluation' OR NOT procedure.prosecdef)
           AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')
       ) AS unauthorized_function_execute,
       has_function_privilege(
         current_user,
         format('%I.persist_authorized_evaluation(text, character, character, jsonb, jsonb, text, jsonb)', $1),
         'EXECUTE'
       ) AS evaluation_persist_execute,
       EXISTS (
         SELECT 1 FROM information_schema.sequences sequence
         WHERE sequence.sequence_schema = $1
           AND has_sequence_privilege(
             current_user,
             format('%I.%I', sequence.sequence_schema, sequence.sequence_name),
             'UPDATE'
           )
       ) AS sequence_update,
       EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc procedure
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname <> $1
           AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND namespace.nspname <> 'information_schema'
           AND procedure.prosecdef
           AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')
       ) AS cross_schema_security_definer_access`,
        [this.schema],
      );
      const privilegeState = privileges.rows[0];
      if (
        privilegeState?.database_connect !== true ||
        privilegeState?.evaluation_persist_execute !== false ||
        Object.entries(privilegeState ?? {}).some(
          ([name, value]) =>
            !["database_connect", "database_temp", "evaluation_persist_execute"].includes(name) && Boolean(value),
        )
      )
        storeError("schema_unhealthy", "Runtime DDL or immutable-table privilege detected");
      const runtimeOwnership = await client.query(
        `SELECT count(*)::integer AS owned
     FROM pg_catalog.pg_tables WHERE schemaname = $1 AND tableowner = current_user`,
        [this.schema],
      );
      if (runtimeOwnership.rows[0].owned !== 0) storeError("schema_unhealthy", "Runtime role owns canary tables");
      if (!transactionOpen) await client.query("COMMIT");
      return true;
    } catch (error) {
      if (!transactionOpen) await client.query("ROLLBACK").catch(() => {});
      if (error instanceof CanaryStoreError) throw error;
      storeError("schema_unhealthy", "Schema readiness verification failed");
    } finally {
      if (ownsClient) client.release();
    }
  }

  async close() {
    this.#initialized = false;
    await this.#pool.end();
  }

  async health() {
    return this.#verifySchema();
  }

  #assertInitialized() {
    if (!this.#initialized) storeError("not_initialized", "CEO canary store requires immutable database readiness");
  }

  async #verifyTransactionSentinel(client, requireProfile) {
    return verifyCanaryDatabaseSentinel(client, this.runtimeScope, requireProfile);
  }

  async #transaction(operation, entityRef = null, requireProfile = true) {
    this.#assertInitialized();
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL search_path = pg_catalog");
      await client.query("SET LOCAL statement_timeout = '10s'");
      await client.query("SELECT pg_advisory_xact_lock_shared(hashtext($1))", [CANARY_MAINTENANCE_LOCK_KEY]);
      await this.#verifyTransactionSentinel(client, requireProfile);
      if (entityRef !== null) {
        await client.query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))", [
          `${this.runtimeScope.profileRef}:${this.runtimeScope.profileSha256}`,
          entityRef,
        ]);
      }
      const result = await operation(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  #assertContext(context) {
    this.#assertInitialized();
    const checkedContext = assertContext(context);
    if (checkedContext.principalRef !== this.authority.principalRef) {
      storeError("invalid_context", "Authenticated principal is outside the runtime authority");
    }
    return checkedContext;
  }

  async claimIngress({ nonce, requestHash, expiresAt }) {
    this.#assertInitialized();
    return this.#transaction(async (client) => {
      const result = await client.query(
        `WITH pruned AS (
     DELETE FROM ${this.schema}.ingress_requests
     WHERE profile_ref = $1 AND profile_sha256 = $2
       AND expires_at < clock_timestamp() - interval '1 hour'
     RETURNING nonce
   )
   INSERT INTO ${this.schema}.ingress_requests (profile_ref, profile_sha256, nonce, request_hash, expires_at)
   VALUES ($1, $2, $3, $4, $5::timestamptz)
   ON CONFLICT (profile_ref, profile_sha256, nonce) DO NOTHING
   RETURNING nonce`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, nonce, requestHash, expiresAt],
      );
      return result.rowCount === 1;
    }, `ingress:${nonce}`);
  }

  async #audit(client, context, operation, entityType, entityId, beforeHash, afterHash) {
    this.#assertInitialized();
    await client.query(
      `INSERT INTO ${this.schema}.audit_events
 (profile_ref, profile_sha256, request_hash, principal_ref, operation, entity_type, entity_id, before_hash, after_hash)
 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        this.runtimeScope.profileRef,
        this.runtimeScope.profileSha256,
        context.requestHash,
        context.principalRef,
        operation,
        entityType,
        entityId,
        beforeHash,
        afterHash,
      ],
    );
  }

  async #databaseNow(client) {
    this.#assertInitialized();
    const result = await client.query("SELECT clock_timestamp() AS database_now");
    return result.rows[0].database_now.toISOString();
  }

  async createRun(run, payloadHash, context) {
    this.#assertInitialized();
    context = this.#assertContext(context);
    if (!HASH.test(payloadHash)) storeError("invalid_payload_hash", "Run payload hash is invalid");
    const checkedRun = this.domain.assertRun(run);
    if (sha256Canonical(checkedRun) !== payloadHash)
      storeError("payload_hash_mismatch", "Run payload hash does not match");
    try {
      return await this.#transaction(async (client) => {
        const databaseNow = await this.#databaseNow(client);
        if (Math.abs(Date.parse(checkedRun.startedAt) - Date.parse(databaseNow)) > this.maxClockSkewMs) {
          storeError("run_time_invalid", "Run start time is outside the database clock window");
        }
        if (checkedRun.parentRunId) {
          const parent = await client.query(
            `SELECT run_id, principal_ref, payload FROM ${this.schema}.workflow_runs
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND run_id = $3 AND principal_ref = $4
       FOR SHARE`,
            [
              this.runtimeScope.profileRef,
              this.runtimeScope.profileSha256,
              checkedRun.parentRunId,
              context.principalRef,
            ],
          );
          if (!parent.rows[0]) storeError("parent_run_not_found", "Parent run was not found within authority");
          let parentRun;
          try {
            parentRun = this.domain.assertRun(parent.rows[0].payload);
          } catch {
            storeError("stored_run_corrupt", "Stored parent run is invalid");
          }
          if (
            parentRun.runId !== parent.rows[0].run_id ||
            parentRun.actor.principalRef !== parent.rows[0].principal_ref
          ) {
            storeError("stored_run_corrupt", "Stored parent run lineage does not match its row");
          }
          if (Date.parse(parentRun.startedAt) > Date.parse(checkedRun.startedAt)) {
            storeError("run_time_invalid", "Child run predates its parent");
          }
        }
        const result = await client.query(
          `INSERT INTO ${this.schema}.workflow_runs (profile_ref, profile_sha256, run_id, principal_ref, payload_hash, payload)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb)
     RETURNING run_id, principal_ref, payload_hash, payload, created_at`,
          [
            this.runtimeScope.profileRef,
            this.runtimeScope.profileSha256,
            checkedRun.runId,
            context.principalRef,
            payloadHash,
            JSON.stringify(checkedRun),
          ],
        );
        await this.#audit(client, context, "create", "workflow_run", checkedRun.runId, null, payloadHash);
        return result.rows[0];
      }, `run:${checkedRun.runId}`);
    } catch (error) {
      if (error?.code === "23505") storeError("run_already_exists", "Workflow run already exists");
      throw error;
    }
  }

  async readRun(runId, context) {
    this.#assertInitialized();
    context = this.#assertContext(context);
    return this.#transaction(async (client) => {
      const result = await client.query(
        `SELECT run_id, principal_ref, payload_hash, payload, created_at
   FROM ${this.schema}.workflow_runs
   WHERE profile_ref = $1 AND profile_sha256 = $2 AND run_id = $3 AND principal_ref = $4`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, runId, context.principalRef],
      );
      const row = result.rows[0];
      if (!row) storeError("run_not_found", "Workflow run was not found");
      try {
        const storedRun = this.domain.assertRun(row.payload);
        if (storedRun.runId !== row.run_id || storedRun.actor.principalRef !== row.principal_ref) {
          storeError("stored_run_corrupt", "Stored workflow run lineage does not match its row");
        }
      } catch {
        storeError("stored_run_corrupt", "Stored workflow run is invalid");
      }
      if (sha256Canonical(row.payload) !== row.payload_hash) {
        storeError("stored_run_corrupt", "Stored workflow run hash does not match its content");
      }
      await this.#audit(client, context, "read", "workflow_run", runId, row.payload_hash, row.payload_hash);
      return row;
    }, `run:${runId}`);
  }

  async createAction(proposal, context) {
    this.#assertInitialized();
    context = this.#assertContext(context);
    const checkedProposal = this.domain.assertProposal(proposal);
    const state = createActionState(checkedProposal);
    const stateHash = sha256Canonical(state);
    try {
      return await this.#transaction(async (client) => {
        const run = await client.query(
          `SELECT run_id, principal_ref, payload_hash, payload, clock_timestamp() AS database_now
     FROM ${this.schema}.workflow_runs
     WHERE profile_ref = $1 AND profile_sha256 = $2 AND run_id = $3
     FOR SHARE`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, checkedProposal.runId],
        );
        if (!run.rows[0] || run.rows[0].principal_ref !== context.principalRef) {
          storeError("run_not_found", "Proposal workflow run was not found within authority");
        }
        let workflowRun;
        try {
          workflowRun = this.domain.assertRun(run.rows[0].payload);
        } catch {
          storeError("stored_run_corrupt", "Proposal workflow run is invalid");
        }
        if (sha256Canonical(workflowRun) !== run.rows[0].payload_hash) {
          storeError("stored_run_corrupt", "Proposal workflow run hash does not match its content");
        }
        if (workflowRun.runId !== run.rows[0].run_id || workflowRun.actor.principalRef !== run.rows[0].principal_ref) {
          storeError("stored_run_corrupt", "Proposal workflow run lineage does not match its row");
        }
        if (sha256Canonical(workflowRun.actor) !== sha256Canonical(checkedProposal.actor)) {
          storeError("lineage_mismatch", "Proposal actor does not exactly match its workflow run");
        }
        const databaseNow = run.rows[0].database_now.toISOString();
        const createdAt = Date.parse(checkedProposal.createdAt);
        const expiresAt = Date.parse(checkedProposal.expiresAt);
        if (
          createdAt < Date.parse(workflowRun.startedAt) ||
          Math.abs(createdAt - Date.parse(databaseNow)) > this.maxClockSkewMs ||
          expiresAt <= Date.parse(databaseNow) ||
          expiresAt - createdAt > this.maxProposalLifetimeMs
        ) {
          storeError("proposal_time_invalid", "Proposal time lineage is outside its database-authorized window");
        }
        await client.query(
          `INSERT INTO ${this.schema}.action_states
     (profile_ref, profile_sha256, proposal_id, run_id, principal_ref, proposal_hash, effect_key, proposal, state, state_hash, revision)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, 0)`,
          [
            this.runtimeScope.profileRef,
            this.runtimeScope.profileSha256,
            checkedProposal.proposalId,
            checkedProposal.runId,
            context.principalRef,
            checkedProposal.proposalHash,
            checkedProposal.effectKey,
            JSON.stringify(checkedProposal),
            JSON.stringify(state),
            stateHash,
          ],
        );
        await client.query(
          `INSERT INTO ${this.schema}.action_effect_reservations
     (profile_ref, profile_sha256, effect_key, proposal_id, proposal_hash, principal_ref)
     VALUES ($1, $2, $3, $4, $5, $6)`,
          [
            this.runtimeScope.profileRef,
            this.runtimeScope.profileSha256,
            checkedProposal.effectKey,
            checkedProposal.proposalId,
            checkedProposal.proposalHash,
            context.principalRef,
          ],
        );
        await this.#audit(
          client,
          context,
          "create_and_reserve_effect",
          "action",
          checkedProposal.proposalId,
          null,
          stateHash,
        );
        return { proposal: checkedProposal, state, stateHash, revision: 0 };
      }, `action:${checkedProposal.proposalId}`);
    } catch (error) {
      if (error?.code === "23505") {
        if (
          String(error.constraint ?? "").includes("effect_key") ||
          error.constraint === "action_effect_reservations_pkey"
        ) {
          storeError("effect_already_reserved", "Action effect is already reserved");
        }
        storeError("action_already_exists", "Action proposal already exists");
      }
      throw error;
    }
  }

  async readAction(proposalId, context) {
    this.#assertInitialized();
    context = this.#assertContext(context);
    return this.#transaction(async (client) => {
      const result = await client.query(
        `SELECT proposal_id, run_id, principal_ref, proposal_hash, effect_key, proposal, state, state_hash, revision
   FROM ${this.schema}.action_states
   WHERE profile_ref = $1 AND profile_sha256 = $2 AND proposal_id = $3 AND principal_ref = $4`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, proposalId, context.principalRef],
      );
      const action = asAction(result.rows[0], this.domain);
      if (!action) storeError("action_not_found", "Action proposal was not found");
      await this.#audit(client, context, "read", "action", proposalId, action.stateHash, action.stateHash);
      return action;
    }, `action:${proposalId}`);
  }

  #assertExpected(row, expected, context) {
    if (!row || row.principal_ref !== context.principalRef)
      storeError("action_not_found", "Action proposal was not found");
    const action = asAction(row, this.domain);
    if (
      Number(row.revision) !== expected.expectedRevision ||
      row.state_hash !== expected.expectedStateHash ||
      row.proposal_hash !== expected.proposalHash ||
      row.effect_key !== expected.effectKey
    ) {
      storeError("revision_conflict", "Action state changed or payload binding does not match");
    }
    return action.state;
  }

  async #lockedAction(client, proposalId) {
    this.#assertInitialized();
    const result = await client.query(
      `SELECT proposal_id, run_id, principal_ref, proposal_hash, effect_key, proposal, state, state_hash, revision
 FROM ${this.schema}.action_states
 WHERE profile_ref = $1 AND profile_sha256 = $2 AND proposal_id = $3
 FOR UPDATE`,
      [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, proposalId],
    );
    return result.rows[0];
  }

  async #assertReservation(client, row) {
    this.#assertInitialized();
    const result = await client.query(
      `SELECT proposal_id, proposal_hash, principal_ref
 FROM ${this.schema}.action_effect_reservations
 WHERE profile_ref = $1 AND profile_sha256 = $2 AND effect_key = $3
 FOR SHARE`,
      [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, row.effect_key],
    );
    const reservation = result.rows[0];
    if (
      !reservation ||
      reservation.proposal_id !== row.proposal_id ||
      reservation.proposal_hash !== row.proposal_hash ||
      reservation.principal_ref !== row.principal_ref
    ) {
      storeError("effect_reservation_mismatch", "Action effect reservation is missing or does not match");
    }
  }

  async #persistTransition(client, row, currentState, event, nextState, context, operation) {
    this.#assertInitialized();
    const stateHash = sha256Canonical(nextState);
    const eventHash = sha256Canonical(event);
    const update = await client.query(
      `UPDATE ${this.schema}.action_states
 SET state = $1::jsonb, state_hash = $2, revision = $3, updated_at = clock_timestamp()
 WHERE profile_ref = $4 AND profile_sha256 = $5 AND proposal_id = $6 AND revision = $7
   AND state_hash = $8 AND proposal_hash = $9 AND effect_key = $10
 RETURNING proposal`,
      [
        JSON.stringify(nextState),
        stateHash,
        nextState.revision,
        this.runtimeScope.profileRef,
        this.runtimeScope.profileSha256,
        row.proposal_id,
        currentState.revision,
        row.state_hash,
        row.proposal_hash,
        row.effect_key,
      ],
    );
    if (update.rowCount !== 1) storeError("revision_conflict", "Action state compare-and-swap failed");
    await client.query(
      `INSERT INTO ${this.schema}.action_events
 (profile_ref, profile_sha256, proposal_id, revision, principal_ref, event_type, event_hash, event, resulting_state_hash, resulting_state)
 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10::jsonb)`,
      [
        this.runtimeScope.profileRef,
        this.runtimeScope.profileSha256,
        row.proposal_id,
        nextState.revision,
        context.principalRef,
        event.type,
        eventHash,
        JSON.stringify(event),
        stateHash,
        JSON.stringify(nextState),
      ],
    );
    await this.#audit(client, context, operation, "action", row.proposal_id, row.state_hash, stateHash);
    return {
      proposal: canonicalSnapshot(update.rows[0].proposal),
      state: nextState,
      stateHash,
      revision: nextState.revision,
    };
  }

  async transitionAction(proposalId, expected, event, reconciliationLeaseId, context) {
    this.#assertInitialized();
    context = this.#assertContext(context);
    if (event?.type === "claim_execution")
      storeError("reservation_required", "Execution claims require the reservation API");
    return this.#transaction(async (client) => {
      const row = await this.#lockedAction(client, proposalId);
      const state = this.#assertExpected(row, expected, context);
      await this.#assertReservation(client, row);
      let reconciliationRequired = false;
      if (event?.type === "record_receipt") {
        const databaseNow = await this.#databaseNow(client);
        const executionLeaseExpired =
          state.status === "executing" &&
          state.claim &&
          Date.parse(databaseNow) >= Date.parse(state.claim.leaseExpiresAt);
        reconciliationRequired = executionLeaseExpired || state.status === "outcome_unknown";
        if (reconciliationRequired) {
          const lease = await client.query(
            `SELECT lease_id FROM ${this.schema}.reconciliation_leases
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND proposal_id = $3
         AND principal_ref = $4 AND revision = $5 AND lease_id = $6 AND expires_at > clock_timestamp()
       FOR UPDATE`,
            [
              this.runtimeScope.profileRef,
              this.runtimeScope.profileSha256,
              proposalId,
              context.principalRef,
              state.revision,
              reconciliationLeaseId ?? "",
            ],
          );
          if (!lease.rows[0]) storeError("reconciliation_lease_required", "An active reconciliation lease is required");
        } else if (reconciliationLeaseId !== undefined) {
          storeError("invalid_lease", "A reconciliation lease is not valid for this transition");
        }
      }
      const nextState = this.domain.reduceActionState(state, event);
      const result = await this.#persistTransition(
        client,
        row,
        state,
        event,
        nextState,
        context,
        `transition:${event.type}`,
      );
      if (event.type === "record_receipt" && reconciliationRequired) {
        const released = await client.query(
          `DELETE FROM ${this.schema}.reconciliation_leases
     WHERE profile_ref = $1 AND profile_sha256 = $2 AND proposal_id = $3
       AND lease_id = $4 AND revision = $5 AND principal_ref = $6`,
          [
            this.runtimeScope.profileRef,
            this.runtimeScope.profileSha256,
            proposalId,
            reconciliationLeaseId,
            state.revision,
            context.principalRef,
          ],
        );
        if (released.rowCount !== 1)
          storeError("reconciliation_lease_required", "The reconciliation lease changed before release");
      }
      return result;
    }, `action:${proposalId}`);
  }

  async reserveExecution(proposalId, expected, leaseId, leaseDurationSeconds, context) {
    this.#assertInitialized();
    context = this.#assertContext(context);
    if (!LEASE_ID.test(leaseId)) storeError("invalid_lease", "Execution lease identifier is invalid");
    if (!Number.isInteger(leaseDurationSeconds) || leaseDurationSeconds < 10 || leaseDurationSeconds > 300) {
      storeError("invalid_lease", "Execution lease duration is invalid");
    }
    return this.#transaction(async (client) => {
      const row = await this.#lockedAction(client, proposalId);
      const state = this.#assertExpected(row, expected, context);
      await this.#assertReservation(client, row);
      const times = await client.query(
        `SELECT database_now, database_now + ($1 * interval '1 second') AS expires_at
   FROM (SELECT clock_timestamp() AS database_now) clock`,
        [leaseDurationSeconds],
      );
      const event = {
        type: "claim_execution",
        at: times.rows[0].database_now.toISOString(),
        claimId: leaseId,
        leaseExpiresAt: times.rows[0].expires_at.toISOString(),
      };
      const nextState = this.domain.reduceActionState(state, event);
      return this.#persistTransition(client, row, state, event, nextState, context, "reserve_execution");
    }, `action:${proposalId}`);
  }

  async reserveReconciliation(proposalId, expected, leaseId, leaseDurationSeconds, context) {
    this.#assertInitialized();
    context = this.#assertContext(context);
    if (!LEASE_ID.test(leaseId)) storeError("invalid_lease", "Reconciliation lease identifier is invalid");
    if (!Number.isInteger(leaseDurationSeconds) || leaseDurationSeconds < 10 || leaseDurationSeconds > 300) {
      storeError("invalid_lease", "Reconciliation lease duration is invalid");
    }
    return this.#transaction(async (client) => {
      const row = await this.#lockedAction(client, proposalId);
      const state = this.#assertExpected(row, expected, context);
      await this.#assertReservation(client, row);
      const times = await client.query(
        `SELECT database_now, database_now + ($1 * interval '1 second') AS expires_at
   FROM (SELECT clock_timestamp() AS database_now) clock`,
        [leaseDurationSeconds],
      );
      const acquiredAt = times.rows[0].database_now.toISOString();
      const expiresAt = times.rows[0].expires_at.toISOString();
      const executionExpired =
        state.status === "executing" && state.claim && Date.parse(acquiredAt) >= Date.parse(state.claim.leaseExpiresAt);
      if (!executionExpired && state.status !== "outcome_unknown") {
        storeError("reconciliation_not_available", "Action is not eligible for reconciliation");
      }
      const result = await client.query(
        `INSERT INTO ${this.schema}.reconciliation_leases
   (profile_ref, profile_sha256, proposal_id, lease_id, principal_ref, acquired_at, expires_at, revision)
   VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8)
   ON CONFLICT (profile_ref, profile_sha256, proposal_id) DO UPDATE
   SET lease_id = EXCLUDED.lease_id,
       principal_ref = EXCLUDED.principal_ref,
       acquired_at = EXCLUDED.acquired_at,
       expires_at = EXCLUDED.expires_at,
       revision = EXCLUDED.revision
   WHERE ${this.schema}.reconciliation_leases.profile_ref = EXCLUDED.profile_ref
     AND ${this.schema}.reconciliation_leases.profile_sha256 = EXCLUDED.profile_sha256
     AND ${this.schema}.reconciliation_leases.expires_at <= clock_timestamp()
   RETURNING lease_id, acquired_at, expires_at, revision`,
        [
          this.runtimeScope.profileRef,
          this.runtimeScope.profileSha256,
          proposalId,
          leaseId,
          context.principalRef,
          acquiredAt,
          expiresAt,
          state.revision,
        ],
      );
      if (result.rowCount !== 1) storeError("lease_conflict", "A reconciliation lease is already active");
      await this.#audit(
        client,
        context,
        "reserve_reconciliation",
        "action",
        proposalId,
        row.state_hash,
        row.state_hash,
      );
      return { ...result.rows[0], proposalId, stateHash: row.state_hash };
    }, `action:${proposalId}`);
  }
}

export async function verifyCanaryDatabase(pool) {
  return new PostgresCanaryStore({ pool, scope: READINESS_SCOPE }).verifySchema();
}

export async function verifyCanaryDatabaseClient(client, transactionOpen = false) {
  const unavailable = async () => {
    throw new TypeError("Fixed client verification cannot acquire another database connection");
  };
  const pool = Object.freeze({ connect: unavailable, query: unavailable });
  return new PostgresCanaryStore({ pool, scope: READINESS_SCOPE }).verifySchema(client, transactionOpen);
}
