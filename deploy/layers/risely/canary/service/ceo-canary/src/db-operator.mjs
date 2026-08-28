import { spawn } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import { chmod, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { bootstrapSql } from "./db-operator-bootstrap-sql.mjs";
import { migrate } from "./migrate.mjs";
import { assertFixedDatabaseContract, runtimePoolConfig } from "./database-connection.mjs";
import { assertExactCanaryCatalog, assertRuntimeDatabaseBoundary } from "./database-security.mjs";
import { provisionCanaryCredentials } from "./provision-credentials.mjs";
import {
  CANARY_BOOTSTRAP_ADMIN_ROLE,
  CANARY_DATABASE_NAME,
  CANARY_EVALUATION_WRITER_DATABASE_USER,
  CANARY_MIGRATION_DATABASE_USER,
  CANARY_OWNER_DATABASE_USER,
  CANARY_RUNTIME_DATABASE_USER,
  CANARY_SCHEMA_NAME,
  SCHEMA_VERSION,
} from "./schema.mjs";

const { Client, Pool } = pg;
const phases = Object.freeze(["inventory", "bootstrap", "provision", "migrate", "readiness"]);
const secretEnvironmentNames = Object.freeze([
  "CANARY_BOOTSTRAP_DATABASE_URL",
  "CANARY_MIGRATION_DATABASE_URL",
  "CANARY_DATABASE_URL",
  "DATABASE_CA_CERT",
]);
const psqlPath = "/usr/bin/psql";
const timeoutMilliseconds = 30000;
const maximumOutputBytes = 16384;
const credentialPattern = /^[A-Za-z0-9_-]{43}$/;

function databaseIdentity(value, expectedUser, env, label) {
  if (typeof value !== "string") throw new Error(`${label} is required`);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a PostgreSQL connection URL`);
  }
  let credential;
  let database;
  let username;
  try {
    credential = decodeURIComponent(url.password);
    database = decodeURIComponent(url.pathname.slice(1));
    username = decodeURIComponent(url.username);
  } catch {
    throw new Error(`${label} contains invalid credential encoding`);
  }
  if (
    !["postgres:", "postgresql:"].includes(url.protocol) ||
    url.search ||
    url.hash ||
    url.hostname.toLowerCase() !== env.CANARY_DATABASE_HOST ||
    (url.port || "5432") !== env.CANARY_DATABASE_PORT ||
    database !== CANARY_DATABASE_NAME ||
    username !== expectedUser ||
    !credential ||
    /[\u0000\r\n]/u.test(credential)
  ) {
    throw new Error(`${label} does not match the fixed Risely QM database identity`);
  }
  return Object.freeze({ connectionString: value, credential });
}

function canonicalCredential(value, label) {
  const encoded = Buffer.from(value, "utf8");
  const decoded = Buffer.from(value, "base64url");
  if (
    encoded.length !== 43 ||
    !credentialPattern.test(value) ||
    decoded.length !== 32 ||
    decoded.toString("base64url") !== value
  ) {
    encoded.fill(0);
    decoded.fill(0);
    throw new Error(`${label} must be one canonical 32-byte base64url credential`);
  }
  decoded.fill(0);
  return encoded;
}

function assertDistinctCredentials(identities) {
  const credentials = identities.map(({ credential }) => Buffer.from(credential, "utf8"));
  try {
    for (let left = 0; left < credentials.length; left += 1) {
      for (let right = left + 1; right < credentials.length; right += 1) {
        if (
          credentials[left].length === credentials[right].length &&
          timingSafeEqual(credentials[left], credentials[right])
        ) {
          throw new Error("Database operator credentials must remain distinct");
        }
      }
    }
  } finally {
    credentials.forEach((credential) => credential.fill(0));
  }
}

function fixedEnvironment(env) {
  assertFixedDatabaseContract(env);
  if (env.CANARY_MUTATIONS_ENABLED !== "0" || env.CANARY_PROVIDER_EXECUTION_ENABLED !== "0") {
    throw new Error("Database operator provider and action execution must remain disabled");
  }
  if (typeof env.DATABASE_CA_CERT !== "string" || !env.DATABASE_CA_CERT.includes("BEGIN CERTIFICATE")) {
    throw new Error("DATABASE_CA_CERT must contain the fixed database CA bundle");
  }
  return env;
}

function adminPoolConfig(env) {
  const identity = databaseIdentity(
    env.CANARY_BOOTSTRAP_DATABASE_URL,
    CANARY_BOOTSTRAP_ADMIN_ROLE,
    env,
    "CANARY_BOOTSTRAP_DATABASE_URL",
  );
  return {
    identity,
    config: {
      connectionString: identity.connectionString,
      ssl: { ca: env.DATABASE_CA_CERT, rejectUnauthorized: true },
      application_name: "risely-ceo-canary-db-operator-inventory",
      connectionTimeoutMillis: 5000,
      query_timeout: 10000,
    },
  };
}

async function readInventory(env) {
  const { config } = adminPoolConfig(env);
  const client = new Client(config);
  await client.connect();
  try {
    await client.query("BEGIN READ ONLY");
    await client.query("SET LOCAL search_path = pg_catalog");
    await client.query("SET LOCAL statement_timeout = '10s'");
    const identity = await client.query(
      `SELECT pg_catalog.current_database() AS database_name,
              current_user AS database_user,
              database_record.datdba = current_user::pg_catalog.regrole AS owns_database,
              role_record.rolcanlogin,
              role_record.rolcreaterole,
              role_record.rolsuper,
              pg_catalog.current_setting('server_version_num')::pg_catalog.int4 AS server_version_num
         FROM pg_catalog.pg_database database_record
         JOIN pg_catalog.pg_roles role_record ON role_record.oid = current_user::pg_catalog.regrole
        WHERE database_record.datname = pg_catalog.current_database()`,
    );
    const roles = await client.query(
      `SELECT role_record.rolname,
              role_record.rolcanlogin,
              role_record.rolinherit,
              role_record.rolsuper,
              role_record.rolcreatedb,
              role_record.rolcreaterole,
              role_record.rolreplication,
              role_record.rolbypassrls
         FROM pg_catalog.pg_roles role_record
        WHERE role_record.rolname = ANY($1::pg_catalog.text[])
        ORDER BY role_record.rolname`,
      [
        [
          CANARY_OWNER_DATABASE_USER,
          CANARY_MIGRATION_DATABASE_USER,
          CANARY_RUNTIME_DATABASE_USER,
          CANARY_EVALUATION_WRITER_DATABASE_USER,
        ],
      ],
    );
    const namespace = await client.query(
      `SELECT namespace.nspname, owner.rolname AS owner
         FROM pg_catalog.pg_namespace namespace
         JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
        WHERE namespace.nspname = $1`,
      [CANARY_SCHEMA_NAME],
    );
    const hazards = await client.query(
      `SELECT
          (SELECT pg_catalog.count(*)::pg_catalog.int4
             FROM pg_catalog.pg_event_trigger event_trigger
            WHERE event_trigger.evtenabled <> 'D') AS enabled_event_triggers,
          (SELECT pg_catalog.count(*)::pg_catalog.int4
             FROM pg_catalog.pg_foreign_data_wrapper wrapper
            WHERE EXISTS (
              SELECT 1
                FROM pg_catalog.aclexplode(
                  COALESCE(wrapper.fdwacl, pg_catalog.acldefault('F', wrapper.fdwowner))
                ) acl
               WHERE acl.grantee = 0
                 AND acl.privilege_type = 'USAGE'
            )) AS public_fdw_usage,
          (SELECT pg_catalog.count(*)::pg_catalog.int4
             FROM pg_catalog.pg_namespace namespace_record
            WHERE namespace_record.nspname = $1) AS canary_schema_count`,
      [CANARY_SCHEMA_NAME],
    );
    let migrations = [];
    if (namespace.rowCount === 1) {
      const migrationRelation = await client.query(
        `SELECT relation.oid::pg_catalog.text AS relation_oid,
                owner.rolname AS owner
           FROM pg_catalog.pg_class relation
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
           JOIN pg_catalog.pg_roles owner ON owner.oid = relation.relowner
          WHERE namespace.nspname = $1
            AND relation.relname = 'schema_migrations'
            AND relation.relkind = 'r'`,
        [CANARY_SCHEMA_NAME],
      );
      migrations = migrationRelation.rows;
    }
    await client.query("COMMIT");
    const current = identity.rows[0];
    if (
      identity.rowCount !== 1 ||
      current.database_name !== CANARY_DATABASE_NAME ||
      current.database_user !== CANARY_BOOTSTRAP_ADMIN_ROLE ||
      !current.owns_database ||
      !current.rolcanlogin ||
      !current.rolcreaterole ||
      current.rolsuper ||
      Math.trunc(Number(current.server_version_num) / 10000) !== 16
    ) {
      throw new Error("Database operator inventory identity is incompatible");
    }
    return Object.freeze({
      database: current.database_name,
      user: current.database_user,
      schema: namespace.rows[0] ?? null,
      roles: roles.rows,
      migrations,
      hazards: hazards.rows[0],
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    await client.end();
  }
}

function escapePgpass(value) {
  return value.replaceAll("\\", "\\\\").replaceAll(":", "\\:");
}

async function createSupportFiles(env, credentials = undefined) {
  const directory = await mkdtemp(join(tmpdir(), "risely-db-operator-"));
  const files = {
    directory,
    ca: join(directory, "ca.pem"),
    passfile: join(directory, "admin.pgpass"),
    migration: join(directory, "migration.secret"),
    runtime: join(directory, "runtime.secret"),
  };
  try {
    await chmod(directory, 0o700);
    const admin = adminPoolConfig(env).identity;
    const passfile = `${env.CANARY_DATABASE_HOST}:${env.CANARY_DATABASE_PORT}:${CANARY_DATABASE_NAME}:${CANARY_BOOTSTRAP_ADMIN_ROLE}:${escapePgpass(admin.credential)}\n`;
    await writeFile(files.ca, env.DATABASE_CA_CERT, { flag: "wx", mode: 0o400 });
    await writeFile(files.passfile, passfile, { flag: "wx", mode: 0o400 });
    if (credentials) {
      await writeFile(files.migration, credentials.migration, { flag: "wx", mode: 0o400 });
      await writeFile(files.runtime, credentials.runtime, { flag: "wx", mode: 0o400 });
    }
    return files;
  } catch (error) {
    await rm(directory, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
}

async function closeAndRemove(files, handles = []) {
  await Promise.all(handles.map((handle) => handle?.close().catch(() => {})));
  if (files?.directory) await rm(files.directory, { recursive: true, force: true }).catch(() => {});
}

async function runBootstrapPsql(env, files) {
  const passfile = await open(files.passfile, "r");
  const ca = await open(files.ca, "r");
  let child;
  let timer;
  let outputBytes = 0;
  let diagnostic = "";
  try {
    child = spawn(
      psqlPath,
      [
        "-X",
        "--quiet",
        "-h",
        env.CANARY_DATABASE_HOST,
        "-p",
        env.CANARY_DATABASE_PORT,
        "-U",
        CANARY_BOOTSTRAP_ADMIN_ROLE,
        "-d",
        CANARY_DATABASE_NAME,
        "-v",
        `canary_bootstrap_admin_role=${CANARY_BOOTSTRAP_ADMIN_ROLE}`,
        "-f",
        "-",
      ],
      {
        env: {
          PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          PGPASSFILE: "/proc/self/fd/3",
          PGSSLMODE: "verify-full",
          PGSSLROOTCERT: "/proc/self/fd/4",
          PGCONNECT_TIMEOUT: "5",
        },
        stdio: ["pipe", "pipe", "pipe", passfile.fd, ca.fd],
      },
    );
    const consume = (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > maximumOutputBytes) child.kill("SIGKILL");
    };
    child.stdout.on("data", consume);
    child.stderr.on("data", (chunk) => {
      consume(chunk);
      if (diagnostic.length < maximumOutputBytes) diagnostic += chunk.toString("utf8");
    });
    timer = setTimeout(() => child.kill("SIGKILL"), timeoutMilliseconds);
    child.stdin.on("error", () => {});
    child.stdin.end(bootstrapSql);
    const result = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    if (result.code !== 0 || result.signal || outputBytes > maximumOutputBytes) {
      throw new Error("Structural database bootstrap failed", {
        cause: new Error(diagnostic.slice(0, maximumOutputBytes)),
      });
    }
  } finally {
    clearTimeout(timer);
    await closeAndRemove(undefined, [passfile, ca]);
  }
}

function requirePristineInventory(inventory) {
  if (inventory.schema !== null || inventory.roles.length !== 0 || inventory.migrations.length !== 0) {
    throw new Error("Structural bootstrap requires an exact pristine canary boundary");
  }
}

function requireBootstrappedInventory(inventory) {
  if (
    inventory.schema?.nspname !== CANARY_SCHEMA_NAME ||
    inventory.schema?.owner !== CANARY_OWNER_DATABASE_USER ||
    inventory.roles.length !== 4 ||
    inventory.migrations.length !== 0
  ) {
    throw new Error("Credential provisioning requires the exact empty structural bootstrap");
  }
}

function requireProvisionableInventory(inventory) {
  requireBootstrappedInventory({ ...inventory, migrations: [] });
  if (
    inventory.migrations.length > 1 ||
    (inventory.migrations.length === 1 && inventory.migrations[0].owner !== CANARY_OWNER_DATABASE_USER)
  ) {
    throw new Error("Credential provisioning found an incompatible migration catalog");
  }
}

async function bootstrap(env) {
  const before = await readInventory(env);
  requirePristineInventory(before);
  const files = await createSupportFiles(env);
  try {
    await runBootstrapPsql(env, files);
  } finally {
    await closeAndRemove(files);
  }
  requireBootstrappedInventory(await readInventory(env));
}

async function provision(env) {
  const admin = adminPoolConfig(env).identity;
  const migration = databaseIdentity(
    env.CANARY_MIGRATION_DATABASE_URL,
    CANARY_MIGRATION_DATABASE_USER,
    env,
    "CANARY_MIGRATION_DATABASE_URL",
  );
  const runtime = databaseIdentity(env.CANARY_DATABASE_URL, CANARY_RUNTIME_DATABASE_USER, env, "CANARY_DATABASE_URL");
  assertDistinctCredentials([admin, migration, runtime]);
  let migrationCredential;
  let runtimeCredential;
  let files;
  try {
    migrationCredential = canonicalCredential(migration.credential, "Migration credential");
    runtimeCredential = canonicalCredential(runtime.credential, "Runtime credential");
    requireProvisionableInventory(await readInventory(env));
    files = await createSupportFiles(env, {
      migration: migrationCredential,
      runtime: runtimeCredential,
    });
    await provisionCanaryCredentials({
      ...env,
      DATABASE_URL: env.CANARY_BOOTSTRAP_DATABASE_URL,
      CANARY_BOOTSTRAP_ADMIN_PASSFILE: files.passfile,
      CANARY_DATABASE_CA_FILE: files.ca,
      CANARY_MIGRATION_PASSWORD_FILE: files.migration,
      CANARY_RUNTIME_PASSWORD_FILE: files.runtime,
    });
  } finally {
    migrationCredential?.fill(0);
    runtimeCredential?.fill(0);
    await closeAndRemove(files);
  }
}

async function readiness(env) {
  const pool = new Pool(runtimePoolConfig(env));
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    await client.query("SET LOCAL search_path = pg_catalog");
    await client.query("SET LOCAL statement_timeout = '10s'");
    const identity = await client.query("SELECT current_user, pg_catalog.current_database() AS current_database");
    if (
      identity.rows[0]?.current_user !== CANARY_RUNTIME_DATABASE_USER ||
      identity.rows[0]?.current_database !== CANARY_DATABASE_NAME
    ) {
      throw new Error("Database operator readiness identity mismatch");
    }
    await assertRuntimeDatabaseBoundary(client);
    await assertExactCanaryCatalog(client);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

export async function runCompiledDatabaseOperatorPhase(phase, env = process.env) {
  if (!phases.includes(phase)) throw new Error("Unknown compiled database operator phase");
  fixedEnvironment(env);
  const requiredSecrets = {
    inventory: ["CANARY_BOOTSTRAP_DATABASE_URL"],
    bootstrap: ["CANARY_BOOTSTRAP_DATABASE_URL"],
    provision: ["CANARY_BOOTSTRAP_DATABASE_URL", "CANARY_MIGRATION_DATABASE_URL", "CANARY_DATABASE_URL"],
    migrate: ["CANARY_MIGRATION_DATABASE_URL"],
    readiness: ["CANARY_DATABASE_URL"],
  }[phase];
  for (const name of requiredSecrets) {
    if (typeof env[name] !== "string" || env[name].length === 0) throw new Error(`${name} is required`);
  }
  const extraSecret = secretEnvironmentNames.find(
    (name) => name !== "DATABASE_CA_CERT" && !requiredSecrets.includes(name) && env[name],
  );
  if (extraSecret) throw new Error(`${phase} received an unnecessary database credential`);
  if (phase === "inventory") return readInventory(env);
  if (phase === "bootstrap") return bootstrap(env);
  if (phase === "provision") return provision(env);
  if (phase === "migrate") return migrate(env);
  return readiness(env);
}

async function main() {
  if (process.argv.length !== 3 || !phases.includes(process.argv[2])) {
    throw new Error("Database operator phase must be compiled into the task entrypoint");
  }
  const phase = process.argv[2];
  const result = await runCompiledDatabaseOperatorPhase(phase, process.env);
  for (const name of secretEnvironmentNames) delete process.env[name];
  if (phase === "inventory") process.stdout.write(`${JSON.stringify(result)}\n`);
  process.stdout.write(`risely_agent_runtime_operator_${phase}_complete_v1\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(() => {
    for (const name of secretEnvironmentNames) delete process.env[name];
    process.stderr.write("Risely database operator phase failed\n");
    process.exitCode = 1;
  });
}
