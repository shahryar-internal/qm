import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import pg from "pg";
import {
  CANARY_BOOTSTRAP_ADMIN_ROLE,
  CANARY_DATABASE_NAME,
  CANARY_EVALUATION_WRITER_DATABASE_USER,
  CANARY_MIGRATION_DATABASE_USER,
  CANARY_OWNER_DATABASE_USER,
  CANARY_RUNTIME_DATABASE_USER,
  CANARY_SCHEMA_NAME,
} from "../../canary/service/ceo-canary/src/schema.mjs";

const { Client, Pool } = pg;
const enabled = process.env.TEST_CANARY_PG16_DOCKER_BOOTSTRAP === "1";
const skip = enabled ? false : "set TEST_CANARY_PG16_DOCKER_BOOTSTRAP=1 to run the isolated PostgreSQL 16 bootstrap";
const containerName = `risely-agent-runtime-pg16-bootstrap-${process.pid}`;
const containerPort = 55439;
const postgresImage = "postgres:16-alpine";
const bootstrapPath = fileURLToPath(
  new URL("../../canary/service/ceo-canary/migrations/bootstrap.sql", import.meta.url),
);
const creatorUser = CANARY_BOOTSTRAP_ADMIN_ROLE;
const postgresCredential = "postgres-bootstrap-fixture-v1";
const creatorCredential = "creator-bootstrap-fixture-v1";
const migrationCredential = "migration-bootstrap-fixture-v1";
const runtimeCredential = "runtime-bootstrap-fixture-v1";
const untrustedCreatorUser = "risely_bootstrap_without_database_create";

function docker(args, input = null) {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"] });
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
    child.stdin.end(input ?? undefined);
  });
}

async function requireDocker(args, input = null) {
  const result = await docker(args, input);
  assert.equal(result.exitCode, 0, result.stderr || result.stdout);
  return result;
}

async function waitUntilReady() {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const result = await docker(["exec", containerName, "pg_isready", "-U", "postgres", "-d", CANARY_DATABASE_NAME]);
    if (result.exitCode === 0) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  assert.fail("isolated PostgreSQL 16 container did not become ready");
}

async function waitUntilHostReady(connection) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const client = new Client(connection);
    try {
      await client.connect();
      await client.query("SELECT 1");
      await client.end();
      return;
    } catch {
      await client.end().catch(() => {});
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  assert.fail("isolated PostgreSQL 16 host port did not become ready");
}

function connectionConfig(user, credential) {
  return {
    host: "127.0.0.1",
    port: containerPort,
    database: CANARY_DATABASE_NAME,
    user,
    ...Object.fromEntries([["password", credential]]),
  };
}

async function bootstrapFingerprint(pool) {
  const result = await pool.query(
    `SELECT pg_catalog.jsonb_build_object(
       'roles', (
         SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
           role_record.rolname, role_record.rolcanlogin, role_record.rolinherit,
           role_record.rolsuper, role_record.rolcreaterole, role_record.rolcreatedb,
           role_record.rolreplication, role_record.rolbypassrls, role_record.rolpassword IS NULL
         ) ORDER BY role_record.rolname)
         FROM pg_catalog.pg_authid role_record
         WHERE role_record.rolname = ANY ($1::text[])
       ),
       'edges', (
         SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
           granted_role.rolname, member_role.rolname, grantor_role.rolname,
           membership.inherit_option, membership.set_option, membership.admin_option
         ) ORDER BY granted_role.rolname, member_role.rolname, grantor_role.rolname)
         FROM pg_catalog.pg_auth_members membership
         JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
         JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
         JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
         WHERE granted_role.rolname = ANY ($1::text[])
            OR member_role.rolname = ANY ($1::text[])
       ),
       'schema', (
         SELECT pg_catalog.jsonb_build_array(namespace.oid, owner.rolname, namespace.nspacl)
         FROM pg_catalog.pg_namespace namespace
         JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
         WHERE namespace.nspname = $2
       ),
       'settings', (
         SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(role_record.rolname, setting.setconfig)
           ORDER BY role_record.rolname)
         FROM pg_catalog.pg_roles role_record
         LEFT JOIN pg_catalog.pg_db_role_setting setting
           ON setting.setrole = role_record.oid
          AND setting.setdatabase = (
            SELECT database_record.oid FROM pg_catalog.pg_database database_record
            WHERE database_record.datname = pg_catalog.current_database()
          )
         WHERE role_record.rolname = ANY ($1::text[])
       )
     ) AS fingerprint`,
    [
      [
        CANARY_OWNER_DATABASE_USER,
        CANARY_MIGRATION_DATABASE_USER,
        CANARY_RUNTIME_DATABASE_USER,
        CANARY_EVALUATION_WRITER_DATABASE_USER,
      ],
      CANARY_SCHEMA_NAME,
    ],
  );
  return result.rows[0].fingerprint;
}

test(
  "vanilla PostgreSQL 16 bootstrap preserves a durable grantor and rolls back an exact rerun",
  { skip },
  async (t) => {
    let adminPool;
    let creatorPool;
    t.after(async () => {
      await creatorPool?.end().catch(() => {});
      await adminPool?.end().catch(() => {});
      await docker(["rm", "--force", containerName]);
    });
    await requireDocker([
      "run",
      "--detach",
      "--name",
      containerName,
      "--publish",
      `127.0.0.1:${containerPort}:5432`,
      "--env",
      `POSTGRES_PASSWORD=${postgresCredential}`,
      "--env",
      `POSTGRES_DB=${CANARY_DATABASE_NAME}`,
      postgresImage,
    ]);
    await waitUntilReady();
    const adminConnection = connectionConfig("postgres", postgresCredential);
    await waitUntilHostReady(adminConnection);
    adminPool = new Pool({ ...adminConnection, max: 1 });
    const server = await adminPool.query(
      `SELECT pg_catalog.current_setting('server_version_num')::integer AS version,
            pg_catalog.current_database() AS database`,
    );
    assert.equal(Math.floor(server.rows[0].version / 10000), 16);
    assert.equal(server.rows[0].database, CANARY_DATABASE_NAME);
    await adminPool.query(
      `CREATE ROLE ${creatorUser}
       LOGIN CREATEROLE NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS
       PASSWORD '${creatorCredential}';
     ALTER DATABASE ${CANARY_DATABASE_NAME} OWNER TO ${creatorUser};`,
    );
    creatorPool = new Pool({ ...connectionConfig(creatorUser, creatorCredential), max: 1 });
    const creator = await creatorPool.query(
      `SELECT current_user, session_user,
            role_record.rolcanlogin, role_record.rolcreaterole, role_record.rolsuper,
            pg_catalog.has_database_privilege(current_user, pg_catalog.current_database(), 'CREATE') AS database_create
     FROM pg_catalog.pg_roles role_record
     WHERE role_record.rolname = current_user`,
    );
    assert.deepEqual(creator.rows, [
      {
        current_user: creatorUser,
        session_user: creatorUser,
        rolcanlogin: true,
        rolcreaterole: true,
        rolsuper: false,
        database_create: true,
      },
    ]);
    const bootstrap = await readFile(bootstrapPath, "utf8");
    await requireDocker(["cp", bootstrapPath, `${containerName}:/tmp/risely-agent-runtime-bootstrap.sql`]);
    const emptyFingerprint = await bootstrapFingerprint(adminPool);
    const wrongAdmin = await docker([
      "exec",
      containerName,
      "psql",
      "-X",
      "--set",
      "ON_ERROR_STOP=1",
      "--set",
      `canary_bootstrap_admin_role=${untrustedCreatorUser}`,
      "--username",
      creatorUser,
      "--dbname",
      CANARY_DATABASE_NAME,
      "--file",
      "/tmp/risely-agent-runtime-bootstrap.sql",
    ]);
    assert.notEqual(wrongAdmin.exitCode, 0);
    assert.match(wrongAdmin.stdout, /canary_bootstrap_admin_role does not match session_user/);
    await adminPool.query(`ALTER DATABASE ${CANARY_DATABASE_NAME} OWNER TO postgres`);
    const insufficientAuthority = await docker([
      "exec",
      containerName,
      "psql",
      "-X",
      "--set",
      "ON_ERROR_STOP=1",
      "--set",
      `canary_bootstrap_admin_role=${creatorUser}`,
      "--username",
      creatorUser,
      "--dbname",
      CANARY_DATABASE_NAME,
      "--file",
      "/tmp/risely-agent-runtime-bootstrap.sql",
    ]);
    assert.notEqual(insufficientAuthority.exitCode, 0);
    assert.match(insufficientAuthority.stderr, /canary_bootstrap_requires_direct_nonsuperuser_createrole_session/);
    await adminPool.query(`GRANT CREATE ON DATABASE ${CANARY_DATABASE_NAME} TO ${creatorUser}`);
    const directCreateNonowner = await docker([
      "exec",
      containerName,
      "psql",
      "-X",
      "--set",
      "ON_ERROR_STOP=1",
      "--set",
      `canary_bootstrap_admin_role=${creatorUser}`,
      "--username",
      creatorUser,
      "--dbname",
      CANARY_DATABASE_NAME,
      "--file",
      "/tmp/risely-agent-runtime-bootstrap.sql",
    ]);
    assert.notEqual(directCreateNonowner.exitCode, 0);
    assert.match(directCreateNonowner.stderr, /canary_bootstrap_requires_exact_database_owner/);
    await adminPool.query(`REVOKE CREATE ON DATABASE ${CANARY_DATABASE_NAME} FROM ${creatorUser}`);
    await adminPool.query(`ALTER DATABASE ${CANARY_DATABASE_NAME} OWNER TO ${creatorUser}`);
    assert.deepEqual(await bootstrapFingerprint(adminPool), emptyFingerprint);
    await adminPool.query(
      `SET ROLE ${creatorUser}; REVOKE CONNECT ON DATABASE ${CANARY_DATABASE_NAME} FROM PUBLIC; RESET ROLE`,
    );
    const incompatiblePublicAcl = await docker([
      "exec",
      containerName,
      "psql",
      "-X",
      "--set",
      "ON_ERROR_STOP=1",
      "--set",
      `canary_bootstrap_admin_role=${creatorUser}`,
      "--username",
      creatorUser,
      "--dbname",
      CANARY_DATABASE_NAME,
      "--file",
      "/tmp/risely-agent-runtime-bootstrap.sql",
    ]);
    assert.notEqual(incompatiblePublicAcl.exitCode, 0);
    assert.match(incompatiblePublicAcl.stderr, /canary_bootstrap_incompatible_public_database_acl/);
    assert.deepEqual(await bootstrapFingerprint(adminPool), emptyFingerprint);
    await adminPool.query(
      `SET ROLE ${creatorUser}; GRANT CONNECT ON DATABASE ${CANARY_DATABASE_NAME} TO PUBLIC; RESET ROLE`,
    );
    await adminPool.query(
      `CREATE SCHEMA bootstrap_escape;
     CREATE TABLE bootstrap_escape.events (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
     CREATE FUNCTION bootstrap_escape.capture_ddl() RETURNS event_trigger
       LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
       AS 'BEGIN INSERT INTO bootstrap_escape.events DEFAULT VALUES; END';
     REVOKE EXECUTE ON FUNCTION bootstrap_escape.capture_ddl() FROM PUBLIC;
     CREATE EVENT TRIGGER bootstrap_escape_enabled
       ON ddl_command_start EXECUTE FUNCTION bootstrap_escape.capture_ddl();
     TRUNCATE bootstrap_escape.events`,
    );
    const eventTriggerRefusal = await docker([
      "exec",
      containerName,
      "psql",
      "-X",
      "--set",
      "ON_ERROR_STOP=1",
      "--set",
      `canary_bootstrap_admin_role=${creatorUser}`,
      "--username",
      creatorUser,
      "--dbname",
      CANARY_DATABASE_NAME,
      "--file",
      "/tmp/risely-agent-runtime-bootstrap.sql",
    ]);
    assert.notEqual(eventTriggerRefusal.exitCode, 0);
    assert.match(eventTriggerRefusal.stderr, /canary_bootstrap_enabled_event_trigger/);
    assert.deepEqual(await bootstrapFingerprint(adminPool), emptyFingerprint);
    assert.equal(
      (await adminPool.query("SELECT count(*)::integer AS count FROM bootstrap_escape.events")).rows[0].count,
      0,
    );
    await adminPool.query("DROP EVENT TRIGGER bootstrap_escape_enabled; DROP SCHEMA bootstrap_escape CASCADE");
    await adminPool.query("CREATE EXTENSION file_fdw; GRANT USAGE ON FOREIGN DATA WRAPPER file_fdw TO PUBLIC");
    const foreignDataWrapperRefusal = await docker([
      "exec",
      containerName,
      "psql",
      "-X",
      "--set",
      "ON_ERROR_STOP=1",
      "--set",
      `canary_bootstrap_admin_role=${creatorUser}`,
      "--username",
      creatorUser,
      "--dbname",
      CANARY_DATABASE_NAME,
      "--file",
      "/tmp/risely-agent-runtime-bootstrap.sql",
    ]);
    assert.notEqual(foreignDataWrapperRefusal.exitCode, 0);
    assert.match(foreignDataWrapperRefusal.stderr, /canary_bootstrap_foreign_data_wrapper_authority/);
    assert.deepEqual(await bootstrapFingerprint(adminPool), emptyFingerprint);
    assert.equal(
      (await adminPool.query("SELECT count(*)::integer AS count FROM pg_catalog.pg_foreign_server")).rows[0].count,
      0,
    );
    await adminPool.query("REVOKE USAGE ON FOREIGN DATA WRAPPER file_fdw FROM PUBLIC; DROP EXTENSION file_fdw");
    await requireDocker([
      "exec",
      containerName,
      "psql",
      "-X",
      "--set",
      "ON_ERROR_STOP=1",
      "--set",
      `canary_bootstrap_admin_role=${creatorUser}`,
      "--username",
      creatorUser,
      "--dbname",
      CANARY_DATABASE_NAME,
      "--file",
      "/tmp/risely-agent-runtime-bootstrap.sql",
    ]);
    assert.doesNotMatch(bootstrap, /\\password|PASSWORD\s+'[^']+'/i);
    const topology = await adminPool.query(
      `SELECT granted_role.rolname AS granted_role,
            member_role.rolname AS member_role,
            grantor_role.rolname AS grantor_role,
            membership.inherit_option,
            membership.set_option,
            membership.admin_option
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
    assert.deepEqual(topology.rows, [
      {
        granted_role: CANARY_EVALUATION_WRITER_DATABASE_USER,
        member_role: creatorUser,
        grantor_role: "postgres",
        inherit_option: false,
        set_option: false,
        admin_option: true,
      },
      {
        granted_role: CANARY_MIGRATION_DATABASE_USER,
        member_role: creatorUser,
        grantor_role: "postgres",
        inherit_option: false,
        set_option: false,
        admin_option: true,
      },
      {
        granted_role: CANARY_OWNER_DATABASE_USER,
        member_role: creatorUser,
        grantor_role: "postgres",
        inherit_option: false,
        set_option: false,
        admin_option: true,
      },
      {
        granted_role: CANARY_OWNER_DATABASE_USER,
        member_role: CANARY_MIGRATION_DATABASE_USER,
        grantor_role: creatorUser,
        inherit_option: false,
        set_option: true,
        admin_option: false,
      },
      {
        granted_role: CANARY_RUNTIME_DATABASE_USER,
        member_role: creatorUser,
        grantor_role: "postgres",
        inherit_option: false,
        set_option: false,
        admin_option: true,
      },
    ]);
    const authority = await adminPool.query(
      `SELECT role_record.rolname,
            role_record.rolcanlogin,
            role_record.rolcreaterole,
            pg_catalog.has_database_privilege(role_record.rolname, pg_catalog.current_database(), 'CREATE') AS database_create
     FROM pg_catalog.pg_roles role_record
     WHERE role_record.rolname = ANY ($1::text[])
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
    assert.deepEqual(
      authority.rows.map((row) => [row.rolname, row.rolcanlogin, row.rolcreaterole, row.database_create]),
      [
        [CANARY_EVALUATION_WRITER_DATABASE_USER, false, false, false],
        [CANARY_MIGRATION_DATABASE_USER, false, false, false],
        [CANARY_OWNER_DATABASE_USER, false, false, false],
        [CANARY_RUNTIME_DATABASE_USER, false, false, false],
      ].sort((left, right) => left[0].localeCompare(right[0])),
    );
    const beforeRerun = await bootstrapFingerprint(adminPool);
    const rerun = await docker([
      "exec",
      containerName,
      "psql",
      "-X",
      "--set",
      "ON_ERROR_STOP=1",
      "--set",
      `canary_bootstrap_admin_role=${creatorUser}`,
      "--username",
      creatorUser,
      "--dbname",
      CANARY_DATABASE_NAME,
      "--file",
      "/tmp/risely-agent-runtime-bootstrap.sql",
    ]);
    assert.notEqual(rerun.exitCode, 0);
    assert.match(rerun.stderr, /canary_bootstrap_fixed_role_preexists/);
    assert.deepEqual(await bootstrapFingerprint(adminPool), beforeRerun);
  },
);
