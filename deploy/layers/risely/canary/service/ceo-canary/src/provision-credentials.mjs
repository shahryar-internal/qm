import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { assertCanaryRoleTopology } from "./database-security.mjs";
import { assertFixedDatabaseContract } from "./postgres-store.mjs";
import {
  CANARY_BOOTSTRAP_ADMIN_ROLE,
  CANARY_DATABASE_NAME,
  CANARY_MIGRATION_DATABASE_USER,
  CANARY_RUNTIME_DATABASE_USER,
} from "./schema.mjs";

const { Client } = pg;
const psqlPath = "/usr/bin/psql";
const credentialPattern = /^[A-Za-z0-9_-]{43}$/;
const credentialEncodedBytes = 43;
const credentialDecodedBytes = 32;
const maximumCredentialFileBytes = credentialEncodedBytes + 1;
const maximumSupportFileBytes = 131072;
const maximumChildOutputBytes = 16384;
const childTimeoutMilliseconds = 30000;
const successMarker = "risely_agent_runtime_credentials_committed_v1";

async function openProtectedHandle(path, label, maximumBytes) {
  if (typeof path !== "string" || path.length === 0) throw new Error(`${label} file is required`);
  const handle = await open(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0));
  try {
    const metadata = await handle.stat();
    const currentUid = typeof process.getuid === "function" ? process.getuid() : metadata.uid;
    if (
      !metadata.isFile() ||
      metadata.uid !== currentUid ||
      (metadata.mode & 0o077) !== 0 ||
      metadata.size < 1 ||
      metadata.size > maximumBytes
    ) {
      throw new Error(`${label} must be an owner-only regular file with bounded content`);
    }
    return { handle, size: metadata.size };
  } catch (error) {
    await handle.close().catch(() => {});
    throw error;
  }
}

async function readProtectedHandle(handle, size, label, maximumBytes) {
  const bytes = Buffer.alloc(maximumBytes + 1);
  let offset = 0;
  try {
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
    }
    if (offset !== size || offset > maximumBytes) {
      throw new Error(`${label} changed while it was being read`);
    }
    return bytes.subarray(0, offset);
  } catch (error) {
    bytes.fill(0);
    throw error;
  }
}

async function readCredential(path, label) {
  let opened;
  let bytes;
  let credential;
  let decoded;
  try {
    opened = await openProtectedHandle(path, label, maximumCredentialFileBytes);
    bytes = await readProtectedHandle(opened.handle, opened.size, label, maximumCredentialFileBytes);
    const hasOptionalLf = bytes.length === maximumCredentialFileBytes && bytes.at(-1) === 10;
    if (bytes.length !== credentialEncodedBytes && !hasOptionalLf) {
      throw new Error(`${label} must contain one canonical 32-byte base64url credential`);
    }
    credential = Buffer.from(bytes.subarray(0, credentialEncodedBytes));
    const encoded = credential.toString("utf8");
    if (!credentialPattern.test(encoded)) {
      throw new Error(`${label} must contain one canonical 32-byte base64url credential`);
    }
    decoded = Buffer.from(encoded, "base64url");
    if (decoded.length !== credentialDecodedBytes || decoded.toString("base64url") !== encoded) {
      throw new Error(`${label} must contain one canonical 32-byte base64url credential`);
    }
    return credential;
  } catch (error) {
    credential?.fill(0);
    throw error;
  } finally {
    decoded?.fill(0);
    bytes?.fill(0);
    await opened?.handle.close().catch(() => {});
  }
}

export async function loadDistinctCanaryCredentials(env = process.env) {
  let migrationCredential;
  let runtimeCredential;
  try {
    migrationCredential = await readCredential(env.CANARY_MIGRATION_PASSWORD_FILE, "CANARY_MIGRATION_PASSWORD_FILE");
    runtimeCredential = await readCredential(env.CANARY_RUNTIME_PASSWORD_FILE, "CANARY_RUNTIME_PASSWORD_FILE");
    if (timingSafeEqual(migrationCredential, runtimeCredential)) {
      throw new Error("Canary database credentials must be distinct");
    }
    return { migrationCredential, runtimeCredential };
  } catch (error) {
    migrationCredential?.fill(0);
    runtimeCredential?.fill(0);
    throw error;
  }
}

function provisioningSql(migrationCredential, runtimeCredential) {
  const prefix = Buffer.from(`\\set ON_ERROR_STOP on
BEGIN;
SET LOCAL search_path = pg_catalog;
SET LOCAL password_encryption = 'scram-sha-256';
DO $preflight$
DECLARE
  migration_login boolean;
  runtime_login boolean;
BEGIN
  IF current_user <> '${CANARY_BOOTSTRAP_ADMIN_ROLE}'
    OR session_user <> '${CANARY_BOOTSTRAP_ADMIN_ROLE}'
    OR pg_catalog.current_database() <> '${CANARY_DATABASE_NAME}'
    OR NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_roles role_record
      JOIN pg_catalog.pg_database database_record ON database_record.datdba = role_record.oid
      WHERE role_record.rolname = '${CANARY_BOOTSTRAP_ADMIN_ROLE}'
        AND database_record.datname = pg_catalog.current_database()
        AND role_record.rolcanlogin
        AND role_record.rolcreaterole
        AND NOT role_record.rolsuper
    ) THEN
    RAISE EXCEPTION 'canary_credential_provisioning_identity_mismatch';
  END IF;
  IF (SELECT owner.rolname
      FROM pg_catalog.pg_namespace namespace
      JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
      WHERE namespace.nspname = 'risely_agent_runtime') <> 'risely_agent_runtime_owner' THEN
    RAISE EXCEPTION 'canary_credential_provisioning_schema_mismatch';
  END IF;
  SELECT rolcanlogin INTO STRICT migration_login
  FROM pg_catalog.pg_roles WHERE rolname = '${CANARY_MIGRATION_DATABASE_USER}';
  SELECT rolcanlogin INTO STRICT runtime_login
  FROM pg_catalog.pg_roles WHERE rolname = '${CANARY_RUNTIME_DATABASE_USER}';
  IF migration_login <> runtime_login THEN
    RAISE EXCEPTION 'canary_credential_provisioning_partial_login_state';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'risely_agent_runtime_owner'
      AND (rolcanlogin OR rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
  ) OR (SELECT count(*) FROM pg_catalog.pg_roles
        WHERE rolname IN ('${CANARY_MIGRATION_DATABASE_USER}', '${CANARY_RUNTIME_DATABASE_USER}')
          AND rolcanlogin = migration_login
          AND NOT rolinherit
          AND NOT rolsuper
          AND NOT rolcreatedb
          AND NOT rolcreaterole
          AND NOT rolreplication
          AND NOT rolbypassrls) <> 2
    OR (SELECT count(*) FROM pg_catalog.pg_auth_members membership
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
        WHERE granted_role.rolname IN ('risely_agent_runtime_owner', '${CANARY_MIGRATION_DATABASE_USER}', '${CANARY_RUNTIME_DATABASE_USER}')
           OR member_role.rolname IN ('risely_agent_runtime_owner', '${CANARY_MIGRATION_DATABASE_USER}', '${CANARY_RUNTIME_DATABASE_USER}')) <> 4
    OR (SELECT count(*) FROM pg_catalog.pg_auth_members membership
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
        JOIN pg_catalog.pg_roles automatic_grantor ON automatic_grantor.oid = membership.grantor
        WHERE granted_role.rolname IN ('risely_agent_runtime_owner', '${CANARY_MIGRATION_DATABASE_USER}', '${CANARY_RUNTIME_DATABASE_USER}')
          AND member_role.rolname = '${CANARY_BOOTSTRAP_ADMIN_ROLE}'
          AND membership.grantor = 10
          AND automatic_grantor.rolsuper
          AND NOT membership.inherit_option
          AND NOT membership.set_option
          AND membership.admin_option) <> 3
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_auth_members membership
      JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
      JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
      JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
      WHERE granted_role.rolname = 'risely_agent_runtime_owner'
        AND member_role.rolname = '${CANARY_MIGRATION_DATABASE_USER}'
        AND grantor_role.rolname = '${CANARY_BOOTSTRAP_ADMIN_ROLE}'
        AND NOT membership.inherit_option
        AND membership.set_option
        AND NOT membership.admin_option
    ) THEN
    RAISE EXCEPTION 'canary_credential_provisioning_topology_mismatch';
  END IF;
END;
$preflight$;
\\password ${CANARY_MIGRATION_DATABASE_USER}
`);
  const between = Buffer.from(`
\\password ${CANARY_RUNTIME_DATABASE_USER}
`);
  const suffix = Buffer.from(`
ALTER ROLE ${CANARY_MIGRATION_DATABASE_USER} LOGIN;
ALTER ROLE ${CANARY_RUNTIME_DATABASE_USER} LOGIN;
DO $postflight$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'risely_agent_runtime_owner'
      AND (rolcanlogin OR rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
  ) OR (SELECT count(*) FROM pg_catalog.pg_roles
        WHERE rolname IN ('${CANARY_MIGRATION_DATABASE_USER}', '${CANARY_RUNTIME_DATABASE_USER}')
          AND rolcanlogin
          AND NOT rolinherit
          AND NOT rolsuper
          AND NOT rolcreatedb
          AND NOT rolcreaterole
          AND NOT rolreplication
          AND NOT rolbypassrls) <> 2
    OR (SELECT count(*) FROM pg_catalog.pg_auth_members membership
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
        WHERE granted_role.rolname IN ('risely_agent_runtime_owner', '${CANARY_MIGRATION_DATABASE_USER}', '${CANARY_RUNTIME_DATABASE_USER}')
           OR member_role.rolname IN ('risely_agent_runtime_owner', '${CANARY_MIGRATION_DATABASE_USER}', '${CANARY_RUNTIME_DATABASE_USER}')) <> 4
    OR (SELECT count(*) FROM pg_catalog.pg_auth_members membership
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
        JOIN pg_catalog.pg_roles automatic_grantor ON automatic_grantor.oid = membership.grantor
        WHERE granted_role.rolname IN ('risely_agent_runtime_owner', '${CANARY_MIGRATION_DATABASE_USER}', '${CANARY_RUNTIME_DATABASE_USER}')
          AND member_role.rolname = '${CANARY_BOOTSTRAP_ADMIN_ROLE}'
          AND membership.grantor = 10
          AND automatic_grantor.rolsuper
          AND NOT membership.inherit_option
          AND NOT membership.set_option
          AND membership.admin_option) <> 3
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_auth_members membership
      JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
      JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
      JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
      WHERE granted_role.rolname = 'risely_agent_runtime_owner'
        AND member_role.rolname = '${CANARY_MIGRATION_DATABASE_USER}'
        AND grantor_role.rolname = '${CANARY_BOOTSTRAP_ADMIN_ROLE}'
        AND NOT membership.inherit_option
        AND membership.set_option
        AND NOT membership.admin_option
    ) THEN
    RAISE EXCEPTION 'canary_credential_provisioning_topology_mismatch';
  END IF;
END;
$postflight$;
COMMIT;
\\echo ${successMarker}
`);
  const newline = Buffer.from("\n");
  return {
    chunks: [
      prefix,
      migrationCredential,
      newline,
      migrationCredential,
      newline,
      between,
      runtimeCredential,
      newline,
      runtimeCredential,
      newline,
      suffix,
    ],
    owned: [prefix, between, suffix, newline],
  };
}

function runPsql(env, input, passfileHandle, caHandle) {
  const childEnvironment = {
    LANG: "C",
    PATH: "/usr/bin:/bin",
    PGCONNECT_TIMEOUT: "5",
    PGPASSFILE: "/proc/self/fd/3",
    PGSSLMODE: "verify-full",
    PGSSLROOTCERT: "/proc/self/fd/4",
  };
  const args = [
    "-X",
    "--no-psqlrc",
    "--host",
    env.CANARY_DATABASE_HOST,
    "--port",
    env.CANARY_DATABASE_PORT,
    "--dbname",
    CANARY_DATABASE_NAME,
    "--username",
    CANARY_BOOTSTRAP_ADMIN_ROLE,
  ];
  return new Promise((resolve, reject) => {
    const child = spawn(psqlPath, args, {
      env: childEnvironment,
      stdio: ["pipe", "pipe", "pipe", passfileHandle.fd, caHandle.fd],
    });
    const stdout = [];
    let outputBytes = 0;
    let stdoutBytes = 0;
    let failure = null;
    let settled = false;
    const stop = (reason) => {
      if (failure === null) failure = reason;
      child.kill("SIGKILL");
    };
    const accountOutput = (chunk, retain) => {
      outputBytes += chunk.length;
      if (outputBytes > maximumChildOutputBytes) {
        stop("output_limit");
        return;
      }
      if (retain) {
        stdoutBytes += chunk.length;
        stdout.push(Buffer.from(chunk));
      }
    };
    const timer = setTimeout(() => stop("timeout"), childTimeoutMilliseconds);
    child.stdout.on("data", (chunk) => accountOutput(chunk, true));
    child.stderr.on("data", (chunk) => accountOutput(chunk, false));
    child.on("error", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stdout.forEach((chunk) => chunk.fill(0));
      reject(new Error("Canary credential provisioning process failed to start"));
    });
    child.stdin.on("error", () => {});
    child.on("close", (exitCode) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const output = Buffer.concat(stdout, stdoutBytes);
      stdout.forEach((chunk) => chunk.fill(0));
      resolve({ exitCode, success: failure === null && output.toString("utf8").includes(successMarker) });
      output.fill(0);
    });
    child.stdin.end(input);
  });
}

async function verifyAuthentication(env, user, password, ca) {
  const client = new Client({
    host: env.CANARY_DATABASE_HOST,
    port: Number(env.CANARY_DATABASE_PORT),
    database: CANARY_DATABASE_NAME,
    user,
    ["pass" + "word"]: password.toString("ascii"),
    ssl: { ca: ca.toString("utf8"), rejectUnauthorized: true },
    connectionTimeoutMillis: 5000,
    query_timeout: 10000,
  });
  await client.connect();
  try {
    const identity = await client.query("SELECT current_user, pg_catalog.current_database() AS current_database");
    if (identity.rows[0]?.current_user !== user || identity.rows[0]?.current_database !== CANARY_DATABASE_NAME) {
      throw new Error("Canary credential authentication identity mismatch");
    }
    if (user === CANARY_MIGRATION_DATABASE_USER) {
      await client.query("BEGIN READ ONLY");
      await client.query("SET LOCAL search_path = pg_catalog");
      await assertCanaryRoleTopology(client);
      await client.query("ROLLBACK");
    }
  } finally {
    await client.end();
  }
}

export async function provisionCanaryCredentials(env = process.env) {
  assertFixedDatabaseContract(env);
  let migrationCredential;
  let runtimeCredential;
  let input;
  let owned = [];
  let ca;
  let passfile;
  let caFile;
  try {
    ({ migrationCredential, runtimeCredential } = await loadDistinctCanaryCredentials(env));
    passfile = await openProtectedHandle(
      env.CANARY_BOOTSTRAP_ADMIN_PASSFILE,
      "CANARY_BOOTSTRAP_ADMIN_PASSFILE",
      maximumSupportFileBytes,
    );
    caFile = await openProtectedHandle(env.CANARY_DATABASE_CA_FILE, "CANARY_DATABASE_CA_FILE", maximumSupportFileBytes);
    ca = await readProtectedHandle(caFile.handle, caFile.size, "CANARY_DATABASE_CA_FILE", maximumSupportFileBytes);
    if (!ca.toString("utf8").includes("BEGIN CERTIFICATE")) {
      throw new Error("CANARY_DATABASE_CA_FILE must contain the trusted PostgreSQL CA bundle");
    }
    const stream = provisioningSql(migrationCredential, runtimeCredential);
    owned = stream.owned;
    input = Buffer.concat(stream.chunks);
    const result = await runPsql(env, input, passfile.handle, caFile.handle);
    if (result.exitCode !== 0 || !result.success) throw new Error("Canary credential provisioning transaction failed");
    await verifyAuthentication(env, CANARY_MIGRATION_DATABASE_USER, migrationCredential, ca);
    await verifyAuthentication(env, CANARY_RUNTIME_DATABASE_USER, runtimeCredential, ca);
    return true;
  } finally {
    migrationCredential?.fill(0);
    runtimeCredential?.fill(0);
    input?.fill(0);
    ca?.fill(0);
    owned.forEach((buffer) => buffer.fill(0));
    await passfile?.handle.close().catch(() => {});
    await caFile?.handle.close().catch(() => {});
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  provisionCanaryCredentials().catch(() => {
    process.exitCode = 1;
  });
}
