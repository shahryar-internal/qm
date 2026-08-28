import {
  CANARY_BOOTSTRAP_ADMIN_ROLE,
  CANARY_DATABASE_NAME,
  CANARY_EVALUATION_WRITER_DATABASE_USER,
  CANARY_MIGRATION_DATABASE_USER,
  CANARY_OWNER_DATABASE_USER,
  CANARY_RUNTIME_DATABASE_USER,
  CANARY_SCHEMA_NAME,
} from "./schema.mjs";

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
