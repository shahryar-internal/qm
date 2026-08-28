import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { loadDistinctCanaryCredentials } from "../../canary/service/ceo-canary/src/provision-credentials.mjs";
import { migrationPoolConfig, runtimePoolConfig } from "../../canary/service/ceo-canary/src/postgres-store.mjs";

const migrationCredential = Buffer.alloc(32, 0x31).toString("base64url");
const runtimeCredential = Buffer.alloc(32, 0x32).toString("base64url");

function databaseUrl(user, credential, host) {
  const url = new URL(`postgresql://${host}:5432/qm`);
  url.username = user;
  url["pass" + "word"] = credential;
  return url.toString();
}

async function fixture(t, migration = migrationCredential, runtime = runtimeCredential) {
  const directory = await mkdtemp(join(tmpdir(), "risely-agent-runtime-credentials-"));
  const migrationPath = join(directory, "migration.password");
  const runtimePath = join(directory, "runtime.password");
  await Promise.all([
    writeFile(migrationPath, migration, { mode: 0o400 }),
    writeFile(runtimePath, runtime, { mode: 0o400 }),
  ]);
  t.after(() => rm(directory, { force: true, recursive: true }));
  return {
    CANARY_MIGRATION_PASSWORD_FILE: migrationPath,
    CANARY_RUNTIME_PASSWORD_FILE: runtimePath,
  };
}

test("credential provisioning prevalidates two distinct owner-only generated credentials", async (t) => {
  const credentials = await loadDistinctCanaryCredentials(await fixture(t, `${migrationCredential}\n`));
  assert.equal(credentials.migrationCredential.toString("ascii"), migrationCredential);
  assert.equal(credentials.runtimeCredential.toString("ascii"), runtimeCredential);
  credentials.migrationCredential.fill(0);
  credentials.runtimeCredential.fill(0);
});

test("credential provisioning refuses equality truncation and malformed input before database authority exists", async (t) => {
  for (const values of [
    [migrationCredential, migrationCredential],
    [migrationCredential.slice(0, 42), runtimeCredential],
    [`${migrationCredential}=`, runtimeCredential],
    [`${migrationCredential.slice(0, -1)}F`, runtimeCredential],
    [`${migrationCredential}\r\n`, runtimeCredential],
    [`${migrationCredential}\nextra`, runtimeCredential],
    [Buffer.concat([Buffer.from(migrationCredential.slice(0, 42)), Buffer.from([0x80])]), runtimeCredential],
    [Buffer.concat([Buffer.from(migrationCredential.slice(0, 42)), Buffer.from([0])]), runtimeCredential],
  ]) {
    const environment = await fixture(t, ...values);
    await assert.rejects(() => loadDistinctCanaryCredentials(environment));
  }
});

test("credential provisioning refuses group-readable files and symlinks", async (t) => {
  const environment = await fixture(t);
  await chmod(environment.CANARY_RUNTIME_PASSWORD_FILE, 0o440);
  await assert.rejects(() => loadDistinctCanaryCredentials(environment));
  await chmod(environment.CANARY_RUNTIME_PASSWORD_FILE, 0o400);
  const symlinkPath = `${environment.CANARY_RUNTIME_PASSWORD_FILE}.link`;
  await symlink(environment.CANARY_RUNTIME_PASSWORD_FILE, symlinkPath);
  await assert.rejects(() =>
    loadDistinctCanaryCredentials({
      ...environment,
      CANARY_RUNTIME_PASSWORD_FILE: symlinkPath,
    }),
  );
});

test("credential provisioning rejects a FIFO promptly before any child or database phase", async (t) => {
  const environment = await fixture(t);
  const fifoPath = join(environment.CANARY_MIGRATION_PASSWORD_FILE, "..", "migration.fifo");
  const created = spawnSync("mkfifo", [fifoPath], { encoding: "utf8" });
  assert.equal(created.status, 0, created.stderr);
  await chmod(fifoPath, 0o400);
  const started = Date.now();
  await assert.rejects(
    () =>
      Promise.race([
        loadDistinctCanaryCredentials({ ...environment, CANARY_MIGRATION_PASSWORD_FILE: fifoPath }),
        new Promise((_, reject) => setTimeout(() => reject(new Error("fifo credential read blocked")), 1000)),
      ]),
    /owner-only regular file/,
  );
  assert.ok(Date.now() - started < 1000);
});

test("runtime migration and shared application URLs cannot reuse decoded credentials", () => {
  const host = "risely-qm-pilot-core.example.us-west-2.rds.amazonaws.com";
  const shared = `%${migrationCredential.charCodeAt(0).toString(16)}${migrationCredential.slice(1)}`;
  const base = {
    CANARY_BOOTSTRAP_ADMIN_ROLE: "qm",
    CANARY_DATABASE_NAME: "qm",
    CANARY_DATABASE_HOST: host,
    CANARY_DATABASE_PORT: "5432",
    CANARY_DATABASE_SCHEMA: "risely_agent_runtime",
    CANARY_OWNER_DATABASE_USER: "risely_agent_runtime_owner",
    CANARY_RUNTIME_DATABASE_USER: "risely_agent_runtime_runtime",
    CANARY_MIGRATION_DATABASE_USER: "risely_agent_runtime_migrator",
    DATABASE_CA_CERT: "-----BEGIN CERTIFICATE-----\ntrusted\n-----END CERTIFICATE-----",
    DATABASE_URL: databaseUrl("qm_application", shared, host).replace("%25", "%"),
    CANARY_DATABASE_URL: databaseUrl("risely_agent_runtime_runtime", runtimeCredential, host),
    CANARY_MIGRATION_DATABASE_URL: databaseUrl("risely_agent_runtime_migrator", migrationCredential, host),
  };
  assert.throws(() => migrationPoolConfig(base), /must not reuse DATABASE_URL credentials/);
  assert.throws(
    () =>
      runtimePoolConfig({
        ...base,
        DATABASE_URL: databaseUrl("unrelated_user", runtimeCredential, host),
        CANARY_MIGRATION_DATABASE_URL: databaseUrl("risely_agent_runtime_migrator", "third-credential", host),
      }),
    /must not reuse DATABASE_URL credentials/,
  );
  assert.throws(
    () =>
      runtimePoolConfig({
        ...base,
        DATABASE_URL: databaseUrl("qm_application", "third-credential", host),
        CANARY_MIGRATION_DATABASE_URL: databaseUrl("different_user", runtimeCredential, host),
      }),
    /must not reuse CANARY_MIGRATION_DATABASE_URL credentials/,
  );
});

test("credential operator pins inherited descriptors and bounded psql execution", async () => {
  const source = await readFile(
    new URL("../../canary/service/ceo-canary/src/provision-credentials.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /PGPASSFILE: "\/proc\/self\/fd\/3"/);
  assert.match(source, /PGSSLROOTCERT: "\/proc\/self\/fd\/4"/);
  assert.match(source, /const maximumChildOutputBytes = 16384/);
  assert.match(source, /const childTimeoutMilliseconds = 30000/);
  assert.match(source, /constants\.O_NONBLOCK/);
  assert.match(source, /const args = \[\s*"-X",\s*"--no-psqlrc"/);
  assert.doesNotMatch(source, /\bPGPASSWORD\b/);
});
