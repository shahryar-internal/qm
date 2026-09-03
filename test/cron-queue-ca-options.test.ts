import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mock, test } from "node:test";
import { configurePgCaTrust } from "../src/persistence/pg-pool.ts";

const constructed: unknown[] = [];

class FakePgBoss {
  constructor(options: unknown) {
    constructed.push(options);
  }

  on(): void {}
}

mock.module("pg-boss", { namedExports: { PgBoss: FakePgBoss } });

const { createPgBossCronQueue } = await import("../src/cron/job-queue.ts");

test("the cron queue source has one verified CA propagation seam and no insecure TLS override", () => {
  const source = readFileSync(new URL("../src/cron/job-queue.ts", import.meta.url), "utf8");
  assert.match(source, /new PgBoss\(\{ connectionString: databaseUrl, \.\.\.pgCaOptions\(\), schema, max: 5 \}\)/);
  assert.doesNotMatch(source, /rejectUnauthorized\s*:\s*false|sslmode=(?:disable|no-verify)/i);
});

test("the cron queue passes configured CA trust to pg-boss", () => {
  const ca = "-----BEGIN CERTIFICATE-----\nverified-root\n-----END CERTIFICATE-----\n";
  configurePgCaTrust({ cert: ca });
  createPgBossCronQueue("postgresql://database.invalid/qm", "pgboss_test", 3);
  assert.deepEqual(constructed.pop(), {
    connectionString: "postgresql://database.invalid/qm",
    ssl: { ca },
    schema: "pgboss_test",
    max: 5,
  });
});

test("the cron queue leaves connection-string TLS semantics untouched without configured CA trust", () => {
  configurePgCaTrust({});
  createPgBossCronQueue("postgresql://database.invalid/qm", "pgboss_test");
  assert.deepEqual(constructed.pop(), {
    connectionString: "postgresql://database.invalid/qm",
    schema: "pgboss_test",
    max: 5,
  });
});
