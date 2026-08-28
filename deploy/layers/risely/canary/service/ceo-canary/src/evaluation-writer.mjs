import pg from "pg";
import { PrincipalBinding } from "../../../shared-contracts/index.mjs";
import { assertRuntimeScope, productionRuntimeScopeFromEnv } from "../../../runtime-scope/index.mjs";
import { assertAuthorizedEvaluationDecision } from "../../../evals/index.mjs";
import { bindPostgresEvaluationResultStore } from "../../../evals/result-store.mjs";
import {
  CANARY_DATABASE_NAME,
  CANARY_EVALUATION_WRITER_DATABASE_USER,
  CANARY_MAINTENANCE_LOCK_KEY,
  CANARY_SCHEMA_NAME,
  EXPECTED_CATALOG_AUTHORITY_SHA256,
  SCHEMA_VERSION,
  migrationChecksum,
} from "./schema.mjs";
import { assertEvaluationWriterDatabaseBoundary, assertExactCanaryCatalog } from "./database-security.mjs";
import { evaluationWriterPoolConfig } from "./postgres-store.mjs";

const { Pool } = pg;
const hash = PrincipalBinding.hash;
const snapshot = PrincipalBinding.snapshot;
const digestPattern = /^[0-9a-f]{64}$/u;
const activeWriters = new WeakSet();
const portsByWriter = new WeakMap();
const expectedMigrationChecksum = migrationChecksum();

export class EvaluationWriterError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "EvaluationWriterError";
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new EvaluationWriterError(code, message);
};

export class PostgresEvaluationWriter {
  #initialized = false;
  #pool;

  constructor(options = {}) {
    if (Object.keys(options).some((name) => !["pool", "scope"].includes(name))) {
      throw new TypeError("Evaluation writer database security settings cannot be supplied by a caller");
    }
    const { pool, scope: scopeValue } = options;
    if (!pool || typeof pool.connect !== "function" || typeof pool.query !== "function") {
      throw new TypeError("PostgresEvaluationWriter requires a PostgreSQL pool");
    }
    const scope = assertRuntimeScope(scopeValue);
    this.#pool = pool;
    Object.defineProperties(this, {
      schema: { value: CANARY_SCHEMA_NAME, enumerable: true },
      runtimeScope: { value: scope, enumerable: false },
    });
    Object.preventExtensions(this);
  }

  static fromEnv(env = process.env, runtimeScope = productionRuntimeScopeFromEnv(env)) {
    return new PostgresEvaluationWriter({
      pool: new Pool(evaluationWriterPoolConfig(env)),
      scope: assertRuntimeScope(runtimeScope),
    });
  }

  async initialize() {
    if (this.#initialized) return true;
    await this.#verifySchema();
    this.#initialized = true;
    activeWriters.add(this);
    return true;
  }

  async #verifySchema() {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN READ ONLY");
      await client.query("SET LOCAL search_path = pg_catalog");
      await client.query("SET LOCAL statement_timeout = '10s'");
      await assertEvaluationWriterDatabaseBoundary(client);
      await assertExactCanaryCatalog(client);
      const stored = await client.query(
        `SELECT profile FROM ${this.schema}.deployment_profiles
         WHERE profile_ref = $1 AND profile_sha256 = $2`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256],
      );
      if (stored.rows.length !== 1 || hash(stored.rows[0].profile) !== hash(this.runtimeScope.profile)) {
        fail("schema_unhealthy", "Evaluation writer profile authority is not registered");
      }
      await client.query("COMMIT");
      return true;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      if (error instanceof EvaluationWriterError) throw error;
      fail("schema_unhealthy", "Evaluation writer readiness verification failed");
    } finally {
      client.release();
    }
  }

  async health() {
    this.#assertInitialized();
    return this.#verifySchema();
  }

  async close() {
    activeWriters.delete(this);
    portsByWriter.delete(this);
    this.#initialized = false;
    await this.#pool.end();
  }

  #assertInitialized() {
    if (!this.#initialized || !activeWriters.has(this)) {
      fail("not_initialized", "Evaluation writer requires immutable database readiness");
    }
  }

  async #verifySentinel(client) {
    const result = await client.query(
      `SELECT current_user,
              current_database(),
              pg_catalog.to_regnamespace($1)::text AS schema_name,
              migration.version,
              migration.checksum,
              migration.catalog_authority_sha256,
              profile.profile,
              pg_catalog.has_table_privilege(current_user, pg_catalog.format('%I.evaluation_candidates', $1), 'INSERT') AS candidate_insert,
              pg_catalog.has_table_privilege(current_user, pg_catalog.format('%I.evaluation_judge_results', $1), 'INSERT') AS judge_insert,
              pg_catalog.has_table_privilege(current_user, pg_catalog.format('%I.evaluation_releases', $1), 'INSERT') AS release_insert,
              pg_catalog.has_function_privilege(current_user, pg_catalog.format('%I.persist_authorized_evaluation(text, character, character, jsonb, jsonb, text, jsonb)', $1), 'EXECUTE') AS persist_execute
       FROM ${this.schema}.schema_migrations migration
       LEFT JOIN ${this.schema}.deployment_profiles profile
         ON profile.profile_ref = $2 AND profile.profile_sha256 = $3
       WHERE migration.version = $4`,
      [this.schema, this.runtimeScope.profileRef, this.runtimeScope.profileSha256, SCHEMA_VERSION],
    );
    const row = result.rows[0];
    if (
      result.rows.length !== 1 ||
      row.current_user !== CANARY_EVALUATION_WRITER_DATABASE_USER ||
      row.current_database !== CANARY_DATABASE_NAME ||
      row.schema_name !== this.schema ||
      row.version !== SCHEMA_VERSION ||
      row.checksum !== expectedMigrationChecksum ||
      row.catalog_authority_sha256 !== EXPECTED_CATALOG_AUTHORITY_SHA256 ||
      row.candidate_insert ||
      row.judge_insert ||
      row.release_insert ||
      row.persist_execute !== true ||
      hash(row.profile) !== hash(this.runtimeScope.profile)
    ) {
      fail("schema_unhealthy", "Evaluation writer database sentinel drift detected");
    }
  }

  async #transaction(operation, entityRef) {
    this.#assertInitialized();
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL search_path = pg_catalog");
      await client.query("SET LOCAL statement_timeout = '10s'");
      await client.query("SELECT pg_advisory_xact_lock_shared(hashtext($1))", [CANARY_MAINTENANCE_LOCK_KEY]);
      await this.#verifySentinel(client);
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))", [
        `${this.runtimeScope.profileRef}:${this.runtimeScope.profileSha256}`,
        entityRef,
      ]);
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

  evaluationResultStore() {
    this.#assertInitialized();
    const existing = portsByWriter.get(this);
    if (existing) return existing;
    const port = Object.freeze({
      durability: "postgres_append_only",
      profileRef: this.runtimeScope.profileRef,
      profileSha256: this.runtimeScope.profileSha256,
      persistAuthorityEvaluation: (value) => this.#persistEvaluation(value),
      appendReplayTombstone: (value) => this.#appendReplayTombstone(value),
      readRelease: (releaseId) => this.#readRelease(releaseId),
    });
    bindPostgresEvaluationResultStore(port, this.runtimeScope, () => activeWriters.has(this));
    portsByWriter.set(this, port);
    return port;
  }

  #persistEvaluation = async (value) => {
    this.#assertInitialized();
    const input = assertAuthorizedEvaluationDecision(value, this.runtimeScope, this.evaluationResultStore());
    const candidate = input.candidate;
    if (
      candidate?.deploymentProfileRef !== this.runtimeScope.profileRef ||
      candidate?.deploymentProfileSha256 !== this.runtimeScope.profileSha256 ||
      typeof candidate.runRef !== "string" ||
      !digestPattern.test(candidate.artifactSha256) ||
      !digestPattern.test(candidate.evaluationProfileSha256) ||
      !digestPattern.test(candidate.policySha256)
    ) {
      fail("invalid_evaluation_candidate", "Evaluation candidate does not match writer scope");
    }
    this.runtimeScope.contracts.WorkflowArtifact.validate(candidate.artifact);
    const candidateSha256 = hash({
      digestRevision: "EvaluationCandidate.store.sha256.v1",
      profileRef: this.runtimeScope.profileRef,
      profileSha256: this.runtimeScope.profileSha256,
      candidate,
    });
    const judgeResults = input.judgeResults;
    const release = this.runtimeScope.contracts.EvalRelease.validate(input.release, candidate.artifact);
    const releaseId = `evaluation-release:${release.releaseSha256}`;
    return this.#transaction(async (client) => {
      await client.query(
        `SELECT ${this.schema}.persist_authorized_evaluation(
           $1::text, $2::character(64), $3::character(64), $4::jsonb, $5::jsonb, $6::text, $7::jsonb
         )`,
        [
          this.runtimeScope.profileRef,
          this.runtimeScope.profileSha256,
          candidateSha256,
          JSON.stringify(candidate),
          JSON.stringify(judgeResults),
          releaseId,
          JSON.stringify(release),
        ],
      );
      const storedCandidate = await client.query(
        `SELECT candidate_sha256, candidate, policy_snapshot FROM ${this.schema}.evaluation_candidates
         WHERE profile_ref = $1 AND profile_sha256 = $2 AND candidate_id = $3`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, candidate.runRef],
      );
      if (
        storedCandidate.rows.length !== 1 ||
        storedCandidate.rows[0].candidate_sha256 !== candidateSha256 ||
        hash(storedCandidate.rows[0].candidate) !== hash(candidate) ||
        hash(storedCandidate.rows[0].policy_snapshot) !== hash(input.policySnapshot)
      ) {
        fail("evaluation_candidate_conflict", "Evaluation candidate identity conflicts within writer scope");
      }
      for (const result of judgeResults) {
        const resultId = `evaluation-judge-result:${result.receiptSha256}`;
        const storedResult = await client.query(
          `SELECT candidate_id, result_sha256, receipt_sha256, result FROM ${this.schema}.evaluation_judge_results
           WHERE profile_ref = $1 AND profile_sha256 = $2 AND result_id = $3`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, resultId],
        );
        if (
          storedResult.rows.length !== 1 ||
          storedResult.rows[0].candidate_id !== candidate.runRef ||
          storedResult.rows[0].result_sha256 !== result.receiptSha256 ||
          storedResult.rows[0].receipt_sha256 !== result.receiptSha256 ||
          hash(storedResult.rows[0].result) !== hash(result)
        ) {
          fail("evaluation_judge_result_conflict", "Evaluation judge result conflicts within writer scope");
        }
      }
      const storedRelease = await client.query(
        `SELECT candidate_id, release_sha256, release_record, policy_snapshot FROM ${this.schema}.evaluation_releases
         WHERE profile_ref = $1 AND profile_sha256 = $2 AND release_id = $3`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, releaseId],
      );
      if (
        storedRelease.rows.length !== 1 ||
        storedRelease.rows[0].candidate_id !== candidate.runRef ||
        storedRelease.rows[0].release_sha256 !== release.releaseSha256 ||
        hash(storedRelease.rows[0].release_record) !== hash(release) ||
        hash(storedRelease.rows[0].policy_snapshot) !== hash(input.policySnapshot)
      ) {
        fail("evaluation_release_conflict", "Evaluation release conflicts within writer scope");
      }
      const links = await client.query(
        `SELECT result_id, receipt_sha256 FROM ${this.schema}.evaluation_release_judge_results
         WHERE profile_ref = $1 AND profile_sha256 = $2 AND release_id = $3 AND candidate_id = $4
         ORDER BY result_id`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, releaseId, candidate.runRef],
      );
      const expectedLinks = judgeResults
        .map((result) => ({
          result_id: `evaluation-judge-result:${result.receiptSha256}`,
          receipt_sha256: result.receiptSha256,
        }))
        .sort((left, right) => left.result_id.localeCompare(right.result_id));
      if (hash(links.rows) !== hash(expectedLinks)) {
        fail("evaluation_release_linkage_conflict", "Evaluation release judge linkage conflicts within writer scope");
      }
      return { candidateId: candidate.runRef, candidateSha256, releaseId, release };
    }, `evaluation:${candidate.runRef}`);
  };

  #appendReplayTombstone = async (value) => {
    const input = snapshot(value, "evaluation replay tombstone");
    if (
      !input ||
      Object.keys(input).sort().join("\n") !== "releaseId\nreplayRef\nterminalRecord" ||
      typeof input.releaseId !== "string" ||
      typeof input.replayRef !== "string"
    ) {
      fail("invalid_evaluation_replay_tombstone", "Evaluation replay tombstone is invalid");
    }
    const release = await this.#readRelease(input.releaseId);
    if (!release) fail("evaluation_release_not_found", "Evaluation release was not found");
    const recordSha256 = hash({
      digestRevision: "EvaluationReplayTombstone.store.sha256.v1",
      profileRef: this.runtimeScope.profileRef,
      profileSha256: this.runtimeScope.profileSha256,
      replayRef: input.replayRef,
      releaseId: input.releaseId,
      terminalRecord: input.terminalRecord,
    });
    return this.#transaction(async (client) => {
      const result = await client.query(
        `INSERT INTO ${this.schema}.evaluation_replay_tombstones
           (profile_ref, profile_sha256, replay_ref, release_id, release_sha256, record_sha256, terminal_record)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
         ON CONFLICT (profile_ref, profile_sha256, replay_ref) DO NOTHING
         RETURNING replay_ref`,
        [
          this.runtimeScope.profileRef,
          this.runtimeScope.profileSha256,
          input.replayRef,
          input.releaseId,
          release.releaseSha256,
          recordSha256,
          JSON.stringify(input.terminalRecord),
        ],
      );
      if (result.rowCount !== 1) fail("evaluation_replay_retired", "Evaluation replay identity is retired");
      return { replayRef: input.replayRef, recordSha256 };
    }, `evaluation-replay:${input.replayRef}`);
  };

  #readRelease = async (releaseId) => {
    if (typeof releaseId !== "string") fail("invalid_evaluation_release", "Evaluation release identifier is invalid");
    return this.#transaction(async (client) => {
      const result = await client.query(
        `SELECT release_record FROM ${this.schema}.evaluation_releases
         WHERE profile_ref = $1 AND profile_sha256 = $2 AND release_id = $3`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, releaseId],
      );
      return result.rows[0]?.release_record ?? null;
    }, `evaluation-release:${releaseId}`);
  };
}
