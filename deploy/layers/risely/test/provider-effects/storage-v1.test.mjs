import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  PROVIDER_EFFECT_AUTHORITY_MIGRATION_SHA256,
  PROVIDER_EFFECT_AUTHORITY_SCHEMA,
  PROVIDER_EFFECT_AUTHORITY_SCHEMA_VERSION,
  providerEffectAuthoritySchemaSql,
} from "../../canary/provider-effects/storage-v1/schema.mjs";
import { inspectProviderEffectProductionReadiness } from "../../canary/provider-effects/authority.mjs";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";

const layer = new URL("../../", import.meta.url);
const storeSource = readFileSync(new URL("canary/provider-effects/storage-v1/store.mjs", layer), "utf8");
const authoritySource = readFileSync(new URL("canary/provider-effects/authority.mjs", layer), "utf8");
const runtimeDockerfile = readFileSync(new URL("canary/service/ceo-canary/Dockerfile.runtime", layer), "utf8");

test("future provider-effect storage is isolated from the active version-eight schema and authority", () => {
  const sql = providerEffectAuthoritySchemaSql();
  const readiness = inspectProviderEffectProductionReadiness(createRuntimeScope(ceoDeploymentProfile));
  assert.equal(PROVIDER_EFFECT_AUTHORITY_SCHEMA, "risely_provider_effect_authority_future_v1");
  assert.equal(PROVIDER_EFFECT_AUTHORITY_SCHEMA_VERSION, 1);
  assert.match(PROVIDER_EFFECT_AUTHORITY_MIGRATION_SHA256, /^[0-9a-f]{64}$/u);
  assert.doesNotMatch(sql, /risely_agent_runtime\./u);
  assert.doesNotMatch(authoritySource, /storage-v1/u);
  assert.match(runtimeDockerfile, /COPY .*provider-effects\/index\.mjs/u);
  assert.doesNotMatch(runtimeDockerfile, /provider-effects\/storage-v1/u);
  assert.equal(readiness.constructionAvailable, false);
  assert.equal(readiness.providerInvocationAllowed, false);
  assert.equal(ceoDeploymentProfile.providerExecutionAllowed, false);
});

test("future schema is one-shot, append-only, proof-linked, and fail-closed", () => {
  const sql = providerEffectAuthoritySchemaSql();
  assert.match(sql, new RegExp(`CREATE SCHEMA ${PROVIDER_EFFECT_AUTHORITY_SCHEMA};`, "u"));
  assert.doesNotMatch(sql, /CREATE SCHEMA IF NOT EXISTS/u);
  assert.match(sql, /provider_execution_allowed boolean NOT NULL CHECK \(provider_execution_allowed = false\)/u);
  assert.match(sql, /provider_release_eligible boolean NOT NULL CHECK \(provider_release_eligible\)/u);
  assert.match(sql, /attempt_number integer NOT NULL CHECK \(attempt_number = 1\)/u);
  assert.match(sql, /UNIQUE \(profile_ref, profile_sha256, prospective_effect_key\)/u);
  assert.match(sql, /approval_consumptions/u);
  assert.match(sql, /status IN \('verified', 'failed', 'outcome_unknown'\)/u);
  assert.match(sql, /mode = 'read_only_status_lookup'/u);
  assert.match(sql, /provider_effect_authority_append_only/u);
  assert.match(sql, /REVOKE ALL ON SCHEMA .* FROM PUBLIC/u);
  assert.equal((sql.match(/BEFORE UPDATE OR DELETE/gu) ?? []).length, 14);
});

test("store exposes no adapter, provider credential, or network construction surface", () => {
  assert.doesNotMatch(storeSource, /fetch\(|https?:\/\//u);
  assert.doesNotMatch(
    storeSource,
    /DATABASE_URL|GOOGLE_CLIENT_SECRET|SLACK_BOT_TOKEN|access[_-]?token|refresh[_-]?token/iu,
  );
  assert.doesNotMatch(storeSource, /effectAdapters|\.invoke\(/u);
  assert.match(storeSource, /attempts !== 0/u);
  assert.match(storeSource, /provider_kill_switch_changed_after_reservation/u);
  assert.match(storeSource, /provider_attempt_lease_expired/u);
  assert.match(storeSource, /read_only_status_lookup/u);
  assert.match(storeSource, /receiptAuthority/u);
});
