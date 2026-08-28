import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  ActivationGateError,
  bundledManifestSha256,
  evaluateActivationGates,
} from "../../canary/activation-gates/index.mjs";
import * as evaluatorModule from "../../canary/activation-gates/evaluator.mjs";
import { evaluateClosedManifest } from "../../canary/activation-gates/evaluator.mjs";
import { parseStrictJson, StrictJsonError } from "../../canary/activation-gates/strict-json.mjs";

const layerRoot = fileURLToPath(new URL("../..", import.meta.url));
const sourceRoot = resolve(layerRoot, "canary/activation-gates");
const manifestPath = resolve(sourceRoot, "manifest.json");
const manifestText = await readFile(manifestPath, "utf8");
const manifest = parseStrictJson(manifestText);
const fixedManifestSegments = Object.freeze(["canary", "activation-gates", "manifest.json"]);
const hash = (value) => createHash("sha256").update(value).digest("hex");
const encode = (value) => `${JSON.stringify(value, null, 2)}\n`;
const clone = () => structuredClone(manifest);
const importAllowlists = Object.freeze({
  "evaluator.mjs": Object.freeze([
    "node:crypto",
    "node:fs",
    "node:fs/promises",
    "node:path",
    "node:url",
    "./strict-json.mjs",
  ]),
  "index.mjs": Object.freeze(["./evaluator.mjs"]),
  "strict-json.mjs": Object.freeze([]),
});
const sourceDigests = Object.freeze({
  "evaluator.mjs": "986d0fff29bb51510ecf58be5abf5fc98e7d67adf946fb437ac6c095bb7b6631",
  "index.mjs": "fc89263b5c110dad1ec7488248d09d2c7bfe64b993f6ab1ba395360b102017f9",
  "strict-json.mjs": "512e6a35c325633fe3e274a600b886651a252764e0f192ebe4ac6b7556e4c21a",
});
const identifierStart = /[A-Za-z_$]/u;
const identifierPart = /[A-Za-z0-9_$]/u;
const forbiddenIdentifiers = new Set([
  "Function",
  "EventSource",
  "WebSocket",
  "XMLHttpRequest",
  "child_process",
  "eval",
  "exec",
  "execSync",
  "fetch",
  "fork",
  "getBuiltinModule",
  "globalThis",
  "module",
  "process",
  "require",
  "sendBeacon",
  "spawn",
  "spawnSync",
]);
const forbiddenStringFragments = ["child_process", "getBuiltinModule", "node:child_process", "process.env"];
const forbiddenStringWord =
  /(?:^|[^A-Za-z0-9_$])(?:Function|constructor|eval|fetch|globalThis|require)(?:$|[^A-Za-z0-9_$])/u;

const sourceTokens = (source) => {
  const tokens = [];
  let offset = 0;
  while (offset < source.length) {
    const character = source[offset];
    if (/\s/u.test(character)) {
      offset += 1;
      continue;
    }
    if (character === "/" && source[offset + 1] === "/") assert.fail("source_comments_forbidden");
    if (character === "/" && source[offset + 1] === "*") assert.fail("source_comments_forbidden");
    if (character === "/") {
      let value = "/";
      let characterClass = false;
      let closed = false;
      offset += 1;
      while (offset < source.length) {
        const item = source[offset];
        value += item;
        if (item === "\\") {
          value += source[offset + 1] ?? "";
          offset += 2;
          continue;
        }
        if (item === "[") characterClass = true;
        if (item === "]") characterClass = false;
        offset += 1;
        if (item === "/" && !characterClass) {
          closed = true;
          break;
        }
      }
      if (!closed) assert.fail("source_regex_invalid");
      while (offset < source.length && /[a-z]/iu.test(source[offset])) {
        value += source[offset];
        offset += 1;
      }
      tokens.push({ type: "regex", value });
      continue;
    }
    if (character === '"' || character === "'") {
      const quote = character;
      let value = "";
      offset += 1;
      let closed = false;
      while (offset < source.length) {
        const item = source[offset];
        if (item === quote) {
          offset += 1;
          closed = true;
          break;
        }
        if (item === "\\") {
          offset += 1;
          if (offset >= source.length) assert.fail("source_string_invalid");
          const escape = source[offset];
          if (escape === "u" && /^[0-9a-fA-F]{4}$/u.test(source.slice(offset + 1, offset + 5))) {
            value += String.fromCharCode(Number.parseInt(source.slice(offset + 1, offset + 5), 16));
            offset += 5;
            continue;
          }
          value += escape;
          offset += 1;
          continue;
        }
        value += item;
        offset += 1;
      }
      if (!closed) assert.fail("source_string_invalid");
      tokens.push({ type: "string", value });
      continue;
    }
    if (character === "`") {
      let value = "";
      offset += 1;
      let closed = false;
      while (offset < source.length) {
        const item = source[offset];
        if (item === "\\") {
          value += item;
          value += source[offset + 1] ?? "";
          offset += 2;
          continue;
        }
        if (item === "`") {
          offset += 1;
          closed = true;
          break;
        }
        value += item;
        offset += 1;
      }
      if (!closed) assert.fail("source_template_invalid");
      tokens.push({ type: "template", value });
      continue;
    }
    if (identifierStart.test(character)) {
      const start = offset;
      offset += 1;
      while (offset < source.length && identifierPart.test(source[offset])) offset += 1;
      tokens.push({ type: "identifier", value: source.slice(start, offset) });
      continue;
    }
    tokens.push({ type: "punctuator", value: character });
    offset += 1;
  }
  return tokens;
};

const rejectDangerousTokens = (tokens) => {
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type === "identifier" && forbiddenIdentifiers.has(token.value)) assert.fail("source_authority_forbidden");
    if (token.type === "identifier" && token.value === "constructor" && tokens[index - 1]?.value === ".") {
      assert.fail("source_constructor_forbidden");
    }
    if (token.type === "string" || token.type === "template") {
      let combined = token.value;
      let cursor = index;
      while (tokens[cursor + 1]?.value === "+" && tokens[cursor + 2]?.type === "string") {
        combined += tokens[cursor + 2].value;
        cursor += 2;
      }
      if (forbiddenStringWord.test(combined) || forbiddenStringFragments.some((value) => combined.includes(value))) {
        assert.fail("source_string_authority_forbidden");
      }
    }
  }
};

const importSpecifiers = (tokens) => {
  const specifiers = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type !== "identifier" || !["import", "export"].includes(token.value)) continue;
    const next = tokens[index + 1];
    if (token.value === "import") {
      if (next?.value === "." && tokens[index + 2]?.value === "meta") continue;
      if (next?.value === "(") assert.fail("source_dynamic_import_forbidden");
      if (next?.type === "string") {
        specifiers.push(next.value);
        continue;
      }
      let cursor = index + 1;
      while (cursor < tokens.length && tokens[cursor].value !== ";" && tokens[cursor].value !== "from") cursor += 1;
      if (tokens[cursor]?.value !== "from" || tokens[cursor + 1]?.type !== "string") {
        assert.fail("source_import_unrecognized");
      }
      specifiers.push(tokens[cursor + 1].value);
      continue;
    }
    if (["const", "class", "function"].includes(next?.value)) continue;
    if (next?.value === "async" && tokens[index + 2]?.value === "function") continue;
    if (!["{", "*"].includes(next?.value)) assert.fail("source_export_unrecognized");
    let cursor = index + 1;
    let depth = 0;
    while (cursor < tokens.length) {
      if (tokens[cursor].value === "{") depth += 1;
      if (tokens[cursor].value === "}") depth -= 1;
      if (depth === 0 && tokens[cursor].value === "from") break;
      if (depth === 0 && tokens[cursor].value === ";") assert.fail("source_export_unrecognized");
      cursor += 1;
    }
    if (tokens[cursor]?.value !== "from" || tokens[cursor + 1]?.type !== "string") {
      assert.fail("source_export_unrecognized");
    }
    specifiers.push(tokens[cursor + 1].value);
  }
  return specifiers;
};

const assertClosedSource = (name, source, requireDigest = true) => {
  const tokens = sourceTokens(source);
  rejectDangerousTokens(tokens);
  assert.deepEqual(importSpecifiers(tokens), importAllowlists[name]);
  if (requireDigest) assert.equal(hash(source), sourceDigests[name]);
};

const expectCode = async (operation, code) => {
  await assert.rejects(operation, (error) => error instanceof ActivationGateError && error.code === code);
};

class TestManifestBoundaryError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const testBoundaryFail = (code) => {
  throw new TestManifestBoundaryError(code);
};

const readTestFixedManifest = async (root) => {
  const rootMetadata = await lstat(root).catch(() => testBoundaryFail("root_unavailable"));
  if (rootMetadata.isSymbolicLink() || !rootMetadata.isDirectory()) testBoundaryFail("root_invalid");
  const canonicalRoot = await realpath(root);
  let lexical = root;
  let canonicalExpected = canonicalRoot;
  for (let index = 0; index < fixedManifestSegments.length; index += 1) {
    lexical = resolve(lexical, fixedManifestSegments[index]);
    canonicalExpected = resolve(canonicalExpected, fixedManifestSegments[index]);
    const metadata = await lstat(lexical).catch(() => testBoundaryFail("manifest_unavailable"));
    if (metadata.isSymbolicLink()) testBoundaryFail("symlink_rejected");
    if (index < fixedManifestSegments.length - 1 && !metadata.isDirectory()) testBoundaryFail("parent_nonregular");
    if (index === fixedManifestSegments.length - 1 && !metadata.isFile()) testBoundaryFail("nonregular");
    if ((await realpath(lexical)) !== canonicalExpected) testBoundaryFail("path_escape");
  }
  let handle;
  try {
    handle = await open(lexical, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = await handle.stat();
    if (!metadata.isFile()) testBoundaryFail("nonregular");
    if (metadata.size > 131_072) testBoundaryFail("too_large");
    const bytes = await handle.readFile();
    if (bytes.byteLength > 131_072) testBoundaryFail("too_large");
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } finally {
    await handle?.close();
  }
};

const expectTestBoundaryCode = async (operation, code) => {
  await assert.rejects(operation, (error) => error instanceof TestManifestBoundaryError && error.code === code);
};

const evidenceRoot = async (t) => {
  const root = await mkdtemp(join(tmpdir(), "risely-activation-gates-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const entry of manifest.evidence) {
    const destination = resolve(root, entry.path);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(resolve(layerRoot, entry.path), destination);
  }
  return root;
};

const fixedManifestRoot = async (t, content = manifestText) => {
  const root = await mkdtemp(join(tmpdir(), "risely-fixed-manifest-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = resolve(root, ...fixedManifestSegments);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content);
  return { root, path };
};

test("bundled evaluator returns one stable blocked offline report and no live authority", async () => {
  const first = await evaluateActivationGates();
  const second = await evaluateActivationGates();
  assert.deepEqual(first, second);
  assert.equal(first.manifestSha256, bundledManifestSha256);
  assert.equal(first.manifestSha256, "268fe674a90b159df8f956074e9c01a2065bb54128c5337834deb9fa992bab2b");
  assert.equal(first.evidenceSetSha256, "b1257b22f9d29f49ec7ea1c083eeaab558747e6361797dab40545b7974ee8fd1");
  assert.equal(first.dependencyGraphSha256, "0d6ac8aae4aaab36c55c4b09a41935fb36fdbd399de4e5ca26200bd5b6c87079");
  assert.equal(first.reportSha256, "c09ca5587b8580e9421386b0a09e2b0bf527354945d1fece10940d6c42c24e68");
  assert.equal(first.overallState, "blocked");
  assert.equal(first.liveReadiness, "not_assessed");
  assert.equal(first.activationAuthorized, false);
  assert.equal(first.providerInvocationAllowed, false);
  assert.equal(first.networkContacted, false);
  assert.equal(first.secretValuesRead, false);
  assert.equal(
    first.secretValuesReadBasis,
    "closed_regular_repo_digests_with_explicit_hash_only_deployment_configuration_and_no_environment_or_secret_store_access",
  );
  assert.deepEqual(first.readBoundary, {
    mode: "closed_regular_repo_source_and_test_digests_only",
    evidencePathSetSha256: "db627435a0950ad9b17a0c3c3d97d3513af39d8a095bf35db04b11b795f2e633",
    hashOnlyContentPaths: ["infra/main.tf", "infra/terraform.tfvars", "infra/versions.tf", "infra/.terraform.lock.hcl"],
    environmentFilesAllowed: false,
    secretStoresAllowed: false,
    importedProviderPackagesAllowed: false,
  });
  assert.equal(first.evidence.length, 79);
  assert.equal(first.gates.length, 12);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.gates[0]), true);
});

test("all twelve closed gates verify only offline evidence and retain their exact blockers", async () => {
  const result = await evaluateActivationGates();
  assert.deepEqual(
    result.gates.map((gate) => gate.id),
    [
      "shadow_v6",
      "disposable_postgres_sentinel",
      "secret_routing",
      "qm_shadow_ingress",
      "google_broker",
      "provider_effect_authority",
      "mercury_invoicing",
      "slack_identity_eval_outbox",
      "notion_private_root",
      "clarify_read",
      "brain_read",
      "hard_disable_transition",
    ],
  );
  assert.deepEqual(result.blockers, [
    "live_shadow_execution_not_assessed",
    "disposable_postgres_sentinel_not_run",
    "production_postgres_deployment_sentinel_contract_unmet",
    "ceo_canary_task_host_provenance_unverified",
    "ceo_canary_iam_role_inventory_unverified",
    "ceo_canary_private_dns_compatibility_unverified",
    "ceo_canary_state_plan_lineage_unverified",
    "ceo_canary_runtime_image_security_unverified",
    "live_secret_route_not_assessed",
    "upstream_qm_turn_observer_merge_unverified",
    "upstream_qm_turn_observer_deployment_binding_unavailable",
    "upstream_qm_postgres_outbox_acceptance_unverified",
    "qm_surface_identity_bridge_unverified",
    "route_scoped_qm_observer_signing_key_unprovisioned",
    "same_qm_runtime_schema_not_live_verified",
    "private_slack_and_web_acceptance_not_completed",
    "trusted_google_broker_not_activated",
    "provider_execution_not_activated",
    "provider_grant_not_activated",
    "immutable_provider_effect_proof_registry_unavailable",
    "production_provider_effect_durable_port_unavailable",
    "production_provider_effect_adapters_unavailable",
    "production_provider_effect_reconciliation_ports_unavailable",
    "mercury_provider_effect_policy_not_approved",
    "mercury_schedule_fire_receipt_not_live_assessed",
    "mercury_trusted_billing_receipts_not_live_assessed",
    "mercury_cli_sandbox_acceptance_not_completed",
    "mercury_durable_approval_reconciliation_not_implemented",
    "qm_workflow_artifact_ui_live_acceptance_unverified",
    "slack_identity_and_delivery_not_live_assessed",
    "notion_private_root_not_live_assessed",
    "clarify_read_binding_not_live_assessed",
    "command_center_brain_read_binding_not_live_assessed",
    "activation_transition_review_not_performed",
  ]);
  for (const gate of result.gates) {
    assert.equal(gate.offlineEvidence, "source_and_test_hashes_verified");
    assert.equal(gate.dependencyGraphVerified, true);
    assert.equal(gate.state, "blocked");
    assert.equal(gate.liveReadiness, "not_assessed");
    assert.equal(gate.activationAuthorized, false);
    assert.equal(gate.providerInvocationAllowed, false);
    assert.ok(gate.evidence.every((digest) => /^[0-9a-f]{64}$/.test(digest)));
  }
});

test("deployment configuration bytes are digest-bound without a secret-absence claim", async (t) => {
  const result = await evaluateActivationGates();
  for (const path of ["infra/main.tf", "infra/terraform.tfvars", "infra/versions.tf", "infra/.terraform.lock.hcl"]) {
    const evidence = result.evidence.find((entry) => entry.path === path);
    assert.equal(evidence.contentInspection, "not_assessed_hash_only");
    assert.equal(evidence.verification, "offline_hash_verified");
    assert.match(evidence.sha256, /^[0-9a-f]{64}$/);
  }
  assert.ok(
    result.evidence
      .filter((entry) => !result.readBoundary.hashOnlyContentPaths.includes(entry.path))
      .every((entry) => entry.contentInspection === "secret_patterns_rejected"),
  );
  const root = await evidenceRoot(t);
  await writeFile(
    resolve(root, "infra/main.tf"),
    `${await readFile(resolve(root, "infra/main.tf"), "utf8")}\nresource {}`,
  );
  const candidate = clone();
  candidate.evidence.find((entry) => entry.path === "infra/main.tf").sha256 = hash(
    await readFile(resolve(root, "infra/main.tf")),
  );
  await expectCode(() => evaluateClosedManifest(encode(candidate), root), "evidence_digest_not_closed");
});

test("offline evidence cannot satisfy infrastructure or upstream QM and UI live requirements", async () => {
  const result = await evaluateActivationGates();
  assert.deepEqual(result.externalRequirements, [
    {
      id: "production_postgres_deployment_sentinel",
      gateId: "disposable_postgres_sentinel",
      state: "unmet",
      evidenceClass: "external_production_deployment_sentinel",
      offlineEvidenceCanSatisfy: false,
      blocker: "production_postgres_deployment_sentinel_contract_unmet",
    },
    {
      id: "ceo_canary_task_host_provenance",
      gateId: "disposable_postgres_sentinel",
      state: "unmet",
      evidenceClass: "external_task_definition_host_provenance",
      offlineEvidenceCanSatisfy: false,
      blocker: "ceo_canary_task_host_provenance_unverified",
    },
    {
      id: "ceo_canary_iam_role_inventory",
      gateId: "disposable_postgres_sentinel",
      state: "unmet",
      evidenceClass: "external_iam_role_inventory",
      offlineEvidenceCanSatisfy: false,
      blocker: "ceo_canary_iam_role_inventory_unverified",
    },
    {
      id: "ceo_canary_private_dns_compatibility",
      gateId: "disposable_postgres_sentinel",
      state: "unmet",
      evidenceClass: "external_vpc_private_dns_resolution",
      offlineEvidenceCanSatisfy: false,
      blocker: "ceo_canary_private_dns_compatibility_unverified",
    },
    {
      id: "ceo_canary_state_plan_lineage",
      gateId: "disposable_postgres_sentinel",
      state: "unmet",
      evidenceClass: "external_terraform_state_plan_backend_workspace_lineage",
      offlineEvidenceCanSatisfy: false,
      blocker: "ceo_canary_state_plan_lineage_unverified",
    },
    {
      id: "ceo_canary_runtime_image_security",
      gateId: "disposable_postgres_sentinel",
      state: "unmet",
      evidenceClass: "external_ecr_enhanced_image_scan",
      offlineEvidenceCanSatisfy: false,
      blocker: "ceo_canary_runtime_image_security_unverified",
    },
    {
      id: "upstream_qm_private_turn_observer_merge",
      gateId: "qm_shadow_ingress",
      state: "unmet",
      evidenceClass: "external_upstream_qm_merge",
      offlineEvidenceCanSatisfy: false,
      blocker: "upstream_qm_turn_observer_merge_unverified",
    },
    {
      id: "upstream_qm_private_turn_observer_deployment",
      gateId: "qm_shadow_ingress",
      state: "unmet",
      evidenceClass: "external_upstream_qm_deployment",
      offlineEvidenceCanSatisfy: false,
      blocker: "upstream_qm_turn_observer_deployment_binding_unavailable",
    },
    {
      id: "qm_shadow_route_signing_key",
      gateId: "qm_shadow_ingress",
      state: "unmet",
      evidenceClass: "external_route_scoped_signing_key",
      offlineEvidenceCanSatisfy: false,
      blocker: "route_scoped_qm_observer_signing_key_unprovisioned",
    },
    {
      id: "upstream_qm_observer_postgres_outbox",
      gateId: "qm_shadow_ingress",
      state: "unmet",
      evidenceClass: "external_postgres_outbox_live_acceptance",
      offlineEvidenceCanSatisfy: false,
      blocker: "upstream_qm_postgres_outbox_acceptance_unverified",
    },
    {
      id: "qm_workflow_artifact_ui_live_acceptance",
      gateId: "mercury_invoicing",
      state: "unmet",
      evidenceClass: "external_authenticated_ui_live_acceptance",
      offlineEvidenceCanSatisfy: false,
      blocker: "qm_workflow_artifact_ui_live_acceptance_unverified",
    },
  ]);
  const gate = result.gates.find((entry) => entry.id === "disposable_postgres_sentinel");
  assert.equal(gate.offlineEvidence, "source_and_test_hashes_verified");
  assert.deepEqual(manifest.gates.find((entry) => entry.id === "disposable_postgres_sentinel").evidence, [
    "postgres_store_source",
    "postgres_evaluation_writer_source",
    "postgres_database_security_source",
    "postgres_database_boundary_source",
    "postgres_schema_source",
    "postgres_catalog_authority_source",
    "postgres_bootstrap_source",
    "postgres_bootstrap_test",
    "postgres_db_operator_source",
    "postgres_db_operator_bootstrap_source",
    "postgres_migrate_source",
    "postgres_credential_provisioner_source",
    "postgres_credential_test",
    "postgres_lifecycle_test",
    "postgres_retention_source",
    "ceo_canary_security_doc",
    "ceo_canary_migration_runbook",
    "postgres_infra_host_source",
    "ceo_canary_task_contract_data",
    "ceo_canary_task_renderer_source",
    "ceo_canary_task_sealed_provenance_source",
    "ceo_canary_task_infra_source",
    "ceo_canary_infra_main_hash_only",
    "ceo_canary_tfvars_hash_only",
    "ceo_canary_terraform_versions_hash_only",
    "ceo_canary_terraform_lock_hash_only",
    "ceo_canary_task_variables_source",
    "ceo_canary_task_test",
    "ceo_canary_task_runbook",
    "ceo_canary_db_operator_contract_data",
    "ceo_canary_db_operator_infra_source",
    "ceo_canary_db_operator_test",
    "ceo_canary_db_operator_runbook",
    "postgres_sentinel_test",
    "postgres_dockerfile_source",
    "postgres_runtime_dockerfile_source",
    "secret_boundary_test",
    "postgres_container_test",
  ]);
  assert.deepEqual(gate.blockers, [
    "disposable_postgres_sentinel_not_run",
    "production_postgres_deployment_sentinel_contract_unmet",
    "ceo_canary_task_host_provenance_unverified",
    "ceo_canary_iam_role_inventory_unverified",
    "ceo_canary_private_dns_compatibility_unverified",
    "ceo_canary_state_plan_lineage_unverified",
    "ceo_canary_runtime_image_security_unverified",
  ]);
  for (const index of result.externalRequirements.keys()) {
    for (const field of ["state", "offlineEvidenceCanSatisfy", "evidenceClass"]) {
      const candidate = clone();
      candidate.externalRequirements[index][field] = field === "offlineEvidenceCanSatisfy" ? true : "satisfied";
      await expectCode(() => evaluateClosedManifest(encode(candidate), layerRoot), "external_requirement_not_closed");
    }
  }
});

for (const [gateIndex, gate] of manifest.gates.entries()) {
  test(`${gate.id} rejects ready-state injection, blocker removal, and forged evidence hashes`, async (t) => {
    const root = await evidenceRoot(t);
    const ready = clone();
    ready.gates[gateIndex].state = "ready";
    await expectCode(() => evaluateClosedManifest(encode(ready), root), "gate_shape_invalid");

    const blockerless = clone();
    blockerless.gates[gateIndex].blockers = [];
    await expectCode(() => evaluateClosedManifest(encode(blockerless), root), "gate_blocker_invalid");

    const forgedHash = clone();
    const evidenceId = forgedHash.gates[gateIndex].evidence[0];
    const evidence = forgedHash.evidence.find((entry) => entry.id === evidenceId);
    evidence.sha256 = evidence.sha256 === "0".repeat(64) ? "1".repeat(64) : "0".repeat(64);
    await expectCode(() => evaluateClosedManifest(encode(forgedHash), root), "evidence_hash_mismatch");
  });
}

test("strict JSON rejects duplicate keys at the root and nested gate levels", () => {
  const rootDuplicate = manifestText.replace('"schemaVersion": 1,', '"schemaVersion": 1,\n  "schemaVersion": 1,');
  assert.throws(
    () => parseStrictJson(rootDuplicate),
    (error) => error instanceof StrictJsonError && error.code === "manifest_json_duplicate_key",
  );
  const nestedDuplicate = manifestText.replace('"id": "shadow_v6",', '"id": "shadow_v6",\n      "id": "shadow_v6",');
  assert.throws(
    () => parseStrictJson(nestedDuplicate),
    (error) => error instanceof StrictJsonError && error.code === "manifest_json_duplicate_key",
  );
});

test("manifest input rejects oversize, malformed, and trailing JSON", async () => {
  await expectCode(() => evaluateClosedManifest(" ".repeat(131_073), layerRoot), "manifest_json_too_large");
  await expectCode(() => evaluateClosedManifest('{"schemaVersion":}', layerRoot), "manifest_json_invalid");
  await expectCode(() => evaluateClosedManifest(`${manifestText}true`, layerRoot), "manifest_json_invalid");
});

test("production exports no arbitrary manifest reader and fixed traversal rejects unsafe files", async (t) => {
  assert.equal(Object.hasOwn(evaluatorModule, "readBoundedManifest"), false);
  assert.equal(Object.hasOwn(evaluatorModule, "readBundledManifest"), false);

  const regular = await fixedManifestRoot(t);
  assert.equal(await readTestFixedManifest(regular.root), manifestText);

  const linked = await fixedManifestRoot(t);
  const fakeEnvironment = resolve(linked.root, ".env");
  await writeFile(fakeEnvironment, manifestText);
  await unlink(linked.path);
  await symlink(fakeEnvironment, linked.path);
  await expectTestBoundaryCode(() => readTestFixedManifest(linked.root), "symlink_rejected");

  const environmentOnly = await mkdtemp(join(tmpdir(), "risely-env-decoy-"));
  t.after(() => rm(environmentOnly, { recursive: true, force: true }));
  await mkdir(resolve(environmentOnly, "canary/activation-gates"), { recursive: true });
  await writeFile(resolve(environmentOnly, "canary/activation-gates/.env"), manifestText);
  await expectTestBoundaryCode(() => readTestFixedManifest(environmentOnly), "manifest_unavailable");

  const nonregular = await fixedManifestRoot(t);
  await unlink(nonregular.path);
  await mkdir(nonregular.path);
  await expectTestBoundaryCode(() => readTestFixedManifest(nonregular.root), "nonregular");

  const oversized = await fixedManifestRoot(t, " ".repeat(131_073));
  await expectTestBoundaryCode(() => readTestFixedManifest(oversized.root), "too_large");
});

test("fixed manifest traversal rejects symlinked canary and activation-gates parents", async (t) => {
  for (const parent of ["canary", "activation-gates"]) {
    const root = await mkdtemp(join(tmpdir(), "risely-parent-symlink-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const external = resolve(root, `external-${parent}`);
    if (parent === "canary") {
      await mkdir(resolve(external, "activation-gates"), { recursive: true });
      await writeFile(resolve(external, "activation-gates/manifest.json"), manifestText);
      await symlink(external, resolve(root, "canary"));
    } else {
      await mkdir(resolve(root, "canary"), { recursive: true });
      await mkdir(external);
      await writeFile(resolve(external, "manifest.json"), manifestText);
      await symlink(external, resolve(root, "canary/activation-gates"));
    }
    await expectTestBoundaryCode(() => readTestFixedManifest(root), "symlink_rejected");
  }
});

test("closed evidence rejects traversal, absolute paths, backslashes, and arbitrary allowlist expansion", async () => {
  for (const path of ["../outside.mjs", "/tmp/outside.mjs", "canary\\outside.mjs", "canary/../outside.mjs"]) {
    const candidate = clone();
    candidate.evidence[0].path = path;
    await expectCode(() => evaluateClosedManifest(encode(candidate), layerRoot), "evidence_path_invalid");
  }
  const arbitrary = clone();
  arbitrary.evidence[0].path = "canary/arbitrary-but-relative.mjs";
  await expectCode(() => evaluateClosedManifest(encode(arbitrary), layerRoot), "evidence_set_not_closed");
  const executable = clone();
  executable.evidence[0].path = "canary/arbitrary.sh";
  await expectCode(() => evaluateClosedManifest(encode(executable), layerRoot), "evidence_path_invalid");
  const arbitraryDockerfile = clone();
  arbitraryDockerfile.evidence[0].path = "canary/service/ceo-canary/Dockerfile.attacker";
  await expectCode(() => evaluateClosedManifest(encode(arbitraryDockerfile), layerRoot), "evidence_path_invalid");
});

test("file and parent-directory symlinks are rejected before evidence is read", async (t) => {
  const fileRoot = await evidenceRoot(t);
  const fileEntry = manifest.evidence[0];
  const fileTarget = resolve(fileRoot, fileEntry.path);
  const fileBackup = `${fileTarget}.regular`;
  await rename(fileTarget, fileBackup);
  await symlink(fileBackup, fileTarget);
  await expectCode(() => evaluateClosedManifest(manifestText, fileRoot), "evidence_symlink_rejected");

  const directoryRoot = await evidenceRoot(t);
  const directoryEntry = manifest.evidence.find((entry) => entry.id === "google_broker_source");
  const directoryTarget = resolve(directoryRoot, "canary/google-broker");
  const directoryBackup = resolve(directoryRoot, "google-broker-regular");
  await rename(directoryTarget, directoryBackup);
  await symlink(directoryBackup, directoryTarget);
  const candidate = clone();
  candidate.evidence = [directoryEntry, ...candidate.evidence.filter((entry) => entry.id !== directoryEntry.id)];
  candidate.evidence.sort(
    (left, right) =>
      manifest.evidence.findIndex((entry) => entry.id === left.id) -
      manifest.evidence.findIndex((entry) => entry.id === right.id),
  );
  await expectCode(() => evaluateClosedManifest(encode(candidate), directoryRoot), "evidence_symlink_rejected");
});

test("directories and oversized regular files cannot masquerade as evidence", async (t) => {
  const directoryRoot = await evidenceRoot(t);
  const target = resolve(directoryRoot, manifest.evidence[0].path);
  await unlink(target);
  await mkdir(target);
  await expectCode(() => evaluateClosedManifest(manifestText, directoryRoot), "evidence_path_nonregular");

  const oversizeRoot = await evidenceRoot(t);
  const oversized = resolve(oversizeRoot, manifest.evidence[0].path);
  await writeFile(oversized, "x".repeat(65_537));
  await expectCode(() => evaluateClosedManifest(manifestText, oversizeRoot), "evidence_file_too_large");
});

test("secret-shaped content is rejected even when an attacker updates its manifest hash", async (t) => {
  const root = await evidenceRoot(t);
  const candidate = clone();
  const entry = candidate.evidence[0];
  const probes = [
    'export const credential = "xoxb-attacker-controlled-value";\n',
    'export const credential = "sk-live-attacker-controlled-value";\n',
    'export const credential = "postgresql://owner:attacker-secret@database.invalid/db";\n',
    'export const password = "correct-horse-battery-staple";\n',
    'export const headers = { Authorization: "Bearer attacker-controlled-token" };\n',
    'export const endpoint = "https://owner:attacker-secret@example.invalid/path";\n',
  ];
  for (const probe of probes) {
    await writeFile(resolve(root, entry.path), probe);
    entry.sha256 = hash(probe);
    await expectCode(() => evaluateClosedManifest(encode(candidate), root), "evidence_secret_like");
  }
});

test("ordinary content replacement fails its fixed digest even without a secret signature", async (t) => {
  const root = await evidenceRoot(t);
  await writeFile(resolve(root, manifest.evidence[0].path), "export const forged = false;\n");
  await expectCode(() => evaluateClosedManifest(manifestText, root), "evidence_hash_mismatch");
});

test("manifest hash updates cannot bless arbitrary benign evidence outside the compiled digest closure", async (t) => {
  const root = await evidenceRoot(t);
  const candidate = clone();
  const replacement = "export const forged = false;\n";
  await writeFile(resolve(root, candidate.evidence[0].path), replacement);
  candidate.evidence[0].sha256 = hash(replacement);
  await expectCode(() => evaluateClosedManifest(encode(candidate), root), "evidence_digest_not_closed");
});

test("unknown, duplicate, and non-source evidence entries cannot enter the closed set", async () => {
  const unknown = clone();
  unknown.evidence[0].id = "unknown_evidence";
  await expectCode(() => evaluateClosedManifest(encode(unknown), layerRoot), "evidence_set_not_closed");

  const duplicate = clone();
  duplicate.evidence[1].id = duplicate.evidence[0].id;
  await expectCode(() => evaluateClosedManifest(encode(duplicate), layerRoot), "evidence_id_invalid");

  const arbitraryKind = clone();
  arbitraryKind.evidence[0].kind = "live_receipt";
  await expectCode(() => evaluateClosedManifest(encode(arbitraryKind), layerRoot), "evidence_kind_invalid");
});

test("cycles, missing dependencies, duplicate edges, and dependency rewrites fail closed", async () => {
  const cycle = clone();
  cycle.gates[0].dependsOn = ["hard_disable_transition"];
  await expectCode(() => evaluateClosedManifest(encode(cycle), layerRoot), "gate_dependency_cycle");

  const missing = clone();
  missing.gates[1].dependsOn = ["unknown_gate"];
  await expectCode(() => evaluateClosedManifest(encode(missing), layerRoot), "gate_dependency_invalid");

  const duplicate = clone();
  duplicate.gates.find((gate) => gate.id === "google_broker").dependsOn = ["shadow_v6", "shadow_v6"];
  await expectCode(() => evaluateClosedManifest(encode(duplicate), layerRoot), "gate_dependency_invalid");

  const rewrite = clone();
  rewrite.gates.find((gate) => gate.id === "qm_shadow_ingress").dependsOn = ["shadow_v6"];
  await expectCode(() => evaluateClosedManifest(encode(rewrite), layerRoot), "gate_dependencies_not_closed");
});

test("top-level and gate-level forged authorization fields are unsupported", async () => {
  for (const field of ["activationAuthorized", "providerInvocationAllowed", "liveReadiness", "networkContacted"]) {
    const candidate = clone();
    candidate[field] = field === "liveReadiness" ? "ready" : true;
    await expectCode(() => evaluateClosedManifest(encode(candidate), layerRoot), "manifest_shape_invalid");
  }
  for (const field of ["state", "liveReady", "approved", "providerInvocationAllowed"]) {
    const candidate = clone();
    candidate.gates.find((gate) => gate.id === "hard_disable_transition")[field] = true;
    await expectCode(() => evaluateClosedManifest(encode(candidate), layerRoot), "gate_shape_invalid");
  }
});

test("Notion private-root semantics are an exact closed manifest contract", async () => {
  const result = await evaluateActivationGates();
  assert.deepEqual(result.semanticContracts.notionPrivateRoot, {
    parentRef: "notion:ceo-private-root-v1",
    audienceRef: "audience:ceo-private",
    scope: "private_ceo",
    providerInvocationAllowed: false,
  });
  assert.equal(Object.isFrozen(result.semanticContracts.notionPrivateRoot), true);
  const gate = result.gates.find((entry) => entry.id === "notion_private_root");
  assert.equal(gate.state, "blocked");
  assert.deepEqual(gate.blockers, ["notion_private_root_not_live_assessed"]);
  for (const [field, value] of [
    ["parentRef", "notion:shared-root"],
    ["audienceRef", "slack-audience:ceo-private"],
    ["scope", "organization"],
    ["providerInvocationAllowed", true],
  ]) {
    const candidate = clone();
    candidate.semanticContracts.notionPrivateRoot[field] = value;
    await expectCode(() => evaluateClosedManifest(encode(candidate), layerRoot), "notion_semantic_contract_invalid");
  }
});

test("activation evaluator modules have exact per-file imports and no dynamic execution or ambient authority", async () => {
  const files = (await readdir(sourceRoot)).filter((name) => name.endsWith(".mjs")).sort();
  assert.deepEqual(files, Object.keys(importAllowlists).sort());
  for (const name of files) {
    const source = await readFile(resolve(sourceRoot, name), "utf8");
    assertClosedSource(name, source);
    assert.doesNotMatch(source, /(?:^|\n)\s*(?:\/\/|\/\*)/);
    assert.doesNotMatch(source, /\b(?:TODO|FIXME)\b/);
  }
});

test("source closure rejects provider packages, computed ambient access, dynamic imports, and child processes", () => {
  const probes = [
    'import pg from "pg"\n',
    'import notion from "@notionhq/client"\n',
    'const environment = process["env"];\n',
    'const request = globalThis["fetch"]("https://example.invalid");\n',
    'const packageName = "pg"; await import(packageName);\n',
    'const child = require("node:child_process");\n',
    'const child = module["require"]("node:child_process");\n',
    'import { spawn } from "node:child_process";\n',
    'const child = await import/*split*/("node:child_" + "process")\n',
    'Function("return pro" + "cess.env")()\n',
    '(0, eval)("global" + "This[\\"fe" + "tch\\"]")\n',
    'Function("return pro" + "cess.get" + "BuiltinModule(\\"node:child_process\\")")()\n',
  ];
  for (const probe of probes) {
    assert.throws(() => assertClosedSource("strict-json.mjs", probe));
  }
});

test("activation-gate changes remain confined to the deployment layer", () => {
  assert.equal(relative(layerRoot, sourceRoot), "canary/activation-gates");
  assert.equal(relative(layerRoot, fileURLToPath(new URL(".", import.meta.url))), "test/activation-gates");
});
