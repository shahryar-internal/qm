import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import { publicTurnBody } from "../src/api/routes/turns.ts";
import { parseBackgroundJobDeploymentProfile } from "../src/background-jobs/deployment-profile.ts";
import { createBackgroundJobProfileService, createBackgroundJobRegistry } from "../src/background-jobs/service.ts";
import type {
  BackgroundJobAdapter,
  BackgroundJobAdmissionIntent,
  BackgroundJobApprovalExpectation,
  BackgroundJobApprovalStore,
  BackgroundJobClient,
  BackgroundJobInvocationAuthority,
  BackgroundJobReceipt,
  BackgroundJobReceiptStore,
  BackgroundJobTurnBinding,
} from "../src/background-jobs/types.ts";
import { canonicalJson } from "../src/cron/schedule-authority.ts";
import { parseToolDescriptor } from "../src/deployment/deployment-layer.ts";
import { createDeploymentLayerStore, type StoredDeploymentLayer } from "../src/deployment/deployment-layer-store.ts";
import { emptyDeploymentLayer, resolvedDeploymentLayer } from "../src/deployment/load-layer.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { createSkillStore } from "../src/skills/skill-store.ts";
import { scopeId } from "../src/types.ts";

const PROFILE_PATH = "background-jobs/report-preview/job.json";

function schema() {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    additionalProperties: false,
    properties: {
      recordId: { type: "string", maxLength: 100 },
      receiptIds: { type: "array", minItems: 1, maxItems: 20, items: { type: "string", maxLength: 100 } },
    },
    required: ["recordId", "receiptIds"],
  };
}

function manifest() {
  const json = schema();
  return {
    contract: 1,
    definition: {
      id: "report-preview",
      operation: "report_preview",
      capability: "reports.preview",
      scope: "jobs:submit",
      tokenType: "job-authority+jwt",
      authorityHeader: "x-job-authority",
      prepare: { path: "/api/jobs/report-preview/prepare", maxRequestBytes: 512 },
      start: { path: "/api/jobs/report-preview", maxRequestBytes: 1024 },
      status: { path: "/api/jobs/report-preview/status", maxRequestBytes: 512 },
      cancel: { path: "/api/jobs/report-preview/cancel", maxRequestBytes: 512 },
    },
    issuer: "https://gateway.example.com/authority",
    audience: "https://jobs.example.com/authority",
    origin: "https://jobs.example.com",
    artifactPathPrefix: "/api/jobs/report-preview/artifacts/",
    artifactAccess: "owner_authenticated",
    profile: {
      organizationId: "org_example",
      actorPrincipalId: "principal_owner",
      actorSlackId: "UOWNER1",
      audienceScopeId: "personal:principal_owner",
      slackTeamId: "TTEAM01",
      channelId: "DOWNER1",
    },
    tools: {
      start: { id: "report-preview", label: "Create report preview" },
      status: { id: "report-preview-status", label: "Check report status" },
      cancel: { id: "report-preview-cancel", label: "Cancel report preview" },
    },
    approval: { start: "invocation_receipt", cancel: "invocation_receipt" },
    schema: { sha256: createHash("sha256").update(canonicalJson(json)).digest("hex"), json },
    artifacts: [
      { kind: "report", label: "Report", visibility: "primary" },
      { kind: "evaluation", label: "Evaluation", visibility: "private_review" },
    ],
    dependencies: {
      adapter: "signed-report-compiler",
      receiptStore: "postgres-job-receipts",
      approvalStore: "postgres-job-approvals",
      authority: "kms-rs256-v1",
    },
  };
}

function profile(value = manifest(), enabled = true) {
  return parseBackgroundJobDeploymentProfile(JSON.stringify(value), PROFILE_PATH, enabled);
}

const TURN: Readonly<BackgroundJobTurnBinding> = Object.freeze({
  surface: "slack",
  actorId: "principal_owner",
  actorType: "internal",
  conversationKind: "dm",
  conversationThreadRef: "dm:DOWNER1:1788030000.123456",
  conversationAudienceIds: Object.freeze(["principal_owner"]),
  originKind: "human",
  originMessageTs: "1788030001.123456",
  verifiedSlack: Object.freeze({
    teamId: "TTEAM01",
    userId: "UOWNER1",
    channelId: "DOWNER1",
    messageTs: "1788030001.123456",
    threadTs: "1788030000.123456",
    threaded: true,
    liveHuman: true,
  }),
});

const INVOCATION: Readonly<BackgroundJobInvocationAuthority> = Object.freeze({
  receiptId: "approval-1",
  slack: Object.freeze({
    ...TURN.verifiedSlack!,
    messageTs: "1788030002.123456",
  }),
});

function receiptStore(
  options: {
    failBeforeRemote?: boolean;
    beforeRemote?: () => void;
    durableIntent?: (intent: Readonly<BackgroundJobAdmissionIntent>) => Readonly<BackgroundJobAdmissionIntent>;
  } = {},
) {
  let receipt: Readonly<BackgroundJobReceipt> | null = null;
  const events: string[] = [];
  const value: BackgroundJobReceiptStore = {
    durability: "durable",
    admission: "durable_intent_outbox",
    reconciliation: "automatic_idempotent",
    readiness: () => ({ ready: true }),
    admit: async (intent, start) => {
      events.push("intent_persisted");
      if (options.failBeforeRemote) throw new Error("database unavailable");
      options.beforeRemote?.();
      const admission = await start(options.durableIntent?.(intent) ?? intent);
      events.push("admission_recorded");
      receipt = Object.freeze({
        jobId: intent.jobId,
        authorityId: admission.authorityId,
        runId: admission.runId,
        organizationId: intent.organizationId,
        actorPrincipalId: intent.actorPrincipalId,
        actorSlackId: intent.actorSlackId,
        audienceScopeId: intent.audienceScopeId,
        slackTeamId: intent.slackTeamId,
        channelId: intent.channelId,
        threadTs: intent.threadTs,
        messageTs: intent.messageTs,
        descriptorSha256: intent.descriptorSha256,
        profileSha256: intent.profileSha256,
        schemaSha256: intent.schemaSha256,
        payloadSha256: intent.payloadSha256,
        idempotencyKey: intent.idempotencyKey,
        createdAt: intent.createdAt,
      });
      return receipt;
    },
    latestOwned: async () => receipt,
  };
  return {
    value,
    events,
    get: () => receipt,
    replace: (value: Readonly<BackgroundJobReceipt> | null) => {
      receipt = value;
    },
  };
}

function approvalStore(approve = true) {
  const consumed = new Set<string>();
  const expectations: BackgroundJobApprovalExpectation[] = [];
  const value: BackgroundJobApprovalStore = {
    durability: "durable",
    consumption: "one_time",
    readiness: () => ({ ready: true }),
    consume: async (authority, expected) => {
      expectations.push(expected);
      if (!approve || consumed.has(authority.receiptId)) return false;
      consumed.add(authority.receiptId);
      return true;
    },
  };
  return { value, expectations };
}

function adapter(): BackgroundJobAdapter<
  { recordId: string; receiptIds: string[] },
  { state: string },
  { state: string }
> {
  return {
    readiness: () => ({ ready: true }),
    parseInput(value) {
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid");
      const item = value as Record<string, unknown>;
      if (
        Object.keys(item).sort().join(",") !== "receiptIds,recordId" ||
        typeof item.recordId !== "string" ||
        !Array.isArray(item.receiptIds) ||
        item.receiptIds.some((entry) => typeof entry !== "string")
      ) {
        throw new Error("invalid");
      }
      return { recordId: item.recordId, receiptIds: item.receiptIds as string[] };
    },
    prepare: async (input) => ({ bodyBytes: Buffer.from(canonicalJson(input)), idempotencyKey: "decision-123" }),
    statusView: (status) => ({
      state: status.state as "complete",
      artifacts: [
        {
          kind: "report",
          href: "https://jobs.example.com/api/jobs/report-preview/artifacts/report-1",
          sha256: "d".repeat(64),
        },
        {
          kind: "evaluation",
          href: "https://jobs.example.com/api/jobs/report-preview/artifacts/evaluation-1",
          sha256: "e".repeat(64),
        },
      ],
    }),
    cancellationState: () => "cancel_requested",
  };
}

function client(events: string[] = []) {
  let starts = 0;
  const value: BackgroundJobClient<{ state: string }, { state: string }> = {
    start: async () => {
      starts += 1;
      events.push("remote_started");
      return { authorityId: "authority-1", runId: "run-0000001" };
    },
    status: async () => ({ state: "complete" }),
    cancel: async () => ({ state: "cancelling" }),
  };
  return { value, starts: () => starts };
}

function service(
  options: {
    active?: () => boolean;
    receipts?: ReturnType<typeof receiptStore>;
    approve?: boolean;
    deployment?: ReturnType<typeof profile>;
    adapter?: ReturnType<typeof adapter>;
  } = {},
) {
  const receipts = options.receipts ?? receiptStore();
  const approvals = approvalStore(options.approve);
  const remote = client(receipts.events);
  const deployment = options.deployment ?? profile();
  const value = createBackgroundJobProfileService({
    deployment,
    adapter: options.adapter ?? adapter(),
    receipts: receipts.value,
    approvals: approvals.value,
    client: remote.value,
    authorityReady: () => true,
    active: options.active ?? (() => true),
    now: () => 1_788_030_000_000,
  });
  return { value, deployment, receipts, approvals, remote };
}

test("start requires an exact fresh invocation receipt and persists the durable intent before remote admission", async () => {
  const built = service();
  const bound = built.value.bind(TURN)!;
  assert.equal(bound.canStart(), true);
  assert.equal((await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }, undefined)).state, "denied");
  assert.equal(built.remote.starts(), 0);
  assert.equal(
    (await bound.start({ recordId: "record-1", receiptIds: ["decision-1"], pricing: "forged" }, INVOCATION)).state,
    "invalid",
  );
  assert.equal((await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state, "accepted");
  assert.deepEqual(built.receipts.events, ["intent_persisted", "remote_started", "admission_recorded"]);
  assert.equal(built.receipts.get()!.messageTs, INVOCATION.slack.messageTs);
  assert.equal(built.receipts.get()!.threadTs, INVOCATION.slack.threadTs);
  assert.equal(built.receipts.get()!.descriptorSha256, built.deployment.binding.descriptorSha256);
  assert.equal(built.approvals.expectations[0]!.effect, "background_job_start");
  assert.equal(built.approvals.expectations[0]!.payloadSha256, built.receipts.get()!.payloadSha256);
  assert.equal(built.approvals.expectations[0]!.maximumExpiresAt - built.approvals.expectations[0]!.now, 5 * 60 * 1000);
  assert.equal(built.approvals.expectations[0]!.messageTs, INVOCATION.slack.messageTs);
  assert.equal((await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state, "denied");
});

test("durable intent failure and disable races yield zero remote admission", async () => {
  const failedReceipts = receiptStore({ failBeforeRemote: true });
  const failed = service({ receipts: failedReceipts });
  assert.equal(
    (await failed.value.bind(TURN)!.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state,
    "unavailable",
  );
  assert.equal(failed.remote.starts(), 0);
  let active = true;
  const disabled = service({ active: () => active });
  const bound = disabled.value.bind(TURN)!;
  active = false;
  assert.equal(bound.canStart(), false);
  assert.equal((await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state, "denied");
  assert.equal(disabled.remote.starts(), 0);
  let admittingActive = true;
  const admittingReceipts = receiptStore({ beforeRemote: () => (admittingActive = false) });
  const admitting = service({ active: () => admittingActive, receipts: admittingReceipts });
  assert.equal(
    (await admitting.value.bind(TURN)!.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state,
    "unavailable",
  );
  assert.equal(admitting.remote.starts(), 0);
  for (const durableIntent of [
    (intent: Readonly<BackgroundJobAdmissionIntent>) => ({ ...intent, bodyBytes: Buffer.from('{"forged":true}') }),
    (intent: Readonly<BackgroundJobAdmissionIntent>) => ({ ...intent, actorPrincipalId: "principal_attacker" }),
    (intent: Readonly<BackgroundJobAdmissionIntent>) => ({ ...intent, messageTs: "1788030009.123456" }),
  ]) {
    const tamperedReceipts = receiptStore({ durableIntent });
    const tampered = service({ receipts: tamperedReceipts });
    assert.equal(
      (await tampered.value.bind(TURN)!.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state,
      "unavailable",
    );
    assert.equal(tampered.remote.starts(), 0);
  }
});

test("compiled job bodies must be canonical JSON matching the hash-bound schema", async () => {
  for (const bodyBytes of [
    Buffer.from('{"recordId":"record-1", "receiptIds":["decision-1"]}'),
    Buffer.from('{"receiptIds":["decision-1"],"recordId":1}'),
  ]) {
    const invalidAdapter = adapter();
    invalidAdapter.prepare = async () => ({ bodyBytes, idempotencyKey: "decision-123" });
    const built = service({ adapter: invalidAdapter });
    assert.equal(
      (await built.value.bind(TURN)!.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state,
      "unavailable",
    );
    assert.equal(built.remote.starts(), 0);
  }
});

test("owner control survives disable while start disappears and completion cards omit private review evidence", async () => {
  let active = true;
  const built = service({ active: () => active });
  const bound = built.value.bind(TURN)!;
  assert.equal((await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state, "accepted");
  active = false;
  assert.equal(bound.canStart(), false);
  const status = await bound.status();
  assert.equal(status.state, "complete");
  assert.ok(status.ok && status.card);
  const visible = JSON.stringify(status.card);
  assert.match(visible, /Report/);
  assert.doesNotMatch(visible, /Evaluation|evaluation-1|[de]{64}|sha256/i);
  const cancelInvocation = { ...INVOCATION, receiptId: "approval-cancel" };
  assert.equal((await bound.cancel(cancelInvocation)).state, "cancel_requested");
  assert.equal(built.approvals.expectations[1]!.effect, "background_job_cancel");
  assert.equal((await bound.cancel(cancelInvocation)).state, "denied");
  const disabledProfile = profile(manifest(), false);
  assert.equal(disabledProfile.binding.descriptorSha256, built.deployment.binding.descriptorSha256);
  const restarted = service({ active: () => false, receipts: built.receipts, deployment: disabledProfile });
  const registry = createBackgroundJobRegistry({ profiles: () => [disabledProfile], resolve: () => restarted.value });
  const controls = registry.bind(TURN);
  assert.equal(controls.length, 1);
  assert.equal(controls[0]!.canStart(), false);
  assert.equal((await controls[0]!.status()).state, "complete");
});

test("owner control rejects receipts from an older descriptor revision", async () => {
  const built = service();
  const bound = built.value.bind(TURN)!;
  assert.equal((await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state, "accepted");
  built.receipts.replace(
    Object.freeze({
      ...built.receipts.get()!,
      descriptorSha256: "a".repeat(64),
    }),
  );
  assert.equal((await bound.status()).state, "not_found");
  assert.equal((await bound.cancel({ ...INVOCATION, receiptId: "approval-cancel" })).state, "not_found");
});

test("the multi-profile registry re-resolves current profiles and never treats audience provenance as start authority", async () => {
  const built = service();
  let profiles = [built.deployment];
  const registry = createBackgroundJobRegistry({ profiles: () => profiles, resolve: () => built.value });
  const bound = registry.bind(TURN);
  assert.equal(bound.length, 1);
  assert.equal(
    (await bound[0]!.start({ recordId: "record-1", receiptIds: ["decision-1"] }, undefined)).state,
    "denied",
  );
  profiles = [];
  assert.equal(registry.bind(TURN).length, 0);
});

test("dependency readiness exposes only fixed public reason codes", () => {
  const unavailableAdapter = adapter();
  unavailableAdapter.readiness = () => ({ ready: false, reason: "password=private postgres://internal" });
  const built = service({ adapter: unavailableAdapter });
  assert.deepEqual(built.value.readiness(), {
    ready: false,
    reason: "background_job_adapter_unavailable",
  });
  assert.doesNotMatch(JSON.stringify(built.value.readiness()), /password|postgres|private|internal/i);
});

test("result projection rejects incomplete, foreign-origin, and private-review-only artifact substitutions", async () => {
  const built = service();
  const bound = built.value.bind(TURN)!;
  await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION);
  const invalidAdapter = adapter();
  invalidAdapter.statusView = () => ({
    state: "complete",
    artifacts: [
      {
        kind: "report",
        href: "https://foreign.example.com/api/jobs/report-preview/artifacts/report-1",
        sha256: "d".repeat(64),
      },
    ],
  });
  const invalid = service({ receipts: built.receipts, adapter: invalidAdapter });
  assert.equal((await invalid.value.bind(TURN)!.status()).state, "unavailable");
});

test("the dedicated registry is closed, deeply frozen, bounded, public-origin-only, and collision-safe", () => {
  const parsed = profile();
  assert.equal(Object.isFrozen(parsed.schema.json), true);
  assert.equal(Object.isFrozen((parsed.schema.json as { properties: unknown }).properties), true);
  assert.throws(() =>
    parseToolDescriptor(
      JSON.stringify({ id: "report-preview", backgroundJob: manifest() }),
      "tools/report-preview/tool.json",
    ),
  );
  assert.throws(
    () =>
      resolvedDeploymentLayer(
        "",
        [],
        [
          parsed,
          {
            ...parsed,
            definition: { ...parsed.definition, id: "other-preview" },
            tools: {
              start: { id: "other-preview", label: "Other preview" },
              status: parsed.tools.status,
              cancel: { id: "other-preview-cancel", label: "Cancel other preview" },
            },
          },
        ],
      ),
    /collides/,
  );
  const cases = [
    { ...manifest(), extra: true },
    { ...manifest(), origin: "https://localhost" },
    { ...manifest(), origin: "https://127.0.0.1" },
    { ...manifest(), origin: "https://jobs.example.com/%2e%2e/private" },
    { ...manifest(), artifactPathPrefix: "/api/jobs/../private/" },
    { ...manifest(), tools: { ...manifest().tools, start: { id: "execute", label: "Execute" } } },
    {
      ...manifest(),
      dependencies: { ...manifest().dependencies, adapter: "secret-token" },
    },
    {
      ...manifest(),
      schema: {
        sha256: createHash("sha256").update(canonicalJson({})).digest("hex"),
        json: {},
      },
    },
    {
      ...manifest(),
      schema: {
        sha256: createHash("sha256")
          .update(
            canonicalJson({ type: "object", properties: { any: {} }, additionalProperties: true, required: ["any"] }),
          )
          .digest("hex"),
        json: { type: "object", properties: { any: {} }, additionalProperties: true, required: ["any"] },
      },
    },
  ];
  for (const value of cases) {
    assert.throws(() => parseBackgroundJobDeploymentProfile(JSON.stringify(value), PROFILE_PATH));
  }
});

test("the deployment store durably tombstones removals and restores owner control configuration on restart", async () => {
  const backing = createMemoryMap<StoredDeploymentLayer>();
  const skills = createSkillStore({ signingSecret: "background-job-layer-test" });
  const runtime = emptyDeploymentLayer();
  const deployment = createDeploymentLayerStore({
    backing,
    runtime,
    skills,
    scopeId: scopeId("org", "example"),
  });
  const job = { path: PROFILE_PATH, content: JSON.stringify(manifest()) };
  await assert.rejects(
    deployment.put(
      { contract: 1, tools: [], skills: [], backgroundJobs: [{ ...job, executable: true }] },
      "signed-admin",
    ),
    /entries require/,
  );
  await deployment.put({ contract: 1, tools: [], skills: [], backgroundJobs: [job] }, "signed-admin");
  assert.equal(runtime.backgroundJobs[0]!.enabled, true);
  const originalDescriptorSha256 = runtime.backgroundJobs[0]!.binding.descriptorSha256;
  const changed = manifest();
  changed.definition.status.path = "/api/jobs/report-preview/changed-status";
  await assert.rejects(
    deployment.put(
      {
        contract: 1,
        tools: [],
        skills: [],
        backgroundJobs: [{ path: PROFILE_PATH, content: JSON.stringify(changed) }],
      },
      "signed-admin",
    ),
    /immutable/,
  );
  await deployment.put(
    {
      contract: 1,
      tools: [],
      skills: [],
      backgroundJobs: [{ ...job, enabled: false }],
    },
    "signed-admin",
  );
  assert.equal(runtime.backgroundJobs[0]!.enabled, false);
  assert.equal(runtime.backgroundJobs[0]!.binding.descriptorSha256, originalDescriptorSha256);
  await assert.rejects(
    deployment.put({ contract: 1, tools: [], skills: [], backgroundJobs: [job] }, "signed-admin"),
    /retired/,
  );
  await deployment.put({ contract: 1, tools: [], skills: [], backgroundJobs: [] }, "signed-admin");
  assert.equal(runtime.backgroundJobs.length, 1);
  assert.equal(runtime.backgroundJobs[0]!.enabled, false);
  const record = await deployment.get();
  assert.equal(record!.bundle.backgroundJobs!.length, 1);
  const hydratedRuntime = emptyDeploymentLayer();
  const hydrated = createDeploymentLayerStore({
    backing,
    runtime: hydratedRuntime,
    skills,
    scopeId: scopeId("org", "example"),
  });
  await hydrated.hydrate();
  assert.equal(hydratedRuntime.backgroundJobs.length, 1);
  assert.equal(hydratedRuntime.backgroundJobs[0]!.enabled, false);
  await assert.rejects(
    deployment.put(
      {
        contract: 1,
        tools: [{ path: "tools/report-preview-status/tool.json", content: '{"id":"report-preview-status"}' }],
        skills: [],
        backgroundJobs: [{ ...job, enabled: false }],
      },
      "signed-admin",
    ),
    /collides/,
  );
});

test("terminal receipts and expired approvals permit explicit durable tombstone cleanup", async () => {
  const backing = createMemoryMap<StoredDeploymentLayer>();
  const skills = createSkillStore({ signingSecret: "background-job-retirement-test" });
  const runtime = emptyDeploymentLayer();
  const base = createDeploymentLayerStore({
    backing,
    runtime,
    skills,
    scopeId: scopeId("org", "example"),
  });
  const job = { path: PROFILE_PATH, content: JSON.stringify(manifest()) };
  await base.put({ contract: 1, tools: [], skills: [], backgroundJobs: [job] }, "signed-admin");
  const descriptorSha256 = runtime.backgroundJobs[0]!.binding.descriptorSha256;
  await base.put({ contract: 1, tools: [], skills: [], backgroundJobs: [] }, "signed-admin");
  assert.equal(runtime.backgroundJobs[0]!.enabled, false);
  const cleanup = createDeploymentLayerStore({
    backing,
    runtime,
    skills,
    scopeId: scopeId("org", "example"),
    backgroundJobRetirement: {
      durability: "durable",
      receiptCoverage: "all_owned",
      approvalCoverage: "all_unused",
      decision: "terminal_and_expired",
      canPurge: async (candidate) => candidate.binding.descriptorSha256 === descriptorSha256,
    },
  });
  await cleanup.hydrate();
  await cleanup.put({ contract: 1, tools: [], skills: [], backgroundJobs: [] }, "signed-admin");
  assert.equal(runtime.backgroundJobs.length, 0);
  assert.equal((await cleanup.get())!.bundle.backgroundJobs!.length, 0);
});

test("public and replayable turn shapes never carry internal Slack provenance", () => {
  const result = publicTurnBody({
    surface: "api",
    text: "hello",
    actor: { externalId: "external-1" },
    conversation: { threadRef: "thread-1", kind: "dm" },
    verifiedSlack: TURN.verifiedSlack,
    ownerKeychainUnion: true,
    unattendedGrants: ["grant-1"],
    spawned: true,
  });
  assert.equal("verifiedSlack" in result, false);
  assert.equal("ownerKeychainUnion" in result, false);
  assert.equal("unattendedGrants" in result, false);
  assert.equal("spawned" in result, false);
});
