import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { canonicalJson } from "../src/cron/schedule-authority.ts";
import { createBackgroundJobService } from "../src/background-jobs/service.ts";
import { parseToolDescriptor } from "../src/deployment/deployment-layer.ts";
import { createDeploymentLayerStore, type StoredDeploymentLayer } from "../src/deployment/deployment-layer-store.ts";
import { emptyDeploymentLayer } from "../src/deployment/load-layer.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { createSkillStore } from "../src/skills/skill-store.ts";
import { scopeId } from "../src/types.ts";
import { publicTurnBody } from "../src/api/routes/turns.ts";
import type {
  BackgroundJobAdapter,
  BackgroundJobClient,
  BackgroundJobDefinition,
  BackgroundJobReceipt,
  BackgroundJobReceiptStore,
  BackgroundJobTurnBinding,
} from "../src/background-jobs/types.ts";

const DEFINITION: Readonly<BackgroundJobDefinition> = Object.freeze({
  id: "report-preview",
  operation: "report_preview",
  capability: "reports.preview",
  scope: "jobs:submit",
  tokenType: "job-authority+jwt",
  authorityHeader: "x-job-authority",
  prepare: Object.freeze({ path: "/api/jobs/report-preview/prepare", maxRequestBytes: 512 }),
  start: Object.freeze({ path: "/api/jobs/report-preview", maxRequestBytes: 1024 }),
  status: Object.freeze({ path: "/api/jobs/report-preview/status", maxRequestBytes: 512 }),
  cancel: Object.freeze({ path: "/api/jobs/report-preview/cancel", maxRequestBytes: 512 }),
});

const PROFILE = Object.freeze({
  organizationId: "org_example",
  actorPrincipalId: "principal_owner",
  actorSlackId: "UOWNER1",
  audienceScopeId: "personal:principal_owner",
  slackTeamId: "TTEAM01",
  channelId: "DOWNER1",
});

const TURN: Readonly<BackgroundJobTurnBinding> = Object.freeze({
  surface: "slack",
  actorId: PROFILE.actorPrincipalId,
  actorType: "internal",
  conversationKind: "dm",
  conversationThreadRef: "dm:DOWNER1:1788030000.123456",
  conversationAudienceIds: Object.freeze([PROFILE.actorPrincipalId]),
  originKind: "human",
  originMessageTs: "1788030001.123456",
  verifiedSlack: Object.freeze({
    teamId: PROFILE.slackTeamId,
    userId: PROFILE.actorSlackId,
    channelId: PROFILE.channelId,
    messageTs: "1788030001.123456",
    threadTs: "1788030000.123456",
    threaded: true,
    liveHuman: true,
  }),
});

function store(ready = true) {
  let receipt: Readonly<BackgroundJobReceipt> | null = null;
  const value: BackgroundJobReceiptStore = {
    durability: "durable",
    readiness: () => (ready ? { ready: true } : { ready: false }),
    save: async (next) => {
      receipt = next;
    },
    latestOwned: async () => receipt,
  };
  return {
    value,
    get: () => receipt,
    set: (next: Readonly<BackgroundJobReceipt> | null) => {
      receipt = next;
    },
  };
}

function adapter(
  ready = true,
): BackgroundJobAdapter<{ recordId: string; receiptIds: string[] }, { state: string }, { state: string }> {
  return {
    readiness: () => (ready ? { ready: true } : { ready: false, reason: "resolver_unconfigured" }),
    parseInput(value) {
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid");
      const item = value as Record<string, unknown>;
      if (
        Object.keys(item).sort().join(",") !== "receiptIds,recordId" ||
        typeof item.recordId !== "string" ||
        !Array.isArray(item.receiptIds)
      ) {
        throw new Error("invalid");
      }
      return { recordId: item.recordId, receiptIds: item.receiptIds as string[] };
    },
    prepare: async (input) => ({ bodyBytes: Buffer.from(canonicalJson(input)), idempotencyKey: "decision-123" }),
    admissionOutcome: () => ({ ok: true, state: "accepted", message: "The job is queued." }),
    statusOutcome: (status) => ({ ok: true, state: status.state, message: "The job result is ready." }),
    cancellationOutcome: (status) => ({ ok: true, state: status.state, message: "Cancellation requested." }),
  };
}

function client(): BackgroundJobClient<{ state: string }, { state: string }> {
  return {
    start: async () => ({ authorityId: "authority-1", runId: "run-0000001" }),
    status: async () => ({ state: "complete" }),
    cancel: async () => ({ state: "cancelling" }),
  };
}

function service(options: { ready?: boolean; store?: BackgroundJobReceiptStore; authority?: boolean } = {}) {
  return createBackgroundJobService({
    definition: DEFINITION,
    profile: PROFILE,
    adapter: adapter(options.ready),
    receipts: options.store ?? store().value,
    client: client(),
    authorityReady: () => options.authority ?? true,
    now: () => 1_788_030_000_000,
  });
}

test("generic background jobs stay hidden without adapter, durable receipts, signer readiness, or exact live human DM binding", () => {
  assert.deepEqual(service({ ready: false }).readiness(), { ready: false, reason: "resolver_unconfigured" });
  assert.deepEqual(service({ store: store(false).value }).readiness(), {
    ready: false,
    reason: "background_job_receipt_store_unavailable",
  });
  assert.deepEqual(service({ authority: false }).readiness(), {
    ready: false,
    reason: "background_job_authority_unavailable",
  });
  assert.equal(service({ ready: false }).bind(TURN), undefined);
  const mutations: Partial<BackgroundJobTurnBinding>[] = [
    { surface: "web" },
    { originKind: "automation" },
    { actorType: "guest" },
    { actorId: "principal_other" },
    { conversationKind: "channel" },
    { conversationAudienceIds: [] },
    { originMessageTs: "1788039999.123456" },
    { conversationThreadRef: "dm:DOWNER1:1788039999.123456" },
  ];
  for (const mutation of mutations) assert.equal(service().bind({ ...TURN, ...mutation }), undefined);
  for (const mutation of [
    { teamId: "TOTHER1" },
    { userId: "UOTHER1" },
    { channelId: "DOTHER1" },
    { threadTs: "1788039999.123456" },
  ]) {
    assert.equal(service().bind({ ...TURN, verifiedSlack: { ...TURN.verifiedSlack!, ...mutation } }), undefined);
  }
  assert.equal(
    service().bind({
      ...TURN,
      conversationThreadRef: "dm:DOWNER1",
      verifiedSlack: { ...TURN.verifiedSlack!, threaded: false, threadTs: "1788039999.123456" },
    }),
    undefined,
  );
  assert.ok(
    service().bind({
      ...TURN,
      conversationThreadRef: "dm:DOWNER1:1788030001.123456",
      verifiedSlack: {
        ...TURN.verifiedSlack!,
        threaded: false,
        threadTs: "1788030001.123456",
      },
    }),
  );
  assert.ok(service().bind(TURN));
});

test("generic service accepts only adapter-closed input and persists owner/thread-bound durable receipts", async () => {
  const receipts = store();
  const bound = service({ store: receipts.value }).bind(TURN)!;
  assert.deepEqual(await bound.start({ recordId: "record-1", receiptIds: ["decision-1"], pricing: "forged" }), {
    ok: false,
    state: "invalid",
    message: "The background job request is invalid.",
  });
  assert.equal(receipts.get(), null);
  assert.deepEqual(await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }), {
    ok: true,
    state: "accepted",
    message: "The job is queued.",
  });
  assert.deepEqual(receipts.get(), {
    jobId: DEFINITION.id,
    authorityId: "authority-1",
    runId: "run-0000001",
    ...PROFILE,
    threadTs: "1788030000.123456",
    idempotencyKey: "decision-123",
    createdAt: 1_788_030_000_000,
  });
  assert.equal((await bound.status()).state, "complete");
  assert.equal((await bound.cancel()).state, "cancelling");
  receipts.set({ ...receipts.get()!, actorPrincipalId: "principal_other" });
  assert.equal((await bound.status()).state, "not_found");
});

function deploymentProfile() {
  const schema = { type: "object", additionalProperties: false, required: ["recordId", "receiptIds"] };
  return {
    contract: 1,
    enabled: true,
    definition: DEFINITION,
    issuer: "https://gateway.example/authority",
    audience: "https://jobs.example/authority",
    origin: "https://jobs.example",
    profile: PROFILE,
    tools: {
      start: { id: DEFINITION.id, label: "Create report preview" },
      status: { id: "report-preview-status", label: "Check report status" },
      cancel: { id: "report-preview-cancel", label: "Cancel report preview" },
    },
    schema: { sha256: createHash("sha256").update(canonicalJson(schema)).digest("hex"), json: schema },
    artifacts: [
      { kind: "report", label: "Report", visibility: "primary" },
      { kind: "evaluation", label: "Evaluation", visibility: "private_review" },
    ],
    dependencies: {
      adapter: "signed-report-compiler",
      receiptStore: "postgres-job-receipts",
      authority: "kms-rs256-v1",
    },
  };
}

test("deployment tool descriptors carry only a closed, schema-hash-bound generic job profile", () => {
  const profile = deploymentProfile();
  const parsed = parseToolDescriptor(
    JSON.stringify({ id: DEFINITION.id, label: "Report preview", backgroundJob: profile }),
    "tools/report-preview/tool.json",
  );
  assert.deepEqual(parsed.backgroundJob, profile);
  const cases = [
    { ...profile, schema: { ...profile.schema, sha256: "a".repeat(64) } },
    { ...profile, extra: true },
    { ...profile, profile: { ...profile.profile, channelId: "CCHANNEL" } },
    { ...profile, definition: { ...profile.definition, cancel: profile.definition.status } },
    { ...profile, artifacts: [...profile.artifacts, profile.artifacts[0]] },
    { ...profile, dependencies: { ...profile.dependencies, secret: "value" } },
    { ...profile, dependencies: { ...profile.dependencies, authority: "SECRET_TOKEN_ENV" } },
  ];
  for (const value of cases) {
    assert.throws(() =>
      parseToolDescriptor(
        JSON.stringify({ id: DEFINITION.id, backgroundJob: value }),
        "tools/report-preview/tool.json",
      ),
    );
  }
  assert.throws(() =>
    parseToolDescriptor(JSON.stringify({ id: "other-tool", backgroundJob: profile }), "tools/other-tool/tool.json"),
  );
  assert.throws(
    () =>
      parseToolDescriptor(
        JSON.stringify({ id: DEFINITION.id, install: { binary: "report-preview" }, backgroundJob: profile }),
        "tools/report-preview/tool.json",
      ),
    /cannot be advertised/,
  );
});

test("the deployment-layer store durably versions, hydrates, disables, and removes background job profiles", async () => {
  const profile = deploymentProfile();
  const backing = createMemoryMap<StoredDeploymentLayer>();
  const skills = createSkillStore({ signingSecret: "background-job-layer-test" });
  const runtime = emptyDeploymentLayer();
  const deployment = createDeploymentLayerStore({
    backing,
    runtime,
    skills,
    scopeId: scopeId("org", "example"),
  });
  const descriptor = {
    path: `tools/${DEFINITION.id}/tool.json`,
    content: JSON.stringify({ id: DEFINITION.id, label: "Report preview", backgroundJob: profile }),
  };
  const enabled = await deployment.put({ contract: 1, tools: [descriptor], skills: [] }, "signed-admin");
  assert.equal(enabled.version, 1);
  assert.equal(runtime.tools[0]!.backgroundJob?.enabled, true);
  const hydratedRuntime = emptyDeploymentLayer();
  const hydrated = createDeploymentLayerStore({
    backing,
    runtime: hydratedRuntime,
    skills,
    scopeId: scopeId("org", "example"),
  });
  await hydrated.hydrate();
  assert.equal(hydratedRuntime.tools[0]!.backgroundJob?.schema.sha256, profile.schema.sha256);
  const disabledDescriptor = {
    ...descriptor,
    content: JSON.stringify({
      id: DEFINITION.id,
      label: "Report preview",
      backgroundJob: { ...profile, enabled: false },
    }),
  };
  const disabled = await deployment.put({ contract: 1, tools: [disabledDescriptor], skills: [] }, "signed-admin");
  assert.equal(disabled.version, 2);
  assert.equal(runtime.tools[0]!.backgroundJob?.enabled, false);
  const removed = await deployment.put({ contract: 1, tools: [], skills: [] }, "signed-admin");
  assert.equal(removed.version, 3);
  assert.equal(runtime.tools.length, 0);
});

test("public turn route strips internal Slack provenance and privilege-only request fields", () => {
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
