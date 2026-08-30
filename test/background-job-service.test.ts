import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import { publicTurnBody } from "../src/api/routes/turns.ts";
import {
  parseBackgroundJobDeploymentProfile,
  validateBackgroundJobSchemaValue,
} from "../src/background-jobs/deployment-profile.ts";
import { createBackgroundJobCompletionPoller } from "../src/background-jobs/completion-poller.ts";
import {
  backgroundJobApprovalDigest,
  backgroundJobEffectApprovalKey,
  createBackgroundJobProfileService,
  createBackgroundJobRegistry,
} from "../src/background-jobs/service.ts";
import type {
  BackgroundJobAdapter,
  BackgroundJobAdmissionIntent,
  BackgroundJobApprovalGrant,
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

function profileWithSchema(json: unknown) {
  const value = structuredClone(manifest()) as unknown as { schema: { sha256: string; json: unknown } };
  value.schema = { sha256: createHash("sha256").update(canonicalJson(json)).digest("hex"), json };
  return parseBackgroundJobDeploymentProfile(JSON.stringify(value), PROFILE_PATH);
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
    actionTs: "1788030002.123456",
  }),
});

const STANDARD_INPUT = Object.freeze({ recordId: "record-1", receiptIds: Object.freeze(["decision-1"]) });
const STANDARD_APPROVAL_KEY = backgroundJobEffectApprovalKey(profile(), "background_job_start", STANDARD_INPUT);
const INVOCATION: Readonly<BackgroundJobInvocationAuthority> = Object.freeze({
  receiptId: "approval-1",
  approvalKey: STANDARD_APPROVAL_KEY,
  actionTs: TURN.verifiedSlack!.actionTs!,
  slack: Object.freeze({ ...TURN.verifiedSlack! }),
});

function receiptStore(
  options: {
    failBeforeRemote?: boolean;
    beforeRemote?: () => void;
    durableIntent?: (intent: Readonly<BackgroundJobAdmissionIntent>) => Readonly<BackgroundJobAdmissionIntent>;
  } = {},
) {
  let receipt: Readonly<BackgroundJobReceipt> | null = null;
  const controls: unknown[] = [];
  const events: string[] = [];
  let startEffect:
    | ((intent: Readonly<BackgroundJobAdmissionIntent>) => Promise<Readonly<{ authorityId: string; runId: string }>>)
    | undefined;
  let cancelEffect: ((intent: Parameters<BackgroundJobReceiptStore["enqueueControl"]>[0]) => Promise<void>) | undefined;
  let effectAllowed = () => true;
  const value: BackgroundJobReceiptStore = {
    durability: "durable",
    admission: "durable_intent_outbox",
    reconciliation: "automatic_idempotent",
    controls: "durable_intent_outbox",
    readiness: () => ({ ready: true }),
    enqueueAdmission: async (intent) => {
      events.push("intent_persisted");
      if (options.failBeforeRemote) throw new Error("database unavailable");
      options.beforeRemote?.();
      if (!effectAllowed() || !startEffect) throw new Error("effect unavailable");
      const durableIntent = options.durableIntent?.(intent) ?? intent;
      if (canonicalJson(durableIntent) !== canonicalJson(intent)) throw new Error("durable intent changed");
      const admission = await startEffect(durableIntent);
      events.push("admission_recorded");
      const grant = intent.approvalGrant;
      receipt = Object.freeze({
        intentId: intent.intentId,
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
        conversationThreadRef: intent.conversationThreadRef,
        messageTs: intent.messageTs,
        descriptorSha256: intent.descriptorSha256,
        profileSha256: intent.profileSha256,
        schemaSha256: intent.schemaSha256,
        payloadSha256: intent.payloadSha256,
        approvalId: grant.approvalId,
        approvalDigest: grant.digest,
        approvalEffect: "background_job_start",
        approvalKey: grant.approvalKey,
        approvalActionTs: grant.actionTs,
        approvalMessageTs: grant.messageTs,
        approvalThreadTs: grant.threadTs,
        idempotencyKey: intent.idempotencyKey,
        createdAt: intent.createdAt,
      });
      return "persisted";
    },
    leaseAdmissions: async () => [],
    completeAdmission: async () => {
      if (!receipt) throw new Error("missing receipt");
      return receipt;
    },
    retryAdmission: async () => undefined,
    latestOwned: async () => receipt,
    ownedRun: async () => receipt,
    enqueueControl: async (intent) => {
      events.push("control_intent_persisted");
      controls.push({ ...structuredClone(intent), approvalId: intent.approvalGrant.approvalId });
      if (!cancelEffect) throw new Error("effect unavailable");
      await cancelEffect(intent);
      return "persisted";
    },
    leaseControls: async () => [],
    completeControl: async () => undefined,
    retryControl: async () => undefined,
    manualAttention: async () => [],
  };
  return {
    value,
    events,
    controls,
    get: () => receipt,
    replace: (value: Readonly<BackgroundJobReceipt> | null) => {
      receipt = value;
    },
    configure: (input: {
      start: NonNullable<typeof startEffect>;
      cancel: NonNullable<typeof cancelEffect>;
      active: () => boolean;
    }) => {
      startEffect = input.start;
      cancelEffect = input.cancel;
      effectAllowed = input.active;
    },
  };
}

function approvalStore(
  approve = true,
  mutate?: (grant: Readonly<BackgroundJobApprovalGrant>) => Readonly<BackgroundJobApprovalGrant>,
) {
  const consumed = new Set<string>();
  const expectations: BackgroundJobApprovalExpectation[] = [];
  const value: BackgroundJobApprovalStore = {
    durability: "durable",
    consumption: "one_time",
    grants: "verified_immutable",
    retirementFence: "atomic_permanent",
    readiness: () => ({ ready: true }),
    consume: async (authority, expected) => {
      expectations.push(expected);
      if (!approve || consumed.has(authority.receiptId)) return null;
      consumed.add(authority.receiptId);
      const unsigned = {
        approvalId: authority.receiptId,
        approvalKey: authority.approvalKey,
        actionTs: authority.actionTs,
        effect: expected.effect,
        jobId: expected.jobId,
        organizationId: expected.organizationId,
        actorPrincipalId: expected.actorPrincipalId,
        actorSlackId: expected.actorSlackId,
        audienceScopeId: expected.audienceScopeId,
        slackTeamId: expected.slackTeamId,
        channelId: expected.channelId,
        conversationThreadRef: expected.conversationThreadRef,
        threadTs: expected.threadTs,
        messageTs: expected.messageTs,
        descriptorSha256: expected.descriptorSha256,
        profileSha256: expected.profileSha256,
        schemaSha256: expected.schemaSha256,
        payloadSha256: expected.payloadSha256,
        idempotencyKey: expected.idempotencyKey,
        issuedAt: expected.now,
        expiresAt: expected.maximumExpiresAt,
      } as const;
      const grant = Object.freeze({ ...unsigned, digest: backgroundJobApprovalDigest(unsigned) });
      return mutate ? mutate(grant) : grant;
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
  const startGrants: Readonly<BackgroundJobApprovalGrant>[] = [];
  const cancelGrants: Readonly<BackgroundJobApprovalGrant>[] = [];
  const value: BackgroundJobClient<{ state: string }, { state: string }> = {
    start: async (_body, grant) => {
      starts += 1;
      startGrants.push(grant);
      events.push("remote_started");
      return { authorityId: "authority-1", runId: "run-0000001" };
    },
    status: async () => ({ state: "complete" }),
    cancel: async (_receipt, grant) => {
      cancelGrants.push(grant);
      return { state: "cancelling" };
    },
  };
  return { value, starts: () => starts, startGrants, cancelGrants };
}

function service(
  options: {
    active?: () => boolean;
    receipts?: ReturnType<typeof receiptStore>;
    approve?: boolean;
    mutateGrant?: (grant: Readonly<BackgroundJobApprovalGrant>) => Readonly<BackgroundJobApprovalGrant>;
    deployment?: ReturnType<typeof profile>;
    adapter?: ReturnType<typeof adapter>;
  } = {},
) {
  const receipts = options.receipts ?? receiptStore();
  const approvals = approvalStore(options.approve, options.mutateGrant);
  const remote = client(receipts.events);
  const deployment = options.deployment ?? profile();
  const jobAdapter = options.adapter ?? adapter();
  const active = options.active ?? (() => true);
  receipts.configure({
    start: (intent) =>
      remote.value.start(
        Buffer.from(intent.bodyBase64, "base64"),
        intent.approvalGrant,
        intent.idempotencyKey,
        intent.createdAt,
      ),
    cancel: async (intent) => {
      const receipt = receipts.get();
      if (!receipt) throw new Error("receipt unavailable");
      await remote.value.cancel(receipt, intent.approvalGrant, intent.createdAt);
    },
    active,
  });
  const value = createBackgroundJobProfileService({
    deployment,
    adapter: jobAdapter,
    receipts: receipts.value,
    approvals: approvals.value,
    client: remote.value,
    authorityReady: () => true,
    active,
    now: () => 1_788_030_000_000,
  });
  return { value, deployment, receipts, approvals, remote, adapter: jobAdapter };
}

test("start requires an exact fresh invocation receipt and persists the durable intent before remote admission", async () => {
  const built = service();
  const bound = built.value.bind(TURN)!;
  assert.equal(bound.canStart(), true);
  assert.equal((await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }, undefined)).state, "denied");
  assert.equal(built.remote.starts(), 0);
  assert.equal(
    (await bound.start({ recordId: "record-1", receiptIds: ["decision-1"], pricing: "forged" }, INVOCATION)).state,
    "denied",
  );
  assert.equal((await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state, "accepted");
  assert.deepEqual(built.receipts.events, ["intent_persisted", "remote_started", "admission_recorded"]);
  assert.equal(built.receipts.get()!.messageTs, INVOCATION.slack.messageTs);
  assert.equal(built.receipts.get()!.threadTs, INVOCATION.slack.threadTs);
  assert.equal(built.receipts.get()!.descriptorSha256, built.deployment.binding.descriptorSha256);
  assert.equal(built.receipts.get()!.approvalId, INVOCATION.receiptId);
  assert.equal(built.receipts.get()!.approvalEffect, "background_job_start");
  assert.equal(built.receipts.get()!.approvalMessageTs, INVOCATION.slack.messageTs);
  assert.match(built.receipts.get()!.approvalDigest, /^[a-f0-9]{64}$/);
  assert.equal(Object.isFrozen(built.remote.startGrants[0]), true);
  assert.equal(built.approvals.expectations[0]!.effect, "background_job_start");
  assert.equal(built.approvals.expectations[0]!.payloadSha256, built.receipts.get()!.payloadSha256);
  assert.equal(built.approvals.expectations[0]!.maximumExpiresAt - built.approvals.expectations[0]!.now, 5 * 60 * 1000);
  assert.equal(built.approvals.expectations[0]!.messageTs, INVOCATION.slack.messageTs);
  assert.equal((await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state, "denied");
});

test("approval grants are closed, digest-bound to the current Slack act, and immutable before any remote effect", async () => {
  const stale = service({
    mutateGrant: (grant) => {
      const { digest: _digest, ...unsigned } = { ...grant, actionTs: "1788030001.123456" };
      return Object.freeze({ ...unsigned, digest: backgroundJobApprovalDigest(unsigned) });
    },
  });
  assert.equal(
    (await stale.value.bind(TURN)!.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state,
    "denied",
  );
  assert.equal(stale.remote.starts(), 0);
  const badDigest = service({ mutateGrant: (grant) => ({ ...grant, digest: "0".repeat(64) }) });
  assert.equal(
    (await badDigest.value.bind(TURN)!.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state,
    "denied",
  );
  assert.equal(badDigest.remote.starts(), 0);
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
  assert.match(status.cardDeliveryKey!, /^background-job-card:[a-f0-9]{64}$/);
  const visible = JSON.stringify(status.card);
  assert.match(visible, /Report/);
  assert.doesNotMatch(visible, /Evaluation|evaluation-1|[de]{64}|sha256/i);
  const cancelInvocation = {
    ...INVOCATION,
    receiptId: "approval-cancel",
    approvalKey: backgroundJobEffectApprovalKey(built.deployment, "background_job_cancel", {
      authorityId: built.receipts.get()!.authorityId,
      runId: built.receipts.get()!.runId,
    }),
  };
  assert.equal((await bound.cancel(cancelInvocation)).state, "cancel_requested");
  assert.equal(built.approvals.expectations[1]!.effect, "background_job_cancel");
  assert.equal(built.remote.cancelGrants[0]!.approvalId, cancelInvocation.receiptId);
  assert.equal(built.remote.cancelGrants[0]!.messageTs, cancelInvocation.slack.messageTs);
  assert.notEqual(built.remote.cancelGrants[0]!.approvalId, built.receipts.get()!.approvalId);
  assert.equal((built.receipts.controls[0] as { approvalId: string }).approvalId, cancelInvocation.receiptId);
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

test("the automatic completion poller durably reconciles one-time owner-thread delivery across restart", async () => {
  const built = service();
  const bound = built.value.bind(TURN)!;
  assert.equal((await bound.start({ recordId: "record-1", receiptIds: ["decision-1"] }, INVOCATION)).state, "accepted");
  const disabled = profile(manifest(), false);
  let terminal = false;
  let failTerminalOnce = true;
  const deliveries = new Map<string, unknown>();
  const visible: string[] = [];
  const completionReceipts = {
    durability: "durable" as const,
    polling: "bounded_active_only" as const,
    terminalTransition: "after_delivery_outbox" as const,
    leaseActive: async (jobId: string, _now: number, limit: number, leaseId: string, leaseExpiresAt: number) => {
      assert.equal(jobId, disabled.definition.id);
      assert.ok(limit <= 10);
      return terminal
        ? []
        : [{ receipt: built.receipts.get()!, leaseId, leaseExpiresAt, attempt: 1, failureAttempt: 0 }];
    },
    retry: async () => undefined,
    manualAttention: async () => [],
    terminal: async (
      receipt: BackgroundJobReceipt,
      _leaseId: string,
      state: "complete" | "failed" | "cancelled",
      deliveryKey: string,
    ) => {
      assert.equal(receipt.runId, "run-0000001");
      assert.equal(state, "complete");
      assert.match(deliveryKey, /^background-job-delivery:[a-f0-9]{64}$/);
      if (failTerminalOnce) {
        failTerminalOnce = false;
        throw new Error("restart after delivery persistence");
      }
      terminal = true;
    },
  };
  const outbox = {
    durability: "durable" as const,
    admission: "persist_before_send" as const,
    reconciliation: "automatic_idempotent_delivery" as const,
    transport: "slack_first_party_render_only" as const,
    rawFallback: "forbidden" as const,
    readiness: () => ({ ready: true as const }),
    enqueue: async (
      intent: Parameters<import("../src/background-jobs/types.ts").BackgroundJobDeliveryOutbox["enqueue"]>[0],
    ) => {
      if (deliveries.has(intent.deliveryKey)) return "already_persisted" as const;
      deliveries.set(intent.deliveryKey, structuredClone(intent));
      visible.push(JSON.stringify({ text: intent.text, card: intent.card }));
      return "persisted" as const;
    },
    lease: async () => [],
    sent: async () => undefined,
    retry: async () => undefined,
    manualAttention: async () => [],
  };
  const dependencies = {
    profiles: () => [disabled],
    resolve: () => ({ receipts: completionReceipts, client: built.remote.value, adapter: built.adapter }),
    outbox,
    batchSize: 10,
    intervalMs: 1_000,
    now: () => 1_788_030_100_000,
  };
  assert.equal(await createBackgroundJobCompletionPoller(dependencies).runOnce(), 0);
  assert.equal(deliveries.size, 1);
  assert.equal(visible.length, 1);
  const restarted = createBackgroundJobCompletionPoller(dependencies);
  assert.equal(await restarted.runOnce(), 1);
  assert.equal(await restarted.runOnce(), 0);
  assert.equal(deliveries.size, 1);
  assert.equal(visible.length, 1);
  const delivered = [...deliveries.values()][0] as Record<string, unknown>;
  assert.equal(delivered.organizationId, disabled.profile.organizationId);
  assert.equal(delivered.actorSlackId, disabled.profile.actorSlackId);
  assert.equal(delivered.channelId, disabled.profile.channelId);
  assert.equal(delivered.threadTs, INVOCATION.slack.threadTs);
  assert.equal(delivered.messageTs, INVOCATION.slack.messageTs);
  assert.equal(delivered.runId, "run-0000001");
  assert.doesNotMatch(visible[0]!, /Evaluation|evaluation-1|sha256|prompt|tool|model|[de]{64}/i);
  restarted.start();
  restarted.stop();
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

test("the closed schema subset rejects patterns, malformed or cyclic refs, unsafe numbers, false dates, and non-HTTPS URIs", () => {
  const schemaWith = (property: unknown, defs?: unknown) => ({
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    additionalProperties: false,
    properties: { value: property },
    required: ["value"],
    ...(defs === undefined ? {} : { $defs: defs }),
  });
  assert.throws(() => profileWithSchema(schemaWith({ type: "string", maxLength: 100, pattern: "^(a+)+$" })));
  assert.throws(() =>
    profileWithSchema(schemaWith({ $ref: "#/$defsX/Value" }, { Value: { type: "string", maxLength: 10 } })),
  );
  assert.throws(() =>
    profileWithSchema(
      schemaWith({ $ref: "#/$defs/First" }, { First: { $ref: "#/$defs/Second" }, Second: { $ref: "#/$defs/First" } }),
    ),
  );
  const shared: Record<string, unknown> = {};
  for (let index = 0; index < 16; index += 1) {
    shared[`Shared${index}`] =
      index === 15 ? { type: "string", maxLength: 10 } : { $ref: `#/$defs/Shared${index + 1}` };
  }
  for (let index = 0; index < 20; index += 1) {
    shared[`Long${index}`] = { $ref: index === 19 ? "#/$defs/Shared0" : `#/$defs/Long${index + 1}` };
  }
  assert.throws(() => profileWithSchema(schemaWith({ $ref: "#/$defs/Long0" }, shared)));
  const datetime = profileWithSchema(schemaWith({ type: "string", format: "date-time", maxLength: 40 }));
  validateBackgroundJobSchemaValue(datetime.schema.json, { value: "2024-02-29T23:59:59Z" });
  assert.throws(() => validateBackgroundJobSchemaValue(datetime.schema.json, { value: "2025-02-29T23:59:59Z" }));
  assert.throws(() => profileWithSchema(schemaWith({ type: "string", format: "uri", maxLength: 200 })));
  assert.throws(() => profileWithSchema(schemaWith({ type: "string", format: "hostname", maxLength: 200 })));
  const number = profileWithSchema(schemaWith({ type: "number", minimum: 0, maximum: 100 }));
  validateBackgroundJobSchemaValue(number.schema.json, { value: 100 });
  assert.throws(() => validateBackgroundJobSchemaValue(number.schema.json, { value: 1.5 }));
  assert.throws(() =>
    profileWithSchema(schemaWith({ type: "integer", minimum: 0, maximum: Number.MAX_SAFE_INTEGER + 1 })),
  );
  const referenced = profileWithSchema(
    schemaWith({ $ref: "#/$defs/Value" }, { Value: { type: "string", maxLength: 10 } }),
  );
  validateBackgroundJobSchemaValue(referenced.schema.json, { value: "bounded" });
});

test("the deployment store durably tombstones removals and restores owner control configuration on restart", async () => {
  const backing = createMemoryMap<StoredDeploymentLayer>();
  const skills = createSkillStore({ signingSecret: "background-job-layer-test" });
  const runtime = emptyDeploymentLayer();
  let terminalAndExpired = false;
  let fenceDigest = "f".repeat(64);
  const retirement = {
    durability: "durable" as const,
    receiptCoverage: "all_owned" as const,
    approvalCoverage: "all_unused" as const,
    retiredIdLedger: "permanent" as const,
    approvalIssuanceFence: "atomic" as const,
    retireAndFenceApprovalIssuance: async (candidate: ReturnType<typeof profile>) => ({
      jobId: candidate.definition.id,
      descriptorSha256: candidate.binding.descriptorSha256,
      approvalFenceDigest: fenceDigest,
      retiredAt: 1_788_030_000_000,
      terminalAndExpired,
    }),
  };
  const deployment = createDeploymentLayerStore({
    backing,
    runtime,
    skills,
    scopeId: scopeId("org", "example"),
    backgroundJobRetirement: retirement,
  });
  const job = { path: PROFILE_PATH, content: JSON.stringify(manifest()) };
  await assert.rejects(
    deployment.put(
      { contract: 1, tools: [], skills: [], backgroundJobs: [{ ...job, executable: true }] },
      "signed-admin",
    ),
    /entries require/,
  );
  const installed = await deployment.put({ contract: 1, tools: [], skills: [], backgroundJobs: [job] }, "signed-admin");
  assert.equal(installed.contentHash, createHash("sha256").update(JSON.stringify(installed.bundle)).digest("hex"));
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
  assert.equal(record!.retiredBackgroundJobs!.length, 1);
  assert.equal(record!.contentHash, createHash("sha256").update(JSON.stringify(record!.bundle)).digest("hex"));
  fenceDigest = "0".repeat(64);
  await assert.rejects(
    deployment.put({ contract: 1, tools: [], skills: [], backgroundJobs: [] }, "signed-admin"),
    /permanent retirement ledger changed/,
  );
  fenceDigest = "f".repeat(64);
  const hydratedRuntime = emptyDeploymentLayer();
  const hydrated = createDeploymentLayerStore({
    backing,
    runtime: hydratedRuntime,
    skills,
    scopeId: scopeId("org", "example"),
    backgroundJobRetirement: retirement,
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
  terminalAndExpired = true;
  await deployment.put({ contract: 1, tools: [], skills: [], backgroundJobs: [] }, "signed-admin");
  assert.equal(runtime.backgroundJobs.length, 0);
  const cleaned = (await deployment.get())!;
  assert.equal(cleaned.retiredBackgroundJobs!.length, 1);
  assert.equal(cleaned.contentHash, createHash("sha256").update(JSON.stringify(cleaned.bundle)).digest("hex"));
  await assert.rejects(
    deployment.put({ contract: 1, tools: [], skills: [], backgroundJobs: [job] }, "signed-admin"),
    /permanently retired/,
  );
});

test("retirement cannot disable or remove a profile without the durable atomic approval fence", async () => {
  const backing = createMemoryMap<StoredDeploymentLayer>();
  const runtime = emptyDeploymentLayer();
  const deployment = createDeploymentLayerStore({
    backing,
    runtime,
    skills: createSkillStore({ signingSecret: "background-job-fence-test" }),
    scopeId: scopeId("org", "example"),
  });
  const job = { path: PROFILE_PATH, content: JSON.stringify(manifest()) };
  await deployment.put({ contract: 1, tools: [], skills: [], backgroundJobs: [job] }, "signed-admin");
  await assert.rejects(
    deployment.put(
      { contract: 1, tools: [], skills: [], backgroundJobs: [{ ...job, enabled: false }] },
      "signed-admin",
    ),
    /durable atomic approval fence/,
  );
  await assert.rejects(
    deployment.put({ contract: 1, tools: [], skills: [], backgroundJobs: [] }, "signed-admin"),
    /durable atomic approval fence/,
  );
  assert.equal(runtime.backgroundJobs[0]!.enabled, true);
  assert.equal((await deployment.get())!.retiredBackgroundJobs, undefined);
});

test("terminal receipts and expired approvals permit explicit durable tombstone cleanup", async () => {
  const backing = createMemoryMap<StoredDeploymentLayer>();
  const skills = createSkillStore({ signingSecret: "background-job-retirement-test" });
  const runtime = emptyDeploymentLayer();
  let terminalAndExpired = false;
  const retirement = {
    durability: "durable" as const,
    receiptCoverage: "all_owned" as const,
    approvalCoverage: "all_unused" as const,
    retiredIdLedger: "permanent" as const,
    approvalIssuanceFence: "atomic" as const,
    retireAndFenceApprovalIssuance: async (candidate: ReturnType<typeof profile>) => ({
      jobId: candidate.definition.id,
      descriptorSha256: candidate.binding.descriptorSha256,
      approvalFenceDigest: "e".repeat(64),
      retiredAt: 1_788_030_000_000,
      terminalAndExpired,
    }),
  };
  const base = createDeploymentLayerStore({
    backing,
    runtime,
    skills,
    scopeId: scopeId("org", "example"),
    backgroundJobRetirement: retirement,
  });
  const job = { path: PROFILE_PATH, content: JSON.stringify(manifest()) };
  await base.put({ contract: 1, tools: [], skills: [], backgroundJobs: [job] }, "signed-admin");
  const descriptorSha256 = runtime.backgroundJobs[0]!.binding.descriptorSha256;
  await base.put({ contract: 1, tools: [], skills: [], backgroundJobs: [] }, "signed-admin");
  assert.equal(runtime.backgroundJobs[0]!.enabled, false);
  terminalAndExpired = true;
  const cleanup = createDeploymentLayerStore({
    backing,
    runtime,
    skills,
    scopeId: scopeId("org", "example"),
    backgroundJobRetirement: retirement,
  });
  await cleanup.hydrate();
  await cleanup.put({ contract: 1, tools: [], skills: [], backgroundJobs: [] }, "signed-admin");
  assert.equal(runtime.backgroundJobs.length, 0);
  assert.equal((await cleanup.get())!.bundle.backgroundJobs!.length, 0);
  assert.equal((await cleanup.get())!.retiredBackgroundJobs![0]!.descriptorSha256, descriptorSha256);
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
