import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { GetPublicKeyCommand, KeyUsageType, SigningAlgorithmSpec, type KMSClient } from "@aws-sdk/client-kms";
import { test } from "node:test";
import { createDurableBackgroundJobApprovalLedger } from "../src/background-jobs/approval-ledger.ts";
import { createBackgroundJobCompletionPoller } from "../src/background-jobs/completion-poller.ts";
import { parseBackgroundJobDeploymentProfile } from "../src/background-jobs/deployment-profile.ts";
import { createBackgroundJobDeliveryScheduler } from "../src/background-jobs/delivery-sender.ts";
import {
  createDurableBackgroundJobDeliveryOutbox,
  createDurableBackgroundJobStore,
  type BackgroundJobDeliveryRecord,
  type BackgroundJobDurableRecord,
} from "../src/background-jobs/durable-store.ts";
import { createBackgroundJobEffectReconciler } from "../src/background-jobs/effect-reconciler.ts";
import { backgroundJobEffectApprovalKey, createBackgroundJobProfileService } from "../src/background-jobs/service.ts";
import { createProductionBackgroundJobRuntime } from "../src/background-jobs/runtime.ts";
import type { BackgroundJobAuthorityStageRecord } from "../src/background-jobs/staged-authority.ts";
import type {
  BackgroundJobAdapter,
  BackgroundJobClient,
  BackgroundJobInvocationAuthority,
  BackgroundJobRenderOnlySender,
  BackgroundJobTurnBinding,
} from "../src/background-jobs/types.ts";
import type { BackgroundJobApprovalLedgerRecord } from "../src/background-jobs/approval-ledger.ts";
import { canonicalJson } from "../src/cron/schedule-authority.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";

function deployment() {
  const schema = {
    type: "object",
    additionalProperties: false,
    properties: { decisionId: { type: "string", maxLength: 100 } },
    required: ["decisionId"],
  };
  return parseBackgroundJobDeploymentProfile(
    JSON.stringify({
      contract: 1,
      definition: {
        id: "durable-report",
        operation: "durable_report",
        capability: "reports.create",
        scope: "jobs:submit",
        tokenType: "job-authority+jwt",
        authorityHeader: "x-job-authority",
        start: { path: "/jobs/start", maxRequestBytes: 1024 },
        status: { path: "/jobs/status", maxRequestBytes: 512 },
        cancel: { path: "/jobs/cancel", maxRequestBytes: 512 },
      },
      issuer: "https://gateway.example.com/authority",
      audience: "https://jobs.example.com/authority",
      origin: "https://jobs.example.com",
      artifactPathPrefix: "/artifacts/",
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
        start: { id: "durable-report", label: "Create durable report" },
        status: { id: "durable-report-status", label: "Check durable report" },
        cancel: { id: "durable-report-cancel", label: "Cancel durable report" },
      },
      approval: { start: "invocation_receipt", cancel: "invocation_receipt" },
      schema: { sha256: createHash("sha256").update(canonicalJson(schema)).digest("hex"), json: schema },
      binding: undefined,
      artifacts: [{ kind: "report", label: "Report", visibility: "primary" }],
      dependencies: {
        adapter: "native-compiler",
        receiptStore: "durable-receipts",
        approvalStore: "durable-approvals",
        authority: "kms-rs256-v1",
      },
    }),
    "background-jobs/durable-report/job.json",
  );
}

function adapter(): BackgroundJobAdapter<{ decisionId: string }, { state: string }, { state: string }> {
  return {
    readiness: () => ({ ready: true }),
    parseInput: (value) => {
      if (
        !value ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        typeof (value as { decisionId?: unknown }).decisionId !== "string"
      ) {
        throw new Error("invalid");
      }
      return { decisionId: (value as { decisionId: string }).decisionId };
    },
    prepare: async (input) => ({
      bodyBytes: Buffer.from(canonicalJson(input)),
      idempotencyKey: `decision:${input.decisionId}`,
    }),
    statusView: (value) => ({
      state: value.state as "complete",
      artifacts: [
        {
          kind: "report",
          href: "https://jobs.example.com/artifacts/report-1",
          sha256: "a".repeat(64),
        },
      ],
    }),
    cancellationState: () => "cancel_requested",
  };
}

test("durable effects reconcile crash-before-effect, remote ack loss, restart, cancellation, and render-only delivery", async () => {
  const profile = deployment();
  const records = createMemoryMap<BackgroundJobDurableRecord>();
  const deliveries = createMemoryMap<BackgroundJobDeliveryRecord>();
  const approvalsBacking = createMemoryMap<BackgroundJobApprovalLedgerRecord>();
  const receipts = createDurableBackgroundJobStore(records, true);
  const outbox = createDurableBackgroundJobDeliveryOutbox(deliveries, true);
  let now = 1_788_030_002_000;
  const approvals = createDurableBackgroundJobApprovalLedger({
    backing: approvalsBacking,
    durable: true,
    now: () => now,
    terminalAndExpired: async () => false,
  });
  const starts = new Map<string, { authorityId: string; runId: string }>();
  const cancellations = new Set<string>();
  let startCalls = 0;
  let cancelCalls = 0;
  let loseStartAck = true;
  let loseCancelAck = true;
  const client: BackgroundJobClient<{ state: string }, { state: string }> = {
    start: async (_body, _grant, idempotencyKey) => {
      startCalls += 1;
      const admission = starts.get(idempotencyKey) ?? { authorityId: "authority-1", runId: "run-1" };
      starts.set(idempotencyKey, admission);
      if (loseStartAck) {
        loseStartAck = false;
        throw new Error("remote start acknowledgement lost");
      }
      return admission;
    },
    status: async () => ({ state: "complete" }),
    cancel: async (receipt) => {
      cancelCalls += 1;
      cancellations.add(`${receipt.authorityId}:${receipt.runId}`);
      if (loseCancelAck) {
        loseCancelAck = false;
        throw new Error("remote cancel acknowledgement lost");
      }
      return { state: "cancel_requested" };
    },
  };
  const jobAdapter = adapter();
  const service = createBackgroundJobProfileService({
    deployment: profile,
    adapter: jobAdapter,
    receipts,
    approvals,
    client,
    authorityReady: () => true,
    active: () => true,
    now: () => now,
  });
  const slack = Object.freeze({
    teamId: "TTEAM01",
    userId: "UOWNER1",
    channelId: "DOWNER1",
    messageTs: "1788030001.000000",
    threadTs: "1788030001.000000",
    threaded: false,
    liveHuman: true as const,
    actionTs: "1788030002.000000",
  });
  const turn: Readonly<BackgroundJobTurnBinding> = Object.freeze({
    surface: "slack",
    actorId: "principal_owner",
    actorType: "internal",
    conversationKind: "dm",
    conversationThreadRef: "dm:DOWNER1",
    conversationAudienceIds: Object.freeze(["principal_owner"]),
    originKind: "human",
    originMessageTs: slack.messageTs,
    verifiedSlack: slack,
  });
  const input = Object.freeze({ decisionId: "decision-1" });
  const startAuthority: Readonly<BackgroundJobInvocationAuthority> = Object.freeze({
    receiptId: "approval-start-1",
    approvalKey: backgroundJobEffectApprovalKey(profile, "background_job_start", input),
    actionTs: slack.actionTs,
    slack,
  });
  const bound = service.bind(turn)!;
  assert.equal((await bound.start(input, startAuthority)).state, "accepted");
  assert.equal(startCalls, 0);
  const admissionRecord = (await records.all()).find((record) => record.kind === "admission");
  assert.ok(admissionRecord?.kind === "admission");
  const expectedApproval = {
    effect: "background_job_start" as const,
    jobId: profile.definition.id,
    ...profile.profile,
    threadTs: slack.threadTs,
    conversationThreadRef: turn.conversationThreadRef,
    messageTs: slack.messageTs,
    approvalKey: startAuthority.approvalKey,
    actionTs: startAuthority.actionTs,
    ...profile.binding,
    payloadSha256: admissionRecord.intent.payloadSha256,
    idempotencyKey: admissionRecord.intent.idempotencyKey,
    now,
    maximumExpiresAt: now + 5 * 60_000,
  };
  assert.equal(await approvals.consume(startAuthority, expectedApproval), null);
  assert.equal(
    await approvals.consume({ ...startAuthority, receiptId: "approval-start-replayed" }, expectedApproval),
    null,
  );
  const runtime = { receipts, client, adapter: jobAdapter };
  const reconcile = () =>
    createBackgroundJobEffectReconciler({
      profiles: () => [profile],
      resolve: () => runtime,
      intervalMs: 1_000,
      now: () => now,
      randomId: () => "lease-1",
    });
  assert.equal(await reconcile().runOnce(), 0);
  assert.equal(starts.size, 1);
  assert.equal(startCalls, 1);
  assert.equal(
    await receipts.latestOwned(profile.definition.id, {
      ...profile.profile,
      threadTs: slack.threadTs,
      conversationThreadRef: turn.conversationThreadRef,
    }),
    null,
  );
  now += 1_000;
  assert.equal(await reconcile().runOnce(), 1);
  assert.equal(startCalls, 2);
  const receipt = await receipts.latestOwned(profile.definition.id, {
    ...profile.profile,
    threadTs: slack.threadTs,
    conversationThreadRef: turn.conversationThreadRef,
  });
  assert.ok(receipt);
  assert.equal(await reconcile().runOnce(), 0);
  now = 1_788_030_004_000;
  const cancelSlack = Object.freeze({
    ...slack,
    messageTs: "1788030003.000000",
    threadTs: "1788030003.000000",
    actionTs: "1788030004.000000",
  });
  const cancelBound = service.bind(
    Object.freeze({
      ...turn,
      originMessageTs: cancelSlack.messageTs,
      verifiedSlack: cancelSlack,
    }),
  )!;
  const cancelValue = { authorityId: receipt.authorityId, runId: receipt.runId };
  const cancelAuthority: Readonly<BackgroundJobInvocationAuthority> = Object.freeze({
    receiptId: "approval-cancel-1",
    approvalKey: backgroundJobEffectApprovalKey(profile, "background_job_cancel", cancelValue),
    actionTs: cancelSlack.actionTs,
    slack: cancelSlack,
  });
  assert.equal((await cancelBound.cancel(cancelAuthority)).state, "cancel_requested");
  assert.equal(cancelCalls, 0);
  assert.equal(await reconcile().runOnce(), 0);
  now += 1_000;
  assert.equal(await reconcile().runOnce(), 1);
  assert.equal(cancelCalls, 2);
  assert.equal(cancellations.size, 1);
  let terminalAttempt = 0;
  const completionReceipts = {
    ...receipts,
    terminal: async (...args: Parameters<typeof receipts.terminal>) => {
      terminalAttempt += 1;
      if (terminalAttempt === 1) throw new Error("restart after delivery persistence");
      await receipts.terminal(...args);
      if (terminalAttempt === 2) throw new Error("completion acknowledgement lost");
    },
  };
  const completion = createBackgroundJobCompletionPoller({
    profiles: () => [profile],
    resolve: () => ({ ...runtime, receipts: completionReceipts }),
    outbox,
    intervalMs: 1_000,
    now: () => now,
    randomId: () => "completion-lease-1",
  });
  assert.equal(await completion.runOnce(), 0);
  assert.equal((await deliveries.all()).length, 1);
  assert.equal(await completion.runOnce(), 0);
  now += 1_000;
  assert.equal(await completion.runOnce(), 0);
  assert.equal(await completion.runOnce(), 0);
  assert.equal((await deliveries.all()).length, 1);
  const sent = new Set<string>();
  const sender: BackgroundJobRenderOnlySender = {
    transport: "slack_first_party_render_only",
    rawFallback: "forbidden",
    idempotency: "durable_delivery_key",
    readiness: () => ({ ready: true }),
    send: async (intent, deliveryKey) => {
      assert.equal(intent.deliveryKey, deliveryKey);
      sent.add(deliveryKey);
    },
  };
  const scheduler = createBackgroundJobDeliveryScheduler({
    outbox: createDurableBackgroundJobDeliveryOutbox(deliveries, true),
    sender,
    intervalMs: 1_000,
    now: () => now,
    randomId: () => "delivery-lease-1",
  });
  assert.equal(await scheduler.runOnce(), 1);
  assert.equal(await scheduler.runOnce(), 0);
  assert.equal(sent.size, 1);
  assert.equal(JSON.stringify(await deliveries.all()).includes("bodyBase64"), false);
});

test("retirement fences approval issuance before checking terminal state", async () => {
  const profile = deployment();
  const backing = createMemoryMap<BackgroundJobApprovalLedgerRecord>();
  let checked = false;
  const ledger = createDurableBackgroundJobApprovalLedger({
    backing,
    durable: true,
    now: () => 1_788_030_002_000,
    terminalAndExpired: async () => {
      checked = true;
      const fenced = await backing.get(profile.definition.id);
      assert.ok(fenced?.retirement);
      return true;
    },
  });
  const retired = await ledger.retireAndFenceApprovalIssuance(profile);
  assert.equal(checked, true);
  assert.equal(retired.terminalAndExpired, true);
});

test("delivery scheduling isolates a bad row and retries it without blocking the batch", async () => {
  const profile = deployment();
  const backing = createMemoryMap<BackgroundJobDeliveryRecord>();
  const outbox = createDurableBackgroundJobDeliveryOutbox(backing, true);
  let now = 1_788_030_100_000;
  const intent = (deliveryKey: string, runId: string) => ({
    deliveryKey,
    jobId: profile.definition.id,
    authorityId: "authority-1",
    runId,
    ...profile.profile,
    ...profile.binding,
    messageTs: "1788030001.000000",
    threadTs: "1788030001.000000",
    conversationThreadRef: "dm:DOWNER1",
    state: "complete" as const,
    text: "The report is ready.",
    createdAt: now,
  });
  await outbox.enqueue(intent("delivery-bad", "run-bad"));
  await outbox.enqueue(intent("delivery-good", "run-good"));
  let failBad = true;
  const sent: string[] = [];
  const scheduler = createBackgroundJobDeliveryScheduler({
    outbox,
    sender: {
      transport: "slack_first_party_render_only",
      rawFallback: "forbidden",
      idempotency: "durable_delivery_key",
      readiness: () => ({ ready: true }),
      send: async (value) => {
        if (value.runId === "run-bad" && failBad) throw new Error("bad row");
        sent.push(value.deliveryKey);
      },
    },
    intervalMs: 1_000,
    now: () => now,
    randomId: () => "delivery-isolation",
  });
  assert.equal(await scheduler.runOnce(), 1);
  assert.deepEqual(sent, ["delivery-good"]);
  failBad = false;
  now += 1_000;
  assert.equal(await scheduler.runOnce(), 1);
  assert.deepEqual(sent, ["delivery-good", "delivery-bad"]);
});

test("delivery acknowledgement loss does not invoke an idempotent sender twice after restart", async () => {
  const profile = deployment();
  const backing = createMemoryMap<BackgroundJobDeliveryRecord>();
  const durable = createDurableBackgroundJobDeliveryOutbox(backing, true);
  const deliveryKey = "delivery-ack-loss";
  await durable.enqueue({
    deliveryKey,
    jobId: profile.definition.id,
    authorityId: "authority-1",
    runId: "run-ack-loss",
    ...profile.profile,
    ...profile.binding,
    messageTs: "1788030001.000000",
    threadTs: "1788030001.000000",
    conversationThreadRef: "dm:DOWNER1",
    state: "complete",
    text: "The report is ready.",
    createdAt: 1_788_030_100_000,
  });
  let loseAck = true;
  const outbox = {
    ...durable,
    sent: async (...args: Parameters<typeof durable.sent>) => {
      await durable.sent(...args);
      if (loseAck) {
        loseAck = false;
        throw new Error("delivery acknowledgement lost");
      }
    },
  };
  const delivered = new Set<string>();
  let calls = 0;
  const scheduler = () =>
    createBackgroundJobDeliveryScheduler({
      outbox,
      sender: {
        transport: "slack_first_party_render_only",
        rawFallback: "forbidden",
        idempotency: "durable_delivery_key",
        readiness: () => ({ ready: true }),
        send: async (_intent, key) => {
          calls += 1;
          delivered.add(key);
        },
      },
      intervalMs: 1_000,
      now: () => 1_788_030_100_000,
      randomId: () => "delivery-ack-loss",
    });
  assert.equal(await scheduler().runOnce(), 0);
  assert.equal(await scheduler().runOnce(), 0);
  assert.equal(calls, 1);
  assert.deepEqual([...delivered], [deliveryKey]);
});

test("production composition exposes only fully healthy named durable profiles and wires JWKS", async () => {
  const profile = deployment();
  let profiles = [profile];
  const receipts = createDurableBackgroundJobStore(createMemoryMap<BackgroundJobDurableRecord>(), true);
  const outbox = createDurableBackgroundJobDeliveryOutbox(createMemoryMap<BackgroundJobDeliveryRecord>(), true);
  const approvals = createDurableBackgroundJobApprovalLedger({
    backing: createMemoryMap<BackgroundJobApprovalLedgerRecord>(),
    durable: true,
    terminalAndExpired: async () => true,
  });
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const raw = pair.publicKey.export({ format: "jwk" });
  const publicJwk = { kty: "RSA", alg: "RS256", use: "sig", kid: "runtime-key-1", n: raw.n, e: raw.e };
  const kms = {
    async send(command: unknown) {
      if (!(command instanceof GetPublicKeyCommand)) throw new Error("unexpected command");
      return {
        PublicKey: pair.publicKey.export({ format: "der", type: "spki" }),
        KeyUsage: KeyUsageType.SIGN_VERIFY,
        SigningAlgorithms: [SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256],
      };
    },
  } as unknown as KMSClient;
  const sender: BackgroundJobRenderOnlySender = {
    transport: "slack_first_party_render_only",
    rawFallback: "forbidden",
    idempotency: "durable_delivery_key",
    readiness: () => ({ ready: true }),
    send: async () => undefined,
  };
  let registryReady = true;
  const registry = {
    readiness: () => (registryReady ? { ready: true as const } : { ready: false as const }),
    resolveAdapter: (name: string) =>
      name === profile.dependencies.adapter
        ? {
            adapter: adapter() as BackgroundJobAdapter<unknown, unknown, unknown>,
            parsers: {
              admission: (value: unknown) => value as { authorityId: string; runId: string },
              status: (value: unknown) => value as { runId: string },
              cancellation: (value: unknown) => value as { runId: string },
              statusRunId: (value: unknown) => (value as { runId: string }).runId,
              cancellationRunId: (value: unknown) => (value as { runId: string }).runId,
            },
          }
        : undefined,
    resolveAuthority: () => ({
      active: { keyId: "kms-runtime-key-1", tokenKid: "runtime-key-1", publicJwk },
      kms: { kms },
    }),
  };
  const runtime = createProductionBackgroundJobRuntime({
    profiles: () => profiles,
    receiptStoreName: profile.dependencies.receiptStore,
    approvalStoreName: profile.dependencies.approvalStore,
    receipts,
    approvals,
    outbox,
    sender,
    authorityStages: createMemoryMap<BackgroundJobAuthorityStageRecord>(),
    durable: true,
    registry,
  });
  assert.deepEqual(runtime.visibleProfiles(), []);
  await runtime.ready();
  assert.deepEqual(runtime.visibleProfiles(), [{ profileId: profile.definition.id, label: profile.tools.start.label }]);
  assert.equal(runtime.service.readiness().ready, true);
  assert.deepEqual(
    runtime.jwks().keys.map((key) => key.kid),
    ["runtime-key-1"],
  );
  registryReady = false;
  assert.deepEqual(runtime.visibleProfiles(), []);
  assert.equal(runtime.service.readiness().ready, false);
  registryReady = true;
  profiles = [{ ...profile, enabled: false }];
  assert.deepEqual(runtime.visibleProfiles(), []);
  assert.equal(runtime.service.bind({} as BackgroundJobTurnBinding).length, 0);
  profiles = [];
  assert.deepEqual(runtime.visibleProfiles(), []);
  assert.equal(runtime.service.bind({} as BackgroundJobTurnBinding).length, 0);
  profiles = [profile];
  const unavailable = createProductionBackgroundJobRuntime({
    profiles: () => [profile],
    receiptStoreName: profile.dependencies.receiptStore,
    approvalStoreName: profile.dependencies.approvalStore,
    receipts,
    approvals,
    outbox,
    sender,
    authorityStages: createMemoryMap<BackgroundJobAuthorityStageRecord>(),
    durable: true,
    registry: { ...registry, readiness: () => ({ ready: false as const }) },
  });
  await unavailable.ready();
  assert.deepEqual(unavailable.visibleProfiles(), []);
  assert.equal(unavailable.service.readiness().ready, false);
  assert.equal(unavailable.blockedProfiles()[profile.definition.id], "durable_dependencies_unavailable");
});
