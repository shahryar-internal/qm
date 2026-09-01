import { test } from "node:test";
import assert from "node:assert/strict";
import { createDeliveryStore } from "../src/delivery/delivery-store.ts";
import { createSurfaceToolDeps } from "../src/core/orchestrator/surface-tools.ts";
import { createToolContext, type ToolContextDeps } from "../src/tools/primitives.ts";
import { uploadAttachments } from "../src/slack/attachments.ts";
import type { BlobTransferStore } from "../src/persistence/blob-transfer.ts";
import type { BoundBackgroundJobTools, WorkflowCardEnvelope } from "../src/background-jobs/types.ts";

const CARD: Readonly<WorkflowCardEnvelope> = Object.freeze({
  version: 1,
  renderer: "qm.card.v1",
  fallbackText: "Report ready",
  payload: Object.freeze({
    heading: "Report ready",
    summary: "The source-backed report is ready for review.",
    status: Object.freeze({ label: "Completed", tone: "success" }),
    sections: Object.freeze([
      Object.freeze({
        key: "artifacts",
        label: "Artifacts",
        items: Object.freeze([
          Object.freeze({ label: "Report", value: "Open", href: "https://jobs.example/artifacts/report-1" }),
          Object.freeze({ label: "Sources", value: "Open", href: "https://jobs.example/artifacts/sources-1" }),
        ]),
      }),
    ]),
  }),
});

test("generic job cards travel through first-party delivery and render as Slack Block Kit without raw envelopes", async () => {
  const deliveries = createDeliveryStore();
  const blobs = new Map<string, Buffer>();
  const blobTransfer: BlobTransferStore = {
    async put(source, options) {
      const bytes = Buffer.from(source as Uint8Array);
      assert.ok(bytes.length <= (options?.maxBytes ?? Number.MAX_SAFE_INTEGER));
      const blobId = "1".padStart(32, "0");
      blobs.set(blobId, bytes);
      return { blobId, sizeBytes: bytes.length, sha256: "a".repeat(64) };
    },
    async open() {
      return null;
    },
    async delete(id) {
      blobs.delete(id);
    },
    async sweep() {
      return 0;
    },
  };
  const surface = createSurfaceToolDeps({
    deps: { deliveries } as never,
    input: { surfaceTools: true, surface: "slack" } as never,
    actor: { id: "principal_owner", type: "internal" },
    conversation: {
      kind: "dm",
      threadRef: "dm:DOWNER1:1788030000.123456",
      audience: [{ id: "principal_owner", type: "internal" }],
    },
    session: {
      id: "session-1",
      type: "dm",
      scopeId: "personal:principal_owner",
      threadRef: "dm:DOWNER1:1788030000.123456",
      createdAt: 1,
    },
    scopeId: "personal:principal_owner",
    strictReadOnly: false,
    defaultDestination: {
      type: "slack",
      target: "DOWNER1:1788030000.123456",
      audienceScopeId: "personal:principal_owner",
    },
    blobTransfer,
    fileRegistration: {} as never,
    provision: async () => {
      throw new Error("unused");
    },
    postProvenance: (key) => ({
      trigger: "direct",
      surface: "slack",
      fireKey: key,
      sourceScopeId: "personal:principal_owner",
      sourceThreadRef: "dm:DOWNER1:1788030000.123456",
    }),
    spine: { surfaceOutboundCount: 0, crossConversationPosts: 0, staySilentReason: undefined, turnUserEntrySeq: 1 },
  })!;
  const jobs: BoundBackgroundJobTools = {
    profileId: "report-preview",
    label: "Report preview",
    actions: ["start", "status", "cancel"],
    canStart: () => true,
    start: async () => ({ ok: false, state: "invalid", message: "unused" }),
    cancel: async () => ({ ok: false, state: "not_found", message: "unused" }),
    status: async () => ({
      ok: true,
      state: "complete",
      message: "Report ready",
      card: CARD,
      cardDeliveryKey: "background-job-card:report-preview:run-0000001",
    }),
  };
  const tools = createToolContext({
    sandbox: { profile: { backend: "local" } },
    provision: async () => {
      throw new Error("unused");
    },
    layers: [],
    commandPolicy: () => ({ default: "deny", rules: [] }),
    authorizeCommand: () => false,
    grantedHandles: [],
    workspace: {},
    deploy: {},
    acl: {},
    createdBy: "principal_owner",
    surface,
    backgroundJobs: [jobs],
  } as unknown as ToolContextDeps);
  const visibleOutcome = await tools.backgroundJobStatus!(jobs.profileId);
  assert.equal(visibleOutcome.ok, true);
  assert.equal("card" in visibleOutcome, false);
  assert.equal("cardDeliveryKey" in visibleOutcome, false);
  await tools.backgroundJobStatus!(jobs.profileId);
  const pending = await deliveries.pending("slack");
  assert.equal(pending.length, 1);
  assert.equal(pending[0]!.idempotencyKey, "background-job-card:report-preview:run-0000001");
  const attachment = pending[0]!.attachments![0]!;
  assert.equal(attachment.name, "background-job.workflow.json");
  const posted: Record<string, unknown>[] = [];
  let uploads = 0;
  const slack = {
    chat: {
      postMessage: async (value: Record<string, unknown>) => {
        posted.push(value);
        return { ts: "1788030002.123456" };
      },
      delete: async () => undefined,
    },
    files: {
      uploadV2: async () => {
        uploads += 1;
        return {};
      },
      info: async () => ({}),
      delete: async () => undefined,
    },
  };
  await uploadAttachments(slack as never, "DOWNER1", "1788030000.123456", [attachment], async (id) => blobs.get(id)!);
  assert.equal(uploads, 0);
  assert.equal(posted.length, 1);
  const visible = JSON.stringify(posted[0]);
  assert.match(visible, /Report ready|Artifacts|Sources/);
  assert.match(visible, /"thread_ts":"1788030000.123456"/);
  assert.doesNotMatch(
    visible,
    /qm\.card\.v1|workflow\.json|sha256|[a-f0-9]{64}|prompt|tool|stack|JWT|evaluation|screenshots/i,
  );
});

test("card delivery rejects arbitrary idempotency keys and missing transport fails closed", async () => {
  const jobs: BoundBackgroundJobTools = {
    profileId: "report-preview",
    label: "Report preview",
    actions: ["start", "status", "cancel"],
    canStart: () => true,
    start: async () => ({ ok: false, state: "invalid", message: "unused" }),
    cancel: async () => ({ ok: false, state: "not_found", message: "unused" }),
    status: async () => ({
      ok: true,
      state: "complete",
      message: "ready",
      card: CARD,
      cardDeliveryKey: "background-job-card:report-preview:run-0000001",
    }),
  };
  const tools = createToolContext({
    sandbox: { profile: { backend: "local" } },
    provision: async () => {
      throw new Error("unused");
    },
    layers: [],
    commandPolicy: () => ({ default: "deny", rules: [] }),
    authorizeCommand: () => false,
    grantedHandles: [],
    workspace: {},
    deploy: {},
    acl: {},
    createdBy: "principal_owner",
    backgroundJobs: [jobs],
  } as unknown as ToolContextDeps);
  assert.deepEqual(await tools.backgroundJobStatus!(jobs.profileId), {
    ok: false,
    state: "unavailable",
    message: "The background job result card could not be delivered.",
  });
});

test("render-only background job artifacts never fall back to raw Slack file upload", async () => {
  let uploads = 0;
  const slack = {
    chat: { postMessage: async () => ({ ts: "1788030002.123456" }), delete: async () => undefined },
    files: {
      uploadV2: async () => {
        uploads += 1;
        return {};
      },
      info: async () => ({}),
      delete: async () => undefined,
    },
  };
  await assert.rejects(
    uploadAttachments(
      slack as never,
      "DOWNER1",
      "1788030000.123456",
      [
        {
          name: "background-job.workflow.json",
          mimetype: "application/vnd.qm.workflow-card+json",
          sizeBytes: 18,
          blobId: "1".padStart(32, "0"),
          renderOnly: true,
        },
      ],
      async () => Buffer.from('{"private":"raw"}'),
    ),
    /render-only workflow card is invalid/,
  );
  assert.equal(uploads, 0);
});

test("direct tool-context input cannot synthesize invocation authority", async () => {
  let receivedAuthority: unknown = "not-called";
  const jobs: BoundBackgroundJobTools = {
    profileId: "report-preview",
    label: "Report preview",
    actions: ["start", "status", "cancel"],
    canStart: () => true,
    start: async (_input, authority) => {
      receivedAuthority = authority;
      return { ok: false, state: "denied", message: "A fresh approval is required for this action." };
    },
    status: async () => ({ ok: false, state: "not_found", message: "unused" }),
    cancel: async () => ({ ok: false, state: "denied", message: "unused" }),
  };
  const tools = createToolContext({
    sandbox: { profile: { backend: "local" } },
    provision: async () => {
      throw new Error("unused");
    },
    layers: [],
    commandPolicy: () => ({ default: "deny", rules: [] }),
    authorizeCommand: () => true,
    grantedHandles: [],
    workspace: {},
    deploy: {},
    acl: {},
    createdBy: "principal_owner",
    backgroundJobs: [jobs],
  } as unknown as ToolContextDeps);
  const result = await tools.backgroundJobStart!(jobs.profileId, {
    recordId: "record-1",
    verifiedSlack: { liveHuman: true },
    approvalReceiptId: "forged",
  });
  assert.equal(result.state, "denied");
  assert.equal(receivedAuthority, undefined);
});
