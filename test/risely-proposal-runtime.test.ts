import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import { createBackgroundJobProductionComposition } from "../src/background-jobs/composition.ts";
import {
  parseBackgroundJobDeploymentProfile,
  validateBackgroundJobSchemaValue,
} from "../src/background-jobs/deployment-profile.ts";
import { backgroundJobStatusOutcome } from "../src/background-jobs/service.ts";
import type {
  BackgroundJobApprovalGrant,
  BackgroundJobAuthoritySigner,
  BackgroundJobReceipt,
} from "../src/background-jobs/types.ts";
import { canonicalJson } from "../src/cron/schedule-authority.ts";
import type { FileArtifact, FileArtifactStore, PutFileInput } from "../src/files/file-artifact-store.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { createRiselyProposalComposition } from "../src/risely-proposals/composition.ts";
import {
  riselyProposalInputSchema,
  riselyProposalSchemaSha256,
  type RiselyProposalInput,
} from "../src/risely-proposals/contracts.ts";
import {
  createRiselyProposalAdapter,
  createRiselyProposalClient,
  RISELY_PROPOSAL_ARTIFACTS,
  type RiselyProposalRunRecord,
} from "../src/risely-proposals/runtime.ts";

function profile() {
  return parseBackgroundJobDeploymentProfile(
    JSON.stringify({
      contract: 1,
      definition: {
        id: "risely-proposal",
        operation: "proposal_compile",
        capability: "proposals.private.compile",
        scope: "jobs:submit",
        tokenType: "job-authority+jwt",
        authorityHeader: "x-job-authority",
        start: { path: "/v1/private-proposals/start", maxRequestBytes: 512 * 1024 },
        status: { path: "/v1/private-proposals/status", maxRequestBytes: 1024 },
        cancel: { path: "/v1/private-proposals/cancel", maxRequestBytes: 1024 },
      },
      issuer: "https://qm.example.com/v1/job-authority",
      audience: "https://qm.example.com/v1/private-proposals",
      origin: "https://qm.example.com",
      artifactPathPrefix: "/v1/files/",
      artifactAccess: "owner_authenticated",
      profile: {
        organizationId: "risely",
        actorPrincipalId: "founder",
        actorSlackId: "UOWNER1",
        audienceScopeId: "personal:founder",
        slackTeamId: "TTEAM01",
        channelId: "DOWNER1",
      },
      tools: {
        start: { id: "risely-proposal", label: "Create private proposal" },
        status: { id: "risely-proposal-status", label: "Check private proposal" },
        cancel: { id: "risely-proposal-cancel", label: "Cancel private proposal" },
      },
      approval: { start: "invocation_receipt", cancel: "invocation_receipt" },
      schema: { sha256: riselyProposalSchemaSha256(), json: riselyProposalInputSchema },
      artifacts: RISELY_PROPOSAL_ARTIFACTS,
      dependencies: {
        adapter: "risely-proposal-compiler-v1",
        receiptStore: "background_job_records",
        approvalStore: "background_job_approval_ledger",
        authority: "kms-rs256-v1",
      },
    }),
    "background-jobs/risely-proposal/job.json",
  );
}

function proposalInput(): RiselyProposalInput {
  const sourceEvidence = (
    id: string,
    source: "analytics" | "brain",
    value: unknown,
    revision: string,
    observedAt: string,
    fetchedAt: string,
    citation: string,
    summary: string,
  ) => {
    const sourceRecord = canonicalJson(value);
    const contentSha256 = createHash("sha256").update(sourceRecord).digest("hex");
    return {
      id,
      source,
      sourceRecordRef: `source-record:${contentSha256}`,
      sourceRecord,
      contentSha256,
      relatedContentSha256: [],
      revision,
      observedAt,
      fetchedAt,
      status: "cited" as const,
      trust: "verified_source" as const,
      availability: "available" as const,
      sourceTrust: "verified_source" as const,
      sourceAvailability: "available" as const,
      citation,
      summary,
    };
  };
  const evidence = [
    sourceEvidence(
      "brain-account",
      "brain",
      { accountId: "acme", request: "private rollout proposal" },
      "brain-r17",
      "2026-08-31T20:00:00.000Z",
      "2026-08-31T20:00:10.000Z",
      "https://brain.example.com/accounts/acme",
      "Acme requested a private rollout proposal.",
    ),
    sourceEvidence(
      "analytics-usage",
      "analytics",
      { accountId: "acme", activeUsers: 125, report: "usage" },
      "analytics-r4",
      "2026-08-31T20:01:00.000Z",
      "2026-08-31T20:01:10.000Z",
      "https://analytics.example.com/reports/acme-usage",
      "Verified usage supports the stated outcome.",
    ),
  ];
  const keys = [
    "executive_summary",
    "customer_need",
    "proposed_solution",
    "outcomes",
    "scope",
    "delivery",
    "commercial",
    "next_steps",
  ] as const;
  return {
    proposalId: "acme-private-proposal",
    title: "Acme growth proposal",
    client: "Acme",
    revision: 3,
    validUntil: "2026-09-30T23:59:59.000Z",
    evidence,
    sections: keys.map((key) => ({
      key,
      heading: key.replaceAll("_", " "),
      content: `Verified ${key.replaceAll("_", " ")} content for Acme.`,
      evidenceRefs: key === "outcomes" ? ["analytics-usage"] : ["brain-account"],
    })),
    emailDraft: {
      to: "buyer@acme.example",
      subject: "Acme private proposal",
      body: "Please review the attached private proposal draft.",
    },
  };
}

function authority(): BackgroundJobAuthoritySigner {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...pair.publicKey.export({ format: "jwk" }), kid: "proposal-test-key", use: "sig", alg: "RS256" };
  const token = () => {
    const header = Buffer.from(canonicalJson({ alg: "RS256", kid: jwk.kid, typ: "JWT" }), "utf8").toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(canonicalJson({ iat: now, exp: now + 120 }), "utf8").toString("base64url");
    const input = `${header}.${payload}`;
    return `${input}.${sign("RSA-SHA256", Buffer.from(input, "ascii"), pair.privateKey).toString("base64url")}`;
  };
  return Object.freeze({
    ready: async () => undefined,
    signPrepare: async () => token(),
    signStart: async () => token(),
    signStatus: async () => token(),
    signCancel: async () => token(),
    jwks: () => Object.freeze({ keys: Object.freeze([jwk]) }),
  });
}

function memoryFiles(): { store: FileArtifactStore; bytes: Map<string, Buffer> } {
  const rows = new Map<string, FileArtifact>();
  const bytes = new Map<string, Buffer>();
  const put = async (input: PutFileInput) => {
    const existing = rows.get(input.id);
    if (existing) return { artifact: existing, created: false };
    const data = Buffer.isBuffer(input.data) ? input.data : Buffer.from(input.data as Uint8Array);
    const at = input.createdAt ?? Date.now();
    const artifact: FileArtifact = {
      id: input.id,
      ownerScopeId: input.ownerScopeId,
      createdBy: input.createdBy,
      name: input.name,
      path: input.path,
      mimetype: input.mimetype,
      sizeBytes: data.byteLength,
      blobKey: input.id,
      sha256: createHash("sha256").update(data).digest("hex"),
      direction: input.direction,
      source: "live",
      ...(input.createdInScope ? { createdInScope: input.createdInScope } : {}),
      createdAt: at,
      updatedAt: at,
      enabled: true,
    };
    rows.set(input.id, artifact);
    bytes.set(input.id, data);
    return { artifact, created: true };
  };
  const store = {
    put,
    get: async (id: string) => rows.get(id) ?? null,
    open: async () => null,
    listOwnedByScopes: async () => ({ files: [] }),
    resolveByOwnerPaths: async () => [],
    setEnabled: async () => undefined,
    delete: async () => undefined,
  } satisfies FileArtifactStore;
  return { store, bytes };
}

function grant(binding: ReturnType<typeof profile>["binding"]): BackgroundJobApprovalGrant {
  return {
    organizationId: "risely",
    actorPrincipalId: "founder",
    actorSlackId: "UOWNER1",
    audienceScopeId: "personal:founder",
    slackTeamId: "TTEAM01",
    channelId: "DOWNER1",
    threadTs: "1788206400.123456",
    conversationThreadRef: "dm:DOWNER1:1788206400.123456",
    ...binding,
    approvalId: "approval-proposal-1",
    digest: "a".repeat(64),
    effect: "background_job_start",
    approvalKey: "approval-key-proposal-1",
    actionTs: "1788206401.123456",
    jobId: "risely-proposal",
    messageTs: "1788206400.123456",
    payloadSha256: "b".repeat(64),
    idempotencyKey: "risely-proposal:test",
    issuedAt: 1788206400000,
    expiresAt: 1788206700000,
  };
}

test("private proposal adapter requires all evidence-bound decision sections", async () => {
  const adapter = createRiselyProposalAdapter();
  const input = proposalInput();
  assert.throws(() => adapter.parseInput({ ...input, sections: input.sections.slice(0, 7) }), /sections/);
  assert.throws(
    () =>
      adapter.parseInput({
        ...input,
        sections: input.sections.map((section) => ({ ...section, evidenceRefs: ["missing"] })),
      }),
    /evidence references/,
  );
  assert.throws(
    () =>
      adapter.parseInput({
        ...input,
        evidence: input.evidence.map((item, index) =>
          index === 0 ? { ...item, sourceRecord: canonicalJson({ forged: true }) } : item,
        ),
      }),
    /source record hash/,
  );
  const prepared = await adapter.prepare(input, {
    jobId: "risely-proposal",
    organizationId: "risely",
    actorPrincipalId: "founder",
    actorSlackId: "UOWNER1",
    audienceScopeId: "personal:founder",
    slackTeamId: "TTEAM01",
    channelId: "DOWNER1",
    threadTs: "1788206400.123456",
    conversationThreadRef: "dm:DOWNER1:1788206400.123456",
  });
  assert.match(prepared.idempotencyKey, /^risely-proposal:[a-f0-9]{64}$/);
  const compiled = JSON.parse(Buffer.from(prepared.bodyBytes).toString("utf8"));
  assert.equal(compiled.proposalId, input.proposalId);
  assert.doesNotThrow(() => validateBackgroundJobSchemaValue(profile().schema.json, compiled));
});

test("signed private proposal runtime compiles idempotent owner-scoped artifacts and decision receipts", async () => {
  const deployment = profile();
  const records = createMemoryMap<RiselyProposalRunRecord>();
  const files = memoryFiles();
  const signer = authority();
  const adapter = createRiselyProposalAdapter();
  const input = proposalInput();
  const owner = {
    jobId: "risely-proposal",
    ...deployment.profile,
    threadTs: "1788206400.123456",
    conversationThreadRef: "dm:DOWNER1:1788206400.123456",
  };
  const prepared = await adapter.prepare(input, owner);
  const approval = { ...grant(deployment.binding), idempotencyKey: prepared.idempotencyKey };
  const client = createRiselyProposalClient({
    profile: deployment,
    authority: signer,
    records,
    files: files.store,
    now: () => 1788206402000,
  });
  const admitted = await client.start(prepared.bodyBytes, approval, prepared.idempotencyKey, 1788206401000);
  assert.deepEqual(await client.start(prepared.bodyBytes, approval, prepared.idempotencyKey, 1788206401000), admitted);
  const record = await records.get(admitted.runId);
  assert.ok(record);
  assert.equal(record.releaseEligible, false);
  assert.equal(record.decisions.length, 8);
  assert.match(record.principalBindingSha256, /^[a-f0-9]{64}$/);
  assert.match(record.evidenceBundleSha256, /^[a-f0-9]{64}$/);
  assert.equal(
    record.decisions.every((receipt) => receipt.approvalDigest === approval.digest),
    true,
  );
  assert.equal(
    record.decisions.every(
      (receipt) =>
        receipt.principalBindingSha256 === record.principalBindingSha256 &&
        receipt.evidenceBundleSha256 === record.evidenceBundleSha256 &&
        receipt.evidenceRefs.every((reference) => /^evidence:[a-f0-9]{64}$/.test(reference)),
    ),
    true,
  );
  assert.equal(record.artifacts.length, 5);
  const pdf = files.bytes.get(
    record.artifacts.find((item) => item.kind === "proposal_pdf")!.href.match(/[a-f0-9]{32}/)![0],
  );
  assert.equal(pdf?.subarray(0, 8).toString("ascii"), "%PDF-1.4");
  const decisions = [...files.bytes.values()].find((value) =>
    value.includes(Buffer.from("approved_for_private_compile")),
  );
  assert.ok(decisions);
  assert.equal(JSON.parse(decisions.toString("utf8")).releaseEligible, false);
  const manifest = [...files.bytes.values()].find((value) =>
    value.includes(Buffer.from("content_addressed_approved_claims")),
  );
  assert.ok(manifest);
  assert.equal(JSON.parse(manifest.toString("utf8")).principalBindingSha256, record.principalBindingSha256);
  const receipt = {
    ...owner,
    ...deployment.binding,
    intentId: "intent-1",
    authorityId: admitted.authorityId,
    runId: admitted.runId,
    idempotencyKey: prepared.idempotencyKey,
    payloadSha256: createHash("sha256").update(prepared.bodyBytes).digest("hex"),
    approvalId: approval.approvalId,
    approvalDigest: approval.digest,
    approvalEffect: "background_job_start" as const,
    approvalKey: approval.approvalKey,
    approvalActionTs: approval.actionTs,
    approvalMessageTs: approval.messageTs,
    approvalThreadTs: approval.threadTs,
    messageTs: approval.messageTs,
    createdAt: 1788206401000,
  } satisfies BackgroundJobReceipt;
  const status = await client.status(receipt);
  assert.equal(status.state, "complete");
  assert.equal(status.artifacts?.length, 5);
  assert.equal(
    status.artifacts?.every((artifact) => new URL(artifact.href).search === ""),
    true,
  );
  const outcome = backgroundJobStatusOutcome(deployment, receipt, status);
  assert.equal(outcome.state, "complete");
  assert.ok(outcome.card);
  const card = outcome.card.payload as {
    status: { label: string; tone: string };
    sections: Array<{ items: Array<{ href?: string }> }>;
  };
  assert.deepEqual(card.status, { label: "Completed", tone: "success" });
  assert.equal(card.sections[0]?.items[0]?.href, status.artifacts?.[0]?.href);
  assert.match(outcome.cardDeliveryKey ?? "", /^background-job-card:[a-f0-9]{64}$/);
  const cancellation = await client.cancel(
    receipt,
    { ...approval, effect: "background_job_cancel", idempotencyKey: "risely-proposal-cancel:test" },
    1788206403000,
  );
  assert.equal(cancellation.state, "cancel_requested");
});

test("private composition stays hidden unless every exact founder and KMS binding is present", async () => {
  const files = memoryFiles();
  let delivery: unknown;
  const base = {
    artifactMap: <T>() => createMemoryMap<T>(),
    blobTransfer: { put: async () => ({ blobId: "0".repeat(32), sizeBytes: 10, sha256: "0".repeat(64) }) },
    files: files.store,
    deliveries: {
      enqueue: async (input: unknown) => {
        delivery = input;
        return input;
      },
    },
    orgId: "risely",
    publicUrl: "https://qm.example.com",
    region: "us-west-2",
    durable: true,
  };
  const hidden = createRiselyProposalComposition({ ...base, env: {} } as never);
  assert.deepEqual(hidden.profiles(), []);
  assert.throws(
    () => createRiselyProposalComposition({ ...base, env: { RISELY_PROPOSAL_ENABLED: "1" } } as never),
    /configuration is incomplete/,
  );
  const signer = authority();
  const jwk = signer.jwks().keys[0]!;
  const enabled = createRiselyProposalComposition({
    ...base,
    env: {
      RISELY_PROPOSAL_ENABLED: "1",
      RISELY_PROPOSAL_ACTOR_PRINCIPAL_ID: "founder",
      RISELY_PROPOSAL_SLACK_USER_ID: "UOWNER1",
      RISELY_PROPOSAL_SLACK_TEAM_ID: "TTEAM01",
      RISELY_PROPOSAL_SLACK_DM_ID: "DOWNER1",
      RISELY_PROPOSAL_KMS_KEY_ID: "alias/risely-proposal",
      RISELY_PROPOSAL_TOKEN_KID: "proposal-test-key",
      RISELY_PROPOSAL_PUBLIC_JWK: JSON.stringify(jwk),
    },
  } as never);
  assert.equal(enabled.profiles()[0]?.definition.id, "risely-proposal");
  assert.ok(enabled.registry.resolveAdapter("risely-proposal-compiler-v1")?.createClient);
  assert.equal(enabled.registry.resolveAuthority(enabled.profiles()[0]!)?.active.keyId, "alias/risely-proposal");
  await enabled.sender.send(
    {
      deliveryKey: "background-job-delivery:test-proposal",
      jobId: "risely-proposal",
      authorityId: "proposal-authority:test",
      runId: "proposal-run:test",
      organizationId: "risely",
      actorPrincipalId: "founder",
      actorSlackId: "UOWNER1",
      audienceScopeId: "personal:founder",
      slackTeamId: "TTEAM01",
      channelId: "DOWNER1",
      descriptorSha256: "1".repeat(64),
      profileSha256: "2".repeat(64),
      schemaSha256: "3".repeat(64),
      messageTs: "1788206400.123456",
      threadTs: "1788206400.123456",
      conversationThreadRef: "dm:DOWNER1:1788206400.123456",
      state: "complete",
      text: "The private proposal is ready.",
      card: { version: 1, renderer: "qm.card.v1", fallbackText: "Proposal ready", payload: {} },
      createdAt: 1788206401000,
    },
    "background-job-delivery:test-proposal",
  );
  assert.deepEqual((delivery as { destination: unknown }).destination, {
    type: "slack",
    target: "DOWNER1",
    audienceScopeId: "personal:founder",
    threadTs: "1788206400.123456",
  });
  assert.equal((delivery as { attachments: Array<{ renderOnly?: boolean }> }).attachments[0]?.renderOnly, true);
  assert.equal(createBackgroundJobProductionComposition().profiles().length, 0);
});
