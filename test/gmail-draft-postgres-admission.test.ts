import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { gmailDraftReceiptDigest, sha256Bytes, sha256Canonical } from "../src/gmail-drafts/contracts.ts";
import type {
  GmailDraftVerifiedOwnerSlackBinding,
  GmailDraftVerifiedThreadSource,
} from "../src/gmail-drafts/postgres-store.ts";
import { GMAIL_TEST_NOW, gmailDraftProposal } from "./gmail-draft-fixture.ts";

const statements: Array<{ text: string; params: readonly unknown[] }> = [];
let admissionOutcome = "admitted";
let databaseDoctorOverrides: Record<string, unknown> = {};

function databaseDoctorRow(): Record<string, unknown> {
  return {
    session_identity_exact: true,
    provider_exact: true,
    login_posture_exact: true,
    membership_exact: true,
    protected_bindings_exact: true,
    schema_identity_exact: true,
    schema_privileges_exact: true,
    relation_shape_exact: true,
    relation_privileges_exact: true,
    routine_privileges_exact: true,
    routine_signatures_exact: true,
    ...databaseDoctorOverrides,
  };
}

class FakePool {
  on(): void {}

  async connect() {
    return {
      query: async () => ({ rows: [], rowCount: 0 }),
      release: () => undefined,
    };
  }

  async query(text: string, params: readonly unknown[]) {
    statements.push({ text, params });
    if (text.includes("session_identity_exact")) {
      return { rows: [databaseDoctorRow()], rowCount: 1 };
    }
    if (
      text.includes("reject_before_effect") ||
      text.includes("reject_definitive_no_write") ||
      text.includes("record_created") ||
      text.includes("retain_unknown")
    ) {
      return { rows: [{ accepted: true }], rowCount: 1 };
    }
    return { rows: [{ outcome: admissionOutcome }], rowCount: 1 };
  }

  async end(): Promise<void> {}
}

mock.module("pg", { defaultExport: { Pool: FakePool } });

const { createPostgresGmailDraftApprovalAdmissionStore, createPostgresGmailDraftExecutionStore } =
  await import("../src/gmail-drafts/postgres-store.ts");

test("private admission sends every current owner-DM binding to one durable atomic RPC", async () => {
  statements.length = 0;
  admissionOutcome = "admitted";
  databaseDoctorOverrides = {};
  const proposal = gmailDraftProposal();
  const store = createPostgresGmailDraftApprovalAdmissionStore({
    connectionString: "postgresql://unit.invalid/database",
    now: () => GMAIL_TEST_NOW,
  });
  assert.deepEqual(store.readiness(), { ready: false, reason: "database startup doctor has not passed" });
  assert.deepEqual(
    await store.admit({ proposal, proposalCiphertext: { keyId: "cipher-key-1", ciphertext: "sealed" } }),
    { status: "rejected", code: "approval_invalid" },
  );
  assert.equal(statements.length, 0);
  assert.deepEqual(await store.startupDoctor(), {
    ready: true,
    provider: "postgresql",
    providerMajorVersion: 16,
    schema: "gmail_draft_broker",
    runtimeRole: "qm_gmail_draft_admission",
  });
  const ownerBinding: GmailDraftVerifiedOwnerSlackBinding = {
    contractType: "qm-gmail-draft-owner-slack-binding",
    contractVersion: 1,
    issuer: proposal.approval.issuer,
    keyId: proposal.approval.keyId,
    bindingJti: "owner-binding-1",
    receiptId: "owner-binding-receipt-1",
    organizationId: proposal.organizationId,
    ownerPrincipalId: proposal.ownerPrincipalId,
    slackTeamId: proposal.approval.slackTeamId,
    slackUserId: proposal.approval.slackUserId,
    issuedAt: GMAIL_TEST_NOW,
    expiresAt: GMAIL_TEST_NOW + 86_400_000,
    signedReceiptSha256: sha256Bytes("signed owner binding"),
    verifiedReceiptSha256: sha256Bytes("verified owner binding"),
  };
  assert.deepEqual(await store.admitOwnerSlackBinding(ownerBinding), { status: "admitted" });
  const ownerAdmission = statements.find((statement) =>
    statement.text.includes("gmail_draft_broker.admit_owner_slack_binding"),
  );
  assert(ownerAdmission);
  assert.equal(ownerAdmission.params.length, 12);
  assert.deepEqual(
    await store.admit({ proposal, proposalCiphertext: { keyId: "cipher-key-1", ciphertext: "sealed" } }),
    { status: "admitted" },
  );
  const admission = statements.find((statement) => statement.text.includes("gmail_draft_broker.admit_intent"));
  assert(admission);
  assert.equal(
    statements.filter((statement) => /CREATE\s+(?:TABLE|SCHEMA|ROLE|FUNCTION)/iu.test(statement.text)).length,
    0,
  );
  assert.equal(admission.params.length, 42);
  assert.deepEqual(admission.params.slice(0, 22), [
    proposal.effectProposalId,
    proposal.revision,
    proposal.draftRevision,
    sha256Canonical(proposal),
    proposal.approval.jti,
    proposal.approval.receiptId,
    proposal.approval.issuer,
    proposal.approval.keyId,
    proposal.approval.signedReceiptSha256,
    proposal.approval.verifiedReceiptSha256,
    proposal.organizationId,
    proposal.ownerPrincipalId,
    proposal.approval.actorPrincipalId,
    proposal.approval.actorSlackId,
    proposal.approval.slackTeamId,
    proposal.approval.slackUserId,
    proposal.approval.channelId,
    proposal.approval.messageTs,
    proposal.approval.threadTs,
    proposal.approval.actionTs,
    proposal.approval.issuedAt,
    proposal.approval.expiresAt,
  ]);
  admissionOutcome = "replayed";
  assert.deepEqual(
    await store.admit({ proposal, proposalCiphertext: { keyId: "cipher-key-1", ciphertext: "sealed" } }),
    { status: "replayed" },
  );
  const beforeInvalid = statements.length;
  const wrongChannel = gmailDraftProposal();
  wrongChannel.approval.channelId = "C12345678";
  assert.deepEqual(
    await store.admit({ proposal: wrongChannel, proposalCiphertext: { keyId: "cipher-key-1", ciphertext: "sealed" } }),
    { status: "rejected", code: "approval_invalid" },
  );
  assert.equal(statements.length, beforeInvalid);

  const sourceReceiptSha256 = sha256Bytes("verified thread source");
  const threadSource: GmailDraftVerifiedThreadSource = {
    contractType: "qm-gmail-draft-thread-source",
    contractVersion: 1,
    issuer: "private-gmail-thread-source",
    keyId: "thread-source-key-1",
    sourceJti: "thread-source-jti-1",
    sourceReceiptSha256,
    organizationId: proposal.organizationId,
    ownerPrincipalId: proposal.ownerPrincipalId,
    logicalConnectionId: proposal.logicalConnectionId,
    connectionVersion: proposal.connectionVersion,
    googleSubject: proposal.googleSubject,
    mailbox: proposal.mailbox,
    gmailThreadId: "thread_1",
    parentMessageId: "<parent@example.com>",
    referenceMessageIds: ["<earlier@example.com>", "<parent@example.com>"],
    subjectSha256: proposal.subjectSha256,
    issuedAt: GMAIL_TEST_NOW,
    expiresAt: GMAIL_TEST_NOW + 86_400_000,
    signedReceiptSha256: sha256Bytes("signed thread source"),
    verifiedReceiptSha256: sourceReceiptSha256,
  };
  admissionOutcome = "admitted";
  assert.deepEqual(await store.admitThreadSource(threadSource), { status: "admitted" });
  const sourceAdmission = statements.find((statement) =>
    statement.text.includes("gmail_draft_broker.admit_thread_source"),
  );
  assert(sourceAdmission);
  assert.equal(sourceAdmission.params.length, 18);
  const threadedProposal = gmailDraftProposal({
    effectProposalId: "effect-proposal-threaded",
    gmailThreadId: threadSource.gmailThreadId,
    replyAuthority: {
      contractType: "qm-gmail-draft-reply-authority",
      contractVersion: 1,
      sourceReceiptSha256,
      gmailThreadId: threadSource.gmailThreadId,
      parentMessageId: threadSource.parentMessageId,
      referenceMessageIds: threadSource.referenceMessageIds,
      subjectSha256: threadSource.subjectSha256,
    },
    sourceReceiptSha256s: [sha256Bytes("meeting-receipt"), sourceReceiptSha256],
  });
  assert.deepEqual(
    await store.admit({
      proposal: threadedProposal,
      proposalCiphertext: { keyId: "cipher-key-1", ciphertext: "sealed-threaded" },
    }),
    { status: "admitted" },
  );
  const threadedAdmission = statements.at(-1);
  if (!threadedAdmission?.text.includes("gmail_draft_broker.admit_intent"))
    throw new Error("missing threaded admission");
  assert.deepEqual(threadedAdmission.params.slice(36, 41), [
    threadSource.gmailThreadId,
    sourceReceiptSha256,
    threadSource.parentMessageId,
    threadSource.referenceMessageIds,
    threadSource.subjectSha256,
  ]);
  const substitutedSource = { ...threadSource, verifiedReceiptSha256: sha256Bytes("substituted source receipt") };
  const beforeSubstitution = statements.length;
  assert.deepEqual(await store.admitThreadSource(substitutedSource), {
    status: "rejected",
    code: "approval_invalid",
  });
  assert.equal(statements.length, beforeSubstitution);
});

test("execution store binds each no-write proof to its exact rejection RPC", async () => {
  statements.length = 0;
  databaseDoctorOverrides = {};
  const proposal = gmailDraftProposal();
  const execution = createPostgresGmailDraftExecutionStore({
    connectionString: "postgresql://unit.invalid/database",
    cipher: {
      boundary: "private_gmail_draft_intent_cipher",
      readiness: () => ({ ready: true }),
      open: async () => JSON.stringify(proposal),
    },
    approvalAdmission: {
      boundary: "private_verified_slack_owner_dm_approval_store",
      durability: "postgres",
      readiness: () => ({ ready: true }),
      startupDoctor: async () => ({
        ready: true,
        provider: "postgresql",
        providerMajorVersion: 16,
        schema: "gmail_draft_broker",
        runtimeRole: "qm_gmail_draft_admission",
      }),
      admitOwnerSlackBinding: async () => ({ status: "admitted" }),
      admitThreadSource: async () => ({ status: "admitted" }),
      admit: async () => ({ status: "admitted" }),
    },
  });
  assert.equal(execution.readiness().ready, false);
  assert.deepEqual(await execution.begin(proposal.effectProposalId), {
    status: "rejected",
    code: "approval_invalid",
  });
  assert.equal(statements.length, 0);
  assert.equal((await execution.startupDoctor()).ready, true);
  assert.equal(
    statements.find((statement) => statement.text.includes("session_identity_exact"))?.params[0],
    "qm_gmail_draft_broker",
  );
  const attempt = {
    attemptId: "attempt-1",
    effectProposalId: proposal.effectProposalId,
    proposalRevision: proposal.revision,
    draftRevision: proposal.draftRevision,
    startedAt: GMAIL_TEST_NOW,
    proposal,
  };
  assert.equal(await execution.reject(attempt, "proposal_invalid", "before_effect"), true);
  assert.equal(await execution.reject(attempt, "gmail_rejected", "provider_definitive_no_write"), true);
  assert(statements.some((statement) => statement.text.includes("reject_before_effect")));
  assert(statements.some((statement) => statement.text.includes("reject_definitive_no_write")));
});

test("execution store passes the exact reconciliation nonce only to reconciliation completion RPCs", async () => {
  statements.length = 0;
  databaseDoctorOverrides = {};
  const proposal = gmailDraftProposal();
  const execution = createPostgresGmailDraftExecutionStore({
    connectionString: "postgresql://unit.invalid/database",
    cipher: {
      boundary: "private_gmail_draft_intent_cipher",
      readiness: () => ({ ready: true }),
      open: async () => JSON.stringify(proposal),
    },
    approvalAdmission: {
      boundary: "private_verified_slack_owner_dm_approval_store",
      durability: "postgres",
      readiness: () => ({ ready: true }),
      startupDoctor: async () => ({
        ready: true,
        provider: "postgresql",
        providerMajorVersion: 16,
        schema: "gmail_draft_broker",
        runtimeRole: "qm_gmail_draft_admission",
      }),
      admitOwnerSlackBinding: async () => ({ status: "admitted" }),
      admitThreadSource: async () => ({ status: "admitted" }),
      admit: async () => ({ status: "admitted" }),
    },
  });
  assert.equal((await execution.startupDoctor()).ready, true);
  const attempt = {
    attemptId: "attempt-1",
    effectProposalId: proposal.effectProposalId,
    proposalRevision: proposal.revision,
    draftRevision: proposal.draftRevision,
    startedAt: GMAIL_TEST_NOW,
    proposal,
  };
  const unknownUnsigned = {
    contractType: "qm-gmail-draft-outcome-unknown" as const,
    contractVersion: 1 as const,
    operation: proposal.operation,
    effectProposalId: proposal.effectProposalId,
    proposalRevision: proposal.revision,
    draftRevision: proposal.draftRevision,
    attemptId: attempt.attemptId,
    effectPayloadSha256: proposal.effectPayloadSha256,
    requestSha256: sha256Bytes("request"),
    markerMessageId: `<qm.${proposal.effectPayloadSha256}@drafts.invalid>`,
    draftId: proposal.draftId,
    code: "network_failure" as const,
    recordedAt: GMAIL_TEST_NOW,
  };
  const unknown = { ...unknownUnsigned, receiptSha256: gmailDraftReceiptDigest(unknownUnsigned) };
  const createdUnsigned = {
    contractType: "qm-gmail-draft-receipt" as const,
    contractVersion: 1 as const,
    operation: proposal.operation,
    effectProposalId: proposal.effectProposalId,
    proposalRevision: proposal.revision,
    draftRevision: proposal.draftRevision,
    attemptId: attempt.attemptId,
    organizationId: proposal.organizationId,
    ownerPrincipalId: proposal.ownerPrincipalId,
    logicalConnectionId: proposal.logicalConnectionId,
    connectionVersion: proposal.connectionVersion,
    googleSubject: proposal.googleSubject,
    mailbox: proposal.mailbox,
    approvalJti: proposal.approval.jti,
    draftId: "draft_1",
    messageId: "message_1",
    threadId: null,
    recipientsSha256: proposal.recipientsSha256,
    subjectSha256: proposal.subjectSha256,
    bodySha256: proposal.bodySha256,
    threadBindingSha256: proposal.threadBindingSha256,
    businessContextSha256: proposal.businessContextSha256,
    sourceBundleSha256: proposal.sourceBundleSha256,
    effectPayloadSha256: proposal.effectPayloadSha256,
    mimeSha256: sha256Bytes("mime"),
    requestSha256: unknown.requestSha256,
    responseSha256: sha256Bytes("response"),
    credentialReceiptSha256: sha256Bytes("credential"),
    createdAt: GMAIL_TEST_NOW,
    reconciled: true,
  };
  const created = { ...createdUnsigned, receiptSha256: gmailDraftReceiptDigest(createdUnsigned) };
  const lease = { nonce: "reconciliation-nonce-2", expiresAt: GMAIL_TEST_NOW + 30_000 };
  await execution.recordCreated(attempt, created, lease);
  await execution.retainUnknown(attempt, unknown, lease);
  const createdRpc = statements.find((statement) => statement.text.includes("record_created"));
  const retainedRpc = statements.find((statement) => statement.text.includes("retain_unknown"));
  assert.equal(createdRpc?.params.length, 14);
  assert.equal(createdRpc?.params.at(-1), lease.nonce);
  assert.equal(retainedRpc?.params.length, 9);
  assert.equal(retainedRpc?.params.at(-1), lease.nonce);
});

test("startup doctors reject wrong-role, superuser-equivalent, provider, schema, and effective privilege drift", async () => {
  statements.length = 0;
  const cases = [
    ["membership_exact", "database runtime role mismatch"],
    ["login_posture_exact", "database login posture mismatch"],
    ["provider_exact", "database provider mismatch"],
    ["schema_identity_exact", "database schema identity mismatch"],
    ["routine_privileges_exact", "database routine privileges mismatch"],
    ["relation_privileges_exact", "database relation privileges mismatch"],
  ] as const;
  for (const [field, reason] of cases) {
    databaseDoctorOverrides = { [field]: false };
    const store = createPostgresGmailDraftApprovalAdmissionStore({
      connectionString: "postgresql://unit.invalid/database",
    });
    assert.deepEqual(await store.startupDoctor(), { ready: false, reason });
    assert.deepEqual(store.readiness(), { ready: false, reason });
  }
  databaseDoctorOverrides = {};
  const attestation = statements.find((statement) => statement.text.includes("session_identity_exact"));
  assert.deepEqual(attestation?.params[0], "qm_gmail_draft_admission");
  assert.deepEqual(attestation?.params[1], ["admit_owner_slack_binding", "admit_thread_source", "admit_intent"]);
  assert(attestation?.text.includes("CURRENT_USER = SESSION_USER"));
  assert(attestation?.text.includes("has_function_privilege"));
  assert(attestation?.text.includes("has_any_column_privilege"));
  assert(attestation?.text.includes("server_version_num"));
});
