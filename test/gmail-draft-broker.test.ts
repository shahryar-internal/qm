import assert from "node:assert/strict";
import { test } from "node:test";
import { createGmailDraftBroker } from "../src/gmail-drafts/broker.ts";
import { gmailDraftReviewCard, type GmailDraftOwnerDmReviewAuthority } from "../src/gmail-drafts/card.ts";
import {
  sha256Bytes,
  type GmailDraftAttempt,
  type GmailDraftBeginResult,
  type GmailDraftEffectProposal,
  type GmailDraftExecutionStore,
  type GmailDraftNoWriteRejectionProof,
  type GmailDraftReceipt,
  type GmailDraftReconcileBeginResult,
  type GmailDraftReconciliationLease,
  type GmailDraftRejectionCode,
  type GmailDraftUnknownReceipt,
} from "../src/gmail-drafts/contracts.ts";
import { buildPlainTextGmailDraftMime } from "../src/gmail-drafts/mime.ts";
import type {
  GmailDraftMutationResult,
  GmailDraftProviderDraft,
  GmailDraftProviderPort,
  GmailDraftReadResult,
} from "../src/gmail-drafts/provider-client.ts";
import { GMAIL_TEST_NOW, gmailDraftProposal } from "./gmail-draft-fixture.ts";

class MemoryStore implements GmailDraftExecutionStore {
  readonly durability = "postgres" as const;
  readonly idempotency = "single_effect_proposal" as const;
  readonly approvalAdmission = "signature_verified_current_click_one_time" as const;
  readonly terminalUnknownPolicy = "reconcile_only_no_automatic_mutation_retry" as const;
  state: "approved" | "pre_effect" | "effect_started" | "unknown" | "reconciling" | "created" | "rejected" = "approved";
  receipt: GmailDraftReceipt | null = null;
  unknown: GmailDraftUnknownReceipt | null = null;
  rejection: GmailDraftRejectionCode | null = null;
  rejectionProof: GmailDraftNoWriteRejectionProof | null = null;
  rejectEnabled = true;
  readonly attempt: GmailDraftAttempt;

  constructor(proposal: GmailDraftEffectProposal) {
    this.attempt = {
      attemptId: "attempt-1",
      effectProposalId: proposal.effectProposalId,
      proposalRevision: proposal.revision,
      draftRevision: proposal.draftRevision,
      startedAt: GMAIL_TEST_NOW,
      proposal: structuredClone(proposal),
    };
  }

  readiness() {
    return { ready: true as const };
  }

  async begin(effectProposalId: string): Promise<GmailDraftBeginResult> {
    if (effectProposalId !== this.attempt.effectProposalId) return { status: "rejected", code: "approval_invalid" };
    if (this.state === "created") return { status: "created", receipt: this.receipt! };
    if (this.state === "unknown" || this.state === "effect_started" || this.state === "reconciling") {
      return { status: "outcome_unknown", receipt: this.unknown! };
    }
    if (this.state === "rejected") return { status: "rejected", code: this.rejection! };
    if (this.state !== "approved") return { status: "in_progress" };
    this.state = "pre_effect";
    return { status: "claimed", attempt: structuredClone(this.attempt) };
  }

  async beginReconciliation(effectProposalId: string): Promise<GmailDraftReconcileBeginResult> {
    if (effectProposalId !== this.attempt.effectProposalId) return { status: "rejected", code: "approval_invalid" };
    if (this.state === "created") return { status: "created", receipt: this.receipt! };
    if (this.state === "rejected") return { status: "rejected", code: this.rejection! };
    if (this.state !== "unknown" && this.state !== "effect_started") return { status: "in_progress" };
    this.state = "reconciling";
    return {
      status: "claimed",
      attempt: structuredClone(this.attempt),
      unknown: structuredClone(this.unknown!),
      lease: { nonce: "reconciliation-nonce-1", expiresAt: GMAIL_TEST_NOW + 30_000 },
    };
  }

  async armEffect(_attempt: GmailDraftAttempt, crashReceipt: GmailDraftUnknownReceipt): Promise<boolean> {
    if (this.state !== "pre_effect") return false;
    this.state = "effect_started";
    this.unknown = structuredClone(crashReceipt);
    return true;
  }

  async reject(
    _attempt: GmailDraftAttempt,
    code: GmailDraftRejectionCode,
    proof: GmailDraftNoWriteRejectionProof,
  ): Promise<boolean> {
    if (!this.rejectEnabled) return false;
    if (
      (this.state === "pre_effect" && proof === "before_effect") ||
      (this.state === "effect_started" && proof === "provider_definitive_no_write")
    ) {
      this.state = "rejected";
      this.rejection = code;
      this.rejectionProof = proof;
      return true;
    }
    return false;
  }

  async recordCreated(
    _attempt: GmailDraftAttempt,
    receipt: GmailDraftReceipt,
    _reconciliationLease: GmailDraftReconciliationLease | null,
  ): Promise<GmailDraftReceipt> {
    if (this.state !== "effect_started" && this.state !== "reconciling") throw new Error("lost authority");
    this.state = "created";
    this.receipt = structuredClone(receipt);
    return structuredClone(receipt);
  }

  async recordUnknown(
    _attempt: GmailDraftAttempt,
    receipt: GmailDraftUnknownReceipt,
  ): Promise<GmailDraftUnknownReceipt> {
    if (this.state !== "effect_started") throw new Error("lost authority");
    this.state = "unknown";
    this.unknown = structuredClone(receipt);
    return structuredClone(receipt);
  }

  async retainUnknown(
    _attempt: GmailDraftAttempt,
    receipt: GmailDraftUnknownReceipt,
    _reconciliationLease: GmailDraftReconciliationLease,
  ): Promise<GmailDraftUnknownReceipt> {
    if (this.state !== "reconciling") throw new Error("lost authority");
    this.state = "unknown";
    this.unknown = structuredClone(receipt);
    return structuredClone(receipt);
  }
}

class MemoryProvider implements GmailDraftProviderPort {
  mutationCount = 0;
  mutationResult: GmailDraftMutationResult | Error | null = null;
  saved: GmailDraftProviderDraft | null = null;
  savedResponseSha256 = sha256Bytes("provider response");

  readiness() {
    return { ready: true as const };
  }

  async mutate(input: { requestBody: string }): Promise<GmailDraftMutationResult> {
    this.mutationCount += 1;
    const body = JSON.parse(input.requestBody) as { message: { raw: string; threadId?: string } };
    this.saved = {
      draftId: "draft_1",
      messageId: "message_1",
      threadId: body.message.threadId ?? null,
      raw: body.message.raw,
    };
    if (this.mutationResult instanceof Error) throw this.mutationResult;
    return (
      this.mutationResult ?? {
        status: "ok",
        draft: { ...this.saved, raw: null },
        responseSha256: this.savedResponseSha256,
        credentialReceiptSha256: sha256Bytes("credential receipt"),
      }
    );
  }

  async findByMarker(): Promise<GmailDraftReadResult> {
    return this.saved
      ? {
          status: "ok",
          draft: structuredClone(this.saved),
          responseSha256: this.savedResponseSha256,
          credentialReceiptSha256: sha256Bytes("credential receipt"),
        }
      : { status: "not_found" };
  }

  async read(): Promise<GmailDraftReadResult> {
    return this.findByMarker();
  }
}

function reviewAuthority(
  proposal: GmailDraftEffectProposal,
  receipt: GmailDraftReceipt,
): GmailDraftOwnerDmReviewAuthority {
  return {
    contractType: "qm-gmail-draft-owner-dm-review-authority",
    contractVersion: 1,
    reviewGrantId: "opaque-review-grant-1",
    organizationId: proposal.organizationId,
    ownerPrincipalId: proposal.ownerPrincipalId,
    slackTeamId: proposal.approval.slackTeamId,
    slackUserId: proposal.approval.slackUserId,
    channelId: proposal.approval.channelId,
    effectProposalId: proposal.effectProposalId,
    proposalRevision: proposal.revision,
    draftRevision: proposal.draftRevision,
    effectPayloadSha256: proposal.effectPayloadSha256,
    draftReceiptSha256: receipt.receiptSha256,
    issuedAt: GMAIL_TEST_NOW,
    expiresAt: GMAIL_TEST_NOW + 120_000,
    verifiedReceiptSha256: proposal.approval.verifiedReceiptSha256,
  };
}

test("broker creates one draft and replays the durable receipt without a second provider mutation", async () => {
  const proposal = gmailDraftProposal();
  const store = new MemoryStore(proposal);
  const provider = new MemoryProvider();
  const broker = createGmailDraftBroker({ store, provider, now: () => GMAIL_TEST_NOW });
  const [first, concurrent] = await Promise.all([
    broker.execute(proposal.effectProposalId),
    broker.execute(proposal.effectProposalId),
  ]);
  assert.equal(first.status, "created");
  assert.equal(concurrent.status, "in_progress");
  const replay = await broker.execute(proposal.effectProposalId);
  assert.equal(replay.status, "replayed");
  assert.equal(provider.mutationCount, 1);
  if (replay.status !== "replayed") throw new Error("missing receipt");
  assert.equal(replay.receipt.recipientsSha256, proposal.recipientsSha256);
  assert.equal(replay.receipt.threadBindingSha256, proposal.threadBindingSha256);
  assert.equal(replay.receipt.bodySha256, proposal.bodySha256);
  assert.equal(replay.receipt.sourceBundleSha256, proposal.sourceBundleSha256);
});

test("standalone create accepts provider-assigned thread identity without fabricating reply semantics", async () => {
  const proposal = gmailDraftProposal();
  const store = new MemoryStore(proposal);
  const provider = new MemoryProvider();
  provider.mutationResult = {
    status: "ok",
    draft: { draftId: "draft_1", messageId: "message_1", threadId: "provider_thread_1", raw: null },
    responseSha256: sha256Bytes("provider response"),
    credentialReceiptSha256: sha256Bytes("credential receipt"),
  };
  const result = await createGmailDraftBroker({ store, provider, now: () => GMAIL_TEST_NOW }).execute(
    proposal.effectProposalId,
  );
  assert.equal(result.status, "created");
  if (result.status !== "created") throw new Error("missing created receipt");
  assert.equal(result.receipt.threadId, "provider_thread_1");
  const mime = buildPlainTextGmailDraftMime(proposal);
  assert(!mime.mimeSource.includes("In-Reply-To:"));
  assert(!mime.mimeSource.includes("References:"));
  assert(!("threadId" in (JSON.parse(mime.requestBody) as { message: object }).message));
});

test("write then response loss becomes durable outcome_unknown, never blind retries, and reconciles exact MIME", async () => {
  const proposal = gmailDraftProposal();
  const store = new MemoryStore(proposal);
  const provider = new MemoryProvider();
  provider.mutationResult = { status: "outcome_unknown", code: "network_failure" };
  const broker = createGmailDraftBroker({ store, provider, now: () => GMAIL_TEST_NOW });
  const unknown = await broker.execute(proposal.effectProposalId);
  assert.equal(unknown.status, "outcome_unknown");
  assert.equal((await broker.execute(proposal.effectProposalId)).status, "outcome_unknown");
  assert.equal(provider.mutationCount, 1);
  const reconciled = await broker.reconcile(proposal.effectProposalId);
  assert.equal(reconciled.status, "reconciled");
  assert.equal(provider.mutationCount, 1);
  if (reconciled.status !== "reconciled") throw new Error("missing reconciled receipt");
  assert.equal(reconciled.receipt.mimeSha256, buildPlainTextGmailDraftMime(proposal).mimeSha256);
  assert.equal(reconciled.receipt.reconciled, true);
});

test("provider exception after the durable effect fence cannot produce a second mutation", async () => {
  const proposal = gmailDraftProposal();
  const store = new MemoryStore(proposal);
  const provider = new MemoryProvider();
  provider.mutationResult = new Error("secret provider failure");
  const broker = createGmailDraftBroker({ store, provider, now: () => GMAIL_TEST_NOW });
  assert.equal((await broker.execute(proposal.effectProposalId)).status, "outcome_unknown");
  assert.equal((await broker.execute(proposal.effectProposalId)).status, "outcome_unknown");
  assert.equal(provider.mutationCount, 1);
});

test("only explicit pre-effect or definitive provider no-write proofs can reject", async () => {
  const definitiveProposal = gmailDraftProposal();
  const definitiveStore = new MemoryStore(definitiveProposal);
  const definitiveProvider = new MemoryProvider();
  definitiveProvider.mutationResult = { status: "rejected", code: "gmail_rejected" };
  const definitive = await createGmailDraftBroker({
    store: definitiveStore,
    provider: definitiveProvider,
    now: () => GMAIL_TEST_NOW,
  }).execute(definitiveProposal.effectProposalId);
  assert.deepEqual(definitive, { status: "rejected", code: "gmail_rejected" });
  assert.equal(definitiveStore.rejectionProof, "provider_definitive_no_write");

  const failedPersistenceStore = new MemoryStore(definitiveProposal);
  failedPersistenceStore.rejectEnabled = false;
  const failedPersistenceProvider = new MemoryProvider();
  failedPersistenceProvider.mutationResult = { status: "rejected", code: "gmail_rejected" };
  const failedPersistence = await createGmailDraftBroker({
    store: failedPersistenceStore,
    provider: failedPersistenceProvider,
    now: () => GMAIL_TEST_NOW,
  }).execute(definitiveProposal.effectProposalId);
  assert.equal(failedPersistence.status, "outcome_unknown");
  assert.equal(failedPersistenceStore.state, "unknown");

  const unknownProposal = gmailDraftProposal();
  const unknownStore = new MemoryStore(unknownProposal);
  const unknownProvider = new MemoryProvider();
  unknownProvider.mutationResult = { status: "outcome_unknown", code: "network_failure" };
  const broker = createGmailDraftBroker({ store: unknownStore, provider: unknownProvider, now: () => GMAIL_TEST_NOW });
  assert.equal((await broker.execute(unknownProposal.effectProposalId)).status, "outcome_unknown");
  unknownStore.attempt.proposal.bodyText = "corrupted sealed payload";
  assert.equal((await broker.reconcile(unknownProposal.effectProposalId)).status, "outcome_unknown");
  assert.equal(unknownStore.state, "unknown");
  assert.equal(unknownStore.rejectionProof, null);
});

test("expired or substituted approval rejects before provider mutation", async () => {
  const expired = gmailDraftProposal();
  expired.approval.expiresAt = GMAIL_TEST_NOW - 1;
  const expiredStore = new MemoryStore(expired);
  const expiredProvider = new MemoryProvider();
  const expiredBroker = createGmailDraftBroker({
    store: expiredStore,
    provider: expiredProvider,
    now: () => GMAIL_TEST_NOW,
  });
  assert.deepEqual(await expiredBroker.execute(expired.effectProposalId), {
    status: "rejected",
    code: "proposal_invalid",
  });
  assert.equal(expiredProvider.mutationCount, 0);
  assert.equal(expiredStore.rejectionProof, "before_effect");

  const substituted = gmailDraftProposal();
  substituted.bodyText = "payload substitution";
  const substitutedStore = new MemoryStore(substituted);
  const substitutedProvider = new MemoryProvider();
  const substitutedBroker = createGmailDraftBroker({
    store: substitutedStore,
    provider: substitutedProvider,
    now: () => GMAIL_TEST_NOW,
  });
  assert.equal((await substitutedBroker.execute(substituted.effectProposalId)).status, "rejected");
  assert.equal(substitutedProvider.mutationCount, 0);
});

test("private qm.card.v1 review projection contains no mailbox content, provider IDs, hashes, or send action", async () => {
  const proposal = gmailDraftProposal();
  const store = new MemoryStore(proposal);
  const provider = new MemoryProvider();
  const result = await createGmailDraftBroker({ store, provider, now: () => GMAIL_TEST_NOW }).execute(
    proposal.effectProposalId,
  );
  if (result.status !== "created") throw new Error("draft was not created");
  const card = gmailDraftReviewCard({
    proposal,
    receipt: result.receipt,
    authority: reviewAuthority(proposal, result.receipt),
    privateUiBaseUrl: "https://private.example.test/app",
    now: GMAIL_TEST_NOW,
  });
  const serialized = JSON.stringify(card);
  assert.equal(card.renderer, "qm.card.v1");
  assert(serialized.includes("Nothing was sent"));
  assert(serialized.includes("/gmail-drafts/review/opaque-review-grant-1"));
  for (const secret of [
    proposal.mailbox,
    ...proposal.to,
    proposal.subject,
    proposal.bodyText,
    result.receipt.draftId,
    result.receipt.messageId,
    proposal.effectProposalId,
    proposal.bodySha256,
    proposal.sourceBundleSha256,
  ]) {
    assert(!serialized.includes(secret));
  }
  assert(!serialized.toLowerCase().includes("send draft"));
  assert.throws(() =>
    gmailDraftReviewCard({
      proposal,
      receipt: result.receipt,
      authority: reviewAuthority(proposal, result.receipt),
      privateUiBaseUrl: "https://user:pass@example.test",
      now: GMAIL_TEST_NOW,
    }),
  );
  for (const mutate of [
    (authority: GmailDraftOwnerDmReviewAuthority) => {
      authority.channelId = "D87654321";
    },
    (authority: GmailDraftOwnerDmReviewAuthority) => {
      authority.slackUserId = "U87654321";
    },
    (authority: GmailDraftOwnerDmReviewAuthority) => {
      authority.verifiedReceiptSha256 = sha256Bytes("unrelated approval receipt");
    },
    (authority: GmailDraftOwnerDmReviewAuthority) => {
      authority.draftReceiptSha256 = sha256Bytes("unrelated draft receipt");
    },
    (authority: GmailDraftOwnerDmReviewAuthority) => {
      authority.expiresAt = GMAIL_TEST_NOW;
    },
  ]) {
    const authority = reviewAuthority(proposal, result.receipt);
    mutate(authority);
    assert.throws(() =>
      gmailDraftReviewCard({
        proposal,
        receipt: result.receipt,
        authority,
        privateUiBaseUrl: "https://private.example.test/app",
        now: GMAIL_TEST_NOW,
      }),
    );
  }
});
