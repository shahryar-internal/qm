import {
  assertProviderIdentifier,
  assertSha256,
  gmailDraftReceiptDigest,
  sha256Bytes,
  validateEffectProposal,
  type GmailDraftBrokerOutcome,
  type GmailDraftConnectionBinding,
  type GmailDraftEffectProposal,
  type GmailDraftExecutionStore,
  type GmailDraftNoWriteRejectionProof,
  type GmailDraftReceipt,
  type GmailDraftRejectionCode,
  type GmailDraftUnknownCode,
  type GmailDraftUnknownReceipt,
} from "./contracts.ts";
import { buildPlainTextGmailDraftMime, type GmailDraftMime } from "./mime.ts";
import type { GmailDraftProviderDraft, GmailDraftProviderPort } from "./provider-client.ts";

function binding(proposal: GmailDraftEffectProposal): GmailDraftConnectionBinding {
  return {
    organizationId: proposal.organizationId,
    logicalConnectionId: proposal.logicalConnectionId,
    connectionVersion: proposal.connectionVersion,
    ownerPrincipalId: proposal.ownerPrincipalId,
    googleSubject: proposal.googleSubject,
    mailbox: proposal.mailbox,
    accountType: proposal.accountType,
    grantedScopes: proposal.grantedScopes,
  };
}

function unknownReceipt(input: {
  proposal: GmailDraftEffectProposal;
  attemptId: string;
  mime: GmailDraftMime;
  code: GmailDraftUnknownCode;
  at: number;
}): GmailDraftUnknownReceipt {
  const receipt = {
    contractType: "qm-gmail-draft-outcome-unknown" as const,
    contractVersion: 1 as const,
    operation: input.proposal.operation,
    effectProposalId: input.proposal.effectProposalId,
    proposalRevision: input.proposal.revision,
    draftRevision: input.proposal.draftRevision,
    attemptId: input.attemptId,
    effectPayloadSha256: input.proposal.effectPayloadSha256,
    requestSha256: input.mime.requestSha256,
    markerMessageId: input.mime.markerMessageId,
    draftId: input.proposal.draftId,
    code: input.code,
    recordedAt: input.at,
  };
  return Object.freeze({ ...receipt, receiptSha256: gmailDraftReceiptDigest(receipt) });
}

function createdReceipt(input: {
  proposal: GmailDraftEffectProposal;
  attemptId: string;
  mime: GmailDraftMime;
  draft: GmailDraftProviderDraft;
  responseSha256: string;
  credentialReceiptSha256: string;
  at: number;
  reconciled: boolean;
}): GmailDraftReceipt {
  const receipt = {
    contractType: "qm-gmail-draft-receipt" as const,
    contractVersion: 1 as const,
    operation: input.proposal.operation,
    effectProposalId: input.proposal.effectProposalId,
    proposalRevision: input.proposal.revision,
    draftRevision: input.proposal.draftRevision,
    attemptId: input.attemptId,
    organizationId: input.proposal.organizationId,
    ownerPrincipalId: input.proposal.ownerPrincipalId,
    logicalConnectionId: input.proposal.logicalConnectionId,
    connectionVersion: input.proposal.connectionVersion,
    googleSubject: input.proposal.googleSubject,
    mailbox: input.proposal.mailbox,
    approvalJti: input.proposal.approval.jti,
    draftId: input.draft.draftId,
    messageId: input.draft.messageId,
    threadId: input.draft.threadId,
    recipientsSha256: input.proposal.recipientsSha256,
    subjectSha256: input.proposal.subjectSha256,
    bodySha256: input.proposal.bodySha256,
    threadBindingSha256: input.proposal.threadBindingSha256,
    businessContextSha256: input.proposal.businessContextSha256,
    sourceBundleSha256: input.proposal.sourceBundleSha256,
    effectPayloadSha256: input.proposal.effectPayloadSha256,
    mimeSha256: input.mime.mimeSha256,
    requestSha256: input.mime.requestSha256,
    responseSha256: input.responseSha256,
    credentialReceiptSha256: input.credentialReceiptSha256,
    createdAt: input.at,
    reconciled: input.reconciled,
  };
  return Object.freeze({ ...receipt, receiptSha256: gmailDraftReceiptDigest(receipt) });
}

function validProviderBinding(
  proposal: GmailDraftEffectProposal,
  draft: GmailDraftProviderDraft,
  responseSha256: string,
  credentialReceiptSha256: string,
): boolean {
  try {
    assertProviderIdentifier(draft.draftId, "draftId");
    assertProviderIdentifier(draft.messageId, "messageId");
    if (draft.threadId !== null) assertProviderIdentifier(draft.threadId, "threadId");
    assertSha256(responseSha256, "responseSha256");
    assertSha256(credentialReceiptSha256, "credentialReceiptSha256");
  } catch {
    return false;
  }
  return (
    (proposal.operation !== "update" || draft.draftId === proposal.draftId) &&
    (proposal.gmailThreadId === null || draft.threadId === proposal.gmailThreadId)
  );
}

function rawSha256(raw: string | null): string | null {
  if (raw === null || !/^[A-Za-z0-9_-]+={0,2}$/u.test(raw)) return null;
  try {
    return sha256Bytes(Buffer.from(raw, "base64url"));
  } catch {
    return null;
  }
}

async function safelyReject(
  store: GmailDraftExecutionStore,
  attempt: Parameters<GmailDraftExecutionStore["reject"]>[0],
  code: GmailDraftRejectionCode,
  proof: GmailDraftNoWriteRejectionProof,
): Promise<boolean> {
  return store.reject(attempt, code, proof).catch(() => false);
}

export function createGmailDraftBroker(options: {
  store: GmailDraftExecutionStore;
  provider: GmailDraftProviderPort;
  now?: () => number;
}): Readonly<{
  execute(effectProposalId: string): Promise<GmailDraftBrokerOutcome>;
  reconcile(effectProposalId: string): Promise<GmailDraftBrokerOutcome>;
}> {
  const now = options.now ?? Date.now;
  const execute = async (effectProposalId: string): Promise<GmailDraftBrokerOutcome> => {
    try {
      if (!options.store.readiness().ready || !options.provider.readiness().ready) return { status: "unavailable" };
    } catch {
      return { status: "unavailable" };
    }
    const begun = await options.store.begin(effectProposalId).catch(() => null);
    if (!begun) return { status: "unavailable" };
    if (begun.status === "created") return { status: "replayed", receipt: begun.receipt };
    if (begun.status === "outcome_unknown" || begun.status === "rejected" || begun.status === "in_progress")
      return begun;
    let proposal: GmailDraftEffectProposal;
    let mime: GmailDraftMime;
    try {
      proposal = validateEffectProposal(begun.attempt.proposal, now());
      if (
        proposal.effectProposalId !== effectProposalId ||
        begun.attempt.effectProposalId !== effectProposalId ||
        begun.attempt.proposalRevision !== proposal.revision
      )
        throw new TypeError("attempt binding mismatch");
      mime = buildPlainTextGmailDraftMime(proposal);
    } catch {
      return (await safelyReject(options.store, begun.attempt, "proposal_invalid", "before_effect"))
        ? { status: "rejected", code: "proposal_invalid" }
        : { status: "unavailable" };
    }
    const crashReceipt = unknownReceipt({
      proposal,
      attemptId: begun.attempt.attemptId,
      mime,
      code: "network_failure",
      at: now(),
    });
    if (!(await options.store.armEffect(begun.attempt, crashReceipt).catch(() => false))) {
      return { status: "outcome_unknown", receipt: crashReceipt };
    }
    const result = await options.provider
      .mutate({
        binding: binding(proposal),
        operation: proposal.operation,
        draftId: proposal.draftId,
        requestBody: mime.requestBody,
      })
      .catch(() => null);
    if (!result) {
      const durable = await options.store.recordUnknown(begun.attempt, crashReceipt).catch(() => crashReceipt);
      return { status: "outcome_unknown", receipt: durable };
    }
    if (result.status === "rejected") {
      if (await safelyReject(options.store, begun.attempt, result.code, "provider_definitive_no_write")) return result;
      const durable = await options.store.recordUnknown(begun.attempt, crashReceipt).catch(() => crashReceipt);
      return { status: "outcome_unknown", receipt: durable };
    }
    if (
      result.status === "outcome_unknown" ||
      !validProviderBinding(proposal, result.draft, result.responseSha256, result.credentialReceiptSha256)
    ) {
      const receipt = unknownReceipt({
        proposal,
        attemptId: begun.attempt.attemptId,
        mime,
        code: result.status === "outcome_unknown" ? result.code : "invalid_success_response",
        at: now(),
      });
      const durable = await options.store.recordUnknown(begun.attempt, receipt).catch(() => receipt);
      return { status: "outcome_unknown", receipt: durable };
    }
    const receipt = createdReceipt({
      proposal,
      attemptId: begun.attempt.attemptId,
      mime,
      draft: result.draft,
      responseSha256: result.responseSha256,
      credentialReceiptSha256: result.credentialReceiptSha256,
      at: now(),
      reconciled: false,
    });
    try {
      return { status: "created", receipt: await options.store.recordCreated(begun.attempt, receipt, null) };
    } catch {
      const unknown = unknownReceipt({
        proposal,
        attemptId: begun.attempt.attemptId,
        mime,
        code: "invalid_success_response",
        at: now(),
      });
      const durable = await options.store.recordUnknown(begun.attempt, unknown).catch(() => unknown);
      return { status: "outcome_unknown", receipt: durable };
    }
  };
  const reconcile = async (effectProposalId: string): Promise<GmailDraftBrokerOutcome> => {
    try {
      if (!options.store.readiness().ready || !options.provider.readiness().ready) return { status: "unavailable" };
    } catch {
      return { status: "unavailable" };
    }
    const begun = await options.store.beginReconciliation(effectProposalId).catch(() => null);
    if (!begun) return { status: "unavailable" };
    if (begun.status === "created") return { status: "replayed", receipt: begun.receipt };
    if (begun.status === "rejected" || begun.status === "in_progress") return begun;
    if (begun.status === "outcome_unknown") return { status: "outcome_unknown", receipt: begun.receipt };
    let proposal: GmailDraftEffectProposal;
    let mime: GmailDraftMime;
    try {
      proposal = validateEffectProposal(begun.attempt.proposal, begun.attempt.startedAt);
      mime = buildPlainTextGmailDraftMime(proposal);
      if (
        begun.unknown.operation !== proposal.operation ||
        begun.unknown.effectProposalId !== proposal.effectProposalId ||
        begun.unknown.proposalRevision !== proposal.revision ||
        begun.unknown.effectPayloadSha256 !== proposal.effectPayloadSha256 ||
        begun.unknown.requestSha256 !== mime.requestSha256 ||
        begun.unknown.markerMessageId !== mime.markerMessageId ||
        begun.unknown.draftId !== proposal.draftId ||
        begun.unknown.attemptId !== begun.attempt.attemptId
      )
        throw new TypeError("unknown binding mismatch");
    } catch {
      const durable = await options.store
        .retainUnknown(begun.attempt, begun.unknown, begun.lease)
        .catch(() => begun.unknown);
      return { status: "outcome_unknown", receipt: durable };
    }
    const result = await (
      proposal.operation === "create"
        ? options.provider.findByMarker({ binding: binding(proposal), markerMessageId: mime.markerMessageId })
        : options.provider.read({ binding: binding(proposal), draftId: proposal.draftId! })
    ).catch(() => null);
    if (!result) {
      const durable = await options.store
        .retainUnknown(begun.attempt, begun.unknown, begun.lease)
        .catch(() => begun.unknown);
      return { status: "outcome_unknown", receipt: durable };
    }
    if (
      result.status !== "ok" ||
      !validProviderBinding(proposal, result.draft, result.responseSha256, result.credentialReceiptSha256) ||
      rawSha256(result.status === "ok" ? result.draft.raw : null) !== mime.mimeSha256
    ) {
      const durable = await options.store
        .retainUnknown(begun.attempt, begun.unknown, begun.lease)
        .catch(() => begun.unknown);
      return { status: "outcome_unknown", receipt: durable };
    }
    const receipt = createdReceipt({
      proposal,
      attemptId: begun.attempt.attemptId,
      mime,
      draft: result.draft,
      responseSha256: result.responseSha256,
      credentialReceiptSha256: result.credentialReceiptSha256,
      at: now(),
      reconciled: true,
    });
    try {
      return {
        status: "reconciled",
        receipt: await options.store.recordCreated(begun.attempt, receipt, begun.lease),
      };
    } catch {
      const durable = await options.store
        .retainUnknown(begun.attempt, begun.unknown, begun.lease)
        .catch(() => begun.unknown);
      return { status: "outcome_unknown", receipt: durable };
    }
  };
  return Object.freeze({ execute, reconcile });
}
