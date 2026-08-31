import {
  WORKFLOW_ARTIFACT_CARD_RENDERER,
  validateWorkflowArtifactCard,
  validateWorkflowArtifactEnvelope,
  type WorkflowArtifactEnvelope,
} from "../../plugins/chassis/src/workflow-artifact-card.ts";
import { assertIdentifier, assertSha256, type GmailDraftEffectProposal, type GmailDraftReceipt } from "./contracts.ts";

export interface GmailDraftOwnerDmReviewAuthority {
  contractType: "qm-gmail-draft-owner-dm-review-authority";
  contractVersion: 1;
  reviewGrantId: string;
  organizationId: string;
  ownerPrincipalId: string;
  slackTeamId: string;
  slackUserId: string;
  channelId: string;
  effectProposalId: string;
  proposalRevision: number;
  draftRevision: number;
  effectPayloadSha256: string;
  draftReceiptSha256: string;
  issuedAt: number;
  expiresAt: number;
  verifiedReceiptSha256: string;
}

export interface GmailDraftOwnerDmPublication {
  authority: GmailDraftOwnerDmReviewAuthority;
  envelope: WorkflowArtifactEnvelope;
}

export interface GmailDraftPrivateOwnerDmPublisherPort {
  boundary: "private_gmail_draft_owner_dm_publisher";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
  publish(input: GmailDraftOwnerDmPublication): Promise<Readonly<{ publicationId: string }>>;
}

export interface GmailDraftPrivateReviewRoutePort {
  boundary: "private_gmail_draft_review_route";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
  issue(input: {
    proposal: GmailDraftEffectProposal;
    receipt: GmailDraftReceipt;
  }): Promise<GmailDraftOwnerDmReviewAuthority>;
}

function validateReviewAuthority(
  authority: GmailDraftOwnerDmReviewAuthority,
  proposal: GmailDraftEffectProposal,
  receipt: GmailDraftReceipt,
  now: number,
): void {
  assertIdentifier(authority.reviewGrantId, "reviewGrantId");
  assertIdentifier(authority.organizationId, "review organizationId");
  assertIdentifier(authority.ownerPrincipalId, "review ownerPrincipalId");
  assertSha256(authority.effectPayloadSha256, "review effectPayloadSha256");
  assertSha256(authority.draftReceiptSha256, "review draftReceiptSha256");
  assertSha256(authority.verifiedReceiptSha256, "review verifiedReceiptSha256");
  if (
    authority.contractType !== "qm-gmail-draft-owner-dm-review-authority" ||
    authority.contractVersion !== 1 ||
    !/^T[A-Z0-9]{8,31}$/u.test(authority.slackTeamId) ||
    !/^U[A-Z0-9]{8,31}$/u.test(authority.slackUserId) ||
    !/^D[A-Z0-9]{8,31}$/u.test(authority.channelId) ||
    authority.organizationId !== proposal.organizationId ||
    authority.ownerPrincipalId !== proposal.ownerPrincipalId ||
    authority.slackTeamId !== proposal.approval.slackTeamId ||
    authority.slackUserId !== proposal.approval.slackUserId ||
    authority.channelId !== proposal.approval.channelId ||
    authority.effectProposalId !== proposal.effectProposalId ||
    authority.proposalRevision !== proposal.revision ||
    authority.draftRevision !== proposal.draftRevision ||
    authority.effectPayloadSha256 !== proposal.effectPayloadSha256 ||
    authority.draftReceiptSha256 !== receipt.receiptSha256 ||
    authority.verifiedReceiptSha256 !== proposal.approval.verifiedReceiptSha256 ||
    receipt.organizationId !== authority.organizationId ||
    receipt.ownerPrincipalId !== authority.ownerPrincipalId ||
    !Number.isSafeInteger(authority.issuedAt) ||
    !Number.isSafeInteger(authority.expiresAt) ||
    authority.issuedAt > now + 30_000 ||
    authority.expiresAt <= now ||
    authority.expiresAt <= authority.issuedAt ||
    authority.expiresAt - authority.issuedAt > 10 * 60_000
  ) {
    throw new TypeError("draft review owner DM authority mismatch");
  }
}

export function gmailDraftReviewCard(input: {
  proposal: GmailDraftEffectProposal;
  receipt: GmailDraftReceipt;
  authority: GmailDraftOwnerDmReviewAuthority;
  privateUiBaseUrl: string;
  now?: number;
}): WorkflowArtifactEnvelope {
  assertIdentifier(input.proposal.effectProposalId, "effectProposalId");
  if (
    input.receipt.effectProposalId !== input.proposal.effectProposalId ||
    input.receipt.effectPayloadSha256 !== input.proposal.effectPayloadSha256 ||
    input.receipt.proposalRevision !== input.proposal.revision ||
    input.receipt.draftRevision !== input.proposal.draftRevision
  ) {
    throw new TypeError("draft review card receipt binding mismatch");
  }
  validateReviewAuthority(input.authority, input.proposal, input.receipt, input.now ?? Date.now());
  const base = new URL(input.privateUiBaseUrl);
  if (base.protocol !== "https:" || base.username || base.password || base.search || base.hash) {
    throw new TypeError("private UI base URL is invalid");
  }
  const review = new URL(`/gmail-drafts/review/${encodeURIComponent(input.authority.reviewGrantId)}`, base);
  if (review.origin !== base.origin) throw new TypeError("draft review URL origin mismatch");
  const card = validateWorkflowArtifactCard(
    {
      heading: "Gmail draft ready for review",
      summary: "A private, source-bound draft was saved to the approved mailbox. Nothing was sent.",
      status: { label: input.receipt.reconciled ? "Reconciled" : "Draft created", tone: "success" },
      sections: [
        {
          key: "draft",
          label: "Draft",
          items: [
            { label: "Operation", value: input.proposal.operation === "create" ? "New draft" : "Updated draft" },
            { label: "Recipients", value: String(input.proposal.to.length) },
            { label: "Sources", value: String(input.proposal.sourceReceiptSha256s.length) },
          ],
        },
      ],
      links: [{ label: "Review draft", href: review.href }],
    },
    base.href,
  );
  return validateWorkflowArtifactEnvelope({
    version: 1,
    renderer: WORKFLOW_ARTIFACT_CARD_RENDERER,
    fallbackText: "Gmail draft ready for private review. Nothing was sent.",
    payload: card,
  });
}
