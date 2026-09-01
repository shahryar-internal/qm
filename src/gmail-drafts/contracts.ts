import { createHash } from "node:crypto";
import { canonicalJson } from "../cron/schedule-authority.ts";

export const GMAIL_COMPOSE_SCOPE = "https://www.googleapis.com/auth/gmail.compose";
export const GMAIL_DRAFT_CREATE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/drafts";
export const GMAIL_DRAFT_RESPONSE_MAX_BYTES = 256 * 1024;
export const GMAIL_DRAFT_REQUEST_MAX_BYTES = 512 * 1024;
export const GMAIL_DRAFT_BODY_MAX_BYTES = 96 * 1024;
export const GMAIL_DRAFT_DEADLINE_MS = 5_000;

const SHA256 = /^[a-f0-9]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$/u;
const PROVIDER_IDENTIFIER = /^[A-Za-z0-9_-]{1,256}$/u;
const MAILBOX =
  /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/iu;
const SLACK_TIMESTAMP = /^\d{10,13}\.\d{6}$/u;
const MESSAGE_ID = /^<[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+>$/u;

export type GmailDraftOperation = "create" | "update";

export interface GmailDraftConnectionBinding {
  organizationId: string;
  logicalConnectionId: string;
  connectionVersion: number;
  ownerPrincipalId: string;
  googleSubject: string;
  mailbox: string;
  accountType: "personal" | "company";
  grantedScopes: readonly [typeof GMAIL_COMPOSE_SCOPE];
}

export interface VerifiedGmailDraftApproval {
  contractType: "qm-verified-gmail-draft-approval";
  contractVersion: 1;
  issuer: string;
  keyId: string;
  jti: string;
  receiptId: string;
  organizationId: string;
  ownerPrincipalId: string;
  actorPrincipalId: string;
  actorSlackId: string;
  slackTeamId: string;
  slackUserId: string;
  channelId: string;
  messageTs: string;
  threadTs: string;
  actionTs: string;
  humanOrigin: true;
  effectProposalId: string;
  proposalRevision: number;
  draftRevision: number;
  operation: GmailDraftOperation;
  logicalConnectionId: string;
  connectionVersion: number;
  mailbox: string;
  approvedPayloadSha256: string;
  issuedAt: number;
  expiresAt: number;
  signedReceiptSha256: string;
  verifiedReceiptSha256: string;
}

export interface GmailDraftReplyAuthority {
  contractType: "qm-gmail-draft-reply-authority";
  contractVersion: 1;
  sourceReceiptSha256: string;
  gmailThreadId: string;
  parentMessageId: string;
  referenceMessageIds: readonly string[];
  subjectSha256: string;
}

export interface GmailDraftEffectProposal extends GmailDraftConnectionBinding {
  contractType: "qm-gmail-draft-effect-proposal";
  contractVersion: 1;
  effectProposalId: string;
  revision: number;
  draftRevision: number;
  operation: GmailDraftOperation;
  draftId: string | null;
  priorDraftReceiptSha256: string | null;
  to: readonly string[];
  subject: string;
  bodyText: string;
  gmailThreadId: string | null;
  replyAuthority: GmailDraftReplyAuthority | null;
  recipientsSha256: string;
  subjectSha256: string;
  bodySha256: string;
  threadBindingSha256: string;
  businessContextSha256: string;
  sourceReceiptSha256s: readonly string[];
  sourceBundleSha256: string;
  effectPayloadSha256: string;
  approval: VerifiedGmailDraftApproval;
}

export interface GmailDraftAttempt {
  attemptId: string;
  effectProposalId: string;
  proposalRevision: number;
  draftRevision: number;
  startedAt: number;
  proposal: GmailDraftEffectProposal;
}

export interface GmailDraftReconciliationLease {
  nonce: string;
  expiresAt: number;
}

export interface GmailDraftReceipt {
  contractType: "qm-gmail-draft-receipt";
  contractVersion: 1;
  operation: GmailDraftOperation;
  effectProposalId: string;
  proposalRevision: number;
  draftRevision: number;
  attemptId: string;
  organizationId: string;
  ownerPrincipalId: string;
  logicalConnectionId: string;
  connectionVersion: number;
  googleSubject: string;
  mailbox: string;
  approvalJti: string;
  draftId: string;
  messageId: string;
  threadId: string | null;
  recipientsSha256: string;
  subjectSha256: string;
  bodySha256: string;
  threadBindingSha256: string;
  businessContextSha256: string;
  sourceBundleSha256: string;
  effectPayloadSha256: string;
  mimeSha256: string;
  requestSha256: string;
  responseSha256: string;
  credentialReceiptSha256: string;
  createdAt: number;
  reconciled: boolean;
  receiptSha256: string;
}

export type GmailDraftUnknownCode =
  | "network_failure"
  | "deadline_exceeded"
  | "redirect_response"
  | "response_too_large"
  | "invalid_success_response"
  | "server_error";

export interface GmailDraftUnknownReceipt {
  contractType: "qm-gmail-draft-outcome-unknown";
  contractVersion: 1;
  operation: GmailDraftOperation;
  effectProposalId: string;
  proposalRevision: number;
  draftRevision: number;
  attemptId: string;
  effectPayloadSha256: string;
  requestSha256: string;
  markerMessageId: string;
  draftId: string | null;
  code: GmailDraftUnknownCode;
  recordedAt: number;
  receiptSha256: string;
}

export type GmailDraftRejectionCode =
  | "approval_invalid"
  | "approval_expired"
  | "proposal_invalid"
  | "connection_unavailable"
  | "connection_mismatch"
  | "scope_missing"
  | "gmail_unauthorized"
  | "gmail_rejected";

export type GmailDraftNoWriteRejectionProof = "before_effect" | "provider_definitive_no_write";

export type GmailDraftBeginResult =
  | { status: "claimed"; attempt: GmailDraftAttempt }
  | { status: "created"; receipt: GmailDraftReceipt }
  | { status: "outcome_unknown"; receipt: GmailDraftUnknownReceipt }
  | { status: "rejected"; code: GmailDraftRejectionCode }
  | { status: "in_progress" };

export type GmailDraftReconcileBeginResult =
  | {
      status: "claimed";
      attempt: GmailDraftAttempt;
      unknown: GmailDraftUnknownReceipt;
      lease: GmailDraftReconciliationLease;
    }
  | { status: "created"; receipt: GmailDraftReceipt }
  | { status: "outcome_unknown"; receipt: GmailDraftUnknownReceipt }
  | { status: "rejected"; code: GmailDraftRejectionCode }
  | { status: "in_progress" };

export interface GmailDraftExecutionStore {
  durability: "postgres";
  idempotency: "single_effect_proposal";
  approvalAdmission: "signature_verified_current_click_one_time";
  terminalUnknownPolicy: "reconcile_only_no_automatic_mutation_retry";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
  begin(effectProposalId: string): Promise<GmailDraftBeginResult>;
  beginReconciliation(effectProposalId: string): Promise<GmailDraftReconcileBeginResult>;
  armEffect(attempt: GmailDraftAttempt, crashReceipt: GmailDraftUnknownReceipt): Promise<boolean>;
  reject(
    attempt: GmailDraftAttempt,
    code: GmailDraftRejectionCode,
    proof: GmailDraftNoWriteRejectionProof,
  ): Promise<boolean>;
  recordCreated(
    attempt: GmailDraftAttempt,
    receipt: GmailDraftReceipt,
    reconciliationLease: GmailDraftReconciliationLease | null,
  ): Promise<GmailDraftReceipt>;
  recordUnknown(attempt: GmailDraftAttempt, receipt: GmailDraftUnknownReceipt): Promise<GmailDraftUnknownReceipt>;
  retainUnknown(
    attempt: GmailDraftAttempt,
    receipt: GmailDraftUnknownReceipt,
    reconciliationLease: GmailDraftReconciliationLease,
  ): Promise<GmailDraftUnknownReceipt>;
}

export type GmailDraftBrokerOutcome =
  | { status: "created" | "replayed" | "reconciled"; receipt: GmailDraftReceipt }
  | { status: "outcome_unknown"; receipt: GmailDraftUnknownReceipt }
  | { status: "rejected"; code: GmailDraftRejectionCode }
  | { status: "in_progress" }
  | { status: "unavailable" };

export function sha256Bytes(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function sha256Canonical(value: unknown): string {
  return sha256Bytes(canonicalJson(value));
}

function exactKeys(value: object, expected: readonly string[], name: string): void {
  canonicalJson(value);
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new TypeError(`${name} has an invalid shape`);
  }
}

export function assertIdentifier(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new TypeError(`${name} is invalid`);
}

export function assertProviderIdentifier(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !PROVIDER_IDENTIFIER.test(value)) throw new TypeError(`${name} is invalid`);
}

export function assertSha256(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError(`${name} is invalid`);
}

export function normalizedMailbox(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length > 254 || !MAILBOX.test(value) || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError(`${name} is invalid`);
  }
  const at = value.lastIndexOf("@");
  return `${value.slice(0, at)}@${value.slice(at + 1).toLowerCase()}`;
}

function slackTimestamp(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !SLACK_TIMESTAMP.test(value)) throw new TypeError(`${name} is invalid`);
}

function slackTimestampMicros(value: string): bigint {
  const separator = value.indexOf(".");
  return BigInt(value.slice(0, separator)) * 1_000_000n + BigInt(value.slice(separator + 1));
}

function messageId(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || value.length > 998 || /[\r\n]/u.test(value) || !MESSAGE_ID.test(value))
    throw new TypeError(`${name} is invalid`);
}

function immutable<T>(value: T): T {
  const clone = structuredClone(value);
  const freeze = (entry: unknown): void => {
    if (!entry || typeof entry !== "object" || Object.isFrozen(entry)) return;
    for (const child of Object.values(entry)) freeze(child);
    Object.freeze(entry);
  };
  freeze(clone);
  return clone;
}

export function validateConnectionBinding(value: GmailDraftConnectionBinding): GmailDraftConnectionBinding {
  exactKeys(
    value,
    [
      "organizationId",
      "logicalConnectionId",
      "connectionVersion",
      "ownerPrincipalId",
      "googleSubject",
      "mailbox",
      "accountType",
      "grantedScopes",
    ],
    "connection binding",
  );
  assertIdentifier(value.organizationId, "organizationId");
  assertIdentifier(value.logicalConnectionId, "logicalConnectionId");
  assertIdentifier(value.ownerPrincipalId, "ownerPrincipalId");
  assertIdentifier(value.googleSubject, "googleSubject");
  if (!Number.isSafeInteger(value.connectionVersion) || value.connectionVersion < 1) {
    throw new TypeError("connectionVersion is invalid");
  }
  if (value.accountType !== "personal" && value.accountType !== "company") {
    throw new TypeError("accountType is invalid");
  }
  if (normalizedMailbox(value.mailbox, "mailbox") !== value.mailbox) throw new TypeError("mailbox is not canonical");
  if (
    !Array.isArray(value.grantedScopes) ||
    value.grantedScopes.length !== 1 ||
    value.grantedScopes[0] !== GMAIL_COMPOSE_SCOPE
  ) {
    throw new TypeError("grantedScopes must be exact gmail.compose");
  }
  return immutable(value);
}

function validateApproval(value: VerifiedGmailDraftApproval, proposal: GmailDraftEffectProposal, now: number): void {
  exactKeys(
    value,
    [
      "contractType",
      "contractVersion",
      "issuer",
      "keyId",
      "jti",
      "receiptId",
      "organizationId",
      "ownerPrincipalId",
      "actorPrincipalId",
      "actorSlackId",
      "slackTeamId",
      "slackUserId",
      "channelId",
      "messageTs",
      "threadTs",
      "actionTs",
      "humanOrigin",
      "effectProposalId",
      "proposalRevision",
      "draftRevision",
      "operation",
      "logicalConnectionId",
      "connectionVersion",
      "mailbox",
      "approvedPayloadSha256",
      "issuedAt",
      "expiresAt",
      "signedReceiptSha256",
      "verifiedReceiptSha256",
    ],
    "approval",
  );
  if (
    value.contractType !== "qm-verified-gmail-draft-approval" ||
    value.contractVersion !== 1 ||
    value.humanOrigin !== true
  ) {
    throw new TypeError("approval contract is invalid");
  }
  for (const [name, entry] of Object.entries({
    issuer: value.issuer,
    keyId: value.keyId,
    jti: value.jti,
    receiptId: value.receiptId,
    organizationId: value.organizationId,
    ownerPrincipalId: value.ownerPrincipalId,
    actorPrincipalId: value.actorPrincipalId,
    logicalConnectionId: value.logicalConnectionId,
  }))
    assertIdentifier(entry, `approval.${name}`);
  if (
    !/^T[A-Z0-9]{8,31}$/u.test(value.slackTeamId) ||
    !/^U[A-Z0-9]{8,31}$/u.test(value.slackUserId) ||
    value.actorSlackId !== value.slackUserId ||
    !/^D[A-Z0-9]{8,31}$/u.test(value.channelId)
  ) {
    throw new TypeError("approval Slack owner DM binding is invalid");
  }
  slackTimestamp(value.messageTs, "approval.messageTs");
  slackTimestamp(value.threadTs, "approval.threadTs");
  slackTimestamp(value.actionTs, "approval.actionTs");
  const messageSequence = slackTimestampMicros(value.messageTs);
  const threadSequence = slackTimestampMicros(value.threadTs);
  const actionSequence = slackTimestampMicros(value.actionTs);
  const actionAt = Number(actionSequence / 1_000n);
  if (
    value.actorPrincipalId !== value.ownerPrincipalId ||
    value.organizationId !== proposal.organizationId ||
    value.ownerPrincipalId !== proposal.ownerPrincipalId ||
    value.effectProposalId !== proposal.effectProposalId ||
    value.proposalRevision !== proposal.revision ||
    value.draftRevision !== proposal.draftRevision ||
    value.operation !== proposal.operation ||
    value.logicalConnectionId !== proposal.logicalConnectionId ||
    value.connectionVersion !== proposal.connectionVersion ||
    value.mailbox !== proposal.mailbox ||
    value.approvedPayloadSha256 !== proposal.effectPayloadSha256
  ) {
    throw new TypeError("approval effect binding mismatch");
  }
  if (
    !Number.isSafeInteger(value.issuedAt) ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.issuedAt > now + 30_000 ||
    value.expiresAt <= now ||
    value.expiresAt <= value.issuedAt ||
    value.expiresAt - value.issuedAt > 5 * 60_000 ||
    !Number.isSafeInteger(actionAt) ||
    threadSequence > messageSequence ||
    messageSequence > actionSequence ||
    actionAt < value.issuedAt - 30_000 ||
    actionAt > value.issuedAt + 30_000
  ) {
    throw new TypeError("approval is not current");
  }
  assertSha256(value.approvedPayloadSha256, "approval.approvedPayloadSha256");
  assertSha256(value.signedReceiptSha256, "approval.signedReceiptSha256");
  assertSha256(value.verifiedReceiptSha256, "approval.verifiedReceiptSha256");
}

export function gmailDraftThreadBinding(
  proposal: Pick<GmailDraftEffectProposal, "gmailThreadId" | "replyAuthority">,
): Readonly<Record<string, unknown>> {
  return {
    gmailThreadId: proposal.gmailThreadId,
    replyAuthority:
      proposal.replyAuthority === null
        ? null
        : { ...proposal.replyAuthority, referenceMessageIds: [...proposal.replyAuthority.referenceMessageIds] },
  };
}

export function gmailDraftEffectPayload(proposal: GmailDraftEffectProposal): Readonly<Record<string, unknown>> {
  return {
    effectProposalId: proposal.effectProposalId,
    organizationId: proposal.organizationId,
    ownerPrincipalId: proposal.ownerPrincipalId,
    logicalConnectionId: proposal.logicalConnectionId,
    connectionVersion: proposal.connectionVersion,
    googleSubject: proposal.googleSubject,
    mailbox: proposal.mailbox,
    accountType: proposal.accountType,
    grantedScopes: [...proposal.grantedScopes],
    revision: proposal.revision,
    draftRevision: proposal.draftRevision,
    operation: proposal.operation,
    draftId: proposal.draftId,
    priorDraftReceiptSha256: proposal.priorDraftReceiptSha256,
    to: [...proposal.to],
    subject: proposal.subject,
    bodyText: proposal.bodyText,
    gmailThreadId: proposal.gmailThreadId,
    replyAuthority:
      proposal.replyAuthority === null
        ? null
        : { ...proposal.replyAuthority, referenceMessageIds: [...proposal.replyAuthority.referenceMessageIds] },
    recipientsSha256: proposal.recipientsSha256,
    subjectSha256: proposal.subjectSha256,
    bodySha256: proposal.bodySha256,
    threadBindingSha256: proposal.threadBindingSha256,
    businessContextSha256: proposal.businessContextSha256,
    sourceReceiptSha256s: [...proposal.sourceReceiptSha256s],
    sourceBundleSha256: proposal.sourceBundleSha256,
  };
}

export function validateEffectProposal(value: GmailDraftEffectProposal, now: number): GmailDraftEffectProposal {
  exactKeys(
    value,
    [
      "contractType",
      "contractVersion",
      "effectProposalId",
      "revision",
      "draftRevision",
      "operation",
      "draftId",
      "priorDraftReceiptSha256",
      "organizationId",
      "logicalConnectionId",
      "connectionVersion",
      "ownerPrincipalId",
      "googleSubject",
      "mailbox",
      "accountType",
      "grantedScopes",
      "to",
      "subject",
      "bodyText",
      "gmailThreadId",
      "replyAuthority",
      "recipientsSha256",
      "subjectSha256",
      "bodySha256",
      "threadBindingSha256",
      "businessContextSha256",
      "sourceReceiptSha256s",
      "sourceBundleSha256",
      "effectPayloadSha256",
      "approval",
    ],
    "effect proposal",
  );
  if (value.contractType !== "qm-gmail-draft-effect-proposal" || value.contractVersion !== 1) {
    throw new TypeError("effect proposal contract is invalid");
  }
  validateConnectionBinding({
    organizationId: value.organizationId,
    logicalConnectionId: value.logicalConnectionId,
    connectionVersion: value.connectionVersion,
    ownerPrincipalId: value.ownerPrincipalId,
    googleSubject: value.googleSubject,
    mailbox: value.mailbox,
    accountType: value.accountType,
    grantedScopes: value.grantedScopes,
  });
  assertIdentifier(value.effectProposalId, "effectProposalId");
  if (
    !Number.isSafeInteger(value.revision) ||
    value.revision < 1 ||
    !Number.isSafeInteger(value.draftRevision) ||
    value.draftRevision < 1 ||
    !["create", "update"].includes(value.operation)
  ) {
    throw new TypeError("effect proposal revision or operation is invalid");
  }
  if (value.operation === "create") {
    if (value.draftRevision !== 1 || value.draftId !== null || value.priorDraftReceiptSha256 !== null)
      throw new TypeError("create draft target is invalid");
  } else {
    if (value.draftRevision <= 1) throw new TypeError("update draft revision is invalid");
    assertProviderIdentifier(value.draftId, "draftId");
    assertSha256(value.priorDraftReceiptSha256, "priorDraftReceiptSha256");
  }
  if (!Array.isArray(value.to) || value.to.length < 1 || value.to.length > 20) {
    throw new TypeError("effect proposal recipients are invalid");
  }
  const recipients = value.to.map((entry) => normalizedMailbox(entry, "recipient"));
  if (
    new Set(recipients.map((entry) => entry.toLowerCase())).size !== recipients.length ||
    recipients.some((entry, index) => entry !== value.to[index])
  ) {
    throw new TypeError("effect proposal recipients are duplicated or noncanonical");
  }
  if (
    typeof value.subject !== "string" ||
    value.subject.length < 1 ||
    value.subject.length > 300 ||
    /[\r\n\u0000-\u001f\u007f]/u.test(value.subject)
  )
    throw new TypeError("effect proposal subject is invalid");
  if (
    typeof value.bodyText !== "string" ||
    value.bodyText.length < 1 ||
    Buffer.byteLength(value.bodyText, "utf8") > GMAIL_DRAFT_BODY_MAX_BYTES ||
    /[\u0000\u000b\u000c\u007f]/u.test(value.bodyText)
  ) {
    throw new TypeError("effect proposal body is invalid");
  }
  if (value.gmailThreadId !== null) assertProviderIdentifier(value.gmailThreadId, "gmailThreadId");
  if (value.replyAuthority === null) {
    if (value.operation === "create" && value.gmailThreadId !== null) {
      throw new TypeError("new threaded draft requires reply authority");
    }
  } else {
    exactKeys(
      value.replyAuthority,
      [
        "contractType",
        "contractVersion",
        "sourceReceiptSha256",
        "gmailThreadId",
        "parentMessageId",
        "referenceMessageIds",
        "subjectSha256",
      ],
      "reply authority",
    );
    if (
      value.replyAuthority.contractType !== "qm-gmail-draft-reply-authority" ||
      value.replyAuthority.contractVersion !== 1
    ) {
      throw new TypeError("reply authority contract is invalid");
    }
    assertSha256(value.replyAuthority.sourceReceiptSha256, "replyAuthority.sourceReceiptSha256");
    assertProviderIdentifier(value.replyAuthority.gmailThreadId, "replyAuthority.gmailThreadId");
    messageId(value.replyAuthority.parentMessageId, "replyAuthority.parentMessageId");
    assertSha256(value.replyAuthority.subjectSha256, "replyAuthority.subjectSha256");
    if (
      !Array.isArray(value.replyAuthority.referenceMessageIds) ||
      value.replyAuthority.referenceMessageIds.length > 20
    ) {
      throw new TypeError("replyAuthority.referenceMessageIds is invalid");
    }
    for (const entry of value.replyAuthority.referenceMessageIds) messageId(entry, "replyAuthority.referenceMessageId");
    if (
      value.replyAuthority.referenceMessageIds.length === 0 ||
      new Set(value.replyAuthority.referenceMessageIds).size !== value.replyAuthority.referenceMessageIds.length ||
      value.replyAuthority.referenceMessageIds.at(-1) !== value.replyAuthority.parentMessageId ||
      value.replyAuthority.gmailThreadId !== value.gmailThreadId ||
      value.replyAuthority.subjectSha256 !== value.subjectSha256 ||
      !value.sourceReceiptSha256s.includes(value.replyAuthority.sourceReceiptSha256)
    ) {
      throw new TypeError("reply source authority mismatch");
    }
  }
  if (
    !Array.isArray(value.sourceReceiptSha256s) ||
    value.sourceReceiptSha256s.length < 1 ||
    value.sourceReceiptSha256s.length > 64 ||
    new Set(value.sourceReceiptSha256s).size !== value.sourceReceiptSha256s.length
  ) {
    throw new TypeError("source receipts are invalid");
  }
  for (const digest of value.sourceReceiptSha256s) assertSha256(digest, "sourceReceiptSha256");
  for (const [name, digest] of Object.entries({
    recipientsSha256: value.recipientsSha256,
    subjectSha256: value.subjectSha256,
    bodySha256: value.bodySha256,
    threadBindingSha256: value.threadBindingSha256,
    businessContextSha256: value.businessContextSha256,
    sourceBundleSha256: value.sourceBundleSha256,
    effectPayloadSha256: value.effectPayloadSha256,
  }))
    assertSha256(digest, name);
  if (
    sha256Canonical(recipients) !== value.recipientsSha256 ||
    sha256Bytes(value.subject) !== value.subjectSha256 ||
    sha256Bytes(value.bodyText) !== value.bodySha256 ||
    sha256Canonical(gmailDraftThreadBinding(value)) !== value.threadBindingSha256 ||
    sha256Canonical(value.sourceReceiptSha256s) !== value.sourceBundleSha256
  ) {
    throw new TypeError("effect proposal content hash mismatch");
  }
  if (sha256Canonical(gmailDraftEffectPayload(value)) !== value.effectPayloadSha256) {
    throw new TypeError("effect payload hash mismatch");
  }
  validateApproval(value.approval, value, now);
  return immutable(value);
}

export function gmailDraftReceiptDigest<T extends GmailDraftReceipt | GmailDraftUnknownReceipt>(
  receipt: Omit<T, "receiptSha256">,
): string {
  return sha256Canonical(receipt);
}
