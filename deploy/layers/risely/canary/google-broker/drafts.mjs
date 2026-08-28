import {
  boundedText,
  exactRecord,
  GoogleBrokerContractError,
  integer,
  nonce32,
  sha256,
  sha256Text,
  timestamp,
} from "./canonical.mjs";
import { validateRequestBinding } from "./contracts.mjs";
import { createPinnedEd25519Verifier } from "./receipts.mjs";

const emailPattern =
  /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const inspectedAttempts = new WeakSet();
const inspectedReconciliations = new WeakSet();
const proposalKeys = Object.freeze([
  "version",
  "proposalId",
  "revision",
  "operation",
  "binding",
  "businessKey",
  "recipients",
  "subject",
  "bodyText",
  "citations",
  "createdAt",
  "expiresAt",
  "payloadHash",
  "effectKey",
  "authorizationHash",
]);
const citationKeys = Object.freeze([
  "version",
  "evidenceHash",
  "organizationId",
  "deploymentId",
  "servicePrincipal",
  "qmPrincipalId",
  "credentialOwnerId",
  "provider",
  "providerAccountSubject",
  "mailbox",
  "accountType",
  "credentialId",
  "credentialVersion",
  "grantId",
  "grantVersion",
  "leaseId",
  "leaseExpiresAt",
  "leaseNonce",
  "jobId",
  "jobClass",
  "operation",
  "requestNonce",
  "idempotencyKey",
  "requestHash",
  "responseHash",
  "receiptId",
  "keyId",
  "observedAt",
]);
const attemptReceiptKeys = Object.freeze([
  "version",
  "receiptId",
  "keyId",
  "algorithm",
  "attemptId",
  "proposalId",
  "proposalRevision",
  "payloadHash",
  "effectKey",
  "authorizationHash",
  "organizationId",
  "deploymentId",
  "servicePrincipal",
  "qmPrincipalId",
  "credentialOwnerId",
  "provider",
  "providerAccountSubject",
  "mailbox",
  "accountType",
  "credentialId",
  "credentialVersion",
  "grantId",
  "grantVersion",
  "leaseId",
  "leaseExpiresAt",
  "leaseNonce",
  "jobId",
  "jobClass",
  "operation",
  "serverClock",
  "serverReceivedAt",
  "serverCompletedAt",
  "providerStatus",
  "outcome",
  "providerDraftId",
  "providerThreadId",
  "signature",
]);
const reconciliationReceiptKeys = Object.freeze([
  "version",
  "receiptId",
  "keyId",
  "algorithm",
  "reconciliationId",
  "priorReceiptId",
  "priorReceiptHash",
  "priorOutcome",
  "payloadHash",
  "effectKey",
  "authorizationHash",
  "organizationId",
  "deploymentId",
  "servicePrincipal",
  "qmPrincipalId",
  "credentialOwnerId",
  "provider",
  "providerAccountSubject",
  "mailbox",
  "accountType",
  "credentialId",
  "credentialVersion",
  "grantId",
  "grantVersion",
  "leaseId",
  "jobId",
  "jobClass",
  "operation",
  "serverClock",
  "serverReceivedAt",
  "serverCheckedAt",
  "serverCompletedAt",
  "durability",
  "providerStatus",
  "outcome",
  "providerDraftId",
  "providerThreadId",
  "signature",
]);

const body = (value) => {
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > 32_768 || value.includes("\u0000")) {
    throw new GoogleBrokerContractError("draft_body_invalid");
  }
  return value;
};

const normalizeRecipients = (value) => {
  const record = exactRecord(value, ["to", "cc", "bcc"], "draft_recipients_invalid");
  const normalize = (entries, label) => {
    if (!Array.isArray(entries) || entries.length > 20) throw new GoogleBrokerContractError("draft_recipients_invalid");
    const result = entries.map((entry) => boundedText(entry, label, 320, emailPattern));
    if (result.some((entry) => entry !== entry.toLowerCase()) || new Set(result).size !== result.length) {
      throw new GoogleBrokerContractError("draft_recipients_invalid");
    }
    return Object.freeze([...result].sort());
  };
  const normalized = Object.freeze({
    to: normalize(record.to, "draft_to"),
    cc: normalize(record.cc, "draft_cc"),
    bcc: normalize(record.bcc, "draft_bcc"),
  });
  const all = [...normalized.to, ...normalized.cc, ...normalized.bcc];
  if (normalized.to.length < 1 || all.length > 20 || new Set(all).size !== all.length) {
    throw new GoogleBrokerContractError("draft_recipients_invalid");
  }
  return normalized;
};

const normalizeCitation = (value, binding) => {
  const record = exactRecord(value, citationKeys, "draft_citation_invalid");
  const citation = Object.freeze({
    version: integer(record.version, "citation_version", 1, 1),
    evidenceHash: sha256Text(record.evidenceHash, "citation_evidence_hash"),
    organizationId: boundedText(record.organizationId, "citation_organization_id", 192),
    deploymentId: boundedText(record.deploymentId, "citation_deployment_id", 192),
    servicePrincipal: boundedText(record.servicePrincipal, "citation_service_principal", 192),
    qmPrincipalId: boundedText(record.qmPrincipalId, "citation_qm_principal", 192),
    credentialOwnerId: boundedText(record.credentialOwnerId, "citation_credential_owner", 192),
    provider: record.provider,
    providerAccountSubject: boundedText(record.providerAccountSubject, "citation_provider_subject", 255),
    mailbox: boundedText(record.mailbox, "citation_mailbox", 320),
    accountType: boundedText(record.accountType, "citation_account_type", 32),
    credentialId: boundedText(record.credentialId, "citation_credential_id", 160),
    credentialVersion: integer(record.credentialVersion, "citation_credential_version", 1, Number.MAX_SAFE_INTEGER),
    grantId: boundedText(record.grantId, "citation_grant_id", 160),
    grantVersion: integer(record.grantVersion, "citation_grant_version", 1, Number.MAX_SAFE_INTEGER),
    leaseId: boundedText(record.leaseId, "citation_lease_id", 160),
    leaseExpiresAt: timestamp(record.leaseExpiresAt, "citation_lease_expires_at").text,
    leaseNonce: nonce32(record.leaseNonce, "citation_lease_nonce"),
    jobId: boundedText(record.jobId, "citation_job_id", 160),
    jobClass: boundedText(record.jobClass, "citation_job_class", 160),
    operation: boundedText(record.operation, "citation_operation", 96),
    requestNonce: nonce32(record.requestNonce, "citation_request_nonce"),
    idempotencyKey: boundedText(record.idempotencyKey, "citation_idempotency_key", 160),
    requestHash: sha256Text(record.requestHash, "citation_request_hash"),
    responseHash: sha256Text(record.responseHash, "citation_response_hash"),
    receiptId: boundedText(record.receiptId, "citation_receipt_id", 160),
    keyId: boundedText(record.keyId, "citation_key_id", 160),
    observedAt: timestamp(record.observedAt, "citation_observed_at").text,
  });
  for (const key of [
    "organizationId",
    "deploymentId",
    "servicePrincipal",
    "qmPrincipalId",
    "credentialOwnerId",
    "provider",
    "providerAccountSubject",
    "mailbox",
    "accountType",
  ]) {
    if (citation[key] !== binding[key]) throw new GoogleBrokerContractError("draft_citation_account_mismatch");
  }
  return citation;
};

const normalizeCitations = (value, binding) => {
  if (!Array.isArray(value) || value.length < 1 || value.length > 50) {
    throw new GoogleBrokerContractError("draft_citations_invalid");
  }
  const citations = value.map((citation) => normalizeCitation(citation, binding));
  if (new Set(citations.map((citation) => citation.evidenceHash)).size !== citations.length) {
    throw new GoogleBrokerContractError("draft_citations_invalid");
  }
  return Object.freeze([...citations].sort((left, right) => left.evidenceHash.localeCompare(right.evidenceHash)));
};

const providerPayload = (proposal) =>
  Object.freeze({
    domain: "qm.google.gmail.draft.provider-payload.v1",
    organizationId: proposal.binding.organizationId,
    provider: proposal.binding.provider,
    providerAccountSubject: proposal.binding.providerAccountSubject,
    mailbox: proposal.binding.mailbox,
    accountType: proposal.binding.accountType,
    businessKey: proposal.businessKey,
    recipients: proposal.recipients,
    subject: proposal.subject,
    bodyText: proposal.bodyText,
    evidenceHashes: proposal.citations.map((citation) => citation.evidenceHash),
  });

const effectPayload = (proposal) =>
  Object.freeze({
    domain: "qm.google.gmail.draft.effect.v1",
    organizationId: proposal.binding.organizationId,
    provider: proposal.binding.provider,
    providerAccountSubject: proposal.binding.providerAccountSubject,
    mailbox: proposal.binding.mailbox,
    accountType: proposal.binding.accountType,
    businessKey: proposal.businessKey,
    payloadHash: proposal.payloadHash,
  });

const authorizationPayload = (proposal) =>
  Object.freeze({
    domain: "qm.google.gmail.draft.authorization.v1",
    proposalId: proposal.proposalId,
    revision: proposal.revision,
    operation: proposal.operation,
    binding: proposal.binding,
    createdAt: proposal.createdAt,
    expiresAt: proposal.expiresAt,
    citations: proposal.citations,
    payloadHash: proposal.payloadHash,
    effectKey: proposal.effectKey,
  });

export const validateDraftProposal = (value) => {
  const record = exactRecord(value, proposalKeys, "draft_proposal_shape_invalid");
  if (record.version !== 1 || record.operation !== "google.gmail.drafts.create") {
    throw new GoogleBrokerContractError("draft_operation_invalid");
  }
  const binding = validateRequestBinding(record.binding);
  const created = timestamp(record.createdAt, "draft_created_at");
  const expires = timestamp(record.expiresAt, "draft_expires_at");
  if (
    expires.epoch <= created.epoch ||
    expires.epoch - created.epoch > 300_000 ||
    expires.epoch > timestamp(binding.leaseExpiresAt, "lease_expires_at").epoch
  ) {
    throw new GoogleBrokerContractError("draft_expiry_invalid");
  }
  const proposal = Object.freeze({
    version: 1,
    proposalId: boundedText(record.proposalId, "proposal_id", 160, /^[A-Za-z0-9][A-Za-z0-9_-]{7,159}$/),
    revision: integer(record.revision, "proposal_revision", 1, Number.MAX_SAFE_INTEGER),
    operation: "google.gmail.drafts.create",
    binding,
    businessKey: boundedText(record.businessKey, "draft_business_key", 160, /^[A-Za-z0-9][A-Za-z0-9_.:-]{7,159}$/),
    recipients: normalizeRecipients(record.recipients),
    subject: boundedText(record.subject, "draft_subject", 998),
    bodyText: body(record.bodyText),
    citations: normalizeCitations(record.citations, binding),
    createdAt: created.text,
    expiresAt: expires.text,
    payloadHash: sha256Text(record.payloadHash, "draft_payload_hash"),
    effectKey: sha256Text(record.effectKey, "draft_effect_key"),
    authorizationHash: sha256Text(record.authorizationHash, "draft_authorization_hash"),
  });
  if (proposal.payloadHash !== sha256(providerPayload(proposal)))
    throw new GoogleBrokerContractError("draft_payload_hash_mismatch");
  if (proposal.effectKey !== sha256(effectPayload(proposal)))
    throw new GoogleBrokerContractError("draft_effect_key_mismatch");
  if (proposal.authorizationHash !== sha256(authorizationPayload(proposal))) {
    throw new GoogleBrokerContractError("draft_authorization_hash_mismatch");
  }
  return proposal;
};

export const createDraftProposal = (value) => {
  const record = exactRecord(value, [
    "version",
    "proposalId",
    "revision",
    "operation",
    "binding",
    "businessKey",
    "recipients",
    "subject",
    "bodyText",
    "citations",
    "createdAt",
    "expiresAt",
  ]);
  const draft = {
    version: record.version,
    proposalId: record.proposalId,
    revision: record.revision,
    operation: record.operation,
    binding: validateRequestBinding(record.binding),
    businessKey: record.businessKey,
    recipients: normalizeRecipients(record.recipients),
    subject: record.subject,
    bodyText: record.bodyText,
    citations: record.citations,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
  };
  draft.citations = normalizeCitations(record.citations, draft.binding);
  draft.payloadHash = sha256(providerPayload(draft));
  draft.effectKey = sha256(effectPayload(draft));
  draft.authorizationHash = sha256(authorizationPayload(draft));
  return validateDraftProposal(draft);
};

const signedPayload = (record) => {
  const { signature, ...payload } = record;
  return payload;
};

const normalizeAttemptReceipt = (value) => {
  const record = exactRecord(value, attemptReceiptKeys, "draft_attempt_receipt_shape_invalid");
  if (
    record.version !== 1 ||
    record.algorithm !== "Ed25519" ||
    record.provider !== "google" ||
    record.operation !== "google.gmail.drafts.create" ||
    record.serverClock !== "postgresql" ||
    !["succeeded", "outcome_unknown"].includes(record.outcome)
  ) {
    throw new GoogleBrokerContractError("draft_attempt_receipt_invalid");
  }
  const received = timestamp(record.serverReceivedAt, "server_received_at");
  const completed = timestamp(record.serverCompletedAt, "server_completed_at");
  if (completed.epoch < received.epoch) throw new GoogleBrokerContractError("draft_attempt_time_invalid");
  const status = record.providerStatus === null ? null : integer(record.providerStatus, "provider_status", 100, 599);
  const draftId =
    record.providerDraftId === null ? null : boundedText(record.providerDraftId, "provider_draft_id", 160);
  const threadId =
    record.providerThreadId === null ? null : boundedText(record.providerThreadId, "provider_thread_id", 160);
  const binding = validateRequestBinding({
    organizationId: record.organizationId,
    deploymentId: record.deploymentId,
    servicePrincipal: record.servicePrincipal,
    qmPrincipalId: record.qmPrincipalId,
    credentialOwnerId: record.credentialOwnerId,
    provider: record.provider,
    providerAccountSubject: record.providerAccountSubject,
    mailbox: record.mailbox,
    accountType: record.accountType,
    credentialId: record.credentialId,
    credentialVersion: record.credentialVersion,
    grantId: record.grantId,
    grantVersion: record.grantVersion,
    leaseId: record.leaseId,
    leaseExpiresAt: record.leaseExpiresAt,
    leaseNonce: record.leaseNonce,
    jobId: record.jobId,
    jobClass: record.jobClass,
  });
  if (record.outcome === "succeeded" && (!(status >= 200 && status <= 299) || !draftId || !threadId)) {
    throw new GoogleBrokerContractError("draft_attempt_outcome_invalid");
  }
  if (record.outcome === "outcome_unknown" && (status !== null || draftId || threadId)) {
    throw new GoogleBrokerContractError("draft_attempt_outcome_invalid");
  }
  return Object.freeze({
    ...record,
    version: 1,
    receiptId: boundedText(record.receiptId, "receipt_id", 160),
    keyId: boundedText(record.keyId, "key_id", 160),
    algorithm: "Ed25519",
    attemptId: boundedText(record.attemptId, "attempt_id", 160),
    proposalId: boundedText(record.proposalId, "proposal_id", 160),
    proposalRevision: integer(record.proposalRevision, "proposal_revision", 1, Number.MAX_SAFE_INTEGER),
    ...binding,
    payloadHash: sha256Text(record.payloadHash, "payload_hash"),
    effectKey: sha256Text(record.effectKey, "effect_key"),
    authorizationHash: sha256Text(record.authorizationHash, "authorization_hash"),
    serverReceivedAt: received.text,
    serverCompletedAt: completed.text,
    providerStatus: status,
    providerDraftId: draftId,
    providerThreadId: threadId,
    signature: boundedText(record.signature, "signature", 512, /^[A-Za-z0-9_-]+$/),
  });
};

const proposalReceiptKeys = Object.freeze([
  "organizationId",
  "deploymentId",
  "servicePrincipal",
  "qmPrincipalId",
  "credentialOwnerId",
  "provider",
  "providerAccountSubject",
  "mailbox",
  "accountType",
  "credentialId",
  "credentialVersion",
  "grantId",
  "grantVersion",
  "leaseId",
  "leaseExpiresAt",
  "leaseNonce",
  "jobId",
  "jobClass",
]);

export const createDraftAttemptInspector = ({ keyId, publicKey }) => {
  const verifier = createPinnedEd25519Verifier({ keyId, publicKey });
  return Object.freeze({
    inspect({ receipt: receiptValue, proposal: proposalValue }) {
      const proposal = validateDraftProposal(proposalValue);
      const receipt = normalizeAttemptReceipt(receiptValue);
      verifier.verify(signedPayload(receipt), {
        keyId: receipt.keyId,
        algorithm: receipt.algorithm,
        signature: receipt.signature,
      });
      for (const key of proposalReceiptKeys) {
        if (receipt[key] !== proposal.binding[key])
          throw new GoogleBrokerContractError("draft_attempt_binding_mismatch");
      }
      if (
        receipt.proposalId !== proposal.proposalId ||
        receipt.proposalRevision !== proposal.revision ||
        receipt.payloadHash !== proposal.payloadHash ||
        receipt.effectKey !== proposal.effectKey ||
        receipt.authorizationHash !== proposal.authorizationHash
      ) {
        throw new GoogleBrokerContractError("draft_attempt_proposal_mismatch");
      }
      const received = timestamp(receipt.serverReceivedAt, "server_received_at").epoch;
      if (
        received < timestamp(proposal.createdAt, "draft_created_at").epoch ||
        received >= timestamp(proposal.expiresAt, "draft_expires_at").epoch ||
        received >= timestamp(proposal.binding.leaseExpiresAt, "lease_expires_at").epoch
      ) {
        throw new GoogleBrokerContractError("draft_attempt_time_invalid");
      }
      const result = Object.freeze({
        receipt,
        proposal,
        receiptHash: sha256(receipt),
        cryptographicallyVerified: true,
        pinFingerprint: verifier.pinFingerprint,
      });
      inspectedAttempts.add(result);
      return result;
    },
  });
};

const normalizeReconciliationReceipt = (value) => {
  const record = exactRecord(value, reconciliationReceiptKeys, "draft_reconciliation_shape_invalid");
  if (
    record.version !== 1 ||
    record.algorithm !== "Ed25519" ||
    record.priorOutcome !== "outcome_unknown" ||
    record.provider !== "google" ||
    record.operation !== "google.gmail.drafts.create" ||
    record.serverClock !== "postgresql" ||
    record.durability !== "postgresql_committed" ||
    !["reconciled_succeeded", "reconciled_absent"].includes(record.outcome)
  ) {
    throw new GoogleBrokerContractError("draft_reconciliation_invalid");
  }
  const received = timestamp(record.serverReceivedAt, "reconciliation_received_at");
  const checked = timestamp(record.serverCheckedAt, "reconciliation_checked_at");
  const completed = timestamp(record.serverCompletedAt, "reconciliation_completed_at");
  if (checked.epoch < received.epoch || completed.epoch < checked.epoch) {
    throw new GoogleBrokerContractError("draft_reconciliation_time_invalid");
  }
  const status = integer(record.providerStatus, "provider_status", 200, 299);
  const draftId =
    record.providerDraftId === null ? null : boundedText(record.providerDraftId, "provider_draft_id", 160);
  const threadId =
    record.providerThreadId === null ? null : boundedText(record.providerThreadId, "provider_thread_id", 160);
  if (record.outcome === "reconciled_succeeded" && (!draftId || !threadId)) {
    throw new GoogleBrokerContractError("draft_reconciliation_outcome_invalid");
  }
  if (record.outcome === "reconciled_absent" && (draftId || threadId)) {
    throw new GoogleBrokerContractError("draft_reconciliation_outcome_invalid");
  }
  return Object.freeze({
    ...record,
    version: 1,
    receiptId: boundedText(record.receiptId, "receipt_id", 160),
    keyId: boundedText(record.keyId, "key_id", 160),
    algorithm: "Ed25519",
    reconciliationId: boundedText(record.reconciliationId, "reconciliation_id", 160),
    priorReceiptId: boundedText(record.priorReceiptId, "prior_receipt_id", 160),
    priorReceiptHash: sha256Text(record.priorReceiptHash, "prior_receipt_hash"),
    payloadHash: sha256Text(record.payloadHash, "payload_hash"),
    effectKey: sha256Text(record.effectKey, "effect_key"),
    authorizationHash: sha256Text(record.authorizationHash, "authorization_hash"),
    organizationId: boundedText(record.organizationId, "organization_id", 192),
    deploymentId: boundedText(record.deploymentId, "deployment_id", 192),
    servicePrincipal: boundedText(record.servicePrincipal, "service_principal", 192),
    qmPrincipalId: boundedText(record.qmPrincipalId, "qm_principal", 192),
    credentialOwnerId: boundedText(record.credentialOwnerId, "credential_owner", 192),
    providerAccountSubject: boundedText(record.providerAccountSubject, "provider_account_subject", 255),
    mailbox: boundedText(record.mailbox, "mailbox", 320),
    accountType: boundedText(record.accountType, "account_type", 32, /^(default|personal|company)$/),
    credentialId: boundedText(record.credentialId, "credential_id", 160),
    credentialVersion: integer(record.credentialVersion, "credential_version", 1, Number.MAX_SAFE_INTEGER),
    grantId: boundedText(record.grantId, "grant_id", 160),
    grantVersion: integer(record.grantVersion, "grant_version", 1, Number.MAX_SAFE_INTEGER),
    leaseId: boundedText(record.leaseId, "lease_id", 160),
    jobId: boundedText(record.jobId, "job_id", 160),
    jobClass: boundedText(record.jobClass, "job_class", 160),
    serverReceivedAt: received.text,
    serverCheckedAt: checked.text,
    serverCompletedAt: completed.text,
    providerStatus: status,
    providerDraftId: draftId,
    providerThreadId: threadId,
    signature: boundedText(record.signature, "signature", 512, /^[A-Za-z0-9_-]+$/),
  });
};

export const createDraftReconciliationInspector = ({ keyId, publicKey }) => {
  const verifier = createPinnedEd25519Verifier({ keyId, publicKey });
  return Object.freeze({
    inspect({ receipt: receiptValue, prior: priorValue }) {
      if (!priorValue || !inspectedAttempts.has(priorValue) || priorValue.receipt.outcome !== "outcome_unknown") {
        throw new GoogleBrokerContractError("signed_outcome_unknown_required");
      }
      if (priorValue.pinFingerprint !== verifier.pinFingerprint || priorValue.receipt.keyId !== verifier.keyId) {
        throw new GoogleBrokerContractError("draft_reconciliation_pin_mismatch");
      }
      const receipt = normalizeReconciliationReceipt(receiptValue);
      verifier.verify(signedPayload(receipt), {
        keyId: receipt.keyId,
        algorithm: receipt.algorithm,
        signature: receipt.signature,
      });
      for (const key of [
        "organizationId",
        "deploymentId",
        "servicePrincipal",
        "qmPrincipalId",
        "credentialOwnerId",
        "provider",
        "providerAccountSubject",
        "mailbox",
        "accountType",
        "credentialId",
        "credentialVersion",
        "grantId",
        "grantVersion",
        "leaseId",
        "jobId",
        "jobClass",
        "operation",
        "payloadHash",
        "effectKey",
        "authorizationHash",
      ]) {
        if (receipt[key] !== priorValue.receipt[key]) {
          throw new GoogleBrokerContractError("draft_reconciliation_prior_mismatch");
        }
      }
      if (
        receipt.priorReceiptId !== priorValue.receipt.receiptId ||
        receipt.priorReceiptHash !== priorValue.receiptHash ||
        timestamp(receipt.serverReceivedAt, "reconciliation_received_at").epoch <
          Math.max(
            timestamp(priorValue.receipt.serverCompletedAt, "attempt_completed_at").epoch,
            timestamp(priorValue.receipt.leaseExpiresAt, "lease_expires_at").epoch,
          )
      ) {
        throw new GoogleBrokerContractError("draft_reconciliation_prior_mismatch");
      }
      const result = Object.freeze({
        receipt,
        prior: priorValue,
        cryptographicallyVerified: true,
        pinFingerprint: verifier.pinFingerprint,
      });
      inspectedReconciliations.add(result);
      return result;
    },
  });
};

export const evaluateDraftRetry = ({ prior, reconciliation }) => {
  if (!prior || !inspectedAttempts.has(prior) || prior.receipt.outcome !== "outcome_unknown") {
    throw new GoogleBrokerContractError("signed_outcome_unknown_required");
  }
  if (!reconciliation || !inspectedReconciliations.has(reconciliation) || reconciliation.prior !== prior) {
    throw new GoogleBrokerContractError("signed_durable_reconciliation_required");
  }
  return Object.freeze({
    mayRequestNewAuthorization: reconciliation.receipt.outcome === "reconciled_absent",
    authorizationRequired: true,
    usableAsExecutionAuthority: false,
    effectKey: prior.receipt.effectKey,
    priorReceiptHash: prior.receiptHash,
    reconciliationReceiptId: reconciliation.receipt.receiptId,
  });
};

export const draftAttemptReceiptPayload = (value) => signedPayload(normalizeAttemptReceipt(value));

export const draftReconciliationReceiptPayload = (value) => signedPayload(normalizeReconciliationReceipt(value));
