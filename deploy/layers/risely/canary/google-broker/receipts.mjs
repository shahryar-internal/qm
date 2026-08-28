import { createPublicKey, verify } from "node:crypto";
import {
  boundedText,
  canonicalBytes,
  exactRecord,
  GoogleBrokerContractError,
  integer,
  nonce32,
  sha256,
  sha256Text,
  timestamp,
} from "./canonical.mjs";
import { inspectUntrustedAuthorityRequest, inspectUntrustedGrantLease, snapshotProviderJson } from "./contracts.mjs";

const inspectedAuthorities = new WeakSet();
const inspectedReads = new WeakSet();
const receiptOutcomes = Object.freeze(["succeeded", "revoked", "quarantined", "unavailable"]);
const envelopeKeys = Object.freeze([
  "version",
  "keyId",
  "algorithm",
  "grant",
  "lease",
  "serverAssertedAt",
  "signature",
]);
const receiptKeys = Object.freeze([
  "version",
  "receiptId",
  "keyId",
  "algorithm",
  "authorityEnvelopeHash",
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
  "grantExpiresAt",
  "leaseId",
  "leaseExpiresAt",
  "leaseNonce",
  "jobId",
  "jobClass",
  "operation",
  "requestNonce",
  "idempotencyKey",
  "requestHash",
  "serverClock",
  "serverReceivedAt",
  "serverCompletedAt",
  "providerStatus",
  "redirected",
  "responseHash",
  "responseBytes",
  "outcome",
  "outcomeReason",
  "signature",
]);
const identityKeys = Object.freeze([
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
]);

const base64url = (value, label, bytes) => {
  boundedText(value, label, 512, /^[A-Za-z0-9_-]+$/);
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength !== bytes || decoded.toString("base64url") !== value) {
    throw new GoogleBrokerContractError(`${label}_invalid`);
  }
  return decoded;
};

export const createPinnedEd25519Verifier = ({ keyId, publicKey }) => {
  const pinnedKeyId = boundedText(keyId, "pinned_key_id", 160, /^[A-Za-z0-9][A-Za-z0-9_.-]{7,159}$/);
  if (
    typeof publicKey !== "string" ||
    publicKey.length > 16_384 ||
    !publicKey.includes("-----BEGIN PUBLIC KEY-----") ||
    !publicKey.includes("-----END PUBLIC KEY-----") ||
    publicKey.includes("PRIVATE KEY")
  ) {
    throw new GoogleBrokerContractError("pinned_public_key_invalid");
  }
  let key;
  try {
    key = createPublicKey(publicKey);
  } catch {
    throw new GoogleBrokerContractError("pinned_public_key_invalid");
  }
  if (key.asymmetricKeyType !== "ed25519") throw new GoogleBrokerContractError("pinned_public_key_invalid");
  const pinFingerprint = sha256(key.export({ format: "jwk" }));
  return Object.freeze({
    keyId: pinnedKeyId,
    pinFingerprint,
    verify(payload, envelope) {
      const record = exactRecord(envelope, ["keyId", "algorithm", "signature"], "signature_envelope_invalid");
      if (record.keyId !== pinnedKeyId) throw new GoogleBrokerContractError("signature_key_id_mismatch");
      if (record.algorithm !== "Ed25519") throw new GoogleBrokerContractError("signature_algorithm_invalid");
      const signature = base64url(record.signature, "signature", 64);
      if (!verify(null, canonicalBytes(payload), key, signature))
        throw new GoogleBrokerContractError("signature_invalid");
      return true;
    },
  });
};

const withoutSignature = (record) => {
  const { signature, ...payload } = record;
  return payload;
};

const normalizeAuthorityEnvelope = (value) => {
  const record = exactRecord(value, envelopeKeys, "authority_envelope_shape_invalid");
  if (record.version !== 1 || record.algorithm !== "Ed25519") {
    throw new GoogleBrokerContractError("authority_envelope_invalid");
  }
  const inspected = inspectUntrustedGrantLease({ grant: record.grant, lease: record.lease });
  const grant = inspected.grant;
  const lease = inspected.lease;
  const asserted = timestamp(record.serverAssertedAt, "authority_server_asserted_at");
  if (
    grant.state !== "active" ||
    lease.state !== "active" ||
    asserted.epoch < timestamp(grant.issuedAt, "grant_issued_at").epoch ||
    asserted.epoch >= timestamp(grant.expiresAt, "grant_expires_at").epoch ||
    asserted.epoch < timestamp(lease.issuedAt, "lease_issued_at").epoch ||
    asserted.epoch >= timestamp(lease.expiresAt, "lease_expires_at").epoch
  ) {
    throw new GoogleBrokerContractError("authority_server_assertion_invalid");
  }
  return Object.freeze({
    version: 1,
    keyId: boundedText(record.keyId, "key_id", 160),
    algorithm: "Ed25519",
    grant,
    lease,
    serverAssertedAt: asserted.text,
    signature: boundedText(record.signature, "signature", 512, /^[A-Za-z0-9_-]+$/),
  });
};

export const createAuthorityInspector = ({ keyId, publicKey }) => {
  const verifier = createPinnedEd25519Verifier({ keyId, publicKey });
  return Object.freeze({
    inspect(value) {
      const envelope = normalizeAuthorityEnvelope(value);
      verifier.verify(withoutSignature(envelope), {
        keyId: envelope.keyId,
        algorithm: envelope.algorithm,
        signature: envelope.signature,
      });
      const result = Object.freeze({
        envelope,
        envelopeHash: sha256(envelope),
        pinFingerprint: verifier.pinFingerprint,
        cryptographicallyVerified: true,
        usable: false,
        reason: "trusted_current_time_unavailable",
      });
      inspectedAuthorities.add(result);
      return result;
    },
  });
};

const normalizeReceipt = (value) => {
  const record = exactRecord(value, receiptKeys, "receipt_shape_invalid");
  if (
    record.version !== 1 ||
    record.provider !== "google" ||
    record.algorithm !== "Ed25519" ||
    record.serverClock !== "postgresql" ||
    record.redirected !== false ||
    !receiptOutcomes.includes(record.outcome)
  ) {
    throw new GoogleBrokerContractError(record.redirected === true ? "provider_redirect_rejected" : "receipt_invalid");
  }
  const received = timestamp(record.serverReceivedAt, "server_received_at");
  const completed = timestamp(record.serverCompletedAt, "server_completed_at");
  const grantExpires = timestamp(record.grantExpiresAt, "grant_expires_at");
  const leaseExpires = timestamp(record.leaseExpiresAt, "lease_expires_at");
  if (completed.epoch < received.epoch) throw new GoogleBrokerContractError("receipt_time_invalid");
  const normalized = {
    version: 1,
    receiptId: boundedText(record.receiptId, "receipt_id", 160, /^[A-Za-z0-9][A-Za-z0-9_-]{7,159}$/),
    keyId: boundedText(record.keyId, "key_id", 160, /^[A-Za-z0-9][A-Za-z0-9_.-]{7,159}$/),
    algorithm: "Ed25519",
    authorityEnvelopeHash: sha256Text(record.authorityEnvelopeHash, "authority_envelope_hash"),
    organizationId: boundedText(record.organizationId, "organization_id", 192),
    deploymentId: boundedText(record.deploymentId, "deployment_id", 192),
    servicePrincipal: boundedText(record.servicePrincipal, "service_principal", 192),
    qmPrincipalId: boundedText(record.qmPrincipalId, "qm_principal_id", 192),
    credentialOwnerId: boundedText(record.credentialOwnerId, "credential_owner_id", 192),
    provider: "google",
    providerAccountSubject: boundedText(record.providerAccountSubject, "provider_account_subject", 255),
    mailbox: boundedText(record.mailbox, "mailbox", 320),
    accountType: boundedText(record.accountType, "account_type", 32),
    credentialId: boundedText(record.credentialId, "credential_id", 160),
    credentialVersion: integer(record.credentialVersion, "credential_version", 1, Number.MAX_SAFE_INTEGER),
    grantId: boundedText(record.grantId, "grant_id", 160),
    grantVersion: integer(record.grantVersion, "grant_version", 1, Number.MAX_SAFE_INTEGER),
    grantExpiresAt: grantExpires.text,
    leaseId: boundedText(record.leaseId, "lease_id", 160),
    leaseExpiresAt: leaseExpires.text,
    leaseNonce: nonce32(record.leaseNonce, "lease_nonce"),
    jobId: boundedText(record.jobId, "job_id", 160),
    jobClass: boundedText(record.jobClass, "job_class", 160),
    operation: boundedText(record.operation, "operation", 96),
    requestNonce: nonce32(record.requestNonce, "request_nonce"),
    idempotencyKey: boundedText(record.idempotencyKey, "idempotency_key", 160),
    requestHash: sha256Text(record.requestHash, "request_hash"),
    serverClock: "postgresql",
    serverReceivedAt: received.text,
    serverCompletedAt: completed.text,
    providerStatus: integer(record.providerStatus, "provider_status", 100, 599),
    redirected: false,
    responseHash: sha256Text(record.responseHash, "response_hash"),
    responseBytes: integer(record.responseBytes, "response_bytes", 1, 262_144),
    outcome: record.outcome,
    outcomeReason:
      record.outcomeReason === null
        ? null
        : boundedText(record.outcomeReason, "outcome_reason", 128, /^[a-z][a-z0-9_.-]{1,127}$/),
    signature: boundedText(record.signature, "signature", 512, /^[A-Za-z0-9_-]+$/),
  };
  if ((normalized.outcome === "succeeded") !== (normalized.providerStatus >= 200 && normalized.providerStatus <= 299)) {
    throw new GoogleBrokerContractError("receipt_outcome_invalid");
  }
  if ((normalized.outcome === "succeeded") !== (normalized.outcomeReason === null)) {
    throw new GoogleBrokerContractError("receipt_outcome_reason_invalid");
  }
  return Object.freeze(normalized);
};

const assertAuthorityInspection = (value) => {
  if (!value || !inspectedAuthorities.has(value))
    throw new GoogleBrokerContractError("signed_authority_inspection_required");
  return value;
};

const assertListingInspection = (value) => {
  if (!value || !inspectedReads.has(value)) throw new GoogleBrokerContractError("signed_listing_inspection_required");
  if (value.receipt.operation !== "google.gmail.messages.list") {
    throw new GoogleBrokerContractError("gmail_inbox_listing_required");
  }
  return value;
};

const assertProviderCardinality = (request, response, outcome) => {
  if (request.operation === "google.calendar.events.list") {
    const items = response.items === undefined ? [] : response.items;
    if (!Array.isArray(items) || items.length > request.parameters.maxResults) {
      throw new GoogleBrokerContractError("calendar_result_bounds_exceeded");
    }
  }
  if (request.operation === "google.gmail.messages.list") {
    const messages = response.messages === undefined ? [] : response.messages;
    if (!Array.isArray(messages) || messages.length > request.parameters.maxResults) {
      throw new GoogleBrokerContractError("gmail_result_bounds_exceeded");
    }
  }
  if (
    request.operation === "google.gmail.messages.get" &&
    outcome === "succeeded" &&
    response.id !== request.parameters.messageId
  ) {
    throw new GoogleBrokerContractError("gmail_message_binding_mismatch");
  }
};

export const createReadReceiptInspector = ({ keyId, publicKey }) => {
  const verifier = createPinnedEd25519Verifier({ keyId, publicKey });
  return Object.freeze({
    inspect({
      authority: authorityValue,
      receipt: receiptValue,
      request: requestValue,
      response: responseValue,
      listing,
    }) {
      const authority = assertAuthorityInspection(authorityValue);
      if (authority.pinFingerprint !== verifier.pinFingerprint || authority.envelope.keyId !== verifier.keyId) {
        throw new GoogleBrokerContractError("receipt_pin_mismatch");
      }
      const envelope = authority.envelope;
      const inspected = inspectUntrustedAuthorityRequest({
        grant: envelope.grant,
        lease: envelope.lease,
        request: requestValue,
      });
      const { request } = inspected;
      const receipt = normalizeReceipt(receiptValue);
      verifier.verify(withoutSignature(receipt), {
        keyId: receipt.keyId,
        algorithm: receipt.algorithm,
        signature: receipt.signature,
      });
      if (receipt.authorityEnvelopeHash !== authority.envelopeHash) {
        throw new GoogleBrokerContractError("receipt_authority_mismatch");
      }
      for (const key of identityKeys) {
        if (receipt[key] !== request.binding[key]) throw new GoogleBrokerContractError("receipt_binding_mismatch");
      }
      if (
        receipt.grantExpiresAt !== envelope.grant.expiresAt ||
        receipt.leaseId !== request.binding.leaseId ||
        receipt.leaseExpiresAt !== request.binding.leaseExpiresAt ||
        receipt.leaseNonce !== request.binding.leaseNonce ||
        receipt.jobId !== request.binding.jobId ||
        receipt.jobClass !== request.binding.jobClass ||
        receipt.operation !== request.operation ||
        receipt.requestNonce !== request.requestNonce ||
        receipt.idempotencyKey !== request.idempotencyKey ||
        receipt.requestHash !== request.requestHash
      ) {
        throw new GoogleBrokerContractError("receipt_request_mismatch");
      }
      const received = timestamp(receipt.serverReceivedAt, "server_received_at").epoch;
      if (
        received < timestamp(envelope.serverAssertedAt, "authority_server_asserted_at").epoch ||
        received < timestamp(envelope.lease.issuedAt, "lease_issued_at").epoch ||
        received >= timestamp(envelope.lease.expiresAt, "lease_expires_at").epoch
      ) {
        throw new GoogleBrokerContractError("receipt_time_invalid");
      }
      const response = snapshotProviderJson(responseValue);
      if (canonicalBytes(response).byteLength !== receipt.responseBytes || sha256(response) !== receipt.responseHash) {
        throw new GoogleBrokerContractError("response_binding_mismatch");
      }
      assertProviderCardinality(request, response, receipt.outcome);
      if (request.operation === "google.gmail.messages.get") {
        const source = assertListingInspection(listing);
        if (source.receipt.outcome !== "succeeded" || receipt.outcome !== "succeeded") {
          throw new GoogleBrokerContractError("gmail_successful_inbox_receipts_required");
        }
        for (const key of identityKeys) {
          if (source.receipt[key] !== receipt[key])
            throw new GoogleBrokerContractError("gmail_listing_account_mismatch");
        }
        if (
          source.receipt.receiptId !== request.parameters.listingReceiptId ||
          source.receipt.requestHash !== request.parameters.listingRequestHash ||
          source.receipt.responseHash !== request.parameters.listingResponseHash ||
          !Array.isArray(source.response.messages) ||
          !source.response.messages.some((message) => message?.id === request.parameters.messageId)
        ) {
          throw new GoogleBrokerContractError("gmail_listing_membership_missing");
        }
        if (
          !Array.isArray(response.labelIds) ||
          !response.labelIds.includes("INBOX") ||
          response.labelIds.includes("SPAM") ||
          response.labelIds.includes("TRASH")
        ) {
          throw new GoogleBrokerContractError("gmail_message_not_inbox");
        }
      }
      const result = Object.freeze({
        authority,
        receipt,
        request,
        response,
        cryptographicallyVerified: true,
        pinFingerprint: verifier.pinFingerprint,
        usable: false,
        reason: "trusted_current_time_unavailable",
      });
      inspectedReads.add(result);
      return result;
    },
  });
};

export const assertVerifiedRead = () => {
  throw new GoogleBrokerContractError("trusted_current_time_unavailable");
};

export const inspectReadLineage = (value) => {
  if (!value || !inspectedReads.has(value)) throw new GoogleBrokerContractError("signed_read_inspection_required");
  const { receipt } = value;
  return Object.freeze({
    version: 1,
    source: "google_broker",
    usable: false,
    reason: "trusted_current_time_unavailable",
    contentTrust: "external_untrusted",
    organizationId: receipt.organizationId,
    deploymentId: receipt.deploymentId,
    servicePrincipal: receipt.servicePrincipal,
    qmPrincipalId: receipt.qmPrincipalId,
    credentialOwnerId: receipt.credentialOwnerId,
    provider: receipt.provider,
    providerAccountSubject: receipt.providerAccountSubject,
    mailbox: receipt.mailbox,
    accountType: receipt.accountType,
    credentialId: receipt.credentialId,
    credentialVersion: receipt.credentialVersion,
    grantId: receipt.grantId,
    grantVersion: receipt.grantVersion,
    grantExpiresAt: receipt.grantExpiresAt,
    leaseId: receipt.leaseId,
    leaseExpiresAt: receipt.leaseExpiresAt,
    leaseNonce: receipt.leaseNonce,
    jobId: receipt.jobId,
    jobClass: receipt.jobClass,
    operation: receipt.operation,
    requestNonce: receipt.requestNonce,
    idempotencyKey: receipt.idempotencyKey,
    requestHash: receipt.requestHash,
    responseHash: receipt.responseHash,
    authorityEnvelopeHash: receipt.authorityEnvelopeHash,
    receiptId: receipt.receiptId,
    keyId: receipt.keyId,
    observedAt: receipt.serverCompletedAt,
  });
};

export const authorityEnvelopePayload = (value) => withoutSignature(normalizeAuthorityEnvelope(value));

export const readReceiptPayload = (value) => withoutSignature(normalizeReceipt(value));
