import {
  boundedText,
  exactRecord,
  GoogleBrokerContractError,
  integer,
  nonce32,
  sha256,
  sha256Text,
  snapshotJson,
  timestamp,
} from "./canonical.mjs";

export const readOperations = Object.freeze([
  "google.calendar.events.list",
  "google.gmail.messages.list",
  "google.gmail.messages.get",
]);

const accountTypes = Object.freeze(["default", "personal", "company"]);
const authorityStates = Object.freeze(["active", "revoked", "quarantined", "unavailable"]);
const maximumGrantLifetimeMs = 31 * 86_400_000;
const maximumLeaseLifetimeMs = 300_000;
const refPattern = /^[A-Za-z0-9][A-Za-z0-9_.:@+-]{2,191}$/;
const opaquePattern = /^[A-Za-z0-9][A-Za-z0-9_-]{7,159}$/;
const subjectPattern = /^[A-Za-z0-9][A-Za-z0-9_.:@+-]{2,254}$/;
const mailboxPattern =
  /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const messagePattern = /^[A-Za-z0-9_-]{3,160}$/;

const ref = (value, label) => boundedText(value, label, 192, refPattern);
const opaque = (value, label) => boundedText(value, label, 160, opaquePattern);
const mailbox = (value) => {
  const normalized = boundedText(value, "mailbox", 320, mailboxPattern);
  if (normalized !== normalized.toLowerCase()) throw new GoogleBrokerContractError("mailbox_invalid");
  return normalized;
};

const exactStringArray = (value, label, allowed, maximum) => {
  if (!Array.isArray(value) || value.length < 1 || value.length > maximum) {
    throw new GoogleBrokerContractError(`${label}_invalid`);
  }
  const normalized = value.map((entry) => {
    if (typeof entry !== "string" || !allowed.includes(entry)) throw new GoogleBrokerContractError(`${label}_invalid`);
    return entry;
  });
  if (new Set(normalized).size !== normalized.length) throw new GoogleBrokerContractError(`${label}_invalid`);
  return Object.freeze([...normalized].sort());
};

const identityFields = Object.freeze([
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

const validateIdentity = (record) => {
  if (record.provider !== "google") throw new GoogleBrokerContractError("provider_invalid");
  if (!accountTypes.includes(record.accountType)) throw new GoogleBrokerContractError("account_type_invalid");
  return Object.freeze({
    organizationId: ref(record.organizationId, "organization_id"),
    deploymentId: ref(record.deploymentId, "deployment_id"),
    servicePrincipal: ref(record.servicePrincipal, "service_principal"),
    qmPrincipalId: ref(record.qmPrincipalId, "qm_principal"),
    credentialOwnerId: ref(record.credentialOwnerId, "credential_owner"),
    provider: "google",
    providerAccountSubject: boundedText(record.providerAccountSubject, "provider_account_subject", 255, subjectPattern),
    mailbox: mailbox(record.mailbox),
    accountType: record.accountType,
    credentialId: opaque(record.credentialId, "credential_id"),
    credentialVersion: integer(record.credentialVersion, "credential_version", 1, Number.MAX_SAFE_INTEGER),
    grantId: opaque(record.grantId, "grant_id"),
    grantVersion: integer(record.grantVersion, "grant_version", 1, Number.MAX_SAFE_INTEGER),
  });
};

const grantKeys = Object.freeze([
  "version",
  ...identityFields,
  "jobClass",
  "operations",
  "purpose",
  "state",
  "issuedAt",
  "expiresAt",
  "serverClock",
]);

export const validateGrantRequest = (value) => {
  const record = exactRecord(value, grantKeys, "grant_shape_invalid");
  if (record.version !== 1 || record.serverClock !== "postgresql" || !authorityStates.includes(record.state)) {
    throw new GoogleBrokerContractError("grant_invalid");
  }
  const issued = timestamp(record.issuedAt, "grant_issued_at");
  const expires = timestamp(record.expiresAt, "grant_expires_at");
  if (expires.epoch <= issued.epoch || expires.epoch - issued.epoch > maximumGrantLifetimeMs) {
    throw new GoogleBrokerContractError("grant_expiry_invalid");
  }
  return Object.freeze({
    version: 1,
    ...validateIdentity(record),
    jobClass: opaque(record.jobClass, "job_class"),
    operations: exactStringArray(record.operations, "grant_operations", readOperations, readOperations.length),
    purpose: boundedText(record.purpose, "grant_purpose", 500),
    state: record.state,
    issuedAt: issued.text,
    expiresAt: expires.text,
    serverClock: "postgresql",
  });
};

const leaseKeys = Object.freeze([
  "version",
  ...identityFields,
  "leaseId",
  "jobId",
  "jobClass",
  "operations",
  "state",
  "stateReason",
  "nonce",
  "issuedAt",
  "expiresAt",
  "serverClock",
]);

export const validateLeaseRequest = (value) => {
  const record = exactRecord(value, leaseKeys, "lease_shape_invalid");
  if (record.version !== 1 || record.serverClock !== "postgresql" || !authorityStates.includes(record.state)) {
    throw new GoogleBrokerContractError("lease_invalid");
  }
  if ((record.state === "active") !== (record.stateReason === null)) {
    throw new GoogleBrokerContractError("lease_state_reason_invalid");
  }
  const issued = timestamp(record.issuedAt, "lease_issued_at");
  const expires = timestamp(record.expiresAt, "lease_expires_at");
  if (expires.epoch <= issued.epoch || expires.epoch - issued.epoch > maximumLeaseLifetimeMs) {
    throw new GoogleBrokerContractError("lease_expiry_invalid");
  }
  return Object.freeze({
    version: 1,
    ...validateIdentity(record),
    leaseId: opaque(record.leaseId, "lease_id"),
    jobId: opaque(record.jobId, "job_id"),
    jobClass: opaque(record.jobClass, "job_class"),
    operations: exactStringArray(record.operations, "lease_operations", readOperations, readOperations.length),
    state: record.state,
    stateReason:
      record.stateReason === null
        ? null
        : boundedText(record.stateReason, "lease_state_reason", 128, /^[a-z][a-z0-9_.-]{1,127}$/),
    nonce: nonce32(record.nonce, "lease_nonce"),
    issuedAt: issued.text,
    expiresAt: expires.text,
    serverClock: "postgresql",
  });
};

const requestBindingKeys = Object.freeze([
  ...identityFields,
  "leaseId",
  "leaseExpiresAt",
  "leaseNonce",
  "jobId",
  "jobClass",
]);

export const validateRequestBinding = (value) => {
  const record = exactRecord(value, requestBindingKeys, "binding_shape_invalid");
  return Object.freeze({
    ...validateIdentity(record),
    leaseId: opaque(record.leaseId, "lease_id"),
    leaseExpiresAt: timestamp(record.leaseExpiresAt, "lease_expires_at").text,
    leaseNonce: nonce32(record.leaseNonce, "lease_nonce"),
    jobId: opaque(record.jobId, "job_id"),
    jobClass: opaque(record.jobClass, "job_class"),
  });
};

const parametersFor = (operation, value) => {
  if (operation === "google.calendar.events.list") {
    const record = exactRecord(
      value,
      ["timeMin", "timeMax", "maxResults", "singleEvents", "orderBy", "pageToken"],
      "calendar_parameters_invalid",
    );
    const minimum = timestamp(record.timeMin, "calendar_time_min");
    const maximum = timestamp(record.timeMax, "calendar_time_max");
    if (maximum.epoch <= minimum.epoch || maximum.epoch - minimum.epoch > 31 * 86_400_000) {
      throw new GoogleBrokerContractError("calendar_window_invalid");
    }
    if (record.singleEvents !== true || record.orderBy !== "startTime") {
      throw new GoogleBrokerContractError("calendar_parameters_invalid");
    }
    return Object.freeze({
      timeMin: minimum.text,
      timeMax: maximum.text,
      maxResults: integer(record.maxResults, "calendar_max_results", 1, 100),
      singleEvents: true,
      orderBy: "startTime",
      pageToken:
        record.pageToken === null ? null : boundedText(record.pageToken, "calendar_page_token", 512, opaquePattern),
    });
  }
  if (operation === "google.gmail.messages.list") {
    const record = exactRecord(
      value,
      ["labelIds", "maxResults", "includeSpamTrash", "pageToken"],
      "gmail_list_parameters_invalid",
    );
    if (
      record.includeSpamTrash !== false ||
      !Array.isArray(record.labelIds) ||
      record.labelIds.length !== 1 ||
      record.labelIds[0] !== "INBOX"
    ) {
      throw new GoogleBrokerContractError("gmail_list_parameters_invalid");
    }
    return Object.freeze({
      labelIds: Object.freeze(["INBOX"]),
      maxResults: integer(record.maxResults, "gmail_max_results", 1, 20),
      includeSpamTrash: false,
      pageToken:
        record.pageToken === null ? null : boundedText(record.pageToken, "gmail_page_token", 512, opaquePattern),
    });
  }
  if (operation === "google.gmail.messages.get") {
    const record = exactRecord(
      value,
      ["messageId", "format", "listingReceiptId", "listingRequestHash", "listingResponseHash"],
      "gmail_get_parameters_invalid",
    );
    if (record.format !== "full") throw new GoogleBrokerContractError("gmail_get_parameters_invalid");
    return Object.freeze({
      messageId: boundedText(record.messageId, "gmail_message_id", 160, messagePattern),
      format: "full",
      listingReceiptId: opaque(record.listingReceiptId, "listing_receipt_id"),
      listingRequestHash: sha256Text(record.listingRequestHash, "listing_request_hash"),
      listingResponseHash: sha256Text(record.listingResponseHash, "listing_response_hash"),
    });
  }
  throw new GoogleBrokerContractError("operation_unsupported");
};

const requestKeys = Object.freeze([
  "version",
  "operation",
  "binding",
  "parameters",
  "requestNonce",
  "idempotencyKey",
  "requestHash",
]);

export const requestHashPayload = (request) =>
  Object.freeze({
    domain: "qm.google.read.request.v1",
    version: request.version,
    operation: request.operation,
    binding: request.binding,
    parameters: request.parameters,
    idempotencyKey: request.idempotencyKey,
  });

export const validateReadRequest = (value) => {
  const record = exactRecord(value, requestKeys, "request_shape_invalid");
  if (record.version !== 1 || !readOperations.includes(record.operation)) {
    throw new GoogleBrokerContractError("operation_unsupported");
  }
  const request = Object.freeze({
    version: 1,
    operation: record.operation,
    binding: validateRequestBinding(record.binding),
    parameters: parametersFor(record.operation, record.parameters),
    requestNonce: nonce32(record.requestNonce, "request_nonce"),
    idempotencyKey: opaque(record.idempotencyKey, "idempotency_key"),
    requestHash: sha256Text(record.requestHash, "request_hash"),
  });
  if (sha256(requestHashPayload(request)) !== request.requestHash)
    throw new GoogleBrokerContractError("request_hash_mismatch");
  return request;
};

const sharedIdentityKeys = Object.freeze([...identityFields]);

const assertSame = (left, right, keys, code) => {
  for (const key of keys) if (left[key] !== right[key]) throw new GoogleBrokerContractError(code);
};

export const inspectUntrustedGrantLease = ({ grant: grantValue, lease: leaseValue }) => {
  const grant = validateGrantRequest(grantValue);
  const lease = validateLeaseRequest(leaseValue);
  assertSame(grant, lease, sharedIdentityKeys, "grant_lease_binding_mismatch");
  if (
    lease.jobClass !== grant.jobClass ||
    Date.parse(lease.issuedAt) < Date.parse(grant.issuedAt) ||
    Date.parse(lease.expiresAt) > Date.parse(grant.expiresAt) ||
    !lease.operations.every((operation) => grant.operations.includes(operation))
  ) {
    throw new GoogleBrokerContractError("authority_binding_mismatch");
  }
  return Object.freeze({ grant, lease, usable: false, reason: "broker_signature_required" });
};

export const inspectUntrustedAuthorityRequest = ({ grant: grantValue, lease: leaseValue, request: requestValue }) => {
  const { grant, lease } = inspectUntrustedGrantLease({ grant: grantValue, lease: leaseValue });
  const request = validateReadRequest(requestValue);
  assertSame(lease, request.binding, sharedIdentityKeys, "lease_request_binding_mismatch");
  if (
    lease.leaseId !== request.binding.leaseId ||
    lease.expiresAt !== request.binding.leaseExpiresAt ||
    lease.nonce !== request.binding.leaseNonce ||
    lease.jobId !== request.binding.jobId ||
    lease.jobClass !== request.binding.jobClass ||
    !grant.operations.includes(request.operation) ||
    !lease.operations.includes(request.operation) ||
    !lease.operations.every((operation) => grant.operations.includes(operation))
  ) {
    throw new GoogleBrokerContractError("authority_binding_mismatch");
  }
  return Object.freeze({
    grant,
    lease,
    request,
    usable: false,
    reason: "broker_signature_and_trusted_clock_required",
  });
};

const historyKeys = Object.freeze(["usedRequestNonces", "idempotency"]);

export const evaluateReadHistory = (requestValue, historyValue) => {
  const request = validateReadRequest(requestValue);
  const history = exactRecord(historyValue, historyKeys, "history_shape_invalid");
  if (
    !Array.isArray(history.usedRequestNonces) ||
    history.usedRequestNonces.some((value) => {
      try {
        nonce32(value, "history_nonce");
        return false;
      } catch {
        return true;
      }
    })
  ) {
    throw new GoogleBrokerContractError("history_shape_invalid");
  }
  const idempotency =
    history.idempotency === null
      ? null
      : exactRecord(history.idempotency, ["key", "requestHash"], "history_shape_invalid");
  if (history.usedRequestNonces.includes(request.requestNonce)) return Object.freeze({ decision: "replayed" });
  if (idempotency?.key === request.idempotencyKey) {
    return Object.freeze({
      decision:
        sha256Text(idempotency.requestHash, "history_request_hash") === request.requestHash
          ? "idempotent_retry"
          : "changed_hash",
    });
  }
  return Object.freeze({ decision: "fresh" });
};

export const createReadRequest = (value) => {
  const record = exactRecord(value, [
    "version",
    "operation",
    "binding",
    "parameters",
    "requestNonce",
    "idempotencyKey",
  ]);
  const normalized = {
    version: record.version,
    operation: record.operation,
    binding: validateRequestBinding(record.binding),
    parameters: parametersFor(record.operation, record.parameters),
    requestNonce: nonce32(record.requestNonce, "request_nonce"),
    idempotencyKey: opaque(record.idempotencyKey, "idempotency_key"),
  };
  return validateReadRequest({ ...normalized, requestHash: sha256(requestHashPayload(normalized)) });
};

export const snapshotProviderJson = (value) =>
  snapshotJson(value, {
    maxDepth: 16,
    maxNodes: 4_000,
    maxStringBytes: 32_768,
    maxArrayItems: 200,
    maxObjectKeys: 500,
    maxBytes: 262_144,
  });
