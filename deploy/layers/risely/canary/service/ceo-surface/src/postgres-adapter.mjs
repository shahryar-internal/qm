import {
  ceoCanaryDatabaseIdentity,
  verifyCeoCanaryDatabaseBoundary,
  verifyCeoCanaryDatabaseClientSentinel,
} from "../../ceo-canary/src/index.mjs";
import { types } from "node:util";
import { assertRuntimeScope, createRuntimeScope } from "../../../runtime-scope/index.mjs";
import { ceoDeploymentProfile } from "../../../deployment-profiles/index.mjs";
import { PrincipalBinding } from "../../../shared-contracts/index.mjs";
import { createSurfaceContractSuite, validateIdentityResolution, validateOutboxItem } from "./contracts.mjs";
import { assertDurableOutboxAdapter, assertDurableReceiptStoreAdapter, deliveryReceiptHash } from "./durability.mjs";
import { compileShadowPublication, reconstructShadowPublication } from "./publisher.mjs";
import { exactKeys, hash, identifier, integer, sha256Canonical, text, timestamp } from "./validation.mjs";

const snapshot = PrincipalBinding.snapshot;
const CEO_RUNTIME_SCOPE = createRuntimeScope(ceoDeploymentProfile);

const maximumClaimSeconds = 300;
const maximumReconciliationSeconds = 900;
const minimumAttemptUncertaintyMs = 30_000;
const CANARY_MAINTENANCE_LOCK_KEY = ceoCanaryDatabaseIdentity.maintenanceLockKey;
const CANARY_SCHEMA_NAME = ceoCanaryDatabaseIdentity.schemaName;
const publicationKeys = [
  "contractType",
  "contractVersion",
  "mode",
  "providerInvocationAllowed",
  "outboxEventId",
  "outboxPayloadSha256",
  "artifactId",
  "artifactRevision",
  "artifactSha256",
  "evalReceiptSha256",
  "deploymentBindingSha256",
  "identityResolutionSha256",
  "targetBindingSha256",
  "deliveryKey",
  "target",
  "message",
  "messageSha256",
  "receiptContract",
];
const receiptKeys = [
  "contractType",
  "contractVersion",
  "deliveryKey",
  "outboxEventId",
  "outboxPayloadSha256",
  "artifactId",
  "artifactRevision",
  "artifactSha256",
  "deploymentBindingSha256",
  "identityResolutionSha256",
  "targetBindingSha256",
  "messageSha256",
  "attemptRef",
  "providerReceiptRef",
  "status",
  "attemptedAt",
  "completedAt",
  "receiptSha256",
];

export class CeoSurfaceStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CeoSurfaceStoreError";
    this.code = code;
  }
}

function storeError(code, message) {
  throw new CeoSurfaceStoreError(code, message);
}

function iso(value, label) {
  const result = value instanceof Date ? value.toISOString() : value;
  return timestamp(result, label);
}

function optionalIso(value, label) {
  return value === null || value === undefined ? null : iso(value, label);
}

function same(left, right) {
  return sha256Canonical(left) === sha256Canonical(right);
}

function eventIdentitySha256(value) {
  return sha256Canonical({
    deploymentBindingSha256: value.deploymentBindingSha256,
    eventId: value.eventId,
    artifactId: value.artifactId,
    artifactRevision: value.artifactRevision,
  });
}

function poolMethod(pool, name) {
  let owner = pool;
  while (owner && !Object.hasOwn(owner, name)) owner = Object.getPrototypeOf(owner);
  const descriptor = owner ? Object.getOwnPropertyDescriptor(owner, name) : undefined;
  if (!descriptor || descriptor.get || descriptor.set || typeof descriptor.value !== "function")
    throw new TypeError(`PostgresCeoSurfaceStore requires a PostgreSQL pool ${name} method`);
  if (types.isProxy(descriptor.value)) throw new TypeError("CEO surface PostgreSQL methods must not be Proxies");
  return descriptor.value;
}

function validatePublication(value, deployment) {
  const publication = exactKeys(snapshot(value, "publication"), publicationKeys, publicationKeys, "publication");
  if (
    publication.contractType !== "ceo-surface-shadow-publication" ||
    publication.contractVersion !== 1 ||
    publication.mode !== "shadow" ||
    publication.providerInvocationAllowed !== false
  ) {
    throw new TypeError("publication is not an inert CEO shadow publication");
  }
  identifier(publication.outboxEventId, "publication.outboxEventId");
  identifier(publication.artifactId, "publication.artifactId");
  text(publication.artifactRevision, "publication.artifactRevision", 64);
  for (const field of [
    "outboxPayloadSha256",
    "artifactSha256",
    "evalReceiptSha256",
    "deploymentBindingSha256",
    "identityResolutionSha256",
    "targetBindingSha256",
    "deliveryKey",
    "messageSha256",
  ]) {
    hash(publication[field], `publication.${field}`);
  }
  if (publication.deploymentBindingSha256 !== deployment.bindingSha256)
    throw new TypeError("publication deployment binding does not match");
  const deliveryKey = sha256Canonical({
    deploymentBindingSha256: deployment.bindingSha256,
    outboxEventId: publication.outboxEventId,
  });
  if (publication.deliveryKey !== deliveryKey) throw new TypeError("publication delivery key does not match");
  if (publication.messageSha256 !== sha256Canonical(publication.message))
    throw new TypeError("publication message digest does not match");
  if (
    publication.targetBindingSha256 !==
    sha256Canonical({ deploymentBindingSha256: deployment.bindingSha256, target: publication.target })
  ) {
    throw new TypeError("publication target binding does not match");
  }
  return publication;
}

function validatePublicationIdentity(publication, value, deployment, now) {
  const identity = validateIdentityResolution(value, deployment, now);
  if (identity.resolutionSha256 !== publication.identityResolutionSha256)
    throw new TypeError("publication identity resolution does not match");
  for (const field of ["teamRef", "ceoUserRef", "ceoEmail", "qmPrincipalRef", "credentialOwnerRef", "slackTeamId"])
    if (publication.target[field] !== identity[field])
      throw new TypeError(`publication target ${field} does not match identity resolution`);
  if (
    publication.target.slackUserId !== identity.slackUserId ||
    publication.target.slackDirectMessageId !== identity.slackDirectMessageId
  ) {
    throw new TypeError("publication Slack target does not match identity resolution");
  }
  return identity;
}

function validateReceipt(value, reservation) {
  const optional = value && Object.hasOwn(value, "providerReceiptRef") ? [] : ["providerReceiptRef"];
  const receipt = exactKeys(
    snapshot(value, "deliveryReceipt"),
    receiptKeys,
    receiptKeys.filter((key) => !optional.includes(key)),
    "deliveryReceipt",
  );
  if (receipt.contractType !== "ceo-surface-delivery-receipt" || receipt.contractVersion !== 1)
    throw new TypeError("deliveryReceipt contract is not supported");
  if (!["verified", "failed", "outcome_unknown"].includes(receipt.status))
    throw new TypeError("deliveryReceipt status is not supported");
  for (const [field, expected] of [
    ["deliveryKey", reservation.delivery_key],
    ["outboxEventId", reservation.outbox_event_id],
    ["outboxPayloadSha256", reservation.outbox_payload_sha256],
    ["artifactId", reservation.publication.artifactId],
    ["artifactRevision", reservation.publication.artifactRevision],
    ["artifactSha256", reservation.artifact_sha256],
    ["deploymentBindingSha256", reservation.deployment_binding_sha256],
    ["identityResolutionSha256", reservation.identity_resolution_sha256],
    ["targetBindingSha256", reservation.target_binding_sha256],
    ["messageSha256", reservation.message_sha256],
    ["attemptRef", reservation.attempt_ref],
  ]) {
    if (receipt[field] !== expected) throw new TypeError(`deliveryReceipt.${field} does not match reservation`);
  }
  const attemptedAt = timestamp(receipt.attemptedAt, "deliveryReceipt.attemptedAt");
  const completedAt = timestamp(receipt.completedAt, "deliveryReceipt.completedAt");
  if (attemptedAt !== iso(reservation.attempted_at, "reservation.attemptedAt"))
    throw new TypeError("deliveryReceipt.attemptedAt does not match reservation");
  if (Date.parse(completedAt) < Date.parse(attemptedAt))
    throw new TypeError("deliveryReceipt completion precedes the attempt");
  if (Date.parse(completedAt) > Date.parse(iso(reservation.database_now, "reservation.databaseNow")))
    throw new TypeError("deliveryReceipt completion is in the future");
  if (receipt.status === "verified") identifier(receipt.providerReceiptRef, "deliveryReceipt.providerReceiptRef");
  else if (receipt.providerReceiptRef !== undefined)
    throw new TypeError("only a verified receipt may include a provider receipt");
  hash(receipt.receiptSha256, "deliveryReceipt.receiptSha256");
  if (receipt.receiptSha256 !== deliveryReceiptHash(receipt))
    throw new TypeError("deliveryReceipt receipt digest does not match");
  return receipt;
}

function outcomeUnknownReceipt(reservation) {
  const publication = reservation.publication;
  const receipt = {
    contractType: "ceo-surface-delivery-receipt",
    contractVersion: 1,
    deliveryKey: reservation.delivery_key,
    outboxEventId: reservation.outbox_event_id,
    outboxPayloadSha256: reservation.outbox_payload_sha256,
    artifactId: publication.artifactId,
    artifactRevision: publication.artifactRevision,
    artifactSha256: reservation.artifact_sha256,
    deploymentBindingSha256: reservation.deployment_binding_sha256,
    identityResolutionSha256: reservation.identity_resolution_sha256,
    targetBindingSha256: reservation.target_binding_sha256,
    messageSha256: reservation.message_sha256,
    attemptRef: reservation.attempt_ref,
    status: "outcome_unknown",
    attemptedAt: iso(reservation.attempted_at, "reservation.attemptedAt"),
    completedAt: iso(reservation.database_now, "reservation.databaseNow"),
  };
  receipt.receiptSha256 = deliveryReceiptHash(receipt);
  return validateReceipt(receipt, reservation);
}

function outboxResult(row, deployment) {
  if (!row) return null;
  const queuedAt = iso(row.queued_at, "storedOutbox.queuedAt");
  const outboxItem = validateOutboxItem(row.outbox_item, deployment, queuedAt);
  if (
    row.event_id !== outboxItem.eventId ||
    row.deployment_binding_sha256 !== outboxItem.deploymentBindingSha256 ||
    row.outbox_payload_sha256 !== outboxItem.payloadSha256 ||
    row.artifact_id !== outboxItem.artifact.id ||
    row.artifact_revision !== outboxItem.artifact.revision ||
    row.artifact_sha256 !== outboxItem.artifactSha256 ||
    row.eval_receipt_sha256 !== outboxItem.evalRelease.receiptSha256 ||
    queuedAt !== outboxItem.queuedAt
  ) {
    storeError("stored_outbox_corrupt", "Stored outbox bindings do not match the envelope");
  }
  if (!["pending", "claimed", "delivered", "failed", "outcome_unknown"].includes(row.status))
    storeError("stored_outbox_corrupt", "Stored outbox status is not supported");
  const revision = integer(Number(row.revision), "storedOutbox.revision");
  const claimAcquiredAt = optionalIso(row.claim_acquired_at, "storedOutbox.claimAcquiredAt");
  const claimExpiresAt = optionalIso(row.claim_expires_at, "storedOutbox.claimExpiresAt");
  if (
    (row.status === "claimed" &&
      (!row.claim_ref || !row.claim_owner_ref || !claimAcquiredAt || !claimExpiresAt || row.failure_code !== null)) ||
    (row.status !== "claimed" &&
      [row.claim_ref, row.claim_owner_ref, claimAcquiredAt, claimExpiresAt].some((item) => item !== null)) ||
    (row.status === "failed" && !row.failure_code) ||
    (row.status !== "failed" && row.failure_code !== null)
  ) {
    storeError("stored_outbox_corrupt", "Stored outbox state fields are inconsistent");
  }
  if (row.status === "claimed") {
    identifier(row.claim_ref, "storedOutbox.claimRef");
    identifier(row.claim_owner_ref, "storedOutbox.claimOwnerRef");
    if (Date.parse(claimExpiresAt) <= Date.parse(claimAcquiredAt))
      storeError("stored_outbox_corrupt", "Stored outbox claim lease is invalid");
  }
  if (row.failure_code !== null) identifier(row.failure_code, "storedOutbox.failureCode");
  let reservation = null;
  if (row.delivery_key) {
    const publication = validatePublication(row.publication, deployment);
    const identityInput = snapshot(row.identity_resolution, "storedReservation.identityResolution");
    const reservedAt = iso(row.reserved_at, "storedReservation.reservedAt");
    const identity = validatePublicationIdentity(publication, identityInput, deployment, reservedAt);
    if (publication.outboxEventId !== outboxItem.eventId || publication.deliveryKey !== row.delivery_key)
      storeError("stored_reservation_corrupt", "Stored reservation does not bind its outbox event");
    if (!["reserved", "attempting", "outcome_unknown", "verified", "failed"].includes(row.delivery_status))
      storeError("stored_reservation_corrupt", "Stored reservation status is not supported");
    reservation = Object.freeze({
      deliveryKey: row.delivery_key,
      attemptRef: identifier(row.attempt_ref, "storedReservation.attemptRef"),
      status: row.delivery_status,
      revision: integer(Number(row.delivery_revision), "storedReservation.revision"),
      reservedAt,
      publication,
      identityResolution: identity,
    });
  }
  const result = {
    outboxItem,
    status: row.status,
    claimRef: row.claim_ref,
    claimOwnerRef: row.claim_owner_ref,
    claimAcquiredAt,
    claimExpiresAt,
    failureCode: row.failure_code,
    revision,
    reservation,
  };
  return Object.freeze(result);
}

function reservationResult(row, deployment) {
  if (!row) return null;
  const publication = validatePublication(row.publication, deployment);
  const identityInput = snapshot(row.identity_resolution, "reservation.identityResolution");
  const reservedAt = iso(row.reserved_at, "reservation.reservedAt");
  const identity = validatePublicationIdentity(publication, identityInput, deployment, reservedAt);
  for (const [field, expected] of [
    ["delivery_key", publication.deliveryKey],
    ["outbox_event_id", publication.outboxEventId],
    ["outbox_payload_sha256", publication.outboxPayloadSha256],
    ["artifact_sha256", publication.artifactSha256],
    ["deployment_binding_sha256", publication.deploymentBindingSha256],
    ["identity_resolution_sha256", identity.resolutionSha256],
    ["target_binding_sha256", publication.targetBindingSha256],
    ["message_sha256", publication.messageSha256],
  ]) {
    if (row[field] !== expected) storeError("stored_reservation_corrupt", `Stored reservation ${field} does not match`);
  }
  identifier(row.attempt_ref, "reservation.attemptRef");
  if (!["reserved", "attempting", "outcome_unknown", "verified", "failed"].includes(row.status))
    storeError("stored_reservation_corrupt", "Stored reservation status is not supported");
  const revision = integer(Number(row.revision), "reservation.revision");
  const attemptedAt = optionalIso(row.attempted_at, "reservation.attemptedAt");
  const completedAt = optionalIso(row.completed_at, "reservation.completedAt");
  const reconciliationValues = [
    row.reconciliation_ref,
    row.reconciliation_owner_ref,
    row.reconciliation_acquired_at,
    row.reconciliation_expires_at,
  ];
  if (
    (row.status === "reserved" && (attemptedAt !== null || completedAt !== null)) ||
    (["attempting", "outcome_unknown"].includes(row.status) && (attemptedAt === null || completedAt !== null)) ||
    (["verified", "failed"].includes(row.status) && (attemptedAt === null || completedAt === null)) ||
    (reconciliationValues.some((value) => value !== null) && reconciliationValues.some((value) => value === null)) ||
    (row.reconciliation_ref !== null && row.status !== "outcome_unknown")
  ) {
    storeError("stored_reservation_corrupt", "Stored reservation state fields are inconsistent");
  }
  if (
    (attemptedAt !== null && Date.parse(attemptedAt) < Date.parse(reservedAt)) ||
    (completedAt !== null && Date.parse(completedAt) < Date.parse(attemptedAt))
  )
    storeError("stored_reservation_corrupt", "Stored reservation timestamps are not chronological");
  if (row.reconciliation_ref !== null) {
    identifier(row.reconciliation_ref, "reservation.reconciliationRef");
    identifier(row.reconciliation_owner_ref, "reservation.reconciliationOwnerRef");
    const acquiredAt = iso(row.reconciliation_acquired_at, "reservation.reconciliationAcquiredAt");
    const expiresAt = iso(row.reconciliation_expires_at, "reservation.reconciliationExpiresAt");
    if (Date.parse(expiresAt) <= Date.parse(acquiredAt))
      storeError("stored_reservation_corrupt", "Stored reconciliation lease is invalid");
  }
  return Object.freeze({
    deliveryKey: row.delivery_key,
    outboxEventId: row.outbox_event_id,
    attemptRef: row.attempt_ref,
    status: row.status,
    revision,
    reservedAt,
    attemptedAt,
    completedAt,
    reconciliationRef: row.reconciliation_ref,
    reconciliationOwnerRef: row.reconciliation_owner_ref,
    reconciliationAcquiredAt: optionalIso(row.reconciliation_acquired_at, "reservation.reconciliationAcquiredAt"),
    reconciliationExpiresAt: optionalIso(row.reconciliation_expires_at, "reservation.reconciliationExpiresAt"),
    publication,
    identityResolution: identity,
  });
}

function tombstoneResult(row, deployment, deploymentInput) {
  if (!row) return null;
  const record = snapshot(row.terminal_record, "deliveryTombstone.terminalRecord");
  const keys = [
    "contractType",
    "contractVersion",
    "deliveryKey",
    "outboxEventId",
    "outboxItem",
    "identityResolution",
    "publication",
    "reservedAt",
    "attemptRef",
    "attemptedAt",
    "receipts",
    "terminalStatus",
    "completedAt",
    "auditBinding",
  ];
  exactKeys(record, keys, keys, "deliveryTombstone.terminalRecord");
  if (record.contractType !== "ceo-surface-delivery-tombstone" || record.contractVersion !== 1)
    storeError("stored_tombstone_corrupt", "Stored delivery tombstone contract is not supported");
  const reservedAt = timestamp(record.reservedAt, "deliveryTombstone.reservedAt");
  const outbox = validateOutboxItem(record.outboxItem, deployment, reservedAt);
  const identity = validateIdentityResolution(record.identityResolution, deployment, reservedAt);
  const publication = reconstructShadowPublication(
    {
      deploymentBinding: deploymentInput,
      outboxItem: outbox,
      identityResolution: identity,
    },
    reservedAt,
  );
  if (!same(publication, record.publication))
    storeError("stored_tombstone_corrupt", "Stored tombstone publication is not the exact compiler output");
  const recordSha256 = sha256Canonical(record);
  for (const [actual, expected, label] of [
    [row.delivery_key, publication.deliveryKey, "deliveryKey"],
    [row.outbox_event_id, outbox.eventId, "outboxEventId"],
    [row.outbox_payload_sha256, outbox.payloadSha256, "outboxPayloadSha256"],
    [row.deployment_binding_sha256, deployment.bindingSha256, "deploymentBindingSha256"],
    [row.artifact_sha256, outbox.artifactSha256, "artifactSha256"],
    [row.identity_resolution_sha256, identity.resolutionSha256, "identityResolutionSha256"],
    [row.target_binding_sha256, publication.targetBindingSha256, "targetBindingSha256"],
    [row.message_sha256, publication.messageSha256, "messageSha256"],
    [row.terminal_status, record.terminalStatus, "terminalStatus"],
    [row.record_sha256, recordSha256, "recordSha256"],
    [iso(row.completed_at, "deliveryTombstone.completedAt"), record.completedAt, "completedAt"],
    [record.deliveryKey, publication.deliveryKey, "record.deliveryKey"],
    [record.outboxEventId, outbox.eventId, "record.outboxEventId"],
  ]) {
    if (actual !== expected) storeError("stored_tombstone_corrupt", `Stored tombstone ${label} does not match`);
  }
  if (!["verified", "failed"].includes(record.terminalStatus) || !Array.isArray(record.receipts))
    storeError("stored_tombstone_corrupt", "Stored tombstone terminal state is invalid");
  const reservation = {
    delivery_key: publication.deliveryKey,
    outbox_event_id: outbox.eventId,
    outbox_payload_sha256: outbox.payloadSha256,
    artifact_sha256: outbox.artifactSha256,
    deployment_binding_sha256: deployment.bindingSha256,
    identity_resolution_sha256: identity.resolutionSha256,
    target_binding_sha256: publication.targetBindingSha256,
    message_sha256: publication.messageSha256,
    attempt_ref: identifier(record.attemptRef, "deliveryTombstone.attemptRef"),
    attempted_at: timestamp(record.attemptedAt, "deliveryTombstone.attemptedAt"),
    database_now: iso(row.recorded_at, "deliveryTombstone.recordedAt"),
    publication,
  };
  if (Date.parse(reservation.attempted_at) < Date.parse(reservedAt))
    storeError("stored_tombstone_corrupt", "Stored tombstone attempt precedes its reservation");
  const receipts = record.receipts.map((entry, index) => {
    const input = exactKeys(
      entry,
      ["revision", "status", "receiptSha256", "receipt", "recordedAt"],
      ["revision", "status", "receiptSha256", "receipt", "recordedAt"],
      `deliveryTombstone.receipts[${index}]`,
    );
    const receipt = validateReceipt(input.receipt, reservation);
    const recordedAt = timestamp(input.recordedAt, `deliveryTombstone.receipts[${index}].recordedAt`);
    if (
      input.revision !== index + 1 ||
      input.status !== receipt.status ||
      input.receiptSha256 !== receipt.receiptSha256 ||
      Date.parse(recordedAt) < Date.parse(receipt.completedAt)
    ) {
      storeError("stored_tombstone_corrupt", "Stored tombstone receipt history is not contiguous");
    }
    return Object.freeze({ ...input, receipt, recordedAt });
  });
  if (receipts.length < 1 || receipts.at(-1).status !== record.terminalStatus)
    storeError("stored_tombstone_corrupt", "Stored tombstone terminal receipt is absent");
  if (record.completedAt !== receipts.at(-1).receipt.completedAt)
    storeError("stored_tombstone_corrupt", "Stored tombstone completion does not match its terminal receipt");
  const allowed = receipts.map((entry) => entry.status).join(",");
  if (!["verified", "failed", "outcome_unknown,verified", "outcome_unknown,failed"].includes(allowed))
    storeError("stored_tombstone_corrupt", "Stored tombstone receipt lineage is invalid");
  const auditBinding = exactKeys(
    record.auditBinding,
    ["principalRef", "operation", "request", "requestSha256", "afterSha256"],
    ["principalRef", "operation", "request", "requestSha256", "afterSha256"],
    "deliveryTombstone.auditBinding",
  );
  const reconciliation = auditBinding.operation === "surface_delivery_reconciled";
  const request = exactKeys(
    auditBinding.request,
    reconciliation
      ? ["receipt", "expectedRevision", "reconciliationRef", "reconciliationOwnerRef"]
      : ["receipt", "expectedRevision"],
    reconciliation
      ? ["receipt", "expectedRevision", "reconciliationRef", "reconciliationOwnerRef"]
      : ["receipt", "expectedRevision"],
    "deliveryTombstone.auditBinding.request",
  );
  integer(request.expectedRevision, "deliveryTombstone.auditBinding.request.expectedRevision");
  if (reconciliation) {
    identifier(request.reconciliationRef, "deliveryTombstone.auditBinding.request.reconciliationRef");
    identifier(request.reconciliationOwnerRef, "deliveryTombstone.auditBinding.request.reconciliationOwnerRef");
  }
  if (
    auditBinding.principalRef !== deployment.qmPrincipalRef ||
    !["surface_delivery_receipt_recorded", "surface_delivery_reconciled"].includes(auditBinding.operation) ||
    !same(request.receipt, receipts.at(-1).receipt) ||
    hash(auditBinding.requestSha256, "deliveryTombstone.auditBinding.requestSha256") !== sha256Canonical(request) ||
    auditBinding.afterSha256 !== receipts.at(-1).receiptSha256
  ) {
    storeError("stored_tombstone_corrupt", "Stored tombstone audit operation is invalid");
  }
  return Object.freeze({
    retired: true,
    deliveryKey: row.delivery_key,
    reservedAt,
    terminalStatus: row.terminal_status,
    completedAt: record.completedAt,
    recordSha256,
    record,
    receipts: Object.freeze(receipts),
  });
}

function eventTombstoneResult(row, deployment) {
  if (!row) return null;
  const record = exactKeys(
    snapshot(row.terminal_record, "eventTombstone.terminalRecord"),
    [
      "contractType",
      "contractVersion",
      "eventId",
      "deploymentBindingSha256",
      "outboxPayloadSha256",
      "artifactId",
      "artifactRevision",
      "artifactSha256",
      "evalReceiptSha256",
      "identityResolutionSha256",
      "targetBindingSha256",
      "messageSha256",
      "failureCode",
      "eventIdentitySha256",
      "completedAt",
    ],
    [
      "contractType",
      "contractVersion",
      "eventId",
      "deploymentBindingSha256",
      "outboxPayloadSha256",
      "artifactId",
      "artifactRevision",
      "artifactSha256",
      "evalReceiptSha256",
      "identityResolutionSha256",
      "targetBindingSha256",
      "messageSha256",
      "failureCode",
      "eventIdentitySha256",
      "completedAt",
    ],
    "eventTombstone.terminalRecord",
  );
  if (
    record.contractType !== "ceo-surface-event-identity-tombstone" ||
    record.contractVersion !== 1 ||
    record.deploymentBindingSha256 !== deployment.bindingSha256 ||
    !["eval_release_expired", "identity_resolution_expired"].includes(record.failureCode)
  ) {
    storeError("stored_event_tombstone_corrupt", "Stored event tombstone contract is not supported");
  }
  identifier(record.eventId, "eventTombstone.eventId");
  identifier(record.artifactId, "eventTombstone.artifactId");
  text(record.artifactRevision, "eventTombstone.artifactRevision", 64);
  for (const field of [
    "deploymentBindingSha256",
    "outboxPayloadSha256",
    "artifactSha256",
    "evalReceiptSha256",
    "eventIdentitySha256",
  ])
    hash(record[field], `eventTombstone.${field}`);
  for (const field of ["identityResolutionSha256", "targetBindingSha256", "messageSha256"]) {
    if (record[field] !== null) hash(record[field], `eventTombstone.${field}`);
  }
  const identityExpired = record.failureCode === "identity_resolution_expired";
  if (
    [record.identityResolutionSha256, record.targetBindingSha256, record.messageSha256].some(
      (value) => (value !== null) !== identityExpired,
    ) ||
    record.eventIdentitySha256 !== eventIdentitySha256(record)
  ) {
    storeError("stored_event_tombstone_corrupt", "Stored event tombstone conflict lineage is invalid");
  }
  timestamp(record.completedAt, "eventTombstone.completedAt");
  const recordSha256 = sha256Canonical(record);
  for (const [actual, expected] of [
    [row.event_id, record.eventId],
    [row.deployment_binding_sha256, record.deploymentBindingSha256],
    [row.outbox_payload_sha256, record.outboxPayloadSha256],
    [row.artifact_id, record.artifactId],
    [row.artifact_revision, record.artifactRevision],
    [row.artifact_sha256, record.artifactSha256],
    [row.eval_receipt_sha256, record.evalReceiptSha256],
    [row.identity_resolution_sha256, record.identityResolutionSha256],
    [row.target_binding_sha256, record.targetBindingSha256],
    [row.message_sha256, record.messageSha256],
    [row.failure_code, record.failureCode],
    [row.event_identity_sha256, record.eventIdentitySha256],
    [row.record_sha256, recordSha256],
    [iso(row.completed_at, "eventTombstone.completedAt"), record.completedAt],
  ]) {
    if (actual !== expected) storeError("stored_event_tombstone_corrupt", "Stored event tombstone row does not match");
  }
  return Object.freeze({ retired: true, recordSha256, record: Object.freeze(record) });
}

async function transact(pool, runtimeScope, entityRef, operation) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL search_path = pg_catalog");
    await client.query("SET LOCAL statement_timeout = '10s'");
    await client.query("SELECT pg_advisory_xact_lock_shared(hashtext($1))", [CANARY_MAINTENANCE_LOCK_KEY]);
    await verifyCeoCanaryDatabaseClientSentinel(client, runtimeScope, true);
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))", [
      `${runtimeScope.profileRef}:${runtimeScope.profileSha256}`,
      entityRef,
    ]);
    const result = await operation(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function snapshotRead(pool, runtimeScope, operation) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    await client.query("SET LOCAL search_path = pg_catalog");
    await client.query("SET LOCAL statement_timeout = '10s'");
    await client.query("SELECT pg_advisory_xact_lock_shared(hashtext($1))", [CANARY_MAINTENANCE_LOCK_KEY]);
    await verifyCeoCanaryDatabaseClientSentinel(client, runtimeScope, true);
    const result = await operation(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function audit(client, deployment, operation, entityType, entityId, request, beforeHash, afterHash) {
  await client.query(
    `INSERT INTO ${CANARY_SCHEMA_NAME}.audit_events
       (profile_ref, profile_sha256, request_hash, principal_ref, operation, entity_type, entity_id, before_hash, after_hash)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      deployment.profileRef,
      deployment.profileSha256,
      sha256Canonical({ profileRef: deployment.profileRef, profileSha256: deployment.profileSha256, request }),
      deployment.qmPrincipalRef,
      operation,
      entityType,
      entityId,
      beforeHash,
      afterHash,
    ],
  );
}

const outboxSelect = `
SELECT events.*,
       states.status,
       states.claim_ref,
       states.claim_owner_ref,
       states.claim_acquired_at,
       states.claim_expires_at,
       states.failure_code,
       states.revision,
       states.claim_expires_at > clock_timestamp() AS claim_active,
       reservations.delivery_key,
       reservations.attempt_ref,
       reservations.status AS delivery_status,
       reservations.revision AS delivery_revision,
       reservations.reserved_at,
       reservations.publication,
       reservations.identity_resolution
FROM ${CANARY_SCHEMA_NAME}.surface_outbox_events events
JOIN ${CANARY_SCHEMA_NAME}.surface_outbox_states states
  ON states.profile_ref = events.profile_ref
 AND states.profile_sha256 = events.profile_sha256
 AND states.event_id = events.event_id
LEFT JOIN ${CANARY_SCHEMA_NAME}.surface_delivery_reservations reservations
  ON reservations.profile_ref = events.profile_ref
 AND reservations.profile_sha256 = events.profile_sha256
 AND reservations.outbox_event_id = events.event_id`;

const reservationSelect = `
SELECT *,
       reconciliation_expires_at > clock_timestamp() AS reconciliation_active,
       clock_timestamp() AS database_now
FROM ${CANARY_SCHEMA_NAME}.surface_delivery_reservations`;

export class PostgresCeoSurfaceStore {
  #initialized = false;

  constructor(options = {}) {
    if (types.isProxy(options)) throw new TypeError("CEO surface store options must not be a Proxy");
    const descriptors = Object.getOwnPropertyDescriptors(options);
    if (Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set || !descriptor.enumerable))
      throw new TypeError("CEO surface store options must contain only enumerable data properties");
    if (Object.keys(options).some((name) => !["pool", "deploymentBinding", "scope"].includes(name)))
      throw new TypeError("CEO surface database security settings cannot be supplied by a caller");
    if (types.isProxy(options.pool)) throw new TypeError("CEO surface PostgreSQL pool must not be a Proxy");
    const pool = options.pool;
    if (!pool || (typeof pool !== "object" && typeof pool !== "function"))
      throw new TypeError("PostgresCeoSurfaceStore requires a PostgreSQL pool");
    const connect = poolMethod(pool, "connect");
    const query = poolMethod(pool, "query");
    const capturedPool = Object.freeze({
      connect: (...args) => Reflect.apply(connect, pool, args),
      query: (...args) => Reflect.apply(query, pool, args),
    });
    const deploymentInput = snapshot(options.deploymentBinding, "deploymentBinding");
    const runtimeScope = assertRuntimeScope(options.scope);
    const surfaceContracts = createSurfaceContractSuite(runtimeScope);
    Object.defineProperties(this, {
      pool: { value: capturedPool, enumerable: false },
      deploymentInput: { value: deploymentInput, enumerable: false },
      runtimeScope: { value: runtimeScope, enumerable: false },
      surfaceContracts: { value: surfaceContracts, enumerable: false },
      deployment: { value: surfaceContracts.compileDeploymentBinding(deploymentInput), enumerable: false },
    });
  }

  async initialize() {
    if (this.#initialized) return true;
    await verifyCeoCanaryDatabaseBoundary(this.pool);
    this.#initialized = true;
    return true;
  }

  assertInitialized() {
    if (!this.#initialized) storeError("not_initialized", "CEO surface store requires full database readiness");
  }

  adapters() {
    this.assertInitialized();
    const binding = this.deployment.bindingSha256;
    const outbox = {
      contractType: "ceo-surface-outbox-adapter",
      contractVersion: 1,
      durability: "postgres",
      atomicClaims: true,
      deploymentBindingSha256: binding,
      enqueueEvaluatedArtifactRevision: this.enqueueEvaluatedArtifactRevision.bind(this),
      claimEvaluatedArtifactRevision: this.claimEvaluatedArtifactRevision.bind(this),
      renewClaim: this.renewClaim.bind(this),
      releaseClaim: this.releaseClaim.bind(this),
      readOutboxEvent: this.readOutboxEvent.bind(this),
    };
    const receipts = {
      contractType: "ceo-surface-receipt-store-adapter",
      contractVersion: 1,
      durability: "postgres",
      atomicReservations: true,
      deploymentBindingSha256: binding,
      reserveDeliveryKey: this.reserveDeliveryKey.bind(this),
      beginDeliveryAttempt: this.beginDeliveryAttempt.bind(this),
      commitDeliveryReceipt: this.commitDeliveryReceipt.bind(this),
      reserveDeliveryReconciliation: this.reserveDeliveryReconciliation.bind(this),
      commitReconciliationReceipt: this.commitReconciliationReceipt.bind(this),
      readDeliveryReceipt: this.readDeliveryReceipt.bind(this),
    };
    return Object.freeze({
      outbox: assertDurableOutboxAdapter(outbox, binding),
      receipts: assertDurableReceiptStoreAdapter(receipts, binding),
    });
  }

  async enqueueEvaluatedArtifactRevision(value) {
    this.assertInitialized();
    const now = new Date().toISOString();
    const outbox = validateOutboxItem(value, this.deployment, now);
    const durableEventIdentitySha256 = eventIdentitySha256({
      deploymentBindingSha256: outbox.deploymentBindingSha256,
      eventId: outbox.eventId,
      artifactId: outbox.artifact.id,
      artifactRevision: outbox.artifact.revision,
    });
    return transact(this.pool, this.runtimeScope, outbox.eventId, async (client) => {
      const expiredEvent = (
        await client.query(
          `SELECT * FROM ${CANARY_SCHEMA_NAME}.surface_event_tombstones
           WHERE profile_ref = $1 AND profile_sha256 = $2
             AND (event_id = $3 OR outbox_payload_sha256 = $4 OR event_identity_sha256 = $5)`,
          [
            this.runtimeScope.profileRef,
            this.runtimeScope.profileSha256,
            outbox.eventId,
            outbox.payloadSha256,
            durableEventIdentitySha256,
          ],
        )
      ).rows[0];
      if (expiredEvent) {
        eventTombstoneResult(expiredEvent, this.deployment);
        storeError("outbox_event_retired", "Outbox event identity has a permanent expiry tombstone");
      }
      const terminal = (
        await client.query(
          `SELECT * FROM ${CANARY_SCHEMA_NAME}.surface_delivery_tombstones
           WHERE profile_ref = $1 AND profile_sha256 = $2
             AND (outbox_event_id = $3 OR outbox_payload_sha256 = $4)`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, outbox.eventId, outbox.payloadSha256],
        )
      ).rows[0];
      if (terminal) {
        tombstoneResult(terminal, this.deployment, this.deploymentInput);
        storeError("delivery_already_terminal", "Outbox event has a permanent terminal delivery tombstone");
      }
      const release = await client.query(
        `SELECT release_id FROM ${CANARY_SCHEMA_NAME}.evaluation_releases
         WHERE profile_ref = $1 AND profile_sha256 = $2 AND release_sha256 = $3
           AND mode = 'synthetic_shadow' AND passed AND release
           AND NOT provider_release_eligible AND expires_at > clock_timestamp()`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, outbox.evalRelease.receiptSha256],
      );
      if (release.rows.length !== 1) {
        storeError(
          "eval_release_not_durable",
          "Outbox requires a durable unexpired same-profile synthetic shadow release",
        );
      }
      let inserted;
      try {
        inserted = await client.query(
          `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_outbox_events
             (profile_ref, profile_sha256, event_id, deployment_binding_sha256, outbox_payload_sha256,
              artifact_id, artifact_revision, artifact_sha256, eval_receipt_sha256, evaluation_release_id,
              outbox_item, queued_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::timestamptz)
           ON CONFLICT (profile_ref, profile_sha256, event_id) DO NOTHING
           RETURNING event_id`,
          [
            this.runtimeScope.profileRef,
            this.runtimeScope.profileSha256,
            outbox.eventId,
            outbox.deploymentBindingSha256,
            outbox.payloadSha256,
            outbox.artifact.id,
            outbox.artifact.revision,
            outbox.artifactSha256,
            outbox.evalRelease.receiptSha256,
            release.rows[0].release_id,
            JSON.stringify(outbox),
            outbox.queuedAt,
          ],
        );
      } catch (error) {
        if (error?.code === "23505") storeError("outbox_conflict", "Outbox payload is already bound to another event");
        throw error;
      }
      await client.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_outbox_states (profile_ref, profile_sha256, event_id, status)
         VALUES ($1, $2, $3, 'pending') ON CONFLICT (profile_ref, profile_sha256, event_id) DO NOTHING`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, outbox.eventId],
      );
      const row = (
        await client.query(
          `${outboxSelect} WHERE events.profile_ref = $1 AND events.profile_sha256 = $2 AND events.event_id = $3`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, outbox.eventId],
        )
      ).rows[0];
      const result = outboxResult(row, this.deployment);
      if (!same(result.outboxItem, outbox))
        storeError("outbox_conflict", "Outbox event identity has conflicting content");
      if (inserted.rowCount === 1)
        await audit(
          client,
          this.deployment,
          "surface_outbox_enqueued",
          "surface_outbox",
          outbox.eventId,
          outbox,
          null,
          outbox.payloadSha256,
        );
      return result;
    });
  }

  async claimEvaluatedArtifactRevision(value) {
    this.assertInitialized();
    const input = exactKeys(
      snapshot(value, "claimRequest"),
      ["claimRef", "claimOwnerRef", "leaseSeconds"],
      ["claimRef", "claimOwnerRef", "leaseSeconds"],
      "claimRequest",
    );
    const claimRef = identifier(input.claimRef, "claimRequest.claimRef");
    const claimOwnerRef = identifier(input.claimOwnerRef, "claimRequest.claimOwnerRef");
    const leaseSeconds = integer(input.leaseSeconds, "claimRequest.leaseSeconds", 30, maximumClaimSeconds);
    return transact(this.pool, this.runtimeScope, claimRef, async (client) => {
      const expired = await client.query(
        `UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_states states
         SET status = 'failed', claim_ref = NULL, claim_owner_ref = NULL,
             claim_acquired_at = NULL, claim_expires_at = NULL,
             failure_code = CASE
               WHEN reservations.delivery_key IS NOT NULL THEN 'identity_resolution_expired'
               ELSE 'eval_release_expired'
             END,
             revision = revision + 1, updated_at = clock_timestamp()
         FROM ${CANARY_SCHEMA_NAME}.surface_outbox_events events
         JOIN ${CANARY_SCHEMA_NAME}.evaluation_releases releases
           ON releases.profile_ref = events.profile_ref
          AND releases.profile_sha256 = events.profile_sha256
          AND releases.release_id = events.evaluation_release_id
         LEFT JOIN ${CANARY_SCHEMA_NAME}.surface_delivery_reservations reservations
           ON reservations.profile_ref = events.profile_ref
          AND reservations.profile_sha256 = events.profile_sha256
          AND reservations.outbox_event_id = events.event_id
         WHERE states.profile_ref = $1 AND states.profile_sha256 = $2
           AND states.profile_ref = events.profile_ref AND states.profile_sha256 = events.profile_sha256
           AND states.event_id = events.event_id
           AND (states.status = 'pending' OR (states.status = 'claimed' AND states.claim_expires_at <= clock_timestamp()))
           AND (reservations.delivery_key IS NULL OR reservations.status = 'reserved')
           AND (
             releases.expires_at <= clock_timestamp()
             OR (reservations.identity_resolution #>> '{expiresAt}')::timestamptz <= clock_timestamp()
           )
         RETURNING states.event_id, states.failure_code, states.revision, states.updated_at,
                   events.deployment_binding_sha256, events.outbox_payload_sha256,
                   events.artifact_id, events.artifact_revision, events.artifact_sha256,
                   events.eval_receipt_sha256,
                   reservations.identity_resolution_sha256,
                   reservations.target_binding_sha256,
                   reservations.message_sha256`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256],
      );
      for (const row of expired.rows) {
        const completedAt = iso(row.updated_at, "eventTombstone.completedAt");
        const terminalRecord = {
          contractType: "ceo-surface-event-identity-tombstone",
          contractVersion: 1,
          eventId: row.event_id,
          deploymentBindingSha256: row.deployment_binding_sha256,
          outboxPayloadSha256: row.outbox_payload_sha256,
          artifactId: row.artifact_id,
          artifactRevision: row.artifact_revision,
          artifactSha256: row.artifact_sha256,
          evalReceiptSha256: row.eval_receipt_sha256,
          identityResolutionSha256: row.identity_resolution_sha256,
          targetBindingSha256: row.target_binding_sha256,
          messageSha256: row.message_sha256,
          failureCode: row.failure_code,
          eventIdentitySha256: eventIdentitySha256({
            deploymentBindingSha256: row.deployment_binding_sha256,
            eventId: row.event_id,
            artifactId: row.artifact_id,
            artifactRevision: row.artifact_revision,
          }),
          completedAt,
        };
        const recordSha256 = sha256Canonical(terminalRecord);
        try {
          await client.query(
            `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_event_tombstones
               (profile_ref, profile_sha256, event_id, deployment_binding_sha256, outbox_payload_sha256, artifact_id, artifact_revision,
                artifact_sha256, eval_receipt_sha256, identity_resolution_sha256, target_binding_sha256,
                message_sha256, failure_code, event_identity_sha256, record_sha256, terminal_record, completed_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb, $17::timestamptz)
             ON CONFLICT (profile_ref, profile_sha256, event_id) DO NOTHING`,
            [
              this.runtimeScope.profileRef,
              this.runtimeScope.profileSha256,
              terminalRecord.eventId,
              terminalRecord.deploymentBindingSha256,
              terminalRecord.outboxPayloadSha256,
              terminalRecord.artifactId,
              terminalRecord.artifactRevision,
              terminalRecord.artifactSha256,
              terminalRecord.evalReceiptSha256,
              terminalRecord.identityResolutionSha256,
              terminalRecord.targetBindingSha256,
              terminalRecord.messageSha256,
              terminalRecord.failureCode,
              terminalRecord.eventIdentitySha256,
              recordSha256,
              JSON.stringify(terminalRecord),
              completedAt,
            ],
          );
        } catch (error) {
          if (error?.code === "23505") {
            storeError("outbox_event_retirement_conflict", "Expired outbox event conflicts with a permanent identity");
          }
          throw error;
        }
        const tombstone = (
          await client.query(
            `SELECT * FROM ${CANARY_SCHEMA_NAME}.surface_event_tombstones
             WHERE profile_ref = $1 AND profile_sha256 = $2 AND event_id = $3`,
            [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, row.event_id],
          )
        ).rows[0];
        if (eventTombstoneResult(tombstone, this.deployment).recordSha256 !== recordSha256) {
          storeError("outbox_event_retirement_conflict", "Expired outbox event identity has conflicting content");
        }
        await audit(
          client,
          this.deployment,
          "surface_outbox_expired",
          "surface_outbox",
          row.event_id,
          { eventId: row.event_id, failureCode: row.failure_code },
          null,
          sha256Canonical({ failureCode: row.failure_code, revision: Number(row.revision) }),
        );
      }
      const candidate = await client.query(
        `SELECT states.event_id, states.revision
         FROM ${CANARY_SCHEMA_NAME}.surface_outbox_states states
         JOIN ${CANARY_SCHEMA_NAME}.surface_outbox_events events
           ON events.profile_ref = states.profile_ref
          AND events.profile_sha256 = states.profile_sha256
          AND events.event_id = states.event_id
         JOIN ${CANARY_SCHEMA_NAME}.evaluation_releases releases
           ON releases.profile_ref = events.profile_ref
          AND releases.profile_sha256 = events.profile_sha256
          AND releases.release_id = events.evaluation_release_id
         LEFT JOIN ${CANARY_SCHEMA_NAME}.surface_delivery_reservations reservations
           ON reservations.profile_ref = states.profile_ref
          AND reservations.profile_sha256 = states.profile_sha256
          AND reservations.outbox_event_id = states.event_id
         WHERE states.profile_ref = $1 AND states.profile_sha256 = $2
           AND (states.status = 'pending' OR (states.status = 'claimed' AND states.claim_expires_at <= clock_timestamp()))
           AND releases.mode = 'synthetic_shadow' AND releases.passed AND releases.release
           AND NOT releases.provider_release_eligible AND releases.expires_at > clock_timestamp()
           AND (
             reservations.delivery_key IS NULL
             OR (reservations.status = 'reserved' AND (reservations.identity_resolution #>> '{expiresAt}')::timestamptz > clock_timestamp())
           )
         ORDER BY events.queued_at, states.event_id
         FOR UPDATE OF states SKIP LOCKED
         LIMIT 1`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256],
      );
      if (!candidate.rows[0]) return null;
      const updated = await client.query(
        `UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_states
         SET status = 'claimed', claim_ref = $4, claim_owner_ref = $5,
             claim_acquired_at = clock_timestamp(),
             claim_expires_at = clock_timestamp() + ($6::integer * interval '1 second'),
             failure_code = NULL, revision = revision + 1, updated_at = clock_timestamp()
         WHERE profile_ref = $1 AND profile_sha256 = $2 AND event_id = $3 AND revision = $7
         RETURNING revision`,
        [
          this.runtimeScope.profileRef,
          this.runtimeScope.profileSha256,
          candidate.rows[0].event_id,
          claimRef,
          claimOwnerRef,
          leaseSeconds,
          candidate.rows[0].revision,
        ],
      );
      if (updated.rowCount !== 1) storeError("claim_conflict", "Outbox claim lost its revision race");
      const row = (
        await client.query(
          `${outboxSelect} WHERE events.profile_ref = $1 AND events.profile_sha256 = $2 AND events.event_id = $3`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, candidate.rows[0].event_id],
        )
      ).rows[0];
      const result = outboxResult(row, this.deployment);
      await audit(
        client,
        this.deployment,
        "surface_outbox_claimed",
        "surface_outbox",
        result.outboxItem.eventId,
        input,
        null,
        sha256Canonical({ claimRef, revision: result.revision }),
      );
      return result;
    });
  }

  async renewClaim(value) {
    this.assertInitialized();
    const input = exactKeys(
      snapshot(value, "claimRenewal"),
      ["eventId", "claimRef", "expectedRevision", "leaseSeconds"],
      ["eventId", "claimRef", "expectedRevision", "leaseSeconds"],
      "claimRenewal",
    );
    const eventId = identifier(input.eventId, "claimRenewal.eventId");
    const claimRef = identifier(input.claimRef, "claimRenewal.claimRef");
    const expectedRevision = integer(input.expectedRevision, "claimRenewal.expectedRevision");
    const leaseSeconds = integer(input.leaseSeconds, "claimRenewal.leaseSeconds", 30, maximumClaimSeconds);
    return transact(this.pool, this.runtimeScope, eventId, async (client) => {
      const update = await client.query(
        `UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_states
         SET claim_expires_at = clock_timestamp() + ($6::integer * interval '1 second'),
             revision = revision + 1, updated_at = clock_timestamp()
         WHERE profile_ref = $1 AND profile_sha256 = $2 AND event_id = $3
           AND status = 'claimed' AND claim_ref = $4 AND revision = $5
           AND claim_expires_at > clock_timestamp()
           AND EXISTS (
             SELECT 1
             FROM ${CANARY_SCHEMA_NAME}.surface_outbox_events events
             JOIN ${CANARY_SCHEMA_NAME}.evaluation_releases releases
               ON releases.profile_ref = events.profile_ref
              AND releases.profile_sha256 = events.profile_sha256
              AND releases.release_id = events.evaluation_release_id
             LEFT JOIN ${CANARY_SCHEMA_NAME}.surface_delivery_reservations reservations
               ON reservations.profile_ref = events.profile_ref
              AND reservations.profile_sha256 = events.profile_sha256
              AND reservations.outbox_event_id = events.event_id
             WHERE events.profile_ref = surface_outbox_states.profile_ref
               AND events.profile_sha256 = surface_outbox_states.profile_sha256
               AND events.event_id = surface_outbox_states.event_id
               AND releases.mode = 'synthetic_shadow' AND releases.passed AND releases.release
               AND NOT releases.provider_release_eligible AND releases.expires_at > clock_timestamp()
               AND (reservations.delivery_key IS NULL OR (reservations.identity_resolution #>> '{expiresAt}')::timestamptz > clock_timestamp())
           )
         RETURNING event_id`,
        [
          this.runtimeScope.profileRef,
          this.runtimeScope.profileSha256,
          eventId,
          claimRef,
          expectedRevision,
          leaseSeconds,
        ],
      );
      if (update.rowCount !== 1) storeError("claim_conflict", "Outbox claim cannot be renewed");
      const result = outboxResult(
        (
          await client.query(
            `${outboxSelect} WHERE events.profile_ref = $1 AND events.profile_sha256 = $2 AND events.event_id = $3`,
            [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, eventId],
          )
        ).rows[0],
        this.deployment,
      );
      await audit(
        client,
        this.deployment,
        "surface_outbox_claim_renewed",
        "surface_outbox",
        eventId,
        input,
        null,
        sha256Canonical({ claimRef, revision: result.revision }),
      );
      return result;
    });
  }

  async releaseClaim(value) {
    this.assertInitialized();
    const input = exactKeys(
      snapshot(value, "claimRelease"),
      ["eventId", "claimRef", "expectedRevision"],
      ["eventId", "claimRef", "expectedRevision"],
      "claimRelease",
    );
    const eventId = identifier(input.eventId, "claimRelease.eventId");
    const claimRef = identifier(input.claimRef, "claimRelease.claimRef");
    const expectedRevision = integer(input.expectedRevision, "claimRelease.expectedRevision");
    return transact(this.pool, this.runtimeScope, eventId, async (client) => {
      const update = await client.query(
        `UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_states states
         SET status = 'pending', claim_ref = NULL, claim_owner_ref = NULL, claim_acquired_at = NULL,
             claim_expires_at = NULL, revision = revision + 1, updated_at = clock_timestamp()
         WHERE states.profile_ref = $1 AND states.profile_sha256 = $2 AND states.event_id = $3
           AND states.status = 'claimed' AND states.claim_ref = $4 AND states.revision = $5
           AND NOT EXISTS (
             SELECT 1 FROM ${CANARY_SCHEMA_NAME}.surface_delivery_reservations reservations
             WHERE reservations.profile_ref = states.profile_ref
               AND reservations.profile_sha256 = states.profile_sha256
               AND reservations.outbox_event_id = states.event_id
           )
         RETURNING event_id`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, eventId, claimRef, expectedRevision],
      );
      if (update.rowCount !== 1) storeError("claim_conflict", "Reserved or stale outbox claim cannot be released");
      const result = outboxResult(
        (
          await client.query(
            `${outboxSelect} WHERE events.profile_ref = $1 AND events.profile_sha256 = $2 AND events.event_id = $3`,
            [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, eventId],
          )
        ).rows[0],
        this.deployment,
      );
      await audit(
        client,
        this.deployment,
        "surface_outbox_claim_released",
        "surface_outbox",
        eventId,
        input,
        null,
        sha256Canonical({ status: result.status, revision: result.revision }),
      );
      return result;
    });
  }

  async readOutboxEvent(value) {
    this.assertInitialized();
    const eventId = identifier(value, "eventId");
    return snapshotRead(this.pool, this.runtimeScope, async (client) => {
      const row = (
        await client.query(
          `${outboxSelect} WHERE events.profile_ref = $1 AND events.profile_sha256 = $2 AND events.event_id = $3`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, eventId],
        )
      ).rows[0];
      return outboxResult(row, this.deployment);
    });
  }

  async reserveDeliveryKey(value) {
    this.assertInitialized();
    const input = exactKeys(
      snapshot(value, "deliveryReservation"),
      ["publication", "identityResolution", "attemptRef", "claimRef", "expectedOutboxRevision"],
      ["publication", "identityResolution", "attemptRef", "claimRef", "expectedOutboxRevision"],
      "deliveryReservation",
    );
    const now = new Date().toISOString();
    const publication = validatePublication(input.publication, this.deployment);
    const identity = validatePublicationIdentity(publication, input.identityResolution, this.deployment, now);
    const attemptRef = identifier(input.attemptRef, "deliveryReservation.attemptRef");
    const claimRef = identifier(input.claimRef, "deliveryReservation.claimRef");
    const expectedOutboxRevision = integer(input.expectedOutboxRevision, "deliveryReservation.expectedOutboxRevision");
    return transact(this.pool, this.runtimeScope, publication.outboxEventId, async (client) => {
      const outbox = (
        await client.query(
          `${outboxSelect} WHERE events.profile_ref = $1 AND events.profile_sha256 = $2 AND events.event_id = $3 FOR UPDATE OF states`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, publication.outboxEventId],
        )
      ).rows[0];
      if (
        !outbox ||
        outbox.status !== "claimed" ||
        outbox.claim_ref !== claimRef ||
        Number(outbox.revision) !== expectedOutboxRevision ||
        outbox.claim_active !== true
      ) {
        storeError("claim_conflict", "Delivery reservation requires the exact active outbox claim");
      }
      if (
        outbox.outbox_payload_sha256 !== publication.outboxPayloadSha256 ||
        outbox.artifact_id !== publication.artifactId ||
        outbox.artifact_revision !== publication.artifactRevision ||
        outbox.artifact_sha256 !== publication.artifactSha256 ||
        outbox.eval_receipt_sha256 !== publication.evalReceiptSha256
      ) {
        storeError("publication_conflict", "Delivery publication does not bind the claimed outbox revision");
      }
      const reconstructed = compileShadowPublication({
        deploymentBinding: this.deploymentInput,
        outboxItem: outbox.outbox_item,
        identityResolution: identity,
      });
      if (!same(publication, reconstructed))
        storeError("publication_conflict", "Delivery publication is not the exact actionless compiler output");
      let inserted;
      try {
        inserted = await client.query(
          `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_delivery_reservations
             (profile_ref, profile_sha256, delivery_key, outbox_event_id, outbox_payload_sha256, artifact_sha256,
              deployment_binding_sha256, identity_resolution_sha256, target_binding_sha256,
              message_sha256, attempt_ref, identity_resolution, publication, status, revision)
           SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13::jsonb, 'reserved', 0
           WHERE ($12::jsonb #>> '{expiresAt}')::timestamptz > clock_timestamp()
             AND EXISTS (
               SELECT 1 FROM ${CANARY_SCHEMA_NAME}.surface_outbox_events events
               JOIN ${CANARY_SCHEMA_NAME}.evaluation_releases releases
                 ON releases.profile_ref = events.profile_ref
                AND releases.profile_sha256 = events.profile_sha256
                AND releases.release_id = events.evaluation_release_id
               WHERE events.profile_ref = $1 AND events.profile_sha256 = $2 AND events.event_id = $4
                 AND releases.mode = 'synthetic_shadow' AND releases.passed AND releases.release
                 AND NOT releases.provider_release_eligible AND releases.expires_at > clock_timestamp()
             )
           ON CONFLICT (profile_ref, profile_sha256, delivery_key) DO NOTHING`,
          [
            this.runtimeScope.profileRef,
            this.runtimeScope.profileSha256,
            publication.deliveryKey,
            publication.outboxEventId,
            publication.outboxPayloadSha256,
            publication.artifactSha256,
            publication.deploymentBindingSha256,
            publication.identityResolutionSha256,
            publication.targetBindingSha256,
            publication.messageSha256,
            attemptRef,
            JSON.stringify(identity),
            JSON.stringify(publication),
          ],
        );
      } catch (error) {
        if (error?.code === "23505") storeError("delivery_conflict", "Attempt or outbox event is already reserved");
        throw error;
      }
      const row = (
        await client.query(
          `${reservationSelect} WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3 FOR UPDATE`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, publication.deliveryKey],
        )
      ).rows[0];
      if (!row) storeError("delivery_conflict", "Delivery authority expired before reservation");
      const expected = {
        delivery_key: publication.deliveryKey,
        outbox_event_id: publication.outboxEventId,
        outbox_payload_sha256: publication.outboxPayloadSha256,
        artifact_sha256: publication.artifactSha256,
        deployment_binding_sha256: publication.deploymentBindingSha256,
        identity_resolution_sha256: publication.identityResolutionSha256,
        target_binding_sha256: publication.targetBindingSha256,
        message_sha256: publication.messageSha256,
        attempt_ref: attemptRef,
        identity_resolution: identity,
        publication,
      };
      for (const [field, expectedValue] of Object.entries(expected))
        if (!same(row[field], expectedValue))
          storeError("delivery_conflict", `Delivery reservation ${field} conflicts`);
      const result = reservationResult(row, this.deployment);
      const reservedPublication = reconstructShadowPublication(
        {
          deploymentBinding: this.deploymentInput,
          outboxItem: outbox.outbox_item,
          identityResolution: result.identityResolution,
        },
        result.reservedAt,
      );
      if (!same(publication, reservedPublication))
        storeError("delivery_conflict", "Delivery publication was not valid at its database reservation time");
      if (inserted.rowCount === 1)
        await audit(
          client,
          this.deployment,
          "surface_delivery_reserved",
          "surface_delivery",
          publication.deliveryKey,
          input,
          null,
          sha256Canonical({ deliveryKey: result.deliveryKey, revision: result.revision }),
        );
      return result;
    });
  }

  async beginDeliveryAttempt(value) {
    this.assertInitialized();
    const input = exactKeys(
      snapshot(value, "deliveryAttempt"),
      ["deliveryKey", "attemptRef", "claimRef", "expectedRevision"],
      ["deliveryKey", "attemptRef", "claimRef", "expectedRevision"],
      "deliveryAttempt",
    );
    const deliveryKey = hash(input.deliveryKey, "deliveryAttempt.deliveryKey");
    const attemptRef = identifier(input.attemptRef, "deliveryAttempt.attemptRef");
    const claimRef = identifier(input.claimRef, "deliveryAttempt.claimRef");
    const expectedRevision = integer(input.expectedRevision, "deliveryAttempt.expectedRevision");
    return transact(this.pool, this.runtimeScope, deliveryKey, async (client) => {
      const update = await client.query(
        `UPDATE ${CANARY_SCHEMA_NAME}.surface_delivery_reservations reservations
         SET status = 'attempting', attempted_at = clock_timestamp(), revision = revision + 1,
             updated_at = clock_timestamp()
         FROM ${CANARY_SCHEMA_NAME}.surface_outbox_states states
         WHERE reservations.profile_ref = $1 AND reservations.profile_sha256 = $2
           AND reservations.delivery_key = $3 AND reservations.attempt_ref = $4
           AND reservations.status = 'reserved' AND reservations.revision = $5
           AND states.profile_ref = reservations.profile_ref
           AND states.profile_sha256 = reservations.profile_sha256
           AND states.event_id = reservations.outbox_event_id AND states.status = 'claimed'
           AND states.claim_ref = $6 AND states.claim_expires_at > clock_timestamp()
           AND (reservations.identity_resolution #>> '{expiresAt}')::timestamptz > clock_timestamp()
           AND EXISTS (
             SELECT 1 FROM ${CANARY_SCHEMA_NAME}.surface_outbox_events events
             JOIN ${CANARY_SCHEMA_NAME}.evaluation_releases releases
               ON releases.profile_ref = events.profile_ref
              AND releases.profile_sha256 = events.profile_sha256
              AND releases.release_id = events.evaluation_release_id
             WHERE events.profile_ref = reservations.profile_ref
               AND events.profile_sha256 = reservations.profile_sha256
               AND events.event_id = reservations.outbox_event_id
               AND releases.mode = 'synthetic_shadow' AND releases.passed AND releases.release
               AND NOT releases.provider_release_eligible AND releases.expires_at > clock_timestamp()
           )
         RETURNING reservations.*`,
        [
          this.runtimeScope.profileRef,
          this.runtimeScope.profileSha256,
          deliveryKey,
          attemptRef,
          expectedRevision,
          claimRef,
        ],
      );
      if (update.rowCount !== 1) storeError("delivery_conflict", "Delivery attempt cannot start");
      const result = reservationResult(update.rows[0], this.deployment);
      await audit(
        client,
        this.deployment,
        "surface_delivery_attempt_started",
        "surface_delivery",
        deliveryKey,
        input,
        null,
        sha256Canonical({ status: result.status, revision: result.revision, attemptedAt: result.attemptedAt }),
      );
      return result;
    });
  }

  async commitDeliveryReceipt(value) {
    this.assertInitialized();
    return this.commitReceipt(value, false);
  }

  async reserveDeliveryReconciliation(value) {
    this.assertInitialized();
    const input = exactKeys(
      snapshot(value, "reconciliationReservation"),
      ["deliveryKey", "reconciliationRef", "reconciliationOwnerRef", "leaseSeconds", "expectedRevision"],
      ["deliveryKey", "reconciliationRef", "reconciliationOwnerRef", "leaseSeconds", "expectedRevision"],
      "reconciliationReservation",
    );
    const deliveryKey = hash(input.deliveryKey, "reconciliationReservation.deliveryKey");
    const reconciliationRef = identifier(input.reconciliationRef, "reconciliationReservation.reconciliationRef");
    const reconciliationOwnerRef = identifier(
      input.reconciliationOwnerRef,
      "reconciliationReservation.reconciliationOwnerRef",
    );
    const leaseSeconds = integer(
      input.leaseSeconds,
      "reconciliationReservation.leaseSeconds",
      30,
      maximumReconciliationSeconds,
    );
    const expectedRevision = integer(input.expectedRevision, "reconciliationReservation.expectedRevision");
    return transact(this.pool, this.runtimeScope, deliveryKey, async (client) => {
      const locked = (
        await client.query(
          `${reservationSelect} WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3 FOR UPDATE`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, deliveryKey],
        )
      ).rows[0];
      if (!locked || Number(locked.revision) !== expectedRevision)
        storeError("reconciliation_conflict", "Delivery reconciliation revision does not match");
      reservationResult(locked, this.deployment);
      const update = await client.query(
        `UPDATE ${CANARY_SCHEMA_NAME}.surface_delivery_reservations
         SET status = 'outcome_unknown', reconciliation_ref = $4, reconciliation_owner_ref = $5,
             reconciliation_acquired_at = clock_timestamp(),
             reconciliation_expires_at = clock_timestamp() + ($6::integer * interval '1 second'),
             revision = revision + 1, updated_at = clock_timestamp()
         WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3 AND revision = $7
           AND (
             (status = 'attempting' AND attempted_at <= clock_timestamp() - ($8::integer * interval '1 millisecond'))
             OR status = 'outcome_unknown'
           )
           AND (reconciliation_expires_at IS NULL OR reconciliation_expires_at <= clock_timestamp())
         RETURNING *`,
        [
          this.runtimeScope.profileRef,
          this.runtimeScope.profileSha256,
          deliveryKey,
          reconciliationRef,
          reconciliationOwnerRef,
          leaseSeconds,
          expectedRevision,
          minimumAttemptUncertaintyMs,
        ],
      );
      if (update.rowCount !== 1) storeError("reconciliation_conflict", "Delivery is not eligible for reconciliation");
      if (locked.status === "attempting") {
        const classification = outcomeUnknownReceipt(locked);
        const nextReceiptRevision = Number(
          (
            await client.query(
              `SELECT COALESCE(max(revision), 0)::bigint + 1 AS revision
               FROM ${CANARY_SCHEMA_NAME}.surface_delivery_receipts
               WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3`,
              [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, deliveryKey],
            )
          ).rows[0].revision,
        );
        await client.query(
          `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_delivery_receipts
             (profile_ref, profile_sha256, delivery_key, revision, status, receipt_sha256, receipt)
           VALUES ($1, $2, $3, $4, 'outcome_unknown', $5, $6::jsonb)`,
          [
            this.runtimeScope.profileRef,
            this.runtimeScope.profileSha256,
            deliveryKey,
            nextReceiptRevision,
            classification.receiptSha256,
            JSON.stringify(classification),
          ],
        );
      }
      await client.query(
        `UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_states states
         SET status = 'outcome_unknown', claim_ref = NULL, claim_owner_ref = NULL,
             claim_acquired_at = NULL, claim_expires_at = NULL,
             revision = revision + 1, updated_at = clock_timestamp()
         FROM ${CANARY_SCHEMA_NAME}.surface_delivery_reservations reservations
         WHERE reservations.profile_ref = $1 AND reservations.profile_sha256 = $2
           AND reservations.delivery_key = $3
           AND states.profile_ref = reservations.profile_ref
           AND states.profile_sha256 = reservations.profile_sha256
           AND states.event_id = reservations.outbox_event_id
           AND states.status IN ('claimed', 'outcome_unknown')`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, deliveryKey],
      );
      const result = reservationResult(update.rows[0], this.deployment);
      await audit(
        client,
        this.deployment,
        "surface_delivery_reconciliation_reserved",
        "surface_delivery",
        deliveryKey,
        input,
        null,
        sha256Canonical({
          status: result.status,
          revision: result.revision,
          reconciliationRef: result.reconciliationRef,
        }),
      );
      return result;
    });
  }

  async commitReconciliationReceipt(value) {
    this.assertInitialized();
    return this.commitReceipt(value, true);
  }

  async commitReceipt(value, reconciliation) {
    const input = exactKeys(
      snapshot(value, reconciliation ? "reconciliationReceipt" : "deliveryReceiptCommit"),
      reconciliation
        ? ["receipt", "expectedRevision", "reconciliationRef", "reconciliationOwnerRef"]
        : ["receipt", "expectedRevision"],
      reconciliation
        ? ["receipt", "expectedRevision", "reconciliationRef", "reconciliationOwnerRef"]
        : ["receipt", "expectedRevision"],
      reconciliation ? "reconciliationReceipt" : "deliveryReceiptCommit",
    );
    const expectedRevision = integer(input.expectedRevision, "receiptCommit.expectedRevision");
    const authorityRef = reconciliation ? identifier(input.reconciliationRef, "receiptCommit.reconciliationRef") : null;
    const authorityOwnerRef = reconciliation
      ? identifier(input.reconciliationOwnerRef, "receiptCommit.reconciliationOwnerRef")
      : null;
    const deliveryKey = hash(input.receipt.deliveryKey, "deliveryReceipt.deliveryKey");
    return transact(this.pool, this.runtimeScope, deliveryKey, async (client) => {
      const reservation = (
        await client.query(
          `${reservationSelect} WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3 FOR UPDATE`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, deliveryKey],
        )
      ).rows[0];
      if (!reservation || Number(reservation.revision) !== expectedRevision)
        storeError("delivery_conflict", "Delivery receipt revision does not match");
      reservationResult(reservation, this.deployment);
      if (reconciliation) {
        if (
          reservation.status !== "outcome_unknown" ||
          reservation.reconciliation_ref !== authorityRef ||
          reservation.reconciliation_owner_ref !== authorityOwnerRef ||
          reservation.reconciliation_active !== true
        ) {
          storeError("reconciliation_conflict", "Delivery reconciliation lease is not active");
        }
      } else if (reservation.status !== "attempting") {
        storeError("delivery_conflict", "Delivery is not awaiting its initial receipt");
      }
      const receipt = validateReceipt(input.receipt, reservation);
      if (reconciliation && receipt.status === "outcome_unknown")
        storeError("reconciliation_conflict", "Reconciliation must reach a verified or failed outcome");
      const nextRevision = Number(
        (
          await client.query(
            `SELECT COALESCE(max(revision), 0)::bigint + 1 AS revision
             FROM ${CANARY_SCHEMA_NAME}.surface_delivery_receipts
             WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3`,
            [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, deliveryKey],
          )
        ).rows[0].revision,
      );
      await client.query(
        `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_delivery_receipts
           (profile_ref, profile_sha256, delivery_key, revision, status, receipt_sha256, receipt)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
        [
          this.runtimeScope.profileRef,
          this.runtimeScope.profileSha256,
          deliveryKey,
          nextRevision,
          receipt.status,
          receipt.receiptSha256,
          JSON.stringify(receipt),
        ],
      );
      const terminalOperation = reconciliation ? "surface_delivery_reconciled" : "surface_delivery_receipt_recorded";
      if (receipt.status !== "outcome_unknown") {
        const event = (
          await client.query(
            `SELECT outbox_item FROM ${CANARY_SCHEMA_NAME}.surface_outbox_events
             WHERE profile_ref = $1 AND profile_sha256 = $2 AND event_id = $3`,
            [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, reservation.outbox_event_id],
          )
        ).rows[0];
        if (!event) storeError("stored_outbox_corrupt", "Terminal delivery lost its outbox envelope");
        const history = await client.query(
          `SELECT delivery_key, revision, status, receipt_sha256, receipt, recorded_at
           FROM ${CANARY_SCHEMA_NAME}.surface_delivery_receipts
           WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3 ORDER BY revision`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, deliveryKey],
        );
        const terminalRecord = {
          contractType: "ceo-surface-delivery-tombstone",
          contractVersion: 1,
          deliveryKey,
          outboxEventId: reservation.outbox_event_id,
          outboxItem: snapshot(event.outbox_item, "terminalOutboxItem"),
          identityResolution: snapshot(reservation.identity_resolution, "terminalIdentityResolution"),
          publication: snapshot(reservation.publication, "terminalPublication"),
          attemptRef: reservation.attempt_ref,
          attemptedAt: iso(reservation.attempted_at, "terminalAttemptedAt"),
          reservedAt: iso(reservation.reserved_at, "terminalReservedAt"),
          receipts: history.rows.map((entry) => {
            if (entry.delivery_key !== deliveryKey)
              storeError("stored_receipt_corrupt", "Terminal receipt history crossed a delivery identity");
            return {
              revision: Number(entry.revision),
              status: entry.status,
              receiptSha256: entry.receipt_sha256,
              receipt: snapshot(entry.receipt, "terminalReceipt"),
              recordedAt: iso(entry.recorded_at, "terminalReceiptRecordedAt"),
            };
          }),
          terminalStatus: receipt.status,
          completedAt: receipt.completedAt,
          auditBinding: {
            principalRef: this.deployment.qmPrincipalRef,
            operation: terminalOperation,
            request: snapshot(input, "terminalAuditRequest"),
            requestSha256: sha256Canonical(input),
            afterSha256: receipt.receiptSha256,
          },
        };
        const recordSha256 = sha256Canonical(terminalRecord);
        try {
          await client.query(
            `INSERT INTO ${CANARY_SCHEMA_NAME}.surface_delivery_tombstones
               (profile_ref, profile_sha256, delivery_key, outbox_event_id, outbox_payload_sha256, deployment_binding_sha256,
                artifact_sha256, identity_resolution_sha256, target_binding_sha256, message_sha256,
                terminal_status, record_sha256, terminal_record, completed_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14::timestamptz)
             ON CONFLICT (profile_ref, profile_sha256, delivery_key) DO NOTHING`,
            [
              this.runtimeScope.profileRef,
              this.runtimeScope.profileSha256,
              deliveryKey,
              reservation.outbox_event_id,
              reservation.outbox_payload_sha256,
              reservation.deployment_binding_sha256,
              reservation.artifact_sha256,
              reservation.identity_resolution_sha256,
              reservation.target_binding_sha256,
              reservation.message_sha256,
              receipt.status,
              recordSha256,
              JSON.stringify(terminalRecord),
              receipt.completedAt,
            ],
          );
        } catch (error) {
          if (error?.code === "23505")
            storeError("delivery_conflict", "Delivery tombstone conflicts with a permanent delivery identity");
          throw error;
        }
        const tombstone = (
          await client.query(
            `SELECT * FROM ${CANARY_SCHEMA_NAME}.surface_delivery_tombstones
             WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3`,
            [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, deliveryKey],
          )
        ).rows[0];
        if (
          tombstone?.record_sha256 !== recordSha256 ||
          tombstoneResult(tombstone, this.deployment, this.deploymentInput).recordSha256 !== recordSha256
        )
          storeError("delivery_conflict", "Delivery tombstone content conflicts with its permanent identity");
      }
      const terminalStatus = receipt.status === "verified" ? "delivered" : receipt.status;
      const completedAt = receipt.status === "outcome_unknown" ? null : receipt.completedAt;
      const updated = await client.query(
        `UPDATE ${CANARY_SCHEMA_NAME}.surface_delivery_reservations
         SET status = $4, revision = revision + 1, completed_at = $5::timestamptz,
             reconciliation_ref = NULL, reconciliation_owner_ref = NULL,
             reconciliation_acquired_at = NULL, reconciliation_expires_at = NULL,
             updated_at = clock_timestamp()
         WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3 AND revision = $6
         RETURNING *`,
        [
          this.runtimeScope.profileRef,
          this.runtimeScope.profileSha256,
          deliveryKey,
          receipt.status,
          completedAt,
          expectedRevision,
        ],
      );
      if (updated.rowCount !== 1) storeError("delivery_conflict", "Delivery receipt lost its revision race");
      await client.query(
        `UPDATE ${CANARY_SCHEMA_NAME}.surface_outbox_states states
         SET status = $4, claim_ref = NULL, claim_owner_ref = NULL,
             claim_acquired_at = NULL, claim_expires_at = NULL,
             failure_code = $5, revision = revision + 1, updated_at = clock_timestamp()
         FROM ${CANARY_SCHEMA_NAME}.surface_delivery_reservations reservations
         WHERE reservations.profile_ref = $1 AND reservations.profile_sha256 = $2
           AND reservations.delivery_key = $3
           AND states.profile_ref = reservations.profile_ref
           AND states.profile_sha256 = reservations.profile_sha256
           AND states.event_id = reservations.outbox_event_id`,
        [
          this.runtimeScope.profileRef,
          this.runtimeScope.profileSha256,
          deliveryKey,
          terminalStatus,
          receipt.status === "failed" ? "provider_refused" : null,
        ],
      );
      await audit(
        client,
        this.deployment,
        terminalOperation,
        "surface_delivery",
        deliveryKey,
        input,
        null,
        receipt.receiptSha256,
      );
      return reservationResult(updated.rows[0], this.deployment);
    });
  }

  async readDeliveryReceipt(value) {
    this.assertInitialized();
    const deliveryKey = hash(value, "deliveryKey");
    return snapshotRead(this.pool, this.runtimeScope, async (client) => {
      const reservation = (
        await client.query(
          `${reservationSelect} WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, deliveryKey],
        )
      ).rows[0];
      const tombstoneRow = (
        await client.query(
          `SELECT * FROM ${CANARY_SCHEMA_NAME}.surface_delivery_tombstones
           WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, deliveryKey],
        )
      ).rows[0];
      const tombstone = tombstoneResult(tombstoneRow, this.deployment, this.deploymentInput);
      if (!reservation) return tombstone;
      const checkedReservation = reservationResult(reservation, this.deployment);
      const outboxRow = (
        await client.query(
          `${outboxSelect} WHERE events.profile_ref = $1 AND events.profile_sha256 = $2 AND events.event_id = $3`,
          [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, reservation.outbox_event_id],
        )
      ).rows[0];
      const outbox = outboxResult(outboxRow, this.deployment);
      if (!outbox) storeError("stored_reservation_corrupt", "Stored reservation lost its outbox envelope");
      const reconstructed = reconstructShadowPublication(
        {
          deploymentBinding: this.deploymentInput,
          outboxItem: outbox.outboxItem,
          identityResolution: checkedReservation.identityResolution,
        },
        checkedReservation.reservedAt,
      );
      if (!same(reconstructed, checkedReservation.publication))
        storeError("stored_reservation_corrupt", "Stored reservation publication is not compiler-authentic");
      const storedReceipts = await client.query(
        `SELECT delivery_key, revision, status, receipt_sha256, receipt, recorded_at
         FROM ${CANARY_SCHEMA_NAME}.surface_delivery_receipts
         WHERE profile_ref = $1 AND profile_sha256 = $2 AND delivery_key = $3 ORDER BY revision`,
        [this.runtimeScope.profileRef, this.runtimeScope.profileSha256, deliveryKey],
      );
      const receipts = storedReceipts.rows.map((row, index) => {
        const receipt = validateReceipt(row.receipt, reservation);
        const revision = integer(Number(row.revision), "storedDeliveryReceipt.revision", 1);
        const recordedAt = iso(row.recorded_at, "storedDeliveryReceipt.recordedAt");
        if (
          row.delivery_key !== deliveryKey ||
          revision !== index + 1 ||
          row.status !== receipt.status ||
          row.receipt_sha256 !== receipt.receiptSha256 ||
          Date.parse(recordedAt) < Date.parse(receipt.completedAt)
        ) {
          storeError("stored_receipt_corrupt", "Stored receipt row or revision lineage does not match");
        }
        return Object.freeze({
          revision,
          status: row.status,
          receiptSha256: row.receipt_sha256,
          receipt,
          recordedAt,
        });
      });
      const statuses = receipts.map((entry) => entry.status).join(",");
      const allowed = {
        reserved: [""],
        attempting: [""],
        outcome_unknown: ["outcome_unknown"],
        verified: ["verified", "outcome_unknown,verified"],
        failed: ["failed", "outcome_unknown,failed"],
      }[reservation.status];
      if (!allowed?.includes(statuses))
        storeError("stored_receipt_corrupt", "Stored receipt history does not match reservation status");
      const reservationRevision = integer(Number(reservation.revision), "storedReservation.revision");
      if (
        (reservation.status === "reserved" && reservationRevision !== 0) ||
        (reservation.status === "attempting" && reservationRevision !== 1) ||
        (["outcome_unknown", "verified", "failed"].includes(reservation.status) &&
          reservationRevision < receipts.length + 1)
      )
        storeError("stored_receipt_corrupt", "Stored receipt history does not match reservation revision lineage");
      const expectedOutboxStatus = {
        reserved: "claimed",
        attempting: "claimed",
        outcome_unknown: "outcome_unknown",
        verified: "delivered",
        failed: "failed",
      }[reservation.status];
      if (outbox.status !== expectedOutboxStatus)
        storeError("stored_receipt_corrupt", "Stored outbox state does not match delivery reservation lineage");
      if (
        tombstone &&
        (tombstone.terminalStatus !== reservation.status ||
          tombstone.reservedAt !== checkedReservation.reservedAt ||
          tombstone.record.attemptRef !== checkedReservation.attemptRef ||
          tombstone.record.attemptedAt !== checkedReservation.attemptedAt ||
          !same(tombstone.record.identityResolution, checkedReservation.identityResolution) ||
          !same(tombstone.record.publication, checkedReservation.publication) ||
          !same(tombstone.receipts, receipts))
      )
        storeError("stored_tombstone_corrupt", "Stored terminal detail does not match its tombstone");
      return Object.freeze({
        retired: false,
        reservation: checkedReservation,
        receipts: Object.freeze(receipts),
        tombstone,
      });
    });
  }
}

const canonicalFacadeTestKey = Symbol("canonical-ceo-surface-v5-test-port");

function canonicalV5Outbox(contracts, event, envelope, deployment) {
  return contracts.PrincipalBinding.freeze({
    contractType: "ceo-surface-canonical-outbox",
    contractVersion: 1,
    eventId: event.eventId,
    deploymentBindingSha256: deployment.bindingSha256,
    artifact: {
      id: event.artifact.artifactRef,
      revision: event.artifact.revision,
    },
    artifactSha256: event.artifact.artifactSha256,
    evalRelease: {
      evaluatedAt: event.evalRelease.evaluatedAt,
      expiresAt: event.evalRelease.expiresAt,
      receiptSha256: event.evalRelease.releaseSha256,
    },
    queuedAt: event.queuedAt,
    payloadSha256: envelope.envelopeSha256,
    canonicalEvent: event,
    publicationEnvelope: envelope,
  });
}

function facadeResult(contracts, value) {
  if (!value) return null;
  const item = value.outboxItem;
  if (!item || item.contractType !== "ceo-surface-canonical-outbox") {
    storeError("stored_outbox_corrupt", "Canonical facade encountered a noncanonical v5 outbox item");
  }
  const event = contracts.OutboxEvent.validate(item.canonicalEvent);
  const envelope = contracts.PublicationEnvelope.validate(item.publicationEnvelope, event);
  if (
    item.eventId !== event.eventId ||
    item.artifact.id !== event.artifact.artifactRef ||
    item.artifact.revision !== event.artifact.revision ||
    item.artifactSha256 !== event.artifact.artifactSha256 ||
    item.evalRelease.receiptSha256 !== event.evalRelease.releaseSha256 ||
    item.payloadSha256 !== envelope.envelopeSha256
  ) {
    storeError("stored_outbox_corrupt", "Canonical facade v5 aliases do not match their shared contracts");
  }
  return contracts.PrincipalBinding.freeze({
    outboxEvent: event,
    publicationEnvelope: envelope,
    status: value.status,
    revision: value.revision,
    claimRef: value.claimRef ?? null,
    claimOwnerRef: value.claimOwnerRef ?? null,
    claimAcquiredAt: value.claimAcquiredAt ?? null,
    claimExpiresAt: value.claimExpiresAt ?? null,
    failureCode: value.failureCode ?? null,
  });
}

function methodValue(value, name) {
  let owner = value;
  while (owner && !Object.hasOwn(owner, name)) owner = Object.getPrototypeOf(owner);
  const descriptor = owner ? Object.getOwnPropertyDescriptor(owner, name) : undefined;
  if (
    !descriptor ||
    descriptor.get ||
    descriptor.set ||
    typeof descriptor.value !== "function" ||
    types.isProxy(descriptor.value)
  ) {
    throw new TypeError(`Canonical CEO surface facade requires a descriptor-safe ${name} method`);
  }
  return (...args) => Reflect.apply(descriptor.value, value, args);
}

export class CanonicalCeoSurfaceStore {
  constructor(options, key, testStore) {
    if (key === canonicalFacadeTestKey) {
      const runtimeScope = assertRuntimeScope(options.scope);
      const deploymentInput = snapshot(options.deploymentBinding, "deploymentBinding");
      const surfaceContracts = createSurfaceContractSuite(runtimeScope);
      Object.defineProperties(this, {
        runtimeScope: { value: runtimeScope, enumerable: false },
        contracts: { value: runtimeScope.contracts, enumerable: false },
        deployment: { value: surfaceContracts.compileDeploymentBinding(deploymentInput), enumerable: false },
        initializeStore: { value: methodValue(testStore, "initialize"), enumerable: false },
        enqueueStore: { value: methodValue(testStore, "enqueueEvaluatedArtifactRevision"), enumerable: false },
        readStore: { value: methodValue(testStore, "readOutboxEvent"), enumerable: false },
      });
      return;
    }
    const store = new PostgresCeoSurfaceStore(options);
    Object.defineProperties(this, {
      contracts: { value: store.runtimeScope.contracts, enumerable: false },
      deployment: { value: store.deployment, enumerable: false },
      initializeStore: { value: store.initialize.bind(store), enumerable: false },
      enqueueStore: { value: store.enqueueEvaluatedArtifactRevision.bind(store), enumerable: false },
      readStore: { value: store.readOutboxEvent.bind(store), enumerable: false },
    });
  }

  async initialize() {
    await this.initializeStore();
    return true;
  }

  async enqueuePublication(value) {
    const input = exactKeys(
      snapshot(value, "canonical publication enqueue"),
      ["outboxEvent", "publicationEnvelope"],
      ["outboxEvent", "publicationEnvelope"],
      "canonical publication enqueue",
    );
    const event = this.contracts.OutboxEvent.validate(input.outboxEvent);
    const envelope = this.contracts.PublicationEnvelope.validate(input.publicationEnvelope, event);
    const stored = await this.enqueueStore(canonicalV5Outbox(this.contracts, event, envelope, this.deployment));
    return facadeResult(this.contracts, stored);
  }

  async readPublication(eventId) {
    const stored = await this.readStore(identifier(eventId, "eventId"));
    return facadeResult(this.contracts, stored);
  }
}

export function bindCanonicalCeoSurfaceStoreForProviderFreeTest(store, deploymentBinding) {
  return new CanonicalCeoSurfaceStore({ deploymentBinding, scope: CEO_RUNTIME_SCOPE }, canonicalFacadeTestKey, store);
}
