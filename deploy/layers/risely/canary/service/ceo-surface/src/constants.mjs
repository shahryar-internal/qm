export const fixedCeoSurface = Object.freeze({
  contractVersion: 1,
  deploymentId: "risely-ceo-surface",
  teamRef: "team:risely",
  audienceRef: "audience:risely:ceo-private",
  qmRootUrl: "https://qm.riselyinternal.ai/",
  qmAuthenticationMode: "oidc",
  deliveryMode: "shadow",
});

export const activationRequirements = Object.freeze([
  "deployment_owned_binding_anchor",
  "authenticated_eval_release_authority",
  "authenticated_outbox_writer",
  "reviewed_identity_resolver_adapter",
  "reviewed_durable_outbox_adapter",
  "reviewed_durable_receipt_store_adapter",
  "reviewed_slack_delivery_adapter",
  "independent_security_approval",
  "explicit_production_startup_implementation",
]);

export const durableOutboxMethods = Object.freeze([
  "enqueueEvaluatedArtifactRevision",
  "claimEvaluatedArtifactRevision",
  "renewClaim",
  "releaseClaim",
  "readOutboxEvent",
]);

export const durableReceiptMethods = Object.freeze([
  "reserveDeliveryKey",
  "beginDeliveryAttempt",
  "commitDeliveryReceipt",
  "reserveDeliveryReconciliation",
  "commitReconciliationReceipt",
  "readDeliveryReceipt",
]);

export const receiptRequiredFields = Object.freeze([
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
  "status",
  "attemptedAt",
  "completedAt",
  "receiptSha256",
]);

export const receiptOptionalFields = Object.freeze(["providerReceiptRef"]);

export const reservationConflictFields = Object.freeze([
  "outboxPayloadSha256",
  "artifactSha256",
  "identityResolutionSha256",
  "targetBindingSha256",
  "messageSha256",
]);

export const liveReceiptAuthorityRequirements = Object.freeze([
  "authenticated_slack_adapter_receipt",
  "durable_delivery_key_reservation",
  "exact_publication_conflict_binding",
]);
