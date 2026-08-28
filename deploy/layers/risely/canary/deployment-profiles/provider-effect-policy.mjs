import { createHash } from "node:crypto";

const capability = (value) =>
  Object.freeze({ capabilityVersion: 1, maximumAttempts: 1, maximumLeaseLifetimeMs: 300_000, ...value });

const capabilities = Object.freeze([
  capability({
    capability: "google.calendar.events.create",
    provider: "google",
    operation: "google.calendar.events.create",
    authorizationMode: "automatic",
    ownershipMode: "agent-managed-resource",
    targetClass: "primary-calendar-managed-event",
    reconciliationRequired: true,
  }),
  capability({
    capability: "google.calendar.events.update",
    provider: "google",
    operation: "google.calendar.events.update",
    authorizationMode: "automatic",
    ownershipMode: "agent-managed-resource",
    targetClass: "primary-calendar-managed-event",
    reconciliationRequired: true,
  }),
  capability({
    capability: "google.gmail.drafts.create",
    provider: "google",
    operation: "google.gmail.drafts.create",
    authorizationMode: "automatic",
    ownershipMode: "owner-mailbox-draft",
    targetClass: "exact-owner-mailbox",
    reconciliationRequired: true,
  }),
  capability({
    capability: "google.gmail.drafts.send",
    provider: "google",
    operation: "google.gmail.drafts.send",
    authorizationMode: "approval-once",
    ownershipMode: "owner-mailbox-draft",
    targetClass: "exact-approved-draft-revision",
    reconciliationRequired: true,
  }),
  capability({
    capability: "notion.pages.upsert",
    provider: "notion",
    operation: "notion.pages.upsert",
    authorizationMode: "automatic",
    ownershipMode: "agent-managed-resource",
    targetClass: "attested-private-ceo-root",
    reconciliationRequired: true,
  }),
  capability({
    capability: "slack.chat.post",
    provider: "slack",
    operation: "slack.chat.post-message",
    authorizationMode: "automatic",
    ownershipMode: "fixed-private-destination",
    targetClass: "verified-ceo-direct-message",
    reconciliationRequired: true,
  }),
]);

const projection = Object.freeze({
  contractType: "ProviderEffectPolicyCatalog",
  contractVersion: 1,
  digestRevision: "ProviderEffectPolicyCatalog.sha256.v1",
  policyRef: "provider-effect-policy:risely:v1",
  sourceAliases: Object.freeze([
    Object.freeze({
      source: "gmail",
      provider: "google",
      accountBinding: "signed-google-subject-mailbox-required",
    }),
  ]),
  capabilities,
});

export const providerEffectPolicyCatalogSha256 = createHash("sha256")
  .update(JSON.stringify(projection), "utf8")
  .digest("hex");

export const providerEffectPolicyCatalog = Object.freeze({
  ...projection,
  policySha256: providerEffectPolicyCatalogSha256,
});
