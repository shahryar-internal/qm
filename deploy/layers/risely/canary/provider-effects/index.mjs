import { assertRuntimeScope } from "../runtime-scope/index.mjs";
import { assertActionProposalHashes } from "../contracts/index.mjs";
import { providerEffectPolicyCatalog, providerEffectPolicyCatalogSha256 } from "../deployment-profiles/index.mjs";

const definitions = providerEffectPolicyCatalog.capabilities;

const byCapability = new Map(definitions.map((definition) => [definition.capability, definition]));
const digestPattern = /^[a-f0-9]{64}$/u;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const emailPattern =
  /^(?=.{3,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/u;

const exact = (value, fields, label) => {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  ) {
    throw new TypeError(`${label} has an unsupported shape`);
  }
  return value;
};

const identifier = (value, label) => {
  if (typeof value !== "string" || !identifierPattern.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
};

const digest = (value, label) => {
  if (typeof value !== "string" || !digestPattern.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
};

const text = (value, label, maximum) => {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > maximum ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
};

const headerText = (value, label, maximum) => {
  if (typeof value !== "string" || !value || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
};

const instant = (value, label) => {
  if (typeof value !== "string" || new Date(value).toISOString() !== value) throw new TypeError(`${label} is invalid`);
  return value;
};

const validateGmailDraft = (scope, proposal, providerOwnerRef) => {
  const target = exact(proposal.target, ["providerOwnerRef", "mailbox", "to"], "Gmail draft target");
  const payload = exact(
    proposal.payload,
    ["body", "evidenceSha256", "payloadSha256", "subject"],
    "Gmail draft payload",
  );
  if (
    target.providerOwnerRef !== providerOwnerRef ||
    target.mailbox !== scope.profile.identity.humanEmail ||
    !Array.isArray(target.to) ||
    target.to.length < 1 ||
    target.to.length > 20 ||
    new Set(target.to).size !== target.to.length ||
    target.to.some(
      (entry) =>
        typeof entry !== "string" || entry.length > 254 || entry !== entry.toLowerCase() || !emailPattern.test(entry),
    )
  ) {
    throw new TypeError("Gmail draft target is invalid");
  }
  headerText(payload.subject, "Gmail draft subject", 200);
  text(payload.body, "Gmail draft body", 100_000);
  const evidenceSha256 = scope.contracts.PrincipalBinding.hash(proposal.evidenceRefs);
  const payloadSha256 = scope.contracts.PrincipalBinding.hash({
    target,
    payload: { body: payload.body, evidenceSha256, subject: payload.subject },
  });
  if (payload.evidenceSha256 !== evidenceSha256 || payload.payloadSha256 !== payloadSha256) {
    throw new TypeError("Gmail draft payload lineage is invalid");
  }
};

const validateGmailSend = (scope, proposal, providerOwnerRef) => {
  const target = exact(
    proposal.target,
    ["providerOwnerRef", "mailbox", "draftId", "draftRevisionSha256"],
    "Gmail send target",
  );
  const payload = exact(proposal.payload, ["expectedContentSha256"], "Gmail send payload");
  if (target.providerOwnerRef !== providerOwnerRef || target.mailbox !== scope.profile.identity.humanEmail) {
    throw new TypeError("Gmail send target is invalid");
  }
  identifier(target.draftId, "Gmail draft identifier");
  digest(target.draftRevisionSha256, "Gmail draft revision digest");
  digest(payload.expectedContentSha256, "Gmail expected content digest");
  if (payload.expectedContentSha256 !== target.draftRevisionSha256) {
    throw new TypeError("Gmail send draft revision is invalid");
  }
};

const calendarPayload = (value) => {
  const payload = exact(
    value,
    ["summary", "description", "startAt", "endAt", "timeZone", "location", "privateOwnershipKey"],
    "Calendar event payload",
  );
  text(payload.summary, "Calendar event summary", 512);
  if (payload.description !== null) text(payload.description, "Calendar event description", 8_192);
  if (payload.location !== null) text(payload.location, "Calendar event location", 512);
  instant(payload.startAt, "Calendar event start");
  instant(payload.endAt, "Calendar event end");
  if (Date.parse(payload.endAt) <= Date.parse(payload.startAt))
    throw new TypeError("Calendar event interval is invalid");
  text(payload.timeZone, "Calendar event time zone", 64);
  digest(payload.privateOwnershipKey, "Calendar event ownership key");
};

const validateCalendarCreate = (_scope, proposal, providerOwnerRef) => {
  const target = exact(proposal.target, ["providerOwnerRef", "calendarRef", "resourceKey"], "Calendar create target");
  if (target.providerOwnerRef !== providerOwnerRef || target.calendarRef !== "google-calendar:primary") {
    throw new TypeError("Calendar create target is invalid");
  }
  digest(target.resourceKey, "Calendar resource key");
  calendarPayload(proposal.payload);
  const expectedOwnershipKey = _scope.contracts.PrincipalBinding.hash({
    profileRef: _scope.profileRef,
    profileSha256: _scope.profileSha256,
    providerOwnerRef,
    calendarRef: target.calendarRef,
    resourceKey: target.resourceKey,
  });
  if (proposal.payload.privateOwnershipKey !== expectedOwnershipKey) {
    throw new TypeError("Calendar event ownership key is invalid");
  }
};

const validateCalendarUpdate = (_scope, proposal, providerOwnerRef) => {
  const target = exact(
    proposal.target,
    ["providerOwnerRef", "calendarRef", "resourceKey", "providerEventId", "expectedEtag", "ownershipReceiptSha256"],
    "Calendar update target",
  );
  if (target.providerOwnerRef !== providerOwnerRef || target.calendarRef !== "google-calendar:primary") {
    throw new TypeError("Calendar update target is invalid");
  }
  digest(target.resourceKey, "Calendar resource key");
  identifier(target.providerEventId, "Calendar provider event identifier");
  text(target.expectedEtag, "Calendar expected ETag", 512);
  digest(target.ownershipReceiptSha256, "Calendar ownership receipt digest");
  calendarPayload(proposal.payload);
  const expectedOwnershipKey = _scope.contracts.PrincipalBinding.hash({
    profileRef: _scope.profileRef,
    profileSha256: _scope.profileSha256,
    providerOwnerRef,
    calendarRef: target.calendarRef,
    resourceKey: target.resourceKey,
  });
  if (proposal.payload.privateOwnershipKey !== expectedOwnershipKey) {
    throw new TypeError("Calendar event ownership key is invalid");
  }
};

const validateSlackPost = (scope, proposal, providerOwnerRef) => {
  const target = exact(
    proposal.target,
    ["providerOwnerRef", "teamRef", "principalRef", "audienceRef"],
    "Slack private target",
  );
  const payload = exact(
    proposal.payload,
    ["text", "artifactSha256", "outboxEventId", "messageSha256"],
    "Slack private payload",
  );
  if (
    target.providerOwnerRef !== providerOwnerRef ||
    target.teamRef !== scope.profile.anchors.slackTeamRef ||
    target.principalRef !== scope.profile.audiences.slack.principalRef ||
    target.audienceRef !== scope.profile.audiences.slack.audienceRef
  ) {
    throw new TypeError("Slack private target is invalid");
  }
  text(payload.text, "Slack private message", 4_000);
  digest(payload.artifactSha256, "Slack artifact digest");
  identifier(payload.outboxEventId, "Slack outbox event identifier");
  digest(payload.messageSha256, "Slack message digest");
  if (
    payload.messageSha256 !==
    scope.contracts.PrincipalBinding.hash({
      target,
      text: payload.text,
      artifactSha256: payload.artifactSha256,
      outboxEventId: payload.outboxEventId,
    })
  ) {
    throw new TypeError("Slack message digest is invalid");
  }
};

const validateNotionUpsert = (scope, proposal, providerOwnerRef) => {
  const target = exact(
    proposal.target,
    ["providerOwnerRef", "parentRef", "audienceRef", "resourceKey"],
    "Notion private target",
  );
  const payload = exact(
    proposal.payload,
    ["title", "artifactRef", "artifactRevision", "artifactSha256", "renderSha256"],
    "Notion private payload",
  );
  if (
    target.providerOwnerRef !== providerOwnerRef ||
    target.parentRef !== scope.profile.audiences.notion.parentRef ||
    target.audienceRef !== scope.profile.audiences.notion.audienceRef
  ) {
    throw new TypeError("Notion private target is invalid");
  }
  digest(target.resourceKey, "Notion resource key");
  text(payload.title, "Notion page title", 512);
  identifier(payload.artifactRef, "Notion artifact reference");
  if (!Number.isSafeInteger(payload.artifactRevision) || payload.artifactRevision < 1) {
    throw new TypeError("Notion artifact revision is invalid");
  }
  digest(payload.artifactSha256, "Notion artifact digest");
  digest(payload.renderSha256, "Notion render digest");
  if (
    target.resourceKey !==
    scope.contracts.PrincipalBinding.hash({
      profileRef: scope.profileRef,
      profileSha256: scope.profileSha256,
      parentRef: target.parentRef,
      audienceRef: target.audienceRef,
      artifactRef: payload.artifactRef,
    })
  ) {
    throw new TypeError("Notion resource key is invalid");
  }
};

const proposalValidators = Object.freeze({
  "google.gmail.drafts.create": validateGmailDraft,
  "google.gmail.drafts.send": validateGmailSend,
  "google.calendar.events.create": validateCalendarCreate,
  "google.calendar.events.update": validateCalendarUpdate,
  "notion.pages.upsert": validateNotionUpsert,
  "slack.chat.post": validateSlackPost,
});

const unavailableProofs = Object.freeze({
  "google.calendar.events.create": Object.freeze([
    "google_account_identity_receipt_unavailable",
    "google_calendar_operation_adapter_unavailable",
  ]),
  "google.calendar.events.update": Object.freeze([
    "google_account_identity_receipt_unavailable",
    "google_calendar_operation_adapter_unavailable",
    "managed_calendar_resource_receipt_unavailable",
  ]),
  "google.gmail.drafts.create": Object.freeze([
    "google_account_identity_receipt_unavailable",
    "google_compose_operation_adapter_unavailable",
  ]),
  "google.gmail.drafts.send": Object.freeze([
    "google_account_identity_receipt_unavailable",
    "google_send_operation_adapter_unavailable",
    "managed_draft_receipt_unavailable",
    "one_use_approval_unavailable",
  ]),
  "notion.pages.upsert": Object.freeze([
    "notion_private_root_receipt_unavailable",
    "notion_owned_resource_mapping_unavailable",
    "notion_operation_adapter_unavailable",
  ]),
  "slack.chat.post": Object.freeze([
    "slack_identity_receipt_unavailable",
    "slack_direct_message_receipt_unavailable",
    "slack_operation_adapter_unavailable",
  ]),
});

const policyFor = (scope, capability) => {
  const definition = byCapability.get(capability);
  if (!definition) throw new TypeError("Provider effect capability is unsupported");
  if (
    scope.profile.providerEffectPolicyRef !== providerEffectPolicyCatalog.policyRef ||
    scope.profile.providerEffectPolicySha256 !== providerEffectPolicyCatalogSha256
  ) {
    throw new TypeError("Provider effect policy catalog does not match the deployment profile");
  }
  const providerOwnerRef = scope.profile.providerOwners.find(
    (entry) => entry.provider === definition.provider,
  )?.providerOwnerRef;
  if (!providerOwnerRef) throw new TypeError("Provider effect owner is unavailable");
  const profileCapabilityDeclared = scope.profile.allowedCapabilities.includes(capability);
  const blockers = [
    ...(profileCapabilityDeclared ? [] : ["capability_not_declared"]),
    ...(scope.profile.providerExecutionAllowed ? [] : ["provider_execution_not_activated"]),
    ...(scope.profile.grantPolicy.maximumProviderGrantLifetimeMs > 0 ? [] : ["provider_grant_not_activated"]),
    "provider_identity_receipt_unavailable",
    "durable_effect_authority_unavailable",
    "evaluation_release_unavailable",
    ...unavailableProofs[definition.capability],
  ].sort();
  return scope.contracts.PrincipalBinding.freeze({
    contractType: "ProviderEffectPolicy",
    contractVersion: 1,
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    policyRef: providerEffectPolicyCatalog.policyRef,
    policySha256: providerEffectPolicyCatalogSha256,
    capability: definition.capability,
    capabilityVersion: definition.capabilityVersion,
    provider: definition.provider,
    providerOwnerRef,
    operation: definition.operation,
    authorizationMode: definition.authorizationMode,
    ownershipMode: definition.ownershipMode,
    targetClass: definition.targetClass,
    maximumApprovalLifetimeMs:
      definition.authorizationMode === "approval-once" ? scope.profile.grantPolicy.maximumApprovalLifetimeMs : 0,
    maximumGrantLifetimeMs: scope.profile.grantPolicy.maximumProviderGrantLifetimeMs,
    maximumLeaseLifetimeMs: definition.maximumLeaseLifetimeMs,
    maximumAttempts: definition.maximumAttempts,
    reconciliationRequired: definition.reconciliationRequired,
    profileCapabilityDeclared,
    executionAvailable: blockers.length === 0,
    blockers,
  });
};

const intentFor = (scope, proposal, policy) => {
  const prospectiveEffectKey = scope.contracts.PrincipalBinding.hash({
    digestRevision: "ProviderEffectIntent.effectKey.v1",
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    policyRef: policy.policyRef,
    policySha256: policy.policySha256,
    capability: policy.capability,
    capabilityVersion: policy.capabilityVersion,
    provider: policy.provider,
    operation: policy.operation,
    providerOwnerRef: policy.providerOwnerRef,
    proposalEffectKey: proposal.effectKey,
  });
  const projection = {
    contractType: "ProviderEffectIntent",
    contractVersion: 1,
    digestRevision: "ProviderEffectIntent.sha256.v1",
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    policyRef: policy.policyRef,
    policySha256: policy.policySha256,
    proposalId: proposal.proposalId,
    proposalHash: proposal.proposalHash,
    capability: policy.capability,
    capabilityVersion: policy.capabilityVersion,
    provider: policy.provider,
    operation: policy.operation,
    providerOwnerRef: policy.providerOwnerRef,
    authorizationMode: policy.authorizationMode,
    proposalEffectKey: proposal.effectKey,
    prospectiveEffectKey,
  };
  return scope.contracts.PrincipalBinding.freeze({
    ...projection,
    intentSha256: scope.contracts.PrincipalBinding.hash(projection),
  });
};

const validateProposalFor = (scope, value) => {
  const proposal = assertActionProposalHashes(value);
  const policy = policyFor(scope, proposal.capability);
  const expected = scope.domainAuthority;
  if (
    !policy.profileCapabilityDeclared ||
    proposal.capabilityVersion !== policy.capabilityVersion ||
    proposal.provider !== policy.provider ||
    proposal.actor.principalRef !== expected.principalRef ||
    proposal.actor.qmPrincipalId !== expected.qmPrincipalId ||
    proposal.actor.externalPrincipalRef !== expected.externalPrincipalRef ||
    proposal.actor.agent.id !== expected.agentId ||
    proposal.actor.agent.version !== expected.agentVersion ||
    proposal.actor.scopeRef !== expected.scopeRef ||
    proposal.actor.audienceRef !== expected.audienceRef ||
    proposal.actor.credentialOwnerRef !== expected.credentialOwnerRef ||
    proposal.credentialRef !== expected.credentialOwnerRef ||
    Date.parse(proposal.expiresAt) <= Date.parse(proposal.createdAt) ||
    Date.parse(proposal.expiresAt) - Date.parse(proposal.createdAt) >
      scope.profile.grantPolicy.maximumApprovalLifetimeMs
  ) {
    throw new TypeError("Provider effect proposal is outside profile authority");
  }
  if (proposal.evidenceRefs.some((entry) => entry.audienceRef !== expected.audienceRef)) {
    throw new TypeError("Provider effect evidence is outside the profile audience");
  }
  proposalValidators[proposal.capability](scope, proposal, policy.providerOwnerRef);
  return scope.contracts.PrincipalBinding.freeze({ proposal, policy, intent: intentFor(scope, proposal, policy) });
};

export const providerEffectCapabilities = Object.freeze(definitions.map((definition) => definition.capability));

export function createProviderEffectPolicySuite(runtimeScope) {
  const scope = assertRuntimeScope(runtimeScope);
  return Object.freeze({
    runtimeScope: scope,
    capabilities: providerEffectCapabilities,
    policy: (capability) => policyFor(scope, capability),
    policies: () => Object.freeze(providerEffectCapabilities.map((capability) => policyFor(scope, capability))),
    assertProposal: (value) => validateProposalFor(scope, value),
    executionAvailable: false,
  });
}
