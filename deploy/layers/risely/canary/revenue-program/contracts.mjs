import {
  assertDate,
  assertEmail,
  assertExactKeys,
  assertHash,
  assertInstant,
  assertInteger,
  assertReference,
  assertSingleLineText,
  assertText,
  assertTimeZone,
  compareCodepoints,
  dateInTimeZone,
  fail,
  sha256Canonical,
  snapshotPlainJson,
} from "./validation.mjs";
import { ceoDeploymentProfile } from "../deployment-profiles/index.mjs";
import { assertProfileAuthority, hashProfileData } from "../deployment-profiles/profile-contract/index.mjs";

export const revenueProgramPolicy = Object.freeze({
  version: "revenue-program.v1",
  emailDailyMinimum: 100,
  emailDailyMaximum: 200,
  linkedinDailyTarget: 20,
  inboxDailyMaximum: 50,
  maximumInboxes: 4,
  maximumCandidates: 2_000,
  maximumSourceRecords: 2_000,
  maximumProgramProposals: 512,
  staleDealDailyMaximum: 50,
  linkedinDmDailyMaximum: 50,
  demoDailyMaximum: 50,
  notionArtifactDailyMaximum: 20,
  demoReminderLeadMilliseconds: 72 * 60 * 60 * 1_000,
  demoReminderWindowMilliseconds: 24 * 60 * 60 * 1_000,
  approvalLifetimeMilliseconds: 24 * 60 * 60 * 1_000,
});

export const candidateAccountPolicy = Object.freeze({
  duplicateAccounts: "allowed_for_distinct_contacts",
  duplicateProfiles: "rejected",
  maximumContactsPerAccount: 8,
});

const revenueContractSuites = new WeakSet();
const normalizedRevenueAuthorities = new WeakMap();

const providerOwnerRef = (profile, provider) =>
  profile.providerOwners.find((entry) => entry.provider === provider)?.providerOwnerRef;

const connectionAnchor = (profile, provider) => {
  const ownerRef = providerOwnerRef(profile, provider);
  if (!ownerRef) fail("unsupported_revenue_profile");
  return `connection-anchor:${provider}:${hashProfileData({ profileRef: profile.profileRef, profileSha256: profile.profileSha256, provider, providerOwnerRef: ownerRef })}`;
};

const revenueAuthority = (value) => {
  const profile = assertProfileAuthority(value);
  const requiredCapabilities = [
    "google.gmail.drafts.create",
    "demo_repository.read",
    "linkedin.connection_propose",
    "linkedin.dm_propose",
    "notion.artifact_propose",
    "sales.outreach_propose",
    "slack.surface_compile",
  ];
  const requiredProviders = [
    "apollo",
    "clarify",
    "command_center_brain",
    "demo_repository",
    "gmail",
    "google",
    "linkedin",
    "notion",
    "posthog",
    "rb2b",
    "slack",
  ];
  if (
    requiredCapabilities.some((capability) => !profile.allowedCapabilities.includes(capability)) ||
    requiredProviders.some((provider) => !profile.providerOwners.some((entry) => entry.provider === provider)) ||
    profile.providerExecutionAllowed !== false
  ) {
    fail("unsupported_revenue_profile");
  }
  return Object.freeze({
    profile,
    principalBindingAnchor: Object.freeze({
      deploymentRef: profile.anchors.deploymentRef,
      anchorRef: profile.anchors.principalBindingRef,
      tenantRef: profile.anchors.tenantRef,
      workspaceRef: profile.anchors.workspaceRef,
      principalRef: profile.identity.humanPrincipalRef,
      principalEmail: profile.identity.humanEmail,
      credentialOwnerRef: profile.identity.credentialOwnerRef,
    }),
    connectionAnchors: Object.freeze({
      apolloAccountRef: connectionAnchor(profile, "apollo"),
      googleAccountRef: connectionAnchor(profile, "google"),
      notionRootRef: profile.audiences.notion.parentRef,
      clarifyAccountRef: connectionAnchor(profile, "clarify"),
      brainServerRef: connectionAnchor(profile, "command_center_brain"),
      linkedinAccountRef: connectionAnchor(profile, "linkedin"),
      rb2bAccountRef: connectionAnchor(profile, "rb2b"),
      posthogAccountRef: connectionAnchor(profile, "posthog"),
      demoRepositoryRef: connectionAnchor(profile, "demo_repository"),
    }),
    connectionOwnerRefs: Object.freeze({
      apolloAccountRef: providerOwnerRef(profile, "apollo"),
      googleAccountRef: providerOwnerRef(profile, "google"),
      notionRootRef: providerOwnerRef(profile, "notion"),
      clarifyAccountRef: providerOwnerRef(profile, "clarify"),
      brainServerRef: providerOwnerRef(profile, "command_center_brain"),
      linkedinAccountRef: providerOwnerRef(profile, "linkedin"),
      rb2bAccountRef: providerOwnerRef(profile, "rb2b"),
      posthogAccountRef: providerOwnerRef(profile, "posthog"),
      demoRepositoryRef: providerOwnerRef(profile, "demo_repository"),
      workspaceRef: providerOwnerRef(profile, "slack"),
    }),
    slackAudience: Object.freeze({
      teamRef: profile.anchors.slackTeamRef,
      userRef: profile.audiences.slack.principalRef,
      audienceRef: profile.audiences.slack.audienceRef,
    }),
    notionAudience: profile.audiences.notion.scope,
    voiceProfileRef: `voice-profile:${hashProfileData({ profileRef: profile.profileRef, profileSha256: profile.profileSha256 })}`,
  });
};

const ceoRevenueAuthority = revenueAuthority(ceoDeploymentProfile);
export const deploymentPrincipalBindingAnchor = ceoRevenueAuthority.principalBindingAnchor;
export const deploymentConnectionAnchors = ceoRevenueAuthority.connectionAnchors;
export const deploymentSlackAudience = ceoRevenueAuthority.slackAudience;

export const slackActionRegistry = Object.freeze(["approve_proposal", "reject_proposal", "request_changes"]);

export const proposalPresentationLabels = Object.freeze({
  "demo.customization_review": "Demo review",
  "gmail.cold_email_draft": "Cold email draft",
  "gmail.stale_deal_followup_draft": "Stale deal draft",
  "linkedin.connection_request": "LinkedIn connection proposal",
  "linkedin.dm_draft": "LinkedIn DM draft",
  "notion.revenue_artifact": "Private Notion artifact",
  "slack.demo_reminder": "Demo reminder",
});

export const brainReadTools = Object.freeze([
  "brain_analytics_targetable_deployments",
  "brain_as_of",
  "brain_episodes_about",
  "brain_open_commitments_for_account",
  "brain_open_risks_for_account",
  "brain_person_context",
  "brain_project_status",
  "brain_search",
  "brain_slipped_initiatives",
  "brain_what_changed_since",
  "brain_who_owns",
]);

export const brainToolFactFields = Object.freeze(
  Object.fromEntries(brainReadTools.map((tool) => [tool, "result_state"])),
);

export const brainToolSubjectRefs = Object.freeze({
  brain_analytics_targetable_deployments: "deployment:portfolio",
  brain_as_of: "portfolio:revenue",
  brain_episodes_about: "account:portfolio",
  brain_open_commitments_for_account: "account:portfolio",
  brain_open_risks_for_account: "account:portfolio",
  brain_person_context: "person:ceo",
  brain_project_status: "project:revenue",
  brain_search: "query:revenue",
  brain_slipped_initiatives: "portfolio:revenue",
  brain_what_changed_since: "portfolio:revenue",
  brain_who_owns: "account:portfolio",
});

export const revenueSourceNames = Object.freeze([
  "apollo",
  "calendar",
  "clarify",
  "command_center_brain",
  "gmail",
  "google_analytics",
  "linkedin",
  "notion",
  "posthog",
  "rb2b",
  "transcripts",
]);

export const providerFactSchemas = Object.freeze({
  apollo: Object.freeze([
    "account_domain",
    "account_ref",
    "contact_email",
    "content_basis",
    "email_body_hash",
    "email_subject_hash",
    "linkedin_profile_ref",
    "sequence_ref",
  ]),
  calendar: Object.freeze([
    "account_ref",
    "cancelled_at",
    "change_status",
    "event_version",
    "meeting_ref",
    "occurrence_ref",
    "original_start_at",
    "moved_from_start_at",
    "previous_event_version",
    "previous_schedule_revision",
    "previous_start_at",
    "schedule_revision",
    "start_at",
    "status",
  ]),
  clarify: Object.freeze([
    "account_ref",
    "contact_email",
    "content_basis",
    "deal_ref",
    "draft_body_hash",
    "draft_subject_hash",
    "last_verified_touch_at",
    "stage",
  ]),
  gmail: Object.freeze(["capability", "credential_owner_ref", "mailbox_email", "provider_account_ref"]),
  google_analytics: Object.freeze(["account_domain", "account_ref", "confidence", "intent_signal", "observed_at"]),
  linkedin: Object.freeze(["acceptance_ref", "accepted_at", "account_ref", "linkedin_profile_ref"]),
  notion: Object.freeze([
    "audience",
    "content_basis",
    "dm_body_hash",
    "linkedin_profile_ref",
    "root_ref",
    "voice_profile_ref",
  ]),
  posthog: Object.freeze(["account_domain", "account_ref", "confidence", "intent_signal", "observed_at"]),
  rb2b: Object.freeze(["account_domain", "account_ref", "confidence", "intent_signal", "observed_at"]),
  transcripts: Object.freeze([
    "artifact_body_hash",
    "artifact_ref",
    "artifact_title_hash",
    "content_summary",
    "finalized_at",
    "transcript_ended_at",
  ]),
});

export const sourceSemanticPolicies = Object.freeze({
  apollo: Object.freeze(["candidate"]),
  calendar: Object.freeze(["meeting"]),
  clarify: Object.freeze(["deal"]),
  command_center_brain: Object.freeze([]),
  gmail: Object.freeze([]),
  google_analytics: Object.freeze(["visitor_account"]),
  linkedin: Object.freeze(["acceptance"]),
  notion: Object.freeze(["acceptance"]),
  posthog: Object.freeze(["visitor_account"]),
  rb2b: Object.freeze(["visitor_account"]),
  transcripts: Object.freeze(["artifact"]),
});

export const proposedEffectTypes = Object.freeze([
  "demo.customization_review",
  "gmail.cold_email_draft",
  "gmail.stale_deal_followup_draft",
  "linkedin.connection_request",
  "linkedin.dm_draft",
  "notion.revenue_artifact",
  "slack.demo_reminder",
]);

export const requiredEvaluationGates = Object.freeze([
  "quality",
  "voice_accuracy",
  "research_depth",
  "source_integrity",
  "recipient_safety",
  "suppression",
  "rate_limit",
  "ownership",
]);

const sourceKeys = new Set(["source", "status", "checkedAt", "binding", "evidenceHash", "unavailableCode", "records"]);
const sourceBindingKeys = new Set([
  "deploymentRef",
  "anchorRef",
  "tenantRef",
  "workspaceRef",
  "principalRef",
  "credentialOwnerRef",
  "accountRef",
  "rootRef",
]);
const sourceRecordKeys = new Set(["recordRef", "observedAt", "evidenceHash", "facts"]);
const factKeys = new Set(["field", "value", "citationRef"]);
const domainPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const fixedProviderFactValues = (authority) =>
  Object.freeze({
    apollo: Object.freeze({ content_basis: "verified_prospect_profile" }),
    clarify: Object.freeze({ content_basis: "verified_crm_timeline" }),
    gmail: Object.freeze({
      capability: "draft_proposal_only",
      mailbox_email: authority.principalBindingAnchor.principalEmail,
    }),
    google_analytics: Object.freeze({ intent_signal: "account_page_view" }),
    notion: Object.freeze({
      audience: authority.notionAudience,
      content_basis: "approved_ceo_voice",
      voice_profile_ref: authority.voiceProfileRef,
    }),
    posthog: Object.freeze({ intent_signal: "anonymous_product_event" }),
    rb2b: Object.freeze({ intent_signal: "account_domain_match" }),
  });

const canonicalReferenceFacts = (facts) =>
  facts
    .map((fact) => Object.freeze({ field: fact.field, value: fact.value }))
    .sort((left, right) => compareCodepoints(left.field, right.field));

export const providerRecordReference = ({ providerAccountRef, rootRef, source, observedAt, facts }) =>
  `source-record:${sha256Canonical({
    providerAccountRef,
    rootRef,
    source,
    observedAt,
    facts: canonicalReferenceFacts(facts),
  })}`;

export const providerCitationReference = ({ providerAccountRef, source, recordRef, field }) =>
  `source-citation:${sha256Canonical({ providerAccountRef, source, recordRef, field })}`;

export const brainQueryReference = ({ providerAccountRef, tool, subjectRef, asOf }) =>
  `brain-query:${sha256Canonical({ providerAccountRef, tool, subjectRef, asOf })}`;

export const providerCorrelationReference = ({
  providerAccountRef,
  source,
  sourceRecordRef,
  subjectType,
  subjectRef,
}) => `correlation:${sha256Canonical({ providerAccountRef, source, sourceRecordRef, subjectType, subjectRef })}`;

const normalizeFact = (value) => {
  assertExactKeys(value, factKeys, "invalid_source_fact");
  return Object.freeze({
    field: assertReference(value.field, "invalid_source_fact"),
    value: assertText(value.value, 4_096, "invalid_source_fact"),
    citationRef: assertReference(value.citationRef, "invalid_source_fact"),
  });
};

const assertFactValue = (field, value, code) => {
  if (field === "account_domain") {
    if (!domainPattern.test(value)) fail(code);
    return;
  }
  if (field === "contact_email") {
    assertEmail(value, code);
    return;
  }
  if (field === "mailbox_email") {
    assertEmail(value, code);
    return;
  }
  if (
    new Set([
      "accepted_at",
      "as_of",
      "finalized_at",
      "last_verified_touch_at",
      "observed_at",
      "original_start_at",
      "previous_start_at",
      "start_at",
      "transcript_ended_at",
    ]).has(field)
  ) {
    assertInstant(value, code);
    return;
  }
  if (new Set(["cancelled_at", "moved_from_start_at"]).has(field)) {
    if (value !== "none") assertInstant(value, code);
    return;
  }
  if (
    new Set(["event_version", "previous_event_version", "previous_schedule_revision", "schedule_revision"]).has(field)
  ) {
    assertInteger(Number(value), 1, 1_000_000, code);
    if (String(Number(value)) !== value) fail(code);
    return;
  }
  if (field === "confidence") {
    if (!new Set(["low", "medium", "high"]).has(value)) fail(code);
    return;
  }
  if (field === "content_summary") {
    assertText(value, 4_096, code);
    return;
  }
  if (field.endsWith("_hash")) {
    assertHash(value, code);
    return;
  }
  if (field === "result_state") {
    if (value !== "opaque_unresolved") fail(code);
    return;
  }
  assertReference(value, code);
};

const normalizeSourceRecord = (value, now, checkedAt, expectedSource, expectedBinding) => {
  assertExactKeys(value, sourceRecordKeys, "invalid_source_record");
  const observedAt = assertInstant(value.observedAt, "invalid_source_record");
  if (observedAt > now || observedAt > checkedAt) fail("future_source_record");
  if (!Array.isArray(value.facts) || value.facts.length < 1 || value.facts.length > 64) fail("invalid_source_record");
  const facts = value.facts
    .map(normalizeFact)
    .sort(
      (left, right) =>
        compareCodepoints(left.field, right.field) || compareCodepoints(left.citationRef, right.citationRef),
    );
  const factIdentities = facts.map((fact) => `${fact.field}\u0000${fact.citationRef}`);
  if (new Set(factIdentities).size !== factIdentities.length) fail("duplicate_source_fact");
  const expectedFields = providerFactSchemas[expectedSource];
  if (expectedFields) {
    const actualFields = facts.map((fact) => fact.field).sort(compareCodepoints);
    const requiredFields = [...expectedFields].sort(compareCodepoints);
    if (
      actualFields.length !== requiredFields.length ||
      actualFields.some((field, index) => field !== requiredFields[index])
    )
      fail("invalid_provider_fact_schema");
  }
  for (const fact of facts) assertFactValue(fact.field, fact.value, "invalid_provider_fact_value");
  const recordRef = providerRecordReference({
    providerAccountRef: expectedBinding.accountRef,
    rootRef: expectedBinding.rootRef,
    source: expectedSource,
    observedAt: observedAt.toISOString(),
    facts,
  });
  if (
    value.recordRef !== recordRef ||
    facts.some(
      (fact) =>
        fact.citationRef !==
        providerCitationReference({
          providerAccountRef: expectedBinding.accountRef,
          source: expectedSource,
          recordRef,
          field: fact.field,
        }),
    )
  )
    fail("unqualified_source_reference");
  return Object.freeze({
    recordRef,
    observedAt: observedAt.toISOString(),
    evidenceHash: assertHash(value.evidenceHash, "invalid_source_record"),
    facts: Object.freeze(facts),
  });
};

const normalizeSourceBinding = (value, expected) => {
  assertExactKeys(value, sourceBindingKeys, "invalid_source_binding");
  const binding = Object.freeze({
    deploymentRef: assertReference(value.deploymentRef, "invalid_source_binding"),
    anchorRef: assertReference(value.anchorRef, "invalid_source_binding"),
    tenantRef: assertReference(value.tenantRef, "invalid_source_binding"),
    workspaceRef: assertReference(value.workspaceRef, "invalid_source_binding"),
    principalRef: assertReference(value.principalRef, "invalid_source_binding"),
    credentialOwnerRef: assertReference(value.credentialOwnerRef, "invalid_source_binding"),
    accountRef: assertReference(value.accountRef, "invalid_source_binding"),
    rootRef: assertReference(value.rootRef, "invalid_source_binding"),
  });
  if (Object.keys(binding).some((key) => binding[key] !== expected[key])) fail("source_binding_mismatch");
  return binding;
};

const normalizeSourceSnapshotForAuthority = (value, expectedSource, now, expectedBinding, authority) => {
  assertExactKeys(value, sourceKeys, "invalid_source_snapshot");
  if (value.source !== expectedSource || !revenueSourceNames.includes(expectedSource)) fail("invalid_source_snapshot");
  if (!new Set(["available", "none", "unavailable"]).has(value.status)) fail("invalid_source_status");
  const checkedAt = assertInstant(value.checkedAt, "invalid_source_snapshot");
  if (checkedAt > now || now.valueOf() - checkedAt.valueOf() > 86_400_000) fail("stale_source_snapshot");
  if (!Array.isArray(value.records) || value.records.length > revenueProgramPolicy.maximumSourceRecords)
    fail("invalid_source_snapshot");
  const available = value.status === "available";
  const unavailable = value.status === "unavailable";
  if (
    (available && value.records.length === 0) ||
    (!available && value.records.length !== 0) ||
    (available && (value.evidenceHash === null || value.unavailableCode !== null)) ||
    (!available && value.evidenceHash !== null) ||
    (value.status === "none" && value.unavailableCode !== null) ||
    (unavailable && typeof value.unavailableCode !== "string")
  )
    fail("invalid_source_semantics");
  const binding = normalizeSourceBinding(value.binding, expectedBinding);
  const records = value.records
    .map((record) => normalizeSourceRecord(record, now, checkedAt, expectedSource, binding))
    .sort((left, right) => compareCodepoints(left.recordRef, right.recordRef));
  if (new Set(records.map((record) => record.recordRef)).size !== records.length) fail("duplicate_source_record");
  for (const record of records) {
    const facts = new Map(record.facts.map((fact) => [fact.field, fact.value]));
    if (
      Object.entries(fixedProviderFactValues(authority)[expectedSource] ?? {}).some(
        ([field, expected]) => facts.get(field) !== expected,
      )
    )
      fail("provider_fact_constant_mismatch");
    if (
      (expectedSource === "gmail" &&
        (facts.get("provider_account_ref") !== expectedBinding.accountRef ||
          facts.get("credential_owner_ref") !== expectedBinding.credentialOwnerRef)) ||
      (expectedSource === "notion" &&
        (facts.get("root_ref") !== expectedBinding.rootRef || facts.get("audience") !== authority.notionAudience))
    )
      fail("provider_fact_binding_mismatch");
    if (expectedSource === "transcripts") {
      const endedAt = assertInstant(facts.get("transcript_ended_at"), "invalid_transcript_chronology");
      const finalizedAt = assertInstant(facts.get("finalized_at"), "invalid_transcript_chronology");
      const observedAt = new Date(record.observedAt);
      if (endedAt > finalizedAt || finalizedAt > observedAt || finalizedAt > now) fail("invalid_transcript_chronology");
    }
  }
  return Object.freeze({
    source: expectedSource,
    status: value.status,
    checkedAt: checkedAt.toISOString(),
    binding,
    evidenceHash: available ? assertHash(value.evidenceHash, "invalid_source_snapshot") : null,
    unavailableCode: unavailable ? assertReference(value.unavailableCode, "invalid_source_snapshot") : null,
    records: Object.freeze(records),
  });
};

export const normalizeSourceSnapshot = (value, expectedSource, now, expectedBinding) =>
  normalizeSourceSnapshotForAuthority(value, expectedSource, now, expectedBinding, ceoRevenueAuthority);

const brainSnapshotKeys = new Set(["tool", "queryRef", "query", "snapshot"]);
const brainQueryKeys = new Set(["tool", "subjectRef", "asOf"]);

const normalizeBrainSnapshots = (values, now, binding) => {
  if (!Array.isArray(values) || values.length !== brainReadTools.length) fail("invalid_brain_context");
  const snapshots = values
    .map((value) => {
      assertExactKeys(value, brainSnapshotKeys, "invalid_brain_context");
      if (!brainReadTools.includes(value.tool)) fail("invalid_brain_tool");
      assertExactKeys(value.query, brainQueryKeys, "invalid_brain_query");
      if (
        value.query.tool !== value.tool ||
        value.query.subjectRef !== brainToolSubjectRefs[value.tool] ||
        assertInstant(value.query.asOf, "invalid_brain_query") > now
      )
        fail("invalid_brain_query");
      const snapshot = normalizeSourceSnapshot(value.snapshot, "command_center_brain", now, {
        deploymentRef: binding.deploymentRef,
        anchorRef: binding.anchorRef,
        tenantRef: binding.tenantRef,
        workspaceRef: binding.workspaceRef,
        principalRef: binding.principalRef,
        credentialOwnerRef: binding.credentialOwnerRef,
        accountRef: binding.brainServerRef,
        rootRef: value.tool,
      });
      if (value.query.asOf !== snapshot.checkedAt) fail("invalid_brain_as_of");
      const queryRef = brainQueryReference({
        providerAccountRef: binding.brainServerRef,
        tool: value.tool,
        subjectRef: value.query.subjectRef,
        asOf: value.query.asOf,
      });
      if (value.queryRef !== queryRef) fail("unqualified_brain_query_reference");
      if (snapshot.status === "available") {
        const expectedFields = ["as_of", brainToolFactFields[value.tool], "subject_ref"].sort(compareCodepoints);
        if (
          snapshot.records.some((record) => {
            const fields = record.facts.map((fact) => fact.field).sort(compareCodepoints);
            const facts = new Map(record.facts.map((fact) => [fact.field, fact.value]));
            return (
              fields.length !== expectedFields.length ||
              fields.some((field, index) => field !== expectedFields[index]) ||
              facts.get("subject_ref") !== value.query.subjectRef ||
              facts.get("as_of") !== value.query.asOf ||
              facts.get(brainToolFactFields[value.tool]) !== "opaque_unresolved"
            );
          })
        )
          fail("invalid_brain_response_shape");
      }
      return Object.freeze({
        tool: value.tool,
        queryRef,
        query: Object.freeze({
          tool: value.tool,
          subjectRef: assertReference(value.query.subjectRef, "invalid_brain_query"),
          asOf: value.query.asOf,
        }),
        snapshot,
      });
    })
    .sort((left, right) => compareCodepoints(left.tool, right.tool));
  if (new Set(snapshots.map((snapshot) => snapshot.tool)).size !== brainReadTools.length) fail("duplicate_brain_tool");
  if (new Set(snapshots.map((snapshot) => snapshot.queryRef)).size !== brainReadTools.length)
    fail("duplicate_brain_query");
  const recordRefs = snapshots.flatMap((entry) => entry.snapshot.records.map((record) => record.recordRef));
  const citationRefs = snapshots.flatMap((entry) =>
    entry.snapshot.records.flatMap((record) => record.facts.map((fact) => fact.citationRef)),
  );
  if (new Set(recordRefs).size !== recordRefs.length || new Set(citationRefs).size !== citationRefs.length)
    fail("duplicate_brain_response_reference");
  return Object.freeze(snapshots);
};

const principalKeys = new Set(["principalRef", "email"]);
const bindingKeys = new Set([
  "deploymentRef",
  "anchorRef",
  "tenantRef",
  "workspaceRef",
  "principalRef",
  "principalEmail",
  "credentialOwnerRef",
  "apolloAccountRef",
  "googleAccountRef",
  "notionRootRef",
  "clarifyAccountRef",
  "brainServerRef",
  "linkedinAccountRef",
  "rb2bAccountRef",
  "posthogAccountRef",
  "demoRepositoryRef",
]);
const inboxKeys = new Set(["inboxRef", "ownerEmail"]);
const ledgerKeys = new Set([
  "entryRef",
  "idempotencyKey",
  "deploymentRef",
  "anchorRef",
  "tenantRef",
  "workspaceRef",
  "principalRef",
  "credentialOwnerRef",
  "goalDate",
  "channel",
  "state",
  "subjectRef",
  "recipient",
  "providerAccountRef",
  "inboxRef",
  "createdAt",
]);
const ledgerRecipientKeys = new Set(["kind", "value", "eventVersion", "scheduleRevision", "startAt"]);
const suppressionKeys = new Set([
  "entryRef",
  "tenantRef",
  "workspaceRef",
  "principalRef",
  "channel",
  "subjectRef",
  "stableRecipientIdentity",
  "reason",
  "effectiveAt",
  "evidenceHash",
]);
const candidateKeys = new Set([
  "candidateRef",
  "accountRef",
  "accountDomain",
  "contactEmail",
  "linkedinProfileRef",
  "ownerPrincipalRef",
  "inboxRef",
  "priorityScore",
  "researchEvidenceHashes",
  "sequenceRef",
  "emailSubject",
  "emailBody",
]);
const intentKeys = new Set(["intentRef", "accountRef", "accountDomain", "identityScope", "observations"]);
const intentObservationKeys = new Set([
  "source",
  "sourceRecordRef",
  "evidenceHash",
  "observedAt",
  "confidence",
  "identityScope",
]);
const staleDealKeys = new Set([
  "dealRef",
  "accountRef",
  "ownerPrincipalRef",
  "recipientEmail",
  "stage",
  "lastVerifiedTouchAt",
  "lastVerifiedTouchCitation",
  "evidenceHashes",
  "draftSubject",
  "draftBody",
]);
const touchCitationKeys = new Set(["source", "sourceRecordRef", "evidenceHash", "occurredAt"]);
const acceptanceKeys = new Set([
  "acceptanceRef",
  "candidateRef",
  "ownerPrincipalRef",
  "acceptedAt",
  "evidenceHash",
  "dmBody",
  "voiceEvidenceHash",
]);
const meetingKeys = new Set([
  "meetingRef",
  "accountRef",
  "ownerPrincipalRef",
  "startAt",
  "originalStartAt",
  "previousStartAt",
  "movedFromStartAt",
  "status",
  "eventVersion",
  "scheduleRevision",
  "previousEventVersion",
  "previousScheduleRevision",
  "changeStatus",
  "recurringEventRef",
  "cancelledAt",
  "segment",
  "stage",
  "repositoryRef",
  "customizationEvidenceHash",
  "calendarEvidenceHash",
]);
const artifactKeys = new Set([
  "artifactRef",
  "rootRef",
  "audience",
  "title",
  "body",
  "contentSummary",
  "transcriptSourceRecordRef",
  "transcriptEndedAt",
  "transcriptFinalizedAt",
  "evidenceHashes",
]);
const correlationKeys = new Set([
  "correlationRef",
  "deploymentRef",
  "anchorRef",
  "tenantRef",
  "workspaceRef",
  "principalRef",
  "credentialOwnerRef",
  "providerAccountRef",
  "source",
  "sourceRecordRef",
  "subjectType",
  "subjectRef",
  "accountRef",
  "contactRef",
  "meetingOccurrenceRef",
  "evidenceHash",
  "factCitationRefs",
]);
const inputKeys = new Set([
  "version",
  "programRef",
  "programRevision",
  "goalDate",
  "timeZone",
  "now",
  "principal",
  "binding",
  "inboxes",
  "ledger",
  "suppressions",
  "brain",
  "sources",
  "candidates",
  "visitorIntent",
  "staleDeals",
  "linkedinAcceptances",
  "meetings",
  "notionArtifacts",
  "correlations",
]);

const normalizeHashes = (values, maximum, code) => {
  if (!Array.isArray(values) || values.length < 1 || values.length > maximum) fail(code);
  const hashes = values.map((value) => assertHash(value, code)).sort(compareCodepoints);
  if (new Set(hashes).size !== hashes.length) fail(code);
  return Object.freeze(hashes);
};

const normalizePrincipal = (value, authority) => {
  assertExactKeys(value, principalKeys, "invalid_principal");
  const principal = Object.freeze({
    principalRef: assertReference(value.principalRef, "invalid_principal"),
    email: assertEmail(value.email, "invalid_principal"),
  });
  if (
    principal.principalRef !== authority.principalBindingAnchor.principalRef ||
    principal.email !== authority.principalBindingAnchor.principalEmail
  )
    fail("untrusted_principal_mailbox");
  return principal;
};

const normalizeBinding = (value, principal, authority) => {
  assertExactKeys(value, bindingKeys, "invalid_binding");
  const binding = Object.freeze({
    deploymentRef: assertReference(value.deploymentRef, "invalid_binding"),
    anchorRef: assertReference(value.anchorRef, "invalid_binding"),
    tenantRef: assertReference(value.tenantRef, "invalid_binding"),
    workspaceRef: assertReference(value.workspaceRef, "invalid_binding"),
    principalRef: assertReference(value.principalRef, "invalid_binding"),
    principalEmail: assertEmail(value.principalEmail, "invalid_binding"),
    credentialOwnerRef: assertReference(value.credentialOwnerRef, "invalid_binding"),
    apolloAccountRef: assertReference(value.apolloAccountRef, "invalid_binding"),
    googleAccountRef: assertReference(value.googleAccountRef, "invalid_binding"),
    notionRootRef: assertReference(value.notionRootRef, "invalid_binding"),
    clarifyAccountRef: assertReference(value.clarifyAccountRef, "invalid_binding"),
    brainServerRef: assertReference(value.brainServerRef, "invalid_binding"),
    linkedinAccountRef: assertReference(value.linkedinAccountRef, "invalid_binding"),
    rb2bAccountRef: assertReference(value.rb2bAccountRef, "invalid_binding"),
    posthogAccountRef: assertReference(value.posthogAccountRef, "invalid_binding"),
    demoRepositoryRef: assertReference(value.demoRepositoryRef, "invalid_binding"),
  });
  if (binding.principalRef !== principal.principalRef) fail("principal_binding_mismatch");
  for (const [key, expected] of Object.entries(authority.principalBindingAnchor)) {
    if (binding[key] !== expected) fail("deployment_principal_binding_mismatch");
  }
  for (const [key, expected] of Object.entries(authority.connectionAnchors)) {
    if (binding[key] !== expected) fail("caller_selected_connection_binding");
  }
  return binding;
};

const normalizeInboxes = (values, principal, authority) => {
  if (!Array.isArray(values) || values.length < 1 || values.length > revenueProgramPolicy.maximumInboxes)
    fail("invalid_inboxes");
  const inboxes = values
    .map((value) => {
      assertExactKeys(value, inboxKeys, "invalid_inbox");
      const ownerEmail = assertEmail(value.ownerEmail, "invalid_inbox");
      if (ownerEmail !== authority.principalBindingAnchor.principalEmail || ownerEmail !== principal.email)
        fail("inbox_owner_mismatch");
      return Object.freeze({ inboxRef: assertReference(value.inboxRef, "invalid_inbox"), ownerEmail });
    })
    .sort((left, right) => compareCodepoints(left.inboxRef, right.inboxRef));
  if (new Set(inboxes.map((inbox) => inbox.inboxRef)).size !== inboxes.length) fail("duplicate_inbox");
  return Object.freeze(inboxes);
};

const normalizeLedger = (values, input, identityIndex, meetings) => {
  if (!Array.isArray(values) || values.length > 5_000) fail("invalid_ledger");
  const inboxRefs = new Set(input.inboxes.map((inbox) => inbox.inboxRef));
  const ledger = values
    .map((value) => {
      assertExactKeys(value, ledgerKeys, "invalid_ledger_entry");
      if (
        !new Set([
          "cold_email",
          "stale_email",
          "linkedin_connection",
          "linkedin_dm",
          "demo_reminder",
          "demo_customization",
          "notion_artifact",
        ]).has(value.channel)
      )
        fail("invalid_ledger_entry");
      if (!new Set(["reserved", "proposed", "approved", "executed", "cancelled"]).has(value.state))
        fail("invalid_ledger_entry");
      const createdAt = assertInstant(value.createdAt, "invalid_ledger_entry");
      if (
        createdAt > input.now ||
        input.now.valueOf() - createdAt.valueOf() > 86_400_000 ||
        dateInTimeZone(createdAt, input.timeZone) !== input.goalDate
      )
        fail("invalid_ledger_local_day");
      if (
        value.tenantRef !== input.binding.tenantRef ||
        value.deploymentRef !== input.binding.deploymentRef ||
        value.anchorRef !== input.binding.anchorRef ||
        value.workspaceRef !== input.binding.workspaceRef ||
        value.principalRef !== input.binding.principalRef ||
        value.credentialOwnerRef !== input.binding.credentialOwnerRef ||
        value.goalDate !== input.goalDate
      )
        fail("ledger_binding_mismatch");
      const inboxRef = value.inboxRef === null ? null : assertReference(value.inboxRef, "invalid_ledger_entry");
      if (
        new Set(["cold_email", "stale_email"]).has(value.channel) !== (inboxRef !== null) ||
        (inboxRef !== null && !inboxRefs.has(inboxRef))
      )
        fail("ledger_inbox_mismatch");
      const providerAccountByChannel = {
        cold_email: input.binding.googleAccountRef,
        stale_email: input.binding.googleAccountRef,
        linkedin_connection: input.binding.linkedinAccountRef,
        linkedin_dm: input.binding.linkedinAccountRef,
        demo_reminder: input.binding.workspaceRef,
        demo_customization: input.binding.demoRepositoryRef,
        notion_artifact: input.binding.notionRootRef,
      };
      if (value.providerAccountRef !== providerAccountByChannel[value.channel]) fail("ledger_provider_mismatch");
      assertExactKeys(value.recipient, ledgerRecipientKeys, "invalid_ledger_recipient");
      const kindByChannel = {
        cold_email: "email",
        stale_email: "email",
        linkedin_connection: "linkedin_profile",
        linkedin_dm: "linkedin_profile",
        demo_reminder: "meeting_occurrence",
        demo_customization: "meeting_occurrence",
      };
      const allowedKind =
        value.channel === "notion_artifact"
          ? new Set(["artifact", "account_domain"])
          : new Set([kindByChannel[value.channel]]);
      if (!allowedKind.has(value.recipient.kind)) fail("ledger_recipient_kind_mismatch");
      let canonicalValue;
      let eventVersion = null;
      let scheduleRevision = null;
      let recipientStartAt = null;
      if (value.recipient.kind === "email")
        canonicalValue = assertEmail(value.recipient.value, "invalid_ledger_recipient");
      else if (value.recipient.kind === "linkedin_profile")
        canonicalValue = assertReference(value.recipient.value, "invalid_ledger_recipient").toLowerCase();
      else if (value.recipient.kind === "account_domain") {
        if (typeof value.recipient.value !== "string" || !domainPattern.test(value.recipient.value))
          fail("invalid_ledger_recipient");
        canonicalValue = value.recipient.value;
      } else canonicalValue = assertReference(value.recipient.value, "invalid_ledger_recipient");
      if (value.recipient.kind === "meeting_occurrence") {
        eventVersion = assertInteger(value.recipient.eventVersion, 1, 1_000_000, "invalid_ledger_recipient");
        scheduleRevision = assertInteger(value.recipient.scheduleRevision, 1, 1_000_000, "invalid_ledger_recipient");
        recipientStartAt = assertInstant(value.recipient.startAt, "invalid_ledger_recipient").toISOString();
      } else if (
        value.recipient.eventVersion !== null ||
        value.recipient.scheduleRevision !== null ||
        value.recipient.startAt !== null
      ) {
        fail("invalid_ledger_recipient");
      }
      const stableRecipientIdentity =
        value.recipient.kind === "email"
          ? `email:${sha256Canonical(canonicalValue)}`
          : value.recipient.kind === "linkedin_profile"
            ? `linkedin:${sha256Canonical(canonicalValue)}`
            : value.recipient.kind === "meeting_occurrence"
              ? `meeting:${sha256Canonical({ occurrenceRef: canonicalValue, eventVersion, scheduleRevision })}`
              : value.recipient.kind === "account_domain"
                ? `account-domain:${sha256Canonical(canonicalValue)}`
                : `artifact:${sha256Canonical(canonicalValue)}`;
      const subjectRef = assertReference(value.subjectRef, "invalid_ledger_entry");
      const expectedSubject = identityIndex.get(`${value.channel}\u0000${subjectRef}`);
      const historicalMeeting = meetings.find((meeting) => meeting.occurrenceRef === canonicalValue);
      const historicalSubjectRef = `meeting-schedule:${sha256Canonical({
        occurrenceRef: canonicalValue,
        eventVersion,
        scheduleRevision,
        startAt: recipientStartAt,
      })}`;
      const validHistoricalMeeting =
        new Set(["demo_reminder", "demo_customization"]).has(value.channel) &&
        value.recipient.kind === "meeting_occurrence" &&
        historicalMeeting &&
        subjectRef === historicalSubjectRef &&
        eventVersion <= historicalMeeting.eventVersion &&
        scheduleRevision <= historicalMeeting.scheduleRevision;
      if (new Set(["demo_reminder", "demo_customization"]).has(value.channel) && subjectRef !== historicalSubjectRef)
        fail("ledger_recipient_subject_mismatch");
      if (
        (expectedSubject?.stableRecipientIdentity !== stableRecipientIdentity ||
          (expectedSubject.inboxRef !== null && expectedSubject.inboxRef !== inboxRef)) &&
        !validHistoricalMeeting
      )
        fail("ledger_recipient_subject_mismatch");
      return Object.freeze({
        entryRef: assertReference(value.entryRef, "invalid_ledger_entry"),
        idempotencyKey: assertHash(value.idempotencyKey, "invalid_ledger_entry"),
        deploymentRef: value.deploymentRef,
        anchorRef: value.anchorRef,
        tenantRef: value.tenantRef,
        workspaceRef: value.workspaceRef,
        principalRef: value.principalRef,
        credentialOwnerRef: value.credentialOwnerRef,
        goalDate: value.goalDate,
        channel: value.channel,
        state: value.state,
        subjectRef,
        recipient: Object.freeze({
          kind: value.recipient.kind,
          value: canonicalValue,
          eventVersion,
          scheduleRevision,
          startAt: recipientStartAt,
        }),
        stableRecipientIdentity,
        providerAccountRef: assertReference(value.providerAccountRef, "invalid_ledger_entry"),
        inboxRef,
        createdAt: createdAt.toISOString(),
      });
    })
    .sort((left, right) => compareCodepoints(left.entryRef, right.entryRef));
  if (
    new Set(ledger.map((entry) => entry.entryRef)).size !== ledger.length ||
    new Set(ledger.map((entry) => entry.idempotencyKey)).size !== ledger.length
  )
    fail("duplicate_ledger_entry");
  const activeSubjects = ledger
    .filter((entry) => entry.state !== "cancelled")
    .map((entry) => `${entry.channel}\u0000${entry.subjectRef}`);
  if (new Set(activeSubjects).size !== activeSubjects.length) fail("duplicate_ledger_subject");
  const activeGmailRecipients = ledger
    .filter((entry) => entry.state !== "cancelled" && new Set(["cold_email", "stale_email"]).has(entry.channel))
    .map((entry) => entry.stableRecipientIdentity);
  if (new Set(activeGmailRecipients).size !== activeGmailRecipients.length) fail("duplicate_ledger_recipient_identity");
  return Object.freeze(ledger);
};

const normalizeSuppressions = (values, input) => {
  if (!Array.isArray(values) || values.length > 10_000) fail("invalid_suppressions");
  const suppressions = values
    .map((value) => {
      assertExactKeys(value, suppressionKeys, "invalid_suppression");
      if (!new Set(["email", "linkedin_connection", "linkedin_dm"]).has(value.channel)) fail("invalid_suppression");
      const effectiveAt = assertInstant(value.effectiveAt, "invalid_suppression");
      if (effectiveAt > input.now) fail("future_suppression");
      if (
        value.tenantRef !== input.binding.tenantRef ||
        value.workspaceRef !== input.binding.workspaceRef ||
        value.principalRef !== input.binding.principalRef
      )
        fail("suppression_binding_mismatch");
      return Object.freeze({
        entryRef: assertReference(value.entryRef, "invalid_suppression"),
        tenantRef: value.tenantRef,
        workspaceRef: value.workspaceRef,
        principalRef: value.principalRef,
        channel: value.channel,
        subjectRef: assertReference(value.subjectRef, "invalid_suppression"),
        stableRecipientIdentity: assertReference(value.stableRecipientIdentity, "invalid_suppression"),
        reason: assertReference(value.reason, "invalid_suppression"),
        effectiveAt: effectiveAt.toISOString(),
        evidenceHash: assertHash(value.evidenceHash, "invalid_suppression"),
      });
    })
    .sort((left, right) => compareCodepoints(left.entryRef, right.entryRef));
  if (new Set(suppressions.map((entry) => entry.entryRef)).size !== suppressions.length) fail("duplicate_suppression");
  return Object.freeze(suppressions);
};

const normalizeCandidates = (values, input) => {
  if (!Array.isArray(values) || values.length > revenueProgramPolicy.maximumCandidates) fail("invalid_candidates");
  const inboxRefs = new Set(input.inboxes.map((inbox) => inbox.inboxRef));
  const candidates = values
    .map((value) => {
      assertExactKeys(value, candidateKeys, "invalid_candidate");
      if (value.ownerPrincipalRef !== input.principal.principalRef || !inboxRefs.has(value.inboxRef))
        fail("candidate_owner_mismatch");
      return Object.freeze({
        candidateRef: assertReference(value.candidateRef, "invalid_candidate"),
        accountRef: assertReference(value.accountRef, "invalid_candidate"),
        accountDomain:
          typeof value.accountDomain === "string" && domainPattern.test(value.accountDomain)
            ? value.accountDomain
            : fail("invalid_candidate"),
        contactEmail: assertEmail(value.contactEmail, "invalid_candidate"),
        linkedinProfileRef:
          value.linkedinProfileRef === null
            ? null
            : assertReference(value.linkedinProfileRef, "invalid_candidate").toLowerCase(),
        ownerPrincipalRef: value.ownerPrincipalRef,
        inboxRef: value.inboxRef,
        priorityScore: assertInteger(value.priorityScore, 0, 1_000_000, "invalid_candidate"),
        researchEvidenceHashes: normalizeHashes(value.researchEvidenceHashes, 32, "invalid_candidate"),
        sequenceRef: assertReference(value.sequenceRef, "invalid_candidate"),
        emailSubject: assertSingleLineText(value.emailSubject, 200, "invalid_candidate"),
        emailBody: assertText(value.emailBody, 20_000, "invalid_candidate"),
      });
    })
    .sort((left, right) => compareCodepoints(left.candidateRef, right.candidateRef));
  if (
    new Set(candidates.map((candidate) => candidate.candidateRef)).size !== candidates.length ||
    new Set(candidates.map((candidate) => candidate.contactEmail)).size !== candidates.length ||
    new Set(
      candidates
        .filter((candidate) => candidate.linkedinProfileRef)
        .map((candidate) => candidate.linkedinProfileRef.toLowerCase()),
    ).size !== candidates.filter((candidate) => candidate.linkedinProfileRef).length
  )
    fail("duplicate_candidate");
  const contactsPerAccount = new Map();
  const domainByAccount = new Map();
  const accountByDomain = new Map();
  for (const candidate of candidates) {
    contactsPerAccount.set(candidate.accountRef, (contactsPerAccount.get(candidate.accountRef) ?? 0) + 1);
    if (
      (domainByAccount.has(candidate.accountRef) &&
        domainByAccount.get(candidate.accountRef) !== candidate.accountDomain) ||
      (accountByDomain.has(candidate.accountDomain) &&
        accountByDomain.get(candidate.accountDomain) !== candidate.accountRef)
    )
      fail("candidate_account_domain_mismatch");
    domainByAccount.set(candidate.accountRef, candidate.accountDomain);
    accountByDomain.set(candidate.accountDomain, candidate.accountRef);
  }
  if ([...contactsPerAccount.values()].some((count) => count > candidateAccountPolicy.maximumContactsPerAccount))
    fail("candidate_account_contact_limit");
  return Object.freeze(candidates);
};

const normalizeVisitorIntent = (values, input, sources) => {
  if (!Array.isArray(values) || values.length > revenueProgramPolicy.maximumCandidates) fail("invalid_visitor_intent");
  const records = values
    .map((value) => {
      assertExactKeys(value, intentKeys, "invalid_visitor_intent");
      const intentRef = assertReference(value.intentRef, "invalid_visitor_intent");
      const accountRef = assertReference(value.accountRef, "invalid_visitor_intent");
      const accountDomain =
        typeof value.accountDomain === "string" && domainPattern.test(value.accountDomain)
          ? value.accountDomain
          : fail("invalid_visitor_intent");
      if (
        value.identityScope !== "account_level_only" ||
        !Array.isArray(value.observations) ||
        value.observations.length !== 3
      )
        fail("invalid_visitor_intent");
      const observations = value.observations
        .map((observation) => {
          assertExactKeys(observation, intentObservationKeys, "invalid_visitor_intent");
          if (
            !new Set(["rb2b", "google_analytics", "posthog"]).has(observation.source) ||
            !new Set(["low", "medium", "high"]).has(observation.confidence) ||
            !new Set(["anonymous", "account"]).has(observation.identityScope) ||
            (observation.source !== "rb2b" && observation.identityScope !== "anonymous")
          )
            fail("invalid_visitor_intent");
          const observedAt = assertInstant(observation.observedAt, "invalid_visitor_intent");
          const sourceRecord = sources[observation.source].records.find(
            (record) => record.recordRef === observation.sourceRecordRef,
          );
          const facts = new Map(sourceRecord?.facts.map((fact) => [fact.field, fact.value]) ?? []);
          if (
            observedAt > input.now ||
            input.now.valueOf() - observedAt.valueOf() > 86_400_000 ||
            dateInTimeZone(observedAt, input.timeZone) !== input.goalDate ||
            !sourceRecord ||
            sourceRecord.observedAt !== observedAt.toISOString() ||
            sourceRecord.evidenceHash !== observation.evidenceHash ||
            facts.get("account_ref") !== accountRef ||
            facts.get("account_domain") !== accountDomain ||
            facts.get("observed_at") !== observedAt.toISOString() ||
            facts.get("confidence") !== observation.confidence
          )
            fail("invalid_visitor_observation_binding");
          return Object.freeze({
            source: observation.source,
            sourceRecordRef: assertReference(observation.sourceRecordRef, "invalid_visitor_intent"),
            evidenceHash: assertHash(observation.evidenceHash, "invalid_visitor_intent"),
            observedAt: observedAt.toISOString(),
            confidence: observation.confidence,
            identityScope: observation.identityScope,
          });
        })
        .sort((left, right) => compareCodepoints(left.source, right.source));
      if (new Set(observations.map((observation) => observation.source)).size !== 3) fail("invalid_visitor_intent");
      const confidenceScore = Object.freeze({ low: 1, medium: 2, high: 3 });
      return Object.freeze({
        intentRef,
        accountRef,
        accountDomain,
        score: Math.min(
          9,
          observations.reduce((total, observation) => total + confidenceScore[observation.confidence], 0),
        ),
        identityScope: "account_level_only",
        observations: Object.freeze(observations),
        evidenceHashes: Object.freeze(
          observations.map((observation) => observation.evidenceHash).sort(compareCodepoints),
        ),
      });
    })
    .sort((left, right) => compareCodepoints(left.intentRef, right.intentRef));
  if (
    new Set(records.map((record) => record.intentRef)).size !== records.length ||
    new Set(records.map((record) => record.accountRef)).size !== records.length ||
    new Set(records.map((record) => record.accountDomain)).size !== records.length
  )
    fail("duplicate_visitor_intent");
  return Object.freeze(records);
};

const normalizeStaleDeals = (values, input) => {
  if (!Array.isArray(values) || values.length > 1_000) fail("invalid_stale_deals");
  const deals = values
    .map((value) => {
      assertExactKeys(value, staleDealKeys, "invalid_stale_deal");
      if (value.ownerPrincipalRef !== input.principal.principalRef) fail("stale_deal_owner_mismatch");
      const lastVerifiedTouchAt =
        value.lastVerifiedTouchAt === null ? null : assertInstant(value.lastVerifiedTouchAt, "invalid_stale_deal");
      if (lastVerifiedTouchAt && lastVerifiedTouchAt > input.now) fail("future_deal_touch");
      if (!new Set(["Discovery", "HOT", "Proposal", "POC", "Strategic POC", "Launching", "LIVE"]).has(value.stage))
        fail("invalid_stale_deal");
      let lastVerifiedTouchCitation = null;
      if (value.lastVerifiedTouchAt !== null) {
        assertExactKeys(value.lastVerifiedTouchCitation, touchCitationKeys, "invalid_stale_deal");
        if (!new Set(["clarify", "command_center_brain"]).has(value.lastVerifiedTouchCitation.source))
          fail("invalid_stale_deal");
        const occurredAt = assertInstant(value.lastVerifiedTouchCitation.occurredAt, "invalid_stale_deal");
        if (occurredAt.toISOString() !== lastVerifiedTouchAt.toISOString()) fail("stale_touch_citation_mismatch");
        lastVerifiedTouchCitation = Object.freeze({
          source: value.lastVerifiedTouchCitation.source,
          sourceRecordRef: assertReference(value.lastVerifiedTouchCitation.sourceRecordRef, "invalid_stale_deal"),
          evidenceHash: assertHash(value.lastVerifiedTouchCitation.evidenceHash, "invalid_stale_deal"),
          occurredAt: occurredAt.toISOString(),
        });
      } else if (value.lastVerifiedTouchCitation !== null) {
        fail("invalid_stale_deal");
      }
      return Object.freeze({
        dealRef: assertReference(value.dealRef, "invalid_stale_deal"),
        accountRef: assertReference(value.accountRef, "invalid_stale_deal"),
        ownerPrincipalRef: value.ownerPrincipalRef,
        recipientEmail: assertEmail(value.recipientEmail, "invalid_stale_deal"),
        stage: value.stage,
        lastVerifiedTouchAt: lastVerifiedTouchAt?.toISOString() ?? null,
        lastVerifiedTouchCitation,
        evidenceHashes: normalizeHashes(value.evidenceHashes, 32, "invalid_stale_deal"),
        draftSubject: assertSingleLineText(value.draftSubject, 200, "invalid_stale_deal"),
        draftBody: assertText(value.draftBody, 20_000, "invalid_stale_deal"),
      });
    })
    .sort((left, right) => compareCodepoints(left.dealRef, right.dealRef));
  if (new Set(deals.map((deal) => deal.dealRef)).size !== deals.length) fail("duplicate_stale_deal");
  return Object.freeze(deals);
};

const normalizeAcceptances = (values, input, candidates) => {
  if (!Array.isArray(values) || values.length > 1_000) fail("invalid_linkedin_acceptances");
  const records = values
    .map((value) => {
      assertExactKeys(value, acceptanceKeys, "invalid_linkedin_acceptance");
      const candidate = candidates.get(value.candidateRef);
      if (
        value.ownerPrincipalRef !== input.principal.principalRef ||
        !candidate ||
        candidate.linkedinProfileRef === null
      )
        fail("linkedin_acceptance_owner_mismatch");
      const acceptedAt = assertInstant(value.acceptedAt, "invalid_linkedin_acceptance");
      if (acceptedAt > input.now) fail("future_linkedin_acceptance");
      return Object.freeze({
        acceptanceRef: assertReference(value.acceptanceRef, "invalid_linkedin_acceptance"),
        candidateRef: value.candidateRef,
        ownerPrincipalRef: value.ownerPrincipalRef,
        acceptedAt: acceptedAt.toISOString(),
        evidenceHash: assertHash(value.evidenceHash, "invalid_linkedin_acceptance"),
        dmBody: assertText(value.dmBody, 3_000, "invalid_linkedin_acceptance"),
        voiceEvidenceHash: assertHash(value.voiceEvidenceHash, "invalid_linkedin_acceptance"),
      });
    })
    .sort((left, right) => compareCodepoints(left.acceptanceRef, right.acceptanceRef));
  if (new Set(records.map((record) => record.acceptanceRef)).size !== records.length)
    fail("duplicate_linkedin_acceptance");
  if (new Set(records.map((record) => record.candidateRef)).size !== records.length)
    fail("duplicate_linkedin_acceptance_candidate");
  return Object.freeze(records);
};

const normalizeMeetings = (values, input) => {
  if (!Array.isArray(values) || values.length > 1_000) fail("invalid_meetings");
  const records = values
    .map((value) => {
      assertExactKeys(value, meetingKeys, "invalid_meeting");
      if (value.ownerPrincipalRef !== input.principal.principalRef) fail("meeting_owner_mismatch");
      if (value.repositoryRef !== input.binding.demoRepositoryRef) fail("caller_selected_demo_repository");
      const startAt = assertInstant(value.startAt, "invalid_meeting");
      const originalStartAt = assertInstant(value.originalStartAt, "invalid_meeting");
      const previousStartAt = assertInstant(value.previousStartAt, "invalid_meeting");
      const movedFromStartAt =
        value.movedFromStartAt === null ? null : assertInstant(value.movedFromStartAt, "invalid_meeting");
      const cancelledAt = value.cancelledAt === null ? null : assertInstant(value.cancelledAt, "invalid_meeting");
      const eventVersion = assertInteger(value.eventVersion, 1, 1_000_000, "invalid_meeting");
      const scheduleRevision = assertInteger(value.scheduleRevision, 1, 1_000_000, "invalid_meeting");
      const previousEventVersion = assertInteger(value.previousEventVersion, 1, 1_000_000, "invalid_meeting");
      const previousScheduleRevision = assertInteger(value.previousScheduleRevision, 1, 1_000_000, "invalid_meeting");
      if (
        !new Set(["scheduled", "cancelled"]).has(value.status) ||
        !new Set(["unchanged", "moved", "cancelled"]).has(value.changeStatus) ||
        (value.status === "scheduled" && cancelledAt !== null) ||
        (value.status === "cancelled" && cancelledAt === null) ||
        (cancelledAt !== null && cancelledAt > input.now) ||
        (movedFromStartAt !== null && movedFromStartAt.toISOString() === startAt.toISOString()) ||
        (value.changeStatus === "unchanged" &&
          (value.status !== "scheduled" ||
            movedFromStartAt !== null ||
            startAt.toISOString() !== previousStartAt.toISOString() ||
            eventVersion !== previousEventVersion ||
            scheduleRevision !== previousScheduleRevision)) ||
        (value.changeStatus === "moved" &&
          (value.status !== "scheduled" ||
            movedFromStartAt === null ||
            movedFromStartAt.toISOString() !== previousStartAt.toISOString() ||
            startAt.toISOString() === previousStartAt.toISOString() ||
            eventVersion <= previousEventVersion ||
            scheduleRevision <= previousScheduleRevision)) ||
        (value.changeStatus === "cancelled" &&
          (value.status !== "cancelled" ||
            movedFromStartAt !== null ||
            startAt.toISOString() !== previousStartAt.toISOString() ||
            eventVersion <= previousEventVersion ||
            scheduleRevision <= previousScheduleRevision))
      )
        fail("invalid_meeting_lifecycle");
      if (!new Set(["advancement", "admissions"]).has(value.segment)) fail("invalid_meeting");
      if (!new Set(["advancement", "discovery", "proposal", "poc"]).has(value.stage)) fail("invalid_meeting");
      const meetingRef = assertReference(value.meetingRef, "invalid_meeting");
      const recurringEventRef =
        value.recurringEventRef === null ? null : assertReference(value.recurringEventRef, "invalid_meeting");
      const occurrenceRef = `occurrence:${sha256Canonical({
        meetingRef,
        originalStartAt: originalStartAt.toISOString(),
        recurringEventRef,
      })}`;
      return Object.freeze({
        meetingRef,
        accountRef: assertReference(value.accountRef, "invalid_meeting"),
        ownerPrincipalRef: value.ownerPrincipalRef,
        startAt: startAt.toISOString(),
        originalStartAt: originalStartAt.toISOString(),
        previousStartAt: previousStartAt.toISOString(),
        movedFromStartAt: movedFromStartAt?.toISOString() ?? null,
        status: value.status,
        eventVersion,
        scheduleRevision,
        previousEventVersion,
        previousScheduleRevision,
        changeStatus: value.changeStatus,
        occurrenceRef,
        recurringEventRef,
        cancelledAt: cancelledAt?.toISOString() ?? null,
        segment: value.segment,
        stage: value.stage,
        repositoryRef: assertReference(value.repositoryRef, "invalid_meeting"),
        customizationEvidenceHash:
          value.customizationEvidenceHash === null
            ? null
            : assertHash(value.customizationEvidenceHash, "invalid_meeting"),
        calendarEvidenceHash: assertHash(value.calendarEvidenceHash, "invalid_meeting"),
      });
    })
    .sort((left, right) => compareCodepoints(left.meetingRef, right.meetingRef));
  if (new Set(records.map((record) => record.meetingRef)).size !== records.length) fail("duplicate_meeting");
  return Object.freeze(records);
};

const normalizeArtifacts = (values, authority) => {
  if (!Array.isArray(values) || values.length > 64) fail("invalid_notion_artifacts");
  const artifacts = values
    .map((value) => {
      assertExactKeys(value, artifactKeys, "invalid_notion_artifact");
      const transcriptEndedAt = assertInstant(value.transcriptEndedAt, "invalid_notion_artifact");
      const transcriptFinalizedAt = assertInstant(value.transcriptFinalizedAt, "invalid_notion_artifact");
      if (transcriptEndedAt > transcriptFinalizedAt) fail("invalid_notion_artifact");
      return Object.freeze({
        artifactRef: assertReference(value.artifactRef, "invalid_notion_artifact"),
        rootRef: assertReference(value.rootRef, "invalid_notion_artifact"),
        audience: value.audience === authority.notionAudience ? value.audience : fail("invalid_notion_artifact"),
        title: assertText(value.title, 256, "invalid_notion_artifact"),
        body: assertText(value.body, 100_000, "invalid_notion_artifact"),
        contentSummary: assertText(value.contentSummary, 4_096, "invalid_notion_artifact"),
        transcriptSourceRecordRef: assertReference(value.transcriptSourceRecordRef, "invalid_notion_artifact"),
        transcriptEndedAt: transcriptEndedAt.toISOString(),
        transcriptFinalizedAt: transcriptFinalizedAt.toISOString(),
        evidenceHashes: normalizeHashes(value.evidenceHashes, 128, "invalid_notion_artifact"),
      });
    })
    .sort((left, right) => compareCodepoints(left.artifactRef, right.artifactRef));
  if (new Set(artifacts.map((artifact) => artifact.artifactRef)).size !== artifacts.length)
    fail("duplicate_notion_artifact");
  return Object.freeze(artifacts);
};

const normalizeCorrelations = (values, input, subjects, subjectFacts, sourceRecordIndex) => {
  if (!Array.isArray(values) || values.length > 10_000) fail("invalid_correlations");
  const correlations = values
    .map((value) => {
      assertExactKeys(value, correlationKeys, "invalid_correlation");
      if (
        value.deploymentRef !== input.binding.deploymentRef ||
        value.anchorRef !== input.binding.anchorRef ||
        value.tenantRef !== input.binding.tenantRef ||
        value.workspaceRef !== input.binding.workspaceRef ||
        value.principalRef !== input.binding.principalRef ||
        value.credentialOwnerRef !== input.binding.credentialOwnerRef ||
        !revenueSourceNames.includes(value.source) ||
        !new Set(["candidate", "deal", "meeting", "acceptance", "artifact", "visitor_account"]).has(
          value.subjectType,
        ) ||
        !sourceSemanticPolicies[value.source]?.includes(value.subjectType) ||
        !subjects.get(value.subjectType)?.has(value.subjectRef)
      )
        fail("invalid_correlation");
      const sourceRecord = sourceRecordIndex.get(`${value.source}\u0000${value.sourceRecordRef}`);
      const expectedFacts = subjectFacts.get(`${value.subjectType}\u0000${value.subjectRef}`);
      const facts = new Map(sourceRecord?.record.facts.map((fact) => [fact.field, fact.value]) ?? []);
      const expectedCitationRefs = (sourceRecord?.record.facts ?? [])
        .map((fact) => fact.citationRef)
        .sort(compareCodepoints);
      if (
        !Array.isArray(value.factCitationRefs) ||
        value.factCitationRefs.length !== expectedCitationRefs.length ||
        value.factCitationRefs.some((reference, index) => reference !== expectedCitationRefs[index])
      )
        fail("correlation_citation_mismatch");
      const semanticMismatch =
        (value.subjectType === "candidate" &&
          (facts.get("account_ref") !== expectedFacts?.accountRef ||
            facts.get("account_domain") !== expectedFacts?.accountDomain ||
            facts.get("contact_email") !== expectedFacts?.contactEmail ||
            facts.get("linkedin_profile_ref") !== (expectedFacts?.linkedinProfileRef ?? "none") ||
            facts.get("sequence_ref") !== expectedFacts?.sequenceRef ||
            facts.get("email_subject_hash") !== expectedFacts?.emailSubjectHash ||
            facts.get("email_body_hash") !== expectedFacts?.emailBodyHash)) ||
        (value.subjectType === "deal" &&
          (facts.get("deal_ref") !== value.subjectRef ||
            facts.get("account_ref") !== expectedFacts?.accountRef ||
            facts.get("contact_email") !== expectedFacts?.contactEmail ||
            facts.get("last_verified_touch_at") !== expectedFacts?.lastVerifiedTouchAt ||
            facts.get("stage") !== expectedFacts?.stage ||
            facts.get("draft_subject_hash") !== expectedFacts?.draftSubjectHash ||
            facts.get("draft_body_hash") !== expectedFacts?.draftBodyHash)) ||
        (value.subjectType === "meeting" &&
          (facts.get("meeting_ref") !== value.subjectRef ||
            facts.get("account_ref") !== expectedFacts?.accountRef ||
            facts.get("occurrence_ref") !== expectedFacts?.meetingOccurrenceRef ||
            facts.get("start_at") !== expectedFacts?.startAt ||
            facts.get("original_start_at") !== expectedFacts?.originalStartAt ||
            facts.get("event_version") !== String(expectedFacts?.eventVersion) ||
            facts.get("schedule_revision") !== String(expectedFacts?.scheduleRevision) ||
            facts.get("previous_start_at") !== expectedFacts?.previousStartAt ||
            facts.get("previous_event_version") !== String(expectedFacts?.previousEventVersion) ||
            facts.get("previous_schedule_revision") !== String(expectedFacts?.previousScheduleRevision) ||
            facts.get("moved_from_start_at") !== (expectedFacts?.movedFromStartAt ?? "none") ||
            facts.get("cancelled_at") !== (expectedFacts?.cancelledAt ?? "none") ||
            facts.get("change_status") !== expectedFacts?.changeStatus ||
            facts.get("status") !== expectedFacts?.status)) ||
        (value.subjectType === "acceptance" &&
          (facts.get("linkedin_profile_ref") !== expectedFacts?.linkedinProfileRef ||
            (value.source === "notion" && facts.get("dm_body_hash") !== expectedFacts?.dmBodyHash) ||
            (value.source === "linkedin" &&
              (facts.get("acceptance_ref") !== value.subjectRef ||
                facts.get("account_ref") !== expectedFacts?.accountRef ||
                facts.get("accepted_at") !== expectedFacts?.acceptedAt)))) ||
        (value.subjectType === "artifact" &&
          (value.sourceRecordRef !== expectedFacts?.transcriptSourceRecordRef ||
            facts.get("artifact_ref") !== value.subjectRef ||
            facts.get("artifact_title_hash") !== expectedFacts?.artifactTitleHash ||
            facts.get("artifact_body_hash") !== expectedFacts?.artifactBodyHash ||
            facts.get("content_summary") !== expectedFacts?.contentSummary ||
            facts.get("transcript_ended_at") !== expectedFacts?.transcriptEndedAt ||
            facts.get("finalized_at") !== expectedFacts?.transcriptFinalizedAt)) ||
        (value.subjectType === "visitor_account" &&
          (facts.get("account_ref") !== expectedFacts?.accountRef ||
            facts.get("account_domain") !== expectedFacts?.accountDomain));
      if (
        !sourceRecord ||
        !expectedFacts ||
        semanticMismatch ||
        sourceRecord.record.evidenceHash !== value.evidenceHash ||
        sourceRecord.binding.accountRef !== value.providerAccountRef ||
        value.accountRef !== expectedFacts.accountRef ||
        value.contactRef !== expectedFacts.contactRef ||
        value.meetingOccurrenceRef !== expectedFacts.meetingOccurrenceRef
      )
        fail("correlation_semantic_mismatch");
      const correlationRef = providerCorrelationReference({
        providerAccountRef: value.providerAccountRef,
        source: value.source,
        sourceRecordRef: value.sourceRecordRef,
        subjectType: value.subjectType,
        subjectRef: value.subjectRef,
      });
      if (value.correlationRef !== correlationRef) fail("unqualified_correlation_reference");
      return Object.freeze({
        correlationRef,
        deploymentRef: value.deploymentRef,
        anchorRef: value.anchorRef,
        tenantRef: value.tenantRef,
        workspaceRef: value.workspaceRef,
        principalRef: value.principalRef,
        credentialOwnerRef: value.credentialOwnerRef,
        providerAccountRef: assertReference(value.providerAccountRef, "invalid_correlation"),
        source: value.source,
        sourceRecordRef: assertReference(value.sourceRecordRef, "invalid_correlation"),
        subjectType: value.subjectType,
        subjectRef: assertReference(value.subjectRef, "invalid_correlation"),
        accountRef: value.accountRef === null ? null : assertReference(value.accountRef, "invalid_correlation"),
        contactRef: value.contactRef === null ? null : assertReference(value.contactRef, "invalid_correlation"),
        meetingOccurrenceRef:
          value.meetingOccurrenceRef === null
            ? null
            : assertReference(value.meetingOccurrenceRef, "invalid_correlation"),
        evidenceHash: assertHash(value.evidenceHash, "invalid_correlation"),
        factCitationRefs: Object.freeze(
          value.factCitationRefs.map((reference) => assertReference(reference, "invalid_correlation")),
        ),
      });
    })
    .sort((left, right) => compareCodepoints(left.correlationRef, right.correlationRef));
  if (new Set(correlations.map((entry) => entry.correlationRef)).size !== correlations.length)
    fail("duplicate_correlation");
  for (const [subjectType, refs] of subjects.entries()) {
    for (const subjectRef of refs) {
      if (!correlations.some((entry) => entry.subjectType === subjectType && entry.subjectRef === subjectRef))
        fail("missing_subject_correlation");
    }
  }
  return Object.freeze(correlations);
};

const normalizeRevenueProgramInputForAuthority = (raw, authority) => {
  const value = snapshotPlainJson(raw);
  assertExactKeys(value, inputKeys, "invalid_input");
  if (value.version !== revenueProgramPolicy.version) fail("invalid_version");
  const now = assertInstant(value.now, "invalid_input");
  const goalDate = assertDate(value.goalDate, "invalid_input");
  const timeZone = assertTimeZone(value.timeZone, "invalid_input");
  if (dateInTimeZone(now, timeZone) !== goalDate) fail("goal_date_mismatch");
  const principal = normalizePrincipal(value.principal, authority);
  const binding = normalizeBinding(value.binding, principal, authority);
  const partial = { now, principal, binding, goalDate, timeZone };
  const inboxes = normalizeInboxes(value.inboxes, principal, authority);
  const input = { ...partial, inboxes };
  const sourcesValue = value.sources;
  assertExactKeys(
    sourcesValue,
    revenueSourceNames.filter((name) => name !== "command_center_brain"),
    "invalid_sources",
  );
  const sources = Object.freeze(
    Object.fromEntries(
      revenueSourceNames
        .filter((name) => name !== "command_center_brain")
        .map((source) => {
          const sourceBindings = {
            apollo: [binding.apolloAccountRef, "prospect_research"],
            calendar: [binding.googleAccountRef, "primary"],
            clarify: [binding.clarifyAccountRef, "read_context"],
            gmail: [binding.googleAccountRef, "drafts"],
            google_analytics: [binding.googleAccountRef, "visitor_intent"],
            linkedin: [binding.linkedinAccountRef, "acceptance_read"],
            notion: [binding.notionRootRef, binding.notionRootRef],
            posthog: [binding.posthogAccountRef, "visitor_intent"],
            rb2b: [binding.rb2bAccountRef, "visitor_intent"],
            transcripts: [binding.clarifyAccountRef, "finalized_transcripts"],
          };
          const [accountRef, rootRef] = sourceBindings[source];
          return [
            source,
            normalizeSourceSnapshotForAuthority(
              sourcesValue[source],
              source,
              now,
              {
                deploymentRef: binding.deploymentRef,
                anchorRef: binding.anchorRef,
                tenantRef: binding.tenantRef,
                workspaceRef: binding.workspaceRef,
                principalRef: binding.principalRef,
                credentialOwnerRef: binding.credentialOwnerRef,
                accountRef,
                rootRef,
              },
              authority,
            ),
          ];
        }),
    ),
  );
  const candidates = normalizeCandidates(value.candidates, input);
  const candidateMap = new Map(candidates.map((candidate) => [candidate.candidateRef, candidate]));
  const brain = normalizeBrainSnapshots(value.brain, now, binding);
  if (
    Object.values(sources).some((source) => dateInTimeZone(new Date(source.checkedAt), timeZone) !== goalDate) ||
    brain.some((entry) => dateInTimeZone(new Date(entry.snapshot.checkedAt), timeZone) !== goalDate) ||
    Object.values(sources).some((source) =>
      source.records.some(
        (record) =>
          dateInTimeZone(new Date(record.observedAt), timeZone) !== goalDate ||
          now.valueOf() - new Date(record.observedAt).valueOf() > 86_400_000,
      ),
    ) ||
    brain.some((entry) =>
      entry.snapshot.records.some(
        (record) =>
          dateInTimeZone(new Date(record.observedAt), timeZone) !== goalDate ||
          now.valueOf() - new Date(record.observedAt).valueOf() > 86_400_000,
      ),
    )
  )
    fail("source_local_day_mismatch");
  const staleDeals = normalizeStaleDeals(value.staleDeals, input);
  const linkedinAcceptances = normalizeAcceptances(value.linkedinAcceptances, input, candidateMap);
  const meetings = normalizeMeetings(value.meetings, input);
  const notionArtifacts = normalizeArtifacts(value.notionArtifacts, authority);
  const visitorIntent = normalizeVisitorIntent(value.visitorIntent, input, sources);
  const sourceRecordIndex = new Map();
  for (const source of Object.values(sources)) {
    for (const record of source.records)
      sourceRecordIndex.set(`${source.source}\u0000${record.recordRef}`, { record, binding: source.binding });
  }
  for (const call of brain) {
    for (const record of call.snapshot.records)
      sourceRecordIndex.set(`command_center_brain\u0000${record.recordRef}`, {
        record,
        binding: call.snapshot.binding,
      });
  }
  const providerQualifiedRecordRefs = [];
  const providerQualifiedCitationRefs = [];
  const globalBoundaryReferences = brain.map((entry) => entry.queryRef);
  const collectReferences = (snapshot) => {
    for (const record of snapshot.records) {
      globalBoundaryReferences.push(record.recordRef);
      providerQualifiedRecordRefs.push(`${snapshot.binding.accountRef}\u0000${record.recordRef}`);
      for (const fact of record.facts) {
        globalBoundaryReferences.push(fact.citationRef);
        providerQualifiedCitationRefs.push(`${snapshot.binding.accountRef}\u0000${fact.citationRef}`);
      }
    }
  };
  for (const source of Object.values(sources)) collectReferences(source);
  for (const call of brain) collectReferences(call.snapshot);
  if (
    new Set(providerQualifiedRecordRefs).size !== providerQualifiedRecordRefs.length ||
    new Set(providerQualifiedCitationRefs).size !== providerQualifiedCitationRefs.length
  )
    fail("duplicate_provider_qualified_reference");
  const subjects = new Map([
    ["candidate", new Set(candidates.map((entry) => entry.candidateRef))],
    ["deal", new Set(staleDeals.map((entry) => entry.dealRef))],
    ["meeting", new Set(meetings.map((entry) => entry.meetingRef))],
    ["acceptance", new Set(linkedinAcceptances.map((entry) => entry.acceptanceRef))],
    ["artifact", new Set(notionArtifacts.map((entry) => entry.artifactRef))],
    ["visitor_account", new Set(visitorIntent.map((entry) => entry.intentRef))],
  ]);
  const rawSubjectRefs = [...subjects.values()].flatMap((refs) => [...refs]);
  if (new Set(rawSubjectRefs).size !== rawSubjectRefs.length) fail("subject_namespace_collision");
  const subjectFacts = new Map([
    ...candidates.map((candidate) => [
      `candidate\u0000${candidate.candidateRef}`,
      {
        accountRef: candidate.accountRef,
        accountDomain: candidate.accountDomain,
        contactEmail: candidate.contactEmail,
        linkedinProfileRef: candidate.linkedinProfileRef,
        sequenceRef: candidate.sequenceRef,
        emailSubjectHash: sha256Canonical(candidate.emailSubject),
        emailBodyHash: sha256Canonical(candidate.emailBody),
        contactRef: `email:${sha256Canonical(candidate.contactEmail)}`,
        meetingOccurrenceRef: null,
      },
    ]),
    ...staleDeals.map((deal) => [
      `deal\u0000${deal.dealRef}`,
      {
        accountRef: deal.accountRef,
        contactEmail: deal.recipientEmail,
        lastVerifiedTouchAt: deal.lastVerifiedTouchAt,
        stage: deal.stage,
        draftSubjectHash: sha256Canonical(deal.draftSubject),
        draftBodyHash: sha256Canonical(deal.draftBody),
        contactRef: `email:${sha256Canonical(deal.recipientEmail)}`,
        meetingOccurrenceRef: null,
      },
    ]),
    ...meetings.map((meeting) => [
      `meeting\u0000${meeting.meetingRef}`,
      {
        accountRef: meeting.accountRef,
        contactRef: null,
        meetingOccurrenceRef: meeting.occurrenceRef,
        startAt: meeting.startAt,
        originalStartAt: meeting.originalStartAt,
        previousStartAt: meeting.previousStartAt,
        movedFromStartAt: meeting.movedFromStartAt,
        cancelledAt: meeting.cancelledAt,
        status: meeting.status,
        eventVersion: meeting.eventVersion,
        scheduleRevision: meeting.scheduleRevision,
        previousEventVersion: meeting.previousEventVersion,
        previousScheduleRevision: meeting.previousScheduleRevision,
        changeStatus: meeting.changeStatus,
      },
    ]),
    ...linkedinAcceptances.map((acceptance) => {
      const candidate = candidateMap.get(acceptance.candidateRef);
      return [
        `acceptance\u0000${acceptance.acceptanceRef}`,
        {
          accountRef: candidate.accountRef,
          linkedinProfileRef: candidate.linkedinProfileRef,
          acceptedAt: acceptance.acceptedAt,
          dmBodyHash: sha256Canonical(acceptance.dmBody),
          contactRef: `linkedin:${sha256Canonical(candidate.linkedinProfileRef)}`,
          meetingOccurrenceRef: null,
        },
      ];
    }),
    ...notionArtifacts.map((artifact) => [
      `artifact\u0000${artifact.artifactRef}`,
      {
        accountRef: null,
        contactRef: null,
        meetingOccurrenceRef: null,
        artifactTitleHash: sha256Canonical(artifact.title),
        artifactBodyHash: sha256Canonical(artifact.body),
        contentSummary: artifact.contentSummary,
        transcriptSourceRecordRef: artifact.transcriptSourceRecordRef,
        transcriptEndedAt: artifact.transcriptEndedAt,
        transcriptFinalizedAt: artifact.transcriptFinalizedAt,
      },
    ]),
    ...visitorIntent.map((intent) => [
      `visitor_account\u0000${intent.intentRef}`,
      {
        accountRef: intent.accountRef,
        accountDomain: intent.accountDomain,
        contactRef: null,
        meetingOccurrenceRef: null,
      },
    ]),
  ]);
  const correlations = normalizeCorrelations(value.correlations, input, subjects, subjectFacts, sourceRecordIndex);
  globalBoundaryReferences.push(...correlations.map((correlation) => correlation.correlationRef));
  if (new Set(globalBoundaryReferences).size !== globalBoundaryReferences.length) fail("global_reference_collision");
  const ledgerIdentityIndex = new Map();
  for (const candidate of candidates) {
    ledgerIdentityIndex.set(
      `cold_email\u0000${candidate.candidateRef}`,
      Object.freeze({
        stableRecipientIdentity: `email:${sha256Canonical(candidate.contactEmail)}`,
        inboxRef: candidate.inboxRef,
      }),
    );
    if (candidate.linkedinProfileRef !== null)
      ledgerIdentityIndex.set(
        `linkedin_connection\u0000${candidate.candidateRef}`,
        Object.freeze({
          stableRecipientIdentity: `linkedin:${sha256Canonical(candidate.linkedinProfileRef)}`,
          inboxRef: null,
        }),
      );
  }
  for (const deal of staleDeals)
    ledgerIdentityIndex.set(
      `stale_email\u0000${deal.dealRef}`,
      Object.freeze({
        stableRecipientIdentity: `email:${sha256Canonical(deal.recipientEmail)}`,
        inboxRef: null,
      }),
    );
  for (const acceptance of linkedinAcceptances) {
    const candidate = candidateMap.get(acceptance.candidateRef);
    ledgerIdentityIndex.set(
      `linkedin_dm\u0000${acceptance.acceptanceRef}`,
      Object.freeze({
        stableRecipientIdentity: `linkedin:${sha256Canonical(candidate.linkedinProfileRef)}`,
        inboxRef: null,
      }),
    );
  }
  for (const meeting of meetings) {
    const subjectRef = `meeting-schedule:${sha256Canonical({
      occurrenceRef: meeting.occurrenceRef,
      eventVersion: meeting.eventVersion,
      scheduleRevision: meeting.scheduleRevision,
      startAt: meeting.startAt,
    })}`;
    const identity = `meeting:${sha256Canonical({
      occurrenceRef: meeting.occurrenceRef,
      eventVersion: meeting.eventVersion,
      scheduleRevision: meeting.scheduleRevision,
    })}`;
    ledgerIdentityIndex.set(
      `demo_reminder\u0000${subjectRef}`,
      Object.freeze({ stableRecipientIdentity: identity, inboxRef: null }),
    );
    ledgerIdentityIndex.set(
      `demo_customization\u0000${subjectRef}`,
      Object.freeze({ stableRecipientIdentity: identity, inboxRef: null }),
    );
  }
  for (const artifact of notionArtifacts)
    ledgerIdentityIndex.set(
      `notion_artifact\u0000${artifact.artifactRef}`,
      Object.freeze({
        stableRecipientIdentity: `artifact:${sha256Canonical(artifact.artifactRef)}`,
        inboxRef: null,
      }),
    );
  for (const intent of visitorIntent)
    ledgerIdentityIndex.set(
      `notion_artifact\u0000${intent.intentRef}`,
      Object.freeze({
        stableRecipientIdentity: `account-domain:${sha256Canonical(intent.accountDomain)}`,
        inboxRef: null,
      }),
    );
  const normalized = Object.freeze({
    version: revenueProgramPolicy.version,
    programRef: assertReference(value.programRef, "invalid_input"),
    programRevision: assertInteger(value.programRevision, 0, 1_000_000, "invalid_input"),
    goalDate,
    timeZone,
    now: now.toISOString(),
    principal,
    binding,
    inboxes,
    ledger: normalizeLedger(value.ledger, input, ledgerIdentityIndex, meetings),
    suppressions: normalizeSuppressions(value.suppressions, input),
    brain,
    sources,
    candidates,
    visitorIntent,
    staleDeals,
    linkedinAcceptances,
    meetings,
    notionArtifacts,
    correlations,
    boundaryReferences: Object.freeze(globalBoundaryReferences.sort(compareCodepoints)),
  });
  const result = Object.freeze({ ...normalized, inputHash: sha256Canonical(normalized) });
  normalizedRevenueAuthorities.set(result, authority);
  return result;
};

export const providerOwnerRefForNormalizedRevenueInput = (input, providerAccountRef) => {
  const authority = normalizedRevenueAuthorities.get(input);
  if (!authority) fail("invalid_input");
  for (const [anchorKey, expectedAccountRef] of Object.entries(authority.connectionAnchors)) {
    if (providerAccountRef === expectedAccountRef) return authority.connectionOwnerRefs[anchorKey];
  }
  if (providerAccountRef === authority.principalBindingAnchor.workspaceRef)
    return authority.connectionOwnerRefs.workspaceRef;
  fail("caller_selected_connection_binding");
};

export function createRevenueProgramContractSuite(profile) {
  const authority = revenueAuthority(profile);
  const suite = Object.freeze({
    profile: authority.profile,
    deploymentPrincipalBindingAnchor: authority.principalBindingAnchor,
    deploymentConnectionAnchors: authority.connectionAnchors,
    deploymentConnectionOwnerRefs: authority.connectionOwnerRefs,
    deploymentSlackAudience: authority.slackAudience,
    notionAudience: authority.notionAudience,
    voiceProfileRef: authority.voiceProfileRef,
    normalizeRevenueProgramInput: (raw) => normalizeRevenueProgramInputForAuthority(raw, authority),
    providerExecutionAllowed: false,
  });
  revenueContractSuites.add(suite);
  return suite;
}

export function assertRevenueProgramContractSuite(value) {
  if (!revenueContractSuites.has(value)) fail("invalid_revenue_contract_suite");
  return value;
}

export const ceoRevenueProgramContractSuite = createRevenueProgramContractSuite(ceoDeploymentProfile);
export const normalizeRevenueProgramInput = ceoRevenueProgramContractSuite.normalizeRevenueProgramInput;
