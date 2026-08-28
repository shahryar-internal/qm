import {
  brainReadTools,
  brainToolFactFields,
  brainToolSubjectRefs,
  brainQueryReference,
  assertRevenueProgramContractSuite,
  ceoRevenueProgramContractSuite,
  providerCitationReference,
  providerCorrelationReference,
  providerRecordReference,
  revenueSourceNames,
} from "./contracts.mjs";
import { sha256Canonical } from "./validation.mjs";

const evidenceHash = (label) => sha256Canonical({ fixture: label });

const sourceRecord = (source, providerAccountRef, rootRef, observedAt, facts) => {
  const factValues = Object.entries(facts).map(([field, value]) => ({ field, value }));
  const recordRef = providerRecordReference({ providerAccountRef, rootRef, source, observedAt, facts: factValues });
  return {
    recordRef,
    observedAt,
    evidenceHash: evidenceHash(`${source}:${recordRef}`),
    facts: factValues.map(({ field, value }) => ({
      field,
      value,
      citationRef: providerCitationReference({ providerAccountRef, source, recordRef, field }),
    })),
  };
};

const sourceSnapshot = (source, checkedAt, binding, records) => ({
  source,
  status: records.length > 0 ? "available" : "none",
  checkedAt,
  binding,
  evidenceHash: records.length > 0 ? evidenceHash(`${source}:${binding.rootRef}:snapshot`) : null,
  unavailableCode: null,
  records,
});

const candidate = (index, principalRef) => {
  const sequence = String(index + 1).padStart(4, "0");
  return {
    candidateRef: `candidate:${sequence}`,
    accountRef: `account:${sequence}`,
    accountDomain: `school${sequence}.edu`,
    contactEmail: `buyer${sequence}@example.edu`,
    linkedinProfileRef: `linkedin:profile:${sequence}`,
    ownerPrincipalRef: principalRef,
    inboxRef: `inbox:${(index % 4) + 1}`,
    priorityScore: 100_000 - index,
    researchEvidenceHashes: [],
    sequenceRef: "sequence:advancement:v1",
    emailSubject: `Advancement planning ${sequence}`,
    emailBody: `Hello buyer ${sequence},\n\nHere is a researched advancement note.`,
  };
};

export const createRevenueProgramBoundaryFixtureForContractSuite = (contractSuite, { candidateCount = 120 } = {}) => {
  const contracts = assertRevenueProgramContractSuite(contractSuite);
  const deploymentPrincipalBindingAnchor = contracts.deploymentPrincipalBindingAnchor;
  const deploymentConnectionAnchors = contracts.deploymentConnectionAnchors;
  const notionAudience = contracts.notionAudience;
  const voiceProfileRef = contracts.voiceProfileRef;
  const now = "2026-08-26T16:00:00.000Z";
  const principalRef = deploymentPrincipalBindingAnchor.principalRef;
  const binding = {
    ...deploymentPrincipalBindingAnchor,
    ...deploymentConnectionAnchors,
  };
  const candidates = Array.from({ length: candidateCount }, (_, index) => candidate(index, principalRef));
  const meetingOccurrenceRef = `occurrence:${sha256Canonical({
    meetingRef: "meeting:advancement:1",
    originalStartAt: "2026-08-29T16:00:00.000Z",
    recurringEventRef: null,
  })}`;
  const visitorAccounts = Array.from({ length: 3 }, (_, index) => {
    const sequence = String(index + 1).padStart(4, "0");
    return {
      intentRef: `visitor-account:${sequence}`,
      accountRef: `visitor-account-ref:${sequence}`,
      accountDomain: `visitor${sequence}.edu`,
    };
  });
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
  const record = (source, observedAt, facts) => {
    const [providerAccountRef, rootRef] = sourceBindings[source];
    return sourceRecord(source, providerAccountRef, rootRef, observedAt, facts);
  };
  const recordsBySource = {
    apollo: candidates.map((entry) =>
      record("apollo", now, {
        account_domain: entry.accountDomain,
        account_ref: entry.accountRef,
        contact_email: entry.contactEmail,
        content_basis: "verified_prospect_profile",
        email_body_hash: sha256Canonical(entry.emailBody),
        email_subject_hash: sha256Canonical(entry.emailSubject),
        linkedin_profile_ref: entry.linkedinProfileRef ?? "none",
        sequence_ref: entry.sequenceRef,
      }),
    ),
    calendar: [
      record("calendar", now, {
        account_ref: "account:0001",
        cancelled_at: "none",
        change_status: "unchanged",
        event_version: "1",
        meeting_ref: "meeting:advancement:1",
        occurrence_ref: meetingOccurrenceRef,
        original_start_at: "2026-08-29T16:00:00.000Z",
        moved_from_start_at: "none",
        previous_event_version: "1",
        previous_schedule_revision: "1",
        previous_start_at: "2026-08-29T16:00:00.000Z",
        schedule_revision: "1",
        start_at: "2026-08-29T16:00:00.000Z",
        status: "scheduled",
      }),
    ],
    clarify: [
      record("clarify", now, {
        account_ref: "account:stale:1",
        contact_email: "champion@example.edu",
        content_basis: "verified_crm_timeline",
        deal_ref: "deal:stale:1",
        draft_body_hash: sha256Canonical("Hello champion,\n\nWould it be useful to review the proposal together?"),
        draft_subject_hash: sha256Canonical("Proposal follow-up"),
        last_verified_touch_at: "2026-08-10T16:00:00.000Z",
        stage: "Proposal",
      }),
    ],
    gmail: [
      record("gmail", now, {
        capability: "draft_proposal_only",
        credential_owner_ref: binding.credentialOwnerRef,
        mailbox_email: binding.principalEmail,
        provider_account_ref: binding.googleAccountRef,
      }),
    ],
    google_analytics: visitorAccounts.map((entry) =>
      record("google_analytics", now, {
        account_domain: entry.accountDomain,
        account_ref: entry.accountRef,
        confidence: "low",
        intent_signal: "account_page_view",
        observed_at: now,
      }),
    ),
    linkedin:
      candidateCount > 0
        ? [
            record("linkedin", now, {
              acceptance_ref: "linkedin:acceptance:1",
              accepted_at: "2026-08-26T15:00:00.000Z",
              account_ref: candidates[0].accountRef,
              linkedin_profile_ref: candidates[0].linkedinProfileRef,
            }),
          ]
        : [],
    notion: [
      record("notion", now, {
        audience: notionAudience,
        content_basis: "approved_ceo_voice",
        dm_body_hash: sha256Canonical("Thanks for connecting. Your advancement work caught my attention."),
        linkedin_profile_ref: candidates[0]?.linkedinProfileRef ?? "none",
        root_ref: binding.notionRootRef,
        voice_profile_ref: voiceProfileRef,
      }),
    ],
    posthog: visitorAccounts.map((entry) =>
      record("posthog", now, {
        account_domain: entry.accountDomain,
        account_ref: entry.accountRef,
        confidence: "low",
        intent_signal: "anonymous_product_event",
        observed_at: now,
      }),
    ),
    rb2b: visitorAccounts.map((entry) =>
      record("rb2b", now, {
        account_domain: entry.accountDomain,
        account_ref: entry.accountRef,
        confidence: "medium",
        intent_signal: "account_domain_match",
        observed_at: now,
      }),
    ),
    transcripts: [
      record("transcripts", now, {
        artifact_body_hash: sha256Canonical("Daily revenue evidence and proposed actions for review."),
        artifact_ref: "artifact:revenue:2026-08-26",
        artifact_title_hash: sha256Canonical("CEO revenue review"),
        content_summary: "Finalized revenue meeting evidence for the private CEO artifact.",
        finalized_at: now,
        transcript_ended_at: "2026-08-26T15:45:00.000Z",
      }),
    ],
  };
  const sources = Object.fromEntries(
    revenueSourceNames
      .filter((source) => source !== "command_center_brain")
      .map((source) => {
        const [accountRef, rootRef] = sourceBindings[source];
        return [
          source,
          sourceSnapshot(
            source,
            now,
            {
              deploymentRef: binding.deploymentRef,
              anchorRef: binding.anchorRef,
              tenantRef: binding.tenantRef,
              workspaceRef: binding.workspaceRef,
              principalRef,
              credentialOwnerRef: binding.credentialOwnerRef,
              accountRef,
              rootRef,
            },
            recordsBySource[source],
          ),
        ];
      }),
  );
  for (const [index, entry] of candidates.entries()) {
    entry.researchEvidenceHashes = [sources.apollo.records[index].evidenceHash];
  }
  const visitorIntent = visitorAccounts.map((entry, index) => ({
    ...entry,
    identityScope: "account_level_only",
    observations: ["rb2b", "google_analytics", "posthog"].map((source) => ({
      source,
      sourceRecordRef: sources[source].records[index].recordRef,
      evidenceHash: sources[source].records[index].evidenceHash,
      observedAt: now,
      confidence: source === "rb2b" ? "medium" : "low",
      identityScope: source === "rb2b" ? "account" : "anonymous",
    })),
  }));
  const correlation = (_correlationRef, subjectType, subjectRef, source, record, facts) => ({
    correlationRef: providerCorrelationReference({
      providerAccountRef: sources[source].binding.accountRef,
      source,
      sourceRecordRef: record.recordRef,
      subjectType,
      subjectRef,
    }),
    deploymentRef: binding.deploymentRef,
    anchorRef: binding.anchorRef,
    tenantRef: binding.tenantRef,
    workspaceRef: binding.workspaceRef,
    principalRef: binding.principalRef,
    credentialOwnerRef: binding.credentialOwnerRef,
    providerAccountRef: sources[source].binding.accountRef,
    source,
    sourceRecordRef: record.recordRef,
    subjectType,
    subjectRef,
    accountRef: facts.accountRef,
    contactRef: facts.contactRef,
    meetingOccurrenceRef: facts.meetingOccurrenceRef,
    evidenceHash: record.evidenceHash,
    factCitationRefs: record.facts.map((fact) => fact.citationRef).sort(),
  });
  return {
    version: "revenue-program.v1",
    programRef: "program:2026-08-26:ceo",
    programRevision: 0,
    goalDate: "2026-08-26",
    timeZone: "America/Los_Angeles",
    now,
    principal: { principalRef, email: deploymentPrincipalBindingAnchor.principalEmail },
    binding,
    inboxes: Array.from({ length: 4 }, (_, index) => ({
      inboxRef: `inbox:${index + 1}`,
      ownerEmail: deploymentPrincipalBindingAnchor.principalEmail,
    })),
    ledger: [],
    suppressions: [],
    brain: brainReadTools.map((tool) => {
      const subjectRef = brainToolSubjectRefs[tool];
      const record = sourceRecord("command_center_brain", binding.brainServerRef, tool, now, {
        as_of: now,
        [brainToolFactFields[tool]]: "opaque_unresolved",
        subject_ref: subjectRef,
      });
      return {
        tool,
        queryRef: brainQueryReference({
          providerAccountRef: binding.brainServerRef,
          tool,
          subjectRef,
          asOf: now,
        }),
        query: { tool, subjectRef, asOf: now },
        snapshot: sourceSnapshot(
          "command_center_brain",
          now,
          {
            deploymentRef: binding.deploymentRef,
            anchorRef: binding.anchorRef,
            tenantRef: binding.tenantRef,
            workspaceRef: binding.workspaceRef,
            principalRef,
            credentialOwnerRef: binding.credentialOwnerRef,
            accountRef: binding.brainServerRef,
            rootRef: tool,
          },
          [record],
        ),
      };
    }),
    sources,
    candidates,
    visitorIntent,
    staleDeals: [
      {
        dealRef: "deal:stale:1",
        accountRef: "account:stale:1",
        ownerPrincipalRef: principalRef,
        recipientEmail: "champion@example.edu",
        stage: "Proposal",
        lastVerifiedTouchAt: "2026-08-10T16:00:00.000Z",
        lastVerifiedTouchCitation: {
          source: "clarify",
          sourceRecordRef: sources.clarify.records[0].recordRef,
          evidenceHash: sources.clarify.records[0].evidenceHash,
          occurredAt: "2026-08-10T16:00:00.000Z",
        },
        evidenceHashes: [sources.clarify.records[0].evidenceHash],
        draftSubject: "Proposal follow-up",
        draftBody: "Hello champion,\n\nWould it be useful to review the proposal together?",
      },
    ],
    linkedinAcceptances:
      candidateCount > 0
        ? [
            {
              acceptanceRef: "linkedin:acceptance:1",
              candidateRef: "candidate:0001",
              ownerPrincipalRef: principalRef,
              acceptedAt: "2026-08-26T15:00:00.000Z",
              evidenceHash: sources.linkedin.records[0].evidenceHash,
              dmBody: "Thanks for connecting. Your advancement work caught my attention.",
              voiceEvidenceHash: sources.notion.records[0].evidenceHash,
            },
          ]
        : [],
    meetings: [
      {
        meetingRef: "meeting:advancement:1",
        accountRef: "account:0001",
        ownerPrincipalRef: principalRef,
        startAt: "2026-08-29T16:00:00.000Z",
        originalStartAt: "2026-08-29T16:00:00.000Z",
        previousStartAt: "2026-08-29T16:00:00.000Z",
        movedFromStartAt: null,
        status: "scheduled",
        eventVersion: 1,
        scheduleRevision: 1,
        previousEventVersion: 1,
        previousScheduleRevision: 1,
        changeStatus: "unchanged",
        recurringEventRef: null,
        cancelledAt: null,
        segment: "advancement",
        stage: "advancement",
        repositoryRef: binding.demoRepositoryRef,
        customizationEvidenceHash: null,
        calendarEvidenceHash: sources.calendar.records[0].evidenceHash,
      },
    ],
    notionArtifacts: [
      {
        artifactRef: "artifact:revenue:2026-08-26",
        rootRef: binding.notionRootRef,
        audience: notionAudience,
        title: "CEO revenue review",
        body: "Daily revenue evidence and proposed actions for review.",
        contentSummary: "Finalized revenue meeting evidence for the private CEO artifact.",
        transcriptSourceRecordRef: sources.transcripts.records[0].recordRef,
        transcriptEndedAt: "2026-08-26T15:45:00.000Z",
        transcriptFinalizedAt: now,
        evidenceHashes: [sources.transcripts.records[0].evidenceHash],
      },
    ],
    correlations: [
      ...candidates.map((entry, index) =>
        correlation(
          `correlation:${entry.candidateRef}:apollo`,
          "candidate",
          entry.candidateRef,
          "apollo",
          sources.apollo.records[index],
          {
            accountRef: entry.accountRef,
            contactRef: `email:${sha256Canonical(entry.contactEmail)}`,
            meetingOccurrenceRef: null,
          },
        ),
      ),
      correlation("correlation:deal:stale:1", "deal", "deal:stale:1", "clarify", sources.clarify.records[0], {
        accountRef: "account:stale:1",
        contactRef: `email:${sha256Canonical("champion@example.edu")}`,
        meetingOccurrenceRef: null,
      }),
      ...(candidateCount > 0
        ? [
            correlation(
              "correlation:linkedin:acceptance:1",
              "acceptance",
              "linkedin:acceptance:1",
              "linkedin",
              sources.linkedin.records[0],
              {
                accountRef: candidates[0].accountRef,
                contactRef: `linkedin:${sha256Canonical(candidates[0].linkedinProfileRef)}`,
                meetingOccurrenceRef: null,
              },
            ),
            correlation(
              "correlation:linkedin:acceptance:1:notion",
              "acceptance",
              "linkedin:acceptance:1",
              "notion",
              sources.notion.records[0],
              {
                accountRef: candidates[0].accountRef,
                contactRef: `linkedin:${sha256Canonical(candidates[0].linkedinProfileRef)}`,
                meetingOccurrenceRef: null,
              },
            ),
          ]
        : []),
      correlation(
        "correlation:meeting:advancement:1",
        "meeting",
        "meeting:advancement:1",
        "calendar",
        sources.calendar.records[0],
        { accountRef: "account:0001", contactRef: null, meetingOccurrenceRef },
      ),
      correlation(
        "correlation:artifact:revenue:2026-08-26",
        "artifact",
        "artifact:revenue:2026-08-26",
        "transcripts",
        sources.transcripts.records[0],
        { accountRef: null, contactRef: null, meetingOccurrenceRef: null },
      ),
      ...visitorIntent.flatMap((intent, index) =>
        ["rb2b", "google_analytics", "posthog"].map((source) =>
          correlation(
            `correlation:${intent.intentRef}:${source}`,
            "visitor_account",
            intent.intentRef,
            source,
            sources[source].records[index],
            { accountRef: intent.accountRef, contactRef: null, meetingOccurrenceRef: null },
          ),
        ),
      ),
    ],
  };
};

export const createRevenueProgramBoundaryFixture = (options) =>
  createRevenueProgramBoundaryFixtureForContractSuite(ceoRevenueProgramContractSuite, options);
