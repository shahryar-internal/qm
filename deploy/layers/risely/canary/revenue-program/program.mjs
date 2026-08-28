import {
  brainReadTools,
  assertRevenueProgramContractSuite,
  ceoRevenueProgramContractSuite,
  proposedEffectTypes,
  providerOwnerRefForNormalizedRevenueInput,
  revenueProgramPolicy,
  revenueSourceNames,
} from "./contracts.mjs";
import { compareCodepoints, fail, sha256Canonical } from "./validation.mjs";

const activeLedgerStates = new Set(["reserved", "proposed", "approved", "executed"]);
const builtRevenuePrograms = new WeakSet();
const revenueProgramContractSuites = new WeakMap();

export const isBuiltRevenueProgram = (value) =>
  value !== null && typeof value === "object" && builtRevenuePrograms.has(value);

export const assertBuiltRevenueProgramForContractSuite = (contractSuite, value) => {
  const contracts = assertRevenueProgramContractSuite(contractSuite);
  if (!isBuiltRevenueProgram(value) || revenueProgramContractSuites.get(value) !== contracts)
    fail("untrusted_program_instance");
  return value;
};
const staleThresholdDays = Object.freeze({
  Discovery: 7,
  HOT: 3,
  Proposal: 5,
  POC: 7,
  "Strategic POC": 10,
  Launching: 5,
  LIVE: 14,
});

const activeLedger = (input) =>
  input.ledger.filter((entry) => activeLedgerStates.has(entry.state) && entry.goalDate === input.goalDate);

const suppressionSet = (input, channel) =>
  new Set(
    input.suppressions
      .filter((entry) => entry.channel === channel)
      .flatMap((entry) => [entry.subjectRef, entry.stableRecipientIdentity]),
  );

const ledgerSubjects = (ledger, channel) =>
  new Set(ledger.filter((entry) => entry.channel === channel).map((entry) => entry.subjectRef));

const evidenceUniverse = (input) => {
  const hashes = new Set();
  for (const source of Object.values(input.sources)) {
    for (const record of source.records) hashes.add(record.evidenceHash);
  }
  for (const call of input.brain) {
    for (const record of call.snapshot.records) hashes.add(record.evidenceHash);
  }
  return hashes;
};

const snapshotEvidence = (snapshot) =>
  new Set(snapshot.status === "available" ? snapshot.records.map((record) => record.evidenceHash) : []);

const assertEvidenceBindings = (input, contracts) => {
  const universe = evidenceUniverse(input);
  const claims = [];
  for (const [source, snapshot] of Object.entries(input.sources)) {
    if (snapshot.evidenceHash) claims.push([snapshot.evidenceHash, `${source}:snapshot`]);
    for (const record of snapshot.records) claims.push([record.evidenceHash, `${source}:${record.recordRef}`]);
  }
  for (const call of input.brain) {
    if (call.snapshot.evidenceHash) claims.push([call.snapshot.evidenceHash, `${call.tool}:snapshot`]);
    for (const record of call.snapshot.records) claims.push([record.evidenceHash, `${call.tool}:${record.recordRef}`]);
  }
  if (new Set(claims.map(([hash]) => hash)).size !== claims.length) fail("evidence_provenance_collision");
  const groups = [
    ...input.candidates.map((candidate) => candidate.researchEvidenceHashes),
    ...input.visitorIntent.map((intent) => intent.evidenceHashes),
    ...input.staleDeals.map((deal) => deal.evidenceHashes),
    ...input.notionArtifacts.map((artifact) => artifact.evidenceHashes),
    ...input.meetings.map((meeting) =>
      meeting.customizationEvidenceHash
        ? [meeting.calendarEvidenceHash, meeting.customizationEvidenceHash]
        : [meeting.calendarEvidenceHash],
    ),
    ...input.linkedinAcceptances.map((acceptance) => [acceptance.evidenceHash, acceptance.voiceEvidenceHash]),
  ];
  if (groups.some((hashes) => hashes.some((hash) => !universe.has(hash)))) fail("unbound_evidence");
  const visitorSources = ["rb2b", "google_analytics", "posthog"];
  if (input.visitorIntent.length > 0 && visitorSources.some((source) => input.sources[source].status !== "available"))
    fail("visitor_intent_source_unavailable");
  for (const intent of input.visitorIntent) {
    if (
      intent.evidenceHashes.length !== visitorSources.length ||
      visitorSources.some((source) => {
        const observation = intent.observations.find((candidate) => candidate.source === source);
        const record = input.sources[source].records.find(
          (candidate) => candidate.recordRef === observation?.sourceRecordRef,
        );
        return !record || record.evidenceHash !== observation.evidenceHash;
      })
    )
      fail("visitor_intent_evidence_mismatch");
  }
  const dealEvidence = snapshotEvidence(input.sources.clarify);
  if (input.staleDeals.some((deal) => !deal.evidenceHashes.some((hash) => dealEvidence.has(hash))))
    fail("stale_deal_evidence_mismatch");
  const linkedinEvidence = snapshotEvidence(input.sources.linkedin);
  const notionEvidence = snapshotEvidence(input.sources.notion);
  if (
    input.linkedinAcceptances.some(
      (acceptance) =>
        !linkedinEvidence.has(acceptance.evidenceHash) || !notionEvidence.has(acceptance.voiceEvidenceHash),
    )
  )
    fail("linkedin_acceptance_evidence_mismatch");
  const calendarEvidence = snapshotEvidence(input.sources.calendar);
  if (input.meetings.some((meeting) => !calendarEvidence.has(meeting.calendarEvidenceHash)))
    fail("meeting_calendar_evidence_mismatch");
  const correlationsFor = (subjectType, subjectRef) =>
    input.correlations.filter((entry) => entry.subjectType === subjectType && entry.subjectRef === subjectRef);
  if (
    input.candidates.some((candidate) =>
      correlationsFor("candidate", candidate.candidateRef).every(
        (correlation) => !candidate.researchEvidenceHashes.includes(correlation.evidenceHash),
      ),
    )
  )
    fail("candidate_correlation_evidence_mismatch");
  for (const deal of input.staleDeals) {
    const citation = deal.lastVerifiedTouchCitation;
    if (deal.lastVerifiedTouchAt === null) continue;
    const snapshots =
      citation.source === "clarify" ? [input.sources.clarify] : input.brain.map((entry) => entry.snapshot);
    const record = snapshots
      .flatMap((snapshot) => snapshot.records)
      .find(
        (candidate) =>
          candidate.recordRef === citation.sourceRecordRef && candidate.evidenceHash === citation.evidenceHash,
      );
    const timestampFact = record?.facts.find(
      (fact) => fact.field === "last_verified_touch_at" && fact.value === deal.lastVerifiedTouchAt,
    );
    if (!record || !timestampFact || !deal.evidenceHashes.includes(citation.evidenceHash))
      fail("stale_touch_citation_mismatch");
  }
  if (
    input.notionArtifacts.some(
      (artifact) => artifact.rootRef !== input.binding.notionRootRef || artifact.audience !== contracts.notionAudience,
    )
  )
    fail("notion_private_root_mismatch");
};

const sourceHealth = (input) => {
  const sources = Object.freeze(
    revenueSourceNames.map((source) => {
      if (source === "command_center_brain") {
        const toolStatus = Object.freeze(
          brainReadTools.map((tool) => {
            const call = input.brain.find((candidate) => candidate.tool === tool);
            return Object.freeze({
              tool,
              status: call.snapshot.status,
              queryRef: call.queryRef,
              unavailableCode: call.snapshot.unavailableCode,
            });
          }),
        );
        const statuses = new Set(toolStatus.map((entry) => entry.status));
        return Object.freeze({
          source,
          status:
            statuses.has("unavailable") || statuses.size > 1
              ? "partial_or_unavailable"
              : statuses.has("available")
                ? "available"
                : "none",
          toolStatus,
        });
      }
      return Object.freeze({
        source,
        status: input.sources[source].status,
        unavailableCode: input.sources[source].unavailableCode,
      });
    }),
  );
  const blockers = sources
    .filter((source) => source.status === "unavailable" || source.status === "partial_or_unavailable")
    .map((source) => `source_unavailable:${source.source}`)
    .sort(compareCodepoints);
  return Object.freeze({ sources, blockers: Object.freeze(blockers) });
};

const idempotencyKey = (input, type, subjectRef, inboxRef, providerAccountRef, stableRecipientIdentity, contentHash) =>
  sha256Canonical({
    version: revenueProgramPolicy.version,
    deploymentRef: input.binding.deploymentRef,
    anchorRef: input.binding.anchorRef,
    tenantRef: input.binding.tenantRef,
    workspaceRef: input.binding.workspaceRef,
    principalRef: input.principal.principalRef,
    credentialOwnerRef: input.binding.credentialOwnerRef,
    providerAccountRef,
    stableRecipientIdentity,
    goalDate: input.goalDate,
    programRef: input.programRef,
    programRevision: input.programRevision,
    type,
    subjectRef,
    inboxRef,
    contentHash,
  });

const proposal = (
  input,
  type,
  subjectRef,
  content,
  evidenceHashes,
  providerAccountRef,
  stableRecipientIdentity,
  inboxRef = null,
  correlationSubjectRef = subjectRef,
) => {
  if (!proposedEffectTypes.includes(type)) fail("invalid_effect_type");
  const canonicalEvidenceHashes = [...new Set(evidenceHashes)].sort(compareCodepoints);
  const contentHash = sha256Canonical(content);
  const key = idempotencyKey(
    input,
    type,
    subjectRef,
    inboxRef,
    providerAccountRef,
    stableRecipientIdentity,
    contentHash,
  );
  const effectKey = sha256Canonical({
    idempotencyKey: key,
    providerAccountRef,
    credentialOwnerRef: input.binding.credentialOwnerRef,
    stableRecipientIdentity,
    payloadHash: contentHash,
    goalDate: input.goalDate,
    programRevision: input.programRevision,
  });
  const proposalRef = `proposal:${sha256Canonical({
    programRef: input.programRef,
    programRevision: input.programRevision,
    idempotencyKey: key,
    effectKey,
  })}`;
  const connectionBindingRef = `connection-binding:${sha256Canonical({
    deploymentRef: input.binding.deploymentRef,
    providerAccountRef,
    providerOwnerRef: providerOwnerRefForNormalizedRevenueInput(input, providerAccountRef),
  })}`;
  const correlationRefs = input.correlations
    .filter((correlation) => correlation.subjectRef === correlationSubjectRef)
    .map((correlation) => correlation.correlationRef)
    .sort(compareCodepoints);
  if (correlationRefs.length < 1) fail("proposal_correlation_missing");
  const correlatedEvidence = new Set(
    input.correlations
      .filter((correlation) => correlation.subjectRef === correlationSubjectRef)
      .map((correlation) => correlation.evidenceHash),
  );
  if (canonicalEvidenceHashes.some((evidenceHash) => !correlatedEvidence.has(evidenceHash)))
    fail("proposal_evidence_correlation_missing");
  return Object.freeze({
    proposalRef,
    type,
    subjectRef,
    inboxRef,
    providerAccountRef,
    connectionBindingRef,
    stableRecipientIdentity,
    content,
    contentHash,
    evidenceHashes: Object.freeze(canonicalEvidenceHashes),
    correlationRefs: Object.freeze(correlationRefs),
    idempotencyKey: key,
    effectKey,
    binding: Object.freeze({
      deploymentRef: input.binding.deploymentRef,
      anchorRef: input.binding.anchorRef,
      tenantRef: input.binding.tenantRef,
      workspaceRef: input.binding.workspaceRef,
      principalRef: input.binding.principalRef,
      credentialOwnerRef: input.binding.credentialOwnerRef,
    }),
    approvalRequired: true,
    approvalChannel: "slack",
    disposition: "unresolved",
    readiness: "blocked_connection_binding",
  });
};

const rankCandidates = (input) => {
  return [...input.candidates]
    .map((candidate) =>
      Object.freeze({
        candidate,
        score: candidate.priorityScore,
      }),
    )
    .sort(
      (left, right) =>
        right.score - left.score || compareCodepoints(left.candidate.candidateRef, right.candidate.candidateRef),
    );
};

const compileOutbound = (input, ledger, stalePlan) => {
  const activeColdEntries = ledger.filter((entry) => entry.channel === "cold_email");
  const activeGmailEntries = ledger.filter((entry) => new Set(["cold_email", "stale_email"]).has(entry.channel));
  const activeLinkedinEntries = ledger.filter((entry) => entry.channel === "linkedin_connection");
  const activeByInbox = new Map(stalePlan.inboxCounts);
  if (
    activeGmailEntries.length + stalePlan.proposals.length > revenueProgramPolicy.emailDailyMaximum ||
    [...activeByInbox.values()].some((count) => count > revenueProgramPolicy.inboxDailyMaximum) ||
    activeLinkedinEntries.length > revenueProgramPolicy.linkedinDailyTarget
  )
    fail("ledger_rate_limit_exceeded");
  if (input.sources.gmail.status !== "available") {
    return Object.freeze({
      selectedCandidateRefs: Object.freeze([]),
      proposals: Object.freeze([]),
      accounting: Object.freeze({
        email: Object.freeze({
          minimum: revenueProgramPolicy.emailDailyMinimum,
          maximum: revenueProgramPolicy.emailDailyMaximum,
          activeBefore: activeGmailEntries.length,
          coldActiveBefore: activeColdEntries.length,
          staleActiveBefore: activeGmailEntries.length - activeColdEntries.length,
          coldProposed: 0,
          staleProposed: 0,
          proposed: 0,
          totalAfterProposal: activeGmailEntries.length,
          minimumShortfall: Math.max(0, revenueProgramPolicy.emailDailyMinimum - activeGmailEntries.length),
          maximumRemaining: Math.max(0, revenueProgramPolicy.emailDailyMaximum - activeGmailEntries.length),
        }),
        linkedinConnection: Object.freeze({
          target: revenueProgramPolicy.linkedinDailyTarget,
          activeBefore: activeLinkedinEntries.length,
          proposed: 0,
          totalAfterProposal: activeLinkedinEntries.length,
          targetShortfall: Math.max(0, revenueProgramPolicy.linkedinDailyTarget - activeLinkedinEntries.length),
        }),
        inboxes: Object.freeze(
          [...activeByInbox.entries()].map(([inboxRef, totalAfterProposal]) =>
            Object.freeze({
              inboxRef,
              maximum: revenueProgramPolicy.inboxDailyMaximum,
              totalAfterProposal,
            }),
          ),
        ),
      }),
    });
  }
  const emailSuppressions = suppressionSet(input, "email");
  const linkedinSuppressions = suppressionSet(input, "linkedin_connection");
  const existingEmails = ledgerSubjects(ledger, "cold_email");
  const existingLinkedin = ledgerSubjects(ledger, "linkedin_connection");
  const emailCapacity = Math.max(
    0,
    revenueProgramPolicy.emailDailyMaximum - activeGmailEntries.length - stalePlan.proposals.length,
  );
  const ranked = rankCandidates(input);
  const unavailableRecipientIdentities = new Set([
    ...activeGmailEntries.map((entry) => entry.stableRecipientIdentity),
    ...stalePlan.proposals.map((entry) => entry.stableRecipientIdentity),
  ]);
  const selected = [];
  for (const rankedCandidate of ranked) {
    if (selected.length >= emailCapacity) break;
    const candidate = rankedCandidate.candidate;
    const stableRecipientIdentity = `email:${sha256Canonical(candidate.contactEmail)}`;
    if (
      emailSuppressions.has(candidate.candidateRef) ||
      emailSuppressions.has(stableRecipientIdentity) ||
      existingEmails.has(candidate.candidateRef) ||
      unavailableRecipientIdentities.has(stableRecipientIdentity)
    )
      continue;
    const current = activeByInbox.get(candidate.inboxRef) ?? 0;
    if (current >= revenueProgramPolicy.inboxDailyMaximum) continue;
    activeByInbox.set(candidate.inboxRef, current + 1);
    unavailableRecipientIdentities.add(stableRecipientIdentity);
    selected.push(rankedCandidate);
  }
  const emailProposals = selected.map(({ candidate, score }) =>
    proposal(
      input,
      "gmail.cold_email_draft",
      candidate.candidateRef,
      Object.freeze({
        to: candidate.contactEmail,
        inboxRef: candidate.inboxRef,
        mailboxEmail: input.binding.principalEmail,
        sequenceRef: candidate.sequenceRef,
        subject: candidate.emailSubject,
        body: candidate.emailBody,
        rankScore: score,
      }),
      candidate.researchEvidenceHashes,
      input.binding.googleAccountRef,
      `email:${sha256Canonical(candidate.contactEmail)}`,
      candidate.inboxRef,
    ),
  );
  const linkedinCapacity = Math.max(0, revenueProgramPolicy.linkedinDailyTarget - activeLinkedinEntries.length);
  const acceptedCandidates = new Set(input.linkedinAcceptances.map((acceptance) => acceptance.candidateRef));
  const linkedinCandidates = selected
    .filter(
      ({ candidate }) =>
        candidate.linkedinProfileRef !== null &&
        input.sources.linkedin.status === "available" &&
        !acceptedCandidates.has(candidate.candidateRef) &&
        !linkedinSuppressions.has(candidate.candidateRef) &&
        !linkedinSuppressions.has(`linkedin:${sha256Canonical(candidate.linkedinProfileRef)}`) &&
        !existingLinkedin.has(candidate.candidateRef),
    )
    .slice(0, linkedinCapacity);
  const linkedinProposals = linkedinCandidates.map(({ candidate, score }) =>
    proposal(
      input,
      "linkedin.connection_request",
      candidate.candidateRef,
      Object.freeze({
        linkedinProfileRef: candidate.linkedinProfileRef,
        rankScore: score,
      }),
      candidate.researchEvidenceHashes,
      input.binding.linkedinAccountRef,
      `linkedin:${sha256Canonical(candidate.linkedinProfileRef)}`,
    ),
  );
  const totalEmails = activeGmailEntries.length + stalePlan.proposals.length + emailProposals.length;
  const totalLinkedin = activeLinkedinEntries.length + linkedinProposals.length;
  return Object.freeze({
    selectedCandidateRefs: Object.freeze(selected.map(({ candidate }) => candidate.candidateRef)),
    proposals: Object.freeze([...emailProposals, ...linkedinProposals]),
    accounting: Object.freeze({
      email: Object.freeze({
        minimum: revenueProgramPolicy.emailDailyMinimum,
        maximum: revenueProgramPolicy.emailDailyMaximum,
        activeBefore: activeGmailEntries.length,
        coldActiveBefore: activeColdEntries.length,
        staleActiveBefore: activeGmailEntries.length - activeColdEntries.length,
        coldProposed: emailProposals.length,
        staleProposed: stalePlan.proposals.length,
        proposed: emailProposals.length + stalePlan.proposals.length,
        totalAfterProposal: totalEmails,
        minimumShortfall: Math.max(0, revenueProgramPolicy.emailDailyMinimum - totalEmails),
        maximumRemaining: Math.max(0, revenueProgramPolicy.emailDailyMaximum - totalEmails),
      }),
      linkedinConnection: Object.freeze({
        target: revenueProgramPolicy.linkedinDailyTarget,
        activeBefore: activeLinkedinEntries.length,
        proposed: linkedinProposals.length,
        totalAfterProposal: totalLinkedin,
        targetShortfall: Math.max(0, revenueProgramPolicy.linkedinDailyTarget - totalLinkedin),
      }),
      inboxes: Object.freeze(
        [...activeByInbox.entries()]
          .sort(([left], [right]) => compareCodepoints(left, right))
          .map(([inboxRef, totalAfterProposal]) =>
            Object.freeze({ inboxRef, maximum: revenueProgramPolicy.inboxDailyMaximum, totalAfterProposal }),
          ),
      ),
    }),
  });
};

const staleOrder = (left, right) => {
  const leftTime = left.lastVerifiedTouchAt ? new Date(left.lastVerifiedTouchAt).valueOf() : 0;
  const rightTime = right.lastVerifiedTouchAt ? new Date(right.lastVerifiedTouchAt).valueOf() : 0;
  return leftTime - rightTime || compareCodepoints(left.dealRef, right.dealRef);
};

const compileStaleDeals = (input, ledger) => {
  const activeGmailEntries = ledger.filter((entry) => new Set(["cold_email", "stale_email"]).has(entry.channel));
  const inboxCounts = new Map(input.inboxes.map((inbox) => [inbox.inboxRef, 0]));
  for (const entry of activeGmailEntries) inboxCounts.set(entry.inboxRef, inboxCounts.get(entry.inboxRef) + 1);
  if (input.sources.gmail.status !== "available")
    return Object.freeze({ proposals: Object.freeze([]), inboxCounts: Object.freeze([...inboxCounts]) });
  const suppressed = suppressionSet(input, "email");
  const existing = ledgerSubjects(ledger, "stale_email");
  const now = new Date(input.now).valueOf();
  const recipientIdentities = new Set(activeGmailEntries.map((entry) => entry.stableRecipientIdentity));
  const stale = input.staleDeals
    .filter((deal) => {
      const threshold = staleThresholdDays[deal.stage] * 86_400_000;
      return deal.lastVerifiedTouchAt !== null && now - new Date(deal.lastVerifiedTouchAt).valueOf() >= threshold;
    })
    .filter(
      (deal) =>
        !suppressed.has(deal.dealRef) &&
        !suppressed.has(`email:${sha256Canonical(deal.recipientEmail)}`) &&
        !existing.has(deal.dealRef),
    )
    .sort(staleOrder);
  const proposals = [];
  for (const deal of stale) {
    if (
      proposals.length >= revenueProgramPolicy.staleDealDailyMaximum ||
      activeGmailEntries.length + proposals.length >= revenueProgramPolicy.emailDailyMaximum
    )
      break;
    const stableRecipientIdentity = `email:${sha256Canonical(deal.recipientEmail)}`;
    if (recipientIdentities.has(stableRecipientIdentity)) continue;
    const inbox = [...inboxCounts.entries()]
      .filter(([, count]) => count < revenueProgramPolicy.inboxDailyMaximum)
      .sort(
        ([leftRef, leftCount], [rightRef, rightCount]) =>
          leftCount - rightCount || compareCodepoints(leftRef, rightRef),
      )[0];
    if (!inbox) break;
    const [inboxRef, count] = inbox;
    proposals.push(
      proposal(
        input,
        "gmail.stale_deal_followup_draft",
        deal.dealRef,
        Object.freeze({
          to: deal.recipientEmail,
          inboxRef,
          mailboxEmail: input.binding.principalEmail,
          subject: deal.draftSubject,
          body: deal.draftBody,
          stage: deal.stage,
          lastVerifiedTouchAt: deal.lastVerifiedTouchAt,
        }),
        deal.evidenceHashes,
        input.binding.googleAccountRef,
        stableRecipientIdentity,
        inboxRef,
      ),
    );
    recipientIdentities.add(stableRecipientIdentity);
    inboxCounts.set(inboxRef, count + 1);
  }
  return Object.freeze({ proposals: Object.freeze(proposals), inboxCounts: Object.freeze([...inboxCounts]) });
};

const compileLinkedinDms = (input, ledger) => {
  if (input.sources.linkedin.status !== "available" || input.sources.notion.status !== "available")
    return Object.freeze([]);
  const suppressed = suppressionSet(input, "linkedin_dm");
  const existing = ledgerSubjects(ledger, "linkedin_dm");
  const candidates = new Map(input.candidates.map((candidate) => [candidate.candidateRef, candidate]));
  return Object.freeze(
    input.linkedinAcceptances
      .filter(
        (acceptance) =>
          !suppressed.has(acceptance.candidateRef) &&
          !suppressed.has(acceptance.acceptanceRef) &&
          !suppressed.has(`linkedin:${sha256Canonical(candidates.get(acceptance.candidateRef).linkedinProfileRef)}`) &&
          !existing.has(acceptance.acceptanceRef),
      )
      .slice(0, revenueProgramPolicy.linkedinDmDailyMaximum)
      .map((acceptance) => {
        const candidate = candidates.get(acceptance.candidateRef);
        return proposal(
          input,
          "linkedin.dm_draft",
          acceptance.acceptanceRef,
          Object.freeze({
            linkedinProfileRef: candidate.linkedinProfileRef,
            acceptedAt: acceptance.acceptedAt,
            body: acceptance.dmBody,
          }),
          [acceptance.evidenceHash, acceptance.voiceEvidenceHash],
          input.binding.linkedinAccountRef,
          `linkedin:${sha256Canonical(candidate.linkedinProfileRef)}`,
        );
      }),
  );
};

const compileDemoReminders = (input, ledger) => {
  if (input.sources.calendar.status !== "available") return Object.freeze([]);
  const existingReminders = ledgerSubjects(ledger, "demo_reminder");
  const existingCustomizations = ledgerSubjects(ledger, "demo_customization");
  const now = new Date(input.now).valueOf();
  const proposals = [];
  for (const meeting of input.meetings) {
    if (meeting.status !== "scheduled") continue;
    const start = new Date(meeting.startAt).valueOf();
    const due = start - revenueProgramPolicy.demoReminderLeadMilliseconds;
    if (now < due || now >= due + revenueProgramPolicy.demoReminderWindowMilliseconds) continue;
    if (meeting.customizationEvidenceHash !== null) fail("untrusted_demo_customization_evidence");
    const readiness = "not_verified";
    const evidenceHashes = [meeting.calendarEvidenceHash];
    const scheduleIdentity = `meeting-schedule:${sha256Canonical({
      occurrenceRef: meeting.occurrenceRef,
      eventVersion: meeting.eventVersion,
      scheduleRevision: meeting.scheduleRevision,
      startAt: meeting.startAt,
    })}`;
    const stableMeetingIdentity = `meeting:${sha256Canonical({
      occurrenceRef: meeting.occurrenceRef,
      eventVersion: meeting.eventVersion,
      scheduleRevision: meeting.scheduleRevision,
    })}`;
    if (!existingReminders.has(scheduleIdentity))
      proposals.push(
        proposal(
          input,
          "slack.demo_reminder",
          scheduleIdentity,
          Object.freeze({
            meetingRef: meeting.meetingRef,
            occurrenceRef: meeting.occurrenceRef,
            accountRef: meeting.accountRef,
            startAt: meeting.startAt,
            originalStartAt: meeting.originalStartAt,
            eventVersion: meeting.eventVersion,
            scheduleRevision: meeting.scheduleRevision,
            recurringEventRef: meeting.recurringEventRef,
            segment: meeting.segment,
            readiness,
          }),
          evidenceHashes,
          input.binding.workspaceRef,
          stableMeetingIdentity,
          null,
          meeting.meetingRef,
        ),
      );
    if (!existingCustomizations.has(scheduleIdentity))
      proposals.push(
        proposal(
          input,
          "demo.customization_review",
          scheduleIdentity,
          Object.freeze({
            meetingRef: meeting.meetingRef,
            occurrenceRef: meeting.occurrenceRef,
            startAt: meeting.startAt,
            eventVersion: meeting.eventVersion,
            scheduleRevision: meeting.scheduleRevision,
            repositoryRef: meeting.repositoryRef,
            requestedOperation: "review_only",
            repositoryAccess: "read_only",
            readiness,
          }),
          evidenceHashes,
          input.binding.demoRepositoryRef,
          stableMeetingIdentity,
          null,
          meeting.meetingRef,
        ),
      );
    if (proposals.length >= revenueProgramPolicy.demoDailyMaximum * 2) break;
  }
  return Object.freeze(proposals);
};

const compileNotionArtifacts = (input, ledger) => {
  if (input.sources.notion.status !== "available") return Object.freeze([]);
  const existing = ledgerSubjects(ledger, "notion_artifact");
  const visitorArtifacts = input.visitorIntent
    .filter((intent) => !existing.has(intent.intentRef))
    .map((intent) =>
      proposal(
        input,
        "notion.revenue_artifact",
        intent.intentRef,
        Object.freeze({
          artifactKind: "visitor_account_research",
          rootRef: input.binding.notionRootRef,
          audience: "private_ceo",
          accountRef: intent.accountRef,
          accountDomain: intent.accountDomain,
          boundedIntentScore: intent.score,
          observations: intent.observations,
          parentScope: "exact_bound_root",
        }),
        intent.evidenceHashes,
        input.binding.notionRootRef,
        `account-domain:${sha256Canonical(intent.accountDomain)}`,
      ),
    );
  const providedArtifacts = input.notionArtifacts
    .filter((artifact) => !existing.has(artifact.artifactRef))
    .map((artifact) =>
      proposal(
        input,
        "notion.revenue_artifact",
        artifact.artifactRef,
        Object.freeze({
          artifactKind: "provided_revenue_artifact",
          rootRef: input.binding.notionRootRef,
          audience: "private_ceo",
          title: artifact.title,
          body: artifact.body,
          contentSummary: artifact.contentSummary,
          transcriptSourceRecordRef: artifact.transcriptSourceRecordRef,
          transcriptEndedAt: artifact.transcriptEndedAt,
          transcriptFinalizedAt: artifact.transcriptFinalizedAt,
          parentScope: "exact_bound_root",
        }),
        artifact.evidenceHashes,
        input.binding.notionRootRef,
        `artifact:${sha256Canonical(artifact.artifactRef)}`,
      ),
    );
  return Object.freeze(
    [...visitorArtifacts, ...providedArtifacts]
      .sort((left, right) => compareCodepoints(left.proposalRef, right.proposalRef))
      .slice(0, revenueProgramPolicy.notionArtifactDailyMaximum),
  );
};

export const buildRevenueProgramForContractSuite = (contractSuite, rawInput) => {
  const contracts = assertRevenueProgramContractSuite(contractSuite);
  const input = contracts.normalizeRevenueProgramInput(rawInput);
  assertEvidenceBindings(input, contracts);
  const ledger = activeLedger(input);
  const stalePlan = compileStaleDeals(input, ledger);
  const outbound = compileOutbound(input, ledger, stalePlan);
  const staleDeals = stalePlan.proposals;
  const linkedinDms = compileLinkedinDms(input, ledger);
  const demoReminders = compileDemoReminders(input, ledger);
  const notionArtifacts = compileNotionArtifacts(input, ledger);
  const proposals = [...outbound.proposals, ...staleDeals, ...linkedinDms, ...demoReminders, ...notionArtifacts].sort(
    (left, right) => compareCodepoints(left.proposalRef, right.proposalRef),
  );
  if (proposals.length > revenueProgramPolicy.maximumProgramProposals) fail("proposal_budget_exceeded");
  if (new Set(proposals.map((entry) => entry.idempotencyKey)).size !== proposals.length) fail("duplicate_proposal");
  const globalReferences = [...input.boundaryReferences, ...proposals.map((entry) => entry.proposalRef)];
  if (new Set(globalReferences).size !== globalReferences.length) fail("global_reference_collision");
  const health = sourceHealth(input);
  const program = Object.freeze({
    version: revenueProgramPolicy.version,
    programRef: input.programRef,
    programRevision: input.programRevision,
    goalDate: input.goalDate,
    timeZone: input.timeZone,
    createdAt: input.now,
    inputHash: input.inputHash,
    principalBinding: input.binding,
    connectionBindings: Object.freeze(
      [
        ...Object.entries(contracts.deploymentConnectionAnchors).map(([anchorKey, providerAccountRef]) => ({
          providerAccountRef,
          providerOwnerRef: contracts.deploymentConnectionOwnerRefs[anchorKey],
        })),
        {
          providerAccountRef: input.binding.workspaceRef,
          providerOwnerRef: contracts.deploymentConnectionOwnerRefs.workspaceRef,
        },
      ]
        .sort((left, right) => compareCodepoints(left.providerAccountRef, right.providerAccountRef))
        .map(({ providerAccountRef, providerOwnerRef }) =>
          Object.freeze({
            connectionBindingRef: `connection-binding:${sha256Canonical({
              deploymentRef: input.binding.deploymentRef,
              providerAccountRef,
              providerOwnerRef,
            })}`,
            providerAccountRef,
            providerOwnerRef,
            status: "unresolved",
            trustedReceiptRequired: true,
          }),
        ),
    ),
    sourceHealth: health,
    correlations: input.correlations,
    accounting: outbound.accounting,
    selectedCandidateRefs: outbound.selectedCandidateRefs,
    proposals: Object.freeze(proposals),
    safety: Object.freeze({
      disposition: "unresolved_proposals",
      commandCenterAccess: "read_only",
      gmailAccess: "draft_proposal_only",
      linkedinAccess: "proposal_only",
      crmAccess: "read_only",
      notionAccess: "artifact_proposal_only",
      demoRepositoryAccess: "read_only",
    }),
  });
  const built = Object.freeze({ ...program, programHash: sha256Canonical(program) });
  builtRevenuePrograms.add(built);
  revenueProgramContractSuites.set(built, contracts);
  return built;
};

export const buildRevenueProgram = (rawInput) =>
  buildRevenueProgramForContractSuite(ceoRevenueProgramContractSuite, rawInput);
