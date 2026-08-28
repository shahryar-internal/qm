import assert from "node:assert/strict";
import test from "node:test";
import {
  brainReadTools,
  buildRevenueProgram,
  createRevenueProgramBoundaryFixture,
  evaluationGateCriteria,
  initializeRevenueProgramState,
  presentRevenueProgram,
  prospectiveEvaluatorRegistry,
  prospectiveReconciliationContract,
  providerCitationReference,
  providerCorrelationReference,
  providerRecordReference,
  recordRevenueProgramApproval,
  recordRevenueProgramEvaluation,
  requestRevenueProgramApproval,
  requestRevenueProgramEvaluation,
  RevenueProgramError,
  sha256Canonical,
  snapshotPlainJson,
  verifyRevenueProgramOutput,
} from "../../canary/revenue-program/index.mjs";

const clone = (value) => structuredClone(value);
const hash = (value) => sha256Canonical({ test: value });
const typeCount = (program, type) => program.proposals.filter((proposal) => proposal.type === type).length;
const programWithoutHash = (program) =>
  Object.fromEntries(Object.entries(program).filter(([key]) => key !== "programHash"));

const ledgerEntry = (fixture, overrides = {}) => ({
  entryRef: "ledger:1",
  idempotencyKey: hash("ledger:1"),
  deploymentRef: fixture.binding.deploymentRef,
  anchorRef: fixture.binding.anchorRef,
  tenantRef: fixture.binding.tenantRef,
  workspaceRef: fixture.binding.workspaceRef,
  principalRef: fixture.binding.principalRef,
  credentialOwnerRef: fixture.binding.credentialOwnerRef,
  goalDate: fixture.goalDate,
  channel: "cold_email",
  state: "proposed",
  subjectRef: "candidate:0001",
  recipient: {
    kind: "email",
    value: "buyer0001@example.edu",
    eventVersion: null,
    scheduleRevision: null,
    startAt: null,
  },
  providerAccountRef: fixture.binding.googleAccountRef,
  inboxRef: "inbox:1",
  createdAt: "2026-08-26T15:00:00.000Z",
  ...overrides,
});

const evaluationRequest = (record, requestRef = "evaluation-request:1") => ({
  requestRef,
  expectedRevision: record.revision,
  expectedFenceRef: record.durableFenceRef,
  programHash: record.programHash,
});

const approvalRequest = (record, proposal, overrides = {}) => {
  const request = {
    requestRef: "approval-request:1",
    expectedRevision: record.revision,
    expectedFenceRef: record.durableFenceRef,
    programHash: record.programHash,
    proposalRef: proposal.proposalRef,
    teamRef: "slack-team:risely",
    userRef: "slack-user:ceo",
    audienceRef: "slack-audience:ceo-private",
    messageRef: "slack-message:1",
    interactionRef: "slack-interaction:1",
    actionId: "approve_proposal",
    ...overrides,
  };
  request.payloadHash = sha256Canonical({
    programHash: record.programHash,
    programRevision: record.programRevision,
    expectedRevision: record.revision,
    expectedFenceRef: record.durableFenceRef,
    proposalRef: proposal.proposalRef,
    proposalContentHash: proposal.contentHash,
    teamRef: request.teamRef,
    userRef: request.userRef,
    audienceRef: request.audienceRef,
    messageRef: request.messageRef,
    interactionRef: request.interactionRef,
    actionId: request.actionId,
  });
  return request;
};

const requalifyRecord = (source, binding, record) => {
  const previousRecordRef = record.recordRef;
  record.recordRef = providerRecordReference({
    providerAccountRef: binding.accountRef,
    rootRef: binding.rootRef,
    source,
    observedAt: record.observedAt,
    facts: record.facts,
  });
  for (const fact of record.facts)
    fact.citationRef = providerCitationReference({
      providerAccountRef: binding.accountRef,
      source,
      recordRef: record.recordRef,
      field: fact.field,
    });
  return previousRecordRef;
};

const refreshSourceRecord = (fixture, source, record) => {
  const snapshot = fixture.sources[source];
  const previousRecordRef = requalifyRecord(source, snapshot.binding, record);
  for (const intent of fixture.visitorIntent)
    for (const observation of intent.observations)
      if (observation.source === source && observation.sourceRecordRef === previousRecordRef)
        observation.sourceRecordRef = record.recordRef;
  for (const deal of fixture.staleDeals)
    if (
      deal.lastVerifiedTouchCitation.source === source &&
      deal.lastVerifiedTouchCitation.sourceRecordRef === previousRecordRef
    )
      deal.lastVerifiedTouchCitation.sourceRecordRef = record.recordRef;
  for (const artifact of fixture.notionArtifacts)
    if (artifact.transcriptSourceRecordRef === previousRecordRef) artifact.transcriptSourceRecordRef = record.recordRef;
  for (const correlation of fixture.correlations) {
    if (correlation.source !== source || correlation.sourceRecordRef !== previousRecordRef) continue;
    correlation.sourceRecordRef = record.recordRef;
    correlation.factCitationRefs = record.facts.map((fact) => fact.citationRef).sort();
    correlation.correlationRef = providerCorrelationReference({
      providerAccountRef: correlation.providerAccountRef,
      source,
      sourceRecordRef: record.recordRef,
      subjectType: correlation.subjectType,
      subjectRef: correlation.subjectRef,
    });
  }
};

const syncMeetingEvidence = (fixture) => {
  const meeting = fixture.meetings[0];
  const occurrenceRef = `occurrence:${sha256Canonical({
    meetingRef: meeting.meetingRef,
    originalStartAt: meeting.originalStartAt,
    recurringEventRef: meeting.recurringEventRef,
  })}`;
  const facts = new Map(fixture.sources.calendar.records[0].facts.map((fact) => [fact.field, fact]));
  facts.get("account_ref").value = meeting.accountRef;
  facts.get("meeting_ref").value = meeting.meetingRef;
  facts.get("occurrence_ref").value = occurrenceRef;
  facts.get("start_at").value = meeting.startAt;
  facts.get("original_start_at").value = meeting.originalStartAt;
  facts.get("previous_start_at").value = meeting.previousStartAt;
  facts.get("moved_from_start_at").value = meeting.movedFromStartAt ?? "none";
  facts.get("cancelled_at").value = meeting.cancelledAt ?? "none";
  facts.get("status").value = meeting.status;
  facts.get("change_status").value = meeting.changeStatus;
  facts.get("event_version").value = String(meeting.eventVersion);
  facts.get("schedule_revision").value = String(meeting.scheduleRevision);
  facts.get("previous_event_version").value = String(meeting.previousEventVersion);
  facts.get("previous_schedule_revision").value = String(meeting.previousScheduleRevision);
  const correlation = fixture.correlations.find((entry) => entry.subjectType === "meeting");
  correlation.accountRef = meeting.accountRef;
  correlation.meetingOccurrenceRef = occurrenceRef;
  refreshSourceRecord(fixture, "calendar", fixture.sources.calendar.records[0]);
};

test("builds a completely unresolved provider-free revenue program", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture());
  assert.equal(program.accounting.email.coldProposed, 120);
  assert.equal(program.accounting.email.staleProposed, 1);
  assert.equal(program.accounting.email.totalAfterProposal, 121);
  assert.equal(program.accounting.linkedinConnection.proposed, 20);
  assert.equal(typeCount(program, "gmail.cold_email_draft"), 120);
  assert.equal(typeCount(program, "gmail.stale_deal_followup_draft"), 1);
  assert.equal(typeCount(program, "linkedin.connection_request"), 20);
  assert.equal(typeCount(program, "linkedin.dm_draft"), 1);
  assert.equal(typeCount(program, "slack.demo_reminder"), 1);
  assert.equal(typeCount(program, "demo.customization_review"), 1);
  assert.equal(typeCount(program, "notion.revenue_artifact"), 4);
  assert.equal(program.safety.disposition, "unresolved_proposals");
  assert.equal(program.safety.commandCenterAccess, "read_only");
  assert.ok(program.proposals.every((proposal) => proposal.disposition === "unresolved"));
  assert.ok(program.proposals.every((proposal) => proposal.correlationRefs.length > 0));
  assert.ok(program.proposals.every((proposal) => !Object.hasOwn(proposal, "execution")));
});

test("normalization produces stable hashes across input ordering", () => {
  const first = createRevenueProgramBoundaryFixture();
  const second = clone(first);
  second.candidates.reverse();
  second.visitorIntent.reverse();
  second.brain.reverse();
  second.correlations.reverse();
  assert.equal(buildRevenueProgram(first).programHash, buildRevenueProgram(second).programHash);
});

test("applies the 100 to 200 limit to every Gmail draft combined", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture({ candidateCount: 250 }));
  assert.equal(program.accounting.email.totalAfterProposal, 200);
  assert.equal(program.accounting.email.coldProposed, 199);
  assert.equal(program.accounting.email.staleProposed, 1);
  assert.ok(program.accounting.inboxes.every((inbox) => inbox.totalAfterProposal <= 50));
});

test("reports a total Gmail shortfall without inventing work", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture({ candidateCount: 80 }));
  assert.equal(program.accounting.email.totalAfterProposal, 81);
  assert.equal(program.accounting.email.minimumShortfall, 19);
});

test("distributes stale drafts across the least-used inboxes", () => {
  const fixture = createRevenueProgramBoundaryFixture({ candidateCount: 0 });
  fixture.linkedinAcceptances = [];
  fixture.correlations = fixture.correlations.filter((entry) => entry.subjectType !== "acceptance");
  const base = fixture.staleDeals[0];
  fixture.staleDeals = Array.from({ length: 8 }, (_, index) => ({
    ...clone(base),
    dealRef: `deal:stale:${index + 1}`,
    accountRef: `account:stale:${index + 1}`,
    recipientEmail: `champion${index + 1}@example.edu`,
  }));
  const baseRecord = fixture.sources.clarify.records[0];
  fixture.sources.clarify.records = fixture.staleDeals.map((deal, index) => {
    const record = clone(baseRecord);
    record.evidenceHash = hash(`clarify:deal:stale:${index + 1}`);
    for (const fact of record.facts) {
      if (fact.field === "deal_ref") fact.value = deal.dealRef;
      if (fact.field === "account_ref") fact.value = deal.accountRef;
      if (fact.field === "contact_email") fact.value = deal.recipientEmail;
    }
    requalifyRecord("clarify", fixture.sources.clarify.binding, record);
    deal.evidenceHashes = [record.evidenceHash];
    deal.lastVerifiedTouchCitation.sourceRecordRef = record.recordRef;
    deal.lastVerifiedTouchCitation.evidenceHash = record.evidenceHash;
    return record;
  });
  fixture.correlations = fixture.correlations.filter((entry) => entry.subjectType !== "deal");
  fixture.correlations.push(
    ...fixture.staleDeals.map((deal, index) => ({
      ...clone(fixture.correlations.find((entry) => entry.subjectType === "artifact")),
      correlationRef: providerCorrelationReference({
        providerAccountRef: fixture.sources.clarify.binding.accountRef,
        source: "clarify",
        sourceRecordRef: fixture.sources.clarify.records[index].recordRef,
        subjectType: "deal",
        subjectRef: deal.dealRef,
      }),
      providerAccountRef: fixture.sources.clarify.binding.accountRef,
      source: "clarify",
      sourceRecordRef: fixture.sources.clarify.records[index].recordRef,
      subjectType: "deal",
      subjectRef: deal.dealRef,
      accountRef: deal.accountRef,
      contactRef: `email:${sha256Canonical(deal.recipientEmail)}`,
      meetingOccurrenceRef: null,
      evidenceHash: fixture.sources.clarify.records[index].evidenceHash,
      factCitationRefs: fixture.sources.clarify.records[index].facts.map((fact) => fact.citationRef).sort(),
    })),
  );
  const proposals = buildRevenueProgram(fixture).proposals.filter(
    (proposal) => proposal.type === "gmail.stale_deal_followup_draft",
  );
  assert.equal(proposals.length, 8);
  assert.equal(new Set(proposals.map((proposal) => proposal.inboxRef)).size, 4);
});

test("deduplicates canonical email and profile identities", () => {
  const profile = createRevenueProgramBoundaryFixture();
  profile.candidates[1].linkedinProfileRef = profile.candidates[0].linkedinProfileRef.toUpperCase();
  assert.throws(() => buildRevenueProgram(profile), /duplicate_candidate/);
  const email = createRevenueProgramBoundaryFixture();
  email.staleDeals[0].recipientEmail = email.candidates[0].contactEmail;
  email.sources.clarify.records[0].facts.find((fact) => fact.field === "contact_email").value =
    email.candidates[0].contactEmail;
  email.correlations.find((entry) => entry.subjectType === "deal").contactRef =
    `email:${sha256Canonical(email.candidates[0].contactEmail)}`;
  refreshSourceRecord(email, "clarify", email.sources.clarify.records[0]);
  const program = buildRevenueProgram(email);
  assert.equal(
    program.proposals.some(
      (proposal) => proposal.type === "gmail.cold_email_draft" && proposal.subjectRef === "candidate:0001",
    ),
    false,
  );
});

test("derives ledger identity and deduplicates cold and stale Gmail workflows", () => {
  const fixture = createRevenueProgramBoundaryFixture();
  fixture.staleDeals[0].recipientEmail = fixture.candidates[0].contactEmail;
  fixture.sources.clarify.records[0].facts.find((fact) => fact.field === "contact_email").value =
    fixture.candidates[0].contactEmail;
  fixture.correlations.find((entry) => entry.subjectType === "deal").contactRef =
    `email:${sha256Canonical(fixture.candidates[0].contactEmail)}`;
  refreshSourceRecord(fixture, "clarify", fixture.sources.clarify.records[0]);
  fixture.ledger.push(ledgerEntry(fixture));
  const program = buildRevenueProgram(fixture);
  assert.equal(
    program.proposals.some(
      (proposal) =>
        proposal.type.startsWith("gmail.") &&
        proposal.stableRecipientIdentity === `email:${sha256Canonical(fixture.candidates[0].contactEmail)}`,
    ),
    false,
  );
});

test("never proposes a connection request for an accepted connection", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture());
  assert.equal(
    program.proposals.some(
      (proposal) => proposal.type === "linkedin.connection_request" && proposal.subjectRef === "candidate:0001",
    ),
    false,
  );
  assert.equal(typeCount(program, "linkedin.connection_request"), 20);
});

test("binds idempotency to provider account, credential owner, stable recipient, day, payload, and revision", () => {
  const firstFixture = createRevenueProgramBoundaryFixture({ candidateCount: 2 });
  firstFixture.staleDeals = [];
  firstFixture.linkedinAcceptances = [];
  firstFixture.meetings = [];
  firstFixture.notionArtifacts = [];
  firstFixture.visitorIntent = [];
  firstFixture.correlations = firstFixture.correlations.filter((entry) => entry.subjectType === "candidate");
  const first = buildRevenueProgram(firstFixture);
  const revisedFixture = clone(firstFixture);
  revisedFixture.programRevision = 1;
  const revised = buildRevenueProgram(revisedFixture);
  const firstEmail = first.proposals.find((proposal) => proposal.type === "gmail.cold_email_draft");
  const revisedEmail = revised.proposals.find((proposal) => proposal.type === "gmail.cold_email_draft");
  assert.notEqual(firstEmail.idempotencyKey, revisedEmail.idempotencyKey);
  assert.equal(firstEmail.providerAccountRef, firstFixture.binding.googleAccountRef);
  assert.equal(firstEmail.binding.credentialOwnerRef, firstFixture.binding.credentialOwnerRef);
  assert.match(firstEmail.stableRecipientIdentity, /^email:[0-9a-f]{64}$/);
});

test("suppression and bound durable ledger prevent duplicate preparation", () => {
  const fixture = createRevenueProgramBoundaryFixture();
  fixture.suppressions.push({
    entryRef: "suppression:1",
    tenantRef: fixture.binding.tenantRef,
    workspaceRef: fixture.binding.workspaceRef,
    principalRef: fixture.binding.principalRef,
    channel: "email",
    subjectRef: "candidate:0002",
    stableRecipientIdentity: `email:${sha256Canonical("buyer0002@example.edu")}`,
    reason: "opt_out",
    effectiveAt: "2026-08-26T15:00:00.000Z",
    evidenceHash: hash("suppression:1"),
  });
  fixture.ledger.push(ledgerEntry(fixture));
  const program = buildRevenueProgram(fixture);
  const subjects = new Set(
    program.proposals
      .filter((proposal) => proposal.type === "gmail.cold_email_draft")
      .map((proposal) => proposal.subjectRef),
  );
  assert.equal(subjects.has("candidate:0001"), false);
  assert.equal(subjects.has("candidate:0002"), false);
  assert.equal(program.accounting.email.activeBefore, 1);
});

test("rejects ledger binding, recipient, duplicate, provider, and rate violations", () => {
  const independent = createRevenueProgramBoundaryFixture();
  const independentEntry = ledgerEntry(independent);
  independentEntry.stableRecipientIdentity = `email:${hash("attacker")}`;
  independent.ledger = [independentEntry];
  assert.throws(() => buildRevenueProgram(independent), /invalid_ledger_entry/);
  const binding = createRevenueProgramBoundaryFixture();
  binding.ledger = [ledgerEntry(binding, { workspaceRef: "workspace:other" })];
  assert.throws(() => buildRevenueProgram(binding), /ledger_binding_mismatch/);
  const provider = createRevenueProgramBoundaryFixture();
  provider.ledger = [ledgerEntry(provider, { providerAccountRef: provider.binding.linkedinAccountRef })];
  assert.throws(() => buildRevenueProgram(provider), /ledger_provider_mismatch/);
  const duplicate = createRevenueProgramBoundaryFixture();
  const first = ledgerEntry(duplicate);
  duplicate.ledger = [
    first,
    ledgerEntry(duplicate, {
      entryRef: "ledger:2",
      idempotencyKey: hash("ledger:2"),
      subjectRef: "candidate:0002",
      recipient: first.recipient,
      inboxRef: "inbox:2",
    }),
  ];
  assert.throws(() => buildRevenueProgram(duplicate), /ledger_recipient_subject_mismatch/);
  const overflow = createRevenueProgramBoundaryFixture({ candidateCount: 60 });
  for (const candidate of overflow.candidates) candidate.inboxRef = "inbox:1";
  overflow.ledger = Array.from({ length: 51 }, (_, index) =>
    ledgerEntry(overflow, {
      entryRef: `ledger:overflow:${index}`,
      idempotencyKey: hash(`ledger:overflow:${index}`),
      subjectRef: `candidate:${String(index + 1).padStart(4, "0")}`,
      recipient: {
        kind: "email",
        value: `buyer${String(index + 1).padStart(4, "0")}@example.edu`,
        eventVersion: null,
        scheduleRevision: null,
        startAt: null,
      },
      inboxRef: "inbox:1",
    }),
  );
  assert.throws(() => buildRevenueProgram(overflow), /ledger_rate_limit_exceeded/);
});

test("distinguishes none, unavailable, and partial without using them as evidence", () => {
  const none = createRevenueProgramBoundaryFixture();
  none.linkedinAcceptances = [];
  none.correlations = none.correlations.filter((entry) => entry.subjectType !== "acceptance");
  none.sources.notion = {
    ...none.sources.notion,
    status: "none",
    evidenceHash: null,
    unavailableCode: null,
    records: [],
  };
  const noneProgram = buildRevenueProgram(none);
  assert.equal(typeCount(noneProgram, "notion.revenue_artifact"), 0);
  assert.equal(noneProgram.sourceHealth.sources.find((source) => source.source === "notion").status, "none");
  const unavailable = clone(none);
  unavailable.sources.notion = {
    ...unavailable.sources.notion,
    status: "unavailable",
    evidenceHash: null,
    unavailableCode: "oauth_unavailable",
    records: [],
  };
  const unavailableProgram = buildRevenueProgram(unavailable);
  assert.ok(unavailableProgram.sourceHealth.blockers.includes("source_unavailable:notion"));
  const partial = createRevenueProgramBoundaryFixture();
  partial.brain[0].snapshot = {
    ...partial.brain[0].snapshot,
    status: "unavailable",
    evidenceHash: null,
    unavailableCode: "mcp_unavailable",
    records: [],
  };
  const brain = buildRevenueProgram(partial).sourceHealth.sources.find(
    (source) => source.source === "command_center_brain",
  );
  assert.equal(brain.status, "partial_or_unavailable");
});

test("requires present source records and exact typed correlations", () => {
  const absent = createRevenueProgramBoundaryFixture();
  absent.sources.clarify.status = "none";
  absent.sources.clarify.evidenceHash = null;
  absent.sources.clarify.records = [];
  absent.sources.clarify.unavailableCode = null;
  assert.throws(
    () => buildRevenueProgram(absent),
    /correlation_semantic_mismatch|correlation_citation_mismatch|unbound_evidence/,
  );
  const binding = createRevenueProgramBoundaryFixture();
  binding.correlations[0].credentialOwnerRef = "credential-owner:other";
  assert.throws(() => buildRevenueProgram(binding), /invalid_correlation/);
  const missing = createRevenueProgramBoundaryFixture();
  missing.correlations = missing.correlations.filter(
    (entry) => !(entry.subjectType === "candidate" && entry.subjectRef === "candidate:0001"),
  );
  assert.throws(() => buildRevenueProgram(missing), /missing_subject_correlation/);
});

test("pins every source and proposal to the external CEO PrincipalBinding anchor", () => {
  const fixture = createRevenueProgramBoundaryFixture();
  fixture.binding.anchorRef = "principal-binding:other";
  assert.throws(() => buildRevenueProgram(fixture), /deployment_principal_binding_mismatch/);
  const principal = createRevenueProgramBoundaryFixture();
  principal.principal.email = "attacker@risely.ai";
  assert.throws(() => buildRevenueProgram(principal), /untrusted_principal_mailbox/);
  const inbox = createRevenueProgramBoundaryFixture();
  inbox.inboxes[0].ownerEmail = "attacker@risely.ai";
  assert.throws(() => buildRevenueProgram(inbox), /inbox_owner_mismatch/);
  const principalBinding = createRevenueProgramBoundaryFixture();
  principalBinding.binding.principalEmail = "attacker@risely.ai";
  assert.throws(() => buildRevenueProgram(principalBinding), /deployment_principal_binding_mismatch/);
  const googleMailbox = createRevenueProgramBoundaryFixture();
  googleMailbox.sources.gmail.records[0].facts.find((fact) => fact.field === "mailbox_email").value =
    "attacker@risely.ai";
  refreshSourceRecord(googleMailbox, "gmail", googleMailbox.sources.gmail.records[0]);
  assert.throws(() => buildRevenueProgram(googleMailbox), /provider_fact_constant_mismatch/);
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture());
  assert.ok(
    program.proposals.every(
      (proposal) =>
        proposal.binding.anchorRef === program.principalBinding.anchorRef &&
        proposal.binding.credentialOwnerRef === program.principalBinding.credentialOwnerRef,
    ),
  );
});

test("rejects caller-selected provider anchors and keeps every connection unresolved", () => {
  const forged = createRevenueProgramBoundaryFixture();
  forged.binding.googleAccountRef = "provider-account:attacker";
  assert.throws(() => buildRevenueProgram(forged), /caller_selected_connection_binding/);
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture());
  assert.equal(program.connectionBindings.length, 10);
  assert.ok(
    program.connectionBindings.every(
      (binding) => binding.status === "unresolved" && binding.trustedReceiptRequired === true,
    ),
  );
  assert.ok(program.proposals.every((proposal) => proposal.readiness === "blocked_connection_binding"));
});

test("blocks each provider-dependent proposal family when its source is unavailable", () => {
  const gmail = createRevenueProgramBoundaryFixture();
  gmail.sources.gmail = {
    ...gmail.sources.gmail,
    status: "unavailable",
    evidenceHash: null,
    unavailableCode: "oauth_unavailable",
    records: [],
  };
  const gmailProgram = buildRevenueProgram(gmail);
  assert.equal(typeCount(gmailProgram, "gmail.cold_email_draft"), 0);
  assert.equal(typeCount(gmailProgram, "gmail.stale_deal_followup_draft"), 0);
  assert.equal(typeCount(gmailProgram, "linkedin.connection_request"), 0);
  const calendar = createRevenueProgramBoundaryFixture();
  calendar.meetings = [];
  calendar.correlations = calendar.correlations.filter((entry) => entry.subjectType !== "meeting");
  calendar.sources.calendar = {
    ...calendar.sources.calendar,
    status: "unavailable",
    evidenceHash: null,
    unavailableCode: "oauth_unavailable",
    records: [],
  };
  assert.equal(typeCount(buildRevenueProgram(calendar), "slack.demo_reminder"), 0);
});

test("requires confidence-labelled account-level visitor observations from all three sources", () => {
  const identity = createRevenueProgramBoundaryFixture();
  identity.visitorIntent[0].identityScope = "person_identified";
  assert.throws(() => buildRevenueProgram(identity), /invalid_visitor_intent/);
  const missing = createRevenueProgramBoundaryFixture();
  missing.visitorIntent[0].observations.pop();
  assert.throws(() => buildRevenueProgram(missing), /invalid_visitor_intent/);
  const mismatch = createRevenueProgramBoundaryFixture();
  mismatch.visitorIntent[0].observations[0].sourceRecordRef = mismatch.sources.clarify.records[0].recordRef;
  mismatch.visitorIntent[0].observations[0].evidenceHash = mismatch.sources.clarify.records[0].evidenceHash;
  assert.throws(() => buildRevenueProgram(mismatch), /invalid_visitor_observation_binding/);
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture());
  const cold = program.proposals.find(
    (proposal) => proposal.type === "gmail.cold_email_draft" && proposal.subjectRef === "candidate:0001",
  );
  assert.equal(Object.hasOwn(cold.content, "visitorIntent"), false);
  const accountArtifacts = program.proposals.filter(
    (proposal) =>
      proposal.type === "notion.revenue_artifact" && proposal.content.artifactKind === "visitor_account_research",
  );
  assert.equal(accountArtifacts.length, 3);
  assert.ok(accountArtifacts.every((proposal) => proposal.content.audience === "private_ceo"));
  assert.ok(accountArtifacts.every((proposal) => proposal.content.boundedIntentScore <= 9));
  assert.ok(accountArtifacts.every((proposal) => !Object.hasOwn(proposal.content, "contactEmail")));
});

test("visitor intent is causally isolated from every person-level outreach proposal", () => {
  const withVisitor = createRevenueProgramBoundaryFixture({ candidateCount: 25 });
  const withoutVisitor = clone(withVisitor);
  withoutVisitor.visitorIntent = [];
  withoutVisitor.correlations = withoutVisitor.correlations.filter(
    (correlation) => correlation.subjectType !== "visitor_account",
  );
  const outreach = (program) =>
    program.proposals
      .filter((proposal) => proposal.type.startsWith("gmail.") || proposal.type.startsWith("linkedin."))
      .map((proposal) => [proposal.proposalRef, proposal.contentHash]);
  assert.deepEqual(outreach(buildRevenueProgram(withVisitor)), outreach(buildRevenueProgram(withoutVisitor)));
  const domainMismatch = createRevenueProgramBoundaryFixture();
  domainMismatch.sources.rb2b.records[0].facts.find((fact) => fact.field === "account_domain").value =
    "attacker.example";
  refreshSourceRecord(domainMismatch, "rb2b", domainMismatch.sources.rb2b.records[0]);
  assert.throws(() => buildRevenueProgram(domainMismatch), /invalid_visitor_observation_binding/);
});

test("requires provider-backed candidate identity and rejects unrelated evidence providers", () => {
  const callerIdentity = createRevenueProgramBoundaryFixture();
  callerIdentity.candidates[0].contactEmail = "attacker@example.edu";
  callerIdentity.correlations.find(
    (correlation) => correlation.subjectType === "candidate" && correlation.subjectRef === "candidate:0001",
  ).contactRef = `email:${sha256Canonical("attacker@example.edu")}`;
  assert.throws(() => buildRevenueProgram(callerIdentity), /correlation_semantic_mismatch/);
  const unrelated = createRevenueProgramBoundaryFixture();
  const candidateCorrelation = unrelated.correlations.find(
    (correlation) => correlation.subjectType === "candidate" && correlation.subjectRef === "candidate:0001",
  );
  candidateCorrelation.source = "clarify";
  candidateCorrelation.providerAccountRef = unrelated.sources.clarify.binding.accountRef;
  candidateCorrelation.sourceRecordRef = unrelated.sources.clarify.records[0].recordRef;
  candidateCorrelation.evidenceHash = unrelated.sources.clarify.records[0].evidenceHash;
  assert.throws(() => buildRevenueProgram(unrelated), /invalid_correlation/);
  const extraFact = createRevenueProgramBoundaryFixture();
  extraFact.sources.gmail.records[0].facts.push({
    field: "contact_email",
    value: "attacker@example.edu",
    citationRef: "gmail:citation:attacker:contact",
  });
  assert.throws(() => buildRevenueProgram(extraFact), /invalid_provider_fact_schema/);
  const unrelatedArtifact = createRevenueProgramBoundaryFixture();
  const artifactCorrelation = unrelatedArtifact.correlations.find(
    (correlation) => correlation.subjectType === "artifact",
  );
  artifactCorrelation.source = "apollo";
  artifactCorrelation.providerAccountRef = unrelatedArtifact.sources.apollo.binding.accountRef;
  artifactCorrelation.sourceRecordRef = unrelatedArtifact.sources.apollo.records[0].recordRef;
  artifactCorrelation.evidenceHash = unrelatedArtifact.sources.apollo.records[0].evidenceHash;
  unrelatedArtifact.notionArtifacts[0].evidenceHashes = [artifactCorrelation.evidenceHash];
  assert.throws(() => buildRevenueProgram(unrelatedArtifact), /invalid_correlation/);
});

test("enforces exact Brain tool queries, response fields, and unique references", () => {
  const missing = createRevenueProgramBoundaryFixture();
  missing.brain.pop();
  assert.throws(() => buildRevenueProgram(missing), /invalid_brain_context/);
  const query = createRevenueProgramBoundaryFixture();
  query.brain[0].query.tool = "brain_search";
  assert.throws(() => buildRevenueProgram(query), /invalid_brain_query/);
  const response = createRevenueProgramBoundaryFixture();
  response.brain[0].snapshot.records[0].facts[0].field = "summary";
  requalifyRecord("command_center_brain", response.brain[0].snapshot.binding, response.brain[0].snapshot.records[0]);
  assert.throws(() => buildRevenueProgram(response), /invalid_brain_response_shape/);
  const duplicate = createRevenueProgramBoundaryFixture();
  duplicate.brain[1].queryRef = duplicate.brain[0].queryRef;
  assert.throws(() => buildRevenueProgram(duplicate), /unqualified_brain_query_reference/);
  const asOf = createRevenueProgramBoundaryFixture();
  asOf.brain[0].query.asOf = "2026-08-26T15:00:00.000Z";
  asOf.brain[0].snapshot.records[0].facts.find((fact) => fact.field === "as_of").value = asOf.brain[0].query.asOf;
  requalifyRecord("command_center_brain", asOf.brain[0].snapshot.binding, asOf.brain[0].snapshot.records[0]);
  assert.throws(() => buildRevenueProgram(asOf), /invalid_brain_as_of/);
  const garbage = createRevenueProgramBoundaryFixture();
  garbage.brain[0].snapshot.records[0].facts.find((fact) => fact.field === "result_state").value =
    "untyped garbage payload";
  assert.throws(() => buildRevenueProgram(garbage), /invalid_provider_fact_value/);
  const opaque = createRevenueProgramBoundaryFixture();
  const opaqueProgram = buildRevenueProgram(opaque);
  const brainEvidence = new Set(
    opaque.brain.flatMap((entry) => entry.snapshot.records.map((record) => record.evidenceHash)),
  );
  assert.ok(
    opaqueProgram.proposals.every((proposal) =>
      proposal.evidenceHashes.every((evidenceHash) => !brainEvidence.has(evidenceHash)),
    ),
  );
  assert.equal(brainReadTools.length, 11);
});

test("treats mixed Brain none and unavailable as partial and none as non-citable", () => {
  const mixed = createRevenueProgramBoundaryFixture();
  for (const call of mixed.brain) {
    call.snapshot.status = "none";
    call.snapshot.evidenceHash = null;
    call.snapshot.unavailableCode = null;
    call.snapshot.records = [];
  }
  mixed.brain[0].snapshot.status = "unavailable";
  mixed.brain[0].snapshot.unavailableCode = "mcp_unavailable";
  const brain = buildRevenueProgram(mixed).sourceHealth.sources.find(
    (source) => source.source === "command_center_brain",
  );
  assert.equal(brain.status, "partial_or_unavailable");
  const positiveNone = createRevenueProgramBoundaryFixture();
  positiveNone.brain[0].snapshot.status = "none";
  positiveNone.brain[0].snapshot.records = [];
  positiveNone.brain[0].snapshot.unavailableCode = null;
  assert.throws(() => buildRevenueProgram(positiveNone), /invalid_source_semantics/);
  const availableAndNone = createRevenueProgramBoundaryFixture();
  availableAndNone.brain[0].snapshot.status = "none";
  availableAndNone.brain[0].snapshot.evidenceHash = null;
  availableAndNone.brain[0].snapshot.records = [];
  const mixedStatus = buildRevenueProgram(availableAndNone).sourceHealth.sources.find(
    (source) => source.source === "command_center_brain",
  );
  assert.equal(mixedStatus.status, "partial_or_unavailable");
});

test("enforces global provider-qualified record and citation references", () => {
  const record = createRevenueProgramBoundaryFixture();
  record.sources.transcripts.records[0].recordRef = record.sources.clarify.records[0].recordRef;
  assert.throws(() => buildRevenueProgram(record), /unqualified_source_reference/);
  const citation = createRevenueProgramBoundaryFixture();
  citation.sources.transcripts.records[0].facts[0].citationRef =
    citation.sources.clarify.records[0].facts[0].citationRef;
  assert.throws(() => buildRevenueProgram(citation), /unqualified_source_reference/);
  const query = createRevenueProgramBoundaryFixture();
  query.brain[0].queryRef = query.sources.clarify.records[0].recordRef;
  assert.throws(() => buildRevenueProgram(query), /unqualified_brain_query_reference/);
  const correlation = createRevenueProgramBoundaryFixture();
  correlation.correlations[0].correlationRef = correlation.sources.apollo.records[0].recordRef;
  assert.throws(() => buildRevenueProgram(correlation), /unqualified_correlation_reference/);
  const complete = createRevenueProgramBoundaryFixture();
  const program = buildRevenueProgram(complete);
  const references = [
    ...complete.brain.map((entry) => entry.queryRef),
    ...Object.values(complete.sources).flatMap((source) =>
      source.records.flatMap((sourceRecord) => [
        sourceRecord.recordRef,
        ...sourceRecord.facts.map((fact) => fact.citationRef),
      ]),
    ),
    ...complete.brain.flatMap((entry) =>
      entry.snapshot.records.flatMap((sourceRecord) => [
        sourceRecord.recordRef,
        ...sourceRecord.facts.map((fact) => fact.citationRef),
      ]),
    ),
    ...complete.correlations.map((entry) => entry.correlationRef),
    ...program.proposals.map((proposal) => proposal.proposalRef),
  ];
  assert.equal(new Set(references).size, references.length);
});

test("defines candidate account duplication and rejects cross-domain subject collisions", () => {
  const allowed = createRevenueProgramBoundaryFixture({ candidateCount: 2 });
  allowed.candidates[1].accountRef = allowed.candidates[0].accountRef;
  allowed.candidates[1].accountDomain = allowed.candidates[0].accountDomain;
  allowed.sources.apollo.records[1].facts.find((fact) => fact.field === "account_ref").value =
    allowed.candidates[0].accountRef;
  allowed.sources.apollo.records[1].facts.find((fact) => fact.field === "account_domain").value =
    allowed.candidates[0].accountDomain;
  for (const correlation of allowed.correlations.filter(
    (entry) => entry.subjectType === "candidate" && entry.subjectRef === allowed.candidates[1].candidateRef,
  )) {
    correlation.accountRef = allowed.candidates[0].accountRef;
  }
  refreshSourceRecord(allowed, "apollo", allowed.sources.apollo.records[1]);
  assert.doesNotThrow(() => buildRevenueProgram(allowed));
  const overflow = createRevenueProgramBoundaryFixture({ candidateCount: 9 });
  for (const [index, candidate] of overflow.candidates.entries()) {
    candidate.accountRef = "account:shared";
    candidate.accountDomain = "shared.edu";
    overflow.sources.apollo.records[index].facts.find((fact) => fact.field === "account_ref").value = "account:shared";
    overflow.sources.apollo.records[index].facts.find((fact) => fact.field === "account_domain").value = "shared.edu";
  }
  for (const correlation of overflow.correlations.filter((entry) => entry.subjectType === "candidate")) {
    correlation.accountRef = "account:shared";
  }
  for (const record of overflow.sources.apollo.records) refreshSourceRecord(overflow, "apollo", record);
  assert.throws(() => buildRevenueProgram(overflow), /candidate_account_contact_limit/);
  const collision = createRevenueProgramBoundaryFixture();
  collision.staleDeals[0].dealRef = collision.candidates[0].candidateRef;
  collision.correlations.find((entry) => entry.subjectType === "deal").subjectRef =
    collision.candidates[0].candidateRef;
  assert.throws(() => buildRevenueProgram(collision), /subject_namespace_collision/);
});

test("requires exact stale-touch record timestamp evidence", () => {
  const mismatch = createRevenueProgramBoundaryFixture();
  mismatch.staleDeals[0].lastVerifiedTouchCitation.occurredAt = "2026-08-11T16:00:00.000Z";
  assert.throws(() => buildRevenueProgram(mismatch), /stale_touch_citation_mismatch/);
  const missingFact = createRevenueProgramBoundaryFixture();
  missingFact.sources.clarify.records[0].facts = missingFact.sources.clarify.records[0].facts.filter(
    (fact) => fact.field !== "last_verified_touch_at",
  );
  assert.throws(() => buildRevenueProgram(missingFact), /invalid_provider_fact_schema/);
  const unknown = createRevenueProgramBoundaryFixture();
  unknown.staleDeals[0].lastVerifiedTouchAt = unknown.now;
  unknown.staleDeals[0].lastVerifiedTouchCitation.occurredAt = unknown.now;
  unknown.sources.clarify.records[0].facts.find((fact) => fact.field === "last_verified_touch_at").value = unknown.now;
  refreshSourceRecord(unknown, "clarify", unknown.sources.clarify.records[0]);
  assert.equal(typeCount(buildRevenueProgram(unknown), "gmail.stale_deal_followup_draft"), 0);
});

test("binds artifact evidence to finalized transcript chronology", () => {
  const future = createRevenueProgramBoundaryFixture();
  future.sources.transcripts.records[0].facts.find((fact) => fact.field === "finalized_at").value =
    "2026-08-26T16:01:00.000Z";
  future.notionArtifacts[0].transcriptFinalizedAt = "2026-08-26T16:01:00.000Z";
  refreshSourceRecord(future, "transcripts", future.sources.transcripts.records[0]);
  assert.throws(() => buildRevenueProgram(future), /invalid_transcript_chronology/);
  const beforeEnd = createRevenueProgramBoundaryFixture();
  beforeEnd.sources.transcripts.records[0].facts.find((fact) => fact.field === "finalized_at").value =
    "2026-08-26T15:30:00.000Z";
  beforeEnd.notionArtifacts[0].transcriptFinalizedAt = "2026-08-26T15:30:00.000Z";
  refreshSourceRecord(beforeEnd, "transcripts", beforeEnd.sources.transcripts.records[0]);
  assert.throws(() => buildRevenueProgram(beforeEnd), /invalid_transcript_chronology/);
  const mismatchedArtifact = createRevenueProgramBoundaryFixture();
  mismatchedArtifact.notionArtifacts[0].contentSummary = "Caller substituted summary.";
  assert.throws(() => buildRevenueProgram(mismatchedArtifact), /correlation_semantic_mismatch/);
  const missingCitation = createRevenueProgramBoundaryFixture();
  missingCitation.correlations.find((correlation) => correlation.subjectType === "artifact").factCitationRefs.pop();
  assert.throws(() => buildRevenueProgram(missingCitation), /correlation_citation_mismatch/);
});

test("models meeting cancellation, moves, recurrence, and event versions", () => {
  const cancelled = createRevenueProgramBoundaryFixture();
  cancelled.meetings[0].status = "cancelled";
  cancelled.meetings[0].cancelledAt = cancelled.now;
  cancelled.meetings[0].changeStatus = "cancelled";
  cancelled.meetings[0].eventVersion = 2;
  cancelled.meetings[0].scheduleRevision = 2;
  syncMeetingEvidence(cancelled);
  assert.equal(typeCount(buildRevenueProgram(cancelled), "slack.demo_reminder"), 0);
  const cancelledMove = createRevenueProgramBoundaryFixture();
  cancelledMove.meetings[0].status = "cancelled";
  cancelledMove.meetings[0].cancelledAt = cancelledMove.now;
  cancelledMove.meetings[0].changeStatus = "cancelled";
  cancelledMove.meetings[0].movedFromStartAt = cancelledMove.meetings[0].previousStartAt;
  cancelledMove.meetings[0].startAt = "2026-08-29T15:00:00.000Z";
  cancelledMove.meetings[0].eventVersion = 2;
  cancelledMove.meetings[0].scheduleRevision = 2;
  syncMeetingEvidence(cancelledMove);
  assert.throws(() => buildRevenueProgram(cancelledMove), /invalid_meeting_lifecycle/);
  const moved = createRevenueProgramBoundaryFixture();
  moved.meetings[0].movedFromStartAt = moved.meetings[0].previousStartAt;
  moved.meetings[0].startAt = "2026-08-29T15:00:00.000Z";
  moved.meetings[0].changeStatus = "moved";
  moved.meetings[0].eventVersion = 2;
  moved.meetings[0].scheduleRevision = 2;
  moved.meetings[0].recurringEventRef = "recurrence:advancement:1";
  syncMeetingEvidence(moved);
  const reminder = buildRevenueProgram(moved).proposals.find((proposal) => proposal.type === "slack.demo_reminder");
  assert.equal(reminder.content.eventVersion, 2);
  assert.equal(reminder.content.recurringEventRef, "recurrence:advancement:1");
  const staleVersion = createRevenueProgramBoundaryFixture();
  staleVersion.meetings[0].movedFromStartAt = staleVersion.meetings[0].previousStartAt;
  staleVersion.meetings[0].startAt = "2026-08-29T15:00:00.000Z";
  staleVersion.meetings[0].changeStatus = "moved";
  assert.throws(() => buildRevenueProgram(staleVersion), /invalid_meeting_lifecycle/);
  const disguisedMove = createRevenueProgramBoundaryFixture();
  disguisedMove.meetings[0].startAt = "2026-08-29T15:00:00.000Z";
  syncMeetingEvidence(disguisedMove);
  assert.throws(() => buildRevenueProgram(disguisedMove), /invalid_meeting_lifecycle/);
});

test("supersedes moved meeting schedules and ledgers reminder and customization separately", () => {
  const fixture = createRevenueProgramBoundaryFixture();
  const initial = buildRevenueProgram(fixture);
  const reminder = initial.proposals.find((proposal) => proposal.type === "slack.demo_reminder");
  const customization = initial.proposals.find((proposal) => proposal.type === "demo.customization_review");
  fixture.ledger.push(
    ledgerEntry(fixture, {
      channel: "demo_reminder",
      subjectRef: reminder.subjectRef,
      recipient: {
        kind: "meeting_occurrence",
        value: reminder.content.occurrenceRef,
        eventVersion: reminder.content.eventVersion,
        scheduleRevision: reminder.content.scheduleRevision,
        startAt: reminder.content.startAt,
      },
      providerAccountRef: fixture.binding.workspaceRef,
      inboxRef: null,
    }),
  );
  const reminderSuppressed = buildRevenueProgram(fixture);
  assert.equal(typeCount(reminderSuppressed, "slack.demo_reminder"), 0);
  assert.equal(typeCount(reminderSuppressed, "demo.customization_review"), 1);
  fixture.ledger.push(
    ledgerEntry(fixture, {
      entryRef: "ledger:2",
      idempotencyKey: hash("ledger:2"),
      channel: "demo_customization",
      subjectRef: customization.subjectRef,
      recipient: {
        kind: "meeting_occurrence",
        value: customization.content.occurrenceRef,
        eventVersion: customization.content.eventVersion,
        scheduleRevision: customization.content.scheduleRevision,
        startAt: customization.content.startAt,
      },
      providerAccountRef: fixture.binding.demoRepositoryRef,
      inboxRef: null,
    }),
  );
  assert.equal(typeCount(buildRevenueProgram(fixture), "demo.customization_review"), 0);
  fixture.meetings[0].movedFromStartAt = fixture.meetings[0].startAt;
  fixture.meetings[0].startAt = "2026-08-29T15:00:00.000Z";
  fixture.meetings[0].changeStatus = "moved";
  fixture.meetings[0].eventVersion = 2;
  fixture.meetings[0].scheduleRevision = 2;
  syncMeetingEvidence(fixture);
  const moved = buildRevenueProgram(fixture);
  assert.equal(typeCount(moved, "slack.demo_reminder"), 1);
  assert.equal(typeCount(moved, "demo.customization_review"), 1);
});

test("emits T-3 reminders only inside the exact window and never claims unverified preparation", () => {
  const due = buildRevenueProgram(createRevenueProgramBoundaryFixture());
  const reminder = due.proposals.find((proposal) => proposal.type === "slack.demo_reminder");
  const review = due.proposals.find((proposal) => proposal.type === "demo.customization_review");
  assert.equal(reminder.content.readiness, "not_verified");
  assert.equal(review.content.repositoryAccess, "read_only");
  const early = createRevenueProgramBoundaryFixture();
  early.meetings[0].startAt = "2026-08-30T16:00:00.000Z";
  early.meetings[0].movedFromStartAt = early.meetings[0].originalStartAt;
  early.meetings[0].changeStatus = "moved";
  early.meetings[0].eventVersion = 2;
  early.meetings[0].scheduleRevision = 2;
  syncMeetingEvidence(early);
  assert.equal(typeCount(buildRevenueProgram(early), "slack.demo_reminder"), 0);
});

test("enforces canonical local day and source freshness", () => {
  const day = createRevenueProgramBoundaryFixture();
  day.goalDate = "2026-08-25";
  assert.throws(() => buildRevenueProgram(day), /goal_date_mismatch/);
  const stale = createRevenueProgramBoundaryFixture();
  stale.sources.gmail.checkedAt = "2026-08-24T16:00:00.000Z";
  assert.throws(() => buildRevenueProgram(stale), /stale_source_snapshot/);
  const local = createRevenueProgramBoundaryFixture();
  local.sources.gmail.checkedAt = "2026-08-26T06:00:00.000Z";
  local.sources.gmail.records[0].observedAt = "2026-08-26T06:00:00.000Z";
  refreshSourceRecord(local, "gmail", local.sources.gmail.records[0]);
  assert.throws(() => buildRevenueProgram(local), /source_local_day_mismatch/);
  const ledger = createRevenueProgramBoundaryFixture();
  ledger.ledger.push(ledgerEntry(ledger, { createdAt: "2026-08-26T06:00:00.000Z" }));
  assert.throws(() => buildRevenueProgram(ledger), /invalid_ledger_local_day/);
  const visitor = createRevenueProgramBoundaryFixture();
  visitor.visitorIntent[0].observations[0].observedAt = "2026-08-26T15:59:59.000Z";
  assert.throws(() => buildRevenueProgram(visitor), /invalid_visitor_observation_binding/);
});

test("pins Notion proposals to the private CEO root", () => {
  const wrong = createRevenueProgramBoundaryFixture();
  wrong.notionArtifacts[0].rootRef = "notion:other";
  assert.throws(() => buildRevenueProgram(wrong), /notion_private_root_mismatch/);
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture());
  const notion = program.proposals.find((proposal) => proposal.type === "notion.revenue_artifact");
  assert.equal(notion.content.rootRef, program.principalBinding.notionRootRef);
  assert.equal(notion.content.audience, "private_ceo");
});

test("counts object-key bytes against the JSON boundary cap", () => {
  const value = {};
  for (let index = 0; index < 9_000; index += 1) {
    value[`${String(index).padStart(6, "0")}${"k".repeat(240)}`] = "x";
  }
  assert.throws(() => snapshotPlainJson(value), /invalid_plain_json/);
});

test("rejects accessors, proxies, and mail header injection", () => {
  const accessor = createRevenueProgramBoundaryFixture();
  Object.defineProperty(accessor, "programRef", { enumerable: true, get: () => "program:trap" });
  assert.throws(() => buildRevenueProgram(accessor), /invalid_plain_json/);
  assert.throws(() => buildRevenueProgram(new Proxy(createRevenueProgramBoundaryFixture(), {})), /invalid_plain_json/);
  const subject = createRevenueProgramBoundaryFixture();
  subject.candidates[0].emailSubject = "Hello\nBcc: attacker@example.com";
  assert.throws(() => buildRevenueProgram(subject), /invalid_candidate/);
});

test("initializer rejects every caller execution control and derives hard-disabled state", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture({ candidateCount: 5 }));
  const state = initializeRevenueProgramState(program);
  assert.equal(state.state, "uncommitted_initialization");
  assert.equal(state.commitDisposition, "uncommitted");
  assert.equal(state.safetyDisposition, "hard_disabled");
  assert.deepEqual(state.reconciliation, { status: "not_attempted", attemptRef: null, receiptRef: null });
  for (const field of ["execution", "live", "enabled", "providerEffect"]) {
    const forged = clone(program);
    forged[field] = true;
    forged.programHash = sha256Canonical(programWithoutHash(forged));
    assert.throws(() => initializeRevenueProgramState(forged), /caller_execution_control_forbidden/);
  }
  const selfHashed = clone(program);
  selfHashed.programHash = sha256Canonical(programWithoutHash(selfHashed));
  assert.throws(() => initializeRevenueProgramState(selfHashed), /untrusted_program_instance/);
  assert.throws(() => initializeRevenueProgramState(null), RevenueProgramError);
});

test("public Revenue verification accepts only the branded exact program across independent mutation classes", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture({ candidateCount: 5 }));
  assert.equal(verifyRevenueProgramOutput(program).programHash, program.programHash);
  const variants = [
    (value) => {
      value.goalDate = "2026-08-27";
    },
    (value) => {
      value.timeZone = "UTC";
    },
    (value) => {
      value.inputHash = hash("forged-input");
    },
    (value) => {
      value.programRevision += 1;
    },
    (value) => {
      value.connectionBindings[0].providerAccountRef = "connection-anchor:google:other:v1";
    },
    (value) => {
      value.correlations[0].evidenceHash = hash("forged-correlation");
    },
    (value) => {
      value.sourceHealth.sources[0].status = "none";
    },
    (value) => {
      value.accounting.email.proposed += 1;
    },
    (value) => {
      value.proposals[0].contentHash = hash("forged-proposal");
    },
  ];
  for (const mutate of variants) {
    const forged = clone(program);
    mutate(forged);
    forged.programHash = sha256Canonical(programWithoutHash(forged));
    assert.throws(() => verifyRevenueProgramOutput(forged), /untrusted_program_instance/);
  }
  const exactClone = clone(program);
  exactClone.programHash = sha256Canonical(programWithoutHash(exactClone));
  assert.throws(() => verifyRevenueProgramOutput(exactClone), /untrusted_program_instance/);
});

test("property: every successfully built program initializes and has canonical evidence", () => {
  for (const candidateCount of [0, 1, 2, 8, 20, 80, 120, 250]) {
    const fixture = createRevenueProgramBoundaryFixture({ candidateCount });
    if (candidateCount > 2) {
      fixture.candidates.reverse();
      fixture.correlations.reverse();
    }
    const program = buildRevenueProgram(fixture);
    assert.doesNotThrow(() => initializeRevenueProgramState(program));
    assert.ok(
      program.proposals.every((proposal) => new Set(proposal.evidenceHashes).size === proposal.evidenceHashes.length),
    );
  }
});

test("creates one-to-one unresolved eval lineage from a fixed two-origin registry", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture({ candidateCount: 5 }));
  const initial = initializeRevenueProgramState(program);
  const transition = requestRevenueProgramEvaluation(initial, evaluationRequest(initial));
  assert.equal(transition.transitionKind, "evaluation_request");
  assert.equal(transition.safetyDisposition, "hard_disabled");
  assert.equal(transition.cas.status, "unresolved");
  assert.equal(transition.cas.externalCommitRequired, true);
  assert.equal(transition.operation.resolution, "unresolved");
  assert.equal(transition.operation.lineage.length, program.proposals.length);
  assert.equal(new Set(transition.operation.lineage.map((entry) => entry.proposalRef)).size, program.proposals.length);
  assert.equal(
    transition.operation.runs.length,
    Object.keys(evaluationGateCriteria).length * Object.keys(prospectiveEvaluatorRegistry).length,
  );
  assert.deepEqual(new Set(transition.operation.runs.map((run) => run.originClass)), new Set(["deterministic", "llm"]));
  assert.equal(new Set(transition.operation.runs.map((run) => run.runRef)).size, transition.operation.runs.length);
  assert.equal(Object.keys(prospectiveEvaluatorRegistry).length, 2);
  assert.equal(
    requestRevenueProgramEvaluation(initial, evaluationRequest(initial)).transitionRef,
    transition.transitionRef,
  );
  const second = requestRevenueProgramEvaluation(initial, evaluationRequest(initial, "evaluation-request:2"));
  assert.equal(
    transition.operation.runs.some((run) => second.operation.runs.some((candidate) => candidate.runRef === run.runRef)),
    false,
  );
});

test("rejects every unbranded evaluator receipt even when self-hashed", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture({ candidateCount: 5 }));
  const state = initializeRevenueProgramState(program);
  const transition = requestRevenueProgramEvaluation(state, evaluationRequest(state));
  const forged = {
    programHash: program.programHash,
    artifactDigest: transition.operation.artifactDigest,
    runRef: transition.operation.runs[0].runRef,
    passed: true,
  };
  forged.receiptHash = sha256Canonical(forged);
  assert.throws(() => recordRevenueProgramEvaluation(state, forged), /untrusted_evaluation_receipt/);
});

test("creates exact unresolved Slack approval payloads but never authorization", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture({ candidateCount: 5 }));
  const initial = initializeRevenueProgramState(program);
  const target = program.proposals.find((proposal) => proposal.type === "linkedin.dm_draft");
  const request = approvalRequest(initial, target);
  const transition = requestRevenueProgramApproval(initial, request);
  const approval = transition.operation;
  assert.equal(transition.transitionKind, "approval_request");
  assert.equal(approval.teamRef, "slack-team:risely");
  assert.equal(approval.userRef, "slack-user:ceo");
  assert.equal(approval.audienceRef, "slack-audience:ceo-private");
  assert.equal(approval.messageRef, "slack-message:1");
  assert.equal(approval.interactionRef, "slack-interaction:1");
  assert.equal(approval.programRevision, program.programRevision);
  assert.equal(approval.resolution, "unresolved");
  assert.equal(approval.timeBinding.trustedServerTimeRequired, true);
  assert.equal(transition.cas.externalCommitRequired, true);
  assert.equal(transition.safetyDisposition, "hard_disabled");
});

test("rejects altered, caller-timed, wrong-audience, and untrusted Slack approvals", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture({ candidateCount: 5 }));
  const initial = initializeRevenueProgramState(program);
  const target = program.proposals.find((proposal) => proposal.type === "linkedin.dm_draft");
  const valid = approvalRequest(initial, target);
  assert.throws(
    () => requestRevenueProgramApproval(initial, { ...valid, payloadHash: hash("altered") }),
    /approval_payload_mismatch/,
  );
  const callerTimed = { ...valid, expiresAt: "2026-08-28T18:00:00.000Z" };
  assert.throws(() => requestRevenueProgramApproval(initial, callerTimed), /invalid_approval_request/);
  const wrongAudience = approvalRequest(initial, target, { audienceRef: "slack-audience:other" });
  assert.throws(() => requestRevenueProgramApproval(initial, wrongAudience), /untrusted_slack_audience_or_action/);
  const transition = requestRevenueProgramApproval(initial, valid);
  const forged = { ...transition.operation, decision: "approved" };
  forged.receiptHash = sha256Canonical(forged);
  assert.throws(() => recordRevenueProgramApproval(initial, forged), /untrusted_approval_receipt/);
});

test("detects durable request record tampering", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture({ candidateCount: 5 }));
  const initial = initializeRevenueProgramState(program);
  const tampered = clone(initial);
  tampered.proposals[0].readiness = "ready";
  tampered.recordHash = sha256Canonical(
    Object.fromEntries(Object.entries(tampered).filter(([key]) => key !== "recordHash")),
  );
  assert.throws(
    () => requestRevenueProgramEvaluation(tampered, evaluationRequest(tampered, "evaluation-request:2")),
    /untrusted_state_record/,
  );
});

test("models reconciliation states prospectively without exposing a mutation", () => {
  assert.deepEqual(prospectiveReconciliationContract.statuses, ["outcome_unknown", "confirmed", "failed"]);
  assert.equal(prospectiveReconciliationContract.mutationsAvailable, false);
  assert.equal(prospectiveReconciliationContract.trustedProviderReceiptRequired, true);
});

test("presents every proposal and source status without an execution affordance", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture());
  const presentation = presentRevenueProgram(program);
  assert.equal(presentation.proposals.length, program.proposals.length);
  assert.equal(presentation.safetyDisposition, "hard_disabled");
  assert.match(presentation.safetyLabel, /no external action can run/);
  assert.ok(presentation.proposals.every((proposal) => proposal.disposition.includes("Awaiting")));
  assert.equal(presentation.sourceStatus.length, program.sourceHealth.sources.length);
  assert.throws(() => presentRevenueProgram(null), RevenueProgramError);
  assert.throws(() => presentRevenueProgram(new Proxy({}, {})), RevenueProgramError);
  const accessor = {};
  Object.defineProperty(accessor, "enabled", { enumerable: true, get: () => true });
  assert.throws(() => presentRevenueProgram(accessor), RevenueProgramError);
});

test("rejects recursive caller controls on every public transition", () => {
  const program = buildRevenueProgram(createRevenueProgramBoundaryFixture({ candidateCount: 5 }));
  const state = initializeRevenueProgramState(program);
  assert.throws(
    () =>
      requestRevenueProgramEvaluation(state, {
        ...evaluationRequest(state),
        nested: { enabled: true },
      }),
    /caller_execution_control_forbidden/,
  );
  const proposal = program.proposals[0];
  assert.throws(
    () =>
      requestRevenueProgramApproval(state, {
        ...approvalRequest(state, proposal),
        providerEffect: { live: true },
      }),
    /caller_execution_control_forbidden/,
  );
});
