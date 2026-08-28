import assert from "node:assert/strict";
import test from "node:test";
import { sha256Canonical } from "../../canary/contracts/canonicalize.mjs";
import {
  buildGoalsAndEodArtifact,
  buildPostMeetingAnalysisInput,
  correlateFinalTranscript,
  normalizeMeetingDossier,
  proposeGmailDraftOnly,
  sourceVerificationReceiptContract,
} from "../../canary/chief-of-staff/index.mjs";
import { hash, instant, lineage } from "./fixtures.mjs";

const meetingKey = hash("1");
const calendarEvidenceHash = hash("2");
const transcriptEvidenceHash = hash("6");

const dossierInput = () => ({
  meetingKey,
  generatedAt: instant.now,
  calendarEvidenceHash,
  sources: [
    { source: "calendar", availability: "available" },
    { source: "gmail", availability: "available" },
    { source: "clarify", availability: "not_connected" },
    { source: "command_center_brain", availability: "available" },
    { source: "notion", availability: "unavailable" },
  ],
  evidence: [
    {
      evidenceRef: "ev_calendar_01",
      source: "calendar",
      evidenceHash: calendarEvidenceHash,
      capturedAt: "2026-08-26T16:55:00.000Z",
    },
    {
      evidenceRef: "ev_brain_01",
      source: "command_center_brain",
      evidenceHash: hash("4"),
      capturedAt: "2026-08-26T16:50:00.000Z",
    },
    { evidenceRef: "ev_gmail_01", source: "gmail", evidenceHash: hash("5"), capturedAt: "2026-08-26T16:45:00.000Z" },
  ],
  sections: {
    accountOverview: [
      {
        claimId: "claim_account_01",
        text: "The institution is evaluating advancement workflows.",
        citations: ["ev_brain_01"],
      },
    ],
    contactBackground: [
      { claimId: "claim_contact_01", text: "The buyer asked about implementation timing.", citations: ["ev_gmail_01"] },
    ],
    recommendedPositioning: [
      {
        claimId: "claim_position_01",
        text: "Lead with a phased rollout.",
        citations: ["ev_calendar_01", "ev_brain_01"],
      },
    ],
  },
});

const meeting = (overrides = {}) => ({
  deploymentRef: lineage.deploymentRef,
  principalRef: lineage.principalRef,
  credentialOwnerRef: lineage.credentialOwnerRef,
  connectionRef: lineage.connectionRef,
  calendarAccountRef: lineage.calendarAccountRef,
  meetingKey,
  calendarEventId: "event_customer_01",
  occurrenceRef: "event:event_customer_01",
  eventRevisionHash: hash("a"),
  startAt: "2026-08-26T15:00:00.000Z",
  endAt: "2026-08-26T16:00:00.000Z",
  participants: [
    { email: "shahryar@risely.ai", role: "ceo", response: "accepted" },
    { email: "buyer_team@example.edu", role: "external", response: "accepted" },
  ],
  calendarEvidenceHash,
  ...overrides,
});

const transcript = (overrides = {}) => ({
  transcriptRef: "transcript_clarify_01",
  providerTranscriptId: "clarify_transcript_provider_01",
  providerAccountRef: "clarify_account_risely_01",
  revision: "final",
  revisionHash: hash("b"),
  calendarEventId: "event_customer_01",
  occurrenceRef: "event:event_customer_01",
  recordedStartAt: "2026-08-26T15:02:00.000Z",
  recordedEndAt: "2026-08-26T15:58:00.000Z",
  finalizedAt: "2026-08-26T16:20:00.000Z",
  participants: [
    { email: "buyer_team@example.edu", role: "speaker" },
    { email: "shahryar@risely.ai", role: "speaker" },
  ],
  evidenceHash: transcriptEvidenceHash,
  contentHash: sha256Canonical({ transcriptText: "The buyer asked for a proposal next week." }),
  ...overrides,
});

const goalDefinition = (overrides = {}) => {
  const definition = {
    goalRef: "goal_pipeline_01",
    definitionVersion: "goal_definition_v1",
    title: "Build qualified pipeline",
    target: "Ten qualified opportunities",
    targetDate: "2026-09-30T23:59:59.000Z",
    ...overrides,
  };
  return { ...definition, definitionHash: sha256Canonical(definition), evidenceRefs: ["ev_work_01"] };
};

const goalsInput = () => ({
  principalRef: lineage.principalRef,
  periodKind: "daily",
  periodStart: "2026-08-26T07:00:00.000Z",
  periodEnd: "2026-08-27T07:00:00.000Z",
  timezone: "America/Los_Angeles",
  generatedAt: "2026-08-27T07:05:00.000Z",
  goals: [goalDefinition()],
  evidence: [
    {
      evidenceRef: "ev_work_01",
      source: "command_center_brain",
      occurredAt: "2026-08-26T16:00:00.000Z",
      evidenceHash: hash("9"),
      summary: "Two qualified opportunities advanced today.",
      temporalRole: "period_observation",
    },
  ],
  updates: [
    {
      goalRef: "goal_pipeline_01",
      status: "on_track",
      summary: "Pipeline advanced against the weekly target.",
      citations: ["ev_work_01"],
      confidence: "high",
    },
  ],
});

const correlationRequest = (meetingOverrides = {}, transcriptOverrides = {}) =>
  correlateFinalTranscript({
    now: instant.now,
    transcript: transcript(transcriptOverrides),
    candidateMeetings: [meeting(meetingOverrides)],
  });

test("dossiers normalize cited claims and bind the exact available Calendar evidence", () => {
  const dossier = normalizeMeetingDossier(dossierInput());
  assert.deepEqual(dossier.missingContext, ["clarify", "notion"]);
  assert.equal(dossier.providerContentTrust, "untrusted_data_only");
  assert.equal(dossier.presentationSinkAllowed, false);
  assert.equal(dossier.evidence[0].trust, "untrusted_source_data");
  assert.match(dossier.artifactHash, /^[0-9a-f]{64}$/);
});

test("dossiers reject uncited, unavailable, missing, future, or mismatched Calendar evidence", () => {
  const uncited = dossierInput();
  uncited.sections.accountOverview[0].citations = [];
  assert.throws(() => normalizeMeetingDossier(uncited), /uncited_dossier_claim/);
  const unknown = dossierInput();
  unknown.sections.accountOverview[0].citations = ["ev_missing_01"];
  assert.throws(() => normalizeMeetingDossier(unknown), /unknown_dossier_citation/);
  const future = dossierInput();
  future.evidence[0].capturedAt = "2026-08-26T18:00:00.000Z";
  assert.throws(() => normalizeMeetingDossier(future), /future_dossier_evidence/);
  const unavailable = dossierInput();
  unavailable.sources.find((source) => source.source === "gmail").availability = "unavailable";
  assert.throws(() => normalizeMeetingDossier(unavailable), /dossier_evidence_source_unavailable/);
  const incomplete = dossierInput();
  incomplete.sources = incomplete.sources.filter((source) => source.source !== "notion");
  assert.throws(() => normalizeMeetingDossier(incomplete), /incomplete_dossier_source_inventory/);
  const mismatched = dossierInput();
  mismatched.calendarEvidenceHash = hash("f");
  assert.throws(() => normalizeMeetingDossier(mismatched), /calendar_evidence_mismatch/);
});

test("final transcripts produce an unresolved exact source-verification request", () => {
  const correlation = correlateFinalTranscript({
    now: instant.now,
    transcript: transcript(),
    candidateMeetings: [meeting()],
  });
  assert.equal(correlation.status, "verification_required");
  assert.equal(correlation.strength, "exact_provider_identity");
  assert.equal(correlation.principalRef, lineage.principalRef);
  assert.equal(correlation.calendarAccountRef, lineage.calendarAccountRef);
  assert.equal(correlation.occurrenceRef, "event:event_customer_01");
  assert.equal(correlation.transcriptRevisionHash, hash("b"));
  assert.equal(correlation.providerTranscriptId, "clarify_transcript_provider_01");
  assert.equal(correlation.transcriptFinalizedAt, "2026-08-26T16:20:00.000Z");
  assert.equal(correlation.eventStartAt, "2026-08-26T15:00:00.000Z");
  assert.deepEqual(correlation.meetingParticipants[0], {
    email: "buyer_team@example.edu",
    role: "external",
    response: "accepted",
  });
  assert.equal(correlation.actionAllowed, false);
  assert.equal(correlation.providerEffectAllowed, false);
  assert.equal(correlation.requiredBrokerOrigin, "qm_core_source_verification_broker");
  const later = correlationRequest({}, { finalizedAt: "2026-08-26T16:30:00.000Z" });
  const roleChanged = correlationRequest(
    {},
    {
      participants: [
        { email: "buyer_team@example.edu", role: "attendee" },
        { email: "shahryar@risely.ai", role: "speaker" },
      ],
    },
  );
  assert.notEqual(later.correlationHash, correlation.correlationHash);
  assert.notEqual(roleChanged.correlationHash, correlation.correlationHash);
  assert.notEqual(later.verificationRequestHash, correlation.verificationRequestHash);
});

test("heuristic correlation requires unique time, participant, and finalization after meeting end", () => {
  const withoutIdentity = transcript();
  delete withoutIdentity.calendarEventId;
  delete withoutIdentity.occurrenceRef;
  const unique = correlateFinalTranscript({
    now: instant.now,
    transcript: withoutIdentity,
    candidateMeetings: [meeting()],
  });
  assert.equal(unique.status, "verification_required");
  const beforeEnd = { ...withoutIdentity, finalizedAt: "2026-08-26T15:59:00.000Z" };
  const early = correlateFinalTranscript({ now: instant.now, transcript: beforeEnd, candidateMeetings: [meeting()] });
  assert.equal(early.status, "unmatched");
  const secondMeeting = meeting({
    meetingKey: hash("7"),
    calendarEventId: "event_customer_02",
    occurrenceRef: "event:event_customer_02",
  });
  const ambiguous = correlateFinalTranscript({
    now: instant.now,
    transcript: withoutIdentity,
    candidateMeetings: [meeting(), secondMeeting],
  });
  assert.equal(ambiguous.status, "ambiguous");
});

test("contradictory provider identity never falls back to heuristic correlation", () => {
  const mismatch = transcript({ calendarEventId: "event_other_01" });
  const result = correlateFinalTranscript({ now: instant.now, transcript: mismatch, candidateMeetings: [meeting()] });
  assert.equal(result.status, "unmatched");
});

test("post-meeting analysis binds the exact unresolved correlation and respects finality", () => {
  const correlation = correlateFinalTranscript({
    now: instant.now,
    transcript: transcript(),
    candidateMeetings: [meeting()],
  });
  const base = {
    generatedAt: instant.now,
    meeting: meeting(),
    dossierBinding: { artifactHash: hash("8"), meetingKey, calendarEvidenceHash },
    transcriptCorrelation: correlation,
    transcriptText: "The buyer asked for a proposal next week.",
  };
  const analysis = buildPostMeetingAnalysisInput(base);
  assert.equal(analysis.actionAllowed, false);
  assert.equal(analysis.dossierBinding.meetingKey, meetingKey);
  assert.equal(analysis.transcript.trust, "unverified_transcript_data");
  assert.equal(analysis.sourceVerification.status, "required");
  assert.throws(
    () => buildPostMeetingAnalysisInput({ ...base, dossierBinding: { ...base.dossierBinding, meetingKey: hash("f") } }),
    /dossier_binding_mismatch/,
  );
  assert.throws(
    () => buildPostMeetingAnalysisInput({ ...base, transcriptText: "Altered transcript" }),
    /transcript_content_mismatch/,
  );
  assert.throws(
    () =>
      buildPostMeetingAnalysisInput({
        ...base,
        transcriptCorrelation: { ...correlation, correlationHash: hash("f") },
      }),
    /transcript_correlation_hash_mismatch/,
  );
  assert.throws(
    () => buildPostMeetingAnalysisInput({ ...base, generatedAt: "2026-08-26T16:19:59.000Z" }),
    /invalid_post_meeting_generation_time/,
  );
  assert.throws(
    () => buildPostMeetingAnalysisInput({ ...base, generatedAt: "2026-08-26T16:30:00.000Z" }),
    /invalid_post_meeting_generation_time/,
  );
  assert.throws(
    () => buildPostMeetingAnalysisInput({ ...base, generatedAt: "2026-08-27T17:00:00.001Z" }),
    /invalid_post_meeting_generation_time/,
  );
});

test("raw, fabricated, accessor, proxy, and cloned receipts cannot produce a Gmail proposal", () => {
  const correlation = correlationRequest();
  assert.equal(sourceVerificationReceiptContract.publicMintAvailable, false);
  assert.equal(sourceVerificationReceiptContract.gmailDraftProposalAvailable, false);
  assert.throws(() => proposeGmailDraftOnly(correlation), /untrusted_source_verification_receipt/);
  const fabricatedIdentity = Object.fromEntries(
    sourceVerificationReceiptContract.exactFields
      .filter((key) => key !== "receiptHash")
      .map((key) => {
        if (Object.hasOwn(correlation, key)) return [key, correlation[key]];
        if (key === "schemaVersion") return [key, 1];
        if (key === "receiptType") return [key, "source_verification_receipt"];
        if (key === "brokerOrigin") return [key, "qm_core_source_verification_broker"];
        if (key === "brokerInstanceRef") return [key, "qm_core_instance_01"];
        if (key === "verifiedAt") return [key, instant.now];
        if (key === "serverSequence") return [key, 1];
        throw new Error(`unhandled receipt field: ${key}`);
      }),
  );
  const fabricated = Object.freeze({ ...fabricatedIdentity, receiptHash: sha256Canonical(fabricatedIdentity) });
  assert.throws(() => proposeGmailDraftOnly(fabricated), /untrusted_source_verification_receipt/);
  assert.throws(() => proposeGmailDraftOnly(Object.freeze({ ...fabricated })), /untrusted_source_verification_receipt/);
  const accessor = { ...fabricated };
  Object.defineProperty(accessor, "receiptHash", { enumerable: true, get: () => hash("e") });
  Object.freeze(accessor);
  assert.throws(() => proposeGmailDraftOnly(accessor), /untrusted_source_verification_receipt/);
  assert.throws(() => proposeGmailDraftOnly(new Proxy(fabricated, {})), /untrusted_source_verification_receipt/);
});

test("goals artifacts bind an explicit period, timezone, versioned definition, and cited evidence", () => {
  const input = goalsInput();
  const artifact = buildGoalsAndEodArtifact(input);
  assert.equal(artifact.artifactType, "chief_of_staff.eod_update");
  assert.equal(artifact.period.timezone, "America/Los_Angeles");
  assert.equal(artifact.goals[0].trust, "configured_goal_definition");
  assert.equal(artifact.updates[0].trust, "generated_evidence_cited_update");
  assert.equal(artifact.presentationSinkAllowed, false);
  assert.throws(
    () => buildGoalsAndEodArtifact({ ...input, updates: [{ ...input.updates[0], citations: [] }] }),
    /unsupported_goal_status/,
  );
  assert.throws(
    () => buildGoalsAndEodArtifact({ ...input, goals: [{ ...input.goals[0], definitionHash: hash("f") }] }),
    /goal_definition_hash_mismatch/,
  );
});

test("goals reject dangling evidence and evidence-free goals only allow low-confidence unknown", () => {
  const dangling = goalsInput();
  dangling.goals[0].evidenceRefs = ["ev_missing_01"];
  assert.throws(() => buildGoalsAndEodArtifact(dangling), /dangling_goal_evidence_ref/);
  const definition = goalDefinition({
    goalRef: "goal_hiring_01",
    title: "Hire a sales lead",
    target: "Accepted offer",
  });
  const artifact = buildGoalsAndEodArtifact({
    principalRef: lineage.principalRef,
    periodKind: "weekly",
    periodStart: "2026-08-24T07:00:00.000Z",
    periodEnd: "2026-08-31T07:00:00.000Z",
    timezone: "America/Los_Angeles",
    generatedAt: "2026-08-31T07:05:00.000Z",
    goals: [{ ...definition, evidenceRefs: [] }],
    evidence: [],
    updates: [
      {
        goalRef: "goal_hiring_01",
        status: "unknown",
        summary: "No verified work evidence was available.",
        citations: [],
        confidence: "low",
      },
    ],
  });
  assert.equal(artifact.updates[0].status, "unknown");
});

test("goal status requires current-period evidence and generation after the period closes", () => {
  const beforeClose = goalsInput();
  beforeClose.generatedAt = "2026-08-27T06:59:59.000Z";
  assert.throws(() => buildGoalsAndEodArtifact(beforeClose), /invalid_goal_period/);
  const old = goalsInput();
  old.evidence[0] = {
    ...old.evidence[0],
    occurredAt: "2026-08-25T16:00:00.000Z",
    temporalRole: "prior_baseline",
  };
  assert.throws(() => buildGoalsAndEodArtifact(old), /stale_goal_status_evidence/);
  const mistyped = goalsInput();
  mistyped.evidence[0] = { ...mistyped.evidence[0], occurredAt: "2026-08-25T16:00:00.000Z" };
  assert.throws(() => buildGoalsAndEodArtifact(mistyped), /invalid_goal_evidence_period/);
});

test("daily weekly and quarterly periods require canonical local-midnight boundaries including DST", () => {
  const dstDaily = goalsInput();
  dstDaily.periodStart = "2026-11-01T07:00:00.000Z";
  dstDaily.periodEnd = "2026-11-02T08:00:00.000Z";
  dstDaily.generatedAt = "2026-11-02T08:05:00.000Z";
  dstDaily.evidence[0] = { ...dstDaily.evidence[0], occurredAt: "2026-11-01T18:00:00.000Z" };
  assert.equal(buildGoalsAndEodArtifact(dstDaily).period.kind, "daily");
  const noncanonical = goalsInput();
  noncanonical.periodEnd = "2026-08-27T08:00:00.000Z";
  noncanonical.generatedAt = "2026-08-27T08:05:00.000Z";
  assert.throws(() => buildGoalsAndEodArtifact(noncanonical), /noncanonical_goal_period/);
  const quarterly = goalsInput();
  quarterly.periodKind = "quarterly";
  quarterly.periodStart = "2026-01-01T08:00:00.000Z";
  quarterly.periodEnd = "2026-04-01T07:00:00.000Z";
  quarterly.generatedAt = "2026-04-01T07:05:00.000Z";
  quarterly.evidence[0] = { ...quarterly.evidence[0], occurredAt: "2026-03-01T18:00:00.000Z" };
  assert.equal(buildGoalsAndEodArtifact(quarterly).period.kind, "quarterly");
  const fractionalStart = goalsInput();
  fractionalStart.periodStart = "2026-08-26T07:00:00.001Z";
  assert.throws(() => buildGoalsAndEodArtifact(fractionalStart), /noncanonical_goal_period/);
  const fractionalEnd = goalsInput();
  fractionalEnd.periodEnd = "2026-08-27T07:00:00.001Z";
  fractionalEnd.generatedAt = "2026-08-27T07:05:00.000Z";
  assert.throws(() => buildGoalsAndEodArtifact(fractionalEnd), /noncanonical_goal_period/);
});

test("directional and invisible marks are rejected before any artifact contract", () => {
  const dossier = dossierInput();
  dossier.sections.accountOverview[0].text = "Safe\u200Bhidden";
  assert.throws(() => normalizeMeetingDossier(dossier), /invalid_plain_json/);
  const goals = goalsInput();
  goals.updates[0].summary = "Safe\u206Ahidden";
  assert.throws(() => buildGoalsAndEodArtifact(goals), /invalid_plain_json/);
  const endpoint = goalsInput();
  endpoint.updates[0].summary = "Safe\u206Fhidden";
  assert.throws(() => buildGoalsAndEodArtifact(endpoint), /invalid_plain_json/);
});
