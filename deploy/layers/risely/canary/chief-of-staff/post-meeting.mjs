import { types as utilTypes } from "node:util";
import { sha256Canonical } from "../contracts/index.mjs";
import {
  assertEmail,
  assertHash,
  assertInteger,
  assertRecord,
  assertRef,
  assertText,
  assertUnique,
  compareCodepoints,
  fail,
  parseInstant,
  snapshotPlainJson,
} from "./validation.mjs";

const meetingKeys = [
  "deploymentRef",
  "principalRef",
  "credentialOwnerRef",
  "connectionRef",
  "calendarAccountRef",
  "meetingKey",
  "calendarEventId",
  "occurrenceRef",
  "eventRevisionHash",
  "startAt",
  "endAt",
  "participants",
  "calendarEvidenceHash",
];
const correlationIdentityKeys = [
  "observedAt",
  "deploymentRef",
  "principalRef",
  "credentialOwnerRef",
  "connectionRef",
  "calendarAccountRef",
  "meetingKey",
  "calendarEventId",
  "occurrenceRef",
  "eventRevisionHash",
  "calendarEvidenceHash",
  "eventStartAt",
  "eventEndAt",
  "meetingParticipants",
  "transcriptRef",
  "providerTranscriptId",
  "transcriptProviderAccountRef",
  "transcriptRevision",
  "transcriptRevisionHash",
  "transcriptEvidenceHash",
  "transcriptContentHash",
  "transcriptRecordedStartAt",
  "transcriptRecordedEndAt",
  "transcriptFinalizedAt",
  "transcriptParticipants",
  "strength",
];
const correlationKeys = [
  "schemaVersion",
  "status",
  ...correlationIdentityKeys,
  "correlationHash",
  "verificationRequestHash",
  "requiredBrokerOrigin",
  "actionAllowed",
  "providerEffectAllowed",
];
const receiptKeys = [
  "schemaVersion",
  "receiptType",
  "brokerOrigin",
  "brokerInstanceRef",
  ...correlationIdentityKeys,
  "correlationHash",
  "verificationRequestHash",
  "verifiedAt",
  "serverSequence",
  "receiptHash",
];
const trustedSourceVerificationReceipts = new WeakSet();
const sourceBrokerOrigin = "qm_core_source_verification_broker";
const maxAnalysisDelayMs = 24 * 60 * 60 * 1000;

const normalizeMeetingParticipant = (input) => {
  assertRecord(input, ["email", "role", "response"], "invalid_meeting_participant");
  if (
    !["ceo", "internal", "external"].includes(input.role) ||
    !["accepted", "tentative", "needsAction", "declined"].includes(input.response)
  ) {
    fail("invalid_meeting_participant");
  }
  return Object.freeze({ email: assertEmail(input.email), role: input.role, response: input.response });
};

const normalizeMeetingCandidate = (input) => {
  assertRecord(input, meetingKeys, "invalid_meeting_candidate");
  const startAt = parseInstant(input.startAt);
  const endAt = parseInstant(input.endAt);
  if (endAt <= startAt || !Array.isArray(input.participants) || input.participants.length > 128) {
    fail("invalid_meeting_candidate");
  }
  const participants = input.participants
    .map(normalizeMeetingParticipant)
    .sort((left, right) => compareCodepoints(left.email, right.email));
  assertUnique(participants, (participant) => participant.email, "duplicate_meeting_participant");
  if (participants.filter((participant) => participant.role === "ceo").length !== 1) {
    fail("invalid_meeting_participant_roles");
  }
  return Object.freeze({
    deploymentRef: assertRef(input.deploymentRef),
    principalRef: assertRef(input.principalRef),
    credentialOwnerRef: assertRef(input.credentialOwnerRef),
    connectionRef: assertRef(input.connectionRef),
    calendarAccountRef: assertRef(input.calendarAccountRef),
    meetingKey: assertHash(input.meetingKey),
    calendarEventId: assertRef(input.calendarEventId),
    occurrenceRef: assertRef(input.occurrenceRef),
    eventRevisionHash: assertHash(input.eventRevisionHash),
    startAt: startAt.toISOString(),
    endAt: endAt.toISOString(),
    participants: Object.freeze(participants),
    calendarEvidenceHash: assertHash(input.calendarEvidenceHash),
  });
};

const normalizeTranscriptParticipant = (input) => {
  assertRecord(input, ["email", "role"], "invalid_transcript_participant");
  if (!["speaker", "attendee"].includes(input.role)) fail("invalid_transcript_participant");
  return Object.freeze({ email: assertEmail(input.email), role: input.role });
};

const normalizeTranscript = (input) => {
  if (!input || typeof input !== "object") fail("invalid_transcript");
  const required = [
    "transcriptRef",
    "providerTranscriptId",
    "providerAccountRef",
    "revision",
    "revisionHash",
    "recordedStartAt",
    "recordedEndAt",
    "finalizedAt",
    "participants",
    "evidenceHash",
    "contentHash",
  ];
  const optional = ["calendarEventId", "occurrenceRef"];
  const keys = Object.keys(input);
  if (
    required.some((key) => !Object.hasOwn(input, key)) ||
    keys.some((key) => !required.includes(key) && !optional.includes(key)) ||
    (input.calendarEventId === undefined) !== (input.occurrenceRef === undefined)
  ) {
    fail("invalid_transcript");
  }
  const recordedStartAt = parseInstant(input.recordedStartAt);
  const recordedEndAt = parseInstant(input.recordedEndAt);
  const finalizedAt = parseInstant(input.finalizedAt);
  if (
    input.revision !== "final" ||
    recordedEndAt <= recordedStartAt ||
    finalizedAt < recordedEndAt ||
    !Array.isArray(input.participants) ||
    input.participants.length > 128
  ) {
    fail("invalid_transcript");
  }
  const participants = input.participants
    .map(normalizeTranscriptParticipant)
    .sort((left, right) => compareCodepoints(left.email, right.email));
  assertUnique(participants, (participant) => participant.email, "duplicate_transcript_participant");
  return Object.freeze({
    transcriptRef: assertRef(input.transcriptRef),
    providerTranscriptId: assertRef(input.providerTranscriptId),
    providerAccountRef: assertRef(input.providerAccountRef),
    revision: "final",
    revisionHash: assertHash(input.revisionHash),
    ...(input.calendarEventId === undefined
      ? {}
      : { calendarEventId: assertRef(input.calendarEventId), occurrenceRef: assertRef(input.occurrenceRef) }),
    recordedStartAt: recordedStartAt.toISOString(),
    recordedEndAt: recordedEndAt.toISOString(),
    finalizedAt: finalizedAt.toISOString(),
    participants: Object.freeze(participants),
    evidenceHash: assertHash(input.evidenceHash),
    contentHash: assertHash(input.contentHash),
  });
};

const overlapsWithinTolerance = (meeting, transcript) => {
  const tolerance = 30 * 60 * 1000;
  return (
    parseInstant(transcript.recordedStartAt).valueOf() < parseInstant(meeting.endAt).valueOf() + tolerance &&
    parseInstant(transcript.recordedEndAt).valueOf() > parseInstant(meeting.startAt).valueOf() - tolerance
  );
};

const eligibleExternalEmails = (meeting) =>
  meeting.participants
    .filter((participant) => participant.role === "external" && participant.response !== "declined")
    .map((participant) => participant.email);

const sharesExternalParticipant = (meeting, transcript) => {
  const transcriptEmails = new Set(transcript.participants.map((participant) => participant.email));
  return eligibleExternalEmails(meeting).some((email) => transcriptEmails.has(email));
};

const finalizedAfterMeeting = (meeting, transcript) =>
  parseInstant(transcript.finalizedAt) >= parseInstant(meeting.endAt);

const verificationRequestIdentity = (identity) =>
  Object.freeze({
    brokerOrigin: sourceBrokerOrigin,
    deploymentRef: identity.deploymentRef,
    principalRef: identity.principalRef,
    credentialOwnerRef: identity.credentialOwnerRef,
    connectionRef: identity.connectionRef,
    calendarAccountRef: identity.calendarAccountRef,
    meetingKey: identity.meetingKey,
    calendarEventId: identity.calendarEventId,
    occurrenceRef: identity.occurrenceRef,
    eventRevisionHash: identity.eventRevisionHash,
    calendarEvidenceHash: identity.calendarEvidenceHash,
    transcriptRef: identity.transcriptRef,
    providerTranscriptId: identity.providerTranscriptId,
    transcriptProviderAccountRef: identity.transcriptProviderAccountRef,
    transcriptRevisionHash: identity.transcriptRevisionHash,
    transcriptEvidenceHash: identity.transcriptEvidenceHash,
    transcriptContentHash: identity.transcriptContentHash,
    correlationHash: sha256Canonical(identity),
  });

const normalizeCorrelationIdentity = (input) => {
  const observedAt = parseInstant(input.observedAt);
  if (!["exact_provider_identity", "unique_time_and_participant"].includes(input.strength)) {
    fail("invalid_transcript_correlation_request");
  }
  const meeting = normalizeMeetingCandidate({
    deploymentRef: input.deploymentRef,
    principalRef: input.principalRef,
    credentialOwnerRef: input.credentialOwnerRef,
    connectionRef: input.connectionRef,
    calendarAccountRef: input.calendarAccountRef,
    meetingKey: input.meetingKey,
    calendarEventId: input.calendarEventId,
    occurrenceRef: input.occurrenceRef,
    eventRevisionHash: input.eventRevisionHash,
    startAt: input.eventStartAt,
    endAt: input.eventEndAt,
    participants: input.meetingParticipants,
    calendarEvidenceHash: input.calendarEvidenceHash,
  });
  const transcript = normalizeTranscript({
    transcriptRef: input.transcriptRef,
    providerTranscriptId: input.providerTranscriptId,
    providerAccountRef: input.transcriptProviderAccountRef,
    revision: input.transcriptRevision,
    revisionHash: input.transcriptRevisionHash,
    ...(input.strength === "exact_provider_identity"
      ? { calendarEventId: meeting.calendarEventId, occurrenceRef: meeting.occurrenceRef }
      : {}),
    recordedStartAt: input.transcriptRecordedStartAt,
    recordedEndAt: input.transcriptRecordedEndAt,
    finalizedAt: input.transcriptFinalizedAt,
    participants: input.transcriptParticipants,
    evidenceHash: input.transcriptEvidenceHash,
    contentHash: input.transcriptContentHash,
  });
  if (
    parseInstant(transcript.finalizedAt) > observedAt ||
    !overlapsWithinTolerance(meeting, transcript) ||
    !sharesExternalParticipant(meeting, transcript) ||
    !finalizedAfterMeeting(meeting, transcript)
  ) {
    fail("invalid_transcript_correlation_request");
  }
  return Object.freeze({
    observedAt: observedAt.toISOString(),
    deploymentRef: meeting.deploymentRef,
    principalRef: meeting.principalRef,
    credentialOwnerRef: meeting.credentialOwnerRef,
    connectionRef: meeting.connectionRef,
    calendarAccountRef: meeting.calendarAccountRef,
    meetingKey: meeting.meetingKey,
    calendarEventId: meeting.calendarEventId,
    occurrenceRef: meeting.occurrenceRef,
    eventRevisionHash: meeting.eventRevisionHash,
    calendarEvidenceHash: meeting.calendarEvidenceHash,
    eventStartAt: meeting.startAt,
    eventEndAt: meeting.endAt,
    meetingParticipants: meeting.participants,
    transcriptRef: transcript.transcriptRef,
    providerTranscriptId: transcript.providerTranscriptId,
    transcriptProviderAccountRef: transcript.providerAccountRef,
    transcriptRevision: transcript.revision,
    transcriptRevisionHash: transcript.revisionHash,
    transcriptEvidenceHash: transcript.evidenceHash,
    transcriptContentHash: transcript.contentHash,
    transcriptRecordedStartAt: transcript.recordedStartAt,
    transcriptRecordedEndAt: transcript.recordedEndAt,
    transcriptFinalizedAt: transcript.finalizedAt,
    transcriptParticipants: transcript.participants,
    strength: input.strength,
  });
};

export const correlateFinalTranscript = (input) => {
  const value = snapshotPlainJson(input);
  assertRecord(value, ["now", "transcript", "candidateMeetings"], "invalid_transcript_correlation");
  const observedAt = parseInstant(value.now);
  const transcript = normalizeTranscript(value.transcript);
  if (parseInstant(transcript.finalizedAt) > observedAt) fail("future_final_transcript");
  if (!Array.isArray(value.candidateMeetings) || value.candidateMeetings.length > 128) {
    fail("invalid_transcript_correlation");
  }
  const meetings = value.candidateMeetings.map(normalizeMeetingCandidate);
  assertUnique(meetings, (meeting) => meeting.meetingKey, "duplicate_meeting_candidate");
  const exact =
    transcript.calendarEventId === undefined
      ? []
      : meetings.filter(
          (meeting) =>
            meeting.calendarEventId === transcript.calendarEventId &&
            meeting.occurrenceRef === transcript.occurrenceRef &&
            overlapsWithinTolerance(meeting, transcript) &&
            sharesExternalParticipant(meeting, transcript) &&
            finalizedAfterMeeting(meeting, transcript),
        );
  const heuristic = meetings.filter(
    (meeting) =>
      overlapsWithinTolerance(meeting, transcript) &&
      sharesExternalParticipant(meeting, transcript) &&
      finalizedAfterMeeting(meeting, transcript),
  );
  const matches = transcript.calendarEventId === undefined ? heuristic : exact;
  if (matches.length !== 1) {
    return Object.freeze({
      schemaVersion: 1,
      status: matches.length === 0 ? "unmatched" : "ambiguous",
      transcriptRef: transcript.transcriptRef,
      providerTranscriptId: transcript.providerTranscriptId,
      transcriptRevision: transcript.revision,
      transcriptRevisionHash: transcript.revisionHash,
      candidateMeetingKeys: Object.freeze(matches.map((meeting) => meeting.meetingKey).sort(compareCodepoints)),
      actionAllowed: false,
    });
  }
  const meeting = matches[0];
  const identity = Object.freeze({
    observedAt: observedAt.toISOString(),
    deploymentRef: meeting.deploymentRef,
    principalRef: meeting.principalRef,
    credentialOwnerRef: meeting.credentialOwnerRef,
    connectionRef: meeting.connectionRef,
    calendarAccountRef: meeting.calendarAccountRef,
    meetingKey: meeting.meetingKey,
    calendarEventId: meeting.calendarEventId,
    occurrenceRef: meeting.occurrenceRef,
    eventRevisionHash: meeting.eventRevisionHash,
    calendarEvidenceHash: meeting.calendarEvidenceHash,
    eventStartAt: meeting.startAt,
    eventEndAt: meeting.endAt,
    meetingParticipants: meeting.participants,
    transcriptRef: transcript.transcriptRef,
    providerTranscriptId: transcript.providerTranscriptId,
    transcriptProviderAccountRef: transcript.providerAccountRef,
    transcriptRevision: transcript.revision,
    transcriptRevisionHash: transcript.revisionHash,
    transcriptEvidenceHash: transcript.evidenceHash,
    transcriptContentHash: transcript.contentHash,
    transcriptRecordedStartAt: transcript.recordedStartAt,
    transcriptRecordedEndAt: transcript.recordedEndAt,
    transcriptFinalizedAt: transcript.finalizedAt,
    transcriptParticipants: transcript.participants,
    strength: exact.length === 1 ? "exact_provider_identity" : "unique_time_and_participant",
  });
  const correlationHash = sha256Canonical(identity);
  const requestIdentity = verificationRequestIdentity(identity);
  return Object.freeze({
    schemaVersion: 1,
    status: "verification_required",
    ...identity,
    correlationHash,
    verificationRequestHash: sha256Canonical(requestIdentity),
    requiredBrokerOrigin: sourceBrokerOrigin,
    actionAllowed: false,
    providerEffectAllowed: false,
  });
};

const normalizeCorrelation = (input) => {
  assertRecord(input, correlationKeys, "invalid_transcript_correlation_request");
  if (
    input.schemaVersion !== 1 ||
    input.status !== "verification_required" ||
    input.requiredBrokerOrigin !== sourceBrokerOrigin ||
    input.actionAllowed !== false ||
    input.providerEffectAllowed !== false ||
    input.transcriptRevision !== "final" ||
    !["exact_provider_identity", "unique_time_and_participant"].includes(input.strength)
  ) {
    fail("invalid_transcript_correlation_request");
  }
  const identity = normalizeCorrelationIdentity(
    Object.fromEntries(correlationIdentityKeys.map((key) => [key, input[key]])),
  );
  if (assertHash(input.correlationHash) !== sha256Canonical(identity)) fail("transcript_correlation_hash_mismatch");
  const requestIdentity = verificationRequestIdentity(identity);
  if (assertHash(input.verificationRequestHash) !== sha256Canonical(requestIdentity)) {
    fail("transcript_verification_request_mismatch");
  }
  return Object.freeze({ ...input, ...identity });
};

export const buildPostMeetingAnalysisInput = (input) => {
  const value = snapshotPlainJson(input);
  assertRecord(
    value,
    ["generatedAt", "meeting", "dossierBinding", "transcriptCorrelation", "transcriptText"],
    "invalid_post_meeting_input",
  );
  const generatedAt = parseInstant(value.generatedAt);
  const meeting = normalizeMeetingCandidate(value.meeting);
  assertRecord(value.dossierBinding, ["artifactHash", "meetingKey", "calendarEvidenceHash"], "invalid_dossier_binding");
  if (
    value.dossierBinding.meetingKey !== meeting.meetingKey ||
    value.dossierBinding.calendarEvidenceHash !== meeting.calendarEvidenceHash
  ) {
    fail("dossier_binding_mismatch");
  }
  const dossierBinding = Object.freeze({
    artifactHash: assertHash(value.dossierBinding.artifactHash),
    meetingKey: meeting.meetingKey,
    calendarEvidenceHash: meeting.calendarEvidenceHash,
  });
  const correlation = normalizeCorrelation(value.transcriptCorrelation);
  if (
    correlation.deploymentRef !== meeting.deploymentRef ||
    correlation.principalRef !== meeting.principalRef ||
    correlation.credentialOwnerRef !== meeting.credentialOwnerRef ||
    correlation.connectionRef !== meeting.connectionRef ||
    correlation.calendarAccountRef !== meeting.calendarAccountRef ||
    correlation.meetingKey !== meeting.meetingKey ||
    correlation.calendarEventId !== meeting.calendarEventId ||
    correlation.occurrenceRef !== meeting.occurrenceRef ||
    correlation.eventRevisionHash !== meeting.eventRevisionHash ||
    correlation.calendarEvidenceHash !== meeting.calendarEvidenceHash ||
    correlation.eventStartAt !== meeting.startAt ||
    correlation.eventEndAt !== meeting.endAt ||
    sha256Canonical(correlation.meetingParticipants) !== sha256Canonical(meeting.participants)
  ) {
    fail("transcript_correlation_mismatch");
  }
  const finalizedAt = parseInstant(correlation.transcriptFinalizedAt);
  const observedAt = parseInstant(correlation.observedAt);
  if (
    generatedAt < finalizedAt ||
    generatedAt < observedAt ||
    generatedAt.valueOf() > observedAt.valueOf() + maxAnalysisDelayMs ||
    generatedAt.valueOf() > finalizedAt.valueOf() + maxAnalysisDelayMs
  ) {
    fail("invalid_post_meeting_generation_time");
  }
  const transcriptText = assertText(value.transcriptText, 131_072);
  if (sha256Canonical({ transcriptText }) !== assertHash(correlation.transcriptContentHash)) {
    fail("transcript_content_mismatch");
  }
  const normalized = Object.freeze({
    schemaVersion: 1,
    generatedAt: generatedAt.toISOString(),
    meeting,
    dossierBinding,
    sourceVerification: Object.freeze({
      status: "required",
      requiredBrokerOrigin: sourceBrokerOrigin,
      correlationHash: correlation.correlationHash,
      verificationRequestHash: correlation.verificationRequestHash,
      providerEffectAllowed: false,
    }),
    transcript: Object.freeze({
      transcriptRef: correlation.transcriptRef,
      providerTranscriptId: correlation.providerTranscriptId,
      providerAccountRef: correlation.transcriptProviderAccountRef,
      revision: correlation.transcriptRevision,
      revisionHash: correlation.transcriptRevisionHash,
      evidenceHash: correlation.transcriptEvidenceHash,
      contentHash: correlation.transcriptContentHash,
      recordedStartAt: correlation.transcriptRecordedStartAt,
      recordedEndAt: correlation.transcriptRecordedEndAt,
      finalizedAt: correlation.transcriptFinalizedAt,
      participants: correlation.transcriptParticipants,
      text: transcriptText,
      trust: "unverified_transcript_data",
    }),
    requiredAnalysis: Object.freeze([
      "whatWentWell",
      "whatDidnt",
      "decisions",
      "actionItems",
      "risks",
      "recommendedNextSteps",
    ]),
    citationsRequired: true,
    presentationSinkAllowed: false,
    actionAllowed: false,
  });
  return Object.freeze({ ...normalized, inputHash: sha256Canonical(normalized) });
};

const assertDescriptorSafeVerificationReceipt = (input) => {
  if (
    !input ||
    typeof input !== "object" ||
    utilTypes.isProxy(input) ||
    Object.getPrototypeOf(input) !== Object.prototype ||
    Object.getOwnPropertySymbols(input).length !== 0 ||
    !Object.isFrozen(input)
  ) {
    fail("untrusted_source_verification_receipt");
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (
    Object.keys(descriptors).length !== receiptKeys.length ||
    receiptKeys.some((key) => {
      const descriptor = descriptors[key];
      return (
        !descriptor ||
        !Object.hasOwn(descriptor, "value") ||
        Object.hasOwn(descriptor, "get") ||
        Object.hasOwn(descriptor, "set") ||
        descriptor.enumerable !== true
      );
    })
  ) {
    fail("untrusted_source_verification_receipt");
  }
  const value = snapshotPlainJson(
    Object.freeze(Object.fromEntries(receiptKeys.map((key) => [key, descriptors[key].value]))),
  );
  if (
    value.schemaVersion !== 1 ||
    value.receiptType !== "source_verification_receipt" ||
    value.brokerOrigin !== sourceBrokerOrigin ||
    value.transcriptRevision !== "final" ||
    !["exact_provider_identity", "unique_time_and_participant"].includes(value.strength)
  ) {
    fail("untrusted_source_verification_receipt");
  }
  assertRef(value.brokerInstanceRef);
  assertInteger(value.serverSequence, 1, Number.MAX_SAFE_INTEGER);
  const verifiedAt = parseInstant(value.verifiedAt);
  const observedAt = parseInstant(value.observedAt);
  const transcriptFinalizedAt = parseInstant(value.transcriptFinalizedAt);
  if (verifiedAt < observedAt || verifiedAt < transcriptFinalizedAt) {
    fail("invalid_source_verification_time");
  }
  const correlationIdentity = normalizeCorrelationIdentity(
    Object.fromEntries(correlationIdentityKeys.map((key) => [key, value[key]])),
  );
  if (assertHash(value.correlationHash) !== sha256Canonical(correlationIdentity)) {
    fail("source_verification_correlation_mismatch");
  }
  const requestIdentity = verificationRequestIdentity(correlationIdentity);
  if (assertHash(value.verificationRequestHash) !== sha256Canonical(requestIdentity)) {
    fail("source_verification_request_mismatch");
  }
  const receiptIdentity = Object.freeze({
    schemaVersion: 1,
    receiptType: "source_verification_receipt",
    brokerOrigin: sourceBrokerOrigin,
    brokerInstanceRef: value.brokerInstanceRef,
    ...correlationIdentity,
    correlationHash: value.correlationHash,
    verificationRequestHash: value.verificationRequestHash,
    verifiedAt: verifiedAt.toISOString(),
    serverSequence: value.serverSequence,
  });
  if (assertHash(value.receiptHash) !== sha256Canonical(receiptIdentity)) {
    fail("source_verification_receipt_hash_mismatch");
  }
  if (!trustedSourceVerificationReceipts.has(input)) fail("untrusted_source_verification_receipt");
  return input;
};

export const proposeGmailDraftOnly = (sourceVerificationReceipt) => {
  assertDescriptorSafeVerificationReceipt(sourceVerificationReceipt);
  fail("source_verification_broker_not_implemented");
};

export const sourceVerificationReceiptContract = Object.freeze({
  schemaVersion: 1,
  receiptType: "source_verification_receipt",
  brokerOrigin: sourceBrokerOrigin,
  exactFields: Object.freeze([...receiptKeys]),
  descriptorSafeReceiptRequired: true,
  serverMintedReceiptRequired: true,
  publicMintAvailable: false,
  gmailDraftProposalAvailable: false,
  maxAnalysisDelaySeconds: maxAnalysisDelayMs / 1_000,
});
