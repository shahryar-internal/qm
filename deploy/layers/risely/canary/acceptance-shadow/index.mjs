import { types } from "node:util";
import {
  buildPostMeetingAnalysisInput,
  correlateFinalTranscript,
  normalizeMeetingDossier,
  planChiefOfStaffSchedule,
} from "../chief-of-staff/index.mjs";
import { deploymentConnectionAnchors } from "../revenue-program/index.mjs";
import { mintEvaluationRelease, prepareEvaluationCandidate } from "../evals/index.mjs";
import {
  EvidenceBundle,
  OutboxEvent,
  PrincipalBinding,
  PublicationEnvelope,
  WorkflowArtifact,
} from "../shared-contracts/index.mjs";
import { composePrivateCeoSurfaces } from "../surface-integration/index.mjs";
import { bindProviderFreeV6AcceptanceFacade, ProviderFreeV6AcceptanceStore } from "./provider-free-v6.mjs";

export { bindProviderFreeV6AcceptanceFacade, ProviderFreeV6AcceptanceStore };

const snapshot = PrincipalBinding.snapshot;
const hash = PrincipalBinding.hash;
const freeze = PrincipalBinding.freeze;
const compiledMeetingPreps = new WeakSet();
const issuedDossiers = new WeakSet();
const issuedSchedules = new WeakSet();

const calendarLineage = Object.freeze({
  connectionRef: "connection:google-calendar:ceo-shadow",
  calendarAccountRef: "calendar-account:ceo-shadow",
  providerAccountSubject: "google-subject:ceo-shadow",
  destinationRef: "destination:slack:ceo-private-dm",
  destination: "slack_ceo_dm",
});

const sourceNames = Object.freeze(["calendar", "gmail", "clarify", "command_center_brain", "notion"]);

function exact(value, fields, label) {
  const input = snapshot(value, label);
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).some((field) => !fields.includes(field)) ||
    fields.some((field) => !Object.hasOwn(input, field))
  ) {
    throw new TypeError(`${label} has an unsupported shape`);
  }
  return input;
}

function exactOptional(value, required, optional, label) {
  const input = snapshot(value, label);
  const allowed = [...required, ...optional];
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).some((field) => !allowed.includes(field)) ||
    required.some((field) => !Object.hasOwn(input, field))
  ) {
    throw new TypeError(`${label} has an unsupported shape`);
  }
  return input;
}

function calendarBindingReceipt() {
  const projection = {
    contractType: "CalendarBindingResolutionReceipt",
    contractVersion: 1,
    brokerOrigin: "future_qm_connector_binding_broker",
    logicalGoogleAnchorRef: deploymentConnectionAnchors.googleAccountRef,
    connectionRef: calendarLineage.connectionRef,
    calendarAccountRef: calendarLineage.calendarAccountRef,
    providerAccountSubject: calendarLineage.providerAccountSubject,
    principalRef: PrincipalBinding.identity.principalRef,
    credentialOwnerRef: PrincipalBinding.identity.credentialOwnerRef,
    receiptDisposition: "unresolved",
  };
  return freeze({ ...projection, receiptSha256: hash(projection) });
}

function adaptCalendarOccurrenceForAcceptance(meeting) {
  const bindingResolution = calendarBindingReceipt();
  const recurring = meeting.seriesId !== undefined;
  const providerIdentity = recurring
    ? { seriesId: meeting.seriesId, originalStartAt: meeting.originalStartAt }
    : { providerEventId: meeting.providerEventId };
  const occurrenceRef = `occurrence:${hash({
    principalBindingSha256: PrincipalBinding.value.bindingSha256,
    calendarAccountRef: bindingResolution.calendarAccountRef,
    providerIdentity,
  })}`;
  const occurrence = freeze({
    providerEventId: meeting.providerEventId,
    originalStartAt: recurring ? meeting.originalStartAt : meeting.startAt,
    startAt: meeting.startAt,
    endAt: meeting.endAt,
    status: meeting.status,
    allDay: meeting.allDay,
    visibility: meeting.visibility,
    seriesId: recurring ? meeting.seriesId : null,
    attendees: meeting.attendees.map((entry) => ({
      attendeeRef: entry.attendeeRef,
      role: entry.role,
      response: entry.response,
    })),
    occurrenceRef,
  });
  const evidence = freeze({
    evidenceSha256: hash(occurrence),
    source: "google_calendar",
    providerAccountSubject: bindingResolution.providerAccountSubject,
    calendarAccountRef: bindingResolution.calendarAccountRef,
    occurrenceRef,
  });
  const shared = freeze({ ...occurrence, evidence });
  const laneProjection = (lane) =>
    freeze({
      lane,
      ...(lane === "chief_of_staff"
        ? { connectionRef: bindingResolution.connectionRef }
        : { logicalGoogleAnchorRef: bindingResolution.logicalGoogleAnchorRef }),
      calendarAccountRef: bindingResolution.calendarAccountRef,
      providerAccountSubject: bindingResolution.providerAccountSubject,
      principalRef: bindingResolution.principalRef,
      occurrence: shared,
      evidence,
      disposition: "prospective_unverified",
      providerEffectAllowed: false,
    });
  return freeze({
    bindingResolution,
    revenue: laneProjection("revenue_program"),
    chiefOfStaff: laneProjection("chief_of_staff"),
    receiptAuthenticated: false,
    disposition: "prospective_unverified",
  });
}

function normalizeSanitizedMeeting(value) {
  const meeting = exactOptional(
    value,
    ["providerEventId", "startAt", "endAt", "status", "allDay", "visibility", "title", "evidenceHash", "attendees"],
    ["seriesId", "originalStartAt"],
    "Sanitized Calendar meeting",
  );
  if ((meeting.seriesId === undefined) !== (meeting.originalStartAt === undefined)) {
    throw new TypeError("Sanitized recurring meeting identity is incomplete");
  }
  if (!Array.isArray(meeting.attendees) || meeting.attendees.length < 2) {
    throw new TypeError("Sanitized Calendar meeting requires CEO and external attendees");
  }
  const attendees = meeting.attendees.map((entry, index) =>
    exact(entry, ["attendeeRef", "email", "role", "response"], `Sanitized Calendar attendee ${index}`),
  );
  if (attendees.filter((entry) => entry.role === "ceo").length !== 1) {
    throw new TypeError("Sanitized Calendar meeting requires one CEO attendee");
  }
  if (!attendees.some((entry) => entry.role === "external")) {
    throw new TypeError("Sanitized Calendar meeting requires an external attendee");
  }
  return freeze({ ...meeting, attendees: freeze(attendees) });
}

function schedulerResponse(value) {
  return value === "needs_action" ? "needsAction" : value;
}

function scheduleLineage() {
  return {
    organizationRef: PrincipalBinding.identity.organizationRef,
    deploymentRef: PrincipalBinding.identity.deploymentRef,
    principalRef: PrincipalBinding.identity.principalRef,
    credentialOwnerRef: PrincipalBinding.identity.credentialOwnerRef,
    connectionRef: calendarLineage.connectionRef,
    calendarAccountRef: calendarLineage.calendarAccountRef,
    audienceRef: PrincipalBinding.identity.audienceRef,
    audience: "ceo_private",
    destinationRef: calendarLineage.destinationRef,
    destination: calendarLineage.destination,
  };
}

export function compileCalendarLifecycle(value) {
  const input = exact(
    value,
    ["now", "pollWindowEnd", "calendarAvailability", "meeting", "priorJobs"],
    "Calendar lifecycle acceptance input",
  );
  if (!Array.isArray(input.priorJobs)) throw new TypeError("Calendar lifecycle priorJobs must be a list");
  if (input.calendarAvailability === "unavailable") {
    if (input.meeting !== null) throw new TypeError("Unavailable Calendar cannot include a meeting");
    const schedule = planChiefOfStaffSchedule({
      now: input.now,
      pollWindowEnd: input.pollWindowEnd,
      ...scheduleLineage(),
      calendarSnapshotHash: hash({ calendarAvailability: "unavailable", now: input.now }),
      calendarAvailability: "unavailable",
      events: [],
      priorJobs: input.priorJobs,
    });
    issuedSchedules.add(schedule);
    return freeze({
      state: "calendar_unavailable",
      calendarProjection: null,
      schedule,
      receiptAuthenticated: false,
      providerEffectAllowed: false,
    });
  }
  if (input.calendarAvailability !== "available" || input.meeting === null) {
    throw new TypeError("Available Calendar requires one sanitized meeting");
  }
  const meeting = normalizeSanitizedMeeting(input.meeting);
  const recurring = meeting.seriesId !== undefined;
  const calendarProjection = adaptCalendarOccurrenceForAcceptance(meeting);
  const ceo = meeting.attendees.find((entry) => entry.role === "ceo");
  const schedulerEvent = {
    calendarEventId: meeting.providerEventId,
    occurrenceRef: recurring
      ? `series:${meeting.seriesId}:${meeting.originalStartAt}`
      : `event:${meeting.providerEventId}`,
    recurrenceKind: recurring ? "recurring" : "single",
    ...(recurring ? { seriesId: meeting.seriesId, recurrenceOriginalStartAt: meeting.originalStartAt } : {}),
    startAt: meeting.startAt,
    endAt: meeting.endAt,
    status: meeting.status,
    allDay: meeting.allDay,
    visibility: meeting.visibility,
    ceoResponse: schedulerResponse(ceo.response),
    title: meeting.title,
    attendees: meeting.attendees.map((entry) => ({
      email: entry.email,
      external: entry.role === "external",
      response: schedulerResponse(entry.response),
    })),
    evidenceHash: meeting.evidenceHash,
  };
  const schedule = planChiefOfStaffSchedule({
    now: input.now,
    pollWindowEnd: input.pollWindowEnd,
    ...scheduleLineage(),
    calendarSnapshotHash: hash({
      providerEventId: meeting.providerEventId,
      startAt: meeting.startAt,
      endAt: meeting.endAt,
      status: meeting.status,
      evidenceHash: meeting.evidenceHash,
    }),
    calendarAvailability: "available",
    events: [schedulerEvent],
    priorJobs: input.priorJobs,
  });
  issuedSchedules.add(schedule);
  return freeze({
    state: schedule.desiredJobs.length ? "scheduled" : "suppressed",
    meeting,
    calendarProjection,
    schedule,
    acceptanceBinding: freeze({
      providerEventId: meeting.providerEventId,
      publicOccurrenceRef: calendarProjection.chiefOfStaff.occurrence.occurrenceRef,
      schedulerOccurrenceRef: schedulerEvent.occurrenceRef,
      evidenceHash: meeting.evidenceHash,
      disposition: "prospective_unverified_bridge",
    }),
    receiptAuthenticated: false,
    providerEffectAllowed: false,
  });
}

export function priorJobsFromSchedule(plan, status = "scheduled") {
  if (types.isProxy(plan) || !issuedSchedules.has(plan)) {
    throw new TypeError("Prior jobs require a scheduler-issued plan");
  }
  if (!Array.isArray(plan.desiredJobs) || !["scheduled", "leased"].includes(status)) {
    throw new TypeError("Prior job status is unsupported");
  }
  return freeze(
    plan.desiredJobs.map((job, index) => ({
      organizationRef: job.organizationRef,
      deploymentRef: job.deploymentRef,
      principalRef: job.principalRef,
      credentialOwnerRef: job.credentialOwnerRef,
      connectionRef: job.connectionRef,
      calendarAccountRef: job.calendarAccountRef,
      audienceRef: job.audienceRef,
      audience: job.audience,
      destinationRef: job.destinationRef,
      destination: job.destination,
      planHash: job.planHash,
      jobId: job.jobId,
      meetingKey: job.meetingKey,
      kind: job.kind,
      scheduleRevision: job.scheduleRevision,
      jobRevision: job.jobRevision,
      claimFence: status === "leased" ? `claim:acceptance:${index + 1}` : null,
      fireAt: job.fireAt,
      status,
    })),
  );
}

function dossierFromLifecycle(lifecycle, generatedAt, availabilityValue) {
  const availability = exact(availabilityValue, sourceNames, "Dossier source availability");
  if (availability.calendar !== "available")
    throw new TypeError("Meeting dossier requires available Calendar evidence");
  const firstJob = lifecycle.schedule.desiredJobs[0];
  if (!firstJob) throw new TypeError("Meeting dossier requires an eligible scheduled meeting");
  const sources = sourceNames.map((source) => ({ source, availability: availability[source] }));
  const evidence = sources
    .filter((entry) => entry.availability === "available")
    .map((entry) => ({
      evidenceRef: `acceptance:${entry.source}:${firstJob.meetingKey.slice(0, 24)}`,
      source: entry.source,
      evidenceHash:
        entry.source === "calendar"
          ? firstJob.input.calendarEvidenceHash
          : hash({ source: entry.source, meetingKey: firstJob.meetingKey, generatedAt }),
      capturedAt: generatedAt,
    }));
  const evidenceBySource = new Map(evidence.map((entry) => [entry.source, entry.evidenceRef]));
  const citationFor = (...preferred) => {
    for (const source of preferred) if (evidenceBySource.has(source)) return evidenceBySource.get(source);
    return evidenceBySource.get("calendar");
  };
  const dossier = normalizeMeetingDossier({
    meetingKey: firstJob.meetingKey,
    generatedAt,
    calendarEvidenceHash: firstJob.input.calendarEvidenceHash,
    sources,
    evidence,
    sections: {
      accountOverview: [
        {
          claimId: "claim:acceptance:account",
          text: "Account context is ready for review.",
          citations: [citationFor("command_center_brain", "notion")],
        },
      ],
      contactBackground: [
        {
          claimId: "claim:acceptance:contact",
          text: "Contact context is ready for review.",
          citations: [citationFor("gmail", "clarify")],
        },
      ],
      recommendedPositioning: [
        {
          claimId: "claim:acceptance:positioning",
          text: "Recommended positioning is ready for review.",
          citations: evidence.map((entry) => entry.evidenceRef),
        },
      ],
    },
  });
  issuedDossiers.add(dossier);
  return dossier;
}

function adaptDossierForAcceptance(dossier) {
  if (types.isProxy(dossier) || !issuedDossiers.has(dossier)) {
    throw new TypeError("Acceptance dossier adapter requires an issued dossier");
  }
  const claims = Object.values(dossier.sections).flat();
  const claimRefsByEvidence = new Map();
  for (const claim of claims) {
    const claimRef = `claim:${hash({ claimId: claim.claimId, text: claim.text, trust: claim.trust })}`;
    for (const citation of claim.citations) {
      const current = claimRefsByEvidence.get(citation) ?? [];
      current.push(claimRef);
      claimRefsByEvidence.set(citation, current);
    }
  }
  const evidence = dossier.evidence.map((entry) => {
    const claimRefs = claimRefsByEvidence.get(entry.evidenceRef) ?? [];
    if (claimRefs.length === 0) throw new TypeError("Acceptance dossier evidence is not cited");
    return {
      source: entry.source,
      sourceRecordRef: `source-record:${hash(entry)}`,
      contentSha256: entry.evidenceHash,
      relatedContentSha256: [],
      observedAt: entry.capturedAt,
      fetchedAt: entry.capturedAt,
      status: "cited",
      trust: "untrusted_source_data",
      availability: "available",
      sourceTrust: "untrusted_source_data",
      sourceAvailability: "available",
      claimRefs,
    };
  });
  const evidenceBundle = EvidenceBundle.create({ principalBinding: PrincipalBinding.value, evidence });
  return WorkflowArtifact.create({
    principalBinding: PrincipalBinding.value,
    sourceLane: "chief_of_staff",
    sourceArtifactRef: `source:${hash({ lane: "chief_of_staff", meetingKey: dossier.meetingKey })}`,
    sourceArtifactSha256: dossier.artifactHash,
    sourceRevision: hash({ artifactHash: dossier.artifactHash, generatedAt: dossier.generatedAt }),
    workflowKind: "meeting_prep",
    state: "ready",
    evidenceBundle,
    updatedAt: dossier.generatedAt,
  });
}

function surfaceArtifact(artifact) {
  const value = WorkflowArtifact.validate(artifact);
  return freeze({
    schemaVersion: 1,
    artifactRef: value.artifactRef,
    revision: value.revision,
    kind: value.workflowKind,
    state: value.state,
    evidence: value.evidenceBundle.evidence.map((entry) => ({
      evidenceRef: entry.evidenceRef,
      trust: entry.trust,
      availability: entry.availability,
    })),
    links: [],
  });
}

function publicationEnvelope(event) {
  return PublicationEnvelope.create({ outboxEvent: OutboxEvent.validate(event) });
}

function publicationSet(artifact, evalRelease, queuedAt, surfaces) {
  return freeze(
    Object.fromEntries(
      ["slack", "qm", "notion"].map((surface) => {
        const outboxEvent = OutboxEvent.create({
          principalBinding: PrincipalBinding.value,
          artifact,
          evalRelease,
          surface,
          queuedAt,
        });
        const envelope = publicationEnvelope(outboxEvent);
        const rendered = surfaces[surface];
        return [
          surface,
          freeze({
            outboxEvent,
            publicationEnvelope: envelope,
            publication: freeze({
              surface,
              audienceRef: outboxEvent.audienceRef,
              artifactRef: artifact.artifactRef,
              artifactRevision: artifact.revision,
              artifactSha256: artifact.artifactSha256,
              evalReleaseSha256: evalRelease.releaseSha256,
              eventId: outboxEvent.eventId,
              eventSha256: outboxEvent.eventSha256,
              envelopeSha256: envelope.envelopeSha256,
              renderedSha256: hash(rendered),
              actionless: true,
              providerInvocationAllowed: false,
            }),
          }),
        ];
      }),
    ),
  );
}

function evaluationCandidate(authority, artifact, dossier, input) {
  return prepareEvaluationCandidate(authority, {
    artifact,
    evaluationPayload: dossier,
    evaluationStartedAt: input.evaluatedAt,
    expiresAt: input.expiresAt,
    runNonce: hash({
      artifactSha256: artifact.artifactSha256,
      evaluatedAt: input.evaluatedAt,
      expiresAt: input.expiresAt,
      purpose: "meeting-prep-shadow-acceptance",
    }),
  });
}

function prepareMeetingPrep(value) {
  const input = exact(
    value,
    ["now", "pollWindowEnd", "meeting", "sourceAvailability", "generatedAt", "evaluatedAt", "expiresAt", "queuedAt"],
    "Meeting prep shadow input",
  );
  const lifecycle = compileCalendarLifecycle({
    now: input.now,
    pollWindowEnd: input.pollWindowEnd,
    calendarAvailability: "available",
    meeting: input.meeting,
    priorJobs: [],
  });
  const dossier = dossierFromLifecycle(lifecycle, input.generatedAt, input.sourceAvailability);
  const artifact = adaptDossierForAcceptance(dossier);
  return freeze({ input, lifecycle, dossier, artifact });
}

export function prepareMeetingPrepShadowEvaluation(value, authority) {
  const prepared = prepareMeetingPrep(value);
  return evaluationCandidate(authority, prepared.artifact, prepared.dossier, prepared.input);
}

export async function compileMeetingPrepShadow(value, authority, judgeResults) {
  const prepared = prepareMeetingPrep(value);
  const candidate = evaluationCandidate(authority, prepared.artifact, prepared.dossier, prepared.input);
  const evalRelease = await mintEvaluationRelease(authority, {
    candidate,
    judgeResults,
  });
  const surfaces = composePrivateCeoSurfaces(surfaceArtifact(prepared.artifact));
  const compiledPublications = publicationSet(prepared.artifact, evalRelease, prepared.input.queuedAt, surfaces);
  const compiled = freeze({
    schemaVersion: 1,
    state: "ready",
    lifecycle: prepared.lifecycle,
    dossier: prepared.dossier,
    artifact: prepared.artifact,
    evalRelease,
    publicationSet: compiledPublications,
    surfaces,
    providerInvocationAllowed: false,
  });
  compiledMeetingPreps.add(compiled);
  return compiled;
}

export async function runMeetingPrepShadowAcceptance(value, authority, judgeResults, providerEffects) {
  const compiled = await compileMeetingPrepShadow(value, authority, judgeResults);
  const store = new ProviderFreeV6AcceptanceStore(providerEffects);
  const facade = bindProviderFreeV6AcceptanceFacade(store);
  await facade.initialize();
  const durableRecords = [];
  for (const surface of ["slack", "qm", "notion"]) {
    const item = compiled.publicationSet[surface];
    durableRecords.push(
      await facade.enqueuePublication(
        { outboxEvent: item.outboxEvent, publicationEnvelope: item.publicationEnvelope },
        item.outboxEvent.queuedAt,
      ),
    );
  }
  const providerEffectStatus = await facade.providerEffectStatus();
  return freeze({
    schemaVersion: 1,
    compiled,
    durableRecords,
    persistedSurfaceCount: durableRecords.length,
    durability: "provider_free_v6_behavioral_fake",
    providerEffectStatus,
    providerInvocationAllowed: false,
  });
}

function meetingCandidate(compiled) {
  const job = compiled.lifecycle.schedule.desiredJobs[0];
  const roles = new Map(compiled.lifecycle.meeting.attendees.map((entry) => [entry.email, entry.role]));
  return {
    deploymentRef: job.deploymentRef,
    principalRef: job.principalRef,
    credentialOwnerRef: job.credentialOwnerRef,
    connectionRef: job.connectionRef,
    calendarAccountRef: job.calendarAccountRef,
    meetingKey: job.meetingKey,
    calendarEventId: job.input.calendarEventId,
    occurrenceRef: job.input.occurrenceRef,
    eventRevisionHash: job.scheduleRevision,
    startAt: job.input.startAt,
    endAt: job.input.endAt,
    participants: job.input.attendees.map((entry) => ({
      email: entry.email,
      role: roles.get(entry.email),
      response: entry.response,
    })),
    calendarEvidenceHash: job.input.calendarEvidenceHash,
  };
}

export function compilePostMeetingShadow(value) {
  if (
    !value ||
    typeof value !== "object" ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    throw new TypeError("Post-meeting shadow input must be plain data");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const fields = ["meetingPrep", "observedAt", "generatedAt", "transcript"];
  if (
    Object.keys(descriptors).length !== fields.length ||
    Object.keys(descriptors).some((field) => !fields.includes(field)) ||
    fields.some((field) => {
      const descriptor = descriptors[field];
      return (
        !descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value") || descriptor.get || descriptor.set
      );
    })
  ) {
    throw new TypeError("Post-meeting shadow input has an unsupported shape");
  }
  const compiled = descriptors.meetingPrep.value;
  if (types.isProxy(compiled) || !compiledMeetingPreps.has(compiled)) {
    throw new TypeError("Post-meeting shadow requires an acceptance-issued meeting prep");
  }
  const observedAt = snapshot(descriptors.observedAt.value, "Post-meeting observedAt");
  const generatedAt = snapshot(descriptors.generatedAt.value, "Post-meeting generatedAt");
  const transcript = snapshot(descriptors.transcript.value, "Post-meeting transcript");
  if (transcript?.revision === "pending") {
    const pending = exact(transcript, ["revision", "transcriptRef"], "Pending transcript");
    const projection = {
      schemaVersion: 1,
      state: "waiting",
      transcriptRef: pending.transcriptRef,
      blocker: "final_transcript_required",
      canonicalArtifactAvailable: false,
      providerInvocationAllowed: false,
    };
    return freeze({ ...projection, stateSha256: hash(projection) });
  }
  const finalTranscript = exact(
    transcript,
    [
      "revision",
      "transcriptRef",
      "providerTranscriptId",
      "providerAccountRef",
      "revisionHash",
      "recordedStartAt",
      "recordedEndAt",
      "finalizedAt",
      "participants",
      "evidenceHash",
      "text",
    ],
    "Final transcript",
  );
  if (finalTranscript.revision !== "final") throw new TypeError("Transcript revision is unsupported");
  const meeting = meetingCandidate(compiled);
  const transcriptInput = {
    transcriptRef: finalTranscript.transcriptRef,
    providerTranscriptId: finalTranscript.providerTranscriptId,
    providerAccountRef: finalTranscript.providerAccountRef,
    revision: "final",
    revisionHash: finalTranscript.revisionHash,
    recordedStartAt: finalTranscript.recordedStartAt,
    recordedEndAt: finalTranscript.recordedEndAt,
    finalizedAt: finalTranscript.finalizedAt,
    participants: finalTranscript.participants,
    evidenceHash: finalTranscript.evidenceHash,
    contentHash: hash({ transcriptText: finalTranscript.text }),
  };
  const correlation = correlateFinalTranscript({
    now: observedAt,
    transcript: transcriptInput,
    candidateMeetings: [meeting],
  });
  if (correlation.status !== "verification_required") {
    return freeze({
      schemaVersion: 1,
      state: correlation.status,
      correlation,
      canonicalArtifactAvailable: false,
      providerInvocationAllowed: false,
    });
  }
  const analysisInput = buildPostMeetingAnalysisInput({
    generatedAt,
    meeting,
    dossierBinding: {
      artifactHash: compiled.dossier.artifactHash,
      meetingKey: compiled.dossier.meetingKey,
      calendarEvidenceHash: compiled.dossier.calendarEvidenceHash,
    },
    transcriptCorrelation: correlation,
    transcriptText: finalTranscript.text,
  });
  return freeze({
    schemaVersion: 1,
    state: "verification_required",
    correlation,
    analysisInput,
    blocker: "trusted_source_verification_broker_and_public_post_meeting_adapter_required",
    canonicalArtifactAvailable: false,
    providerInvocationAllowed: false,
  });
}
