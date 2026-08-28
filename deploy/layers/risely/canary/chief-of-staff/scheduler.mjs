import { sha256Canonical } from "../contracts/index.mjs";
import {
  assertEmail,
  assertHash,
  assertInteger,
  assertOptionalRecord,
  assertRecord,
  assertRef,
  assertText,
  assertUnique,
  compareCodepoints,
  fail,
  parseInstant,
  snapshotPlainJson,
} from "./validation.mjs";

const triggerOffsets = Object.freeze({
  "meeting.dossier.prepare": 24 * 60 * 60 * 1000,
  "meeting.briefing.refresh": 90 * 60 * 1000,
  "meeting.briefing.deliver": 15 * 60 * 1000,
});
const triggerOrder = Object.freeze(["meeting.dossier.prepare", "meeting.briefing.refresh", "meeting.briefing.deliver"]);
const nonterminalStatuses = new Set(["scheduled", "leased"]);
const terminalStatuses = new Set(["completed", "cancelled", "failed"]);

const normalizeAttendee = (input) => {
  assertRecord(input, ["email", "external", "response"], "invalid_calendar_attendee");
  if (
    typeof input.external !== "boolean" ||
    !["accepted", "tentative", "declined", "needsAction"].includes(input.response)
  ) {
    fail("invalid_calendar_attendee");
  }
  return Object.freeze({ email: assertEmail(input.email), external: input.external, response: input.response });
};

const normalizeEvent = (input) => {
  assertOptionalRecord(
    input,
    [
      "calendarEventId",
      "occurrenceRef",
      "recurrenceKind",
      "startAt",
      "endAt",
      "status",
      "allDay",
      "visibility",
      "ceoResponse",
      "title",
      "attendees",
      "evidenceHash",
    ],
    ["seriesId", "recurrenceOriginalStartAt"],
    "invalid_calendar_event",
  );
  const startAt = parseInstant(input.startAt);
  const endAt = parseInstant(input.endAt);
  const recurring = input.recurrenceKind === "recurring";
  if (
    endAt <= startAt ||
    !["single", "recurring"].includes(input.recurrenceKind) ||
    recurring !== (input.recurrenceOriginalStartAt !== undefined) ||
    recurring !== (input.seriesId !== undefined) ||
    !["confirmed", "cancelled"].includes(input.status) ||
    typeof input.allDay !== "boolean" ||
    !["default", "private"].includes(input.visibility) ||
    !["accepted", "tentative", "declined", "needsAction"].includes(input.ceoResponse) ||
    !Array.isArray(input.attendees) ||
    input.attendees.length > 128
  ) {
    fail("invalid_calendar_event");
  }
  const attendees = input.attendees
    .map(normalizeAttendee)
    .sort((left, right) => compareCodepoints(left.email, right.email));
  assertUnique(attendees, (attendee) => attendee.email, "duplicate_calendar_attendee");
  const calendarEventId = assertRef(input.calendarEventId);
  const seriesId = input.seriesId === undefined ? undefined : assertRef(input.seriesId);
  const recurrenceOriginalStartAt =
    input.recurrenceOriginalStartAt === undefined
      ? undefined
      : parseInstant(input.recurrenceOriginalStartAt).toISOString();
  const expectedOccurrenceRef = recurring
    ? `series:${seriesId}:${recurrenceOriginalStartAt}`
    : `event:${calendarEventId}`;
  if (assertRef(input.occurrenceRef) !== expectedOccurrenceRef) fail("unstable_calendar_occurrence_reference");
  return Object.freeze({
    calendarEventId,
    occurrenceRef: expectedOccurrenceRef,
    recurrenceKind: input.recurrenceKind,
    ...(seriesId === undefined ? {} : { seriesId }),
    ...(recurrenceOriginalStartAt === undefined ? {} : { recurrenceOriginalStartAt }),
    startAt: startAt.toISOString(),
    endAt: endAt.toISOString(),
    status: input.status,
    allDay: input.allDay,
    visibility: input.visibility,
    ceoResponse: input.ceoResponse,
    title: assertText(input.title, 512),
    attendees: Object.freeze(attendees),
    evidenceHash: assertHash(input.evidenceHash),
  });
};

const normalizePriorJob = (input) => {
  assertRecord(
    input,
    [
      "organizationRef",
      "deploymentRef",
      "principalRef",
      "credentialOwnerRef",
      "connectionRef",
      "calendarAccountRef",
      "audienceRef",
      "audience",
      "destinationRef",
      "destination",
      "planHash",
      "jobId",
      "meetingKey",
      "kind",
      "scheduleRevision",
      "jobRevision",
      "claimFence",
      "fireAt",
      "status",
    ],
    "invalid_prior_job",
  );
  if (
    !triggerOrder.includes(input.kind) ||
    (!nonterminalStatuses.has(input.status) && !terminalStatuses.has(input.status))
  ) {
    fail("invalid_prior_job");
  }
  if (
    (input.status === "scheduled" && input.claimFence !== null) ||
    (input.status === "leased" && input.claimFence === null) ||
    input.audience !== "ceo_private" ||
    !["slack_ceo_dm", "qm_ceo_inbox"].includes(input.destination)
  ) {
    fail("invalid_prior_job");
  }
  return Object.freeze({
    organizationRef: assertRef(input.organizationRef),
    deploymentRef: assertRef(input.deploymentRef),
    principalRef: assertRef(input.principalRef),
    credentialOwnerRef: assertRef(input.credentialOwnerRef),
    connectionRef: assertRef(input.connectionRef),
    calendarAccountRef: assertRef(input.calendarAccountRef),
    audienceRef: assertRef(input.audienceRef),
    audience: input.audience,
    destinationRef: assertRef(input.destinationRef),
    destination: input.destination,
    planHash: assertHash(input.planHash),
    jobId: assertHash(input.jobId),
    meetingKey: assertHash(input.meetingKey),
    kind: input.kind,
    scheduleRevision: assertHash(input.scheduleRevision),
    jobRevision: assertInteger(input.jobRevision, 1, Number.MAX_SAFE_INTEGER),
    claimFence: input.claimFence === null ? null : assertRef(input.claimFence),
    fireAt: parseInstant(input.fireAt).toISOString(),
    status: input.status,
  });
};

const eligibility = (event) => {
  if (event.status === "cancelled") return "cancelled";
  if (event.allDay) return "all_day";
  if (event.visibility === "private") return "private";
  if (event.ceoResponse === "declined") return "ceo_declined";
  if (!event.attendees.some((attendee) => attendee.external && attendee.response !== "declined")) {
    return "no_participating_external_attendee";
  }
  return "eligible";
};

const meetingKeyFor = (lineage, event) => sha256Canonical({ ...lineage, occurrenceRef: event.occurrenceRef });

const revisionFor = (meetingKey, event) =>
  sha256Canonical({
    meetingKey,
    calendarEventId: event.calendarEventId,
    occurrenceRef: event.occurrenceRef,
    startAt: event.startAt,
    endAt: event.endAt,
    status: event.status,
    evidenceHash: event.evidenceHash,
  });

const desiredJob = (now, lineage, meetingKey, scheduleRevision, event, kind, dependency) => {
  const intendedAt = new Date(parseInstant(event.startAt).valueOf() - triggerOffsets[kind]);
  const fireAt = new Date(Math.max(now.valueOf(), intendedAt.valueOf())).toISOString();
  const jobId = sha256Canonical({ ...lineage, kind, meetingKey, scheduleRevision });
  return Object.freeze({
    jobId,
    idempotencyKey: jobId,
    ...lineage,
    meetingKey,
    kind,
    scheduleRevision,
    jobRevision: 1,
    claimFence: null,
    claimFenceRequired: true,
    intendedAt: intendedAt.toISOString(),
    fireAt,
    timing: intendedAt < now ? "late_before_start" : "on_time",
    dependency,
    input: Object.freeze({
      ...lineage,
      meetingKey,
      calendarEventId: event.calendarEventId,
      occurrenceRef: event.occurrenceRef,
      recurrenceKind: event.recurrenceKind,
      ...(event.recurrenceOriginalStartAt === undefined
        ? {}
        : { recurrenceOriginalStartAt: event.recurrenceOriginalStartAt }),
      startAt: event.startAt,
      endAt: event.endAt,
      title: event.title,
      titleTrust: "untrusted_provider_data",
      attendees: Object.freeze(
        event.attendees.map((attendee) => Object.freeze({ ...attendee, trust: "untrusted_provider_data" })),
      ),
      calendarEvidenceHash: event.evidenceHash,
    }),
  });
};

export const planChiefOfStaffSchedule = (input) => {
  const value = snapshotPlainJson(input);
  assertRecord(
    value,
    [
      "now",
      "pollWindowEnd",
      "organizationRef",
      "deploymentRef",
      "principalRef",
      "credentialOwnerRef",
      "connectionRef",
      "calendarAccountRef",
      "audienceRef",
      "audience",
      "destinationRef",
      "destination",
      "calendarSnapshotHash",
      "calendarAvailability",
      "events",
      "priorJobs",
    ],
    "invalid_schedule_input",
  );
  const now = parseInstant(value.now);
  const pollWindowEnd = parseInstant(value.pollWindowEnd);
  if (pollWindowEnd <= now || pollWindowEnd.valueOf() - now.valueOf() > 31 * 86_400_000) fail("invalid_poll_window");
  if (
    !value.events ||
    !Array.isArray(value.events) ||
    value.events.length > 512 ||
    !Array.isArray(value.priorJobs) ||
    value.priorJobs.length > 1_024
  ) {
    fail("invalid_schedule_input");
  }
  if (!["available", "unavailable"].includes(value.calendarAvailability)) fail("invalid_calendar_availability");
  if (value.calendarAvailability === "unavailable" && value.events.length !== 0) fail("invalid_calendar_availability");
  const lineage = Object.freeze({
    organizationRef: assertRef(value.organizationRef),
    deploymentRef: assertRef(value.deploymentRef),
    principalRef: assertRef(value.principalRef),
    credentialOwnerRef: assertRef(value.credentialOwnerRef),
    connectionRef: assertRef(value.connectionRef),
    calendarAccountRef: assertRef(value.calendarAccountRef),
    audienceRef: assertRef(value.audienceRef),
    audience: value.audience,
    destinationRef: assertRef(value.destinationRef),
    destination: value.destination,
  });
  if (lineage.audience !== "ceo_private" || !["slack_ceo_dm", "qm_ceo_inbox"].includes(lineage.destination)) {
    fail("invalid_schedule_destination");
  }
  const calendarSnapshotHash = assertHash(value.calendarSnapshotHash);
  const events = value.events.map(normalizeEvent);
  const priorJobs = value.priorJobs.map(normalizePriorJob);
  if (priorJobs.some((job) => Object.keys(lineage).some((field) => job[field] !== lineage[field]))) {
    fail("prior_job_lineage_mismatch");
  }
  assertUnique(events, (event) => event.occurrenceRef, "duplicate_calendar_event");
  assertUnique(priorJobs, (job) => job.jobId, "duplicate_prior_job");
  const desiredJobs = [];
  const suppressions = [];
  const desiredIds = new Set();
  const observedMeetingKeys = new Set();
  for (const event of events.sort(
    (left, right) =>
      compareCodepoints(left.startAt, right.startAt) || compareCodepoints(left.occurrenceRef, right.occurrenceRef),
  )) {
    const meetingKey = meetingKeyFor(lineage, event);
    observedMeetingKeys.add(meetingKey);
    const reason = eligibility(event);
    const startAt = parseInstant(event.startAt);
    if (reason !== "eligible" || startAt <= now || startAt > pollWindowEnd) {
      suppressions.push(
        Object.freeze({
          meetingKey,
          reason: reason === "eligible" ? (startAt <= now ? "meeting_started" : "outside_active_window") : reason,
        }),
      );
      continue;
    }
    const scheduleRevision = revisionFor(meetingKey, event);
    let dependency = null;
    for (let index = 0; index < triggerOrder.length; index += 1) {
      const job = desiredJob(now, lineage, meetingKey, scheduleRevision, event, triggerOrder[index], dependency);
      desiredJobs.push(job);
      desiredIds.add(job.jobId);
      dependency = Object.freeze({
        jobId: job.jobId,
        scheduleRevision: job.scheduleRevision,
        jobRevision: job.jobRevision,
      });
    }
  }
  const cancellations = priorJobs
    .filter(
      (job) =>
        nonterminalStatuses.has(job.status) && observedMeetingKeys.has(job.meetingKey) && !desiredIds.has(job.jobId),
    )
    .map((job) =>
      Object.freeze({
        cancellationId: sha256Canonical({
          jobId: job.jobId,
          scheduleRevision: job.scheduleRevision,
          jobRevision: job.jobRevision,
          claimFence: job.claimFence,
          planHash: job.planHash,
        }),
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
        meetingKey: job.meetingKey,
        jobId: job.jobId,
        scheduleRevision: job.scheduleRevision,
        expectedJobRevision: job.jobRevision,
        expectedClaimFence: job.claimFence,
        expectedPlanHash: job.planHash,
        expectedStatus: job.status,
        fencedCasRequired: true,
        reason: suppressions.some((entry) => entry.meetingKey === job.meetingKey && entry.reason === "cancelled")
          ? "provider_cancelled"
          : suppressions.some((entry) => entry.meetingKey === job.meetingKey)
            ? "meeting_ineligible"
            : "schedule_moved_or_changed",
      }),
    )
    .sort((left, right) => compareCodepoints(left.jobId, right.jobId));
  const planHash = sha256Canonical({
    now: now.toISOString(),
    pollWindowEnd: pollWindowEnd.toISOString(),
    ...lineage,
    calendarSnapshotHash,
    desiredJobDrafts: desiredJobs,
    cancellations,
    suppressions,
  });
  const boundDesiredJobs = desiredJobs.map((job) => Object.freeze({ ...job, planHash }));
  return Object.freeze({
    schemaVersion: 1,
    planHash,
    ...lineage,
    calendarAvailability: value.calendarAvailability,
    desiredJobs: Object.freeze(boundDesiredJobs),
    cancellations: Object.freeze(cancellations),
    suppressions: Object.freeze(suppressions),
    deletionInferenceAllowed: false,
  });
};

export const chiefOfStaffTriggerOffsets = triggerOffsets;
