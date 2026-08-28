import { sha256Canonical } from "../contracts/canonicalize.mjs";

const MAX_EVENTS = 256;
const MAX_TRANSCRIPTS = 256;
const MAX_PRIOR_SCHEDULES = 512;
const MAX_DEPTH = 32;
const MAX_NODES = 20_000;
const MAX_STRING_BYTES = 1_048_576;
const OPERATIONAL_WINDOW_MS = 2 * 366 * 24 * 60 * 60 * 1000;
const HASH = /^[0-9a-f]{64}$/;
const REF = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const EMAIL =
  /^(?=.{1,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const UNSAFE_TEXT = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/;
const MEETING_KINDS = new Set(["customer", "demo", "external"]);
const EVENT_KEYS = new Set([
  "eventId",
  "originalStartAt",
  "startAt",
  "endAt",
  "meetingKind",
  "status",
  "allDay",
  "isPrivate",
  "ceoResponse",
  "attendees",
  "title",
  "evidenceHash",
  "providerSupersedesKey",
]);
const ATTENDEE_KEYS = new Set(["email", "external", "response"]);
const TRANSCRIPT_KEYS = new Set(["eventId", "originalStartAt", "revision", "evidenceHash", "finalizedAt"]);
const PRIOR_KEYS = new Set([
  "meetingKey",
  "currentStartAt",
  "preparedArtifactFingerprint",
  "refreshedArtifactFingerprint",
  "providerSupersedesKey",
]);
const ROOT_KEYS = new Set(["ceoTimezone", "now", "calendar", "transcripts", "priorSchedules"]);
const CALENDAR_KEYS = new Set(["availability", "events"]);
const TRANSCRIPTS_KEYS = new Set(["availability", "records"]);
const CANCELLED_WORK = Object.freeze([
  "meeting.prep",
  "meeting.prep.refresh",
  "meeting.demo_reminder",
  "meeting.transcript.recheck",
  "meeting.followup",
]);

const fail = (code) => {
  throw new TypeError(`meeting_lifecycle_${code}`);
};

const compareCodepoints = (left, right) => {
  const leftPoints = Array.from(left);
  const rightPoints = Array.from(right);
  const limit = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < limit; index += 1) {
    const leftCode = leftPoints[index].codePointAt(0);
    const rightCode = rightPoints[index].codePointAt(0);
    if (leftCode !== rightCode) return leftCode < rightCode ? -1 : 1;
  }
  return leftPoints.length - rightPoints.length;
};

const isPlainObject = (value) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

const assertSafeString = (value, budget) => {
  if (typeof value !== "string" || LONE_SURROGATE.test(value) || UNSAFE_TEXT.test(value)) fail("invalid_plain_json");
  budget.stringBytes += Buffer.byteLength(value, "utf8");
  if (budget.stringBytes > MAX_STRING_BYTES) fail("invalid_plain_json");
};

const assertPlainJson = (value, depth = 0, budget = { nodes: 0, stringBytes: 0 }) => {
  if (depth > MAX_DEPTH) fail("invalid_plain_json");
  budget.nodes += 1;
  if (budget.nodes > MAX_NODES) fail("invalid_plain_json");
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    assertSafeString(value, budget);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("invalid_plain_json");
    return;
  }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) fail("invalid_plain_json");
    if (Object.getOwnPropertySymbols(value).length !== 0) fail("invalid_plain_json");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (
      Object.entries(descriptors).some(
        ([key, descriptor]) => key !== "length" && (descriptor.get || descriptor.set || !descriptor.enumerable),
      )
    )
      fail("invalid_plain_json");
    const keys = Object.keys(value);
    if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) fail("invalid_plain_json");
    for (const entry of value) assertPlainJson(entry, depth + 1, budget);
    return;
  }
  if (!isPlainObject(value) || Object.getOwnPropertySymbols(value).length !== 0) fail("invalid_plain_json");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set || !descriptor.enumerable))
    fail("invalid_plain_json");
  for (const [key, entry] of Object.entries(value)) {
    assertSafeString(key, budget);
    assertPlainJson(entry, depth + 1, budget);
  }
};

const assertKeys = (value, keys) => {
  if (!isPlainObject(value) || Object.keys(value).some((key) => !keys.has(key))) fail("invalid_object");
};

const assertText = (value, max = 256) => {
  if (typeof value !== "string" || value.length < 1 || value.length > max) fail("invalid_text");
  return value;
};

const assertRef = (value) => {
  const text = assertText(value);
  if (!REF.test(text)) fail("invalid_reference");
  return text;
};

const assertHash = (value) => {
  if (typeof value !== "string" || !HASH.test(value)) fail("invalid_hash");
  return value;
};

const parseInstant = (value) => {
  const text = assertText(value, 64);
  const date = new Date(text);
  if (Number.isNaN(date.valueOf()) || date.toISOString() !== text) fail("invalid_timestamp");
  return date;
};

const iso = (date) => date.toISOString();

const assertTimezone = (value) => {
  const timezone = assertText(value, 128);
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: timezone });
  } catch {
    fail("invalid_timezone");
  }
  return timezone;
};

const localTimestamp = (date, timezone) => {
  const parts = new Intl.DateTimeFormat("en-CA", {
    calendar: "iso8601",
    hourCycle: "h23",
    timeZone: timezone,
    timeZoneName: "longOffset",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(date);
  const values = Object.fromEntries(
    parts.filter((part) => part.type !== "literal").map((part) => [part.type, part.value]),
  );
  const offset = values.timeZoneName === "GMT" ? "+00:00" : values.timeZoneName.replace("GMT", "");
  if (!/^[+-][0-2][0-9]:[0-5][0-9]$/.test(offset)) fail("invalid_timezone");
  return `${values.year}-${values.month}-${values.day}T${values.hour}:${values.minute}:${values.second}${offset}`;
};

const assertAvailability = (value) => {
  if (value !== "available" && value !== "unavailable") fail("invalid_availability");
  return value;
};

const normalizeAttendee = (value) => {
  assertKeys(value, ATTENDEE_KEYS);
  const email = assertText(value.email, 254).toLowerCase();
  if (
    !EMAIL.test(email) ||
    typeof value.external !== "boolean" ||
    !["accepted", "declined", "tentative", "needsAction"].includes(value.response)
  )
    fail("invalid_attendee");
  return Object.freeze({ email, external: value.external, response: value.response });
};

const assertOperationalDate = (date, now) => {
  if (Math.abs(date.valueOf() - now.valueOf()) > OPERATIONAL_WINDOW_MS) fail("event_out_of_range");
  return date;
};

const normalizeEvent = (value, now) => {
  assertKeys(value, EVENT_KEYS);
  const eventId = assertRef(value.eventId);
  const originalStartAt = assertOperationalDate(parseInstant(value.originalStartAt), now);
  const startAt = assertOperationalDate(parseInstant(value.startAt), now);
  const endAt = assertOperationalDate(parseInstant(value.endAt), now);
  if (
    endAt <= startAt ||
    !MEETING_KINDS.has(value.meetingKind) ||
    !["confirmed", "cancelled"].includes(value.status) ||
    typeof value.allDay !== "boolean" ||
    typeof value.isPrivate !== "boolean" ||
    !["accepted", "declined", "tentative", "needsAction"].includes(value.ceoResponse) ||
    !Array.isArray(value.attendees) ||
    value.attendees.length > 128
  )
    fail("invalid_event");
  const attendees = value.attendees
    .map(normalizeAttendee)
    .sort((left, right) => compareCodepoints(left.email, right.email));
  if (new Set(attendees.map((attendee) => attendee.email)).size !== attendees.length) fail("duplicate_attendee");
  return Object.freeze({
    eventId,
    originalStartAt: iso(originalStartAt),
    startAt: iso(startAt),
    endAt: iso(endAt),
    meetingKind: value.meetingKind,
    status: value.status,
    allDay: value.allDay,
    isPrivate: value.isPrivate,
    ceoResponse: value.ceoResponse,
    attendees,
    title: assertText(value.title, 512),
    evidenceHash: assertHash(value.evidenceHash),
    providerSupersedesKey:
      value.providerSupersedesKey === undefined ? undefined : assertHash(value.providerSupersedesKey),
  });
};

const normalizeTranscript = (value, now) => {
  assertKeys(value, TRANSCRIPT_KEYS);
  const eventId = assertRef(value.eventId);
  const originalStartAt = iso(parseInstant(value.originalStartAt));
  if (!["draft", "final"].includes(value.revision)) fail("invalid_transcript");
  const finalizedAt = value.finalizedAt === undefined ? undefined : parseInstant(value.finalizedAt);
  if ((value.revision === "final" && finalizedAt === undefined) || (finalizedAt && finalizedAt > now))
    fail("invalid_transcript");
  return Object.freeze({
    eventId,
    originalStartAt,
    revision: value.revision,
    evidenceHash: assertHash(value.evidenceHash),
    finalizedAt: finalizedAt && iso(finalizedAt),
  });
};

const normalizePrior = (value) => {
  assertKeys(value, PRIOR_KEYS);
  const preparedArtifactFingerprint =
    value.preparedArtifactFingerprint === undefined ? undefined : assertHash(value.preparedArtifactFingerprint);
  const refreshedArtifactFingerprint =
    value.refreshedArtifactFingerprint === undefined ? undefined : assertHash(value.refreshedArtifactFingerprint);
  if (refreshedArtifactFingerprint !== undefined && preparedArtifactFingerprint === undefined)
    fail("invalid_prior_schedule");
  return Object.freeze({
    meetingKey: assertHash(value.meetingKey),
    currentStartAt: iso(parseInstant(value.currentStartAt)),
    preparedArtifactFingerprint,
    refreshedArtifactFingerprint,
    providerSupersedesKey:
      value.providerSupersedesKey === undefined ? undefined : assertHash(value.providerSupersedesKey),
  });
};

const normalizeInput = (value) => {
  assertPlainJson(value);
  assertKeys(value, ROOT_KEYS);
  const ceoTimezone = assertTimezone(value.ceoTimezone);
  const now = parseInstant(value.now);
  assertKeys(value.calendar, CALENDAR_KEYS);
  const calendarAvailability = assertAvailability(value.calendar.availability);
  if (
    !Array.isArray(value.calendar.events) ||
    value.calendar.events.length > MAX_EVENTS ||
    (calendarAvailability === "unavailable" && value.calendar.events.length !== 0)
  )
    fail("invalid_calendar");
  assertKeys(value.transcripts, TRANSCRIPTS_KEYS);
  const transcriptAvailability = assertAvailability(value.transcripts.availability);
  if (
    !Array.isArray(value.transcripts.records) ||
    value.transcripts.records.length > MAX_TRANSCRIPTS ||
    (transcriptAvailability === "unavailable" && value.transcripts.records.length !== 0)
  )
    fail("invalid_transcripts");
  if (!Array.isArray(value.priorSchedules) || value.priorSchedules.length > MAX_PRIOR_SCHEDULES)
    fail("invalid_prior_schedules");
  const events = value.calendar.events
    .map((event) => normalizeEvent(event, now))
    .sort(
      (left, right) =>
        compareCodepoints(left.eventId, right.eventId) ||
        compareCodepoints(left.originalStartAt, right.originalStartAt),
    );
  if (new Set(events.map((event) => `${event.eventId}\u0000${event.originalStartAt}`)).size !== events.length)
    fail("duplicate_event");
  const records = value.transcripts.records
    .map((record) => normalizeTranscript(record, now))
    .sort(
      (left, right) =>
        compareCodepoints(left.eventId, right.eventId) ||
        compareCodepoints(left.originalStartAt, right.originalStartAt) ||
        compareCodepoints(left.revision, right.revision) ||
        compareCodepoints(left.finalizedAt ?? "", right.finalizedAt ?? ""),
    );
  if (
    new Set(
      records.map(
        (record) =>
          `${record.eventId}\u0000${record.originalStartAt}\u0000${record.revision}\u0000${record.finalizedAt ?? ""}`,
      ),
    ).size !== records.length
  )
    fail("duplicate_transcript");
  const priorSchedules = value.priorSchedules
    .map(normalizePrior)
    .sort((left, right) => compareCodepoints(left.meetingKey, right.meetingKey));
  if (new Set(priorSchedules.map((schedule) => schedule.meetingKey)).size !== priorSchedules.length)
    fail("duplicate_prior_schedule");
  return Object.freeze({
    ceoTimezone,
    now,
    calendarAvailability,
    transcriptAvailability,
    events,
    records,
    priorSchedules,
  });
};

const meetingKeyFor = (event) => sha256Canonical({ eventId: event.eventId, originalStartAt: event.originalStartAt });

const eligibility = (event) => {
  if (event.status === "cancelled") return "cancelled";
  if (event.allDay) return "all_day";
  if (event.isPrivate) return "private";
  if (event.ceoResponse === "declined") return "ceo_declined";
  if (event.attendees.length === 0) return "no_attendees";
  if (
    event.attendees.some((attendee) => attendee.external) &&
    !event.attendees.some((attendee) => attendee.external && attendee.response !== "declined")
  )
    return "external_attendee_declined";
  if (
    event.meetingKind === "external" &&
    !event.attendees.some((attendee) => attendee.external && attendee.response !== "declined")
  )
    return "external_attendee_unavailable";
  return "eligible";
};

const intent = (type, meetingKey, deliveryAt, effect, payload) => {
  const effectIdentity = Object.freeze({ type, meetingKey, effect: Object.freeze(effect) });
  return Object.freeze({
    intentId: sha256Canonical({ intent: effectIdentity }),
    idempotencyKey: sha256Canonical({ idempotency: effectIdentity }),
    type,
    meetingKey,
    deliveryAt,
    payload: Object.freeze(payload),
  });
};

const eventInput = (event, meetingKey, timezone) => {
  const input = Object.freeze({
    meetingKey,
    event: Object.freeze({
      eventId: event.eventId,
      originalStartAt: event.originalStartAt,
      startAt: event.startAt,
      endAt: event.endAt,
      meetingKind: event.meetingKind,
      title: event.title,
      titleTrust: "untrusted_data",
      attendees: Object.freeze(
        event.attendees.map((attendee) =>
          Object.freeze({
            email: attendee.email,
            external: attendee.external,
            response: attendee.response,
            trust: "untrusted_data",
          }),
        ),
      ),
    }),
    calendarEvidenceHash: event.evidenceHash,
    ceoTimezone: timezone,
    ceoLocalStart: localTimestamp(new Date(event.startAt), timezone),
  });
  return Object.freeze({ input, artifactFingerprint: sha256Canonical(input) });
};

const deliveryAt = (now, scheduledAt) => iso(now < scheduledAt ? scheduledAt : now);

const finalTranscript = (records, event) =>
  records
    .filter(
      (record) =>
        record.eventId === event.eventId &&
        record.originalStartAt === event.originalStartAt &&
        record.revision === "final",
    )
    .sort((left, right) => compareCodepoints(right.finalizedAt, left.finalizedAt))[0];

const requiresPrep = (prior) =>
  prior === undefined ||
  (prior.preparedArtifactFingerprint === undefined && prior.refreshedArtifactFingerprint === undefined);

const requiresRefresh = (prior, artifactFingerprint) =>
  prior !== undefined &&
  prior.preparedArtifactFingerprint !== undefined &&
  prior.preparedArtifactFingerprint !== artifactFingerprint &&
  prior.refreshedArtifactFingerprint !== artifactFingerprint;

const matchingPriors = (priorSchedules, meetingKey, event) =>
  priorSchedules.filter(
    (prior) =>
      prior.meetingKey === meetingKey ||
      (event.providerSupersedesKey !== undefined &&
        (prior.meetingKey === event.providerSupersedesKey ||
          prior.providerSupersedesKey === event.providerSupersedesKey)),
  );

const suppressedSnapshotKeys = (events) => {
  const keys = new Set(events.map(meetingKeyFor));
  const aliases = new Set();
  const nextAlias = new Map();
  for (const event of events) {
    if (event.providerSupersedesKey === undefined || !keys.has(event.providerSupersedesKey)) continue;
    const meetingKey = meetingKeyFor(event);
    if (event.providerSupersedesKey === meetingKey || aliases.has(event.providerSupersedesKey))
      fail("ambiguous_snapshot_alias");
    aliases.add(event.providerSupersedesKey);
    nextAlias.set(meetingKey, event.providerSupersedesKey);
  }
  for (const meetingKey of nextAlias.keys()) {
    const visited = new Set();
    let cursor = meetingKey;
    while (nextAlias.has(cursor)) {
      if (visited.has(cursor)) fail("ambiguous_snapshot_alias");
      visited.add(cursor);
      cursor = nextAlias.get(cursor);
    }
  }
  return aliases;
};

const cancellationIntent = (type, meetingKey, now, prior, reason, replacementStartAt) => {
  const replacement = replacementStartAt === undefined ? {} : { replacementStartAt };
  return intent(
    type,
    meetingKey,
    iso(now),
    { priorMeetingKey: prior.meetingKey, priorStartAt: prior.currentStartAt, reason, ...replacement },
    Object.freeze({
      priorMeetingKey: prior.meetingKey,
      priorStartAt: prior.currentStartAt,
      reason,
      ...replacement,
      cancelScope: "all_prior_work",
      cancelledWork: CANCELLED_WORK,
    }),
  );
};

export const planMeetingLifecycle = (input) => {
  const normalized = normalizeInput(input);
  const notices = [];
  const intents = [];
  const meetings = [];
  if (normalized.calendarAvailability === "unavailable") {
    notices.push(Object.freeze({ code: "calendar_source_unavailable" }));
    return Object.freeze({
      version: 1,
      ceoTimezone: normalized.ceoTimezone,
      evaluatedAt: iso(normalized.now),
      notices: Object.freeze(notices),
      meetings: Object.freeze(meetings),
      intents: Object.freeze(intents),
    });
  }
  const suppressedKeys = suppressedSnapshotKeys(normalized.events);
  for (const event of normalized.events) {
    const meetingKey = meetingKeyFor(event);
    const state = suppressedKeys.has(meetingKey) ? "superseded_current_snapshot" : eligibility(event);
    const prior = matchingPriors(normalized.priorSchedules, meetingKey, event);
    meetings.push(Object.freeze({ eventId: event.eventId, originalStartAt: event.originalStartAt, meetingKey, state }));
    if (state === "superseded_current_snapshot") continue;
    if (state !== "eligible") {
      for (const previous of prior)
        intents.push(cancellationIntent("meeting.schedule.cancel", meetingKey, normalized.now, previous, state));
      continue;
    }
    if (prior.length > 1) {
      notices.push(Object.freeze({ code: "ambiguous_prior_alias", meetingKey }));
      for (const previous of prior)
        intents.push(
          cancellationIntent("meeting.schedule.cancel", meetingKey, normalized.now, previous, "ambiguous_prior_alias"),
        );
      continue;
    }
    const priorSchedule = prior[0];
    const artifact = eventInput(event, meetingKey, normalized.ceoTimezone);
    const start = new Date(event.startAt);
    const end = new Date(event.endAt);
    if (priorSchedule && priorSchedule.currentStartAt !== event.startAt) {
      intents.push(
        cancellationIntent(
          "meeting.schedule.supersede",
          meetingKey,
          normalized.now,
          priorSchedule,
          "rescheduled",
          event.startAt,
        ),
      );
    }
    const prepAt = new Date(start.valueOf() - 24 * 60 * 60 * 1000);
    const refreshAt = new Date(start.valueOf() - 90 * 60 * 1000);
    if (normalized.now < start && (normalized.now < prepAt || requiresPrep(priorSchedule))) {
      intents.push(
        intent(
          "meeting.prep",
          meetingKey,
          deliveryAt(normalized.now, prepAt),
          { artifactFingerprint: artifact.artifactFingerprint },
          Object.freeze({ artifactInput: artifact.input }),
        ),
      );
    }
    if (
      normalized.now < start &&
      (normalized.now < refreshAt || requiresRefresh(priorSchedule, artifact.artifactFingerprint))
    ) {
      intents.push(
        intent(
          "meeting.prep.refresh",
          meetingKey,
          deliveryAt(normalized.now, refreshAt),
          { artifactFingerprint: artifact.artifactFingerprint },
          Object.freeze({ artifactInput: artifact.input }),
        ),
      );
    }
    if (event.meetingKind === "demo" && normalized.now < start) {
      const demoAt = new Date(start.valueOf() - 15 * 60 * 1000);
      intents.push(
        intent(
          "meeting.demo_reminder",
          meetingKey,
          deliveryAt(normalized.now, demoAt),
          { startAt: event.startAt, artifactFingerprint: artifact.artifactFingerprint },
          Object.freeze({ artifactInput: artifact.input }),
        ),
      );
    }
    if (normalized.now < end) continue;
    if (normalized.transcriptAvailability === "unavailable") {
      notices.push(Object.freeze({ code: "transcript_source_unavailable", meetingKey }));
      intents.push(
        intent(
          "meeting.followup.waiting_for_notes",
          meetingKey,
          iso(normalized.now),
          { artifactFingerprint: artifact.artifactFingerprint, reason: "transcript_source_unavailable" },
          Object.freeze({
            artifactInput: artifact.input,
            reason: "transcript_source_unavailable",
            allowedInput: "ceo_notes",
          }),
        ),
      );
      continue;
    }
    const transcript = finalTranscript(normalized.records, event);
    if (transcript) {
      intents.push(
        intent(
          "meeting.followup",
          meetingKey,
          iso(normalized.now),
          { artifactFingerprint: artifact.artifactFingerprint, transcriptEvidenceHash: transcript.evidenceHash },
          Object.freeze({
            artifactInput: artifact.input,
            transcript: Object.freeze({
              evidenceHash: transcript.evidenceHash,
              finalizedAt: transcript.finalizedAt,
              trust: "untrusted_data",
            }),
          }),
        ),
      );
      continue;
    }
    const graceAt = new Date(end.valueOf() + 30 * 60 * 1000);
    if (normalized.now <= graceAt) {
      intents.push(
        intent(
          "meeting.transcript.recheck",
          meetingKey,
          deliveryAt(normalized.now, graceAt),
          { graceEndsAt: iso(graceAt) },
          Object.freeze({ artifactInput: artifact.input, graceEndsAt: iso(graceAt) }),
        ),
      );
      intents.push(
        intent(
          "meeting.followup.waiting_for_notes",
          meetingKey,
          iso(normalized.now),
          { artifactFingerprint: artifact.artifactFingerprint, reason: "transcript_pending" },
          Object.freeze({ artifactInput: artifact.input, reason: "transcript_pending", allowedInput: "ceo_notes" }),
        ),
      );
    } else {
      intents.push(
        intent(
          "meeting.followup.waiting_for_notes",
          meetingKey,
          iso(normalized.now),
          { artifactFingerprint: artifact.artifactFingerprint, reason: "transcript_not_finalized_after_grace" },
          Object.freeze({
            artifactInput: artifact.input,
            reason: "transcript_not_finalized_after_grace",
            allowedInput: "ceo_notes",
          }),
        ),
      );
    }
  }
  if (normalized.events.length === 0) notices.push(Object.freeze({ code: "no_calendar_events_in_window" }));
  const orderedMeetings = meetings.sort((left, right) => compareCodepoints(left.meetingKey, right.meetingKey));
  const orderedIntents = intents.sort(
    (left, right) =>
      compareCodepoints(left.deliveryAt, right.deliveryAt) ||
      compareCodepoints(left.type, right.type) ||
      compareCodepoints(left.intentId, right.intentId),
  );
  const orderedNotices = notices.sort(
    (left, right) =>
      compareCodepoints(left.code, right.code) || compareCodepoints(left.meetingKey ?? "", right.meetingKey ?? ""),
  );
  return Object.freeze({
    version: 1,
    ceoTimezone: normalized.ceoTimezone,
    evaluatedAt: iso(normalized.now),
    notices: Object.freeze(orderedNotices),
    meetings: Object.freeze(orderedMeetings),
    intents: Object.freeze(orderedIntents),
  });
};

export const meetingLifecycleRules = Object.freeze({
  prepLeadMinutes: 24 * 60,
  refreshLeadMinutes: 90,
  demoReminderLeadMinutes: 15,
  transcriptFinalGraceMinutes: 30,
  eligibleMeetingKinds: Object.freeze(["customer", "demo", "external"]),
});
