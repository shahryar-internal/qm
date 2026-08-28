import { sha256Canonical } from "../contracts/canonicalize.mjs";
import { gmailDraftContentHash } from "../presentation/index.mjs";

const MAX_DEALS = 512;
const MAX_TOUCHES = 2048;
const MAX_EVENTS = 256;
const MAX_TRANSCRIPTS = 256;
const MAX_FINDINGS_PER_GROUP = 64;
const MAX_CITATIONS_PER_FINDING = 8;
const MAX_DEPTH = 32;
const MAX_NODES = 20_000;
const MAX_STRING_BYTES = 1_048_576;
const HASH = /^[0-9a-f]{64}$/;
const REF = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const EMAIL =
  /^(?=.{1,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const UNSAFE_TEXT = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/;
const UNSAFE_EMAIL_TEXT =
  /[<>\[\]{}*_`~|\\\u0000-\u0009\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/;
const UNSAFE_EMAIL_ADDRESS = /[\s<>\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/;
const STAGES = new Set(["HOT", "Proposal", "POC", "Strategic POC", "Launching", "Discovery", "LIVE"]);
const ROOT_DIGEST_KEYS = new Set(["ceo", "now", "pipeline", "commandCenter", "brain"]);
const CEO_KEYS = new Set(["email"]);
const PIPELINE_KEYS = new Set(["availability", "records"]);
const DEAL_KEYS = new Set(["dealId", "name", "stage", "ownerEmail", "sourceId", "evidenceHash"]);
const CONTEXT_KEYS = new Set(["availability", "touches"]);
const TOUCH_KEYS = new Set(["dealId", "touchId", "occurredAt", "evidenceHash", "verification"]);
const ROOT_POST_MEETING_KEYS = new Set(["ceo", "now", "meeting", "calendar", "transcripts"]);
const ROOT_FOLLOWUP_KEYS = new Set(["ceo", "now", "meeting", "calendar", "transcripts", "recipient", "draft"]);
const MEETING_KEYS = new Set(["eventId", "originalStartAt"]);
const CALENDAR_KEYS = new Set(["availability", "accountEmail", "events"]);
const EVENT_KEYS = new Set([
  "eventId",
  "originalStartAt",
  "startAt",
  "endAt",
  "organizerEmail",
  "attendees",
  "evidenceHash",
]);
const ATTENDEE_KEYS = new Set(["email", "external", "response"]);
const TRANSCRIPTS_KEYS = new Set(["availability", "records"]);
const TRANSCRIPT_KEYS = new Set([
  "transcriptId",
  "eventId",
  "originalStartAt",
  "revision",
  "finalizedAt",
  "evidenceHash",
  "findings",
]);
const FINDINGS_KEYS = new Set([
  "decisions",
  "actionItems",
  "risks",
  "whatWentWell",
  "whatDidnt",
  "recommendedNextSteps",
]);
const FINDING_KEYS = new Set(["findingId", "text", "citations"]);
const CITATION_KEYS = new Set(["transcriptId", "evidenceHash"]);
const RECIPIENT_KEYS = new Set(["email"]);
const DRAFT_KEYS = new Set(["subject", "body"]);
const FINDING_GROUPS = Object.freeze([
  "decisions",
  "actionItems",
  "risks",
  "whatWentWell",
  "whatDidnt",
  "recommendedNextSteps",
]);
const URGENCY_ORDER = Object.freeze({
  critical: 0,
  high: 1,
  medium: 2,
  recent: 3,
  no_verified_touch_record: 4,
  touch_source_unavailable: 5,
});

export const staleDealThresholdDays = Object.freeze({
  HOT: 3,
  Proposal: 5,
  POC: 7,
  "Strategic POC": 10,
  Launching: 5,
  Discovery: 7,
  LIVE: 14,
});

const fail = (code) => {
  throw new TypeError(`revenue_workflows_${code}`);
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

const isDataDescriptor = (value) =>
  value && Object.hasOwn(value, "value") && !Object.hasOwn(value, "get") && !Object.hasOwn(value, "set");

const assertSafeString = (value, budget) => {
  if (typeof value !== "string" || LONE_SURROGATE.test(value) || UNSAFE_TEXT.test(value)) fail("invalid_plain_json");
  budget.stringBytes += Buffer.byteLength(value, "utf8");
  if (budget.stringBytes > MAX_STRING_BYTES) fail("invalid_plain_json");
};

const snapshotPlainJson = (value, depth = 0, budget = { nodes: 0, stringBytes: 0 }, stack = new Set()) => {
  if (depth > MAX_DEPTH) fail("invalid_plain_json");
  budget.nodes += 1;
  if (budget.nodes > MAX_NODES) fail("invalid_plain_json");
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    assertSafeString(value, budget);
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("invalid_plain_json");
    return value;
  }
  if (typeof value !== "object" || stack.has(value)) fail("invalid_plain_json");
  stack.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length !== 0)
        fail("invalid_plain_json");
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const length = descriptors.length;
      if (
        !isDataDescriptor(length) ||
        !Number.isSafeInteger(length.value) ||
        length.value < 0 ||
        length.value > MAX_NODES
      )
        fail("invalid_plain_json");
      const entries = Object.entries(descriptors).filter(([key]) => key !== "length");
      if (
        entries.length !== length.value ||
        entries.some(
          ([key, descriptor], index) =>
            key !== String(index) || !isDataDescriptor(descriptor) || !descriptor.enumerable,
        )
      )
        fail("invalid_plain_json");
      const snapshot = entries.map(([, descriptor]) => snapshotPlainJson(descriptor.value, depth + 1, budget, stack));
      return Object.freeze(snapshot);
    }
    if (!isPlainObject(value) || Object.getOwnPropertySymbols(value).length !== 0) fail("invalid_plain_json");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const entries = Object.entries(descriptors);
    if (
      entries.length > MAX_NODES ||
      entries.some(([key, descriptor]) => !isDataDescriptor(descriptor) || !descriptor.enumerable)
    )
      fail("invalid_plain_json");
    const snapshot = Object.create(null);
    for (const [key, descriptor] of entries) {
      assertSafeString(key, budget);
      snapshot[key] = snapshotPlainJson(descriptor.value, depth + 1, budget, stack);
    }
    return Object.freeze(snapshot);
  } finally {
    stack.delete(value);
  }
};

const assertKeys = (value, keys) => {
  if (!isPlainObject(value) || Object.keys(value).some((key) => !keys.has(key))) fail("invalid_object");
};

const assertText = (value, max = 256) => {
  if (typeof value !== "string" || value.length < 1 || value.length > max) fail("invalid_text");
  return value;
};

const assertReference = (value) => {
  const text = assertText(value);
  if (!REF.test(text)) fail("invalid_reference");
  return text;
};

const assertHash = (value) => {
  if (typeof value !== "string" || !HASH.test(value)) fail("invalid_hash");
  return value;
};

const assertEmail = (value) => {
  if (typeof value !== "string") fail("invalid_email");
  const email = value.replace(/\r\n/g, "\n").trim().toLowerCase();
  if (!email || !EMAIL.test(email) || UNSAFE_EMAIL_ADDRESS.test(email)) fail("invalid_email");
  return email;
};

const assertEmailText = (value, max) => {
  if (typeof value !== "string") fail("invalid_email_text");
  const normalized = value.replace(/\r\n/g, "\n").trim();
  if (!normalized || normalized.length > max || UNSAFE_EMAIL_TEXT.test(normalized)) fail("invalid_email_text");
  return normalized;
};

const parseInstant = (value) => {
  const text = assertText(value, 64);
  const date = new Date(text);
  if (Number.isNaN(date.valueOf()) || date.toISOString() !== text) fail("invalid_timestamp");
  return date;
};

const iso = (date) => date.toISOString();

const assertAvailability = (value) => {
  if (value !== "available" && value !== "unavailable") fail("invalid_availability");
  return value;
};

const normalizeCeo = (value) => {
  assertKeys(value, CEO_KEYS);
  return Object.freeze({ email: assertEmail(value.email) });
};

const normalizeDeal = (value) => {
  assertKeys(value, DEAL_KEYS);
  const stage = assertText(value.stage, 32);
  if (!STAGES.has(stage)) fail("invalid_stage");
  return Object.freeze({
    dealId: assertReference(value.dealId),
    name: assertText(value.name, 512),
    stage,
    ownerEmail: assertEmail(value.ownerEmail),
    sourceId: assertReference(value.sourceId),
    evidenceHash: assertHash(value.evidenceHash),
  });
};

const normalizeTouch = (value, now) => {
  assertKeys(value, TOUCH_KEYS);
  const occurredAt = parseInstant(value.occurredAt);
  if (occurredAt > now) fail("future_touch");
  if (value.verification !== "verified" && value.verification !== "unverified") fail("invalid_verification");
  return Object.freeze({
    dealId: assertReference(value.dealId),
    touchId: assertReference(value.touchId),
    occurredAt: iso(occurredAt),
    evidenceHash: assertHash(value.evidenceHash),
    verification: value.verification,
  });
};

const normalizeContext = (value, now) => {
  assertKeys(value, CONTEXT_KEYS);
  const availability = assertAvailability(value.availability);
  if (
    !Array.isArray(value.touches) ||
    value.touches.length > MAX_TOUCHES ||
    (availability === "unavailable" && value.touches.length !== 0)
  )
    fail("invalid_touches");
  const touches = value.touches
    .map((item) => normalizeTouch(item, now))
    .sort(
      (left, right) => compareCodepoints(left.dealId, right.dealId) || compareCodepoints(left.touchId, right.touchId),
    );
  if (new Set(touches.map((item) => item.touchId)).size !== touches.length) fail("duplicate_touch");
  return Object.freeze({ availability, touches: Object.freeze(touches) });
};

const normalizeDigestInput = (value) => {
  const input = snapshotPlainJson(value);
  assertKeys(input, ROOT_DIGEST_KEYS);
  const ceo = normalizeCeo(input.ceo);
  const now = parseInstant(input.now);
  assertKeys(input.pipeline, PIPELINE_KEYS);
  const pipelineAvailability = assertAvailability(input.pipeline.availability);
  if (
    !Array.isArray(input.pipeline.records) ||
    input.pipeline.records.length > MAX_DEALS ||
    (pipelineAvailability === "unavailable" && input.pipeline.records.length !== 0)
  )
    fail("invalid_pipeline");
  const deals = input.pipeline.records
    .map(normalizeDeal)
    .sort((left, right) => compareCodepoints(left.dealId, right.dealId));
  if (new Set(deals.map((item) => item.dealId)).size !== deals.length) fail("duplicate_deal");
  const commandCenter = normalizeContext(input.commandCenter, now);
  const brain = normalizeContext(input.brain, now);
  if (pipelineAvailability === "available") {
    const dealIds = new Set(deals.map((item) => item.dealId));
    for (const touch of [...commandCenter.touches, ...brain.touches]) {
      if (!dealIds.has(touch.dealId)) fail("unknown_touch_deal");
    }
  }
  return Object.freeze({ ceo, now, pipelineAvailability, deals: Object.freeze(deals), commandCenter, brain });
};

const citation = (source, sourceId, evidenceHash, occurredAt) =>
  Object.freeze({ source, sourceId, evidenceHash, ...(occurredAt === undefined ? {} : { occurredAt }) });

const urgencyFor = (ageMilliseconds, thresholdDays) => {
  const thresholdMilliseconds = thresholdDays * 24 * 60 * 60 * 1000;
  if (ageMilliseconds < thresholdMilliseconds) return "recent";
  if (ageMilliseconds >= thresholdMilliseconds * 2) return "critical";
  if (ageMilliseconds >= thresholdMilliseconds * 1.5) return "high";
  return "medium";
};

const digestEntry = (deal, normalized) => {
  const dealCitation = citation("pipeline", deal.sourceId, deal.evidenceHash);
  if (normalized.commandCenter.availability === "unavailable" || normalized.brain.availability === "unavailable") {
    return Object.freeze({
      dealId: deal.dealId,
      name: deal.name,
      nameTrust: "untrusted_read_only",
      stage: deal.stage,
      touchState: "touch_source_unavailable",
      urgency: "touch_source_unavailable",
      citations: Object.freeze([dealCitation]),
    });
  }
  const candidates = [
    ...normalized.commandCenter.touches.map((item) => Object.freeze({ source: "command_center", ...item })),
    ...normalized.brain.touches.map((item) => Object.freeze({ source: "brain", ...item })),
  ]
    .filter((item) => item.dealId === deal.dealId && item.verification === "verified")
    .sort(
      (left, right) =>
        compareCodepoints(right.occurredAt, left.occurredAt) ||
        compareCodepoints(left.source, right.source) ||
        compareCodepoints(left.touchId, right.touchId),
    );
  const newest = candidates[0];
  if (!newest) {
    return Object.freeze({
      dealId: deal.dealId,
      name: deal.name,
      nameTrust: "untrusted_read_only",
      stage: deal.stage,
      touchState: "no_verified_touch_record",
      urgency: "no_verified_touch_record",
      citations: Object.freeze([dealCitation]),
    });
  }
  const ageMilliseconds = normalized.now.valueOf() - new Date(newest.occurredAt).valueOf();
  const thresholdDays = staleDealThresholdDays[deal.stage];
  const urgency = urgencyFor(ageMilliseconds, thresholdDays);
  return Object.freeze({
    dealId: deal.dealId,
    name: deal.name,
    nameTrust: "untrusted_read_only",
    stage: deal.stage,
    touchState: "verified_touch",
    newestVerifiedTouch: Object.freeze({
      source: newest.source,
      touchId: newest.touchId,
      occurredAt: newest.occurredAt,
      evidenceHash: newest.evidenceHash,
    }),
    thresholdDays,
    ageMilliseconds,
    urgency,
    citations: Object.freeze([
      dealCitation,
      citation(newest.source, newest.touchId, newest.evidenceHash, newest.occurredAt),
    ]),
  });
};

const compareDigestEntries = (left, right) => {
  const urgency = URGENCY_ORDER[left.urgency] - URGENCY_ORDER[right.urgency];
  if (urgency !== 0) return urgency;
  const age = (right.ageMilliseconds ?? -1) - (left.ageMilliseconds ?? -1);
  if (age !== 0) return age;
  return compareCodepoints(left.dealId, right.dealId);
};

const digestArtifact = (normalized, entries, status) => {
  const stale = entries.filter((entry) => ["critical", "high", "medium"].includes(entry.urgency));
  const unknown = entries.filter((entry) => entry.urgency === "no_verified_touch_record");
  const counts = Object.fromEntries(
    ["critical", "high", "medium"].map((urgency) => [
      urgency,
      stale.filter((entry) => entry.urgency === urgency).length,
    ]),
  );
  const identity = sha256Canonical({
    ceoEmail: normalized.ceo.email,
    deals: entries.map((entry) => ({
      dealId: entry.dealId,
      urgency: entry.urgency,
      citations: entry.citations.map((item) => ({
        source: item.source,
        sourceId: item.sourceId,
        evidenceHash: item.evidenceHash,
        ...(item.occurredAt === undefined ? {} : { occurredAt: item.occurredAt }),
      })),
    })),
  });
  const evidence = [
    ...stale,
    ...unknown,
    ...entries.filter((entry) => !stale.includes(entry) && !unknown.includes(entry)),
  ]
    .slice(0, 8)
    .map((entry) => {
      const pipeline = entry.citations.find((item) => item.source === "pipeline");
      return Object.freeze({
        label: "Pipeline record",
        source: "Pipeline",
        resourceRef: pipeline.sourceId,
      });
    });
  const ready = status === "ready" || status === "followup_needed";
  return Object.freeze({
    version: 1,
    id: `stale-digest-${identity.slice(0, 40)}`,
    revision: sha256Canonical({ identity, status, evaluatedAt: iso(normalized.now) }),
    kind: "stale_deals",
    state: ready ? "ready" : "waiting",
    title: "Stale deal digest",
    summary: !ready
      ? "A source is unavailable, so no stale-deal conclusion was generated."
      : stale.length > 0
        ? `${stale.length} stale deal${stale.length === 1 ? "" : "s"} require CEO review.`
        : unknown.length > 0
          ? `${unknown.length} deal${unknown.length === 1 ? "" : "s"} have no verified touch and need follow-up before staleness can be assessed.`
          : "No stale deals were identified from verified touches.",
    facts: Object.freeze([
      Object.freeze({ label: "Critical", value: `${counts.critical} deal${counts.critical === 1 ? "" : "s"}` }),
      Object.freeze({ label: "High", value: `${counts.high} deal${counts.high === 1 ? "" : "s"}` }),
      Object.freeze(
        unknown.length > 0
          ? { label: "Follow-up needed", value: `${unknown.length} deal${unknown.length === 1 ? "" : "s"}` }
          : { label: "Medium", value: `${counts.medium} deal${counts.medium === 1 ? "" : "s"}` },
      ),
    ]),
    evidence: Object.freeze(evidence),
    links: Object.freeze([]),
    actions:
      ready && (stale.length > 0 || unknown.length > 0)
        ? Object.freeze([
            Object.freeze({ key: "review_deals", label: "Review deals", primary: true }),
            ...(unknown.length > 0 ? [Object.freeze({ key: "draft_followup", label: "Draft follow-up" })] : []),
          ])
        : Object.freeze([]),
    updatedAt: iso(normalized.now),
    ...(ready ? {} : { errorCode: "connector_unavailable" }),
  });
};

export const buildStaleDealDigest = (input) => {
  const normalized = normalizeDigestInput(input);
  if (normalized.pipelineAvailability === "unavailable") {
    const artifact = digestArtifact(normalized, [], "source_unavailable");
    return Object.freeze({
      version: 1,
      kind: "stale_deal_digest",
      audience: Object.freeze({ scope: "ceo_personal", email: normalized.ceo.email }),
      evaluatedAt: iso(normalized.now),
      thresholdsDays: staleDealThresholdDays,
      sourceAvailability: Object.freeze({
        pipeline: "unavailable",
        commandCenter: normalized.commandCenter.availability,
        brain: normalized.brain.availability,
      }),
      status: "source_unavailable",
      notices: Object.freeze([Object.freeze({ code: "pipeline_source_unavailable" })]),
      entries: Object.freeze([]),
      artifact,
    });
  }
  const entries = normalized.deals
    .filter((deal) => deal.ownerEmail === normalized.ceo.email)
    .map((deal) => digestEntry(deal, normalized))
    .sort(compareDigestEntries);
  const incomplete =
    normalized.commandCenter.availability === "unavailable" || normalized.brain.availability === "unavailable";
  const notices = [
    ...(normalized.commandCenter.availability === "unavailable"
      ? [Object.freeze({ code: "command_center_source_unavailable" })]
      : []),
    ...(normalized.brain.availability === "unavailable" ? [Object.freeze({ code: "brain_source_unavailable" })] : []),
  ];
  const status = incomplete
    ? "source_incomplete"
    : entries.some((entry) => entry.urgency === "no_verified_touch_record")
      ? "followup_needed"
      : "ready";
  return Object.freeze({
    version: 1,
    kind: "stale_deal_digest",
    audience: Object.freeze({ scope: "ceo_personal", email: normalized.ceo.email }),
    evaluatedAt: iso(normalized.now),
    thresholdsDays: staleDealThresholdDays,
    sourceAvailability: Object.freeze({
      pipeline: "available",
      commandCenter: normalized.commandCenter.availability,
      brain: normalized.brain.availability,
    }),
    status,
    notices: Object.freeze(notices),
    entries: Object.freeze(entries),
    artifact: digestArtifact(normalized, entries, status),
  });
};

const normalizeAttendee = (value) => {
  assertKeys(value, ATTENDEE_KEYS);
  if (
    typeof value.external !== "boolean" ||
    !["accepted", "declined", "tentative", "needsAction"].includes(value.response)
  )
    fail("invalid_attendee");
  return Object.freeze({ email: assertEmail(value.email), external: value.external, response: value.response });
};

const normalizeEvent = (value) => {
  assertKeys(value, EVENT_KEYS);
  const startAt = parseInstant(value.startAt);
  const endAt = parseInstant(value.endAt);
  if (endAt <= startAt || !Array.isArray(value.attendees) || value.attendees.length > 128) fail("invalid_event");
  const attendees = value.attendees
    .map(normalizeAttendee)
    .sort((left, right) => compareCodepoints(left.email, right.email));
  if (new Set(attendees.map((item) => item.email)).size !== attendees.length) fail("duplicate_attendee");
  return Object.freeze({
    eventId: assertReference(value.eventId),
    originalStartAt: iso(parseInstant(value.originalStartAt)),
    startAt: iso(startAt),
    endAt: iso(endAt),
    organizerEmail: assertEmail(value.organizerEmail),
    attendees: Object.freeze(attendees),
    evidenceHash: assertHash(value.evidenceHash),
  });
};

const normalizeCitation = (value) => {
  assertKeys(value, CITATION_KEYS);
  return Object.freeze({
    transcriptId: assertReference(value.transcriptId),
    evidenceHash: assertHash(value.evidenceHash),
  });
};

const normalizeFinding = (value) => {
  assertKeys(value, FINDING_KEYS);
  if (
    !Array.isArray(value.citations) ||
    value.citations.length < 1 ||
    value.citations.length > MAX_CITATIONS_PER_FINDING
  )
    fail("invalid_finding_citations");
  const citations = value.citations
    .map(normalizeCitation)
    .sort(
      (left, right) =>
        compareCodepoints(left.transcriptId, right.transcriptId) ||
        compareCodepoints(left.evidenceHash, right.evidenceHash),
    );
  if (new Set(citations.map((item) => `${item.transcriptId}\u0000${item.evidenceHash}`)).size !== citations.length)
    fail("duplicate_finding_citation");
  return Object.freeze({
    findingId: assertReference(value.findingId),
    text: assertText(value.text, 2000),
    citations: Object.freeze(citations),
  });
};

const normalizeFindings = (value) => {
  assertKeys(value, FINDINGS_KEYS);
  const groups = {};
  for (const group of FINDING_GROUPS) {
    if (!Array.isArray(value[group]) || value[group].length > MAX_FINDINGS_PER_GROUP) fail("invalid_findings");
    const findings = value[group]
      .map(normalizeFinding)
      .sort((left, right) => compareCodepoints(left.findingId, right.findingId));
    if (new Set(findings.map((item) => item.findingId)).size !== findings.length) fail("duplicate_finding");
    groups[group] = Object.freeze(findings);
  }
  if (
    new Set(FINDING_GROUPS.flatMap((group) => groups[group].map((finding) => finding.findingId))).size !==
    FINDING_GROUPS.reduce((count, group) => count + groups[group].length, 0)
  )
    fail("duplicate_finding");
  return Object.freeze(groups);
};

const normalizeTranscript = (value, now) => {
  assertKeys(value, TRANSCRIPT_KEYS);
  if (value.revision !== "draft" && value.revision !== "final") fail("invalid_transcript_revision");
  const finalizedAt = parseInstant(value.finalizedAt);
  if (finalizedAt > now) fail("future_transcript");
  return Object.freeze({
    transcriptId: assertReference(value.transcriptId),
    eventId: assertReference(value.eventId),
    originalStartAt: iso(parseInstant(value.originalStartAt)),
    revision: value.revision,
    finalizedAt: iso(finalizedAt),
    evidenceHash: assertHash(value.evidenceHash),
    findings: normalizeFindings(value.findings),
  });
};

const normalizePostMeetingInput = (value, followup = false) => {
  const input = snapshotPlainJson(value);
  assertKeys(input, followup ? ROOT_FOLLOWUP_KEYS : ROOT_POST_MEETING_KEYS);
  const ceo = normalizeCeo(input.ceo);
  const now = parseInstant(input.now);
  assertKeys(input.meeting, MEETING_KEYS);
  const meeting = Object.freeze({
    eventId: assertReference(input.meeting.eventId),
    originalStartAt: iso(parseInstant(input.meeting.originalStartAt)),
  });
  assertKeys(input.calendar, CALENDAR_KEYS);
  const calendarAvailability = assertAvailability(input.calendar.availability);
  const calendarAccountEmail = assertEmail(input.calendar.accountEmail);
  if (
    !Array.isArray(input.calendar.events) ||
    input.calendar.events.length > MAX_EVENTS ||
    (calendarAvailability === "unavailable" && input.calendar.events.length !== 0)
  )
    fail("invalid_calendar");
  const events = input.calendar.events
    .map(normalizeEvent)
    .sort(
      (left, right) =>
        compareCodepoints(left.eventId, right.eventId) ||
        compareCodepoints(left.originalStartAt, right.originalStartAt),
    );
  if (new Set(events.map((item) => `${item.eventId}\u0000${item.originalStartAt}`)).size !== events.length)
    fail("duplicate_event");
  assertKeys(input.transcripts, TRANSCRIPTS_KEYS);
  const transcriptAvailability = assertAvailability(input.transcripts.availability);
  if (
    !Array.isArray(input.transcripts.records) ||
    input.transcripts.records.length > MAX_TRANSCRIPTS ||
    (transcriptAvailability === "unavailable" && input.transcripts.records.length !== 0)
  )
    fail("invalid_transcripts");
  const transcripts = input.transcripts.records
    .map((item) => normalizeTranscript(item, now))
    .sort(
      (left, right) =>
        compareCodepoints(left.eventId, right.eventId) ||
        compareCodepoints(left.originalStartAt, right.originalStartAt) ||
        compareCodepoints(left.revision, right.revision),
    );
  if (
    new Set(transcripts.map((item) => `${item.eventId}\u0000${item.originalStartAt}\u0000${item.revision}`)).size !==
    transcripts.length
  )
    fail("duplicate_transcript");
  for (const transcript of transcripts) {
    if (transcript.revision !== "final") continue;
    const occurrence = events.find(
      (event) => event.eventId === transcript.eventId && event.originalStartAt === transcript.originalStartAt,
    );
    if (occurrence && new Date(transcript.finalizedAt) < new Date(occurrence.endAt)) {
      fail("final_transcript_before_event_end");
    }
  }
  const base = {
    ceo,
    now,
    meeting,
    calendarAvailability,
    calendarAccountEmail,
    events: Object.freeze(events),
    transcriptAvailability,
    transcripts: Object.freeze(transcripts),
  };
  if (!followup) return Object.freeze(base);
  assertKeys(input.recipient, RECIPIENT_KEYS);
  assertKeys(input.draft, DRAFT_KEYS);
  return Object.freeze({
    ...base,
    recipient: assertEmail(input.recipient.email),
    draft: Object.freeze({
      subject: assertEmailText(input.draft.subject, 200),
      body: assertEmailText(input.draft.body, 12_000),
    }),
  });
};

const calendarCitation = (event) => citation("calendar_occurrence", event.eventId, event.evidenceHash, event.endAt);

const transcriptCitation = (transcript) =>
  citation("final_transcript", transcript.transcriptId, transcript.evidenceHash, transcript.finalizedAt);

const postMeetingArtifact = (normalized, event, transcript, status, reason, analysis) => {
  const identity = sha256Canonical({ meeting: normalized.meeting, eventEvidenceHash: event?.evidenceHash ?? null });
  const ready = status === "ready";
  const evidence = event
    ? Object.freeze([
        Object.freeze({ label: "Calendar occurrence", source: "Calendar", resourceRef: event.eventId }),
        ...(transcript
          ? [Object.freeze({ label: "Final transcript", source: "Transcript", resourceRef: transcript.transcriptId })]
          : []),
      ])
    : Object.freeze([]);
  const fact = (label, group) => Object.freeze({ label, value: `${analysis?.[group]?.length ?? 0} evidenced` });
  return Object.freeze({
    version: 1,
    id: `meeting-analysis-${identity.slice(0, 40)}`,
    revision: sha256Canonical({ identity, status, reason, analysis }),
    kind: "meeting_followup",
    state: ready ? "ready" : "waiting",
    title: "Post-meeting analysis",
    summary: ready
      ? "Final transcript findings are bound to the meeting occurrence."
      : "No post-meeting analysis was generated because required context is unavailable.",
    facts: ready
      ? Object.freeze([fact("Decisions", "decisions"), fact("Action items", "actionItems"), fact("Risks", "risks")])
      : Object.freeze([]),
    evidence,
    links: Object.freeze([]),
    actions: ready
      ? Object.freeze([Object.freeze({ key: "review_followup", label: "Review follow-up", primary: true })])
      : Object.freeze([
          Object.freeze({ key: "add_notes", label: "Add notes", primary: true }),
          Object.freeze({ key: "retry", label: "Retry" }),
        ]),
    updatedAt: iso(normalized.now),
    ...(ready
      ? {}
      : {
          errorCode:
            reason === "transcript_source_unavailable" || reason === "calendar_source_unavailable"
              ? "connector_unavailable"
              : "transcript_pending",
        }),
  });
};

const postMeetingPlan = (normalized) => {
  if (normalized.calendarAvailability === "unavailable") {
    const artifact = postMeetingArtifact(
      normalized,
      undefined,
      undefined,
      "waiting",
      "calendar_source_unavailable",
      null,
    );
    return Object.freeze({
      status: "waiting",
      reason: "calendar_source_unavailable",
      event: null,
      transcript: null,
      analysis: null,
      artifact,
    });
  }
  const event = normalized.events.find(
    (item) =>
      item.eventId === normalized.meeting.eventId && item.originalStartAt === normalized.meeting.originalStartAt,
  );
  if (!event) {
    const artifact = postMeetingArtifact(
      normalized,
      undefined,
      undefined,
      "waiting",
      "meeting_occurrence_not_found",
      null,
    );
    return Object.freeze({
      status: "waiting",
      reason: "meeting_occurrence_not_found",
      event: null,
      transcript: null,
      analysis: null,
      artifact,
    });
  }
  if (normalized.now < new Date(event.endAt)) {
    const artifact = postMeetingArtifact(normalized, event, undefined, "waiting", "meeting_not_ended", null);
    return Object.freeze({
      status: "waiting",
      reason: "meeting_not_ended",
      event,
      transcript: null,
      analysis: null,
      artifact,
    });
  }
  if (normalized.transcriptAvailability === "unavailable") {
    const artifact = postMeetingArtifact(
      normalized,
      event,
      undefined,
      "waiting",
      "transcript_source_unavailable",
      null,
    );
    return Object.freeze({
      status: "waiting",
      reason: "transcript_source_unavailable",
      event,
      transcript: null,
      analysis: null,
      artifact,
    });
  }
  const transcript = normalized.transcripts.find(
    (item) =>
      item.eventId === event.eventId && item.originalStartAt === event.originalStartAt && item.revision === "final",
  );
  if (!transcript) {
    const artifact = postMeetingArtifact(normalized, event, undefined, "waiting", "final_transcript_not_found", null);
    return Object.freeze({
      status: "waiting",
      reason: "final_transcript_not_found",
      event,
      transcript: null,
      analysis: null,
      artifact,
    });
  }
  const groups = Object.fromEntries(
    FINDING_GROUPS.map((group) => [
      group,
      Object.freeze(
        transcript.findings[group].map((finding) =>
          Object.freeze({
            findingId: finding.findingId,
            text: finding.text,
            trust: "untrusted_read_only",
            citations: Object.freeze(
              finding.citations.map((item) =>
                Object.freeze({
                  source: "final_transcript",
                  sourceId: item.transcriptId,
                  evidenceHash: item.evidenceHash,
                }),
              ),
            ),
          }),
        ),
      ),
    ]),
  );
  for (const group of FINDING_GROUPS) {
    for (const finding of groups[group]) {
      if (
        finding.citations.some(
          (item) => item.sourceId !== transcript.transcriptId || item.evidenceHash !== transcript.evidenceHash,
        )
      )
        fail("finding_not_bound_to_final_transcript");
    }
  }
  const analysis = Object.freeze({
    meeting: Object.freeze({
      eventId: event.eventId,
      originalStartAt: event.originalStartAt,
      startAt: event.startAt,
      endAt: event.endAt,
      trust: "untrusted_read_only",
    }),
    transcript: Object.freeze({
      transcriptId: transcript.transcriptId,
      finalizedAt: transcript.finalizedAt,
      evidenceHash: transcript.evidenceHash,
      trust: "untrusted_read_only",
    }),
    ...groups,
    evidence: Object.freeze([calendarCitation(event), transcriptCitation(transcript)]),
  });
  const artifact = postMeetingArtifact(normalized, event, transcript, "ready", null, analysis);
  return Object.freeze({ status: "ready", reason: null, event, transcript, analysis, artifact });
};

export const buildPostMeetingAnalysis = (input) => {
  const normalized = normalizePostMeetingInput(input);
  const plan = postMeetingPlan(normalized);
  return Object.freeze({
    version: 1,
    kind: "post_meeting_analysis",
    audience: Object.freeze({ scope: "ceo_personal", email: normalized.ceo.email }),
    evaluatedAt: iso(normalized.now),
    status: plan.status,
    ...(plan.reason === null ? {} : { reason: plan.reason }),
    analysis: plan.analysis,
    artifact: plan.artifact,
  });
};

const followupArtifact = (normalized, plan, proposal) => {
  const identity = sha256Canonical({ meeting: normalized.meeting, recipient: normalized.recipient });
  if (!proposal)
    return Object.freeze({
      ...plan.artifact,
      id: `meeting-followup-${identity.slice(0, 40)}`,
      revision: sha256Canonical({ identity, status: plan.status, reason: plan.reason }),
      title: "Follow-up draft proposal",
    });
  const gmailDraft = Object.freeze({
    to: proposal.payloadInputs.to,
    subject: proposal.payloadInputs.subject,
    body: proposal.payloadInputs.body,
    contentSha256: gmailDraftContentHash(proposal.payloadInputs),
  });
  return Object.freeze({
    version: 1,
    id: `meeting-followup-${identity.slice(0, 40)}`,
    revision: sha256Canonical({ identity, proposal }),
    kind: "meeting_followup",
    state: "ready",
    title: "Follow-up draft proposal",
    summary: "A CEO personal Gmail draft is proposed for review only.",
    facts: Object.freeze([
      Object.freeze({ label: "Recipient", value: "External meeting attendee" }),
      Object.freeze({ label: "Scope", value: "CEO personal Gmail draft" }),
      Object.freeze({ label: "Status", value: "Draft proposal only" }),
    ]),
    evidence: Object.freeze([
      Object.freeze({ label: "Calendar occurrence", source: "Calendar", resourceRef: plan.event.eventId }),
      Object.freeze({ label: "Final transcript", source: "Transcript", resourceRef: plan.transcript.transcriptId }),
    ]),
    links: Object.freeze([]),
    actions: Object.freeze([
      Object.freeze({ key: "review_followup", label: "Review follow-up", primary: true }),
      Object.freeze({ key: "create_gmail_draft", label: "Create Gmail draft" }),
    ]),
    updatedAt: iso(normalized.now),
    gmailDraft,
  });
};

const followupEligibilityReason = (normalized, event) => {
  if (normalized.calendarAccountEmail !== normalized.ceo.email) return "calendar_not_ceo_bound";
  const ceoAttendee = event.attendees.find(
    (attendee) => attendee.email === normalized.ceo.email && !attendee.external && attendee.response !== "declined",
  );
  if (event.organizerEmail !== normalized.ceo.email && !ceoAttendee) return "ceo_not_internal_attendee_or_organizer";
  return null;
};

export const proposeMeetingFollowupDraft = (input) => {
  const normalized = normalizePostMeetingInput(input, true);
  const plan = postMeetingPlan(normalized);
  if (plan.status !== "ready") {
    return Object.freeze({
      version: 1,
      kind: "gmail_personal_draft_proposal",
      audience: Object.freeze({ scope: "ceo_personal", email: normalized.ceo.email }),
      evaluatedAt: iso(normalized.now),
      status: "not_proposed",
      reason: plan.reason,
      proposal: null,
      artifact: followupArtifact(normalized, plan, null),
    });
  }
  const eligibilityReason = followupEligibilityReason(normalized, plan.event);
  if (eligibilityReason !== null) {
    return Object.freeze({
      version: 1,
      kind: "gmail_personal_draft_proposal",
      audience: Object.freeze({ scope: "ceo_personal", email: normalized.ceo.email }),
      evaluatedAt: iso(normalized.now),
      status: "not_proposed",
      reason: eligibilityReason,
      proposal: null,
      artifact: followupArtifact(normalized, plan, null),
    });
  }
  const attendee = plan.event.attendees.find(
    (item) => item.email === normalized.recipient && item.external && item.response !== "declined",
  );
  if (!attendee) fail("recipient_not_bound_to_calendar_occurrence");
  const payloadInputs = Object.freeze({
    gmailAccount: normalized.ceo.email,
    to: normalized.recipient,
    subject: normalized.draft.subject,
    body: normalized.draft.body,
  });
  const evidence = Object.freeze([calendarCitation(plan.event), transcriptCitation(plan.transcript)]);
  const proposal = Object.freeze({
    kind: "gmail_personal_draft",
    status: "draft_only",
    audience: Object.freeze({ scope: "ceo_personal", email: normalized.ceo.email }),
    recipients: Object.freeze([
      Object.freeze({
        email: normalized.recipient,
        source: "calendar_attendee",
        eventId: plan.event.eventId,
        originalStartAt: plan.event.originalStartAt,
        evidenceHash: plan.event.evidenceHash,
      }),
    ]),
    subject: normalized.draft.subject,
    body: normalized.draft.body,
    evidence,
    payloadInputs,
  });
  return Object.freeze({
    version: 1,
    kind: "gmail_personal_draft_proposal",
    audience: Object.freeze({ scope: "ceo_personal", email: normalized.ceo.email }),
    evaluatedAt: iso(normalized.now),
    status: "proposed",
    proposal,
    artifact: followupArtifact(normalized, plan, proposal),
  });
};
