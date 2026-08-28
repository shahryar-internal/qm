import { sha256Canonical } from "../contracts/index.mjs";
import {
  assertHash,
  assertRecord,
  assertRef,
  assertText,
  assertUnique,
  compareCodepoints,
  fail,
  parseInstant,
  snapshotPlainJson,
} from "./validation.mjs";

const normalizeEvidence = (input, generatedAt, periodStart, periodEnd) => {
  assertRecord(
    input,
    ["evidenceRef", "source", "occurredAt", "evidenceHash", "summary", "temporalRole"],
    "invalid_goal_evidence",
  );
  const occurredAt = parseInstant(input.occurredAt);
  if (
    occurredAt > generatedAt ||
    !["period_observation", "prior_baseline"].includes(input.temporalRole) ||
    (input.temporalRole === "period_observation" && (occurredAt < periodStart || occurredAt >= periodEnd)) ||
    (input.temporalRole === "prior_baseline" && occurredAt >= periodStart)
  ) {
    fail("invalid_goal_evidence_period");
  }
  return Object.freeze({
    evidenceRef: assertRef(input.evidenceRef),
    source: assertRef(input.source),
    occurredAt: occurredAt.toISOString(),
    evidenceHash: assertHash(input.evidenceHash),
    summary: assertText(input.summary, 1_024),
    temporalRole: input.temporalRole,
    trust: "untrusted_source_data",
  });
};

const normalizeGoal = (input) => {
  assertRecord(
    input,
    ["goalRef", "definitionVersion", "definitionHash", "title", "target", "targetDate", "evidenceRefs"],
    "invalid_goal",
  );
  if (!Array.isArray(input.evidenceRefs) || input.evidenceRefs.length > 64) fail("invalid_goal");
  const evidenceRefs = input.evidenceRefs.map(assertRef).sort(compareCodepoints);
  assertUnique(evidenceRefs, (ref) => ref, "duplicate_goal_evidence_ref");
  const definition = Object.freeze({
    goalRef: assertRef(input.goalRef),
    definitionVersion: assertRef(input.definitionVersion),
    title: assertText(input.title, 512),
    target: assertText(input.target, 1_024),
    targetDate: parseInstant(input.targetDate).toISOString(),
  });
  if (assertHash(input.definitionHash) !== sha256Canonical(definition)) fail("goal_definition_hash_mismatch");
  return Object.freeze({
    ...definition,
    definitionHash: input.definitionHash,
    evidenceRefs: Object.freeze(evidenceRefs),
    trust: "configured_goal_definition",
  });
};

const normalizeUpdate = (input, goal, evidenceByRef) => {
  assertRecord(input, ["goalRef", "status", "summary", "citations", "confidence"], "invalid_goal_update");
  if (
    input.goalRef !== goal.goalRef ||
    !["on_track", "at_risk", "off_track", "unknown"].includes(input.status) ||
    !["high", "medium", "low"].includes(input.confidence) ||
    !Array.isArray(input.citations) ||
    input.citations.length > 16
  ) {
    fail("invalid_goal_update");
  }
  const citations = input.citations.map(assertRef).sort(compareCodepoints);
  assertUnique(citations, (ref) => ref, "duplicate_goal_update_citation");
  if (citations.some((ref) => !goal.evidenceRefs.includes(ref) || !evidenceByRef.has(ref))) {
    fail("unknown_goal_update_citation");
  }
  if (citations.length === 0 && (input.status !== "unknown" || input.confidence !== "low")) {
    fail("unsupported_goal_status");
  }
  if (
    input.status !== "unknown" &&
    !citations.some((citation) => evidenceByRef.get(citation)?.temporalRole === "period_observation")
  ) {
    fail("stale_goal_status_evidence");
  }
  return Object.freeze({
    goalRef: goal.goalRef,
    status: input.status,
    summary: assertText(input.summary, 2_048),
    citations: Object.freeze(citations),
    confidence: input.confidence,
    trust: "generated_evidence_cited_update",
  });
};

const assertTimezone = (value) => {
  const timezone = assertText(value, 128);
  try {
    const canonical = new Intl.DateTimeFormat("en-US", { timeZone: timezone }).resolvedOptions().timeZone;
    if (canonical !== timezone) fail("invalid_goal_timezone");
  } catch {
    fail("invalid_goal_timezone");
  }
  return timezone;
};

const localBoundary = (instant, timezone) => {
  if (instant.getUTCMilliseconds() !== 0) fail("noncanonical_goal_period");
  const parts = new Intl.DateTimeFormat("en-CA", {
    calendar: "iso8601",
    hourCycle: "h23",
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(instant);
  const values = Object.fromEntries(
    parts.filter((part) => part.type !== "literal").map((part) => [part.type, part.value]),
  );
  if (values.hour !== "00" || values.minute !== "00" || values.second !== "00") fail("noncanonical_goal_period");
  return Object.freeze({
    year: Number(values.year),
    month: Number(values.month),
    day: Number(values.day),
    dayNumber: Math.floor(Date.UTC(Number(values.year), Number(values.month) - 1, Number(values.day)) / 86_400_000),
  });
};

const assertCanonicalPeriod = (kind, start, end, timezone) => {
  const localStart = localBoundary(start, timezone);
  const localEnd = localBoundary(end, timezone);
  if (kind === "daily" && localEnd.dayNumber !== localStart.dayNumber + 1) fail("noncanonical_goal_period");
  if (
    kind === "weekly" &&
    (new Date(Date.UTC(localStart.year, localStart.month - 1, localStart.day)).getUTCDay() !== 1 ||
      localEnd.dayNumber !== localStart.dayNumber + 7)
  ) {
    fail("noncanonical_goal_period");
  }
  if (kind === "quarterly") {
    if (![1, 4, 7, 10].includes(localStart.month) || localStart.day !== 1 || localEnd.day !== 1) {
      fail("noncanonical_goal_period");
    }
    const expectedEndMonth = ((localStart.month + 2) % 12) + 1;
    const expectedEndYear = localStart.year + (localStart.month === 10 ? 1 : 0);
    if (localEnd.month !== expectedEndMonth || localEnd.year !== expectedEndYear) fail("noncanonical_goal_period");
  }
};

export const buildGoalsAndEodArtifact = (input) => {
  const value = snapshotPlainJson(input);
  assertRecord(
    value,
    [
      "principalRef",
      "periodKind",
      "periodStart",
      "periodEnd",
      "timezone",
      "generatedAt",
      "goals",
      "evidence",
      "updates",
    ],
    "invalid_goals_artifact",
  );
  if (
    !Array.isArray(value.goals) ||
    value.goals.length > 64 ||
    !Array.isArray(value.evidence) ||
    value.evidence.length > 512 ||
    !Array.isArray(value.updates)
  ) {
    fail("invalid_goals_artifact");
  }
  const generatedAt = parseInstant(value.generatedAt);
  const periodStart = parseInstant(value.periodStart);
  const periodEnd = parseInstant(value.periodEnd);
  if (periodEnd <= periodStart || generatedAt < periodEnd) fail("invalid_goal_period");
  if (!["daily", "weekly", "quarterly"].includes(value.periodKind)) fail("invalid_goal_period");
  const timezone = assertTimezone(value.timezone);
  assertCanonicalPeriod(value.periodKind, periodStart, periodEnd, timezone);
  const goals = value.goals.map(normalizeGoal).sort((left, right) => compareCodepoints(left.goalRef, right.goalRef));
  assertUnique(goals, (goal) => goal.goalRef, "duplicate_goal");
  if (value.updates.length !== goals.length) fail("missing_goal_update");
  const evidence = value.evidence
    .map((entry) => normalizeEvidence(entry, generatedAt, periodStart, periodEnd))
    .sort((left, right) => compareCodepoints(left.evidenceRef, right.evidenceRef));
  assertUnique(evidence, (entry) => entry.evidenceRef, "duplicate_goal_evidence");
  const evidenceByRef = new Map(evidence.map((entry) => [entry.evidenceRef, entry]));
  if (goals.some((goal) => goal.evidenceRefs.some((evidenceRef) => !evidenceByRef.has(evidenceRef)))) {
    fail("dangling_goal_evidence_ref");
  }
  const updatesByGoal = new Map(value.updates.map((entry) => [entry.goalRef, entry]));
  if (updatesByGoal.size !== value.updates.length) fail("duplicate_goal_update");
  const updates = goals.map((goal) => normalizeUpdate(updatesByGoal.get(goal.goalRef), goal, evidenceByRef));
  const normalized = Object.freeze({
    schemaVersion: 1,
    artifactType: value.periodKind === "daily" ? "chief_of_staff.eod_update" : "chief_of_staff.goals_review",
    principalRef: assertRef(value.principalRef),
    period: Object.freeze({
      kind: value.periodKind,
      start: periodStart.toISOString(),
      end: periodEnd.toISOString(),
      timezone,
    }),
    generatedAt: generatedAt.toISOString(),
    goals: Object.freeze(goals),
    evidence: Object.freeze(evidence),
    updates: Object.freeze(updates),
    citationsRequired: true,
    presentationSinkAllowed: false,
    providerEffectAllowed: false,
  });
  return Object.freeze({ ...normalized, artifactHash: sha256Canonical(normalized) });
};
