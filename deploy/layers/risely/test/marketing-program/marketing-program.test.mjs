import assert from "node:assert/strict";
import test from "node:test";
import {
  buildDailyMarketingDraft,
  buildWeeklyMarketingPlan,
  createMarketingBoundaryFixture,
  initializeMarketingState,
  inspectDailyMarketingDraft,
  MarketingProgramError,
  presentMarketingProgram,
  prospectiveEvaluatorRegistry,
  recordMarketingEvaluation,
  recordMarketingPlanApproval,
  requestMarketingEvaluation,
  requestMarketingPlanApproval,
  sha256Canonical,
  snapshotPlainJson,
} from "../../canary/marketing-program/index.mjs";

const clone = (value) => structuredClone(value);
const evaluationRequest = (program, expectedRevision = 0) => ({
  requestRef: "evaluation-request:one",
  expectedRevision,
  programHash: program.programHash,
  artifactHash: sha256Canonical(program.artifact),
  programKind: program.kind,
  programRevision: program.programRevision,
  rubricHash: program.rubricHash,
  researchHash: program.researchHash,
  mappingHash: program.artifact.mappingHash,
  citationRefsHash: sha256Canonical(program.artifact.citationRefs),
  sourceRefsHash: sha256Canonical(program.artifact.sourceRefs),
  requestedAt: "2026-08-28T17:00:00.000Z",
  expiresAt: "2026-08-28T18:00:00.000Z",
});
const approvalRequest = (program, expectedRevision = 0) => {
  const bare = {
    requestRef: "approval-request:one",
    expectedRevision,
    programHash: program.programHash,
    artifactHash: sha256Canonical(program.artifact),
    programKind: program.kind,
    programRevision: program.programRevision,
    rubricHash: program.rubricHash,
    researchHash: program.researchHash,
    mappingHash: program.artifact.mappingHash,
    citationRefsHash: sha256Canonical(program.artifact.citationRefs),
    sourceRefsHash: sha256Canonical(program.artifact.sourceRefs),
    planHash: program.planHash,
    teamRef: program.principalBinding.slackTeamRef,
    userRef: program.principalBinding.slackUserRef,
    messageRef: "slack-message:one",
    interactionRef: "slack-interaction:one",
    requestedAt: "2026-08-28T17:00:00.000Z",
    expiresAt: "2026-08-28T18:00:00.000Z",
  };
  return {
    ...bare,
    payloadHash: sha256Canonical({
      programHash: bare.programHash,
      artifactHash: bare.artifactHash,
      programKind: bare.programKind,
      programRevision: bare.programRevision,
      stateRevision: bare.expectedRevision,
      rubricHash: bare.rubricHash,
      researchHash: bare.researchHash,
      mappingHash: bare.mappingHash,
      citationRefsHash: bare.citationRefsHash,
      sourceRefsHash: bare.sourceRefsHash,
      planHash: bare.planHash,
      teamRef: bare.teamRef,
      userRef: bare.userRef,
      messageRef: bare.messageRef,
      interactionRef: bare.interactionRef,
    }),
  };
};

test("creates a Friday-only, actionless CEO weekly plan with exact rotation", () => {
  const program = buildWeeklyMarketingPlan(createMarketingBoundaryFixture());
  assert.equal(program.kind, "weekly_plan");
  assert.deepEqual(
    program.weeklyPlan.entries.map((entry) => entry.lane),
    ["admissions", "advancement", "admissions", "advancement", "admissions"],
  );
  assert.equal(program.artifact.programHash, program.programHash);
  assert.equal(program.artifact.rubricHash, program.rubricHash);
  assert.equal(program.artifact.researchHash, program.researchHash);
  assert.equal(program.safety.executionDisposition, "hard_disabled");
  assert.equal(program.artifact.slackArtifact.actionless, true);
});

test("canonicalization property preserves identity over permissible source ordering", () => {
  const baseline = createMarketingBoundaryFixture();
  baseline.history.unshift({
    date: "2026-05-01",
    lane: "admissions",
    topicRef: "topic:older",
    noveltyKey: "novelty:older",
  });
  const expected = buildWeeklyMarketingPlan(baseline).programHash;
  for (let rotation = 0; rotation < 10; rotation += 1) {
    const candidate = clone(baseline);
    candidate.weeklyPlan.entries = [
      ...candidate.weeklyPlan.entries.slice(rotation % 5),
      ...candidate.weeklyPlan.entries.slice(0, rotation % 5),
    ];
    candidate.research = [...candidate.research.slice(rotation % 5), ...candidate.research.slice(0, rotation % 5)];
    if (rotation % 2) candidate.history.reverse();
    assert.equal(buildWeeklyMarketingPlan(candidate).programHash, expected);
  }
});

test("rejects timing, rotation, duplicate topics, cooldown, novelty, and arbitrary research origins", () => {
  const friday = createMarketingBoundaryFixture();
  friday.goalDate = "2026-08-27";
  assert.throws(() => buildWeeklyMarketingPlan(friday), /friday_plan_required/);
  const rotation = createMarketingBoundaryFixture();
  rotation.weeklyPlan.entries[0].lane = "advancement";
  assert.throws(() => buildWeeklyMarketingPlan(rotation), /rotation_violation/);
  const duplicate = createMarketingBoundaryFixture();
  duplicate.weeklyPlan.entries[1].topicRef = duplicate.weeklyPlan.entries[0].topicRef;
  assert.throws(() => buildWeeklyMarketingPlan(duplicate), /invalid_plan_schedule/);
  const cooldown = createMarketingBoundaryFixture();
  cooldown.history[0].topicRef = cooldown.weeklyPlan.entries[0].topicRef;
  assert.throws(() => buildWeeklyMarketingPlan(cooldown), /topic_cooldown_violation/);
  const novelty = createMarketingBoundaryFixture();
  novelty.history[0].noveltyKey = novelty.weeklyPlan.entries[0].noveltyKey;
  assert.throws(() => buildWeeklyMarketingPlan(novelty), /novelty_violation/);
  const arbitraryHost = createMarketingBoundaryFixture();
  arbitraryHost.research[0].sourceUrl = "https://example.org/claim";
  assert.throws(() => buildWeeklyMarketingPlan(arbitraryHost), /invalid_research/);
  const stale = createMarketingBoundaryFixture();
  stale.research[0].fetchedAt = "1900-01-01T00:00:00.000Z";
  assert.throws(() => buildWeeklyMarketingPlan(stale), /invalid_research/);
});

test("keeps source citation text isolated while binding exact provider receipts and spans", () => {
  const program = buildWeeklyMarketingPlan(createMarketingBoundaryFixture());
  assert.equal(Object.hasOwn(program.research[0], "exactCitation"), false);
  assert.equal(program.research[0].providerRef, "research-provider:ipeds");
  assert.equal(program.research[0].citationSpan.start, 0);
  const invalidSpan = createMarketingBoundaryFixture();
  invalidSpan.research[0].citationEnd = 9_999;
  assert.throws(() => buildWeeklyMarketingPlan(invalidSpan), /invalid_research/);
});

test("inspects daily voice and schedule safety but never admits caller-forged approval context", () => {
  const safe = createMarketingBoundaryFixture({ daily: true });
  const inspected = inspectDailyMarketingDraft(safe);
  assert.equal(inspected.copyDisposition, "untrusted_candidate");
  assert.equal(inspected.releaseDisposition, "impossible_without_independent_trusted_eval_receipts");
  assert.ok(
    Object.values(inspected.lexicalPrefilters)
      .filter((item) => typeof item === "boolean")
      .every(Boolean),
  );
  const dailyProgram = buildDailyMarketingDraft(safe);
  assert.equal(dailyProgram.kind, "daily_draft");
  assert.equal(dailyProgram.safety.executionDisposition, "hard_disabled");
  assert.equal(dailyProgram.artifact.releaseDisposition, "impossible_without_independent_trusted_eval_receipts");
  assert.throws(() => buildDailyMarketingDraft(safe, {}), /caller_approval_context_unsupported/);
  const wrongNotion = createMarketingBoundaryFixture({ daily: true });
  wrongNotion.draft.notionParentRef = "notion:other";
  assert.throws(() => inspectDailyMarketingDraft(wrongNotion), /invalid_draft/);
  const invisible = createMarketingBoundaryFixture({ daily: true });
  invisible.draft.text = "A ga\u200bme changer.";
  assert.throws(() => inspectDailyMarketingDraft(invisible), /invalid_plain_json/);
  const markup = createMarketingBoundaryFixture({ daily: true });
  markup.draft.text = "<b>A useful idea.</b>";
  assert.throws(() => inspectDailyMarketingDraft(markup), /invalid_draft|invalid_marketing_text/);
  const anecdote = createMarketingBoundaryFixture({ daily: true });
  anecdote.draft.text = "One customer told us this worked.";
  assert.throws(() => inspectDailyMarketingDraft(anecdote), /invalid_draft|invalid_marketing_text/);
});

test("requires an exact citation mapping for each substantive sentence and binds mapping identity", () => {
  const unmapped = createMarketingBoundaryFixture({ daily: true });
  unmapped.draft.claimCitations = [];
  assert.throws(() => inspectDailyMarketingDraft(unmapped), /missing_claim_citation/);
  const base = createMarketingBoundaryFixture({ daily: true });
  base.weeklyPlan.entries[0].citationRefs = ["citation:one", "citation:two"];
  base.draft.citationRefs = ["citation:one", "citation:two"];
  base.draft.planHash = sha256Canonical(base.weeklyPlan);
  const first = inspectDailyMarketingDraft(base);
  const remapped = clone(base);
  remapped.draft.claimCitations = [
    { sentence: "A cited point is included for review.", citationRefs: ["citation:two"] },
  ];
  const second = inspectDailyMarketingDraft(remapped);
  assert.notEqual(first.mappingHash, second.mappingHash);
});

test("rejects incorrect occurrence versions, non-forward moves, and DST gaps without asserting currentness", () => {
  const moved = createMarketingBoundaryFixture({ daily: true });
  moved.draft.schedule = { ...moved.draft.schedule, status: "moved", movedFromDate: "2026-08-30" };
  assert.equal(inspectDailyMarketingDraft(moved).planHash, moved.draft.planHash);
  const badVersion = createMarketingBoundaryFixture({ daily: true });
  badVersion.draft.schedule.occurrenceVersion = 2;
  assert.throws(() => inspectDailyMarketingDraft(badVersion), /invalid_schedule/);
  const noForwardMove = createMarketingBoundaryFixture({ daily: true });
  noForwardMove.draft.schedule = {
    ...noForwardMove.draft.schedule,
    status: "moved",
    movedFromDate: noForwardMove.goalDate,
  };
  assert.throws(() => inspectDailyMarketingDraft(noForwardMove), /invalid_schedule/);
  const missed = createMarketingBoundaryFixture({ daily: true });
  missed.draft.schedule = { ...missed.draft.schedule, status: "missed", missedReason: "operator_absent" };
  assert.throws(() => inspectDailyMarketingDraft(missed), /invalid_schedule/);
});

test("creates an exact unresolved two-origin LLM and deterministic evaluation quorum", () => {
  const program = buildWeeklyMarketingPlan(createMarketingBoundaryFixture());
  const initial = initializeMarketingState(program);
  const request = evaluationRequest(program);
  const requested = requestMarketingEvaluation(initial, request, program);
  assert.equal(requested.evaluationRequests[0].resolution, "unresolved");
  assert.equal(requested.evaluationRequests[0].runs.length, 8);
  assert.deepEqual(
    new Set(requested.evaluationRequests[0].runs.map((run) => run.originClass)),
    new Set(["deterministic", "independent_llm"]),
  );
  assert.equal(Object.keys(prospectiveEvaluatorRegistry).length, 2);
  assert.equal(requestMarketingEvaluation(requested, request, program).recordHash, requested.recordHash);
  const tampered = clone(requested);
  tampered.evaluationRequests[0].runs[0].runRef = "evaluation-run:forged";
  tampered.recordHash = sha256Canonical(
    Object.fromEntries(Object.entries(tampered).filter(([key]) => key !== "recordHash")),
  );
  assert.throws(() => requestMarketingEvaluation(tampered, request, program), /invalid_state/);
  const chronological = requestMarketingPlanApproval(requested, approvalRequest(program, 1), program);
  assert.equal(chronological.revision, 2);
  assert.equal(
    requestMarketingPlanApproval(chronological, approvalRequest(program, 1), program).recordHash,
    chronological.recordHash,
  );
  const forgedRevision = clone(requested);
  forgedRevision.evaluationRequests[0].expectedRevision = 999;
  forgedRevision.recordHash = sha256Canonical(
    Object.fromEntries(Object.entries(forgedRevision).filter(([key]) => key !== "recordHash")),
  );
  assert.throws(
    () => requestMarketingPlanApproval(forgedRevision, approvalRequest(program, 1), program),
    /invalid_state/,
  );
});

test("requires all program bindings for evaluation and approval transitions", () => {
  const program = buildWeeklyMarketingPlan(createMarketingBoundaryFixture());
  const initial = initializeMarketingState(program);
  assert.throws(
    () => requestMarketingEvaluation(initial, { ...evaluationRequest(program), researchHash: "0".repeat(64) }, program),
    /evaluation_binding_mismatch/,
  );
  assert.throws(
    () => requestMarketingPlanApproval(initial, { ...approvalRequest(program), artifactHash: "0".repeat(64) }, program),
    /approval_binding_mismatch/,
  );
  const forged = clone(program);
  forged.artifact.programHash = "0".repeat(64);
  assert.throws(() => initializeMarketingState(forged), /untrusted_program/);
});

test("replays an identical Slack approval without a new state and conflicts changed payload ids", () => {
  const program = buildWeeklyMarketingPlan(createMarketingBoundaryFixture());
  const request = approvalRequest(program);
  const requested = requestMarketingPlanApproval(initializeMarketingState(program), request, program);
  assert.equal(requestMarketingPlanApproval(requested, request, program).recordHash, requested.recordHash);
  assert.throws(
    () => requestMarketingPlanApproval(requested, { ...request, payloadHash: "a".repeat(64) }, program),
    /event_reuse_mismatch/,
  );
  const forged = { receiptHash: sha256Canonical({ decision: "approved" }), decision: "approved" };
  assert.throws(() => recordMarketingPlanApproval(requested, forged), /untrusted_approval_receipt/);
  assert.throws(() => recordMarketingEvaluation(requested, forged), /untrusted_evaluation_receipt/);
});

test("rejects a second new request before it can construct an invalid state", () => {
  const program = buildWeeklyMarketingPlan(createMarketingBoundaryFixture());
  const evaluated = requestMarketingEvaluation(initializeMarketingState(program), evaluationRequest(program), program);
  assert.throws(
    () =>
      requestMarketingEvaluation(
        evaluated,
        { ...evaluationRequest(program, 1), requestRef: "evaluation-request:two" },
        program,
      ),
    /duplicate_evaluation_request/,
  );
  const approved = requestMarketingPlanApproval(initializeMarketingState(program), approvalRequest(program), program);
  assert.throws(
    () =>
      requestMarketingPlanApproval(
        approved,
        { ...approvalRequest(program, 1), requestRef: "approval-request:two" },
        program,
      ),
    /duplicate_approval_request/,
  );
  const crossEvaluation = requestMarketingEvaluation(
    initializeMarketingState(program),
    evaluationRequest(program),
    program,
  );
  assert.throws(
    () =>
      requestMarketingPlanApproval(
        crossEvaluation,
        { ...approvalRequest(program, 1), requestRef: "evaluation-request:one" },
        program,
      ),
    /event_reuse_mismatch/,
  );
  const crossApproval = requestMarketingPlanApproval(
    initializeMarketingState(program),
    approvalRequest(program),
    program,
  );
  assert.throws(
    () =>
      requestMarketingEvaluation(
        crossApproval,
        { ...evaluationRequest(program, 1), requestRef: "approval-request:one" },
        program,
      ),
    /event_reuse_mismatch/,
  );
});

test("normalizes confusables and rejects broad claims, pressure, Unicode numerals, and unsafe outlines", () => {
  const greek = createMarketingBoundaryFixture({ daily: true });
  greek.draft.text = "A gαme chаnger is here.";
  assert.throws(() => inspectDailyMarketingDraft(greek), /invalid_draft|invalid_marketing_text/);
  const arabicDigit = createMarketingBoundaryFixture({ daily: true });
  arabicDigit.draft.text = "This creates ٢ new paths.";
  assert.throws(() => inspectDailyMarketingDraft(arabicDigit), /invalid_draft|invalid_marketing_text/);
  const fullwidthDigit = createMarketingBoundaryFixture({ daily: true });
  fullwidthDigit.draft.text = "This creates ２ new paths。";
  assert.throws(() => inspectDailyMarketingDraft(fullwidthDigit), /invalid_draft|invalid_marketing_text/);
  const spelled = createMarketingBoundaryFixture({ daily: true });
  spelled.draft.text = "Several questions can help.";
  assert.throws(() => inspectDailyMarketingDraft(spelled), /missing_claim_citation/);
  const cited = createMarketingBoundaryFixture({ daily: true });
  cited.draft.text = "Several questions can help.";
  cited.draft.claimCitations = [{ sentence: "Several questions can help.", citationRefs: ["citation:one"] }];
  assert.ok(inspectDailyMarketingDraft(cited).contentHash);
  const pressure = createMarketingBoundaryFixture({ daily: true });
  pressure.draft.text = "Reply now to hear more.";
  assert.throws(() => inspectDailyMarketingDraft(pressure), /invalid_draft|invalid_marketing_text/);
  const absolute = createMarketingBoundaryFixture({ daily: true });
  absolute.draft.text = "This always works.";
  assert.throws(() => inspectDailyMarketingDraft(absolute), /invalid_draft|invalid_marketing_text/);
  const outline = createMarketingBoundaryFixture();
  outline.weeklyPlan.entries[0].outline = "A gаme chаnger for every team.";
  assert.throws(() => buildWeeklyMarketingPlan(outline), /invalid_plan_entry|invalid_marketing_text/);
  const sentenceBoundaries = createMarketingBoundaryFixture({ daily: true });
  sentenceBoundaries.draft.text = "A short thought。Another short thought。A third thought。";
  assert.throws(() => inspectDailyMarketingDraft(sentenceBoundaries), /invalid_draft|invalid_marketing_text/);
  const slack = createMarketingBoundaryFixture({ daily: true });
  slack.draft.text = "@channel a careful thought.";
  assert.throws(() => inspectDailyMarketingDraft(slack), /invalid_draft|invalid_marketing_text/);
  assert.throws(() => snapshotPlainJson({ c1: "a\u0085b" }), /invalid_plain_json/);
});

test("lexical prefilters reject reviewer phrase probes without claiming semantic coverage", () => {
  for (const phrase of [
    "in today's fast-paced world",
    "best in class",
    "world class",
    "cutting edge",
    "hurry",
    "last chance",
    "act today",
    "share with your team",
    "colleague said",
    "founder said",
    "story",
    "in my experience",
  ]) {
    const candidate = createMarketingBoundaryFixture({ daily: true });
    candidate.draft.text = `${phrase}.`;
    candidate.draft.claimCitations = [{ sentence: `${phrase}.`, citationRefs: ["citation:one"] }];
    assert.throws(() => inspectDailyMarketingDraft(candidate), /invalid_draft|invalid_marketing_text/);
  }
});

test("rejects recursively malformed durable state after a valid self-hash", () => {
  const program = buildWeeklyMarketingPlan(createMarketingBoundaryFixture());
  const invalidEffects = clone(initializeMarketingState(program));
  invalidEffects.effects = { enabled: false, available: false, outcome: "outcome_unknown", hidden: true };
  invalidEffects.recordHash = sha256Canonical(
    Object.fromEntries(Object.entries(invalidEffects).filter(([key]) => key !== "recordHash")),
  );
  assert.throws(() => requestMarketingEvaluation(invalidEffects, evaluationRequest(program), program), /invalid_state/);
  const invalidReconciliation = clone(initializeMarketingState(program));
  invalidReconciliation.reconciliation.status = "confirmed";
  invalidReconciliation.recordHash = sha256Canonical(
    Object.fromEntries(Object.entries(invalidReconciliation).filter(([key]) => key !== "recordHash")),
  );
  assert.throws(
    () => requestMarketingEvaluation(invalidReconciliation, evaluationRequest(program), program),
    /invalid_state/,
  );
});

test("rejects descriptor attacks and raw state garbage while preserving actionless presentation totality", () => {
  const accessor = createMarketingBoundaryFixture();
  Object.defineProperty(accessor, "programRef", { enumerable: true, get: () => "program:trap" });
  assert.throws(() => buildWeeklyMarketingPlan(accessor), /invalid_plain_json/);
  assert.throws(() => buildWeeklyMarketingPlan(new Proxy(createMarketingBoundaryFixture(), {})), /invalid_plain_json/);
  assert.throws(() => initializeMarketingState({}), MarketingProgramError);
  assert.throws(() => snapshotPlainJson({ value: "a\u200Bb" }), /invalid_plain_json/);
  const presentation = presentMarketingProgram(buildWeeklyMarketingPlan(createMarketingBoundaryFixture()));
  assert.equal(presentation.executionDisposition, "hard_disabled");
  assert.equal(presentation.artifact.actionlessSlackArtifact, true);
});
