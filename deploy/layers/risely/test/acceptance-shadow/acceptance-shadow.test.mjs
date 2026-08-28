import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";
import {
  bindProviderFreeV6AcceptanceFacade,
  compileCalendarLifecycle,
  compileMeetingPrepShadow as compileMeetingPrepShadowWithEvaluation,
  compilePostMeetingShadow,
  priorJobsFromSchedule,
  ProviderFreeV6AcceptanceStore,
  prepareMeetingPrepShadowEvaluation,
  runMeetingPrepShadowAcceptance as runMeetingPrepShadowAcceptanceWithEvaluation,
} from "../../canary/acceptance-shadow/index.mjs";
import { PrincipalBinding } from "../../canary/shared-contracts/index.mjs";
import { deploymentConnectionAnchors } from "../../canary/revenue-program/index.mjs";
import { createProviderFreeEvaluationFixture } from "../evals/helpers/judge-results.mjs";

const digest = (character) => character.repeat(64);
const acceptanceRoot = new URL("../../canary/acceptance-shadow/", import.meta.url);
const execFileAsync = promisify(execFile);

function meeting(changes = {}) {
  return {
    providerEventId: "calendar-event:acceptance-1",
    startAt: "2026-08-27T17:00:00.000Z",
    endAt: "2026-08-27T17:30:00.000Z",
    status: "confirmed",
    allDay: false,
    visibility: "default",
    title: "Sanitized customer meeting",
    evidenceHash: digest("1"),
    attendees: [
      { attendeeRef: `attendee:${digest("2")}`, email: "ceo@example.invalid", role: "ceo", response: "accepted" },
      {
        attendeeRef: `attendee:${digest("3")}`,
        email: "buyer@example.invalid",
        role: "external",
        response: "accepted",
      },
    ],
    ...changes,
  };
}

function lifecycleInput(changes = {}) {
  return {
    now: "2026-08-26T16:00:00.000Z",
    pollWindowEnd: "2026-08-30T16:00:00.000Z",
    calendarAvailability: "available",
    meeting: meeting(),
    priorJobs: [],
    ...changes,
  };
}

function meetingPrepInput(changes = {}) {
  return {
    now: "2026-08-26T16:00:00.000Z",
    pollWindowEnd: "2026-08-30T16:00:00.000Z",
    meeting: meeting(),
    sourceAvailability: {
      calendar: "available",
      gmail: "available",
      clarify: "unavailable",
      command_center_brain: "available",
      notion: "not_connected",
    },
    generatedAt: "2026-08-26T16:05:00.000Z",
    evaluatedAt: "2026-08-26T16:06:00.000Z",
    expiresAt: "2026-08-26T18:06:00.000Z",
    queuedAt: "2026-08-26T16:07:00.000Z",
    ...changes,
  };
}

function meetingPrepEvaluation(input) {
  const fixture = createProviderFreeEvaluationFixture(input.evaluatedAt);
  const candidate = prepareMeetingPrepShadowEvaluation(input, fixture.authority);
  return { fixture, candidate, judgeResults: fixture.issueQuorum(candidate) };
}

function compileMeetingPrepShadow(input) {
  const evaluation = meetingPrepEvaluation(input);
  return compileMeetingPrepShadowWithEvaluation(input, evaluation.fixture.authority, evaluation.judgeResults);
}

function runMeetingPrepShadowAcceptance(input, providerEffects) {
  const evaluation = meetingPrepEvaluation(input);
  return runMeetingPrepShadowAcceptanceWithEvaluation(
    input,
    evaluation.fixture.authority,
    evaluation.judgeResults,
    providerEffects,
  );
}

function finalTranscript(changes = {}) {
  return {
    revision: "final",
    transcriptRef: "transcript:acceptance-1",
    providerTranscriptId: "provider-transcript:acceptance-1",
    providerAccountRef: "provider-account:clarify-ceo",
    revisionHash: digest("4"),
    recordedStartAt: "2026-08-27T17:00:00.000Z",
    recordedEndAt: "2026-08-27T17:28:00.000Z",
    finalizedAt: "2026-08-27T17:31:00.000Z",
    participants: [
      { email: "buyer@example.invalid", role: "speaker" },
      { email: "ceo@example.invalid", role: "speaker" },
    ],
    evidenceHash: digest("5"),
    text: "The buyer confirmed the next decision step and the CEO agreed to follow up.",
    ...changes,
  };
}

test("normal meeting prep composes T-24 T-90 and T-15 plans through all canonical actionless surfaces", async () => {
  const result = await runMeetingPrepShadowAcceptance(meetingPrepInput());
  const jobs = result.compiled.lifecycle.schedule.desiredJobs;
  assert.deepEqual(
    jobs.map((job) => job.kind),
    ["meeting.dossier.prepare", "meeting.briefing.refresh", "meeting.briefing.deliver"],
  );
  assert.deepEqual(
    jobs.map((job) => job.intendedAt),
    ["2026-08-26T17:00:00.000Z", "2026-08-27T15:30:00.000Z", "2026-08-27T16:45:00.000Z"],
  );
  assert.equal(jobs[1].dependency.jobId, jobs[0].jobId);
  assert.equal(jobs[2].dependency.jobId, jobs[1].jobId);
  assert.equal(result.persistedSurfaceCount, 3);
  assert.ok(result.durableRecords.every((entry) => entry.disposition === "inserted"));
  assert.deepEqual(Object.keys(result.compiled.publicationSet).sort(), ["notion", "qm", "slack"]);
  assert.equal(result.compiled.surfaces.actionless, true);
  assert.equal(
    result.compiled.surfaces.slack.blocks.some((block) => block.type === "actions"),
    false,
  );
  assert.equal(result.compiled.surfaces.qm.actionless, true);
  assert.equal(result.compiled.surfaces.notion.actionless, true);
});

test("run snapshots authority time and never rereads caller input after its first await", async () => {
  const input = meetingPrepInput();
  const expectedQueuedAt = input.queuedAt;
  const pending = runMeetingPrepShadowAcceptance(input);
  input.queuedAt = "2099-01-01T00:00:00.000Z";
  input.meeting.title = "mutated after call";
  input.sourceAvailability.gmail = "unavailable";
  const result = await pending;
  assert.equal(result.compiled.publicationSet.slack.outboxEvent.queuedAt, expectedQueuedAt);
  assert.equal(result.durableRecords[0].record.outboxEvent.queuedAt, expectedQueuedAt);
  assert.equal(result.compiled.lifecycle.meeting.title, "Sanitized customer meeting");
  assert.equal(result.compiled.dossier.missingContext.includes("gmail"), false);
});

test("canonical audience maps to fixed private Notion binding without Slack identity leakage", async () => {
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  assert.equal(compiled.publicationSet.notion.outboxEvent.audienceRef, PrincipalBinding.identity.audienceRef);
  assert.deepEqual(compiled.surfaces.notion.binding, {
    parentRef: "notion:ceo-private-root-v1",
    audienceRef: "audience:ceo-private",
    scope: "private_ceo",
    providerInvocationAllowed: false,
  });
  assert.notEqual(compiled.surfaces.notion.binding.audienceRef, PrincipalBinding.identity.audienceRef);
  assert.doesNotMatch(JSON.stringify(compiled.surfaces.notion), /slack-audience|slack-team|slack-user/);
});

test("acceptance implementation imports only public deployment barrels and no dynamic runtime", async () => {
  for (const file of ["index.mjs", "provider-free-v6.mjs"]) {
    const source = await readFile(new URL(file, acceptanceRoot), "utf8");
    assert.doesNotMatch(source, /\/src\/|\/service\/|import\s*\(|process\.env|fetch\s*\(|node:https|node:http/);
    assert.doesNotMatch(source, /EvalRelease\.create/u);
    for (const match of source.matchAll(/from\s+"([^"]+)"/gu)) {
      const specifier = match[1];
      if (specifier.startsWith("node:")) continue;
      if (specifier.startsWith("./")) continue;
      assert.match(specifier, /\/index\.mjs$/u);
    }
  }
});

test("fresh-process import performs zero environment network or database access", async () => {
  const moduleUrl = new URL("index.mjs", acceptanceRoot).href;
  const script = `
    import Module from "node:module";
    import http from "node:http";
    import https from "node:https";
    import net from "node:net";
    import tls from "node:tls";
    let environmentReads = 0;
    let networkCalls = 0;
    let databaseLoads = 0;
    process.env = new Proxy(process.env, {
      get(target, property, receiver) {
        const stack = new Error().stack ?? "";
        if (/\\/risely-agent-runtime\\/.*\\.mjs:\\d+:\\d+/u.test(stack)) {
          environmentReads += 1;
          throw new Error("environment_access_at_import");
        }
        return Reflect.get(target, property, receiver);
      },
    });
    const networkSentinel = () => {
      networkCalls += 1;
      throw new Error("network_access_at_import");
    };
    net.connect = networkSentinel;
    tls.connect = networkSentinel;
    http.request = networkSentinel;
    https.request = networkSentinel;
    globalThis.fetch = networkSentinel;
    const load = Module._load;
    Module._load = function(request, parent, isMain) {
      if (request === "pg" || request === "pg-native") {
        databaseLoads += 1;
        throw new Error("database_access_at_import");
      }
      return Reflect.apply(load, this, [request, parent, isMain]);
    };
    await import(${JSON.stringify(moduleUrl)});
    process.stdout.write(JSON.stringify({ environmentReads, networkCalls, databaseLoads }));
  `;
  const { stdout } = await execFileAsync(process.execPath, ["--input-type=module", "-e", script]);
  assert.deepEqual(JSON.parse(stdout), { environmentReads: 0, networkCalls: 0, databaseLoads: 0 });
});

test("canonical PrincipalBinding survives lane event envelope and behavioral store without aliases", async () => {
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  const item = compiled.publicationSet.slack;
  const store = new ProviderFreeV6AcceptanceStore();
  const facade = bindProviderFreeV6AcceptanceFacade(store);
  await facade.initialize();
  const inserted = await facade.enqueuePublication(
    { outboxEvent: item.outboxEvent, publicationEnvelope: item.publicationEnvelope },
    meetingPrepInput().queuedAt,
  );
  for (const value of [compiled.artifact, item.outboxEvent, item.publicationEnvelope]) {
    assert.equal(value.principalBindingSha256, PrincipalBinding.value.bindingSha256);
  }
  assert.equal(inserted.record.outboxEvent.principalBindingSha256, PrincipalBinding.value.bindingSha256);
  const eventProjection = {
    ...item.outboxEvent,
    principalBindingSha256: digest("f"),
  };
  delete eventProjection.eventSha256;
  const forgedEvent = { ...eventProjection, eventSha256: PrincipalBinding.hash(eventProjection) };
  await assert.rejects(
    () =>
      facade.enqueuePublication(
        { outboxEvent: forgedEvent, publicationEnvelope: item.publicationEnvelope },
        meetingPrepInput().queuedAt,
      ),
    /bindings do not match|principal binding/,
  );
  const payload = { ...item.publicationEnvelope.payload, audienceRef: "slack-audience:attacker" };
  const envelopeProjection = {
    ...item.publicationEnvelope,
    audienceRef: "slack-audience:attacker",
    payload,
    payloadSha256: PrincipalBinding.hash(payload),
  };
  delete envelopeProjection.envelopeSha256;
  const forgedEnvelope = { ...envelopeProjection, envelopeSha256: PrincipalBinding.hash(envelopeProjection) };
  await assert.rejects(
    () =>
      facade.enqueuePublication(
        { outboxEvent: item.outboxEvent, publicationEnvelope: forgedEnvelope },
        meetingPrepInput().queuedAt,
      ),
    /does not match|not supported/,
  );
});

test("single and recurring Calendar identities stay stable at both public seams", async () => {
  const singleFirst = compileCalendarLifecycle(lifecycleInput());
  const singleSecond = compileCalendarLifecycle(lifecycleInput());
  assert.equal(singleFirst.acceptanceBinding.publicOccurrenceRef, singleSecond.acceptanceBinding.publicOccurrenceRef);
  assert.equal(
    singleFirst.acceptanceBinding.schedulerOccurrenceRef,
    singleSecond.acceptanceBinding.schedulerOccurrenceRef,
  );
  const recurring = {
    ...meeting(),
    providerEventId: "calendar-event:recurring-instance-a",
    seriesId: "calendar-series:acceptance",
    originalStartAt: "2026-08-27T17:00:00.000Z",
  };
  const recurringFirst = compileCalendarLifecycle(lifecycleInput({ meeting: recurring }));
  const recurringSecond = compileCalendarLifecycle(
    lifecycleInput({ meeting: { ...recurring, providerEventId: "calendar-event:recurring-instance-b" } }),
  );
  assert.equal(
    recurringFirst.acceptanceBinding.publicOccurrenceRef,
    recurringSecond.acceptanceBinding.publicOccurrenceRef,
  );
  assert.equal(
    recurringFirst.acceptanceBinding.schedulerOccurrenceRef,
    recurringSecond.acceptanceBinding.schedulerOccurrenceRef,
  );
  assert.notEqual(
    recurringFirst.acceptanceBinding.publicOccurrenceRef,
    recurringFirst.acceptanceBinding.schedulerOccurrenceRef,
  );
  assert.equal(
    recurringFirst.calendarProjection.bindingResolution.logicalGoogleAnchorRef,
    deploymentConnectionAnchors.googleAccountRef,
  );
  assert.notEqual(
    recurringFirst.calendarProjection.bindingResolution.logicalGoogleAnchorRef,
    recurringFirst.calendarProjection.bindingResolution.calendarAccountRef,
  );
  assert.equal(recurringFirst.receiptAuthenticated, false);
});

test("Calendar callers cannot substitute account logical anchor or occurrence identities", async () => {
  for (const injected of [
    { calendarAccountRef: "calendar-account:attacker" },
    { logicalGoogleAnchorRef: "google-account:attacker" },
    { occurrenceRef: "occurrence:attacker" },
  ]) {
    assert.throws(
      () => compileCalendarLifecycle(lifecycleInput({ meeting: { ...meeting(), ...injected } })),
      /unsupported shape/,
    );
  }
});

test("moved meeting cancels all prior revisions with fences and schedules three replacements", async () => {
  const first = compileCalendarLifecycle(lifecycleInput());
  const priorJobs = priorJobsFromSchedule(first.schedule);
  const moved = compileCalendarLifecycle(
    lifecycleInput({
      meeting: meeting({
        startAt: "2026-08-28T18:00:00.000Z",
        endAt: "2026-08-28T18:30:00.000Z",
        evidenceHash: digest("6"),
      }),
      priorJobs,
    }),
  );
  assert.equal(moved.schedule.desiredJobs.length, 3);
  assert.equal(moved.schedule.cancellations.length, 3);
  assert.ok(moved.schedule.cancellations.every((entry) => entry.reason === "schedule_moved_or_changed"));
  assert.ok(moved.schedule.cancellations.every((entry) => entry.fencedCasRequired === true));
  assert.notEqual(moved.schedule.desiredJobs[0].scheduleRevision, first.schedule.desiredJobs[0].scheduleRevision);
});

test("unchanged meeting revision creates no cancellation and retains exact job identities", async () => {
  const first = compileCalendarLifecycle(lifecycleInput());
  const repeated = compileCalendarLifecycle(lifecycleInput({ priorJobs: priorJobsFromSchedule(first.schedule) }));
  assert.equal(repeated.schedule.cancellations.length, 0);
  assert.deepEqual(
    repeated.schedule.desiredJobs.map((job) => job.jobId),
    first.schedule.desiredJobs.map((job) => job.jobId),
  );
  assert.deepEqual(
    repeated.schedule.desiredJobs.map((job) => job.scheduleRevision),
    first.schedule.desiredJobs.map((job) => job.scheduleRevision),
  );
});

test("duplicate and wrong-lineage prior jobs fail before lifecycle planning", async () => {
  const first = compileCalendarLifecycle(lifecycleInput());
  const prior = priorJobsFromSchedule(first.schedule);
  assert.throws(
    () => compileCalendarLifecycle(lifecycleInput({ priorJobs: [...prior, prior[0]] })),
    /duplicate_prior_job/,
  );
  const wrongLineage = prior.map((entry, index) =>
    index === 0 ? { ...entry, calendarAccountRef: "calendar-account:attacker" } : entry,
  );
  assert.throws(
    () => compileCalendarLifecycle(lifecycleInput({ priorJobs: wrongLineage })),
    /prior_job_lineage_mismatch/,
  );
});

test("prior-job conversion reads only WeakSet-branded scheduler plans", async () => {
  assert.throws(() => priorJobsFromSchedule(Object.freeze({ desiredJobs: [] })), /scheduler-issued plan/);
  let getterCalls = 0;
  const getterForgery = {};
  Object.defineProperty(getterForgery, "desiredJobs", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return [];
    },
  });
  Object.freeze(getterForgery);
  assert.throws(() => priorJobsFromSchedule(getterForgery), /scheduler-issued plan/);
  assert.equal(getterCalls, 0);
  let proxyTraps = 0;
  const nestedProxy = new Proxy(
    {},
    {
      get() {
        proxyTraps += 1;
        return undefined;
      },
      ownKeys() {
        proxyTraps += 1;
        return [];
      },
    },
  );
  const nestedForgery = Object.freeze({ desiredJobs: Object.freeze([nestedProxy]) });
  assert.throws(() => priorJobsFromSchedule(nestedForgery), /scheduler-issued plan/);
  assert.equal(proxyTraps, 0);
});

test("cancelled meeting creates provider-cancelled fences and no replacement jobs", async () => {
  const first = compileCalendarLifecycle(lifecycleInput());
  const cancelled = compileCalendarLifecycle(
    lifecycleInput({
      meeting: meeting({ status: "cancelled", evidenceHash: digest("7") }),
      priorJobs: priorJobsFromSchedule(first.schedule),
    }),
  );
  assert.equal(cancelled.schedule.desiredJobs.length, 0);
  assert.equal(cancelled.schedule.cancellations.length, 3);
  assert.ok(cancelled.schedule.cancellations.every((entry) => entry.reason === "provider_cancelled"));
  assert.equal(cancelled.schedule.suppressions[0].reason, "cancelled");
});

test("Calendar unavailability produces no work and never infers deletion", async () => {
  const lifecycle = compileCalendarLifecycle(lifecycleInput({ calendarAvailability: "unavailable", meeting: null }));
  assert.equal(lifecycle.state, "calendar_unavailable");
  assert.equal(lifecycle.schedule.desiredJobs.length, 0);
  assert.equal(lifecycle.schedule.cancellations.length, 0);
  assert.equal(lifecycle.schedule.deletionInferenceAllowed, false);
  assert.equal(lifecycle.providerEffectAllowed, false);
});

test("partial dossier inventory preserves missing source context and cited available evidence", async () => {
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  assert.deepEqual(compiled.dossier.missingContext, ["clarify", "notion"]);
  assert.equal(compiled.artifact.state, "ready");
  assert.equal(compiled.artifact.evidenceBundle.evidence.length, 3);
  assert.ok(compiled.artifact.evidenceBundle.evidence.every((entry) => entry.claimRefs.length > 0));
  assert.ok(compiled.artifact.evidenceBundle.evidence.every((entry) => entry.availability === "available"));
});

test("pending transcript remains waiting and cannot create a canonical artifact", async () => {
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  const postMeeting = compilePostMeetingShadow({
    meetingPrep: compiled,
    observedAt: "2026-08-27T17:32:00.000Z",
    generatedAt: "2026-08-27T17:33:00.000Z",
    transcript: { revision: "pending", transcriptRef: "transcript:acceptance-1" },
  });
  assert.equal(postMeeting.state, "waiting");
  assert.equal(postMeeting.blocker, "final_transcript_required");
  assert.equal(postMeeting.canonicalArtifactAvailable, false);
  assert.equal(postMeeting.providerInvocationAllowed, false);
});

test("post-meeting boundary rejects cloned acceptance output and never accepts caller recipient data", async () => {
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  const cloned = structuredClone(compiled);
  assert.throws(
    () =>
      compilePostMeetingShadow({
        meetingPrep: cloned,
        observedAt: "2026-08-27T17:32:00.000Z",
        generatedAt: "2026-08-27T17:33:00.000Z",
        transcript: { revision: "pending", transcriptRef: "transcript:acceptance-1" },
      }),
    /acceptance-issued meeting prep/,
  );
  assert.throws(
    () =>
      compilePostMeetingShadow({
        meetingPrep: compiled,
        observedAt: "2026-08-27T17:32:00.000Z",
        generatedAt: "2026-08-27T17:33:00.000Z",
        transcript: { ...finalTranscript(), recipient: "attacker@example.invalid" },
      }),
    /unsupported shape/,
  );
});

test("post-meeting outer boundary rejects symbols prototypes hidden fields and accessors without invocation", async () => {
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  const base = {
    meetingPrep: compiled,
    observedAt: "2026-08-27T17:32:00.000Z",
    generatedAt: "2026-08-27T17:33:00.000Z",
    transcript: { revision: "pending", transcriptRef: "transcript:acceptance-1" },
  };
  const symbolInput = { ...base, [Symbol("hidden")]: "secret" };
  assert.throws(() => compilePostMeetingShadow(symbolInput), /plain data/);
  assert.throws(() => compilePostMeetingShadow(Object.assign(Object.create(null), base)), /plain data/);
  assert.throws(() => compilePostMeetingShadow(Object.assign(Object.create({ inherited: true }), base)), /plain data/);
  assert.throws(() => compilePostMeetingShadow(new Date()), /plain data/);
  const hidden = { ...base };
  Object.defineProperty(hidden, "hidden", { value: "secret", enumerable: false });
  assert.throws(() => compilePostMeetingShadow(hidden), /unsupported shape/);
  let getterCalls = 0;
  const accessor = { ...base };
  Object.defineProperty(accessor, "transcript", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return base.transcript;
    },
  });
  assert.throws(() => compilePostMeetingShadow(accessor), /unsupported shape/);
  assert.equal(getterCalls, 0);
});

test("final transcript reaches verification-required analysis with exact provider anchor", async () => {
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  const postMeeting = compilePostMeetingShadow({
    meetingPrep: compiled,
    observedAt: "2026-08-27T17:32:00.000Z",
    generatedAt: "2026-08-27T17:33:00.000Z",
    transcript: finalTranscript(),
  });
  assert.equal(postMeeting.state, "verification_required");
  assert.equal(postMeeting.correlation.strength, "unique_time_and_participant");
  assert.equal(postMeeting.correlation.transcriptProviderAccountRef, "provider-account:clarify-ceo");
  assert.equal(postMeeting.analysisInput.transcript.providerAccountRef, "provider-account:clarify-ceo");
  assert.equal(postMeeting.analysisInput.sourceVerification.status, "required");
  assert.equal(postMeeting.analysisInput.actionAllowed, false);
  assert.equal(postMeeting.canonicalArtifactAvailable, false);
  assert.equal(Object.hasOwn(postMeeting, "recipients"), false);
  assert.equal(Object.hasOwn(postMeeting.analysisInput, "recipients"), false);
  assert.match(postMeeting.blocker, /trusted_source_verification_broker/);
});

test("caller transcript occurrence identity is never fabricated or accepted", async () => {
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  const base = {
    meetingPrep: compiled,
    observedAt: "2026-08-27T17:32:00.000Z",
    generatedAt: "2026-08-27T17:33:00.000Z",
  };
  const absent = compilePostMeetingShadow({ ...base, transcript: finalTranscript() });
  assert.equal(absent.correlation.strength, "unique_time_and_participant");
  assert.equal(Object.hasOwn(absent.analysisInput.transcript, "calendarEventId"), false);
  assert.equal(Object.hasOwn(absent.analysisInput.transcript, "occurrenceRef"), false);
  for (const transcript of [
    { ...finalTranscript(), calendarEventId: "calendar-event:attacker" },
    { ...finalTranscript(), occurrenceRef: "event:calendar-event:attacker" },
    {
      ...finalTranscript(),
      calendarEventId: "calendar-event:attacker",
      occurrenceRef: "event:calendar-event:attacker",
    },
  ]) {
    assert.throws(() => compilePostMeetingShadow({ ...base, transcript }), /unsupported shape/);
  }
});

test("transcript cannot heuristically bind across a non-overlapping occurrence", async () => {
  const later = await compileMeetingPrepShadow(
    meetingPrepInput({
      meeting: meeting({
        providerEventId: "calendar-event:acceptance-later",
        startAt: "2026-08-28T17:00:00.000Z",
        endAt: "2026-08-28T17:30:00.000Z",
        evidenceHash: digest("9"),
      }),
    }),
  );
  const result = compilePostMeetingShadow({
    meetingPrep: later,
    observedAt: "2026-08-28T17:32:00.000Z",
    generatedAt: "2026-08-28T17:33:00.000Z",
    transcript: finalTranscript(),
  });
  assert.equal(result.state, "unmatched");
  assert.equal(result.canonicalArtifactAvailable, false);
  assert.equal(result.providerInvocationAllowed, false);
});

test("transcript evidence and provider anchors are bound into distinct verification requests", async () => {
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  const base = {
    meetingPrep: compiled,
    observedAt: "2026-08-27T17:32:00.000Z",
    generatedAt: "2026-08-27T17:33:00.000Z",
  };
  const first = compilePostMeetingShadow({ ...base, transcript: finalTranscript() });
  const changedEvidence = compilePostMeetingShadow({
    ...base,
    transcript: finalTranscript({ evidenceHash: digest("8") }),
  });
  const changedProvider = compilePostMeetingShadow({
    ...base,
    transcript: finalTranscript({ providerAccountRef: "provider-account:clarify-other" }),
  });
  assert.notEqual(first.correlation.verificationRequestHash, changedEvidence.correlation.verificationRequestHash);
  assert.notEqual(first.correlation.verificationRequestHash, changedProvider.correlation.verificationRequestHash);
  assert.equal(changedProvider.correlation.transcriptProviderAccountRef, "provider-account:clarify-other");
  assert.equal(changedProvider.state, "verification_required");
  assert.equal(changedProvider.providerInvocationAllowed, false);
});

test("transcript from a mismatched participant cannot cross the correlation boundary", async () => {
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  const postMeeting = compilePostMeetingShadow({
    meetingPrep: compiled,
    observedAt: "2026-08-27T17:32:00.000Z",
    generatedAt: "2026-08-27T17:33:00.000Z",
    transcript: finalTranscript({ participants: [{ email: "stranger@example.invalid", role: "speaker" }] }),
  });
  assert.equal(postMeeting.state, "unmatched");
  assert.equal(postMeeting.canonicalArtifactAvailable, false);
  assert.equal(postMeeting.providerInvocationAllowed, false);
});

test("provider-free v6 facade is idempotent for exact replay and rejects same identity changed release", async () => {
  const first = await compileMeetingPrepShadow(meetingPrepInput());
  const changed = await compileMeetingPrepShadow(
    meetingPrepInput({
      evaluatedAt: "2026-08-26T16:06:30.000Z",
      expiresAt: "2026-08-26T18:06:30.000Z",
      queuedAt: "2026-08-26T16:07:30.000Z",
    }),
  );
  const store = new ProviderFreeV6AcceptanceStore();
  const facade = bindProviderFreeV6AcceptanceFacade(store);
  await facade.initialize();
  const firstItem = first.publicationSet.slack;
  const changedItem = changed.publicationSet.slack;
  const inserted = await facade.enqueuePublication(
    { outboxEvent: firstItem.outboxEvent, publicationEnvelope: firstItem.publicationEnvelope },
    "2026-08-26T16:07:00.000Z",
  );
  const replayed = await facade.enqueuePublication(
    { outboxEvent: firstItem.outboxEvent, publicationEnvelope: firstItem.publicationEnvelope },
    "2026-08-26T16:08:00.000Z",
  );
  assert.equal(inserted.disposition, "inserted");
  assert.equal(replayed.disposition, "replayed");
  assert.equal(inserted.record, replayed.record);
  assert.equal(firstItem.outboxEvent.eventId, changedItem.outboxEvent.eventId);
  await assert.rejects(
    () =>
      facade.enqueuePublication(
        { outboxEvent: changedItem.outboxEvent, publicationEnvelope: changedItem.publicationEnvelope },
        "2026-08-26T16:08:00.000Z",
      ),
    /outbox_conflict/,
  );
});

test("provider-free store binding rejects method shadows accessors and proxy prototypes without invocation", async () => {
  let calls = 0;
  const override = new ProviderFreeV6AcceptanceStore();
  override.enqueueValidated = () => {
    calls += 1;
    throw new Error("override_invoked");
  };
  assert.throws(() => bindProviderFreeV6AcceptanceFacade(override), /fixed acceptance store/);
  const accessor = new ProviderFreeV6AcceptanceStore();
  Object.defineProperty(accessor, "initialize", {
    configurable: true,
    get() {
      calls += 1;
      return async () => true;
    },
  });
  assert.throws(() => bindProviderFreeV6AcceptanceFacade(accessor), /fixed acceptance store/);
  const exactPrototypeForgery = Object.create(ProviderFreeV6AcceptanceStore.prototype);
  assert.throws(() => bindProviderFreeV6AcceptanceFacade(exactPrototypeForgery), /fixed acceptance store/);
  let proxyTraps = 0;
  const prototypeProxy = new Proxy(ProviderFreeV6AcceptanceStore.prototype, {
    get() {
      proxyTraps += 1;
      return undefined;
    },
    getPrototypeOf() {
      proxyTraps += 1;
      return Object.prototype;
    },
    ownKeys() {
      proxyTraps += 1;
      return [];
    },
  });
  const forged = Object.create(prototypeProxy);
  assert.throws(() => bindProviderFreeV6AcceptanceFacade(forged), /fixed acceptance store/);
  assert.equal(calls, 0);
  assert.equal(proxyTraps, 0);
});

test("version-six expiry tombstone is immutable and rejects replay or changed content", async () => {
  const first = await compileMeetingPrepShadow(meetingPrepInput());
  const changed = await compileMeetingPrepShadow(
    meetingPrepInput({
      evaluatedAt: "2026-08-26T16:06:30.000Z",
      expiresAt: "2026-08-26T18:06:30.000Z",
      queuedAt: "2026-08-26T16:07:30.000Z",
    }),
  );
  const store = new ProviderFreeV6AcceptanceStore();
  const facade = bindProviderFreeV6AcceptanceFacade(store);
  await facade.initialize();
  const firstItem = first.publicationSet.qm;
  await facade.enqueuePublication(
    { outboxEvent: firstItem.outboxEvent, publicationEnvelope: firstItem.publicationEnvelope },
    "2026-08-26T16:07:00.000Z",
  );
  const tombstone = await facade.expirePublication(firstItem.outboxEvent.eventId, "2026-08-26T18:06:00.000Z");
  assert.equal(tombstone.immutable, true);
  assert.equal(Object.isFrozen(tombstone), true);
  assert.equal((await facade.readTombstone(firstItem.outboxEvent.eventId)).tombstoneSha256, tombstone.tombstoneSha256);
  await assert.rejects(
    () =>
      facade.enqueuePublication(
        { outboxEvent: firstItem.outboxEvent, publicationEnvelope: firstItem.publicationEnvelope },
        "2026-08-26T18:07:00.000Z",
      ),
    /v6_event_identity_expired/,
  );
  const changedItem = changed.publicationSet.qm;
  await assert.rejects(
    () =>
      facade.enqueuePublication(
        { outboxEvent: changedItem.outboxEvent, publicationEnvelope: changedItem.publicationEnvelope },
        "2026-08-26T18:07:00.000Z",
      ),
    /v6_event_identity_tombstone_conflict/,
  );
  const retained = await facade.expirePublication(firstItem.outboxEvent.eventId, "2027-02-24T18:06:00.000Z");
  assert.equal(retained.tombstoneSha256, tombstone.tombstoneSha256);
});

test("expired alternate content cannot poison a stored event identity or mint a tombstone", async () => {
  const first = await compileMeetingPrepShadow(meetingPrepInput());
  const changed = await compileMeetingPrepShadow(
    meetingPrepInput({
      evaluatedAt: "2026-08-26T16:06:30.000Z",
      expiresAt: "2026-08-26T18:06:30.000Z",
      queuedAt: "2026-08-26T16:07:30.000Z",
    }),
  );
  const store = new ProviderFreeV6AcceptanceStore();
  const facade = bindProviderFreeV6AcceptanceFacade(store);
  await facade.initialize();
  const firstItem = first.publicationSet.slack;
  const changedItem = changed.publicationSet.slack;
  await facade.enqueuePublication(
    { outboxEvent: firstItem.outboxEvent, publicationEnvelope: firstItem.publicationEnvelope },
    firstItem.outboxEvent.queuedAt,
  );
  await assert.rejects(
    () =>
      facade.enqueuePublication(
        { outboxEvent: changedItem.outboxEvent, publicationEnvelope: changedItem.publicationEnvelope },
        "2026-08-26T18:07:00.000Z",
      ),
    /outbox_conflict/,
  );
  assert.equal(await facade.readTombstone(firstItem.outboxEvent.eventId), null);
  assert.equal(
    (await facade.readPublication(firstItem.outboxEvent.eventId)).eventSha256,
    firstItem.outboxEvent.eventSha256,
  );
  await assert.rejects(
    () =>
      facade.enqueuePublication(
        { outboxEvent: firstItem.outboxEvent, publicationEnvelope: firstItem.publicationEnvelope },
        "2026-08-26T18:07:00.000Z",
      ),
    /evaluation_release_expired/,
  );
  assert.equal(await facade.readPublication(firstItem.outboxEvent.eventId), null);
  const tombstone = await facade.readTombstone(firstItem.outboxEvent.eventId);
  assert.equal(tombstone.eventSha256, firstItem.outboxEvent.eventSha256);
  assert.equal(tombstone.envelopeSha256, firstItem.publicationEnvelope.envelopeSha256);
});

test("an unstored expired event is rejected without creating a tombstone", async () => {
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  const item = compiled.publicationSet.notion;
  const store = new ProviderFreeV6AcceptanceStore();
  const facade = bindProviderFreeV6AcceptanceFacade(store);
  await facade.initialize();
  await assert.rejects(
    () =>
      facade.enqueuePublication(
        { outboxEvent: item.outboxEvent, publicationEnvelope: item.publicationEnvelope },
        "2026-08-26T18:07:00.000Z",
      ),
    /evaluation_release_expired_unstored/,
  );
  assert.equal(await facade.readPublication(item.outboxEvent.eventId), null);
  assert.equal(await facade.readTombstone(item.outboxEvent.eventId), null);
});

test("PII secret-shaped titles attendee emails and provider narrative never reach surfaces", async () => {
  const title = "ceo@risely.ai +1 415 555 0134 xoxb-12345678901234567890 password=forbidden";
  const compiled = await compileMeetingPrepShadow(
    meetingPrepInput({
      meeting: meeting({
        title,
        attendees: [
          { attendeeRef: `attendee:${digest("2")}`, email: "real-ceo@risely.ai", role: "ceo", response: "accepted" },
          {
            attendeeRef: `attendee:${digest("3")}`,
            email: "person@customer.edu",
            role: "external",
            response: "accepted",
          },
        ],
      }),
    }),
  );
  const surfaces = JSON.stringify(compiled.surfaces);
  for (const probe of [
    title,
    "real-ceo@risely.ai",
    "person@customer.edu",
    "+1 415 555 0134",
    "xoxb-12345678901234567890",
    "password=forbidden",
  ]) {
    assert.doesNotMatch(surfaces, new RegExp(probe.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
  }
  assert.match(surfaces, /Private CEO work record/);
  assert.doesNotMatch(surfaces, /"actions"|action_id|providerInvocationAllowed":true/);
});

test("symbol and inherited inputs are rejected at the first acceptance boundary", async () => {
  const symbolInput = lifecycleInput();
  symbolInput[Symbol("hidden")] = "secret";
  assert.throws(() => compileCalendarLifecycle(symbolInput), /symbols/);
  const inherited = Object.assign(Object.create({ inherited: "secret" }), lifecycleInput());
  assert.throws(() => compileCalendarLifecycle(inherited), /plain data/);
  const nestedSymbol = meeting();
  nestedSymbol.attendees[0][Symbol("hidden")] = "secret";
  assert.throws(() => compileCalendarLifecycle(lifecycleInput({ meeting: nestedSymbol })), /symbols/);
});

test("throwing provider effect sentinels remain unreachable", async () => {
  let calls = 0;
  const sentinels = Object.freeze({
    gmailDraftsCreate() {
      calls += 1;
      throw new Error("gmail_effect_reached");
    },
    slackPost() {
      calls += 1;
      throw new Error("slack_effect_reached");
    },
    notionCreatePage() {
      calls += 1;
      throw new Error("notion_effect_reached");
    },
  });
  assert.equal(Object.keys(sentinels).length, 3);
  const providerEffects = Object.freeze({
    gmailDraftsCreate: sentinels.gmailDraftsCreate,
    googleCalendarRead() {
      calls += 1;
      throw new Error("google_effect_reached");
    },
    notionCreatePage: sentinels.notionCreatePage,
    slackPost: sentinels.slackPost,
  });
  const result = await runMeetingPrepShadowAcceptance(meetingPrepInput(), providerEffects);
  assert.equal(result.providerInvocationAllowed, false);
  assert.ok(result.durableRecords.every((entry) => entry.record.providerInvocationAllowed === false));
  assert.deepEqual(result.providerEffectStatus, {
    installedNames: ["gmailDraftsCreate", "googleCalendarRead", "notionCreatePage", "slackPost"],
    providerInvocationAllowed: false,
  });
  assert.equal(calls, 0);
});

test("accessor inputs are rejected without invocation at lifecycle and facade boundaries", async () => {
  let lifecycleGetterCalls = 0;
  const lifecycle = lifecycleInput();
  Object.defineProperty(lifecycle, "meeting", {
    enumerable: true,
    get() {
      lifecycleGetterCalls += 1;
      return meeting();
    },
  });
  assert.throws(() => compileCalendarLifecycle(lifecycle), /plain data field/);
  assert.equal(lifecycleGetterCalls, 0);
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  const item = compiled.publicationSet.slack;
  const store = new ProviderFreeV6AcceptanceStore();
  const facade = bindProviderFreeV6AcceptanceFacade(store);
  await facade.initialize();
  let envelopeGetterCalls = 0;
  const publication = { outboxEvent: item.outboxEvent };
  Object.defineProperty(publication, "publicationEnvelope", {
    enumerable: true,
    get() {
      envelopeGetterCalls += 1;
      return item.publicationEnvelope;
    },
  });
  await assert.rejects(() => facade.enqueuePublication(publication, meetingPrepInput().queuedAt), /plain data field/);
  assert.equal(envelopeGetterCalls, 0);
});

test("detectable proxies are rejected with zero trap execution", async () => {
  let traps = 0;
  const proxy = new Proxy(
    {},
    {
      ownKeys() {
        traps += 1;
        return [];
      },
      getPrototypeOf() {
        traps += 1;
        return Object.prototype;
      },
    },
  );
  assert.throws(() => compileCalendarLifecycle(proxy), /plain data/);
  assert.equal(traps, 0);
  assert.throws(() => bindProviderFreeV6AcceptanceFacade(proxy), /fixed acceptance store/);
  assert.equal(traps, 0);
  const compiled = await compileMeetingPrepShadow(meetingPrepInput());
  const item = compiled.publicationSet.slack;
  const store = new ProviderFreeV6AcceptanceStore();
  const facade = bindProviderFreeV6AcceptanceFacade(store);
  await facade.initialize();
  await assert.rejects(
    () =>
      facade.enqueuePublication(
        { outboxEvent: item.outboxEvent, publicationEnvelope: proxy },
        meetingPrepInput().queuedAt,
      ),
    /plain data/,
  );
  assert.equal(traps, 0);
});

test("acceptance lane remains deterministic and provider-free across repeated compilation", async () => {
  const input = meetingPrepInput();
  const evaluation = meetingPrepEvaluation(input);
  const first = await compileMeetingPrepShadowWithEvaluation(
    input,
    evaluation.fixture.authority,
    evaluation.judgeResults,
  );
  const second = await compileMeetingPrepShadowWithEvaluation(
    input,
    evaluation.fixture.authority,
    evaluation.judgeResults,
  );
  assert.equal(PrincipalBinding.hash(first), PrincipalBinding.hash(second));
  assert.equal(first.artifact.artifactSha256, second.artifact.artifactSha256);
  assert.equal(first.evalRelease.releaseSha256, second.evalRelease.releaseSha256);
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(first.publicationSet).map(([surface, item]) => [surface, item.publicationEnvelope.envelopeSha256]),
    ),
    Object.fromEntries(
      Object.entries(second.publicationSet).map(([surface, item]) => [
        surface,
        item.publicationEnvelope.envelopeSha256,
      ]),
    ),
  );
  assert.equal(first.lifecycle.receiptAuthenticated, false);
  assert.equal(first.lifecycle.calendarProjection.disposition, "prospective_unverified");
  assert.equal(first.providerInvocationAllowed, false);
});
