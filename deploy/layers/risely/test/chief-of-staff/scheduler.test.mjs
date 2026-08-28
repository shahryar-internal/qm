import assert from "node:assert/strict";
import test from "node:test";
import { sha256Canonical } from "../../canary/contracts/canonicalize.mjs";
import {
  bindDurableChiefOfStaffPort,
  buildOutboxRecord,
  buildSchedulerPollPlan,
  deriveDurableRequestId,
  planChiefOfStaffSchedule,
} from "../../canary/chief-of-staff/index.mjs";
import { calendarEvent, hash, instant, lineage, recurringCalendarEvent, scheduleInput } from "./fixtures.mjs";

const priorFrom = (plan, status = "scheduled") =>
  plan.desiredJobs.map((job) => ({
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
    claimFence: status === "leased" ? "fence_claim_000001" : null,
    fireAt: job.fireAt,
    status,
  }));

const durableAuthority = Object.freeze({
  organizationRef: lineage.organizationRef,
  deploymentRef: lineage.deploymentRef,
  principalRef: lineage.principalRef,
  credentialOwnerRef: lineage.credentialOwnerRef,
  connectionRef: lineage.connectionRef,
  calendarAccountRef: lineage.calendarAccountRef,
  audienceRef: lineage.audienceRef,
  destinationRef: lineage.destinationRef,
});

const durableRequest = (operation, payload, authority = durableAuthority) => ({
  schemaVersion: 1,
  operation,
  requestId: deriveDurableRequestId({ operation, authority, payload }),
  authority,
  payload,
});

test("automatic planning creates deterministic T-24, T-90, and T-15 jobs with full lineage", () => {
  const first = planChiefOfStaffSchedule(scheduleInput());
  const second = planChiefOfStaffSchedule(scheduleInput());
  assert.deepEqual(first, second);
  assert.deepEqual(
    first.desiredJobs.map((job) => job.kind),
    ["meeting.dossier.prepare", "meeting.briefing.refresh", "meeting.briefing.deliver"],
  );
  assert.deepEqual(
    first.desiredJobs.map((job) => job.intendedAt),
    ["2026-08-27T17:00:00.000Z", "2026-08-28T15:30:00.000Z", "2026-08-28T16:45:00.000Z"],
  );
  for (const job of first.desiredJobs) {
    assert.equal(job.deploymentRef, lineage.deploymentRef);
    assert.equal(job.principalRef, lineage.principalRef);
    assert.equal(job.credentialOwnerRef, lineage.credentialOwnerRef);
    assert.equal(job.connectionRef, lineage.connectionRef);
    assert.equal(job.calendarAccountRef, lineage.calendarAccountRef);
    assert.equal(job.audienceRef, lineage.audienceRef);
    assert.equal(job.destinationRef, lineage.destinationRef);
    assert.equal(job.planHash, first.planHash);
    assert.equal(job.jobRevision, 1);
    assert.equal(job.claimFence, null);
  }
  assert.equal(first.desiredJobs[0].dependency, null);
  assert.deepEqual(first.desiredJobs[1].dependency, {
    jobId: first.desiredJobs[0].jobId,
    scheduleRevision: first.desiredJobs[0].scheduleRevision,
    jobRevision: first.desiredJobs[0].jobRevision,
  });
});

test("each recurring occurrence has a distinct stable meeting lineage", () => {
  const later = recurringCalendarEvent({
    calendarEventId: "event_customer_recurring_02",
    occurrenceRef: "series:series_customer_weekly:2026-08-29T17:00:00.000Z",
    recurrenceOriginalStartAt: "2026-08-29T17:00:00.000Z",
    startAt: "2026-08-29T17:00:00.000Z",
    endAt: "2026-08-29T18:00:00.000Z",
  });
  const plan = planChiefOfStaffSchedule(scheduleInput({ events: [recurringCalendarEvent(), later] }));
  assert.equal(new Set(plan.desiredJobs.map((job) => job.meetingKey)).size, 2);
  assert.equal(plan.desiredJobs.length, 6);
});

test("a moved non-recurring meeting preserves occurrence identity and supersedes old jobs", () => {
  const original = planChiefOfStaffSchedule(scheduleInput());
  const moved = calendarEvent({
    startAt: "2026-08-28T19:00:00.000Z",
    endAt: "2026-08-28T20:00:00.000Z",
    evidenceHash: hash("d"),
  });
  const plan = planChiefOfStaffSchedule(scheduleInput({ events: [moved], priorJobs: priorFrom(original) }));
  assert.equal(plan.cancellations.length, 3);
  assert.ok(plan.cancellations.every((entry) => entry.reason === "schedule_moved_or_changed"));
  assert.equal(plan.cancellations[0].fencedCasRequired, true);
  assert.equal(
    plan.cancellations[0].scheduleRevision,
    priorFrom(original).find((job) => job.jobId === plan.cancellations[0].jobId).scheduleRevision,
  );
  assert.equal(plan.cancellations[0].expectedJobRevision, 1);
  assert.equal(plan.cancellations[0].expectedClaimFence, null);
  assert.equal(plan.cancellations[0].expectedPlanHash, original.planHash);
  assert.equal(plan.cancellations[0].meetingKey, original.desiredJobs[0].meetingKey);
  assert.equal(plan.desiredJobs[0].meetingKey, original.desiredJobs[0].meetingKey);
  assert.notEqual(plan.desiredJobs[0].scheduleRevision, original.desiredJobs[0].scheduleRevision);
  assert.equal(Object.hasOwn(moved, "originalStartAt"), false);
  assert.throws(
    () => planChiefOfStaffSchedule(scheduleInput({ events: [calendarEvent({ occurrenceRef: "event:forged" })] })),
    /unstable_calendar_occurrence_reference/,
  );
});

test("leased-job cancellation preserves the exact prior fence and revision for CAS", () => {
  const original = planChiefOfStaffSchedule(scheduleInput());
  const moved = calendarEvent({
    startAt: "2026-08-28T19:00:00.000Z",
    endAt: "2026-08-28T20:00:00.000Z",
    evidenceHash: hash("d"),
  });
  const plan = planChiefOfStaffSchedule(scheduleInput({ events: [moved], priorJobs: priorFrom(original, "leased") }));
  assert.ok(plan.cancellations.every((entry) => entry.expectedClaimFence === "fence_claim_000001"));
  assert.ok(plan.cancellations.every((entry) => entry.expectedJobRevision === 1));
  assert.ok(plan.cancellations.every((entry) => entry.expectedPlanHash === original.planHash));
});

test("cancel then recreate uses a new occurrence lineage while cancelling only the old one", () => {
  const original = planChiefOfStaffSchedule(scheduleInput());
  const cancelled = calendarEvent({ status: "cancelled" });
  const recreated = calendarEvent({
    calendarEventId: "event_customer_recreated_02",
    occurrenceRef: "event:event_customer_recreated_02",
    startAt: "2026-08-29T17:00:00.000Z",
    endAt: "2026-08-29T18:00:00.000Z",
    evidenceHash: hash("e"),
  });
  const plan = planChiefOfStaffSchedule(
    scheduleInput({ events: [cancelled, recreated], priorJobs: priorFrom(original) }),
  );
  assert.equal(plan.cancellations.length, 3);
  assert.ok(plan.cancellations.every((entry) => entry.reason === "provider_cancelled"));
  assert.equal(plan.desiredJobs.length, 3);
  assert.notEqual(plan.desiredJobs[0].meetingKey, original.desiredJobs[0].meetingKey);
});

test("a recurring occurrence moved across DST keeps its stable occurrence key", () => {
  const event = recurringCalendarEvent({
    calendarEventId: "event_dst_01",
    occurrenceRef: "series:series_customer_weekly:2026-11-01T08:30:00.000Z",
    recurrenceOriginalStartAt: "2026-11-01T08:30:00.000Z",
    startAt: "2026-11-01T08:30:00.000Z",
    endAt: "2026-11-01T09:30:00.000Z",
  });
  const baseInput = scheduleInput({
    now: "2026-10-29T07:00:00.000Z",
    pollWindowEnd: "2026-11-03T07:00:00.000Z",
    events: [event],
  });
  const original = planChiefOfStaffSchedule(baseInput);
  const moved = recurringCalendarEvent({
    calendarEventId: "event_dst_01",
    occurrenceRef: "series:series_customer_weekly:2026-11-01T08:30:00.000Z",
    recurrenceOriginalStartAt: "2026-11-01T08:30:00.000Z",
    startAt: "2026-11-01T09:30:00.000Z",
    endAt: "2026-11-01T10:30:00.000Z",
    evidenceHash: hash("f"),
  });
  const revised = planChiefOfStaffSchedule({ ...baseInput, events: [moved], priorJobs: priorFrom(original) });
  assert.equal(revised.desiredJobs[0].meetingKey, original.desiredJobs[0].meetingKey);
  assert.equal(revised.cancellations.length, 3);
});

test("an explicit cancellation cancels work but a missing snapshot event never implies deletion", () => {
  const original = planChiefOfStaffSchedule(scheduleInput());
  const priorJobs = priorFrom(original);
  const cancelled = planChiefOfStaffSchedule(
    scheduleInput({ events: [calendarEvent({ status: "cancelled" })], priorJobs }),
  );
  const missing = planChiefOfStaffSchedule(scheduleInput({ events: [], priorJobs }));
  assert.equal(cancelled.cancellations.length, 3);
  assert.ok(cancelled.cancellations.every((entry) => entry.reason === "provider_cancelled"));
  assert.equal(missing.cancellations.length, 0);
  assert.equal(missing.deletionInferenceAllowed, false);
});

test("private, declined, all-day, and external-free meetings are suppressed", () => {
  const variants = [
    calendarEvent({ visibility: "private" }),
    calendarEvent({
      calendarEventId: "event_2",
      occurrenceRef: "event:event_2",
      startAt: "2026-08-29T17:00:00.000Z",
      endAt: "2026-08-29T18:00:00.000Z",
      ceoResponse: "declined",
    }),
    calendarEvent({
      calendarEventId: "event_3",
      occurrenceRef: "event:event_3",
      startAt: "2026-08-30T17:00:00.000Z",
      endAt: "2026-08-30T18:00:00.000Z",
      allDay: true,
    }),
    calendarEvent({
      calendarEventId: "event_4",
      occurrenceRef: "event:event_4",
      startAt: "2026-08-31T16:00:00.000Z",
      endAt: "2026-08-31T17:00:00.000Z",
      attendees: [{ email: "shahryar@risely.ai", external: false, response: "accepted" }],
    }),
  ];
  const plan = planChiefOfStaffSchedule(scheduleInput({ events: variants }));
  assert.equal(plan.desiredJobs.length, 0);
  assert.deepEqual(
    plan.suppressions.map((entry) => entry.reason),
    ["private", "ceo_declined", "all_day", "no_participating_external_attendee"],
  );
});

test("calendar unavailable is fail-closed and cannot carry fabricated events", () => {
  const plan = planChiefOfStaffSchedule(scheduleInput({ calendarAvailability: "unavailable", events: [] }));
  assert.equal(plan.desiredJobs.length, 0);
  assert.throws(
    () => planChiefOfStaffSchedule(scheduleInput({ calendarAvailability: "unavailable" })),
    /invalid_calendar_availability/,
  );
});

test("late pre-start work is explicit and meetings already started are missed instead of clamped", () => {
  const late = planChiefOfStaffSchedule(
    scheduleInput({
      now: "2026-08-28T16:50:00.000Z",
      pollWindowEnd: "2026-08-29T16:50:00.000Z",
    }),
  );
  assert.ok(late.desiredJobs.every((job) => job.timing === "late_before_start"));
  assert.ok(late.desiredJobs.every((job) => job.fireAt === "2026-08-28T16:50:00.000Z"));
  const started = planChiefOfStaffSchedule(
    scheduleInput({
      now: "2026-08-28T17:01:00.000Z",
      pollWindowEnd: "2026-08-29T17:01:00.000Z",
    }),
  );
  assert.equal(started.desiredJobs.length, 0);
  assert.equal(started.suppressions[0].reason, "meeting_started");
});

test("prior work from another authority lineage is rejected", () => {
  const original = planChiefOfStaffSchedule(scheduleInput());
  const priorJobs = priorFrom(original);
  priorJobs[0].credentialOwnerRef = "usr_other_00000001";
  assert.throws(() => planChiefOfStaffSchedule(scheduleInput({ priorJobs })), /prior_job_lineage_mismatch/);
});

test("poll and outbox identities bind exact deployment, actor, owner, account, and connection", () => {
  const poll = buildSchedulerPollPlan({
    ...lineage,
    schedulerRef: "scheduler_ceo_01",
    runAt: instant.now,
    lookAheadDays: 7,
  });
  const outbox = buildOutboxRecord({
    ...lineage,
    jobId: hash("a"),
    meetingKey: hash("b"),
    planHash: hash("d"),
    jobRevision: 2,
    claimFence: "fence_claim_000001",
    destination: "slack_ceo_dm",
    artifactHash: hash("c"),
    artifactRef: "artifact_briefing_01",
    createdAt: instant.now,
  });
  assert.equal(poll.durableStateRequired, true);
  assert.equal(poll.inMemoryStateAllowed, false);
  const longerPoll = buildSchedulerPollPlan({
    ...lineage,
    schedulerRef: "scheduler_ceo_01",
    runAt: instant.now,
    lookAheadDays: 8,
  });
  assert.notEqual(longerPoll.pollId, poll.pollId);
  assert.equal(poll.lookAheadDays, 7);
  assert.deepEqual(poll.window, {
    from: instant.now,
    to: "2026-09-02T17:00:00.000Z",
  });
  assert.equal(outbox.providerEffectAllowed, false);
  assert.equal(outbox.requiresDurableClaim, true);
  assert.equal(outbox.credentialOwnerRef, lineage.credentialOwnerRef);
  assert.equal(outbox.planHash, hash("d"));
  assert.equal(outbox.jobRevision, 2);
  assert.equal(outbox.claimFence, "fence_claim_000001");
});

test("durable port rejects accessors and proxies and snapshots each method once", async () => {
  assert.throws(() => bindDurableChiefOfStaffPort({}), /invalid_durable_port/);
  const methodNames = [
    "reconcileScheduleTransaction",
    "claimDueJob",
    "completeJobAndAppendOutboxTransaction",
    "claimOutbox",
    "acknowledgeOutbox",
    "releaseExpiredClaims",
  ];
  const calls = [];
  const source = Object.fromEntries(
    methodNames.map((name) => [
      name,
      (request) => {
        calls.push(name);
        return {
          schemaVersion: 1,
          operation: name,
          requestId: request.requestId,
          status: "applied",
          stateRevision: 2,
          resultHash: hash("e"),
        };
      },
    ]),
  );
  const port = bindDurableChiefOfStaffPort(source);
  source.completeJobAndAppendOutboxTransaction = () => calls.push("mutated");
  const completionRequest = durableRequest("completeJobAndAppendOutboxTransaction", {
    jobId: hash("a"),
    scheduleRevision: hash("b"),
    expectedJobRevision: 2,
    claimFence: "fence_claim_000001",
    outboxHash: hash("c"),
    artifactHash: hash("d"),
  });
  const completionResult = await port.completeJobAndAppendOutboxTransaction(completionRequest);
  assert.deepEqual(calls, ["completeJobAndAppendOutboxTransaction"]);
  assert.equal(completionResult.status, "applied");
  const request = durableRequest("claimDueJob", {
    jobId: hash("a"),
    scheduleRevision: hash("b"),
    expectedJobRevision: 1,
    expectedClaimFence: null,
    claimFence: "fence_claim_000001",
    claimTtlSeconds: 60,
  });
  const result = await port.claimDueJob(request);
  assert.deepEqual(calls, ["completeJobAndAppendOutboxTransaction"]);
  assert.equal(result.status, "unresolved");
  assert.equal(result.serverClockReceiptRequired, true);
  const accessor = { ...source };
  Object.defineProperty(accessor, "claimDueJob", {
    enumerable: true,
    get() {
      throw new Error("must not execute");
    },
  });
  assert.throws(() => bindDurableChiefOfStaffPort(accessor), /invalid_durable_port/);
  assert.throws(() => bindDurableChiefOfStaffPort(new Proxy(source, {})), /invalid_durable_port/);
  const proxiedMethod = new Proxy(() => undefined, {});
  assert.throws(() => bindDurableChiefOfStaffPort({ ...source, claimDueJob: proxiedMethod }), /invalid_durable_port/);
  await assert.rejects(
    () => port.claimDueJob({ ...request, payload: { ...request.payload, accessToken: "secret" } }),
    /durable_secret_material_rejected/,
  );
  await assert.rejects(
    () => port.claimDueJob({ ...request, payload: { ...request.payload, unknown: true } }),
    /invalid_durable_payload/,
  );
  const badResultSource = Object.fromEntries(
    methodNames.map((name) => [
      name,
      (entry) => ({
        schemaVersion: 1,
        operation: name,
        requestId: entry.requestId,
        status: "applied",
        stateRevision: 2,
        resultHash: hash("e"),
        refreshToken: "forbidden",
      }),
    ]),
  );
  await assert.rejects(
    () => bindDurableChiefOfStaffPort(badResultSource).completeJobAndAppendOutboxTransaction(completionRequest),
    /durable_secret_material_rejected/,
  );
  const unknownResultSource = Object.fromEntries(
    methodNames.map((name) => [
      name,
      (entry) => ({
        schemaVersion: 1,
        operation: name,
        requestId: entry.requestId,
        status: "applied",
        stateRevision: 2,
        resultHash: hash("e"),
        unknown: true,
      }),
    ]),
  );
  await assert.rejects(
    () => bindDurableChiefOfStaffPort(unknownResultSource).completeJobAndAppendOutboxTransaction(completionRequest),
    /invalid_durable_result/,
  );
});

test("durable request identity changes with exact authority payload revision and fence", async () => {
  let calls = 0;
  const methods = [
    "reconcileScheduleTransaction",
    "claimDueJob",
    "completeJobAndAppendOutboxTransaction",
    "claimOutbox",
    "acknowledgeOutbox",
    "releaseExpiredClaims",
  ];
  const source = Object.fromEntries(
    methods.map((operation) => [
      operation,
      (request) => {
        calls += 1;
        return {
          schemaVersion: 1,
          operation,
          requestId: request.requestId,
          status: "applied",
          stateRevision: 3,
          resultHash: hash("e"),
        };
      },
    ]),
  );
  const port = bindDurableChiefOfStaffPort(source);
  const payload = {
    jobId: hash("a"),
    scheduleRevision: hash("b"),
    expectedJobRevision: 2,
    claimFence: "fence_job_000001",
    outboxHash: hash("c"),
    artifactHash: hash("d"),
  };
  const request = durableRequest("completeJobAndAppendOutboxTransaction", payload);
  const changedPayload = { ...payload, artifactHash: hash("f") };
  await assert.rejects(
    () =>
      port.completeJobAndAppendOutboxTransaction({
        ...request,
        payload: changedPayload,
      }),
    /durable_request_id_mismatch/,
  );
  await assert.rejects(
    () =>
      port.completeJobAndAppendOutboxTransaction({
        ...request,
        payload: { ...payload, expectedJobRevision: 3 },
      }),
    /durable_request_id_mismatch/,
  );
  await assert.rejects(
    () =>
      port.completeJobAndAppendOutboxTransaction({
        ...request,
        payload: { ...payload, claimFence: "fence_job_000002" },
      }),
    /durable_request_id_mismatch/,
  );
  const changedFence = { ...payload, claimFence: "fence_job_000002" };
  assert.notEqual(
    deriveDurableRequestId({
      operation: "completeJobAndAppendOutboxTransaction",
      authority: durableAuthority,
      payload: changedFence,
    }),
    request.requestId,
  );
  const changedAuthority = { ...durableAuthority, principalRef: "usr_other_00000001" };
  await assert.rejects(
    () => port.completeJobAndAppendOutboxTransaction({ ...request, authority: changedAuthority }),
    /durable_authority_mismatch/,
  );
  assert.throws(
    () =>
      deriveDurableRequestId({
        operation: "completeJobAndAppendOutboxTransaction",
        authority: changedAuthority,
        payload,
      }),
    /durable_authority_mismatch/,
  );
  assert.equal(calls, 0);
});

test("clock-sensitive durable methods accept only fixed TTL intent and remain unresolved", async () => {
  let calls = 0;
  const methods = [
    "reconcileScheduleTransaction",
    "claimDueJob",
    "completeJobAndAppendOutboxTransaction",
    "claimOutbox",
    "acknowledgeOutbox",
    "releaseExpiredClaims",
  ];
  const source = Object.fromEntries(
    methods.map((operation) => [
      operation,
      () => {
        calls += 1;
        throw new Error("clock-sensitive adapter must not run");
      },
    ]),
  );
  const port = bindDurableChiefOfStaffPort(source);
  const claimPayload = {
    jobId: hash("a"),
    scheduleRevision: hash("b"),
    expectedJobRevision: 1,
    expectedClaimFence: null,
    claimFence: "fence_job_000001",
    claimTtlSeconds: 60,
  };
  const claim = await port.claimDueJob(durableRequest("claimDueJob", claimPayload));
  assert.equal(claim.status, "unresolved");
  assert.equal(claim.serverClockReceiptRequired, true);
  await assert.rejects(
    () =>
      port.claimDueJob({
        ...durableRequest("claimDueJob", claimPayload),
        payload: { ...claimPayload, claimTtlSeconds: 61 },
      }),
    /invalid_durable_claim_ttl/,
  );
  await assert.rejects(
    () =>
      port.claimDueJob({
        ...durableRequest("claimDueJob", claimPayload),
        payload: { ...claimPayload, leaseExpiresAt: instant.now },
      }),
    /invalid_durable_payload/,
  );
  const releasePayload = { serverClockRequired: true, limit: 100 };
  const release = await port.releaseExpiredClaims(durableRequest("releaseExpiredClaims", releasePayload));
  assert.equal(release.status, "unresolved");
  await assert.rejects(
    () =>
      port.releaseExpiredClaims({
        ...durableRequest("releaseExpiredClaims", releasePayload),
        payload: { ...releasePayload, cutoff: instant.now },
      }),
    /invalid_durable_payload/,
  );
  assert.equal(calls, 0);
});

test("every durable method enforces its exact bounded request and result envelope", async () => {
  const original = planChiefOfStaffSchedule(scheduleInput());
  const moved = planChiefOfStaffSchedule(
    scheduleInput({
      events: [calendarEvent({ startAt: "2026-08-28T19:00:00.000Z", endAt: "2026-08-28T20:00:00.000Z" })],
      priorJobs: priorFrom(original),
    }),
  );
  const methodPayloads = {
    reconcileScheduleTransaction: {
      planHash: moved.planHash,
      desiredJobsHash: sha256Canonical(moved.desiredJobs),
      cancellations: moved.cancellations,
      cancellationsHash: sha256Canonical(moved.cancellations),
      expectedStoreRevision: 3,
    },
    claimDueJob: {
      jobId: hash("a"),
      scheduleRevision: hash("b"),
      expectedJobRevision: 1,
      expectedClaimFence: null,
      claimFence: "fence_job_000001",
      claimTtlSeconds: 60,
    },
    completeJobAndAppendOutboxTransaction: {
      jobId: hash("a"),
      scheduleRevision: hash("b"),
      expectedJobRevision: 2,
      claimFence: "fence_job_000001",
      outboxHash: hash("c"),
      artifactHash: hash("d"),
    },
    claimOutbox: {
      outboxId: hash("c"),
      expectedOutboxRevision: 1,
      expectedClaimFence: null,
      claimFence: "fence_outbox_000001",
      claimTtlSeconds: 60,
    },
    acknowledgeOutbox: {
      outboxId: hash("c"),
      expectedOutboxRevision: 2,
      claimFence: "fence_outbox_000001",
      receiptHash: hash("e"),
    },
    releaseExpiredClaims: { serverClockRequired: true, limit: 100 },
  };
  const source = Object.fromEntries(
    Object.keys(methodPayloads).map((operation) => [
      operation,
      (request) => ({
        schemaVersion: 1,
        operation,
        requestId: request.requestId,
        status: "applied",
        stateRevision: 4,
        resultHash: hash("f"),
      }),
    ]),
  );
  const port = bindDurableChiefOfStaffPort(source);
  for (const [operation, payload] of Object.entries(methodPayloads)) {
    const result = await port[operation](durableRequest(operation, payload));
    assert.equal(result.operation, operation);
    if (["claimDueJob", "claimOutbox", "releaseExpiredClaims"].includes(operation)) {
      assert.equal(result.status, "unresolved");
      assert.equal(result.serverClockReceiptRequired, true);
    }
  }
  const tampered = { ...moved.cancellations[0], expectedClaimFence: "fence_forged_000001" };
  await assert.rejects(
    async () =>
      await port.reconcileScheduleTransaction(
        durableRequest("reconcileScheduleTransaction", {
          ...methodPayloads.reconcileScheduleTransaction,
          cancellations: [tampered],
          cancellationsHash: sha256Canonical([tampered]),
        }),
      ),
    /invalid_cancellation_cas/,
  );
});
