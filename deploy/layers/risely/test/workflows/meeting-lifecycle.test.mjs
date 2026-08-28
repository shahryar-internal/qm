import assert from "node:assert/strict";
import test from "node:test";
import { sha256Canonical } from "../../canary/contracts/index.mjs";
import { planMeetingLifecycle } from "../../canary/workflows/index.mjs";

const hash = (character) => character.repeat(64);

const event = (overrides = {}) => ({
  eventId: "calendar-event-001",
  originalStartAt: "2026-11-01T08:30:00.000Z",
  startAt: "2026-11-01T08:30:00.000Z",
  endAt: "2026-11-01T09:15:00.000Z",
  meetingKind: "customer",
  status: "confirmed",
  allDay: false,
  isPrivate: false,
  ceoResponse: "accepted",
  attendees: [{ email: "alex@example.edu", external: true, response: "accepted" }],
  title: "Admissions discovery",
  evidenceHash: hash("a"),
  ...overrides,
});

const input = (overrides = {}) => ({
  ceoTimezone: "America/Los_Angeles",
  now: "2026-10-30T08:30:00.000Z",
  calendar: { availability: "available", events: [event()] },
  transcripts: { availability: "available", records: [] },
  priorSchedules: [],
  ...overrides,
});

const intentOf = (result, type) => result.intents.find((item) => item.type === type);

const artifactFingerprint = (result) => sha256Canonical(intentOf(result, "meeting.prep").payload.artifactInput);

const stableIdentity = (first, second, type) => {
  const firstIntent = intentOf(first, type);
  const secondIntent = intentOf(second, type);
  assert.equal(secondIntent.intentId, firstIntent.intentId);
  assert.equal(secondIntent.idempotencyKey, firstIntent.idempotencyKey);
  assert.notEqual(secondIntent.deliveryAt, firstIntent.deliveryAt);
};

test("schedules timezone-explicit lifecycle work across DST from canonical instants", () => {
  const result = planMeetingLifecycle(input());
  assert.equal(result.ceoTimezone, "America/Los_Angeles");
  assert.deepEqual(
    result.intents.map((item) => item.type),
    ["meeting.prep", "meeting.prep.refresh"],
  );
  const prep = intentOf(result, "meeting.prep");
  assert.equal(prep.deliveryAt, "2026-10-31T08:30:00.000Z");
  assert.equal(prep.payload.artifactInput.ceoLocalStart, "2026-11-01T01:30:00-07:00");
  assert.equal(prep.payload.artifactInput.event.titleTrust, "untrusted_data");
  for (const ceoTimezone of ["UTC", "GMT", "Etc/GMT"]) {
    const zoneResult = planMeetingLifecycle(input({ ceoTimezone }));
    assert.equal(intentOf(zoneResult, "meeting.prep").payload.artifactInput.ceoLocalStart.endsWith("+00:00"), true);
  }
});

test("deduplicates only on calendar event id plus original start", () => {
  const first = event();
  const movedOccurrence = event({ startAt: "2026-11-01T10:30:00.000Z", endAt: "2026-11-01T11:15:00.000Z" });
  assert.throws(
    () => planMeetingLifecycle(input({ calendar: { availability: "available", events: [first, movedOccurrence] } })),
    /duplicate_event/,
  );
  const distinct = event({ eventId: "calendar-event-002", evidenceHash: hash("b") });
  const result = planMeetingLifecycle(input({ calendar: { availability: "available", events: [first, distinct] } }));
  assert.equal(result.meetings.length, 2);
  assert.notEqual(result.meetings[0].meetingKey, result.meetings[1].meetingKey);
});

test("cancelled and newly ineligible meetings cancel every prior lifecycle work item", () => {
  const original = event();
  const originalPlan = planMeetingLifecycle(input({ calendar: { availability: "available", events: [original] } }));
  const prior = [{ meetingKey: originalPlan.meetings[0].meetingKey, currentStartAt: original.startAt }];
  for (const invalid of [event({ status: "cancelled" }), event({ isPrivate: true }), event({ attendees: [] })]) {
    const result = planMeetingLifecycle(
      input({ calendar: { availability: "available", events: [invalid] }, priorSchedules: prior }),
    );
    const cancellation = intentOf(result, "meeting.schedule.cancel");
    assert.equal(cancellation.payload.cancelScope, "all_prior_work");
    assert.deepEqual(cancellation.payload.cancelledWork, [
      "meeting.prep",
      "meeting.prep.refresh",
      "meeting.demo_reminder",
      "meeting.transcript.recheck",
      "meeting.followup",
    ]);
  }
});

test("provider supersedes aliases preserve reschedule cancellation when event identity changes", () => {
  const original = event();
  const firstPlan = planMeetingLifecycle(input({ calendar: { availability: "available", events: [original] } }));
  const oldKey = firstPlan.meetings[0].meetingKey;
  const changedIdentity = event({
    eventId: "calendar-event-002",
    originalStartAt: "2026-11-03T08:30:00.000Z",
    startAt: "2026-11-03T10:30:00.000Z",
    endAt: "2026-11-03T11:15:00.000Z",
    providerSupersedesKey: oldKey,
    evidenceHash: hash("b"),
  });
  const result = planMeetingLifecycle(
    input({
      calendar: { availability: "available", events: [changedIdentity] },
      priorSchedules: [{ meetingKey: oldKey, currentStartAt: original.startAt, providerSupersedesKey: oldKey }],
    }),
  );
  const supersede = intentOf(result, "meeting.schedule.supersede");
  assert.equal(supersede.payload.priorMeetingKey, oldKey);
  assert.equal(supersede.payload.replacementStartAt, changedIdentity.startAt);
  assert.equal(supersede.payload.cancelScope, "all_prior_work");
});

test("a current snapshot containing old and replacement events suppresses stale old-event work", () => {
  const old = event();
  const oldPlan = planMeetingLifecycle(input({ calendar: { availability: "available", events: [old] } }));
  const oldKey = oldPlan.meetings[0].meetingKey;
  const replacement = event({
    eventId: "calendar-event-002",
    originalStartAt: "2026-11-03T08:30:00.000Z",
    startAt: "2026-11-03T10:30:00.000Z",
    endAt: "2026-11-03T11:15:00.000Z",
    providerSupersedesKey: oldKey,
    evidenceHash: hash("b"),
  });
  const result = planMeetingLifecycle(
    input({
      calendar: { availability: "available", events: [old, replacement] },
      priorSchedules: [{ meetingKey: oldKey, currentStartAt: old.startAt }],
    }),
  );
  assert.equal(result.meetings.find((meeting) => meeting.meetingKey === oldKey).state, "superseded_current_snapshot");
  assert.equal(
    result.intents.some((item) => item.meetingKey === oldKey && item.type === "meeting.prep"),
    false,
  );
  assert.notEqual(intentOf(result, "meeting.schedule.supersede"), undefined);
  assert.equal(
    result.intents.filter(
      (item) => item.type === "meeting.schedule.cancel" || item.type === "meeting.schedule.supersede",
    ).length,
    1,
  );
  const anotherReplacement = event({
    eventId: "calendar-event-003",
    originalStartAt: "2026-11-04T08:30:00.000Z",
    startAt: "2026-11-04T10:30:00.000Z",
    endAt: "2026-11-04T11:15:00.000Z",
    providerSupersedesKey: oldKey,
    evidenceHash: hash("c"),
  });
  assert.throws(
    () =>
      planMeetingLifecycle(
        input({ calendar: { availability: "available", events: [old, replacement, anotherReplacement] } }),
      ),
    /ambiguous_snapshot_alias/,
  );
});

test("current snapshot provider aliases reject cycles", () => {
  const first = event();
  const second = event({
    eventId: "calendar-event-002",
    originalStartAt: "2026-11-02T08:30:00.000Z",
    startAt: "2026-11-02T08:30:00.000Z",
    endAt: "2026-11-02T09:15:00.000Z",
    evidenceHash: hash("b"),
  });
  const baseline = planMeetingLifecycle(input({ calendar: { availability: "available", events: [first, second] } }));
  const firstKey = baseline.meetings.find((meeting) => meeting.eventId === first.eventId).meetingKey;
  const secondKey = baseline.meetings.find((meeting) => meeting.eventId === second.eventId).meetingKey;
  const cycleFirst = event({ providerSupersedesKey: secondKey });
  const cycleSecond = event({ ...second, providerSupersedesKey: firstKey });
  assert.throws(
    () => planMeetingLifecycle(input({ calendar: { availability: "available", events: [cycleFirst, cycleSecond] } })),
    /ambiguous_snapshot_alias/,
  );
});

test("explicit customer and demo meetings allow internal attendees while generic external meetings require a non-declined external attendee", () => {
  const internal = [{ email: "teammate@risely.ai", external: false, response: "accepted" }];
  assert.equal(
    planMeetingLifecycle(
      input({
        calendar: { availability: "available", events: [event({ meetingKind: "customer", attendees: internal })] },
      }),
    ).meetings[0].state,
    "eligible",
  );
  assert.equal(
    planMeetingLifecycle(
      input({ calendar: { availability: "available", events: [event({ meetingKind: "demo", attendees: internal })] } }),
    ).meetings[0].state,
    "eligible",
  );
  assert.equal(
    planMeetingLifecycle(
      input({
        calendar: { availability: "available", events: [event({ meetingKind: "external", attendees: internal })] },
      }),
    ).meetings[0].state,
    "external_attendee_unavailable",
  );
  assert.equal(
    planMeetingLifecycle(
      input({
        calendar: {
          availability: "available",
          events: [
            event({
              meetingKind: "external",
              attendees: [{ email: "alex@example.edu", external: true, response: "declined" }],
            }),
          ],
        },
      }),
    ).meetings[0].state,
    "external_attendee_declined",
  );
  assert.equal(
    planMeetingLifecycle(
      input({
        calendar: {
          availability: "available",
          events: [
            event({
              meetingKind: "external",
              attendees: [{ email: "alex@example.edu", external: true, response: "tentative" }],
            }),
          ],
        },
      }),
    ).meetings[0].state,
    "eligible",
  );
  assert.equal(
    planMeetingLifecycle(
      input({
        calendar: {
          availability: "available",
          events: [
            event({
              meetingKind: "customer",
              attendees: [{ email: "alex@example.edu", external: true, response: "declined" }],
            }),
          ],
        },
      }),
    ).meetings[0].state,
    "external_attendee_declined",
  );
  assert.equal(
    planMeetingLifecycle(
      input({
        calendar: {
          availability: "available",
          events: [
            event({
              meetingKind: "demo",
              attendees: [{ email: "alex@example.edu", external: true, response: "declined" }],
            }),
          ],
        },
      }),
    ).meetings[0].state,
    "external_attendee_declined",
  );
  assert.throws(
    () =>
      planMeetingLifecycle(
        input({
          calendar: {
            availability: "available",
            events: [event({ attendees: [{ email: "not-an-email", external: true, response: "accepted" }] })],
          },
        }),
      ),
    /invalid_attendee/,
  );
});

test("unavailable sources remain unavailable rather than being represented as none found", () => {
  const noCalendar = planMeetingLifecycle(input({ calendar: { availability: "unavailable", events: [] } }));
  assert.deepEqual(noCalendar.notices, [{ code: "calendar_source_unavailable" }]);
  const afterMeeting = planMeetingLifecycle(
    input({ now: "2026-11-01T10:00:00.000Z", transcripts: { availability: "unavailable", records: [] } }),
  );
  assert.equal(afterMeeting.notices[0].code, "transcript_source_unavailable");
  assert.equal(
    afterMeeting.intents.some((item) => item.payload.reason === "transcript_source_unavailable"),
    true,
  );
});

test("full artifact fingerprints make title, attendees, and timezone material refresh inputs", () => {
  const prepared = planMeetingLifecycle(input());
  const meetingKey = prepared.meetings[0].meetingKey;
  const prior = [
    { meetingKey, currentStartAt: event().startAt, preparedArtifactFingerprint: artifactFingerprint(prepared) },
  ];
  const withinRefresh = "2026-11-01T07:45:00.000Z";
  const unchanged = planMeetingLifecycle(input({ now: withinRefresh, priorSchedules: prior }));
  assert.equal(intentOf(unchanged, "meeting.prep.refresh"), undefined);
  const titleChanged = planMeetingLifecycle(
    input({
      now: withinRefresh,
      calendar: { availability: "available", events: [event({ title: "Advancement discovery" })] },
      priorSchedules: prior,
    }),
  );
  assert.notEqual(intentOf(titleChanged, "meeting.prep.refresh"), undefined);
  const timezoneChanged = planMeetingLifecycle(
    input({ now: withinRefresh, ceoTimezone: "UTC", priorSchedules: prior }),
  );
  assert.notEqual(intentOf(timezoneChanged, "meeting.prep.refresh"), undefined);
  const attendeeChanged = planMeetingLifecycle(
    input({
      now: withinRefresh,
      calendar: {
        availability: "available",
        events: [
          event({
            attendees: [
              { email: "alex@example.edu", external: true, response: "accepted" },
              { email: "morgan@example.edu", external: true, response: "tentative" },
            ],
          }),
        ],
      },
      priorSchedules: prior,
    }),
  );
  assert.notEqual(intentOf(attendeeChanged, "meeting.prep.refresh"), undefined);
});

test("transcripts bind to event id and original start, require a nonfuture final revision, and retain notes fallback", () => {
  const afterMeeting = "2026-11-01T10:00:00.000Z";
  const wrongOccurrence = planMeetingLifecycle(
    input({
      now: afterMeeting,
      transcripts: {
        availability: "available",
        records: [
          {
            eventId: "calendar-event-001",
            originalStartAt: "2026-10-25T08:30:00.000Z",
            revision: "final",
            evidenceHash: hash("c"),
            finalizedAt: "2026-11-01T09:25:00.000Z",
          },
        ],
      },
    }),
  );
  assert.equal(intentOf(wrongOccurrence, "meeting.followup"), undefined);
  assert.notEqual(intentOf(wrongOccurrence, "meeting.followup.waiting_for_notes"), undefined);
  const final = planMeetingLifecycle(
    input({
      now: afterMeeting,
      transcripts: {
        availability: "available",
        records: [
          {
            eventId: "calendar-event-001",
            originalStartAt: event().originalStartAt,
            revision: "final",
            evidenceHash: hash("c"),
            finalizedAt: "2026-11-01T09:25:00.000Z",
          },
        ],
      },
    }),
  );
  assert.notEqual(intentOf(final, "meeting.followup"), undefined);
  assert.throws(
    () =>
      planMeetingLifecycle(
        input({
          now: afterMeeting,
          transcripts: {
            availability: "available",
            records: [
              {
                eventId: "calendar-event-001",
                originalStartAt: event().originalStartAt,
                revision: "final",
                evidenceHash: hash("c"),
                finalizedAt: "2026-11-01T10:01:00.000Z",
              },
            ],
          },
        }),
      ),
    /invalid_transcript/,
  );
});

test("immediate work retains semantic intent identity while delivery time changes across polling", () => {
  const immediatePrepFirst = planMeetingLifecycle(input({ now: "2026-11-01T07:00:00.000Z" }));
  const immediatePrepSecond = planMeetingLifecycle(input({ now: "2026-11-01T07:01:00.000Z" }));
  stableIdentity(immediatePrepFirst, immediatePrepSecond, "meeting.prep");
  const prepared = planMeetingLifecycle(input());
  const meetingKey = prepared.meetings[0].meetingKey;
  const refreshPrior = [
    { meetingKey, currentStartAt: event().startAt, preparedArtifactFingerprint: artifactFingerprint(prepared) },
  ];
  const changedEvent = event({ title: "Advancement discovery" });
  const immediateRefreshFirst = planMeetingLifecycle(
    input({
      now: "2026-11-01T07:00:00.000Z",
      calendar: { availability: "available", events: [changedEvent] },
      priorSchedules: refreshPrior,
    }),
  );
  const immediateRefreshSecond = planMeetingLifecycle(
    input({
      now: "2026-11-01T07:01:00.000Z",
      calendar: { availability: "available", events: [changedEvent] },
      priorSchedules: refreshPrior,
    }),
  );
  stableIdentity(immediateRefreshFirst, immediateRefreshSecond, "meeting.prep.refresh");
  const demoFirst = planMeetingLifecycle(
    input({
      now: "2026-11-01T08:20:00.000Z",
      calendar: { availability: "available", events: [event({ meetingKind: "demo" })] },
    }),
  );
  const demoSecond = planMeetingLifecycle(
    input({
      now: "2026-11-01T08:21:00.000Z",
      calendar: { availability: "available", events: [event({ meetingKind: "demo" })] },
    }),
  );
  stableIdentity(demoFirst, demoSecond, "meeting.demo_reminder");
  const transcript = {
    eventId: "calendar-event-001",
    originalStartAt: event().originalStartAt,
    revision: "final",
    evidenceHash: hash("c"),
    finalizedAt: "2026-11-01T09:25:00.000Z",
  };
  const followupFirst = planMeetingLifecycle(
    input({ now: "2026-11-01T10:00:00.000Z", transcripts: { availability: "available", records: [transcript] } }),
  );
  const followupSecond = planMeetingLifecycle(
    input({ now: "2026-11-01T10:01:00.000Z", transcripts: { availability: "available", records: [transcript] } }),
  );
  stableIdentity(followupFirst, followupSecond, "meeting.followup");
  const baseline = planMeetingLifecycle(input());
  const moved = event({
    startAt: "2026-11-01T10:30:00.000Z",
    endAt: "2026-11-01T11:15:00.000Z",
    evidenceHash: hash("b"),
  });
  const supersedePrior = [{ meetingKey: baseline.meetings[0].meetingKey, currentStartAt: event().startAt }];
  const supersedeFirst = planMeetingLifecycle(
    input({ calendar: { availability: "available", events: [moved] }, priorSchedules: supersedePrior }),
  );
  const supersedeSecond = planMeetingLifecycle(
    input({
      now: "2026-10-30T08:31:00.000Z",
      calendar: { availability: "available", events: [moved] },
      priorSchedules: supersedePrior,
    }),
  );
  stableIdentity(supersedeFirst, supersedeSecond, "meeting.schedule.supersede");
});

test("strict plain JSON rejects symbols, accessors, nonenumerables, sparse arrays, named arrays, and lone surrogates", () => {
  const symbolInput = input();
  symbolInput[Symbol("x")] = true;
  assert.throws(() => planMeetingLifecycle(symbolInput), /invalid_plain_json/);
  const accessorEvent = event();
  delete accessorEvent.title;
  Object.defineProperty(accessorEvent, "title", { enumerable: true, get: () => "Admissions discovery" });
  assert.throws(
    () => planMeetingLifecycle(input({ calendar: { availability: "available", events: [accessorEvent] } })),
    /invalid_plain_json/,
  );
  const hiddenInput = input();
  Object.defineProperty(hiddenInput, "hidden", { enumerable: false, value: true });
  assert.throws(() => planMeetingLifecycle(hiddenInput), /invalid_plain_json/);
  const sparseEvents = [];
  sparseEvents[1] = event();
  assert.throws(
    () => planMeetingLifecycle(input({ calendar: { availability: "available", events: sparseEvents } })),
    /invalid_plain_json/,
  );
  const namedEvents = [event()];
  namedEvents.extra = true;
  assert.throws(
    () => planMeetingLifecycle(input({ calendar: { availability: "available", events: namedEvents } })),
    /invalid_plain_json/,
  );
  const hiddenEvents = [event()];
  Object.defineProperty(hiddenEvents, "hidden", { enumerable: false, value: true });
  assert.throws(
    () => planMeetingLifecycle(input({ calendar: { availability: "available", events: hiddenEvents } })),
    /invalid_plain_json/,
  );
  assert.throws(
    () =>
      planMeetingLifecycle(input({ calendar: { availability: "available", events: [event({ title: "bad\uD800" })] } })),
    /invalid_plain_json/,
  );
  assert.throws(() => planMeetingLifecycle(input({ extra: "a".repeat(1_048_577) })), /invalid_plain_json/);
});

test("prior execution state and operational event dates are constrained", () => {
  const plan = planMeetingLifecycle(input());
  const prior = {
    meetingKey: plan.meetings[0].meetingKey,
    currentStartAt: event().startAt,
    refreshedArtifactFingerprint: hash("a"),
  };
  assert.throws(() => planMeetingLifecycle(input({ priorSchedules: [prior] })), /invalid_prior_schedule/);
  assert.throws(
    () =>
      planMeetingLifecycle(
        input({
          calendar: {
            availability: "available",
            events: [
              event({
                originalStartAt: "2030-11-01T08:30:00.000Z",
                startAt: "2030-11-01T08:30:00.000Z",
                endAt: "2030-11-01T09:15:00.000Z",
              }),
            ],
          },
        }),
      ),
    /event_out_of_range/,
  );
});

test("identical retries and reordered trusted records remain deterministic", () => {
  const first = event();
  const second = event({
    eventId: "calendar-event-002",
    originalStartAt: "2026-11-02T08:30:00.000Z",
    startAt: "2026-11-02T08:30:00.000Z",
    endAt: "2026-11-02T09:00:00.000Z",
    evidenceHash: hash("b"),
    attendees: [
      { email: "zeta@example.edu", external: true, response: "accepted" },
      { email: "alpha@example.edu", external: true, response: "accepted" },
    ],
  });
  const ordered = input({ calendar: { availability: "available", events: [first, second] } });
  const reordered = input({
    calendar: { availability: "available", events: [{ ...second, attendees: [...second.attendees].reverse() }, first] },
  });
  assert.deepEqual(planMeetingLifecycle(reordered), planMeetingLifecycle(ordered));
});
