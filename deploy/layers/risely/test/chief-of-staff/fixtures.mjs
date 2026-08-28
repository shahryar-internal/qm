export const hash = (character = "a") => character.repeat(64);

export const instant = Object.freeze({
  now: "2026-08-26T17:00:00.000Z",
  meetingStart: "2026-08-28T17:00:00.000Z",
  meetingEnd: "2026-08-28T18:00:00.000Z",
});

export const lineage = Object.freeze({
  organizationRef: "organization:risely",
  deploymentRef: "deployment:risely:ceo-canary:v1",
  principalRef: "principal:ceo",
  credentialOwnerRef: "credential-owner:ceo",
  connectionRef: "conn_google_00000001",
  calendarAccountRef: "calendar_ceo_primary",
  audienceRef: "slack-audience:ceo-private",
  audience: "ceo_private",
  destinationRef: "destination_ceo_dm",
  destination: "slack_ceo_dm",
});

export const executionProposalInput = (operation = "calendar.events.read") => {
  const { audience, destination, ...authority } = lineage;
  return {
    ...authority,
    deliveryAudience: audience,
    deliveryDestination: destination,
    automationGrantRef: "grant_ceo_google_01",
    providerAccountSubject: "google_subject_ceo_01",
    jobId: hash("1"),
    scheduleRevision: hash("2"),
    requestPlanHash: hash("3"),
    operation,
    nonce: "nonce_00000000000001",
    requestedTtlSeconds: 60,
  };
};

export const calendarEvent = (overrides = {}) => ({
  calendarEventId: "event_customer_01",
  occurrenceRef: "event:event_customer_01",
  recurrenceKind: "single",
  startAt: instant.meetingStart,
  endAt: instant.meetingEnd,
  status: "confirmed",
  allDay: false,
  visibility: "default",
  ceoResponse: "accepted",
  title: "Advancement discovery",
  attendees: [
    { email: "shahryar@risely.ai", external: false, response: "accepted" },
    { email: "buyer_team@example.edu", external: true, response: "accepted" },
  ],
  evidenceHash: hash("b"),
  ...overrides,
});

export const recurringCalendarEvent = (overrides = {}) =>
  calendarEvent({
    calendarEventId: "event_customer_recurring_01",
    occurrenceRef: `series:series_customer_weekly:${instant.meetingStart}`,
    recurrenceKind: "recurring",
    seriesId: "series_customer_weekly",
    recurrenceOriginalStartAt: instant.meetingStart,
    ...overrides,
  });

export const scheduleInput = (overrides = {}) => ({
  now: instant.now,
  pollWindowEnd: "2026-08-31T17:00:00.000Z",
  ...lineage,
  calendarSnapshotHash: hash("c"),
  calendarAvailability: "available",
  events: [calendarEvent()],
  priorJobs: [],
  ...overrides,
});
