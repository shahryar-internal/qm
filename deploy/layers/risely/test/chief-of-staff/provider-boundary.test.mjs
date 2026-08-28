import assert from "node:assert/strict";
import test from "node:test";
import { sha256Canonical } from "../../canary/contracts/canonicalize.mjs";
import {
  assertProviderExecutionProposal,
  coreTokenResolverContract,
  createProviderExecutionProposal,
  googleProviderBoundary,
  planCalendarUpcomingRead,
  planGmailMessageListRead,
  planGmailMessageRead,
} from "../../canary/chief-of-staff/index.mjs";
import { executionProposalInput, hash, instant } from "./fixtures.mjs";

const proposalFor = (operation, requestPlanHash = hash("3")) =>
  createProviderExecutionProposal({ ...executionProposalInput(operation), requestPlanHash });

const calendarRequest = (input) => ({
  method: "GET",
  url: "https://www.googleapis.com/calendar/v3/calendars/primary/events",
  query: {
    timeMin: input.from,
    timeMax: input.to,
    maxResults: String(input.maxResults),
    singleEvents: "true",
    orderBy: "startTime",
    showDeleted: "true",
  },
  responseProjection: "calendar.events.strict.v1",
});

const gmailListRequest = (input) => ({
  method: "GET",
  url: "https://gmail.googleapis.com/gmail/v1/users/me/messages",
  query: { q: input.query, maxResults: String(input.maxResults), includeSpamTrash: "false" },
  responseProjection: "gmail.message-refs.strict.v1",
});

const gmailReadRequest = (messageId) => ({
  method: "GET",
  url: `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}`,
  query: { format: "metadata" },
  responseProjection: "gmail.metadata-only.strict.v1",
});

test("the Google boundary is credential-free and execution-inert", () => {
  assert.equal(googleProviderBoundary.credentialMaterialAllowed, false);
  assert.equal(googleProviderBoundary.providerExecutionAllowed, false);
  assert.deepEqual(Object.keys(googleProviderBoundary.operations), [
    "calendar.events.read",
    "gmail.messages.list",
    "gmail.messages.read",
  ]);
});

test("planning emits an unresolved proposal instead of a replay-proof lease", () => {
  const proposal = proposalFor("calendar.events.read");
  assert.equal(proposal.authorizationState, "unresolved");
  assert.equal(proposal.durableBrokerConsumptionRequired, true);
  assert.equal(proposal.replayProtectionProvided, false);
  assert.equal(proposal.providerExecutionAllowed, false);
  assert.equal(proposal.credentialMaterialAllowed, false);
  assert.equal(Object.hasOwn(proposal, "issuedAt"), false);
  assert.equal(Object.hasOwn(proposal, "expiresAt"), false);
  assert.equal(Object.hasOwn(proposal, "maxUses"), false);
});

test("caller-controlled time, token, receipt, and authority fields are rejected", () => {
  const base = executionProposalInput();
  for (const extra of [
    { now: instant.now },
    { issuedAt: instant.now },
    { expiresAt: instant.meetingStart },
    { accessToken: "secret" },
    { maxUses: 1 },
    { executionAllowed: true },
  ]) {
    assert.throws(() => createProviderExecutionProposal({ ...base, ...extra }), /invalid_provider_execution_proposal/);
  }
});

test("double planning is deterministic but explicitly confers no replay protection", () => {
  const input = { from: instant.now, to: "2026-08-31T17:00:00.000Z", maxResults: 100 };
  const boundProposal = proposalFor("calendar.events.read", sha256Canonical(calendarRequest(input)));
  const first = planCalendarUpcomingRead(boundProposal, input);
  const second = planCalendarUpcomingRead(boundProposal, input);
  assert.deepEqual(first, second);
  assert.equal(first.replayProtectionProvided, false);
  assert.equal(first.providerExecutionAllowed, false);
  assert.equal(first.authorizationState, "unresolved");
});

test("the proposal binds the exact request plan and query hash", () => {
  const input = { from: instant.now, to: "2026-08-31T17:00:00.000Z", maxResults: 100 };
  assert.throws(
    () => planCalendarUpcomingRead(proposalFor("calendar.events.read"), input),
    /provider_request_plan_mismatch/,
  );
});

test("backdating and expiry cannot be forged because only the server broker may assign time", () => {
  const input = {
    from: "2020-01-01T00:00:00.000Z",
    to: "2020-01-02T00:00:00.000Z",
    maxResults: 1,
  };
  const proposal = proposalFor("calendar.events.read", sha256Canonical(calendarRequest(input)));
  const plan = planCalendarUpcomingRead(proposal, input);
  assert.equal(plan.authorizationState, "unresolved");
  assert.equal(plan.providerExecutionAllowed, false);
  assert.equal(coreTokenResolverContract.serverClockRequired, true);
  assert.equal(coreTokenResolverContract.monotonicConsumptionRequired, true);
  assert.equal(coreTokenResolverContract.durableSingleUseReservationRequired, true);
  assert.equal(coreTokenResolverContract.implementationPresent, false);
});

test("calendar plans an exact fixed-host read and never receives an authorization header", () => {
  const input = {
    from: instant.now,
    to: "2026-08-31T17:00:00.000Z",
    maxResults: 100,
  };
  const invocation = planCalendarUpcomingRead(
    proposalFor("calendar.events.read", sha256Canonical(calendarRequest(input))),
    input,
  );
  assert.equal(invocation.request.method, "GET");
  assert.equal(invocation.request.url, "https://www.googleapis.com/calendar/v3/calendars/primary/events");
  assert.equal(invocation.request.query.showDeleted, "true");
  assert.equal(Object.hasOwn(invocation.request, "headers"), false);
  assert.equal(invocation.proposal.calendarAccountRef, "calendar_ceo_primary");
});

test("Gmail plans metadata-only bounded reads on the Gmail host", () => {
  const listInput = {
    query: "newer_than:30d",
    maxResults: 5,
  };
  const list = planGmailMessageListRead(
    proposalFor("gmail.messages.list", sha256Canonical(gmailListRequest(listInput))),
    listInput,
  );
  const read = planGmailMessageRead(proposalFor("gmail.messages.read", sha256Canonical(gmailReadRequest("msg_0001"))), {
    messageId: "msg_0001",
  });
  assert.equal(list.request.url, "https://gmail.googleapis.com/gmail/v1/users/me/messages");
  assert.equal(read.request.url, "https://gmail.googleapis.com/gmail/v1/users/me/messages/msg_0001");
  assert.equal(read.request.query.format, "metadata");
  assert.equal(
    Object.values(read.request.query).some((value) => /body|raw/i.test(value)),
    false,
  );
});

test("unbranded and operation-mismatched proposals cannot plan provider work", () => {
  const forged = { ...proposalFor("calendar.events.read") };
  assert.throws(
    () => planCalendarUpcomingRead(forged, { from: instant.now, to: instant.meetingStart, maxResults: 1 }),
    /untrusted_provider_execution_proposal/,
  );
  assert.throws(
    () =>
      planCalendarUpcomingRead(proposalFor("gmail.messages.list"), {
        from: instant.now,
        to: instant.meetingStart,
        maxResults: 1,
      }),
    /untrusted_provider_execution_proposal/,
  );
  assert.throws(() => assertProviderExecutionProposal(forged, "calendar.events.read"));
});

test("proposal identity binds deployment, actor, owner, account, connection, operation, and nonce", () => {
  const base = executionProposalInput();
  const baseline = createProviderExecutionProposal(base).proposalId;
  for (const [field, value] of [
    ["deploymentRef", "deployment_other"],
    ["principalRef", "usr_other_00000001"],
    ["credentialOwnerRef", "usr_other_00000001"],
    ["calendarAccountRef", "calendar_other_primary"],
    ["providerAccountSubject", "google_subject_other_01"],
    ["connectionRef", "conn_other_00000001"],
    ["jobId", hash("4")],
    ["scheduleRevision", hash("5")],
    ["requestPlanHash", hash("6")],
    ["nonce", "nonce_other_00000001"],
  ]) {
    assert.notEqual(createProviderExecutionProposal({ ...base, [field]: value }).proposalId, baseline);
  }
});
