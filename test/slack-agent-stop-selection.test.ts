import { test } from "node:test";
import assert from "node:assert/strict";
import { selectSlackAgentStopRuns, slackAgentPresentationRequest } from "../src/api/slack-core-client.ts";
import type { Run } from "../src/runs/run-store.ts";
import type { SlackAgentPresentationClaim } from "../src/surfaces/slack-agent-session.ts";
import type { SlackAgentSessionRecord } from "../src/surfaces/slack-agent-session.ts";

function run(input: {
  id: string;
  createdAt: number;
  userId?: string;
  editRef?: string;
  channelId?: string;
  threadTs?: string;
  threadRef?: string;
  sessionToken?: string;
  session?: { teamId: string; agentId: string; channelId: string; threadTs: string; token: string };
}): Run {
  return {
    id: input.id,
    sessionId: "session",
    status: "running",
    request: {
      surface: "slack",
      actor: { id: "owner@example.com", type: "internal" },
      conversation: { kind: "dm", threadRef: input.threadRef ?? "dm:D1:10.1", audience: [] },
      origin: { kind: "human" },
      text: "work",
      ...(input.sessionToken ? { slackAgentSessionToken: input.sessionToken } : {}),
      ...(input.session ? { slackAgentSession: input.session } : {}),
      verifiedSlack: {
        teamId: "T1",
        userId: input.userId ?? "U1",
        channelId: input.channelId ?? "D1",
        messageTs: "10.1",
        threadTs: input.threadTs ?? "10.1",
        threaded: false,
        liveHuman: true,
      },
    },
    result: null,
    deliveryState: input.editRef ? { editRef: input.editRef } : null,
    dedupKey: null,
    attempts: 1,
    errorAttempts: 0,
    maxAttempts: 3,
    leaseToken: "lease",
    leaseExpiresAt: input.createdAt + 60_000,
    workerId: "worker",
    createdAt: input.createdAt,
    startedAt: input.createdAt,
    finishedAt: null,
  };
}

const stop = {
  teamId: "T1",
  agentId: "A1",
  channelId: "D1",
  threadTs: "10.1",
  eventId: "Ev1",
  eventTs: "11.000",
  stoppedByUserId: "U2",
  streamingMessageTs: ["stream-1"],
};

const presentationClaim: SlackAgentPresentationClaim = {
  teamId: "T1",
  agentId: "A1",
  channelId: "D1",
  threadTs: "10.1",
  token: "binding",
  runId: "presentation",
  ownerUserId: "U1",
  triggerTs: "10.1",
  authorityMessageTs: "10.1",
  coreThreadRef: "dm:D1:10.1",
  claimId: "claim",
  generation: 1,
  leaseExpiresAt: 60_000,
};

const session = (runIds: string[], streamTs = "stream-1"): SlackAgentSessionRecord => ({
  teamId: "T1",
  agentId: "A1",
  channelId: "D1",
  threadTs: "10.1",
  status: "processing",
  bindings: [
    {
      token: "binding",
      ownerUserId: "U1",
      status: "processing",
      triggerTs: "10.1",
      coreThreadRef: "dm:D1:10.1",
      authorityMessageTs: "10.1",
      runIds,
      cancelEventId: "Ev1",
      cancelRequestedAt: "11.000",
      ...(streamTs ? { streamTs } : {}),
    },
  ],
  stopEvents: [
    {
      eventId: "Ev1",
      eventTs: "11.000",
      stoppedByUserId: "U2",
      streamingMessageTs: ["stream-1"],
      bindingTokens: ["binding"],
      applicable: true,
      state: "pending",
    },
  ],
  updatedAt: 1,
});

test("ordinary presentation recovery requires the exact durable Slack authority tuple", () => {
  const exact = run({
    id: presentationClaim.runId,
    createdAt: 10_000,
    sessionToken: presentationClaim.token,
    session: {
      teamId: presentationClaim.teamId,
      agentId: presentationClaim.agentId,
      channelId: presentationClaim.channelId,
      threadTs: presentationClaim.threadTs,
      token: presentationClaim.token,
    },
  });
  assert.equal(slackAgentPresentationRequest(exact, presentationClaim)?.text, "work");
  for (const mismatched of [
    { ...presentationClaim, teamId: "T-other" },
    { ...presentationClaim, agentId: "A-other" },
    { ...presentationClaim, channelId: "D-other" },
    { ...presentationClaim, threadTs: "10.2" },
    { ...presentationClaim, token: "other-token" },
    { ...presentationClaim, runId: "other-run" },
    { ...presentationClaim, ownerUserId: "U2" },
    { ...presentationClaim, authorityMessageTs: "10.2" },
    { ...presentationClaim, coreThreadRef: "dm:D1:other" },
  ]) {
    assert.equal(slackAgentPresentationRequest(exact, mismatched), null);
  }
});

test("a second channel participant stops only the exact binding owner and pre-event runs", () => {
  const exact = run({ id: "exact", createdAt: 10_000, editRef: "stream-1" });
  const wrongOwner = run({ id: "wrong-owner", createdAt: 10_000, userId: "U2", editRef: "stream-1" });
  const future = run({ id: "future", createdAt: 13_000, editRef: "stream-1" });
  const oldStream = run({ id: "old-stream", createdAt: 10_000, editRef: "stream-old" });
  assert.deepEqual(
    selectSlackAgentStopRuns([wrongOwner, future, oldStream, exact], stop, session(["exact"])).map((r) => r.id),
    ["exact"],
  );
});

test("native stop selects every exact run in the durable binding regardless of local creation time", () => {
  const first = run({ id: "first", createdAt: 10_000, editRef: "stream-1" });
  const second = run({ id: "second", createdAt: 10_000, editRef: "stream-1" });
  assert.deepEqual(
    selectSlackAgentStopRuns([first, second], stop, session(["first", "second"])).map((r) => r.id),
    ["first", "second"],
  );
  assert.deepEqual(
    selectSlackAgentStopRuns([run({ id: "new", createdAt: 20_000, editRef: "stream-1" })], stop, session(["new"])).map(
      (candidate) => candidate.id,
    ),
    ["new"],
  );
  assert.deepEqual(
    selectSlackAgentStopRuns(
      [run({ id: "just-new", createdAt: 11_001, editRef: "stream-1" })],
      stop,
      session(["just-new"]),
    ).map((candidate) => candidate.id),
    ["just-new"],
  );
});

test("native stop keeps the event-time cutoff for an unbound legacy heuristic", () => {
  const legacy = run({ id: "legacy", createdAt: 20_000 });
  assert.deepEqual(selectSlackAgentStopRuns([legacy], { ...stop, streamingMessageTs: [] }, session([], "")), []);
});

test("missing run and edit checkpoints require the exact pending stream authority", () => {
  const exact = run({ id: "exact", createdAt: 10_000 });
  assert.deepEqual(
    selectSlackAgentStopRuns([exact], { ...stop, streamingMessageTs: [] }, session([], "")).map((r) => r.id),
    ["exact"],
  );
  assert.deepEqual(selectSlackAgentStopRuns([exact], stop, session([], "stream-1")), []);
  assert.deepEqual(
    selectSlackAgentStopRuns([exact], stop, session(["exact"], "stream-1")).map((r) => r.id),
    ["exact"],
  );
});

test("a channel session stops its explicitly bound approval continuation from the approval DM", () => {
  const continuation = run({
    id: "approval-continuation",
    createdAt: 10_000,
    channelId: "DAPPROVAL",
    threadTs: "20.1",
    threadRef: "dm:D1:10.1",
  });
  assert.deepEqual(selectSlackAgentStopRuns([continuation], stop, session(["approval-continuation"])), [continuation]);
});

test("a transactionally persisted binding token closes the stop-before-onQueued crash window", () => {
  const persisted = run({
    id: "persisted-before-callback",
    createdAt: 20_000,
    channelId: "DAPPROVAL",
    threadTs: "20.1",
    threadRef: "dm:D1:10.1",
    session: { teamId: "T1", agentId: "A1", channelId: "D1", threadTs: "10.1", token: "binding" },
  });
  assert.deepEqual(selectSlackAgentStopRuns([persisted], stop, session([])), [persisted]);
  const tokenOnly = run({
    id: "persisted-token-only",
    createdAt: 20_000,
    userId: "U-APPROVER",
    channelId: "DAPPROVAL",
    threadTs: "20.1",
    threadRef: "dm:D1:10.1",
    sessionToken: "binding",
  });
  assert.deepEqual(selectSlackAgentStopRuns([tokenOnly], stop, session([])), [tokenOnly]);
  assert.deepEqual(
    selectSlackAgentStopRuns(
      [
        {
          ...persisted,
          request: {
            ...persisted.request,
            slackAgentSession: {
              teamId: "T1",
              agentId: "A1",
              channelId: "D1",
              threadTs: "10.1",
              token: "wrong",
            },
          },
        },
      ],
      stop,
      session([]),
    ),
    [],
  );
});

test("a bound channel continuation remains stoppable when another authorized user clicked in a DM", () => {
  const continuation = run({
    id: "approval-continuation",
    createdAt: 10_000,
    userId: "U-APPROVER",
    channelId: "DAPPROVAL",
    threadTs: "20.1",
    threadRef: "dm:D1:10.1",
  });
  assert.deepEqual(selectSlackAgentStopRuns([continuation], stop, session(["approval-continuation"])), [continuation]);
});
