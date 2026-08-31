import assert from "node:assert/strict";
import { test } from "node:test";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { drainSlackAgentStatusIntents, requestSlackAgentStatusIntent } from "../src/slack/status-intent.ts";
import {
  createSlackAgentStatusIntentStore,
  type SlackAgentStatusIntentInput,
  type SlackAgentStatusIntentStore,
} from "../src/surfaces/slack-agent-status-intent.ts";
import { createSlackAgentSessionStore, type SlackAgentSessionStore } from "../src/surfaces/slack-agent-session.ts";

const input: SlackAgentStatusIntentInput = {
  teamId: "T1",
  agentId: "A1",
  channelId: "D1",
  threadTs: "1700000000.100000",
  authority: { kind: "binding", token: "binding:exact" },
  sourceTs: "1700000000.100001",
  sequence: 0,
  status: "processing",
  createSession: { initiatorUserId: "U1", title: "Exact request" },
};

function bridge(statuses: SlackAgentStatusIntentStore, sessions: SlackAgentSessionStore) {
  return {
    enqueueSlackAgentStatusIntent: (value: SlackAgentStatusIntentInput) => statuses.enqueue(value),
    claimSlackAgentStatusIntents: (value: { teamId: string; agentId: string; limit: number }) =>
      statuses.claimDue(value),
    slackAgentStatusIntentClaimActive: (claim: Parameters<SlackAgentStatusIntentStore["claimActive"]>[0]) =>
      statuses.claimActive(claim),
    completeSlackAgentStatusIntent: (claim: Parameters<SlackAgentStatusIntentStore["complete"]>[0]) =>
      statuses.complete(claim),
    deferSlackAgentStatusIntent: (
      claim: Parameters<SlackAgentStatusIntentStore["defer"]>[0],
      value: Parameters<SlackAgentStatusIntentStore["defer"]>[1],
    ) => statuses.defer(claim, value),
    failSlackAgentStatusIntent: (
      claim: Parameters<SlackAgentStatusIntentStore["fail"]>[0],
      value: Parameters<SlackAgentStatusIntentStore["fail"]>[1],
    ) => statuses.fail(claim, value),
    reopenSlackAgentStatusIntentAfterStaleEffect: (
      claim: Parameters<SlackAgentStatusIntentStore["reopenCurrentAfterStaleEffect"]>[0],
      value: Parameters<SlackAgentStatusIntentStore["reopenCurrentAfterStaleEffect"]>[1],
    ) => statuses.reopenCurrentAfterStaleEffect(claim, value),
    getSlackAgentStatusIntent: (value: Parameters<SlackAgentStatusIntentStore["get"]>[0]) => statuses.get(value),
    claimSlackAgentProviderWrite: (value: Parameters<SlackAgentSessionStore["claimProviderWrite"]>[0]) =>
      sessions.claimProviderWrite(value),
    deferSlackAgentProviderWrite: (value: Parameters<SlackAgentSessionStore["deferProviderWrite"]>[0]) =>
      sessions.deferProviderWrite(value),
    completeSlackAgentProviderWrite: (value: Parameters<SlackAgentSessionStore["completeProviderWrite"]>[0]) =>
      sessions.completeProviderWrite(value),
    releaseSlackAgentProviderWrite: (value: Parameters<SlackAgentSessionStore["releaseProviderWrite"]>[0]) =>
      sessions.releaseProviderWrite(value),
  };
}

test("status intents are replay-safe, source-ordered, and generation-fenced", async () => {
  let now = 100;
  const store = createSlackAgentStatusIntentStore(createMemoryMap<any>(), () => now);
  const first = await store.enqueue(input);
  assert.equal(first.disposition, "accepted");
  const replay = await store.enqueue(input);
  assert.equal(replay.disposition, "replayed");
  assert.equal(replay.record.intentId, first.record.intentId);
  await assert.rejects(
    () => store.enqueue({ ...input, status: "active", createSession: undefined }),
    /source collision/,
  );

  const [olderClaim] = await store.claimDue({ teamId: input.teamId, agentId: input.agentId, limit: 1 });
  assert.ok(olderClaim);
  now += 1;
  const latestInput: SlackAgentStatusIntentInput = {
    ...input,
    sequence: 10,
    status: "active",
    createSession: undefined,
  };
  const latest = await store.enqueue(latestInput);
  assert.equal(latest.disposition, "accepted");
  assert.equal(latest.record.generation, olderClaim.generation + 1);
  assert.equal(await store.complete(olderClaim), false);

  const staleReplay = await store.enqueue(input);
  assert.equal(staleReplay.disposition, "superseded");
  assert.equal(staleReplay.record.status, "active");
  const [latestClaim] = await store.claimDue({ teamId: input.teamId, agentId: input.agentId, limit: 1 });
  assert.ok(latestClaim);
  assert.equal(await store.complete(latestClaim), true);
  assert.equal((await store.get(input))?.state, "resolved");
});

test("a deferred status survives restart and reconciles only after the durable provider window", async () => {
  let now = 1_000;
  const statusBacking = createMemoryMap<any>();
  const sessionBacking = createMemoryMap<any>();
  const firstStatuses = createSlackAgentStatusIntentStore(statusBacking, () => now);
  const firstSessions = createSlackAgentSessionStore(sessionBacking, () => now);
  const calls: string[] = [];
  const firstClient = {
    apiCall: async (_method: string, args: Record<string, unknown>) => {
      calls.push(String(args.status));
      throw { code: "slack_webapi_rate_limited_error", retryAfter: 3, data: { error: "ratelimited" } };
    },
  };
  const firstResult = await requestSlackAgentStatusIntent(
    bridge(firstStatuses, firstSessions),
    firstClient,
    input,
    () => now,
  );
  assert.deepEqual(firstResult, { verdict: "pending", retryAt: 4_000 });
  assert.deepEqual(calls, ["processing"]);

  for (let replay = 0; replay < 10; replay++) {
    const replayed = await requestSlackAgentStatusIntent(
      bridge(firstStatuses, firstSessions),
      firstClient,
      input,
      () => now,
    );
    assert.equal(replayed.verdict, "pending");
  }
  assert.deepEqual(calls, ["processing"]);
  assert.equal((await firstStatuses.get(input))?.attempts, 0);

  await drainSlackAgentStatusIntents(
    bridge(firstStatuses, firstSessions),
    { apiCall: async () => void calls.push("too-early") },
    { teamId: input.teamId, agentId: input.agentId },
    () => now,
  );
  assert.deepEqual(calls, ["processing"]);

  now = 4_000;
  const restartedStatuses = createSlackAgentStatusIntentStore(statusBacking, () => now);
  const restartedSessions = createSlackAgentSessionStore(sessionBacking, () => now);
  await drainSlackAgentStatusIntents(
    bridge(restartedStatuses, restartedSessions),
    {
      apiCall: async (_method: string, args: Record<string, unknown>) => {
        calls.push(String(args.status));
      },
    },
    { teamId: input.teamId, agentId: input.agentId },
    () => now,
  );
  assert.deepEqual(calls, ["processing", "processing"]);
  assert.equal((await restartedStatuses.get(input))?.state, "resolved");
  assert.equal(await restartedSessions.retryWindow({ ...input, method: "agents.sessions.setStatus" }), null);
});

test("an exhausted short Retry-After durably fences the global provider scope", async () => {
  const now = 1_000;
  const statuses = createSlackAgentStatusIntentStore(createMemoryMap<any>(), () => now);
  const sessions = createSlackAgentSessionStore(createMemoryMap<any>(), () => now);
  let calls = 0;
  const result = await requestSlackAgentStatusIntent(
    bridge(statuses, sessions),
    {
      apiCall: async () => {
        calls += 1;
        throw { code: "slack_webapi_rate_limited_error", retryAfter: 0.001, data: { error: "ratelimited" } };
      },
    },
    input,
    () => now,
  );
  assert.equal(calls, 3);
  assert.deepEqual(result, { verdict: "pending", retryAt: 1_001 });
  assert.equal((await sessions.retryWindow({ ...input, method: "agents.sessions.setStatus" }))?.notBefore, 1_001);
  const otherSession = await sessions.claimProviderWrite({
    ...input,
    channelId: "D2",
    threadTs: "1700000000.200000",
    method: "agents.sessions.setStatus",
  });
  assert.equal(otherSession.acquired, false);
  if (!otherSession.acquired) assert.equal(otherSession.notBefore, 1_001);
});

test("a stale provider effect reopens a newer resolved status for convergence", async () => {
  let now = 100;
  const store = createSlackAgentStatusIntentStore(createMemoryMap<any>(), () => now);
  await store.enqueue(input);
  const [older] = await store.claimDue({ teamId: input.teamId, agentId: input.agentId, limit: 1 });
  assert.ok(older);
  now += 1;
  await store.enqueue({ ...input, sequence: 10, status: "active", createSession: undefined });
  const [newer] = await store.claimDue({ teamId: input.teamId, agentId: input.agentId, limit: 1 });
  assert.ok(newer);
  assert.equal(await store.complete(newer), true);
  const reopened = await store.reopenCurrentAfterStaleEffect(older, { retryAt: now + 1 });
  assert.equal(reopened?.state, "pending");
  assert.ok((reopened?.generation ?? 0) > newer.generation);
});

test("a missing durable status read never confirms a provider effect", async () => {
  const statuses = createSlackAgentStatusIntentStore(createMemoryMap<any>(), () => 100);
  const sessions = createSlackAgentSessionStore(createMemoryMap<any>(), () => 100);
  const durableBridge = bridge(statuses, sessions);

  await assert.rejects(
    () =>
      requestSlackAgentStatusIntent(
        {
          ...durableBridge,
          getSlackAgentStatusIntent: async () => null,
        },
        { apiCall: async () => undefined },
        input,
        () => 100,
      ),
    /durable read failed/,
  );
  assert.equal((await statuses.get(input))?.state, "resolved");
});
