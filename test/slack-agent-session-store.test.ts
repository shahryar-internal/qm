import assert from "node:assert/strict";
import { test } from "node:test";
import { createMemoryMap, type DurableMap } from "../src/persistence/durable-map.ts";
import {
  createSlackAgentSessionStore,
  slackAgentBindingToken,
  type SlackAgentSessionKey,
} from "../src/surfaces/slack-agent-session.ts";

const key: SlackAgentSessionKey = {
  teamId: "T1",
  agentId: "A1",
  channelId: "C1",
  threadTs: "1700000000.100000",
};
const ownerUserId = "U1";

function token(triggerTs: string, owner = ownerUserId): string {
  return slackAgentBindingToken(key, owner, triggerTs, key.threadTs);
}

async function begin(
  store: ReturnType<typeof createSlackAgentSessionStore>,
  triggerTs = key.threadTs,
  owner = ownerUserId,
) {
  return store.begin({
    ...key,
    ownerUserId: owner,
    token: token(triggerTs, owner),
    triggerTs,
    coreThreadRef: "ch:C1:1700000000.100000",
    authorityMessageTs: key.threadTs,
  });
}

async function settlePresentation(
  store: ReturnType<typeof createSlackAgentSessionStore>,
  runId: string,
  triggerTs = key.threadTs,
  owner = ownerUserId,
  outcome: "delivered" | "cancelled_clean" = "delivered",
): Promise<void> {
  const claim = await store.claimPresentation({ ...key, token: token(triggerTs, owner), runId });
  assert.ok(claim);
  assert.equal(await store.settlePresentation(claim, outcome), true);
}

function stop(eventId: string, eventTs: string, stoppedByUserId = "U2", streamingMessageTs: string[] = []) {
  return { ...key, eventId, eventTs, stoppedByUserId, streamingMessageTs };
}

test("a different channel participant can stop the exact session before submit across reconstruction", async () => {
  const backing = createMemoryMap<any>();
  const first = createSlackAgentSessionStore(backing, () => 1);
  assert.equal((await begin(first)).accepted, true);
  const prepared = await first.prepareSubmission({ ...key, token: token(key.threadTs) });
  assert.equal(prepared.binding?.submissionState, "pending");
  const stopped = await first.recordStop(stop("Ev-stop-submit", "1700000000.200000", "U2"));
  assert.equal(stopped.event.state, "pending");
  assert.equal(stopped.event.applicable, true);
  assert.equal(stopped.event.stoppedByUserId, "U2");
  assert.equal(stopped.record.bindings[0]?.ownerUserId, "U1");

  const restarted = createSlackAgentSessionStore(backing, () => 2);
  const bound = await restarted.bindRun({ ...key, token: token(key.threadTs), runId: "R1" });
  assert.equal(bound.accepted, true);
  assert.equal(bound.cancelled, true);
  assert.equal(await restarted.cancelled({ ...key, token: token(key.threadTs), runId: "R1" }), true);
  assert.equal(await restarted.complete({ ...key, token: token(key.threadTs) }), false);
  const claim = await restarted.claimPresentation({ ...key, token: token(key.threadTs), runId: "R1" });
  assert.ok(claim);
  assert.equal(await restarted.settlePresentation(claim, "delivered"), false);
  assert.equal(await restarted.settlePresentation(claim, "cancelled_clean"), true);
  assert.equal((await restarted.get(key))?.bindings[0]?.submissionState, "settled");
});

test("reaction cleanup authority requires the exact accepted binding and its durable cancel latch", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  const exactToken = token(key.threadTs);
  assert.equal(await store.cancellationLatched({ ...key, token: exactToken }), false);
  await begin(store);
  assert.equal(await store.cancellationLatched({ ...key, token: "binding:forged" }), false);
  assert.equal(await store.cancellationLatched({ ...key, token: exactToken }), false);
  await store.recordStop(stop("Ev-cleanup-authority", "1700000000.200000"));
  assert.equal(await store.cancellationLatched({ ...key, token: exactToken }), true);
  assert.equal(await store.cancellationLatched({ ...key, channelId: "C2", token: exactToken }), false);
});

test("session creation fields are claimed until processing succeeds and omitted on later turns", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  const first = await begin(store);
  assert.equal(first.created, true);
  assert.equal(await store.finish({ ...key, token: token(key.threadTs), status: "processing" }), true);
  assert.equal(await store.finish({ ...key, token: token(key.threadTs), status: "active" }), true);
  assert.equal(await store.complete({ ...key, token: token(key.threadTs) }), true);
  const next = await begin(store, "1700000000.150000");
  assert.equal(next.accepted, true);
  assert.equal(next.created, false);
});

test("a stop between run submission and stream checkpoint remains authoritative", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  await begin(store);
  await store.bindRun({ ...key, token: token(key.threadTs), runId: "R2" });
  await store.recordStop(stop("Ev-stop-stream", "1700000000.210000", "U2", ["1700000000.220000"]));
  const stream = await store.bindStream({ ...key, token: token(key.threadTs), streamTs: "1700000000.220000" });
  assert.equal(stream.accepted, true);
  assert.equal(stream.cancelled, true);
  assert.equal(stream.binding?.streamTs, "1700000000.220000");
});

test("submitted takeover can rebind the exact run after crashing before native bind", async () => {
  const backing = createMemoryMap<any>();
  const first = createSlackAgentSessionStore(backing);
  await begin(first);
  await first.prepareSubmission({ ...key, token: token(key.threadTs) });

  const restarted = createSlackAgentSessionStore(backing);
  const recovered = await begin(restarted);
  assert.equal(recovered.accepted, true);
  const rebound = await restarted.bindRun({ ...key, token: token(key.threadTs), runId: "R-recovered-bind" });
  assert.equal(rebound.accepted, true);
  assert.deepEqual(rebound.binding?.runIds, ["R-recovered-bind"]);
  await restarted.finish({ ...key, token: token(key.threadTs), status: "active" });
  await settlePresentation(restarted, "R-recovered-bind");
  assert.ok((await restarted.get(key))?.bindings[0]?.finishedAt);
  const afterCompletionCrash = await begin(restarted);
  assert.equal(typeof afterCompletionCrash.binding?.finishedAt, "number");
  assert.equal(afterCompletionCrash.binding?.submissionState, "settled");
  assert.equal(afterCompletionCrash.binding?.presentation?.state, "settled");
  await restarted.recordStop(stop("Ev-recovered-bind", "1700000000.200000"));
  assert.equal(await restarted.cancelled({ ...key, token: token(key.threadTs), runId: "R-recovered-bind" }), true);
  assert.equal((await restarted.get(key))?.bindings[0]?.presentation?.state, "pending");
});

test("approval generation fences delayed native completion after takeover", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>(), () => 1_700_000_000_250);
  const bindingToken = token(key.threadTs);
  const input = {
    ...key,
    ownerUserId,
    token: bindingToken,
    triggerTs: key.threadTs,
    coreThreadRef: "ch:C1:1700000000.100000",
    authorityMessageTs: key.threadTs,
  };
  const firstClaim = { claimId: "claim-1", generation: 1 };
  const takeoverClaim = { claimId: "claim-2", generation: 2 };

  assert.equal((await store.begin({ ...input, approvalClaim: firstClaim })).accepted, true);
  assert.equal((await store.bindRun({ ...key, token: bindingToken, runId: "R-fenced" })).accepted, true);
  const takeover = await store.begin({ ...input, approvalClaim: takeoverClaim });
  assert.equal(takeover.accepted, true);
  assert.deepEqual(takeover.binding?.approvalClaim, takeoverClaim);

  assert.equal(await store.finish({ ...key, token: bindingToken, status: "active", approvalClaim: firstClaim }), false);
  assert.equal(await store.complete({ ...key, token: bindingToken, approvalClaim: firstClaim }), false);
  assert.equal((await store.get(key))?.bindings[0]?.finishedAt, undefined);
  assert.equal(await store.complete({ ...key, token: bindingToken, approvalClaim: takeoverClaim }), true);
  assert.ok((await store.get(key))?.bindings[0]?.finishedAt);
});

test("normal run presentation ownership survives restart and fences stale settlement", async () => {
  let now = 1_000;
  const backing = createMemoryMap<any>();
  const first = createSlackAgentSessionStore(backing, () => now);
  await begin(first);
  await first.prepareSubmission({ ...key, token: token(key.threadTs) });
  await first.bindRun({ ...key, token: token(key.threadTs), runId: "R-presentation" });
  const original = await first.claimPresentation({
    ...key,
    token: token(key.threadTs),
    runId: "R-presentation",
  });
  assert.ok(original);
  assert.equal(await first.complete({ ...key, token: token(key.threadTs) }), false);

  const beforeExpiry = createSlackAgentSessionStore(backing, () => now);
  assert.deepEqual(await beforeExpiry.claimDuePresentations({ teamId: "T1", agentId: "A1", limit: 10 }), []);

  now = original.leaseExpiresAt;
  const restarted = createSlackAgentSessionStore(backing, () => now);
  const [takeover] = await restarted.claimDuePresentations({ teamId: "T1", agentId: "A1", limit: 10 });
  assert.ok(takeover);
  assert.equal(takeover.runId, "R-presentation");
  assert.equal(takeover.generation, original.generation + 1);
  assert.equal(await first.settlePresentation(original, "delivered"), false);
  assert.equal(await restarted.presentationClaimActive(takeover), true);
  assert.equal(await restarted.finish({ ...key, token: token(key.threadTs), status: "active" }), true);
  assert.equal(await restarted.settlePresentation(takeover, "delivered"), true);
  assert.ok((await restarted.get(key))?.bindings[0]?.finishedAt);
  assert.equal((await restarted.get(key))?.status, "active");
  assert.deepEqual(await restarted.claimDuePresentations({ teamId: "T1", agentId: "A1", limit: 10 }), []);
});

test("one session stop atomically latches every in-flight owner binding", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  const first = await begin(store, "1700000000.100000", "U1");
  const second = await begin(store, "1700000000.150000", "U3");
  await store.bindRun({ ...key, token: token("1700000000.100000", "U1"), runId: "R-owner-one" });
  await store.bindRun({ ...key, token: token("1700000000.150000", "U3"), runId: "R-owner-three" });
  const stopped = await store.recordStop(stop("Ev-all-bindings", "1700000000.200000", "U2"));

  assert.equal(first.binding?.ownerUserId, "U1");
  assert.equal(second.binding?.ownerUserId, "U3");
  assert.deepEqual(new Set(stopped.event.bindingTokens), new Set([first.binding?.token, second.binding?.token]));
  assert.equal(await store.cancelled({ ...key, token: token("1700000000.100000", "U1") }), true);
  assert.equal(await store.cancelled({ ...key, token: token("1700000000.150000", "U3") }), true);
});

test("session status remains processing until every in-flight binding leaves processing", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  await begin(store, "1700000000.100000", "U1");
  await begin(store, "1700000000.150000", "U3");
  await store.finish({ ...key, token: token("1700000000.100000", "U1"), status: "active" });
  await store.complete({ ...key, token: token("1700000000.100000", "U1") });
  assert.equal((await store.get(key))?.status, "processing");
  await store.finish({ ...key, token: token("1700000000.150000", "U3"), status: "suspended" });
  assert.equal((await store.get(key))?.status, "suspended");
});

test("cancelled bindings become terminal and repeated stop cycles remain prunable", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  for (let index = 0; index < 20; index++) {
    const triggerTs = `17000000${String(index).padStart(2, "0")}.100000`;
    const eventTs = `17000000${String(index).padStart(2, "0")}.200000`;
    const begun = await begin(store, triggerTs);
    assert.equal(begun.accepted, true);
    const stopped = await store.recordStop(stop(`Ev-cycle-${index}`, eventTs));
    assert.equal(stopped.event.applicable, true);
    assert.ok(stopped.record.bindings.find((binding) => binding.token === token(triggerTs))?.finishedAt);
    await store.acknowledgeStop({ ...key, eventId: `Ev-cycle-${index}` });
  }
  assert.ok(((await store.get(key))?.bindings.length ?? 0) <= 16);
});

test("listed and late-created streams retain distinct durable cancellation evidence", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  await begin(store);
  await store.recordStop(stop("Ev-stream-evidence", "1700000000.200000", "U2", ["1700000000.300000"]));
  const listed = await store.bindStream({
    ...key,
    token: token(key.threadTs),
    streamTs: "1700000000.300000",
  });
  assert.equal(listed.binding?.streamStopState, "listed");

  const secondTrigger = "1700000001.100000";
  await begin(store, secondTrigger);
  await store.recordStop(stop("Ev-stream-late", "1700000001.200000"));
  const late = await store.bindStream({ ...key, token: token(secondTrigger), streamTs: "1700000001.300000" });
  assert.equal(late.binding?.streamStopState, "late");
});

test("provider retry windows persist exact not-before time without poisoning later attempts", async () => {
  let now = 1;
  const store = createSlackAgentSessionStore(createMemoryMap<any>(), () => now);
  await begin(store);
  const method = "agents.sessions.setStatus";
  for (const notBefore of [90_000, 100_000, 110_000, 120_000, 130_000]) {
    const claimed = await store.claimProviderWrite({ ...key, method });
    assert.equal(claimed.acquired, true);
    assert.equal(
      (
        await store.deferProviderWrite({
          ...(claimed.acquired ? claimed.claim : assert.fail("provider write was not claimed")),
          notBefore,
        })
      ).applied,
      true,
    );
    now = notBefore;
  }
  assert.equal((await store.retryWindow({ ...key, method }))?.attempts, 5);
  assert.equal((await store.retryWindow({ ...key, method }))?.notBefore, 130_000);
  const sameWorkspace = { ...key, channelId: "D2", threadTs: "1700000002.100000" };
  const otherWorkspace = { ...sameWorkspace, teamId: "T2" };
  assert.equal((await store.retryWindow({ ...sameWorkspace, method }))?.notBefore, 130_000);
  assert.equal(await store.retryWindow({ ...otherWorkspace, method }), null);
  const recovered = await store.claimProviderWrite({ ...sameWorkspace, method });
  assert.equal(recovered.acquired, true);
  assert.equal(recovered.acquired ? await store.completeProviderWrite(recovered.claim) : false, true);
  assert.equal(await store.retryWindow({ ...key, method }), null);
});

test("an older provider success cannot clear a newer Retry-After generation", async () => {
  let now = 1_000;
  const backing = createMemoryMap<any>();
  const first = createSlackAgentSessionStore(backing, () => now);
  const method = "agents.sessions.setStatus";
  const older = await first.claimProviderWrite({ ...key, method });
  assert.equal(older.acquired, true);
  if (!older.acquired) return;
  let resolveOlderSuccess: (() => void) | undefined;
  const olderProviderCall = new Promise<void>((resolve) => {
    resolveOlderSuccess = resolve;
  });
  const olderCompletion = olderProviderCall.then(() => first.completeProviderWrite(older.claim));

  now = older.claim.leaseExpiresAt;
  const restarted = createSlackAgentSessionStore(backing, () => now);
  const newer = await restarted.claimProviderWrite({ ...key, method });
  assert.equal(newer.acquired, true);
  if (!newer.acquired) return;
  const newerNotBefore = now + 90_000;
  const deferred = await restarted.deferProviderWrite({ ...newer.claim, notBefore: newerNotBefore });
  assert.equal(deferred.applied, true);

  resolveOlderSuccess!();
  assert.equal(await olderCompletion, false);
  assert.equal((await first.retryWindow({ ...key, method }))?.notBefore, newerNotBefore);
});

test("a Retry-After release admits one provider call across a restart without a stampede", async () => {
  let now = 10_000;
  const backing = createMemoryMap<any>();
  const first = createSlackAgentSessionStore(backing, () => now);
  const method = "chat.stopStream";
  const seed = await first.claimProviderWrite({ ...key, method });
  assert.equal(seed.acquired, true);
  if (!seed.acquired) return;
  const releaseAt = now + 30_000;
  assert.equal((await first.deferProviderWrite({ ...seed.claim, notBefore: releaseAt })).applied, true);

  now = releaseAt - 1;
  const beforeRelease = await Promise.all(
    Array.from({ length: 8 }, () => first.claimProviderWrite({ ...key, method })),
  );
  assert.equal(
    beforeRelease.every((result) => !result.acquired && result.notBefore === releaseAt),
    true,
  );

  now = releaseAt;
  const restarted = createSlackAgentSessionStore(backing, () => now);
  const atRelease = await Promise.all(
    Array.from({ length: 8 }, () => restarted.claimProviderWrite({ ...key, method })),
  );
  const winners = atRelease.filter((result) => result.acquired);
  assert.equal(winners.length, 1);
  assert.equal(
    atRelease.filter((result) => !result.acquired).every((result) => result.reason === "lease_held"),
    true,
  );

  const afterSecondRestart = createSlackAgentSessionStore(backing, () => now);
  const stillLeased = await afterSecondRestart.claimProviderWrite({ ...key, method });
  assert.equal(stillLeased.acquired, false);
  if (!stillLeased.acquired) assert.equal(stillLeased.reason, "lease_held");
});

test("provider write leases isolate exact workspace, agent, and method scopes", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>(), () => 1_000);
  const held = await store.claimProviderWrite({ ...key, method: "agents.sessions.setStatus" });
  assert.equal(held.acquired, true);

  const sameScopeOtherChannel = await store.claimProviderWrite({
    ...key,
    channelId: "D2",
    threadTs: "1700000002.100000",
    method: "agents.sessions.setStatus",
  });
  assert.equal(sameScopeOtherChannel.acquired, false);
  if (!sameScopeOtherChannel.acquired) {
    assert.equal(sameScopeOtherChannel.reason, "lease_held");
    assert.equal(sameScopeOtherChannel.sameSession, false);
  }

  assert.equal(
    (await store.claimProviderWrite({ ...key, teamId: "T2", method: "agents.sessions.setStatus" })).acquired,
    true,
  );
  assert.equal(
    (await store.claimProviderWrite({ ...key, agentId: "A2", method: "agents.sessions.setStatus" })).acquired,
    true,
  );
  assert.equal((await store.claimProviderWrite({ ...key, method: "chat.stopStream" })).acquired, true);
});

test("stop replay stays pending until confirmation is durably acknowledged", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  await begin(store);
  const input = stop("Ev-replay", "1700000000.300000");
  const first = await store.recordStop(input);
  const replay = await store.recordStop(input);
  assert.equal(first.event.state, "pending");
  assert.equal(replay.replay, true);
  assert.equal(replay.event.state, "pending");
  assert.equal(
    await store.acknowledgeStop({ ...key, eventId: input.eventId, confirmationTs: "1700000000.310000" }),
    true,
  );
  const acknowledged = await store.recordStop(input);
  assert.equal(acknowledged.replay, true);
  assert.equal(acknowledged.event.state, "acknowledged");
  const duplicateClick = await store.recordStop(stop("Ev-replay-second", "1700000000.320000", "U1"));
  assert.equal(duplicateClick.event.applicable, false);
  assert.equal(duplicateClick.event.state, "acknowledged");
});

test("a pending stop and its exact binding survive more than sixteen later stop records", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  await begin(store);
  await store.bindRun({ ...key, token: token(key.threadTs), runId: "R-pending-prune" });
  const pending = stop("Ev-pending-prune", "1700000000.300000");
  assert.equal((await store.recordStop(pending)).event.state, "pending");

  for (let index = 0; index < 20; index += 1) {
    const triggerTs = `18000000${String(index + 1).padStart(2, "0")}.100000`;
    assert.equal((await begin(store, triggerTs)).accepted, true);
    await store.finish({ ...key, token: token(triggerTs), status: "active" });
    await store.complete({ ...key, token: token(triggerTs) });
  }

  for (let index = 0; index < 20; index += 1) {
    await store.recordStop(stop(`Ev-later-${index}`, `17000000${String(index + 1).padStart(2, "0")}.400000`));
  }

  const replay = await store.recordStop(pending);
  assert.equal(replay.replay, true);
  assert.equal(replay.event.state, "pending");
  assert.deepEqual(replay.event.bindingTokens, [token(key.threadTs)]);
  assert.equal(
    replay.record.bindings.find((binding) => binding.token === token(key.threadTs))?.runIds.includes("R-pending-prune"),
    true,
  );
});

test("an unsettled stopped presentation survives binding pruning after stop acknowledgment", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  await begin(store);
  await store.prepareSubmission({ ...key, token: token(key.threadTs) });
  await store.bindRun({ ...key, token: token(key.threadTs), runId: "R-presentation-prune" });
  const stopped = stop("Ev-presentation-prune", "1700000000.300000");
  assert.equal((await store.recordStop(stopped)).event.applicable, true);
  assert.equal(await store.acknowledgeStop({ ...key, eventId: stopped.eventId }), true);

  for (let index = 0; index < 20; index += 1) {
    const triggerTs = `18000001${String(index + 1).padStart(2, "0")}.100000`;
    assert.equal((await begin(store, triggerTs)).accepted, true);
    await store.finish({ ...key, token: token(triggerTs), status: "active" });
    await store.complete({ ...key, token: token(triggerTs) });
  }

  const record = await store.get(key);
  assert.equal(
    record?.bindings.find((binding) => binding.token === token(key.threadTs))?.presentation?.state,
    "pending",
  );
  const claims = await store.claimDuePresentations({ teamId: key.teamId, agentId: key.agentId, limit: 100 });
  assert.equal(
    claims.some((claim) => claim.runId === "R-presentation-prune"),
    true,
  );
});

test("an atomic stop failure never creates process-local cancellation authority", async () => {
  const backing = createMemoryMap<any>();
  const baseUpdate = backing.update!.bind(backing);
  let fail = false;
  const failing: DurableMap<any> = {
    ...backing,
    update: async (id, fn) => {
      if (fail) throw new Error("database unavailable");
      return baseUpdate(id, fn);
    },
  };
  const store = createSlackAgentSessionStore(failing);
  await begin(store);
  fail = true;
  await assert.rejects(store.recordStop(stop("Ev-db", "1700000000.400000")), /database unavailable/);
  fail = false;
  assert.equal(await store.cancelled({ ...key, token: token(key.threadTs) }), false);
});

test("an orphan stop is acknowledged without poisoning a later turn", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  const stopped = await store.recordStop(stop("Ev-orphan", "1700000000.500000"));
  assert.equal(stopped.event.applicable, false);
  assert.equal(stopped.event.state, "acknowledged");
  const later = await begin(store, "1700000000.600000");
  assert.equal(later.accepted, true);
  assert.equal(later.cancelled, false);
});

test("an acknowledged out-of-order stop atomically cancels its later-arriving trigger", async () => {
  const backing = createMemoryMap<any>();
  const first = createSlackAgentSessionStore(backing, () => 1_700_000_000_700);
  const stopped = await first.recordStop(stop("Ev-out-of-order", "1700000000.500000"));
  assert.equal(stopped.event.state, "acknowledged");
  assert.equal(stopped.event.applicable, false);

  const restarted = createSlackAgentSessionStore(backing, () => 1_700_000_000_800);
  const delayedTrigger = await begin(restarted, "1700000000.400000");
  assert.equal(delayedTrigger.accepted, true);
  assert.equal(delayedTrigger.cancelled, true);
  assert.equal(delayedTrigger.binding?.cancelEventId, "Ev-out-of-order");
  assert.equal(delayedTrigger.binding?.cancelRequestedAt, "1700000000.500000");
  assert.deepEqual(delayedTrigger.record?.stopEvents[0]?.bindingTokens, [token("1700000000.400000")]);
  assert.equal(delayedTrigger.record?.stopEvents[0]?.state, "acknowledged");
});

test("one out-of-order stop cancels every delayed binding through its causal timestamp", async () => {
  const backing = createMemoryMap<any>();
  const first = createSlackAgentSessionStore(backing, () => 1_700_000_000_700);
  await first.recordStop(stop("Ev-causal-frontier", "1700000000.500000"));

  const restarted = createSlackAgentSessionStore(backing, () => 1_700_000_000_800);
  const delayedOne = await begin(restarted, "1700000000.300000", "U1");
  const delayedTwo = await begin(restarted, "1700000000.400000", "U3");
  const later = await begin(restarted, "1700000000.500001", "U4");

  assert.equal(delayedOne.cancelled, true);
  assert.equal(delayedTwo.cancelled, true);
  assert.equal(later.cancelled, false);
  assert.deepEqual(
    new Set(delayedTwo.record?.stopEvents[0]?.bindingTokens),
    new Set([token("1700000000.300000", "U1"), token("1700000000.400000", "U3")]),
  );
});

test("a pruned stop still fences every delayed binding through the durable causal frontier", async () => {
  const backing = createMemoryMap<any>();
  const first = createSlackAgentSessionStore(backing, () => 1_700_000_000_700);
  await first.recordStop(stop("Ev-frontier", "1700000100.500000"));
  for (let index = 0; index < 20; index += 1) {
    await first.recordStop(stop(`Ev-older-${index}`, `17000000${String(index).padStart(2, "0")}.500000`));
  }

  const restarted = createSlackAgentSessionStore(backing, () => 1_700_000_000_800);
  const delayedOne = await begin(restarted, "1700000100.300000", "U1");
  const delayedTwo = await begin(restarted, "1700000100.400000", "U3");
  const later = await begin(restarted, "1700000100.500001", "U4");

  assert.equal(delayedOne.cancelled, true);
  assert.equal(delayedTwo.cancelled, true);
  assert.equal(later.cancelled, false);
  assert.equal(delayedTwo.binding?.cancelEventId, "Ev-frontier");
});

test("an acknowledged orphan older than a later trigger remains a prior-turn stop", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  await store.recordStop(stop("Ev-prior-turn", "1700000000.500000"));
  const later = await begin(store, "1700000000.500001");
  assert.equal(later.accepted, true);
  assert.equal(later.cancelled, false);
  assert.equal(later.binding?.cancelEventId, undefined);
  assert.deepEqual(later.record?.stopEvents[0]?.bindingTokens, []);
});

test("a delayed pre-completion stop fences downstream work after completion was recorded", async () => {
  let now = 1_700_000_000_250;
  const store = createSlackAgentSessionStore(createMemoryMap<any>(), () => now);
  await begin(store);
  await store.bindRun({ ...key, token: token(key.threadTs), runId: "R-delayed" });
  assert.equal(await store.finish({ ...key, token: token(key.threadTs), status: "active" }), true);
  assert.equal(await store.complete({ ...key, token: token(key.threadTs) }), true);
  now += 10;
  const stopped = await store.recordStop(stop("Ev-delayed", "1700000000.200000"));
  assert.equal(stopped.event.applicable, true);
  assert.equal(await store.cancelled({ ...key, token: token(key.threadTs), runId: "R-delayed" }), true);
});

test("a stop created after the durable completion boundary does not retroactively cancel", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>(), () => 1_700_000_000_250);
  await begin(store);
  assert.equal(await store.finish({ ...key, token: token(key.threadTs), status: "active" }), true);
  assert.equal(await store.complete({ ...key, token: token(key.threadTs) }), true);
  const stopped = await store.recordStop(stop("Ev-after", "1700000000.300000"));
  assert.equal(stopped.event.applicable, false);
  assert.equal(await store.cancelled({ ...key, token: token(key.threadTs) }), false);
});

test("title changes retain binding ownership only as request audit", async () => {
  const store = createSlackAgentSessionStore(createMemoryMap<any>());
  await begin(store);
  assert.equal(
    await store.rename({
      ...key,
      changedByUserId: "U-EDITOR",
      title: "Quarter plan",
      eventTs: "1700000000.700000",
    }),
    true,
  );
  assert.equal((await store.get(key))?.bindings[0]?.ownerUserId, "U1");
  assert.equal((await store.get(key))?.titleChangedBy, "U-EDITOR");
  assert.equal(
    await store.rename({
      ...key,
      channelId: "not-a-channel",
      changedByUserId: "U-EDITOR",
      title: "Leak",
      eventTs: "1700000000.800000",
    }),
    false,
  );
  assert.equal(
    await store.rename({
      ...key,
      changedByUserId: "U-EDITOR-2",
      title: "Stale",
      eventTs: "1700000000.650000",
    }),
    false,
  );
  assert.equal((await store.get(key))?.title, "Quarter plan");
});
