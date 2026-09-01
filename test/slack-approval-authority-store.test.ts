import assert from "node:assert/strict";
import { test } from "node:test";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { createSlackApprovalAuthorityStore } from "../src/surfaces/slack-approval-authority.ts";

const authority = {
  teamId: "T1",
  agentId: "A1",
  requesterUserId: "U1",
  requestId: "approval-1",
  channelId: "D9",
  messageTs: "1700000000.000001",
};

test("approval click authority survives restart and cannot move to another message", async () => {
  const backing = createMemoryMap<any>();
  const first = createSlackApprovalAuthorityStore(backing, () => 10);
  assert.equal(await first.bind(authority), true);

  const restarted = createSlackApprovalAuthorityStore(backing, () => 20);
  assert.deepEqual(await restarted.get(authority), { ...authority, createdAt: 10 });
  assert.equal(await restarted.bind({ ...authority, messageTs: "1700000000.000002" }), false);
  assert.deepEqual(await restarted.get(authority), { ...authority, createdAt: 10 });
});

test("an existing message authority is enriched with durable recovery context", async () => {
  const store = createSlackApprovalAuthorityStore(createMemoryMap<any>(), () => 10);
  assert.equal(await store.bind(authority), true);
  const recovery = {
    command: "send-email",
    reason: "external write",
    agentRequest: {
      requesterId: "U1",
      targetUserId: "U2",
      originChannel: "C1",
      originThreadOnly: true,
      dmChannel: "D9",
      task: "send it",
      originAgentLabel: "channel agent",
      targetAgentLabel: "personal agent",
    },
    request: { text: "send it" },
  };
  assert.equal(await store.bind({ ...authority, recovery }), true);
  assert.deepEqual((await store.get(authority))?.recovery, recovery);
});

test("approval click authority fails closed across owner and malformed channel boundaries", async () => {
  const store = createSlackApprovalAuthorityStore(createMemoryMap<any>());
  assert.equal(await store.bind(authority), true);
  assert.equal(await store.get({ ...authority, requesterUserId: "U2" }), null);
  assert.equal(await store.bind({ ...authority, requestId: "approval-2", channelId: "not-a-channel" }), false);
});

test("approval continuation admission coalesces blue-green clicks and resumes durably", async () => {
  let now = 100;
  const backing = createMemoryMap<any>();
  const first = createSlackApprovalAuthorityStore(backing, () => now);
  const second = createSlackApprovalAuthorityStore(backing, () => now);
  await first.bind(authority);
  const click = {
    ...authority,
    actionId: "hilo_allow_once" as const,
    actionTs: "1700000000.100001",
    clickerUserId: "U1",
  };

  const competing = await Promise.all([first.admitContinuation(click), second.admitContinuation(click)]);
  const winner = competing.find((result) => result.acquired);
  const loser = competing.find((result) => !result.acquired);
  assert.ok(winner?.acquired);
  assert.equal(loser?.acquired, false);
  if (!winner?.acquired || loser?.acquired !== false) return;
  assert.equal(loser.reason, "busy");
  assert.match(winner.claim.idempotencyKey, /^slack-approval:[a-f0-9]{64}$/);

  now = 60_101;
  const restarted = createSlackApprovalAuthorityStore(backing, () => now);
  const resumed = await restarted.admitContinuation({ ...click, actionTs: "1700000000.100002" });
  assert.equal(resumed.acquired, true);
  if (!resumed.acquired) return;
  assert.equal(resumed.resumed, true);
  assert.equal(resumed.claim.actionTs, "1700000000.100002");
  assert.equal(resumed.claim.idempotencyKey, winner.claim.idempotencyKey);
  assert.equal(await first.releaseContinuation(winner.claim), false);
  assert.equal(await restarted.markContinuationSubmitted({ ...resumed.claim, runId: "R-approval" }), true);
  now = 1_000_000;
  const submittedReplay = await first.admitContinuation(click);
  assert.equal(submittedReplay.acquired, true);
  if (!submittedReplay.acquired) return;
  assert.equal(submittedReplay.resumed, true);
  assert.equal(submittedReplay.claim.runId, "R-approval");
  assert.equal(submittedReplay.claim.idempotencyKey, resumed.claim.idempotencyKey);
  assert.equal(submittedReplay.claim.generation, resumed.claim.generation + 1);
  assert.equal(await restarted.settleContinuation(resumed.claim), false);
  assert.equal(await first.settleContinuation(submittedReplay.claim), true);

  const settledReplay = await first.admitContinuation(click);
  assert.equal(settledReplay.acquired, false);
  if (!settledReplay.acquired) assert.equal(settledReplay.reason, "settled");
});

test("submitted approval recovery lists only expired exact run continuations", async () => {
  let now = 100;
  const store = createSlackApprovalAuthorityStore(createMemoryMap<any>(), () => now);
  await store.bind(authority);
  const admitted = await store.admitContinuation({
    ...authority,
    actionId: "hilo_deny",
    actionTs: "1700000000.100001",
    clickerUserId: "U1",
  });
  assert.equal(admitted.acquired, true);
  if (!admitted.acquired) return;
  assert.equal(await store.markContinuationSubmitted({ ...admitted.claim, runId: "R-deny" }), true);
  assert.deepEqual(await store.recoverableContinuations({ teamId: "T1", agentId: "A1", limit: 10 }), []);

  now += 60_001;
  assert.deepEqual(await store.recoverableContinuations({ teamId: "T1", agentId: "A1", limit: 10 }), [
    {
      ...authority,
      actionId: "hilo_deny",
      actionTs: "1700000000.100001",
      clickerUserId: "U1",
    },
  ]);
});

test("submitted approval outbox repairs a crash before the authority checkpoint and drains on settlement", async () => {
  let now = 100;
  const authorityBacking = createMemoryMap<any>();
  const pendingBacking = createMemoryMap<any>();
  const baseUpdate = authorityBacking.update!.bind(authorityBacking);
  let failUpdate = false;
  authorityBacking.update = async (id, fn) => {
    if (failUpdate) {
      failUpdate = false;
      throw new Error("checkpoint interrupted");
    }
    return baseUpdate(id, fn);
  };
  const first = createSlackApprovalAuthorityStore(authorityBacking, () => now, pendingBacking);
  await first.bind(authority);
  const admitted = await first.admitContinuation({
    ...authority,
    actionId: "hilo_allow_once",
    actionTs: "1700000000.100001",
    clickerUserId: "U1",
  });
  assert.equal(admitted.acquired, true);
  if (!admitted.acquired) return;
  failUpdate = true;
  await assert.rejects(first.markContinuationSubmitted({ ...admitted.claim, runId: "R-repair" }), /interrupted/);
  assert.equal((await pendingBacking.all()).length, 1);

  const restarted = createSlackApprovalAuthorityStore(authorityBacking, () => now, pendingBacking);
  const submitted = await restarted.submittedContinuations({ teamId: "T1", agentId: "A1" });
  assert.equal(submitted[0]?.runId, "R-repair");
  assert.equal((await restarted.get(authority))?.continuation?.state, "submitted");

  now += 60_001;
  const takeover = await restarted.admitContinuation({
    ...authority,
    actionId: "hilo_allow_once",
    actionTs: "1700000000.100002",
    clickerUserId: "U1",
  });
  assert.equal(takeover.acquired, true);
  if (!takeover.acquired) return;
  assert.equal(takeover.claim.runId, "R-repair");
  assert.equal(await restarted.settleContinuation(takeover.claim), true);
  assert.deepEqual(
    (await pendingBacking.all()).filter((record) => record.kind === "slack_approval_continuation"),
    [],
  );
});

test("a committed approval settlement survives outbox cleanup failure", async () => {
  const authorityBacking = createMemoryMap<any>();
  const pendingBacking = createMemoryMap<any>();
  const baseDelete = pendingBacking.delete.bind(pendingBacking);
  let failDelete = false;
  pendingBacking.delete = async (id) => {
    if (failDelete) {
      failDelete = false;
      throw new Error("cleanup interrupted");
    }
    await baseDelete(id);
  };
  const store = createSlackApprovalAuthorityStore(authorityBacking, () => 100, pendingBacking);
  await store.bind(authority);
  const admitted = await store.admitContinuation({
    ...authority,
    actionId: "hilo_deny",
    actionTs: "1700000000.100001",
    clickerUserId: "U1",
  });
  assert.equal(admitted.acquired, true);
  if (!admitted.acquired) return;
  await store.markContinuationSubmitted({ ...admitted.claim, runId: "R-settle" });
  failDelete = true;
  assert.equal(await store.settleContinuation(admitted.claim), true);
  assert.equal((await store.get(authority))?.continuation?.state, "settled");
  assert.deepEqual(await store.submittedContinuations({ teamId: "T1", agentId: "A1" }), []);
});

test("continuation discovery cannot prune an admission before its authority commit", async () => {
  const authorityBacking = createMemoryMap<any>();
  const pendingBacking = createMemoryMap<any>();
  const baseUpdate = authorityBacking.update!.bind(authorityBacking);
  let releaseUpdate!: () => void;
  const updateGate = new Promise<void>((resolve) => (releaseUpdate = resolve));
  let updateStarted!: () => void;
  const started = new Promise<void>((resolve) => (updateStarted = resolve));
  let hold = false;
  authorityBacking.update = async (id, fn) => {
    if (hold) {
      updateStarted();
      await updateGate;
    }
    return baseUpdate(id, fn);
  };
  const store = createSlackApprovalAuthorityStore(authorityBacking, () => 100, pendingBacking);
  await store.bind(authority);
  hold = true;
  const admission = store.admitContinuation({
    ...authority,
    actionId: "hilo_allow_once",
    actionTs: "1700000000.100001",
    clickerUserId: "U1",
  });
  await started;
  assert.deepEqual(await store.submittedContinuations({ teamId: "T1", agentId: "A1" }), []);
  assert.equal(
    (await pendingBacking.all()).filter((record) => record.kind === "slack_approval_continuation").length,
    1,
  );
  releaseUpdate();
  assert.equal((await admission).acquired, true);
  assert.equal(
    (await pendingBacking.all()).filter((record) => record.kind === "slack_approval_continuation").length,
    1,
  );
});

test("a stale submitted writer cannot erase a newer generation's outbox", async () => {
  let now = 100;
  const authorityBacking = createMemoryMap<any>();
  const pendingBacking = createMemoryMap<any>();
  const store = createSlackApprovalAuthorityStore(authorityBacking, () => now, pendingBacking);
  await store.bind(authority);
  const first = await store.admitContinuation({
    ...authority,
    actionId: "hilo_allow_once",
    actionTs: "1700000000.100001",
    clickerUserId: "U1",
  });
  assert.equal(first.acquired, true);
  if (!first.acquired) return;
  now += 60_001;
  const second = await store.admitContinuation({
    ...authority,
    actionId: "hilo_allow_once",
    actionTs: "1700000000.100002",
    clickerUserId: "U1",
  });
  assert.equal(second.acquired, true);
  if (!second.acquired) return;
  assert.equal(await store.markContinuationSubmitted({ ...second.claim, runId: "R-new" }), true);
  assert.equal(await store.markContinuationSubmitted({ ...first.claim, runId: "R-old" }), false);
  assert.equal((await store.submittedContinuations({ teamId: "T1", agentId: "A1" }))[0]?.runId, "R-new");
});

test("legacy reconciliation repeats during cutover and discovers a late old-writer submission", async () => {
  let now = 100;
  const authorityBacking = createMemoryMap<any>();
  const pendingBacking = createMemoryMap<any>();
  const store = createSlackApprovalAuthorityStore(authorityBacking, () => now, pendingBacking);
  assert.deepEqual(await store.submittedContinuations({ teamId: "T1", agentId: "A1" }), []);
  await store.bind(authority);
  const admitted = await store.admitContinuation({
    ...authority,
    actionId: "hilo_allow_once",
    actionTs: "1700000000.100001",
    clickerUserId: "U1",
  });
  assert.equal(admitted.acquired, true);
  if (!admitted.acquired) return;
  await store.markContinuationSubmitted({ ...admitted.claim, runId: "R-late-legacy" });
  for (const [id, record] of await pendingBacking.entries()) {
    if (record.kind === "slack_approval_continuation") await pendingBacking.delete(id);
  }
  now += 60_001;
  assert.equal((await store.submittedContinuations({ teamId: "T1", agentId: "A1" }))[0]?.runId, "R-late-legacy");
});

test("concurrent startup waits for the winning legacy scan before returning submitted pins", async () => {
  const authorityBacking = createMemoryMap<any>();
  const pendingBacking = createMemoryMap<any>();
  const setup = createSlackApprovalAuthorityStore(authorityBacking, () => 100, pendingBacking);
  await setup.bind(authority);
  const admitted = await setup.admitContinuation({
    ...authority,
    actionId: "hilo_allow_once",
    actionTs: "1700000000.100001",
    clickerUserId: "U1",
  });
  assert.equal(admitted.acquired, true);
  if (!admitted.acquired) return;
  await setup.markContinuationSubmitted({ ...admitted.claim, runId: "R-startup-pin" });
  for (const [id, record] of await pendingBacking.entries()) {
    if (record.kind === "slack_approval_continuation") await pendingBacking.delete(id);
  }

  const baseAll = authorityBacking.all.bind(authorityBacking);
  let releaseScan!: () => void;
  const scanGate = new Promise<void>((resolve) => (releaseScan = resolve));
  let scanStarted!: () => void;
  const started = new Promise<void>((resolve) => (scanStarted = resolve));
  let held = true;
  authorityBacking.all = async () => {
    if (held) {
      held = false;
      scanStarted();
      await scanGate;
    }
    return baseAll();
  };
  const first = createSlackApprovalAuthorityStore(authorityBacking, () => 100, pendingBacking);
  const second = createSlackApprovalAuthorityStore(authorityBacking, () => 100, pendingBacking);
  const firstPins = first.submittedContinuations({ teamId: "T1", agentId: "A1" });
  await started;
  let secondReturned = false;
  const secondPins = second.submittedContinuations({ teamId: "T1", agentId: "A1" }).then((pins) => {
    secondReturned = true;
    return pins;
  });
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(secondReturned, false);
  releaseScan();
  assert.equal((await firstPins)[0]?.runId, "R-startup-pin");
  assert.equal((await secondPins)[0]?.runId, "R-startup-pin");
});

test("the first durable approval decision rejects a conflicting later click", async () => {
  const store = createSlackApprovalAuthorityStore(createMemoryMap<any>(), () => 100);
  await store.bind(authority);
  const first = await store.admitContinuation({
    ...authority,
    actionId: "hilo_allow_once",
    actionTs: "1700000000.100001",
    clickerUserId: "U1",
  });
  assert.equal(first.acquired, true);
  const conflict = await store.admitContinuation({
    ...authority,
    actionId: "hilo_deny",
    actionTs: "1700000000.100002",
    clickerUserId: "U1",
  });
  assert.equal(conflict.acquired, false);
  if (!conflict.acquired) assert.equal(conflict.reason, "conflict");
});
