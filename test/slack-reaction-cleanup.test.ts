import assert from "node:assert/strict";
import { test } from "node:test";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { applyReactions } from "../src/slack/reactions.ts";
import { drainSlackReactionCleanups, type SlackReactionCleanupBridge } from "../src/slack/reaction-cleanup.ts";
import { applyAndLogReactions } from "../src/slack/messaging.ts";
import {
  createSlackReactionCleanupStore,
  recoverSlackReactionCleanupAdmissions,
  type SlackReactionCleanupInput,
  type SlackReactionCleanupStore,
} from "../src/surfaces/slack-reaction-cleanup.ts";
import {
  createSlackReactionDesireStore,
  type SlackReactionDesireInput,
} from "../src/surfaces/slack-reaction-desire.ts";
import { createSlackAgentSessionStore, slackAgentBindingToken } from "../src/surfaces/slack-agent-session.ts";

const input: SlackReactionCleanupInput = {
  teamId: "T1",
  agentId: "A1",
  sessionChannelId: "D1",
  sessionThreadTs: "1700000000.100000",
  sessionToken: "binding:exact",
  effectId: "reaction-effect:first",
  sourceTs: "1700000000.100001",
  sequence: 100,
  channelId: "D1",
  messageTs: "1700000000.100000",
  name: "eyes",
};

function bridge(store: SlackReactionCleanupStore): SlackReactionCleanupBridge {
  return {
    enqueueSlackReactionCleanup: (value) => store.enqueue(value),
    claimSlackReactionCleanups: (value) => store.claimDue(value),
    slackReactionCleanupAction: async (claim) =>
      (await store.claimActive(claim)) ? { action: "remove", desireGeneration: 0, desireEffectId: null } : "stale",
    completeSlackReactionCleanup: (claim) => store.complete(claim),
    failSlackReactionCleanup: (claim, value) => store.fail(claim, value),
    reopenSlackReactionCleanupAfterStaleEffect: (claim, value) => store.reopenAfterStaleEffect(claim, value),
    getSlackReactionCleanup: (value) => store.get(value),
  };
}

function desireBridge(
  cleanupStore: SlackReactionCleanupStore,
  desireStore: ReturnType<typeof createSlackReactionDesireStore>,
): SlackReactionCleanupBridge {
  const base = bridge(cleanupStore);
  const decision = async (
    claim: Parameters<SlackReactionCleanupBridge["slackReactionCleanupAction"]>[0],
  ): ReturnType<SlackReactionCleanupBridge["slackReactionCleanupAction"]> => {
    if (!(await cleanupStore.claimActive(claim))) return "stale";
    const current = await desireStore.get(claim);
    return current?.desired
      ? { action: "preserve", desireGeneration: current.generation, desireEffectId: current.effectId }
      : {
          action: "remove",
          desireGeneration: current?.generation ?? 0,
          desireEffectId: current?.effectId ?? null,
        };
  };
  return {
    ...base,
    slackReactionCleanupAction: decision,
    completeSlackReactionCleanup: async (claim, expected) => {
      const before = await decision(claim);
      if (
        before === "stale" ||
        before.action !== expected.action ||
        before.desireGeneration !== expected.desireGeneration ||
        before.desireEffectId !== expected.desireEffectId
      ) {
        return false;
      }
      if (!(await cleanupStore.complete(claim))) return false;
      const current = await desireStore.get(claim);
      const after = current?.desired
        ? { action: "preserve", desireGeneration: current.generation, desireEffectId: current.effectId }
        : {
            action: "remove",
            desireGeneration: current?.generation ?? 0,
            desireEffectId: current?.effectId ?? null,
          };
      if (
        after.action === expected.action &&
        after.desireGeneration === expected.desireGeneration &&
        after.desireEffectId === expected.desireEffectId
      ) {
        return true;
      }
      await cleanupStore.reopenAfterDecisionChange(claim, { retryAt: 0 });
      return false;
    },
  };
}

test("reaction cleanup enqueue is exact, durable, and idempotent", async () => {
  const store = createSlackReactionCleanupStore(createMemoryMap(), () => 100);
  const first = await store.enqueue(input);
  const replay = await store.enqueue(input);
  assert.deepEqual(replay, first);
  assert.equal(first.status, "pending");
  assert.equal(await store.get({ teamId: "T2", agentId: "A1", id: first.id }), null);
  await assert.rejects(() => store.enqueue({ ...input, messageTs: "not-a-timestamp" }), /invalid/);
});

test("reaction cleanup identities cannot collide across sessions, workspaces, or targets", async () => {
  const store = createSlackReactionCleanupStore(createMemoryMap(), () => 100);
  const records = await Promise.all([
    store.enqueue(input),
    store.enqueue({ ...input, sessionToken: "binding:other" }),
    store.enqueue({ ...input, effectId: "reaction-effect:fresh" }),
    store.enqueue({ ...input, teamId: "T2" }),
    store.enqueue({ ...input, messageTs: "1700000000.200000" }),
    store.enqueue({ ...input, name: "tada" }),
  ]);
  assert.equal(new Set(records.map((record) => record.id)).size, records.length);
});

test("fresh identical reaction landings remove twice while an exact landing replay removes once", async () => {
  const store = createSlackReactionCleanupStore(createMemoryMap<any>(), () => 100);
  const cleanupBridge = bridge(store);
  let removals = 0;
  const client = {
    reactions: {
      add: async () => {},
      remove: async () => {
        removals += 1;
      },
    },
  };
  const first = await store.enqueue(input);
  await drainSlackReactionCleanups(cleanupBridge, client, { teamId: input.teamId, agentId: input.agentId });
  assert.equal(removals, 1);
  assert.equal((await store.get({ teamId: input.teamId, agentId: input.agentId, id: first.id }))?.status, "resolved");

  const replay = await store.enqueue(input);
  assert.equal(replay.id, first.id);
  await drainSlackReactionCleanups(cleanupBridge, client, { teamId: input.teamId, agentId: input.agentId });
  assert.equal(removals, 1);

  const fresh = await store.enqueue({ ...input, effectId: "reaction-effect:second-landing" });
  assert.notEqual(fresh.id, first.id);
  await drainSlackReactionCleanups(cleanupBridge, client, { teamId: input.teamId, agentId: input.agentId });
  assert.equal(removals, 2);
});

test("reaction landing effect IDs are stable for redelivery and distinct for a fresh run", async () => {
  const effectIds: string[] = [];
  const land = async (scope: string) => {
    let cancelled = false;
    await applyAndLogReactions(
      {
        reactions: {
          add: async () => {
            cancelled = true;
          },
        },
      },
      input.channelId,
      input.messageTs,
      [{ names: [input.name] }],
      {
        isCancelled: () => cancelled,
        reactionEffectScopeId: scope,
        admitDesiredReaction: async () => true,
        withdrawDesiredReaction: async () => {},
        cancelDesiredReaction: async () => {},
        compensateCreatedReaction: async ({ effectId }) => {
          effectIds.push(effectId);
          return "confirmed";
        },
      },
    );
  };
  await land("binding:one:reply-result");
  await land("binding:one:reply-result");
  await land("binding:two:reply-result");
  assert.equal(effectIds[0], effectIds[1]);
  assert.notEqual(effectIds[1], effectIds[2]);
});

test("reaction desire admission precedes provider add and superseded redelivery makes no provider call", async () => {
  let providerAdds = 0;
  const result = await applyReactions(
    { reactions: { add: async () => void (providerAdds += 1) } },
    input.channelId,
    input.messageTs,
    [input.name],
    {
      compensationEffectId: () => input.effectId,
      admitDesiredReaction: async () => false,
      withdrawDesiredReaction: async () => {},
    },
  );
  assert.equal(providerAdds, 0);
  assert.deepEqual(result, { added: [], failed: [] });
});

test("a definitive provider add failure withdraws the exact durable desire", async () => {
  const events: string[] = [];
  const result = await applyReactions(
    {
      reactions: {
        add: async () => {
          events.push("provider-add");
          throw { data: { error: "missing_scope" } };
        },
      },
    },
    input.channelId,
    input.messageTs,
    [input.name],
    {
      compensationEffectId: () => input.effectId,
      admitDesiredReaction: async () => {
        events.push("desire-admit");
        return true;
      },
      withdrawDesiredReaction: async () => void events.push("desire-withdraw"),
    },
  );
  assert.deepEqual(events, ["desire-admit", "provider-add", "desire-withdraw"]);
  assert.deepEqual(result, { added: [], failed: [input.name] });
});

test("a landed cancellation durably withdraws desire before cleanup admission", async () => {
  const events: string[] = [];
  let cancelled = false;
  await applyReactions(
    {
      reactions: {
        add: async () => {
          events.push("provider-add");
          cancelled = true;
        },
      },
    },
    input.channelId,
    input.messageTs,
    [input.name],
    {
      isCancelled: () => cancelled,
      compensationEffectId: () => input.effectId,
      admitDesiredReaction: async () => {
        events.push("desire-admit");
        return true;
      },
      withdrawDesiredReaction: async () => void events.push("desire-withdraw"),
      cancelDesiredReaction: async () => void events.push("desire-cancel"),
      compensateCreatedReaction: async () => {
        events.push("cleanup-admit");
        return "pending";
      },
    },
  );
  assert.deepEqual(events, ["desire-admit", "provider-add", "desire-cancel", "cleanup-admit"]);
});

test("a crash after landed cancellation is recovered into cleanup on poller restart", async () => {
  const desireBacking = createMemoryMap<any>();
  const cleanupBacking = createMemoryMap<any>();
  const firstDesires = createSlackReactionDesireStore(desireBacking, () => 100);
  await firstDesires.admit(input);
  await firstDesires.cancel(input, { admitCleanup: true });
  assert.deepEqual(await firstDesires.pendingCleanupAdmissions({ teamId: "T1", agentId: "A1", limit: 25 }), [input]);

  const restartedDesires = createSlackReactionDesireStore(desireBacking, () => 200);
  const restartedCleanups = createSlackReactionCleanupStore(cleanupBacking, () => 200);
  await recoverSlackReactionCleanupAdmissions(restartedDesires, restartedCleanups, {
    teamId: "T1",
    agentId: "A1",
    limit: 25,
  });
  assert.deepEqual(await restartedDesires.pendingCleanupAdmissions({ teamId: "T1", agentId: "A1", limit: 25 }), []);
  assert.equal((await restartedCleanups.claimDue({ teamId: "T1", agentId: "A1", limit: 25 })).length, 1);
});

test("restart reconciliation cleans a landed desired reaction when stop won after the final read", async () => {
  const desireBacking = createMemoryMap<any>();
  const cleanupBacking = createMemoryMap<any>();
  const sessionBacking = createMemoryMap<any>();
  const sessionKey = {
    teamId: input.teamId,
    agentId: input.agentId,
    channelId: input.sessionChannelId,
    threadTs: input.sessionThreadTs,
  };
  const sessionToken = slackAgentBindingToken(sessionKey, "U1", input.sourceTs, input.sessionThreadTs);
  const desired = { ...input, sessionToken };
  const sessions = createSlackAgentSessionStore(sessionBacking, () => 100);
  await sessions.begin({
    ...sessionKey,
    ownerUserId: "U1",
    token: sessionToken,
    triggerTs: input.sourceTs,
    coreThreadRef: "dm:D1:1700000000.100000",
    authorityMessageTs: input.sessionThreadTs,
  });
  await createSlackReactionDesireStore(desireBacking, () => 100).admit(desired);
  await sessions.recordStop({
    ...sessionKey,
    eventId: "Ev-stop-after-add",
    eventTs: "1700000000.100002",
    stoppedByUserId: "U2",
    streamingMessageTs: [],
  });

  const restartedDesires = createSlackReactionDesireStore(desireBacking, () => 200);
  const restartedCleanups = createSlackReactionCleanupStore(cleanupBacking, () => 200);
  await recoverSlackReactionCleanupAdmissions(
    restartedDesires,
    restartedCleanups,
    { teamId: input.teamId, agentId: input.agentId, limit: 25 },
    createSlackAgentSessionStore(sessionBacking, () => 200),
  );

  assert.equal((await restartedDesires.get(desired))?.desired, false);
  const claims = await restartedCleanups.claimDue({ teamId: input.teamId, agentId: input.agentId, limit: 25 });
  assert.equal(claims.length, 1);
  assert.equal(claims[0]?.effectId, desired.effectId);
});

test("a crash after cleanup landing but before outbox completion replays idempotently", async () => {
  const desireBacking = createMemoryMap<any>();
  const cleanupBacking = createMemoryMap<any>();
  const firstDesires = createSlackReactionDesireStore(desireBacking, () => 100);
  const firstCleanups = createSlackReactionCleanupStore(cleanupBacking, () => 100);
  await firstDesires.admit(input);
  await firstDesires.cancel(input, { admitCleanup: true });
  await firstCleanups.enqueue(input);

  const restartedDesires = createSlackReactionDesireStore(desireBacking, () => 200);
  const restartedCleanups = createSlackReactionCleanupStore(cleanupBacking, () => 200);
  await recoverSlackReactionCleanupAdmissions(restartedDesires, restartedCleanups, {
    teamId: "T1",
    agentId: "A1",
    limit: 25,
  });
  assert.deepEqual(await restartedDesires.pendingCleanupAdmissions({ teamId: "T1", agentId: "A1", limit: 25 }), []);
  assert.equal((await restartedCleanups.claimDue({ teamId: "T1", agentId: "A1", limit: 25 })).length, 1);
});

test("a superseded landed effect retains cleanup authority through a newer failed desire", async () => {
  const desireBacking = createMemoryMap<any>();
  const cleanupBacking = createMemoryMap<any>();
  const desires = createSlackReactionDesireStore(desireBacking, () => 100);
  const newer = {
    ...input,
    sessionToken: "binding:newer",
    effectId: "reaction-effect:newer",
    sourceTs: "1700000000.100002",
  };
  await desires.admit(input);
  await desires.admit(newer);
  await desires.cancel(input, { admitCleanup: true });
  await desires.cancel(newer);
  assert.equal((await desires.get(input))?.desired, false);
  assert.deepEqual(await desires.pendingCleanupAdmissions({ teamId: "T1", agentId: "A1", limit: 25 }), [input]);

  const cleanups = createSlackReactionCleanupStore(cleanupBacking, () => 200);
  await recoverSlackReactionCleanupAdmissions(
    createSlackReactionDesireStore(desireBacking, () => 200),
    cleanups,
    { teamId: "T1", agentId: "A1", limit: 25 },
  );
  assert.equal((await cleanups.claimDue({ teamId: "T1", agentId: "A1", limit: 25 })).length, 1);
});

test("a failed cancellation transaction creates no cleanup authority", async () => {
  const backing = createMemoryMap<any>();
  const update = backing.update!.bind(backing);
  let fail = false;
  const failing = {
    ...backing,
    update: async (id: string, fn: (value: any) => any) => {
      if (fail) throw new Error("database unavailable");
      return update(id, fn);
    },
  };
  const desires = createSlackReactionDesireStore(failing, () => 100);
  await desires.admit(input);
  fail = true;
  await assert.rejects(desires.cancel(input, { admitCleanup: true }), /database unavailable/);
  fail = false;
  assert.equal((await desires.get(input))?.desired, true);
  assert.deepEqual(await desires.pendingCleanupAdmissions({ teamId: "T1", agentId: "A1", limit: 25 }), []);
});

test("a newer same-emoji desire supersedes old redelivery and fences its pending cleanup", async () => {
  const cleanupStore = createSlackReactionCleanupStore(createMemoryMap<any>(), () => 100);
  const desireStore = createSlackReactionDesireStore(createMemoryMap<any>(), () => 100);
  const oldDesire: SlackReactionDesireInput = { ...input };
  await desireStore.admit(oldDesire);
  await desireStore.cancel(oldDesire);
  const cleanup = await cleanupStore.enqueue(input);
  const newerDesire: SlackReactionDesireInput = {
    ...oldDesire,
    sessionToken: "binding:newer",
    effectId: "reaction-effect:newer",
    sourceTs: "1700000000.100002",
  };
  const newer = await desireStore.admit(newerDesire);
  assert.equal(newer.record.generation, 2);
  assert.equal((await desireStore.admit(oldDesire)).disposition, "superseded");
  await desireStore.cancel(oldDesire);
  assert.equal((await desireStore.get(newerDesire))?.desired, true);

  let additions = 0;
  let removals = 0;
  const guardedBridge = desireBridge(cleanupStore, desireStore);
  await drainSlackReactionCleanups(
    guardedBridge,
    {
      reactions: {
        add: async () => void (additions += 1),
        remove: async () => void (removals += 1),
      },
    },
    { teamId: input.teamId, agentId: input.agentId },
  );
  assert.equal(additions, 1);
  assert.equal(removals, 0);
  assert.equal(
    (await cleanupStore.get({ teamId: input.teamId, agentId: input.agentId, id: cleanup.id }))?.status,
    "resolved",
  );
});

test("a canceled newer already-reacted effect removes the latest-wins owned reaction", async () => {
  const cleanupStore = createSlackReactionCleanupStore(createMemoryMap<any>(), () => 100);
  const desireStore = createSlackReactionDesireStore(createMemoryMap<any>(), () => 100);
  const oldDesire: SlackReactionDesireInput = { ...input };
  const newerDesire: SlackReactionDesireInput = {
    ...oldDesire,
    sessionToken: "binding:newer",
    effectId: "reaction-effect:newer",
    sourceTs: "1700000000.100002",
  };
  await desireStore.admit(oldDesire);
  let cancelled = false;
  let removals = 0;
  const guardedBridge = desireBridge(cleanupStore, desireStore);
  const result = await applyReactions(
    {
      reactions: {
        add: async () => {
          cancelled = true;
          throw { data: { error: "already_reacted" } };
        },
        remove: async () => void (removals += 1),
      },
    },
    input.channelId,
    input.messageTs,
    [input.name],
    {
      isCancelled: () => cancelled,
      compensationEffectId: () => newerDesire.effectId,
      admitDesiredReaction: async () => {
        const admitted = await desireStore.admit(newerDesire);
        return admitted.record.desired;
      },
      withdrawDesiredReaction: async () => void (await desireStore.cancel(newerDesire)),
      cancelDesiredReaction: async () => void (await desireStore.cancel(newerDesire)),
      compensateCreatedReaction: async () => {
        const cleanup = await cleanupStore.enqueue(newerDesire);
        await drainSlackReactionCleanups(
          guardedBridge,
          {
            reactions: {
              add: async () => {},
              remove: async () => void (removals += 1),
            },
          },
          { teamId: input.teamId, agentId: input.agentId },
        );
        return (await cleanupStore.get({ teamId: input.teamId, agentId: input.agentId, id: cleanup.id }))?.status ===
          "resolved"
          ? "confirmed"
          : "pending";
      },
    },
  );
  assert.equal((await desireStore.get(newerDesire))?.desired, false);
  assert.equal(removals, 1);
  assert.deepEqual(result, { added: [], failed: [input.name], removed: [input.name] });
});

test("an exact canceled effect still removes when no newer desire exists", async () => {
  const cleanupStore = createSlackReactionCleanupStore(createMemoryMap<any>(), () => 100);
  const desireStore = createSlackReactionDesireStore(createMemoryMap<any>(), () => 100);
  const oldDesire: SlackReactionDesireInput = { ...input };
  await desireStore.admit(oldDesire);
  await desireStore.cancel(oldDesire);
  await cleanupStore.enqueue(input);
  let removals = 0;
  await drainSlackReactionCleanups(
    desireBridge(cleanupStore, desireStore),
    {
      reactions: {
        add: async () => {},
        remove: async () => void (removals += 1),
      },
    },
    { teamId: input.teamId, agentId: input.agentId },
  );
  assert.equal(removals, 1);
});

test("old cleanup removes after a newer same-emoji desire fails to land and is withdrawn", async () => {
  const cleanupStore = createSlackReactionCleanupStore(createMemoryMap<any>(), () => 100);
  const desireStore = createSlackReactionDesireStore(createMemoryMap<any>(), () => 100);
  const oldDesire: SlackReactionDesireInput = { ...input };
  const newerDesire: SlackReactionDesireInput = {
    ...oldDesire,
    sessionToken: "binding:newer",
    effectId: "reaction-effect:newer",
    sourceTs: "1700000000.100002",
  };
  await desireStore.admit(oldDesire);
  await desireStore.cancel(oldDesire);
  await cleanupStore.enqueue(input);
  await desireStore.admit(newerDesire);
  await desireStore.cancel(newerDesire);

  let additions = 0;
  let removals = 0;
  await drainSlackReactionCleanups(
    desireBridge(cleanupStore, desireStore),
    {
      reactions: {
        add: async () => void (additions += 1),
        remove: async () => void (removals += 1),
      },
    },
    { teamId: input.teamId, agentId: input.agentId },
  );
  assert.equal(additions, 0);
  assert.equal(removals, 1);
});

test("cleanup revalidates after remove and restores a desire admitted during the provider race", async () => {
  const cleanupStore = createSlackReactionCleanupStore(createMemoryMap<any>(), () => 100);
  const desireStore = createSlackReactionDesireStore(createMemoryMap<any>(), () => 100);
  const oldDesire: SlackReactionDesireInput = { ...input };
  await desireStore.admit(oldDesire);
  await desireStore.cancel(oldDesire);
  await cleanupStore.enqueue(input);
  const newerDesire: SlackReactionDesireInput = {
    ...oldDesire,
    sessionToken: "binding:newer",
    effectId: "reaction-effect:newer",
    sourceTs: "1700000000.100002",
  };
  let reactionPresent = true;
  let removals = 0;
  let additions = 0;
  const guardedBridge = desireBridge(cleanupStore, desireStore);
  await drainSlackReactionCleanups(
    guardedBridge,
    {
      reactions: {
        add: async () => {
          additions += 1;
          reactionPresent = true;
        },
        remove: async () => {
          removals += 1;
          reactionPresent = false;
          await desireStore.admit(newerDesire);
        },
      },
    },
    { teamId: input.teamId, agentId: input.agentId },
  );
  assert.equal(removals, 1);
  assert.equal(additions, 1);
  assert.equal(reactionPresent, true);
});

test("cleanup completion cannot resolve a remove decision across a newer desire generation", async () => {
  let now = 100;
  const cleanupStore = createSlackReactionCleanupStore(createMemoryMap<any>(), () => now);
  const desireStore = createSlackReactionDesireStore(createMemoryMap<any>(), () => now);
  const oldDesire: SlackReactionDesireInput = { ...input };
  const newerDesire: SlackReactionDesireInput = {
    ...oldDesire,
    sessionToken: "binding:newer",
    effectId: "reaction-effect:newer",
    sourceTs: "1700000000.100002",
  };
  await desireStore.admit(oldDesire);
  await desireStore.cancel(oldDesire);
  const cleanup = await cleanupStore.enqueue(input);
  const guarded = desireBridge(cleanupStore, desireStore);
  let inject = true;
  let additions = 0;
  let removals = 0;
  const racingBridge: SlackReactionCleanupBridge = {
    ...guarded,
    completeSlackReactionCleanup: async (claim, decision) => {
      if (inject) {
        inject = false;
        await desireStore.admit(newerDesire);
      }
      return guarded.completeSlackReactionCleanup(claim, decision);
    },
  };
  const client = {
    reactions: {
      add: async () => void (additions += 1),
      remove: async () => void (removals += 1),
    },
  };
  await drainSlackReactionCleanups(racingBridge, client, { teamId: input.teamId, agentId: input.agentId }, () => now);
  const pending = await cleanupStore.get({ teamId: input.teamId, agentId: input.agentId, id: cleanup.id });
  assert.equal(pending?.status, "pending");
  assert.equal(removals, 1);
  now = pending?.nextAttemptAt ?? now;
  await drainSlackReactionCleanups(guarded, client, { teamId: input.teamId, agentId: input.agentId }, () => now);
  assert.equal(additions, 1);
  assert.equal(
    (await cleanupStore.get({ teamId: input.teamId, agentId: input.agentId, id: cleanup.id }))?.status,
    "resolved",
  );
});

test("cleanup completion cannot resolve a preserve decision across a newer cancellation", async () => {
  let now = 100;
  const cleanupStore = createSlackReactionCleanupStore(createMemoryMap<any>(), () => now);
  const desireStore = createSlackReactionDesireStore(createMemoryMap<any>(), () => now);
  const oldDesire: SlackReactionDesireInput = { ...input };
  const newerDesire: SlackReactionDesireInput = {
    ...oldDesire,
    sessionToken: "binding:newer",
    effectId: "reaction-effect:newer",
    sourceTs: "1700000000.100002",
  };
  await desireStore.admit(oldDesire);
  await desireStore.cancel(oldDesire);
  await desireStore.admit(newerDesire);
  const cleanup = await cleanupStore.enqueue(input);
  const guarded = desireBridge(cleanupStore, desireStore);
  let inject = true;
  let additions = 0;
  let removals = 0;
  const racingBridge: SlackReactionCleanupBridge = {
    ...guarded,
    completeSlackReactionCleanup: async (claim, decision) => {
      if (inject) {
        inject = false;
        await desireStore.cancel(newerDesire);
      }
      return guarded.completeSlackReactionCleanup(claim, decision);
    },
  };
  const client = {
    reactions: {
      add: async () => void (additions += 1),
      remove: async () => void (removals += 1),
    },
  };
  await drainSlackReactionCleanups(racingBridge, client, { teamId: input.teamId, agentId: input.agentId }, () => now);
  const pending = await cleanupStore.get({ teamId: input.teamId, agentId: input.agentId, id: cleanup.id });
  assert.equal(pending?.status, "pending");
  assert.equal(additions, 1);
  now = pending?.nextAttemptAt ?? now;
  await drainSlackReactionCleanups(guarded, client, { teamId: input.teamId, agentId: input.agentId }, () => now);
  assert.equal(removals, 1);
  assert.equal(
    (await cleanupStore.get({ teamId: input.teamId, agentId: input.agentId, id: cleanup.id }))?.status,
    "resolved",
  );
});

test("add-held cancellation persists failed removal and a restart eventually removes it", async () => {
  let now = 1_000;
  const backing = createMemoryMap<any>();
  const firstStore = createSlackReactionCleanupStore(backing, () => now);
  const firstBridge = bridge(firstStore);
  let releaseAdd: (() => void) | undefined;
  let cancelled = false;
  let reactionPresent = false;
  let removeAttempts = 0;
  const firstClient = {
    reactions: {
      add: async () => {
        await new Promise<void>((resolve) => {
          releaseAdd = resolve;
        });
        reactionPresent = true;
      },
      remove: async () => {
        removeAttempts += 1;
        throw { retryAfter: 3, data: { error: "ratelimited" } };
      },
    },
  };

  const applying = applyReactions(firstClient, input.channelId, input.messageTs, [input.name], {
    isCancelled: async () => cancelled,
    compensateCreatedReaction: async () => {
      const enqueued = await firstStore.enqueue(input);
      await drainSlackReactionCleanups(
        firstBridge,
        firstClient,
        { teamId: input.teamId, agentId: input.agentId },
        () => now,
      );
      const current = await firstStore.get({ teamId: input.teamId, agentId: input.agentId, id: enqueued.id });
      return current?.status === "resolved" ? "confirmed" : "pending";
    },
    compensationEffectId: () => input.effectId,
  });
  while (!releaseAdd) await new Promise((resolve) => setImmediate(resolve));
  cancelled = true;
  releaseAdd();
  const firstResult = await applying;
  assert.equal(reactionPresent, true);
  assert.deepEqual(firstResult.added, ["eyes"]);
  assert.deepEqual(firstResult.pendingRemoval, ["eyes"]);
  assert.equal(removeAttempts, 1);

  const pending = await firstStore.enqueue(input);
  assert.equal(pending.status, "pending");
  assert.equal(pending.attempts, 1);
  assert.equal(pending.nextAttemptAt, 4_000);
  now = pending.nextAttemptAt;

  const restartedStore = createSlackReactionCleanupStore(backing, () => now);
  const restartedBridge = bridge(restartedStore);
  const restartedClient = {
    reactions: {
      add: async () => {},
      remove: async () => {
        removeAttempts += 1;
        reactionPresent = false;
      },
    },
  };
  await drainSlackReactionCleanups(
    restartedBridge,
    restartedClient,
    { teamId: input.teamId, agentId: input.agentId },
    () => now,
  );
  const resolved = await restartedStore.get({ teamId: input.teamId, agentId: input.agentId, id: pending.id });
  assert.equal(reactionPresent, false);
  assert.equal(removeAttempts, 2);
  assert.equal(resolved?.status, "resolved");
  assert.equal(resolved?.completedAt, now);
});

test("a stale cleanup worker cannot complete a newer leased retry", async () => {
  let now = 1_000;
  const backing = createMemoryMap<any>();
  const first = createSlackReactionCleanupStore(backing, () => now);
  await first.enqueue(input);
  const [older] = await first.claimDue({ teamId: input.teamId, agentId: input.agentId, limit: 1 });
  assert.ok(older);
  now = older.leaseExpiresAt;
  const restarted = createSlackReactionCleanupStore(backing, () => now);
  const [newer] = await restarted.claimDue({ teamId: input.teamId, agentId: input.agentId, limit: 1 });
  assert.ok(newer);
  assert.notEqual(newer.claimId, older.claimId);
  assert.equal(await first.complete(older), false);
  assert.equal(await restarted.complete(newer), true);
});

test("a stale removal landing after newer preservation durably reopens and restores desired state", async () => {
  let now = 1_000;
  const cleanupStore = createSlackReactionCleanupStore(createMemoryMap<any>(), () => now);
  const desireStore = createSlackReactionDesireStore(createMemoryMap<any>(), () => now);
  const oldDesire: SlackReactionDesireInput = { ...input };
  await desireStore.admit(oldDesire);
  await desireStore.cancel(oldDesire);
  const cleanup = await cleanupStore.enqueue(input);
  const guardedBridge = desireBridge(cleanupStore, desireStore);
  let releaseOldRemove: (() => void) | undefined;
  let oldRemoveStarted = false;
  let reactionPresent = true;
  const oldDrain = drainSlackReactionCleanups(
    guardedBridge,
    {
      reactions: {
        add: async () => void (reactionPresent = true),
        remove: async () => {
          oldRemoveStarted = true;
          await new Promise<void>((resolve) => {
            releaseOldRemove = resolve;
          });
          reactionPresent = false;
        },
      },
    },
    { teamId: input.teamId, agentId: input.agentId },
    () => now,
  );
  while (!oldRemoveStarted) await new Promise((resolve) => setImmediate(resolve));
  now += 60_000;
  await desireStore.admit({
    ...oldDesire,
    sessionToken: "binding:newer",
    effectId: "reaction-effect:newer",
    sourceTs: "1700000000.100002",
  });
  await drainSlackReactionCleanups(
    guardedBridge,
    {
      reactions: { add: async () => void (reactionPresent = true), remove: async () => void (reactionPresent = false) },
    },
    { teamId: input.teamId, agentId: input.agentId },
    () => now,
  );
  assert.equal(reactionPresent, true);
  assert.ok(releaseOldRemove);
  releaseOldRemove();
  await oldDrain;
  assert.equal(reactionPresent, false);
  assert.equal(
    (await cleanupStore.get({ teamId: input.teamId, agentId: input.agentId, id: cleanup.id }))?.status,
    "pending",
  );
  await drainSlackReactionCleanups(
    guardedBridge,
    {
      reactions: { add: async () => void (reactionPresent = true), remove: async () => void (reactionPresent = false) },
    },
    { teamId: input.teamId, agentId: input.agentId },
    () => now,
  );
  assert.equal(reactionPresent, true);
  assert.equal(
    (await cleanupStore.get({ teamId: input.teamId, agentId: input.agentId, id: cleanup.id }))?.status,
    "resolved",
  );
});

test("cleanup remains durably retriable past eight failures and recovers after configuration repair", async () => {
  let now = 1_000;
  const store = createSlackReactionCleanupStore(createMemoryMap<any>(), () => now);
  const enqueued = await store.enqueue(input);
  const cleanupBridge = bridge(store);
  let reactionPresent = true;
  let removeAttempts = 0;
  const client = {
    reactions: {
      add: async () => {},
      remove: async () => {
        removeAttempts += 1;
        if (removeAttempts <= 9) throw { data: { error: "xoxb-secret-reflection" } };
        reactionPresent = false;
      },
    },
  };
  let current = enqueued;
  for (let attempt = 0; attempt < 9; attempt++) {
    await drainSlackReactionCleanups(
      cleanupBridge,
      client,
      { teamId: input.teamId, agentId: input.agentId },
      () => now,
    );
    current = (await store.get({ teamId: input.teamId, agentId: input.agentId, id: enqueued.id }))!;
    now = current.nextAttemptAt;
  }
  assert.equal(current.status, "pending");
  assert.equal(current.lastErrorCode, "provider_error");
  assert.equal(removeAttempts, 9);
  await drainSlackReactionCleanups(cleanupBridge, client, { teamId: input.teamId, agentId: input.agentId }, () => now);
  assert.equal(removeAttempts, 10);
  assert.equal(reactionPresent, false);
  assert.equal(
    (await store.get({ teamId: input.teamId, agentId: input.agentId, id: enqueued.id }))?.status,
    "resolved",
  );
});
