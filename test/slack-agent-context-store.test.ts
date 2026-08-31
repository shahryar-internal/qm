import { test } from "node:test";
import assert from "node:assert/strict";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { createSlackAgentContextStore } from "../src/surfaces/slack-agent-context.ts";

test("agent context store closes the entity schema and enforces team, owner, channel, and thread keys", async () => {
  const backing = createMemoryMap<any>();
  const store = createSlackAgentContextStore(backing, () => 123);
  await store.bindThread({
    teamId: "T1",
    ownerUserId: "U1",
    channelId: "D1",
    threadTs: "10.1",
    context: {
      entities: [
        { type: "slack#/types/channel_id", team_id: "T1", value: "C1" },
        { type: "slack#/types/canvas_id", team_id: "T1", value: "F1" },
        { type: "slack#/types/unknown", team_id: "T1", value: "SECRET" },
        { type: "slack#/types/channel_id", team_id: "T2", value: "C2" },
      ],
    },
    source: "message",
    eventTs: "10.2",
  });

  const exact = await store.getThread({ teamId: "T1", ownerUserId: "U1", channelId: "D1", threadTs: "10.1" });
  assert.deepEqual(exact?.entities, [
    { type: "slack#/types/channel_id", teamId: "T1", value: "C1" },
    { type: "slack#/types/canvas_id", teamId: "T1", value: "F1" },
  ]);
  assert.equal(await store.getThread({ teamId: "T1", ownerUserId: "U2", channelId: "D1", threadTs: "10.1" }), null);
  assert.equal(await store.getThread({ teamId: "T1", ownerUserId: "U1", channelId: "D1", threadTs: "10.2" }), null);
});

test("agent context store survives reconstruction and rejects stale writes", async () => {
  const backing = createMemoryMap<any>();
  const first = createSlackAgentContextStore(backing, () => 100);
  await first.bindThread({
    teamId: "T1",
    ownerUserId: "U1",
    channelId: "D1",
    threadTs: "20.1",
    context: { entities: [{ type: "slack#/types/channel_id", team_id: "T1", value: "C-NEW" }] },
    source: "message",
    eventTs: "20.2",
  });
  const restarted = createSlackAgentContextStore(backing, () => 200);
  await restarted.bindThread({
    teamId: "T1",
    ownerUserId: "U1",
    channelId: "D1",
    threadTs: "20.1",
    context: { entities: [{ type: "slack#/types/channel_id", team_id: "T1", value: "C-OLD" }] },
    source: "assistant_thread",
    eventTs: "20.0",
  });

  const record = await restarted.getThread({ teamId: "T1", ownerUserId: "U1", channelId: "D1", threadTs: "20.1" });
  assert.equal(record?.updatedAt, 100);
  assert.deepEqual(record?.entities, [{ type: "slack#/types/channel_id", teamId: "T1", value: "C-NEW" }]);
});

test("a newer global app context never contaminates an exact message without context", async () => {
  const store = createSlackAgentContextStore(createMemoryMap<any>());
  await store.saveCurrent({
    teamId: "T1",
    ownerUserId: "U1",
    context: { entities: [{ type: "slack#/types/channel_id", team_id: "T1", value: "C-PRIVATE" }] },
    source: "app_context",
    eventTs: "30.9",
  });
  await store.bindThread({
    teamId: "T1",
    ownerUserId: "U1",
    channelId: "D1",
    threadTs: "30.1",
    context: { entities: [] },
    source: "message",
    eventTs: "30.2",
  });
  assert.deepEqual(
    (await store.getThread({ teamId: "T1", ownerUserId: "U1", channelId: "D1", threadTs: "30.1" }))?.entities,
    [],
  );
});
