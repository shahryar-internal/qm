import { test } from "node:test";
import assert from "node:assert/strict";
import { registerSlackEvents } from "../src/slack/events.ts";
import { createDeduper } from "../src/slack/lib.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { createSlackAgentContextStore } from "../src/surfaces/slack-agent-context.ts";
import { createSlackAgentSessionStore } from "../src/surfaces/slack-agent-session.ts";
import type { TurnHandler } from "../src/slack/turn-handler.ts";

function fakeApp() {
  const events = new Map<string, (args: any) => Promise<void>>();
  const messages: Array<(args: any) => Promise<void>> = [];
  return {
    app: {
      event: (name: string, handler: (args: any) => Promise<void>) => void events.set(name, handler),
      message: (handler: (args: any) => Promise<void>) => void messages.push(handler),
    },
    fire: (name: string, event: unknown) =>
      events.get(name)!({ event, body: { team_id: "T1" }, client: {}, context: {} }),
    hasEvent: (name: string) => events.has(name),
    im: (message: Record<string, unknown>) =>
      messages[0]!({
        message: { channel_type: "im", ...message },
        body: { team_id: "T1" },
        client: {},
        context: {},
      }),
  };
}

function register(
  app: ReturnType<typeof fakeApp>,
  dispatched: any[],
  contexts: ReturnType<typeof createSlackAgentContextStore>,
) {
  registerSlackEvents(app.app, {
    handler: {
      dispatch: async (_key: string, inc: any) => void dispatched.push(inc),
      handleReactionEvent: async () => {},
      handleAgentSessionStopped: async () => {},
      botHasStakeInThread: async () => false,
    } as unknown as TurnHandler,
    mirror: { mirrorMessageEvent: async () => {}, pushSurfaceEvents: async () => {} } as any,
    directory: { syncForUnseenGroup: () => {}, forceDirectorySync: async () => {} } as any,
    ids: { botUserId: "UBOT", ownBotId: "BBOT", ownTeamId: "T1", agentId: "A1" } as any,
    deduper: createDeduper(),
    saveAgentContext: (input) => contexts.saveCurrent(input),
    bindAgentThread: (input) => contexts.bindThread({ ...input, context: input.context ?? { entities: [] } }),
    getAgentThread: (input) => contexts.getThread(input),
    renameAgentSession: (input) => createSlackAgentSessionStore(createMemoryMap<any>()).rename(input),
  });
}

test("agent and legacy assistant events persist exact owner-bound context across a plugin restart", async () => {
  const backing = createMemoryMap<any>();
  const contexts = createSlackAgentContextStore(backing);
  const first = fakeApp();
  register(first, [], contexts);
  assert.equal(first.hasEvent("app_home_opened"), true);
  assert.equal(first.hasEvent("app_context_changed"), true);
  assert.equal(first.hasEvent("assistant_thread_started"), true);
  assert.equal(first.hasEvent("assistant_thread_context_changed"), true);
  assert.equal(first.hasEvent("agent_session_stopped"), true);
  assert.equal(first.hasEvent("agent_session_title_changed"), true);
  await first.fire("assistant_thread_started", {
    assistant_thread: {
      user_id: "U1",
      channel_id: "D111",
      thread_ts: "100.1",
      context: { channel_id: "C9", team_id: "T1" },
    },
    event_ts: "100.0",
  });

  const dispatched: any[] = [];
  const restarted = fakeApp();
  register(restarted, dispatched, createSlackAgentContextStore(backing));
  await restarted.im({ channel: "D111", user: "U1", text: "hello", ts: "100.2", thread_ts: "100.1" });
  await restarted.im({ channel: "D111", user: "U2", text: "hello", ts: "100.3", thread_ts: "100.1" });

  assert.deepEqual(dispatched[0].agentContext, [{ type: "slack#/types/channel_id", teamId: "T1", value: "C9" }]);
  assert.equal(dispatched[1].agentContext, undefined);
});

test("message app_context is bound to the exact agent thread and stale updates cannot replace it", async () => {
  const contexts = createSlackAgentContextStore(createMemoryMap<any>());
  const dispatched: any[] = [];
  const app = fakeApp();
  register(app, dispatched, contexts);
  await app.im({
    channel: "D111",
    user: "U1",
    text: "summarize this",
    ts: "200.2",
    thread_ts: "200.1",
    app_context: {
      entities: [
        {
          type: "slack#/types/message_context",
          team_id: "T1",
          value: { channel_id: "C2", message_ts: "199.9" },
        },
        { type: "slack#/types/channel_id", team_id: "T-OTHER", value: "C-PRIVATE" },
      ],
    },
  });
  await app.fire("assistant_thread_context_changed", {
    assistant_thread: {
      user_id: "U1",
      channel_id: "D111",
      thread_ts: "200.1",
      context: { channel_id: "C-STALE", team_id: "T1" },
    },
    event_ts: "199.0",
  });
  const stored = await contexts.getThread({ teamId: "T1", ownerUserId: "U1", channelId: "D111", threadTs: "200.1" });

  assert.deepEqual(dispatched[0].agentContext, [
    {
      type: "slack#/types/message_context",
      teamId: "T1",
      value: { channelId: "C2", messageTs: "199.9" },
    },
  ]);
  assert.deepEqual(stored?.entities, dispatched[0].agentContext);
});

test("an Agent View message without app_context clears an older active view", async () => {
  const contexts = createSlackAgentContextStore(createMemoryMap<any>());
  const dispatched: any[] = [];
  const app = fakeApp();
  register(app, dispatched, contexts);
  await app.im({
    channel: "D111",
    user: "U1",
    text: "first",
    ts: "300.2",
    thread_ts: "300.1",
    app_context: {
      entities: [{ type: "slack#/types/channel_id", team_id: "T1", value: "C-OLD" }],
    },
  });
  await app.im({ channel: "D111", user: "U1", text: "second", ts: "300.3", thread_ts: "300.1" });

  const stored = await contexts.getThread({ teamId: "T1", ownerUserId: "U1", channelId: "D111", threadTs: "300.1" });
  assert.equal(dispatched[1].agentContext, undefined);
  assert.deepEqual(stored?.entities, []);
});

test("a channel app mention carries only its own message app context", async () => {
  const contexts = createSlackAgentContextStore(createMemoryMap<any>());
  const dispatched: any[] = [];
  const app = fakeApp();
  register(app, dispatched, contexts);
  await app.fire("app_mention", {
    channel: "C111",
    user: "U1",
    text: "<@UBOT> summarize",
    ts: "400.2",
    thread_ts: "400.1",
    app_context: {
      entities: [{ type: "slack#/types/canvas_id", team_id: "T1", value: "F-CANVAS" }],
    },
  });
  assert.deepEqual(dispatched[0].agentContext, [{ type: "slack#/types/canvas_id", teamId: "T1", value: "F-CANVAS" }]);
});
