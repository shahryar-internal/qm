import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SlackAgentWriteDeferredError,
  renderTaskList,
  createTaskListPresenter,
  createAckPresenter,
  createNativeAgentPresenter,
  retrySlackAgentWrite,
  stripAckPrefix,
  stripReactionDirectives,
  type NativeAgentStatusIntentRequest,
} from "../src/slack/lib.ts";

const acceptStatusIntent = async (_input: NativeAgentStatusIntentRequest): Promise<void> => {};

test("Agent Sessions writes retry bounded rate limits and transient server failures", async () => {
  const delays: number[] = [];
  let attempts = 0;
  const result = await retrySlackAgentWrite(
    async () => {
      attempts += 1;
      if (attempts === 1)
        throw { code: "slack_webapi_rate_limited_error", retryAfter: 1, data: { error: "ratelimited" } };
      if (attempts === 2) throw { statusCode: 503, data: { error: "service_unavailable" } };
      return "ok";
    },
    async (ms) => void delays.push(ms),
  );
  assert.equal(result, "ok");
  assert.equal(attempts, 3);
  assert.deepEqual(delays, [1_000, 200]);
});

test("Agent Sessions writes do not retry permanent errors", async () => {
  let attempts = 0;
  await assert.rejects(
    retrySlackAgentWrite(
      async () => {
        attempts += 1;
        throw new Error("invalid_arguments");
      },
      async () => {},
    ),
    /invalid_arguments/,
  );
  assert.equal(attempts, 1);
});

test("Agent Sessions writes preserve a provider Retry-After above the local retry window", async () => {
  const delays: number[] = [];
  let attempts = 0;
  await assert.rejects(
    retrySlackAgentWrite(
      async () => {
        attempts += 1;
        throw { code: "slack_webapi_rate_limited_error", retryAfter: 90, data: { error: "ratelimited" } };
      },
      async (ms) => void delays.push(ms),
    ),
    (error: unknown) => error instanceof SlackAgentWriteDeferredError && error.retryAfterMs === 90_000,
  );
  assert.equal(attempts, 1);
  assert.deepEqual(delays, []);
});

test("Agent Sessions writes preserve a short Retry-After after local retries are exhausted", async () => {
  const delays: number[] = [];
  let attempts = 0;
  await assert.rejects(
    retrySlackAgentWrite(
      async () => {
        attempts += 1;
        throw { code: "slack_webapi_rate_limited_error", retryAfter: 1, data: { error: "ratelimited" } };
      },
      async (ms) => void delays.push(ms),
    ),
    (error: unknown) => error instanceof SlackAgentWriteDeferredError && error.retryAfterMs === 1_000,
  );
  assert.equal(attempts, 3);
  assert.deepEqual(delays, [1_000, 1_000]);
});

test("native agent presenter uses the current session endpoint, chunk streaming, and plan tasks", async () => {
  const apiCalls: Array<{ method: string; args: any }> = [];
  const starts: any[] = [];
  const appends: any[] = [];
  const stops: any[] = [];
  const checkpoints: string[] = [];
  const client = {
    apiCall: async (method: string, args: any) => void apiCalls.push({ method, args }),
    chat: {
      startStream: async (args: any) => {
        starts.push(args);
        return { ts: "171.2" };
      },
      appendStream: async (args: any) => void appends.push(args),
      stopStream: async (args: any) => void stops.push(args),
    },
  };
  const presenter = createNativeAgentPresenter({
    client,
    channel: "C1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    recipientTeamId: "T1",
    streaming: true,
    title: "Check today's calendar",
    sanitize: stripReactionDirectives,
    checkpoint: async (ts) => void checkpoints.push(ts),
    writeStatusIntent: async (input) => {
      apiCalls.push({
        method: "agents.sessions.setStatus",
        args: {
          channel_id: "C1",
          thread_ts: "170.1",
          status: input.status,
          ...(input.createSession
            ? {
                initiator_user_id: input.createSession.initiatorUserId,
                title: input.createSession.title,
              }
            : {}),
        },
      });
    },
    onSurfacePosted: () => {},
  });

  assert.equal(await presenter.begin(), true);
  presenter.onDelta("A".repeat(400));
  await presenter.onTasks([{ id: "calendar", title: "Read calendar", status: "in_progress" }]);
  presenter.onDelta("[[react: white_check_mark]]");
  await presenter.finish("A".repeat(400));

  assert.deepEqual(apiCalls, [
    {
      method: "agents.sessions.setStatus",
      args: {
        channel_id: "C1",
        thread_ts: "170.1",
        status: "processing",
        initiator_user_id: "U1",
        title: "Check today's calendar",
      },
    },
    {
      method: "agents.sessions.setStatus",
      args: {
        channel_id: "C1",
        thread_ts: "170.1",
        status: "active",
      },
    },
  ]);
  assert.equal(starts[0].task_display_mode, "plan");
  assert.equal(starts[0].recipient_user_id, "U1");
  assert.equal(starts[0].recipient_team_id, "T1");
  assert.deepEqual(checkpoints, ["171.2"]);
  assert.deepEqual(appends[0].chunks, [
    { type: "plan_update", title: "Check today's calendar" },
    { type: "task_update", id: "calendar", title: "Read calendar", status: "in_progress" },
  ]);
  assert.equal(stops[0].session_status, "active");
  assert.equal(JSON.stringify([starts, appends, stops]).includes("[[react:"), false);
});

test("native agent presenter omits title and initiator after durable session creation", async () => {
  const calls: any[] = [];
  const presenter = createNativeAgentPresenter({
    client: {
      apiCall: async (_method: string, args: any) => void calls.push(args),
      chat: { startStream: async () => ({ ts: "171.2" }), appendStream: async () => {}, stopStream: async () => {} },
    },
    channel: "D1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    createSession: false,
    title: "Do not rename",
    sanitize: (text) => text,
    checkpoint: async () => {},
    writeStatusIntent: async (input) => void calls.push({ channel_id: "D1", thread_ts: "170.1", status: input.status }),
    onSurfacePosted: () => {},
  });
  assert.equal(await presenter.begin(), true);
  assert.deepEqual(calls[0], { channel_id: "D1", thread_ts: "170.1", status: "processing" });
});

test("native agent presenter takeover stops and replaces the exact persisted stream", async () => {
  const starts: any[] = [];
  const appends: any[] = [];
  const stops: any[] = [];
  const updates: any[] = [];
  const methods: string[] = [];
  const presenter = createNativeAgentPresenter({
    client: {
      apiCall: async () => ({ ok: true }),
      chat: {
        startStream: async (args: any) => void starts.push(args),
        appendStream: async (args: any) => void appends.push(args),
        stopStream: async (args: any) => void stops.push(args),
        update: async (args: any) => void updates.push(args),
      },
    },
    channel: "D1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    resumeStreamTs: "171.2",
    streaming: true,
    title: "Continue",
    sanitize: (text) => text,
    checkpoint: async () => {},
    writeStatusIntent: acceptStatusIntent,
    beforeProviderWrite: async (method) => {
      methods.push(method);
      return undefined;
    },
    onSurfacePosted: () => {},
  });

  await presenter.finish("Recovered final result");

  assert.deepEqual(starts, []);
  assert.deepEqual(appends, []);
  assert.deepEqual(stops, [{ channel: "D1", ts: "171.2", session_status: "active" }]);
  assert.equal(updates[0]?.ts, "171.2");
  assert.equal(updates[0]?.text, "Recovered final result");
  assert.deepEqual(methods, ["chat.stopStream", "chat.update"]);
});

test("native cancellation omits stopStream for an event-listed stream", async () => {
  let cancelled = false;
  const stops: any[] = [];
  const deletes: any[] = [];
  const presenter = createNativeAgentPresenter({
    client: {
      apiCall: async () => ({ ok: true }),
      chat: {
        startStream: async () => ({ ts: "171.2" }),
        appendStream: async () => {},
        stopStream: async (args: any) => void stops.push(args),
        delete: async (args: any) => void deletes.push(args),
      },
    },
    channel: "D1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    streaming: true,
    title: "Work",
    sanitize: (text) => text,
    checkpoint: async () => {
      cancelled = true;
      return true;
    },
    writeStatusIntent: acceptStatusIntent,
    isCancelled: async () => cancelled,
    alreadyStopped: async () => true,
    onSurfacePosted: () => {},
  });
  assert.equal(await presenter.begin(), true);
  await presenter.finish("Result");
  assert.deepEqual(stops, []);
  assert.deepEqual(deletes, [{ channel: "D1", ts: "171.2" }]);
});

test("late-created stream cleanup tolerates only exact terminal stop outcomes", async () => {
  for (const reason of ["stopped_by_user", "message_not_in_streaming_state"]) {
    let cancelled = false;
    const deletes: any[] = [];
    const presenter = createNativeAgentPresenter({
      client: {
        apiCall: async () => ({ ok: true }),
        chat: {
          startStream: async () => ({ ts: "171.3" }),
          appendStream: async () => {},
          stopStream: async () => {
            throw { data: { error: reason } };
          },
          delete: async (args: any) => void deletes.push(args),
        },
      },
      channel: "D1",
      threadTs: "170.1",
      initiatorUserId: "U1",
      streaming: true,
      title: "Work",
      sanitize: (text) => text,
      checkpoint: async () => {
        cancelled = true;
        return true;
      },
      writeStatusIntent: acceptStatusIntent,
      isCancelled: async () => cancelled,
      alreadyStopped: async () => false,
      onSurfacePosted: () => {},
    });
    assert.equal(await presenter.begin(), true);
    await presenter.finish("Result");
    assert.deepEqual(deletes, [{ channel: "D1", ts: "171.3" }]);
  }

  let cancelled = false;
  const rejected = createNativeAgentPresenter({
    client: {
      apiCall: async () => ({ ok: true }),
      chat: {
        startStream: async () => ({ ts: "171.4" }),
        appendStream: async () => {},
        stopStream: async () => {
          throw { data: { error: "channel_not_found" } };
        },
        delete: async () => {},
      },
    },
    channel: "D1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    streaming: true,
    title: "Work",
    sanitize: (text) => text,
    checkpoint: async () => {
      cancelled = true;
      return true;
    },
    writeStatusIntent: acceptStatusIntent,
    isCancelled: async () => cancelled,
    alreadyStopped: async () => false,
    onSurfacePosted: () => {},
  });
  assert.equal(await rejected.begin(), true);
  await assert.rejects(rejected.finish("Result"), (error: any) => error?.data?.error === "channel_not_found");
});

test("native agent presenter clears external processing when the durable status checkpoint fails", async () => {
  const statuses: string[] = [];
  const presenter = createNativeAgentPresenter({
    client: {
      apiCall: async (_method: string, args: any) => void statuses.push(args.status),
      chat: { startStream: async () => ({ ts: "171.2" }), appendStream: async () => {}, stopStream: async () => {} },
    },
    channel: "D1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    title: "Durable checkpoint",
    sanitize: (text) => text,
    checkpoint: async () => {},
    writeStatusIntent: async (input) => void statuses.push(input.status),
    onStatus: async () => {
      throw new Error("database unavailable");
    },
    onSurfacePosted: () => {},
  });
  assert.equal(await presenter.begin(), false);
  assert.deepEqual(statuses, ["processing", "active"]);
});

test("native fallback is blocked when its durable status intent cannot be persisted", async () => {
  const phases: string[] = [];
  const presenter = createNativeAgentPresenter({
    client: {
      apiCall: async () => undefined,
      chat: { startStream: async () => ({ ts: "171.2" }), appendStream: async () => {}, stopStream: async () => {} },
    },
    channel: "D1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    title: "Durable checkpoint",
    sanitize: (text) => text,
    checkpoint: async () => {},
    writeStatusIntent: async (input) => {
      phases.push(input.phase);
      if (input.phase === "begin_failed") throw new Error("status store unavailable");
    },
    onStatus: async () => {
      throw new Error("database unavailable");
    },
    onSurfacePosted: () => {},
  });
  await assert.rejects(() => presenter.begin(), /status store unavailable/);
  assert.deepEqual(phases, ["begin_processing", "begin_failed"]);
});

test("stream checkpoint failure cannot swallow a missing terminal status intent", async () => {
  const phases: string[] = [];
  const deleted: string[] = [];
  const presenter = createNativeAgentPresenter({
    client: {
      apiCall: async () => undefined,
      chat: {
        startStream: async () => ({ ts: "171.2" }),
        appendStream: async () => {},
        stopStream: async () => {},
        delete: async ({ ts }: { ts: string }) => void deleted.push(ts),
      },
    },
    channel: "D1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    streaming: true,
    title: "Durable checkpoint",
    sanitize: (text) => text,
    checkpoint: async () => {
      throw new Error("checkpoint unavailable");
    },
    writeStatusIntent: async (input) => {
      phases.push(input.phase);
      if (input.phase === "finish") throw new Error("status store unavailable");
    },
    onSurfacePosted: () => {},
  });
  assert.equal(await presenter.begin(), true);
  presenter.onDelta("A".repeat(400));
  await assert.rejects(() => presenter.finish("A".repeat(400)), /status store unavailable/);
  assert.deepEqual(phases, ["begin_processing", "finish", "finish"]);
  assert.deepEqual(deleted, ["171.2"]);
});

test("native agent presenter clears processing if stream startup fails", async () => {
  const statuses: string[] = [];
  const presenter = createNativeAgentPresenter({
    client: {
      apiCall: async (_method: string, args: any) => void statuses.push(args.status),
      chat: {
        startStream: async () => {
          throw new Error("feature_disabled");
        },
        appendStream: async () => {},
        stopStream: async () => {},
      },
    },
    channel: "D1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    streaming: true,
    title: "Hello",
    sanitize: (text) => text,
    checkpoint: async () => {},
    writeStatusIntent: async (input) => void statuses.push(input.status),
    onSurfacePosted: () => {},
  });
  assert.equal(await presenter.begin(), true);
  presenter.onDelta("A".repeat(400));
  await assert.rejects(() => presenter.finish("A".repeat(400)), /feature_disabled/);
  assert.deepEqual(statuses, ["processing", "active"]);
});

test("native task-card delivery failure never interrupts core polling and settles on final fallback", async () => {
  const statuses: string[] = [];
  const presenter = createNativeAgentPresenter({
    client: {
      apiCall: async (_method: string, args: any) => void statuses.push(args.status),
      chat: {
        startStream: async () => {
          throw new Error("feature_disabled");
        },
        appendStream: async () => {},
        stopStream: async () => {},
      },
    },
    channel: "C1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    recipientTeamId: "T1",
    streaming: true,
    title: "Plan",
    sanitize: (text) => text,
    checkpoint: async () => {},
    writeStatusIntent: async (input) => void statuses.push(input.status),
    onSurfacePosted: () => {},
  });
  assert.equal(await presenter.begin(), true);
  await presenter.onTasks([{ id: "a", title: "Read calendar", status: "in_progress" }]);
  await assert.rejects(() => presenter.finish("Here is the result"), /feature_disabled/);
  assert.deepEqual(statuses, ["processing", "active"]);
});

test("native agent presenter splits long Markdown without breaking surrogate pairs", async () => {
  const starts: any[] = [];
  const appends: any[] = [];
  const stops: any[] = [];
  const client = {
    apiCall: async () => ({ ok: true }),
    chat: {
      startStream: async (args: any) => {
        starts.push(args);
        return { ts: "171.2" };
      },
      appendStream: async (args: any) => void appends.push(args),
      stopStream: async (args: any) => void stops.push(args),
    },
  };
  const presenter = createNativeAgentPresenter({
    client,
    channel: "D1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    streaming: true,
    title: "Long answer",
    sanitize: (text) => text,
    checkpoint: async () => {},
    writeStatusIntent: acceptStatusIntent,
    onSurfacePosted: () => {},
  });
  const reply = `${"a".repeat(11_999)}😀${"b".repeat(12_001)}`;

  assert.equal(await presenter.begin(), true);
  presenter.onDelta(reply);
  await presenter.finish(reply);

  const chunks = [starts[0], ...appends].flatMap((call) => call.chunks).map((chunk) => chunk.text);
  assert.equal(chunks.join(""), reply);
  assert.ok(chunks.every((chunk) => chunk.length <= 12_000));
  assert.ok(chunks.every((chunk) => !/[\uD800-\uDBFF]$/.test(chunk) && !/^[\uDC00-\uDFFF]/.test(chunk)));
  assert.equal(stops[0].session_status, "active");
});

test("native agent presenter preserves every Agent Sessions terminal status including multi-agent responses", async () => {
  const calls: Array<{ method: string; args: any }> = [];
  const client = {
    apiCall: async (method: string, args: any) => {
      calls.push({ method, args });
      return args.status === "active"
        ? { status: "processing", agent_status: "active" }
        : { status: args.status, agent_status: args.status };
    },
    chat: {
      startStream: async () => ({ ts: "171.3" }),
      appendStream: async () => ({ ok: true }),
      stopStream: async () => ({ ok: true }),
    },
  };
  const presenter = createNativeAgentPresenter({
    client,
    channel: "D1",
    threadTs: "170.1",
    initiatorUserId: "U1",
    title: "Need a decision",
    sanitize: (text) => text,
    checkpoint: async () => {},
    writeStatusIntent: async (input) =>
      void calls.push({ method: "agents.sessions.setStatus", args: { status: input.status } }),
    onSurfacePosted: () => {},
  });
  assert.equal(await presenter.begin(), true);
  await presenter.suspend();
  assert.deepEqual(
    calls.map((call) => [call.method, call.args.status]),
    [
      ["agents.sessions.setStatus", "processing"],
      ["agents.sessions.setStatus", "suspended"],
    ],
  );

  const closed = createNativeAgentPresenter({
    client,
    channel: "D1",
    threadTs: "170.2",
    initiatorUserId: "U1",
    title: "Terminal task",
    sanitize: (text) => text,
    checkpoint: async () => {},
    writeStatusIntent: async (input) =>
      void calls.push({ method: "agents.sessions.setStatus", args: { status: input.status } }),
    onSurfacePosted: () => {},
  });
  assert.equal(await closed.begin(), true);
  await closed.finish("", "closed");
  assert.equal(calls.at(-1)?.args.status, "closed");
});

test("renderTaskList renders every terminal state", () => {
  assert.equal(
    renderTaskList([
      { id: "a", title: "done", status: "completed" },
      { id: "b", title: "omitted", status: "skipped" },
      { id: "c", title: "broken", status: "failed" },
    ]),
    "*3 tasks*\n✓ ~done~\n– ~omitted~\n✕ ~broken~",
  );
});

test("renderTaskList escapes task titles as Slack text", () => {
  assert.equal(
    renderTaskList([{ id: "a", title: "inspect <@U123> & report", status: "pending" }]),
    "*1 task*\n○ inspect &lt;@U123&gt; &amp; report",
  );
});

test("renderTaskList preserves distinct tasks that share a title", () => {
  assert.equal(
    renderTaskList([
      { id: "a", title: "research queue", status: "failed" },
      { id: "b", title: "research queue", status: "in_progress" },
      { id: "c", title: "write report", status: "completed" },
    ]),
    "*3 tasks*\n✕ ~research queue~\n◐ research queue\n✓ ~write report~",
  );
});

test("renderTaskList bounds rows and normalizes titles to one line", () => {
  const rendered = renderTaskList(
    Array.from({ length: 25 }, (_, index) => ({
      id: String(index),
      title: `${index} ${"x".repeat(140)}\nforged row`,
      status: "pending" as const,
    })),
  );
  assert.ok(rendered.length < 3_000);
  assert.match(rendered, /… 5 more$/);
  assert.equal(rendered.includes("\nforged row"), false);
});

test("task presenter posts once, updates in place, checkpoints, and finalizes the same message", async () => {
  const calls: string[] = [];
  const presenter = createTaskListPresenter({
    post: async (text) => {
      calls.push(`post:${text}`);
      return "171.2";
    },
    update: async (ts, text) => {
      calls.push(`update:${ts}:${text}`);
    },
    checkpoint: async (ts) => {
      calls.push(`checkpoint:${ts}`);
    },
    remove: async (ts) => {
      calls.push(`remove:${ts}`);
    },
    onSurfacePosted: () => calls.push("surface"),
  });

  await presenter.onTasks([{ id: "a", title: "research", status: "pending" }]);
  await presenter.onTasks([{ id: "a", title: "research", status: "completed" }]);
  assert.equal(await presenter.finalize("Final answer"), true);
  assert.deepEqual(calls, [
    "post:*1 task*\n○ research",
    "checkpoint:171.2",
    "surface",
    "update:171.2:*1 task*\n✓ ~research~",
    "update:171.2:Final answer",
  ]);
});

test("task presenter attaches beneath an existing ack and retries terminal updates", async () => {
  const calls: string[] = [];
  let attempts = 0;
  const presenter = createTaskListPresenter({
    post: async () => {
      throw new Error("must not post");
    },
    update: async (ts, text) => {
      attempts += 1;
      calls.push(`${ts}:${text}`);
      if (text === "Final" && attempts < 4) throw new Error("transient");
    },
    checkpoint: async (ts) => {
      calls.push(`checkpoint:${ts}`);
    },
    remove: async (ts) => {
      calls.push(`remove:${ts}`);
    },
    onSurfacePosted: () => calls.push("surface"),
    sleep: async () => {},
  });
  await presenter.attach("171.3", "On it.");
  await presenter.onTasks([{ id: "a", title: "consult", status: "in_progress" }]);
  assert.equal(await presenter.finalize("Final"), true);
  assert.deepEqual(calls, [
    "checkpoint:171.3",
    "171.3:On it.\n\n*1 task*\n◐ consult",
    "171.3:Final",
    "171.3:Final",
    "171.3:Final",
  ]);
});

test("task presenter merges a late ack into the existing task message", async () => {
  const calls: string[] = [];
  const presenter = createTaskListPresenter({
    post: async () => "171.4",
    update: async (ts, text) => {
      calls.push(`${ts}:${text}`);
    },
    checkpoint: async () => {},
    remove: async () => {},
    onSurfacePosted: () => {},
  });
  await presenter.onTasks([{ id: "a", title: "research", status: "in_progress" }]);
  assert.equal(await presenter.addLead("Still working."), true);
  assert.deepEqual(calls, ["171.4:Still working.\n\n*1 task*\n◐ research"]);
});

test("task presenter removes an ack whose durable checkpoint fails", async () => {
  const removed: string[] = [];
  const presenter = createTaskListPresenter({
    post: async () => undefined,
    update: async () => {},
    checkpoint: async () => {
      throw new Error("core unavailable");
    },
    remove: async (ts) => {
      removed.push(ts);
    },
    onSurfacePosted: () => {},
  });
  await assert.rejects(presenter.attach("171.5", "On it."), /core unavailable/);
  assert.deepEqual(removed, ["171.5"]);
});

test("task presenter reports a failed late-ack merge", async () => {
  const removed: string[] = [];
  const presenter = createTaskListPresenter({
    post: async () => "171.6",
    update: async () => {
      throw new Error("Slack unavailable");
    },
    checkpoint: async () => {},
    remove: async (ts) => {
      removed.push(ts);
    },
    onSurfacePosted: () => {},
    sleep: async () => {},
  });
  await presenter.onTasks([{ id: "a", title: "research", status: "in_progress" }]);
  assert.equal(await presenter.addLead("Still working."), false);
  assert.deepEqual(removed, ["171.6"]);
});

function presenterHarness(opts: { reactionDelayMs?: number } = {}) {
  const calls: string[] = [];
  const presenter = createAckPresenter({
    postAck: async (t) => {
      calls.push(`post:${t}`);
    },
    addReaction: async (e) => {
      calls.push(`add:${e}`);
    },
    removeReaction: async (e) => {
      calls.push(`remove:${e}`);
    },
    emojiCandidates: ["eyes"],
    reactionDelayMs: opts.reactionDelayMs ?? 10,
    random: () => 0,
  });
  return { presenter, calls };
}

const tick = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("ack presenter: a short first block posts as the ack and suppresses the fallback reaction", async () => {
  const { presenter, calls } = presenterHarness({ reactionDelayMs: 50 });
  presenter.onFirstBlock("On it — checking the deploy logs.");
  await tick(80);
  await presenter.settle();
  assert.deepEqual(calls, ["post:On it — checking the deploy logs."]);
});

test("ack presenter: nothing visible by the deadline → ONE reaction, removed on settle (never left stuck)", async () => {
  const { presenter, calls } = presenterHarness({ reactionDelayMs: 5 });
  await tick(30);
  await presenter.settle();
  assert.deepEqual(calls, ["add:eyes", "remove:eyes"]);
});

test("ack presenter: an ack arriving after the reaction removes it before posting (never both at once)", async () => {
  const { presenter, calls } = presenterHarness({ reactionDelayMs: 5 });
  await tick(30);
  presenter.onFirstBlock("On it.");
  await presenter.settle();
  assert.deepEqual(calls, ["add:eyes", "remove:eyes", "post:On it."]);
});

test("ack presenter: a long first block still posts as the ack (no length gate)", async () => {
  const { presenter, calls } = presenterHarness({ reactionDelayMs: 5_000 });
  const long = "y".repeat(400);
  presenter.onFirstBlock(long);
  await presenter.settle();
  assert.deepEqual(calls, [`post:${long}`]);
});

test("ack presenter: onSurfacePosted clears the reaction (spine post reached the channel)", async () => {
  const { presenter, calls } = presenterHarness({ reactionDelayMs: 5 });
  await tick(30);
  presenter.onSurfacePosted();
  await presenter.settle();
  assert.deepEqual(calls, ["add:eyes", "remove:eyes"]);
});

test("ack presenter: settle before the deadline cancels the pending reaction entirely", async () => {
  const { presenter, calls } = presenterHarness({ reactionDelayMs: 30 });
  await presenter.settle();
  await tick(60);
  assert.deepEqual(calls, []);
});

test("ack presenter: only the FIRST first-block signal counts", async () => {
  const { presenter, calls } = presenterHarness({ reactionDelayMs: 5_000 });
  presenter.onFirstBlock("On it.");
  presenter.onFirstBlock("Second block never posts.");
  await presenter.settle();
  assert.deepEqual(calls, ["post:On it."]);
});

function pickHarness(emojiPick: Promise<string | undefined>) {
  const calls: string[] = [];
  const presenter = createAckPresenter({
    postAck: async (t) => void calls.push(`post:${t}`),
    addReaction: async (e) => void calls.push(`add:${e}`),
    removeReaction: async (e) => void calls.push(`remove:${e}`),
    emojiCandidates: ["eyes", "bug"],
    emojiPick,
    reactionDelayMs: 5,
    random: () => 0,
  });
  return { presenter, calls };
}

test("ack presenter: a topical pick that arrives in time is used (and removed on settle)", async () => {
  const { presenter, calls } = pickHarness(Promise.resolve("bug"));
  await tick(30);
  await presenter.settle();
  assert.deepEqual(calls, ["add:bug", "remove:bug"]);
});

test("ack presenter: a declined pick (undefined) falls back to a random candidate", async () => {
  const { presenter, calls } = pickHarness(Promise.resolve(undefined));
  await tick(30);
  await presenter.settle();
  assert.deepEqual(calls, ["add:eyes", "remove:eyes"]);
});

test("ack presenter: a pick that isn't ready when the timer fires falls back to random (never awaited)", async () => {
  let resolvePick: (v: string) => void = () => {};
  const { presenter, calls } = pickHarness(new Promise<string>((r) => (resolvePick = r)));
  await tick(30);
  resolvePick("bug");
  await presenter.settle();
  assert.deepEqual(calls, ["add:eyes", "remove:eyes"]);
});

test("ack presenter: settle never blocks on a never-resolving pick", async () => {
  const { presenter, calls } = pickHarness(new Promise<string>(() => {}));
  await tick(30);
  await presenter.settle();
  assert.deepEqual(calls, ["add:eyes", "remove:eyes"]);
});

test("stripAckPrefix: removes exactly the posted ack prefix (plus the gap), and only when it leads", () => {
  assert.equal(stripAckPrefix("On it.\n\nDone — cloned it.", "On it."), "Done — cloned it.");
  assert.equal(stripAckPrefix("  On it.\nDone.", "On it."), "Done.");
  assert.equal(stripAckPrefix("Done. On it.", "On it."), "Done. On it.", "non-prefix mentions stay");
  assert.equal(stripAckPrefix("Done.", undefined), "Done.", "no ack posted → untouched");
});

test("ack presenter: postedAck exposes the exact posted text; a held block exposes none", async () => {
  const posted = presenterHarness({ reactionDelayMs: 5_000 });
  posted.presenter.onFirstBlock("On it — checking.");
  await posted.presenter.settle();
  assert.equal(posted.presenter.postedAck(), "On it — checking.");

  const long = presenterHarness({ reactionDelayMs: 5_000 });
  long.presenter.onFirstBlock("z".repeat(400));
  await long.presenter.settle();
  assert.equal(long.presenter.postedAck(), "z".repeat(400), "a long block posts too — and is exposed for the strip");
});

test("ack presenter does not report a failed post as surfaced", async () => {
  const presenter = createAckPresenter({
    postAck: async () => {
      throw new Error("checkpoint failed");
    },
    addReaction: async () => {},
    removeReaction: async () => {},
  });
  presenter.onFirstBlock("On it.");
  await presenter.settle();
  assert.equal(presenter.postedAck(), undefined);
});
