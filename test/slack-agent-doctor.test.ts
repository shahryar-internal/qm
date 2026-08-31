import { readFile } from "node:fs/promises";
import { test } from "node:test";
import assert from "node:assert/strict";
import { missingSlackAgentCapabilities, requiredSlackScopes, slackCheck } from "../cli/src/backends/doctor.ts";

test("doctor accepts the shipped Agent View manifest contract", async () => {
  const manifest = await readFile(new URL("../cli/templates/slack-manifest.json", import.meta.url), "utf8");
  assert.deepEqual(missingSlackAgentCapabilities(manifest), []);
});

test("doctor rejects an Assistant-era manifest without Agent Sessions lifecycle events", () => {
  const manifest = JSON.stringify({
    features: {
      assistant_view: { assistant_description: "legacy" },
      app_home: { messages_tab_enabled: true, messages_tab_read_only_enabled: false },
    },
    settings: { event_subscriptions: { bot_events: ["message.im"] }, interactivity: { is_enabled: true } },
  });
  const missing = missingSlackAgentCapabilities(manifest);
  assert.ok(missing.includes("features.agent_view"));
  assert.ok(missing.includes("event:app_home_opened"));
  assert.ok(missing.includes("event:app_context_changed"));
  assert.ok(missing.includes("event:assistant_thread_started"));
  assert.ok(missing.includes("event:assistant_thread_context_changed"));
  assert.ok(missing.includes("event:agent_session_stopped"));
});

test("doctor parses YAML structurally and ignores commented fake capabilities", () => {
  const fake = `
features:
  app_home:
    messages_tab_enabled: true
    messages_tab_read_only_enabled: false
  # agent_view:
  #   agent_description: forged
  #   suggested_prompts:
  #     - title: forged
settings:
  interactivity:
    is_enabled: true
  event_subscriptions:
    bot_events:
      - message.im
      - app_home_opened
      - app_context_changed
      # - agent_session_stopped
      # - agent_session_title_changed
`;
  const missing = missingSlackAgentCapabilities(fake);
  assert.ok(missing.includes("features.agent_view"));
  assert.ok(missing.includes("event:agent_session_stopped"));
  assert.ok(missing.includes("event:agent_session_title_changed"));
});

test("doctor accepts an equivalent structurally nested YAML Agent View manifest", () => {
  const manifest = `
features:
  agent_view:
    agent_description: Workspace agent
    suggested_prompts:
      - title: Research
        message: Research this
  app_home:
    messages_tab_enabled: true
    messages_tab_read_only_enabled: false
settings:
  interactivity:
    is_enabled: true
  event_subscriptions:
    bot_events:
      - message.im
      - app_home_opened
      - app_context_changed
      - assistant_thread_started
      - assistant_thread_context_changed
      - agent_session_stopped
      - agent_session_title_changed
`;
  assert.deepEqual(missingSlackAgentCapabilities(manifest), []);
});

test("doctor accepts unquoted inline-flow Agent View capabilities", () => {
  const manifest = `
features:
  agent_view: {agent_description: Workspace agent, suggested_prompts: [{title: Research, message: Research this}]}
  app_home: {messages_tab_enabled: true, messages_tab_read_only_enabled: false}
settings:
  interactivity: {is_enabled: true}
  event_subscriptions:
    bot_events: [message.im, app_home_opened, app_context_changed, assistant_thread_started, assistant_thread_context_changed, agent_session_stopped, agent_session_title_changed]
`;
  assert.deepEqual(missingSlackAgentCapabilities(manifest), []);
});

test("doctor accepts the maintained deployment manifest contract", async () => {
  const manifest = await readFile(new URL("../deploy/stacks/acme/slack-app-manifest.yml", import.meta.url), "utf8");
  assert.deepEqual(missingSlackAgentCapabilities(manifest), []);
});

test("doctor rejects an installed Slack manifest that is behind the reviewed local contract", async () => {
  const previousFetch = globalThis.fetch;
  const calls: Array<{ url: string; body?: string }> = [];
  const scopes = requiredSlackScopes().join(",");
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, ...(typeof init?.body === "string" ? { body: init.body } : {}) });
    if (url.endsWith("/auth.test")) {
      return new Response(JSON.stringify({ ok: true, app_id: "A1" }), {
        status: 200,
        headers: { "content-type": "application/json", "x-oauth-scopes": scopes },
      });
    }
    if (url.endsWith("/apps.manifest.export")) {
      return new Response(
        JSON.stringify({
          ok: true,
          manifest: {
            features: {
              app_home: { messages_tab_enabled: true, messages_tab_read_only_enabled: false },
              assistant_view: { assistant_description: "stale" },
            },
            settings: {
              interactivity: { is_enabled: true },
              event_subscriptions: { bot_events: ["message.im"] },
            },
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error(`unexpected URL ${url}`);
  }) as typeof fetch;
  try {
    await assert.rejects(slackCheck("xoxb-test", "xapp-test", undefined, "xoxe-test"), /installed app is missing/i);
    assert.equal(calls[1]?.url.endsWith("/apps.manifest.export"), true);
    assert.equal(new URLSearchParams(calls[1]?.body).get("app_id"), "A1");
  } finally {
    globalThis.fetch = previousFetch;
  }
});
