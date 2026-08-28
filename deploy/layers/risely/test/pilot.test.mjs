import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createGeminiCompatibilityServer, normalizeGeminiPayload } from "../plugins/gemini-compat/server.mjs";

const root = new URL("../", import.meta.url);
const text = async (path) => readFile(new URL(path, root), "utf8");
const listen = async (server) => {
  server.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  return `http://127.0.0.1:${server.address().port}`;
};
const close = (server) => new Promise((resolve) => server.close(resolve));

test("Slack manifest is branded and runs in Socket Mode", async () => {
  const manifest = await text("slack-app-manifest.yml");
  assert.match(manifest, /name: Risely/);
  assert.match(manifest, /display_name: Risely/);
  assert.match(manifest, /socket_mode_enabled: true/);
  assert.match(manifest, /app_mention/);
  assert.match(manifest, /message\.im/);
  for (const forbidden of ["channels:manage", "groups:write", "files:write", "pins:write", "chat:write.customize"]) {
    assert.doesNotMatch(manifest, new RegExp(forbidden.replace(":", "\\\\:")));
  }
});

test("Gemini provider is pinned to the restricted compatible endpoint", async () => {
  const provider = JSON.parse(await text("gemini-provider.json"));
  assert.equal(provider.id, "google-gemini");
  assert.equal(provider.protocol, "openai");
  assert.equal(provider.baseUrl, "http://gemini-compat.risely-qm-pilot.internal:8080/v1beta/openai");
  assert.deepEqual(
    provider.models.map((model) => model.id),
    ["gemini-3.7-flash", "gemini-3.5-flash"],
  );
  assert.deepEqual(provider.models[0], {
    id: "gemini-3.7-flash",
    name: "Gemini 3.7 Flash",
    contextWindow: 1048576,
    maxTokens: 65536,
    input: 0.75,
    output: 3.75,
  });
});

test("Gemini credential check rejects an arbitrary endpoint before any request", async (t) => {
  let requests = 0;
  const sink = createServer((_request, response) => {
    requests += 1;
    response.writeHead(500);
    response.end();
  });
  const sinkBase = await listen(sink);
  t.after(() => close(sink));

  const child = spawn(process.execPath, [fileURLToPath(new URL("../scripts/check-gemini.mjs", import.meta.url))], {
    env: { ...process.env, GEMINI_API_KEY: "test-only", GEMINI_BASE_URL: sinkBase },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const [code] = await once(child, "exit");
  assert.notEqual(code, 0);
  assert.match(stderr, /GEMINI_BASE_URL must be the committed private gateway or the Google Gemini API endpoint/);
  assert.equal(requests, 0);
});

test("public chat check rejects an arbitrary origin before sending a session cookie", async (t) => {
  const script = await text("scripts/check-public-chat.mjs");
  assert.match(script, /AbortSignal\.timeout\(15_000\)/);
  assert.match(script, /redirect: "error"/);
  let requests = 0;
  const sink = createServer((_request, response) => {
    requests += 1;
    response.writeHead(500);
    response.end();
  });
  const sinkBase = await listen(sink);
  t.after(() => close(sink));

  const child = spawn(process.execPath, [fileURLToPath(new URL("../scripts/check-public-chat.mjs", import.meta.url))], {
    env: {
      ...process.env,
      PUBLIC_API_URL: sinkBase,
      PORTAL_SESSION_SECRET: "test-only",
      AUTH_ALLOWED_EMAILS: "pilot@example.com",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const [code] = await once(child, "exit");
  assert.notEqual(code, 0);
  assert.match(stderr, /PUBLIC_API_URL must be the committed Risely pilot origin/);
  assert.equal(requests, 0);
});

test("Gemini compatibility gateway normalizes QM requests without becoming an open proxy", () => {
  const normalized = normalizeGeminiPayload({
    store: false,
    stream_options: { include_usage: true },
    max_completion_tokens: 4096,
    messages: [
      {
        role: "assistant",
        tool_calls: [{ id: "call-1", type: "function", function: { name: "read", arguments: "{}" } }],
      },
    ],
  });
  assert.equal(normalized.store, undefined);
  assert.equal(normalized.stream_options, undefined);
  assert.equal(normalized.max_completion_tokens, undefined);
  assert.equal(normalized.max_tokens, 4096);
  assert.equal(
    normalized.messages[0].tool_calls[0].extra_content.google.thought_signature,
    "skip_thought_signature_validator",
  );
});

test("Gemini compatibility gateway exposes health and rejects arbitrary destinations", async (t) => {
  const server = createGeminiCompatibilityServer();
  const base = await listen(server);
  t.after(() => close(server));
  assert.equal((await fetch(`${base}/healthz`)).status, 200);
  assert.equal((await fetch(`${base}/https://example.com`)).status, 404);
});

test("Gemini compatibility gateway preserves a sequential tool replay", async (t) => {
  const realFetch = globalThis.fetch.bind(globalThis);
  let upstreamCalls = 0;
  globalThis.fetch = async (input, init) => {
    assert.equal(String(input), "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions");
    const payload = JSON.parse(init.body);
    upstreamCalls += 1;
    if (upstreamCalls === 1) {
      assert.equal(payload.messages[0].content, "Check readiness");
      return new Response(
        JSON.stringify({
          choices: [
            {
              message: {
                role: "assistant",
                content: null,
                tool_calls: [
                  {
                    id: "call-readiness",
                    type: "function",
                    function: { name: "report_readiness", arguments: '{"ready":true}' },
                  },
                ],
              },
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    assert.equal(payload.messages[1].tool_calls[0].id, "call-readiness");
    assert.equal(
      payload.messages[1].tool_calls[0].extra_content.google.thought_signature,
      "skip_thought_signature_validator",
    );
    assert.equal(payload.messages[2].tool_call_id, "call-readiness");
    return new Response(JSON.stringify({ choices: [{ message: { role: "assistant", content: "Ready" } }] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  t.after(() => {
    globalThis.fetch = realFetch;
  });

  const gateway = createGeminiCompatibilityServer();
  const gatewayBase = await listen(gateway);
  t.after(() => close(gateway));

  const first = await realFetch(`${gatewayBase}/v1beta/openai/chat/completions`, {
    method: "POST",
    headers: { authorization: "Bearer test-only", "content-type": "application/json" },
    body: JSON.stringify({
      model: "gemini-test",
      messages: [{ role: "user", content: "Check readiness" }],
      tools: [{ type: "function", function: { name: "report_readiness", parameters: { type: "object" } } }],
    }),
  });
  assert.equal(first.status, 200);
  const firstBody = await first.json();
  const assistant = firstBody.choices[0].message;

  const second = await realFetch(`${gatewayBase}/v1beta/openai/chat/completions`, {
    method: "POST",
    headers: { authorization: "Bearer test-only", "content-type": "application/json" },
    body: JSON.stringify({
      model: "gemini-test",
      messages: [
        { role: "user", content: "Check readiness" },
        assistant,
        { role: "tool", tool_call_id: "call-readiness", content: '{"ready":true}' },
      ],
    }),
  });
  assert.equal(second.status, 200);
  assert.equal((await second.json()).choices[0].message.content, "Ready");
  assert.equal(upstreamCalls, 2);
});

test("Gemini compatibility gateway survives an upstream body-stream failure", async (t) => {
  const realFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = async () =>
    new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"partial":'));
          controller.error(new Error("test upstream stream failure"));
        },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  t.after(() => {
    globalThis.fetch = realFetch;
  });

  const gateway = createGeminiCompatibilityServer();
  const gatewayBase = await listen(gateway);
  t.after(() => close(gateway));

  await assert.rejects(
    realFetch(`${gatewayBase}/v1beta/openai/chat/completions`, {
      method: "POST",
      headers: { authorization: "Bearer test-only", "content-type": "application/json" },
      body: JSON.stringify({ model: "gemini-test", messages: [{ role: "user", content: "Fail safely" }] }),
    }),
  );
  assert.equal((await realFetch(`${gatewayBase}/healthz`)).status, 200);
});

test("deployment uses a published reproducible QM CLI", async () => {
  const packageJson = JSON.parse(await text("package.json"));
  assert.equal(packageJson.dependencies["@yc-software/qm"], "0.1.5");
  assert.doesNotMatch(JSON.stringify(packageJson), /file:\.\.\/\.\.\/\.\.\/cli/);
  assert.equal(packageJson.scripts["gemini:register-local"], undefined);
  assert.equal(packageJson.scripts["governance:lock"], "node --env-file=.env scripts/lock-pilot-governance.mjs");
});

test("pilot governance lock denies every shell command by default", async () => {
  const script = await text("scripts/lock-pilot-governance.mjs");
  assert.match(script, /const desired = \{ mode: "allowlist", rules: \[\] \}/);
  assert.match(script, /Governance lock verification failed/);
});

test("AWS database transport preserves QM's verified RDS CA configuration", async () => {
  const main = await text("infra/main.tf");
  const variables = await text("infra/variables.tf");
  const envExample = await text(".env.example");
  assert.match(main, /deletion_protection\s+= var\.db_deletion_protection/);
  assert.doesNotMatch(main, /sslmode=/);
  assert.match(main, /secret_string = "postgresql:\/\/.+\$\{var\.db_name\}"/);
  assert.match(envExample, /^DATABASE_CA_CERT=$/m);
  assert.match(envExample, /us-west-2-bundle\.pem/);
  assert.match(variables, /variable "db_deletion_protection"/);
});

test("Risely portal opens chat when its verified custom provider is ready", async () => {
  const config = await text("qm.config.jsonc");
  const dockerfile = await text("overrides/portal/Dockerfile");
  const patch = await text("overrides/portal/patch.mjs");
  const status = await text("PILOT-STATUS.md");
  assert.match(
    config,
    /"portal": "075343201918\.dkr\.ecr\.us-west-2\.amazonaws\.com\/risely-qm-pilot-portal@sha256:eedc2a58d758344b383fd5680545f18f3392f1dbd6b653ef4bc62ea44cd7547f"/,
  );
  assert.match(config, /"portal": \{ "RISELY_CUSTOM_PROVIDER_READY": "1" \}/);
  assert.match(
    dockerfile,
    /FROM ghcr\.io\/yc-software\/qm\/portal@sha256:33aa80f67ddd9967d0f6b70cd3f2a060bc34b66b711d3940fb9bd047899972c0/,
  );
  assert.match(status, /sha256:eedc2a58d758344b383fd5680545f18f3392f1dbd6b653ef4bc62ea44cd7547f/);
  assert.match(patch, /modelProviderConfigured === false && process\.env\.RISELY_CUSTOM_PROVIDER_READY !== "1"/);
});

test("every pilot workflow declares a fail-closed approval boundary", async () => {
  const paths = [
    "sandbox/skills/chief-of-staff/SKILL.md",
    "sandbox/skills/sales-deal/SKILL.md",
    "sandbox/skills/pipeline/SKILL.md",
  ];
  for (const path of paths) {
    const skill = await text(path);
    assert.match(skill, /^---\nname: [a-z-]+\ndescription: .+\n---/);
    assert.match(skill, /explicit (?:human )?approval/i);
    assert.match(skill, /If the approval tool is unavailable, return a draft only and state that no action occurred/);
  }
});

test("chief of staff prohibits unapproved side effects", async () => {
  const skill = await text("sandbox/skills/chief-of-staff/SKILL.md");
  for (const action of [
    "send email",
    "post to a channel",
    "calendar event",
    "mutate CRM",
    "publish or share an artifact",
  ]) {
    assert.match(skill, new RegExp(action, "i"));
  }
});

test("workflows protect shared-channel evidence and sales cannot claim unexecuted work", async () => {
  const chief = await text("sandbox/skills/chief-of-staff/SKILL.md");
  const deal = await text("sandbox/skills/sales-deal/SKILL.md");
  const pipeline = await text("sandbox/skills/pipeline/SKILL.md");
  assert.match(deal, /Never mark .+ complete until the executing tool returns success/);
  assert.match(deal, /Never send or write directly/);
  assert.match(deal, /Never infer proposal scope, deliverables, integrations, technical standards, CRM stage/);
  assert.match(deal, /Preserve every supplied unknown as `Unknown` or `To be confirmed`/);
  assert.match(deal, /A customer commitment is an explicit promise by the customer to act/);
  assert.match(deal, /Attach a date only to the exact request or commitment it modifies/);
  assert.match(deal, /Customer-stated desired outcome/);
  assert.match(deal, /Do not replace `review` with `integration`/);
  assert.match(deal, /Do not classify a meeting or opportunity as qualified unless the evidence explicitly does so/);
  assert.match(deal, /A draft customer email may include only supplied facts and explicit commitments/);
  assert.match(deal, /## Mandatory evidence audit/);
  assert.match(deal, /Keep supplied unknowns together under `Unresolved unknowns`/);
  assert.match(deal, /If an output section has no directly supplied evidence, write `None evidenced`/);
  assert.match(deal, /proposal due September 1 and security-question list due `To be confirmed`/);
  assert.match(deal, /Do not expand it into SSO integration, SSO standards, policies, specifications/);
  assert.match(
    deal,
    /Action status: Draft only\. No email was sent, no CRM record was changed, and no proposal was published\./,
  );
  for (const skill of [chief, deal, pipeline]) {
    assert.match(
      skill,
      /If channel membership or audience permissions are uncertain, offer a private response and do not disclose the evidence/,
    );
  }
});

test("company goals are explicitly internal", async () => {
  const goals = await text("sandbox/skills/chief-of-staff/references/q3-2026-goals.md");
  assert.match(goals, /Classification: Risely internal/);
  assert.match(goals, /Do not disclose customer names, financial targets, or person-level evidence/);
});
