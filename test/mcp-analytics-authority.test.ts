import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { test } from "node:test";
import { createAuditLog } from "../src/audit/audit-log.ts";
import { deriveConnectorKey } from "../src/connectors/connector-client-store.ts";
import {
  createMcpAuthoritySigner,
  mcpAuthoritySignerConfigFromEnv,
  type McpAuthorityPayload,
  type McpHumanCallContext,
} from "../src/mcp/mcp-authority.ts";
import { createMcpServerStore, type McpAllowedTool, type McpServer } from "../src/mcp/mcp-server-store.ts";
import { createMcpToolService } from "../src/mcp/mcp-tool-service.ts";
import type { McpFetch } from "../src/mcp/mcp-client.ts";
import { parseAnalyticsNativeDelivery } from "../src/mcp/mcp-native-card.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { analyticsNativeCardBlocks } from "../src/slack/native-cards.ts";

const keys = generateKeyPairSync("ed25519");
const signerConfig = {
  issuer: "qm:test",
  organizationId: "org-founder",
  principalId: "founder-principal",
  slackTeamId: "T123",
  slackUserId: "U123",
  slackDmChannelId: "D123",
  privateKey: keys.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
  ttlSeconds: 30,
};
const context: McpHumanCallContext = {
  surface: "slack",
  conversationType: "dm",
  principalId: "U123",
  slackTeamId: "T123",
  slackUserId: "U123",
  slackChannelId: "D123",
  slackMessageTs: "1788119999.000001",
  slackThreadTs: "1788119999.000001",
};
const inputSchema = {
  type: "object",
  properties: { question: { type: "string", minLength: 3, maxLength: 2_000 } },
  required: ["question"],
  additionalProperties: false,
};
const remoteTool = {
  name: "analytics_query",
  description: "Bounded analytics",
  inputSchema,
  annotations: { readOnlyHint: true, destructiveHint: false },
};
const allowedTool: McpAllowedTool = {
  name: "analytics_query",
  label: "Analyze account",
  status: "Analyzing account",
  readOnly: true,
  inputSchema,
  requestAuthority: "qm.ed25519.founder-dm.v1",
  nativeRenderer: "qm.analytics.card.v1",
};
const server: McpServer = {
  id: "analytics",
  name: "Analytics",
  url: "https://analytics.example.com/api/mcp/analytics/mcp",
  auth: "none",
  scopes: [],
  allowedTools: [allowedTool],
  readOnly: true,
  enabled: true,
  credentialState: "none",
  updatedAt: 1,
  updatedBy: "UADMIN",
};

function response(id: number, result: unknown) {
  return {
    ok: true,
    status: 200,
    headers: { get: (name: string) => (name.toLowerCase() === "content-type" ? "application/json" : null) },
    text: async () => JSON.stringify({ jsonrpc: "2.0", id, result }),
  };
}

function decodeAuthority(token: string): McpAuthorityPayload {
  const [encoded, signature] = token.split(".");
  assert.ok(encoded && signature);
  assert.equal(verify(null, Buffer.from(encoded, "ascii"), keys.publicKey, Buffer.from(signature, "base64url")), true);
  return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as McpAuthorityPayload;
}

function delivery(authority: McpAuthorityPayload, over: Record<string, unknown> = {}) {
  return {
    version: 1,
    delivery: {
      version: 1,
      renderer: "qm.analytics.card.v1",
      receiptId: "a".repeat(64),
      authority: {
        organizationId: authority.organizationId,
        principalId: authority.principalId,
        slackTeamId: authority.slackTeamId,
        slackUserId: authority.slackUserId,
        slackChannelId: authority.slackChannelId,
        slackConversationType: authority.slackConversationType,
        slackMessageTs: authority.slackMessageTs,
        slackThreadTs: authority.slackThreadTs,
        jti: authority.jti,
      },
      fallbackText: "Analytics result",
      heading: "Analytics · UC Online",
      question: "How is UC Online doing?",
      findings: [{ source: "posthog", topic: "usage", text: "Active usage is 12.", confidence: "high" }],
      confidenceNotes: ["Missing: clarify"],
      nextStep: "Review the evidence.",
      proposedActions: ["Draft an email."],
      ...over,
    },
  };
}

async function serviceWith(fetchImpl: McpFetch, withSigner = true) {
  const store = createMcpServerStore(
    createMemoryMap(),
    deriveConnectorKey("mcp-authority-test-key", "mcp-server-secrets"),
  );
  const service = createMcpToolService({
    servers: store,
    fetchImpl,
    audit: createAuditLog(),
    ...(withSigner ? { authoritySigner: createMcpAuthoritySigner(signerConfig, () => 1_788_119_999_000) } : {}),
    refreshIntervalMs: 3_600_000,
  });
  await store.put(server);
  await service.refresh();
  return service;
}

test("founder-DM signer binds canonical body and rejects every other user, team, channel, or surface", () => {
  const signer = createMcpAuthoritySigner(signerConfig, () => 1_788_119_999_000);
  const envelope = signer.sign("analytics_query", { question: "How is UC Online doing?" }, context);
  const payload = decodeAuthority(envelope.token);
  assert.equal(payload.bodySha256, "9933fef2fa384037708bb2ba23efe6e986823f3cec76ba4f60f8c17acfdc4ae2");
  assert.equal(payload.iat, 1_788_119_999);
  assert.equal(payload.exp, 1_788_120_029);
  for (const changed of [
    { principalId: "U999", slackUserId: "U999" },
    { slackTeamId: "T999" },
    { slackChannelId: "D999" },
    { conversationType: "group" },
    { surface: "web" },
    { slackThreadTs: "bad" },
  ]) {
    assert.throws(() => signer.sign("analytics_query", {}, { ...context, ...changed } as McpHumanCallContext));
  }
  assert.throws(() =>
    signer.sign("analytics_query", {}, {
      ...context,
      slackTeamId: undefined,
      slackTeamIds: ["T123", "T999"],
    } as unknown as McpHumanCallContext),
  );
  assert.throws(() => signer.sign("other", {}, context));
  const unicodeBody = { "\uE000": "private", "😀": "surrogate" };
  const unicodePayload = decodeAuthority(signer.sign("analytics_query", unicodeBody, context).token);
  assert.equal(
    unicodePayload.bodySha256,
    createHash("sha256")
      .update(JSON.stringify({ "😀": "surrogate", "\uE000": "private" }))
      .digest("hex"),
  );
});

test("authority environment loading is default-off and rejects partial configuration", () => {
  assert.equal(mcpAuthoritySignerConfigFromEnv({}), undefined);
  assert.throws(() => mcpAuthoritySignerConfigFromEnv({ QM_MCP_AUTHORITY_ISSUER: "qm:test" }));
  assert.throws(() => createMcpAuthoritySigner({ ...signerConfig, ttlSeconds: 1 }));
});

test("native analytics parser rejects remote blocks and QM renders bounded escaped Slack blocks", () => {
  const authority = decodeAuthority(
    createMcpAuthoritySigner(signerConfig, () => 1_788_119_999_000).sign(
      "analytics_query",
      { question: "How is UC Online doing?" },
      context,
    ).token,
  );
  assert.equal(parseAnalyticsNativeDelivery(delivery(authority, { blocks: [] }), authority), null);
  const parsed = parseAnalyticsNativeDelivery(
    delivery(authority, {
      fallbackText: "Ping <@U123> or @Alice & review",
      question: "How is UC Online doing?\nUse current evidence.",
      findings: [{ source: "posthog", topic: "usage", text: "<@here> & 12 active", confidence: "high" }],
    }),
    authority,
  );
  assert.ok(parsed);
  assert.equal(parsed.card.fallbackText, "Ping &lt;@\u200bU123&gt; or @\u200bAlice &amp; review");
  const rendered = JSON.stringify(analyticsNativeCardBlocks(parsed.card));
  assert.doesNotMatch(rendered, /<@here>/);
  assert.match(rendered, /&lt;@here&gt; &amp; 12 active/);
});

test("tool service injects authority only on tools/call and accepts one exact authority-bound native card", async () => {
  const seen: Array<{ method: string; authority?: string }> = [];
  const fetchImpl: McpFetch = async (_url, init) => {
    const request = JSON.parse(init.body) as { id: number; method: string };
    const authorityToken = init.headers["x-risely-qm-authority"];
    seen.push({ method: request.method, ...(authorityToken ? { authority: authorityToken } : {}) });
    if (request.method === "tools/list") return response(request.id, { tools: [remoteTool] });
    assert.ok(authorityToken);
    const authority = decodeAuthority(authorityToken);
    return response(request.id, {
      content: [{ type: "text", text: JSON.stringify({ answer: 12 }) }],
      structuredContent: delivery(authority),
    });
  };
  const service = await serviceWith(fetchImpl);
  const result = await service.callWithContext(
    "analytics_analytics_query",
    { question: "How is UC Online doing?" },
    context,
    "U123",
  );
  assert.equal(result.text, JSON.stringify({ answer: 12 }));
  assert.equal(result.nativeCard?.renderer, "qm.analytics.card.v1");
  assert.equal(result.nativeCardIdempotencyKey, `mcp-card:${"a".repeat(64)}`);
  assert.ok(seen.filter((entry) => entry.method === "tools/list").every((entry) => !entry.authority));
  assert.equal(seen.filter((entry) => entry.method === "tools/call").length, 1);
  assert.ok(seen.find((entry) => entry.method === "tools/call")?.authority);
  service.close();
});

test("missing signer and tampered native-card authority fail closed", async () => {
  let calls = 0;
  const noSigner = await serviceWith(async (_url, init) => {
    const request = JSON.parse(init.body) as { id: number; method: string };
    if (request.method === "tools/call") calls += 1;
    return response(request.id, { tools: [remoteTool] });
  }, false);
  await assert.rejects(
    () =>
      noSigner.callWithContext("analytics_analytics_query", { question: "How is UC Online doing?" }, context, "U123"),
    /authority is unavailable/,
  );
  assert.equal(calls, 0);
  noSigner.close();

  const tampered = await serviceWith(async (_url, init) => {
    const request = JSON.parse(init.body) as { id: number; method: string };
    if (request.method === "tools/list") return response(request.id, { tools: [remoteTool] });
    const authority = decodeAuthority(init.headers["x-risely-qm-authority"]!);
    return response(request.id, {
      content: [{ type: "text", text: "result" }],
      structuredContent: delivery(authority, {
        authority: {
          organizationId: authority.organizationId,
          principalId: authority.principalId,
          slackTeamId: authority.slackTeamId,
          slackUserId: "U999",
          slackChannelId: authority.slackChannelId,
          slackConversationType: authority.slackConversationType,
          slackMessageTs: authority.slackMessageTs,
          slackThreadTs: authority.slackThreadTs,
          jti: authority.jti,
        },
      }),
    });
  });
  await assert.rejects(
    () =>
      tampered.callWithContext("analytics_analytics_query", { question: "How is UC Online doing?" }, context, "U123"),
    /native renderer result is invalid/,
  );
  tampered.close();
});
