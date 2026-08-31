import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { createLocalJWKSet, importJWK, jwtVerify } from "jose";
import type { App } from "../src/api/app.ts";
import { createServer } from "../src/api/server.ts";
import { createAuditLog } from "../src/audit/audit-log.ts";
import { deriveConnectorKey } from "../src/connectors/connector-client-store.ts";
import type { McpFetch } from "../src/mcp/mcp-client.ts";
import type { McpHumanCallContext } from "../src/mcp/mcp-authority.ts";
import {
  createMcpServerStore,
  notionAuthorityServerContract,
  parseMcpAllowedTools,
  type McpAllowedTool,
  type McpServer,
} from "../src/mcp/mcp-server-store.ts";
import { createMcpToolService } from "../src/mcp/mcp-tool-service.ts";
import {
  NOTION_READ_AUTHORITY,
  createNotionAuthoritySigner,
  notionAuthoritySignerConfigFromEnv,
  notionReadCanonicalPayload,
  type NotionAuthorityClaims,
  type NotionAuthoritySigner,
} from "../src/mcp/notion-authority.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";

const keys = generateKeyPairSync("rsa", { modulusLength: 2_048, publicExponent: 0x10001 });
const privateKey = keys.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
const config = {
  issuer: "https://qm.example.com/",
  audience: "https://command-center.example.com/notion",
  keyId: "notion-authority-2026-08",
  organizationId: "risely",
  actorPrincipalId: "founder@example.com",
  slackTeamId: "T12345678",
  slackUserId: "U12345678",
  slackDmChannelId: "D12345678",
  privateKey,
  ttlSeconds: 30,
};
const context: McpHumanCallContext = {
  surface: "slack",
  conversationType: "dm",
  principalId: config.actorPrincipalId,
  slackTeamId: config.slackTeamId,
  slackUserId: config.slackUserId,
  slackChannelId: config.slackDmChannelId,
  slackMessageTs: "1788119999.000001",
  slackThreadTs: "1788119999.000001",
  deliveryTarget: config.slackDmChannelId,
};
const workflowSchema = {
  type: "string",
  enum: ["meeting_brief", "post_meeting_notes", "proposal", "research", "marketing_draft", "general"],
};
const authoritySchema = { type: "string", minLength: 1, maxLength: 16_384 };
const searchSchema = {
  type: "object",
  properties: {
    workflow: workflowSchema,
    query: { type: "string", minLength: 1, maxLength: 1_000 },
    authorityEnvelope: authoritySchema,
  },
  required: ["workflow", "query", "authorityEnvelope"],
  additionalProperties: false,
};
const readSchema = {
  type: "object",
  properties: {
    workflow: workflowSchema,
    pageId: { type: "string", minLength: 1, maxLength: 128 },
    authorityEnvelope: authoritySchema,
  },
  required: ["workflow", "pageId", "authorityEnvelope"],
  additionalProperties: false,
};
const allowedTools: McpAllowedTool[] = [
  {
    name: "notion_search",
    label: "Search Notion",
    status: "Searching Notion",
    readOnly: true,
    inputSchema: searchSchema,
    requestAuthority: NOTION_READ_AUTHORITY,
  },
  {
    name: "notion_read_page",
    label: "Read Notion page",
    status: "Reading Notion page",
    readOnly: true,
    inputSchema: readSchema,
    requestAuthority: NOTION_READ_AUTHORITY,
  },
];
const notionMcpUrl = "https://command-center.example.com/api/mcp/notion/mcp";
const tokenUrl = "https://identity.example.com/oauth/token";
const server: McpServer = {
  id: "notion",
  name: "Command Center Notion",
  url: notionMcpUrl,
  auth: "client-credentials",
  clientId: "qm-notion-reader",
  clientSecret: "notion-client-secret",
  tokenUrl,
  audience: notionMcpUrl,
  tokenAuthMethod: "client_secret_post",
  tokenAudienceParameter: "audience",
  scopes: ["notion:read"],
  allowedTools,
  readOnly: true,
  enabled: true,
  credentialState: "ready",
  updatedAt: 1,
  updatedBy: "UADMIN",
};
const commandCenterFixtureBytes = readFileSync(
  new URL("./fixtures/command-center-notion-m2m-tools-list.json", import.meta.url),
  "utf8",
);
const commandCenterFixture = JSON.parse(commandCenterFixtureBytes) as {
  tools: Array<{
    name: string;
    annotations: Record<string, unknown>;
    inputSchema: Record<string, unknown>;
  }>;
};
const commandCenterFixtureSource = JSON.parse(
  readFileSync(new URL("./fixtures/command-center-notion-m2m-tools-list.source.json", import.meta.url), "utf8"),
) as { repository: string; commit: string; path: string; sha256: string };
const remoteTools = commandCenterFixture.tools;

function response(id: number, result: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name: string) => (name.toLowerCase() === "content-type" ? "application/json" : null) },
    text: async () => JSON.stringify({ jsonrpc: "2.0", id, result }),
  };
}

function decodeClaims(token: string): NotionAuthorityClaims {
  const pieces = token.split(".");
  assert.equal(pieces.length, 3);
  return JSON.parse(Buffer.from(pieces[1]!, "base64url").toString("utf8")) as NotionAuthorityClaims;
}

async function verifyEnvelope(token: string, signer: NotionAuthoritySigner) {
  const jwk = signer.publicState().jwks.keys[0]!;
  return jwtVerify(token, await importJWK(jwk, "RS256"), {
    algorithms: ["RS256"],
    issuer: config.issuer,
    audience: config.audience,
    currentDate: new Date("2026-08-30T20:00:15.000Z"),
  });
}

async function serviceWith(fetchImpl: McpFetch, signer?: NotionAuthoritySigner, audit = createAuditLog()) {
  const store = createMcpServerStore(
    createMemoryMap(),
    deriveConnectorKey("notion-authority-test-key", "mcp-server-secrets"),
  );
  const service = createMcpToolService({
    servers: store,
    fetchImpl: async (url, init) => {
      if (url === tokenUrl) {
        const tokenRequest = new URLSearchParams(init.body);
        assert.equal(init.method, "POST");
        assert.equal(tokenRequest.get("grant_type"), "client_credentials");
        assert.equal(tokenRequest.get("client_id"), server.clientId);
        assert.equal(tokenRequest.get("client_secret"), server.clientSecret);
        assert.equal(tokenRequest.get("audience"), notionMcpUrl);
        assert.equal(tokenRequest.get("scope"), "notion:read");
        return {
          ok: true,
          status: 200,
          headers: { get: (name: string) => (name.toLowerCase() === "content-type" ? "application/json" : null) },
          text: async () =>
            JSON.stringify({ access_token: "notion-m2m-access-token", token_type: "Bearer", expires_in: 300 }),
        };
      }
      assert.equal(url, notionMcpUrl);
      assert.equal(init.headers.authorization, "Bearer notion-m2m-access-token");
      return fetchImpl(url, init);
    },
    audit,
    ...(signer ? { notionAuthoritySigner: signer } : {}),
    refreshIntervalMs: 3_600_000,
  });
  await store.put(server);
  await service.refresh();
  return service;
}

test("RS256 Notion authority binds the exact founder DM, tool, canonical body, issuer, audience, and kid", async () => {
  const signer = createNotionAuthoritySigner(config, { now: () => Date.parse("2026-08-30T20:00:00.000Z") });
  const body = { workflow: "proposal", query: "CBS" };
  const envelope = signer.sign("notion_search", body, context);
  const verified = await verifyEnvelope(envelope.token, signer);
  assert.deepEqual(verified.protectedHeader, {
    alg: "RS256",
    typ: "job-authority+jwt",
    kid: config.keyId,
  });
  assert.equal(envelope.canonicalPayload, notionReadCanonicalPayload("notion_search", body));
  assert.match(envelope.claims.jti, /^[A-Za-z0-9][A-Za-z0-9._:@/-]{15,199}$/u);
  assert.match(envelope.claims.requestId, /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/u);
  assert.equal(
    verified.payload.payloadSha256,
    createHash("sha256").update(envelope.canonicalPayload, "utf8").digest("hex"),
  );
  assert.deepEqual(verified.payload, envelope.claims);
  assert.deepEqual(envelope.claims, {
    iss: config.issuer,
    sub: config.actorPrincipalId,
    aud: config.audience,
    exp: 1_788_120_030,
    iat: 1_788_120_000,
    jti: envelope.claims.jti,
    scope: "notion:read",
    organizationId: config.organizationId,
    actorPrincipalId: config.actorPrincipalId,
    actorSlackId: config.slackUserId,
    audienceScopeId: `personal:${config.actorPrincipalId}`,
    slackTeamId: config.slackTeamId,
    channelId: config.slackDmChannelId,
    messageTs: context.slackMessageTs,
    threadTs: context.slackThreadTs,
    tool: "notion_search",
    requestId: envelope.claims.requestId,
    payloadSha256: envelope.claims.payloadSha256,
  });
  assert.deepEqual(envelope.dispatchArguments, { ...body, authorityEnvelope: envelope.token });
  const publicKey = await importJWK(signer.publicState().jwks.keys[0]!, "RS256");
  await assert.rejects(() =>
    jwtVerify(envelope.token, publicKey, {
      algorithms: ["RS256"],
      issuer: "https://other.example.com/",
      audience: config.audience,
      currentDate: new Date("2026-08-30T20:00:15.000Z"),
    }),
  );
  await assert.rejects(() =>
    jwtVerify(envelope.token, publicKey, {
      algorithms: ["RS256"],
      issuer: config.issuer,
      audience: "https://other.example.com/notion",
      currentDate: new Date("2026-08-30T20:00:15.000Z"),
    }),
  );
  await assert.rejects(() =>
    jwtVerify(
      envelope.token,
      createLocalJWKSet({ keys: [{ ...signer.publicState().jwks.keys[0]!, kid: "other-key" }] }),
      {
        algorithms: ["RS256"],
        issuer: config.issuer,
        audience: config.audience,
        currentDate: new Date("2026-08-30T20:00:15.000Z"),
      },
    ),
  );
  assert.deepEqual(signer.publicState().readiness, {
    status: "ready",
    algorithm: "RS256",
    authority: NOTION_READ_AUTHORITY,
    tools: ["notion_search", "notion_read_page"],
  });
  assert.equal(JSON.stringify(signer.publicState().readiness).includes(config.issuer), false);
  assert.equal(JSON.stringify(signer.publicState().readiness).includes(config.audience), false);
  assert.equal(JSON.stringify(signer.publicState().readiness).includes(config.keyId), false);
  assert.equal(Object.isFrozen(signer.publicState()), true);
  assert.equal(Object.isFrozen(signer.publicState().jwks), true);
  assert.equal(Object.isFrozen(signer.publicState().jwks.keys), true);
  assert.equal(Object.isFrozen(signer.publicState().jwks.keys[0]), true);
  assert.equal(Object.isFrozen(signer.publicState().readiness), true);
  assert.equal(Object.isFrozen(signer.publicState().readiness.tools), true);
});

test("Notion authority rejects every provenance substitution and every non-read or caller-authority body", () => {
  const signer = createNotionAuthoritySigner(config);
  for (const changed of [
    { principalId: "attacker@example.com" },
    { slackUserId: "U87654321" },
    { slackTeamId: "T87654321" },
    { slackChannelId: "D87654321" },
    { slackMessageTs: "bad" },
    { slackThreadTs: "bad" },
    { conversationType: "group" },
    { surface: "web" },
    { deliveryTarget: "D87654321" },
  ]) {
    assert.throws(() =>
      signer.sign("notion_search", { workflow: "research", query: "plans" }, {
        ...context,
        ...changed,
      } as McpHumanCallContext),
    );
  }
  assert.throws(() => signer.sign("notion_create_page", {}, context), /tool is not allowed/);
  assert.throws(
    () => signer.sign("notion_search", { workflow: "research", query: "plans", authorityEnvelope: "caller" }, context),
    /body is invalid/,
  );
  assert.throws(() => signer.sign("notion_read_page", { workflow: "research", pageId: "bad page" }, context));
  assert.throws(() => signer.sign("notion_search", { workflow: "write", query: "plans" }, context));
});

test("Notion authority configuration is default-off and fails closed on partial, mismatched, or weak settings", () => {
  const env = {
    QM_NOTION_READ_AUTHORITY_ISSUER: config.issuer,
    QM_NOTION_READ_AUTHORITY_AUDIENCE: config.audience,
    QM_NOTION_READ_AUTHORITY_KEY_ID: config.keyId,
    QM_NOTION_READ_AUTHORITY_ORGANIZATION_ID: config.organizationId,
    QM_NOTION_READ_AUTHORITY_ACTOR_PRINCIPAL_ID: config.actorPrincipalId,
    QM_NOTION_READ_AUTHORITY_SLACK_TEAM_ID: config.slackTeamId,
    QM_NOTION_READ_AUTHORITY_SLACK_USER_ID: config.slackUserId,
    QM_NOTION_READ_AUTHORITY_SLACK_DM_CHANNEL_ID: config.slackDmChannelId,
    QM_NOTION_READ_AUTHORITY_RS256_PRIVATE_KEY: config.privateKey,
    QM_NOTION_READ_AUTHORITY_TTL_SECONDS: String(config.ttlSeconds),
  };
  assert.equal(notionAuthoritySignerConfigFromEnv({}, undefined), undefined);
  assert.equal(notionAuthoritySignerConfigFromEnv(env, config.issuer), undefined);
  assert.throws(() => notionAuthoritySignerConfigFromEnv({ QM_NOTION_READ_AUTHORITY_ENABLED: "true" }, config.issuer));
  assert.throws(() => notionAuthoritySignerConfigFromEnv({ QM_NOTION_READ_AUTHORITY_ENABLED: "1" }, config.issuer));
  assert.throws(() =>
    notionAuthoritySignerConfigFromEnv({ QM_NOTION_READ_AUTHORITY_ISSUER: config.issuer }, config.issuer),
  );
  const enabled = { ...env, QM_NOTION_READ_AUTHORITY_ENABLED: "true" };
  assert.throws(() => notionAuthoritySignerConfigFromEnv(enabled, undefined), /requires PUBLIC_API_URL/);
  assert.throws(() => notionAuthoritySignerConfigFromEnv(enabled, "https://other.example.com/"), /must match/);
  assert.throws(() =>
    notionAuthoritySignerConfigFromEnv({ ...enabled, QM_NOTION_READ_AUTHORITY_TTL_SECONDS: "61" }, config.issuer),
  );
  assert.throws(() =>
    notionAuthoritySignerConfigFromEnv({ ...enabled, QM_NOTION_READ_AUTHORITY_KEY_ID: "bad key" }, config.issuer),
  );
  assert.throws(() =>
    notionAuthoritySignerConfigFromEnv(
      { ...enabled, QM_NOTION_READ_AUTHORITY_AUDIENCE: "http://bad.test" },
      config.issuer,
    ),
  );
  assert.throws(() => createNotionAuthoritySigner({ ...config, actorPrincipalId: `a${"b".repeat(198)}` }));
  const weak = generateKeyPairSync("rsa", { modulusLength: 1_024, publicExponent: 0x10001 });
  assert.throws(
    () =>
      createNotionAuthoritySigner({
        ...config,
        privateKey: weak.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
      }),
    /2048-4096/,
  );
  const mutableConfig = { ...config };
  const immutableSigner = createNotionAuthoritySigner(mutableConfig);
  mutableConfig.slackUserId = "U87654321";
  assert.throws(() =>
    immutableSigner.sign(
      "notion_search",
      { workflow: "general", query: "roadmap" },
      {
        ...context,
        slackUserId: mutableConfig.slackUserId,
      },
    ),
  );
  assert.deepEqual(notionAuthoritySignerConfigFromEnv(enabled, "https://qm.example.com/v1"), config);
});

test("MCP tool records allow only exact read-only Notion authority contracts", () => {
  assert.deepEqual(parseMcpAllowedTools(allowedTools), allowedTools);
  assert.equal(notionAuthorityServerContract(server), true);
  assert.throws(() => parseMcpAllowedTools([{ ...allowedTools[0], name: "notion_create_page" }]));
  assert.throws(() => parseMcpAllowedTools([{ ...allowedTools[0], readOnly: false }]));
  assert.throws(() => parseMcpAllowedTools([{ ...allowedTools[0], nativeRenderer: "qm.analytics.card.v1" }]));
  assert.throws(() =>
    parseMcpAllowedTools([
      {
        ...allowedTools[0],
        inputSchema: {
          ...searchSchema,
          properties: {
            ...searchSchema.properties,
            query: { type: "string", minLength: 1, maxLength: 1_001 },
          },
        },
      },
    ]),
  );
  assert.throws(() =>
    parseMcpAllowedTools([
      {
        ...allowedTools[0],
        inputSchema: {
          ...searchSchema,
          properties: { workflow: workflowSchema, query: searchSchema.properties.query },
          required: ["workflow", "query"],
        },
      },
    ]),
  );
  for (const changed of [
    { url: "https://command-center.example.com/api/mcp/command-center/mcp" },
    { audience: "https://command-center.example.com/api/mcp/command-center/mcp" },
    { auth: "bearer" },
    { scopes: [] },
    { scopes: ["notion:read", "artifacts:write"] },
    { tokenAudienceParameter: "resource" },
    { readOnly: false },
    { allowedTools: [allowedTools[0]] },
    { allowedTools: [...allowedTools, { ...allowedTools[0], name: "notion_extra" }] },
  ]) {
    assert.equal(notionAuthorityServerContract({ ...server, ...changed } as McpServer), false);
  }
});

test("frozen Command Center discovery passes the exact QM Notion contract", async () => {
  assert.deepEqual(commandCenterFixtureSource, {
    contract: "notion-m2m-tools-list/v1",
    path: "command-center-notion-m2m-tools-list.json",
    sha256: "ab3cd79ecca651e57de59ce940f642b0487b9a464945595b556fd6dceb0ad3ab",
  });
  assert.equal(
    createHash("sha256").update(commandCenterFixtureBytes, "utf8").digest("hex"),
    commandCenterFixtureSource.sha256,
  );
  assert.deepEqual(
    remoteTools.map((tool) => tool.name),
    allowedTools.map((tool) => tool.name),
  );
  assert.deepEqual(
    remoteTools.map((tool) => tool.inputSchema),
    allowedTools.map((tool) => tool.inputSchema),
  );
  assert.deepEqual(
    remoteTools.map((tool) => tool.annotations),
    allowedTools.map(() => ({
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    })),
  );
  const service = await serviceWith(async (_url, init) => {
    const request = JSON.parse(init.body) as { id: number; method: string };
    assert.equal(request.method, "tools/list");
    return response(request.id, commandCenterFixture);
  });
  const tools = service.toolDefs().filter((tool) => tool.serverId === server.id);
  assert.deepEqual(
    tools.map((tool) => tool.remoteName),
    allowedTools.map((tool) => tool.name),
  );
  for (const tool of tools) {
    const properties = tool.inputSchema.properties as Record<string, unknown>;
    assert.equal(Object.hasOwn(properties, "authorityEnvelope"), false);
    assert.equal((tool.inputSchema.required as string[]).includes("authorityEnvelope"), false);
  }
  service.close();
});

test("Notion discovery rejects annotation drift and extra remote tools", async () => {
  for (const tools of [
    remoteTools.map((tool) =>
      tool.name === "notion_search" ? { ...tool, annotations: { ...tool.annotations, openWorldHint: false } } : tool,
    ),
    remoteTools.map((tool) =>
      tool.name === "notion_search" ? { ...tool, annotations: { readOnlyHint: true, destructiveHint: false } } : tool,
    ),
    [...remoteTools, { ...remoteTools[0]!, name: "notion_write_page" }],
  ]) {
    const service = await serviceWith(async (_url, init) => {
      const request = JSON.parse(init.body) as { id: number; method: string };
      assert.equal(request.method, "tools/list");
      return response(request.id, { tools });
    });
    assert.deepEqual(service.toolDefs(), []);
    service.close();
  }
});

test("MCP service hides caller authority, injects one fresh envelope after revalidation, and rejects substitution", async () => {
  const signer = createNotionAuthoritySigner(config, { now: () => Date.parse("2026-08-30T20:00:00.000Z") });
  const audit = createAuditLog();
  const calls: Array<{ method: string; arguments?: Record<string, unknown>; header?: string }> = [];
  const fetchImpl: McpFetch = async (_url, init) => {
    const request = JSON.parse(init.body) as {
      id: number;
      method: string;
      params?: { arguments?: Record<string, unknown> };
    };
    calls.push({
      method: request.method,
      ...(request.params?.arguments ? { arguments: request.params.arguments } : {}),
      ...(init.headers["x-risely-qm-authority"] ? { header: init.headers["x-risely-qm-authority"] } : {}),
    });
    if (request.method === "tools/list") return response(request.id, { tools: remoteTools });
    const token = request.params?.arguments?.authorityEnvelope;
    assert.equal(typeof token, "string");
    await verifyEnvelope(token as string, signer);
    return response(request.id, { content: [{ type: "text", text: "cited result" }] });
  };
  const service = await serviceWith(fetchImpl, signer, audit);
  const search = service.toolDefs().find((tool) => tool.remoteName === "notion_search")!;
  const properties = search.inputSchema.properties as Record<string, unknown>;
  assert.equal(Object.hasOwn(properties, "authorityEnvelope"), false);
  assert.equal((search.inputSchema.required as string[]).includes("authorityEnvelope"), false);
  assert.deepEqual(Object.keys(properties).sort(), ["query", "workflow"]);
  assert.equal(
    await service
      .callWithContext("notion_notion_search", { workflow: "proposal", query: "CBS" }, context, config.actorPrincipalId)
      .then((result) => result.text),
    "cited result",
  );
  const dispatched = calls.find((call) => call.method === "tools/call")!;
  assert.equal(dispatched.header, undefined);
  assert.deepEqual(
    { ...dispatched.arguments, authorityEnvelope: undefined },
    { workflow: "proposal", query: "CBS", authorityEnvelope: undefined },
  );
  const token = dispatched.arguments!.authorityEnvelope as string;
  assert.equal(
    decodeClaims(token).payloadSha256,
    createHash("sha256")
      .update(notionReadCanonicalPayload("notion_search", { workflow: "proposal", query: "CBS" }))
      .digest("hex"),
  );
  const callCount = calls.filter((call) => call.method === "tools/call").length;
  await assert.rejects(
    () =>
      service.callWithContext(
        "notion_notion_search",
        { workflow: "proposal", query: "CBS", authorityEnvelope: token },
        context,
      ),
    /pinned contract/,
  );
  await assert.rejects(
    () =>
      service.callWithContext(
        "notion_notion_search",
        { workflow: "proposal", query: "CBS" },
        { ...context, slackUserId: "U87654321" },
      ),
    /authority denied/,
  );
  assert.equal(calls.filter((call) => call.method === "tools/call").length, callCount);
  const auditBytes = JSON.stringify(await audit.events());
  assert.equal(auditBytes.includes("CBS"), false);
  assert.equal(auditBytes.includes(token), false);
  service.close();
});

test("network retries and process restarts mint unique JTIs without exposing tokens in errors", async () => {
  const firstSigner = createNotionAuthoritySigner(config, { now: () => Date.parse("2026-08-30T20:00:00.000Z") });
  const restartedSigner = createNotionAuthoritySigner(config, { now: () => Date.parse("2026-08-30T20:00:01.000Z") });
  assert.deepEqual(restartedSigner.publicState().jwks, firstSigner.publicState().jwks);
  const restarted = restartedSigner.sign("notion_read_page", { workflow: "meeting_brief", pageId: "page-1" }, context);
  const original = firstSigner.sign("notion_read_page", { workflow: "meeting_brief", pageId: "page-1" }, context);
  assert.notEqual(restarted.claims.jti, original.claims.jti);
  await verifyEnvelope(original.token, firstSigner);

  const tokens: string[] = [];
  let toolCalls = 0;
  const fetchImpl: McpFetch = async (_url, init) => {
    const request = JSON.parse(init.body) as {
      id: number;
      method: string;
      params?: { arguments?: Record<string, unknown> };
    };
    if (request.method === "tools/list") return response(request.id, { tools: remoteTools });
    toolCalls += 1;
    const token = request.params?.arguments?.authorityEnvelope as string;
    tokens.push(token);
    if (toolCalls === 1) {
      return {
        ok: false,
        status: 503,
        headers: { get: () => "text/plain" },
        text: async () => token,
      };
    }
    if (toolCalls === 3) {
      return {
        ok: true,
        status: 200,
        headers: { get: () => "application/json" },
        text: async () =>
          JSON.stringify({
            jsonrpc: "2.0",
            id: request.id,
            error: { code: -32_000, message: token },
          }),
      };
    }
    return response(request.id, { content: [{ type: "text", text: "page" }] });
  };
  const service = await serviceWith(fetchImpl, restartedSigner);
  const call = () =>
    service.callWithContext(
      "notion_notion_read_page",
      { workflow: "meeting_brief", pageId: "page-1" },
      context,
      config.actorPrincipalId,
    );
  await assert.rejects(call, (error: Error) => error.message === "MCP Notion read failed: notion_read_page");
  await assert.doesNotReject(call);
  assert.notEqual(decodeClaims(tokens[0]!).jti, decodeClaims(tokens[1]!).jti);
  await assert.rejects(
    call,
    (error: Error) =>
      error.message === "MCP Notion read failed: notion_read_page" && !error.message.includes(tokens[2]!),
  );
  assert.equal(new Set(tokens.map((token) => decodeClaims(token).jti)).size, 3);
  service.close();
});

test("missing runtime signer fails before a Notion tools/call", async () => {
  let toolCalls = 0;
  const service = await serviceWith(async (_url, init) => {
    const request = JSON.parse(init.body) as { id: number; method: string };
    if (request.method === "tools/call") toolCalls += 1;
    return response(request.id, { tools: remoteTools });
  });
  await assert.rejects(
    () => service.callWithContext("notion_notion_search", { workflow: "general", query: "roadmap" }, context),
    /authority is unavailable/,
  );
  assert.equal(toolCalls, 0);
  service.close();
});

test("public JWKS endpoint exposes only the configured RSA verification key and stays absent by default", async (t) => {
  const signer = createNotionAuthoritySigner(config);
  const signingSecret = "notion-jwks-route-test-secret".repeat(3);
  const configured = createServer({} as App, { signingSecret, notionAuthorityPublic: signer.publicState() });
  const absent = createServer({} as App, { signingSecret });
  t.after(() => {
    configured.close();
    absent.close();
  });
  await new Promise<void>((resolve) => configured.listen(0, "127.0.0.1", resolve));
  await new Promise<void>((resolve) => absent.listen(0, "127.0.0.1", resolve));
  const configuredPort = (configured.address() as AddressInfo).port;
  const absentPort = (absent.address() as AddressInfo).port;
  const ready = await fetch(`http://127.0.0.1:${configuredPort}/.well-known/jwks.json`);
  assert.equal(ready.status, 200);
  const body = (await ready.json()) as { keys: Array<Record<string, unknown>> };
  assert.deepEqual(body, signer.publicState().jwks);
  assert.deepEqual(Object.keys(body.keys[0]!).sort(), ["alg", "e", "kid", "kty", "n", "use"]);
  assert.equal(Object.hasOwn(body.keys[0]!, "d"), false);
  const readiness = await fetch(`http://127.0.0.1:${configuredPort}/.well-known/notion-read-authority-readiness.json`);
  assert.equal(readiness.status, 200);
  assert.deepEqual(await readiness.json(), signer.publicState().readiness);
  assert.equal(
    (await fetch(`http://127.0.0.1:${absentPort}/.well-known/notion-read-authority-readiness.json`)).status,
    404,
  );
  assert.equal((await fetch(`http://127.0.0.1:${absentPort}/.well-known/jwks.json`)).status, 404);
});

test("BuiltApp and ServerDeps expose public Notion state without a callable signer", () => {
  const wiring = readFileSync(new URL("../src/wiring.ts", import.meta.url), "utf8");
  const builtApp = wiring.slice(
    wiring.indexOf("export interface BuiltApp"),
    wiring.indexOf("export function buildApp"),
  );
  const deps = readFileSync(new URL("../src/api/deps.ts", import.meta.url), "utf8");
  assert.match(builtApp, /notionAuthorityPublic\?: NotionAuthorityPublicState/u);
  assert.doesNotMatch(builtApp, /NotionAuthoritySigner|notionAuthoritySigner/u);
  assert.match(deps, /notionAuthorityPublic\?: NotionAuthorityPublicState/u);
  assert.doesNotMatch(deps, /NotionAuthoritySigner|notionAuthoritySigner/u);
});
