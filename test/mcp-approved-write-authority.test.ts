import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { deriveConnectorKey } from "../src/connectors/connector-client-store.ts";
import { MCP_REQUEST_AUTHORITY_HEADER, type McpFetch } from "../src/mcp/mcp-client.ts";
import {
  APPROVED_WRITE_AUTHORITY,
  APPROVED_WRITE_RECEIPT_SCHEMA,
  loadApprovedWriteAuthoritySigner,
  parseApprovedWriteAuthorityDescriptor,
} from "../src/mcp/approved-write-authority.ts";
import type { McpHumanCallContext } from "../src/mcp/mcp-authority.ts";
import {
  createMcpServerStore,
  mcpCallerInputSchema,
  parseMcpAllowedTools,
  type McpAllowedTool,
  type McpServer,
  type StoredMcpServer,
} from "../src/mcp/mcp-server-store.ts";
import { createMcpToolService } from "../src/mcp/mcp-tool-service.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { exactMcpApprovalTool, exactToolApprovalArguments, toolApprovalKey } from "../src/tools/exact-tool-approval.ts";

const payloadSchema = Object.freeze({
  type: "object",
  properties: Object.freeze({ note: Object.freeze({ type: "string", minLength: 1, maxLength: 4_096 }) }),
  required: Object.freeze(["note"]),
  additionalProperties: false,
});
const remoteInputSchema = Object.freeze({
  type: "object",
  properties: Object.freeze({ payload: payloadSchema, approval: APPROVED_WRITE_RECEIPT_SCHEMA }),
  required: Object.freeze(["payload", "approval"]),
  additionalProperties: false,
});
const allowedTool: McpAllowedTool = {
  name: "append_note",
  label: "Append note",
  status: "Appending the approved note",
  readOnly: false,
  inputSchema: remoteInputSchema,
  requestAuthority: APPROVED_WRITE_AUTHORITY,
};
const server: McpServer = {
  id: "approved-write",
  name: "Approved write",
  url: "https://mcp.example.com/mcp",
  auth: "none",
  scopes: [],
  allowedTools: [allowedTool],
  readOnly: false,
  enabled: true,
  credentialState: "none",
  updatedAt: 1,
  updatedBy: "admin",
};
const payload = Object.freeze({ note: "Exact approved note" });
const approval = Object.freeze({
  approvalId: "approval_123",
  approvalPayloadSha256: "a".repeat(64),
  actionTs: "1788291123.000001",
  slackTeamId: "T12345678",
  actorSlackUserId: "U12345678",
  channelId: "D12345678",
  messageTs: "1788291100.000001",
  threadTs: "1788291100.000001",
});

function context(toolApprovalKey: string): McpHumanCallContext {
  return {
    surface: "slack",
    conversationType: "dm",
    principalId: "founder@example.com",
    slackTeamId: approval.slackTeamId,
    slackUserId: approval.actorSlackUserId,
    slackChannelId: approval.channelId,
    slackMessageTs: approval.messageTs,
    slackThreadTs: approval.threadTs,
    deliveryTarget: approval.channelId,
    approval: {
      approvalId: approval.approvalId,
      toolApprovalKey,
      argumentsSha256: exactToolApprovalArguments({ payload }).sha256,
      actionTs: approval.actionTs,
      slackTeamId: approval.slackTeamId,
      actorSlackUserId: approval.actorSlackUserId,
      channelId: approval.channelId,
      messageTs: approval.messageTs,
      threadTs: approval.threadTs,
    },
  };
}

test("approved write contracts hide the injected receipt and reject weaker contracts", () => {
  assert.deepEqual(parseMcpAllowedTools([allowedTool]), [allowedTool]);
  assert.deepEqual(mcpCallerInputSchema(allowedTool), {
    type: "object",
    properties: { payload: payloadSchema },
    required: ["payload"],
    additionalProperties: false,
  });
  for (const invalid of [
    { ...allowedTool, readOnly: true },
    { ...allowedTool, inputSchema: { ...remoteInputSchema, required: ["payload"] } },
    { ...allowedTool, inputSchema: { ...remoteInputSchema, additionalProperties: true } },
    { ...allowedTool, inputSchema: { ...remoteInputSchema, additionalProperties: undefined } },
    {
      ...allowedTool,
      inputSchema: {
        ...remoteInputSchema,
        properties: { ...remoteInputSchema.properties, payload: { ...payloadSchema, additionalProperties: true } },
      },
    },
    {
      ...allowedTool,
      inputSchema: {
        ...remoteInputSchema,
        properties: { ...remoteInputSchema.properties, approval: { type: "object" } },
      },
    },
  ])
    assert.throws(() => parseMcpAllowedTools([invalid]));
});

test("approved writes inject a matching receipt and three-part authority only after exact approval", async () => {
  const backing = createMemoryMap<StoredMcpServer>();
  const store = createMcpServerStore(backing, deriveConnectorKey("approved-write-test", "mcp-server-secrets"));
  const dispatched: Array<{ headers: Record<string, string>; body: Record<string, unknown> }> = [];
  const fetch: McpFetch = async (_url, init) => {
    const body = JSON.parse(init.body) as { id: number; method: string };
    if (body.method === "tools/call") dispatched.push({ headers: init.headers, body });
    const result =
      body.method === "tools/list"
        ? {
            tools: [
              {
                name: allowedTool.name,
                description: allowedTool.status,
                inputSchema: remoteInputSchema,
                annotations: {
                  readOnlyHint: false,
                  destructiveHint: true,
                  idempotentHint: true,
                  openWorldHint: true,
                },
              },
            ],
          }
        : { content: [{ type: "text", text: "confirmed" }] };
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ jsonrpc: "2.0", id: body.id, result }),
      headers: { get: () => "application/json" },
    };
  };
  let signed = 0;
  const service = createMcpToolService({
    servers: store,
    fetchImpl: fetch,
    refreshIntervalMs: 3_600_000,
    approvedWriteAuthoritySigner: {
      sign(_tool, args, callContext) {
        signed += 1;
        assert.equal(callContext.approval?.argumentsSha256, exactToolApprovalArguments(args).sha256);
        return {
          authorityHeader: `header.payload.${"s".repeat(86)}`,
          dispatchArguments: { ...args, approval },
        };
      },
    },
  });
  await store.put(server);
  await service.refresh();
  const descriptor = service.toolDefs()[0]!;
  const args = { payload };
  const exactTool = exactMcpApprovalTool(descriptor.serverContractSha256, descriptor.name);
  await assert.rejects(
    () => service.callWithContext(descriptor.name, args, context("tool:mcp-exact:")),
    /does not match/,
  );
  assert.equal(signed, 0);
  await assert.rejects(() => service.callWithContext(descriptor.name, args, undefined), /receipt is unavailable/);
  assert.equal(signed, 0);
  const result = await service.callWithContext(descriptor.name, args, context(toolApprovalKey(exactTool, args)));
  assert.equal(result.text, "confirmed");
  assert.equal(signed, 1);
  await assert.rejects(
    () =>
      service.callWithContext(
        descriptor.name,
        { payload: { note: "Changed" } },
        context(toolApprovalKey(exactTool, args)),
      ),
    /does not match/,
  );
  assert.equal(signed, 1);
  assert.equal(dispatched.length, 1);
  assert.equal(dispatched[0]!.headers[MCP_REQUEST_AUTHORITY_HEADER], `header.payload.${"s".repeat(86)}`);
  const call = dispatched[0]!.body as { params?: { arguments?: unknown } };
  assert.deepEqual(call.params?.arguments, { payload, approval });
  service.close();
});

test("approved write discovery rejects annotation drift before signer access", async () => {
  const backing = createMemoryMap<StoredMcpServer>();
  const store = createMcpServerStore(backing, deriveConnectorKey("approved-write-drift", "mcp-server-secrets"));
  const fetch: McpFetch = async (_url, init) => {
    const body = JSON.parse(init.body) as { id: number };
    return {
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            tools: [
              {
                name: allowedTool.name,
                inputSchema: remoteInputSchema,
                annotations: {
                  readOnlyHint: false,
                  destructiveHint: true,
                  idempotentHint: false,
                  openWorldHint: true,
                },
              },
            ],
          },
        }),
      headers: { get: () => "application/json" },
    };
  };
  const service = createMcpToolService({ servers: store, fetchImpl: fetch, refreshIntervalMs: 3_600_000 });
  await store.put(server);
  await service.refresh();
  assert.deepEqual(service.toolDefs(), []);
  service.close();
});

function authorityDescriptor(): Record<string, unknown> {
  return {
    contract: 1,
    profile: APPROVED_WRITE_AUTHORITY,
    id: "append-note",
    tool: "append_note",
    issuerEnv: "WRITE_ISSUER",
    keyIdEnv: "WRITE_KEY_ID",
    privateKeyEnv: "WRITE_PRIVATE_KEY",
    principalEnv: "WRITE_PRINCIPAL",
    slackTeamIdEnv: "WRITE_TEAM_ID",
    slackUserIdEnv: "WRITE_USER_ID",
    slackDmChannelIdEnv: "WRITE_DM_ID",
    audience: "service:approved-note",
    type: "approved-note-authority+jwt",
    version: "approved-note-authority/v1",
    operation: "append-note",
    ttlSeconds: 300,
    maximumSigningDelaySeconds: 30,
    approvalPayload: {
      schemaVersion: { argument: "/payload/schemaVersion" },
      recordId: { argument: "/payload/recordId" },
      note: { argument: "/payload/note" },
    },
    claims: [
      { name: "recordId", argument: "/payload/recordId" },
      { name: "noteSha256", sha256Argument: "/payload/note" },
    ],
  };
}

test("deployment authority descriptors are closed and reject unsafe projections", () => {
  const descriptor = authorityDescriptor();
  assert.deepEqual(parseApprovedWriteAuthorityDescriptor(JSON.stringify(descriptor)), descriptor);
  for (const invalid of [
    { ...descriptor, extra: true },
    { ...descriptor, claims: [...(descriptor.claims as unknown[]), { name: "recordId", argument: "/payload/note" }] },
    { ...descriptor, approvalPayload: { unsafe: { argument: "/payload/__proto__" } } },
    { ...descriptor, claims: [{ name: "iss", argument: "/payload/note" }] },
  ]) {
    assert.throws(() => parseApprovedWriteAuthorityDescriptor(JSON.stringify(invalid)));
  }
});

test("deployment authority signer binds a fresh founder DM click and emits ordered EdDSA JWS bytes", () => {
  const dir = mkdtempSync(join(tmpdir(), "approved-write-layer-"));
  mkdirSync(join(dir, "mcp-authorities"));
  writeFileSync(join(dir, "mcp-authorities", "append-note.json"), JSON.stringify(authorityDescriptor()));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const env = {
    WRITE_ISSUER: "https://issuer.example.com/",
    WRITE_KEY_ID: "write-key-1",
    WRITE_PRIVATE_KEY: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    WRITE_PRINCIPAL: "founder@example.com",
    WRITE_TEAM_ID: "T12345678",
    WRITE_USER_ID: "U12345678",
    WRITE_DM_ID: "D12345678",
  };
  const signer = loadApprovedWriteAuthoritySigner(dir, env, () => 1_788_291_125_000)!;
  const callerArgs = {
    payload: {
      schemaVersion: "approved-note/v1",
      recordId: "record-1",
      note: "Exact approved note",
    },
  };
  const exactTool = exactMcpApprovalTool("b".repeat(64), "approved-write_append_note");
  const callContext = context(toolApprovalKey(exactTool, callerArgs));
  callContext.approval!.argumentsSha256 = exactToolApprovalArguments(callerArgs).sha256;
  const signed = signer.sign("append_note", callerArgs, callContext);
  assert.deepEqual(signed.dispatchArguments, {
    ...callerArgs,
    approval: {
      ...approval,
      approvalPayloadSha256: "a6aeb0d3338ac064b3fc9138479c0177b848749e36e0259bd3ebcfa963b58eae",
    },
  });
  const parts = signed.authorityHeader.split(".");
  assert.equal(parts.length, 3);
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  assert.deepEqual(JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8")), {
    alg: "EdDSA",
    kid: "write-key-1",
    typ: "approved-note-authority+jwt",
  });
  const claims = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8")) as Record<string, unknown>;
  assert.deepEqual(Object.keys(claims), [
    "version",
    "iss",
    "aud",
    "jti",
    "iat",
    "exp",
    "operation",
    "approvedArgumentsSha256",
    "approvalId",
    "approvalPayloadSha256",
    "slackTeamId",
    "actorSlackUserId",
    "channelId",
    "messageTs",
    "threadTs",
    "actionTs",
    "recordId",
    "noteSha256",
  ]);
  assert.equal(claims.recordId, "record-1");
  assert.equal(claims.approvedArgumentsSha256, exactToolApprovalArguments(callerArgs).sha256);
  assert.equal(claims.noteSha256, "0f1a47bf66b3a86513f78be1f7f4e92612896b647f98981afb6b14499dbf5179");
  assert.equal(
    verify(
      null,
      Buffer.from(`${headerPart}.${payloadPart}`, "ascii"),
      publicKey,
      Buffer.from(signaturePart, "base64url"),
    ),
    true,
  );
  assert.throws(
    () => signer.sign("append_note", { payload: { ...callerArgs.payload, note: "Changed" } }, callContext),
    /arguments do not match/,
  );
  const lateSigner = loadApprovedWriteAuthoritySigner(dir, env, () => 1_788_291_154_000)!;
  assert.throws(() => lateSigner.sign("append_note", callerArgs, callContext), /no longer fresh/);
});

test("deployment authority signer loads a descriptor delivered inside one deployment skill", () => {
  const dir = mkdtempSync(join(tmpdir(), "approved-write-layer-skill-"));
  const descriptorDir = join(dir, "skills", "governed-write", "mcp-authorities");
  mkdirSync(descriptorDir, { recursive: true });
  writeFileSync(join(descriptorDir, "append-note.json"), JSON.stringify(authorityDescriptor()));
  const { privateKey } = generateKeyPairSync("ed25519");
  const signer = loadApprovedWriteAuthoritySigner(dir, {
    WRITE_ISSUER: "https://issuer.example.com/",
    WRITE_KEY_ID: "write-key-1",
    WRITE_PRIVATE_KEY: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
    WRITE_PRINCIPAL: "founder@example.com",
    WRITE_TEAM_ID: "T12345678",
    WRITE_USER_ID: "U12345678",
    WRITE_DM_ID: "D12345678",
  });
  assert.ok(signer);
});
