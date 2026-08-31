import { createHash, createPrivateKey, randomBytes, sign } from "node:crypto";

export const MCP_AUTHORITY_HEADER = "x-risely-qm-authority";

export interface McpHumanCallContext {
  surface: "slack";
  conversationType: "dm";
  principalId: string;
  slackTeamId: string;
  slackUserId: string;
  slackChannelId: string;
  slackMessageTs: string;
  slackThreadTs: string;
}

export interface McpAuthorityPayload {
  version: 1;
  issuer: string;
  organizationId: string;
  principalId: string;
  slackTeamId: string;
  slackUserId: string;
  slackChannelId: string;
  slackConversationType: "im";
  slackMessageTs: string;
  slackThreadTs: string;
  tool: "analytics_query";
  bodySha256: string;
  jti: string;
  iat: number;
  exp: number;
}

export interface McpAuthorityEnvelope {
  token: string;
  payload: McpAuthorityPayload;
}

export interface McpAuthoritySigner {
  sign(tool: string, body: Record<string, unknown>, context: McpHumanCallContext | undefined): McpAuthorityEnvelope;
}

export interface McpAuthoritySignerConfig {
  issuer: string;
  organizationId: string;
  principalId: string;
  slackTeamId: string;
  slackUserId: string;
  slackDmChannelId: string;
  privateKey: string;
  ttlSeconds: number;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$/;
const SLACK_TS = /^\d{10,12}\.\d{6}$/;

function codeUnitOrder(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => codeUnitOrder(left, right))
        .map(([key, child]) => [key, canonicalValue(child)]),
    );
  }
  return value;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

function exactConfig(config: McpAuthoritySignerConfig): McpAuthoritySignerConfig {
  if (
    !/^[A-Za-z0-9][A-Za-z0-9_.:/-]{2,127}$/.test(config.issuer) ||
    !IDENTIFIER.test(config.organizationId) ||
    !IDENTIFIER.test(config.principalId) ||
    !/^T[A-Z0-9]{2,31}$/.test(config.slackTeamId) ||
    !/^U[A-Z0-9]{2,31}$/.test(config.slackUserId) ||
    !/^D[A-Z0-9]{2,31}$/.test(config.slackDmChannelId) ||
    !Number.isSafeInteger(config.ttlSeconds) ||
    config.ttlSeconds < 10 ||
    config.ttlSeconds > 60
  ) {
    throw new Error("QM MCP authority signer configuration is invalid");
  }
  return config;
}

export function createMcpAuthoritySigner(
  configInput: McpAuthoritySignerConfig,
  now = () => Date.now(),
): McpAuthoritySigner {
  const config = exactConfig(configInput);
  let key: ReturnType<typeof createPrivateKey>;
  try {
    key = createPrivateKey({ key: Buffer.from(config.privateKey, "base64"), format: "der", type: "pkcs8" });
  } catch {
    throw new Error("QM MCP authority signer private key is invalid");
  }
  if (key.asymmetricKeyType !== "ed25519") throw new Error("QM MCP authority signer private key must be Ed25519");
  return {
    sign(tool, body, context) {
      if (
        tool !== "analytics_query" ||
        !context ||
        context.surface !== "slack" ||
        context.conversationType !== "dm" ||
        context.principalId !== config.slackUserId ||
        context.slackUserId !== config.slackUserId ||
        context.slackChannelId !== config.slackDmChannelId ||
        context.slackTeamId !== config.slackTeamId ||
        !SLACK_TS.test(context.slackMessageTs) ||
        !SLACK_TS.test(context.slackThreadTs)
      ) {
        throw new Error("MCP founder DM authority denied");
      }
      const iat = Math.floor(now() / 1_000);
      const payload: McpAuthorityPayload = {
        version: 1,
        issuer: config.issuer,
        organizationId: config.organizationId,
        principalId: config.principalId,
        slackTeamId: config.slackTeamId,
        slackUserId: config.slackUserId,
        slackChannelId: config.slackDmChannelId,
        slackConversationType: "im",
        slackMessageTs: context.slackMessageTs,
        slackThreadTs: context.slackThreadTs,
        tool: "analytics_query",
        bodySha256: createHash("sha256").update(canonicalJson(body)).digest("hex"),
        jti: randomBytes(32).toString("base64url"),
        iat,
        exp: iat + config.ttlSeconds,
      };
      const encoded = Buffer.from(canonicalJson(payload), "utf8").toString("base64url");
      return {
        payload,
        token: `${encoded}.${sign(null, Buffer.from(encoded, "ascii"), key).toString("base64url")}`,
      };
    },
  };
}

export function mcpAuthoritySignerConfigFromEnv(env: NodeJS.ProcessEnv): McpAuthoritySignerConfig | undefined {
  const names = [
    "QM_MCP_AUTHORITY_ISSUER",
    "QM_MCP_AUTHORITY_ORGANIZATION_ID",
    "QM_MCP_AUTHORITY_PRINCIPAL_ID",
    "QM_MCP_AUTHORITY_SLACK_TEAM_ID",
    "QM_MCP_AUTHORITY_SLACK_USER_ID",
    "QM_MCP_AUTHORITY_SLACK_DM_CHANNEL_ID",
    "QM_MCP_AUTHORITY_ED25519_PRIVATE_KEY",
    "QM_MCP_AUTHORITY_TTL_SECONDS",
  ] as const;
  if (names.every((name) => !env[name])) return undefined;
  if (names.some((name) => !env[name])) throw new Error("QM MCP authority signer configuration is incomplete");
  return {
    issuer: env.QM_MCP_AUTHORITY_ISSUER!,
    organizationId: env.QM_MCP_AUTHORITY_ORGANIZATION_ID!,
    principalId: env.QM_MCP_AUTHORITY_PRINCIPAL_ID!,
    slackTeamId: env.QM_MCP_AUTHORITY_SLACK_TEAM_ID!,
    slackUserId: env.QM_MCP_AUTHORITY_SLACK_USER_ID!,
    slackDmChannelId: env.QM_MCP_AUTHORITY_SLACK_DM_CHANNEL_ID!,
    privateKey: env.QM_MCP_AUTHORITY_ED25519_PRIVATE_KEY!,
    ttlSeconds: Number(env.QM_MCP_AUTHORITY_TTL_SECONDS),
  };
}
