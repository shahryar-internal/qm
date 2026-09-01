import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
  type JsonWebKey,
  type KeyObject,
} from "node:crypto";
import type { McpHumanCallContext } from "./mcp-authority.ts";

export const NOTION_READ_AUTHORITY = "qm.rs256.notion-read-founder-dm.v1" as const;
const NOTION_READ_AUTHORITY_ALGORITHM = "RS256" as const;
const NOTION_READ_AUTHORITY_TOKEN_TYPE = "job-authority+jwt" as const;
const NOTION_READ_AUTHORITY_SCOPE = "notion:read" as const;

type NotionReadToolName = "notion_search" | "notion_read_page";

export interface NotionAuthoritySignerConfig {
  issuer: string;
  audience: string;
  keyId: string;
  organizationId: string;
  actorPrincipalId: string;
  slackTeamId: string;
  slackUserId: string;
  slackDmChannelId: string;
  privateKey: string;
  ttlSeconds: number;
}

export interface NotionAuthorityClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
  scope: typeof NOTION_READ_AUTHORITY_SCOPE;
  organizationId: string;
  actorPrincipalId: string;
  actorSlackId: string;
  audienceScopeId: string;
  slackTeamId: string;
  channelId: string;
  messageTs: string;
  threadTs: string;
  tool: NotionReadToolName;
  requestId: string;
  payloadSha256: string;
}

interface NotionAuthorityEnvelope {
  token: string;
  claims: NotionAuthorityClaims;
  canonicalPayload: string;
  dispatchArguments: Record<string, unknown>;
}

interface NotionAuthorityPublicJwk {
  readonly kty: "RSA";
  readonly n: string;
  readonly e: string;
  readonly kid: string;
  readonly alg: typeof NOTION_READ_AUTHORITY_ALGORITHM;
  readonly use: "sig";
}

export interface NotionAuthorityPublicState {
  readonly jwks: Readonly<{ keys: readonly NotionAuthorityPublicJwk[] }>;
  readonly readiness: Readonly<{
    status: "ready";
    algorithm: typeof NOTION_READ_AUTHORITY_ALGORITHM;
    authority: typeof NOTION_READ_AUTHORITY;
    tools: readonly NotionReadToolName[];
  }>;
}

export interface NotionAuthoritySigner {
  sign(tool: string, body: Record<string, unknown>, context: McpHumanCallContext | undefined): NotionAuthorityEnvelope;
  publicState(): NotionAuthorityPublicState;
}

const WORKFLOWS = new Set([
  "meeting_brief",
  "post_meeting_notes",
  "proposal",
  "research",
  "marketing_draft",
  "general",
]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/u;
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/u;
const SLACK_TEAM = /^T[A-Z0-9]{2,31}$/u;
const SLACK_USER = /^[UW][A-Z0-9]{2,31}$/u;
const SLACK_DM = /^D[A-Z0-9]{2,31}$/u;
const SLACK_TS = /^\d{10,}\.\d{6}$/u;
const PRIVATE_KEY_BASE64 = /^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const TOOLS = Object.freeze(["notion_search", "notion_read_page"] as const);

function exactHttpsUrl(value: string, rootOnly: boolean): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("QM Notion authority URL configuration is invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    value !== url.href ||
    (rootOnly && url.pathname !== "/")
  ) {
    throw new Error("QM Notion authority URL configuration is invalid");
  }
  return url;
}

function exactConfig(config: NotionAuthoritySignerConfig): NotionAuthoritySignerConfig {
  const snapshot = { ...config };
  exactHttpsUrl(snapshot.issuer, true);
  exactHttpsUrl(snapshot.audience, false);
  if (
    !IDENTIFIER.test(snapshot.keyId) ||
    !IDENTIFIER.test(snapshot.organizationId) ||
    !IDENTIFIER.test(snapshot.actorPrincipalId) ||
    !IDENTIFIER.test(`personal:${snapshot.actorPrincipalId}`) ||
    !SLACK_TEAM.test(snapshot.slackTeamId) ||
    !SLACK_USER.test(snapshot.slackUserId) ||
    !SLACK_DM.test(snapshot.slackDmChannelId) ||
    typeof snapshot.privateKey !== "string" ||
    snapshot.privateKey.length < 512 ||
    snapshot.privateKey.length > 16_384 ||
    !PRIVATE_KEY_BASE64.test(snapshot.privateKey) ||
    !Number.isSafeInteger(snapshot.ttlSeconds) ||
    snapshot.ttlSeconds < 10 ||
    snapshot.ttlSeconds > 60
  ) {
    throw new Error("QM Notion authority signer configuration is invalid");
  }
  return Object.freeze(snapshot);
}

function privateKey(config: NotionAuthoritySignerConfig): KeyObject {
  let key: KeyObject;
  try {
    const bytes = Buffer.from(config.privateKey, "base64");
    if (bytes.toString("base64") !== config.privateKey) throw new Error("non-canonical key");
    key = createPrivateKey({ key: bytes, format: "der", type: "pkcs8" });
  } catch {
    throw new Error("QM Notion authority signer private key is invalid");
  }
  const modulusLength = key.asymmetricKeyDetails?.modulusLength;
  const publicExponent = key.asymmetricKeyDetails?.publicExponent;
  if (
    key.asymmetricKeyType !== "rsa" ||
    typeof modulusLength !== "number" ||
    modulusLength < 2_048 ||
    modulusLength > 4_096 ||
    publicExponent !== 65_537n
  ) {
    throw new Error("QM Notion authority signer private key must be a 2048-4096 bit RSA key with exponent 65537");
  }
  return key;
}

function publicJwk(key: KeyObject, keyId: string): NotionAuthorityPublicJwk {
  const exported = createPublicKey(key).export({ format: "jwk" }) as JsonWebKey;
  if (exported.kty !== "RSA" || typeof exported.n !== "string" || typeof exported.e !== "string") {
    throw new Error("QM Notion authority signer public key is invalid");
  }
  return Object.freeze({
    kty: "RSA",
    n: exported.n,
    e: exported.e,
    kid: keyId,
    alg: NOTION_READ_AUTHORITY_ALGORITHM,
    use: "sig",
  });
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function safeText(value: unknown, maxBytes: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.trim() === value &&
    value.normalize("NFC") === value &&
    !/\p{Cc}/u.test(value.replace(/[\n\t]/gu, "")) &&
    Buffer.byteLength(value, "utf8") <= maxBytes
  );
}

export function notionReadCanonicalPayload(tool: string, body: Record<string, unknown>): string {
  if (tool === "notion_search") {
    if (
      !exactKeys(body, ["workflow", "query"]) ||
      typeof body.workflow !== "string" ||
      !WORKFLOWS.has(body.workflow) ||
      !safeText(body.query, 1_000)
    ) {
      throw new Error("QM Notion read request body is invalid");
    }
    return JSON.stringify({
      version: "notion-read-request/v1",
      tool,
      workflow: body.workflow,
      query: body.query,
    });
  }
  if (tool === "notion_read_page") {
    if (
      !exactKeys(body, ["workflow", "pageId"]) ||
      typeof body.workflow !== "string" ||
      !WORKFLOWS.has(body.workflow) ||
      typeof body.pageId !== "string" ||
      !SAFE_ID.test(body.pageId)
    ) {
      throw new Error("QM Notion read request body is invalid");
    }
    return JSON.stringify({
      version: "notion-read-request/v1",
      tool,
      workflow: body.workflow,
      pageId: body.pageId,
    });
  }
  throw new Error("QM Notion read tool is not allowed");
}

function assertContext(context: McpHumanCallContext | undefined, config: NotionAuthoritySignerConfig): void {
  if (
    !context ||
    context.surface !== "slack" ||
    context.conversationType !== "dm" ||
    context.principalId !== config.actorPrincipalId ||
    context.slackTeamId !== config.slackTeamId ||
    context.slackUserId !== config.slackUserId ||
    context.slackChannelId !== config.slackDmChannelId ||
    !SLACK_TS.test(context.slackMessageTs) ||
    !SLACK_TS.test(context.slackThreadTs) ||
    (context.deliveryTarget !== config.slackDmChannelId &&
      context.deliveryTarget !== `${config.slackDmChannelId}:${context.slackThreadTs}`)
  ) {
    throw new Error("QM Notion founder DM authority denied");
  }
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

export function createNotionAuthoritySigner(
  configInput: NotionAuthoritySignerConfig,
  options: Readonly<{ now?: () => number; random?: (size: number) => Buffer }> = {},
): NotionAuthoritySigner {
  const config = exactConfig(configInput);
  const key = privateKey(config);
  const jwk = publicJwk(key, config.keyId);
  const jwks = Object.freeze({ keys: Object.freeze([jwk]) });
  const now = options.now ?? Date.now;
  const random = options.random ?? randomBytes;
  const readiness = Object.freeze({
    status: "ready" as const,
    algorithm: NOTION_READ_AUTHORITY_ALGORITHM,
    authority: NOTION_READ_AUTHORITY,
    tools: TOOLS,
  });
  const publicState = Object.freeze({ jwks, readiness });
  const challenge = Buffer.from("qm-notion-read-authority-readiness-v1", "ascii");
  const challengeSignature = cryptoSign("RSA-SHA256", challenge, key);
  if (!cryptoVerify("RSA-SHA256", challenge, createPublicKey(key), challengeSignature)) {
    throw new Error("QM Notion authority signer readiness check failed");
  }
  return Object.freeze({
    sign(tool: string, body: Record<string, unknown>, context: McpHumanCallContext | undefined) {
      assertContext(context, config);
      const canonicalPayload = notionReadCanonicalPayload(tool, body);
      const current = now();
      if (!Number.isSafeInteger(current) || current < 0) throw new Error("QM Notion authority clock is invalid");
      const iat = Math.floor(current / 1_000);
      const jti = `jti-${random(30).toString("base64url")}`;
      const requestId = `request-${random(24).toString("base64url")}`;
      if (!/^jti-[A-Za-z0-9_-]{40}$/u.test(jti) || !/^request-[A-Za-z0-9_-]{32}$/u.test(requestId)) {
        throw new Error("QM Notion authority nonce source is invalid");
      }
      const claims: NotionAuthorityClaims = Object.freeze({
        iss: config.issuer,
        sub: config.actorPrincipalId,
        aud: config.audience,
        exp: iat + config.ttlSeconds,
        iat,
        jti,
        scope: NOTION_READ_AUTHORITY_SCOPE,
        organizationId: config.organizationId,
        actorPrincipalId: config.actorPrincipalId,
        actorSlackId: config.slackUserId,
        audienceScopeId: `personal:${config.actorPrincipalId}`,
        slackTeamId: config.slackTeamId,
        channelId: config.slackDmChannelId,
        messageTs: context!.slackMessageTs,
        threadTs: context!.slackThreadTs,
        tool: tool as NotionReadToolName,
        requestId,
        payloadSha256: createHash("sha256").update(canonicalPayload, "utf8").digest("hex"),
      });
      const header = encode({
        alg: NOTION_READ_AUTHORITY_ALGORITHM,
        typ: NOTION_READ_AUTHORITY_TOKEN_TYPE,
        kid: config.keyId,
      });
      const payload = encode(claims);
      const signed = `${header}.${payload}`;
      const token = `${signed}.${cryptoSign("RSA-SHA256", Buffer.from(signed, "ascii"), key).toString("base64url")}`;
      return Object.freeze({
        token,
        claims,
        canonicalPayload,
        dispatchArguments: Object.freeze({ ...body, authorityEnvelope: token }),
      });
    },
    publicState: () => publicState,
  });
}

export function notionAuthoritySignerConfigFromEnv(
  env: NodeJS.ProcessEnv,
  publicApiUrl: string | undefined,
): NotionAuthoritySignerConfig | undefined {
  const enabled = env.QM_NOTION_READ_AUTHORITY_ENABLED;
  if (enabled !== undefined && enabled !== "true" && enabled !== "false") {
    throw new Error("QM_NOTION_READ_AUTHORITY_ENABLED must be true or false");
  }
  const names = [
    "QM_NOTION_READ_AUTHORITY_ISSUER",
    "QM_NOTION_READ_AUTHORITY_AUDIENCE",
    "QM_NOTION_READ_AUTHORITY_KEY_ID",
    "QM_NOTION_READ_AUTHORITY_ORGANIZATION_ID",
    "QM_NOTION_READ_AUTHORITY_ACTOR_PRINCIPAL_ID",
    "QM_NOTION_READ_AUTHORITY_SLACK_TEAM_ID",
    "QM_NOTION_READ_AUTHORITY_SLACK_USER_ID",
    "QM_NOTION_READ_AUTHORITY_SLACK_DM_CHANNEL_ID",
    "QM_NOTION_READ_AUTHORITY_RS256_PRIVATE_KEY",
    "QM_NOTION_READ_AUTHORITY_TTL_SECONDS",
  ] as const;
  if (names.every((name) => !env[name])) {
    if (enabled === "true") throw new Error("QM Notion authority signer configuration is incomplete");
    return undefined;
  }
  if (names.some((name) => !env[name])) throw new Error("QM Notion authority signer configuration is incomplete");
  if (!publicApiUrl) throw new Error("QM Notion authority signer requires PUBLIC_API_URL");
  const issuer = exactHttpsUrl(env.QM_NOTION_READ_AUTHORITY_ISSUER!, true);
  let publicApi: URL;
  try {
    publicApi = new URL(publicApiUrl);
  } catch {
    throw new Error("QM Notion authority signer PUBLIC_API_URL is invalid");
  }
  if (
    publicApi.protocol !== "https:" ||
    publicApi.username ||
    publicApi.password ||
    publicApi.search ||
    publicApi.hash ||
    publicApi.origin !== issuer.origin
  ) {
    throw new Error("QM Notion authority issuer must match the PUBLIC_API_URL origin");
  }
  const config = exactConfig({
    issuer: issuer.href,
    audience: env.QM_NOTION_READ_AUTHORITY_AUDIENCE!,
    keyId: env.QM_NOTION_READ_AUTHORITY_KEY_ID!,
    organizationId: env.QM_NOTION_READ_AUTHORITY_ORGANIZATION_ID!,
    actorPrincipalId: env.QM_NOTION_READ_AUTHORITY_ACTOR_PRINCIPAL_ID!,
    slackTeamId: env.QM_NOTION_READ_AUTHORITY_SLACK_TEAM_ID!,
    slackUserId: env.QM_NOTION_READ_AUTHORITY_SLACK_USER_ID!,
    slackDmChannelId: env.QM_NOTION_READ_AUTHORITY_SLACK_DM_CHANNEL_ID!,
    privateKey: env.QM_NOTION_READ_AUTHORITY_RS256_PRIVATE_KEY!,
    ttlSeconds: Number(env.QM_NOTION_READ_AUTHORITY_TTL_SECONDS),
  });
  return enabled === "true" ? config : undefined;
}
