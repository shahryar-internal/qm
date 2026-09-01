import { createHash, createPrivateKey, randomUUID, sign, type KeyObject } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { McpHumanCallContext } from "./mcp-authority.ts";
import { exactToolApprovalArguments } from "../tools/exact-tool-approval.ts";

export const APPROVED_WRITE_AUTHORITY = "qm.ed25519.approved-write.v1" as const;

export const APPROVED_WRITE_RECEIPT_SCHEMA = Object.freeze({
  type: "object",
  properties: Object.freeze({
    approvalId: Object.freeze({ type: "string", pattern: "^[A-Za-z0-9_-]{1,128}$" }),
    approvalPayloadSha256: Object.freeze({ type: "string", pattern: "^[a-f0-9]{64}$" }),
    actionTs: Object.freeze({ type: "string", pattern: "^\\d{10}\\.\\d{6}$" }),
    slackTeamId: Object.freeze({ type: "string", pattern: "^T[A-Z0-9]{8,20}$" }),
    actorSlackUserId: Object.freeze({ type: "string", pattern: "^[UW][A-Z0-9]{8,20}$" }),
    channelId: Object.freeze({ type: "string", pattern: "^D[A-Z0-9]{8,20}$" }),
    messageTs: Object.freeze({ type: "string", pattern: "^\\d{10}\\.\\d{6}$" }),
    threadTs: Object.freeze({ type: "string", pattern: "^\\d{10}\\.\\d{6}$" }),
  }),
  required: Object.freeze([
    "approvalId",
    "approvalPayloadSha256",
    "actionTs",
    "slackTeamId",
    "actorSlackUserId",
    "channelId",
    "messageTs",
    "threadTs",
  ]),
  additionalProperties: false,
});

interface ArgumentTemplateLeaf {
  argument: string;
}

interface ArgumentTemplateObject {
  [key: string]: ArgumentTemplate;
}

type ArgumentTemplate = ArgumentTemplateLeaf | ArgumentTemplateObject;

interface ArgumentClaim {
  name: string;
  argument?: string;
  sha256Argument?: string;
}

export interface ApprovedWriteAuthorityDescriptor {
  contract: 1;
  profile: typeof APPROVED_WRITE_AUTHORITY;
  id: string;
  tool: string;
  issuerEnv: string;
  keyIdEnv: string;
  privateKeyEnv: string;
  principalEnv: string;
  slackTeamIdEnv: string;
  slackUserIdEnv: string;
  slackDmChannelIdEnv: string;
  audience: string;
  type: string;
  version: string;
  operation: string;
  ttlSeconds: number;
  maximumSigningDelaySeconds: number;
  approvalPayload: ArgumentTemplateObject;
  claims: ArgumentClaim[];
}

interface ResolvedApprovedWriteAuthority extends ApprovedWriteAuthorityDescriptor {
  issuer: string;
  keyId: string;
  privateKey: KeyObject;
  principal: string;
  slackTeamId: string;
  slackUserId: string;
  slackDmChannelId: string;
}

export interface McpApprovedWriteAuthoritySigner {
  sign(
    tool: string,
    args: Record<string, unknown>,
    context: McpHumanCallContext,
  ): { authorityHeader: string; dispatchArguments: Record<string, unknown> };
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_.:/+-]{1,255}$/;
const TOOL_NAME = /^[A-Za-z0-9_-]{1,128}$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]{1,127}$/;
const CLAIM_NAME = /^[A-Za-z][A-Za-z0-9]{0,127}$/;
const ARGUMENT_POINTER = /^(?:\/[A-Za-z0-9_-]{1,128}){1,12}$/;
const SLACK_TS = /^\d{10}\.\d{6}$/;
const EMAIL =
  /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const RESERVED_CLAIMS = new Set([
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
]);
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const JUNK_FILE = /^(?:\.DS_Store|Thumbs\.db|\._.*)$/;

function plainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: object, keys: readonly string[]): boolean {
  return Reflect.ownKeys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function templateLeaf(value: ArgumentTemplate): value is ArgumentTemplateLeaf {
  return exactKeys(value, ["argument"]);
}

function boundedString(value: unknown, pattern: RegExp, maximum = 256): value is string {
  return typeof value === "string" && value.length <= maximum && value === value.trim() && pattern.test(value);
}

function argumentPointer(value: unknown): value is string {
  return (
    boundedString(value, ARGUMENT_POINTER) &&
    value
      .slice(1)
      .split("/")
      .every((part) => !DANGEROUS_KEYS.has(part))
  );
}

function parseTemplate(value: unknown, depth: number, count: { value: number }): ArgumentTemplate {
  if (!plainRecord(value) || depth > 12 || ++count.value > 128) {
    throw new Error("approved write authority approvalPayload is invalid");
  }
  if (exactKeys(value, ["argument"])) {
    if (!argumentPointer(value.argument)) {
      throw new Error("approved write authority approvalPayload argument is invalid");
    }
    return { argument: value.argument };
  }
  const entries = Object.entries(value);
  if (
    entries.length === 0 ||
    entries.length > 64 ||
    entries.some(
      ([key]) =>
        key.length === 0 ||
        key.length > 128 ||
        key !== key.trim() ||
        DANGEROUS_KEYS.has(key) ||
        /[\u0000-\u001f\u007f]/.test(key),
    )
  ) {
    throw new Error("approved write authority approvalPayload object is invalid");
  }
  return Object.fromEntries(entries.map(([key, child]) => [key, parseTemplate(child, depth + 1, count)]));
}

function parseClaim(value: unknown): ArgumentClaim {
  if (!plainRecord(value)) throw new Error("approved write authority claim is invalid");
  const keys = Object.keys(value);
  if (
    keys.length !== 2 ||
    !keys.includes("name") ||
    (!keys.includes("argument") && !keys.includes("sha256Argument")) ||
    !boundedString(value.name, CLAIM_NAME) ||
    RESERVED_CLAIMS.has(value.name) ||
    (value.argument !== undefined && !argumentPointer(value.argument)) ||
    (value.sha256Argument !== undefined && !argumentPointer(value.sha256Argument))
  ) {
    throw new Error("approved write authority claim is invalid");
  }
  return value.argument !== undefined
    ? { name: value.name, argument: value.argument as string }
    : { name: value.name, sha256Argument: value.sha256Argument as string };
}

export function parseApprovedWriteAuthorityDescriptor(
  input: string,
  source = "approved write authority descriptor",
): ApprovedWriteAuthorityDescriptor {
  let decoded: unknown;
  try {
    decoded = JSON.parse(input) as unknown;
  } catch {
    throw new Error(`${source} is not valid JSON`);
  }
  if (!plainRecord(decoded)) throw new Error(`${source} is invalid`);
  const keys = [
    "contract",
    "profile",
    "id",
    "tool",
    "issuerEnv",
    "keyIdEnv",
    "privateKeyEnv",
    "principalEnv",
    "slackTeamIdEnv",
    "slackUserIdEnv",
    "slackDmChannelIdEnv",
    "audience",
    "type",
    "version",
    "operation",
    "ttlSeconds",
    "maximumSigningDelaySeconds",
    "approvalPayload",
    "claims",
  ];
  if (!exactKeys(decoded, keys)) throw new Error(`${source} has an invalid contract`);
  const envFields = [
    decoded.issuerEnv,
    decoded.keyIdEnv,
    decoded.privateKeyEnv,
    decoded.principalEnv,
    decoded.slackTeamIdEnv,
    decoded.slackUserIdEnv,
    decoded.slackDmChannelIdEnv,
  ];
  if (
    decoded.contract !== 1 ||
    decoded.profile !== APPROVED_WRITE_AUTHORITY ||
    !boundedString(decoded.id, IDENTIFIER) ||
    !boundedString(decoded.tool, TOOL_NAME) ||
    envFields.some((value) => !boundedString(value, ENV_NAME)) ||
    !boundedString(decoded.audience, IDENTIFIER) ||
    !boundedString(decoded.type, IDENTIFIER) ||
    !boundedString(decoded.version, IDENTIFIER) ||
    !boundedString(decoded.operation, IDENTIFIER) ||
    !Number.isSafeInteger(decoded.ttlSeconds) ||
    (decoded.ttlSeconds as number) < 10 ||
    (decoded.ttlSeconds as number) > 300 ||
    !Number.isSafeInteger(decoded.maximumSigningDelaySeconds) ||
    (decoded.maximumSigningDelaySeconds as number) < 1 ||
    (decoded.maximumSigningDelaySeconds as number) > 30 ||
    !Array.isArray(decoded.claims) ||
    decoded.claims.length < 1 ||
    decoded.claims.length > 64
  ) {
    throw new Error(`${source} has invalid fields`);
  }
  const approvalPayload = parseTemplate(decoded.approvalPayload, 0, { value: 0 });
  if (templateLeaf(approvalPayload)) {
    throw new Error(`${source} approvalPayload must be an object template`);
  }
  const claims = decoded.claims.map(parseClaim);
  if (new Set(claims.map((claim) => claim.name)).size !== claims.length) {
    throw new Error(`${source} has duplicate claims`);
  }
  return {
    contract: 1,
    profile: APPROVED_WRITE_AUTHORITY,
    id: decoded.id as string,
    tool: decoded.tool as string,
    issuerEnv: decoded.issuerEnv as string,
    keyIdEnv: decoded.keyIdEnv as string,
    privateKeyEnv: decoded.privateKeyEnv as string,
    principalEnv: decoded.principalEnv as string,
    slackTeamIdEnv: decoded.slackTeamIdEnv as string,
    slackUserIdEnv: decoded.slackUserIdEnv as string,
    slackDmChannelIdEnv: decoded.slackDmChannelIdEnv as string,
    audience: decoded.audience as string,
    type: decoded.type as string,
    version: decoded.version as string,
    operation: decoded.operation as string,
    ttlSeconds: decoded.ttlSeconds as number,
    maximumSigningDelaySeconds: decoded.maximumSigningDelaySeconds as number,
    approvalPayload,
    claims,
  };
}

function requiredEnv(env: Readonly<Record<string, string | undefined>>, name: string): string {
  const value = env[name];
  if (!value || value !== value.trim()) throw new Error(`approved write authority environment ${name} is invalid`);
  return value;
}

function resolveDescriptor(
  descriptor: ApprovedWriteAuthorityDescriptor,
  env: Readonly<Record<string, string | undefined>>,
): ResolvedApprovedWriteAuthority {
  const issuer = requiredEnv(env, descriptor.issuerEnv);
  const keyId = requiredEnv(env, descriptor.keyIdEnv);
  const principal = requiredEnv(env, descriptor.principalEnv);
  const slackTeamId = requiredEnv(env, descriptor.slackTeamIdEnv);
  const slackUserId = requiredEnv(env, descriptor.slackUserIdEnv);
  const slackDmChannelId = requiredEnv(env, descriptor.slackDmChannelIdEnv);
  if (
    !/^https:\/\/[^\s/]+(?:\/[^\s]*)?\/$/.test(issuer) ||
    !/^[A-Za-z0-9._-]{1,128}$/.test(keyId) ||
    principal.length > 254 ||
    principal !== principal.toLowerCase() ||
    !EMAIL.test(principal) ||
    !/^T[A-Z0-9]{8,20}$/.test(slackTeamId) ||
    !/^[UW][A-Z0-9]{8,20}$/.test(slackUserId) ||
    !/^D[A-Z0-9]{8,20}$/.test(slackDmChannelId)
  ) {
    throw new Error(`approved write authority ${descriptor.id} environment is invalid`);
  }
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({
      key: Buffer.from(requiredEnv(env, descriptor.privateKeyEnv), "base64"),
      format: "der",
      type: "pkcs8",
    });
  } catch {
    throw new Error(`approved write authority ${descriptor.id} private key is invalid`);
  }
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error(`approved write authority ${descriptor.id} private key must be Ed25519`);
  }
  return {
    ...descriptor,
    issuer,
    keyId,
    privateKey,
    principal,
    slackTeamId,
    slackUserId,
    slackDmChannelId,
  };
}

function argumentAt(args: Record<string, unknown>, pointer: string): unknown {
  let value: unknown = args;
  for (const part of pointer.slice(1).split("/")) {
    if (!plainRecord(value) || !Object.hasOwn(value, part)) {
      throw new Error(`approved write authority argument ${pointer} is unavailable`);
    }
    value = value[part];
  }
  return value;
}

function materialize(template: ArgumentTemplate, args: Record<string, unknown>): unknown {
  if (templateLeaf(template)) return argumentAt(args, template.argument);
  return Object.fromEntries(
    Object.entries(template as ArgumentTemplateObject).map(([key, child]) => [key, materialize(child, args)]),
  );
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function signingContext(profile: ResolvedApprovedWriteAuthority, context: McpHumanCallContext): void {
  const approval = context.approval;
  if (
    context.surface !== "slack" ||
    context.conversationType !== "dm" ||
    context.principalId !== profile.principal ||
    context.slackTeamId !== profile.slackTeamId ||
    context.slackUserId !== profile.slackUserId ||
    context.slackChannelId !== profile.slackDmChannelId ||
    (context.deliveryTarget !== profile.slackDmChannelId &&
      context.deliveryTarget !== `${profile.slackDmChannelId}:${context.slackThreadTs}`) ||
    !approval ||
    approval.slackTeamId !== context.slackTeamId ||
    approval.actorSlackUserId !== context.slackUserId ||
    approval.channelId !== context.slackChannelId ||
    approval.messageTs !== context.slackMessageTs ||
    approval.threadTs !== context.slackThreadTs ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(approval.approvalId) ||
    !SLACK_TS.test(approval.actionTs) ||
    !SLACK_TS.test(approval.messageTs) ||
    !SLACK_TS.test(approval.threadTs)
  ) {
    throw new Error("approved write authority Slack context is invalid");
  }
}

function createSigner(
  descriptors: ApprovedWriteAuthorityDescriptor[],
  env: Readonly<Record<string, string | undefined>>,
  now: () => number,
): McpApprovedWriteAuthoritySigner {
  const profiles = descriptors.map((descriptor) => resolveDescriptor(descriptor, env));
  if (new Set(profiles.map((profile) => profile.tool)).size !== profiles.length) {
    throw new Error("approved write authority tools must be unique");
  }
  return {
    sign(tool, args, context) {
      const profile = profiles.find((candidate) => candidate.tool === tool);
      if (!profile) throw new Error(`approved write authority has no profile for ${tool}`);
      signingContext(profile, context);
      const approval = context.approval!;
      const approvedArgumentsSha256 = exactToolApprovalArguments(args).sha256;
      if (approval.argumentsSha256 !== approvedArgumentsSha256) {
        throw new Error("approved write authority arguments do not match the approval");
      }
      const iat = Math.floor(now() / 1_000);
      const actionSeconds = Number(approval.actionTs.slice(0, 10));
      if (iat < actionSeconds || iat > actionSeconds + profile.maximumSigningDelaySeconds) {
        throw new Error("approved write authority approval is no longer fresh");
      }
      const approvalPayloadSha256 = sha256(JSON.stringify(materialize(profile.approvalPayload, args)));
      const receipt = {
        approvalId: approval.approvalId,
        approvalPayloadSha256,
        actionTs: approval.actionTs,
        slackTeamId: approval.slackTeamId,
        actorSlackUserId: approval.actorSlackUserId,
        channelId: approval.channelId,
        messageTs: approval.messageTs,
        threadTs: approval.threadTs,
      };
      const claims: Record<string, unknown> = {
        version: profile.version,
        iss: profile.issuer,
        aud: profile.audience,
        jti: randomUUID(),
        iat,
        exp: iat + profile.ttlSeconds,
        operation: profile.operation,
        approvedArgumentsSha256,
        approvalId: receipt.approvalId,
        approvalPayloadSha256: receipt.approvalPayloadSha256,
        slackTeamId: receipt.slackTeamId,
        actorSlackUserId: receipt.actorSlackUserId,
        channelId: receipt.channelId,
        messageTs: receipt.messageTs,
        threadTs: receipt.threadTs,
        actionTs: receipt.actionTs,
      };
      for (const claim of profile.claims) {
        const source = argumentAt(args, claim.argument ?? claim.sha256Argument!);
        if (typeof source !== "string") throw new Error(`approved write authority claim ${claim.name} is invalid`);
        claims[claim.name] = claim.sha256Argument ? sha256(source) : source;
      }
      const header = Buffer.from(JSON.stringify({ alg: "EdDSA", kid: profile.keyId, typ: profile.type })).toString(
        "base64url",
      );
      const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
      const signature = sign(null, Buffer.from(`${header}.${payload}`, "ascii"), profile.privateKey).toString(
        "base64url",
      );
      const authorityHeader = `${header}.${payload}.${signature}`;
      if (Buffer.byteLength(authorityHeader) > 16 * 1_024) {
        throw new Error("approved write authority token exceeds its bound");
      }
      return { authorityHeader, dispatchArguments: { ...args, approval: receipt } };
    },
  };
}

export function loadApprovedWriteAuthoritySigner(
  layerDir: string,
  env: Readonly<Record<string, string | undefined>>,
  now = () => Date.now(),
): McpApprovedWriteAuthoritySigner | undefined {
  const directories = [join(layerDir, "mcp-authorities")];
  const skillsDir = join(layerDir, "skills");
  if (existsSync(skillsDir)) {
    const skillsStat = lstatSync(skillsDir);
    if (skillsStat.isSymbolicLink() || !skillsStat.isDirectory()) {
      throw new Error(`${skillsDir} must be a regular directory`);
    }
    for (const entry of readdirSync(skillsDir, { withFileTypes: true })
      .filter((candidate) => !JUNK_FILE.test(candidate.name))
      .sort((left, right) => left.name.localeCompare(right.name, "en"))) {
      const skillDir = join(skillsDir, entry.name);
      if (entry.isSymbolicLink() || !entry.isDirectory()) {
        throw new Error(`${skillDir} must be a regular directory`);
      }
      directories.push(join(skillDir, "mcp-authorities"));
    }
  }
  const descriptorFiles = directories.flatMap((dir) => {
    if (!existsSync(dir)) return [];
    const dirStat = lstatSync(dir);
    if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
      throw new Error(`${dir} must be a regular directory`);
    }
    return readdirSync(dir, { withFileTypes: true })
      .filter((entry) => !JUNK_FILE.test(entry.name))
      .sort((left, right) => left.name.localeCompare(right.name, "en"))
      .map((entry) => ({ dir, entry }));
  });
  if (descriptorFiles.length === 0) return undefined;
  if (descriptorFiles.length > 16) {
    throw new Error("approved write authority layer must contain 1 through 16 descriptors");
  }
  const descriptors = descriptorFiles.map(({ dir, entry }) => {
    const path = join(dir, entry.name);
    if (!entry.isFile() || !entry.name.endsWith(".json")) {
      throw new Error(`${path} must be a regular JSON file`);
    }
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`${path} must be a regular file`);
    return parseApprovedWriteAuthorityDescriptor(readFileSync(path, "utf8"), path);
  });
  if (new Set(descriptors.map((descriptor) => descriptor.id)).size !== descriptors.length) {
    throw new Error("approved write authority descriptor ids must be unique");
  }
  return createSigner(descriptors, env, now);
}
