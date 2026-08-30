import { createHash } from "node:crypto";
import { canonicalJson } from "../cron/schedule-authority.ts";
import type { BackgroundJobDeploymentProfile, BackgroundJobRoute } from "./types.ts";
import { parseStrictHttpsUrl, validateBackgroundJobProfile, validateDefinition } from "./validation.ts";

const TOOL_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SHA256 = /^[a-f0-9]{64}$/;
const SIMPLE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function record(value: unknown, name: string): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): void {
  const keys = new Set([...required, ...optional]);
  if (!required.every((key) => Object.hasOwn(value, key)) || Object.keys(value).some((key) => !keys.has(key))) {
    throw new TypeError("background job profile has unexpected fields");
  }
}

function string(value: unknown, name: string, pattern: RegExp, max = 200): string {
  if (typeof value !== "string" || value.length > max || !pattern.test(value))
    throw new TypeError(`${name} is invalid`);
  return value;
}

function tool(value: unknown, name: string): { id: string; label: string } {
  const item = record(value, name);
  exact(item, ["id", "label"]);
  return {
    id: string(item.id, `${name}.id`, TOOL_ID, 80),
    label: string(item.label, `${name}.label`, /^\S(?:.{0,118}\S)?$/, 120),
  };
}

function route(value: unknown, name: string): BackgroundJobRoute {
  const item = record(value, name);
  exact(item, ["path", "maxRequestBytes"]);
  return { path: item.path as string, maxRequestBytes: item.maxRequestBytes as number };
}

function validateSchemaJson(value: unknown, depth = 0, budget = { nodes: 0, strings: 0 }): void {
  budget.nodes += 1;
  if (depth > 32 || budget.nodes > 20_000) throw new TypeError("background job schema is too complex");
  if (typeof value === "string") {
    budget.strings += value.length;
    if (value.length > 20_000 || budget.strings > 400_000) throw new TypeError("background job schema is too large");
    return;
  }
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("background job schema is invalid");
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 2_000) throw new TypeError("background job schema is too large");
    for (const item of value) validateSchemaJson(item, depth + 1, budget);
    return;
  }
  const item = record(value, "schema.json");
  const keys = Object.keys(item);
  if (keys.length > 2_000 || keys.some((key) => FORBIDDEN_KEYS.has(key) || key.length > 500)) {
    throw new TypeError("background job schema is invalid");
  }
  for (const key of keys) validateSchemaJson(item[key], depth + 1, budget);
}

export function parseBackgroundJobDeploymentProfile(value: unknown): BackgroundJobDeploymentProfile {
  const root = record(value, "backgroundJob");
  exact(root, [
    "contract",
    "enabled",
    "definition",
    "issuer",
    "audience",
    "origin",
    "profile",
    "tools",
    "schema",
    "artifacts",
    "dependencies",
  ]);
  if (root.contract !== 1 || typeof root.enabled !== "boolean")
    throw new TypeError("background job profile contract is invalid");
  const rawDefinition = record(root.definition, "definition");
  exact(
    rawDefinition,
    ["id", "operation", "capability", "scope", "tokenType", "authorityHeader", "start", "status", "cancel"],
    ["prepare"],
  );
  const definition = {
    id: rawDefinition.id as string,
    operation: rawDefinition.operation as string,
    capability: rawDefinition.capability as string,
    scope: rawDefinition.scope as string,
    tokenType: rawDefinition.tokenType as string,
    authorityHeader: rawDefinition.authorityHeader as string,
    ...(rawDefinition.prepare === undefined ? {} : { prepare: route(rawDefinition.prepare, "definition.prepare") }),
    start: route(rawDefinition.start, "definition.start"),
    status: route(rawDefinition.status, "definition.status"),
    cancel: route(rawDefinition.cancel, "definition.cancel"),
  };
  validateDefinition(definition);
  const rawProfile = record(root.profile, "profile");
  exact(rawProfile, [
    "organizationId",
    "actorPrincipalId",
    "actorSlackId",
    "audienceScopeId",
    "slackTeamId",
    "channelId",
  ]);
  const profile = {
    organizationId: rawProfile.organizationId as string,
    actorPrincipalId: rawProfile.actorPrincipalId as string,
    actorSlackId: rawProfile.actorSlackId as string,
    audienceScopeId: rawProfile.audienceScopeId as string,
    slackTeamId: rawProfile.slackTeamId as string,
    channelId: rawProfile.channelId as string,
  };
  validateBackgroundJobProfile(profile);
  const toolsValue = record(root.tools, "tools");
  exact(toolsValue, ["start", "status", "cancel"]);
  const tools = {
    start: tool(toolsValue.start, "tools.start"),
    status: tool(toolsValue.status, "tools.status"),
    cancel: tool(toolsValue.cancel, "tools.cancel"),
  };
  if (new Set(Object.values(tools).map((entry) => entry.id)).size !== 3)
    throw new TypeError("background job tool ids must be distinct");
  const schemaValue = record(root.schema, "schema");
  exact(schemaValue, ["sha256", "json"]);
  validateSchemaJson(schemaValue.json);
  const schemaSha = string(schemaValue.sha256, "schema.sha256", SHA256, 64);
  const schemaBytes = Buffer.from(canonicalJson(schemaValue.json), "utf8");
  if (schemaBytes.byteLength > 512 * 1024) throw new TypeError("background job schema is too large");
  const actualSchemaSha = createHash("sha256").update(schemaBytes).digest("hex");
  if (schemaSha !== actualSchemaSha) throw new TypeError("background job schema hash does not match");
  if (!Array.isArray(root.artifacts) || root.artifacts.length < 1 || root.artifacts.length > 32) {
    throw new TypeError("background job artifacts are invalid");
  }
  const artifacts = root.artifacts.map((value, index) => {
    const item = record(value, `artifacts[${index}]`);
    exact(item, ["kind", "label", "visibility"]);
    if (item.visibility !== "primary" && item.visibility !== "private_review")
      throw new TypeError("artifact visibility is invalid");
    return {
      kind: string(item.kind, "artifact kind", SIMPLE_ID),
      label: string(item.label, "artifact label", /^\S(?:.{0,118}\S)?$/, 120),
      visibility: item.visibility,
    } as const;
  });
  if (
    new Set(artifacts.map((item) => item.kind)).size !== artifacts.length ||
    !artifacts.some((item) => item.visibility === "primary")
  ) {
    throw new TypeError("background job artifacts are invalid");
  }
  const dependenciesValue = record(root.dependencies, "dependencies");
  exact(dependenciesValue, ["adapter", "receiptStore", "authority"]);
  if (dependenciesValue.authority !== "kms-rs256-v1") throw new TypeError("dependencies.authority is invalid");
  const dependencies = {
    adapter: string(dependenciesValue.adapter, "dependencies.adapter", SIMPLE_ID),
    receiptStore: string(dependenciesValue.receiptStore, "dependencies.receiptStore", SIMPLE_ID),
    authority: "kms-rs256-v1" as const,
  };
  parseStrictHttpsUrl(root.issuer as string, "issuer", false);
  parseStrictHttpsUrl(root.audience as string, "audience", false);
  const issuer = root.issuer as string;
  const audience = root.audience as string;
  const origin = parseStrictHttpsUrl(root.origin as string, "origin", true).origin;
  return Object.freeze({
    contract: 1,
    enabled: root.enabled,
    definition: Object.freeze({
      ...definition,
      ...(definition.prepare ? { prepare: Object.freeze(definition.prepare) } : {}),
      start: Object.freeze(definition.start),
      status: Object.freeze(definition.status),
      cancel: Object.freeze(definition.cancel),
    }),
    issuer,
    audience,
    origin,
    profile: Object.freeze(profile),
    tools: Object.freeze({
      start: Object.freeze(tools.start),
      status: Object.freeze(tools.status),
      cancel: Object.freeze(tools.cancel),
    }),
    schema: Object.freeze({ sha256: schemaSha, json: structuredClone(schemaValue.json) }),
    artifacts: Object.freeze(artifacts.map((item) => Object.freeze(item))),
    dependencies: Object.freeze(dependencies),
  });
}
