import { createHash } from "node:crypto";
import { canonicalJson } from "../cron/schedule-authority.ts";
import type { BackgroundJobDeploymentProfile, BackgroundJobRoute } from "./types.ts";
import { parsePublicHttpsUrl, validateBackgroundJobProfile, validateDefinition } from "./validation.ts";

const TOOL_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SHA256 = /^[a-f0-9]{64}$/;
const SIMPLE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const PROPERTY_ID = /^[A-Za-z_][A-Za-z0-9_-]{0,127}$/;
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const RESERVED_TOOL_IDS = new Set([
  "admin",
  "background",
  "control",
  "core",
  "credential",
  "cron",
  "execute",
  "finish",
  "goal",
  "guidance",
  "history",
  "mcp",
  "memory",
  "miniapp",
  "process",
  "publish",
  "read",
  "run",
  "share",
  "shell",
  "stay",
  "system",
  "tool",
  "webhook",
  "write",
]);
const SCHEMA_KEYS = new Set([
  "$defs",
  "$id",
  "$ref",
  "$schema",
  "additionalProperties",
  "const",
  "description",
  "enum",
  "format",
  "items",
  "maxItems",
  "maxLength",
  "maxProperties",
  "maximum",
  "minItems",
  "minLength",
  "minProperties",
  "minimum",
  "properties",
  "required",
  "title",
  "type",
]);
const SCHEMA_TYPES = new Set(["array", "boolean", "integer", "null", "number", "object", "string"]);
const SCHEMA_FORMATS = new Set(["date-time", "email", "uuid"]);

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
  if (typeof value !== "string" || value.length > max || !pattern.test(value)) {
    throw new TypeError(`${name} is invalid`);
  }
  return value;
}

function integer(value: unknown, name: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new TypeError(`${name} is invalid`);
  }
  return value as number;
}

function tool(value: unknown, name: string): { id: string; label: string } {
  const item = record(value, name);
  exact(item, ["id", "label"]);
  const id = string(item.id, `${name}.id`, TOOL_ID, 80);
  if ([...RESERVED_TOOL_IDS].some((reserved) => id === reserved || id.startsWith(`${reserved}-`))) {
    throw new TypeError(`${name}.id is reserved`);
  }
  return { id, label: string(item.label, `${name}.label`, /^\S(?:.{0,118}\S)?$/, 120) };
}

function route(value: unknown, name: string): BackgroundJobRoute {
  const item = record(value, name);
  exact(item, ["path", "maxRequestBytes"]);
  return { path: item.path as string, maxRequestBytes: item.maxRequestBytes as number };
}

function validateJsonBudget(value: unknown, depth = 0, budget = { nodes: 0, strings: 0 }): void {
  budget.nodes += 1;
  if (depth > 32 || budget.nodes > 20_000) throw new TypeError("background job schema is too complex");
  if (typeof value === "string") {
    budget.strings += value.length;
    if (value.length > 20_000 || budget.strings > 400_000) throw new TypeError("background job schema is too large");
    return;
  }
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("background job schema is invalid");
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 2_000) throw new TypeError("background job schema is too large");
    for (const item of value) validateJsonBudget(item, depth + 1, budget);
    return;
  }
  const item = record(value, "schema.json");
  const keys = Object.keys(item);
  if (keys.length > 2_000 || keys.some((key) => FORBIDDEN_KEYS.has(key) || key.length > 500)) {
    throw new TypeError("background job schema is invalid");
  }
  for (const key of keys) validateJsonBudget(item[key], depth + 1, budget);
}

function schemaString(value: unknown, name: string): string {
  return string(value, name, /^\S(?:[\s\S]{0,19998}\S)?$/, 20_000);
}

function validateSchemaNode(value: unknown, name: string, definitions: ReadonlySet<string>, root = false): void {
  const item = record(value, name);
  if (Object.keys(item).some((key) => !SCHEMA_KEYS.has(key)))
    throw new TypeError(`${name} uses an unsupported keyword`);
  if (item.title !== undefined) schemaString(item.title, `${name}.title`);
  if (item.description !== undefined) schemaString(item.description, `${name}.description`);
  if (item.$schema !== undefined && (!root || item.$schema !== "https://json-schema.org/draft/2020-12/schema")) {
    throw new TypeError(`${name}.$schema is unsupported`);
  }
  if (item.$id !== undefined) {
    if (typeof item.$id !== "string") throw new TypeError(`${name}.$id is invalid`);
    parsePublicHttpsUrl(item.$id, `${name}.$id`, false);
  }
  if (item.$ref !== undefined) {
    const ref = string(item.$ref, `${name}.$ref`, /^#\/\$defs\/[A-Za-z_][A-Za-z0-9_-]{0,127}$/, 136);
    if (!definitions.has(ref.slice("#/$defs/".length))) throw new TypeError(`${name}.$ref is unresolved`);
    const allowed = new Set(["$ref", "title", "description"]);
    if (Object.keys(item).some((key) => !allowed.has(key))) throw new TypeError(`${name}.$ref has siblings`);
    return;
  }
  if (typeof item.type !== "string" || !SCHEMA_TYPES.has(item.type)) throw new TypeError(`${name}.type is unsupported`);
  if (item.enum !== undefined) {
    if (!Array.isArray(item.enum) || item.enum.length < 1 || item.enum.length > 100) {
      throw new TypeError(`${name}.enum is invalid`);
    }
    const values = item.enum.map((entry) => canonicalJson(entry));
    if (new Set(values).size !== values.length) throw new TypeError(`${name}.enum is invalid`);
  }
  if (item.const !== undefined) canonicalJson(item.const);
  if (item.format !== undefined && (item.type !== "string" || !SCHEMA_FORMATS.has(item.format as string))) {
    throw new TypeError(`${name}.format is unsupported`);
  }
  if (item.type === "object") {
    const properties = record(item.properties, `${name}.properties`);
    const propertyNames = Object.keys(properties);
    if (propertyNames.length < 1 || propertyNames.length > 256 || propertyNames.some((key) => !PROPERTY_ID.test(key))) {
      throw new TypeError(`${name}.properties is invalid`);
    }
    if (item.additionalProperties !== false) throw new TypeError(`${name} must reject additional properties`);
    if (!Array.isArray(item.required) || item.required.length < 1 || item.required.length > propertyNames.length) {
      throw new TypeError(`${name}.required is invalid`);
    }
    if (
      item.required.some((key) => typeof key !== "string" || !Object.hasOwn(properties, key)) ||
      new Set(item.required).size !== item.required.length
    ) {
      throw new TypeError(`${name}.required is invalid`);
    }
    if (item.minProperties !== undefined) integer(item.minProperties, `${name}.minProperties`, 0, propertyNames.length);
    if (item.maxProperties !== undefined) integer(item.maxProperties, `${name}.maxProperties`, 1, propertyNames.length);
    for (const key of propertyNames) validateSchemaNode(properties[key], `${name}.properties.${key}`, definitions);
  } else if (item.properties !== undefined || item.required !== undefined || item.additionalProperties !== undefined) {
    throw new TypeError(`${name} has object keywords on a non-object`);
  }
  if (item.type === "array") {
    if (item.items === undefined) throw new TypeError(`${name}.items is required`);
    validateSchemaNode(item.items, `${name}.items`, definitions);
    const maxItems = integer(item.maxItems, `${name}.maxItems`, 1, 2_000);
    if (item.minItems !== undefined && integer(item.minItems, `${name}.minItems`, 0, maxItems) > maxItems) {
      throw new TypeError(`${name}.minItems is invalid`);
    }
  } else if (item.items !== undefined || item.minItems !== undefined || item.maxItems !== undefined) {
    throw new TypeError(`${name} has array keywords on a non-array`);
  }
  if (item.type === "string") {
    const maxLength =
      item.maxLength === undefined ? undefined : integer(item.maxLength, `${name}.maxLength`, 1, 20_000);
    if (maxLength === undefined && item.enum === undefined && item.const === undefined) {
      throw new TypeError(`${name}.maxLength is required`);
    }
    if (item.minLength !== undefined) integer(item.minLength, `${name}.minLength`, 0, maxLength ?? 20_000);
  } else if (item.minLength !== undefined || item.maxLength !== undefined || item.format !== undefined) {
    throw new TypeError(`${name} has string keywords on a non-string`);
  }
  if (item.type === "number" || item.type === "integer") {
    if (item.minimum !== undefined && !Number.isSafeInteger(item.minimum)) {
      throw new TypeError(`${name}.minimum is invalid`);
    }
    if (item.maximum !== undefined && !Number.isSafeInteger(item.maximum)) {
      throw new TypeError(`${name}.maximum is invalid`);
    }
    if (typeof item.minimum === "number" && typeof item.maximum === "number" && item.minimum > item.maximum) {
      throw new TypeError(`${name} numeric bounds are invalid`);
    }
  } else if (item.minimum !== undefined || item.maximum !== undefined) {
    throw new TypeError(`${name} has numeric keywords on a non-number`);
  }
  if (item.$defs !== undefined) {
    if (!root) throw new TypeError(`${name}.$defs is unsupported here`);
    const defs = record(item.$defs, `${name}.$defs`);
    for (const key of Object.keys(defs)) validateSchemaNode(defs[key], `${name}.$defs.${key}`, definitions);
  }
}

function definitionRefs(value: unknown, refs = new Set<string>()): ReadonlySet<string> {
  if (!value || typeof value !== "object") return refs;
  if (Array.isArray(value)) {
    for (const entry of value) definitionRefs(entry, refs);
    return refs;
  }
  const item = value as Record<string, unknown>;
  if (typeof item.$ref === "string") refs.add(item.$ref.slice("#/$defs/".length));
  for (const entry of Object.values(item)) definitionRefs(entry, refs);
  return refs;
}

function validateDefinitionGraph(definitions: Readonly<Record<string, unknown>>): void {
  const graph = new Map(Object.keys(definitions).map((name) => [name, definitionRefs(definitions[name])]));
  const visiting = new Set<string>();
  const depths = new Map<string, number>();
  const visit = (name: string): number => {
    if (visiting.has(name)) throw new TypeError("schema.json.$defs must be acyclic and bounded");
    const prior = depths.get(name);
    if (prior !== undefined) return prior;
    visiting.add(name);
    let depth = 1;
    for (const next of graph.get(name) ?? []) depth = Math.max(depth, visit(next) + 1);
    visiting.delete(name);
    if (depth > 32) throw new TypeError("schema.json.$defs must be acyclic and bounded");
    depths.set(name, depth);
    return depth;
  };
  for (const name of graph.keys()) visit(name);
}

function validateSchemaJson(value: unknown): void {
  validateJsonBudget(value);
  const root = record(value, "schema.json");
  const defs = root.$defs === undefined ? {} : record(root.$defs, "schema.json.$defs");
  const names = Object.keys(defs);
  if (names.some((key) => !PROPERTY_ID.test(key))) throw new TypeError("schema.json.$defs is invalid");
  validateSchemaNode(root, "schema.json", new Set(names), true);
  validateDefinitionGraph(defs);
  if (root.type !== "object") throw new TypeError("schema.json must be a closed object schema");
}

function schemaEqual(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

function validateStringFormat(value: string, format: unknown): boolean {
  if (format === undefined) return true;
  if (format === "date-time") {
    const match = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-](\d{2}):(\d{2}))$/);
    if (!match) return false;
    const [year, month, day, hour, minute, second, offsetHour, offsetMinute] = [
      match[1],
      match[2],
      match[3],
      match[4],
      match[5],
      match[6],
      match[8] ?? "0",
      match[9] ?? "0",
    ].map(Number);
    if (
      year! < 1 ||
      month! < 1 ||
      month! > 12 ||
      day! < 1 ||
      day! > new Date(Date.UTC(year!, month!, 0)).getUTCDate() ||
      hour! > 23 ||
      minute! > 59 ||
      second! > 59 ||
      offsetHour! > 14 ||
      offsetMinute! > 59 ||
      (offsetHour === 14 && offsetMinute !== 0)
    ) {
      return false;
    }
    return !Number.isNaN(Date.parse(value));
  }
  if (format === "email") return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);
  if (format === "uuid") {
    return /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
  }
  return false;
}

function validateSchemaInstance(
  schema: Record<string, unknown>,
  value: unknown,
  definitions: Readonly<Record<string, unknown>>,
  depth = 0,
): boolean {
  if (depth > 64) return false;
  if (typeof schema.$ref === "string") {
    const resolved = definitions[schema.$ref.slice("#/$defs/".length)];
    return (
      Boolean(resolved) && validateSchemaInstance(record(resolved, "schema definition"), value, definitions, depth + 1)
    );
  }
  if (schema.enum !== undefined && !(schema.enum as unknown[]).some((entry) => schemaEqual(entry, value))) return false;
  if (Object.hasOwn(schema, "const") && !schemaEqual(schema.const, value)) return false;
  if (schema.type === "null") return value === null;
  if (schema.type === "boolean") return typeof value === "boolean";
  if (schema.type === "number" || schema.type === "integer") {
    if (typeof value !== "number" || !Number.isSafeInteger(value)) {
      return false;
    }
    if (typeof schema.minimum === "number" && value < schema.minimum) return false;
    if (typeof schema.maximum === "number" && value > schema.maximum) return false;
    return true;
  }
  if (schema.type === "string") {
    if (typeof value !== "string") return false;
    const length = [...value].length;
    if (typeof schema.minLength === "number" && length < schema.minLength) return false;
    if (typeof schema.maxLength === "number" && length > schema.maxLength) return false;
    return validateStringFormat(value, schema.format);
  }
  if (schema.type === "array") {
    if (!Array.isArray(value)) return false;
    if (typeof schema.minItems === "number" && value.length < schema.minItems) return false;
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) return false;
    const items = record(schema.items, "schema items");
    return value.every((entry) => validateSchemaInstance(items, entry, definitions, depth + 1));
  }
  if (schema.type === "object") {
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) {
      return false;
    }
    const instance = value as Record<string, unknown>;
    const properties = record(schema.properties, "schema properties");
    const keys = Object.keys(instance);
    if (keys.some((key) => !Object.hasOwn(properties, key))) return false;
    if ((schema.required as string[]).some((key) => !Object.hasOwn(instance, key))) return false;
    if (typeof schema.minProperties === "number" && keys.length < schema.minProperties) return false;
    if (typeof schema.maxProperties === "number" && keys.length > schema.maxProperties) return false;
    return keys.every((key) =>
      validateSchemaInstance(record(properties[key], "schema property"), instance[key], definitions, depth + 1),
    );
  }
  return false;
}

export function validateBackgroundJobSchemaValue(schema: unknown, value: unknown): void {
  validateSchemaJson(schema);
  const root = record(schema, "schema.json");
  const definitions = root.$defs === undefined ? {} : record(root.$defs, "schema.json.$defs");
  if (!validateSchemaInstance(root, value, definitions))
    throw new TypeError("background job payload does not match schema");
}

function freezeJson(value: unknown): unknown {
  const clone = structuredClone(value);
  const freeze = (entry: unknown): unknown => {
    if (!entry || typeof entry !== "object") return entry;
    for (const child of Object.values(entry)) freeze(child);
    return Object.freeze(entry);
  };
  return freeze(clone);
}

function hash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function parseBackgroundJobDeploymentProfile(
  raw: string,
  sourcePath: string,
  enabled = true,
): BackgroundJobDeploymentProfile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new TypeError(`${sourcePath} is not valid JSON`);
  }
  const root = record(parsed, "backgroundJob");
  exact(root, [
    "contract",
    "definition",
    "issuer",
    "audience",
    "origin",
    "artifactPathPrefix",
    "artifactAccess",
    "profile",
    "tools",
    "approval",
    "schema",
    "artifacts",
    "dependencies",
  ]);
  if (root.contract !== 1 || typeof enabled !== "boolean") {
    throw new TypeError("background job profile contract is invalid");
  }
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
  const expectedPath = `background-jobs/${definition.id}/job.json`;
  if (sourcePath !== expectedPath && !sourcePath.endsWith(`/${expectedPath}`)) {
    throw new TypeError(`${sourcePath}: background job id must match its directory`);
  }
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
  if (new Set(Object.values(tools).map((entry) => entry.id)).size !== 3) {
    throw new TypeError("background job tool ids must be distinct");
  }
  const approvalValue = record(root.approval, "approval");
  exact(approvalValue, ["start", "cancel"]);
  if (approvalValue.start !== "invocation_receipt" || approvalValue.cancel !== "invocation_receipt") {
    throw new TypeError("background job approval policy is invalid");
  }
  const schemaValue = record(root.schema, "schema");
  exact(schemaValue, ["sha256", "json"]);
  validateSchemaJson(schemaValue.json);
  const schemaSha = string(schemaValue.sha256, "schema.sha256", SHA256, 64);
  const schemaBytes = Buffer.from(canonicalJson(schemaValue.json), "utf8");
  if (schemaBytes.byteLength > 512 * 1024) throw new TypeError("background job schema is too large");
  if (schemaSha !== createHash("sha256").update(schemaBytes).digest("hex")) {
    throw new TypeError("background job schema hash does not match");
  }
  if (!Array.isArray(root.artifacts) || root.artifacts.length < 1 || root.artifacts.length > 32) {
    throw new TypeError("background job artifacts are invalid");
  }
  const artifacts = root.artifacts.map((value, index) => {
    const item = record(value, `artifacts[${index}]`);
    exact(item, ["kind", "label", "visibility"]);
    if (item.visibility !== "primary" && item.visibility !== "private_review") {
      throw new TypeError("artifact visibility is invalid");
    }
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
  exact(dependenciesValue, ["adapter", "receiptStore", "approvalStore", "authority"]);
  if (dependenciesValue.authority !== "kms-rs256-v1") throw new TypeError("dependencies.authority is invalid");
  const dependency = (value: unknown, name: string) => {
    const resolved = string(value, name, SIMPLE_ID);
    if (/(credential|env|key|password|private|secret|token)/i.test(resolved)) {
      throw new TypeError(`${name} is invalid`);
    }
    return resolved;
  };
  const dependencies = {
    adapter: dependency(dependenciesValue.adapter, "dependencies.adapter"),
    receiptStore: dependency(dependenciesValue.receiptStore, "dependencies.receiptStore"),
    approvalStore: dependency(dependenciesValue.approvalStore, "dependencies.approvalStore"),
    authority: "kms-rs256-v1" as const,
  };
  if (typeof root.issuer !== "string" || typeof root.audience !== "string" || typeof root.origin !== "string") {
    throw new TypeError("background job URLs are invalid");
  }
  parsePublicHttpsUrl(root.issuer, "issuer", false);
  parsePublicHttpsUrl(root.audience, "audience", false);
  const issuer = root.issuer as string;
  const audience = root.audience as string;
  const origin = parsePublicHttpsUrl(root.origin, "origin", true).origin;
  const artifactPathPrefix = string(
    root.artifactPathPrefix,
    "artifactPathPrefix",
    /^\/[A-Za-z0-9._~!$&'()*+,;=:@/-]{1,499}\/$/,
    500,
  );
  validateDefinition({
    ...definition,
    cancel: { path: artifactPathPrefix.slice(0, -1), maxRequestBytes: 2 },
  });
  if (root.artifactAccess !== "owner_authenticated") throw new TypeError("artifactAccess is invalid");
  const descriptorSha256 = hash(root);
  const profileSha256 = hash(root.profile);
  return Object.freeze({
    contract: 1,
    enabled,
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
    artifactPathPrefix,
    artifactAccess: "owner_authenticated",
    profile: Object.freeze(profile),
    tools: Object.freeze({
      start: Object.freeze(tools.start),
      status: Object.freeze(tools.status),
      cancel: Object.freeze(tools.cancel),
    }),
    approval: Object.freeze({ start: "invocation_receipt", cancel: "invocation_receipt" }),
    schema: Object.freeze({ sha256: schemaSha, json: freezeJson(schemaValue.json) }),
    binding: Object.freeze({ descriptorSha256, profileSha256, schemaSha256: schemaSha }),
    artifacts: Object.freeze(artifacts.map((item) => Object.freeze(item))),
    dependencies: Object.freeze(dependencies),
  });
}
