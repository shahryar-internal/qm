import { createPublicKey, type JsonWebKey } from "node:crypto";
import { isIP } from "node:net";
import type { BackgroundJobAudienceProfile, BackgroundJobContractBinding, BackgroundJobDefinition } from "./types.ts";

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;
const SLACK_USER_ID = /^[UW][A-Z0-9]{2,31}$/;
const SLACK_TEAM_ID = /^T[A-Z0-9]{2,31}$/;
const SLACK_DM_ID = /^D[A-Z0-9]{2,31}$/;
const SLACK_TIMESTAMP = /^\d{10,}\.\d{6}$/;

export function identifier(value: unknown, name: string, pattern = IDENTIFIER): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new TypeError(`${name} is invalid`);
  return value;
}

export function validateBackgroundJobProfile(profile: Readonly<BackgroundJobAudienceProfile>): void {
  identifier(profile.organizationId, "organizationId");
  identifier(profile.actorPrincipalId, "actorPrincipalId");
  identifier(profile.actorSlackId, "actorSlackId", SLACK_USER_ID);
  identifier(profile.audienceScopeId, "audienceScopeId");
  identifier(profile.slackTeamId, "slackTeamId", SLACK_TEAM_ID);
  identifier(profile.channelId, "channelId", SLACK_DM_ID);
  if (profile.audienceScopeId !== `personal:${profile.actorPrincipalId}`)
    throw new TypeError("audienceScopeId is invalid");
}

export function validateSlackTimestamp(value: unknown, name: string): string {
  return identifier(value, name, SLACK_TIMESTAMP);
}

export function validateContractBinding(binding: Readonly<BackgroundJobContractBinding>): void {
  if (!binding || typeof binding !== "object" || Object.getPrototypeOf(binding) !== Object.prototype) {
    throw new TypeError("background job contract binding is invalid");
  }
  for (const [name, value] of Object.entries(binding)) {
    if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new TypeError(`${name} is invalid`);
  }
  if (Object.keys(binding).sort().join(",") !== "descriptorSha256,profileSha256,schemaSha256") {
    throw new TypeError("background job contract binding is invalid");
  }
}

export function validateDefinition(definition: Readonly<BackgroundJobDefinition>): void {
  identifier(definition.id, "job id");
  identifier(definition.operation, "operation");
  identifier(definition.capability, "capability");
  identifier(definition.scope, "scope");
  if (!/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$/.test(definition.tokenType)) throw new TypeError("token type is invalid");
  if (!/^x-[a-z0-9-]{1,100}$/.test(definition.authorityHeader)) throw new TypeError("authority header is invalid");
  const paths = new Set<string>();
  for (const [name, route] of Object.entries({
    prepare: definition.prepare,
    start: definition.start,
    status: definition.status,
    cancel: definition.cancel,
  })) {
    if (!route) continue;
    if (
      !/^\/[A-Za-z0-9._~!$&'()*+,;=:@/-]{1,500}$/.test(route.path) ||
      route.path.includes("//") ||
      route.path.split("/").some((segment) => segment === "." || segment === "..") ||
      new URL(route.path, "https://background-job.invalid").pathname !== route.path
    ) {
      throw new TypeError(`${name} path is invalid`);
    }
    if (
      !Number.isSafeInteger(route.maxRequestBytes) ||
      route.maxRequestBytes < 2 ||
      route.maxRequestBytes > 8 * 1024 * 1024
    ) {
      throw new TypeError(`${name} request limit is invalid`);
    }
    if (paths.has(route.path)) throw new TypeError("background job paths must be distinct");
    paths.add(route.path);
  }
}

export function parseStrictHttpsUrl(value: string, name: string, rootOnly: boolean): URL {
  const raw = typeof value === "string" ? value.match(/^https:\/\/([^/?#]+)(\/[^?#]*)?$/) : null;
  if (
    !raw ||
    value.includes("\\") ||
    /%/i.test(value) ||
    /(?:^|\/)\.{1,2}(?:\/|$)/.test(value.replace(/^https:\/\/[^/]+/, ""))
  ) {
    throw new TypeError(`${name} is invalid`);
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${name} is invalid`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    raw[1] !== parsed.host ||
    (raw[2] ?? "/") !== parsed.pathname ||
    (rootOnly && parsed.pathname !== "/")
  )
    throw new TypeError(`${name} is invalid`);
  return parsed;
}

export function parsePublicHttpsUrl(value: string, name: string, rootOnly: boolean): URL {
  const parsed = parseStrictHttpsUrl(value, name, rootOnly);
  const hostname = parsed.hostname.toLowerCase();
  if (
    isIP(hostname) !== 0 ||
    hostname.endsWith(".") ||
    !hostname.includes(".") ||
    [".example", ".internal", ".invalid", ".local", ".localhost", ".test"].some((suffix) => hostname.endsWith(suffix))
  ) {
    throw new TypeError(`${name} must use a public hostname`);
  }
  return parsed;
}

export function exactPublicRsaJwk(value: unknown, expectedKid?: string): Readonly<JsonWebKey> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError("background job public JWK is invalid");
  }
  const item = value as Record<string, unknown>;
  const keys = Object.keys(item).sort();
  if (
    keys.join(",") !== "alg,e,kid,kty,n,use" ||
    item.kty !== "RSA" ||
    item.alg !== "RS256" ||
    item.use !== "sig" ||
    typeof item.kid !== "string" ||
    !IDENTIFIER.test(item.kid) ||
    (expectedKid !== undefined && item.kid !== expectedKid) ||
    typeof item.n !== "string" ||
    !/^[A-Za-z0-9_-]{342,1366}$/.test(item.n) ||
    typeof item.e !== "string" ||
    !/^[A-Za-z0-9_-]{1,12}$/.test(item.e)
  ) {
    throw new TypeError("background job public JWK is invalid");
  }
  const jwk = { kty: "RSA", alg: "RS256", use: "sig", kid: item.kid, n: item.n, e: item.e };
  let key;
  try {
    key = createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    throw new TypeError("background job public JWK is invalid");
  }
  if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new TypeError("background job public JWK is invalid");
  }
  return Object.freeze(jwk);
}

export function exactPublicRsaJwks(value: unknown): Readonly<{ keys: readonly Readonly<JsonWebKey>[] }> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError("background job JWKS is invalid");
  }
  const item = value as Record<string, unknown>;
  if (
    Object.keys(item).join(",") !== "keys" ||
    !Array.isArray(item.keys) ||
    item.keys.length < 1 ||
    item.keys.length > 2
  ) {
    throw new TypeError("background job JWKS is invalid");
  }
  const keys = item.keys.map((key) => exactPublicRsaJwk(key));
  if (new Set(keys.map((key) => key.kid)).size !== keys.length) throw new TypeError("background job JWKS is invalid");
  return Object.freeze({ keys: Object.freeze(keys) });
}
