import type { BackgroundJobAudienceProfile, BackgroundJobDefinition } from "./types.ts";

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
    if (!/^\/[A-Za-z0-9._~!$&'()*+,;=:@/-]{1,500}$/.test(route.path) || route.path.includes("//")) {
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
    (rootOnly && parsed.pathname !== "/")
  )
    throw new TypeError(`${name} is invalid`);
  return parsed;
}
