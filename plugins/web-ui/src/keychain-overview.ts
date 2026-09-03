export interface KeychainCredential {
  id: string;
  service: string;
  kind?: string;
  envKey?: string;
  accountLabel?: string;
  host?: string;
  fingerprint?: string;
  expiresAt?: number;
  createdAt?: number;
}

export interface KeychainConnectorCredential {
  credentialId: string;
  host: string;
  accountType?: string;
  expiresAt?: number;
  connected: boolean;
  needsReconnect?: boolean;
}

export interface KeychainGrant {
  id: string;
  credentialId: string;
  audienceScopeId: string;
  mode: "once" | "standing";
  purpose: string;
  status: "active" | "revoked" | "used";
  expiresAt?: number;
}

export interface KeychainAsk {
  id: string;
  credentialId: string;
  requesterId: string;
  requesterScopeId: string;
  purpose: string;
  requestedMode?: "once" | "standing";
  expiresAt: number;
}

export interface KeychainUsage {
  credentialId: string;
  ts: number;
  scopeLabel: string;
  status: string;
}

export interface KeychainOverview {
  credentials: KeychainCredential[];
  connectorCredentials: KeychainConnectorCredential[];
  grants: KeychainGrant[];
  asks: KeychainAsk[];
  usage: KeychainUsage[];
  scopeNames: Record<string, string>;
}

function assertBoundedValue(value: unknown, depth: number, budget: { nodes: number; stringUnits: number }): void {
  budget.nodes++;
  if (depth > 5 || budget.nodes > 10_000) throw new Error("invalid keychain overview");
  if (typeof value === "string") {
    budget.stringUnits += value.length;
    if (budget.stringUnits > 262_144) throw new Error("invalid keychain overview");
    return;
  }
  if (value === null || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) return;
  if (Array.isArray(value)) {
    if (value.length > 500) throw new Error("invalid keychain overview");
    for (const entry of value) assertBoundedValue(entry, depth + 1, budget);
    return;
  }
  const row = record(value);
  const entries = Object.entries(row);
  if (entries.length > 1_000) throw new Error("invalid keychain overview");
  for (const [key, entry] of entries) {
    budget.stringUnits += key.length;
    if (budget.stringUnits > 262_144) throw new Error("invalid keychain overview");
    assertBoundedValue(entry, depth + 1, budget);
  }
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error("invalid keychain overview");
  return value as Record<string, unknown>;
}

function string(value: unknown, max = 512): string {
  if (typeof value !== "string" || !value.length || value.length > max) throw new Error("invalid keychain overview");
  return value;
}

function optionalString(value: unknown, max = 512): string | undefined {
  return value === undefined ? undefined : string(value, max);
}

function timestamp(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > 8_640_000_000_000_000)
    throw new Error("invalid keychain overview");
  return value;
}

function optionalNumber(value: unknown): number | undefined {
  return value === undefined ? undefined : timestamp(value);
}

function array(value: unknown, max = 500): unknown[] {
  if (!Array.isArray(value) || value.length > max) throw new Error("invalid keychain overview");
  return value;
}

function credential(value: unknown): KeychainCredential {
  const row = record(value);
  return {
    id: string(row.id),
    service: string(row.service, 200),
    envKey: optionalString(row.envKey, 200),
    accountLabel: optionalString(row.accountLabel),
    host: optionalString(row.host, 253),
    fingerprint: optionalString(row.fingerprint),
    kind: optionalString(row.kind, 100),
    expiresAt: optionalNumber(row.expiresAt),
    createdAt: optionalNumber(row.createdAt),
  };
}

function connectorCredential(value: unknown): KeychainConnectorCredential {
  const row = record(value);
  if (
    typeof row.connected !== "boolean" ||
    (row.needsReconnect !== undefined && typeof row.needsReconnect !== "boolean")
  )
    throw new Error("invalid keychain overview");
  return {
    credentialId: string(row.credentialId),
    host: string(row.host, 253),
    connected: row.connected,
    needsReconnect: row.needsReconnect as boolean | undefined,
    accountType: optionalString(row.accountType, 100),
    expiresAt: optionalNumber(row.expiresAt),
  };
}

function grant(value: unknown): KeychainGrant {
  const row = record(value);
  if ((row.mode !== "once" && row.mode !== "standing") || !["active", "revoked", "used"].includes(String(row.status)))
    throw new Error("invalid keychain overview");
  return {
    id: string(row.id),
    credentialId: string(row.credentialId),
    audienceScopeId: string(row.audienceScopeId),
    mode: row.mode,
    purpose: string(row.purpose, 8_192),
    status: row.status as KeychainGrant["status"],
    expiresAt: optionalNumber(row.expiresAt),
  };
}

function ask(value: unknown): KeychainAsk {
  const row = record(value);
  if (row.requestedMode !== undefined && row.requestedMode !== "once" && row.requestedMode !== "standing")
    throw new Error("invalid keychain overview");
  return {
    id: string(row.id),
    credentialId: string(row.credentialId),
    requesterId: string(row.requesterId),
    requesterScopeId: string(row.requesterScopeId),
    purpose: string(row.purpose, 8_192),
    requestedMode: row.requestedMode as KeychainAsk["requestedMode"],
    expiresAt: timestamp(row.expiresAt),
  };
}

function usage(value: unknown): KeychainUsage {
  const row = record(value);
  return {
    credentialId: string(row.credentialId),
    ts: timestamp(row.ts),
    scopeLabel: string(row.scopeLabel),
    status: string(row.status, 200),
  };
}

export function parseKeychainOverview(value: unknown): KeychainOverview {
  assertBoundedValue(value, 0, { nodes: 0, stringUnits: 0 });
  const overview = record(value);
  const scopeEntries = Object.entries(record(overview.scopeNames));
  if (scopeEntries.length > 1_000) throw new Error("invalid keychain overview");
  const scopeNames: Record<string, string> = {};
  for (const [id, name] of scopeEntries) scopeNames[string(id)] = string(name, 512);
  return {
    credentials: array(overview.credentials).map(credential),
    connectorCredentials: array(overview.connectorCredentials).map(connectorCredential),
    grants: array(overview.grants).map(grant),
    asks: array(overview.asks).map(ask),
    usage: array(overview.usage, 50).map(usage),
    scopeNames,
  };
}
