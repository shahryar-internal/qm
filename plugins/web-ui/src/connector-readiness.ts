export interface ConnectorProviderStatus {
  connected?: boolean;
  needsReconnect?: boolean;
  available?: boolean;
  hosts?: Array<{ host: string } | string>;
}

export type ConnectorReadiness =
  | { kind: "idle" | "loading" }
  | { kind: "ready"; providers: Record<string, ConnectorProviderStatus> }
  | { kind: "error" };

export type ConnectorUiState = "connected" | "blocked" | "disconnected" | "disabled";

export interface ConnectorReadinessSummary {
  connected: number;
  blocked: number;
  disconnected: number;
  disabled: number;
  total: number;
}

function isOptionalBoolean(value: unknown): boolean {
  return value === undefined || typeof value === "boolean";
}

function assertBoundedValue(value: unknown, depth: number, budget: { nodes: number; stringUnits: number }): void {
  budget.nodes++;
  if (depth > 5 || budget.nodes > 1_024) throw new Error("invalid connector readiness");
  if (typeof value === "string") {
    budget.stringUnits += value.length;
    if (budget.stringUnits > 16_384) throw new Error("invalid connector readiness");
    return;
  }
  if (value === null || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) return;
  if (Array.isArray(value)) {
    if (value.length > 64) throw new Error("invalid connector readiness");
    for (const entry of value) assertBoundedValue(entry, depth + 1, budget);
    return;
  }
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error("invalid connector readiness");
  const entries = Object.entries(value);
  if (entries.length > 64) throw new Error("invalid connector readiness");
  for (const [key, entry] of entries) {
    budget.stringUnits += key.length;
    if (budget.stringUnits > 16_384) throw new Error("invalid connector readiness");
    assertBoundedValue(entry, depth + 1, budget);
  }
}

function parseHosts(value: unknown): Array<{ host: string } | string> | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 64) throw new Error("invalid connector readiness");
  const hosts: Array<{ host: string } | string> = [];
  for (const entry of value) {
    let host: unknown;
    if (typeof entry === "string") host = entry;
    else if (entry && typeof entry === "object" && !Array.isArray(entry)) host = (entry as { host?: unknown }).host;
    if (typeof host !== "string" || !host.length || host.length > 253 || /\s/.test(host))
      throw new Error("invalid connector readiness");
    hosts.push(typeof entry === "string" ? host : { host });
  }
  return hosts;
}

export function parseConnectorProviders(value: unknown): Record<string, ConnectorProviderStatus> {
  assertBoundedValue(value, 0, { nodes: 0, stringUnits: 0 });
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid connector readiness");
  const entries = Object.entries(value);
  if (entries.length > 32) throw new Error("invalid connector readiness");
  const providers: Record<string, ConnectorProviderStatus> = {};
  for (const [id, candidate] of entries) {
    if (!/^[a-z][a-z0-9-]{0,40}$/.test(id) || !candidate || typeof candidate !== "object" || Array.isArray(candidate))
      throw new Error("invalid connector readiness");
    const provider = candidate as Record<string, unknown>;
    if (
      typeof provider.connected !== "boolean" ||
      typeof provider.available !== "boolean" ||
      !isOptionalBoolean(provider.needsReconnect)
    )
      throw new Error("invalid connector readiness");
    providers[id] = {
      connected: provider.connected as boolean | undefined,
      needsReconnect: provider.needsReconnect as boolean | undefined,
      available: provider.available as boolean | undefined,
      hosts: parseHosts(provider.hosts),
    };
  }
  return providers;
}

export class ConnectorReadinessController {
  state: ConnectorReadiness = { kind: "idle" };
  private epoch = 0;
  private request: Promise<void> | null = null;

  reset(): void {
    this.epoch++;
    this.state = { kind: "idle" };
    this.request = null;
  }

  refresh(load: () => Promise<unknown>, onChange: () => void = () => undefined): Promise<void> {
    if (this.request) return this.request;
    const epoch = this.epoch;
    this.state = { kind: "loading" };
    onChange();
    const request = load()
      .then((response) => {
        if (epoch !== this.epoch) return;
        if (
          !response ||
          typeof response !== "object" ||
          Array.isArray(response) ||
          Object.getPrototypeOf(response) !== Object.prototype
        )
          throw new Error("invalid connector readiness");
        const providers = parseConnectorProviders((response as { providers?: unknown }).providers);
        this.state = { kind: "ready", providers };
      })
      .catch(() => {
        if (epoch === this.epoch) this.state = { kind: "error" };
      })
      .finally(() => {
        if (this.request === request) this.request = null;
        if (epoch === this.epoch) onChange();
      });
    this.request = request;
    return request;
  }
}

export function connectorUiState(provider: ConnectorProviderStatus): ConnectorUiState {
  if (provider.needsReconnect === true) return "blocked";
  if (provider.connected === true) return "connected";
  if (provider.available === true) return "disconnected";
  return "disabled";
}

export function connectorReadinessSummary(
  providers: Readonly<Record<string, ConnectorProviderStatus>>,
): ConnectorReadinessSummary {
  const summary: ConnectorReadinessSummary = {
    connected: 0,
    blocked: 0,
    disconnected: 0,
    disabled: 0,
    total: 0,
  };
  for (const provider of Object.values(providers)) {
    summary[connectorUiState(provider)]++;
    summary.total++;
  }
  return summary;
}
