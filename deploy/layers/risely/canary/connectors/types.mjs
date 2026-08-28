import { types as utilTypes } from "node:util";

export const connectorProviders = Object.freeze(["calendar", "gmail", "clarify", "notion", "command_center_brain"]);

const serverReferencePattern = /^srv_[A-Za-z0-9_-]{8,160}$/;
const connectionReferencePattern = /^conn_[A-Za-z0-9_-]{8,160}$/;
const principalReferencePattern = /^usr_[A-Za-z0-9_-]{8,160}$/;
const resourceReferencePattern = /^[A-Za-z0-9_-]{3,160}$/;
const credentialLeasePattern = /^lease_[A-Za-z0-9_-]{8,160}$/;
const bindingNoncePattern = /^bind_[A-Za-z0-9_-]{16,160}$/;
const resolvedConnectionKeys = Object.freeze([
  "active",
  "bindingNonce",
  "connectionRef",
  "credentialLeaseRef",
  "principalRef",
  "provider",
  "rootResourceRef",
  "serverAccountRef",
]);

export class ConnectorError extends Error {
  constructor(code) {
    super(code);
    this.name = "ConnectorError";
    this.code = code;
  }
}

export const defaultConnectorLimits = Object.freeze({
  timeoutMs: 5_000,
  maxResponseBytes: 262_144,
  maxVolatileRequests: 24,
  volatileRequestWindowMs: 60_000,
});

export const validateConnectorLimits = (limits) => {
  if (!limits || !Number.isInteger(limits.timeoutMs) || limits.timeoutMs < 100 || limits.timeoutMs > 30_000) {
    throw new ConnectorError("invalid_request");
  }
  if (
    !Number.isInteger(limits.maxResponseBytes) ||
    limits.maxResponseBytes < 1_024 ||
    limits.maxResponseBytes > 1_048_576
  ) {
    throw new ConnectorError("invalid_request");
  }
  if (
    !Number.isInteger(limits.maxVolatileRequests) ||
    limits.maxVolatileRequests < 1 ||
    limits.maxVolatileRequests > 100
  ) {
    throw new ConnectorError("invalid_request");
  }
  if (
    !Number.isInteger(limits.volatileRequestWindowMs) ||
    limits.volatileRequestWindowMs < 1_000 ||
    limits.volatileRequestWindowMs > 3_600_000
  ) {
    throw new ConnectorError("invalid_request");
  }
  return Object.freeze({
    timeoutMs: limits.timeoutMs,
    maxResponseBytes: limits.maxResponseBytes,
    maxVolatileRequests: limits.maxVolatileRequests,
    volatileRequestWindowMs: limits.volatileRequestWindowMs,
  });
};

const isDataDescriptor = (descriptor) =>
  descriptor &&
  Object.hasOwn(descriptor, "value") &&
  !Object.hasOwn(descriptor, "get") &&
  !Object.hasOwn(descriptor, "set");

export const isProxyValue = (value) => {
  try {
    return utilTypes.isProxy(value);
  } catch {
    return true;
  }
};

const cloneJson = (value, depth) => {
  if (depth > 32) {
    throw new ConnectorError("invalid_response");
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new ConnectorError("invalid_response");
    }
    return value;
  }
  if (typeof value !== "object" || isProxyValue(value)) {
    throw new ConnectorError("invalid_response");
  }
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length !== 0) {
        throw new ConnectorError("invalid_response");
      }
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const length = descriptors.length;
      if (
        !isDataDescriptor(length) ||
        !Number.isSafeInteger(length.value) ||
        length.value < 0 ||
        length.value > 2_000
      ) {
        throw new ConnectorError("invalid_response");
      }
      const entries = Object.entries(descriptors).filter(([key]) => key !== "length");
      if (
        entries.length !== length.value ||
        entries.some(
          ([key, descriptor], index) =>
            key !== String(index) || !isDataDescriptor(descriptor) || !descriptor.enumerable,
        )
      ) {
        throw new ConnectorError("invalid_response");
      }
      return Object.freeze(entries.map(([, descriptor]) => cloneJson(descriptor.value, depth + 1)));
    }
    if (
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Reflect.ownKeys(value).some((key) => typeof key === "symbol")
    ) {
      throw new ConnectorError("invalid_response");
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const entries = Object.entries(descriptors);
    if (
      entries.length > 2_000 ||
      entries.some(([key, descriptor]) => key.length > 256 || !isDataDescriptor(descriptor) || !descriptor.enumerable)
    ) {
      throw new ConnectorError("invalid_response");
    }
    const result = Object.create(null);
    for (const [key, descriptor] of entries) {
      result[key] = cloneJson(descriptor.value, depth + 1);
    }
    return Object.freeze(result);
  } catch (error) {
    if (error instanceof ConnectorError) {
      throw error;
    }
    throw new ConnectorError("invalid_response");
  }
};

export const snapshotJson = (value) => cloneJson(value, 0);

export const isJsonValue = (value) => {
  try {
    snapshotJson(value);
    return true;
  } catch {
    return false;
  }
};

export const canonicalJson = (value) => {
  const snapshot = snapshotJson(value);
  const stringify = (entry) => {
    if (entry === null || typeof entry === "string" || typeof entry === "boolean" || typeof entry === "number") {
      return JSON.stringify(entry);
    }
    if (Array.isArray(entry)) {
      return `[${entry.map(stringify).join(",")}]`;
    }
    return `{${Object.keys(entry)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stringify(entry[key])}`)
      .join(",")}}`;
  };
  return stringify(snapshot);
};

export const encodedJsonBytes = (value) => new TextEncoder().encode(canonicalJson(value)).byteLength;

const resolvedConnections = new WeakSet();

export const createResolvedConnection = (record) => {
  let snapshot;
  try {
    snapshot = snapshotJson(record);
  } catch {
    throw new ConnectorError("untrusted_connection_resolution");
  }
  const keys = snapshot && !Array.isArray(snapshot) && typeof snapshot === "object" ? Object.keys(snapshot).sort() : [];
  if (
    keys.length !== resolvedConnectionKeys.length ||
    keys.some((key, index) => key !== resolvedConnectionKeys[index]) ||
    snapshot.active !== true ||
    !connectorProviders.includes(snapshot.provider) ||
    !serverReferencePattern.test(snapshot.serverAccountRef) ||
    !connectionReferencePattern.test(snapshot.connectionRef) ||
    !principalReferencePattern.test(snapshot.principalRef) ||
    !resourceReferencePattern.test(snapshot.rootResourceRef) ||
    !credentialLeasePattern.test(snapshot.credentialLeaseRef) ||
    !bindingNoncePattern.test(snapshot.bindingNonce) ||
    (snapshot.provider === "calendar" && snapshot.rootResourceRef !== "primary") ||
    (snapshot.provider === "gmail" && snapshot.rootResourceRef !== "inbox")
  ) {
    throw new ConnectorError("untrusted_connection_resolution");
  }
  const connection = Object.freeze({
    provider: snapshot.provider,
    serverAccountRef: snapshot.serverAccountRef,
    connectionRef: snapshot.connectionRef,
    principalRef: snapshot.principalRef,
    rootResourceRef: snapshot.rootResourceRef,
    credentialLeaseRef: snapshot.credentialLeaseRef,
    bindingNonce: snapshot.bindingNonce,
  });
  resolvedConnections.add(connection);
  return connection;
};

export const assertResolvedConnection = (connection, provider) => {
  if (!resolvedConnections.has(connection) || connection.provider !== provider) {
    throw new ConnectorError("untrusted_connection_resolution");
  }
  return connection;
};

export const requestBinding = (connection) =>
  Object.freeze({
    provider: connection.provider,
    connectionRef: connection.connectionRef,
    serverAccountRef: connection.serverAccountRef,
    principalRef: connection.principalRef,
    rootResourceRef: connection.rootResourceRef,
    credentialLeaseRef: connection.credentialLeaseRef,
    bindingNonce: connection.bindingNonce,
  });

export const verifyResponseBinding = (connection, binding) => {
  let snapshot;
  try {
    snapshot = snapshotJson(binding);
  } catch {
    throw new ConnectorError("connector_binding_mismatch");
  }
  const expected = requestBinding(connection);
  const actualKeys = Object.keys(snapshot).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index]) ||
    expectedKeys.some((key) => snapshot[key] !== expected[key])
  ) {
    throw new ConnectorError("connector_binding_mismatch");
  }
  return snapshot;
};

export const createVolatileRequestState = () => ({ windowStartedAt: Date.now(), requestCount: 0, quarantined: false });

export const reserveVolatileRequestQuota = (state, limits) => {
  if (state.quarantined) {
    throw new ConnectorError("connector_quarantined");
  }
  const now = Date.now();
  if (now - state.windowStartedAt >= limits.volatileRequestWindowMs) {
    state.windowStartedAt = now;
    state.requestCount = 0;
  }
  if (state.requestCount >= limits.maxVolatileRequests) {
    throw new ConnectorError("connector_volatile_qos_limited");
  }
  state.requestCount += 1;
};

export const createDeadline = (state, limits) => {
  const controller = new AbortController();
  let expired = false;
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      expired = true;
      state.quarantined = true;
      controller.abort();
      reject(new ConnectorError("connector_timeout"));
    }, limits.timeoutMs);
  });
  const race = async (operation) => {
    const execution = Promise.resolve().then(operation);
    execution.then(
      () => undefined,
      () => undefined,
    );
    try {
      return await Promise.race([execution, timeout]);
    } catch (error) {
      if (error instanceof ConnectorError) {
        throw error;
      }
      throw new ConnectorError("connector_transport_failed");
    }
  };
  return Object.freeze({
    signal: controller.signal,
    race,
    finish: () => {
      if (!expired) {
        clearTimeout(timer);
      }
    },
  });
};
