import {
  ConnectorError,
  createDeadline,
  createVolatileRequestState,
  isProxyValue,
  requestBinding,
  reserveVolatileRequestQuota,
  snapshotJson,
  validateConnectorLimits,
  verifyResponseBinding,
} from "./types.mjs";

const notionId = "(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})";

const routes = Object.freeze({
  calendar_events: Object.freeze({ host: "www.googleapis.com", path: /^\/calendar\/v3\/calendars\/primary\/events$/ }),
  gmail_messages: Object.freeze({ host: "gmail.googleapis.com", path: /^\/gmail\/v1\/users\/me\/messages$/ }),
  gmail_message: Object.freeze({
    host: "gmail.googleapis.com",
    path: /^\/gmail\/v1\/users\/me\/messages\/[A-Za-z0-9_-]{3,160}$/,
  }),
  clarify_resources: Object.freeze({
    host: "api.clarify.ai",
    path: /^\/v1\/workspaces\/[A-Za-z0-9_-]{3,160}\/objects\/(deal|person|company|meeting|task)\/resources$/,
  }),
  notion_page: Object.freeze({ host: "api.notion.com", path: new RegExp(`^/v1/pages/${notionId}$`) }),
  notion_children: Object.freeze({ host: "api.notion.com", path: new RegExp(`^/v1/blocks/${notionId}/children$`) }),
});

const queryPolicies = Object.freeze({
  calendar_events: (key) => /^(timeMin|timeMax|maxResults|singleEvents|orderBy|pageToken)$/.test(key),
  gmail_messages: (key) => /^(labelIds|maxResults|includeSpamTrash)$/.test(key),
  gmail_message: (key) => key === "format",
  clarify_resources: (key) =>
    /^(page\[limit\]|filter\[[A-Za-z][A-Za-z0-9_.-]{0,63}\]|sortOrder\[(column|dir)\])$/.test(key),
  notion_page: () => false,
  notion_children: (key) => /^(page_size|start_cursor)$/.test(key),
});

const extraHeaders = Object.freeze({
  calendar_events: Object.freeze([]),
  gmail_messages: Object.freeze([]),
  gmail_message: Object.freeze([]),
  clarify_resources: Object.freeze([]),
  notion_page: Object.freeze(["notion-version"]),
  notion_children: Object.freeze(["notion-version"]),
});

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const safeValue = (value) => typeof value === "string" && value.length <= 512 && !/[\u0000-\u001f\u007f]/.test(value);

const normalizeQuery = (routeName, query) => {
  let snapshot;
  try {
    snapshot = snapshotJson(query);
  } catch {
    throw new ConnectorError("invalid_request");
  }
  if (Array.isArray(snapshot)) {
    throw new ConnectorError("invalid_request");
  }
  const entries = Object.entries(snapshot);
  if (entries.length > 16 || !entries.every(([key, value]) => queryPolicies[routeName](key) && safeValue(value))) {
    throw new ConnectorError("invalid_request");
  }
  return Object.freeze(Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right))));
};

const normalizeHeaders = (routeName, supplied) => {
  if (supplied !== undefined && !(supplied instanceof Headers)) {
    throw new ConnectorError("invalid_request");
  }
  const headers = new Headers({ accept: "application/json" });
  for (const [key, value] of supplied ?? []) {
    const normalized = key.toLowerCase();
    if (!extraHeaders[routeName].includes(normalized) || !safeValue(value)) {
      throw new ConnectorError("invalid_request");
    }
    headers.set(normalized, value);
  }
  const identity = Object.fromEntries([...headers.entries()].sort(([left], [right]) => left.localeCompare(right)));
  return Object.freeze({ headers, identity: Object.freeze(identity) });
};

const isDataDescriptor = (descriptor) =>
  descriptor &&
  Object.hasOwn(descriptor, "value") &&
  !Object.hasOwn(descriptor, "get") &&
  !Object.hasOwn(descriptor, "set");

const dataMethod = (value, key) => {
  if (!value || (typeof value !== "object" && typeof value !== "function") || isProxyValue(value)) {
    throw new ConnectorError("connector_adapter_nonconformant");
  }
  let target = value;
  for (;;) {
    if (isProxyValue(target)) {
      throw new ConnectorError("connector_adapter_nonconformant");
    }
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(target, key);
    } catch {
      throw new ConnectorError("connector_adapter_nonconformant");
    }
    if (descriptor) {
      if (!isDataDescriptor(descriptor) || typeof descriptor.value !== "function") {
        throw new ConnectorError("connector_adapter_nonconformant");
      }
      return descriptor.value;
    }
    try {
      target = Object.getPrototypeOf(target);
    } catch {
      throw new ConnectorError("connector_adapter_nonconformant");
    }
    if (target === null) {
      throw new ConnectorError("connector_adapter_nonconformant");
    }
  }
};

const openBody = (body) => {
  const iterate = dataMethod(body, Symbol.asyncIterator);
  let iterator;
  try {
    iterator = iterate.call(body);
  } catch {
    throw new ConnectorError("connector_adapter_nonconformant");
  }
  const close = dataMethod(iterator, "return");
  let cancelled = false;
  const cancel = () => {
    if (cancelled) return;
    cancelled = true;
    try {
      Promise.resolve(close.call(iterator)).catch(() => undefined);
    } catch {
      return;
    }
  };
  try {
    const next = dataMethod(iterator, "next");
    return Object.freeze({ next: () => next.call(iterator), cancel });
  } catch (error) {
    cancel();
    throw error;
  }
};

const cancelBody = (body) => {
  if (body) {
    body.cancel();
  }
};

const iteratorResult = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || isProxyValue(value)) {
    throw new ConnectorError("connector_adapter_nonconformant");
  }
  let descriptors;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length !== 0) {
      throw new ConnectorError("connector_adapter_nonconformant");
    }
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch (error) {
    if (error instanceof ConnectorError) throw error;
    throw new ConnectorError("connector_adapter_nonconformant");
  }
  const done = descriptors.done;
  if (!isDataDescriptor(done) || !done.enumerable || typeof done.value !== "boolean") {
    throw new ConnectorError("connector_adapter_nonconformant");
  }
  const valueDescriptor = descriptors.value;
  const keys = Object.keys(descriptors).sort();
  if (
    keys.length !== (valueDescriptor === undefined ? 1 : 2) ||
    keys[0] !== "done" ||
    (valueDescriptor !== undefined && keys[1] !== "value") ||
    (valueDescriptor !== undefined && (!isDataDescriptor(valueDescriptor) || !valueDescriptor.enumerable)) ||
    (!done.value && valueDescriptor === undefined)
  ) {
    throw new ConnectorError("connector_adapter_nonconformant");
  }
  return Object.freeze({
    done: done.value,
    ...(valueDescriptor === undefined ? {} : { value: valueDescriptor.value }),
  });
};

const readBody = async (body, maxResponseBytes, deadline) => {
  const chunks = [];
  let size = 0;
  let complete = false;
  try {
    for (;;) {
      const item = iteratorResult(await deadline.race(() => body.next()));
      if (item.done) {
        break;
      }
      const chunk = item.value;
      if (!(chunk instanceof Uint8Array)) {
        throw new ConnectorError("connector_adapter_nonconformant");
      }
      size += chunk.byteLength;
      if (size > maxResponseBytes) {
        throw new ConnectorError("response_too_large");
      }
      chunks.push(chunk);
    }
    const result = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.byteLength;
    }
    complete = true;
    return Object.freeze({ bytes: result });
  } finally {
    if (!complete) {
      cancelBody(body);
    }
  }
};

const responseDescriptors = (response) => {
  if (!response || typeof response !== "object" || Array.isArray(response) || isProxyValue(response)) {
    throw new ConnectorError("connector_adapter_nonconformant");
  }
  try {
    if (Object.getPrototypeOf(response) !== Object.prototype || Object.getOwnPropertySymbols(response).length !== 0) {
      throw new ConnectorError("connector_adapter_nonconformant");
    }
    return Object.getOwnPropertyDescriptors(response);
  } catch (error) {
    if (error instanceof ConnectorError) throw error;
    throw new ConnectorError("connector_adapter_nonconformant");
  }
};

const parseResponse = async (response, connection, maxResponseBytes, deadline) => {
  let body;
  try {
    const descriptors = responseDescriptors(response);
    const bodyDescriptor = descriptors.body;
    if (isDataDescriptor(bodyDescriptor) && bodyDescriptor.enumerable) {
      body = openBody(bodyDescriptor.value);
    }
    const keys = Object.keys(descriptors).sort();
    const expectedKeys = ["binding", "body", "headers", "redirected", "status"];
    if (
      keys.length !== expectedKeys.length ||
      keys.some((key, index) => key !== expectedKeys[index]) ||
      expectedKeys.some((key) => !isDataDescriptor(descriptors[key]) || !descriptors[key].enumerable)
    ) {
      throw new ConnectorError("connector_adapter_nonconformant");
    }
    const status = descriptors.status.value;
    const headers = descriptors.headers.value;
    const redirected = descriptors.redirected.value;
    const binding = descriptors.binding.value;
    if (!body || !Number.isInteger(status) || !(headers instanceof Headers) || typeof redirected !== "boolean") {
      throw new ConnectorError("connector_adapter_nonconformant");
    }
    verifyResponseBinding(connection, binding);
    if (redirected || (status >= 300 && status < 400)) {
      throw new ConnectorError("redirect_rejected");
    }
    if (status !== 200) {
      throw new ConnectorError("connector_transport_failed");
    }
    const contentLength = headers.get("content-length");
    if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > maxResponseBytes)) {
      throw new ConnectorError("response_too_large");
    }
    const payload = await readBody(body, maxResponseBytes, deadline);
    let parsed;
    try {
      parsed = JSON.parse(decoder.decode(payload.bytes));
    } catch {
      throw new ConnectorError("invalid_response");
    }
    try {
      return snapshotJson(parsed);
    } catch {
      throw new ConnectorError("invalid_response");
    }
  } catch (error) {
    cancelBody(body);
    throw error;
  }
};

export class ReadOnlyHttpGateway {
  constructor(transport, limits) {
    if (!transport || typeof transport.execute !== "function") {
      throw new ConnectorError("invalid_request");
    }
    this.transport = transport;
    this.limits = validateConnectorLimits(limits);
    this.state = createVolatileRequestState();
    Object.freeze(this);
  }

  async get(connection, routeName, pathname, query = {}, options = {}) {
    const route = routes[routeName];
    if (!route || !route.path.test(pathname) || pathname.includes("..") || pathname.includes("\\")) {
      throw new ConnectorError("route_not_allowed");
    }
    const normalizedQuery = normalizeQuery(routeName, query);
    const normalizedHeaders = normalizeHeaders(routeName, options.headers);
    const maxResponseBytes = options.maxResponseBytes ?? this.limits.maxResponseBytes;
    if (
      !Number.isInteger(maxResponseBytes) ||
      maxResponseBytes < 1_024 ||
      maxResponseBytes > this.limits.maxResponseBytes
    ) {
      throw new ConnectorError("invalid_request");
    }
    const url = new URL(`https://${route.host}${pathname}`);
    for (const [key, value] of Object.entries(normalizedQuery)) {
      url.searchParams.set(key, value);
    }
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.host !== route.host ||
      !route.path.test(url.pathname)
    ) {
      throw new ConnectorError("route_not_allowed");
    }
    reserveVolatileRequestQuota(this.state, this.limits);
    const binding = requestBinding(connection);
    const deadline = createDeadline(this.state, this.limits);
    try {
      const response = await deadline.race(() =>
        this.transport.execute(
          Object.freeze({
            method: "GET",
            url,
            headers: normalizedHeaders.headers,
            redirect: "manual",
            signal: deadline.signal,
            maxResponseBytes,
            credentialLeaseRef: connection.credentialLeaseRef,
            ...binding,
          }),
        ),
      );
      const content = await parseResponse(response, connection, maxResponseBytes, deadline);
      return Object.freeze({
        content,
        request: Object.freeze({
          route: routeName,
          path: url.pathname,
          query: normalizedQuery,
          headers: normalizedHeaders.identity,
        }),
      });
    } finally {
      deadline.finish();
    }
  }
}
