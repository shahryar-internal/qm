import assert from "node:assert/strict";
import test from "node:test";
import { normalizeEvidence } from "../../canary/connectors/evidence.mjs";
import {
  connectorFoundationState,
  ConnectorError,
  createConnectorService,
  notionVersion,
} from "../../canary/connectors/index.mjs";
import { FakeHttpTransport, FakeMcpTransport, FixtureResolver, fixtureRecord, openFixtureClient } from "./fixtures.mjs";

const encoder = new TextEncoder();
const limits = Object.freeze({
  timeoutMs: 100,
  maxResponseBytes: 262_144,
  maxVolatileRequests: 24,
  volatileRequestWindowMs: 60_000,
});
const smallLimits = Object.freeze({
  timeoutMs: 100,
  maxResponseBytes: 4_096,
  maxVolatileRequests: 24,
  volatileRequestWindowMs: 60_000,
});

const chunks = async function* (bytes, chunkSize = bytes.byteLength) {
  for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
    yield bytes.slice(offset, Math.min(offset + chunkSize, bytes.byteLength));
  }
};

const binding = (request, override = {}) => ({
  provider: request.provider,
  connectionRef: request.connectionRef,
  serverAccountRef: request.serverAccountRef,
  principalRef: request.principalRef,
  rootResourceRef: request.rootResourceRef,
  credentialLeaseRef: request.credentialLeaseRef,
  bindingNonce: request.bindingNonce,
  ...override,
});

const response = (request, value, options = {}) => ({
  status: options.status ?? 200,
  headers: new Headers(options.headers),
  body: options.body ?? chunks(options.bytes ?? encoder.encode(JSON.stringify(value)), options.chunkSize),
  redirected: options.redirected ?? false,
  binding: options.binding ?? binding(request),
});

const open = (provider, rootResourceRef, transport, suppliedLimits = limits, overrides = {}) => ({
  client: openFixtureClient(provider, rootResourceRef, transport, suppliedLimits, overrides),
});

test("public connector foundation is inert and exposes only resolver-backed opaque inspection", async () => {
  const resolver = new FixtureResolver(() => fixtureRecord("calendar", "primary"));
  const service = createConnectorService(resolver, limits);
  const inspection = await service.inspect("conn_12345678", "usr_12345678");
  assert.deepEqual(resolver.calls, [{ connectionRef: "conn_12345678", actorRef: "usr_12345678" }]);
  assert.deepEqual(inspection, {
    provider: "calendar",
    connectionRef: "conn_12345678",
    actorRef: "usr_12345678",
    state: "inert",
  });
  assert.equal(connectorFoundationState, "inert");
  await assert.rejects(
    service.open("conn_12345678", "usr_12345678"),
    (error) => error instanceof ConnectorError && error.code === "connector_live_adapter_unavailable",
  );
});

test("revoked and wrong-actor resolver outcomes fail before provider traffic", async () => {
  const transport = new FakeHttpTransport(async (request) => response(request, { items: [] }));
  for (const overrides of [{ active: false }, { principalRef: "usr_abcdefgh" }]) {
    const resolver = new FixtureResolver(() => fixtureRecord("calendar", "primary", overrides));
    const service = createConnectorService(resolver, limits);
    await assert.rejects(
      service.open("conn_12345678", "usr_12345678"),
      (error) =>
        error instanceof ConnectorError &&
        (error.code === "connection_not_active" || error.code === "untrusted_connection_resolution"),
    );
  }
  assert.equal(transport.requests.length, 0);
});

test("resolver records are descriptor-safe snapshots rather than accessor-backed mutable authority", async () => {
  let reads = 0;
  const record = fixtureRecord("calendar", "primary");
  Object.defineProperty(record, "connectionRef", {
    enumerable: true,
    get() {
      reads += 1;
      return "conn_12345678";
    },
  });
  const service = createConnectorService(new FixtureResolver(() => record), limits);
  await assert.rejects(
    service.inspect("conn_12345678", "usr_12345678"),
    (error) => error instanceof ConnectorError && error.code === "connection_not_active",
  );
  assert.equal(reads, 0);
});

test("binding receipt and two-account mismatches fail closed and opaque leases never carry secret values", async () => {
  for (const mismatch of [
    { bindingNonce: "bind_abcdefgh12345678" },
    { serverAccountRef: "srv_abcdefgh" },
    { credentialLeaseRef: "lease_abcdefgh" },
  ]) {
    const transport = new FakeHttpTransport(async (request) =>
      response(request, { items: [] }, { binding: binding(request, mismatch) }),
    );
    const { client } = await open("calendar", "primary", transport);
    await assert.rejects(
      client.upcoming({
        from: new Date("2026-08-26T00:00:00.000Z"),
        to: new Date("2026-08-27T00:00:00.000Z"),
        maxResults: 1,
      }),
      (error) => error instanceof ConnectorError && error.code === "connector_binding_mismatch",
    );
    assert.equal(JSON.stringify(transport.requests[0]).includes("secret"), false);
  }
  const transport = new FakeHttpTransport(async (request) => response(request, { items: [] }));
  const { client } = await open("calendar", "primary", transport);
  const evidence = await client.upcoming({
    from: new Date("2026-08-26T00:00:00.000Z"),
    to: new Date("2026-08-27T00:00:00.000Z"),
    maxResults: 1,
  });
  assert.equal(evidence.credentialLeaseRef, transport.requests[0].credentialLeaseRef);
  assert.throws(
    () => normalizeEvidence("calendar", fixtureRecord("calendar", "primary"), "calendar.upcoming", {}, {}),
    (error) => error instanceof ConnectorError && error.code === "untrusted_connection_resolution",
  );
});

test("manual redirects, missing content length, and chunked overflow fail safely without capability self-attestation", async () => {
  const autoFollow = new FakeHttpTransport(async (request) => response(request, { items: [] }, { redirected: true }));
  const { client: autoFollowClient } = await open("calendar", "primary", autoFollow, smallLimits);
  await assert.rejects(
    autoFollowClient.upcoming({
      from: new Date("2026-08-26T00:00:00.000Z"),
      to: new Date("2026-08-27T00:00:00.000Z"),
      maxResults: 1,
    }),
    (error) => error instanceof ConnectorError && error.code === "redirect_rejected",
  );
  const redirect = new FakeHttpTransport(async (request) => response(request, {}, { status: 302 }));
  const { client: redirectClient } = await open("calendar", "primary", redirect, smallLimits);
  await assert.rejects(
    redirectClient.upcoming({
      from: new Date("2026-08-26T00:00:00.000Z"),
      to: new Date("2026-08-27T00:00:00.000Z"),
      maxResults: 1,
    }),
    (error) => error instanceof ConnectorError && error.code === "redirect_rejected",
  );
  const chunked = new FakeHttpTransport(async (request) =>
    response(request, {}, { bytes: new Uint8Array(4_097), chunkSize: 512 }),
  );
  const { client: chunkedClient } = await open("calendar", "primary", chunked, smallLimits);
  await assert.rejects(
    chunkedClient.upcoming({
      from: new Date("2026-08-26T00:00:00.000Z"),
      to: new Date("2026-08-27T00:00:00.000Z"),
      maxResults: 1,
    }),
    (error) => error instanceof ConnectorError && error.code === "response_too_large",
  );
});

test("redirects, failed statuses, and bad content lengths cancel response iterators before rejection", async () => {
  for (const options of [{ redirected: true }, { status: 500 }, { headers: { "content-length": "not-a-number" } }]) {
    let cancelled = false;
    const body = {
      [Symbol.asyncIterator]() {
        return this;
      },
      next() {
        return Promise.resolve({ done: false, value: encoder.encode("{}") });
      },
      return() {
        cancelled = true;
        return Promise.resolve({ done: true });
      },
    };
    const transport = new FakeHttpTransport(async (request) => response(request, {}, { ...options, body }));
    const { client } = await open("calendar", "primary", transport, smallLimits);
    await assert.rejects(
      client.upcoming({
        from: new Date("2026-08-26T00:00:00.000Z"),
        to: new Date("2026-08-27T00:00:00.000Z"),
        maxResults: 1,
      }),
      (error) => error instanceof ConnectorError,
    );
    assert.equal(cancelled, true);
  }
});

test("missing or accessor-backed response bindings close a descriptor-snapshotted body exactly once", async () => {
  const invalidResponse = [
    (record) => {
      delete record.binding;
      return record;
    },
    (record) => {
      Object.defineProperty(record, "binding", {
        enumerable: true,
        get() {
          throw new Error("binding accessor was read");
        },
      });
      return record;
    },
  ];
  for (const invalidate of invalidResponse) {
    let iteratorCalls = 0;
    let returnCalls = 0;
    const iterator = {
      next() {
        return Promise.resolve({ done: false, value: encoder.encode("{}") });
      },
      return() {
        returnCalls += 1;
        return Promise.resolve({ done: true });
      },
    };
    const body = {
      [Symbol.asyncIterator]() {
        iteratorCalls += 1;
        return iterator;
      },
    };
    const transport = new FakeHttpTransport(async (request) => invalidate(response(request, {}, { body })));
    const { client } = await open("calendar", "primary", transport, smallLimits);
    await assert.rejects(
      client.upcoming({
        from: new Date("2026-08-26T00:00:00.000Z"),
        to: new Date("2026-08-27T00:00:00.000Z"),
        maxResults: 1,
      }),
      (error) => error instanceof ConnectorError && error.code === "connector_adapter_nonconformant",
    );
    assert.equal(iteratorCalls, 1);
    assert.equal(returnCalls, 1);
  }
});

test("HTTP body accessors are rejected without invoking ambiguous iterator access", async () => {
  let iteratorReads = 0;
  const body = {};
  Object.defineProperty(body, Symbol.asyncIterator, {
    get() {
      iteratorReads += 1;
      return () => undefined;
    },
  });
  const transport = new FakeHttpTransport(async (request) => response(request, {}, { status: 500, body }));
  const { client } = await open("calendar", "primary", transport, smallLimits);
  await assert.rejects(
    client.upcoming({
      from: new Date("2026-08-26T00:00:00.000Z"),
      to: new Date("2026-08-27T00:00:00.000Z"),
      maxResults: 1,
    }),
    (error) => error instanceof ConnectorError && error.code === "connector_adapter_nonconformant",
  );
  assert.equal(iteratorReads, 0);
});

test("iterator construction closes the snapshotted iterator when next is not a data method", async () => {
  let nextReads = 0;
  let returnCalls = 0;
  const iterator = {
    return() {
      returnCalls += 1;
      return Promise.resolve({ done: true });
    },
  };
  Object.defineProperty(iterator, "next", {
    get() {
      nextReads += 1;
      return () => Promise.resolve({ done: true });
    },
  });
  const body = {
    [Symbol.asyncIterator]() {
      return iterator;
    },
  };
  const transport = new FakeHttpTransport(async (request) => response(request, {}, { body }));
  const { client } = await open("calendar", "primary", transport, smallLimits);
  await assert.rejects(
    client.upcoming({
      from: new Date("2026-08-26T00:00:00.000Z"),
      to: new Date("2026-08-27T00:00:00.000Z"),
      maxResults: 1,
    }),
    (error) => error instanceof ConnectorError && error.code === "connector_adapter_nonconformant",
  );
  assert.equal(nextReads, 0);
  assert.equal(returnCalls, 1);
});

test("one deadline spans execute and streamed body consumption, quarantining stalled streams immediately", async () => {
  let cancelled = false;
  const body = {
    [Symbol.asyncIterator]() {
      return this;
    },
    next() {
      return new Promise(() => undefined);
    },
    return() {
      cancelled = true;
      return Promise.resolve({ done: true });
    },
  };
  const stalled = new FakeHttpTransport(async (request) => response(request, {}, { body }));
  const { client } = await open("calendar", "primary", stalled, smallLimits);
  const request = {
    from: new Date("2026-08-26T00:00:00.000Z"),
    to: new Date("2026-08-27T00:00:00.000Z"),
    maxResults: 1,
  };
  await assert.rejects(
    client.upcoming(request),
    (error) => error instanceof ConnectorError && error.code === "connector_timeout",
  );
  assert.equal(cancelled, true);
  await assert.rejects(
    client.upcoming(request),
    (error) => error instanceof ConnectorError && error.code === "connector_quarantined",
  );
});

test("oversize and malformed bodies cancel the source iterator when return is available", async () => {
  let oversizeCancelled = false;
  const oversizeBody = {
    sent: false,
    [Symbol.asyncIterator]() {
      return this;
    },
    next() {
      if (this.sent) return Promise.resolve({ done: true });
      this.sent = true;
      return Promise.resolve({ done: false, value: new Uint8Array(4_097) });
    },
    return() {
      oversizeCancelled = true;
      return Promise.resolve({ done: true });
    },
  };
  const oversize = new FakeHttpTransport(async (request) => response(request, {}, { body: oversizeBody }));
  const { client: oversizeClient } = await open("calendar", "primary", oversize, smallLimits);
  await assert.rejects(
    oversizeClient.upcoming({
      from: new Date("2026-08-26T00:00:00.000Z"),
      to: new Date("2026-08-27T00:00:00.000Z"),
      maxResults: 1,
    }),
    (error) => error instanceof ConnectorError && error.code === "response_too_large",
  );
  assert.equal(oversizeCancelled, true);
  let malformedCancelled = false;
  const malformedBody = {
    step: 0,
    [Symbol.asyncIterator]() {
      return this;
    },
    next() {
      if (this.step > 0) return Promise.resolve({ done: true });
      this.step += 1;
      return Promise.resolve({ done: false, value: encoder.encode("not-json") });
    },
    return() {
      malformedCancelled = true;
      return Promise.resolve({ done: true });
    },
  };
  const malformed = new FakeHttpTransport(async (request) => response(request, {}, { body: malformedBody }));
  const { client: malformedClient } = await open("calendar", "primary", malformed, smallLimits);
  await assert.rejects(
    malformedClient.upcoming({
      from: new Date("2026-08-26T00:00:00.000Z"),
      to: new Date("2026-08-27T00:00:00.000Z"),
      maxResults: 1,
    }),
    (error) => error instanceof ConnectorError && error.code === "invalid_response",
  );
  assert.equal(malformedCancelled, true);
});

test("volatile per-process request QoS is explicitly bounded but not durable spend enforcement", async () => {
  const transport = new FakeHttpTransport(async (request) => response(request, { items: [] }));
  const volatile = Object.freeze({
    timeoutMs: 100,
    maxResponseBytes: 4_096,
    maxVolatileRequests: 1,
    volatileRequestWindowMs: 60_000,
  });
  const { client } = await open("calendar", "primary", transport, volatile);
  const request = {
    from: new Date("2026-08-26T00:00:00.000Z"),
    to: new Date("2026-08-27T00:00:00.000Z"),
    maxResults: 1,
  };
  await client.upcoming(request);
  await assert.rejects(
    client.upcoming(request),
    (error) => error instanceof ConnectorError && error.code === "connector_volatile_qos_limited",
  );
});

test("Gmail projects bounded verified message context and excludes attachments, HTML, and BCC", async () => {
  const plain = Buffer.from("Plain meeting context", "utf8").toString("base64url");
  const transport = new FakeHttpTransport(async (request) => {
    if (request.url.pathname.endsWith("/messages")) {
      return response(request, { messages: [{ id: "msg-one", threadId: "thread-one" }] });
    }
    return response(request, {
      id: "msg-one",
      threadId: "thread-one",
      snippet: "Meeting next steps",
      payload: {
        mimeType: "multipart/mixed",
        headers: [
          { name: "From", value: "a@risely.ai" },
          { name: "Subject", value: "Follow-up" },
          { name: "Bcc", value: "hidden@risely.ai" },
        ],
        parts: [
          { mimeType: "text/html", body: { data: Buffer.from("<b>ignore</b>").toString("base64url") } },
          { mimeType: "application/pdf", body: { attachmentId: "never-fetch" } },
          {
            mimeType: "text/plain",
            filename: "attachment.txt",
            body: { data: Buffer.from("Do not include").toString("base64url") },
          },
          { mimeType: "multipart/alternative", parts: [{ mimeType: "text/plain", body: { data: plain } }] },
        ],
      },
    });
  });
  const { client } = await open("gmail", "inbox", transport);
  const evidence = await client.recentInbox({ maxMessages: 1, maxThreads: 1 });
  assert.equal(evidence.content.messages[0].plainText, "Plain meeting context");
  assert.equal(evidence.content.messages[0].headers.subject, "Follow-up");
  assert.equal(Object.hasOwn(evidence.content.messages[0].headers, "bcc"), false);
  assert.equal(JSON.stringify(evidence.content).includes("never-fetch"), false);
  assert.equal(evidence.content.messages[0].plainText.includes("Do not include"), false);
  assert.equal(transport.requests.filter((request) => request.url.pathname.includes("/messages/")).length, 1);
});

test("Gmail rejects response id or thread mismatches and nested text over the message bound", async () => {
  const mismatch = new FakeHttpTransport(async (request) =>
    request.url.pathname.endsWith("/messages")
      ? response(request, { messages: [{ id: "msg-one", threadId: "thread-one" }] })
      : response(request, {
          id: "msg-other",
          threadId: "thread-one",
          payload: { mimeType: "text/plain", body: { data: "" } },
        }),
  );
  const { client: mismatchClient } = await open("gmail", "inbox", mismatch);
  await assert.rejects(
    mismatchClient.recentInbox({ maxMessages: 1, maxThreads: 1 }),
    (error) => error instanceof ConnectorError && error.code === "invalid_response",
  );
  const oversized = Buffer.from("x".repeat(16_385), "utf8").toString("base64url");
  const huge = new FakeHttpTransport(async (request) =>
    request.url.pathname.endsWith("/messages")
      ? response(request, { messages: [{ id: "msg-one", threadId: "thread-one" }] })
      : response(request, {
          id: "msg-one",
          threadId: "thread-one",
          payload: { mimeType: "text/plain", body: { data: oversized } },
        }),
  );
  const { client: hugeClient } = await open("gmail", "inbox", huge);
  await assert.rejects(
    hugeClient.recentInbox({ maxMessages: 1, maxThreads: 1 }),
    (error) => error instanceof ConnectorError && error.code === "response_too_large",
  );
  const invalidUtf8 = new FakeHttpTransport(async (request) =>
    request.url.pathname.endsWith("/messages")
      ? response(request, { messages: [{ id: "msg-one", threadId: "thread-one" }] })
      : response(request, {
          id: "msg-one",
          threadId: "thread-one",
          payload: { mimeType: "text/plain", body: { data: "wyg" } },
        }),
  );
  const { client: invalidUtf8Client } = await open("gmail", "inbox", invalidUtf8);
  await assert.rejects(
    invalidUtf8Client.recentInbox({ maxMessages: 1, maxThreads: 1 }),
    (error) => error instanceof ConnectorError && error.code === "invalid_response",
  );
  for (const encoded of ["==", "Zg==", "Zh"]) {
    const nonCanonical = new FakeHttpTransport(async (request) =>
      request.url.pathname.endsWith("/messages")
        ? response(request, { messages: [{ id: "msg-one", threadId: "thread-one" }] })
        : response(request, {
            id: "msg-one",
            threadId: "thread-one",
            payload: { mimeType: "text/plain", body: { data: encoded } },
          }),
    );
    const { client } = await open("gmail", "inbox", nonCanonical);
    await assert.rejects(
      client.recentInbox({ maxMessages: 1, maxThreads: 1 }),
      (error) => error instanceof ConnectorError && error.code === "invalid_response",
    );
  }
});

test("Gmail rejects malformed or ambiguous content-disposition before projecting text", async () => {
  for (const headers of [
    [{ name: "Content-Disposition", value: "inline;" }],
    [
      { name: "Content-Disposition", value: "inline" },
      { name: "Content-Disposition", value: "attachment" },
    ],
  ]) {
    const transport = new FakeHttpTransport(async (request) =>
      request.url.pathname.endsWith("/messages")
        ? response(request, { messages: [{ id: "msg-one", threadId: "thread-one" }] })
        : response(request, {
            id: "msg-one",
            threadId: "thread-one",
            payload: {
              mimeType: "text/plain",
              headers,
              body: { data: Buffer.from("untrusted text").toString("base64url") },
            },
          }),
    );
    const { client } = await open("gmail", "inbox", transport);
    await assert.rejects(
      client.recentInbox({ maxMessages: 1, maxThreads: 1 }),
      (error) => error instanceof ConnectorError && error.code === "invalid_response",
    );
  }
});

test("Calendar and Gmail roots must truthfully match their fixed provider roots", () => {
  const transport = new FakeHttpTransport(async (request) => response(request, { items: [] }));
  assert.throws(
    () => open("calendar", "calendar-other", transport),
    (error) => error instanceof ConnectorError && error.code === "untrusted_connection_resolution",
  );
  assert.throws(
    () => open("gmail", "me", transport),
    (error) => error instanceof ConnectorError && error.code === "untrusted_connection_resolution",
  );
});

test("Notion retrieves nested children within global caps and reports incompleteness instead of claiming a full tree", async () => {
  const root = "f3c06c76-d0f7-4a13-a80d-5f7ed467f28e";
  const child = "d5b49ee2-b0aa-47f3-8ad1-0458691e1f77";
  const grandchild = "0303e8e8-d8fe-463d-a183-fa00401b6cc1";
  const transport = new FakeHttpTransport(async (request) => {
    if (request.url.pathname.endsWith(`/blocks/${root}/children`))
      return response(request, {
        results: [{ id: child, has_children: true, parent: { type: "page_id", page_id: root } }],
        has_more: false,
      });
    if (request.url.pathname.endsWith(`/blocks/${child}/children`))
      return response(request, {
        results: [{ id: grandchild, has_children: false, parent: { type: "block_id", block_id: child } }],
        has_more: false,
      });
    return response(request, { object: "page", id: root });
  });
  const { client } = await open("notion", root, transport);
  await client.rootPage();
  const evidence = await client.rootTree({ pageSize: 10, maxPages: 4, maxBlocks: 10, maxDepth: 2 });
  assert.equal(evidence.content.blocks.length, 2);
  assert.equal(evidence.content.complete, true);
  assert.equal(evidence.content.blocks[0].parentId, root);
  assert.equal(evidence.content.blocks[1].parentId, child);
  assert.equal(
    transport.requests.every((request) => request.headers.get("notion-version") === notionVersion),
    true,
  );
  const shallow = await client.rootTree({ pageSize: 10, maxPages: 1, maxBlocks: 10, maxDepth: 0 });
  assert.equal(shallow.content.complete, false);
});

test("Notion rejects returned pages or blocks that are not bound to the requested parent", async () => {
  const root = "f3c06c76-d0f7-4a13-a80d-5f7ed467f28e";
  const child = "d5b49ee2-b0aa-47f3-8ad1-0458691e1f77";
  const transport = new FakeHttpTransport(async (request) =>
    request.url.pathname.endsWith(`/blocks/${root}/children`)
      ? response(request, {
          results: [
            {
              id: child,
              has_children: false,
              parent: { type: "page_id", page_id: "0303e8e8-d8fe-463d-a183-fa00401b6cc1" },
            },
          ],
          has_more: false,
        })
      : response(request, { object: "page", id: root }),
  );
  const { client } = await open("notion", root, transport);
  await assert.rejects(
    client.rootTree({ pageSize: 10, maxPages: 1, maxBlocks: 10, maxDepth: 1 }),
    (error) => error instanceof ConnectorError && error.code === "invalid_response",
  );
});

test("Clarify retains its bound workspace .ai route and legacy insights path cannot run", async () => {
  const transport = new FakeHttpTransport(async (request) => response(request, { data: [] }));
  const { client } = await open("clarify", "risely", transport);
  await client.listResources({
    objectType: "deal",
    limit: 20,
    filters: { stage: "discovery" },
    sort: { column: "updated_at", direction: "DESC" },
  });
  assert.equal(transport.requests[0].url.host, "api.clarify.ai");
  assert.equal(transport.requests[0].url.pathname, "/v1/workspaces/risely/objects/deal/resources");
  assert.equal(
    transport.requests.every((request) => request.url.pathname !== "/v1/insights"),
    true,
  );
});

test("Brain validates current exact search output, citation bindings, restricted access, and unknown input fields", async () => {
  const validSearch = {
    records: [
      {
        passageId: "p1",
        score: 0.9,
        text: "Account context",
        sourceId: "episode-1",
        sourceUrl: "https://example.com/episode-1",
        access: "normal",
      },
    ],
    citations: [
      {
        recordId: "p1",
        episodeIds: ["episode-1"],
        sourceUrls: ["https://example.com/episode-1"],
        citedEpisodes: [{ episodeId: "episode-1", sourceUrl: "https://example.com/episode-1" }],
        evidence: "Account context",
      },
    ],
  };
  const transport = new FakeMcpTransport(async (request) => ({ binding: binding(request), content: validSearch }));
  const { client } = await open("command_center_brain", "brain", transport);
  const evidence = await client.read("brain_search", { query: "Risely goals", k: 3 });
  assert.equal(evidence.content.records[0].access, "normal");
  assert.equal(transport.requests[0].actorRef, "usr_12345678");
  assert.equal(transport.requests[0].audit.bindingNonce, "bind_1234567890abcdef");
  await assert.rejects(
    client.read("brain_search", { query: "q", includeRestricted: true }),
    (error) => error instanceof ConnectorError && error.code === "invalid_request",
  );
  await assert.rejects(
    client.read("brain_search", { query: "q", unexpected: true }),
    (error) => error instanceof ConnectorError && error.code === "invalid_request",
  );
  const invalidOutput = new FakeMcpTransport(async (request) => ({
    binding: binding(request),
    content: {
      ...validSearch,
      citations: [
        {
          recordId: "other",
          episodeIds: ["episode-1"],
          sourceUrls: ["https://example.com/episode-1"],
          citedEpisodes: [{ episodeId: "episode-1", sourceUrl: "https://example.com/episode-1" }],
        },
      ],
    },
  }));
  const { client: invalidClient } = await open("command_center_brain", "brain", invalidOutput);
  await assert.rejects(
    invalidClient.read("brain_search", { query: "q" }),
    (error) => error instanceof ConnectorError && error.code === "invalid_response",
  );
  const restricted = new FakeMcpTransport(async (request) => ({
    binding: binding(request),
    content: { ...validSearch, records: [{ ...validSearch.records[0], access: "restricted" }] },
  }));
  const { client: restrictedClient } = await open("command_center_brain", "brain", restricted);
  await assert.rejects(
    restrictedClient.read("brain_search", { query: "q" }),
    (error) => error instanceof ConnectorError && error.code === "invalid_response",
  );
  const mismatchedSource = new FakeMcpTransport(async (request) => ({
    binding: binding(request),
    content: {
      ...validSearch,
      citations: [
        {
          recordId: "p1",
          episodeIds: ["episode-1"],
          sourceUrls: ["https://example.com/other"],
          citedEpisodes: [{ episodeId: "episode-1", sourceUrl: "https://example.com/other" }],
        },
      ],
    },
  }));
  const { client: mismatchedSourceClient } = await open("command_center_brain", "brain", mismatchedSource);
  await assert.rejects(
    mismatchedSourceClient.read("brain_search", { query: "q" }),
    (error) => error instanceof ConnectorError && error.code === "invalid_response",
  );
  const ownerWithoutEvidence = new FakeMcpTransport(async (request) => ({
    binding: binding(request),
    content: {
      owner: { id: "person-1", name: "Owner" },
      citations: [
        {
          recordId: "other",
          episodeIds: ["episode-1"],
          sourceUrls: ["https://example.com/episode-1"],
          citedEpisodes: [{ episodeId: "episode-1", sourceUrl: "https://example.com/episode-1" }],
        },
      ],
    },
  }));
  const { client: ownerClient } = await open("command_center_brain", "brain", ownerWithoutEvidence);
  await assert.rejects(
    ownerClient.read("brain_who_owns", { entityName: "Entity" }),
    (error) => error instanceof ConnectorError && error.code === "invalid_response",
  );
  const projectWithoutEvidence = new FakeMcpTransport(async (request) => ({
    binding: binding(request),
    content: { status: { phase: "on_track" }, evidence: [], citations: [] },
  }));
  const { client: projectClient } = await open("command_center_brain", "brain", projectWithoutEvidence);
  await assert.rejects(
    projectClient.read("brain_project_status", { entityName: "Entity" }),
    (error) => error instanceof ConnectorError && error.code === "invalid_response",
  );
  const citedEpisodeMismatch = new FakeMcpTransport(async (request) => ({
    binding: binding(request),
    content: {
      ...validSearch,
      citations: [
        {
          recordId: "p1",
          episodeIds: ["episode-1"],
          sourceUrls: ["https://example.com/episode-1"],
          citedEpisodes: [{ episodeId: "episode-2", sourceUrl: "https://example.com/episode-1" }],
        },
      ],
    },
  }));
  const { client: citedEpisodeClient } = await open("command_center_brain", "brain", citedEpisodeMismatch);
  await assert.rejects(
    citedEpisodeClient.read("brain_search", { query: "q" }),
    (error) => error instanceof ConnectorError && error.code === "invalid_response",
  );
  await assert.rejects(
    client.read("brain_what_changed_since", { entityName: "Entity", sinceIso: "2026-08-20" }),
    (error) => error instanceof ConnectorError && error.code === "invalid_request",
  );
  await assert.rejects(
    client.read("brain_what_changed_since", { entityName: "Entity", sinceIso: "2026-02-30T00:00:00.000Z" }),
    (error) => error instanceof ConnectorError && error.code === "invalid_request",
  );
  const strictDateTransport = new FakeMcpTransport(async (request) => ({
    binding: binding(request),
    content: { changes: [], citations: [] },
  }));
  const { client: strictDateClient } = await open("command_center_brain", "brain", strictDateTransport);
  await strictDateClient.read("brain_what_changed_since", { entityName: "Entity", sinceIso: "2026-08-20T00:00:00Z" });
});

test("Brain rejects proxy and accessor MCP responses before reading binding or content", async () => {
  const content = { status: {}, evidence: [], citations: [] };
  let accessorReads = 0;
  const accessorTransport = new FakeMcpTransport(async (request) => {
    const result = { binding: binding(request) };
    Object.defineProperty(result, "content", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return content;
      },
    });
    return result;
  });
  const { client: accessorClient } = await open("command_center_brain", "brain", accessorTransport);
  await assert.rejects(
    accessorClient.read("brain_project_status", { entityName: "Entity" }),
    (error) => error instanceof ConnectorError && error.code === "connector_adapter_nonconformant",
  );
  assert.equal(accessorReads, 0);
  let proxyReads = 0;
  const proxyTransport = new FakeMcpTransport(
    async (request) =>
      new Proxy(
        { binding: binding(request), content },
        {
          get(target, key) {
            if (key === "then") return undefined;
            proxyReads += 1;
            throw new Error("proxy response was read");
          },
        },
      ),
  );
  const { client: proxyClient } = await open("command_center_brain", "brain", proxyTransport);
  await assert.rejects(
    proxyClient.read("brain_project_status", { entityName: "Entity" }),
    (error) => error instanceof ConnectorError && error.code === "connector_adapter_nonconformant",
  );
  assert.equal(proxyReads, 0);
});

test("Brain validates every current Command Center read-tool output shape", async () => {
  const cite = {
    recordId: "edge-1",
    episodeIds: ["episode-1"],
    sourceUrls: ["https://example.com/episode-1"],
    citedEpisodes: [{ episodeId: "episode-1", sourceUrl: "https://example.com/episode-1" }],
  };
  const fact = {
    fromId: "from",
    label: "works_at",
    toId: "to",
    startedAt: null,
    endedAt: null,
    confidence: 0.9,
    citation: cite,
  };
  const outputs = {
    brain_search: {
      records: [
        {
          passageId: "passage-1",
          score: 0.8,
          text: "text",
          sourceId: "episode-1",
          sourceUrl: "https://example.com/episode-1",
          access: "normal",
        },
      ],
      citations: [{ ...cite, recordId: "passage-1" }],
    },
    brain_who_owns: { owner: { id: "person-1", name: "Owner" }, citations: [{ ...cite, recordId: "person-1" }] },
    brain_project_status: { status: {}, evidence: [], citations: [] },
    brain_person_context: { facts: [], passages: [], citations: [] },
    brain_what_changed_since: { changes: [fact], citations: [cite] },
    brain_as_of: { records: [fact], citations: [cite] },
    brain_episodes_about: {
      episodes: [{ id: "episode-1", title: "Meeting", startedAt: null, sourceUrl: "https://example.com/episode-1" }],
      citations: [{ ...cite, recordId: "episode-1" }],
    },
    brain_open_commitments_for_account: {
      commitments: [
        {
          commitmentId: "commitment-1",
          description: null,
          status: null,
          kind: null,
          dueAt: null,
          overdue: false,
          ownerId: null,
          owedToId: null,
          affectedEntityId: "account-1",
          citation: cite,
        },
      ],
      citations: [cite],
    },
    brain_open_risks_for_account: {
      risks: [
        {
          riskId: "risk-1",
          description: null,
          severity: null,
          likelihood: null,
          status: null,
          affectedEntityId: "account-1",
          mitigatedById: null,
          mitigationOwnerId: null,
          citation: cite,
        },
      ],
      citations: [cite],
    },
    brain_slipped_initiatives: {
      initiatives: [
        {
          initiativeId: "initiative-1",
          workstreamId: "workstream-1",
          outcomeId: "outcome-1",
          outcomeStatus: null,
          ownerId: null,
          decisions: [{ decisionId: "decision-1", description: null, supersedesIds: [] }],
          citation: cite,
        },
      ],
      citations: [cite],
    },
    brain_analytics_targetable_deployments: {
      deployments: [{ id: "deployment-1", name: "Deployment", orgDomain: null }],
    },
  };
  const inputs = {
    brain_search: { query: "query" },
    brain_who_owns: { entityName: "Entity", entityType: "Organization" },
    brain_project_status: { entityName: "Entity" },
    brain_person_context: { personName: "Person" },
    brain_what_changed_since: { entityName: "Entity", sinceIso: "2026-08-20T00:00:00.000Z" },
    brain_as_of: { entityName: "Entity", asOfIso: "2026-08-20T00:00:00.000Z" },
    brain_episodes_about: { entityName: "Entity" },
    brain_open_commitments_for_account: { accountName: "Account" },
    brain_open_risks_for_account: { accountName: "Account" },
    brain_slipped_initiatives: {},
    brain_analytics_targetable_deployments: {},
  };
  const transport = new FakeMcpTransport(async (request) => ({
    binding: binding(request),
    content: outputs[request.tool],
  }));
  const { client } = await open("command_center_brain", "brain", transport);
  for (const [tool, input] of Object.entries(inputs)) {
    await client.read(tool, input);
  }
  assert.equal(transport.requests.length, 11);
});
