import assert from "node:assert/strict";
import { test } from "node:test";
import {
  GMAIL_COMPOSE_SCOPE,
  GMAIL_DRAFT_CREATE_URL,
  GMAIL_DRAFT_RESPONSE_MAX_BYTES,
  sha256Bytes,
  validateEffectProposal,
  type GmailDraftConnectionBinding,
} from "../src/gmail-drafts/contracts.ts";
import { buildPlainTextGmailDraftMime } from "../src/gmail-drafts/mime.ts";
import {
  GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST,
  createGmailDraftProviderClient,
  type GmailDraftCredentialTransportRequest,
  type GmailDraftCredentialTransportResult,
  type GmailDraftPrivateCredentialPort,
} from "../src/gmail-drafts/provider-client.ts";
import { GMAIL_TEST_NOW, gmailDraftProposal } from "./gmail-draft-fixture.ts";

const CREDENTIAL_RECEIPT = sha256Bytes("credential receipt 1");
const REFRESHED_CREDENTIAL_RECEIPT = sha256Bytes("credential receipt 2");

function connection(): GmailDraftConnectionBinding {
  const proposal = gmailDraftProposal();
  return {
    organizationId: proposal.organizationId,
    logicalConnectionId: proposal.logicalConnectionId,
    connectionVersion: proposal.connectionVersion,
    ownerPrincipalId: proposal.ownerPrincipalId,
    googleSubject: proposal.googleSubject,
    mailbox: proposal.mailbox,
    accountType: proposal.accountType,
    grantedScopes: proposal.grantedScopes,
  };
}

function response(
  body: string | ReadableStream<Uint8Array> | null,
  status: number,
  url: string,
  redirected = false,
): Response {
  const value = new Response(body, { status });
  Object.defineProperty(value, "url", { value: url });
  Object.defineProperty(value, "redirected", { value: redirected });
  return value;
}

function authenticated(
  request: GmailDraftCredentialTransportRequest,
  body: string | ReadableStream<Uint8Array> | null,
  status = 200,
  options: {
    binding?: GmailDraftConnectionBinding;
    receipt?: string;
    redirected?: boolean;
    finalUrl?: string;
  } = {},
): GmailDraftCredentialTransportResult {
  return {
    status: "response",
    credentialBinding: options.binding ?? connection(),
    credentialReceiptSha256: options.receipt ?? CREDENTIAL_RECEIPT,
    response: response(body, status, options.finalUrl ?? request.url, options.redirected),
  };
}

function credentials(
  input: {
    request?: (request: GmailDraftCredentialTransportRequest) => Promise<GmailDraftCredentialTransportResult>;
    refresh?: (
      request: GmailDraftCredentialTransportRequest & { rejectedCredentialReceiptSha256: string },
    ) => Promise<GmailDraftCredentialTransportResult>;
    ready?: boolean;
  } = {},
): GmailDraftPrivateCredentialPort & {
  requests: GmailDraftCredentialTransportRequest[];
  refreshes: Array<GmailDraftCredentialTransportRequest & { rejectedCredentialReceiptSha256: string }>;
} {
  const port = {
    boundary: "private_gmail_draft_broker_only" as const,
    transportAllowlist: GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST,
    requests: [] as GmailDraftCredentialTransportRequest[],
    refreshes: [] as Array<GmailDraftCredentialTransportRequest & { rejectedCredentialReceiptSha256: string }>,
    readiness: () =>
      input.ready === false ? { ready: false as const, reason: "private adapter disabled" } : { ready: true as const },
    async request(request: GmailDraftCredentialTransportRequest) {
      port.requests.push(request);
      return input.request
        ? input.request(request)
        : authenticated(request, JSON.stringify({ id: "draft_1", message: { id: "message_1" } }));
    },
    async refreshAfterUnauthorized(
      request: GmailDraftCredentialTransportRequest & { rejectedCredentialReceiptSha256: string },
    ) {
      port.refreshes.push(request);
      return input.refresh ? input.refresh(request) : { status: "connection_unavailable" as const };
    },
  };
  return port;
}

test("private credential adapter must attest the immutable Gmail-drafts-only transport allowlist", async () => {
  const credentialPort = credentials();
  credentialPort.transportAllowlist = {
    ...GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST,
    requests: ["POST /gmail/v1/users/me/drafts/send"],
  } as unknown as typeof GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST;
  const client = createGmailDraftProviderClient({ credentials: credentialPort, now: () => GMAIL_TEST_NOW });
  assert.deepEqual(client.readiness(), {
    ready: false,
    reason: "private adapter drafts-only transport allowlist mismatch",
  });
  assert.deepEqual(
    await client.mutate({ binding: connection(), operation: "create", draftId: null, requestBody: "{}" }),
    { status: "rejected", code: "connection_unavailable" },
  );
  assert.equal(credentialPort.requests.length, 0);
});

test("provider permits only fixed create and update Gmail draft transport requests with exact MIME body", async () => {
  const proposal = validateEffectProposal(gmailDraftProposal(), GMAIL_TEST_NOW);
  const mime = buildPlainTextGmailDraftMime(proposal);
  const credentialPort = credentials();
  const client = createGmailDraftProviderClient({ credentials: credentialPort, now: () => GMAIL_TEST_NOW });
  const created = await client.mutate({
    binding: connection(),
    operation: "create",
    draftId: null,
    requestBody: mime.requestBody,
  });
  assert.equal(created.status, "ok");
  assert.deepEqual(
    {
      url: credentialPort.requests[0]?.url,
      method: credentialPort.requests[0]?.method,
      requestBody: credentialPort.requests[0]?.requestBody,
      requiredScope: credentialPort.requests[0]?.requiredScope,
      accept: credentialPort.requests[0]?.accept,
      contentType: credentialPort.requests[0]?.contentType,
      cache: credentialPort.requests[0]?.cache,
      referrerPolicy: credentialPort.requests[0]?.referrerPolicy,
      redirect: credentialPort.requests[0]?.redirect,
    },
    {
      url: GMAIL_DRAFT_CREATE_URL,
      method: "POST",
      requestBody: mime.requestBody,
      requiredScope: GMAIL_COMPOSE_SCOPE,
      accept: "application/json",
      contentType: "application/json; charset=utf-8",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      redirect: "manual",
    },
  );
  const updated = await client.mutate({
    binding: connection(),
    operation: "update",
    draftId: "draft_1",
    requestBody: mime.requestBody,
  });
  assert.equal(updated.status, "ok");
  assert.equal(credentialPort.requests[1]?.url, `${GMAIL_DRAFT_CREATE_URL}/draft_1`);
  assert.equal(credentialPort.requests[1]?.method, "PUT");
  if (created.status !== "ok") throw new Error("draft was not created");
  assert.equal(created.credentialReceiptSha256, CREDENTIAL_RECEIPT);
});

test("provider rejects wrong logical account and wrong exact scope from the private transport", async () => {
  let mode: "account" | "scope" = "account";
  const credentialPort = credentials({
    request: async () => ({ status: mode === "account" ? "connection_mismatch" : "scope_missing" }),
  });
  const client = createGmailDraftProviderClient({ credentials: credentialPort, now: () => GMAIL_TEST_NOW });
  assert.deepEqual(
    await client.mutate({ binding: connection(), operation: "create", draftId: null, requestBody: "{}" }),
    {
      status: "rejected",
      code: "connection_mismatch",
    },
  );
  mode = "scope";
  assert.deepEqual(
    await client.mutate({ binding: connection(), operation: "create", draftId: null, requestBody: "{}" }),
    {
      status: "rejected",
      code: "scope_missing",
    },
  );
});

test("authenticated response with substituted connection binding is outcome_unknown rather than retryable", async () => {
  const credentialPort = credentials({
    request: async (request) =>
      authenticated(request, JSON.stringify({ id: "draft_1", message: { id: "message_1" } }), 200, {
        binding: { ...connection(), logicalConnectionId: "other-account" },
      }),
  });
  const client = createGmailDraftProviderClient({ credentials: credentialPort, now: () => GMAIL_TEST_NOW });
  assert.deepEqual(
    await client.mutate({ binding: connection(), operation: "create", draftId: null, requestBody: "{}" }),
    { status: "outcome_unknown", code: "network_failure" },
  );
});

test("provider refreshes once after 401 using only a credential receipt and never receives or returns a token", async () => {
  const reflectedSecret = "private-access-token-value";
  const credentialPort = credentials({
    request: async (request) => authenticated(request, JSON.stringify({ error: { token: reflectedSecret } }), 401),
    refresh: async (request) =>
      authenticated(request, JSON.stringify({ id: "draft_2", message: { id: "message_2" } }), 200, {
        receipt: REFRESHED_CREDENTIAL_RECEIPT,
      }),
  });
  const client = createGmailDraftProviderClient({ credentials: credentialPort, now: () => GMAIL_TEST_NOW });
  const result = await client.mutate({ binding: connection(), operation: "create", draftId: null, requestBody: "{}" });
  assert.equal(result.status, "ok");
  assert.equal(credentialPort.requests.length, 1);
  assert.equal(credentialPort.refreshes.length, 1);
  assert.equal(credentialPort.refreshes[0]?.rejectedCredentialReceiptSha256, CREDENTIAL_RECEIPT);
  assert(!JSON.stringify(result).includes(reflectedSecret));
  assert(!JSON.stringify(credentialPort.requests).toLowerCase().includes("token"));
});

test("mutation reports unknown for redirect, post-header stall, oversized body, and excessive chunks", async () => {
  let cancelled = false;
  const stalled = new ReadableStream<Uint8Array>({
    cancel() {
      cancelled = true;
    },
  });
  const cases: Array<{
    expected: string;
    deadlineMs?: number;
    make: (request: GmailDraftCredentialTransportRequest) => GmailDraftCredentialTransportResult;
  }> = [
    {
      expected: "redirect_response",
      make: (request) => authenticated(request, "", 302, { redirected: true }),
    },
    { expected: "deadline_exceeded", deadlineMs: 10, make: (request) => authenticated(request, stalled) },
    {
      expected: "response_too_large",
      make: (request) => authenticated(request, "x".repeat(GMAIL_DRAFT_RESPONSE_MAX_BYTES + 1)),
    },
    {
      expected: "response_too_large",
      make: (request) => {
        let count = 0;
        const body = new ReadableStream<Uint8Array>({
          pull(controller) {
            count += 1;
            if (count <= 1_025) controller.enqueue(new Uint8Array());
            else controller.close();
          },
        });
        return authenticated(request, body);
      },
    },
  ];
  for (const entry of cases) {
    const client = createGmailDraftProviderClient({
      credentials: credentials({ request: async (request) => entry.make(request) }),
      now: () => GMAIL_TEST_NOW,
      deadlineMs: entry.deadlineMs ?? 5_000,
    });
    const result = await client.mutate({
      binding: connection(),
      operation: "create",
      draftId: null,
      requestBody: "{}",
    });
    assert.deepEqual(result, { status: "outcome_unknown", code: entry.expected });
  }
  assert.equal(cancelled, true);
});

test("read reconciliation uses exact marker search, rejects ambiguity, and reads one raw draft", async () => {
  const proposal = gmailDraftProposal();
  const marker = buildPlainTextGmailDraftMime(proposal).markerMessageId;
  let mode: "none" | "ambiguous" | "paginated" | "one" = "none";
  const credentialPort = credentials({
    request: async (request) => {
      if (request.url.includes("format=raw")) {
        return authenticated(request, JSON.stringify({ id: "draft_1", message: { id: "message_1", raw: "cmF3" } }));
      }
      let drafts: Array<{ id: string; message: { id: string } }> = [];
      if (mode === "ambiguous") {
        drafts = [
          { id: "draft_1", message: { id: "message_1" } },
          { id: "draft_2", message: { id: "message_2" } },
        ];
      } else if (mode === "one") {
        drafts = [{ id: "draft_1", message: { id: "message_1" } }];
      }
      return authenticated(
        request,
        JSON.stringify({ drafts, ...(mode === "paginated" ? { nextPageToken: "next" } : {}) }),
      );
    },
  });
  const client = createGmailDraftProviderClient({ credentials: credentialPort, now: () => GMAIL_TEST_NOW });
  assert.equal((await client.findByMarker({ binding: connection(), markerMessageId: marker })).status, "not_found");
  mode = "ambiguous";
  assert.equal((await client.findByMarker({ binding: connection(), markerMessageId: marker })).status, "ambiguous");
  mode = "paginated";
  assert.equal((await client.findByMarker({ binding: connection(), markerMessageId: marker })).status, "ambiguous");
  mode = "one";
  assert.equal((await client.findByMarker({ binding: connection(), markerMessageId: marker })).status, "ok");
  const search = new URL(credentialPort.requests.at(-2)!.url);
  assert.equal(search.origin, "https://gmail.googleapis.com");
  assert.equal(search.pathname, "/gmail/v1/users/me/drafts");
  assert.equal(search.searchParams.get("q"), `rfc822msgid:${marker}`);
  assert.equal(search.searchParams.get("maxResults"), "2");
  const raw = new URL(credentialPort.requests.at(-1)!.url);
  assert.equal(raw.pathname, "/gmail/v1/users/me/drafts/draft_1");
  assert.equal(raw.searchParams.get("format"), "raw");
});
