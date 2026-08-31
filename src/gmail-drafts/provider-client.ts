import {
  GMAIL_COMPOSE_SCOPE,
  GMAIL_DRAFT_CREATE_URL,
  GMAIL_DRAFT_DEADLINE_MS,
  GMAIL_DRAFT_REQUEST_MAX_BYTES,
  GMAIL_DRAFT_RESPONSE_MAX_BYTES,
  assertProviderIdentifier,
  assertSha256,
  sha256Bytes,
  validateConnectionBinding,
  type GmailDraftConnectionBinding,
  type GmailDraftUnknownCode,
} from "./contracts.ts";

const MAX_RESPONSE_CHUNKS = 1_024;

export const GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST = Object.freeze({
  contractType: "qm-gmail-draft-private-transport-allowlist" as const,
  contractVersion: 1 as const,
  origin: "https://gmail.googleapis.com" as const,
  requiredScope: GMAIL_COMPOSE_SCOPE,
  requests: Object.freeze([
    "POST /gmail/v1/users/me/drafts",
    "PUT /gmail/v1/users/me/drafts/{draftId}",
    "GET /gmail/v1/users/me/drafts?maxResults=2&q=rfc822msgid:{markerMessageId}&includeSpamTrash=false",
    "GET /gmail/v1/users/me/drafts/{draftId}?format=raw",
  ] as const),
});

export type GmailDraftPrivateTransportAllowlist = typeof GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST;

export interface GmailDraftAuthenticatedResponse {
  credentialBinding: GmailDraftConnectionBinding;
  credentialReceiptSha256: string;
  response: Response;
}

export type GmailDraftCredentialTransportResult =
  | ({ status: "response" } & GmailDraftAuthenticatedResponse)
  | { status: "connection_unavailable" | "connection_mismatch" | "scope_missing" }
  | { status: "network_failure" | "deadline_exceeded" };

export interface GmailDraftCredentialTransportRequest {
  expected: GmailDraftConnectionBinding;
  requiredScope: typeof GMAIL_COMPOSE_SCOPE;
  method: "GET" | "POST" | "PUT";
  url: string;
  requestBody: string | null;
  accept: "application/json";
  contentType: "application/json; charset=utf-8" | null;
  cache: "no-store";
  referrerPolicy: "no-referrer";
  redirect: "manual";
  deadlineAt: number;
  signal: AbortSignal;
}

export interface GmailDraftPrivateCredentialPort {
  boundary: "private_gmail_draft_broker_only";
  transportAllowlist: GmailDraftPrivateTransportAllowlist;
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
  request(input: GmailDraftCredentialTransportRequest): Promise<GmailDraftCredentialTransportResult>;
  refreshAfterUnauthorized(
    input: GmailDraftCredentialTransportRequest & { rejectedCredentialReceiptSha256: string },
  ): Promise<GmailDraftCredentialTransportResult>;
}

export function gmailDraftPrivateCredentialReadiness(
  credentials: GmailDraftPrivateCredentialPort,
): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }> {
  const allowlist = credentials.transportAllowlist;
  const allowlistKeys = allowlist && typeof allowlist === "object" ? Object.keys(allowlist).sort() : [];
  if (
    allowlistKeys.join(",") !== "contractType,contractVersion,origin,requests,requiredScope" ||
    allowlist?.contractType !== GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST.contractType ||
    allowlist.contractVersion !== GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST.contractVersion ||
    allowlist.origin !== GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST.origin ||
    allowlist.requiredScope !== GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST.requiredScope ||
    !Array.isArray(allowlist.requests) ||
    allowlist.requests.length !== GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST.requests.length ||
    allowlist.requests.some((entry, index) => entry !== GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST.requests[index])
  ) {
    return { ready: false, reason: "private adapter drafts-only transport allowlist mismatch" };
  }
  return credentials.readiness();
}

export interface GmailDraftProviderDraft {
  draftId: string;
  messageId: string;
  threadId: string | null;
  raw: string | null;
}

export type GmailDraftMutationResult =
  | {
      status: "ok";
      draft: GmailDraftProviderDraft;
      responseSha256: string;
      credentialReceiptSha256: string;
    }
  | {
      status: "rejected";
      code:
        "connection_unavailable" | "connection_mismatch" | "scope_missing" | "gmail_unauthorized" | "gmail_rejected";
    }
  | { status: "outcome_unknown"; code: GmailDraftUnknownCode };

export type GmailDraftReadResult =
  | {
      status: "ok";
      draft: GmailDraftProviderDraft;
      responseSha256: string;
      credentialReceiptSha256: string;
    }
  | { status: "not_found" }
  | { status: "ambiguous" }
  | { status: "unavailable" };

export interface GmailDraftProviderPort {
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
  mutate(input: {
    binding: GmailDraftConnectionBinding;
    operation: "create" | "update";
    draftId: string | null;
    requestBody: string;
  }): Promise<GmailDraftMutationResult>;
  findByMarker(input: { binding: GmailDraftConnectionBinding; markerMessageId: string }): Promise<GmailDraftReadResult>;
  read(input: { binding: GmailDraftConnectionBinding; draftId: string }): Promise<GmailDraftReadResult>;
}

interface ResponseData {
  status: number;
  body: string;
  responseSha256: string;
  credentialReceiptSha256: string;
}

type RequestResult =
  | { status: "response"; response: ResponseData }
  | { status: "connection_unavailable" | "connection_mismatch" | "scope_missing" }
  | { status: "network_failure" | "deadline_exceeded" | "redirect_response" | "response_too_large" };

function bindingIssue(
  actual: GmailDraftConnectionBinding,
  expected: GmailDraftConnectionBinding,
): "connection_mismatch" | "scope_missing" | null {
  const identityMatches =
    actual.organizationId === expected.organizationId &&
    actual.logicalConnectionId === expected.logicalConnectionId &&
    actual.connectionVersion === expected.connectionVersion &&
    actual.ownerPrincipalId === expected.ownerPrincipalId &&
    actual.googleSubject === expected.googleSubject &&
    actual.mailbox === expected.mailbox &&
    actual.accountType === expected.accountType;
  if (!identityMatches) return "connection_mismatch";
  if (
    !Array.isArray(actual.grantedScopes) ||
    actual.grantedScopes.length !== 1 ||
    actual.grantedScopes[0] !== GMAIL_COMPOSE_SCOPE
  )
    return "scope_missing";
  try {
    validateConnectionBinding(actual);
  } catch {
    return "connection_mismatch";
  }
  return null;
}

async function boundedBody(response: Response, signal: AbortSignal): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let count = 0;
  let completed = false;
  let rejectAborted: ((error: Error) => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectAborted = reject;
  });
  const abort = () => rejectAborted?.(new Error("deadline"));
  signal.addEventListener("abort", abort, { once: true });
  try {
    for (;;) {
      if (signal.aborted) throw new Error("deadline");
      const next = await Promise.race([reader.read(), aborted]);
      if (next.done) {
        completed = true;
        break;
      }
      count += 1;
      if (count > MAX_RESPONSE_CHUNKS) throw new RangeError("response chunks");
      if (!(next.value instanceof Uint8Array) || next.value.byteLength === 0) continue;
      size += next.value.byteLength;
      if (size > GMAIL_DRAFT_RESPONSE_MAX_BYTES) throw new RangeError("response bytes");
      chunks.push(next.value);
    }
    const bytes = Buffer.concat(
      chunks.map((chunk) => Buffer.from(chunk)),
      size,
    );
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } finally {
    signal.removeEventListener("abort", abort);
    if (!completed) await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

function parseObject(body: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(body);
    return value !== null && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function providerDraft(value: unknown, requireRaw: boolean): GmailDraftProviderDraft | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const draft = value as Record<string, unknown>;
  if (
    typeof draft.id !== "string" ||
    !draft.message ||
    typeof draft.message !== "object" ||
    Array.isArray(draft.message)
  )
    return null;
  const message = draft.message as Record<string, unknown>;
  try {
    assertProviderIdentifier(draft.id, "draftId");
    assertProviderIdentifier(message.id, "messageId");
    if (message.threadId !== undefined && message.threadId !== null)
      assertProviderIdentifier(message.threadId, "threadId");
  } catch {
    return null;
  }
  if (requireRaw && (typeof message.raw !== "string" || message.raw.length > GMAIL_DRAFT_RESPONSE_MAX_BYTES * 2))
    return null;
  return {
    draftId: draft.id,
    messageId: message.id,
    threadId: typeof message.threadId === "string" ? message.threadId : null,
    raw: typeof message.raw === "string" ? message.raw : null,
  };
}

function listDrafts(value: unknown): Readonly<{ drafts: readonly GmailDraftProviderDraft[]; hasMore: boolean }> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const drafts = record.drafts;
  const nextPageToken = record.nextPageToken;
  if (
    nextPageToken !== undefined &&
    (typeof nextPageToken !== "string" || nextPageToken.length < 1 || nextPageToken.length > 2_048)
  )
    return null;
  if (drafts === undefined) return { drafts: [], hasMore: nextPageToken !== undefined };
  if (!Array.isArray(drafts) || drafts.length > 2) return null;
  const parsed = drafts.map((entry) => providerDraft(entry, false));
  return parsed.every((entry): entry is GmailDraftProviderDraft => entry !== null)
    ? { drafts: parsed, hasMore: nextPageToken !== undefined }
    : null;
}

export function createGmailDraftProviderClient(options: {
  credentials: GmailDraftPrivateCredentialPort;
  now?: () => number;
  deadlineMs?: number;
}): GmailDraftProviderPort {
  const now = options.now ?? Date.now;
  const deadlineMs = options.deadlineMs ?? GMAIL_DRAFT_DEADLINE_MS;
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > GMAIL_DRAFT_DEADLINE_MS) {
    throw new TypeError("Gmail draft deadline is invalid");
  }
  const readiness = () => gmailDraftPrivateCredentialReadiness(options.credentials);
  const request = async (
    expectedInput: GmailDraftConnectionBinding,
    method: "GET" | "POST" | "PUT",
    url: URL,
    requestBody: string | null,
  ): Promise<RequestResult> => {
    if (!readiness().ready) return { status: "connection_unavailable" };
    const expected = validateConnectionBinding(expectedInput);
    const startedAt = now();
    const deadlineAt = startedAt + deadlineMs;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Math.max(1, deadlineAt - now()));
    const transportInput: GmailDraftCredentialTransportRequest = {
      expected,
      requiredScope: GMAIL_COMPOSE_SCOPE,
      method,
      url: url.href,
      requestBody,
      accept: "application/json",
      contentType: requestBody === null ? null : "application/json; charset=utf-8",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      redirect: "manual",
      deadlineAt,
      signal: controller.signal,
    };
    const perform = async (invoke: () => Promise<GmailDraftCredentialTransportResult>): Promise<RequestResult> => {
      if (controller.signal.aborted || now() >= deadlineAt) return { status: "deadline_exceeded" };
      let transport: GmailDraftCredentialTransportResult;
      try {
        transport = await invoke();
      } catch {
        return controller.signal.aborted ? { status: "deadline_exceeded" } : { status: "network_failure" };
      }
      if (transport.status !== "response") return transport;
      const issue = bindingIssue(transport.credentialBinding, expected);
      if (issue) return { status: "network_failure" };
      try {
        assertSha256(transport.credentialReceiptSha256, "credentialReceiptSha256");
      } catch {
        return { status: "network_failure" };
      }
      const response = transport.response;
      if (!(response instanceof Response)) return { status: "network_failure" };
      if (response.redirected || response.url !== url.href || (response.status >= 300 && response.status < 400)) {
        await response.body?.cancel().catch(() => undefined);
        return { status: "redirect_response" };
      }
      let body: string;
      try {
        body = await boundedBody(response, controller.signal);
      } catch (error) {
        if (controller.signal.aborted) return { status: "deadline_exceeded" };
        return error instanceof RangeError ? { status: "response_too_large" } : { status: "network_failure" };
      }
      return {
        status: "response",
        response: {
          status: response.status,
          body,
          responseSha256: sha256Bytes(body),
          credentialReceiptSha256: transport.credentialReceiptSha256,
        },
      };
    };
    const run = async (): Promise<RequestResult> => {
      let result = await perform(() => options.credentials.request(transportInput));
      if (result.status === "response" && result.response.status === 401 && !controller.signal.aborted) {
        const rejectedCredentialReceiptSha256 = result.response.credentialReceiptSha256;
        const refreshed = await perform(() =>
          options.credentials.refreshAfterUnauthorized({
            ...transportInput,
            rejectedCredentialReceiptSha256,
          }),
        );
        if (refreshed.status === "connection_unavailable") return result;
        if (
          refreshed.status === "response" &&
          refreshed.response.credentialReceiptSha256 === rejectedCredentialReceiptSha256
        ) {
          return { status: "network_failure" };
        }
        result = refreshed;
      }
      return result;
    };
    try {
      const timeoutResult = new Promise<RequestResult>((resolve) => {
        controller.signal.addEventListener("abort", () => resolve({ status: "deadline_exceeded" }), { once: true });
      });
      return await Promise.race([run(), timeoutResult]);
    } finally {
      clearTimeout(timeout);
      controller.abort();
    }
  };
  const read = async (binding: GmailDraftConnectionBinding, url: URL): Promise<GmailDraftReadResult> => {
    const result = await request(binding, "GET", url, null);
    if (result.status !== "response") return { status: "unavailable" };
    if (result.response.status === 404) return { status: "not_found" };
    if (result.response.status < 200 || result.response.status >= 300) return { status: "unavailable" };
    const draft = providerDraft(parseObject(result.response.body), true);
    return draft
      ? {
          status: "ok",
          draft,
          responseSha256: result.response.responseSha256,
          credentialReceiptSha256: result.response.credentialReceiptSha256,
        }
      : { status: "unavailable" };
  };
  const port: GmailDraftProviderPort = {
    readiness,
    async mutate(input) {
      if (Buffer.byteLength(input.requestBody, "utf8") > GMAIL_DRAFT_REQUEST_MAX_BYTES) {
        return { status: "rejected", code: "gmail_rejected" };
      }
      const url =
        input.operation === "create"
          ? new URL(GMAIL_DRAFT_CREATE_URL)
          : (() => {
              assertProviderIdentifier(input.draftId, "draftId");
              return new URL(`${GMAIL_DRAFT_CREATE_URL}/${encodeURIComponent(input.draftId)}`);
            })();
      const result = await request(
        input.binding,
        input.operation === "create" ? "POST" : "PUT",
        url,
        input.requestBody,
      );
      if (
        result.status === "connection_unavailable" ||
        result.status === "connection_mismatch" ||
        result.status === "scope_missing"
      ) {
        return { status: "rejected", code: result.status };
      }
      if (result.status !== "response") return { status: "outcome_unknown", code: result.status };
      if (result.response.status === 401) return { status: "rejected", code: "gmail_unauthorized" };
      if (result.response.status >= 500 || result.response.status === 408 || result.response.status === 429) {
        return { status: "outcome_unknown", code: "server_error" };
      }
      if (result.response.status < 200 || result.response.status >= 300) {
        return { status: "rejected", code: "gmail_rejected" };
      }
      const draft = providerDraft(parseObject(result.response.body), false);
      return draft
        ? {
            status: "ok",
            draft,
            responseSha256: result.response.responseSha256,
            credentialReceiptSha256: result.response.credentialReceiptSha256,
          }
        : { status: "outcome_unknown", code: "invalid_success_response" };
    },
    async findByMarker(input) {
      if (!/^<qm\.[a-f0-9]{64}@drafts\.invalid>$/u.test(input.markerMessageId)) return { status: "unavailable" };
      const url = new URL(GMAIL_DRAFT_CREATE_URL);
      url.searchParams.set("maxResults", "2");
      url.searchParams.set("q", `rfc822msgid:${input.markerMessageId}`);
      url.searchParams.set("includeSpamTrash", "false");
      const result = await request(input.binding, "GET", url, null);
      if (result.status !== "response" || result.response.status < 200 || result.response.status >= 300) {
        return { status: "unavailable" };
      }
      const listed = listDrafts(parseObject(result.response.body));
      if (!listed) return { status: "unavailable" };
      if (listed.drafts.length === 0 && !listed.hasMore) return { status: "not_found" };
      if (listed.drafts.length !== 1 || listed.hasMore) return { status: "ambiguous" };
      const draftId = listed.drafts[0]!.draftId;
      const draftUrl = new URL(`${GMAIL_DRAFT_CREATE_URL}/${encodeURIComponent(draftId)}`);
      draftUrl.searchParams.set("format", "raw");
      return read(input.binding, draftUrl);
    },
    async read(input) {
      assertProviderIdentifier(input.draftId, "draftId");
      const url = new URL(`${GMAIL_DRAFT_CREATE_URL}/${encodeURIComponent(input.draftId)}`);
      url.searchParams.set("format", "raw");
      return read(input.binding, url);
    },
  };
  return Object.freeze(port);
}
