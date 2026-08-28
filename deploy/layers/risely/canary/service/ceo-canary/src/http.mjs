import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { TextDecoder } from "node:util";
import { completeIngressAuthentication, createBodyMac, IngressAuthError, verifyIngressHeaders } from "./auth.mjs";
import { CanaryDomainError } from "./domain.mjs";
import { parseStrictJson } from "./json.mjs";
import { CanaryServiceError } from "./service.mjs";
import { CanaryStoreError } from "./postgres-store.mjs";

const MAX_BODY_BYTES = 256 * 1024;
const MAX_PREAUTH_REQUESTS = 8;

function send(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function rawHeaderCount(request, target) {
  let count = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index].toLowerCase() === target) count += 1;
  }
  return count;
}

function assertUnambiguousTransport(request, verified) {
  if (request.headers["transfer-encoding"] !== undefined || rawHeaderCount(request, "transfer-encoding") !== 0) {
    throw new IngressAuthError("ambiguous_transport", "Transfer encoding is not accepted");
  }
  if (rawHeaderCount(request, "content-length") !== 1 || typeof request.headers["content-length"] !== "string") {
    throw new IngressAuthError("ambiguous_transport", "Exactly one Content-Length header is required");
  }
  if (request.headers["content-encoding"] !== undefined || request.headers.expect !== undefined) {
    throw new IngressAuthError("ambiguous_transport", "Content encoding and Expect are not accepted");
  }
  const transportLength = Number(request.headers["content-length"]);
  if (!Number.isSafeInteger(transportLength) || transportLength !== verified.contentLength) {
    throw new IngressAuthError("content_length_mismatch", "Transport and signed content lengths differ");
  }
  if (transportLength > MAX_BODY_BYTES) {
    throw new IngressAuthError("request_too_large", "Signed request body exceeds its size limit");
  }
  const transportContentType = request.headers["content-type"] ?? "";
  if (transportContentType !== verified.contentType) {
    throw new IngressAuthError("content_type_mismatch", "Transport and signed content types differ");
  }
  const expectedContentType = request.method === "POST" ? "application/json" : "";
  if (verified.contentType !== expectedContentType) {
    throw new IngressAuthError("invalid_content_type", "Signed content type is invalid for the request method");
  }
  if (request.method === "GET" && verified.contentLength !== 0) {
    throw new IngressAuthError("invalid_content_length", "GET requests cannot contain a body");
  }
}

function readAuthenticatedBody(request, verified, secret) {
  return new Promise((resolve, reject) => {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    const digest = createHash("sha256");
    const mac = createBodyMac(secret, verified.metadata);
    const text = [];
    let received = 0;
    let failed = false;

    function fail(error) {
      if (failed) return;
      failed = true;
      reject(error);
    }

    request.on("data", (chunk) => {
      if (failed) return;
      received += chunk.length;
      if (received > verified.contentLength || received > MAX_BODY_BYTES) {
        fail(new IngressAuthError("content_length_mismatch", "Request body exceeds its signed content length"));
        return;
      }
      digest.update(chunk);
      mac.update(chunk);
      try {
        text.push(decoder.decode(chunk, { stream: true }));
      } catch {
        fail(new IngressAuthError("invalid_utf8", "Request body must be valid UTF-8"));
      }
    });
    request.on("end", () => {
      if (failed) return;
      if (received !== verified.contentLength) {
        fail(new IngressAuthError("content_length_mismatch", "Request body length does not match its signed length"));
        return;
      }
      try {
        text.push(decoder.decode());
      } catch {
        fail(new IngressAuthError("invalid_utf8", "Request body must be valid UTF-8"));
        return;
      }
      resolve({
        body: text.join(""),
        bodyDigest: digest.digest("hex"),
        computedBodySignature: `v1=${mac.digest("hex")}`,
      });
    });
    request.on("error", fail);
  });
}

function idFromPath(pathname, expression) {
  const match = expression.exec(pathname);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    throw new CanaryServiceError("invalid_id", "Path identifier is invalid");
  }
}

function statusFor(error) {
  if (error instanceof IngressAuthError && error.code === "request_too_large") return 413;
  if (error instanceof IngressAuthError) return 401;
  if (error instanceof CanaryServiceError && error.code === "preauth_capacity") return 503;
  if (
    error instanceof CanaryServiceError &&
    ["identity_bridge_required", "live_actions_disabled", "mutations_disabled"].includes(error.code)
  ) {
    return 409;
  }
  if (
    error instanceof CanaryStoreError &&
    [
      "stored_state_corrupt",
      "stored_run_corrupt",
      "effect_reservation_mismatch",
      "invalid_context",
      "schema_unhealthy",
    ].includes(error.code)
  ) {
    return 500;
  }
  if (error instanceof CanaryStoreError && error.code.endsWith("_not_found")) return 404;
  if (
    error instanceof CanaryStoreError &&
    [
      "run_already_exists",
      "action_already_exists",
      "effect_already_reserved",
      "revision_conflict",
      "lease_conflict",
      "reconciliation_not_available",
      "reconciliation_lease_required",
      "reservation_required",
    ].includes(error.code)
  ) {
    return 409;
  }
  if (error instanceof CanaryDomainError && ["illegal_transition", "not_expired"].includes(error.code)) return 409;
  if (error instanceof CanaryDomainError || error instanceof CanaryServiceError || error instanceof CanaryStoreError)
    return 400;
  return 500;
}

function safeError(error, status) {
  if (status >= 500) return { error: status === 503 ? "unavailable" : "internal_error" };
  return { error: error.code ?? "request_failed", message: error.message };
}

export function createCanaryHttpServer({ service, store, ingressConfig, now = () => Date.now() }) {
  let preauthRequests = 0;
  let readiness = { checkedAt: 0, ok: false, pending: null };
  const checkReadiness = async () => {
    const checkedAt = now();
    if (readiness.pending) return readiness.pending;
    if (readiness.checkedAt !== 0 && checkedAt >= readiness.checkedAt && checkedAt - readiness.checkedAt < 1000) {
      return readiness.ok;
    }
    const pending = store.health().then(
      (value) => value === true,
      () => false,
    );
    readiness = { ...readiness, pending };
    const ok = await pending;
    readiness = { checkedAt, ok, pending: null };
    return ok;
  };
  const server = createServer({ maxHeaderSize: 16 * 1024 }, async (request, response) => {
    let preauthHeld = false;
    try {
      const method = request.method ?? "";
      const pathWithQuery = request.url ?? "/";
      const url = new URL(pathWithQuery, "http://canary.internal");
      if (method === "GET" && url.pathname === "/livez" && !url.search) {
        send(response, 200, { ok: true, service: "ceo-canary" });
        return;
      }
      if (method === "GET" && ["/healthz", "/readyz"].includes(url.pathname) && !url.search) {
        const ok = await checkReadiness();
        send(response, ok ? 200 : 503, { ok, service: "ceo-canary", storage: "postgres" });
        return;
      }
      if (url.search) throw new IngressAuthError("invalid_path", "Internal API query parameters are not accepted");
      if (preauthRequests >= MAX_PREAUTH_REQUESTS) {
        throw new CanaryServiceError("preauth_capacity", "Pre-authentication request capacity is exhausted");
      }
      preauthRequests += 1;
      preauthHeld = true;
      const verified = verifyIngressHeaders({
        method,
        pathWithQuery,
        headers: request.headers,
        config: ingressConfig,
        now: now(),
      });
      assertUnambiguousTransport(request, verified);
      const streamed = await readAuthenticatedBody(request, verified, ingressConfig.secret);
      const auth = await completeIngressAuthentication({
        verified,
        bodyDigest: streamed.bodyDigest,
        computedBodySignature: streamed.computedBodySignature,
        store,
      });
      preauthRequests -= 1;
      preauthHeld = false;
      const body = streamed.body;
      if (method === "POST" && url.pathname === "/internal/v1/runs") {
        send(response, 201, await service.createRun(parseStrictJson(body), auth.requestHash));
        return;
      }
      let id = idFromPath(url.pathname, /^\/internal\/v1\/runs\/([^/]+)$/);
      if (method === "GET" && id !== null) {
        send(response, 200, await service.readRun(id, auth.requestHash));
        return;
      }
      if (method === "POST" && url.pathname === "/internal/v1/actions") {
        send(response, 201, await service.createAction(parseStrictJson(body), auth.requestHash));
        return;
      }
      id = idFromPath(url.pathname, /^\/internal\/v1\/actions\/([^/]+)$/);
      if (method === "GET" && id !== null) {
        send(response, 200, await service.readAction(id, auth.requestHash));
        return;
      }
      id = idFromPath(url.pathname, /^\/internal\/v1\/actions\/([^/]+)\/transitions$/);
      if (method === "POST" && id !== null) {
        send(response, 200, await service.transitionAction(id, parseStrictJson(body), auth.requestHash));
        return;
      }
      id = idFromPath(url.pathname, /^\/internal\/v1\/actions\/([^/]+)\/reservations$/);
      if (method === "POST" && id !== null) {
        send(response, 200, await service.reserveAction(id, parseStrictJson(body), auth.requestHash));
        return;
      }
      send(response, 404, { error: "not_found" });
    } catch (error) {
      if (response.headersSent || response.destroyed) {
        response.destroy();
        return;
      }
      const status = statusFor(error);
      send(response, status, safeError(error, status));
    } finally {
      if (preauthHeld) preauthRequests -= 1;
    }
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 2000;
  server.maxConnections = 64;
  server.maxRequestsPerSocket = 100;
  return server;
}
