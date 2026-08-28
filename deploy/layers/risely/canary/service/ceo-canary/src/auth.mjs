import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { types } from "node:util";

export const INGRESS_WINDOW_MS = 2 * 60 * 1000;
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const NONCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{31,255}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SIGNATURE = /^v1=[0-9a-f]{64}$/;
const METHOD = /^(?:GET|POST)$/;
const PATH = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,511}$/;

export class IngressAuthError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "IngressAuthError";
    this.code = code;
  }
}

function snapshotConfig(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) {
    throw new Error(`${label} is invalid`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} is invalid`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key)) ||
    fields.some((field) => {
      const descriptor = descriptors[field];
      return !descriptor || !("value" in descriptor) || !descriptor.enumerable;
    })
  ) {
    throw new Error(`${label} is invalid`);
  }
  const snapshot = Object.create(null);
  for (const field of fields) {
    Object.defineProperty(snapshot, field, {
      value: descriptors[field].value,
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }
  return Object.freeze(snapshot);
}

function ingressAuthority(config) {
  if (!config || typeof config.secret !== "string" || config.secret.trim().length < 32) {
    throw new Error("CANARY_INGRESS_SECRET must contain at least 32 characters");
  }
  for (const field of ["issuer", "audience", "keyId"]) {
    if (typeof config[field] !== "string" || !TOKEN.test(config[field])) {
      throw new Error(`Canary ingress ${field} is invalid`);
    }
  }
  return Object.freeze({
    secret: config.secret,
    issuer: config.issuer,
    audience: config.audience,
    keyId: config.keyId,
  });
}

export function assertIngressConfig(config) {
  return ingressAuthority(snapshotConfig(config, ["secret", "issuer", "audience", "keyId"], "Ingress configuration"));
}

export function assertRouteScopedIngressConfig(config) {
  const input = snapshotConfig(
    config,
    ["secret", "issuer", "audience", "keyId", "method", "pathWithQuery", "maxBodyBytes"],
    "Route-scoped ingress configuration",
  );
  const authority = ingressAuthority(input);
  if (!METHOD.test(input.method) || !PATH.test(input.pathWithQuery) || input.pathWithQuery.includes("?")) {
    throw new Error("Route-scoped ingress capability is invalid");
  }
  if (!Number.isSafeInteger(input.maxBodyBytes) || input.maxBodyBytes < 1 || input.maxBodyBytes > 256 * 1024) {
    throw new Error("Route-scoped ingress body limit is invalid");
  }
  return Object.freeze({
    ...authority,
    route: Object.freeze({
      method: input.method,
      pathWithQuery: input.pathWithQuery,
      maxBodyBytes: input.maxBodyBytes,
    }),
  });
}

export function assertIngressAuthoritySeparation(primary, scoped) {
  if (primary.secret === scoped.secret || primary.audience === scoped.audience || primary.keyId === scoped.keyId) {
    throw new Error("Route-scoped ingress must use a distinct secret, audience, and key id");
  }
  return true;
}

function constantEqual(left, right) {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function oneHeader(headers, name) {
  const value = headers[name];
  if (typeof value !== "string") throw new IngressAuthError("missing_header", `Missing ${name}`);
  return value;
}

export function canonicalIngressMetadata(fields) {
  return [
    "ceo-canary-ingress-v1",
    fields.issuer,
    fields.audience,
    fields.keyId,
    fields.method,
    fields.pathWithQuery,
    fields.timestamp,
    fields.nonce,
    fields.contentType,
    fields.contentLength,
    fields.contentSha256,
  ].join("\n");
}

export function headerSignature(secret, metadata) {
  return `v1=${createHmac("sha256", secret).update("header\n").update(metadata).digest("hex")}`;
}

export function createBodyMac(secret, metadata) {
  return createHmac("sha256", secret).update("body\n").update(metadata).update("\n");
}

export function bodySignature(secret, metadata, body) {
  return `v1=${createBodyMac(secret, metadata).update(body).digest("hex")}`;
}

export function verifyIngressHeaders({ method, pathWithQuery, headers, config, now = Date.now() }) {
  const issuer = oneHeader(headers, "x-canary-issuer");
  const audience = oneHeader(headers, "x-canary-audience");
  const keyId = oneHeader(headers, "x-canary-key-id");
  const timestamp = oneHeader(headers, "x-canary-timestamp");
  const nonce = oneHeader(headers, "x-canary-nonce");
  const contentType = oneHeader(headers, "x-canary-content-type");
  const contentLength = oneHeader(headers, "x-canary-content-length");
  const contentSha256 = oneHeader(headers, "x-canary-content-sha256");
  const suppliedHeaderSignature = oneHeader(headers, "x-canary-header-signature");
  const suppliedBodySignature = oneHeader(headers, "x-canary-body-signature");
  if (issuer !== config.issuer || audience !== config.audience || keyId !== config.keyId) {
    throw new IngressAuthError("authority_mismatch", "Ingress authority binding does not match");
  }
  if (config.route && (method !== config.route.method || pathWithQuery !== config.route.pathWithQuery)) {
    throw new IngressAuthError("route_capability_mismatch", "Ingress route is outside the signing capability");
  }
  if (!/^\d{10,12}$/.test(timestamp)) throw new IngressAuthError("invalid_timestamp", "Ingress timestamp is invalid");
  const timestampSeconds = Number(timestamp);
  if (!Number.isSafeInteger(timestampSeconds) || Math.abs(now - timestampSeconds * 1000) > INGRESS_WINDOW_MS) {
    throw new IngressAuthError("stale_request", "Ingress timestamp is outside the replay window");
  }
  if (!NONCE.test(nonce)) throw new IngressAuthError("invalid_nonce", "Ingress nonce is invalid");
  if (!/^(?:0|[1-9][0-9]{0,6})$/.test(contentLength)) {
    throw new IngressAuthError("invalid_content_length", "Signed content length is invalid");
  }
  if (!DIGEST.test(contentSha256))
    throw new IngressAuthError("invalid_content_digest", "Signed content digest is invalid");
  if (!SIGNATURE.test(suppliedHeaderSignature) || !SIGNATURE.test(suppliedBodySignature)) {
    throw new IngressAuthError("invalid_signature", "Ingress signature encoding is invalid");
  }
  const metadata = canonicalIngressMetadata({
    issuer,
    audience,
    keyId,
    method,
    pathWithQuery,
    timestamp,
    nonce,
    contentType,
    contentLength,
    contentSha256,
  });
  if (!constantEqual(headerSignature(config.secret, metadata), suppliedHeaderSignature)) {
    throw new IngressAuthError("invalid_signature", "Ingress header signature mismatch");
  }
  return {
    metadata,
    nonce,
    replayNamespaceSha256: createHash("sha256")
      .update("ceo-canary-ingress-replay-namespace-v1\n")
      .update(issuer)
      .update("\n")
      .update(audience)
      .update("\n")
      .update(keyId)
      .digest("hex"),
    timestampSeconds,
    contentType,
    contentLength: Number(contentLength),
    contentSha256,
    suppliedBodySignature,
  };
}

export async function completeIngressAuthentication({ verified, bodyDigest, computedBodySignature, store }) {
  if (!constantEqual(verified.contentSha256, bodyDigest)) {
    throw new IngressAuthError("content_digest_mismatch", "Request body digest does not match its signed digest");
  }
  if (!constantEqual(verified.suppliedBodySignature, computedBodySignature)) {
    throw new IngressAuthError("invalid_signature", "Ingress body signature mismatch");
  }
  const requestHash = createHash("sha256")
    .update(verified.metadata)
    .update("\n")
    .update(computedBodySignature)
    .digest("hex");
  const replayNonce = createHash("sha256")
    .update("ceo-canary-ingress-replay-nonce-v1\n")
    .update(verified.replayNamespaceSha256)
    .update("\n")
    .update(verified.nonce)
    .digest("hex");
  const expiresAt = new Date(verified.timestampSeconds * 1000 + INGRESS_WINDOW_MS).toISOString();
  if (!(await store.claimIngress({ nonce: replayNonce, requestHash, expiresAt }))) {
    throw new IngressAuthError("replayed_request", "Ingress nonce was already consumed");
  }
  return { requestHash, nonce: verified.nonce };
}
