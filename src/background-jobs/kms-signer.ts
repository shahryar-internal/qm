import { createHash, createPublicKey, randomUUID, verify, type JsonWebKey, type KeyObject } from "node:crypto";
import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
  SigningAlgorithmSpec,
  MessageType,
  KeyUsageType,
} from "@aws-sdk/client-kms";
import { canonicalJson } from "../cron/schedule-authority.ts";
import type { BackgroundJobAuthoritySigner, BackgroundJobAuthoritySignerConfig, BackgroundJobRoute } from "./types.ts";
import {
  identifier,
  parseStrictHttpsUrl,
  validateBackgroundJobProfile,
  validateDefinition,
  validateSlackTimestamp,
} from "./validation.ts";

const KMS_ALGORITHM = SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;

interface KmsSignerDependencies {
  kms?: KMSClient;
  now?: () => number;
  randomId?: () => string;
}

function publicJwk(value: JsonWebKey, tokenKid: string): Readonly<JsonWebKey> {
  if (
    value.kty !== "RSA" ||
    value.alg !== "RS256" ||
    value.use !== "sig" ||
    value.kid !== tokenKid ||
    typeof value.n !== "string" ||
    !value.n ||
    typeof value.e !== "string" ||
    !value.e ||
    Object.keys(value).some((key) => ["d", "p", "q", "dp", "dq", "qi", "oth", "k"].includes(key))
  )
    throw new TypeError("background job public JWK is invalid");
  return Object.freeze({ kty: "RSA", alg: "RS256", use: "sig", kid: tokenKid, n: value.n, e: value.e });
}

function sameRsaKey(left: JsonWebKey, right: JsonWebKey): boolean {
  return left.kty === "RSA" && right.kty === "RSA" && left.n === right.n && left.e === right.e;
}

export function createBackgroundJobAuthoritySigner(
  config: Readonly<BackgroundJobAuthoritySignerConfig>,
  dependencies: KmsSignerDependencies = {},
): BackgroundJobAuthoritySigner {
  validateBackgroundJobProfile(config.profile);
  validateDefinition(config.definition);
  parseStrictHttpsUrl(config.issuer, "issuer", false);
  parseStrictHttpsUrl(config.audience, "audience", false);
  const issuer = config.issuer;
  const audience = config.audience;
  identifier(config.keyId, "key id");
  identifier(config.tokenKid, "token kid");
  const lifetimeSeconds = config.lifetimeSeconds ?? 120;
  if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1 || lifetimeSeconds > 300) {
    throw new TypeError("background job token lifetime is invalid");
  }
  const configuredJwk = publicJwk(config.publicJwk, config.tokenKid);
  const kms = dependencies.kms ?? new KMSClient(config.region ? { region: config.region } : {});
  const now = dependencies.now ?? Date.now;
  const randomId = dependencies.randomId ?? randomUUID;
  let keyPromise: Promise<KeyObject> | undefined;
  const key = (): Promise<KeyObject> => {
    if (keyPromise) return keyPromise;
    keyPromise = kms
      .send(new GetPublicKeyCommand({ KeyId: config.keyId }))
      .then((result) => {
        if (
          !result.PublicKey ||
          result.KeyUsage !== KeyUsageType.SIGN_VERIFY ||
          !result.SigningAlgorithms?.includes(KMS_ALGORITHM)
        ) {
          throw new Error("background job signing key is unavailable");
        }
        const resolved = createPublicKey({ key: Buffer.from(result.PublicKey), format: "der", type: "spki" });
        if (!sameRsaKey(resolved.export({ format: "jwk" }), configuredJwk)) {
          throw new Error("background job signing key does not match the public JWK");
        }
        return resolved;
      })
      .catch((error: unknown) => {
        keyPromise = undefined;
        throw error;
      });
    return keyPromise;
  };
  const sign = async (
    bodyBytes: Uint8Array,
    threadTs: string,
    route: Readonly<BackgroundJobRoute>,
    idempotencyKey: string,
  ): Promise<string> => {
    validateSlackTimestamp(threadTs, "threadTs");
    identifier(idempotencyKey, "idempotency key");
    if (
      !(bodyBytes instanceof Uint8Array) ||
      bodyBytes.byteLength < 2 ||
      bodyBytes.byteLength > route.maxRequestBytes
    ) {
      throw new TypeError("background job payload is invalid");
    }
    const publicKey = await key();
    const issuedAt = Math.floor(now() / 1000);
    const protectedHeader = Buffer.from(
      canonicalJson({ alg: "RS256", kid: config.tokenKid, typ: config.definition.tokenType }),
      "utf8",
    ).toString("base64url");
    const claims = {
      iss: issuer,
      sub: config.profile.actorPrincipalId,
      aud: audience,
      iat: issuedAt,
      exp: issuedAt + lifetimeSeconds,
      jti: randomId(),
      scope: config.definition.scope,
      organizationId: config.profile.organizationId,
      actorPrincipalId: config.profile.actorPrincipalId,
      actorSlackId: config.profile.actorSlackId,
      audienceScopeId: config.profile.audienceScopeId,
      slackTeamId: config.profile.slackTeamId,
      channelId: config.profile.channelId,
      threadTs,
      operation: config.definition.operation,
      capability: config.definition.capability,
      requestId: randomId(),
      idempotencyKey,
      payloadSha256: createHash("sha256").update(bodyBytes).digest("hex"),
      httpMethod: "POST",
      httpPath: route.path,
    };
    const payload = Buffer.from(canonicalJson(claims), "utf8").toString("base64url");
    const input = `${protectedHeader}.${payload}`;
    const digest = createHash("sha256").update(input, "ascii").digest();
    const result = await kms.send(
      new SignCommand({
        KeyId: config.keyId,
        Message: digest,
        MessageType: MessageType.DIGEST,
        SigningAlgorithm: KMS_ALGORITHM,
      }),
    );
    if (!result.Signature || result.SigningAlgorithm !== KMS_ALGORITHM)
      throw new Error("background job signer returned no valid signature");
    const signature = Buffer.from(result.Signature);
    if (!verify("RSA-SHA256", Buffer.from(input, "ascii"), publicKey, signature)) {
      throw new Error("background job signer returned a mismatched signature");
    }
    return `${input}.${signature.toString("base64url")}`;
  };
  const controlKey = (kind: "status" | "cancel", body: Uint8Array) =>
    `${config.definition.id}-${kind}:${createHash("sha256").update(body).digest("hex")}`;
  return Object.freeze({
    ready: () => key().then(() => undefined),
    signPrepare: (body: Uint8Array, threadTs: string, idempotencyKey: string) => {
      if (!config.definition.prepare) throw new Error("background job preparation is unavailable");
      return sign(body, threadTs, config.definition.prepare, idempotencyKey);
    },
    signStart: (body: Uint8Array, threadTs: string, idempotencyKey: string) =>
      sign(body, threadTs, config.definition.start, idempotencyKey),
    signStatus: (body: Uint8Array, threadTs: string) =>
      sign(body, threadTs, config.definition.status, controlKey("status", body)),
    signCancel: (body: Uint8Array, threadTs: string) =>
      sign(body, threadTs, config.definition.cancel, controlKey("cancel", body)),
    jwks: () => Object.freeze({ keys: Object.freeze([configuredJwk]) }),
  });
}
