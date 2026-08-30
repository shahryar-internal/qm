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
import type {
  BackgroundJobAuthoritySigner,
  BackgroundJobAuthoritySignerConfig,
  BackgroundJobContractBinding,
  BackgroundJobRoute,
} from "./types.ts";
import {
  identifier,
  exactPublicRsaJwk,
  parsePublicHttpsUrl,
  validateBackgroundJobProfile,
  validateContractBinding,
  validateDefinition,
  validateSlackTimestamp,
} from "./validation.ts";

const KMS_ALGORITHM = SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;

interface KmsSignerDependencies {
  kms?: KMSClient;
  now?: () => number;
  randomId?: () => string;
}

function sameRsaKey(left: JsonWebKey, right: JsonWebKey): boolean {
  return left.kty === "RSA" && right.kty === "RSA" && left.n === right.n && left.e === right.e;
}

export function createBackgroundJobAuthoritySigner(
  config: Readonly<BackgroundJobAuthoritySignerConfig>,
  dependencies: KmsSignerDependencies = {},
): BackgroundJobAuthoritySigner {
  const profile = Object.freeze({ ...config.profile });
  const binding = Object.freeze({ ...config.binding });
  const definition = Object.freeze({
    ...config.definition,
    ...(config.definition.prepare ? { prepare: Object.freeze({ ...config.definition.prepare }) } : {}),
    start: Object.freeze({ ...config.definition.start }),
    status: Object.freeze({ ...config.definition.status }),
    cancel: Object.freeze({ ...config.definition.cancel }),
  });
  validateBackgroundJobProfile(profile);
  validateContractBinding(binding);
  validateDefinition(definition);
  parsePublicHttpsUrl(config.issuer, "issuer", false);
  parsePublicHttpsUrl(config.audience, "audience", false);
  const issuer = config.issuer;
  const audience = config.audience;
  const keyId = identifier(config.keyId, "key id");
  const tokenKid = identifier(config.tokenKid, "token kid");
  const lifetimeSeconds = config.lifetimeSeconds ?? 120;
  if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1 || lifetimeSeconds > 300) {
    throw new TypeError("background job token lifetime is invalid");
  }
  const configuredJwk = exactPublicRsaJwk(config.publicJwk, tokenKid);
  const kms = dependencies.kms ?? new KMSClient(config.region ? { region: config.region } : {});
  const now = dependencies.now ?? Date.now;
  const randomId = dependencies.randomId ?? randomUUID;
  let keyPromise: Promise<KeyObject> | undefined;
  const key = (): Promise<KeyObject> => {
    if (keyPromise) return keyPromise;
    keyPromise = kms
      .send(new GetPublicKeyCommand({ KeyId: keyId }))
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
    slack: Readonly<{ messageTs: string; threadTs: string }>,
    route: Readonly<BackgroundJobRoute>,
    idempotencyKey: string,
    claimBinding: Readonly<BackgroundJobContractBinding> = binding,
  ): Promise<string> => {
    const messageTs = validateSlackTimestamp(slack.messageTs, "messageTs");
    const threadTs = validateSlackTimestamp(slack.threadTs, "threadTs");
    const exactBinding = Object.freeze({ ...claimBinding });
    validateContractBinding(exactBinding);
    const exactIdempotencyKey = identifier(idempotencyKey, "idempotency key");
    if (
      !(bodyBytes instanceof Uint8Array) ||
      bodyBytes.byteLength < 2 ||
      bodyBytes.byteLength > route.maxRequestBytes
    ) {
      throw new TypeError("background job payload is invalid");
    }
    const exactBodyBytes = Uint8Array.from(bodyBytes);
    const publicKey = await key();
    const issuedAt = Math.floor(now() / 1000);
    const jti = identifier(randomId(), "jti");
    const requestId = identifier(randomId(), "requestId");
    if (jti === requestId) throw new Error("background job signer returned duplicate request identifiers");
    const protectedHeader = Buffer.from(
      canonicalJson({ alg: "RS256", kid: tokenKid, typ: definition.tokenType }),
      "utf8",
    ).toString("base64url");
    const claims = {
      iss: issuer,
      sub: profile.actorPrincipalId,
      aud: audience,
      iat: issuedAt,
      exp: issuedAt + lifetimeSeconds,
      jti,
      scope: definition.scope,
      organizationId: profile.organizationId,
      actorPrincipalId: profile.actorPrincipalId,
      actorSlackId: profile.actorSlackId,
      audienceScopeId: profile.audienceScopeId,
      slackTeamId: profile.slackTeamId,
      channelId: profile.channelId,
      threadTs,
      messageTs,
      descriptorSha256: exactBinding.descriptorSha256,
      profileSha256: exactBinding.profileSha256,
      schemaSha256: exactBinding.schemaSha256,
      operation: definition.operation,
      capability: definition.capability,
      requestId,
      idempotencyKey: exactIdempotencyKey,
      payloadSha256: createHash("sha256").update(exactBodyBytes).digest("hex"),
      httpMethod: "POST",
      httpPath: route.path,
    };
    const payload = Buffer.from(canonicalJson(claims), "utf8").toString("base64url");
    const input = `${protectedHeader}.${payload}`;
    const digest = createHash("sha256").update(input, "ascii").digest();
    const result = await kms.send(
      new SignCommand({
        KeyId: keyId,
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
    `${definition.id}-${kind}:${createHash("sha256").update(body).digest("hex")}`;
  const receiptBinding = (
    receipt: Parameters<BackgroundJobAuthoritySigner["signStatus"]>[1],
  ): Readonly<BackgroundJobContractBinding> => ({
    descriptorSha256: receipt.descriptorSha256,
    profileSha256: receipt.profileSha256,
    schemaSha256: receipt.schemaSha256,
  });
  return Object.freeze({
    ready: () => key().then(() => undefined),
    signPrepare: (
      body: Uint8Array,
      slack: Readonly<{ messageTs: string; threadTs: string }>,
      idempotencyKey: string,
    ) => {
      if (!definition.prepare) throw new Error("background job preparation is unavailable");
      return sign(body, slack, definition.prepare, idempotencyKey);
    },
    signStart: (body: Uint8Array, slack: Readonly<{ messageTs: string; threadTs: string }>, idempotencyKey: string) =>
      sign(body, slack, definition.start, idempotencyKey),
    signStatus: (body: Uint8Array, receipt: Parameters<BackgroundJobAuthoritySigner["signStatus"]>[1]) =>
      sign(body, receipt, definition.status, controlKey("status", body), receiptBinding(receipt)),
    signCancel: (body: Uint8Array, receipt: Parameters<BackgroundJobAuthoritySigner["signCancel"]>[1]) =>
      sign(body, receipt, definition.cancel, controlKey("cancel", body), receiptBinding(receipt)),
    jwks: () => Object.freeze({ keys: Object.freeze([configuredJwk]) }),
  });
}
