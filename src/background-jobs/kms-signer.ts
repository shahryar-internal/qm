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
const JWKS_CACHE_WINDOW_SECONDS = 600;
const SHA256 = /^[a-f0-9]{64}$/;

export interface BackgroundJobKmsSignerDependencies {
  kms?: KMSClient;
  now?: () => number;
  randomId?: () => string;
}

function sameRsaKey(left: JsonWebKey, right: JsonWebKey): boolean {
  return left.kty === "RSA" && right.kty === "RSA" && left.n === right.n && left.e === right.e;
}

export function createBackgroundJobAuthoritySigner(
  config: Readonly<BackgroundJobAuthoritySignerConfig>,
  dependencies: BackgroundJobKmsSignerDependencies = {},
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
  const previousJwk = config.previousPublicJwk === undefined ? undefined : exactPublicRsaJwk(config.previousPublicJwk);
  const previousKeyRetireAt = config.previousKeyRetireAt;
  if (
    (previousJwk === undefined) !== (previousKeyRetireAt === undefined) ||
    (previousJwk !== undefined &&
      (previousJwk.kid === configuredJwk.kid ||
        sameRsaKey(previousJwk, configuredJwk) ||
        !Number.isSafeInteger(previousKeyRetireAt) ||
        previousKeyRetireAt! < now() + (lifetimeSeconds + JWKS_CACHE_WINDOW_SECONDS) * 1000))
  ) {
    throw new TypeError("background job key rotation is invalid");
  }
  const randomId = dependencies.randomId ?? randomUUID;
  let previousRetired = false;
  const validatedApproval = (
    body: Uint8Array,
    grant: Parameters<BackgroundJobAuthoritySigner["signStart"]>[1],
    effect: "background_job_start" | "background_job_cancel",
    idempotencyKey: string,
    authorizedAt: number,
  ) => {
    if (
      !grant ||
      typeof grant !== "object" ||
      Array.isArray(grant) ||
      Object.keys(grant).sort().join(",") !==
        "actionTs,actorPrincipalId,actorSlackId,approvalId,approvalKey,audienceScopeId,channelId,conversationThreadRef,descriptorSha256,digest,effect,expiresAt,idempotencyKey,issuedAt,jobId,messageTs,organizationId,payloadSha256,profileSha256,schemaSha256,slackTeamId,threadTs" ||
      grant.effect !== effect ||
      grant.jobId !== definition.id ||
      grant.organizationId !== profile.organizationId ||
      grant.actorPrincipalId !== profile.actorPrincipalId ||
      grant.actorSlackId !== profile.actorSlackId ||
      grant.audienceScopeId !== profile.audienceScopeId ||
      grant.slackTeamId !== profile.slackTeamId ||
      grant.channelId !== profile.channelId ||
      grant.descriptorSha256 !== binding.descriptorSha256 ||
      grant.profileSha256 !== binding.profileSha256 ||
      grant.schemaSha256 !== binding.schemaSha256 ||
      grant.idempotencyKey !== idempotencyKey ||
      grant.payloadSha256 !== createHash("sha256").update(body).digest("hex") ||
      !Number.isSafeInteger(authorizedAt) ||
      !Number.isSafeInteger(grant.issuedAt) ||
      !Number.isSafeInteger(grant.expiresAt) ||
      grant.issuedAt > authorizedAt ||
      grant.expiresAt <= authorizedAt ||
      authorizedAt > now() ||
      grant.expiresAt - grant.issuedAt > 300_000
    ) {
      throw new TypeError("background job approval grant is invalid");
    }
    const { digest, ...unsigned } = grant;
    if (!SHA256.test(digest) || createHash("sha256").update(canonicalJson(unsigned)).digest("hex") !== digest) {
      throw new TypeError("background job approval grant is invalid");
    }
    return grant;
  };
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
    approval?: Readonly<{
      approvalId: string;
      digest: string;
      effect: "background_job_start" | "background_job_cancel";
      approvalKey: string;
      actionTs: string;
      authorizedAt: number;
      messageTs: string;
      threadTs: string;
      conversationThreadRef: string;
    }>,
  ): Promise<string> => {
    const messageTs = validateSlackTimestamp(slack.messageTs, "messageTs");
    const threadTs = validateSlackTimestamp(slack.threadTs, "threadTs");
    const exactBinding = Object.freeze({ ...claimBinding });
    validateContractBinding(exactBinding);
    const exactIdempotencyKey = identifier(idempotencyKey, "idempotency key");
    if (approval) {
      identifier(approval.approvalId, "approval id");
      identifier(approval.approvalKey, "approval key");
      validateSlackTimestamp(approval.actionTs, "approval actionTs");
      if (!SHA256.test(approval.digest)) throw new TypeError("approval digest is invalid");
      if (approval.messageTs !== messageTs || approval.threadTs !== threadTs) {
        throw new TypeError("approval Slack act is invalid");
      }
    }
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
      ...(approval ? { conversationThreadRef: approval.conversationThreadRef } : {}),
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
      ...(approval
        ? {
            approvalId: approval.approvalId,
            approvalDigest: approval.digest,
            approvalEffect: approval.effect,
            approvalKey: approval.approvalKey,
            approvalActionTs: approval.actionTs,
            approvalAuthorizedAt: approval.authorizedAt,
          }
        : {}),
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
    signStart: (
      body: Parameters<BackgroundJobAuthoritySigner["signStart"]>[0],
      grant: Parameters<BackgroundJobAuthoritySigner["signStart"]>[1],
      idempotencyKey: string,
      authorizedAt: number,
    ) => {
      return sign(body, grant, definition.start, idempotencyKey, binding, {
        ...validatedApproval(body, grant, "background_job_start", idempotencyKey, authorizedAt),
        authorizedAt,
      });
    },
    signStatus: (body: Uint8Array, receipt: Parameters<BackgroundJobAuthoritySigner["signStatus"]>[1]) =>
      sign(body, receipt, definition.status, controlKey("status", body), receiptBinding(receipt)),
    signCancel: (
      body: Parameters<BackgroundJobAuthoritySigner["signCancel"]>[0],
      receipt: Parameters<BackgroundJobAuthoritySigner["signCancel"]>[1],
      grant: Parameters<BackgroundJobAuthoritySigner["signCancel"]>[2],
      authorizedAt: number,
    ) => {
      const idempotencyKey = controlKey("cancel", body);
      return sign(body, grant, definition.cancel, idempotencyKey, receiptBinding(receipt), {
        ...validatedApproval(body, grant, "background_job_cancel", idempotencyKey, authorizedAt),
        authorizedAt,
      });
    },
    jwks: () => {
      if (previousJwk && now() >= previousKeyRetireAt!) previousRetired = true;
      return Object.freeze({
        keys: Object.freeze(previousJwk && !previousRetired ? [configuredJwk, previousJwk] : [configuredJwk]),
      });
    },
  });
}
