import type { JsonWebKey } from "node:crypto";
import { canonicalJson } from "../cron/schedule-authority.ts";
import type { DurableMap } from "../persistence/durable-map.ts";
import { createBackgroundJobCompletionPoller, type BackgroundJobCompletionPoller } from "./completion-poller.ts";
import { createBackgroundJobDeliveryScheduler, type BackgroundJobDeliveryScheduler } from "./delivery-sender.ts";
import { createBackgroundJobEffectReconciler, type BackgroundJobEffectReconciler } from "./effect-reconciler.ts";
import { createFixedBackgroundJobClient, type BackgroundJobResponseParsers } from "./fixed-client.ts";
import { createBackgroundJobAuthoritySigner, type BackgroundJobKmsSignerDependencies } from "./kms-signer.ts";
import { createBackgroundJobProfileService, createBackgroundJobRegistry } from "./service.ts";
import { createStagedBackgroundJobAuthority, type BackgroundJobAuthorityStageRecord } from "./staged-authority.ts";
import type {
  BackgroundJobAdapter,
  BackgroundJobApprovalStore,
  BackgroundJobAuthoritySignerConfig,
  BackgroundJobCompletionRuntime,
  BackgroundJobDeliveryOutbox,
  BackgroundJobDeploymentProfile,
  BackgroundJobEffectRuntime,
  BackgroundJobProfileService,
  BackgroundJobReceiptStore,
  BackgroundJobRenderOnlySender,
  BackgroundJobService,
} from "./types.ts";

export interface BackgroundJobKmsGeneration {
  keyId: string;
  tokenKid: string;
  publicJwk: JsonWebKey;
  region?: string;
  lifetimeSeconds?: number;
}

export interface BackgroundJobNativeDependency {
  adapter: BackgroundJobAdapter<unknown, unknown, unknown>;
  parsers: BackgroundJobResponseParsers<unknown, unknown>;
}

export interface BackgroundJobNativeDependencyRegistry {
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false }>;
  resolveAdapter(name: string): Readonly<BackgroundJobNativeDependency> | undefined;
  resolveAuthority(profile: Readonly<BackgroundJobDeploymentProfile>):
    | Readonly<{
        active: Readonly<BackgroundJobKmsGeneration>;
        next?: Readonly<BackgroundJobKmsGeneration>;
        kms?: BackgroundJobKmsSignerDependencies;
      }>
    | undefined;
}

export interface ProductionBackgroundJobRuntime {
  service: BackgroundJobService;
  ready(): Promise<void>;
  start(): void;
  stop(): void;
  visibleProfiles(): readonly Readonly<{ profileId: string; label: string }>[];
  controlProfiles(): readonly Readonly<{ profileId: string; label: string }>[];
  blockedProfiles(): Readonly<Record<string, string>>;
  jwks(): Readonly<{ keys: readonly Readonly<JsonWebKey>[] }>;
  effectReconciler: BackgroundJobEffectReconciler;
  completionPoller: BackgroundJobCompletionPoller;
  deliveryScheduler: BackgroundJobDeliveryScheduler;
}

function signerConfig(
  profile: Readonly<BackgroundJobDeploymentProfile>,
  generation: Readonly<BackgroundJobKmsGeneration>,
): BackgroundJobAuthoritySignerConfig {
  return {
    issuer: profile.issuer,
    audience: profile.audience,
    keyId: generation.keyId,
    tokenKid: generation.tokenKid,
    publicJwk: generation.publicJwk,
    profile: profile.profile,
    definition: profile.definition,
    binding: profile.binding,
    ...(generation.region ? { region: generation.region } : {}),
    ...(generation.lifetimeSeconds !== undefined ? { lifetimeSeconds: generation.lifetimeSeconds } : {}),
  };
}

export function createProductionBackgroundJobRuntime(options: {
  profiles: () => readonly Readonly<BackgroundJobDeploymentProfile>[];
  receiptStoreName: string;
  approvalStoreName: string;
  receipts: BackgroundJobReceiptStore & BackgroundJobCompletionRuntime["receipts"];
  approvals: BackgroundJobApprovalStore;
  outbox: BackgroundJobDeliveryOutbox;
  sender: BackgroundJobRenderOnlySender;
  authorityStages: DurableMap<BackgroundJobAuthorityStageRecord>;
  durable: boolean;
  registry: BackgroundJobNativeDependencyRegistry;
  now?: () => number;
}): ProductionBackgroundJobRuntime {
  const services = new Map<string, BackgroundJobProfileService>();
  const effectRuntimes = new Map<string, BackgroundJobEffectRuntime>();
  const completionRuntimes = new Map<string, BackgroundJobCompletionRuntime>();
  const authorities = new Map<string, ReturnType<typeof createStagedBackgroundJobAuthority>>();
  const authorityReady = new Set<string>();
  const blocked = new Map<string, string>();
  let sharedAuthorityFingerprint: string | undefined;
  let sharedAuthorityMismatch = false;
  let publicJwksReady = false;
  const runningProfiles = (): readonly Readonly<BackgroundJobDeploymentProfile>[] =>
    options.profiles().filter((profile) => services.has(profile.definition.id));
  if (
    !options.durable ||
    !options.receipts.readiness().ready ||
    !options.approvals.readiness().ready ||
    !options.outbox.readiness().ready ||
    !options.sender.readiness().ready ||
    !options.registry.readiness().ready
  ) {
    for (const profile of options.profiles()) blocked.set(profile.definition.id, "durable_dependencies_unavailable");
  } else {
    for (const profile of options.profiles()) {
      const id = profile.definition.id;
      if (services.has(id)) {
        blocked.set(id, "duplicate_profile_id");
        services.delete(id);
        continue;
      }
      if (
        profile.dependencies.receiptStore !== options.receiptStoreName ||
        profile.dependencies.approvalStore !== options.approvalStoreName ||
        profile.dependencies.authority !== "kms-rs256-v1"
      ) {
        blocked.set(id, "named_dependency_mismatch");
        continue;
      }
      const native = options.registry.resolveAdapter(profile.dependencies.adapter);
      const authorityConfig = options.registry.resolveAuthority(profile);
      if (!native || !native.adapter.readiness().ready) {
        blocked.set(id, "private_adapter_unavailable");
        continue;
      }
      if (!authorityConfig) {
        blocked.set(id, "private_authority_configuration_unavailable");
        continue;
      }
      try {
        const fingerprint = canonicalJson({ active: authorityConfig.active, next: authorityConfig.next ?? null });
        if (sharedAuthorityFingerprint === undefined) sharedAuthorityFingerprint = fingerprint;
        else if (sharedAuthorityFingerprint !== fingerprint) sharedAuthorityMismatch = true;
        const active = createBackgroundJobAuthoritySigner(
          signerConfig(profile, authorityConfig.active),
          authorityConfig.kms,
        );
        const next = authorityConfig.next
          ? createBackgroundJobAuthoritySigner(signerConfig(profile, authorityConfig.next), authorityConfig.kms)
          : undefined;
        const authority = createStagedBackgroundJobAuthority({
          backing: options.authorityStages,
          recordId: `background-job-authority:${id}`,
          durable: options.durable,
          active: { kid: authorityConfig.active.tokenKid, signer: active },
          ...(next && authorityConfig.next ? { next: { kid: authorityConfig.next.tokenKid, signer: next } } : {}),
          ...(options.now ? { now: options.now } : {}),
        });
        const client = createFixedBackgroundJobClient(
          { origin: profile.origin, definition: profile.definition, parsers: native.parsers },
          authority,
        );
        const service = createBackgroundJobProfileService({
          deployment: profile,
          adapter: native.adapter,
          receipts: options.receipts,
          approvals: options.approvals,
          client,
          authorityReady: () =>
            authorityReady.has(id) &&
            options.outbox.readiness().ready &&
            options.sender.readiness().ready &&
            options.registry.readiness().ready,
          active: () =>
            options
              .profiles()
              .some(
                (candidate) =>
                  candidate.enabled &&
                  candidate.definition.id === id &&
                  candidate.binding.descriptorSha256 === profile.binding.descriptorSha256,
              ),
          ...(options.now ? { now: options.now } : {}),
        });
        services.set(id, service);
        authorities.set(id, authority);
        effectRuntimes.set(id, { receipts: options.receipts, client, adapter: native.adapter });
        completionRuntimes.set(id, { receipts: options.receipts, client, adapter: native.adapter });
      } catch {
        blocked.set(id, "background_job_construction_failed");
      }
    }
    if (sharedAuthorityMismatch) {
      services.clear();
      effectRuntimes.clear();
      completionRuntimes.clear();
      authorities.clear();
      for (const profile of options.profiles()) {
        blocked.set(profile.definition.id, "background_job_shared_authority_mismatch");
      }
    }
  }
  const service = createBackgroundJobRegistry({
    profiles: runningProfiles,
    resolve: (profile) => services.get(profile.definition.id),
  });
  const effectReconciler = createBackgroundJobEffectReconciler({
    profiles: runningProfiles,
    resolve: (profile) => effectRuntimes.get(profile.definition.id),
    ...(options.now ? { now: options.now } : {}),
  });
  const completionPoller = createBackgroundJobCompletionPoller({
    profiles: runningProfiles,
    resolve: (profile) => completionRuntimes.get(profile.definition.id),
    outbox: options.outbox,
    ...(options.now ? { now: options.now } : {}),
  });
  const deliveryScheduler = createBackgroundJobDeliveryScheduler({
    outbox: options.outbox,
    sender: options.sender,
    ...(options.now ? { now: options.now } : {}),
  });
  let started = false;
  const publicJwks = (): Readonly<{ keys: readonly Readonly<JsonWebKey>[] }> => {
    const keys = new Map<string, Readonly<JsonWebKey>>();
    for (const [id, authority] of authorities) {
      if (!authorityReady.has(id)) continue;
      for (const key of authority.jwks().keys) {
        if (typeof key.kid !== "string" || !key.kid) return Object.freeze({ keys: Object.freeze([]) });
        const prior = keys.get(key.kid);
        if (prior && (prior.n !== key.n || prior.e !== key.e)) {
          return Object.freeze({ keys: Object.freeze([]) });
        }
        keys.set(key.kid, key);
      }
    }
    const result = [...keys.values()];
    return Object.freeze({ keys: Object.freeze(result.length <= 2 ? result : []) });
  };
  return Object.freeze({
    service,
    effectReconciler,
    completionPoller,
    deliveryScheduler,
    async ready() {
      for (const [id, authority] of authorities) {
        try {
          await authority.ready();
          if (authority.jwks().keys.length < 1) throw new Error("authority JWKS is unavailable");
          authorityReady.add(id);
        } catch {
          authorityReady.delete(id);
          blocked.set(id, "background_job_authority_unavailable");
        }
      }
      publicJwksReady = publicJwks().keys.length > 0;
      if (!publicJwksReady) {
        authorityReady.clear();
        for (const id of services.keys()) blocked.set(id, "background_job_public_jwks_unavailable");
      }
    },
    start() {
      if (started) return;
      started = true;
      effectReconciler.start();
      completionPoller.start();
      deliveryScheduler.start();
    },
    stop() {
      effectReconciler.stop();
      completionPoller.stop();
      deliveryScheduler.stop();
      started = false;
    },
    visibleProfiles: () =>
      Object.freeze(
        options
          .profiles()
          .flatMap((profile) =>
            publicJwksReady && profile.enabled && services.get(profile.definition.id)?.readiness().ready
              ? [{ profileId: profile.definition.id, label: profile.tools.start.label }]
              : [],
          ),
      ),
    controlProfiles: () =>
      Object.freeze(
        options
          .profiles()
          .flatMap((profile) =>
            publicJwksReady && services.get(profile.definition.id)?.readiness().ready
              ? [{ profileId: profile.definition.id, label: profile.tools.status.label }]
              : [],
          ),
      ),
    blockedProfiles: () => Object.freeze(Object.fromEntries(blocked)),
    jwks: publicJwks,
  });
}
