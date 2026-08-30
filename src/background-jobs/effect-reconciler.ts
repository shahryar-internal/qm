import { createHash, randomUUID } from "node:crypto";
import { canonicalJson } from "../cron/schedule-authority.ts";
import { createSweeper, type Sweeper } from "../util/sweeper.ts";
import type { BackgroundJobDeploymentProfile, BackgroundJobEffectRuntime, BackgroundJobOwner } from "./types.ts";

const DEFAULT_BATCH = 25;
const DEFAULT_INTERVAL_MS = 2_000;
const LEASE_MS = 30_000;
const ATTENTION_THRESHOLD = 8;
const MAX_BACKOFF_MS = 5 * 60_000;

export interface BackgroundJobEffectReconcilerDependencies {
  profiles: () => readonly Readonly<BackgroundJobDeploymentProfile>[];
  resolve(profile: Readonly<BackgroundJobDeploymentProfile>): BackgroundJobEffectRuntime | undefined;
  batchSize?: number;
  intervalMs?: number;
  now?: () => number;
  randomId?: () => string;
}

export interface BackgroundJobEffectReconciler extends Sweeper {
  runOnce(): Promise<number>;
}

function retryAt(now: number, attempt: number): number {
  return now + Math.min(MAX_BACKOFF_MS, 1_000 * 2 ** Math.min(attempt - 1, 12));
}

function exactBody(bodyBase64: string, payloadSha256: string, maxBytes: number): Uint8Array {
  if (
    typeof bodyBase64 !== "string" ||
    bodyBase64.length > Math.ceil(maxBytes / 3) * 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(bodyBase64)
  ) {
    throw new Error("background job durable payload is invalid");
  }
  const body = Buffer.from(bodyBase64, "base64");
  if (body.length < 2 || body.length > maxBytes || body.toString("base64") !== bodyBase64) {
    throw new Error("background job durable payload is invalid");
  }
  if (createHash("sha256").update(body).digest("hex") !== payloadSha256) {
    throw new Error("background job durable payload hash changed");
  }
  return body;
}

function ownerOf(value: Readonly<BackgroundJobOwner>): Readonly<BackgroundJobOwner> {
  return Object.freeze({
    organizationId: value.organizationId,
    actorPrincipalId: value.actorPrincipalId,
    actorSlackId: value.actorSlackId,
    audienceScopeId: value.audienceScopeId,
    slackTeamId: value.slackTeamId,
    channelId: value.channelId,
    threadTs: value.threadTs,
    conversationThreadRef: value.conversationThreadRef,
  });
}

export function createBackgroundJobEffectReconciler(
  dependencies: Readonly<BackgroundJobEffectReconcilerDependencies>,
): BackgroundJobEffectReconciler {
  const batchSize = dependencies.batchSize ?? DEFAULT_BATCH;
  const intervalMs = dependencies.intervalMs ?? DEFAULT_INTERVAL_MS;
  const now = dependencies.now ?? Date.now;
  const randomId = dependencies.randomId ?? randomUUID;
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 100) {
    throw new TypeError("background job effect batch size is invalid");
  }
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 1_000 || intervalMs > 60_000) {
    throw new TypeError("background job effect interval is invalid");
  }
  const runOnce = async (): Promise<number> => {
    let remaining = batchSize;
    let completed = 0;
    const ids = new Set<string>();
    for (const profile of dependencies.profiles()) {
      if (remaining < 1 || ids.has(profile.definition.id)) continue;
      ids.add(profile.definition.id);
      const runtime = dependencies.resolve(profile);
      if (!runtime || !runtime.receipts.readiness().ready) continue;
      const at = now();
      const admissionLeaseId = `background-job-admission-lease:${randomId()}`;
      const admissions = await runtime.receipts.leaseAdmissions(
        profile.definition.id,
        at,
        remaining,
        admissionLeaseId,
        at + LEASE_MS,
      );
      remaining -= admissions.length;
      for (const lease of admissions) {
        try {
          const intent = lease.intent;
          if (
            intent.descriptorSha256 !== profile.binding.descriptorSha256 ||
            intent.profileSha256 !== profile.binding.profileSha256 ||
            intent.schemaSha256 !== profile.binding.schemaSha256 ||
            intent.approvalGrant.effect !== "background_job_start" ||
            intent.approvalGrant.digest.length !== 64
          ) {
            throw new Error("background job admission binding changed");
          }
          const body = exactBody(intent.bodyBase64, intent.payloadSha256, profile.definition.start.maxRequestBytes);
          const admission = await runtime.client.start(
            body,
            intent.approvalGrant,
            intent.idempotencyKey,
            intent.createdAt,
          );
          await runtime.receipts.completeAdmission(intent.intentId, lease.leaseId, admission, now());
          completed += 1;
        } catch {
          await runtime.receipts
            .retryAdmission(
              lease.intent.intentId,
              lease.leaseId,
              retryAt(now(), lease.attempt),
              lease.attempt >= ATTENTION_THRESHOLD,
            )
            .catch(() => undefined);
        }
      }
      if (remaining < 1) continue;
      const controlAt = now();
      const controlLeaseId = `background-job-control-lease:${randomId()}`;
      const controls = await runtime.receipts.leaseControls(
        profile.definition.id,
        controlAt,
        remaining,
        controlLeaseId,
        controlAt + LEASE_MS,
      );
      remaining -= controls.length;
      for (const lease of controls) {
        try {
          const intent = lease.intent;
          if (
            intent.descriptorSha256 !== profile.binding.descriptorSha256 ||
            intent.profileSha256 !== profile.binding.profileSha256 ||
            intent.schemaSha256 !== profile.binding.schemaSha256 ||
            intent.approvalGrant.effect !== "background_job_cancel"
          ) {
            throw new Error("background job control binding changed");
          }
          const receipt = await runtime.receipts.ownedRun(
            profile.definition.id,
            ownerOf(intent),
            intent.authorityId,
            intent.runId,
          );
          if (!receipt) throw new Error("background job control receipt is unavailable");
          const payloadSha256 = createHash("sha256")
            .update(Buffer.from(canonicalJson({ authorityId: intent.authorityId, runId: intent.runId })))
            .digest("hex");
          if (
            intent.payloadSha256 !== payloadSha256 ||
            intent.approvalGrant.payloadSha256 !== payloadSha256 ||
            intent.idempotencyKey !== `${profile.definition.id}-cancel:${payloadSha256}` ||
            intent.approvalGrant.idempotencyKey !== intent.idempotencyKey
          ) {
            throw new Error("background job control payload changed");
          }
          const cancellation = await runtime.client.cancel(receipt, intent.approvalGrant, intent.createdAt);
          const state = runtime.adapter.cancellationState(cancellation);
          if (state !== "cancel_requested" && state !== "cancelled") {
            throw new Error("background job cancellation response is invalid");
          }
          await runtime.receipts.completeControl(intent.intentId, lease.leaseId, now());
          completed += 1;
        } catch {
          await runtime.receipts
            .retryControl(
              lease.intent.intentId,
              lease.leaseId,
              retryAt(now(), lease.attempt),
              lease.attempt >= ATTENTION_THRESHOLD,
            )
            .catch(() => undefined);
        }
      }
    }
    return completed;
  };
  const sweeper = createSweeper(runOnce, intervalMs, { label: "background-job-effect", immediate: true });
  return Object.freeze({ runOnce, start: sweeper.start, stop: sweeper.stop });
}
