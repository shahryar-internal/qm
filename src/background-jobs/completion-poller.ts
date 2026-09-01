import { createHash, randomUUID } from "node:crypto";
import { canonicalJson } from "../cron/schedule-authority.ts";
import { createSweeper, type Sweeper } from "../util/sweeper.ts";
import { backgroundJobReceiptOwned, backgroundJobStatusOutcome, validateBackgroundJobStatusView } from "./service.ts";
import type {
  BackgroundJobCompletionRuntime,
  BackgroundJobDeliveryIntent,
  BackgroundJobDeliveryOutbox,
  BackgroundJobDeploymentProfile,
  BackgroundJobOwner,
} from "./types.ts";
import { identifier } from "./validation.ts";

export interface BackgroundJobCompletionPollerDependencies {
  profiles: () => readonly Readonly<BackgroundJobDeploymentProfile>[];
  resolve(profile: Readonly<BackgroundJobDeploymentProfile>): BackgroundJobCompletionRuntime | undefined;
  outbox: BackgroundJobDeliveryOutbox;
  batchSize?: number;
  intervalMs?: number;
  now?: () => number;
  randomId?: () => string;
}

export interface BackgroundJobCompletionPoller extends Sweeper {
  runOnce(): Promise<number>;
}

const LEASE_MS = 30_000;
const ATTENTION_THRESHOLD = 8;
const MAX_BACKOFF_MS = 5 * 60_000;

function nextAttempt(now: number, attempt: number): number {
  return now + Math.min(MAX_BACKOFF_MS, 1_000 * 2 ** Math.min(attempt, 12));
}

function deliveryKey(
  profile: Readonly<BackgroundJobDeploymentProfile>,
  receipt: Readonly<import("./types.ts").BackgroundJobReceipt>,
): string {
  return `background-job-delivery:${createHash("sha256")
    .update(
      canonicalJson({
        actorPrincipalId: receipt.actorPrincipalId,
        actorSlackId: receipt.actorSlackId,
        authorityId: receipt.authorityId,
        channelId: receipt.channelId,
        conversationThreadRef: receipt.conversationThreadRef,
        descriptorSha256: profile.binding.descriptorSha256,
        jobId: profile.definition.id,
        organizationId: receipt.organizationId,
        profileSha256: profile.binding.profileSha256,
        runId: receipt.runId,
        slackTeamId: receipt.slackTeamId,
        threadTs: receipt.threadTs,
      }),
    )
    .digest("hex")}`;
}

export function createBackgroundJobCompletionPoller(
  dependencies: Readonly<BackgroundJobCompletionPollerDependencies>,
): BackgroundJobCompletionPoller {
  const batchSize = dependencies.batchSize ?? 25;
  const intervalMs = dependencies.intervalMs ?? 5_000;
  const now = dependencies.now ?? Date.now;
  const randomId = dependencies.randomId ?? randomUUID;
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 100) {
    throw new TypeError("background job completion batch size is invalid");
  }
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 1_000 || intervalMs > 60_000) {
    throw new TypeError("background job completion interval is invalid");
  }
  if (
    dependencies.outbox.durability !== "durable" ||
    dependencies.outbox.admission !== "persist_before_send" ||
    dependencies.outbox.reconciliation !== "automatic_idempotent_delivery" ||
    dependencies.outbox.transport !== "slack_first_party_render_only" ||
    dependencies.outbox.rawFallback !== "forbidden"
  ) {
    throw new TypeError("background job delivery outbox is invalid");
  }
  const runOnce = async (): Promise<number> => {
    let remaining = batchSize;
    let terminal = 0;
    const profileIds = new Set<string>();
    for (const profile of dependencies.profiles()) {
      if (remaining < 1 || profileIds.has(profile.definition.id)) continue;
      profileIds.add(profile.definition.id);
      const runtime = dependencies.resolve(profile);
      if (
        !runtime ||
        runtime.receipts.durability !== "durable" ||
        runtime.receipts.polling !== "bounded_active_only" ||
        runtime.receipts.terminalTransition !== "after_delivery_outbox"
      ) {
        continue;
      }
      const at = now();
      const leaseId = `background-job-completion-lease:${randomId()}`;
      const receipts = await runtime.receipts.leaseActive(profile.definition.id, at, remaining, leaseId, at + LEASE_MS);
      if (!Array.isArray(receipts) || receipts.length > remaining) {
        throw new Error("background job active receipt batch is invalid");
      }
      remaining -= receipts.length;
      for (const lease of receipts) {
        const receipt = lease.receipt;
        const expectedOwner: Readonly<BackgroundJobOwner> = Object.freeze({
          ...profile.profile,
          threadTs: receipt.threadTs,
          conversationThreadRef: receipt.conversationThreadRef,
        });
        try {
          if (!backgroundJobReceiptOwned(receipt, expectedOwner, profile)) {
            throw new Error("background job completion owner changed");
          }
          const view = validateBackgroundJobStatusView(
            runtime.adapter.statusView(await runtime.client.status(receipt)),
          );
          if (view.state === "queued" || view.state === "running") {
            await runtime.receipts.retry(receipt, lease.leaseId, nextAttempt(now(), lease.attempt), false, false);
            continue;
          }
          const outcome = backgroundJobStatusOutcome(profile, receipt, view);
          if (!outcome.ok) throw new Error("background job terminal outcome is invalid");
          identifier(receipt.authorityId, "authority id");
          identifier(receipt.runId, "run id");
          const key = deliveryKey(profile, receipt);
          const createdAt = receipt.createdAt;
          if (!Number.isSafeInteger(createdAt) || createdAt < 1) {
            throw new Error("background job delivery time is invalid");
          }
          const intent: Readonly<BackgroundJobDeliveryIntent> = Object.freeze({
            deliveryKey: key,
            jobId: profile.definition.id,
            authorityId: receipt.authorityId,
            runId: receipt.runId,
            ...profile.profile,
            ...profile.binding,
            messageTs: receipt.messageTs,
            threadTs: receipt.threadTs,
            conversationThreadRef: receipt.conversationThreadRef,
            state: view.state,
            text: outcome.message,
            ...(outcome.card ? { card: outcome.card } : {}),
            createdAt,
          });
          await dependencies.outbox.enqueue(intent);
          await runtime.receipts.terminal(receipt, lease.leaseId, view.state, key);
          terminal += 1;
        } catch {
          const failures = lease.failureAttempt + 1;
          await runtime.receipts
            .retry(receipt, lease.leaseId, nextAttempt(now(), failures), failures >= ATTENTION_THRESHOLD, true)
            .catch(() => undefined);
        }
      }
    }
    return terminal;
  };
  const sweeper = createSweeper(runOnce, intervalMs, { label: "background-job-completion", immediate: true });
  return Object.freeze({ runOnce, start: sweeper.start, stop: sweeper.stop });
}
