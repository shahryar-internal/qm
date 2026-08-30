import { createHash } from "node:crypto";
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
}

export interface BackgroundJobCompletionPoller extends Sweeper {
  runOnce(): Promise<number>;
}

function deliveryKey(profile: Readonly<BackgroundJobDeploymentProfile>, authorityId: string, runId: string): string {
  return `background-job-delivery:${createHash("sha256")
    .update(
      canonicalJson({
        authorityId,
        descriptorSha256: profile.binding.descriptorSha256,
        jobId: profile.definition.id,
        runId,
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
      const receipts = await runtime.receipts.active(profile.definition.id, remaining);
      if (!Array.isArray(receipts) || receipts.length > remaining) {
        throw new Error("background job active receipt batch is invalid");
      }
      remaining -= receipts.length;
      for (const receipt of receipts) {
        const expectedOwner: Readonly<BackgroundJobOwner> = Object.freeze({
          ...profile.profile,
          threadTs: receipt.threadTs,
        });
        if (!backgroundJobReceiptOwned(receipt, expectedOwner, profile)) continue;
        const view = validateBackgroundJobStatusView(runtime.adapter.statusView(await runtime.client.status(receipt)));
        if (view.state === "queued" || view.state === "running") continue;
        const outcome = backgroundJobStatusOutcome(profile, receipt, view);
        if (!outcome.ok) throw new Error("background job terminal outcome is invalid");
        identifier(receipt.authorityId, "authority id");
        identifier(receipt.runId, "run id");
        const key = deliveryKey(profile, receipt.authorityId, receipt.runId);
        const createdAt = now();
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
          state: view.state,
          text: outcome.message,
          ...(outcome.card ? { card: outcome.card } : {}),
          createdAt,
        });
        await dependencies.outbox.enqueue(intent);
        await runtime.receipts.terminal(receipt, view.state, key);
        terminal += 1;
      }
    }
    return terminal;
  };
  const sweeper = createSweeper(runOnce, intervalMs, { label: "background-job-completion", immediate: true });
  return Object.freeze({ runOnce, start: sweeper.start, stop: sweeper.stop });
}
