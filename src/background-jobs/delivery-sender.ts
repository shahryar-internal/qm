import { randomUUID } from "node:crypto";
import { createSweeper, type Sweeper } from "../util/sweeper.ts";
import type { BackgroundJobDeliveryOutbox, BackgroundJobRenderOnlySender } from "./types.ts";
import { identifier } from "./validation.ts";

export interface BackgroundJobDeliverySchedulerDependencies {
  outbox: BackgroundJobDeliveryOutbox;
  sender: BackgroundJobRenderOnlySender;
  batchSize?: number;
  intervalMs?: number;
  now?: () => number;
  randomId?: () => string;
}

export interface BackgroundJobDeliveryScheduler extends Sweeper {
  runOnce(): Promise<number>;
}

const LEASE_MS = 30_000;
const ATTENTION_THRESHOLD = 8;

function retryAt(now: number, attempt: number): number {
  return now + Math.min(5 * 60_000, 1_000 * 2 ** Math.min(attempt - 1, 12));
}

export function createBackgroundJobDeliveryScheduler(
  dependencies: Readonly<BackgroundJobDeliverySchedulerDependencies>,
): BackgroundJobDeliveryScheduler {
  const batchSize = dependencies.batchSize ?? 25;
  const intervalMs = dependencies.intervalMs ?? 2_000;
  const now = dependencies.now ?? Date.now;
  const randomId = dependencies.randomId ?? randomUUID;
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 100) {
    throw new TypeError("background job delivery batch size is invalid");
  }
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 1_000 || intervalMs > 60_000) {
    throw new TypeError("background job delivery interval is invalid");
  }
  if (
    dependencies.outbox.transport !== "slack_first_party_render_only" ||
    dependencies.outbox.rawFallback !== "forbidden" ||
    dependencies.sender.transport !== "slack_first_party_render_only" ||
    dependencies.sender.rawFallback !== "forbidden" ||
    dependencies.sender.idempotency !== "durable_delivery_key"
  ) {
    throw new TypeError("background job render-only delivery is unavailable");
  }
  const runOnce = async (): Promise<number> => {
    if (!dependencies.outbox.readiness().ready || !dependencies.sender.readiness().ready) return 0;
    const at = now();
    const leaseId = `background-job-delivery-lease:${randomId()}`;
    const leases = await dependencies.outbox.lease(at, batchSize, leaseId, at + LEASE_MS);
    let sent = 0;
    for (const lease of leases) {
      try {
        identifier(lease.intent.deliveryKey, "delivery key");
        if (lease.leaseId !== leaseId) {
          throw new Error("background job delivery lease is invalid");
        }
        await dependencies.sender.send(lease.intent, lease.intent.deliveryKey);
        await dependencies.outbox.sent(lease.intent.deliveryKey, lease.leaseId, now());
        sent += 1;
      } catch {
        await dependencies.outbox
          .retry(
            lease.intent.deliveryKey,
            lease.leaseId,
            retryAt(now(), lease.attempt),
            lease.attempt >= ATTENTION_THRESHOLD,
          )
          .catch(() => undefined);
      }
    }
    return sent;
  };
  const sweeper = createSweeper(runOnce, intervalMs, { label: "background-job-delivery", immediate: true });
  return Object.freeze({ runOnce, start: sweeper.start, stop: sweeper.stop });
}
