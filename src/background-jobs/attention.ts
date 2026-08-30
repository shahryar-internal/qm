import { createHash } from "node:crypto";
import type { BackgroundJobDeliveryOutbox, BackgroundJobReceiptStore } from "./types.ts";

export interface BackgroundJobAttentionView {
  source: "admission" | "control" | "completion" | "delivery";
  recordRef: string;
  jobId: string;
  attempt: number;
  requiredAt: number;
}

export interface BackgroundJobAttentionReader {
  list(limit: number): Promise<readonly Readonly<BackgroundJobAttentionView>[]>;
}

export function createBackgroundJobAttentionReader(
  receipts: BackgroundJobReceiptStore,
  outbox: BackgroundJobDeliveryOutbox,
): BackgroundJobAttentionReader {
  return Object.freeze({
    async list(limit: number) {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
        throw new TypeError("background job attention limit must be an integer from 1 through 100");
      }
      const [receiptRows, deliveryRows] = await Promise.all([receipts.manualAttention(), outbox.manualAttention()]);
      return Object.freeze(
        [...receiptRows, ...deliveryRows]
          .sort((left, right) => right.requiredAt - left.requiredAt || left.key.localeCompare(right.key))
          .slice(0, limit)
          .map((entry) =>
            Object.freeze({
              source: entry.kind,
              recordRef: createHash("sha256").update(entry.key).digest("hex").slice(0, 24),
              jobId: entry.jobId,
              attempt: entry.attempt,
              requiredAt: entry.requiredAt,
            }),
          ),
      );
    },
  });
}
