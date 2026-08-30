import assert from "node:assert/strict";
import { test } from "node:test";
import { createBackgroundJobAttentionReader } from "../src/background-jobs/attention.ts";
import type { BackgroundJobDeliveryOutbox, BackgroundJobReceiptStore } from "../src/background-jobs/types.ts";

test("manual attention is bounded, sorted, and strips durable record keys and payload data", async () => {
  const secret = "approval-token-and-private-payload";
  const receipts = {
    manualAttention: async () => [
      { kind: "admission" as const, key: `${secret}:old`, jobId: "proposal", attempt: 8, requiredAt: 10 },
      { kind: "completion" as const, key: `${secret}:new`, jobId: "research", attempt: 9, requiredAt: 30 },
    ],
  } as unknown as BackgroundJobReceiptStore;
  const outbox = {
    manualAttention: async () => [
      { kind: "delivery" as const, key: `${secret}:middle`, jobId: "proposal", attempt: 10, requiredAt: 20 },
    ],
  } as unknown as BackgroundJobDeliveryOutbox;
  const reader = createBackgroundJobAttentionReader(receipts, outbox);
  const rows = await reader.list(2);
  assert.deepEqual(
    rows.map((row) => ({ source: row.source, jobId: row.jobId, attempt: row.attempt, requiredAt: row.requiredAt })),
    [
      { source: "completion", jobId: "research", attempt: 9, requiredAt: 30 },
      { source: "delivery", jobId: "proposal", attempt: 10, requiredAt: 20 },
    ],
  );
  assert.match(rows[0]!.recordRef, /^[a-f0-9]{24}$/);
  assert.equal(JSON.stringify(rows).includes(secret), false);
  await assert.rejects(reader.list(0), /integer from 1 through 100/);
  await assert.rejects(reader.list(101), /integer from 1 through 100/);
});
