import type { DurableMap } from "../persistence/durable-map.ts";
import type { PendingApprovalRecord } from "../types.ts";

export async function invalidatePendingBackgroundJobApprovals(
  approvals: DurableMap<PendingApprovalRecord>,
): Promise<number> {
  let invalidated = 0;
  for (const [key, pending] of await approvals.entries()) {
    if (pending.kind !== "background_job") continue;
    await approvals.delete(key);
    invalidated += 1;
  }
  return invalidated;
}
