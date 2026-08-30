import assert from "node:assert/strict";
import { test } from "node:test";
import { createBackgroundJobProductionComposition } from "../src/background-jobs/composition.ts";
import { invalidatePendingBackgroundJobApprovals } from "../src/background-jobs/pending-approvals.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import type { PendingApprovalRecord } from "../src/types.ts";
import { buildApp } from "../src/wiring.ts";
import { testConfig } from "./support/test-config.ts";

test("canonical buildApp constructs the core registry and remains hidden without private dependencies", async () => {
  const built = buildApp(testConfig({ backgroundWorkEnabled: true }));
  await built.deploymentLayerReady;
  const runtime = await built.backgroundJobRuntimeReady;
  assert.ok(runtime);
  assert.deepEqual(runtime.visibleProfiles(), []);
  assert.deepEqual(runtime.controlProfiles(), []);
  assert.equal(runtime.service.readiness().ready, false);
  assert.deepEqual(built.jobAuthorityJwks().keys, []);
});

test("production composition resolves only explicitly supplied named dependencies", () => {
  const dependency = {
    adapter: { readiness: () => ({ ready: true as const }) },
    parsers: {},
  } as never;
  const composition = createBackgroundJobProductionComposition({ adapters: { "private-v1": dependency } });
  assert.equal(composition.registry.resolveAdapter("private-v1"), dependency);
  assert.equal(composition.registry.resolveAdapter("missing"), undefined);
  assert.equal(composition.sender.readiness().ready, false);
  assert.equal(composition.receiptStoreName, "background_job_records");
  assert.equal(composition.approvalStoreName, "background_job_approval_ledger");
});

test("a disabled restart durably invalidates only background-job approvals before re-enable", async () => {
  const approvals = createMemoryMap<PendingApprovalRecord>();
  await approvals.put("stale-job", {
    sessionId: "session-1",
    command: "start job",
    kind: "background_job",
  });
  await approvals.put("ordinary", {
    sessionId: "session-1",
    command: "read data",
    kind: "approval",
  });
  assert.equal(await invalidatePendingBackgroundJobApprovals(approvals), 1);
  assert.equal(await approvals.get("stale-job"), null);
  assert.ok(await approvals.get("ordinary"));
  assert.equal(await invalidatePendingBackgroundJobApprovals(approvals), 0);
  assert.equal(await approvals.get("stale-job"), null);
});
