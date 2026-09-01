import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { deploymentLayerBundle } from "../cli/src/deployment-layer.ts";
import {
  createDurableBackgroundJobApprovalLedger,
  type BackgroundJobApprovalLedgerRecord,
} from "../src/background-jobs/approval-ledger.ts";
import {
  createDeploymentLayerStore,
  type DeploymentLayerBundle,
  type StoredDeploymentLayer,
} from "../src/deployment/deployment-layer-store.ts";
import { emptyDeploymentLayer } from "../src/deployment/load-layer.ts";
import { createMemoryMap } from "../src/persistence/durable-map.ts";
import { createSkillStore } from "../src/skills/skill-store.ts";
import { scopeId } from "../src/types.ts";
import { backgroundJobProfileJson } from "./support/background-job-profile.ts";

test("CLI filesystem bundles survive durable restart, disable, removal, and permanent retirement", async () => {
  const sandbox = mkdtempSync(join(tmpdir(), "qm-background-job-layer-"));
  const jobDir = join(sandbox, "background-jobs", "proposal-job");
  mkdirSync(jobDir, { recursive: true });
  writeFileSync(join(jobDir, "job.json"), backgroundJobProfileJson("proposal-job"));
  const cliBundle = deploymentLayerBundle(sandbox);
  const bundle: DeploymentLayerBundle = {
    contract: 1,
    tools: cliBundle.tools,
    skills: cliBundle.skills,
    backgroundJobs: cliBundle.backgroundJobs,
  };
  const durableLayer = createMemoryMap<StoredDeploymentLayer>();
  const durableApprovals = createMemoryMap<BackgroundJobApprovalLedgerRecord>();
  const retirement = createDurableBackgroundJobApprovalLedger({
    backing: durableApprovals,
    durable: true,
    now: () => 1_788_030_002_000,
    terminalAndExpired: async () => true,
  });
  const createStore = (runtime: ReturnType<typeof emptyDeploymentLayer>) =>
    createDeploymentLayerStore({
      backing: durableLayer,
      runtime,
      skills: createSkillStore({ signingSecret: "background-job-layer-test" }),
      scopeId: scopeId("org", "example"),
      durable: true,
      backgroundJobRetirement: retirement,
    });
  const firstRuntime = emptyDeploymentLayer();
  await createStore(firstRuntime).put(bundle, "test:cli");
  assert.deepEqual(
    firstRuntime.backgroundJobs.map((profile) => profile.definition.id),
    ["proposal-job"],
  );
  assert.equal(firstRuntime.backgroundJobs[0]?.enabled, true);
  const restartedRuntime = emptyDeploymentLayer();
  const restarted = createStore(restartedRuntime);
  await restarted.hydrate();
  assert.equal(restartedRuntime.backgroundJobs[0]?.enabled, true);
  await restarted.put(
    {
      ...bundle,
      backgroundJobs: bundle.backgroundJobs?.map((file) => ({ ...file, enabled: false })),
    },
    "test:disable",
  );
  assert.equal(restartedRuntime.backgroundJobs[0]?.enabled, false);
  const disabledRestartRuntime = emptyDeploymentLayer();
  const disabledRestart = createStore(disabledRestartRuntime);
  await disabledRestart.hydrate();
  assert.equal(disabledRestartRuntime.backgroundJobs[0]?.enabled, false);
  await disabledRestart.put({ ...bundle, backgroundJobs: [] }, "test:remove");
  assert.deepEqual(disabledRestartRuntime.backgroundJobs, []);
  await assert.rejects(() => disabledRestart.put(bundle, "test:restore"), /permanently retired/);
});
