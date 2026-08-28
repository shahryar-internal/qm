import "./support/auto-fake-sprites.ts";

import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, afterEach } from "node:test";
import { createInsecureTestServer } from "../src/api/server.ts";
import { buildApp, serverDeps } from "../src/wiring.ts";
import { testConfig } from "./support/test-config.ts";
import { defaultModelForHarness } from "../src/model/pi-models.ts";
import { setCustomProviders } from "../src/model/custom-providers.ts";
import { DEV_GEMINI_MODEL, devGeminiProviderFromEnv } from "../src/model/dev-gemini-provider.ts";

const ADMIN = { "content-type": "application/json", "x-admin-actor": "admin-alice@default-org" };

afterEach(() => setCustomProviders([]));

test("serverDeps wires the custom-provider store and resolves a custom boot default lazily", async () => {
  const config = testConfig({
    dataDir: mkdtempSync(join(tmpdir(), "custom-provider-boot-")),
    harness: "pi",
    modelId: "acme-large",
  });
  const built = buildApp(config, { modelCredentialFetch: async () => new Response(null, { status: 200 }) });
  const deps = serverDeps(config, built);
  assert.equal(deps.customProviders, built.customProviders);
  assert.equal(deps.refreshCustomProviders, built.refreshCustomProviders);
  assert.equal(deps.baseModelDefault, "acme-large");

  const server = createInsecureTestServer(built.app, deps);
  server.listen(0);
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  try {
    assert.notEqual(defaultModelForHarness("pi", deps.baseModelDefault), "acme-large");

    const list = await fetch(`${base}/v1/admin/custom-providers`, { headers: ADMIN });
    assert.equal(list.status, 200);

    const put = await fetch(`${base}/v1/admin/custom-providers/acme-gateway`, {
      method: "PUT",
      headers: ADMIN,
      body: JSON.stringify({
        name: "Acme Gateway",
        protocol: "openai",
        baseUrl: "https://llm.acme.internal/v1",
        models: [{ id: "acme-large", name: "Acme Large" }],
        apiKey: "sk-acme-secret",
        validate: false,
      }),
    });
    assert.equal(put.status, 200);

    assert.equal(defaultModelForHarness("pi", deps.baseModelDefault), "acme-large");

    const runtime = await fetch(
      `${base}/v1/runtime-config?principalId=admin-alice@default-org&scopeId=personal:admin-alice@default-org`,
      { headers: ADMIN },
    );
    assert.equal(runtime.status, 200);
    const body = (await runtime.json()) as {
      effective: { modelId: string };
      modelsByHarness: Record<string, string[]>;
      modelCatalog: Record<string, { name: string; provider: string }>;
    };
    assert.equal(body.effective.modelId, "acme-large");
    assert.ok(body.modelsByHarness.pi?.includes("acme-large"));
    assert.equal(body.modelCatalog["acme-large"]?.provider, "acme-gateway");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("the transient dev provider pins both runtime APIs despite durable or requested drift", async () => {
  const devGeminiProvider = devGeminiProviderFromEnv({
    DEV_INSTANCE_GEMINI_PROVIDER: "1",
    GEMINI_API_KEY: "transient-test-key",
    HARNESS: "pi",
  });
  assert.ok(devGeminiProvider);
  const config = testConfig({
    dataDir: mkdtempSync(join(tmpdir(), "gemini-provider-boot-")),
    harness: "pi",
    modelId: DEV_GEMINI_MODEL,
    devGeminiProvider,
  });
  const built = buildApp(config);
  await built.refreshCustomProviders();
  built.config.setApprovedHarnesses(["codex"]);
  built.config.setRuntimeSelection("org:default-org", { harnessId: "codex", modelId: "gpt-5.5" });
  built.config.setRuntimeSelection("personal:admin-alice@default-org", {
    harnessId: "claude",
    modelId: "claude-opus-5",
  });
  await built.config.flushScope("org:default-org");
  await built.config.flushScope("personal:admin-alice@default-org");
  const deps = serverDeps(config, built);
  assert.deepEqual(deps.runtimeChoiceOverride, { harnessId: "pi", modelId: DEV_GEMINI_MODEL });

  const server = createInsecureTestServer(built.app, deps);
  server.listen(0);
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const target = "principalId=admin-alice@default-org&scopeId=personal:admin-alice@default-org";
  try {
    const runtime = await fetch(`${base}/v1/runtime-config?${target}`);
    const body = (await runtime.json()) as {
      approvedHarnesses: string[];
      modelsByHarness: Record<string, string[]>;
      effective: { harnessId: string; modelId: string };
    };
    assert.equal(runtime.status, 200);
    assert.deepEqual(body.approvedHarnesses, ["pi"]);
    assert.deepEqual(body.modelsByHarness, { pi: [DEV_GEMINI_MODEL] });
    assert.deepEqual(body.effective, { harnessId: "pi", modelId: DEV_GEMINI_MODEL });

    const admitted = await built.app.turn({
      surface: "web",
      actor: { externalId: "admin-alice@default-org" },
      conversation: { kind: "dm", threadRef: "web:admin-alice@default-org:gemini-admission" },
      text: "admission only",
      harness: "pi",
      model: DEV_GEMINI_MODEL,
      async: true,
    });
    assert.notEqual(admitted.status, "refused", JSON.stringify(admitted));
    assert.equal(
      (await built.slackCore.surfaceHeaderFacts("personal:admin-alice@default-org")).modelName,
      "Gemini 3.7 Flash",
    );

    const surface = await fetch(`${base}/v1/surface-config`);
    const surfaceBody = (await surface.json()) as { harnessId: string; baseModel: string; webuiModels: string[] };
    assert.equal(surface.status, 200);
    assert.equal(surfaceBody.harnessId, "pi");
    assert.equal(surfaceBody.baseModel, DEV_GEMINI_MODEL);
    assert.deepEqual(surfaceBody.webuiModels, [DEV_GEMINI_MODEL]);

    const drift = await fetch(`${base}/v1/runtime-config`, {
      method: "PUT",
      headers: ADMIN,
      body: JSON.stringify({
        principalId: "admin-alice@default-org",
        scopeId: "personal:admin-alice@default-org",
        harnessId: "codex",
        modelId: "gpt-5.5",
      }),
    });
    assert.equal(drift.status, 400);
    assert.equal(((await drift.json()) as { error: string }).error, "runtime_fixed");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
