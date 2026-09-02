import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { createPiHarness } from "../src/harness/pi-harness.ts";
import type { HarnessTurnInput } from "../src/harness/harness.ts";
import {
  groundedWebSearchForActiveModel,
  groundedWebSearchForModel,
  safeGroundedCitationUrl,
  safePublicWebQuery,
} from "../src/model/grounded-web-search.ts";
import { setCustomProviders } from "../src/model/custom-providers.ts";
import { resolveModel } from "../src/model/pi-models.ts";

const PROVIDER = {
  id: "gemini-gateway",
  name: "Gemini Gateway",
  protocol: "openai" as const,
  baseUrl: "http://gemini.internal:8080/v1beta/openai",
  models: [{ id: "gemini-search-test" }],
};

afterEach(() => setCustomProviders([]));

test("grounded search uses the selected custom provider key and returns cited untrusted evidence", async () => {
  setCustomProviders([PROVIDER]);
  const model = resolveModel("gemini-search-test");
  assert.ok(model);
  const requests: Array<{ url: string; init: RequestInit }> = [];
  const search = groundedWebSearchForModel(model, "test-secret", async (input, init) => {
    requests.push({ url: String(input), init: init ?? {} });
    return Response.json({
      steps: [
        { type: "google_search_call", arguments: { queries: ["current Acme news"] } },
        {
          type: "model_output",
          content: [
            {
              type: "text",
              text: "Acme announced a new campus yesterday.",
              annotations: [
                {
                  type: "url_citation",
                  url: "https://news.example.com/acme?story=1",
                  title: "News Example",
                  start_index: 0,
                  end_index: 38,
                },
              ],
            },
          ],
        },
      ],
    });
  });
  assert.ok(search);
  const result = await search("What is the latest public news about Acme?");
  assert.equal(requests.length, 1);
  const request = requests[0]!;
  assert.equal(request.url, "http://gemini.internal:8080/v1beta/interactions");
  assert.equal((request.init.headers as Record<string, string>).authorization, "Bearer test-secret");
  assert.deepEqual(JSON.parse(String(request.init.body)), {
    model: "gemini-search-test",
    input: "What is the latest public news about Acme?",
    tools: [{ type: "google_search" }],
  });
  assert.equal(result.provider, "google_search_grounding");
  assert.equal(result.disposition, "untrusted_public_web_evidence");
  assert.deepEqual(result.queries, ["current Acme news"]);
  assert.deepEqual(result.citations, [
    {
      id: "WEB-1",
      title: "News Example",
      url: "https://news.example.com/acme?story=1",
      citedText: "Acme announced a new campus yesterday.",
    },
  ]);
  assert.equal(JSON.stringify(result).includes("test-secret"), false);
});

test("grounded search is absent for other provider shapes or without a provider key", () => {
  setCustomProviders([{ ...PROVIDER, baseUrl: "https://example.com/v1" }]);
  const model = resolveModel("gemini-search-test");
  assert.ok(model);
  assert.equal(groundedWebSearchForModel(model, "test-secret"), undefined);
  setCustomProviders([{ ...PROVIDER, models: [{ id: "other-model" }] }]);
  assert.equal(groundedWebSearchForModel(resolveModel("other-model")!, "test-secret"), undefined);
  setCustomProviders([{ ...PROVIDER, protocol: "anthropic" }]);
  assert.equal(groundedWebSearchForModel(resolveModel("gemini-search-test")!, "test-secret"), undefined);
  setCustomProviders([PROVIDER]);
  assert.equal(groundedWebSearchForModel(resolveModel("gemini-search-test")!, undefined), undefined);
});

test("grounded search rejects uncited and unsafe-citation responses", async () => {
  setCustomProviders([PROVIDER]);
  const model = resolveModel("gemini-search-test")!;
  for (const url of [
    "https://127.0.0.1/private",
    "https://[::]/private",
    "https://[::ffff:7f00:1]/private",
    "https://100.64.0.1/private",
    "https://198.18.0.1/private",
    "https://224.0.0.1/private",
    "https://service.internal/private",
    "https://localhost./private",
    "https://service.internal./private",
    "https://service。internal。/private",
    "https://127.0.0.1./private",
    "https://metadata/private",
    "https://bücher.example/private",
    "https://xn--bcher-kva.example/private",
    "https://[2002:7f00:1::]/private",
    "https://example.localhost/private",
    "https://example.test/private",
    "http://public.example.com/insecure",
  ]) {
    assert.equal(safeGroundedCitationUrl(url), undefined, url);
  }
  assert.equal(safeGroundedCitationUrl("https://[2606:4700:4700::1111]/dns"), "https://[2606:4700:4700::1111]/dns");
  assert.equal(safeGroundedCitationUrl("https://public.example.com/news"), "https://public.example.com/news");
  const search = groundedWebSearchForModel(model, "test-secret", async () =>
    Response.json({
      steps: [
        {
          type: "model_output",
          content: [
            {
              type: "text",
              text: "Unsafe result",
              annotations: [
                {
                  type: "url_citation",
                  url: "https://127.0.0.1/private",
                  title: "Local",
                  start_index: 0,
                  end_index: 6,
                },
              ],
            },
          ],
        },
      ],
    }),
  )!;
  await assert.rejects(() => search("public query"), /no safe citations/);
});

test("the per-turn model override controls whether grounded search is exposed", async () => {
  setCustomProviders([PROVIDER]);
  const seenTools: string[][] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (_input, init) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as { tools?: Array<{ function?: { name?: string } }> };
    seenTools.push((body.tools ?? []).map((tool) => tool.function?.name ?? ""));
    const event = {
      id: "cmpl-test",
      object: "chat.completion.chunk",
      model: "gemini-search-test",
      choices: [{ index: 0, delta: { role: "assistant", content: "Done" }, finish_reason: "stop" }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    };
    return new Response(`data: ${JSON.stringify(event)}\n\ndata: [DONE]\n\n`, {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    });
  }) as typeof fetch;
  try {
    const harness = createPiHarness({ defaultModelId: "gpt-5.6-sol" });
    const turn: HarnessTurnInput = {
      session: { id: "grounded-model-override" } as HarnessTurnInput["session"],
      input: "hello",
      systemPrompt: "Answer briefly.",
      history: [],
      tools: {} as HarnessTurnInput["tools"],
      scopeLabel: "personal:test" as HarnessTurnInput["scopeLabel"],
      orgScopeId: "org:test" as HarnessTurnInput["orgScopeId"],
      emit: async (entry) => ({ ...entry, seq: 1 }) as Awaited<ReturnType<HarnessTurnInput["emit"]>>,
      recordModelCall: () => {},
      model: "gemini-search-test",
      providerKeys: { "gemini-gateway": "test-secret" },
    };
    await harness.turns.runTurn(turn);
    assert.ok(seenTools[0]?.includes("web_search"), JSON.stringify(seenTools));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("a provider fallback cannot reuse the original model's grounded search key", async () => {
  setCustomProviders([PROVIDER]);
  const model = resolveModel("gemini-search-test")!;
  let activeModelId = model.id;
  let fetches = 0;
  const search = groundedWebSearchForActiveModel(
    model,
    "test-secret",
    () => activeModelId,
    async () => {
      fetches += 1;
      return assert.fail("provider fetch was not expected after fallback");
    },
  );
  assert.ok(search);
  activeModelId = "claude-opus-5";
  await assert.rejects(() => search("public Acme news"), /unavailable after a provider fallback/);
  assert.equal(fetches, 0);
});

test("grounded search accepts only bounded public queries", () => {
  assert.equal(
    safePublicWebQuery("latest public news about Acme University"),
    "latest public news about Acme University",
  );
  for (const query of [
    "email alice@example.com about this",
    "use api key abc123",
    "look up Google Calendar event abc",
    "find private transcript details",
    "search confidential customer record 12345 from the internal roadmap",
    "search customer-record 12345",
    "search customer_record 12345",
    "search the email subject acquisition timetable",
    "search transcript from the sales call",
    "search privately shared launch plan",
    "search the credential secret abc123",
    "search Slack DM from Alice about acquisition",
    "search Command Center receipt",
    "token 0123456789abcdef0123456789abcdef",
    "customer 123e4567-e89b-12d3-a456-426614174000",
  ]) {
    assert.equal(safePublicWebQuery(query), undefined, query);
  }
});

test("grounded search rejects noncanonical cited text and aggregate oversized answers", async () => {
  setCustomProviders([PROVIDER]);
  const model = resolveModel("gemini-search-test")!;
  const noncanonical = groundedWebSearchForModel(model, "test-secret", async () =>
    Response.json({
      steps: [
        {
          type: "model_output",
          content: [
            {
              type: "text",
              text: " Leading text",
              annotations: [
                {
                  type: "url_citation",
                  url: "https://public.example.com/news",
                  title: "Public",
                  start_index: 1,
                  end_index: 8,
                },
              ],
            },
          ],
        },
      ],
    }),
  )!;
  await assert.rejects(() => noncanonical("public news"), /no answer/);

  const oversized = groundedWebSearchForModel(model, "test-secret", async () =>
    Response.json({
      steps: [
        { type: "model_output", content: [{ type: "text", text: "a".repeat(9_000) }] },
        {
          type: "model_output",
          content: [
            {
              type: "text",
              text: "b".repeat(8_000),
              annotations: [
                {
                  type: "url_citation",
                  url: "https://public.example.com/news",
                  title: "Public",
                  start_index: 0,
                  end_index: 10,
                },
              ],
            },
          ],
        },
      ],
    }),
  )!;
  await assert.rejects(() => oversized("public news"), /answer exceeded/);
});

test("grounded search rejects invalid queries, oversized responses, and provider failures", async () => {
  setCustomProviders([PROVIDER]);
  const model = resolveModel("gemini-search-test")!;
  const never = groundedWebSearchForModel(model, "test-secret", async () => assert.fail("fetch was not expected"))!;
  await assert.rejects(() => never("\u0001"), /query must be/);
  const failed = groundedWebSearchForModel(model, "test-secret", async () => new Response("no", { status: 503 }))!;
  await assert.rejects(() => failed("public query"), /HTTP 503/);
  const oversized = groundedWebSearchForModel(
    model,
    "test-secret",
    async () => new Response("x".repeat(512 * 1024 + 1)),
  )!;
  await assert.rejects(() => oversized("public query"), /size limit/);
});
