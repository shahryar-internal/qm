import assert from "node:assert/strict";
import { test } from "node:test";
import { WORKFLOW_ARTIFACT_MIME } from "../plugins/chassis/src/workflow-artifact.ts";
import { enforceSlackEvidenceDelivery } from "../src/slack/evidence-delivery.ts";
import type { OutgoingAttachment, TurnResult } from "../src/types.ts";

const sourcedReply = "Activation improved by four points. Source: Analytics · Observed: 2026-09-02 · Link: unavailable";
const linkedReply =
  "Activation improved by four points. Source: Analytics · Observed: 2026-09-02 · Link: https://analytics.example.com/insights/activation";
const allowedLink = "https://analytics.example.com/insights/activation";
const unlinkedSource = [{ sourceType: "Analytics", observedAt: "2026-09-02T17:00:00.000Z", links: [] }];
const linkedSource = [{ sourceType: "Analytics", observedAt: "2026-09-02T17:00:00.000Z", links: [allowedLink] }];
const attachment: OutgoingAttachment = {
  name: "brief.workflow.json",
  mimetype: WORKFLOW_ARTIFACT_MIME,
  sizeBytes: 1,
  blobId: "blob-1",
  renderOnly: true,
};
const card = (item: Record<string, unknown> = {}, summary = sourcedReply) =>
  Buffer.from(
    JSON.stringify({
      version: 1,
      renderer: "qm.card.v1",
      fallbackText: "Account health brief",
      payload: {
        heading: "Account health",
        summary,
        sections: [
          {
            key: "evidence",
            label: "Evidence",
            items: [
              {
                label: "Analytics · observed 2026-09-02",
                value: "Activation improved by four points. Link unavailable.",
                ...item,
              },
            ],
          },
        ],
      },
    }),
  );
const result = (overrides: Partial<TurnResult> = {}): TurnResult => ({
  status: "ok",
  reply: sourcedReply,
  attachments: [attachment],
  deliveryEvidenceSources: unlinkedSource,
  ...overrides,
});

test("complete simple and substantial evidence deliveries pass unchanged", async () => {
  const simple = result({ attachments: undefined });
  assert.deepEqual(
    await enforceSlackEvidenceDelivery("How did analytics change this week?", simple, async () => card()),
    { result: simple, blocked: false },
  );
  const linked = result({ reply: linkedReply, attachments: undefined, deliveryEvidenceSources: linkedSource });
  assert.deepEqual(
    await enforceSlackEvidenceDelivery("How did analytics change this week?", linked, async () => card()),
    { result: linked, blocked: false },
  );
  const substantial = result();
  assert.deepEqual(
    await enforceSlackEvidenceDelivery("Give me an account health brief", substantial, async () => card()),
    { result: substantial, blocked: false },
  );
});

test("acknowledgements, non-evidence turns, and approval controls are exempt", async () => {
  let fetches = 0;
  const fetch = async () => {
    fetches++;
    return card();
  };
  const plain = result({ reply: "You're welcome.", attachments: undefined, deliveryEvidenceSources: undefined });
  assert.equal((await enforceSlackEvidenceDelivery("Thanks!", plain, fetch)).blocked, false);
  assert.equal((await enforceSlackEvidenceDelivery("Draft a friendly greeting", plain, fetch)).blocked, false);
  assert.equal(
    (await enforceSlackEvidenceDelivery("Write a friendly email inviting Sam to lunch", plain, fetch)).blocked,
    false,
  );
  assert.equal(
    (await enforceSlackEvidenceDelivery("Draft calendar invite copy for lunch", plain, fetch)).blocked,
    false,
  );
  assert.equal(
    (await enforceSlackEvidenceDelivery("Write a limerick about how many chats a robot has", plain, fetch)).blocked,
    false,
  );
  assert.equal((await enforceSlackEvidenceDelivery("Design a chat counter button", plain, fetch)).blocked, false);
  const approval = result({ pendingApprovals: [{ requestId: "approval-1", command: "write", reason: "write" }] });
  assert.equal((await enforceSlackEvidenceDelivery("Update the Notion plan", approval, fetch)).blocked, false);
  assert.equal(fetches, 0);
});

test("gated evidence turns fail safe instead of delivering non-workflow attachments", async () => {
  for (const name of ["raw-results.json", "raw-results.txt"]) {
    const checked = await enforceSlackEvidenceDelivery(
      "How did analytics change this week?",
      result({
        attachments: [
          {
            name,
            mimetype: name.endsWith(".json") ? "application/json" : "text/plain",
            sizeBytes: 64,
            blobId: `blob-${name}`,
          },
        ],
      }),
      async () => Buffer.from("raw analytics payload"),
    );
    assert.equal(checked.blocked, true, name);
    assert.equal(checked.reason, "attachment", name);
    assert.equal(checked.result.attachments, undefined, name);
  }

  const requestedFile = result({
    reply: "Created the requested sample.",
    attachments: [{ name: "sample.json", mimetype: "application/json", sizeBytes: 2, blobId: "blob-sample" }],
    deliveryEvidenceSources: undefined,
  });
  const exempt = await enforceSlackEvidenceDelivery("Create a sample JSON file", requestedFile, async () =>
    Buffer.from("{}"),
  );
  assert.deepEqual(exempt, { result: requestedFile, blocked: false });
});

test("explicit evidence intent gates strategic and named-account requests without relying on a tool trace", async () => {
  const plain = result({
    reply: "Use a focused launch plan.",
    attachments: undefined,
    deliveryEvidenceSources: undefined,
  });
  for (const request of [
    "Give me a strategic recommendation for Acme",
    "Tell me how ACME is doing",
    "How is ACME doing?",
    "How's ACME doing?",
    "What about ACME?",
    "How are we doing?",
    "Give me an ACME update",
    "Review tomorrow's calendar",
    "how many chats were created in the last 7 days for Example University",
    "Who founded Stripe?",
    "Can you tell me who founded Stripe?",
    "Give me OpenAI current pricing",
    "Provide OpenAI current pricing",
    "Find me OpenAI current pricing",
    "Research Stripe founders",
    "Check OpenAI current pricing",
    "Look up Stripe founders",
    "Tell me OpenAI current pricing",
    "Report Stripe founders",
    "Show me OpenAI current pricing",
    "Fetch Stripe founders",
    "Retrieve OpenAI current pricing",
    "Verify Stripe founders",
    "Investigate OpenAI current pricing",
    "Outline Stripe founders",
    "Update me on EXAMPLECO",
    "Run research on Stripe",
    "Create an account health brief",
    "Execute a market analysis",
    "Perform a competitor review",
    "Draft an account health brief for EXAMPLECO",
    "Write a current market analysis",
    "Design a competitor comparison",
    "Give me ideas based on our latest analytics",
    "Write a report on Stripe founders",
    "Draft a summary of OpenAI pricing",
    "Design a competitor analysis",
    "Compose an account brief for EXAMPLECO",
    "Brainstorm a report on Stripe founders",
    "Write a note about Stripe founders",
    "Compose a document on Apollo history",
    "Draft an email and report Stripe founders",
    "Send an email and tell me Stripe founders",
    "Create a task and explain quantum computing",
    "Draft an email, then report Stripe founders",
    "Create a task plus explain quantum computing",
    "Draft an email and review Stripe founders",
    "Draft an email and summarize the Apollo program",
    "Write a post and assess Stripe founders",
    "Compose an email plus review the Apollo program",
    "Draft an email reviewing Stripe founders",
    "Write a post summarizing the Apollo program",
    "Compose an email describing Stripe founders",
    "Draft a post about Apollo history",
    "Draft an email while reviewing Stripe founders",
    "What is OpenAI's current pricing?",
    "What's OpenAI's current pricing?",
    "Tell me about the Apollo program",
    "Explain quantum computing",
    "Please explain quantum computing",
    "Describe Stripe",
    "List the top CRM vendors",
  ]) {
    const checked = await enforceSlackEvidenceDelivery(request, plain, async () => card());
    assert.equal(checked.blocked, true, request);
    assert.equal(checked.reason, "reply", request);
  }
  for (const request of [
    "Write a story about who founded a fictional company",
    "Draft copy for a pricing page",
    "How do I write a friendly invitation?",
    "What should I name a new product?",
    "How are you?",
    "What are your capabilities?",
    "What are your Gmail capabilities?",
    "Who are you?",
    "Draft calendar invite copy",
    "Can you write a friendly email?",
    "What should I do with this?",
    "@agent is this possible?",
    "Are you still working?",
    "How are we doing on this task?",
    "What are you working on?",
    "Can you make this more concise?",
    "Should I prioritize this?",
    "Would you help me think through this?",
    "Summarize this email",
    "Can you summarize the following message?",
    "Check this draft for tone",
    'Summarize the following email: "Hello Sam, the launch is Tuesday."',
    "Summarize this text:\n```text\nThe launch is Tuesday.\n```",
    "Can you summarize the following message?\n```\nPlease bring the report.\n```",
    "Summarize this text:\n```text\n    ```\nThe launch is Tuesday.\n```",
    "Summarize this text:\n~~~text\nThe launch is Tuesday.\n~~~",
    'Check this draft for tone: "Hello Sam, send this today."',
    'Repeat the words: "benign update"',
    "Hello!",
    "Tell me a joke",
    "Create a sample JSON file",
    "Schedule a meeting with Sam",
    "Update the Notion plan",
    "Send the approved email",
    "Run the approved maintenance command",
    "Perform the maintenance operation",
    "Deploy the reviewed release",
    "Hello agent",
    "Finish this after restart",
    "Prepare an export",
    "Prepare a private export",
    "Prepare delayed export",
    "First ask",
    "And also this",
    "Ask Bob",
    "Work",
    "New work",
    "Collaborate",
    "Brainstorm product names",
    "Compose a friendly email",
    "Draft an email saying hello and tell John we'll be late",
    "Write a post and show our logo",
    "Write a friendly email to Alice and Bob",
    "Draft a concise and friendly email",
    "Brainstorm names for sales and marketing",
    "Create a red and blue logo",
  ]) {
    const checked = await enforceSlackEvidenceDelivery(request, plain, async () => card());
    assert.equal(checked.blocked, false, request);
  }
  for (const request of [
    "Summarize this email, then find current pricing",
    "Check this draft for tone; then research Stripe founders",
    "Summarize this email:\nHello Sam.\nThen report Stripe founders",
    "Summarize this email: Hello Sam. Also tell me who founded Stripe",
    "Check this draft for tone: Hello. Plus report current pricing",
    "Repeat the words benign update. Then report Stripe founders",
    "Repeat: benign update\nAlso explain quantum computing",
    "Summarize this email:\nHello Sam, the launch is Tuesday.",
    "Summarize this text: The launch is Tuesday.",
    "Can you summarize the following message:\nPlease bring the report.",
    "Check this draft for tone:\nHello Sam, send this today.",
    "Summarize this email:\nHello Sam.\nFinally, report Stripe founders",
    "Summarize this email:\nHello Sam.\nNext, explain quantum computing",
    "Summarize this email:\nHello Sam.\nAfterward, research current pricing",
    "Summarize this email:\nHello Sam.\nReport Stripe founders",
    "Summarize this email:\n```text\nHello Sam.\n```\nThen report Stripe founders\n````",
    "Summarize this email:\n```text\nHello Sam.\n```\nAlso explain quantum computing\n````",
    "Summarize this email:\n```text\nHello Sam.\n   ```\nThen report Stripe founders\n````",
    "Summarize this email:\n~~~text\nHello Sam.\n   ~~~\nThen report Stripe founders\n~~~~",
    "Summarize this text:\n```text\nHello Sam.\n```~~",
    "Summarize this text:\n~~~text\nHello Sam.\n~~~``",
    `Summarize this text: ${"x".repeat(8_300)}`,
    "Summarize this text:\u0007hidden",
  ]) {
    const checked = await enforceSlackEvidenceDelivery(request, plain, async () => card());
    assert.equal(checked.blocked, true, request.slice(0, 120));
  }
});

test("missing reply source parts and raw implementation metadata fail safe", async () => {
  for (const reply of [
    "Activation improved by four points.",
    "Source: Analytics · Observed: 2026-09-02 · Link: https://example.com/?token=secret",
    "Source: Analytics · Observed: 2026-09-02 · Link: https://analytics.example.com/report#access_token=secret",
    "query_id=private. Source: Analytics · Observed: 2026-09-02 · Link: unavailable",
    "receiptHandle=ar_private. Source: Analytics · Observed: 2026-09-02 · Link: unavailable",
    "boxplot_data=[1,2]. Source: Analytics · Observed: 2026-09-02 · Link: unavailable",
    "cache_target_age=30. Source: Analytics · Observed: 2026-09-02 · Link: unavailable",
    "calculation_trigger=query. Source: Analytics · Observed: 2026-09-02 · Link: unavailable",
    "hasMore=true; next_page_token=x. Source: Analytics · Observed: 2026-09-02 · Link: unavailable",
    '{"results":[1,2]}. Source: Analytics · Observed: 2026-09-02 · Link: unavailable',
    "Source: Analytics · Observed: 2026-09-02 · Link: http://analytics.example.com/insights/activation",
    "Source: Analytics · Observed: 2026-09-02 · Link: https://analytics.example.com/insights/fabricated",
    "First claim has no provenance.\n\nSecond claim. Source: Analytics · Observed: 2026-09-02 · Link: unavailable",
    "**Example University has 0 chats**\n\nSecond claim. Source: Analytics · Observed: 2026-09-02 · Link: unavailable",
    "Source: Notion · Observed: 2026-09-02 · Link: unavailable",
    "Source: Analytics · Observed: 2026-09-01 · Link: unavailable",
  ]) {
    const checked = await enforceSlackEvidenceDelivery(
      "How did analytics change this week?",
      result({ reply }),
      async () => card(),
    );
    assert.equal(checked.blocked, true, reply);
    assert.equal(checked.reason, "reply");
    assert.equal(checked.result.attachments, undefined);
    assert.match(checked.result.reply ?? "", /couldn't safely deliver/u);
  }
});

test("public evidence requires publication or update freshness alongside current-run observation", async () => {
  const publicSource = [{ sourceType: "Public web", observedAt: "2026-09-02T17:00:00.000Z", links: [allowedLink] }];
  const withoutFreshness = await enforceSlackEvidenceDelivery(
    "Who founded the current product?",
    result({
      reply: `Current update. Source: Public web · Checked: 2026-09-02 · Link: ${allowedLink}`,
      attachments: undefined,
      deliveryEvidenceSources: publicSource,
    }),
    async () => card(),
  );
  assert.equal(withoutFreshness.blocked, true);
  for (const freshness of [
    "Publication date unavailable Freshness unverified.",
    "Publication date unavailable · Freshness: unknown.",
    "Updated: 2026-09-01.",
  ]) {
    const malformed = result({
      reply: `Current update. ${freshness} Source: Public web · Checked: 2026-09-02 · Link: ${allowedLink}`,
      attachments: undefined,
      deliveryEvidenceSources: publicSource,
    });
    assert.equal(
      (await enforceSlackEvidenceDelivery("Who founded the current product?", malformed, async () => card())).blocked,
      true,
      freshness,
    );
  }
  const withInventedPublished = result({
    reply: `Current update. Published: 2026-09-01. Source: Public web · Checked: 2026-09-02 · Link: ${allowedLink}`,
    attachments: undefined,
    deliveryEvidenceSources: publicSource,
  });
  assert.equal(
    (await enforceSlackEvidenceDelivery("Who founded the current product?", withInventedPublished, async () => card()))
      .blocked,
    true,
  );
  const withUnavailable = result({
    reply: `Current update. Publication date unavailable · Freshness: unverified. Source: Public web · Checked: 2026-09-02 · Link: ${allowedLink}`,
    attachments: undefined,
    deliveryEvidenceSources: publicSource,
  });
  assert.equal(
    (await enforceSlackEvidenceDelivery("Who founded the current product?", withUnavailable, async () => card()))
      .blocked,
    false,
  );
  for (const invented of [
    "Published: 2026-09-01.",
    "Updated: 2026-09-01.",
    "Publication date: 2026-09-01.",
    "Published recently.",
  ]) {
    const contradictory = result({
      reply: `Current update. ${invented} Publication date unavailable · Freshness: unverified. Source: Public web · Checked: 2026-09-02 · Link: ${allowedLink}`,
      attachments: undefined,
      deliveryEvidenceSources: publicSource,
    });
    assert.equal(
      (await enforceSlackEvidenceDelivery("Who founded the current product?", contradictory, async () => card()))
        .blocked,
      true,
      invented,
    );
  }

  const publicCardResult = result({
    reply: withUnavailable.reply,
    deliveryEvidenceSources: publicSource,
  });
  const publicCardWithoutFreshness = Buffer.from(
    JSON.stringify({
      version: 1,
      renderer: "qm.card.v1",
      fallbackText: "Public Research",
      payload: {
        heading: "Public Research",
        summary: withUnavailable.reply,
        sections: [
          {
            key: "public_evidence",
            label: "Public evidence",
            items: [
              {
                label: "Public web · 2026-09-02",
                value: "Current update.",
                href: allowedLink,
              },
            ],
          },
        ],
      },
    }),
  );
  assert.equal(
    (
      await enforceSlackEvidenceDelivery(
        "Give me public research",
        publicCardResult,
        async () => publicCardWithoutFreshness,
      )
    ).blocked,
    true,
  );
});

test("substantial evidence requires exactly one complete safe workflow card", async () => {
  for (const request of ["Give me an account health brief", "Tell me how ACME is doing", "Give me an ACME update"]) {
    const missing = await enforceSlackEvidenceDelivery(request, result({ attachments: undefined }), async () => card());
    assert.equal(missing.reason, "card_count", request);
  }

  for (const bytes of [
    card({ label: "Analytics", value: "Activation improved. Link unavailable." }),
    card({ value: "Activation improved. receiptHash=private. Link unavailable." }),
    card({ value: "Activation improved. boxplot_data=[1,2]. Link unavailable." }),
    card({ value: "Activation improved. cache_target_age=30; has_more=true. Link unavailable." }),
    card({ href: "https://example.com/report?access_token=secret" }),
    card({ href: "https://analytics.example.com/insights/activation#access_token=secret" }),
    card({ href: "http://analytics.example.com/insights/activation" }),
    card({ href: "https://analytics.example.com/insights/fabricated" }),
    card({}, "Activation improved without source provenance."),
    Buffer.from(
      JSON.stringify({
        version: 1,
        renderer: "qm.card.v1",
        fallbackText: "Example University has 0 chats",
        payload: {
          heading: "Example University has 0 chats",
          summary: sourcedReply,
          status: { label: "Example University has 0 chats", tone: "success" },
          sections: [
            {
              key: "recommendations",
              label: "Recommendations",
              items: [{ value: "Example University has 0 chats" }],
            },
          ],
        },
      }),
    ),
    Buffer.from(
      JSON.stringify({
        version: 1,
        renderer: "qm.card.v1",
        fallbackText: "Meeting Brief — Acme has 0 chats",
        payload: {
          heading: "Meeting Brief — Acme has 0 chats",
          summary: sourcedReply,
          sections: [
            {
              key: "evidence",
              label: "Evidence",
              items: [
                {
                  label: "Analytics · observed 2026-09-02",
                  value: "Activation improved. Link unavailable.",
                },
              ],
            },
          ],
        },
      }),
    ),
  ]) {
    const checked = await enforceSlackEvidenceDelivery("Give me an account health brief", result(), async () => bytes);
    assert.equal(checked.blocked, true);
    assert.equal(checked.reason, "card");
    assert.equal(checked.result.attachments, undefined);
  }

  const linked = result({ reply: linkedReply, deliveryEvidenceSources: linkedSource });
  const complete = await enforceSlackEvidenceDelivery("Give me an account health brief", linked, async () =>
    card({ href: allowedLink }, linkedReply),
  );
  assert.equal(complete.blocked, false);

  const duplicate = await enforceSlackEvidenceDelivery(
    "How did analytics change this week?",
    { ...linked, attachments: [attachment, { ...attachment, blobId: "blob-2" }] },
    async () => card({ href: allowedLink }, linkedReply),
  );
  assert.equal(duplicate.blocked, true);
  assert.equal(duplicate.reason, "card_count");

  const specialized = await enforceSlackEvidenceDelivery("Prepare me for my meeting with Acme", linked, async () =>
    Buffer.from(
      JSON.stringify({
        version: 1,
        renderer: "qm.card.v1",
        fallbackText: "Meeting Brief — Acme",
        payload: {
          heading: "Meeting Brief — Acme",
          summary: linkedReply,
          status: { label: "Partially ready", tone: "warning" },
          sections: [
            {
              key: "recommended_next_steps",
              label: "Recommended next steps",
              items: [
                {
                  label: "Inference · Analytics · 2026-09-02",
                  value: "Confirm a rollout owner before the meeting.",
                  href: allowedLink,
                },
              ],
            },
          ],
        },
      }),
    ),
  );
  assert.equal(specialized.blocked, false);

  const badStatus = await enforceSlackEvidenceDelivery("Give me an account health brief", linked, async () =>
    Buffer.from(
      JSON.stringify({
        version: 1,
        renderer: "qm.card.v1",
        fallbackText: "Account health brief",
        payload: {
          heading: "Account health",
          summary: linkedReply,
          status: { label: "Insufficient evidence", tone: "success" },
          sections: [
            {
              key: "evidence",
              label: "Evidence",
              items: [
                {
                  label: "Analytics · observed 2026-09-02",
                  value: "Activation improved.",
                  href: allowedLink,
                },
              ],
            },
          ],
        },
      }),
    ),
  );
  assert.equal(badStatus.blocked, true);
  assert.equal(badStatus.reason, "card");

  const factualStatus = await enforceSlackEvidenceDelivery("Give me an account health brief", linked, async () =>
    Buffer.from(
      JSON.stringify({
        version: 1,
        renderer: "qm.card.v1",
        fallbackText: "Account health brief",
        payload: {
          heading: "Account health",
          summary: linkedReply,
          status: { label: "At risk · fabricated churn doubled", tone: "warning" },
          sections: [
            {
              key: "evidence",
              label: "Evidence",
              items: [
                {
                  label: "Analytics · observed 2026-09-02",
                  value: "Activation improved.",
                  href: allowedLink,
                },
              ],
            },
          ],
        },
      }),
    ),
  );
  assert.equal(factualStatus.blocked, true);
  assert.equal(factualStatus.reason, "card");

  const crossSource = result({
    reply: "Plan changed. Source: Notion · Observed: 2026-09-02 · Link: unavailable",
    deliveryEvidenceSources: [
      ...unlinkedSource,
      { sourceType: "Notion", observedAt: "2026-09-02T17:00:00.000Z", links: [allowedLink] },
    ],
  });
  const crossed = await enforceSlackEvidenceDelivery("Give me an account health brief", crossSource, async () =>
    card({ label: "Notion · observed 2026-09-02", href: allowedLink }),
  );
  assert.equal(crossed.blocked, true, "unavailable cannot pass when that source has a returned safe link");

  const missing = await enforceSlackEvidenceDelivery("Give me an account health brief", result(), async () => {
    throw new Error("missing blob");
  });
  assert.equal(missing.blocked, true);
  assert.equal(missing.reason, "card");
  assert.equal(missing.result.attachments, undefined);
});

test("artifact fallback is bounded to the attachment's exact artifact identity", async () => {
  const artifactAttachment = {
    ...attachment,
    blobId: "missing",
    artifactId: "artifact-1",
    artifactViewerId: "viewer-1",
  };
  const calls: string[] = [];
  const checked = await enforceSlackEvidenceDelivery(
    "Give me an account health brief",
    result({ attachments: [artifactAttachment] }),
    async () => {
      throw new Error("missing");
    },
    async (artifactId, viewerId) => {
      calls.push(`${artifactId}:${viewerId}`);
      return card();
    },
  );
  assert.equal(checked.blocked, false);
  assert.deepEqual(calls, ["artifact-1:viewer-1"]);
});
