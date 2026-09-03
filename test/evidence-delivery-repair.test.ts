import assert from "node:assert/strict";
import { test } from "node:test";
import { enforceAndRepairEvidenceDelivery } from "../src/core/evidence-delivery-repair.ts";
import type { TurnResult } from "../src/types.ts";

const link = "https://example.com/current";
const suffix = `Publication date unavailable · Freshness: unverified. Source: Public web · Checked: 2026-09-02 · Link: ${link}`;
const source = [{ sourceType: "Public web", observedAt: "2026-09-02T18:00:00.000Z", links: [link] }];

function initial(): TurnResult {
  return { status: "ok", reply: "Current finding without provenance.", deliveryEvidenceSources: source };
}

test("one isolated presentation-only model call can repair prose and a substantial card", async () => {
  const blobs = new Map<string, Buffer>();
  let calls = 0;
  const checked = await enforceAndRepairEvidenceDelivery({
    requestText: "Tell me how ACME is doing",
    result: initial(),
    fetchBlob: async (id) => {
      const bytes = blobs.get(id);
      if (!bytes) throw new Error("missing");
      return bytes;
    },
    stageBlob: async (bytes) => {
      blobs.set("fixed", bytes);
      return { blobId: "fixed", sizeBytes: bytes.byteLength };
    },
    oneShot: async (system, prompt) => {
      calls++;
      assert.match(system, /Do not retrieve data, call tools/u);
      assert.match(system, /Meeting Brief/u);
      assert.match(system, /Partially ready/u);
      assert.match(system, /Recommended next steps/u);
      assert.doesNotMatch(prompt, /tool_call|sessionId|auth metadata/u);
      return JSON.stringify({
        reply: `ACME is stable. ${suffix}`,
        card: {
          version: 1,
          renderer: "qm.card.v1",
          fallbackText: "Account health",
          payload: {
            heading: "Account health",
            summary: `ACME is stable. ${suffix}`,
            sections: [
              {
                key: "evidence",
                label: "Evidence",
                items: [
                  {
                    label: "Public web · checked 2026-09-02",
                    value: "ACME is stable. Publication date unavailable · Freshness: unverified.",
                    href: link,
                  },
                ],
              },
            ],
          },
        },
      });
    },
  });
  assert.equal(calls, 1);
  assert.equal(checked.repairAttempted, true);
  assert.equal(checked.repaired, true);
  assert.equal(checked.result.attachments?.length, 1);
});

test("a failed repair is attempted exactly once and then fails safe", async () => {
  let calls = 0;
  const checked = await enforceAndRepairEvidenceDelivery({
    requestText: "Give me an ACME update",
    result: initial(),
    fetchBlob: async () => {
      throw new Error("not expected");
    },
    stageBlob: async () => assert.fail("invalid correction must not stage a blob"),
    oneShot: async () => {
      calls++;
      return JSON.stringify({ reply: "Still incomplete", card: null });
    },
  });
  assert.equal(calls, 1);
  assert.equal(checked.repairAttempted, true);
  assert.equal(checked.repaired, false);
  assert.match(checked.result.reply ?? "", /couldn't safely deliver/u);
  assert.equal(checked.result.attachments, undefined);
});

test("an invalid generated card is rejected before even non-durable staging", async () => {
  let stages = 0;
  const checked = await enforceAndRepairEvidenceDelivery({
    requestText: "Give me an ACME update",
    result: initial(),
    fetchBlob: async () => {
      throw new Error("not expected");
    },
    stageBlob: async () => {
      stages++;
      return { blobId: "unexpected", sizeBytes: 1 };
    },
    oneShot: async () =>
      JSON.stringify({
        reply: `ACME is stable. ${suffix}`,
        card: {
          version: 1,
          renderer: "qm.card.v1",
          fallbackText: "Account health",
          payload: {
            heading: "Account health",
            summary: "Invented summary without provenance.",
            sections: [{ key: "evidence", label: "Evidence", items: [{ value: "Invented value." }] }],
          },
        },
      }),
  });
  assert.equal(checked.repaired, false);
  assert.equal(stages, 0);
  assert.equal(checked.result.attachments, undefined);
});

test("repair never preserves unverified non-workflow attachments", async () => {
  const blobs = new Map<string, Buffer>();
  const checked = await enforceAndRepairEvidenceDelivery({
    requestText: "Tell me how ACME is doing",
    result: {
      ...initial(),
      attachments: [{ name: "raw-analytics.json", mimetype: "application/json", sizeBytes: 64, blobId: "raw" }],
    },
    fetchBlob: async (id) => {
      const bytes = blobs.get(id);
      if (!bytes) throw new Error("missing");
      return bytes;
    },
    stageBlob: async (bytes) => {
      blobs.set("fixed", bytes);
      return { blobId: "fixed", sizeBytes: bytes.byteLength };
    },
    oneShot: async () =>
      JSON.stringify({
        reply: `ACME is stable. ${suffix}`,
        card: {
          version: 1,
          renderer: "qm.card.v1",
          fallbackText: "Account health",
          payload: {
            heading: "Account health",
            summary: `ACME is stable. ${suffix}`,
            sections: [
              {
                key: "evidence",
                label: "Evidence",
                items: [
                  {
                    label: "Public web · checked 2026-09-02",
                    value: "ACME is stable. Publication date unavailable · Freshness: unverified.",
                    href: link,
                  },
                ],
              },
            ],
          },
        },
      }),
  });
  assert.equal(checked.repaired, true);
  assert.deepEqual(
    checked.result.attachments?.map((item) => item.name),
    ["evidence-brief.workflow.json"],
  );
});

test("valid, exempt, and approval results never invoke repair", async () => {
  let calls = 0;
  const oneShot = async () => {
    calls++;
    return undefined;
  };
  const base = { ...initial(), reply: `Current finding. ${suffix}` };
  for (const [requestText, result] of [
    ["Look up current news", base],
    ["Thanks!", { status: "ok", reply: "You're welcome." } as TurnResult],
    [
      "Update Notion",
      {
        status: "pending_approval",
        pendingApprovals: [{ requestId: "a", command: "write", reason: "write" }],
      } as TurnResult,
    ],
  ] as const) {
    const checked = await enforceAndRepairEvidenceDelivery({
      requestText,
      result,
      fetchBlob: async () => Buffer.alloc(0),
      stageBlob: async () => ({ blobId: "unused", sizeBytes: 0 }),
      oneShot,
    });
    assert.equal(checked.repairAttempted, false);
  }
  assert.equal(calls, 0);
});
