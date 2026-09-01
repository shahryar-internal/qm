import { test } from "node:test";
import assert from "node:assert/strict";
import { createDeferredEnvelopeAck, isGatedEnvelope, requiresDurableAck } from "../src/slack/deferred-ack.ts";

const tick = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

test("gated envelope: the real ack fires only AFTER the fake core has durably queued the turn", async () => {
  const events: string[] = [];
  const { ack, gate } = createDeferredEnvelopeAck(
    async () => {
      events.push("socket-ack");
    },
    { gated: true, capMs: 5_000 },
  );

  const fakeCoreEnqueue = async (): Promise<void> => {
    await tick(20);
    events.push("core-persisted");
  };

  await ack();
  assert.deepEqual(events, []);

  await fakeCoreEnqueue();
  gate.persisted();
  await tick(0);
  assert.deepEqual(events, ["core-persisted", "socket-ack"]);
});

test("gated envelope: repeated persisted/ack calls ack the socket exactly once", async () => {
  let acks = 0;
  const { ack, gate } = createDeferredEnvelopeAck(
    async () => {
      acks += 1;
    },
    { gated: true, capMs: 5_000 },
  );
  await ack();
  gate.persisted();
  gate.persisted();
  await ack();
  await tick(0);
  assert.equal(acks, 1);
});

test("gated envelope: the cap acks anyway so Slack's deadline can't drop the socket", async () => {
  let acks = 0;
  const { ack } = createDeferredEnvelopeAck(
    async () => {
      acks += 1;
    },
    { gated: true, capMs: 15 },
  );
  await ack();
  assert.equal(acks, 0);
  await tick(40);
  assert.equal(acks, 1);
});

test("gated envelope: a failure before persistence withholds the ack entirely (Slack redelivers)", async () => {
  let acks = 0;
  const { ack, gate } = createDeferredEnvelopeAck(
    async () => {
      acks += 1;
    },
    { gated: true, capMs: 15 },
  );
  await ack();
  gate.failed("core unreachable");
  await tick(40);
  gate.persisted();
  await tick(0);
  assert.equal(acks, 0);
});

test("ungated envelope acks immediately when Bolt asks", async () => {
  let acks = 0;
  const { ack } = createDeferredEnvelopeAck(
    async () => {
      acks += 1;
    },
    { gated: false },
  );
  await ack();
  await tick(0);
  assert.equal(acks, 1);
});

test("agent_session_stopped withholds its envelope at the cap until durable stop handling succeeds", async () => {
  const body = { type: "event_callback", event: { type: "agent_session_stopped" } };
  assert.equal(isGatedEnvelope(body), true);
  assert.equal(requiresDurableAck(body), true);
  let acks = 0;
  let withheld = 0;
  const { ack, gate } = createDeferredEnvelopeAck(
    async () => {
      acks += 1;
    },
    { gated: true, strict: true, capMs: 10, onWithhold: () => void (withheld += 1) },
  );
  await ack();
  await tick(30);
  gate.persisted();
  assert.equal(acks, 0);
  assert.equal(withheld, 1);
});

test("ordinary message and app_mention envelopes also require durable acceptance", () => {
  assert.equal(requiresDurableAck({ type: "event_callback", event: { type: "message" } }), true);
  assert.equal(requiresDurableAck({ type: "event_callback", event: { type: "app_mention" } }), true);
  assert.equal(requiresDurableAck({ type: "event_callback", event: { type: "reaction_added" } }), false);
});

test("ordinary message delivery withholds at the cap before durable intake", async () => {
  let acks = 0;
  let withheld = 0;
  const { ack, gate } = createDeferredEnvelopeAck(async () => void (acks += 1), {
    gated: true,
    strict: true,
    capMs: 10,
    onWithhold: () => void (withheld += 1),
  });
  await ack();
  await tick(30);
  assert.equal(acks, 0);
  assert.equal(withheld, 1);
  gate.persisted();
  assert.equal(acks, 0);
});
