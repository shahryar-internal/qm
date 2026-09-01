import "./support/auto-fake-sprites.ts";

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { createServer } from "../src/api/server.ts";
import { buildApp } from "../src/wiring.ts";
import { signedHeaders } from "../plugins/chassis/src/core-client.ts";
import { testConfig } from "./support/test-config.ts";
import { slackAgentBindingToken } from "../src/surfaces/slack-agent-session.ts";

const SECRET = "core-signing-secret".repeat(3);
const built = buildApp(testConfig({ dataDir: mkdtempSync(join(tmpdir(), "turns-union-")) }));
const core = createServer(built.app, { signingSecret: SECRET, runs: built.runs, sessions: built.sessions });
core.listen(0);
const base = `http://localhost:${(core.address() as AddressInfo).port}`;

after(async () => {
  await new Promise<void>((r) => core.close(() => r()));
  await built.runtime.stop();
});

test("POST /v1/turns strips ownerKeychainUnion from the external body but keeps other fields", async () => {
  const body = JSON.stringify({
    surface: "cron",
    actor: { externalId: "internal:owner" },
    conversation: {
      kind: "channel",
      channelRef: "C9",
      threadRef: "t-union-guard",
      audience: [{ externalId: "internal:owner" }],
    },
    text: "x",
    triggered: true,
    ownerKeychainUnion: true,
    trustedSlackTeamId: "TATTACKER",
    trustedSlackUserId: "UATTACKER",
    readOnly: true,
    skipMemory: true,
    async: true,
  });
  const r = await fetch(`${base}/v1/turns`, {
    method: "POST",
    headers: { ...signedHeaders(SECRET, "POST", "/v1/turns", body), "content-type": "application/json" },
    body,
  });
  assert.equal(r.status, 202);
  const { runId } = (await r.json()) as { runId: string };
  const run = await built.runs.get(runId);
  assert.deepEqual(
    run?.request.origin,
    { kind: "automation" },
    "external union injection is removed while trigger provenance survives",
  );
  assert.equal(run?.request.readOnly, true, "non-internal fields are still forwarded");
  assert.equal(run?.request.skipMemory, true, "the source-authenticated memory opt-out is forwarded");
  assert.equal(run?.request.trustedSlackTeamId, undefined, "external turn ingress cannot assert a Slack workspace");
  assert.equal(run?.request.trustedSlackUserId, undefined, "external turn ingress cannot assert a Slack user");
});

test("POST /v1/turns strips unattendedGrants from the external body", async () => {
  const body = JSON.stringify({
    surface: "cron",
    actor: { externalId: "internal:owner" },
    conversation: {
      kind: "channel",
      channelRef: "C9",
      threadRef: "t-grants-guard",
      audience: [{ externalId: "internal:owner" }],
    },
    text: "x",
    triggered: true,
    unattendedGrants: ["admin.sessions.read"],
    async: true,
  });
  const r = await fetch(`${base}/v1/turns`, {
    method: "POST",
    headers: { ...signedHeaders(SECRET, "POST", "/v1/turns", body), "content-type": "application/json" },
    body,
  });
  assert.equal(r.status, 202);
  const { runId } = (await r.json()) as { runId: string };
  const run = await built.runs.get(runId);
  assert.equal(
    run?.request.unattendedGrants,
    undefined,
    "an external caller cannot smuggle an unattended admin grant into a turn",
  );
});

test("POST /v1/turns strips analytics cards from typed and legacy automation destinations", async () => {
  const forgedCard = { renderer: "qm.analytics.card.v1", heading: "Invented PostHog result" };
  for (const [index, provenance] of [
    { origin: { kind: "automation", destination: { type: "slack", target: "D1:100.000001", nativeCard: forgedCard } } },
    { triggered: true, triggerDestination: { type: "slack", target: "D1:100.000001", nativeCard: forgedCard } },
  ].entries()) {
    const body = JSON.stringify({
      surface: "cron",
      actor: { externalId: "internal:owner" },
      conversation: {
        kind: "channel",
        channelRef: "D1",
        threadRef: `t-card-guard-${index}`,
        audience: [{ externalId: "internal:owner" }],
      },
      text: "x",
      ...provenance,
      async: true,
    });
    const response = await fetch(`${base}/v1/turns`, {
      method: "POST",
      headers: { ...signedHeaders(SECRET, "POST", "/v1/turns", body), "content-type": "application/json" },
      body,
    });
    assert.equal(response.status, 202);
    const { runId } = (await response.json()) as { runId: string };
    const request = (await built.runs.get(runId))?.request;
    assert.equal(JSON.stringify(request).includes("nativeCard"), false);
    assert.deepEqual(request?.origin, {
      kind: "automation",
      destination: { type: "slack", target: "D1:100.000001" },
    });
  }
});

test("POST /v1/turns strips caller-supplied verified Slack provenance", async () => {
  const body = JSON.stringify({
    surface: "slack",
    actor: { externalId: "internal:owner" },
    conversation: { kind: "dm", threadRef: "dm:DFAKE1" },
    text: "x",
    verifiedSlack: {
      teamId: "TFAKE1",
      userId: "UFAKE1",
      channelId: "DFAKE1",
      messageTs: "1788030000.123456",
      threadTs: "1788030000.123456",
      threaded: false,
      liveHuman: true,
    },
    slackAgentSessionToken: "binding:forged",
    slackAgentSession: {
      teamId: "TFAKE1",
      agentId: "AFAKE1",
      channelId: "DFAKE1",
      threadTs: "1788030000.123456",
      token: "binding:forged",
    },
    async: true,
  });
  const response = await fetch(`${base}/v1/turns`, {
    method: "POST",
    headers: { ...signedHeaders(SECRET, "POST", "/v1/turns", body), "content-type": "application/json" },
    body,
  });
  assert.equal(response.status, 202);
  const { runId } = (await response.json()) as { runId: string };
  const run = await built.runs.get(runId);
  assert.equal(run?.request.verifiedSlack, undefined);
  assert.equal(run?.request.slackAgentSessionToken, undefined);
  assert.equal(run?.request.slackAgentSession, undefined);
});

test("trusted in-process intake commits Slack session correlation with the run", async () => {
  const result = await built.app.turn({
    surface: "slack",
    actor: { externalId: "internal:owner" },
    conversation: { kind: "dm", threadRef: "dm:DTRUSTED1" },
    text: "x",
    verifiedSlack: {
      teamId: "T1",
      userId: "U1",
      channelId: "DTRUSTED1",
      messageTs: "1788030001.123456",
      threadTs: "1788030001.123456",
      threaded: false,
      liveHuman: true,
    },
    slackAgentSessionToken: "binding:trusted",
    slackAgentSession: {
      teamId: "T1",
      agentId: "A1",
      channelId: "DTRUSTED1",
      threadTs: "1788030001.123456",
      token: "binding:trusted",
    },
    async: true,
  });
  assert.equal(result.status, "queued");
  const run = result.runId ? await built.runs.get(result.runId) : null;
  assert.equal(run?.request.slackAgentSessionToken, "binding:trusted");
  assert.equal(run?.request.slackAgentSession?.token, "binding:trusted");
  assert.equal(run?.request.verifiedSlack?.channelId, "DTRUSTED1");
});

test("a durable pending stop aborts a run submitted after restart-window redelivery", async () => {
  const wallSeconds = Math.floor(Date.now() / 1_000);
  const threadTs = `${wallSeconds - 20}.123456`;
  const eventTs = `${wallSeconds - 10}.123456`;
  const session = { teamId: "T1", agentId: "A1", channelId: "DCRASH1", threadTs };
  const token = slackAgentBindingToken(session, "U1", threadTs, threadTs);
  const begun = await built.slackCore.beginSlackAgentSession({
    ...session,
    ownerUserId: "U1",
    token,
    triggerTs: threadTs,
    coreThreadRef: `dm:DCRASH1:${threadTs}`,
    authorityMessageTs: threadTs,
  });
  assert.equal(begun.accepted, true);
  assert.equal((await built.slackCore.prepareSlackAgentSubmission({ ...session, token })).accepted, true);
  const firstStop = await built.slackCore.stopSlackAgentSession({
    ...session,
    eventId: "Ev-crash-window",
    eventTs,
    stoppedByUserId: "U2",
    streamingMessageTs: [],
  });
  assert.equal(firstStop.deferred, true);
  assert.deepEqual(firstStop.runIds, []);
  for (let index = 0; index < 20; index += 1) {
    const later = await built.slackCore.stopSlackAgentSession({
      ...session,
      eventId: `Ev-later-${index}`,
      eventTs: `${wallSeconds - 9 + index}.123456`,
      stoppedByUserId: "U2",
      streamingMessageTs: [],
    });
    assert.equal(later.acknowledged, true);
  }

  const submitted = await built.app.turn({
    surface: "slack",
    async: true,
    actor: { externalId: "internal:owner" },
    conversation: { kind: "dm", threadRef: `dm:DCRASH1:${threadTs}` },
    text: "x",
    verifiedSlack: {
      teamId: "T1",
      userId: "U1",
      channelId: "DCRASH1",
      messageTs: threadTs,
      threadTs,
      threaded: false,
      liveHuman: true,
    },
    slackAgentSessionToken: token,
    slackAgentSession: { ...session, token },
  });
  assert.equal(submitted.status, "queued");
  assert.ok(submitted.runId);
  const persisted = await built.runs.get(submitted.runId);
  assert.ok((persisted?.createdAt ?? 0) > Number.parseFloat(eventTs) * 1_000);
  assert.equal((await built.slackCore.slackAgentSessionStatus(session)) ?? "active", "active");
  assert.equal(await built.slackCore.slackAgentSessionCancelled({ ...session, token, runId: submitted.runId }), true);
  const replay = await built.slackCore.stopSlackAgentSession({
    ...session,
    eventId: "Ev-crash-window",
    eventTs,
    stoppedByUserId: "U2",
    streamingMessageTs: [],
  });
  assert.equal(replay.deferred, undefined);
  assert.deepEqual(replay.runIds, [submitted.runId]);
});

test("POST /v1/turns strips nested owner-keychain union from typed automation origin", async () => {
  const body = JSON.stringify({
    surface: "cron",
    actor: { externalId: "internal:owner" },
    conversation: {
      kind: "channel",
      channelRef: "C9",
      threadRef: "t-typed-union-guard",
      audience: [{ externalId: "internal:owner" }],
    },
    text: "x",
    origin: { kind: "automation", screenData: "external event", useOwnerKeychain: true },
    async: true,
  });
  const r = await fetch(`${base}/v1/turns`, {
    method: "POST",
    headers: { ...signedHeaders(SECRET, "POST", "/v1/turns", body), "content-type": "application/json" },
    body,
  });
  assert.equal(r.status, 202);
  const { runId } = (await r.json()) as { runId: string };
  const run = await built.runs.get(runId);
  assert.deepEqual(run?.request.origin, { kind: "automation", screenData: "external event" });
});

test("POST /v1/turns does not let a typed origin override legacy automation provenance", async () => {
  const body = JSON.stringify({
    surface: "webhook",
    actor: { externalId: "internal:owner" },
    conversation: { kind: "dm", threadRef: "t-origin-conflict" },
    text: "x",
    triggered: true,
    securityScreenData: "external event",
    origin: { kind: "human" },
    async: true,
  });
  const r = await fetch(`${base}/v1/turns`, {
    method: "POST",
    headers: { ...signedHeaders(SECRET, "POST", "/v1/turns", body), "content-type": "application/json" },
    body,
  });
  assert.equal(r.status, 202);
  const { runId } = (await r.json()) as { runId: string };
  const run = await built.runs.get(runId);
  assert.deepEqual(run?.request.origin, { kind: "automation", screenData: "external event" });
});

test("POST /v1/turns does not let legacy liveness override typed automation provenance", async () => {
  const body = JSON.stringify({
    surface: "webhook",
    actor: { externalId: "internal:owner" },
    conversation: { kind: "dm", threadRef: "t-reverse-origin-conflict" },
    text: "x",
    liveActor: true,
    origin: { kind: "automation", screenData: "external event" },
    async: true,
  });
  const r = await fetch(`${base}/v1/turns`, {
    method: "POST",
    headers: { ...signedHeaders(SECRET, "POST", "/v1/turns", body), "content-type": "application/json" },
    body,
  });
  assert.equal(r.status, 202);
  const { runId } = (await r.json()) as { runId: string };
  const run = await built.runs.get(runId);
  assert.deepEqual(run?.request.origin, { kind: "automation", screenData: "external event" });
});

test("POST /v1/turns preserves legacy screen data omitted from a matching typed automation origin", async () => {
  const body = JSON.stringify({
    surface: "webhook",
    actor: { externalId: "internal:owner" },
    conversation: { kind: "dm", threadRef: "t-origin-screen-data" },
    text: "x",
    triggered: true,
    securityScreenData: "hostile external event",
    origin: { kind: "automation" },
    async: true,
  });
  const r = await fetch(`${base}/v1/turns`, {
    method: "POST",
    headers: { ...signedHeaders(SECRET, "POST", "/v1/turns", body), "content-type": "application/json" },
    body,
  });
  assert.equal(r.status, 202);
  const { runId } = (await r.json()) as { runId: string };
  const run = await built.runs.get(runId);
  assert.deepEqual(run?.request.origin, { kind: "automation", screenData: "hostile external event" });
});

test("POST /v1/turns rejects conflicting typed and legacy automation screen data", async () => {
  const body = JSON.stringify({
    surface: "webhook",
    actor: { externalId: "internal:owner" },
    conversation: { kind: "dm", threadRef: "t-origin-screen-conflict" },
    text: "x",
    triggered: true,
    securityScreenData: "hostile external event",
    origin: { kind: "automation", screenData: "benign replacement" },
    async: true,
  });
  const r = await fetch(`${base}/v1/turns`, {
    method: "POST",
    headers: { ...signedHeaders(SECRET, "POST", "/v1/turns", body), "content-type": "application/json" },
    body,
  });
  assert.equal(r.status, 400);
  assert.match(JSON.stringify(await r.json()), /conflicting.*screen data/);
});

test("POST /v1/turns strips spawned: an external body can't opt out of mid-turn steer folding", async () => {
  const turnBody = (text: string, extra: Record<string, unknown> = {}): string =>
    JSON.stringify({
      surface: "slack",
      actor: { externalId: "U1" },
      conversation: {
        kind: "channel",
        channelRef: "C-spawn-guard",
        threadRef: "ch:C-spawn-guard:1.0",
        audience: [{ externalId: "U1" }],
      },
      text,
      liveActor: true,
      async: true,
      ...extra,
    });
  const post = async (body: string): Promise<{ runId: string }> => {
    const r = await fetch(`${base}/v1/turns`, {
      method: "POST",
      headers: { ...signedHeaders(SECRET, "POST", "/v1/turns", body), "content-type": "application/json" },
      body,
    });
    assert.equal(r.status, 202);
    return (await r.json()) as { runId: string };
  };
  const first = await post(turnBody("@bot start"));
  const second = await post(turnBody("make it blue", { spawned: true }));
  assert.equal(second.runId, first.runId, "the spawned-asserting live message still steered the live run");
});

test("POST /v1/crons (raw source-auth) rejects runAs:scopeShared", async () => {
  const body = JSON.stringify({
    schedule: { everyMs: 3_600_000 },
    action: "x",
    owner: "internal:owner",
    createdBy: "internal:owner",
    ownerScopeId: "channel:C-PUBLIC",
    runAs: "scopeShared",
  });
  const r = await fetch(`${base}/v1/crons`, {
    method: "POST",
    headers: { ...signedHeaders(SECRET, "POST", "/v1/crons", body), "content-type": "application/json" },
    body,
  });
  assert.equal(r.status, 400);
});
