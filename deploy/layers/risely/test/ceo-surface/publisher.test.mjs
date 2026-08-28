import assert from "node:assert/strict";
import { test } from "node:test";
import { PrincipalBinding } from "../../canary/shared-contracts/index.mjs";
import { validateArtifact } from "../../canary/presentation/index.mjs";
import {
  compileDeploymentBinding,
  deriveSurfaceOutboxEventId,
  evalReleaseReceiptHash,
  identityResolutionHash,
  outboxPayloadHash,
  validateOutboxItem,
} from "../../canary/service/ceo-surface/src/contracts.mjs";
import {
  compileShadowPublication,
  reconstructShadowPublication,
} from "../../canary/service/ceo-surface/src/publisher.mjs";

const sha256Canonical = PrincipalBinding.hash;

const deploymentBinding = Object.freeze({
  contractType: "ceo-surface-deployment",
  contractVersion: 1,
  ceoUserRef: "slack-user:ceo",
  ceoEmail: "shahryar@risely.ai",
  qmPrincipalRef: "qm:principal:ceo-canary",
  credentialOwnerRef: "credential-owner:ceo",
  slackTeamId: "T123456789",
  evalAuthorityRef: "evaluator:risely:shadow-gate",
  evalPolicySha256: "a".repeat(64),
  identityResolverAuthorityRef: "resolver:risely:slack-identity",
});

function artifact(baseTime = Date.now()) {
  return validateArtifact({
    version: 1,
    id: `artifact:${"b".repeat(64)}`,
    revision: "c".repeat(64),
    kind: "meeting_prep",
    state: "ready",
    title: "Meeting prep · Example University",
    summary: "Confirm the decision owner and implementation timeline.",
    facts: [
      { label: "Outcome", value: "Confirm the executive sponsor." },
      { label: "Watch-out", value: "Implementation timing remains open." },
    ],
    evidence: [
      {
        label: "Calendar event",
        source: "Google Calendar",
        occurredAt: new Date(baseTime - 10 * 60 * 1000).toISOString(),
      },
    ],
    links: [{ label: "Original dossier", url: "https://www.notion.so/private-dossier" }],
    actions: [
      { key: "open", label: "Open briefing", primary: true },
      { key: "ask_qm", label: "Ask QM" },
    ],
    updatedAt: new Date(baseTime - 8 * 60 * 1000).toISOString(),
  });
}

function fixture(baseTime = Date.now()) {
  const resolvedAt = new Date(baseTime - 5 * 60 * 1000).toISOString();
  const evaluatedAt = new Date(baseTime - 4 * 60 * 1000).toISOString();
  const queuedAt = new Date(baseTime - 3 * 60 * 1000).toISOString();
  const evalExpiresAt = new Date(baseTime + 20 * 60 * 1000).toISOString();
  const identityExpiresAt = new Date(baseTime + 25 * 60 * 1000).toISOString();
  const deployment = compileDeploymentBinding(deploymentBinding);
  const typedArtifact = artifact(baseTime);
  const artifactSha256 = sha256Canonical(typedArtifact);
  const evalRelease = {
    contractType: "eval-release",
    contractVersion: 1,
    evalRunId: "eval:meeting:123:7",
    evalAuthorityRef: deployment.evalAuthorityRef,
    deploymentBindingSha256: deployment.bindingSha256,
    artifactId: typedArtifact.id,
    artifactRevision: typedArtifact.revision,
    artifactSha256,
    mode: "shadow",
    passed: true,
    release: true,
    sideEffects: 0,
    deterministicCheckIds: ["check:grounding", "check:recipient"],
    judgeIds: ["judge:luna:quality", "judge:luna:safety"],
    judgeIndependenceKeys: ["origin:luna:quality", "origin:luna:safety"],
    policySha256: deployment.evalPolicySha256,
    rubricVersion: "rubric:2026-08-26:v1",
    evaluatedAt,
    expiresAt: evalExpiresAt,
  };
  evalRelease.receiptSha256 = evalReleaseReceiptHash(evalRelease);
  const outboxItem = {
    contractType: "ceo-surface-outbox",
    contractVersion: 1,
    eventId: deriveSurfaceOutboxEventId(typedArtifact, deployment),
    deploymentBindingSha256: deployment.bindingSha256,
    artifact: typedArtifact,
    artifactSha256,
    evalRelease,
    queuedAt,
  };
  outboxItem.payloadSha256 = outboxPayloadHash(outboxItem);
  const identityResolution = {
    contractType: "ceo-surface-identity-resolution",
    contractVersion: 1,
    resolverReceiptRef: "identity-receipt:123",
    resolverAuthorityRef: deployment.identityResolverAuthorityRef,
    deploymentBindingSha256: deployment.bindingSha256,
    teamRef: deployment.teamRef,
    ceoUserRef: deployment.ceoUserRef,
    ceoEmail: deployment.ceoEmail,
    qmPrincipalRef: deployment.qmPrincipalRef,
    credentialOwnerRef: deployment.credentialOwnerRef,
    slackTeamId: deployment.slackTeamId,
    slackUserId: "U123456789",
    slackDirectMessageId: "D123456789",
    resolvedAt,
    expiresAt: identityExpiresAt,
  };
  identityResolution.resolutionSha256 = identityResolutionHash(identityResolution);
  return { deploymentBinding, outboxItem, identityResolution };
}

function compile(value = fixture()) {
  return compileShadowPublication(value);
}

function replaceArtifact(value, changes) {
  const next = validateArtifact({ ...value.outboxItem.artifact, ...changes });
  const artifactSha256 = sha256Canonical(next);
  value.outboxItem.artifact = next;
  value.outboxItem.artifactSha256 = artifactSha256;
  value.outboxItem.evalRelease.artifactId = next.id;
  value.outboxItem.evalRelease.artifactRevision = next.revision;
  value.outboxItem.evalRelease.artifactSha256 = artifactSha256;
  value.outboxItem.evalRelease.receiptSha256 = evalReleaseReceiptHash(value.outboxItem.evalRelease);
  value.outboxItem.payloadSha256 = outboxPayloadHash(value.outboxItem);
}

test("compiles one immutable actionless CEO DM from an eval-passed artifact revision", () => {
  const publication = compile();
  assert.equal(publication.mode, "shadow");
  assert.equal(publication.providerInvocationAllowed, false);
  assert.equal(publication.target.ceoEmail, "shahryar@risely.ai");
  assert.equal(publication.target.qmPrincipalRef, "qm:principal:ceo-canary");
  assert.equal(publication.target.credentialOwnerRef, "credential-owner:ceo");
  assert.equal(publication.target.slackTeamId, "T123456789");
  assert.equal(publication.target.slackUserId, "U123456789");
  assert.equal(publication.target.slackDirectMessageId, "D123456789");
  assert.equal(
    publication.message.blocks.some((block) => block.type === "actions"),
    false,
  );
  assert.deepEqual(Object.keys(publication.message).sort(), ["blocks", "text"]);
  assert.doesNotMatch(JSON.stringify(publication.message), /action_id|"button"|ir_/);
  assert.equal((JSON.stringify(publication.message).match(/https:\/\/qm\.riselyinternal\.ai\//g) ?? []).length, 1);
  assert.doesNotMatch(JSON.stringify(publication.message), /notion\.so|private-dossier/);
  assert.equal(publication.receiptContract.durability, "postgres");
  assert.equal(publication.receiptContract.atomicReservationRequired, true);
  assert.equal(publication.receiptContract.uniqueKey, publication.deliveryKey);
  assert.deepEqual(publication.receiptContract.conflictFields, [
    "outboxPayloadSha256",
    "artifactSha256",
    "identityResolutionSha256",
    "targetBindingSha256",
    "messageSha256",
  ]);
  assert.deepEqual(publication.receiptContract.optionalFields, ["providerReceiptRef"]);
  assert.deepEqual(publication.receiptContract.authorityRequirements, [
    "authenticated_slack_adapter_receipt",
    "durable_delivery_key_reservation",
    "exact_publication_conflict_binding",
  ]);
  assert.equal(
    publication.deliveryKey,
    sha256Canonical({
      deploymentBindingSha256: publication.deploymentBindingSha256,
      outboxEventId: publication.outboxEventId,
    }),
  );
  assert.equal(Object.isFrozen(publication), true);
  assert.equal(Object.isFrozen(publication.target), true);
  assert.equal(Object.isFrozen(publication.message.blocks), true);
});

test("historical reconstruction is anchored to reservation time after 200 days", () => {
  const authorityTime = Date.now() - 200 * 24 * 60 * 60 * 1000;
  const value = fixture(authorityTime);
  assert.throws(() => compile(value), /expired/);
  const publication = reconstructShadowPublication(value, new Date(authorityTime).toISOString());
  assert.equal(publication.outboxPayloadSha256, value.outboxItem.payloadSha256);
  assert.equal(publication.identityResolutionSha256, value.identityResolution.resolutionSha256);
  assert.equal(publication.providerInvocationAllowed, false);
});

test("artifact and outbox cannot select any Slack destination or recipient", () => {
  for (const field of [
    "channel",
    "channelId",
    "user",
    "userId",
    "destination",
    "slackTeamId",
    "slackDirectMessageId",
  ]) {
    const value = fixture();
    value.outboxItem[field] = field;
    assert.throws(() => compile(value), new RegExp(`outboxItem\\.${field} is not supported`));
  }
  const value = fixture();
  value.outboxItem.artifact = { ...value.outboxItem.artifact, channelId: "C123456789" };
  value.outboxItem.payloadSha256 = outboxPayloadHash(value.outboxItem);
  assert.throws(() => compile(value), /artifact\.channelId is not supported/);
});

test("workflow narrative cannot add an auto-linked destination to the generic CEO message", () => {
  for (const summary of [
    "Review http://attacker.example/path before the meeting.",
    "Review HTTP://attacker.example/path before the meeting.",
    "Review www.attacker.example before the meeting.",
    "Review attacker.example before the meeting.",
    "Review ceo@attacker.example before the meeting.",
    "Review ftp://attacker.example before the meeting.",
    "Review 192.0.2.10 before the meeting.",
    "Review https://qm.riselyinternal.ai/ before the meeting.",
  ]) {
    const value = fixture();
    replaceArtifact(value, { summary });
    const publication = compile(value);
    assert.equal((JSON.stringify(publication.message).match(/https:\/\/qm\.riselyinternal\.ai\//g) ?? []).length, 1);
  }
});

test("the generic CEO message omits workflow personal data and secret-shaped narrative", () => {
  for (const probe of [
    "+44 20 7946 0958",
    "123-45-6789",
    "127.0.0.1",
    "AKIAIOSFODNN7EXAMPLE",
    "xoxb-12345678901234567890",
    "sk-live-12345678901234567890",
    "password=correct-horse-battery-staple",
    "abcdefghijklmnopqrstuvwxyz0123456789abcdef",
  ]) {
    const value = fixture();
    replaceArtifact(value, {
      title: probe,
      summary: probe,
      facts: [{ label: probe, value: probe }],
      evidence: [{ label: probe, source: probe }],
      statusDetail: probe,
    });
    const message = JSON.stringify(compile(value).message);
    assert.doesNotMatch(message, new RegExp(probe.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
    assert.match(message, /Private CEO work record/);
    assert.match(message, /Revision [a-f0-9]{64}/);
  }
});

test("outbox accepts only an explicitly typed artifact revision", () => {
  const value = fixture();
  const { version, ...untyped } = value.outboxItem.artifact;
  assert.equal(version, 1);
  value.outboxItem.artifact = untyped;
  assert.throws(() => compile(value), /explicitly typed v1 artifact/);
});

test("exported outbox validation deep-freezes the exact artifact revision", () => {
  const value = fixture();
  const deployment = compileDeploymentBinding(value.deploymentBinding);
  const validated = validateOutboxItem(value.outboxItem, deployment);
  assert.equal(Object.isFrozen(validated), true);
  assert.equal(Object.isFrozen(validated.artifact), true);
  assert.equal(Object.isFrozen(validated.artifact.facts[0]), true);
  assert.throws(() => {
    validated.artifact.facts[0].value = "Changed after validation";
  }, TypeError);
});

test("identity receipt must bind the exact deployment team CEO email principal and credential owner", () => {
  for (const [field, replacement] of [
    ["teamRef", "team:other"],
    ["ceoUserRef", "user:risely:other"],
    ["ceoEmail", "other@risely.ai"],
    ["qmPrincipalRef", "qm:principal:other"],
    ["credentialOwnerRef", "credential:slack:other"],
    ["slackTeamId", "T987654321"],
  ]) {
    const value = fixture();
    value.identityResolution[field] = replacement;
    value.identityResolution.resolutionSha256 = identityResolutionHash(value.identityResolution);
    assert.throws(() => compile(value), new RegExp(`identityResolution\\.${field} does not match`));
  }
});

test("evaluation and identity authorities are deployment pinned", () => {
  const evaluation = fixture();
  evaluation.outboxItem.evalRelease.evalAuthorityRef = "evaluator:attacker:shadow-gate";
  evaluation.outboxItem.evalRelease.receiptSha256 = evalReleaseReceiptHash(evaluation.outboxItem.evalRelease);
  evaluation.outboxItem.payloadSha256 = outboxPayloadHash(evaluation.outboxItem);
  assert.throws(() => compile(evaluation), /evalRelease\.evalAuthorityRef does not match/);
  const policy = fixture();
  policy.outboxItem.evalRelease.policySha256 = "b".repeat(64);
  policy.outboxItem.evalRelease.receiptSha256 = evalReleaseReceiptHash(policy.outboxItem.evalRelease);
  policy.outboxItem.payloadSha256 = outboxPayloadHash(policy.outboxItem);
  assert.throws(() => compile(policy), /evalRelease\.policySha256 does not match/);
  const resolver = fixture();
  resolver.identityResolution.resolverAuthorityRef = "resolver:attacker:slack-identity";
  resolver.identityResolution.resolutionSha256 = identityResolutionHash(resolver.identityResolution);
  assert.throws(() => compile(resolver), /identityResolution\.resolverAuthorityRef does not match/);
});

test("evaluation release cannot be replayed under a different CEO deployment binding", () => {
  const value = fixture();
  value.deploymentBinding = { ...value.deploymentBinding, ceoEmail: "different-ceo@risely.ai" };
  assert.throws(() => compileDeploymentBinding(value.deploymentBinding), /deploymentBinding\.ceoEmail/);
  assert.throws(() => compile(value), /deploymentBinding\.ceoEmail/);
});

test("identity resolver may return only a canonical Slack user and private DM", () => {
  const channel = fixture();
  channel.identityResolution.slackDirectMessageId = "C123456789";
  channel.identityResolution.resolutionSha256 = identityResolutionHash(channel.identityResolution);
  assert.throws(() => compile(channel), /canonical Slack identifier/);
  const malformedUser = fixture();
  malformedUser.identityResolution.slackUserId = "W123456789";
  malformedUser.identityResolution.resolutionSha256 = identityResolutionHash(malformedUser.identityResolution);
  assert.throws(() => compile(malformedUser), /canonical Slack identifier/);
});

test("delivery idempotency is stable across a fresh receipt for the same exact identity", () => {
  const original = fixture();
  const first = compile(original);
  const refreshed = fixture();
  refreshed.outboxItem = original.outboxItem;
  refreshed.identityResolution.resolverReceiptRef = "identity-receipt:refreshed";
  refreshed.identityResolution.resolvedAt = new Date().toISOString();
  refreshed.identityResolution.expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
  refreshed.identityResolution.resolutionSha256 = identityResolutionHash(refreshed.identityResolution);
  const second = compile(refreshed);
  assert.equal(second.deliveryKey, first.deliveryKey);
  assert.notEqual(second.identityResolutionSha256, first.identityResolutionSha256);
  assert.equal(second.targetBindingSha256, first.targetBindingSha256);
  assert.deepEqual(second.target, first.target);
});

test("one outbox event keeps one delivery key when a changed payload must conflict", () => {
  const original = fixture();
  const changed = structuredClone(original);
  changed.outboxItem.queuedAt = new Date(Date.parse(changed.outboxItem.queuedAt) + 1000).toISOString();
  changed.outboxItem.payloadSha256 = outboxPayloadHash(changed.outboxItem);
  const first = compile(original);
  const second = compile(changed);
  assert.equal(second.outboxEventId, first.outboxEventId);
  assert.equal(second.deliveryKey, first.deliveryKey);
  assert.notEqual(second.outboxPayloadSha256, first.outboxPayloadSha256);
  assert.equal(second.receiptContract.conflictFields.includes("outboxPayloadSha256"), true);
});

test("the durable surface rejects an alternate event id for the same artifact revision", () => {
  const value = fixture();
  value.outboxItem.eventId = `event:${"0".repeat(64)}`;
  value.outboxItem.payloadSha256 = outboxPayloadHash(value.outboxItem);
  assert.throws(() => compile(value), /outboxItem\.eventId does not match/);
});

test("artifact eval outbox and identity digests are exact and tamper evident", () => {
  const artifactTamper = fixture();
  artifactTamper.outboxItem.artifact = { ...artifactTamper.outboxItem.artifact, summary: "Changed after evaluation." };
  assert.throws(() => compile(artifactTamper), /artifactSha256 does not match/);
  const evalTamper = fixture();
  evalTamper.outboxItem.evalRelease.rubricVersion = "rubric:tampered:v1";
  assert.throws(() => compile(evalTamper), /receiptSha256 does not match/);
  const outboxTamper = fixture();
  outboxTamper.outboxItem.queuedAt = new Date(Date.parse(outboxTamper.outboxItem.queuedAt) + 1000).toISOString();
  assert.throws(() => compile(outboxTamper), /payloadSha256 does not match/);
  const identityTamper = fixture();
  identityTamper.identityResolution.slackUserId = "U987654321";
  assert.throws(() => compile(identityTamper), /resolutionSha256 does not match/);
});

test("evaluation receipt is fail closed for release side effects and independent judges", () => {
  for (const [field, replacement, expected] of [
    ["passed", false, /eval-passed shadow release/],
    ["release", false, /eval-passed shadow release/],
    ["mode", "live", /eval-passed shadow release/],
    ["sideEffects", 1, /bounded integer/],
    ["judgeIds", ["judge:luna:quality", "judge:luna:quality"], /unique identifiers/],
    ["judgeIndependenceKeys", ["origin:same", "origin:same"], /unique identifiers/],
  ]) {
    const value = fixture();
    value.outboxItem.evalRelease[field] = replacement;
    value.outboxItem.evalRelease.receiptSha256 = evalReleaseReceiptHash(value.outboxItem.evalRelease);
    value.outboxItem.payloadSha256 = outboxPayloadHash(value.outboxItem);
    assert.throws(() => compile(value), expected);
  }
});

test("expired evaluation and identity receipts are rejected", () => {
  const evaluation = fixture();
  evaluation.outboxItem.evalRelease.expiresAt = "2026-08-25T16:11:30.000Z";
  evaluation.outboxItem.evalRelease.receiptSha256 = evalReleaseReceiptHash(evaluation.outboxItem.evalRelease);
  evaluation.outboxItem.payloadSha256 = outboxPayloadHash(evaluation.outboxItem);
  assert.throws(() => compile(evaluation), /evalRelease is expired/);
  const identity = fixture();
  identity.identityResolution.expiresAt = "2026-08-25T16:11:30.000Z";
  identity.identityResolution.resolutionSha256 = identityResolutionHash(identity.identityResolution);
  assert.throws(() => compile(identity), /identityResolution is expired/);
});

test("evaluation and identity lifetimes are bounded", () => {
  const evaluation = fixture();
  evaluation.outboxItem.evalRelease.expiresAt = new Date(
    Date.parse(evaluation.outboxItem.evalRelease.evaluatedAt) + 24 * 60 * 60 * 1000 + 1,
  ).toISOString();
  evaluation.outboxItem.evalRelease.receiptSha256 = evalReleaseReceiptHash(evaluation.outboxItem.evalRelease);
  evaluation.outboxItem.payloadSha256 = outboxPayloadHash(evaluation.outboxItem);
  assert.throws(() => compile(evaluation), /evalRelease lifetime exceeds/);
  const identity = fixture();
  identity.identityResolution.expiresAt = new Date(
    Date.parse(identity.identityResolution.resolvedAt) + 60 * 60 * 1000 + 1,
  ).toISOString();
  identity.identityResolution.resolutionSha256 = identityResolutionHash(identity.identityResolution);
  assert.throws(() => compile(identity), /identityResolution lifetime exceeds/);
});

test("timestamps reject impossible calendar dates and noncanonical precision", () => {
  for (const evaluatedAt of ["2026-02-31T16:00:00.000Z", "2026-08-25T16:00:00Z"]) {
    const value = fixture();
    value.outboxItem.evalRelease.evaluatedAt = evaluatedAt;
    value.outboxItem.evalRelease.receiptSha256 = evalReleaseReceiptHash(value.outboxItem.evalRelease);
    value.outboxItem.payloadSha256 = outboxPayloadHash(value.outboxItem);
    assert.throws(() => compile(value), /canonical UTC timestamp/);
  }
  for (const [field, changes] of [
    ["updatedAt", { updatedAt: "2026-02-31T16:00:00.000Z" }],
    [
      "occurredAt",
      { evidence: [{ label: "Calendar event", source: "Google Calendar", occurredAt: "2026-02-31T16:00:00.000Z" }] },
    ],
  ]) {
    const value = fixture();
    replaceArtifact(value, changes);
    assert.throws(() => compile(value), new RegExp(`${field}.*canonical UTC timestamp`));
  }
  const postEvaluation = fixture();
  replaceArtifact(postEvaluation, {
    updatedAt: new Date(Date.parse(postEvaluation.outboxItem.evalRelease.evaluatedAt) + 1).toISOString(),
  });
  assert.throws(() => compile(postEvaluation), /artifact\.updatedAt cannot postdate evaluation/);
});

test("compilation snapshots inputs and cannot be changed afterward", () => {
  const value = fixture();
  const publication = compile(value);
  value.identityResolution.slackUserId = "U987654321";
  value.outboxItem.artifact = { ...value.outboxItem.artifact, title: "Mutated title" };
  assert.equal(publication.target.slackUserId, "U123456789");
  assert.doesNotMatch(JSON.stringify(publication.message), /Mutated title/);
  assert.throws(() => {
    publication.target.slackUserId = "U987654321";
  }, TypeError);
});

test("accessors and noncanonical input objects are rejected before compilation", () => {
  const value = fixture();
  let getters = 0;
  Object.defineProperty(value.outboxItem, "destination", {
    enumerable: true,
    get: () => {
      getters += 1;
      return "D987654321";
    },
  });
  assert.throws(() => compile(value), /canonical plain JSON|plain data field/);
  assert.equal(getters, 0);
  let traps = 0;
  const nestedProxy = new Proxy(
    {},
    {
      ownKeys() {
        traps += 1;
        return [];
      },
      getPrototypeOf() {
        traps += 1;
        return Object.prototype;
      },
      getOwnPropertyDescriptor() {
        traps += 1;
        return undefined;
      },
      get() {
        traps += 1;
        return undefined;
      },
    },
  );
  const proxiedArtifact = fixture();
  proxiedArtifact.outboxItem.artifact = nestedProxy;
  assert.throws(() => compile(proxiedArtifact));
  assert.equal(traps, 0);
  const rootProxy = new Proxy(fixture(), {
    ownKeys() {
      traps += 1;
      return [];
    },
    getPrototypeOf() {
      traps += 1;
      return Object.prototype;
    },
    getOwnPropertyDescriptor() {
      traps += 1;
      return undefined;
    },
  });
  assert.throws(() => compile(rootProxy));
  assert.equal(traps, 0);
  const inherited = fixture();
  inherited.identityResolution = Object.assign(
    Object.create({ slackUserId: "U987654321" }),
    inherited.identityResolution,
  );
  assert.throws(() => compile(inherited), /canonical plain JSON|plain data/);
  const topLevel = fixture();
  topLevel.destination = "D987654321";
  assert.throws(() => compile(topLevel), /publicationInput\.destination is not supported/);
});
