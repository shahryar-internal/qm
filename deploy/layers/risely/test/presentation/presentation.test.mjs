import assert from "node:assert/strict";
import { test } from "node:test";
import {
  buildPresentation,
  buildQmRenderer,
  buildSlackCard,
  validateArtifact,
  validateSurfaceArtifact,
} from "../../canary/presentation/index.mjs";

const digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const base = Object.freeze({
  schemaVersion: 1,
  artifactRef: `artifact:${digest}`,
  revision: digest,
  kind: "meeting_prep",
  state: "ready",
  evidence: [
    Object.freeze({
      evidenceRef: `evidence:${digest}`,
      trust: "verified_source",
      availability: "available",
    }),
  ],
  links: [],
});

test("one public surface artifact produces actionless Slack and QM render models", () => {
  const presentation = buildPresentation(base);
  assert.equal(presentation.actionless, true);
  assert.equal(presentation.slack.audience.scope, "private_ceo");
  assert.equal(presentation.qm.type, "qm_work_card");
  assert.equal(Object.hasOwn(presentation.slack, "actions"), false);
  assert.equal(presentation.qm.actionless, true);
  assert.doesNotMatch(JSON.stringify(presentation), /interactionRef|action_id|"actions"|"button"/);
});

test("QM carries artifact revision, evidence, status, and explicit trust labels", () => {
  const card = buildQmRenderer({ ...base, state: "waiting" });
  assert.equal(card.artifact.artifactRef, base.artifactRef);
  assert.equal(card.artifact.revision, base.revision);
  assert.equal(card.status.state, "waiting");
  assert.equal(card.sections.find((section) => section.key === "evidence").items[0].trust, "verified_source");
  assert.equal(card.sections.find((section) => section.key === "cross_surface_record").items[1].value, base.revision);
  assert.equal(
    card.sections
      .find((section) => section.key === "executive_brief")
      .items[0].value.includes("authenticated artifact view"),
    true,
  );
});

test("surface validation rejects inherited, accessor, exotic, and polluted inputs before output", () => {
  const inherited = Object.create(base);
  const accessor = { ...base };
  Object.defineProperty(accessor, "revision", { enumerable: true, get: () => "2" });
  const nullPrototype = Object.assign(Object.create(null), base);
  const polluted = { ...base };
  Object.defineProperty(polluted, "__proto__", { enumerable: true, value: "blocked" });
  for (const value of [inherited, accessor, nullPrototype, new Date(), polluted, { ...base, evidence: [undefined] }]) {
    assert.throws(() => validateSurfaceArtifact(value), /plain data|forbidden key/);
  }
});

test("legacy artifact validation remains available only for the shadow publisher compatibility renderer", () => {
  const legacy = {
    id: "run-meeting-123",
    revision: "2",
    kind: "meeting_prep",
    state: "ready",
    title: "Executive meeting preparation",
    summary: "Focus on the decision owner and the implementation risk.",
    facts: [],
    evidence: [],
    links: [],
    actions: [],
    updatedAt: "2026-08-26T16:00:00.000Z",
  };
  assert.equal(validateArtifact(legacy).id, legacy.id);
  assert.throws(() => validateArtifact({ ...legacy, summary: "<unsafe>" }), /safe plain text/);
  assert.throws(() => buildSlackCard(legacy), /surfaceArtifact\.id is not supported/);
});
