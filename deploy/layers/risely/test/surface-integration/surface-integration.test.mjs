import assert from "node:assert/strict";
import { test } from "node:test";
import { composePrivateCeoSurfaces } from "../../canary/surface-integration/index.mjs";
import {
  surfaceArtifactKinds,
  surfaceArtifactStates,
  surfacePresentationCodeForState,
  surfacePresentationCodes,
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
  links: [Object.freeze({ linkRef: `qm:${digest}`, availability: "available" })],
});

function mutableArtifact() {
  return structuredClone(base);
}

test("one canonical immutable snapshot aligns artifact revision evidence and status across all surfaces", () => {
  const input = mutableArtifact();
  const result = composePrivateCeoSurfaces(input);
  input.revision = "changed";
  input.state = "failed";
  input.evidence[0].trust = "untrusted_source_data";
  const slack = JSON.stringify(result.slack);
  assert.equal(result.audience.scope, "private_ceo");
  assert.equal(result.artifact.revision, base.revision);
  assert.equal(result.status.state, base.state);
  assert.deepEqual(result.evidence, base.evidence);
  assert.equal(result.qm.artifact.artifactRef, base.artifactRef);
  assert.equal(result.qm.artifact.revision, base.revision);
  assert.equal(result.artifact, result.qm.artifact);
  assert.equal(result.evidence, result.qm.sections.find((section) => section.key === "evidence").items);
  assert.equal(result.notion.page.artifactRef, base.artifactRef);
  assert.equal(result.notion.page.revision, base.revision);
  assert.equal(result.notion.page.state, base.state);
  assert.equal(result.evidence, result.notion.sections.find((section) => section.key === "evidence").items);
  assert.match(slack, new RegExp(`artifact:${digest}`));
  assert.match(slack, new RegExp(`evidence:${digest}`));
  assert.match(slack, /verified_source/);
  assert.match(slack, /Status ready/);
  assert.equal(result.actionless, true);
  assert.equal(result.slack.response_type, "ephemeral");
  assert.ok(result.slack.blocks.every((block) => block.type !== "actions"));
  assert.doesNotMatch(JSON.stringify(result), /"actions"|"button"|action_id|https?:\/\//);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.evidence), true);
  assert.equal(Object.isFrozen(result.evidence[0]), true);
});

test("the composition rejects mutating proxies, accessors, exotic values, inherited fields, and missing own fields", () => {
  const proxy = new Proxy(mutableArtifact(), {
    get(target, key, receiver) {
      if (key === "revision") target.revision = "mutated";
      return Reflect.get(target, key, receiver);
    },
  });
  const inherited = Object.create(base);
  const accessor = mutableArtifact();
  Object.defineProperty(accessor, "revision", { enumerable: true, get: () => "7" });
  const nestedProxy = mutableArtifact();
  nestedProxy.evidence[0] = new Proxy(nestedProxy.evidence[0], {
    get(target, key, receiver) {
      if (key === "trust") target.trust = "untrusted_source_data";
      return Reflect.get(target, key, receiver);
    },
  });
  for (const input of [
    proxy,
    nestedProxy,
    inherited,
    accessor,
    { ...mutableArtifact(), evidence: new Set() },
    { ...mutableArtifact(), evidence: undefined },
  ]) {
    assert.throws(() => composePrivateCeoSurfaces(input), /plain data|cloneable|required|must be a list/);
  }
});

test("the composition is total across all CEO work and non-ready states", () => {
  assert.deepEqual(surfacePresentationCodes, Object.values(surfacePresentationCodeForState));
  let ordinal = 0;
  for (const kind of surfaceArtifactKinds) {
    for (const state of surfaceArtifactStates) {
      ordinal += 1;
      const result = composePrivateCeoSurfaces({
        ...base,
        kind,
        state,
        artifactRef: `artifact:${ordinal.toString(16).padStart(64, "a")}`,
      });
      assert.equal(result.artifact.kind, kind);
      assert.equal(result.status.state, state);
      assert.equal(result.artifact.presentationCode, surfacePresentationCodeForState[state]);
      assert.ok(result.slack.blocks.every((block) => block.type !== "actions"));
      assert.equal(result.notion.sections.length, 5);
    }
  }
});

test("the compact surface boundary accepts only opaque identifiers and closed codes", () => {
  for (const field of ["title", "summary", "facts", "highlights", "statusDetail", "narrative", "company", "person"]) {
    assert.throws(
      () => validateSurfaceArtifact({ ...base, [field]: "arbitrary CEO-visible content" }),
      /not supported/,
    );
  }
  for (const artifactRef of [
    `artifact:${digest.slice(1)}`,
    `artifact:${digest}0`,
    `artifact:${digest.toUpperCase()}`,
    "artifact:https://unsafe.example",
    "artifact:foo:bar",
    "artifact:foo/bar",
    "artifact:foo\\bar",
    "artifact:foo@bar",
    "artifact:foo?bar",
    "artifact:foo#bar",
    "artifact:foo%bar",
    "artifact:legacy-record",
    "artifact:www.unsafe",
    "artifact:unsafe.example",
    "artifact:127.0.0.1",
    "artifact:+44-20-7946-0958",
    "artifact:415-555-0100",
    "artifact:123-45-6789",
    "artifact:AKIAIOSFODNN7EXAMPLE",
    "artifact:xoxb-12345678901234567890",
    "artifact:sk-live-12345678901234567890",
    "artifact:password-supersecret",
    "artifact:abcdefghijklmnopqrstuvwxyz0123456789abcdef",
  ]) {
    assert.throws(() => validateSurfaceArtifact({ ...base, artifactRef }), /digest reference/);
  }
  for (const linkRef of [
    "qm:https://unsafe.example",
    "qm:foo:bar",
    "qm:www.unsafe",
    "qm:unsafe.example",
    "qm:127.0.0.1",
    "qm:xoxb-12345678901234567890",
    "qm:sk-live-12345678901234567890",
  ]) {
    assert.throws(
      () => validateSurfaceArtifact({ ...base, links: [{ linkRef, availability: "available" }] }),
      /digest reference/,
    );
  }
  for (const evidenceRef of [
    "evidence:127.0.0.1",
    "evidence:+44-20-7946-0958",
    "evidence:xoxb-12345678901234567890",
    "evidence:sk-live-12345678901234567890",
  ]) {
    assert.throws(
      () =>
        validateSurfaceArtifact({
          ...base,
          evidence: [{ evidenceRef, trust: "verified_source", availability: "available" }],
        }),
      /digest reference/,
    );
  }
  for (const change of [
    { artifactRef: `qm:${digest}` },
    { evidence: [{ evidenceRef: `artifact:${digest}`, trust: "verified_source", availability: "available" }] },
    { links: [{ linkRef: `evidence:${digest}`, availability: "available" }] },
    { revision: "7" },
  ]) {
    assert.throws(() => validateSurfaceArtifact({ ...base, ...change }), /digest reference|digest revision/);
  }
  for (const change of [
    { blocks: [] },
    { actions: [] },
    { html: "unsafe" },
    { presentationCode: "private_ceo_review" },
    {
      evidence: [
        {
          evidenceRef: "evidence:calendar-001",
          source: "Calendar",
          trust: "verified_source",
          availability: "available",
        },
      ],
    },
  ]) {
    assert.throws(() => validateSurfaceArtifact({ ...base, ...change }), /not supported|supported identifier/);
  }
  assert.throws(
    () => validateSurfaceArtifact({ ...base, state: "waiting", presentationCode: "private_ceo_review" }),
    /surfaceArtifact\.presentationCode is not supported/,
  );
});

test("fixed templates keep arbitrary secrets and personal data out of every rendered surface", () => {
  const result = composePrivateCeoSurfaces(base);
  const serialized = JSON.stringify(result);
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
    assert.doesNotMatch(serialized, new RegExp(probe.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
  }
});
