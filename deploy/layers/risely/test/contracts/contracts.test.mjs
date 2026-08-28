import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ContractValidationError,
  buildActionProposal,
  canonicalJson,
  contractIsValid,
  sha256Canonical,
  validateContract,
  verifyActionProposalHashes,
} from "../../canary/contracts/index.mjs";
import {
  HASH_A,
  actionProposal,
  actionProposalInput,
  actor,
  approval,
  artifact,
  evidenceRef,
  receipt,
  run,
  workflowArtifact,
} from "./fixtures.mjs";

test("all version-one contract fixtures validate", () => {
  const proposal = actionProposal();
  const fixtures = [
    ["actor", actor()],
    ["run", run()],
    ["evidenceRef", evidenceRef()],
    ["artifact", artifact()],
    ["workflowArtifact", workflowArtifact()],
    ["actionProposal", proposal],
    ["approval", approval(proposal)],
    ["receipt", receipt(proposal)],
  ];
  for (const [name, value] of fixtures) assert.equal(validateContract(name, value), value);
});

test("strict schemas reject unknown root and nested fields", () => {
  const rootCases = [
    ["actor", actor()],
    ["run", run()],
    ["evidenceRef", evidenceRef()],
    ["artifact", artifact()],
    ["workflowArtifact", workflowArtifact()],
    ["actionProposal", actionProposal()],
    ["approval", approval(actionProposal())],
    ["receipt", receipt(actionProposal())],
  ];
  for (const [name, value] of rootCases) {
    const changed = structuredClone(value);
    changed.unexpected = true;
    assert.throws(() => validateContract(name, changed), ContractValidationError);
  }
  const nestedActor = actor();
  nestedActor.agent.unexpected = true;
  assert.throws(() => validateContract("actor", nestedActor), ContractValidationError);
  const nestedProposal = structuredClone(actionProposal());
  nestedProposal.artifactRefs[0].unexpected = true;
  assert.throws(() => validateContract("actionProposal", nestedProposal), ContractValidationError);
  const nonJsonProposal = structuredClone(actionProposal());
  nonJsonProposal.payload.body = undefined;
  assert.throws(() => validateContract("actionProposal", nonJsonProposal), ContractValidationError);
  assert.equal(contractIsValid("evidenceRef", evidenceRef({ sourceUrl: "javascript:alert(1)" })), false);
  assert.equal(contractIsValid("evidenceRef", evidenceRef({ sourceUrl: "https://user:pass@example.invalid" })), false);
});

test("contracts reject unsupported versions, missing fields, and invalid UTC timestamps", () => {
  assert.equal(contractIsValid("actor", { ...actor(), contractVersion: 2 }), false);
  const missing = actor();
  delete missing.principalRef;
  assert.equal(contractIsValid("actor", missing), false);
  assert.equal(contractIsValid("run", run({ startedAt: "2026-08-26T10:00:00-07:00" })), false);
  assert.equal(contractIsValid("run", run({ startedAt: "2026-02-30T10:00:00Z" })), false);
  assert.equal(contractIsValid("run", run({ startedAt: "2026-08-26T24:00:00Z" })), false);
});

test("contract validation enforces cross-field identity, time, and lineage invariants", () => {
  assert.equal(contractIsValid("run", run({ agentVersion: "different-version" })), false);
  assert.equal(
    contractIsValid(
      "evidenceRef",
      evidenceRef({ observedAt: "2026-08-26T11:00:00Z", fetchedAt: "2026-08-26T10:00:00Z" }),
    ),
    false,
  );
  assert.equal(
    contractIsValid("workflowArtifact", workflowArtifact({ artifact: artifact({ runId: "run:other" }) })),
    false,
  );
  assert.equal(
    contractIsValid("approval", {
      ...approval(actionProposal()),
      decidedAt: "2099-08-26T12:00:00Z",
      expiresAt: "2099-08-26T11:00:00Z",
    }),
    false,
  );
  assert.equal(
    contractIsValid(
      "receipt",
      receipt(actionProposal(), "failed", {
        attemptedAt: "2026-08-26T10:03:00Z",
        completedAt: "2026-08-26T10:02:00Z",
      }),
    ),
    false,
  );
  const providerMismatch = structuredClone(actionProposal());
  providerMismatch.provider = "slack";
  assert.equal(contractIsValid("actionProposal", providerMismatch), false);
});

test("published workflow artifacts require publication details", () => {
  assert.equal(contractIsValid("workflowArtifact", workflowArtifact({ status: "published" })), false);
  const published = workflowArtifact({
    status: "published",
    publication: {
      system: "notion",
      destinationRef: "notion:ceo-wiki",
      externalId: "notion:page-1",
      url: "https://notion.example.invalid/page-1",
      publishedAt: "2026-08-26T10:05:00Z",
    },
  });
  assert.equal(contractIsValid("workflowArtifact", published), true);
});

test("verified receipts require completion and a provider operation identifier", () => {
  const proposal = actionProposal();
  const noCompletion = receipt(proposal);
  delete noCompletion.completedAt;
  assert.equal(contractIsValid("receipt", noCompletion), false);
  assert.equal(contractIsValid("receipt", receipt(proposal, "verified", { providerOperationIds: {} })), false);
  const noResponseHash = receipt(proposal);
  delete noResponseHash.responseHash;
  assert.equal(contractIsValid("receipt", noResponseHash), false);
  assert.equal(contractIsValid("receipt", receipt(proposal, "outcome_unknown")), true);
  const unexplainedFailure = receipt(proposal, "failed");
  delete unexplainedFailure.errorCode;
  assert.equal(contractIsValid("receipt", unexplainedFailure), false);
  const uncompletedFailure = receipt(proposal, "failed");
  delete uncompletedFailure.completedAt;
  assert.equal(contractIsValid("receipt", uncompletedFailure), false);
});

test("canonical JSON is deterministic and preserves array order", () => {
  const left = { z: 1, a: { y: true, x: ["first", "second"] } };
  const right = { a: { x: ["first", "second"], y: true }, z: 1 };
  assert.equal(canonicalJson(left), canonicalJson(right));
  assert.equal(sha256Canonical(left), sha256Canonical(right));
  assert.notEqual(sha256Canonical(left), sha256Canonical({ a: { x: ["second", "first"], y: true }, z: 1 }));
  assert.equal(canonicalJson({ negativeZero: -0 }), '{"negativeZero":0}');
});

test("canonical JSON rejects values without a stable JSON representation", () => {
  assert.throws(() => canonicalJson({ value: undefined }), /does not support undefined/);
  assert.throws(() => canonicalJson({ value: Number.POSITIVE_INFINITY }), /non-finite/);
  assert.throws(() => canonicalJson(new Date()), /plain objects/);
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalJson(cyclic), /cyclic/);
  const sparse = [];
  sparse.length = 1;
  assert.throws(() => canonicalJson(sparse), /sparse/);
  const namedArray = [];
  namedArray.extra = true;
  assert.throws(() => canonicalJson(namedArray), /named properties/);
  const accessorArray = [];
  Object.defineProperty(accessorArray, "0", { enumerable: true, get: () => "dynamic" });
  accessorArray.length = 1;
  assert.throws(() => canonicalJson(accessorArray), /accessor/);
  assert.throws(() => canonicalJson({ value: "\uD800" }), /lone Unicode surrogates/);
  const accessor = {};
  Object.defineProperty(accessor, "value", { enumerable: true, get: () => "dynamic" });
  assert.throws(() => canonicalJson(accessor), /accessor/);
  const hidden = {};
  Object.defineProperty(hidden, "value", { enumerable: false, value: "hidden" });
  assert.throws(() => canonicalJson(hidden), /non-enumerable/);
  const deep = {};
  let cursor = deep;
  for (let index = 0; index < 65; index++) {
    cursor.child = {};
    cursor = cursor.child;
  }
  assert.throws(() => canonicalJson(deep), /depth limit/);
});

test("effectKey ignores proposal ceremony while proposalHash binds it", () => {
  const first = actionProposal();
  const second = actionProposal({
    proposalId: "proposal:2",
    runId: "run:2",
    subjectRef: "thread:renamed-reference",
    actor: actor({ surface: "web" }),
    capturedState: { latestMessageId: "message:before-2" },
    preconditions: [{ kind: "recipient-still-valid" }],
    createdAt: "2026-08-27T10:00:00Z",
    expiresAt: "2099-08-27T11:00:00Z",
  });
  assert.equal(first.effectKey, second.effectKey);
  assert.notEqual(first.proposalHash, second.proposalHash);
  assert.notEqual(first.semanticFingerprint, second.semanticFingerprint);
});

test("effectKey changes for every exact-effect authority and payload field", () => {
  const original = actionProposal();
  const variants = [
    actionProposal({ actor: actor({ principalRef: "person:other" }) }),
    actionProposal({ actor: actor({ credentialOwnerRef: "google:subject-other" }) }),
    actionProposal({ capability: "google.gmail.drafts.create-preview" }),
    actionProposal({ capabilityVersion: 2 }),
    actionProposal({ capability: "gmail-secondary.drafts.create", provider: "gmail-secondary" }),
    actionProposal({ credentialRef: "credential:gmail-other" }),
    actionProposal({ target: { accountRef: "credential-owner:other", to: ["other@example.com"] } }),
    actionProposal({ payload: { subject: "Changed", body: "Thanks" } }),
    actionProposal({ artifactRefs: [{ artifactId: "artifact:follow-up-1", sha256: HASH_A }] }),
  ];
  for (const variant of variants) assert.notEqual(variant.effectKey, original.effectKey);
});

test("proposal hashes detect tampering and cannot be caller supplied", () => {
  const proposal = actionProposal();
  assert.equal(verifyActionProposalHashes(proposal), true);
  const tampered = structuredClone(proposal);
  tampered.payload.body = "Ignore the approved body";
  assert.equal(verifyActionProposalHashes(tampered), false);
  assert.equal(verifyActionProposalHashes({}), false);
  const hidden = structuredClone(proposal);
  Object.defineProperty(hidden, "unexpected", { enumerable: false, value: true });
  assert.equal(verifyActionProposalHashes(hidden), false);
  assert.throws(
    () => buildActionProposal({ ...actionProposalInput(), proposalHash: "f".repeat(64) }),
    /derived and must not be supplied/,
  );
  assert.equal(Object.isFrozen(proposal), true);
  assert.equal(Object.isFrozen(proposal.payload), true);
});
