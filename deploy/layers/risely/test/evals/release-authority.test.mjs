import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { normalizeMeetingDossier } from "../../canary/chief-of-staff/index.mjs";
import {
  assertEvaluationResultStore,
  assertAuthorizedEvaluationDecision,
  createProviderFreeEvaluationAuthority,
  evaluationResultStoreRequirement,
  mintEvaluationRelease,
  prepareEvaluationCandidate,
} from "../../canary/evals/index.mjs";
import * as evalPublic from "../../canary/evals/index.mjs";
import { evaluateFixture } from "../../canary/evals/deterministic.mjs";
import { fixtureById } from "../../canary/evals/fixtures.mjs";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import {
  syntheticDeploymentProfile,
  syntheticTestJudgePrivateKeys,
  syntheticTestJudgeRoots,
} from "../../canary/deployment-profiles/testing.mjs";
import {
  assertInertEvaluationResultStoreForTesting,
  createInertEvaluationResultStoreForTesting,
  createInertProviderFreeEvaluationAuthorityForTesting,
} from "../../canary/evals/testing.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import { createProviderFreeEvaluationFixture } from "./helpers/judge-results.mjs";

const digest = (character) => character.repeat(64);
const startedAt = "2026-08-26T16:06:00.000Z";
const decisionAt = "2026-08-26T16:06:30.000Z";
const expiresAt = "2026-08-26T18:06:00.000Z";
const sourceHashes = Object.freeze({
  "deterministic.mjs": "b039c3eedd5f7bdeaa5cd33b930d5f6d15ed76fa4e53baad4a6f1f5e831ca5ad",
  "index.mjs": "69e4edc0107586399ab6fd3ba4424263bad8e4567f521ab6dadf6d5632354fbe",
  "release-authority.mjs": "37e6484abb116babf7f67f4068a99ce9cc00bf29b877a1b3bd418d724905428c",
  "result-store.mjs": "1b6377d18827fe28cc9bcd20bf2a96bb36e021541be273c8ac616d07d56e0bf3",
  "testing-result-store.mjs": "324ce59870cd28e837bcd90ec0de0a6e246dae50115eb9ae401d0166f68d8bc4",
});
const ceoContracts = createRuntimeScope(ceoDeploymentProfile).contracts;
const { EvidenceBundle, PrincipalBinding, WorkflowArtifact } = ceoContracts;

test("production evaluation source hashes are frozen", async () => {
  for (const [name, expected] of Object.entries(sourceHashes)) {
    const source = await readFile(new URL(`../../canary/evals/${name}`, import.meta.url));
    assert.equal(createHash("sha256").update(source).digest("hex"), expected);
  }
});

test("durable evaluation result stores cannot cross, clone, or forge deployment profiles", () => {
  const ceoScope = createRuntimeScope(ceoDeploymentProfile);
  const syntheticScope = createRuntimeScope(syntheticDeploymentProfile);
  const forged = (scope) => ({
    durability: "postgres_append_only",
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    persistAuthorityEvaluation() {},
    appendReplayTombstone() {},
    readRelease() {},
  });
  const { port: ceoInertStore } = createInertEvaluationResultStoreForTesting(ceoScope);
  const { port: syntheticStore } = createInertEvaluationResultStoreForTesting(syntheticScope);
  assert.equal(assertInertEvaluationResultStoreForTesting(syntheticStore, syntheticScope), syntheticStore);
  assert.throws(() => assertEvaluationResultStore(forged(ceoScope), ceoScope), /initialized PostgreSQL/);
  assert.throws(
    () => assertInertEvaluationResultStoreForTesting(forged(syntheticScope), syntheticScope),
    /inert synthetic/,
  );
  assert.throws(
    () => assertInertEvaluationResultStoreForTesting({ ...syntheticStore }, syntheticScope),
    /inert synthetic/,
  );
  assert.throws(() => assertEvaluationResultStore(ceoInertStore, ceoScope), /initialized PostgreSQL/);
  assert.throws(() => assertEvaluationResultStore(syntheticStore, ceoScope), /initialized PostgreSQL/);
  assert.throws(
    () =>
      createProviderFreeEvaluationAuthority({
        runtimeScope: ceoScope,
        resultStore: forged(ceoScope),
        readAuthorityTime: () => decisionAt,
      }),
    /initialized PostgreSQL/,
  );
  assert.equal(Object.hasOwn(evalPublic, "bindPostgresEvaluationResultStore"), false);
  const fakeDecision = Object.freeze({ decisionType: "AuthorizedProviderFreeEvaluation" });
  assert.throws(
    () => assertAuthorizedEvaluationDecision(fakeDecision, ceoScope, forged(ceoScope)),
    /exact production evaluation authority decision/,
  );
  assert.throws(
    () => assertAuthorizedEvaluationDecision({ ...fakeDecision }, ceoScope, forged(ceoScope)),
    /exact production evaluation authority decision/,
  );
});

test("deployment principals cannot be installed as evaluation trust roots", () => {
  const scope = createRuntimeScope(ceoDeploymentProfile);
  const { port } = createInertEvaluationResultStoreForTesting(scope);
  const trustRoots = scope.profile.evalPolicy.judgeClasses.map((judgeClass, index) => {
    const { publicKey } = generateKeyPairSync("ed25519");
    return {
      keyId: `fixture-key:${judgeClass}:self-review`,
      judgeRef: index === 0 ? scope.profile.identity.humanPrincipalRef : `judge:fixture:${judgeClass}`,
      judgeClass,
      originRef: `judge-origin:fixture:${judgeClass}`,
      publicKey: publicKey.export({ format: "jwk" }),
    };
  });
  assert.throws(
    () =>
      createInertProviderFreeEvaluationAuthorityForTesting({
        runtimeScope: scope,
        resultStore: port,
        trustedJudges: trustRoots,
        readAuthorityTime: () => decisionAt,
      }),
    /permit self review/,
  );
});

test("test judge keys cannot authenticate against production trust roots", () => {
  const message = Buffer.from("production-evaluation-trust-boundary", "utf8");
  const productionRoots = ceoDeploymentProfile.evalPolicy.trustedJudgeRoots;
  assert.equal(
    productionRoots.some((root) => Object.hasOwn(syntheticTestJudgePrivateKeys, root.keyId)),
    false,
  );
  for (const testRoot of syntheticTestJudgeRoots) {
    const privateKey = createPrivateKey({ key: syntheticTestJudgePrivateKeys[testRoot.keyId], format: "jwk" });
    const signature = sign(null, message, privateKey);
    assert.equal(verify(null, message, createPublicKey({ key: testRoot.publicKey, format: "jwk" }), signature), true);
    for (const productionRoot of productionRoots) {
      assert.equal(
        verify(null, message, createPublicKey({ key: productionRoot.publicKey, format: "jwk" }), signature),
        false,
      );
    }
  }
});

function payload(claimText = "Account context is ready for review.") {
  return normalizeMeetingDossier({
    meetingKey: digest("1"),
    generatedAt: "2026-08-26T16:01:00.000Z",
    calendarEvidenceHash: digest("2"),
    sources: [
      { source: "calendar", availability: "available" },
      { source: "clarify", availability: "unavailable" },
      { source: "command_center_brain", availability: "available" },
      { source: "gmail", availability: "available" },
      { source: "notion", availability: "not_connected" },
    ],
    evidence: [
      {
        evidenceRef: "evidence:calendar",
        source: "calendar",
        evidenceHash: digest("2"),
        capturedAt: "2026-08-26T16:00:00.000Z",
      },
      {
        evidenceRef: "evidence:brain",
        source: "command_center_brain",
        evidenceHash: digest("3"),
        capturedAt: "2026-08-26T16:00:00.000Z",
      },
      {
        evidenceRef: "evidence:gmail",
        source: "gmail",
        evidenceHash: digest("4"),
        capturedAt: "2026-08-26T16:00:00.000Z",
      },
    ],
    sections: {
      accountOverview: [{ claimId: "claim:account", text: claimText, citations: ["evidence:brain"] }],
      contactBackground: [
        {
          claimId: "claim:contact",
          text: "Contact context is ready for review.",
          citations: ["evidence:gmail"],
        },
      ],
      recommendedPositioning: [
        {
          claimId: "claim:positioning",
          text: "Positioning is ready for review.",
          citations: ["evidence:calendar"],
        },
      ],
    },
  });
}

function artifact(evaluationPayload = payload(), state = "ready", sourceOverrides = {}) {
  const evidenceBundle = EvidenceBundle.create({
    principalBinding: PrincipalBinding.value,
    evidence: evaluationPayload.evidence.map((entry, index) => ({
      source: sourceOverrides[entry.evidenceHash] ?? entry.source,
      sourceRecordRef: `source-record:${String(index + 5).repeat(64)}`,
      contentSha256: entry.evidenceHash,
      relatedContentSha256: [],
      observedAt: entry.capturedAt,
      fetchedAt: entry.capturedAt,
      status: "cited",
      trust: "untrusted_source_data",
      availability: "available",
      sourceTrust: "untrusted_source_data",
      sourceAvailability: "available",
      claimRefs: Object.values(evaluationPayload.sections)
        .flat()
        .filter((claim) => claim.citations.includes(entry.evidenceRef))
        .map(
          (claim) => `claim:${PrincipalBinding.hash({ claimId: claim.claimId, text: claim.text, trust: claim.trust })}`,
        ),
    })),
  });
  return WorkflowArtifact.create({
    principalBinding: PrincipalBinding.value,
    sourceLane: "chief_of_staff",
    sourceArtifactRef: `source:${digest("7")}`,
    sourceArtifactSha256: evaluationPayload.artifactHash,
    sourceRevision: digest("8"),
    workflowKind: "meeting_prep",
    state,
    evidenceBundle,
    updatedAt: "2026-08-26T16:01:00.000Z",
  });
}

function candidate(fixture, changes = {}) {
  const evaluationPayload = changes.evaluationPayload ?? payload();
  return prepareEvaluationCandidate(fixture.authority, {
    artifact: changes.artifact ?? artifact(evaluationPayload),
    evaluationPayload,
    evaluationStartedAt: changes.evaluationStartedAt ?? startedAt,
    expiresAt: changes.expiresAt ?? expiresAt,
    runNonce: changes.runNonce ?? digest("9"),
  });
}

function release(fixture, prepared, judges = fixture.issueQuorum(prepared)) {
  return mintEvaluationRelease(fixture.authority, { candidate: prepared, judgeResults: judges });
}

test("public authority evaluates the actual dossier and mints one bound synthetic shadow release", async () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  const prepared = candidate(fixture);
  const result = await release(fixture, prepared);
  assert.equal(result.artifactSha256, prepared.artifactSha256);
  assert.equal(result.policySha256, fixture.authority.policy.policySha256);
  assert.equal(result.evaluatedAt, decisionAt);
  assert.equal(result.sideEffectCount, 0);
  assert.equal(result.deploymentProfileRef, fixture.runtimeScope.profileRef);
  assert.equal(result.deploymentProfileSha256, fixture.runtimeScope.profileSha256);
  assert.equal(fixture.records.candidates.length, 1);
  assert.equal(fixture.records.judgeResults.length, 2);
  assert.equal(fixture.records.releases.length, 1);
  assert.deepEqual(result.deterministicCheckIds, [
    "release:artifact-ready",
    "release:evidence-grounded",
    "release:identity-profile-bound",
    "release:payload-content-addressed",
    "release:privacy-sanitized",
    "release:provider-capability-absent",
  ]);
  assert.equal(Object.hasOwn(evalPublic, "createJudgeResult"), false);
  assert.equal(Object.hasOwn(evalPublic, "judgeResultSigningPayload"), false);
});

test("stable subject profile and deterministic hashes are frozen while fixture trust roots are ephemeral", async () => {
  const firstFixture = createProviderFreeEvaluationFixture(decisionAt);
  const secondFixture = createProviderFreeEvaluationFixture(decisionAt);
  const first = candidate(firstFixture);
  const second = candidate(secondFixture);
  assert.equal(first.deploymentProfileSha256, firstFixture.runtimeScope.profileSha256);
  assert.equal(first.evaluationProfileSha256, second.evaluationProfileSha256);
  assert.equal(first.evaluationPayloadSha256, second.evaluationPayloadSha256);
  assert.equal(first.deterministicResultsSha256, second.deterministicResultsSha256);
  assert.notEqual(first.policySha256, second.policySha256);
  assert.equal((await release(firstFixture, first)).releaseSha256, (await release(firstFixture, first)).releaseSha256);
});

test("run nonce candidate lineage and exact judge receipt hashes produce distinct releases", async () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  const first = candidate(fixture, { runNonce: digest("9") });
  const second = candidate(fixture, { runNonce: digest("a") });
  const firstJudges = fixture.issueQuorum(first);
  const secondJudges = fixture.issueQuorum(second);
  const firstRelease = await release(fixture, first, firstJudges);
  const secondRelease = await release(fixture, second, secondJudges);
  assert.notEqual(first.runRef, second.runRef);
  assert.notEqual(firstRelease.releaseSha256, secondRelease.releaseSha256);
  assert.equal(firstRelease.candidateId, first.runRef);
  assert.equal(secondRelease.candidateId, second.runRef);
  assert.deepEqual(
    firstRelease.judges.map((judge) => judge.receiptSha256).sort(),
    firstJudges.map((judge) => judge.receiptSha256).sort(),
  );
  assert.deepEqual(
    secondRelease.judges.map((judge) => judge.receiptSha256).sort(),
    secondJudges.map((judge) => judge.receiptSha256).sort(),
  );
  assert.throws(() => release(fixture, second, firstJudges), /judge_runRef_mismatch/);
  const substituted = structuredClone(secondRelease);
  substituted.candidateId = first.runRef;
  assert.throws(() => ceoContracts.EvalRelease.validate(substituted, second.artifact), /bindings do not match/);
});

test("failed waiting and superseded artifacts can never become evaluation candidates", () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  for (const state of ["failed", "waiting", "superseded"]) {
    assert.throws(() => candidate(fixture, { artifact: artifact(payload(), state) }), /evaluation_artifact_not_ready/);
  }
});

test("caller-supplied canned check ids outputs and malformed payloads are rejected", () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  assert.throws(
    () =>
      prepareEvaluationCandidate(fixture.authority, {
        artifact: artifact(),
        evaluationPayload: payload(),
        evaluationStartedAt: startedAt,
        expiresAt,
        runNonce: digest("9"),
        deterministicCheckIds: ["release:self-asserted"],
      }),
    /unsupported shape/,
  );
  const uncited = structuredClone(payload());
  uncited.sections.accountOverview[0].citations = [];
  const { artifactHash: _artifactHash, ...uncitedProjection } = uncited;
  uncited.artifactHash = PrincipalBinding.hash(uncitedProjection);
  assert.throws(
    () => candidate(fixture, { evaluationPayload: uncited, artifact: artifact(uncited) }),
    /uncited_dossier_claim|deterministic_evaluation_failed/,
  );
  const identifying = payload("Email buyer@example.edu before review.");
  assert.throws(
    () => candidate(fixture, { evaluationPayload: identifying, artifact: artifact(identifying) }),
    /deterministic_evaluation_failed/,
  );
  const phone = payload("Call 415-555-0199 before review.");
  assert.throws(
    () => candidate(fixture, { evaluationPayload: phone, artifact: artifact(phone) }),
    /deterministic_evaluation_failed/,
  );
  const token = payload("Use xoxb-123456789-secretvalue before review.");
  assert.throws(
    () => candidate(fixture, { evaluationPayload: token, artifact: artifact(token) }),
    /deterministic_evaluation_failed/,
  );
  const fullwidth = payload("Email ｂｕｙｅｒ＠ｅｘａｍｐｌｅ．ｅｄｕ before review.");
  assert.throws(
    () => candidate(fixture, { evaluationPayload: fullwidth, artifact: artifact(fullwidth) }),
    /deterministic_evaluation_failed/,
  );
  const sourcesLaundered = payload();
  const launderedArtifact = artifact(sourcesLaundered, "ready", {
    [digest("2")]: "gmail",
    [digest("3")]: "calendar",
    [digest("4")]: "notion",
  });
  assert.throws(
    () => candidate(fixture, { evaluationPayload: sourcesLaundered, artifact: launderedArtifact }),
    /deterministic_evaluation_failed/,
  );
  const capabilityInjected = structuredClone(payload());
  capabilityInjected.presentationSinkAllowed = true;
  capabilityInjected.providerInvocationAllowed = true;
  const { artifactHash: _priorHash, ...capabilityProjection } = capabilityInjected;
  capabilityInjected.artifactHash = PrincipalBinding.hash(capabilityProjection);
  assert.throws(
    () => candidate(fixture, { evaluationPayload: capabilityInjected, artifact: artifact(capabilityInjected) }),
    /unsupported shape|capability is invalid/,
  );
  const actionInjected = structuredClone(payload());
  actionInjected.send = true;
  const { artifactHash: _actionHash, ...actionProjection } = actionInjected;
  actionInjected.artifactHash = PrincipalBinding.hash(actionProjection);
  assert.throws(
    () => candidate(fixture, { evaluationPayload: actionInjected, artifact: artifact(actionInjected) }),
    /unsupported shape/,
  );
});

test("two different dossiers produce different checks and cannot reuse judge receipts", () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  const first = candidate(fixture);
  const changedPayload = payload("A materially changed account finding is ready for review.");
  const second = candidate(fixture, {
    evaluationPayload: changedPayload,
    artifact: artifact(changedPayload),
    runNonce: digest("a"),
  });
  assert.notEqual(first.evaluationPayloadSha256, second.evaluationPayloadSha256);
  assert.notEqual(first.deterministicResultsSha256, second.deterministicResultsSha256);
  assert.throws(() => release(fixture, second, fixture.issueQuorum(first)), /judge_runRef_mismatch/);
});

test("duplicate identities colluding origins renamed judges and duplicate nonces cannot form quorum", () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  const prepared = candidate(fixture);
  const quality = fixture.issue(prepared, "quality");
  assert.throws(() => release(fixture, prepared, [quality, quality]), /independent_judge_quorum_invalid/);
  const colluding = fixture.issue(prepared, "safety", { originRef: quality.originRef });
  assert.throws(() => release(fixture, prepared, [quality, colluding]), /judge_origin_not_trusted/);
  const renamed = fixture.issue(prepared, "safety", { judgeRef: "judge:self-asserted:safety" });
  assert.throws(() => release(fixture, prepared, [quality, renamed]), /judge_origin_not_trusted/);
  const duplicateNonce = fixture.issue(prepared, "safety", { nonce: quality.nonce });
  assert.throws(() => release(fixture, prepared, [quality, duplicateNonce]), /independent_judge_quorum_invalid/);
});

test("artifact evidence payload profile policy and deterministic substitutions fail closed", () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  const prepared = candidate(fixture);
  for (const [field, value] of [
    ["artifactSha256", digest("a")],
    ["evidenceSha256", digest("b")],
    ["evaluationPayloadSha256", digest("c")],
    ["deploymentProfileSha256", digest("d")],
    ["evaluationProfileSha256", digest("0")],
    ["policySha256", digest("e")],
    ["deterministicResultsSha256", digest("f")],
  ]) {
    const judges = fixture.issueQuorum(prepared, { quality: { [field]: value } });
    assert.throws(() => release(fixture, prepared, judges), new RegExp(`judge_${field}_mismatch`));
  }
});

test("captured clock rejects future stale expired and cross-run replay attempts", () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  const prepared = candidate(fixture);
  const future = fixture.issueQuorum(prepared, { safety: { issuedAt: "2026-08-26T16:06:30.001Z" } });
  assert.throws(() => release(fixture, prepared, future), /judge_result_time_bounds_invalid/);
  const preCandidate = fixture.issueQuorum(prepared, { quality: { issuedAt: "2026-08-26T16:05:59.999Z" } });
  assert.throws(() => release(fixture, prepared, preCandidate), /judge_result_time_bounds_invalid/);
  const earlyExpiry = fixture.issueQuorum(prepared, { quality: { expiresAt: "2026-08-26T17:06:00.000Z" } });
  assert.throws(() => release(fixture, prepared, earlyExpiry), /judge_result_time_bounds_invalid/);
  fixture.setAuthorityTime(expiresAt);
  assert.throws(() => release(fixture, prepared), /evaluation_authority_time_invalid/);
  const futureFixture = createProviderFreeEvaluationFixture(decisionAt);
  const futureCandidate = candidate(futureFixture, {
    evaluationStartedAt: "2099-01-01T00:00:00.000Z",
    expiresAt: "2099-01-01T01:00:00.000Z",
  });
  assert.throws(() => release(futureFixture, futureCandidate), /evaluation_authority_time_invalid/);
});

test("low scores disagreement failed verdicts and effect claims never release", () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  const prepared = candidate(fixture);
  assert.throws(
    () => release(fixture, prepared, fixture.issueQuorum(prepared, { quality: { scores: { safety: 3 } } })),
    /judge_score_gate_failed/,
  );
  assert.throws(
    () =>
      release(
        fixture,
        prepared,
        fixture.issueQuorum(prepared, { quality: { scores: { accuracy: 4 } }, safety: { scores: { accuracy: 2 } } }),
      ),
    /judge_score_gate_failed/,
  );
  assert.throws(
    () =>
      release(fixture, prepared, fixture.issueQuorum(prepared, { safety: { passed: false, failures: ["unsafe"] } })),
    /judge_result_failed/,
  );
  assert.throws(
    () => release(fixture, prepared, fixture.issueQuorum(prepared, { quality: { sideEffectCount: 1 } })),
    /judge_side_effects_detected/,
  );
  assert.throws(
    () =>
      release(
        fixture,
        prepared,
        fixture.issueQuorum(prepared, {
          quality: {
            gateResults: Object.fromEntries(
              prepared.policySnapshot.requiredGates.map((gate, index) => [gate, index !== 0]),
            ),
          },
        }),
      ),
    /judge_required_gate_failed/,
  );
  assert.throws(
    () => release(fixture, prepared, fixture.issueQuorum(prepared, { safety: { gateResults: { forged_gate: true } } })),
    /unsupported shape/,
  );
  const forgedCandidate = structuredClone(prepared);
  forgedCandidate.effectObservation.attemptedEffectCount = 1;
  assert.throws(() => release(fixture, forgedCandidate, fixture.issueQuorum(prepared)), /evaluation_candidate_invalid/);
  const substitutedPolicy = structuredClone(prepared);
  substitutedPolicy.policySnapshot.requiredGates = [];
  assert.throws(
    () => release(fixture, substitutedPolicy, fixture.issueQuorum(prepared)),
    /evaluation_candidate_invalid/,
  );
});

test("self-hashed signatures quorum proxies and accessors are rejected without trap execution", () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  const prepared = candidate(fixture);
  const judges = structuredClone(fixture.issueQuorum(prepared));
  judges[0].scores.accuracy = 1;
  const projection = { ...judges[0] };
  delete projection.receiptSha256;
  delete projection.signature;
  judges[0].receiptSha256 = PrincipalBinding.hash(projection);
  assert.throws(() => release(fixture, prepared, judges), /judge_signature_invalid/);
  let traps = 0;
  const proxiedQuorum = new Proxy(fixture.issueQuorum(prepared), {
    get() {
      traps += 1;
      throw new Error("trap");
    },
  });
  assert.throws(() => release(fixture, prepared, proxiedQuorum), /plain data|proxy/);
  assert.equal(traps, 0);
  const quorum = fixture.issueQuorum(prepared);
  const accessor = structuredClone(quorum[0]);
  let accessorCalls = 0;
  Object.defineProperty(accessor, "judgeRef", {
    enumerable: true,
    get: () => {
      accessorCalls += 1;
      return quorum[0].judgeRef;
    },
  });
  assert.throws(() => release(fixture, prepared, [accessor, quorum[1]]), /plain data field/);
  assert.equal(accessorCalls, 0);
});

test("missing partial unknown judges and an unbound authority remain unavailable", () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  const prepared = candidate(fixture);
  assert.throws(() => release(fixture, prepared, []), /independent_judges_unavailable/);
  assert.throws(
    () => release(fixture, prepared, [fixture.issue(prepared, "quality")]),
    /independent_judges_unavailable/,
  );
  assert.throws(
    () => release(fixture, prepared, fixture.issueQuorum(prepared, { safety: { keyId: "fixture-key:unknown:v1" } })),
    /judge_origin_not_trusted/,
  );
  assert.throws(
    () => prepareEvaluationCandidate({ ...fixture.authority }, {}),
    /bound provider-free evaluation authority/,
  );
});

test("shadow authority requires a durable result store and cannot authorize provider activation", () => {
  const fixture = createProviderFreeEvaluationFixture(decisionAt);
  const deploymentPolicy = fixture.runtimeScope.profile.evalPolicy;
  assert.equal(fixture.authority.policy.authoritativeProviderRelease, false);
  assert.equal(fixture.authority.policy.providerInvocationAllowed, false);
  assert.equal(fixture.authority.policy.selfReviewAllowed, false);
  assert.equal(fixture.authority.policy.policyRef, deploymentPolicy.policyRef);
  assert.equal(fixture.authority.policy.deploymentEvalPolicySha256, PrincipalBinding.hash(deploymentPolicy));
  assert.deepEqual(fixture.authority.policy.requiredCheckIds, deploymentPolicy.requiredDeterministicCheckIds);
  assert.deepEqual(fixture.authority.policy.requiredGates, deploymentPolicy.requiredGates);
  assert.equal(fixture.records.candidates.length, 0);
  assert.deepEqual(fixture.authority.policy.requiredJudgeClasses, deploymentPolicy.judgeClasses);
  assert.equal(fixture.authority.policy.minimumScore, deploymentPolicy.minimumScore);
  assert.equal(fixture.authority.policy.maximumScoreSpread, deploymentPolicy.maximumScoreSpread);
  assert.equal(fixture.authority.policy.maximumEvaluationRuntimeMs, deploymentPolicy.maximumEvaluationRuntimeMs);
  assert.deepEqual(evaluationResultStoreRequirement, {
    requiredForProviderActivation: true,
    implemented: true,
    shadowReleaseAllowed: true,
    authorityCanAuthorizeProviderInvocation: false,
    durability: "postgres_append_only_results_releases_and_replay_tombstones",
  });
});

test("grounding rejects two known-source swaps and an unrelated extra citation", () => {
  const fixture = fixtureById("dossier-grounding");
  const baseline = {
    claims: [
      { id: "stage", sourceIds: ["crm-1"] },
      { id: "security-review", sourceIds: ["mail-1"] },
      { id: "pilot-date", sourceIds: ["note-1"], stale: true },
    ],
  };
  for (const claims of [
    baseline.claims.map((claim) => (claim.id === "stage" ? { ...claim, sourceIds: ["mail-1"] } : claim)),
    baseline.claims.map((claim) => (claim.id === "security-review" ? { ...claim, sourceIds: ["note-1"] } : claim)),
    baseline.claims.map((claim) => (claim.id === "pilot-date" ? { ...claim, sourceIds: ["note-1", "crm-1"] } : claim)),
  ]) {
    assert.equal(evaluateFixture(fixture, { claims }).passed, false);
  }
});
