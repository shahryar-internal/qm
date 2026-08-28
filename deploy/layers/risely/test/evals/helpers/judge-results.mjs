import { generateKeyPairSync, sign } from "node:crypto";
import { judgeResultSigningPayload } from "../../../canary/evals/release-authority.mjs";
import { ceoDeploymentProfile } from "../../../canary/deployment-profiles/index.mjs";
import {
  createInertEvaluationResultStoreForTesting,
  createInertProviderFreeEvaluationAuthorityForTesting,
} from "../../../canary/evals/testing.mjs";
import { createRuntimeScope } from "../../../canary/runtime-scope/index.mjs";

function fixtureJudge(judgeClass) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return Object.freeze({
    keyId: `fixture-key:${judgeClass}:v1`,
    judgeRef: `judge:provider-free:${judgeClass}:v1`,
    judgeClass,
    originRef: `origin:provider-free:${judgeClass}:v1`,
    publicKey: Object.freeze(publicKey.export({ format: "jwk" })),
    privateKey,
  });
}

export function createProviderFreeEvaluationFixture(initialAuthorityTime) {
  let authorityTime = initialAuthorityTime;
  const runtimeScope = createRuntimeScope(ceoDeploymentProfile);
  const { port: resultStore, records } = createInertEvaluationResultStoreForTesting(runtimeScope);
  const contracts = runtimeScope.contracts;
  const judges = Object.freeze({ quality: fixtureJudge("quality"), safety: fixtureJudge("safety") });
  const authority = createInertProviderFreeEvaluationAuthorityForTesting({
    runtimeScope,
    resultStore,
    trustedJudges: Object.values(judges).map(({ privateKey: _privateKey, ...judge }) => judge),
    readAuthorityTime: () => authorityTime,
  });

  const issue = (candidate, judgeClass, changes = {}) => {
    const judge = judges[judgeClass];
    if (!judge) throw new TypeError("Unknown fixture judge class");
    const scores = { accuracy: 5, grounding: 5, safety: 5, voice: 4, usefulness: 4, ...(changes.scores ?? {}) };
    const base = {
      schemaVersion: 1,
      receiptType: "ProviderFreeJudgeResult",
      keyId: judge.keyId,
      judgeRef: judge.judgeRef,
      judgeClass: judge.judgeClass,
      originRef: judge.originRef,
      runRef: candidate.runRef,
      artifactSha256: candidate.artifactSha256,
      evidenceSha256: candidate.evidenceSha256,
      evaluationPayloadSha256: candidate.evaluationPayloadSha256,
      deploymentProfileSha256: candidate.deploymentProfileSha256,
      evaluationProfileSha256: candidate.evaluationProfileSha256,
      policySha256: candidate.policySha256,
      deterministicResultsSha256: candidate.deterministicResultsSha256,
      sideEffectCount: 0,
      scores,
      gateResults: Object.fromEntries(runtimeScope.profile.evalPolicy.requiredGates.map((gate) => [gate, true])),
      passed: true,
      failures: [],
      evidenceRefs: [
        `artifact:${candidate.artifactSha256}`,
        `evidence:${candidate.evidenceSha256}`,
        `payload:${candidate.evaluationPayloadSha256}`,
      ],
      issuedAt: authorityTime,
      expiresAt: candidate.expiresAt,
      nonce: contracts.PrincipalBinding.hash({ runRef: candidate.runRef, judgeRef: judge.judgeRef }),
      ...changes,
      scores,
    };
    const projection = { ...base };
    const receiptSha256 = contracts.PrincipalBinding.hash(projection);
    const pending = { ...base, receiptSha256, signature: "A".repeat(86) };
    const signature = sign(null, judgeResultSigningPayload(pending), judge.privateKey).toString("base64url");
    return contracts.PrincipalBinding.freeze({ ...base, receiptSha256, signature });
  };

  return Object.freeze({
    authority,
    runtimeScope,
    records,
    issue,
    issueQuorum(candidate, changes = {}) {
      return Object.freeze([issue(candidate, "quality", changes.quality), issue(candidate, "safety", changes.safety)]);
    },
    setAuthorityTime(value) {
      authorityTime = value;
    },
  });
}
