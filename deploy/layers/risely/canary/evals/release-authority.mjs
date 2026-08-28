import { createPublicKey, verify } from "node:crypto";
import { types } from "node:util";
import { normalizeMeetingDossier } from "../chief-of-staff/index.mjs";
import { PrincipalBinding } from "../shared-contracts/index.mjs";
import { assertRuntimeScope } from "../runtime-scope/index.mjs";
import { assertEvaluationResultStore } from "./result-store.mjs";
import { evaluateReleaseSubject } from "./deterministic.mjs";

const hash = PrincipalBinding.hash;
const freeze = PrincipalBinding.freeze;
const snapshot = PrincipalBinding.snapshot;
const authorityStates = new WeakMap();
const authorizedEvaluationDecisions = new WeakMap();
const digestPattern = /^[a-f0-9]{64}$/u;
const instantPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const base64urlPattern = /^[A-Za-z0-9_-]+$/u;
const scoreNames = Object.freeze(["accuracy", "grounding", "safety", "voice", "usefulness"]);
const judgeFields = Object.freeze([
  "schemaVersion",
  "receiptType",
  "keyId",
  "judgeRef",
  "judgeClass",
  "originRef",
  "runRef",
  "artifactSha256",
  "evidenceSha256",
  "evaluationPayloadSha256",
  "deploymentProfileSha256",
  "evaluationProfileSha256",
  "policySha256",
  "deterministicResultsSha256",
  "sideEffectCount",
  "scores",
  "gateResults",
  "passed",
  "failures",
  "evidenceRefs",
  "issuedAt",
  "expiresAt",
  "nonce",
  "receiptSha256",
  "signature",
]);
const receiptProjectionFields = Object.freeze(
  judgeFields.filter((field) => !["receiptSha256", "signature"].includes(field)),
);
const candidateFields = Object.freeze([
  "schemaVersion",
  "candidateType",
  "artifactRef",
  "artifactRevision",
  "artifactSha256",
  "evidenceSha256",
  "evaluationPayloadSha256",
  "deploymentProfileRef",
  "deploymentProfileSha256",
  "evaluationProfileSha256",
  "policySha256",
  "deterministicResultsSha256",
  "deterministicCheckIds",
  "sideEffectCount",
  "evaluationStartedAt",
  "expiresAt",
  "runNonce",
  "runRef",
  "artifact",
  "evaluationPayload",
  "profile",
  "deterministic",
  "effectObservation",
  "policySnapshot",
]);

export const evaluationResultStoreRequirement = Object.freeze({
  requiredForProviderActivation: true,
  implemented: true,
  shadowReleaseAllowed: true,
  authorityCanAuthorizeProviderInvocation: false,
  durability: "postgres_append_only_results_releases_and_replay_tombstones",
});

function exact(value, fields, label) {
  if (types.isProxy(value)) throw new TypeError(`${label} must not be a proxy`);
  const input = snapshot(value, label);
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(input, field))
  ) {
    throw new TypeError(`${label} has an unsupported shape`);
  }
  return input;
}

function exactPort(value, fields, label) {
  if (
    !value ||
    typeof value !== "object" ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${label} must be a plain exact port`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Object.getOwnPropertySymbols(value).length !== 0 ||
    Object.keys(descriptors).length !== fields.length ||
    fields.some((field) => {
      const descriptor = descriptors[field];
      return !descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value");
    })
  ) {
    throw new TypeError(`${label} must be a plain exact port`);
  }
  return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]));
}

function digest(value, label) {
  if (typeof value !== "string" || !digestPattern.test(value)) throw new TypeError(`${label} must be a digest`);
  return value;
}

function instant(value, label) {
  if (typeof value !== "string" || !instantPattern.test(value) || new Date(value).toISOString() !== value) {
    throw new TypeError(`${label} must be a canonical instant`);
  }
  return value;
}

function boundedIdentifier(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 160 || /[^a-z0-9:._-]/u.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function normalizeTrustedJudges(value, requiredClasses, minimumJudges) {
  const judges = snapshot(value, "Trusted judge registry");
  if (!Array.isArray(judges) || judges.length !== minimumJudges) {
    throw new TypeError("Trusted judge registry does not match deployment policy");
  }
  const normalized = judges.map((entry, index) => {
    const judge = exact(entry, ["keyId", "judgeRef", "judgeClass", "originRef", "publicKey"], `Trusted judge ${index}`);
    const publicKey = exact(judge.publicKey, ["crv", "x", "kty"], `Trusted judge ${index} public key`);
    if (
      publicKey.crv !== "Ed25519" ||
      publicKey.kty !== "OKP" ||
      typeof publicKey.x !== "string" ||
      !base64urlPattern.test(publicKey.x)
    ) {
      throw new TypeError(`Trusted judge ${index} public key is invalid`);
    }
    if (!requiredClasses.includes(judge.judgeClass)) throw new TypeError(`Trusted judge ${index} class is invalid`);
    const normalizedJudge = freeze({
      keyId: boundedIdentifier(judge.keyId, `Trusted judge ${index} keyId`),
      judgeRef: boundedIdentifier(judge.judgeRef, `Trusted judge ${index} judgeRef`),
      judgeClass: judge.judgeClass,
      originRef: boundedIdentifier(judge.originRef, `Trusted judge ${index} originRef`),
      publicKey: freeze(publicKey),
    });
    return freeze({ ...normalizedJudge, verifier: createPublicKey({ key: publicKey, format: "jwk" }) });
  });
  if (
    new Set(normalized.map((judge) => judge.keyId)).size !== normalized.length ||
    new Set(normalized.map((judge) => judge.judgeRef)).size !== normalized.length ||
    new Set(normalized.map((judge) => judge.originRef)).size !== normalized.length ||
    new Set(normalized.map((judge) => judge.judgeClass)).size !== requiredClasses.length ||
    requiredClasses.some((judgeClass) => !normalized.some((judge) => judge.judgeClass === judgeClass))
  ) {
    throw new TypeError("Trusted judges must have independent identities origins and classes");
  }
  return normalized;
}

function createEvaluationAuthority(value, assertResultStore, production) {
  const input = exactPort(
    value,
    production
      ? ["runtimeScope", "resultStore", "readAuthorityTime"]
      : ["runtimeScope", "resultStore", "trustedJudges", "readAuthorityTime"],
    "Evaluation authority configuration",
  );
  if (typeof input.readAuthorityTime !== "function" || types.isProxy(input.readAuthorityTime)) {
    throw new TypeError("Evaluation authority clock must be a fixed function");
  }
  const runtimeScope = assertRuntimeScope(input.runtimeScope);
  const deploymentEvalPolicy = runtimeScope.profile.evalPolicy;
  const trustedJudges = normalizeTrustedJudges(
    production ? deploymentEvalPolicy.trustedJudgeRoots : input.trustedJudges,
    deploymentEvalPolicy.judgeClasses,
    deploymentEvalPolicy.minimumIndependentJudges,
  );
  if (
    deploymentEvalPolicy.selfReviewAllowed !== false ||
    trustedJudges.some((judge) =>
      [
        runtimeScope.profile.identity.humanPrincipalRef,
        runtimeScope.profile.identity.qmPrincipalRef,
        runtimeScope.profile.agent.agentId,
      ].includes(judge.judgeRef),
    )
  ) {
    throw new TypeError("Evaluation judge trust roots permit self review");
  }
  const resultStore = assertResultStore(input.resultStore, runtimeScope);
  const policyJudges = trustedJudges.map(({ verifier: _verifier, ...judge }) => judge);
  const policyProjection = {
    schemaVersion: 2,
    policyRef: deploymentEvalPolicy.policyRef,
    deploymentEvalPolicySha256: hash(deploymentEvalPolicy),
    evalAuthorityRef: `evaluation-authority:${runtimeScope.profileRef}`,
    mode: "shadow",
    authoritativeProviderRelease: false,
    providerInvocationAllowed: false,
    requiredGates: deploymentEvalPolicy.requiredGates,
    requiredCheckIds: deploymentEvalPolicy.requiredDeterministicCheckIds,
    requiredJudgeClasses: deploymentEvalPolicy.judgeClasses,
    minimumIndependentJudges: deploymentEvalPolicy.minimumIndependentJudges,
    independentOriginsRequired: deploymentEvalPolicy.independentOriginsRequired,
    selfReviewAllowed: deploymentEvalPolicy.selfReviewAllowed,
    sideEffectBudget: deploymentEvalPolicy.sideEffectBudget,
    maximumRepairAttempts: deploymentEvalPolicy.maximumRepairAttempts,
    minimumScore: deploymentEvalPolicy.minimumScore,
    maximumScoreSpread: deploymentEvalPolicy.maximumScoreSpread,
    maximumReleaseLifetimeMs: runtimeScope.profile.grantPolicy.maximumEvalReleaseLifetimeMs,
    maximumEvaluationRuntimeMs: deploymentEvalPolicy.maximumEvaluationRuntimeMs,
    trustedJudges: policyJudges,
  };
  const policy = freeze({ ...policyProjection, policySha256: hash(policyProjection) });
  const authority = freeze({
    authorityType: "ProviderFreeEvaluationAuthority",
    policy,
    resultStoreRequirement: evaluationResultStoreRequirement,
    providerInvocationAllowed: false,
  });
  authorityStates.set(
    authority,
    Object.freeze({
      trustedJudges,
      readAuthorityTime: input.readAuthorityTime,
      runtimeScope,
      resultStore,
      contracts: runtimeScope.contracts,
      production,
    }),
  );
  return authority;
}

export function createProviderFreeEvaluationAuthority(value) {
  return createEvaluationAuthority(value, assertEvaluationResultStore, true);
}

export function createInertEvaluationAuthorityForTesting(value, assertResultStore) {
  if (typeof assertResultStore !== "function") throw new TypeError("An inert result-store assertion is required");
  return createEvaluationAuthority(value, assertResultStore, false);
}

function authorityState(authority) {
  if (!authority || typeof authority !== "object" || types.isProxy(authority) || !authorityStates.has(authority)) {
    throw new TypeError("A bound provider-free evaluation authority is required");
  }
  return authorityStates.get(authority);
}

function evaluationProfile(artifact, state) {
  const projection = {
    schemaVersion: 1,
    evaluationProfileRef: "evaluation-profile:meeting-prep-synthetic-shadow:v1",
    deploymentProfileRef: state.runtimeScope.profileRef,
    deploymentProfileSha256: state.runtimeScope.profileSha256,
    deploymentRef: state.contracts.PrincipalBinding.identity.deploymentRef,
    principalBindingSha256: artifact.principalBindingSha256,
    workflowKind: artifact.workflowKind,
    mode: "shadow",
    providerInvocationAllowed: false,
  };
  return freeze({ ...projection, evaluationProfileSha256: hash(projection) });
}

function effectObservation() {
  const projection = {
    schemaVersion: 1,
    mode: "closed_pure_evaluation",
    providerPortCount: 0,
    attemptedEffectCount: 0,
    providerInvocationAllowed: false,
  };
  return freeze({ ...projection, observationSha256: hash(projection) });
}

function normalizedEvaluationPayload(value) {
  const input = exact(
    value,
    [
      "schemaVersion",
      "meetingKey",
      "generatedAt",
      "calendarEvidenceHash",
      "sources",
      "evidence",
      "sections",
      "missingContext",
      "providerContentTrust",
      "presentationSinkAllowed",
      "artifactHash",
    ],
    "Meeting dossier evaluation payload",
  );
  if (
    input.schemaVersion !== 1 ||
    input.providerContentTrust !== "untrusted_data_only" ||
    input.presentationSinkAllowed !== false
  ) {
    throw new TypeError("Meeting dossier evaluation payload capability is invalid");
  }
  const rebuilt = normalizeMeetingDossier({
    meetingKey: input.meetingKey,
    generatedAt: input.generatedAt,
    calendarEvidenceHash: input.calendarEvidenceHash,
    sources: input.sources,
    evidence: input.evidence.map(({ evidenceRef, source, evidenceHash, capturedAt }) => ({
      evidenceRef,
      source,
      evidenceHash,
      capturedAt,
    })),
    sections: Object.fromEntries(
      Object.entries(input.sections).map(([section, claims]) => [
        section,
        claims.map(({ claimId, text, citations }) => ({ claimId, text, citations })),
      ]),
    ),
  });
  if (hash(input) !== hash(rebuilt)) throw new TypeError("Meeting dossier evaluation payload is not canonical");
  return rebuilt;
}

function deterministicResults(artifact, evaluationPayload, profile, observation, state) {
  const checks = evaluateReleaseSubject({
    artifact,
    evaluationPayload,
    profile,
    effectObservation: observation,
    principalBinding: state.contracts.PrincipalBinding,
  });
  const checkIds = checks.map((check) => check.id).sort();
  if (JSON.stringify(checkIds) !== JSON.stringify(state.runtimeScope.profile.evalPolicy.requiredDeterministicCheckIds))
    throw new Error("deterministic_check_set_mismatch");
  if (checks.some((check) => check.hard !== true || check.passed !== true || check.failures.length !== 0)) {
    throw new Error("deterministic_evaluation_failed");
  }
  return freeze({ checkIds: freeze(checkIds), checks, resultsSha256: hash(checks) });
}

export function prepareEvaluationCandidate(authority, value) {
  const state = authorityState(authority);
  const input = exact(
    value,
    ["artifact", "evaluationPayload", "evaluationStartedAt", "expiresAt", "runNonce"],
    "Evaluation candidate input",
  );
  const artifact = state.contracts.WorkflowArtifact.validate(input.artifact);
  if (artifact.state !== "ready") throw new Error("evaluation_artifact_not_ready");
  const evaluationPayload = normalizedEvaluationPayload(input.evaluationPayload);
  if (JSON.stringify(evaluationPayload).length > 1_000_000)
    throw new TypeError("Evaluation payload exceeds the size limit");
  const evaluationStartedAt = instant(input.evaluationStartedAt, "Evaluation candidate start time");
  const expiresAt = instant(input.expiresAt, "Evaluation candidate expiresAt");
  const runNonce = digest(input.runNonce, "Evaluation candidate runNonce");
  const startedTimestamp = Date.parse(evaluationStartedAt);
  const expiresTimestamp = Date.parse(expiresAt);
  if (
    startedTimestamp < Date.parse(artifact.updatedAt) ||
    expiresTimestamp <= startedTimestamp ||
    expiresTimestamp - startedTimestamp > authority.policy.maximumReleaseLifetimeMs
  ) {
    throw new Error("evaluation_candidate_time_bounds_invalid");
  }
  const profile = evaluationProfile(artifact, state);
  const observation = effectObservation();
  const deterministic = deterministicResults(artifact, evaluationPayload, profile, observation, state);
  const projection = {
    schemaVersion: 1,
    candidateType: "ProviderFreeEvaluationCandidate",
    artifactRef: artifact.artifactRef,
    artifactRevision: artifact.revision,
    artifactSha256: artifact.artifactSha256,
    evidenceSha256: artifact.evidenceBundle.bundleSha256,
    evaluationPayloadSha256: hash(evaluationPayload),
    deploymentProfileRef: state.runtimeScope.profileRef,
    deploymentProfileSha256: state.runtimeScope.profileSha256,
    evaluationProfileSha256: profile.evaluationProfileSha256,
    policySha256: authority.policy.policySha256,
    deterministicResultsSha256: deterministic.resultsSha256,
    deterministicCheckIds: deterministic.checkIds,
    sideEffectCount: observation.attemptedEffectCount,
    evaluationStartedAt,
    expiresAt,
    runNonce,
  };
  return freeze({
    ...projection,
    runRef: `evaluation-run:${hash(projection)}`,
    artifact,
    evaluationPayload,
    profile,
    deterministic,
    effectObservation: observation,
    policySnapshot: authority.policy,
  });
}

export function judgeResultSigningPayload(value) {
  const input = exact(value, judgeFields, "Judge result");
  const projection = Object.fromEntries(receiptProjectionFields.map((field) => [field, input[field]]));
  return Buffer.from(JSON.stringify(projection), "utf8");
}

function validateScores(value) {
  const scores = exact(value, scoreNames, "Judge scores");
  for (const name of scoreNames) {
    if (!Number.isInteger(scores[name]) || scores[name] < 1 || scores[name] > 5)
      throw new TypeError(`Judge score ${name} is invalid`);
  }
  return freeze(scores);
}

function validateGateResults(value, authority) {
  const gates = exact(value, authority.policy.requiredGates, "Judge gate results");
  if (authority.policy.requiredGates.some((gate) => gates[gate] !== true)) {
    throw new Error("judge_required_gate_failed");
  }
  return freeze(gates);
}

function validateJudgeResult(value, candidate, authority, state, authorityNow) {
  const input = exact(value, judgeFields, "Judge result");
  if (input.schemaVersion !== 1 || input.receiptType !== "ProviderFreeJudgeResult")
    throw new TypeError("judge_result_contract_invalid");
  const trusted = state.trustedJudges.find((entry) => entry.keyId === input.keyId);
  if (
    !trusted ||
    input.judgeRef !== trusted.judgeRef ||
    input.judgeClass !== trusted.judgeClass ||
    input.originRef !== trusted.originRef
  ) {
    throw new Error("judge_origin_not_trusted");
  }
  for (const field of [
    "artifactSha256",
    "evidenceSha256",
    "evaluationPayloadSha256",
    "deploymentProfileSha256",
    "evaluationProfileSha256",
    "policySha256",
    "deterministicResultsSha256",
    "nonce",
    "receiptSha256",
  ]) {
    digest(input[field], `Judge result ${field}`);
  }
  for (const field of [
    "runRef",
    "artifactSha256",
    "evidenceSha256",
    "evaluationPayloadSha256",
    "deploymentProfileSha256",
    "evaluationProfileSha256",
    "policySha256",
    "deterministicResultsSha256",
  ]) {
    if (input[field] !== candidate[field]) throw new Error(`judge_${field}_mismatch`);
  }
  if (input.sideEffectCount !== 0 || input.sideEffectCount !== candidate.sideEffectCount)
    throw new Error("judge_side_effects_detected");
  const scores = validateScores(input.scores);
  const gateResults = validateGateResults(input.gateResults, authority);
  if (input.passed !== true || !Array.isArray(input.failures) || input.failures.length !== 0)
    throw new Error("judge_result_failed");
  const evidenceRefs = [
    `artifact:${candidate.artifactSha256}`,
    `evidence:${candidate.evidenceSha256}`,
    `payload:${candidate.evaluationPayloadSha256}`,
  ];
  if (!Array.isArray(input.evidenceRefs) || JSON.stringify(input.evidenceRefs) !== JSON.stringify(evidenceRefs)) {
    throw new Error("judge_evidence_binding_invalid");
  }
  const issuedAt = instant(input.issuedAt, "Judge result issuedAt");
  const receiptExpiresAt = instant(input.expiresAt, "Judge result expiresAt");
  const nowTimestamp = Date.parse(authorityNow);
  if (
    Date.parse(issuedAt) < Date.parse(candidate.evaluationStartedAt) ||
    Date.parse(issuedAt) > nowTimestamp ||
    nowTimestamp - Date.parse(candidate.evaluationStartedAt) > authority.policy.maximumEvaluationRuntimeMs ||
    Date.parse(receiptExpiresAt) < Date.parse(candidate.expiresAt) ||
    nowTimestamp >= Date.parse(receiptExpiresAt)
  ) {
    throw new Error("judge_result_time_bounds_invalid");
  }
  const projection = Object.fromEntries(receiptProjectionFields.map((field) => [field, input[field]]));
  if (input.receiptSha256 !== hash(projection)) throw new Error("judge_receipt_digest_mismatch");
  if (
    typeof input.signature !== "string" ||
    input.signature.length < 80 ||
    input.signature.length > 120 ||
    !base64urlPattern.test(input.signature)
  ) {
    throw new TypeError("Judge result signature is invalid");
  }
  if (
    !verify(
      null,
      Buffer.from(JSON.stringify(projection), "utf8"),
      trusted.verifier,
      Buffer.from(input.signature, "base64url"),
    )
  ) {
    throw new Error("judge_signature_invalid");
  }
  if (
    authority.policy.selfReviewAllowed !== false ||
    [
      state.runtimeScope.profile.identity.humanPrincipalRef,
      state.runtimeScope.profile.identity.qmPrincipalRef,
      state.runtimeScope.profile.agent.agentId,
    ].includes(input.judgeRef)
  ) {
    throw new Error("judge_self_review_forbidden");
  }
  return freeze({ ...input, scores, gateResults });
}

function buildAuthorityRelease(state, authority, candidate, judges, authorityNow) {
  const binding = state.contracts.PrincipalBinding.value;
  const projection = {
    contractType: "EvalRelease",
    contractVersion: state.contracts.EvalRelease.version,
    digestRevision: state.contracts.EvalRelease.digestRevision,
    deploymentProfileRef: binding.profileRef,
    deploymentProfileSha256: binding.profileSha256,
    principalBindingSha256: binding.bindingSha256,
    artifactRef: candidate.artifact.artifactRef,
    artifactRevision: candidate.artifact.revision,
    artifactSha256: candidate.artifact.artifactSha256,
    candidateId: candidate.runRef,
    evalAuthorityRef: authority.policy.evalAuthorityRef,
    policyRef: authority.policy.policyRef,
    policySha256: authority.policy.policySha256,
    mode: "shadow",
    passed: true,
    release: true,
    sideEffectCount: 0,
    deterministicCheckIds: candidate.deterministicCheckIds,
    judges: judges
      .map((judge) => ({
        judgeRef: judge.judgeRef,
        independenceKey: judge.originRef,
        receiptSha256: judge.receiptSha256,
      }))
      .sort((left, right) => left.judgeRef.localeCompare(right.judgeRef)),
    evaluatedAt: authorityNow,
    expiresAt: candidate.expiresAt,
  };
  return state.contracts.EvalRelease.validate(
    freeze({ ...projection, releaseSha256: hash(projection) }),
    candidate.artifact,
  );
}

function validateQuorum(authority, state, candidate, judgeResults, authorityNow) {
  if (!Array.isArray(judgeResults) || judgeResults.length !== authority.policy.minimumIndependentJudges) {
    throw new Error("independent_judges_unavailable");
  }
  const judges = judgeResults.map((result) => validateJudgeResult(result, candidate, authority, state, authorityNow));
  if (
    new Set(judges.map((judge) => judge.judgeRef)).size !== judges.length ||
    new Set(judges.map((judge) => judge.originRef)).size !== judges.length ||
    new Set(judges.map((judge) => judge.nonce)).size !== judges.length ||
    new Set(judges.map((judge) => judge.judgeClass)).size !== authority.policy.requiredJudgeClasses.length ||
    authority.policy.requiredJudgeClasses.some((judgeClass) => !judges.some((judge) => judge.judgeClass === judgeClass))
  ) {
    throw new Error("independent_judge_quorum_invalid");
  }
  const averages = scoreNames.map(
    (name) => judges.reduce((total, judge) => total + judge.scores[name], 0) / judges.length,
  );
  const maximumSpread = Math.max(
    ...scoreNames.map(
      (name) =>
        Math.max(...judges.map((judge) => judge.scores[name])) - Math.min(...judges.map((judge) => judge.scores[name])),
    ),
  );
  if (
    averages.some((score) => score < authority.policy.minimumScore) ||
    maximumSpread > authority.policy.maximumScoreSpread
  ) {
    throw new Error("judge_score_gate_failed");
  }
  return freeze(judges);
}

export function mintEvaluationRelease(authority, value) {
  const state = authorityState(authority);
  const input = exactPort(value, ["candidate", "judgeResults"], "Evaluation release input");
  const candidate = exact(input.candidate, candidateFields, "Evaluation candidate");
  let rebuilt;
  try {
    rebuilt = prepareEvaluationCandidate(authority, {
      artifact: candidate.artifact,
      evaluationPayload: candidate.evaluationPayload,
      evaluationStartedAt: candidate.evaluationStartedAt,
      expiresAt: candidate.expiresAt,
      runNonce: candidate.runNonce,
    });
  } catch {
    throw new Error("evaluation_candidate_invalid");
  }
  if (hash(candidate) !== hash(rebuilt)) throw new Error("evaluation_candidate_invalid");
  const authorityNow = instant(state.readAuthorityTime(), "Evaluation authority time");
  if (
    Date.parse(authorityNow) < Date.parse(candidate.evaluationStartedAt) ||
    Date.parse(authorityNow) >= Date.parse(candidate.expiresAt) ||
    Date.parse(authorityNow) - Date.parse(candidate.evaluationStartedAt) > authority.policy.maximumEvaluationRuntimeMs
  ) {
    throw new Error("evaluation_authority_time_invalid");
  }
  const judges = validateQuorum(
    authority,
    state,
    candidate,
    snapshot(input.judgeResults, "Judge result quorum"),
    authorityNow,
  );
  const release = buildAuthorityRelease(state, authority, candidate, judges, authorityNow);
  const decisionProjection = {
    decisionType: "AuthorizedProviderFreeEvaluation",
    candidate,
    judgeResults: judges,
    policySnapshot: authority.policy,
    release,
  };
  const decision = freeze({ ...decisionProjection, decisionSha256: hash(decisionProjection) });
  authorizedEvaluationDecisions.set(
    decision,
    Object.freeze({ authority, runtimeScope: state.runtimeScope, production: state.production }),
  );
  const persisted = state.resultStore.persistAuthorityEvaluation(decision);
  return persisted && typeof persisted.then === "function" ? Promise.resolve(persisted).then(() => release) : release;
}

export function assertAuthorizedEvaluationDecision(value, runtimeScope, resultStore) {
  const scope = assertRuntimeScope(runtimeScope);
  const branded = authorizedEvaluationDecisions.get(value);
  if (
    !branded ||
    branded.runtimeScope !== scope ||
    branded.production !== true ||
    authorityState(branded.authority).resultStore !== resultStore ||
    !Object.isFrozen(value)
  ) {
    throw new TypeError("An exact production evaluation authority decision is required");
  }
  const input = exact(
    value,
    ["decisionType", "candidate", "judgeResults", "policySnapshot", "release", "decisionSha256"],
    "Authorized evaluation decision",
  );
  if (input.decisionType !== "AuthorizedProviderFreeEvaluation") {
    throw new TypeError("Authorized evaluation decision type is invalid");
  }
  const { decisionSha256, ...projection } = input;
  if (decisionSha256 !== hash(projection)) throw new Error("evaluation_decision_digest_mismatch");
  const state = authorityState(branded.authority);
  const candidate = exact(input.candidate, candidateFields, "Evaluation candidate");
  const rebuiltCandidate = prepareEvaluationCandidate(branded.authority, {
    artifact: candidate.artifact,
    evaluationPayload: candidate.evaluationPayload,
    evaluationStartedAt: candidate.evaluationStartedAt,
    expiresAt: candidate.expiresAt,
    runNonce: candidate.runNonce,
  });
  if (
    hash(candidate) !== hash(rebuiltCandidate) ||
    hash(input.policySnapshot) !== hash(branded.authority.policy) ||
    candidate.policySha256 !== branded.authority.policy.policySha256
  ) {
    throw new Error("evaluation_candidate_policy_snapshot_invalid");
  }
  const judges = validateQuorum(
    branded.authority,
    state,
    candidate,
    snapshot(input.judgeResults, "Judge result quorum"),
    input.release.evaluatedAt,
  );
  const expectedRelease = buildAuthorityRelease(state, branded.authority, candidate, judges, input.release.evaluatedAt);
  if (hash(expectedRelease) !== hash(input.release)) throw new Error("evaluation_release_authority_mismatch");
  return input;
}
