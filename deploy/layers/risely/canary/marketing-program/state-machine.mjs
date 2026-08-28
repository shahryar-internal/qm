import {
  assertMarketingProgramContractSuite,
  ceoMarketingProgramContractSuite,
  requiredEvaluationGates,
} from "./contracts.mjs";
import { assertBuiltMarketingProgramForContractSuite, marketingProgramHash } from "./program.mjs";
import {
  assertKeys,
  compareCodepoints,
  digest,
  fail,
  instant,
  ref,
  sha256Canonical,
  snapshotPlainJson,
} from "./validation.mjs";

const evaluatorRegistry = (gates) =>
  Object.freeze({
    "evaluator:deterministic:marketing:v1": Object.freeze({ originClass: "deterministic", gates }),
    "evaluator:llm:independent:marketing:v1": Object.freeze({ originClass: "independent_llm", gates }),
  });
export const prospectiveEvaluatorRegistry = evaluatorRegistry(requiredEvaluationGates);
export const prospectiveReconciliationContract = Object.freeze({
  statuses: Object.freeze(["outcome_unknown", "confirmed", "failed"]),
  mutationsAvailable: false,
  trustedProviderReceiptRequired: true,
});
const programKeys = new Set([
  "version",
  "kind",
  "programRef",
  "programRevision",
  "goalDate",
  "timeZone",
  "principalBinding",
  "rolePolicy",
  "weeklyPlan",
  "planHash",
  "rubric",
  "rubricHash",
  "research",
  "researchHash",
  "artifact",
  "safety",
  "requiredEvaluationGates",
  "programHash",
]);
const weeklyArtifactKeys = new Set([
  "artifactRef",
  "type",
  "disposition",
  "copyDisposition",
  "releaseDisposition",
  "entries",
  "outlineMappings",
  "citationRefs",
  "sourceRefs",
  "mappingHash",
  "slackArtifact",
  "programHash",
  "programRevision",
  "rubricHash",
  "researchHash",
]);
const dailyArtifactKeys = new Set([
  "artifactRef",
  "type",
  "notionParentRef",
  "audience",
  "text",
  "draftRevision",
  "citationRefs",
  "claimCitations",
  "sourceRefs",
  "mappingHash",
  "approvalRequestRef",
  "schedule",
  "lexicalPrefilters",
  "copyDisposition",
  "releaseDisposition",
  "contentHash",
  "slackArtifact",
  "publication",
  "programHash",
  "programRevision",
  "rubricHash",
  "researchHash",
  "idempotencyKey",
]);
const stateKeys = new Set([
  "version",
  "programHash",
  "artifactHash",
  "programKind",
  "programRevision",
  "rubricHash",
  "researchHash",
  "mappingHash",
  "citationRefsHash",
  "sourceRefsHash",
  "state",
  "revision",
  "evaluationRequests",
  "approvalRequests",
  "effects",
  "executionDisposition",
  "reconciliation",
  "recordHash",
]);
const evaluationKeys = new Set([
  "requestRef",
  "expectedRevision",
  "programHash",
  "artifactHash",
  "programKind",
  "programRevision",
  "rubricHash",
  "researchHash",
  "mappingHash",
  "citationRefsHash",
  "sourceRefsHash",
  "requestedAt",
  "expiresAt",
  "runs",
  "resolution",
  "trustedReceiptRequired",
]);
const runKeys = new Set([
  "runRef",
  "gate",
  "evaluatorRef",
  "originClass",
  "programHash",
  "artifactHash",
  "programKind",
  "programRevision",
  "rubricHash",
  "researchHash",
  "mappingHash",
  "citationRefsHash",
  "sourceRefsHash",
  "requestRef",
  "criteriaHash",
]);
const approvalKeys = new Set([
  "requestRef",
  "expectedRevision",
  "programHash",
  "artifactHash",
  "programKind",
  "programRevision",
  "rubricHash",
  "researchHash",
  "mappingHash",
  "citationRefsHash",
  "sourceRefsHash",
  "planHash",
  "teamRef",
  "userRef",
  "messageRef",
  "interactionRef",
  "payloadHash",
  "requestedAt",
  "expiresAt",
  "stateRevision",
  "resolution",
  "trustedServerTimeRequired",
  "trustedReceiptRequired",
]);
const evaluationInputKeys = new Set([
  "requestRef",
  "expectedRevision",
  "programHash",
  "artifactHash",
  "programKind",
  "programRevision",
  "rubricHash",
  "researchHash",
  "mappingHash",
  "citationRefsHash",
  "sourceRefsHash",
  "requestedAt",
  "expiresAt",
]);
const approvalInputKeys = new Set([
  "requestRef",
  "expectedRevision",
  "programHash",
  "artifactHash",
  "programKind",
  "programRevision",
  "rubricHash",
  "researchHash",
  "mappingHash",
  "citationRefsHash",
  "sourceRefsHash",
  "planHash",
  "teamRef",
  "userRef",
  "messageRef",
  "interactionRef",
  "payloadHash",
  "requestedAt",
  "expiresAt",
]);
const checkInteger = (value, code, policy) => {
  if (!Number.isSafeInteger(value) || value < 0 || value > policy.maximumRevision) fail(code);
  return value;
};
const artifactBindings = (program) =>
  Object.freeze({
    artifactHash: sha256Canonical(program.artifact),
    programKind: program.kind,
    programRevision: program.programRevision,
    rubricHash: program.rubricHash,
    researchHash: program.researchHash,
    mappingHash: program.artifact.mappingHash,
    citationRefsHash: sha256Canonical(program.artifact.citationRefs),
    sourceRefsHash: sha256Canonical(program.artifact.sourceRefs),
  });
const expectedSourceRefs = (program) =>
  program.research
    .filter((entry) => program.artifact.citationRefs.includes(entry.citationRef))
    .map((entry) => ({
      citationRef: entry.citationRef,
      sourceRef: entry.sourceRef,
      sourceReceiptProposalRef: entry.sourceReceiptProposalRef,
      sourceReceiptHash: entry.sourceReceiptHash,
      researchHash: entry.researchHash,
    }))
    .sort((left, right) => compareCodepoints(left.citationRef, right.citationRef));
const programShape = (raw, context) => {
  assertBuiltMarketingProgramForContractSuite(context.contracts, raw);
  const value = snapshotPlainJson(raw);
  assertKeys(value, programKeys, "invalid_program");
  assertKeys(
    value.safety,
    new Set(["disposition", "executionDisposition", "providerAccess", "socialExecution", "trustedReceiptRequired"]),
    "invalid_program",
  );
  assertKeys(
    value.principalBinding,
    new Set([
      "deploymentRef",
      "anchorRef",
      "tenantRef",
      "workspaceRef",
      "principalRef",
      "credentialOwnerRef",
      "notionRootRef",
      "slackTeamRef",
      "slackUserRef",
    ]),
    "invalid_program",
  );
  if (
    value.version !== context.policy.version ||
    value.rolePolicy.policySha256 !== context.policy.policySha256 ||
    value.rubric.voiceSha256 !== context.voice.voiceSha256 ||
    !["weekly_plan", "daily_draft"].includes(value.kind) ||
    !Number.isSafeInteger(value.programRevision) ||
    value.programRevision < 0 ||
    value.programRevision > context.policy.maximumRevision ||
    value.safety.disposition !== "unresolved_proposals" ||
    value.safety.executionDisposition !== "hard_disabled" ||
    value.safety.providerAccess !== "none" ||
    value.safety.socialExecution !== "not_available" ||
    value.safety.trustedReceiptRequired !== true ||
    value.programRevision !== value.artifact.programRevision ||
    value.programHash !== value.artifact.programHash ||
    value.rubricHash !== value.artifact.rubricHash ||
    value.researchHash !== value.artifact.researchHash ||
    value.planHash !== sha256Canonical(value.weeklyPlan) ||
    value.rubricHash !== sha256Canonical(value.rubric) ||
    value.researchHash !== sha256Canonical(value.research) ||
    !Array.isArray(value.requiredEvaluationGates) ||
    sha256Canonical(value.requiredEvaluationGates) !== sha256Canonical(context.gates) ||
    marketingProgramHash(value) !== value.programHash
  )
    fail("invalid_program");
  assertKeys(value.artifact, value.kind === "weekly_plan" ? weeklyArtifactKeys : dailyArtifactKeys, "invalid_program");
  if (
    !Array.isArray(value.artifact.citationRefs) ||
    !Array.isArray(value.artifact.sourceRefs) ||
    sha256Canonical(value.artifact.sourceRefs) !== sha256Canonical(expectedSourceRefs(value)) ||
    digest(value.artifact.mappingHash, "invalid_program") !==
      (value.kind === "weekly_plan"
        ? sha256Canonical(value.artifact.outlineMappings)
        : sha256Canonical(value.artifact.claimCitations))
  )
    fail("invalid_program");
  if (
    value.kind === "weekly_plan" &&
    (value.artifact.type !== "slack.plan_approval_proposal" ||
      value.artifact.artifactRef !==
        `marketing-plan:${sha256Canonical({ planRef: value.weeklyPlan.planRef, revision: value.weeklyPlan.revision, outlineMappings: value.artifact.outlineMappings, citationRefs: value.artifact.citationRefs })}` ||
      value.artifact.disposition !== "unresolved" ||
      value.artifact.copyDisposition !== "untrusted_candidate" ||
      value.artifact.releaseDisposition !== "impossible_without_independent_trusted_eval_receipts" ||
      value.artifact.entries.length !== 5 ||
      sha256Canonical(value.artifact.entries) !== sha256Canonical(value.weeklyPlan.entries) ||
      value.artifact.slackArtifact.type !== "qm.marketing_plan" ||
      value.artifact.slackArtifact.actionless !== true ||
      Object.keys(value.artifact.slackArtifact).length !== 2)
  )
    fail("invalid_program");
  if (
    value.kind === "daily_draft" &&
    (value.artifact.type !== "notion.private_ceo_draft_proposal" ||
      value.artifact.artifactRef !==
        `marketing-draft:${sha256Canonical({ planRef: value.weeklyPlan.planRef, date: value.goalDate, draftRevision: value.artifact.draftRevision, contentHash: value.artifact.contentHash, mappingHash: value.artifact.mappingHash, sourceRefs: value.artifact.sourceRefs })}` ||
      !Number.isSafeInteger(value.artifact.draftRevision) ||
      value.artifact.draftRevision < 0 ||
      value.artifact.draftRevision > context.policy.maximumRevision ||
      value.artifact.contentHash !== sha256Canonical(value.artifact.text) ||
      value.artifact.copyDisposition !== "untrusted_candidate" ||
      value.artifact.releaseDisposition !== "impossible_without_independent_trusted_eval_receipts" ||
      value.artifact.notionParentRef !== value.principalBinding.notionRootRef ||
      value.artifact.audience !== "private_ceo" ||
      value.artifact.publication.state !== "impossible_without_independent_trusted_eval_receipts" ||
      value.artifact.idempotencyKey !==
        sha256Canonical({
          version: value.version,
          programHash: value.programHash,
          artifactRef: value.artifact.artifactRef,
          programRevision: value.programRevision,
          goalDate: value.goalDate,
          planHash: value.planHash,
          draftRevision: value.artifact.draftRevision,
          contentHash: value.artifact.contentHash,
          mappingHash: value.artifact.mappingHash,
          sourceRefs: value.artifact.sourceRefs,
          notionParentRef: value.principalBinding.notionRootRef,
        }))
  )
    fail("invalid_program");
  return value;
};
const record = (value) => {
  const { recordHash, ...withoutHash } = value;
  return Object.freeze({ ...withoutHash, recordHash: sha256Canonical(withoutHash) });
};
const requestWindow = (requestedAt, expiresAt, context) => {
  const requested = instant(requestedAt, "invalid_request");
  const expires = instant(expiresAt, "invalid_request");
  if (expires <= requested || expires - requested > context.policy.approvalLifetimeMilliseconds)
    fail("invalid_request_window");
};
const evaluationRunRef = (requestRef, evaluatorRef, gate, state) =>
  `evaluation-run:${sha256Canonical({ version: "marketing-evaluation-run.v1", requestRef, evaluatorRef, gate, artifactHash: state.artifactHash, programHash: state.programHash, programKind: state.programKind, programRevision: state.programRevision })}`;
const exactBinding = (value, state) =>
  value.programHash === state.programHash &&
  value.artifactHash === state.artifactHash &&
  value.programKind === state.programKind &&
  value.programRevision === state.programRevision &&
  value.rubricHash === state.rubricHash &&
  value.researchHash === state.researchHash &&
  value.mappingHash === state.mappingHash &&
  value.citationRefsHash === state.citationRefsHash &&
  value.sourceRefsHash === state.sourceRefsHash;
const checkRun = (value, state, requestRef, context) => {
  assertKeys(value, runKeys, "invalid_state");
  if (
    ref(value.runRef, "invalid_state") !== evaluationRunRef(requestRef, value.evaluatorRef, value.gate, state) ||
    ref(value.evaluatorRef, "invalid_state") !== value.evaluatorRef ||
    value.requestRef !== requestRef ||
    !context.gates.includes(value.gate) ||
    !context.registry[value.evaluatorRef] ||
    value.originClass !== context.registry[value.evaluatorRef].originClass ||
    !exactBinding(value, state) ||
    digest(value.criteriaHash, "invalid_state") !==
      sha256Canonical({
        gate: value.gate,
        evaluatorRef: value.evaluatorRef,
        originClass: value.originClass,
        rubricHash: state.rubricHash,
        mappingHash: state.mappingHash,
      })
  )
    fail("invalid_state");
  return value;
};
const checkEvaluation = (value, state, context) => {
  assertKeys(value, evaluationKeys, "invalid_state");
  if (
    ref(value.requestRef, "invalid_state") !== value.requestRef ||
    checkInteger(value.expectedRevision, "invalid_state", context.policy) < 0 ||
    !exactBinding(value, state) ||
    value.resolution !== "unresolved" ||
    value.trustedReceiptRequired !== true ||
    !Array.isArray(value.runs) ||
    value.runs.length !== context.gates.length * Object.keys(context.registry).length
  )
    fail("invalid_state");
  requestWindow(value.requestedAt, value.expiresAt, context);
  const runs = value.runs.map((run) => checkRun(run, state, value.requestRef, context));
  if (
    new Set(runs.map((run) => run.runRef)).size !== runs.length ||
    new Set(runs.map((run) => `${run.gate}\u0000${run.originClass}`)).size !== runs.length
  )
    fail("invalid_state");
  return value;
};
const checkApproval = (value, state, context) => {
  assertKeys(value, approvalKeys, "invalid_state");
  const payload = sha256Canonical({
    programHash: value.programHash,
    artifactHash: value.artifactHash,
    programKind: value.programKind,
    programRevision: value.programRevision,
    stateRevision: value.stateRevision,
    rubricHash: value.rubricHash,
    researchHash: value.researchHash,
    mappingHash: value.mappingHash,
    citationRefsHash: value.citationRefsHash,
    sourceRefsHash: value.sourceRefsHash,
    planHash: value.planHash,
    teamRef: value.teamRef,
    userRef: value.userRef,
    messageRef: value.messageRef,
    interactionRef: value.interactionRef,
  });
  if (
    ref(value.requestRef, "invalid_state") !== value.requestRef ||
    ref(value.teamRef, "invalid_state") !== value.teamRef ||
    ref(value.userRef, "invalid_state") !== value.userRef ||
    ref(value.messageRef, "invalid_state") !== value.messageRef ||
    ref(value.interactionRef, "invalid_state") !== value.interactionRef ||
    checkInteger(value.expectedRevision, "invalid_state", context.policy) !== value.stateRevision ||
    !exactBinding(value, state) ||
    value.planHash !== state.planHash ||
    digest(value.payloadHash, "invalid_state") !== payload ||
    value.resolution !== "unresolved" ||
    value.trustedServerTimeRequired !== true ||
    value.trustedReceiptRequired !== true
  )
    fail("invalid_state");
  requestWindow(value.requestedAt, value.expiresAt, context);
  return value;
};
const stateShape = (raw, program, context) => {
  const value = snapshotPlainJson(raw);
  assertKeys(value, stateKeys, "invalid_state");
  assertKeys(value.effects, new Set(["enabled", "available", "outcome"]), "invalid_state");
  assertKeys(value.reconciliation, new Set(["status", "attemptRef", "receiptRef"]), "invalid_state");
  const expected = artifactBindings(program);
  if (
    value.version !== "marketing-state.v4" ||
    !["unresolved", "evaluation_requested", "approval_requested"].includes(value.state) ||
    checkInteger(value.revision, "invalid_state", context.policy) < 0 ||
    value.executionDisposition !== "hard_disabled" ||
    value.effects.enabled !== false ||
    value.effects.available !== false ||
    value.effects.outcome !== "outcome_unknown" ||
    value.reconciliation.status !== "outcome_unknown" ||
    value.reconciliation.attemptRef !== null ||
    value.reconciliation.receiptRef !== null ||
    value.programHash !== program.programHash ||
    Object.keys(expected).some((key) => value[key] !== expected[key]) ||
    sha256Canonical(Object.fromEntries(Object.entries(value).filter(([key]) => key !== "recordHash"))) !==
      value.recordHash
  )
    fail("invalid_state");
  const bound = { ...value, planHash: program.planHash };
  if (
    !Array.isArray(value.evaluationRequests) ||
    !Array.isArray(value.approvalRequests) ||
    value.evaluationRequests.length > 1 ||
    value.approvalRequests.length > 1 ||
    value.revision !== value.evaluationRequests.length + value.approvalRequests.length
  )
    fail("invalid_state");
  const evaluations = value.evaluationRequests.map((item) => checkEvaluation(item, bound, context));
  const approvals = value.approvalRequests.map((item) => checkApproval(item, bound, context));
  const requests = [
    ...evaluations.map((item) => ({ kind: "evaluation_requested", item })),
    ...approvals.map((item) => ({ kind: "approval_requested", item })),
  ].sort((left, right) => left.item.expectedRevision - right.item.expectedRevision);
  if (
    new Set(requests.map((entry) => entry.item.requestRef)).size !== requests.length ||
    requests.some((entry, index) => entry.item.expectedRevision !== index) ||
    value.state !== (requests.at(-1)?.kind ?? "unresolved")
  )
    fail("invalid_state");
  return value;
};
const initializeMarketingStateForContext = (context, rawProgram) => {
  const program = programShape(rawProgram, context);
  const bindings = artifactBindings(program);
  return record({
    version: "marketing-state.v4",
    programHash: program.programHash,
    ...bindings,
    state: "unresolved",
    revision: 0,
    evaluationRequests: Object.freeze([]),
    approvalRequests: Object.freeze([]),
    effects: Object.freeze({ enabled: false, available: false, outcome: "outcome_unknown" }),
    executionDisposition: "hard_disabled",
    reconciliation: Object.freeze({ status: "outcome_unknown", attemptRef: null, receiptRef: null }),
  });
};
const sameProgram = (state, program) =>
  state.programHash === program.programHash &&
  Object.entries(artifactBindings(program)).every(([key, value]) => state[key] === value);
const requestMarketingEvaluationForContext = (context, rawState, rawRequest, rawProgram) => {
  const program = programShape(rawProgram, context);
  const state = stateShape(rawState, program, context);
  const request = snapshotPlainJson(rawRequest);
  assertKeys(request, evaluationInputKeys, "invalid_evaluation_request");
  if (
    !sameProgram(state, program) ||
    !exactBinding(request, state) ||
    !Number.isSafeInteger(request.expectedRevision) ||
    request.expectedRevision < 0 ||
    request.expectedRevision > context.policy.maximumRevision
  )
    fail("evaluation_binding_mismatch");
  requestWindow(request.requestedAt, request.expiresAt, context);
  const crossKind = state.approvalRequests.some((item) => item.requestRef === request.requestRef);
  if (crossKind) fail("event_reuse_mismatch");
  const runs = Object.entries(context.registry)
    .flatMap(([evaluatorRef, evaluator]) =>
      context.gates.map((gate) =>
        Object.freeze({
          runRef: evaluationRunRef(request.requestRef, evaluatorRef, gate, state),
          gate,
          evaluatorRef,
          originClass: evaluator.originClass,
          ...artifactBindings(program),
          programHash: state.programHash,
          requestRef: request.requestRef,
          criteriaHash: sha256Canonical({
            gate,
            evaluatorRef,
            originClass: evaluator.originClass,
            rubricHash: state.rubricHash,
            mappingHash: state.mappingHash,
          }),
        }),
      ),
    )
    .sort((left, right) => compareCodepoints(left.runRef, right.runRef));
  const item = Object.freeze({
    requestRef: ref(request.requestRef, "invalid_evaluation_request"),
    expectedRevision: request.expectedRevision,
    programHash: state.programHash,
    ...artifactBindings(program),
    requestedAt: request.requestedAt,
    expiresAt: request.expiresAt,
    runs: Object.freeze(runs),
    resolution: "unresolved",
    trustedReceiptRequired: true,
  });
  const found = state.evaluationRequests.find((entry) => entry.requestRef === item.requestRef);
  if (found) {
    if (sha256Canonical(found) !== sha256Canonical(item)) fail("event_reuse_mismatch");
    return state;
  }
  if (state.evaluationRequests.length !== 0) fail("duplicate_evaluation_request");
  if (request.expectedRevision !== state.revision) fail("revision_conflict");
  return record({
    ...state,
    state: "evaluation_requested",
    revision: state.revision + 1,
    evaluationRequests: Object.freeze([...state.evaluationRequests, item]),
  });
};
const requestMarketingPlanApprovalForContext = (context, rawState, rawRequest, rawProgram) => {
  const program = programShape(rawProgram, context);
  const state = stateShape(rawState, program, context);
  const request = snapshotPlainJson(rawRequest);
  assertKeys(request, approvalInputKeys, "invalid_approval_request");
  if (
    program.kind !== "weekly_plan" ||
    !sameProgram(state, program) ||
    !exactBinding(request, state) ||
    request.planHash !== program.planHash ||
    request.teamRef !== program.principalBinding.slackTeamRef ||
    request.userRef !== program.principalBinding.slackUserRef ||
    !Number.isSafeInteger(request.expectedRevision) ||
    request.expectedRevision < 0 ||
    request.expectedRevision > context.policy.maximumRevision
  )
    fail("approval_binding_mismatch");
  requestWindow(request.requestedAt, request.expiresAt, context);
  const expectedPayload = sha256Canonical({
    programHash: state.programHash,
    artifactHash: state.artifactHash,
    programKind: state.programKind,
    programRevision: state.programRevision,
    stateRevision: request.expectedRevision,
    rubricHash: state.rubricHash,
    researchHash: state.researchHash,
    mappingHash: state.mappingHash,
    citationRefsHash: state.citationRefsHash,
    sourceRefsHash: state.sourceRefsHash,
    planHash: program.planHash,
    teamRef: request.teamRef,
    userRef: request.userRef,
    messageRef: request.messageRef,
    interactionRef: request.interactionRef,
  });
  const crossKind = state.evaluationRequests.some((item) => item.requestRef === request.requestRef);
  if (crossKind) fail("event_reuse_mismatch");
  const existing = state.approvalRequests.find((entry) => entry.requestRef === request.requestRef);
  if (existing && request.payloadHash !== existing.payloadHash) fail("event_reuse_mismatch");
  if (digest(request.payloadHash, "invalid_approval_request") !== expectedPayload) fail("approval_payload_mismatch");
  const item = Object.freeze({
    requestRef: ref(request.requestRef, "invalid_approval_request"),
    expectedRevision: request.expectedRevision,
    programHash: state.programHash,
    ...artifactBindings(program),
    planHash: program.planHash,
    teamRef: ref(request.teamRef, "invalid_approval_request"),
    userRef: ref(request.userRef, "invalid_approval_request"),
    messageRef: ref(request.messageRef, "invalid_approval_request"),
    interactionRef: ref(request.interactionRef, "invalid_approval_request"),
    payloadHash: expectedPayload,
    requestedAt: request.requestedAt,
    expiresAt: request.expiresAt,
    stateRevision: request.expectedRevision,
    resolution: "unresolved",
    trustedServerTimeRequired: true,
    trustedReceiptRequired: true,
  });
  if (existing) {
    if (sha256Canonical(existing) !== sha256Canonical(item)) fail("event_reuse_mismatch");
    return state;
  }
  if (state.approvalRequests.length !== 0) fail("duplicate_approval_request");
  if (request.expectedRevision !== state.revision) fail("revision_conflict");
  return record({
    ...state,
    state: "approval_requested",
    revision: state.revision + 1,
    approvalRequests: Object.freeze([...state.approvalRequests, item]),
  });
};
export const recordMarketingEvaluation = () => fail("untrusted_evaluation_receipt");
export const recordMarketingPlanApproval = () => fail("untrusted_approval_receipt");

export function createMarketingStateMachine(contractSuite) {
  const contracts = assertMarketingProgramContractSuite(contractSuite);
  const gates = contracts.policy.requiredEvaluationGates;
  const context = Object.freeze({
    contracts,
    policy: contracts.policy,
    voice: contracts.voice,
    gates,
    registry: evaluatorRegistry(gates),
  });
  return Object.freeze({
    initializeMarketingState: (program) => initializeMarketingStateForContext(context, program),
    requestMarketingEvaluation: (state, request, program) =>
      requestMarketingEvaluationForContext(context, state, request, program),
    requestMarketingPlanApproval: (state, request, program) =>
      requestMarketingPlanApprovalForContext(context, state, request, program),
    recordMarketingEvaluation,
    recordMarketingPlanApproval,
    prospectiveEvaluatorRegistry: context.registry,
    prospectiveReconciliationContract,
  });
}

const ceoMarketingStateMachine = createMarketingStateMachine(ceoMarketingProgramContractSuite);
export const initializeMarketingState = ceoMarketingStateMachine.initializeMarketingState;
export const requestMarketingEvaluation = ceoMarketingStateMachine.requestMarketingEvaluation;
export const requestMarketingPlanApproval = ceoMarketingStateMachine.requestMarketingPlanApproval;
