import {
  createRevenueProgramStateMachine,
  initializeRevenueProgramState as validateRevenueProgramOutput,
} from "./state-machine.mjs";
import { canonicalJson as canonicalRevenueProgram } from "./validation.mjs";
import { createRevenueProgramContractSuite } from "./contracts.mjs";
import { buildRevenueProgramForContractSuite } from "./program.mjs";
import { createRevenueProgramBoundaryFixtureForContractSuite } from "./boundary-fixtures.mjs";

const freezeVerifiedProjection = (value) => {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const entry of Object.values(value)) freezeVerifiedProjection(entry);
  return Object.freeze(value);
};

export function verifyRevenueProgramOutput(value) {
  validateRevenueProgramOutput(value);
  return freezeVerifiedProjection(JSON.parse(canonicalRevenueProgram(value)));
}

export function createRevenueProgramWorkflow(profile) {
  const contracts = createRevenueProgramContractSuite(profile);
  const stateMachine = createRevenueProgramStateMachine(contracts);
  return Object.freeze({
    profile: contracts.profile,
    contracts,
    buildRevenueProgram: (value) => buildRevenueProgramForContractSuite(contracts, value),
    createBoundaryFixture: (options) => createRevenueProgramBoundaryFixtureForContractSuite(contracts, options),
    verifyRevenueProgramOutput: (value) => {
      stateMachine.initializeRevenueProgramState(value);
      return freezeVerifiedProjection(JSON.parse(canonicalRevenueProgram(value)));
    },
    ...stateMachine,
    providerExecutionAllowed: false,
  });
}

export {
  brainReadTools,
  brainQueryReference,
  brainToolFactFields,
  brainToolSubjectRefs,
  candidateAccountPolicy,
  createRevenueProgramContractSuite,
  deploymentConnectionAnchors,
  deploymentPrincipalBindingAnchor,
  deploymentSlackAudience,
  normalizeRevenueProgramInput,
  proposedEffectTypes,
  proposalPresentationLabels,
  providerCitationReference,
  providerCorrelationReference,
  providerFactSchemas,
  providerRecordReference,
  requiredEvaluationGates,
  revenueProgramPolicy,
  revenueSourceNames,
  sourceSemanticPolicies,
  slackActionRegistry,
} from "./contracts.mjs";
export { buildRevenueProgram } from "./program.mjs";
export { presentRevenueProgram } from "./presentation.mjs";
export { createRevenueProgramBoundaryFixture } from "./boundary-fixtures.mjs";
export {
  initializeRevenueProgramState,
  createRevenueProgramStateMachine,
  evaluationGateCriteria,
  prospectiveEvaluatorRegistry,
  prospectiveReconciliationContract,
  recordRevenueProgramApproval,
  recordRevenueProgramEvaluation,
  requestRevenueProgramApproval,
  requestRevenueProgramEvaluation,
} from "./state-machine.mjs";
export { canonicalJson, RevenueProgramError, sha256Canonical, snapshotPlainJson } from "./validation.mjs";
