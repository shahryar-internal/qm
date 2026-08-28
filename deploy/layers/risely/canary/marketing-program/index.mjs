import { createMarketingProgramContractSuite } from "./contracts.mjs";
import {
  buildDailyMarketingDraftForContractSuite,
  buildWeeklyMarketingPlanForContractSuite,
  inspectDailyMarketingDraftForContractSuite,
} from "./program.mjs";
import { createMarketingBoundaryFixtureForContractSuite } from "./boundary-fixtures.mjs";
import { createMarketingStateMachine } from "./state-machine.mjs";

export function createMarketingProgramWorkflow(profile) {
  const contracts = createMarketingProgramContractSuite(profile);
  const stateMachine = createMarketingStateMachine(contracts);
  return Object.freeze({
    profile: contracts.profile,
    contracts,
    createBoundaryFixture: (options) => createMarketingBoundaryFixtureForContractSuite(contracts, options),
    buildWeeklyMarketingPlan: (value) => buildWeeklyMarketingPlanForContractSuite(contracts, value),
    inspectDailyMarketingDraft: (value) => inspectDailyMarketingDraftForContractSuite(contracts, value),
    buildDailyMarketingDraft: (value, callerApprovalContext) =>
      buildDailyMarketingDraftForContractSuite(contracts, value, callerApprovalContext),
    ...stateMachine,
    providerExecutionAllowed: false,
  });
}

export {
  createMarketingProgramContractSuite,
  marketingBindingAnchor,
  marketingPolicy,
  requiredEvaluationGates,
  shahryarVoiceRubric,
  normalizeMarketingInput,
} from "./contracts.mjs";
export {
  buildDailyMarketingDraft,
  buildWeeklyMarketingPlan,
  inspectDailyMarketingDraft,
  marketingProgramHash,
} from "./program.mjs";
export { createMarketingBoundaryFixture } from "./boundary-fixtures.mjs";
export {
  createMarketingStateMachine,
  initializeMarketingState,
  prospectiveEvaluatorRegistry,
  prospectiveReconciliationContract,
  recordMarketingEvaluation,
  recordMarketingPlanApproval,
  requestMarketingEvaluation,
  requestMarketingPlanApproval,
} from "./state-machine.mjs";
export { presentMarketingProgram } from "./presentation.mjs";
export { MarketingProgramError, canonicalJson, sha256Canonical, snapshotPlainJson } from "./validation.mjs";
