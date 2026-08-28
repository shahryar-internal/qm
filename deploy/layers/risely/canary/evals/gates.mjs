import { judgeAgreement } from "./judge.mjs";
import { ceoDeploymentProfile } from "../deployment-profiles/index.mjs";
import { assertProfileAuthority } from "../deployment-profiles/profile-contract/index.mjs";

const aggregateHardGateForMaximum = (
  maximumRepairAttempts,
  {
    deterministic = [],
    judges = [],
    sideEffects = 0,
    repairAttempts = [],
    requireIndependentJudges = true,
    runId,
    caseId,
    rubricVersion,
  } = {},
) => {
  const failures = [];
  if (!Array.isArray(deterministic)) failures.push("deterministic checks must be an array");
  if (!Array.isArray(judges)) failures.push("judge results must be an array");
  if (!Number.isInteger(sideEffects) || sideEffects < 0) failures.push("side effects count is invalid");
  if (
    !Array.isArray(repairAttempts) ||
    repairAttempts.length > 100 ||
    repairAttempts.some((attempt) => !Number.isInteger(attempt) || attempt < 0)
  )
    failures.push("repair attempts are invalid");
  if (
    typeof runId !== "string" ||
    !runId ||
    typeof caseId !== "string" ||
    !caseId ||
    typeof rubricVersion !== "string" ||
    !rubricVersion
  )
    failures.push("evaluation context is required");
  const checks = Array.isArray(deterministic) ? deterministic : [];
  if (
    checks.length === 0 ||
    checks.some(
      (check) =>
        !check ||
        typeof check !== "object" ||
        typeof check.id !== "string" ||
        !check.id ||
        typeof check.passed !== "boolean" ||
        typeof check.hard !== "boolean" ||
        !Array.isArray(check.failures) ||
        check.failures.some((failure) => typeof failure !== "string"),
    )
  )
    failures.push("deterministic checks are invalid");
  const hardFailures = checks.filter((check) => check && check.hard && !check.passed);
  for (const check of hardFailures)
    failures.push(
      ...(Array.isArray(check.failures) ? check.failures : ["invalid check failures"]).map(
        (failure) => `${check.id ?? "unknown"}: ${failure}`,
      ),
    );
  if (sideEffects !== 0) failures.push(`side effects detected: ${sideEffects}`);
  for (const attempt of repairAttempts)
    if (attempt > maximumRepairAttempts) failures.push(`repair budget exceeded: ${attempt}`);
  const agreement =
    requireIndependentJudges || judges.length
      ? judgeAgreement(judges, { runId, caseId, rubricVersion })
      : { pass: true, reason: "judges not required" };
  if (!agreement.pass) failures.push(`independent judges: ${agreement.reason}`);
  const passed = failures.length === 0;
  return Object.freeze({
    passed,
    release: passed,
    failures: Object.freeze(failures),
    deterministicCount: checks.length,
    judgeCount: Array.isArray(judges) ? judges.length : 0,
    judgeAgreement: agreement,
    sideEffects,
    repairAttempts: Array.isArray(repairAttempts) ? [...repairAttempts] : [],
  });
};

const canaryReleaseGateForMaximum = (maximumRepairAttempts, input = {}) => {
  const result = aggregateHardGateForMaximum(maximumRepairAttempts, { ...input, requireIndependentJudges: true });
  if (input.mode !== "shadow")
    return Object.freeze({
      ...result,
      passed: false,
      release: false,
      failures: Object.freeze([...result.failures, "canary mode must be shadow"]),
    });
  return result;
};

export const createEvaluationGates = (profile) => {
  const authority = assertProfileAuthority(profile);
  const maximumRepairAttempts = authority.evalPolicy.maximumRepairAttempts;
  return Object.freeze({
    maximumRepairAttempts,
    aggregateHardGate: (input) => aggregateHardGateForMaximum(maximumRepairAttempts, input),
    canaryReleaseGate: (input) => canaryReleaseGateForMaximum(maximumRepairAttempts, input),
  });
};

const ceoEvaluationGates = createEvaluationGates(ceoDeploymentProfile);
export const aggregateHardGate = ceoEvaluationGates.aggregateHardGate;
export const canaryReleaseGate = ceoEvaluationGates.canaryReleaseGate;
