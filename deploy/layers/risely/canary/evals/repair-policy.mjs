import { ceoDeploymentProfile } from "../deployment-profiles/index.mjs";
import { assertProfileAuthority } from "../deployment-profiles/profile-contract/index.mjs";

export const nonRepairableFailures = Object.freeze([
  "authorization",
  "recipient",
  "unapproved-effect",
  "payload-tamper",
  "approval-replay",
  "grounding-critical",
]);

const protectedKeys = Object.freeze([
  "recipient",
  "to",
  "cc",
  "bcc",
  "mode",
  "operation",
  "action",
  "principal",
  "accountId",
  "capability",
  "payloadHash",
  "effectKey",
  "approvalToken",
  "proposalId",
  "parentId",
  "databaseId",
  "sourceIds",
  "published",
  "send",
  "externalEffect",
]);

const clone = (value) => {
  try {
    return structuredClone(value);
  } catch {
    return undefined;
  }
};

const protectedSnapshot = (value) => {
  const found = [];
  const visit = (node, path, seen) => {
    if (node === null || typeof node !== "object") return;
    if (seen.has(node)) throw new TypeError("cyclic repair output");
    seen.add(node);
    if (Array.isArray(node)) node.forEach((item, index) => visit(item, `${path}[${index}]`, seen));
    else
      for (const [key, item] of Object.entries(node)) {
        const next = `${path}.${key}`;
        if (protectedKeys.includes(key)) found.push([next, item]);
        visit(item, next, seen);
      }
    seen.delete(node);
  };
  visit(value, "$", new WeakSet());
  return JSON.stringify(found);
};

export const classifyFailure = (failure = "") => {
  const text = String(failure).slice(0, 4096).toLowerCase();
  if (/unauthor|permission|wrong principal/.test(text)) return "authorization";
  if (/recipient|wrong target/.test(text)) return "recipient";
  if (/unapproved|external effect/.test(text)) return "unapproved-effect";
  if (/tamper|hash mismatch/.test(text)) return "payload-tamper";
  if (/replay|duplicate execution/.test(text)) return "approval-replay";
  if (/unsupported claim|fabricat|no evidence|grounding/.test(text)) return "grounding-critical";
  if (/schema|format|field|date/.test(text)) return "schema";
  if (/timeout|429|transport|network/.test(text)) return "transport";
  return "quality";
};

const repairDecisionForMaximum = (maximumRepairAttempts, { attempt = 0, failure = "" } = {}) => {
  if (!Number.isInteger(attempt) || attempt < 0)
    return Object.freeze({ action: "quarantine", category: "quality", attempt, reason: "invalid repair attempt" });
  const category = classifyFailure(failure);
  if (nonRepairableFailures.includes(category))
    return Object.freeze({ action: "quarantine", category, attempt, reason: "safety failure requires human review" });
  if (attempt >= maximumRepairAttempts)
    return Object.freeze({ action: "quarantine", category, attempt, reason: "repair budget exhausted" });
  if (category === "schema") return Object.freeze({ action: "deterministic-repair", category, attempt: attempt + 1 });
  if (category === "transport") return Object.freeze({ action: "retry-read-only", category, attempt: attempt + 1 });
  return Object.freeze({ action: "regenerate-with-evidence", category, attempt: attempt + 1 });
};

const applyRepairForPolicy = (policy, output, decision, repairers = {}) => {
  const original = clone(output);
  if (original === undefined && output !== undefined)
    return {
      output,
      decision: policy.repairDecision({ attempt: policy.maximumRepairAttempts, failure: "repairer unavailable" }),
    };
  if (!decision || decision.action === "quarantine") return { output: original, decision };
  if (
    !Object.prototype.hasOwnProperty.call(
      { "deterministic-repair": true, "retry-read-only": true, "regenerate-with-evidence": true },
      decision.action,
    )
  )
    return {
      output: original,
      decision: policy.repairDecision({ attempt: policy.maximumRepairAttempts, failure: "repairer unavailable" }),
    };
  let repairer;
  try {
    repairer = repairers[decision.action];
  } catch {
    return {
      output: original,
      decision: policy.repairDecision({ attempt: policy.maximumRepairAttempts, failure: "repairer unavailable" }),
    };
  }
  if (typeof repairer !== "function")
    return {
      output: original,
      decision: policy.repairDecision({ attempt: policy.maximumRepairAttempts, failure: "repairer unavailable" }),
    };
  let originalSnapshot;
  try {
    originalSnapshot = protectedSnapshot(original);
  } catch {
    return {
      output: original,
      decision: policy.repairDecision({ attempt: policy.maximumRepairAttempts, failure: "repairer unavailable" }),
    };
  }
  let repaired;
  try {
    repaired = clone(repairer(clone(original)));
  } catch {
    repaired = undefined;
  }
  if (repaired === undefined && output !== undefined)
    return {
      output: original,
      decision: policy.repairDecision({ attempt: policy.maximumRepairAttempts, failure: "repairer unavailable" }),
    };
  try {
    if (protectedSnapshot(repaired) !== originalSnapshot)
      return {
        output: original,
        decision: policy.repairDecision({ attempt: policy.maximumRepairAttempts, failure: "payload-tamper" }),
      };
  } catch {
    return {
      output: original,
      decision: policy.repairDecision({ attempt: policy.maximumRepairAttempts, failure: "payload-tamper" }),
    };
  }
  return { output: repaired, decision };
};

export const createRepairPolicy = (profile) => {
  const authority = assertProfileAuthority(profile);
  const policy = {
    maximumRepairAttempts: authority.evalPolicy.maximumRepairAttempts,
  };
  policy.repairDecision = (input) => repairDecisionForMaximum(policy.maximumRepairAttempts, input);
  policy.applyRepair = (output, decision, repairers) => applyRepairForPolicy(policy, output, decision, repairers);
  return Object.freeze(policy);
};

const ceoRepairPolicy = createRepairPolicy(ceoDeploymentProfile);
export const maxRepairAttempts = ceoRepairPolicy.maximumRepairAttempts;
export const repairDecision = ceoRepairPolicy.repairDecision;
export const applyRepair = ceoRepairPolicy.applyRepair;
