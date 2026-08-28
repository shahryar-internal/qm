import Ajv from "ajv";
import { canonicalJson } from "./canonicalize.mjs";
import { contractSchemas, supportingSchemas } from "./schemas.mjs";

const UTC_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;

export function isUtcTimestamp(value) {
  if (typeof value !== "string") return false;
  const match = UTC_TIMESTAMP.exec(value);
  if (!match) return false;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return false;
  const date = new Date(parsed);
  const parts = match.slice(1).map(Number);
  return (
    date.getUTCFullYear() === parts[0] &&
    date.getUTCMonth() + 1 === parts[1] &&
    date.getUTCDate() === parts[2] &&
    date.getUTCHours() === parts[3] &&
    date.getUTCMinutes() === parts[4] &&
    date.getUTCSeconds() === parts[5]
  );
}

const ajv = new Ajv({ allErrors: true, strict: true });
ajv.addFormat("utc-date-time", {
  type: "string",
  validate: isUtcTimestamp,
});
ajv.addFormat("secure-https-url", {
  type: "string",
  validate(value) {
    try {
      const url = new URL(value);
      return url.protocol === "https:" && url.hostname.length > 0 && url.username === "" && url.password === "";
    } catch {
      return false;
    }
  },
});

for (const schema of supportingSchemas) ajv.addSchema(schema);
for (const schema of Object.values(contractSchemas)) ajv.addSchema(schema);

const validators = Object.fromEntries(
  Object.entries(contractSchemas).map(([name, schema]) => [name, ajv.getSchema(schema.$id)]),
);

function semanticError(instancePath, message) {
  return [{ instancePath, schemaPath: "#semantic", keyword: "semantic", params: {}, message }];
}

function duplicate(values) {
  return values.find((value, index) => values.indexOf(value) !== index);
}

function semanticErrors(contractName, value) {
  if (contractName === "run" && value.agentVersion !== value.actor.agent.version) {
    return semanticError("/agentVersion", "must match actor.agent.version");
  }
  if (
    contractName === "evidenceRef" &&
    value.observedAt &&
    Date.parse(value.observedAt) > Date.parse(value.fetchedAt)
  ) {
    return semanticError("/observedAt", "must not be after fetchedAt");
  }
  if (contractName === "workflowArtifact") {
    if (value.runId !== value.artifact.runId) return semanticError("/artifact/runId", "must match runId");
    const evidenceIds = value.evidenceRefs.map((entry) => entry.evidenceId);
    const repeated = duplicate(evidenceIds);
    if (repeated) return semanticError("/evidenceRefs", `contains duplicate evidenceId ${repeated}`);
    const missing = value.artifact.evidenceIds.find((evidenceId) => !evidenceIds.includes(evidenceId));
    if (missing) return semanticError("/artifact/evidenceIds", `references missing evidenceId ${missing}`);
  }
  if (contractName === "actionProposal") {
    if (value.provider !== value.capability.split(".", 1)[0]) {
      return semanticError("/provider", "must match the capability namespace");
    }
    if (Date.parse(value.createdAt) >= Date.parse(value.expiresAt)) {
      return semanticError("/expiresAt", "must be after createdAt");
    }
    const artifactIds = value.artifactRefs.map((entry) => entry.artifactId);
    const repeatedArtifact = duplicate(artifactIds);
    if (repeatedArtifact) return semanticError("/artifactRefs", `contains duplicate artifactId ${repeatedArtifact}`);
    const evidenceIds = value.evidenceRefs.map((entry) => entry.evidenceId);
    const repeatedEvidence = duplicate(evidenceIds);
    if (repeatedEvidence) return semanticError("/evidenceRefs", `contains duplicate evidenceId ${repeatedEvidence}`);
    const invalidEvidenceTime = value.evidenceRefs.findIndex(
      (entry) =>
        Date.parse(entry.fetchedAt) > Date.parse(value.createdAt) ||
        (entry.observedAt && Date.parse(entry.observedAt) > Date.parse(entry.fetchedAt)),
    );
    if (invalidEvidenceTime !== -1) {
      return semanticError(
        `/evidenceRefs/${invalidEvidenceTime}`,
        "must be observed no later than fetch and fetched no later than proposal creation",
      );
    }
  }
  if (contractName === "approval" && Date.parse(value.decidedAt) >= Date.parse(value.expiresAt)) {
    return semanticError("/decidedAt", "must be before expiresAt");
  }
  if (
    contractName === "receipt" &&
    value.completedAt &&
    Date.parse(value.completedAt) < Date.parse(value.attemptedAt)
  ) {
    return semanticError("/completedAt", "must not be before attemptedAt");
  }
  return null;
}

export class ContractValidationError extends Error {
  constructor(contractName, errors) {
    const detail = ajv.errorsText(errors, { separator: "; " });
    super(`${contractName} contract validation failed: ${detail}`);
    this.name = "ContractValidationError";
    this.contractName = contractName;
    this.errors = structuredClone(errors ?? []);
  }
}

export function validateContract(contractName, value) {
  const validate = validators[contractName];
  if (!validate) throw new Error(`Unknown contract schema: ${contractName}`);
  try {
    canonicalJson(value);
  } catch (error) {
    throw new ContractValidationError(contractName, semanticError("", error.message));
  }
  if (!validate(value)) throw new ContractValidationError(contractName, validate.errors);
  const semantic = semanticErrors(contractName, value);
  if (semantic) throw new ContractValidationError(contractName, semantic);
  return value;
}

export function contractIsValid(contractName, value) {
  try {
    validateContract(contractName, value);
    return true;
  } catch {
    return false;
  }
}
