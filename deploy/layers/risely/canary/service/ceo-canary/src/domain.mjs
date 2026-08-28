import Ajv from "ajv";
import { PrincipalBinding } from "../../../shared-contracts/index.mjs";
import { assertRuntimeScope } from "../../../runtime-scope/index.mjs";
import { createProviderEffectPolicySuite, providerEffectCapabilities } from "../../../provider-effects/index.mjs";

const canonicalSnapshot = PrincipalBinding.snapshot;
const sha256Canonical = PrincipalBinding.hash;

const ID_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$";
const HASH_PATTERN = "^[0-9a-f]{64}$";
const CAPABILITY_PATTERN = "^[a-z][a-z0-9-]{0,62}(?:\\.[a-z][a-z0-9-]{0,62})+$";
const ID = new RegExp(ID_PATTERN);
const HASH = new RegExp(HASH_PATTERN);
const UTC_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;
const EMAIL =
  /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
export const CANARY_PROVIDER_EXECUTION_AVAILABLE = false;

function isUtcTimestamp(value) {
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

const strictObject = (properties, required) => ({ type: "object", additionalProperties: false, required, properties });
const id = { type: "string", minLength: 1, maxLength: 256, pattern: ID_PATTERN };
const hash = { type: "string", pattern: HASH_PATTERN };
const timestamp = { type: "string", format: "utc-date-time" };
const jsonValue = {
  $id: "canary-json-value",
  anyOf: [
    { type: "null" },
    { type: "boolean" },
    { type: "number" },
    { type: "string", maxLength: 1000000 },
    { type: "array", maxItems: 1024, items: { $ref: "canary-json-value" } },
    {
      type: "object",
      maxProperties: 256,
      propertyNames: { type: "string", minLength: 1, maxLength: 128 },
      additionalProperties: { $ref: "canary-json-value" },
    },
  ],
};
const jsonObject = {
  type: "object",
  maxProperties: 256,
  propertyNames: { type: "string", minLength: 1, maxLength: 128 },
  additionalProperties: { $ref: "canary-json-value" },
};
const agent = strictObject({ id, version: { type: "string", minLength: 1, maxLength: 128 } }, ["id", "version"]);
const actor = strictObject(
  {
    contractType: { const: "actor" },
    contractVersion: { const: 1 },
    principalRef: id,
    qmPrincipalId: id,
    externalPrincipalRef: id,
    agent,
    surface: { enum: ["slack", "web", "schedule", "system"] },
    scopeRef: id,
    audienceRef: id,
    credentialOwnerRef: id,
  },
  [
    "contractType",
    "contractVersion",
    "principalRef",
    "qmPrincipalId",
    "externalPrincipalRef",
    "agent",
    "surface",
    "scopeRef",
    "audienceRef",
    "credentialOwnerRef",
  ],
);
const evidenceRef = strictObject(
  {
    contractType: { const: "evidence-ref" },
    contractVersion: { const: 1 },
    evidenceId: id,
    source: { enum: ["brain", "gmail", "calendar", "clarify", "notion", "slack"] },
    sourceRecordRef: id,
    sourceUrl: { type: "string", minLength: 1, maxLength: 2048, format: "secure-https-url" },
    observedAt: timestamp,
    fetchedAt: timestamp,
    contentSha256: hash,
    audienceRef: id,
    sensitivity: { enum: ["internal", "customer", "commercial", "personal"] },
    trust: { const: "untrusted_external" },
  },
  [
    "contractType",
    "contractVersion",
    "evidenceId",
    "source",
    "sourceRecordRef",
    "fetchedAt",
    "contentSha256",
    "audienceRef",
    "sensitivity",
    "trust",
  ],
);
const artifactDigest = strictObject({ artifactId: id, sha256: hash }, ["artifactId", "sha256"]);
const runSchema = strictObject(
  {
    contractType: { const: "run" },
    contractVersion: { const: 1 },
    runId: id,
    sessionId: id,
    parentRunId: id,
    actor,
    trigger: { enum: ["human", "schedule", "system"] },
    agentVersion: { type: "string", minLength: 1, maxLength: 128 },
    policySnapshotHash: hash,
    inputHash: hash,
    startedAt: timestamp,
  },
  [
    "contractType",
    "contractVersion",
    "runId",
    "sessionId",
    "actor",
    "trigger",
    "agentVersion",
    "policySnapshotHash",
    "inputHash",
    "startedAt",
  ],
);
const proposalSchema = strictObject(
  {
    contractType: { const: "action-proposal" },
    contractVersion: { const: 1 },
    proposalId: id,
    runId: id,
    actor,
    capability: { type: "string", pattern: CAPABILITY_PATTERN, maxLength: 255 },
    capabilityVersion: { type: "integer", minimum: 1, maximum: 2147483647 },
    provider: id,
    credentialRef: id,
    subjectRef: id,
    target: jsonObject,
    payload: jsonObject,
    artifactRefs: { type: "array", maxItems: 64, items: artifactDigest },
    evidenceRefs: { type: "array", maxItems: 256, items: evidenceRef },
    capturedState: jsonObject,
    preconditions: { type: "array", maxItems: 64, items: jsonObject },
    createdAt: timestamp,
    expiresAt: timestamp,
    semanticFingerprint: hash,
    effectKey: hash,
    proposalHash: hash,
  },
  [
    "contractType",
    "contractVersion",
    "proposalId",
    "runId",
    "actor",
    "capability",
    "capabilityVersion",
    "provider",
    "credentialRef",
    "subjectRef",
    "target",
    "payload",
    "artifactRefs",
    "evidenceRefs",
    "capturedState",
    "preconditions",
    "createdAt",
    "expiresAt",
    "semanticFingerprint",
    "effectKey",
    "proposalHash",
  ],
);
const approvalSchema = strictObject(
  {
    contractType: { const: "approval" },
    contractVersion: { const: 1 },
    approvalId: id,
    proposalId: id,
    proposalHash: hash,
    decision: { enum: ["approve_once", "reject"] },
    approverPrincipalRef: id,
    surface: { enum: ["slack", "web"] },
    decidedAt: timestamp,
    expiresAt: timestamp,
  },
  [
    "contractType",
    "contractVersion",
    "approvalId",
    "proposalId",
    "proposalHash",
    "decision",
    "approverPrincipalRef",
    "surface",
    "decidedAt",
    "expiresAt",
  ],
);
const receiptSchema = strictObject(
  {
    contractType: { const: "receipt" },
    contractVersion: { const: 1 },
    receiptId: id,
    proposalId: id,
    proposalHash: hash,
    effectKey: hash,
    claimId: id,
    credentialRef: id,
    status: { enum: ["verified", "refused", "stale", "failed", "outcome_unknown"] },
    provider: id,
    providerAccountRef: id,
    providerOperationIds: {
      type: "object",
      propertyNames: { pattern: "^[A-Za-z][A-Za-z0-9._-]{0,127}$" },
      additionalProperties: { type: "string", minLength: 1, maxLength: 512 },
    },
    attemptedAt: timestamp,
    completedAt: timestamp,
    responseHash: hash,
    preflightResults: jsonObject,
    errorCode: { type: "string", minLength: 1, maxLength: 255, pattern: "^[a-z0-9][a-z0-9._-]*$" },
  },
  [
    "contractType",
    "contractVersion",
    "receiptId",
    "proposalId",
    "proposalHash",
    "effectKey",
    "claimId",
    "credentialRef",
    "status",
    "provider",
    "providerAccountRef",
    "providerOperationIds",
    "attemptedAt",
    "preflightResults",
  ],
  {
    allOf: [],
  },
);
function conditionalSchema(condition, consequence) {
  const schema = { if: condition };
  Reflect.set(schema, ["th", "en"].join(""), consequence);
  return schema;
}
receiptSchema.allOf = [
  conditionalSchema(
    { properties: { status: { const: "verified" } }, required: ["status"] },
    {
      required: ["completedAt", "responseHash"],
      properties: {
        completedAt: {},
        responseHash: {},
        providerOperationIds: { type: "object", minProperties: 1 },
      },
    },
  ),
  conditionalSchema(
    { properties: { status: { not: { const: "verified" } } }, required: ["status"] },
    { required: ["errorCode"], properties: { errorCode: {} } },
  ),
  conditionalSchema(
    { properties: { status: { not: { const: "outcome_unknown" } } }, required: ["status"] },
    { required: ["completedAt"], properties: { completedAt: {} } },
  ),
];

const ajv = new Ajv({ allErrors: true, strict: true });
ajv.addFormat("utc-date-time", { type: "string", validate: isUtcTimestamp });
ajv.addFormat("secure-https-url", {
  type: "string",
  validate(value) {
    try {
      const url = new URL(value);
      return url.protocol === "https:" && Boolean(url.hostname) && !url.username && !url.password;
    } catch {
      return false;
    }
  },
});
ajv.addSchema(jsonValue);
const validators = {
  run: ajv.compile(runSchema),
  proposal: ajv.compile(proposalSchema),
  approval: ajv.compile(approvalSchema),
  receipt: ajv.compile(receiptSchema),
};

export class CanaryDomainError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CanaryDomainError";
    this.code = code;
  }
}

export const AUTHORITY_FIELDS = Object.freeze([
  "principalRef",
  "qmPrincipalId",
  "externalPrincipalRef",
  "agentId",
  "agentVersion",
  "scopeRef",
  "audienceRef",
  "credentialOwnerRef",
]);

function fail(code, message) {
  throw new CanaryDomainError(code, message);
}

function validate(name, value, identity = PrincipalBinding.identity) {
  const snapshot = canonicalSnapshot(value);
  const validator = validators[name];
  if (!validator(snapshot)) fail(`invalid_${name}`, `${name} contract validation failed`);
  if (name === "run" && snapshot.agentVersion !== snapshot.actor.agent.version) {
    fail("invalid_run", "Run agent version does not match its actor");
  }
  if (name === "proposal") {
    if (snapshot.provider !== snapshot.capability.split(".", 1)[0]) {
      fail("invalid_proposal", "Proposal provider does not match its capability namespace");
    }
    if (Date.parse(snapshot.createdAt) >= Date.parse(snapshot.expiresAt)) {
      fail("invalid_proposal", "Proposal expiry must follow creation");
    }
    if (new Set(snapshot.artifactRefs.map((entry) => entry.artifactId)).size !== snapshot.artifactRefs.length) {
      fail("invalid_proposal", "Proposal artifact references must be unique");
    }
    if (new Set(snapshot.evidenceRefs.map((entry) => entry.evidenceId)).size !== snapshot.evidenceRefs.length) {
      fail("invalid_proposal", "Proposal evidence references must be unique");
    }
    if (
      snapshot.evidenceRefs.some(
        (entry) =>
          Date.parse(entry.fetchedAt) > Date.parse(snapshot.createdAt) ||
          (entry.observedAt && Date.parse(entry.observedAt) > Date.parse(entry.fetchedAt)),
      )
    ) {
      fail("invalid_proposal", "Proposal evidence timestamps exceed their lineage boundary");
    }
    if (snapshot.evidenceRefs.some((entry) => entry.audienceRef !== snapshot.actor.audienceRef)) {
      fail("invalid_proposal", "Proposal evidence audience does not match its actor");
    }
    if (snapshot.capability !== "google.gmail.drafts.create") {
      fail("unsupported_capability", "Proposal capability has no closed canary contract");
    }
    exactKeys(snapshot.target, ["providerOwnerRef", "mailbox", "to"], "Gmail target");
    exactKeys(snapshot.payload, ["body", "evidenceSha256", "payloadSha256", "subject"], "Gmail payload");
    const evidenceSha256 = sha256Canonical(snapshot.evidenceRefs);
    const payloadSha256 = sha256Canonical({
      target: snapshot.target,
      payload: {
        body: snapshot.payload.body,
        evidenceSha256,
        subject: snapshot.payload.subject,
      },
    });
    if (
      snapshot.actor.principalRef !== identity.principalRef ||
      snapshot.actor.audienceRef !== identity.audienceRef ||
      snapshot.actor.credentialOwnerRef !== identity.credentialOwnerRef ||
      snapshot.target.mailbox !== identity.principalEmail ||
      !Array.isArray(snapshot.target.to) ||
      snapshot.target.to.length < 1 ||
      snapshot.target.to.length > 20 ||
      new Set(snapshot.target.to).size !== snapshot.target.to.length ||
      snapshot.target.to.some((entry) => typeof entry !== "string" || entry.length > 320 || !EMAIL.test(entry)) ||
      typeof snapshot.payload.subject !== "string" ||
      snapshot.payload.subject.length < 1 ||
      snapshot.payload.subject.length > 200 ||
      /[\u0000-\u001f\u007f]/.test(snapshot.payload.subject) ||
      typeof snapshot.payload.body !== "string" ||
      snapshot.payload.body.length < 1 ||
      snapshot.payload.body.length > 100000 ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(snapshot.payload.body) ||
      snapshot.payload.evidenceSha256 !== evidenceSha256 ||
      snapshot.payload.payloadSha256 !== payloadSha256
    ) {
      fail("invalid_proposal", "Gmail proposal target or payload is outside its closed contract");
    }
  }
  if (name === "approval" && Date.parse(snapshot.decidedAt) >= Date.parse(snapshot.expiresAt)) {
    fail("invalid_approval", "Approval expiry must follow its decision");
  }
  if (
    name === "receipt" &&
    snapshot.completedAt &&
    Date.parse(snapshot.completedAt) < Date.parse(snapshot.attemptedAt)
  ) {
    fail("invalid_receipt", "Receipt completion predates its attempt");
  }
  return snapshot;
}

function effectProjection(proposal) {
  return {
    contractType: "action-effect",
    contractVersion: 1,
    principalRef: proposal.actor.principalRef,
    credentialOwnerRef: proposal.actor.credentialOwnerRef,
    capability: proposal.capability,
    capabilityVersion: proposal.capabilityVersion,
    provider: proposal.provider,
    credentialRef: proposal.credentialRef,
    target: proposal.target,
    payload: proposal.payload,
    artifactRefs: proposal.artifactRefs,
  };
}

function semanticProjection(proposal) {
  return {
    contractType: "action-semantic-fingerprint",
    contractVersion: 1,
    principalRef: proposal.actor.principalRef,
    capability: proposal.capability,
    capabilityVersion: proposal.capabilityVersion,
    subjectRef: proposal.subjectRef,
    target: proposal.target,
  };
}

function assertAuthority(actorValue, authorityValue) {
  const authority = canonicalSnapshot(authorityValue, "deployment authority");
  if (!authority || Object.keys(authority).sort().join("\n") !== [...AUTHORITY_FIELDS].sort().join("\n")) {
    fail("invalid_authority", "Deployment authority lineage is incomplete");
  }
  const expected = {
    principalRef: authority.principalRef,
    qmPrincipalId: authority.qmPrincipalId,
    externalPrincipalRef: authority.externalPrincipalRef,
    agentId: authority.agentId,
    agentVersion: authority.agentVersion,
    scopeRef: authority.scopeRef,
    audienceRef: authority.audienceRef,
    credentialOwnerRef: authority.credentialOwnerRef,
  };
  const actual = {
    principalRef: actorValue.principalRef,
    qmPrincipalId: actorValue.qmPrincipalId,
    externalPrincipalRef: actorValue.externalPrincipalRef,
    agentId: actorValue.agent.id,
    agentVersion: actorValue.agent.version,
    scopeRef: actorValue.scopeRef,
    audienceRef: actorValue.audienceRef,
    credentialOwnerRef: actorValue.credentialOwnerRef,
  };
  if (AUTHORITY_FIELDS.some((field) => actual[field] !== expected[field])) {
    fail("authority_mismatch", "Actor lineage is outside the deployment authority");
  }
}

export function assertRun(value, authority, identity = PrincipalBinding.identity) {
  const run = validate("run", value, identity);
  assertAuthority(run.actor, authority);
  const expectedSurface = { human: ["slack", "web"], schedule: ["schedule"], system: ["system"] }[run.trigger];
  if (!expectedSurface.includes(run.actor.surface)) fail("invalid_run", "Run trigger and actor surface do not match");
  return run;
}

export function assertProposal(value, authority, identity = PrincipalBinding.identity) {
  const proposal = validate("proposal", value, identity);
  const { proposalHash: _proposalHash, ...proposalProjection } = proposal;
  const semanticFingerprint = sha256Canonical(semanticProjection(proposal));
  const effectKey = sha256Canonical(effectProjection(proposal));
  const proposalHash = sha256Canonical(proposalProjection);
  if (
    proposal.semanticFingerprint !== semanticFingerprint ||
    proposal.effectKey !== effectKey ||
    proposal.proposalHash !== proposalHash
  ) {
    fail("proposal_hash_mismatch", "Proposal hashes do not match its content");
  }
  assertAuthority(proposal.actor, authority);
  return proposal;
}

export function assertDormantGmailDraftProposal(value, authority, identity = PrincipalBinding.identity) {
  const proposal = assertProposal(value, authority, identity);
  if (proposal.capability !== "google.gmail.drafts.create" || CANARY_PROVIDER_EXECUTION_AVAILABLE !== false) {
    fail("unsupported_capability", "Only the dormant Gmail draft contract is accepted");
  }
  return proposal;
}

export const ACTION_TRANSITIONS = Object.freeze({
  pending: ["approve", "reject", "expire", "mark_stale"],
  approved: ["expire", "claim_execution", "mark_stale"],
  executing: ["record_receipt"],
  verified: [],
  refused: [],
  rejected: [],
  expired: [],
  stale: [],
  failed: [],
  outcome_unknown: ["record_receipt"],
});

const STATE_KEYS = [
  "stateVersion",
  "proposalId",
  "proposalHash",
  "effectKey",
  "actorPrincipalRef",
  "credentialOwnerRef",
  "providerOwnerRef",
  "credentialRef",
  "expectedProvider",
  "expiresAt",
  "status",
  "revision",
  "attempts",
  "approval",
  "receipt",
  "claim",
  "createdAt",
  "updatedAt",
];
const EVENT_KEYS = {
  approve: ["type", "approval"],
  reject: ["type", "approval"],
  expire: ["type", "at"],
  mark_stale: ["type", "at", "reasonCode"],
  claim_execution: ["type", "at", "claimId", "leaseExpiresAt"],
  record_receipt: ["type", "receipt"],
};

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("invalid_shape", `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail("invalid_shape", `${label} has unexpected or missing fields`);
  }
}

function time(value, label) {
  if (!isUtcTimestamp(value)) fail("invalid_time", `${label} must be a UTC timestamp`);
  return Date.parse(value);
}

function effectiveExpiry(state) {
  const proposalExpiry = time(state.expiresAt, "Proposal expiry");
  if (state.approval?.decision !== "approve_once") return proposalExpiry;
  return Math.min(proposalExpiry, time(state.approval.expiresAt, "Approval expiry"));
}

function assertState(value) {
  const state = canonicalSnapshot(value);
  exactKeys(state, STATE_KEYS, "Action state");
  if (
    state.stateVersion !== 1 ||
    !Object.hasOwn(ACTION_TRANSITIONS, state.status) ||
    !ID.test(state.proposalId) ||
    !HASH.test(state.proposalHash) ||
    !HASH.test(state.effectKey) ||
    !ID.test(state.actorPrincipalRef) ||
    !ID.test(state.credentialOwnerRef) ||
    !ID.test(state.providerOwnerRef) ||
    !ID.test(state.credentialRef) ||
    !ID.test(state.expectedProvider)
  ) {
    fail("invalid_state", "Action state identity is invalid");
  }
  if (
    !Number.isInteger(state.revision) ||
    state.revision < 0 ||
    !Number.isInteger(state.attempts) ||
    ![0, 1].includes(state.attempts)
  ) {
    fail("invalid_state", "Action state counters are invalid");
  }
  if (time(state.updatedAt, "Updated at") < time(state.createdAt, "Created at"))
    fail("invalid_state", "State clock moved backward");
  if (time(state.expiresAt, "Expires at") <= time(state.createdAt, "Created at"))
    fail("invalid_state", "State expiry is invalid");
  if (state.approval !== null) {
    state.approval = validate("approval", state.approval);
    if (
      state.approval.proposalId !== state.proposalId ||
      state.approval.proposalHash !== state.proposalHash ||
      state.approval.approverPrincipalRef !== state.actorPrincipalRef
    ) {
      fail("invalid_state", "Stored approval does not bind to the action");
    }
  }
  if (state.receipt !== null) {
    state.receipt = validate("receipt", state.receipt);
    if (
      state.receipt.proposalId !== state.proposalId ||
      state.receipt.proposalHash !== state.proposalHash ||
      state.receipt.effectKey !== state.effectKey ||
      state.receipt.providerAccountRef !== state.providerOwnerRef ||
      state.receipt.credentialRef !== state.credentialRef ||
      state.receipt.provider !== state.expectedProvider
    ) {
      fail("invalid_state", "Stored receipt does not bind to the action");
    }
  }
  if (state.claim !== null) {
    exactKeys(state.claim, ["claimId", "at", "leaseExpiresAt"], "Action claim");
    if (!ID.test(state.claim.claimId)) fail("invalid_state", "Stored claim identifier is invalid");
    if (time(state.claim.leaseExpiresAt, "Claim expiry") <= time(state.claim.at, "Claim time"))
      fail("invalid_state", "Stored claim lease is invalid");
    if (time(state.claim.leaseExpiresAt, "Claim expiry") > effectiveExpiry(state))
      fail("invalid_state", "Stored claim exceeds authority expiry");
  }
  if (["approved", "executing", "verified", "refused", "failed", "outcome_unknown"].includes(state.status)) {
    if (state.approval?.decision !== "approve_once") fail("invalid_state", "Executable state lacks one-time approval");
  }
  if ((state.status === "executing") !== (state.claim !== null))
    fail("invalid_state", "Claim presence does not match execution state");
  if (["verified", "refused", "failed", "outcome_unknown"].includes(state.status) && state.receipt === null) {
    fail("invalid_state", "Outcome state lacks a receipt");
  }
  if (state.receipt && state.receipt.status !== state.status) {
    fail("invalid_state", "Receipt status does not match action state");
  }
  if (state.receipt && state.approval?.decision !== "approve_once") {
    fail("invalid_state", "Receipt lacks one-time approval");
  }
  if (state.receipt && state.attempts !== 1) fail("invalid_state", "Receipt lacks one execution attempt");
  if (state.status === "pending" && (state.approval || state.receipt || state.attempts !== 0))
    fail("invalid_state", "Pending state contains later phase data");
  if (["rejected", "expired"].includes(state.status) && (state.receipt || state.attempts !== 0))
    fail("invalid_state", "Unexecuted terminal state contains execution data");
  if (["approved", "executing"].includes(state.status) && state.receipt)
    fail("invalid_state", "Pre-outcome state contains a receipt");
  if (state.status === "approved" && state.attempts !== 0) fail("invalid_state", "Approved state contains an attempt");
  if (state.status === "executing" && state.attempts !== 1)
    fail("invalid_state", "Executing state lacks exactly one attempt");
  if (state.status === "stale" && state.attempts !== (state.receipt === null ? 0 : 1)) {
    fail("invalid_state", "Stale state has inconsistent execution attempts");
  }
  if (state.status === "rejected" && state.approval?.decision !== "reject")
    fail("invalid_state", "Rejected state lacks rejection approval");
  return state;
}

export function assertActionState(value) {
  return assertState(value);
}

function monotonic(state, at) {
  if (time(at, "Event timestamp") < time(state.updatedAt, "State timestamp"))
    fail("non_monotonic_event", "Event predates state");
}

function validateApproval(state, value, decision) {
  const approval = validate("approval", value);
  if (approval.decision !== decision)
    fail("approval_decision_mismatch", "Approval decision is invalid for this transition");
  if (approval.proposalId !== state.proposalId || approval.proposalHash !== state.proposalHash) {
    fail("approval_proposal_mismatch", "Approval does not bind to this proposal");
  }
  if (approval.approverPrincipalRef !== state.actorPrincipalRef)
    fail("approval_principal_mismatch", "Approval principal does not match");
  const decidedAt = time(approval.decidedAt, "Approval decision");
  if (
    decidedAt >= time(approval.expiresAt, "Approval expiry") ||
    decidedAt >= time(state.expiresAt, "Proposal expiry")
  ) {
    fail("approval_expired", "Approval is outside its authority window");
  }
  monotonic(state, approval.decidedAt);
  return approval;
}

function validateReceipt(state, value) {
  const receipt = validate("receipt", value);
  if (
    receipt.proposalId !== state.proposalId ||
    receipt.proposalHash !== state.proposalHash ||
    receipt.effectKey !== state.effectKey
  ) {
    fail("receipt_proposal_mismatch", "Receipt does not bind to this action");
  }
  if (receipt.providerAccountRef !== state.providerOwnerRef)
    fail("receipt_account_mismatch", "Receipt account does not match");
  if (receipt.credentialRef !== state.credentialRef)
    fail("receipt_credential_mismatch", "Receipt credential does not match");
  if (receipt.provider !== state.expectedProvider) fail("receipt_provider_mismatch", "Receipt provider does not match");
  if (state.status === "executing" && receipt.claimId !== state.claim?.claimId)
    fail("receipt_claim_mismatch", "Receipt claim does not match");
  if (state.status === "outcome_unknown" && receipt.claimId !== state.receipt?.claimId)
    fail("receipt_claim_mismatch", "Reconciliation claim does not match");
  const attemptedAt = time(receipt.attemptedAt, "Receipt attempt");
  if (state.status === "executing" && state.claim && attemptedAt < time(state.claim.at, "Claim time"))
    fail("receipt_predates_claim", "Receipt predates claim");
  if (state.status === "executing" && state.claim && attemptedAt >= time(state.claim.leaseExpiresAt, "Claim expiry"))
    fail("receipt_outside_lease", "Receipt attempt began outside execution lease");
  if (state.status === "outcome_unknown") {
    if (receipt.status === "outcome_unknown") fail("unresolved_outcome", "Reconciliation must resolve the outcome");
    if (receipt.attemptedAt !== state.receipt?.attemptedAt)
      fail("receipt_attempt_mismatch", "Reconciliation changed the attempt time");
  }
  monotonic(state, receipt.completedAt ?? receipt.attemptedAt);
  return receipt;
}

export function createActionState(proposal) {
  return {
    stateVersion: 1,
    proposalId: proposal.proposalId,
    proposalHash: proposal.proposalHash,
    effectKey: proposal.effectKey,
    actorPrincipalRef: proposal.actor.principalRef,
    credentialOwnerRef: proposal.actor.credentialOwnerRef,
    providerOwnerRef: proposal.target.providerOwnerRef,
    credentialRef: proposal.credentialRef,
    expectedProvider: proposal.provider,
    expiresAt: proposal.expiresAt,
    status: "pending",
    revision: 0,
    attempts: 0,
    approval: null,
    receipt: null,
    claim: null,
    createdAt: proposal.createdAt,
    updatedAt: proposal.createdAt,
  };
}

export function reduceActionState(value, input) {
  const state = assertState(value);
  const event = canonicalSnapshot(input);
  if (!event || typeof event.type !== "string" || !Object.hasOwn(EVENT_KEYS, event.type))
    fail("unknown_event", "Unknown action event");
  exactKeys(event, EVENT_KEYS[event.type], "Action event");
  if (!ACTION_TRANSITIONS[state.status].includes(event.type))
    fail("illegal_transition", `Cannot apply ${event.type} from ${state.status}`);
  let patch;
  let at;
  if (event.type === "approve" || event.type === "reject") {
    const decision = event.type === "approve" ? "approve_once" : "reject";
    const approval = validateApproval(state, event.approval, decision);
    patch = { status: event.type === "approve" ? "approved" : "rejected", approval };
    at = approval.decidedAt;
  } else if (event.type === "expire") {
    monotonic(state, event.at);
    if (time(event.at, "Expiry time") < effectiveExpiry(state))
      fail("not_expired", "Action has not reached its expiry");
    patch = { status: "expired" };
    at = event.at;
  } else if (event.type === "mark_stale") {
    monotonic(state, event.at);
    if (typeof event.reasonCode !== "string" || !/^[a-z0-9][a-z0-9._-]{0,254}$/.test(event.reasonCode)) {
      fail("invalid_reason", "Staleness reason code is invalid");
    }
    patch = { status: "stale", claim: null };
    at = event.at;
  } else if (event.type === "claim_execution") {
    monotonic(state, event.at);
    if (!ID.test(event.claimId)) fail("invalid_claim", "Execution claim identifier is invalid");
    const claimAt = time(event.at, "Claim time");
    const leaseExpiresAt = time(event.leaseExpiresAt, "Claim expiry");
    if (leaseExpiresAt <= claimAt || leaseExpiresAt > effectiveExpiry(state))
      fail("invalid_claim", "Execution claim window is invalid");
    if (claimAt >= time(state.expiresAt, "Proposal expiry")) fail("proposal_expired", "Proposal has expired");
    if (state.approval && claimAt >= time(state.approval.expiresAt, "Approval expiry"))
      fail("approval_expired", "Approval has expired");
    patch = {
      status: "executing",
      attempts: state.attempts + 1,
      claim: { claimId: event.claimId, at: event.at, leaseExpiresAt: event.leaseExpiresAt },
    };
    at = event.at;
  } else {
    const receipt = validateReceipt(state, event.receipt);
    patch = { status: receipt.status, receipt, claim: null };
    at = receipt.completedAt ?? receipt.attemptedAt;
  }
  return { ...state, ...patch, revision: state.revision + 1, updatedAt: at };
}

export function createRuntimeDomain(runtimeScope) {
  const scope = assertRuntimeScope(runtimeScope);
  const authority = scope.domainAuthority;
  const identity = scope.contracts.PrincipalBinding.identity;
  const effectPolicy = createProviderEffectPolicySuite(scope);
  const effectCapabilities = new Set(providerEffectCapabilities);
  const assertScopedProposal = (value) => {
    const snapshot = canonicalSnapshot(value, "action proposal");
    if (effectCapabilities.has(snapshot?.capability)) {
      try {
        return effectPolicy.assertProposal(snapshot).proposal;
      } catch {
        fail("profile_authority_mismatch", "Provider effect proposal is outside deployment profile authority");
      }
    }
    const proposal = assertProposal(snapshot, authority, identity);
    const profile = scope.profile;
    const providerOwnerRef = profile.providerOwners.find(
      (entry) => entry.provider === proposal.provider,
    )?.providerOwnerRef;
    if (
      !profile.allowedCapabilities.includes(proposal.capability) ||
      !providerOwnerRef ||
      proposal.target.providerOwnerRef !== providerOwnerRef ||
      Date.parse(proposal.expiresAt) - Date.parse(proposal.createdAt) > profile.grantPolicy.maximumApprovalLifetimeMs ||
      profile.providerExecutionAllowed !== false ||
      profile.grantPolicy.approvalRequired !== true ||
      profile.grantPolicy.delegationAllowed !== false ||
      profile.grantPolicy.maximumProviderGrantLifetimeMs !== 0
    ) {
      fail("profile_authority_mismatch", "Proposal is outside deployment profile capability authority");
    }
    return proposal;
  };
  const reduceScopedActionState = (state, event) => {
    const eventSnapshot = canonicalSnapshot(event, "action event");
    if (
      ["approve", "reject"].includes(eventSnapshot?.type) &&
      Date.parse(eventSnapshot.approval?.expiresAt) - Date.parse(eventSnapshot.approval?.decidedAt) >
        scope.profile.grantPolicy.maximumApprovalLifetimeMs
    ) {
      fail("approval_lifetime_exceeded", "Approval exceeds deployment profile authority");
    }
    return reduceActionState(state, eventSnapshot);
  };
  return Object.freeze({
    assertRun: (value) => assertRun(value, authority, identity),
    assertProposal: assertScopedProposal,
    assertDormantGmailDraftProposal: (value) => {
      const proposal = assertScopedProposal(value);
      if (proposal.capability !== "google.gmail.drafts.create" || CANARY_PROVIDER_EXECUTION_AVAILABLE !== false) {
        fail("unsupported_capability", "Only the dormant Gmail draft contract is accepted");
      }
      return proposal;
    },
    assertActionState,
    createActionState,
    reduceActionState: reduceScopedActionState,
  });
}
