import { canonicalJson, deepFreeze } from "../contracts/canonicalize.mjs";
import { assertActionProposalHashes } from "../contracts/action-proposal.mjs";
import { isUtcTimestamp, validateContract } from "../contracts/validation.mjs";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const HASH = /^[0-9a-f]{64}$/;

const isId = (value) => typeof value === "string" && ID.test(value);
const isHash = (value) => typeof value === "string" && HASH.test(value);

export const ACTION_STATUSES = Object.freeze([
  "pending",
  "approved",
  "executing",
  "verified",
  "refused",
  "rejected",
  "expired",
  "stale",
  "failed",
  "outcome_unknown",
]);

export const ACTION_EVENT_TYPES = Object.freeze([
  "approve",
  "reject",
  "expire",
  "mark_stale",
  "claim_execution",
  "record_receipt",
]);

export const ACTION_TRANSITIONS = deepFreeze({
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

const EVENT_KEYS = Object.freeze({
  approve: ["type", "approval"],
  reject: ["type", "approval"],
  expire: ["type", "at"],
  mark_stale: ["type", "at", "reasonCode"],
  claim_execution: ["type", "at", "claimId", "leaseExpiresAt"],
  record_receipt: ["type", "receipt"],
});

export class ActionTransitionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ActionTransitionError";
    this.code = code;
  }
}

function assertExactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ActionTransitionError("invalid_shape", `${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new ActionTransitionError("invalid_shape", `${label} has unexpected or missing fields`);
  }
}

function snapshot(value, label) {
  try {
    return JSON.parse(canonicalJson(value));
  } catch {
    throw new ActionTransitionError("invalid_shape", `${label} must be plain canonical JSON`);
  }
}

function time(value, label) {
  if (!isUtcTimestamp(value)) {
    throw new ActionTransitionError("invalid_time", `${label} must be a UTC timestamp`);
  }
  return Date.parse(value);
}

function expirationTime(state) {
  const proposalExpiry = time(state.expiresAt, "Proposal expiresAt");
  if (state.approval?.decision !== "approve_once") return proposalExpiry;
  return Math.min(proposalExpiry, time(state.approval.expiresAt, "Approval expiresAt"));
}

function assertEventShape(event) {
  if (!event || typeof event.type !== "string" || !Object.hasOwn(EVENT_KEYS, event.type)) {
    throw new ActionTransitionError("unknown_event", "Action event type is unknown");
  }
  assertExactKeys(event, EVENT_KEYS[event.type], `Action event ${event.type}`);
}

function assertState(state) {
  assertExactKeys(state, STATE_KEYS, "Action state");
  if (state.stateVersion !== 1) throw new ActionTransitionError("invalid_state", "Action state version is unsupported");
  if (!ACTION_STATUSES.includes(state.status))
    throw new ActionTransitionError("invalid_state", "Action state status is unknown");
  if (!isId(state.proposalId) || !isHash(state.proposalHash) || !isHash(state.effectKey)) {
    throw new ActionTransitionError("invalid_state", "Action state proposal identity is invalid");
  }
  if (!isId(state.actorPrincipalRef)) {
    throw new ActionTransitionError("invalid_state", "Action state actor principal is invalid");
  }
  if (!isId(state.credentialOwnerRef)) {
    throw new ActionTransitionError("invalid_state", "Action state credential owner is invalid");
  }
  if (!isId(state.providerOwnerRef)) {
    throw new ActionTransitionError("invalid_state", "Action state provider owner is invalid");
  }
  if (!isId(state.credentialRef)) {
    throw new ActionTransitionError("invalid_state", "Action state credential is invalid");
  }
  if (!isId(state.expectedProvider)) {
    throw new ActionTransitionError("invalid_state", "Action state provider is invalid");
  }
  if (
    !Number.isInteger(state.revision) ||
    state.revision < 0 ||
    !Number.isInteger(state.attempts) ||
    state.attempts < 0 ||
    state.attempts > 1
  ) {
    throw new ActionTransitionError("invalid_state", "Action state counters are invalid");
  }
  const createdAt = time(state.createdAt, "Action state createdAt");
  const updatedAt = time(state.updatedAt, "Action state updatedAt");
  const expiresAt = time(state.expiresAt, "Action state expiresAt");
  if (updatedAt < createdAt || expiresAt <= createdAt) {
    throw new ActionTransitionError("invalid_state", "Action state timestamps are inconsistent");
  }
  if (state.approval !== null) {
    validateContract("approval", state.approval);
    if (state.approval.proposalId !== state.proposalId || state.approval.proposalHash !== state.proposalHash) {
      throw new ActionTransitionError("invalid_state", "Action state approval does not match its proposal");
    }
    if (state.approval.approverPrincipalRef !== state.actorPrincipalRef) {
      throw new ActionTransitionError("invalid_state", "Action state approval principal does not match its actor");
    }
  }
  if (state.receipt !== null) {
    validateContract("receipt", state.receipt);
    if (
      state.receipt.proposalId !== state.proposalId ||
      state.receipt.proposalHash !== state.proposalHash ||
      state.receipt.effectKey !== state.effectKey ||
      state.receipt.providerAccountRef !== state.providerOwnerRef ||
      state.receipt.credentialRef !== state.credentialRef ||
      state.receipt.provider !== state.expectedProvider
    ) {
      throw new ActionTransitionError("invalid_state", "Action state receipt does not match its proposal");
    }
  }
  if (state.claim !== null) {
    assertExactKeys(state.claim, ["claimId", "at", "leaseExpiresAt"], "Action state claim");
    if (!isId(state.claim.claimId)) {
      throw new ActionTransitionError("invalid_state", "Action state claim id is invalid");
    }
    if (
      time(state.claim.leaseExpiresAt, "Action state lease expiry") <= time(state.claim.at, "Action state claim time")
    ) {
      throw new ActionTransitionError("invalid_state", "Action state claim lease is invalid");
    }
    if (time(state.claim.leaseExpiresAt, "Action state lease expiry") > expirationTime(state)) {
      throw new ActionTransitionError("invalid_state", "Action state claim exceeds an authority expiry boundary");
    }
  }
  if (["approved", "executing", "verified", "refused", "failed", "outcome_unknown"].includes(state.status)) {
    if (state.approval?.decision !== "approve_once") {
      throw new ActionTransitionError("invalid_state", "Executable action state lacks an approve-once decision");
    }
  }
  if (state.status === "executing" && state.claim === null) {
    throw new ActionTransitionError("invalid_state", "Executing action state lacks a claim");
  }
  if (state.status !== "executing" && state.claim !== null) {
    throw new ActionTransitionError("invalid_state", "Non-executing action state retains a claim");
  }
  if (state.receipt !== null && state.approval?.decision !== "approve_once") {
    throw new ActionTransitionError("invalid_state", "Action state receipt lacks an approve-once decision");
  }
  if (["verified", "refused", "failed", "outcome_unknown"].includes(state.status) && state.receipt === null) {
    throw new ActionTransitionError("invalid_state", "Action outcome state lacks a receipt");
  }
  if (state.receipt !== null && ["verified", "refused", "stale", "failed", "outcome_unknown"].includes(state.status)) {
    if (state.receipt?.status !== state.status) {
      throw new ActionTransitionError("invalid_state", "Action state status does not match its receipt");
    }
  }
  if (state.receipt !== null && state.attempts !== 1) {
    throw new ActionTransitionError(
      "invalid_state",
      "Action state receipt does not bind to exactly one execution attempt",
    );
  }
  if (state.status === "pending") {
    if (state.approval !== null || state.receipt !== null || state.attempts !== 0) {
      throw new ActionTransitionError("invalid_state", "Pending action state contains later-phase data");
    }
  }
  if (["rejected", "expired"].includes(state.status)) {
    if (state.receipt !== null || state.attempts !== 0) {
      throw new ActionTransitionError("invalid_state", "Unexecuted terminal action state contains execution data");
    }
  }
  if (["approved", "executing"].includes(state.status) && state.receipt !== null) {
    throw new ActionTransitionError("invalid_state", "Pre-outcome action state contains a receipt");
  }
  if (state.status === "approved" && state.attempts !== 0) {
    throw new ActionTransitionError("invalid_state", "Approved action state contains an execution attempt");
  }
  if (state.status === "executing" && state.attempts !== 1) {
    throw new ActionTransitionError("invalid_state", "Executing action state does not contain exactly one attempt");
  }
  if (state.status === "stale" && state.attempts !== (state.receipt === null ? 0 : 1)) {
    throw new ActionTransitionError("invalid_state", "Stale action state has inconsistent attempt data");
  }
  if (state.status === "rejected" && state.approval?.decision !== "reject") {
    throw new ActionTransitionError("invalid_state", "Rejected action state lacks a rejection decision");
  }
}

function assertMonotonic(state, at) {
  if (time(at, "Action event timestamp") < time(state.updatedAt, "Action state updatedAt")) {
    throw new ActionTransitionError("non_monotonic_event", "Action event predates the current state");
  }
}

function assertApproval(state, approval, decision) {
  validateContract("approval", approval);
  if (approval.decision !== decision) {
    throw new ActionTransitionError("approval_decision_mismatch", `Approval decision must be ${decision}`);
  }
  if (approval.proposalId !== state.proposalId || approval.proposalHash !== state.proposalHash) {
    throw new ActionTransitionError("approval_proposal_mismatch", "Approval does not bind to this proposal");
  }
  if (approval.approverPrincipalRef !== state.actorPrincipalRef) {
    throw new ActionTransitionError(
      "approval_principal_mismatch",
      "Approval principal does not match the proposal actor",
    );
  }
  const decidedAt = time(approval.decidedAt, "Approval decidedAt");
  if (
    decidedAt >= time(approval.expiresAt, "Approval expiresAt") ||
    decidedAt >= time(state.expiresAt, "Proposal expiresAt")
  ) {
    throw new ActionTransitionError("approval_expired", "Approval was decided at or after an expiry boundary");
  }
  assertMonotonic(state, approval.decidedAt);
}

function assertClaim(state, event) {
  assertMonotonic(state, event.at);
  if (!isId(event.claimId)) {
    throw new ActionTransitionError("invalid_claim", "Execution claim id is invalid");
  }
  const at = time(event.at, "Execution claim timestamp");
  const leaseExpiresAt = time(event.leaseExpiresAt, "Execution lease expiry");
  if (leaseExpiresAt <= at)
    throw new ActionTransitionError("invalid_claim", "Execution lease must expire after claim time");
  if (at >= time(state.expiresAt, "Proposal expiresAt")) {
    throw new ActionTransitionError("proposal_expired", "Execution cannot begin after proposal expiry");
  }
  if (state.approval && at >= time(state.approval.expiresAt, "Approval expiresAt")) {
    throw new ActionTransitionError("approval_expired", "Execution cannot begin after approval expiry");
  }
  if (leaseExpiresAt > expirationTime(state)) {
    throw new ActionTransitionError("invalid_claim", "Execution lease cannot exceed an authority expiry boundary");
  }
}

function assertReceipt(state, receipt) {
  validateContract("receipt", receipt);
  if (
    receipt.proposalId !== state.proposalId ||
    receipt.proposalHash !== state.proposalHash ||
    receipt.effectKey !== state.effectKey
  ) {
    throw new ActionTransitionError("receipt_proposal_mismatch", "Receipt does not bind to this action");
  }
  if (receipt.providerAccountRef !== state.providerOwnerRef) {
    throw new ActionTransitionError(
      "receipt_account_mismatch",
      "Receipt provider account does not match the provider owner",
    );
  }
  if (receipt.credentialRef !== state.credentialRef) {
    throw new ActionTransitionError(
      "receipt_credential_mismatch",
      "Receipt credential does not match the approved proposal",
    );
  }
  if (receipt.provider !== state.expectedProvider) {
    throw new ActionTransitionError(
      "receipt_provider_mismatch",
      "Receipt provider does not match the approved capability",
    );
  }
  if (state.status === "executing" && receipt.claimId !== state.claim?.claimId) {
    throw new ActionTransitionError("receipt_claim_mismatch", "Receipt does not bind to the active execution claim");
  }
  if (state.status === "outcome_unknown" && receipt.claimId !== state.receipt?.claimId) {
    throw new ActionTransitionError(
      "receipt_claim_mismatch",
      "Reconciliation receipt does not bind to the unknown attempt",
    );
  }
  const attemptedAt = time(receipt.attemptedAt, "Receipt attemptedAt");
  if (receipt.completedAt && time(receipt.completedAt, "Receipt completedAt") < attemptedAt) {
    throw new ActionTransitionError("invalid_receipt_time", "Receipt completion predates its attempt");
  }
  if (state.status === "executing" && state.claim && attemptedAt < time(state.claim.at, "Execution claim timestamp")) {
    throw new ActionTransitionError("receipt_predates_claim", "Receipt predates the execution claim");
  }
  if (
    state.status === "executing" &&
    state.claim &&
    attemptedAt >= time(state.claim.leaseExpiresAt, "Execution lease expiry")
  ) {
    throw new ActionTransitionError("receipt_outside_lease", "Receipt attempt began outside the execution lease");
  }
  if (state.status === "outcome_unknown" && state.receipt) {
    if (receipt.status === "outcome_unknown") {
      throw new ActionTransitionError("unresolved_outcome", "Reconciliation must resolve an unknown outcome");
    }
    if (receipt.attemptedAt !== state.receipt.attemptedAt) {
      throw new ActionTransitionError(
        "receipt_attempt_mismatch",
        "Reconciliation receipt must retain the original attempt time",
      );
    }
  }
  assertMonotonic(state, receipt.completedAt ?? receipt.attemptedAt);
}

function next(state, patch, at) {
  return deepFreeze({
    ...state,
    ...patch,
    revision: state.revision + 1,
    updatedAt: at,
  });
}

export function createActionState(proposal) {
  const approvedProposal = assertActionProposalHashes(proposal);
  return deepFreeze({
    stateVersion: 1,
    proposalId: approvedProposal.proposalId,
    proposalHash: approvedProposal.proposalHash,
    effectKey: approvedProposal.effectKey,
    actorPrincipalRef: approvedProposal.actor.principalRef,
    credentialOwnerRef: approvedProposal.actor.credentialOwnerRef,
    providerOwnerRef: approvedProposal.target.providerOwnerRef,
    credentialRef: approvedProposal.credentialRef,
    expectedProvider: approvedProposal.provider,
    expiresAt: approvedProposal.expiresAt,
    status: "pending",
    revision: 0,
    attempts: 0,
    approval: null,
    receipt: null,
    claim: null,
    createdAt: approvedProposal.createdAt,
    updatedAt: approvedProposal.createdAt,
  });
}

export function reduceActionState(state, event) {
  const currentState = snapshot(state, "Action state");
  const currentEvent = snapshot(event, "Action event");
  assertState(currentState);
  assertEventShape(currentEvent);
  state = currentState;
  event = currentEvent;
  if (!ACTION_TRANSITIONS[state.status].includes(event.type)) {
    throw new ActionTransitionError(
      "illegal_transition",
      `Action event ${event.type} is not allowed from ${state.status}`,
    );
  }

  if (event.type === "approve") {
    assertApproval(state, event.approval, "approve_once");
    return next(state, { status: "approved", approval: structuredClone(event.approval) }, event.approval.decidedAt);
  }
  if (event.type === "reject") {
    assertApproval(state, event.approval, "reject");
    return next(state, { status: "rejected", approval: structuredClone(event.approval) }, event.approval.decidedAt);
  }
  if (event.type === "expire") {
    assertMonotonic(state, event.at);
    if (time(event.at, "Expiry timestamp") < expirationTime(state)) {
      throw new ActionTransitionError("not_expired", "Action cannot expire before its effective expiry boundary");
    }
    return next(state, { status: "expired" }, event.at);
  }
  if (event.type === "mark_stale") {
    assertMonotonic(state, event.at);
    if (typeof event.reasonCode !== "string" || !/^[a-z0-9][a-z0-9._-]{0,254}$/.test(event.reasonCode)) {
      throw new ActionTransitionError("invalid_reason", "Staleness reason code is invalid");
    }
    return next(state, { status: "stale", claim: null }, event.at);
  }
  if (event.type === "claim_execution") {
    assertClaim(state, event);
    return next(
      state,
      {
        status: "executing",
        attempts: state.attempts + 1,
        claim: { claimId: event.claimId, at: event.at, leaseExpiresAt: event.leaseExpiresAt },
      },
      event.at,
    );
  }
  if (event.type === "record_receipt") {
    assertReceipt(state, event.receipt);
    const status = event.receipt.status;
    return next(
      state,
      { status, receipt: structuredClone(event.receipt), claim: null },
      event.receipt.completedAt ?? event.receipt.attemptedAt,
    );
  }
  throw new ActionTransitionError("unknown_event", "Action event type is unknown");
}
