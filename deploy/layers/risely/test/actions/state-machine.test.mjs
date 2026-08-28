import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ACTION_EVENT_TYPES,
  ACTION_STATUSES,
  ACTION_TRANSITIONS,
  ActionTransitionError,
  createActionState,
  reduceActionState,
} from "../../canary/actions/index.mjs";
import { actionProposal, approval, receipt } from "../contracts/fixtures.mjs";

const CLAIM = {
  type: "claim_execution",
  at: "2026-08-26T10:02:00Z",
  claimId: "claim:1",
  leaseExpiresAt: "2026-08-26T10:03:00Z",
};

function states() {
  const proposal = actionProposal();
  const pending = createActionState(proposal);
  const approved = reduceActionState(pending, { type: "approve", approval: approval(proposal) });
  const executing = reduceActionState(approved, CLAIM);
  const outcomeUnknown = reduceActionState(executing, {
    type: "record_receipt",
    receipt: receipt(proposal, "outcome_unknown"),
  });
  return {
    proposal,
    pending,
    approved,
    executing,
    verified: reduceActionState(executing, { type: "record_receipt", receipt: receipt(proposal, "verified") }),
    refused: reduceActionState(executing, { type: "record_receipt", receipt: receipt(proposal, "refused") }),
    rejected: reduceActionState(pending, { type: "reject", approval: approval(proposal, "reject") }),
    expired: reduceActionState(pending, { type: "expire", at: "2100-08-26T11:00:00Z" }),
    stale: reduceActionState(pending, { type: "mark_stale", at: "2026-08-26T10:05:00Z", reasonCode: "source_changed" }),
    failed: reduceActionState(executing, { type: "record_receipt", receipt: receipt(proposal, "failed") }),
    outcome_unknown: outcomeUnknown,
  };
}

function eventFor(type, state, proposal) {
  if (type === "approve") return { type, approval: approval(proposal) };
  if (type === "reject") return { type, approval: approval(proposal, "reject") };
  if (type === "expire") return { type, at: "2100-08-26T11:00:00Z" };
  if (type === "mark_stale") return { type, at: "2090-08-26T10:05:00Z", reasonCode: "source_changed" };
  if (type === "claim_execution") return CLAIM;
  if (type === "record_receipt") return { type, receipt: receipt(proposal, "verified") };
  throw new Error(`Missing event fixture for ${type} from ${state.status}`);
}

test("transition matrix is exhaustive for every status and event", () => {
  const fixture = states();
  assert.deepEqual(Object.keys(ACTION_TRANSITIONS).sort(), [...ACTION_STATUSES].sort());
  for (const status of ACTION_STATUSES) {
    const state = fixture[status];
    assert.ok(state, `missing state fixture for ${status}`);
    for (const eventType of ACTION_EVENT_TYPES) {
      const event = eventFor(eventType, state, fixture.proposal);
      const legal = ACTION_TRANSITIONS[status].includes(eventType);
      if (legal) {
        assert.doesNotThrow(() => reduceActionState(state, event), `${status} should allow ${eventType}`);
      } else {
        assert.throws(
          () => reduceActionState(state, event),
          (error) => error instanceof ActionTransitionError && error.code === "illegal_transition",
          `${status} should reject ${eventType}`,
        );
      }
    }
  }
});

test("happy path binds approval, claim, and verified receipt", () => {
  const proposal = actionProposal();
  const pending = createActionState(proposal);
  const approved = reduceActionState(pending, { type: "approve", approval: approval(proposal) });
  const executing = reduceActionState(approved, CLAIM);
  const verified = reduceActionState(executing, { type: "record_receipt", receipt: receipt(proposal) });
  assert.equal(verified.status, "verified");
  assert.equal(verified.attempts, 1);
  assert.equal(verified.revision, 3);
  assert.equal(verified.approval.proposalHash, proposal.proposalHash);
  assert.equal(verified.receipt.effectKey, proposal.effectKey);
  assert.equal(verified.claim, null);
  assert.equal(Object.isFrozen(verified), true);
  assert.equal(Object.isFrozen(verified.receipt), true);
});

test("approval must be exact, one-time, current, and bound to the proposal", () => {
  const proposal = actionProposal();
  const pending = createActionState(proposal);
  const wrongHash = approval(proposal, "approve_once", { proposalHash: "f".repeat(64) });
  assert.throws(
    () => reduceActionState(pending, { type: "approve", approval: wrongHash }),
    (error) => error.code === "approval_proposal_mismatch",
  );
  const wrongPrincipal = approval(proposal, "approve_once", { approverPrincipalRef: "person:other" });
  assert.throws(
    () => reduceActionState(pending, { type: "approve", approval: wrongPrincipal }),
    (error) => error.code === "approval_principal_mismatch",
  );
  const late = approval(proposal, "approve_once", {
    decidedAt: "2099-08-26T11:30:00Z",
    expiresAt: "2099-08-26T12:00:00Z",
  });
  assert.throws(
    () => reduceActionState(pending, { type: "approve", approval: late }),
    (error) => error.code === "approval_expired",
  );
  const approved = reduceActionState(pending, { type: "approve", approval: approval(proposal) });
  assert.throws(
    () => reduceActionState(approved, { type: "approve", approval: approval(proposal) }),
    (error) => error.code === "illegal_transition",
  );
  assert.throws(
    () =>
      reduceActionState(approved, {
        ...CLAIM,
        leaseExpiresAt: "2100-08-26T10:03:00Z",
      }),
    (error) => error.code === "invalid_claim",
  );
});

test("approved actions expire at the earliest approval or proposal boundary", () => {
  const proposal = actionProposal();
  const approved = reduceActionState(createActionState(proposal), {
    type: "approve",
    approval: approval(proposal),
  });
  assert.throws(
    () => reduceActionState(approved, { type: "expire", at: "2098-08-26T10:59:59Z" }),
    (error) => error.code === "not_expired",
  );
  const expired = reduceActionState(approved, { type: "expire", at: "2098-08-26T11:00:00Z" });
  assert.equal(expired.status, "expired");
});

test("execution claims enforce expiry and cannot be retried in place", () => {
  const proposal = actionProposal();
  const approved = reduceActionState(createActionState(proposal), {
    type: "approve",
    approval: approval(proposal),
  });
  const executing = reduceActionState(approved, CLAIM);
  assert.throws(
    () => reduceActionState(executing, { ...CLAIM, claimId: "claim:2" }),
    (error) => error.code === "illegal_transition",
  );
  assert.throws(
    () =>
      reduceActionState(approved, {
        ...CLAIM,
        at: "2100-08-26T10:02:00Z",
        leaseExpiresAt: "2100-08-26T10:03:00Z",
      }),
    (error) => error.code === "proposal_expired",
  );
});

test("receipt must bind to the exact proposal and follow the claim", () => {
  const proposal = actionProposal();
  const approved = reduceActionState(createActionState(proposal), {
    type: "approve",
    approval: approval(proposal),
  });
  const executing = reduceActionState(approved, CLAIM);
  assert.throws(
    () =>
      reduceActionState(executing, {
        type: "record_receipt",
        receipt: receipt(proposal, "verified", { effectKey: "f".repeat(64) }),
      }),
    (error) => error.code === "receipt_proposal_mismatch",
  );
  assert.throws(
    () =>
      reduceActionState(executing, {
        type: "record_receipt",
        receipt: receipt(proposal, "verified", { providerAccountRef: proposal.actor.credentialOwnerRef }),
      }),
    (error) => error.code === "receipt_account_mismatch",
  );
  assert.throws(
    () =>
      reduceActionState(executing, {
        type: "record_receipt",
        receipt: receipt(proposal, "verified", { providerAccountRef: "google:subject-other" }),
      }),
    (error) => error.code === "receipt_account_mismatch",
  );
  assert.throws(
    () =>
      reduceActionState(executing, {
        type: "record_receipt",
        receipt: receipt(proposal, "verified", { provider: "slack" }),
      }),
    (error) => error.code === "receipt_provider_mismatch",
  );
  assert.throws(
    () =>
      reduceActionState(executing, {
        type: "record_receipt",
        receipt: receipt(proposal, "verified", { credentialRef: "credential:gmail-other" }),
      }),
    (error) => error.code === "receipt_credential_mismatch",
  );
  assert.throws(
    () =>
      reduceActionState(executing, {
        type: "record_receipt",
        receipt: receipt(proposal, "verified", { claimId: "claim:other" }),
      }),
    (error) => error.code === "receipt_claim_mismatch",
  );
  assert.throws(
    () =>
      reduceActionState(executing, {
        type: "record_receipt",
        receipt: receipt(proposal, "verified", {
          attemptedAt: "2026-08-26T10:01:59Z",
          completedAt: "2026-08-26T10:02:31Z",
        }),
      }),
    (error) => error.code === "receipt_predates_claim",
  );
  assert.throws(
    () =>
      reduceActionState(executing, {
        type: "record_receipt",
        receipt: receipt(proposal, "verified", {
          attemptedAt: "2026-08-26T10:03:00Z",
          completedAt: "2026-08-26T10:03:01Z",
        }),
      }),
    (error) => error.code === "receipt_outside_lease",
  );
});

test("unknown outcomes cannot retry in place", () => {
  const fixture = states();
  assert.throws(
    () => reduceActionState(fixture.outcome_unknown, CLAIM),
    (error) => error.code === "illegal_transition",
  );
  assert.deepEqual(ACTION_TRANSITIONS.outcome_unknown, ["record_receipt"]);
  assert.throws(
    () =>
      reduceActionState(fixture.outcome_unknown, {
        type: "record_receipt",
        receipt: receipt(fixture.proposal, "verified", {
          attemptedAt: "2026-08-26T10:02:30.0000Z",
          completedAt: "2026-08-26T10:05:01Z",
        }),
      }),
    (error) => error.code === "receipt_attempt_mismatch",
  );
});

test("unknown outcomes can reconcile directly to a verified receipt", () => {
  const fixture = states();
  const verified = reduceActionState(fixture.outcome_unknown, {
    type: "record_receipt",
    receipt: receipt(fixture.proposal, "verified", {
      completedAt: "2026-08-26T10:05:01Z",
      providerOperationIds: { messageId: "gmail:recovered-message-1" },
    }),
  });
  assert.equal(verified.status, "verified");
  assert.equal(verified.receipt.providerOperationIds.messageId, "gmail:recovered-message-1");
});

test("receipt reconciliation cannot move the state clock backward", () => {
  const proposal = actionProposal();
  const approved = reduceActionState(createActionState(proposal), {
    type: "approve",
    approval: approval(proposal),
  });
  const executing = reduceActionState(approved, CLAIM);
  const unknown = reduceActionState(executing, {
    type: "record_receipt",
    receipt: receipt(proposal, "outcome_unknown", { completedAt: "2026-08-26T10:05:00Z" }),
  });
  assert.throws(
    () =>
      reduceActionState(unknown, {
        type: "record_receipt",
        receipt: receipt(proposal, "verified", {
          attemptedAt: "2026-08-26T10:02:30Z",
          completedAt: "2026-08-26T10:04:00Z",
        }),
      }),
    (error) => error.code === "non_monotonic_event",
  );
});

test("events and state projections reject unknown fields", () => {
  const proposal = actionProposal();
  const pending = createActionState(proposal);
  assert.throws(
    () => reduceActionState(pending, { type: "approve", approval: approval(proposal), unexpected: true }),
    (error) => error.code === "invalid_shape",
  );
  const fabricated = { ...pending, unexpected: true };
  assert.throws(
    () => reduceActionState(fabricated, { type: "expire", at: "2100-08-26T11:00:00Z" }),
    (error) => error.code === "invalid_shape",
  );
  const hiddenEvent = { type: "approve", approval: approval(proposal) };
  Object.defineProperty(hiddenEvent, "unexpected", { enumerable: false, value: true });
  assert.throws(
    () => reduceActionState(pending, hiddenEvent),
    (error) => error.code === "invalid_shape",
  );
  const invalidTimestamp = { ...pending, updatedAt: "2026-02-30T10:00:00Z" };
  assert.throws(
    () => reduceActionState(invalidTimestamp, { type: "expire", at: "2100-08-26T11:00:00Z" }),
    (error) => error.code === "invalid_time",
  );
  const executing = reduceActionState(
    reduceActionState(pending, { type: "approve", approval: approval(proposal) }),
    CLAIM,
  );
  const overlongStoredClaim = {
    ...executing,
    claim: { ...executing.claim, leaseExpiresAt: "2100-08-26T10:03:00Z" },
  };
  assert.throws(
    () => reduceActionState(overlongStoredClaim, { type: "record_receipt", receipt: receipt(proposal) }),
    (error) => error.code === "invalid_state",
  );
  const approved = reduceActionState(pending, { type: "approve", approval: approval(proposal) });
  assert.throws(
    () => reduceActionState({ ...approved, attempts: 1 }, CLAIM),
    (error) => error.code === "invalid_state",
  );
});
