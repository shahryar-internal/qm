import assert from "node:assert/strict";
import test from "node:test";
import {
  createDraftAttemptInspector,
  createDraftProposal,
  createDraftReconciliationInspector,
  evaluateDraftRetry,
  GoogleBrokerContractError,
  sha256,
  validateDraftProposal,
} from "../../canary/google-broker/index.mjs";
import { binding, clock, makeKeys, nonce, signPayload } from "./fixtures.mjs";

const code = (expected) => (error) => error instanceof GoogleBrokerContractError && error.code === expected;

const citation = (overrides = {}) => ({
  version: 1,
  evidenceHash: "1".repeat(64),
  organizationId: binding.organizationId,
  deploymentId: binding.deploymentId,
  servicePrincipal: binding.servicePrincipal,
  qmPrincipalId: binding.qmPrincipalId,
  credentialOwnerId: binding.credentialOwnerId,
  provider: "google",
  providerAccountSubject: binding.providerAccountSubject,
  mailbox: binding.mailbox,
  accountType: binding.accountType,
  credentialId: binding.credentialId,
  credentialVersion: binding.credentialVersion,
  grantId: binding.grantId,
  grantVersion: binding.grantVersion,
  leaseId: binding.leaseId,
  leaseExpiresAt: binding.leaseExpiresAt,
  leaseNonce: binding.leaseNonce,
  jobId: binding.jobId,
  jobClass: binding.jobClass,
  operation: "google.gmail.messages.get",
  requestNonce: nonce(20),
  idempotencyKey: "citation_idempotency_0001",
  requestHash: "2".repeat(64),
  responseHash: "3".repeat(64),
  receiptId: "source_receipt_0001",
  keyId: "google-broker-key-0001",
  observedAt: clock.completed,
  ...overrides,
});

const proposalInput = (overrides = {}) => ({
  version: 1,
  proposalId: "proposal_0000001",
  revision: 1,
  operation: "google.gmail.drafts.create",
  binding,
  businessKey: "board-followup-2026q3",
  recipients: { to: ["board@example.com"], cc: [], bcc: [] },
  subject: "Board follow-up",
  bodyText: "Draft body\nNo send operation is represented.",
  citations: [citation()],
  createdAt: "2026-08-26T12:02:00.000Z",
  expiresAt: "2026-08-26T12:05:00.000Z",
  ...overrides,
});

const makeAttemptReceipt = ({ proposal, keys, overrides = {} }) => {
  const base = {
    version: 1,
    receiptId: "draft_receipt_0001",
    keyId: keys.keyId,
    algorithm: "Ed25519",
    attemptId: "draft_attempt_0001",
    proposalId: proposal.proposalId,
    proposalRevision: proposal.revision,
    payloadHash: proposal.payloadHash,
    effectKey: proposal.effectKey,
    authorizationHash: proposal.authorizationHash,
    ...proposal.binding,
    operation: "google.gmail.drafts.create",
    serverClock: "postgresql",
    serverReceivedAt: clock.received,
    serverCompletedAt: clock.completed,
    providerStatus: null,
    outcome: "outcome_unknown",
    providerDraftId: null,
    providerThreadId: null,
    ...overrides,
  };
  return Object.freeze({ ...base, signature: signPayload(base, keys.privateKey) });
};

const inspectAttempt = ({ proposal, keys, receipt = makeAttemptReceipt({ proposal, keys }) }) =>
  createDraftAttemptInspector({ keyId: keys.keyId, publicKey: keys.publicKey }).inspect({ proposal, receipt });

const makeReconciliationReceipt = ({ prior, keys, overrides = {} }) => {
  const attempt = prior.receipt;
  const base = {
    version: 1,
    receiptId: "reconciliation_receipt_0001",
    keyId: keys.keyId,
    algorithm: "Ed25519",
    reconciliationId: "reconciliation_0001",
    priorReceiptId: attempt.receiptId,
    priorReceiptHash: prior.receiptHash,
    priorOutcome: "outcome_unknown",
    payloadHash: attempt.payloadHash,
    effectKey: attempt.effectKey,
    authorizationHash: attempt.authorizationHash,
    organizationId: attempt.organizationId,
    deploymentId: attempt.deploymentId,
    servicePrincipal: attempt.servicePrincipal,
    qmPrincipalId: attempt.qmPrincipalId,
    credentialOwnerId: attempt.credentialOwnerId,
    provider: attempt.provider,
    providerAccountSubject: attempt.providerAccountSubject,
    mailbox: attempt.mailbox,
    accountType: attempt.accountType,
    credentialId: attempt.credentialId,
    credentialVersion: attempt.credentialVersion,
    grantId: attempt.grantId,
    grantVersion: attempt.grantVersion,
    leaseId: attempt.leaseId,
    jobId: attempt.jobId,
    jobClass: attempt.jobClass,
    operation: attempt.operation,
    serverClock: "postgresql",
    serverReceivedAt: "2026-08-26T12:07:00.000Z",
    serverCheckedAt: "2026-08-26T12:07:01.000Z",
    serverCompletedAt: "2026-08-26T12:07:02.000Z",
    durability: "postgresql_committed",
    providerStatus: 200,
    outcome: "reconciled_absent",
    providerDraftId: null,
    providerThreadId: null,
    ...overrides,
  };
  return Object.freeze({ ...base, signature: signPayload(base, keys.privateKey) });
};

test("provider payload and effect remain stable across three authorization renewals", () => {
  const first = createDraftProposal(proposalInput());
  const renewals = [
    { leaseId: "lease_renewal_01", leaseNonce: nonce(11), leaseExpiresAt: "2026-08-26T12:07:00.000Z" },
    { grantId: "grant_renewal_01", grantVersion: 4, leaseId: "lease_renewal_02", leaseNonce: nonce(12) },
    { credentialId: "credential_0002", credentialVersion: 8, leaseId: "lease_renewal_03", leaseNonce: nonce(13) },
  ];
  for (const [index, renewal] of renewals.entries()) {
    const changed = createDraftProposal(
      proposalInput({
        proposalId: `proposal_renewal_${index}`,
        revision: index + 2,
        binding: { ...binding, ...renewal },
        createdAt: "2026-08-26T12:02:01.000Z",
        expiresAt: "2026-08-26T12:05:01.000Z",
      }),
    );
    assert.equal(changed.payloadHash, first.payloadHash);
    assert.equal(changed.effectKey, first.effectKey);
    assert.notEqual(changed.authorizationHash, first.authorizationHash);
  }
  const changedCitationAuthorization = createDraftProposal(
    proposalInput({
      citations: [citation({ credentialId: "credential_0099", credentialVersion: 99, grantVersion: 99 })],
    }),
  );
  assert.equal(changedCitationAuthorization.payloadHash, first.payloadHash);
  assert.equal(changedCitationAuthorization.effectKey, first.effectKey);
  assert.notEqual(changedCitationAuthorization.authorizationHash, first.authorizationHash);
});

test("domain-separated provider identity changes for business, content, recipient, and evidence mutations", () => {
  const first = createDraftProposal(proposalInput());
  const variants = [
    { businessKey: "board-followup-2026q4" },
    { subject: "Changed subject" },
    { bodyText: "Changed body" },
    { recipients: { to: ["other@example.com"], cc: [], bcc: [] } },
    { citations: [citation({ evidenceHash: "4".repeat(64) })] },
  ];
  for (const variant of variants) {
    const changed = createDraftProposal(proposalInput(variant));
    assert.notEqual(changed.payloadHash, first.payloadHash);
    assert.notEqual(changed.effectKey, first.effectKey);
  }
  const otherAccount = createDraftProposal(
    proposalInput({
      binding: { ...binding, mailbox: "other@example.com", providerAccountSubject: "google-subject-0002" },
      citations: [citation({ mailbox: "other@example.com", providerAccountSubject: "google-subject-0002" })],
    }),
  );
  assert.notEqual(otherAccount.effectKey, first.effectKey);
});

test("draft citations reject three independent cross-account lineage mutations", () => {
  for (const mutation of [
    { mailbox: "other@example.com" },
    { providerAccountSubject: "google-subject-0002" },
    { qmPrincipalId: "person:principal-0002" },
    { deploymentId: "deployment:other-0001" },
  ]) {
    assert.throws(
      () => createDraftProposal(proposalInput({ citations: [citation(mutation)] })),
      code("draft_citation_account_mismatch"),
    );
  }
});

test("draft proposal rejects transport controls, ambiguous recipients, and changed hashes", () => {
  for (const [field, value] of [
    ["accessToken", "secret"],
    ["headers", { authorization: "Bearer secret" }],
    ["url", "https://gmail.googleapis.com/"],
    ["method", "POST"],
    ["raw", "RFC 2822"],
  ]) {
    assert.throws(() => createDraftProposal({ ...proposalInput(), [field]: value }), code("record_shape_invalid"));
  }
  for (const recipients of [
    { to: ["board@example.com"], cc: ["board@example.com"], bcc: [] },
    { to: [], cc: ["board@example.com"], bcc: [] },
    { to: ["Board@example.com"], cc: [], bcc: [] },
  ]) {
    assert.throws(
      () => createDraftProposal(proposalInput({ recipients })),
      (error) => error instanceof GoogleBrokerContractError,
    );
  }
  const proposal = createDraftProposal(proposalInput());
  for (const mutation of [
    { payloadHash: "0".repeat(64) },
    { effectKey: "0".repeat(64) },
    { authorizationHash: "0".repeat(64) },
  ]) {
    assert.throws(
      () => validateDraftProposal({ ...proposal, ...mutation }),
      (error) => error instanceof GoogleBrokerContractError,
    );
  }
});

test("signed outcome_unknown attempt binds complete authorization and permits late completion", () => {
  const keys = makeKeys();
  const proposal = createDraftProposal(proposalInput());
  const receipt = makeAttemptReceipt({
    proposal,
    keys,
    overrides: { serverCompletedAt: "2026-08-26T12:06:30.000Z" },
  });
  const prior = inspectAttempt({ proposal, keys, receipt });
  assert.equal(prior.receipt.outcome, "outcome_unknown");
  assert.equal(prior.receiptHash, sha256(prior.receipt));
  assert.equal(prior.receipt.effectKey, proposal.effectKey);
});

test("attempt receipt rejects three independent signature or authorization mutations", () => {
  const keys = makeKeys();
  const proposal = createDraftProposal(proposalInput());
  const receipt = makeAttemptReceipt({ proposal, keys });
  const variants = [
    { ...receipt, signature: `${receipt.signature[0] === "A" ? "B" : "A"}${receipt.signature.slice(1)}` },
    makeAttemptReceipt({ proposal, keys, overrides: { mailbox: "other@example.com" } }),
    makeAttemptReceipt({ proposal, keys, overrides: { authorizationHash: "0".repeat(64) } }),
    makeAttemptReceipt({ proposal, keys, overrides: { leaseNonce: nonce(14) } }),
  ];
  const expected = [
    "signature_invalid",
    "draft_attempt_binding_mismatch",
    "draft_attempt_proposal_mismatch",
    "draft_attempt_binding_mismatch",
  ];
  variants.forEach((variant, index) => {
    assert.throws(() => inspectAttempt({ proposal, keys, receipt: variant }), code(expected[index]));
  });
});

test("attempt receive time rejects before-created, at-expiry, and after-lease variants", () => {
  const keys = makeKeys();
  const proposal = createDraftProposal(proposalInput());
  for (const serverReceivedAt of ["2026-08-26T12:01:59.999Z", proposal.expiresAt, binding.leaseExpiresAt]) {
    const receipt = makeAttemptReceipt({
      proposal,
      keys,
      overrides: { serverReceivedAt, serverCompletedAt: "2026-08-26T12:07:00.000Z" },
    });
    assert.throws(() => inspectAttempt({ proposal, keys, receipt }), code("draft_attempt_time_invalid"));
  }
});

test("reconciliation binds complete prior receipt and ordered DB times after expired lease", () => {
  const keys = makeKeys();
  const proposal = createDraftProposal(proposalInput());
  const attemptReceipt = makeAttemptReceipt({
    proposal,
    keys,
    overrides: { serverCompletedAt: "2026-08-26T12:06:30.000Z" },
  });
  const prior = inspectAttempt({ proposal, keys, receipt: attemptReceipt });
  const receipt = makeReconciliationReceipt({ prior, keys });
  const reconciliation = createDraftReconciliationInspector({ keyId: keys.keyId, publicKey: keys.publicKey }).inspect({
    prior,
    receipt,
  });
  assert.equal(reconciliation.receipt.durability, "postgresql_committed");
  assert.deepEqual(
    {
      mayRequestNewAuthorization: evaluateDraftRetry({ prior, reconciliation }).mayRequestNewAuthorization,
      authorizationRequired: evaluateDraftRetry({ prior, reconciliation }).authorizationRequired,
      usableAsExecutionAuthority: evaluateDraftRetry({ prior, reconciliation }).usableAsExecutionAuthority,
    },
    { mayRequestNewAuthorization: true, authorizationRequired: true, usableAsExecutionAuthority: false },
  );
});

test("reconciliation rejects prior hash, effect, payload, and account substitutions", () => {
  const keys = makeKeys();
  const proposal = createDraftProposal(proposalInput());
  const prior = inspectAttempt({ proposal, keys });
  for (const mutation of [
    { priorReceiptHash: "0".repeat(64) },
    { effectKey: "0".repeat(64) },
    { payloadHash: "0".repeat(64) },
    { mailbox: "other@example.com" },
  ]) {
    const receipt = makeReconciliationReceipt({ prior, keys, overrides: mutation });
    assert.throws(
      () =>
        createDraftReconciliationInspector({ keyId: keys.keyId, publicKey: keys.publicKey }).inspect({
          prior,
          receipt,
        }),
      code("draft_reconciliation_prior_mismatch"),
    );
  }
});

test("reconciliation rejects two same-key-id public-key substitutions", () => {
  const attemptKeys = makeKeys();
  const proposal = createDraftProposal(proposalInput());
  const prior = inspectAttempt({ proposal, keys: attemptKeys });
  for (let index = 0; index < 2; index += 1) {
    const substitute = makeKeys();
    const receipt = makeReconciliationReceipt({ prior, keys: substitute });
    assert.throws(
      () =>
        createDraftReconciliationInspector({ keyId: substitute.keyId, publicKey: substitute.publicKey }).inspect({
          prior,
          receipt,
        }),
      code("draft_reconciliation_pin_mismatch"),
    );
  }
});

test("reconciliation rejects three DB ordering and durability failures", () => {
  const keys = makeKeys();
  const proposal = createDraftProposal(proposalInput());
  const prior = inspectAttempt({ proposal, keys });
  const variants = [
    { serverReceivedAt: "2026-08-26T12:02:01.999Z" },
    { serverReceivedAt: "2026-08-26T12:05:59.999Z" },
    { serverReceivedAt: "2026-08-26T12:07:00.000Z", serverCheckedAt: "2026-08-26T12:06:59.999Z" },
    { serverCheckedAt: "2026-08-26T12:07:02.000Z", serverCompletedAt: "2026-08-26T12:07:01.999Z" },
    { durability: "memory" },
  ];
  for (const overrides of variants) {
    const receipt = makeReconciliationReceipt({ prior, keys, overrides });
    assert.throws(
      () =>
        createDraftReconciliationInspector({ keyId: keys.keyId, publicKey: keys.publicKey }).inspect({
          prior,
          receipt,
        }),
      (error) => error instanceof GoogleBrokerContractError,
    );
  }
});

test("retry requires branded unknown plus durable absence and rejects three substitutes", () => {
  const keys = makeKeys();
  const proposal = createDraftProposal(proposalInput());
  const prior = inspectAttempt({ proposal, keys });
  const absentReceipt = makeReconciliationReceipt({ prior, keys });
  const absent = createDraftReconciliationInspector({ keyId: keys.keyId, publicKey: keys.publicKey }).inspect({
    prior,
    receipt: absentReceipt,
  });
  assert.equal(evaluateDraftRetry({ prior, reconciliation: absent }).mayRequestNewAuthorization, true);

  const foundReceipt = makeReconciliationReceipt({
    prior,
    keys,
    overrides: {
      outcome: "reconciled_succeeded",
      providerDraftId: "provider_draft_0001",
      providerThreadId: "provider_thread_0001",
    },
  });
  const found = createDraftReconciliationInspector({ keyId: keys.keyId, publicKey: keys.publicKey }).inspect({
    prior,
    receipt: foundReceipt,
  });
  assert.equal(evaluateDraftRetry({ prior, reconciliation: found }).mayRequestNewAuthorization, false);
  assert.throws(
    () => evaluateDraftRetry({ prior: { ...prior }, reconciliation: absent }),
    code("signed_outcome_unknown_required"),
  );
  assert.throws(
    () => evaluateDraftRetry({ prior, reconciliation: { ...absent } }),
    code("signed_durable_reconciliation_required"),
  );
  const succeededReceipt = makeAttemptReceipt({
    proposal,
    keys,
    overrides: {
      outcome: "succeeded",
      providerStatus: 200,
      providerDraftId: "provider_draft_0001",
      providerThreadId: "provider_thread_0001",
    },
  });
  const succeeded = inspectAttempt({ proposal, keys, receipt: succeededReceipt });
  assert.throws(
    () => evaluateDraftRetry({ prior: succeeded, reconciliation: absent }),
    code("signed_outcome_unknown_required"),
  );
});
