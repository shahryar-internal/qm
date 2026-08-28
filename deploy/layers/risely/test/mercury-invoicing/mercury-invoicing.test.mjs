import assert from "node:assert/strict";
import test from "node:test";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { syntheticDeploymentProfile } from "../../canary/deployment-profiles/testing.mjs";
import { createMercuryInvoicingProgram, mercuryWorkflowArtifactMime } from "../../canary/mercury-invoicing/index.mjs";

const buildRecord = (program, overrides = {}) => {
  const projection = {
    billingRecordRef: "billing-record:acme:2026-08",
    customerRef: "mercury-customer:acme",
    customerId: "182bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e",
    customerEmail: "billing@acme.example",
    destinationAccountRef: "mercury-account:risely-operating",
    destinationAccountId: "282bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e",
    invoiceDate: "2026-08-31",
    dueDate: "2026-09-30",
    servicePeriodStartDate: "2026-08-01",
    servicePeriodEndDate: "2026-08-31",
    currencyCode: "USD",
    lineItems: [{ name: "Risely platform", quantity: 1, unitPriceCents: 250_000, salesTaxBasisPoints: null }],
    ccEmails: [],
    payerMemo: "August services",
    internalNote: null,
    poNumber: null,
    deliveryMode: "prepare_only",
    ...overrides,
  };
  return {
    ...projection,
    billingRecordSha256: program.runtimeScope.contracts.PrincipalBinding.hash(projection),
  };
};

const batchInput = (program, records, overrides = {}) => ({
  programRef: "mercury-invoicing:risely:v1",
  environment: "sandbox",
  schedule: {
    scheduleRef: "schedule:mercury:monthly",
    cadence: "monthly",
    timeZone: "America/Los_Angeles",
    localTime: "09:00",
    weeklyDay: null,
    monthlyDay: 28,
    activeFrom: "2026-08-01",
    activeUntil: "2027-07-31",
  },
  occurrenceAt: "2026-08-28T16:00:00.000Z",
  billingRecords: records,
  ...overrides,
});

test("a monthly batch is deterministic, sequential, unsent, and provider-free", () => {
  const program = createMercuryInvoicingProgram(ceoDeploymentProfile);
  const input = batchInput(program, [buildRecord(program)]);
  const first = program.buildBatch(input);
  const second = program.buildBatch(structuredClone(input));
  assert.deepEqual(first, second);
  assert.equal(first.executionOrder, "strictly_sequential");
  assert.equal(first.compiledSchedule.expression, "00 09 28 * *");
  assert.deepEqual(first.compiledSchedule.qmSchedule, {
    cron: "00 09 28 * *",
    timezone: "America/Los_Angeles",
  });
  assert.equal(first.compiledSchedule.scheduler, "qm");
  assert.equal(program.assertSchedule(first.compiledSchedule), first.compiledSchedule);
  assert.equal(first.executionAvailable, false);
  assert.equal(first.candidates[0].sendEmailOption, "DontSend");
  assert.equal(first.candidates[0].state, "prepared_unsent");
  assert.equal(first.candidates[0].approvalRequired, false);
  assert.equal(first.candidates[0].retryAllowed, false);
  assert.equal(first.candidates[0].cliPlan.apiBaseUrl, "https://api-sandbox.mercury.com/api/v1/");
  assert.deepEqual(first.candidates[0].cliPlan.argv.slice(-2), ["invoices", "create"]);
  assert.equal(first.candidates[0].cliPlan.debugAllowed, false);
  assert.equal(first.candidates[0].cliPlan.callerBaseUrlAllowed, false);
  assert.equal(first.candidates[0].cliPlan.source.version, "0.11.8");
  assert.equal(first.candidates[0].cliPlan.environment, "sandbox");
  assert.deepEqual(first.candidates[0].cliPlan.processEnvironment, {
    requiredSecretNames: ["MERCURY_API_KEY"],
    fixedValues: { MERCURY_NO_UPDATE_CHECK: "1" },
    inheritedVariablesAllowed: false,
  });
  assert.equal(first.candidates[0].cliPlan.stdin.sendEmailOption, "DontSend");
  assert.equal(first.candidates[0].subtotalCents, 250_000);
  assert.match(first.candidates[0].invoiceNumber, /^RSLY-M-20260828-[A-F0-9]{32}$/u);
  assert.equal(program.blockers.includes("mercury_cli_adapter_unavailable"), true);
  assert.equal(program.blockers.includes("mercury_capability_not_declared"), false);
  assert.equal(program.blockers.includes("mercury_provider_owner_not_declared"), false);
  assert.equal(program.blockers.includes("mercury_provider_effect_policy_catalog_entry_unavailable"), true);
  assert.equal(program.blockers.includes("trusted_qm_schedule_fire_receipt_unavailable"), true);
  const presentation = program.presentBatch(first);
  assert.equal(presentation.actionless, true);
  assert.equal(presentation.providerExecutionAllowed, false);
  assert.equal(presentation.invoiceCount, 1);
  assert.equal(presentation.candidates[0].subtotalCents, 250_000);
  const artifact = program.presentWorkflowArtifact(first);
  assert.equal(mercuryWorkflowArtifactMime, "application/vnd.qm.workflow-artifact+json;v=1");
  assert.equal(artifact.version, 1);
  assert.equal(artifact.renderer, "qm.card.v1");
  assert.equal(artifact.payload.heading, "Mercury invoice run");
  assert.equal(artifact.payload.status.label, "Prepared without sending");
  assert.equal(artifact.payload.sections[0].items.length, 1);
  assert.match(artifact.payload.sections[0].items[0].value, /USD 2500\.00/u);
  const rendered = JSON.stringify(presentation);
  const renderedArtifact = JSON.stringify(artifact);
  assert.equal(rendered.includes("billing@acme.example"), false);
  assert.equal(rendered.includes("182bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e"), false);
  assert.equal(rendered.includes("282bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e"), false);
  assert.equal(renderedArtifact.includes("billing@acme.example"), false);
  assert.equal(renderedArtifact.includes("182bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e"), false);
  assert.equal(renderedArtifact.includes("282bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e"), false);
});

test("QM schedule contracts cover daily weekly and monthly cadences without provider authority", () => {
  const program = createMercuryInvoicingProgram(ceoDeploymentProfile);
  const monthly = batchInput(program, []).schedule;
  const daily = program.compileSchedule({
    ...monthly,
    scheduleRef: "schedule:daily",
    cadence: "daily",
    monthlyDay: null,
  });
  const weekly = program.compileSchedule({
    ...monthly,
    scheduleRef: "schedule:weekly",
    cadence: "weekly",
    weeklyDay: "FRI",
    monthlyDay: null,
  });
  const compiledMonthly = program.compileSchedule(monthly);
  assert.equal(daily.expression, "00 09 * * *");
  assert.equal(weekly.expression, "00 09 * * FRI");
  assert.equal(compiledMonthly.expression, "00 09 28 * *");
  assert.equal(daily.providerExecutionAllowed, false);
  assert.equal(weekly.triggerTarget, "risely-ceo-canary:signed-internal-ingress");
  assert.equal(Object.isFrozen(compiledMonthly), true);
});

test("send-now is bound to an expiring exact one-use approval request before create", () => {
  const program = createMercuryInvoicingProgram(ceoDeploymentProfile);
  const record = buildRecord(program, { deliveryMode: "send_after_approval" });
  const batch = program.buildBatch(batchInput(program, [record]));
  const candidate = batch.candidates[0];
  assert.equal(candidate.sendEmailOption, "SendNow");
  assert.equal(candidate.state, "approval_required_before_create");
  const approval = program.requestApproval(
    batch,
    candidate.candidateRef,
    "2026-08-28T16:01:00.000Z",
    "2026-08-28T16:31:00.000Z",
  );
  assert.equal(approval.approvalMode, "one_use_exact_invoice_create_and_send");
  assert.equal(approval.approvalBindingSha256, candidate.approvalBindingSha256);
  assert.equal(approval.executionAvailable, false);
  assert.equal(approval.authorizedApproverPrincipalRef, ceoDeploymentProfile.identity.humanPrincipalRef);
  assert.equal(approval.approvalAudienceRef, ceoDeploymentProfile.audiences.slack.audienceRef);
  assert.equal(program.assertApprovalRequest(approval), approval);
  assert.throws(
    () =>
      program.requestApproval(batch, candidate.candidateRef, "2026-08-28T16:01:00.000Z", "2026-08-30T16:01:00.000Z"),
    /approval_lifetime_exceeded/,
  );
  const unsent = program.buildBatch(batchInput(program, [buildRecord(program)]));
  assert.throws(
    () =>
      program.requestApproval(
        unsent,
        unsent.candidates[0].candidateRef,
        "2026-08-28T16:01:00.000Z",
        "2026-08-28T16:31:00.000Z",
      ),
    /approval_not_applicable/,
  );
});

test("ambiguous outcomes become reconciliation holds and never retry", () => {
  const program = createMercuryInvoicingProgram(ceoDeploymentProfile);
  const batch = program.buildBatch(batchInput(program, [buildRecord(program)]));
  const candidate = batch.candidates[0];
  const unknown = program.holdUnknownOutcome(
    batch,
    candidate.candidateRef,
    "effect-attempt:mercury:1",
    "2026-08-28T16:02:00.000Z",
  );
  assert.equal(unknown.state, "outcome_unknown");
  assert.equal(unknown.retryAllowed, false);
  assert.equal(unknown.reconciliationMethod, "list_and_match_exact_invoice_number");
  assert.equal(program.assertOutcomeHold(unknown), unknown);
  const known = program.holdUnknownOutcome(
    batch,
    candidate.candidateRef,
    "effect-attempt:mercury:2",
    "2026-08-28T16:03:00.000Z",
    "mercury-invoice:provider-1",
  );
  assert.equal(known.reconciliationMethod, "get_exact_invoice_id");
});

test("ordering is canonical and deployment profiles cannot share invoice identity", () => {
  const ceo = createMercuryInvoicingProgram(ceoDeploymentProfile);
  const firstRecord = buildRecord(ceo, { billingRecordRef: "billing-record:zeta", customerRef: "customer:zeta" });
  const secondRecord = buildRecord(ceo, {
    billingRecordRef: "billing-record:alpha",
    customerRef: "customer:alpha",
    customerId: "382bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e",
    customerEmail: "billing@alpha.example",
  });
  const forward = ceo.buildBatch(batchInput(ceo, [firstRecord, secondRecord]));
  const reverse = ceo.buildBatch(batchInput(ceo, [secondRecord, firstRecord]));
  assert.equal(forward.batchSha256, reverse.batchSha256);
  assert.deepEqual(
    forward.candidates.map((entry) => entry.billingRecordRef),
    ["billing-record:alpha", "billing-record:zeta"],
  );
  const synthetic = createMercuryInvoicingProgram(syntheticDeploymentProfile);
  const syntheticRecord = buildRecord(synthetic);
  const syntheticBatch = synthetic.buildBatch(batchInput(synthetic, [syntheticRecord]));
  assert.notEqual(forward.profileSha256, syntheticBatch.profileSha256);
  assert.notEqual(forward.candidates[0].candidateRef, syntheticBatch.candidates[0].candidateRef);
  assert.throws(() => ceo.assertBatch(syntheticBatch), /untrusted_batch/);
  assert.throws(() => ceo.assertSchedule(syntheticBatch.compiledSchedule), /untrusted_schedule/);
  const syntheticSendBatch = synthetic.buildBatch(
    batchInput(synthetic, [buildRecord(synthetic, { deliveryMode: "send_after_approval" })]),
  );
  const syntheticApproval = synthetic.requestApproval(
    syntheticSendBatch,
    syntheticSendBatch.candidates[0].candidateRef,
    "2026-08-28T16:01:00.000Z",
    "2026-08-28T16:31:00.000Z",
  );
  const syntheticHold = synthetic.holdUnknownOutcome(
    syntheticBatch,
    syntheticBatch.candidates[0].candidateRef,
    "effect-attempt:mercury:synthetic",
    "2026-08-28T16:02:00.000Z",
  );
  assert.throws(() => ceo.assertApprovalRequest(syntheticApproval), /untrusted_approval_request/);
  assert.throws(() => ceo.assertOutcomeHold(syntheticHold), /untrusted_outcome_hold/);
});

test("candidate, approval, and invoice identities cannot cross sandbox and production", () => {
  const program = createMercuryInvoicingProgram(ceoDeploymentProfile);
  const record = buildRecord(program, { deliveryMode: "send_after_approval" });
  const sandbox = program.buildBatch(batchInput(program, [record]));
  const production = program.buildBatch(batchInput(program, [record], { environment: "production" }));
  assert.notEqual(sandbox.candidates[0].candidateRef, production.candidates[0].candidateRef);
  assert.notEqual(sandbox.candidates[0].approvalBindingSha256, production.candidates[0].approvalBindingSha256);
  assert.notEqual(sandbox.candidates[0].invoiceNumber, production.candidates[0].invoiceNumber);
  assert.equal(sandbox.candidates[0].apiBaseUrl, "https://api-sandbox.mercury.com/api/v1/");
  assert.equal(production.candidates[0].apiBaseUrl, "https://api.mercury.com/api/v1/");
});

test("invalid records, duplicate customers, and dangerous schedule shapes fail closed", () => {
  const program = createMercuryInvoicingProgram(ceoDeploymentProfile);
  const record = buildRecord(program);
  assert.throws(
    () => program.buildBatch(batchInput(program, [{ ...record, billingRecordSha256: "0".repeat(64) }])),
    /invalid_billing_record_hash_0/,
  );
  const duplicate = buildRecord(program, { billingRecordRef: "billing-record:duplicate" });
  assert.throws(() => program.buildBatch(batchInput(program, [record, duplicate])), /duplicate_customer_in_batch/);
  assert.throws(
    () =>
      program.buildBatch(
        batchInput(program, [record], {
          schedule: {
            ...batchInput(program, [record]).schedule,
            cadence: "weekly",
            weeklyDay: null,
            monthlyDay: null,
          },
        }),
      ),
    /invalid_weekly_day/,
  );
  assert.throws(
    () => program.buildBatch({ ...batchInput(program, [record]), baseUrl: "https://evil.example" }),
    /invalid_batch_input/,
  );
  assert.throws(
    () =>
      program.buildBatch(
        batchInput(program, [record], {
          occurrenceAt: "2026-08-28T17:00:00.000Z",
        }),
      ),
    /occurrence_time_mismatch/,
  );
  assert.throws(
    () =>
      program.buildBatch(
        batchInput(program, [record], {
          schedule: { ...batchInput(program, [record]).schedule, timeZone: "US/Pacific" },
        }),
      ),
    /invalid_time_zone/,
  );
  assert.deepEqual(program.prohibitedOperations, [
    "cards",
    "customers.create",
    "customers.delete",
    "customers.update",
    "invoices.cancel",
    "invoices.update",
    "payments",
    "recipients",
    "transfers",
  ]);
});

test("accessors, proxies, symbols, and forged branded objects are rejected without invocation", () => {
  const program = createMercuryInvoicingProgram(ceoDeploymentProfile);
  const record = buildRecord(program);
  let getterCalls = 0;
  const accessor = batchInput(program, [record]);
  Object.defineProperty(accessor, "environment", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "sandbox";
    },
  });
  assert.throws(() => program.buildBatch(accessor), /invalid_object_descriptor/);
  assert.equal(getterCalls, 0);
  let traps = 0;
  const proxied = new Proxy(batchInput(program, [record]), {
    getPrototypeOf() {
      traps += 1;
      return Object.prototype;
    },
  });
  assert.throws(() => program.buildBatch(proxied));
  assert.equal(traps, 0);
  const symbol = batchInput(program, [record]);
  symbol[Symbol("extra")] = true;
  assert.throws(() => program.buildBatch(symbol), /invalid_object_key/);
  assert.throws(() => program.assertBatch({}), /untrusted_batch/);
  assert.throws(() => program.assertSchedule({}), /untrusted_schedule/);
  assert.throws(() => program.assertApprovalRequest({}), /untrusted_approval_request/);
  assert.throws(() => program.assertOutcomeHold({}), /untrusted_outcome_hold/);
});
