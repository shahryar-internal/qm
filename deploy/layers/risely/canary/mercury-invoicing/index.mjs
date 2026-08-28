import { createRuntimeScope } from "../runtime-scope/index.mjs";
import { date, email, exact, fail, identifier, instant, snapshotPlainJson, text } from "./validation.mjs";

export const mercuryWorkflowArtifactMime = "application/vnd.qm.workflow-artifact+json;v=1";
const cadences = Object.freeze(["daily", "weekly", "monthly"]);
const deliveryModes = Object.freeze(["prepare_only", "send_after_approval"]);
const weeklyDays = Object.freeze(["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]);
const mercuryCliSource = Object.freeze({
  repository: "https://github.com/MercuryTechnologies/mercury-cli",
  commit: "25cc254e78eddfbbd4f13cfc90a0beca930a2c0e",
  version: "0.11.8",
  releaseTag: "v0.11.8",
  releasePublishedAt: "2026-08-12T04:44:24Z",
  checksumsAssetSha256: "6ca71e169384a60c2838d562ab0fe4d797e12bec9fe50f2340e541caf7a16991",
  linuxAmd64Archive: Object.freeze({
    name: "mercury_0.11.8_linux_amd64.tar.gz",
    sha256: "f39c3426edaf2750c04366d87c43c846fd50dd258056633fb2dbe633dc336a9c",
    binarySha256: "3bb3a39a3676376998ea3a48034b7a636c5c31d7b7d08dca4c26cebd64520b8b",
    format: "elf_x86_64_static_stripped",
  }),
  executable: "mercury",
});
const mercuryHosts = Object.freeze({
  sandbox: "https://api-sandbox.mercury.com/api/v1/",
  production: "https://api.mercury.com/api/v1/",
});
const prohibitedOperations = Object.freeze([
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

const freeze = (scope, value) => scope.contracts.PrincipalBinding.freeze(value);
const hash = (scope, value) => scope.contracts.PrincipalBinding.hash(value);
const compare = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

const validateSchedule = (value) => {
  const schedule = exact(
    value,
    ["scheduleRef", "cadence", "timeZone", "localTime", "weeklyDay", "monthlyDay", "activeFrom", "activeUntil"],
    "invalid_schedule",
  );
  identifier(schedule.scheduleRef, "invalid_schedule_ref");
  if (!cadences.includes(schedule.cadence)) fail("invalid_cadence");
  text(schedule.timeZone, "invalid_time_zone", 64);
  let canonicalTimeZone;
  try {
    canonicalTimeZone = new Intl.DateTimeFormat("en-US", { timeZone: schedule.timeZone }).resolvedOptions().timeZone;
  } catch {
    fail("invalid_time_zone");
  }
  if (canonicalTimeZone !== schedule.timeZone) fail("invalid_time_zone");
  if (!/^(?:[01]\d|2[0-3]):[0-5]\d$/u.test(schedule.localTime)) fail("invalid_local_time");
  if (schedule.cadence === "weekly") {
    if (!weeklyDays.includes(schedule.weeklyDay)) fail("invalid_weekly_day");
  } else if (schedule.weeklyDay !== null) fail("unexpected_weekly_day");
  if (schedule.cadence === "monthly") {
    if (!Number.isSafeInteger(schedule.monthlyDay) || schedule.monthlyDay < 1 || schedule.monthlyDay > 28)
      fail("invalid_monthly_day");
  } else if (schedule.monthlyDay !== null) fail("unexpected_monthly_day");
  date(schedule.activeFrom, "invalid_active_from");
  date(schedule.activeUntil, "invalid_active_until");
  if (schedule.activeUntil < schedule.activeFrom) fail("invalid_schedule_interval");
  return schedule;
};

const localOccurrence = (schedule, occurrenceAt) => {
  const parsed = Date.parse(occurrenceAt);
  if (parsed % 60_000 !== 0) fail("occurrence_not_on_scheduled_minute");
  const formatter = new Intl.DateTimeFormat("en-CA", {
    timeZone: schedule.timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  });
  const partsAt = (instantMs) =>
    Object.fromEntries(
      formatter
        .formatToParts(new Date(instantMs))
        .filter((part) => part.type !== "literal")
        .map((part) => [part.type, part.value]),
    );
  const values = partsAt(parsed);
  const localDate = `${values.year}-${values.month}-${values.day}`;
  const localTime = `${values.hour}:${values.minute}`;
  const localMinute = `${localDate}T${localTime}`;
  for (let deltaMinutes = -1_800; deltaMinutes <= 1_800; deltaMinutes += 1) {
    if (deltaMinutes === 0) continue;
    const alternate = partsAt(parsed + deltaMinutes * 60_000);
    if (`${alternate.year}-${alternate.month}-${alternate.day}T${alternate.hour}:${alternate.minute}` === localMinute) {
      fail("occurrence_time_ambiguous");
    }
  }
  const weeklyDay = values.weekday.toUpperCase();
  if (localTime !== schedule.localTime) fail("occurrence_time_mismatch");
  if (schedule.cadence === "weekly" && weeklyDay !== schedule.weeklyDay) fail("occurrence_weekday_mismatch");
  if (schedule.cadence === "monthly" && Number(values.day) !== schedule.monthlyDay)
    fail("occurrence_monthly_day_mismatch");
  if (localDate < schedule.activeFrom || localDate > schedule.activeUntil) fail("occurrence_outside_schedule");
  return Object.freeze({ localDate, localTime, weeklyDay });
};

const validateLineItem = (value, index) => {
  const item = exact(
    value,
    ["name", "quantity", "unitPriceCents", "salesTaxBasisPoints"],
    `invalid_line_item_${index}`,
  );
  text(item.name, `invalid_line_item_name_${index}`, 512);
  if (!Number.isSafeInteger(item.quantity) || item.quantity < 1 || item.quantity > 100_000)
    fail(`invalid_line_item_quantity_${index}`);
  if (!Number.isSafeInteger(item.unitPriceCents) || item.unitPriceCents < 1 || item.unitPriceCents > 100_000_000)
    fail(`invalid_line_item_price_${index}`);
  if (
    item.salesTaxBasisPoints !== null &&
    (!Number.isSafeInteger(item.salesTaxBasisPoints) ||
      item.salesTaxBasisPoints < 0 ||
      item.salesTaxBasisPoints > 10_000)
  ) {
    fail(`invalid_line_item_tax_${index}`);
  }
  return item;
};

const validateBillingRecord = (scope, value, index) => {
  const record = exact(
    value,
    [
      "billingRecordRef",
      "billingRecordSha256",
      "customerRef",
      "customerId",
      "customerEmail",
      "destinationAccountRef",
      "destinationAccountId",
      "invoiceDate",
      "dueDate",
      "servicePeriodStartDate",
      "servicePeriodEndDate",
      "currencyCode",
      "lineItems",
      "ccEmails",
      "payerMemo",
      "internalNote",
      "poNumber",
      "deliveryMode",
    ],
    `invalid_billing_record_${index}`,
  );
  identifier(record.billingRecordRef, `invalid_billing_record_ref_${index}`);
  identifier(record.customerRef, `invalid_customer_ref_${index}`);
  identifier(record.customerId, `invalid_customer_id_${index}`);
  email(record.customerEmail, `invalid_customer_email_${index}`);
  identifier(record.destinationAccountRef, `invalid_destination_account_ref_${index}`);
  identifier(record.destinationAccountId, `invalid_destination_account_id_${index}`);
  date(record.invoiceDate, `invalid_invoice_date_${index}`);
  date(record.dueDate, `invalid_due_date_${index}`);
  if (record.dueDate < record.invoiceDate) fail(`invalid_due_date_${index}`);
  date(record.servicePeriodStartDate, `invalid_service_period_start_${index}`);
  date(record.servicePeriodEndDate, `invalid_service_period_end_${index}`);
  if (record.servicePeriodEndDate < record.servicePeriodStartDate) fail(`invalid_service_period_${index}`);
  if (record.currencyCode !== "USD") fail(`unsupported_currency_${index}`);
  if (!Array.isArray(record.lineItems) || record.lineItems.length < 1 || record.lineItems.length > 100)
    fail(`invalid_line_items_${index}`);
  record.lineItems.forEach((item, itemIndex) => validateLineItem(item, `${index}_${itemIndex}`));
  if (
    !Array.isArray(record.ccEmails) ||
    record.ccEmails.length > 20 ||
    new Set(record.ccEmails).size !== record.ccEmails.length
  ) {
    fail(`invalid_cc_emails_${index}`);
  }
  record.ccEmails.forEach((entry) => email(entry, `invalid_cc_email_${index}`));
  for (const [field, maximum] of [
    ["payerMemo", 1_024],
    ["internalNote", 2_048],
    ["poNumber", 255],
  ]) {
    if (record[field] !== null) text(record[field], `invalid_${field}_${index}`, maximum);
  }
  if (!deliveryModes.includes(record.deliveryMode)) fail(`invalid_delivery_mode_${index}`);
  const projection = { ...record };
  delete projection.billingRecordSha256;
  if (record.billingRecordSha256 !== hash(scope, projection)) fail(`invalid_billing_record_hash_${index}`);
  return record;
};

const invoiceNumberFor = (scope, schedule, occurrenceAt, localDate, record, environment, providerOwnerRef) => {
  const prefix = schedule.cadence === "daily" ? "D" : schedule.cadence === "weekly" ? "W" : "M";
  const day = localDate.replaceAll("-", "");
  return `RSLY-${prefix}-${day}-${hash(scope, {
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    scheduleRef: schedule.scheduleRef,
    cadence: schedule.cadence,
    occurrenceAt,
    billingRecordRef: record.billingRecordRef,
    billingRecordSha256: record.billingRecordSha256,
    customerRef: record.customerRef,
    destinationAccountRef: record.destinationAccountRef,
    environment,
    providerOwnerRef,
  })
    .slice(0, 32)
    .toUpperCase()}`;
};

const cliPlanFor = (scope, environment, payload) => {
  const apiBaseUrl = mercuryHosts[environment];
  const stdin = freeze(scope, payload);
  return freeze(scope, {
    contractType: "MercuryCliCreatePlan",
    contractVersion: 1,
    source: mercuryCliSource,
    environment,
    apiBaseUrl,
    argv: ["--base-url", apiBaseUrl, "--format", "json", "--format-error", "json", "invoices", "create"],
    stdin,
    stdinEncoding: "application/json",
    stdinSha256: hash(scope, stdin),
    credentialTransport: "MERCURY_API_KEY_secret_environment_only",
    processEnvironment: {
      requiredSecretNames: ["MERCURY_API_KEY"],
      fixedValues: { MERCURY_NO_UPDATE_CHECK: "1" },
      inheritedVariablesAllowed: false,
    },
    updateCheckDisabled: true,
    debugAllowed: false,
    callerBaseUrlAllowed: false,
    oneProcessPerInvoice: true,
  });
};

const candidateFor = (
  scope,
  environment,
  schedule,
  occurrenceAt,
  localOccurrence,
  record,
  sequence,
  providerOwnerRef,
) => {
  const invoiceNumber = invoiceNumberFor(
    scope,
    schedule,
    occurrenceAt,
    localOccurrence.localDate,
    record,
    environment,
    providerOwnerRef,
  );
  const sendEmailOption = record.deliveryMode === "prepare_only" ? "DontSend" : "SendNow";
  const subtotalCents = record.lineItems.reduce((sum, item) => sum + item.quantity * item.unitPriceCents, 0);
  if (!Number.isSafeInteger(subtotalCents)) fail("invoice_subtotal_out_of_range");
  const payload = {
    achDebitEnabled: false,
    ccEmails: record.ccEmails,
    creditCardEnabled: false,
    customerId: record.customerId,
    destinationAccountId: record.destinationAccountId,
    dueDate: record.dueDate,
    invoiceDate: record.invoiceDate,
    invoiceNumber,
    lineItems: record.lineItems.map((item) => ({
      name: item.name,
      quantity: item.quantity,
      unitPrice: item.unitPriceCents / 100,
      salesTaxRate: item.salesTaxBasisPoints === null ? null : item.salesTaxBasisPoints / 100,
    })),
    useRealAccountNumber: false,
    currencyCode: record.currencyCode,
    internalNote: record.internalNote,
    payerMemo: record.payerMemo,
    poNumber: record.poNumber,
    sendEmailOption,
    servicePeriodStartDate: record.servicePeriodStartDate,
    servicePeriodEndDate: record.servicePeriodEndDate,
  };
  const cliPlan = cliPlanFor(scope, environment, payload);
  const candidateProjection = {
    contractType: "MercuryInvoiceCandidate",
    contractVersion: 1,
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    environment,
    apiBaseUrl: mercuryHosts[environment],
    providerOwnerRef,
    sequence,
    scheduleRef: schedule.scheduleRef,
    occurrenceAt,
    localOccurrence,
    billingRecordRef: record.billingRecordRef,
    billingRecordSha256: record.billingRecordSha256,
    customerRef: record.customerRef,
    destinationAccountRef: record.destinationAccountRef,
    invoiceNumber,
    dueDate: record.dueDate,
    currencyCode: record.currencyCode,
    subtotalCents,
    deliveryMode: record.deliveryMode,
    sendEmailOption,
    approvalRequired: record.deliveryMode === "send_after_approval",
    invoicePayloadSha256: hash(scope, payload),
    cliSourceCommit: mercuryCliSource.commit,
    cliReleaseArtifactSha256: mercuryCliSource.linuxAmd64Archive.sha256,
    cliPlanSha256: hash(scope, cliPlan),
  };
  const candidateSha256 = hash(scope, candidateProjection);
  const candidateRef = `mercury-invoice-candidate:${candidateSha256}`;
  const approvalBindingSha256 = hash(scope, {
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    candidateRef,
    candidateSha256,
    invoiceNumber,
    deliveryMode: record.deliveryMode,
    sendEmailOption,
    invoicePayloadSha256: candidateProjection.invoicePayloadSha256,
    environment,
    apiBaseUrl: mercuryHosts[environment],
    providerOwnerRef,
  });
  return freeze(scope, {
    ...candidateProjection,
    candidateRef,
    candidateSha256,
    approvalBindingSha256,
    cliPlan,
    state: record.deliveryMode === "prepare_only" ? "prepared_unsent" : "approval_required_before_create",
    retryAllowed: false,
    providerExecutionAllowed: false,
  });
};

export const createMercuryInvoicingProgram = (profile) => {
  const scope = createRuntimeScope(profile);
  const builtBatches = new WeakSet();
  const batchScopes = new WeakMap();
  const compiledSchedules = new WeakSet();
  const approvalRequests = new WeakSet();
  const outcomeHolds = new WeakSet();
  const authority = scope.profile;
  const requiredCapability = "mercury.invoices.create";
  const providerOwner = authority.providerOwners.find((entry) => entry.provider === "mercury") ?? null;
  const profileCapabilityDeclared = authority.allowedCapabilities.includes(requiredCapability);
  const blockers = Object.freeze(
    [
      ...(profileCapabilityDeclared ? [] : ["mercury_capability_not_declared"]),
      ...(providerOwner ? [] : ["mercury_provider_owner_not_declared"]),
      "mercury_provider_effect_policy_catalog_entry_unavailable",
      "trusted_qm_schedule_fire_receipt_unavailable",
      "qm_schedule_active_until_disable_transition_unavailable",
      "trusted_billing_record_receipt_unavailable",
      "mercury_organization_identity_receipt_unavailable",
      "mercury_customer_identity_receipt_unavailable",
      "mercury_destination_account_receipt_unavailable",
      "durable_one_use_approval_unavailable",
      "durable_effect_reservation_unavailable",
      "mercury_cli_adapter_unavailable",
      "mercury_reconciliation_receipt_unavailable",
    ].sort(compare),
  );

  const compileSchedule = (raw) => {
    const schedule = validateSchedule(snapshotPlainJson(raw));
    const [hour, minute] = schedule.localTime.split(":");
    const expression =
      schedule.cadence === "daily"
        ? `${minute} ${hour} * * *`
        : schedule.cadence === "weekly"
          ? `${minute} ${hour} * * ${schedule.weeklyDay}`
          : `${minute} ${hour} ${schedule.monthlyDay} * *`;
    const projection = {
      contractType: "MercuryQmSchedule",
      contractVersion: 1,
      profileRef: scope.profileRef,
      profileSha256: scope.profileSha256,
      schedule,
      scheduler: "qm",
      expression,
      qmSchedule: Object.freeze({ cron: expression, timezone: schedule.timeZone }),
      scheduleTimeZone: schedule.timeZone,
      activeFrom: schedule.activeFrom,
      activeUntil: schedule.activeUntil,
      flexibleWindow: false,
      triggerTarget: "risely-ceo-canary:signed-internal-ingress",
      providerExecutionAllowed: false,
    };
    const compiled = freeze(scope, { ...projection, scheduleSha256: hash(scope, projection) });
    compiledSchedules.add(compiled);
    return compiled;
  };

  const buildBatch = (raw) => {
    const input = exact(
      snapshotPlainJson(raw),
      ["programRef", "environment", "schedule", "occurrenceAt", "billingRecords"],
      "invalid_batch_input",
    );
    identifier(input.programRef, "invalid_program_ref");
    if (!Object.hasOwn(mercuryHosts, input.environment)) fail("invalid_environment");
    const compiledSchedule = compileSchedule(input.schedule);
    const schedule = compiledSchedule.schedule;
    instant(input.occurrenceAt, "invalid_occurrence");
    const occurrence = localOccurrence(schedule, input.occurrenceAt);
    if (!Array.isArray(input.billingRecords) || input.billingRecords.length < 1 || input.billingRecords.length > 500)
      fail("invalid_billing_records");
    const records = input.billingRecords.map((record, index) => validateBillingRecord(scope, record, index));
    const sorted = records.toSorted((left, right) => compare(left.billingRecordRef, right.billingRecordRef));
    if (new Set(sorted.map((record) => record.billingRecordRef)).size !== sorted.length)
      fail("duplicate_billing_record");
    if (new Set(sorted.map((record) => record.customerRef)).size !== sorted.length) fail("duplicate_customer_in_batch");
    const candidates = freeze(
      scope,
      sorted.map((record, index) =>
        candidateFor(
          scope,
          input.environment,
          schedule,
          input.occurrenceAt,
          occurrence,
          record,
          index + 1,
          providerOwner?.providerOwnerRef ?? null,
        ),
      ),
    );
    if (new Set(candidates.map((candidate) => candidate.invoiceNumber)).size !== candidates.length)
      fail("duplicate_invoice_number");
    const projection = {
      contractType: "MercuryScheduledInvoiceBatch",
      contractVersion: 1,
      profileRef: scope.profileRef,
      profileSha256: scope.profileSha256,
      programRef: input.programRef,
      environment: input.environment,
      schedule,
      compiledSchedule,
      occurrenceAt: input.occurrenceAt,
      localOccurrence: occurrence,
      cadence: schedule.cadence,
      executionOrder: "strictly_sequential",
      candidates,
      requiredCapability,
      profileCapabilityDeclared,
      providerOwnerRef: providerOwner?.providerOwnerRef ?? null,
      providerExecutionAllowed: false,
      executionAvailable: false,
      blockers,
      prohibitedOperations,
    };
    const batch = freeze(scope, {
      ...projection,
      batchSha256: hash(scope, projection),
    });
    builtBatches.add(batch);
    batchScopes.set(batch, scope);
    return batch;
  };

  const assertBatch = (batch) => {
    if (!builtBatches.has(batch) || batchScopes.get(batch) !== scope) fail("untrusted_batch");
    return batch;
  };

  const requestApproval = (batch, candidateRef, requestedAt, expiresAt) => {
    assertBatch(batch);
    instant(requestedAt, "invalid_approval_requested_at");
    instant(expiresAt, "invalid_approval_expires_at");
    if (Date.parse(expiresAt) <= Date.parse(requestedAt)) fail("invalid_approval_interval");
    if (Date.parse(expiresAt) - Date.parse(requestedAt) > authority.grantPolicy.maximumApprovalLifetimeMs)
      fail("approval_lifetime_exceeded");
    const candidate = batch.candidates.find((entry) => entry.candidateRef === candidateRef);
    if (!candidate) fail("unknown_candidate");
    if (!candidate.approvalRequired || candidate.sendEmailOption !== "SendNow") fail("approval_not_applicable");
    const projection = {
      contractType: "MercuryInvoiceApprovalRequest",
      contractVersion: 1,
      profileRef: scope.profileRef,
      profileSha256: scope.profileSha256,
      batchSha256: batch.batchSha256,
      candidateRef: candidate.candidateRef,
      candidateSha256: candidate.candidateSha256,
      approvalBindingSha256: candidate.approvalBindingSha256,
      invoiceNumber: candidate.invoiceNumber,
      requestedAt,
      expiresAt,
      approvalMode: "one_use_exact_invoice_create_and_send",
      authorizedApproverPrincipalRef: scope.profile.identity.humanPrincipalRef,
      approvalAudienceRef: scope.profile.audiences.slack.audienceRef,
      executionAvailable: false,
    };
    const request = freeze(scope, {
      ...projection,
      approvalRequestSha256: hash(scope, projection),
    });
    approvalRequests.add(request);
    return request;
  };

  const holdUnknownOutcome = (batch, candidateRef, attemptRef, attemptedAt, providerInvoiceId = null) => {
    assertBatch(batch);
    identifier(attemptRef, "invalid_attempt_ref");
    instant(attemptedAt, "invalid_attempted_at");
    if (providerInvoiceId !== null) identifier(providerInvoiceId, "invalid_provider_invoice_id");
    const candidate = batch.candidates.find((entry) => entry.candidateRef === candidateRef);
    if (!candidate) fail("unknown_candidate");
    const projection = {
      contractType: "MercuryInvoiceOutcomeHold",
      contractVersion: 1,
      profileRef: scope.profileRef,
      profileSha256: scope.profileSha256,
      batchSha256: batch.batchSha256,
      candidateRef: candidate.candidateRef,
      candidateSha256: candidate.candidateSha256,
      invoiceNumber: candidate.invoiceNumber,
      attemptRef,
      attemptedAt,
      providerInvoiceId,
      state: "outcome_unknown",
      retryAllowed: false,
      reconciliationMethod: providerInvoiceId === null ? "list_and_match_exact_invoice_number" : "get_exact_invoice_id",
      acceptedProviderStatuses: ["Unpaid", "Processing", "Paid", "Cancelled"],
      executionAvailable: false,
    };
    const hold = freeze(scope, { ...projection, holdSha256: hash(scope, projection) });
    outcomeHolds.add(hold);
    return hold;
  };

  const presentBatch = (batch) => {
    assertBatch(batch);
    const projection = {
      contractType: "MercuryInvoiceBatchPresentation",
      contractVersion: 1,
      profileRef: scope.profileRef,
      profileSha256: scope.profileSha256,
      batchSha256: batch.batchSha256,
      audienceRef: scope.profile.audiences.slack.audienceRef,
      title: "Mercury invoice run",
      cadence: batch.cadence,
      occurrenceAt: batch.occurrenceAt,
      environment: batch.environment,
      invoiceCount: batch.candidates.length,
      approvalRequiredCount: batch.candidates.filter((candidate) => candidate.approvalRequired).length,
      candidates: batch.candidates.map((candidate) => ({
        sequence: candidate.sequence,
        candidateRef: candidate.candidateRef,
        invoiceNumber: candidate.invoiceNumber,
        dueDate: candidate.dueDate,
        currencyCode: candidate.currencyCode,
        subtotalCents: candidate.subtotalCents,
        state: candidate.state,
        approvalRequired: candidate.approvalRequired,
      })),
      actionless: true,
      providerExecutionAllowed: false,
    };
    return freeze(scope, { ...projection, presentationSha256: hash(scope, projection) });
  };

  const presentWorkflowArtifact = (batch) => {
    const presentation = presentBatch(batch);
    const visibleLimit = presentation.candidates.length > 32 ? 31 : 32;
    const hiddenCount = Math.max(0, presentation.candidates.length - visibleLimit);
    const items = presentation.candidates.slice(0, visibleLimit).map((candidate) => ({
      label: `#${candidate.sequence} · ${candidate.invoiceNumber}`,
      value: `${candidate.currencyCode} ${(candidate.subtotalCents / 100).toFixed(2)} · due ${candidate.dueDate} · ${candidate.state}`,
    }));
    if (hiddenCount > 0) {
      items.push({ value: `${hiddenCount} additional invoice candidates are available in the original artifact.` });
    }
    return freeze(scope, {
      version: 1,
      renderer: "qm.card.v1",
      fallbackText: `Mercury invoice run: ${presentation.invoiceCount} candidate${presentation.invoiceCount === 1 ? "" : "s"}; ${presentation.approvalRequiredCount} require approval.`,
      payload: {
        heading: presentation.title,
        summary: `${presentation.cadence} schedule · ${presentation.environment} · ${presentation.occurrenceAt}`,
        status: {
          label:
            presentation.approvalRequiredCount > 0
              ? `${presentation.approvalRequiredCount} awaiting approval`
              : "Prepared without sending",
          tone: presentation.approvalRequiredCount > 0 ? "warning" : "info",
        },
        sections: [
          {
            key: "invoice-candidates",
            label: "Invoice candidates",
            items,
          },
        ],
      },
    });
  };

  return Object.freeze({
    profile: authority,
    runtimeScope: scope,
    requiredCapability,
    providerOwnerRef: providerOwner?.providerOwnerRef ?? null,
    mercuryCliSource,
    mercuryHosts,
    prohibitedOperations,
    cadences,
    deliveryModes,
    weeklyDays,
    blockers,
    executionAvailable: false,
    compileSchedule,
    assertSchedule: (value) => {
      if (!compiledSchedules.has(value)) fail("untrusted_schedule");
      return value;
    },
    buildBatch,
    assertBatch,
    requestApproval,
    holdUnknownOutcome,
    presentBatch,
    presentWorkflowArtifact,
    assertApprovalRequest: (value) => {
      if (!approvalRequests.has(value)) fail("untrusted_approval_request");
      return value;
    },
    assertOutcomeHold: (value) => {
      if (!outcomeHolds.has(value)) fail("untrusted_outcome_hold");
      return value;
    },
  });
};

export { MercuryInvoicingError } from "./validation.mjs";
