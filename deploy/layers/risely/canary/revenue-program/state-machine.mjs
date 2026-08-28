import {
  assertRevenueProgramContractSuite,
  brainReadTools,
  ceoRevenueProgramContractSuite,
  proposalPresentationLabels,
  proposedEffectTypes,
  requiredEvaluationGates,
  revenueProgramPolicy,
  revenueSourceNames,
  slackActionRegistry,
} from "./contracts.mjs";
import { assertBuiltRevenueProgramForContractSuite } from "./program.mjs";
import {
  assertDate,
  assertExactKeys,
  assertHash,
  assertInstant,
  assertInteger,
  assertReference,
  assertTimeZone,
  compareCodepoints,
  dateInTimeZone,
  fail,
  sha256Canonical,
  snapshotPlainJson,
  RevenueProgramError,
} from "./validation.mjs";

export const prospectiveEvaluatorRegistry = Object.freeze({
  "evaluator:deterministic:revenue:v1": Object.freeze({
    originClass: "deterministic",
    allowedGates: requiredEvaluationGates,
  }),
  "evaluator:llm:luna:revenue:v1": Object.freeze({
    originClass: "llm",
    allowedGates: requiredEvaluationGates,
  }),
});

export const evaluationGateCriteria = Object.freeze(
  Object.fromEntries(
    requiredEvaluationGates.map((gate) => [
      gate,
      Object.freeze({
        deterministicCriterionRef: `criterion:${gate}:deterministic:v1`,
        llmCriterionRef: `criterion:${gate}:llm:v1`,
      }),
    ]),
  ),
);

export const prospectiveReconciliationContract = Object.freeze({
  statuses: Object.freeze(["outcome_unknown", "confirmed", "failed"]),
  currentWithoutAttempt: "not_attempted",
  trustedProviderReceiptRequired: true,
  mutationsAvailable: false,
});

const forbiddenInputKey = /execute|execution|enabled|(?:^|[_-])live(?:$|[_-])|provider[-_]?effect/i;
const programKeys = new Set([
  "version",
  "programRef",
  "programRevision",
  "goalDate",
  "timeZone",
  "createdAt",
  "inputHash",
  "principalBinding",
  "connectionBindings",
  "sourceHealth",
  "correlations",
  "accounting",
  "selectedCandidateRefs",
  "proposals",
  "safety",
  "programHash",
]);
const safetyKeys = new Set([
  "disposition",
  "commandCenterAccess",
  "gmailAccess",
  "linkedinAccess",
  "crmAccess",
  "notionAccess",
  "demoRepositoryAccess",
]);
const principalBindingKeys = new Set([
  "deploymentRef",
  "anchorRef",
  "tenantRef",
  "workspaceRef",
  "principalRef",
  "principalEmail",
  "credentialOwnerRef",
  "apolloAccountRef",
  "googleAccountRef",
  "notionRootRef",
  "clarifyAccountRef",
  "brainServerRef",
  "linkedinAccountRef",
  "rb2bAccountRef",
  "posthogAccountRef",
  "demoRepositoryRef",
]);
const connectionBindingKeys = new Set([
  "connectionBindingRef",
  "providerAccountRef",
  "providerOwnerRef",
  "status",
  "trustedReceiptRequired",
]);
const sourceHealthKeys = new Set(["sources", "blockers"]);
const sourceStatusKeys = new Set(["source", "status", "unavailableCode"]);
const brainStatusKeys = new Set(["source", "status", "toolStatus"]);
const brainToolStatusKeys = new Set(["tool", "status", "queryRef", "unavailableCode"]);
const accountingKeys = new Set(["email", "linkedinConnection", "inboxes"]);
const emailAccountingKeys = new Set([
  "minimum",
  "maximum",
  "activeBefore",
  "coldActiveBefore",
  "staleActiveBefore",
  "coldProposed",
  "staleProposed",
  "proposed",
  "totalAfterProposal",
  "minimumShortfall",
  "maximumRemaining",
]);
const linkedinAccountingKeys = new Set(["target", "activeBefore", "proposed", "totalAfterProposal", "targetShortfall"]);
const inboxAccountingKeys = new Set(["inboxRef", "maximum", "totalAfterProposal"]);
const proposalKeys = new Set([
  "proposalRef",
  "type",
  "subjectRef",
  "inboxRef",
  "providerAccountRef",
  "connectionBindingRef",
  "stableRecipientIdentity",
  "content",
  "contentHash",
  "evidenceHashes",
  "correlationRefs",
  "idempotencyKey",
  "effectKey",
  "binding",
  "approvalRequired",
  "approvalChannel",
  "disposition",
  "readiness",
]);
const proposalBindingKeys = new Set([
  "deploymentRef",
  "anchorRef",
  "tenantRef",
  "workspaceRef",
  "principalRef",
  "credentialOwnerRef",
]);
const correlationKeys = new Set([
  "correlationRef",
  "deploymentRef",
  "anchorRef",
  "tenantRef",
  "workspaceRef",
  "principalRef",
  "credentialOwnerRef",
  "providerAccountRef",
  "source",
  "sourceRecordRef",
  "subjectType",
  "subjectRef",
  "accountRef",
  "contactRef",
  "meetingOccurrenceRef",
  "evidenceHash",
  "factCitationRefs",
]);
const stateKeys = new Set([
  "version",
  "programRef",
  "programHash",
  "programRevision",
  "goalDate",
  "timeZone",
  "principalBinding",
  "createdAt",
  "state",
  "revision",
  "durableFenceRef",
  "commitDisposition",
  "proposals",
  "correlations",
  "connectionBindings",
  "safetyDisposition",
  "reconciliation",
  "recordHash",
]);
const reconciliationKeys = new Set(["status", "attemptRef", "receiptRef"]);
const evaluationRequestKeys = new Set(["requestRef", "expectedRevision", "expectedFenceRef", "programHash"]);
const approvalRequestKeys = new Set([
  "requestRef",
  "expectedRevision",
  "expectedFenceRef",
  "programHash",
  "proposalRef",
  "teamRef",
  "userRef",
  "audienceRef",
  "messageRef",
  "interactionRef",
  "actionId",
  "payloadHash",
]);
const transitionKeys = new Set([
  "transitionRef",
  "transitionKind",
  "baseRecordHash",
  "expectedRevision",
  "expectedFenceRef",
  "proposedRevision",
  "programHash",
  "operation",
  "cas",
  "safetyDisposition",
]);

const assertNoForbiddenControlsInner = (value) => {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const entry of value) assertNoForbiddenControlsInner(entry);
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (forbiddenInputKey.test(key)) fail("caller_execution_control_forbidden");
    assertNoForbiddenControlsInner(entry);
  }
};

const assertNoForbiddenControls = (value) => {
  try {
    assertNoForbiddenControlsInner(value);
  } catch (error) {
    if (error instanceof RevenueProgramError) throw error;
    fail("invalid_plain_json");
  }
};

const snapshotWithoutCallerControls = (value) => {
  const snapshot = snapshotPlainJson(value);
  assertNoForbiddenControls(snapshot);
  return snapshot;
};

const withoutHash = (value, key) => Object.fromEntries(Object.entries(value).filter(([entry]) => entry !== key));
const stateHash = (value) => sha256Canonical(withoutHash(value, "recordHash"));

const assertFixedPrincipalBinding = (binding, context) => {
  assertExactKeys(binding, principalBindingKeys, "invalid_principal_binding");
  for (const [key, expected] of Object.entries({
    ...context.contracts.deploymentPrincipalBindingAnchor,
    ...context.contracts.deploymentConnectionAnchors,
  })) {
    if (binding[key] !== expected) fail("untrusted_principal_binding");
  }
};

const assertConnectionBindings = (bindings, principalBinding, context) => {
  const expectedOwners = new Map([
    ...Object.entries(context.contracts.deploymentConnectionAnchors).map(([anchorKey, providerAccountRef]) => [
      providerAccountRef,
      context.contracts.deploymentConnectionOwnerRefs[anchorKey],
    ]),
    [principalBinding.workspaceRef, context.contracts.deploymentConnectionOwnerRefs.workspaceRef],
  ]);
  const expectedProviderAccounts = new Set(expectedOwners.keys());
  if (!Array.isArray(bindings) || bindings.length !== expectedProviderAccounts.size)
    fail("invalid_connection_bindings");
  const references = new Set();
  for (const binding of bindings) {
    assertExactKeys(binding, connectionBindingKeys, "invalid_connection_binding");
    const expectedRef = `connection-binding:${sha256Canonical({
      deploymentRef: principalBinding.deploymentRef,
      providerAccountRef: binding.providerAccountRef,
      providerOwnerRef: expectedOwners.get(binding.providerAccountRef),
    })}`;
    if (!expectedProviderAccounts.has(binding.providerAccountRef)) fail("caller_selected_connection_binding");
    if (
      binding.connectionBindingRef !== expectedRef ||
      binding.providerOwnerRef !== expectedOwners.get(binding.providerAccountRef) ||
      binding.status !== "unresolved" ||
      binding.trustedReceiptRequired !== true
    )
      fail("invalid_connection_binding");
    references.add(binding.connectionBindingRef);
  }
  if (references.size !== bindings.length) fail("duplicate_connection_binding");
  if (new Set(bindings.map((binding) => binding.providerAccountRef)).size !== expectedProviderAccounts.size)
    fail("missing_connection_binding");
  return references;
};

const expectedStableRecipient = (proposal) => {
  if (proposal.type.startsWith("gmail.")) return `email:${sha256Canonical(proposal.content.to)}`;
  if (proposal.type.startsWith("linkedin.")) return `linkedin:${sha256Canonical(proposal.content.linkedinProfileRef)}`;
  if (proposal.type === "notion.revenue_artifact")
    return proposal.content.artifactKind === "visitor_account_research"
      ? `account-domain:${sha256Canonical(proposal.content.accountDomain)}`
      : `artifact:${sha256Canonical(proposal.subjectRef)}`;
  return `meeting:${sha256Canonical({
    occurrenceRef: proposal.content.occurrenceRef,
    eventVersion: proposal.content.eventVersion,
    scheduleRevision: proposal.content.scheduleRevision,
  })}`;
};

const expectedProviderAccount = (proposal, binding) => {
  if (proposal.type.startsWith("gmail.")) return binding.googleAccountRef;
  if (proposal.type.startsWith("linkedin.")) return binding.linkedinAccountRef;
  if (proposal.type === "notion.revenue_artifact") return binding.notionRootRef;
  if (proposal.type === "slack.demo_reminder") return binding.workspaceRef;
  return binding.demoRepositoryRef;
};

const validateProposal = (proposal, program, connectionRefs, context) => {
  assertExactKeys(proposal, proposalKeys, "invalid_proposal");
  assertExactKeys(proposal.binding, proposalBindingKeys, "invalid_proposal");
  if (!proposedEffectTypes.includes(proposal.type) || proposalPresentationLabels[proposal.type] === undefined)
    fail("closed_effect_registry_violation");
  const stableRecipientIdentity = expectedStableRecipient(proposal);
  const providerAccountRef = expectedProviderAccount(proposal, program.principalBinding);
  const contentHash = sha256Canonical(proposal.content);
  const idempotencyKey = sha256Canonical({
    version: revenueProgramPolicy.version,
    deploymentRef: program.principalBinding.deploymentRef,
    anchorRef: program.principalBinding.anchorRef,
    tenantRef: program.principalBinding.tenantRef,
    workspaceRef: program.principalBinding.workspaceRef,
    principalRef: program.principalBinding.principalRef,
    credentialOwnerRef: program.principalBinding.credentialOwnerRef,
    providerAccountRef,
    stableRecipientIdentity,
    goalDate: program.goalDate,
    programRef: program.programRef,
    programRevision: program.programRevision,
    type: proposal.type,
    subjectRef: proposal.subjectRef,
    inboxRef: proposal.inboxRef,
    contentHash,
  });
  const effectKey = sha256Canonical({
    idempotencyKey,
    providerAccountRef,
    credentialOwnerRef: program.principalBinding.credentialOwnerRef,
    stableRecipientIdentity,
    payloadHash: contentHash,
    goalDate: program.goalDate,
    programRevision: program.programRevision,
  });
  const proposalRef = `proposal:${sha256Canonical({
    programRef: program.programRef,
    programRevision: program.programRevision,
    idempotencyKey,
    effectKey,
  })}`;
  const connectionBinding = program.connectionBindings.find((entry) => entry.providerAccountRef === providerAccountRef);
  const connectionBindingRef = `connection-binding:${sha256Canonical({
    deploymentRef: program.principalBinding.deploymentRef,
    providerAccountRef,
    providerOwnerRef: connectionBinding?.providerOwnerRef,
  })}`;
  if (
    proposal.contentHash !== contentHash ||
    proposal.idempotencyKey !== idempotencyKey ||
    proposal.effectKey !== effectKey ||
    proposal.proposalRef !== proposalRef ||
    proposal.providerAccountRef !== providerAccountRef ||
    proposal.stableRecipientIdentity !== stableRecipientIdentity ||
    proposal.connectionBindingRef !== connectionBindingRef ||
    (proposal.type.startsWith("gmail.") && proposal.content.mailboxEmail !== program.principalBinding.principalEmail) ||
    !connectionBinding ||
    !connectionRefs.has(connectionBindingRef) ||
    proposal.binding.deploymentRef !== program.principalBinding.deploymentRef ||
    proposal.binding.anchorRef !== program.principalBinding.anchorRef ||
    proposal.binding.tenantRef !== program.principalBinding.tenantRef ||
    proposal.binding.workspaceRef !== program.principalBinding.workspaceRef ||
    proposal.binding.principalRef !== program.principalBinding.principalRef ||
    proposal.binding.credentialOwnerRef !== program.principalBinding.credentialOwnerRef ||
    proposal.approvalRequired !== true ||
    proposal.approvalChannel !== "slack" ||
    proposal.disposition !== "unresolved" ||
    proposal.readiness !== "blocked_connection_binding" ||
    !Array.isArray(proposal.evidenceHashes) ||
    proposal.evidenceHashes.length < 1 ||
    !Array.isArray(proposal.correlationRefs) ||
    proposal.correlationRefs.length < 1
  )
    fail("invalid_proposal");
  for (const hash of proposal.evidenceHashes) assertHash(hash, "invalid_proposal");
  for (const reference of proposal.correlationRefs) assertReference(reference, "invalid_proposal");
  if (
    new Set(proposal.evidenceHashes).size !== proposal.evidenceHashes.length ||
    new Set(proposal.correlationRefs).size !== proposal.correlationRefs.length
  )
    fail("invalid_proposal");
};

const validateSourceHealth = (sourceHealth) => {
  assertExactKeys(sourceHealth, sourceHealthKeys, "invalid_source_health");
  if (
    !Array.isArray(sourceHealth.sources) ||
    sourceHealth.sources.length !== revenueSourceNames.length ||
    !Array.isArray(sourceHealth.blockers)
  )
    fail("invalid_source_health");
  const seenSources = new Set();
  for (const source of sourceHealth.sources) {
    if (!revenueSourceNames.includes(source.source) || seenSources.has(source.source)) fail("invalid_source_health");
    seenSources.add(source.source);
    if (source.source === "command_center_brain") {
      assertExactKeys(source, brainStatusKeys, "invalid_source_health");
      if (
        !new Set(["available", "none", "partial_or_unavailable"]).has(source.status) ||
        !Array.isArray(source.toolStatus) ||
        source.toolStatus.length !== brainReadTools.length
      )
        fail("invalid_source_health");
      const seenTools = new Set();
      const queryRefs = new Set();
      for (const tool of source.toolStatus) {
        assertExactKeys(tool, brainToolStatusKeys, "invalid_source_health");
        if (
          !brainReadTools.includes(tool.tool) ||
          seenTools.has(tool.tool) ||
          !new Set(["available", "none", "unavailable"]).has(tool.status) ||
          (tool.status === "unavailable") !== (tool.unavailableCode !== null)
        )
          fail("invalid_source_health");
        seenTools.add(tool.tool);
        const queryRef = assertReference(tool.queryRef, "invalid_source_health");
        if (queryRefs.has(queryRef)) fail("invalid_source_health");
        queryRefs.add(queryRef);
        if (tool.unavailableCode !== null) assertReference(tool.unavailableCode, "invalid_source_health");
      }
      const statuses = new Set(source.toolStatus.map((tool) => tool.status));
      const expectedStatus =
        statuses.has("unavailable") || statuses.size > 1
          ? "partial_or_unavailable"
          : statuses.has("available")
            ? "available"
            : "none";
      if (source.status !== expectedStatus) fail("invalid_source_health");
    } else {
      assertExactKeys(source, sourceStatusKeys, "invalid_source_health");
      if (
        !new Set(["available", "none", "unavailable"]).has(source.status) ||
        (source.status === "unavailable") !== (source.unavailableCode !== null)
      )
        fail("invalid_source_health");
      if (source.unavailableCode !== null) assertReference(source.unavailableCode, "invalid_source_health");
    }
  }
  const expectedBlockers = sourceHealth.sources
    .filter((source) => source.status === "unavailable" || source.status === "partial_or_unavailable")
    .map((source) => `source_unavailable:${source.source}`)
    .sort(compareCodepoints);
  const blockers = sourceHealth.blockers.map((blocker) => assertReference(blocker, "invalid_source_health"));
  if (
    blockers.length !== expectedBlockers.length ||
    blockers.some((blocker, index) => blocker !== expectedBlockers[index])
  )
    fail("invalid_source_health");
};

const validateAccounting = (accounting) => {
  assertExactKeys(accounting, accountingKeys, "invalid_accounting");
  assertExactKeys(accounting.email, emailAccountingKeys, "invalid_accounting");
  assertExactKeys(accounting.linkedinConnection, linkedinAccountingKeys, "invalid_accounting");
  if (!Array.isArray(accounting.inboxes)) fail("invalid_accounting");
  for (const key of [
    "activeBefore",
    "coldActiveBefore",
    "staleActiveBefore",
    "coldProposed",
    "staleProposed",
    "proposed",
    "totalAfterProposal",
    "minimumShortfall",
    "maximumRemaining",
  ]) {
    assertInteger(accounting.email[key], 0, revenueProgramPolicy.emailDailyMaximum, "invalid_accounting");
  }
  for (const key of ["activeBefore", "proposed", "totalAfterProposal", "targetShortfall"]) {
    assertInteger(
      accounting.linkedinConnection[key],
      0,
      revenueProgramPolicy.linkedinDailyTarget,
      "invalid_accounting",
    );
  }
  if (
    accounting.email.minimum !== revenueProgramPolicy.emailDailyMinimum ||
    accounting.email.maximum !== revenueProgramPolicy.emailDailyMaximum ||
    accounting.email.totalAfterProposal > revenueProgramPolicy.emailDailyMaximum ||
    accounting.email.activeBefore !== accounting.email.coldActiveBefore + accounting.email.staleActiveBefore ||
    accounting.email.proposed !== accounting.email.coldProposed + accounting.email.staleProposed ||
    accounting.email.totalAfterProposal !== accounting.email.activeBefore + accounting.email.proposed ||
    accounting.email.minimumShortfall !==
      Math.max(0, revenueProgramPolicy.emailDailyMinimum - accounting.email.totalAfterProposal) ||
    accounting.email.maximumRemaining !==
      revenueProgramPolicy.emailDailyMaximum - accounting.email.totalAfterProposal ||
    accounting.linkedinConnection.target !== revenueProgramPolicy.linkedinDailyTarget ||
    accounting.linkedinConnection.totalAfterProposal > revenueProgramPolicy.linkedinDailyTarget ||
    accounting.linkedinConnection.totalAfterProposal !==
      accounting.linkedinConnection.activeBefore + accounting.linkedinConnection.proposed ||
    accounting.linkedinConnection.targetShortfall !==
      revenueProgramPolicy.linkedinDailyTarget - accounting.linkedinConnection.totalAfterProposal
  )
    fail("invalid_accounting");
  const seenInboxes = new Set();
  let inboxTotal = 0;
  for (const inbox of accounting.inboxes) {
    assertExactKeys(inbox, inboxAccountingKeys, "invalid_accounting");
    if (
      inbox.maximum !== revenueProgramPolicy.inboxDailyMaximum ||
      seenInboxes.has(inbox.inboxRef) ||
      assertInteger(inbox.totalAfterProposal, 0, revenueProgramPolicy.inboxDailyMaximum, "invalid_accounting") >
        revenueProgramPolicy.inboxDailyMaximum ||
      inbox.totalAfterProposal > revenueProgramPolicy.inboxDailyMaximum
    )
      fail("invalid_accounting");
    seenInboxes.add(assertReference(inbox.inboxRef, "invalid_accounting"));
    inboxTotal += inbox.totalAfterProposal;
  }
  if (accounting.inboxes.length < 1 || accounting.inboxes.length > revenueProgramPolicy.maximumInboxes)
    fail("invalid_accounting");
  if (inboxTotal !== accounting.email.totalAfterProposal) fail("invalid_accounting");
};

const validateCorrelations = (correlations, program) => {
  if (!Array.isArray(correlations)) fail("invalid_correlations");
  const refs = new Set();
  const subjectKeys = new Set();
  for (const correlation of correlations) {
    assertExactKeys(correlation, correlationKeys, "invalid_correlation");
    if (
      correlation.deploymentRef !== program.principalBinding.deploymentRef ||
      correlation.anchorRef !== program.principalBinding.anchorRef ||
      correlation.tenantRef !== program.principalBinding.tenantRef ||
      correlation.workspaceRef !== program.principalBinding.workspaceRef ||
      correlation.principalRef !== program.principalBinding.principalRef ||
      correlation.credentialOwnerRef !== program.principalBinding.credentialOwnerRef ||
      !new Set(["candidate", "deal", "meeting", "acceptance", "artifact", "visitor_account"]).has(
        correlation.subjectType,
      )
    )
      fail("invalid_correlation");
    refs.add(assertReference(correlation.correlationRef, "invalid_correlation"));
    const subjectKey = `${correlation.subjectType}\u0000${correlation.subjectRef}\u0000${correlation.source}\u0000${correlation.sourceRecordRef}`;
    if (subjectKeys.has(subjectKey)) fail("duplicate_typed_correlation");
    subjectKeys.add(subjectKey);
    assertReference(correlation.subjectRef, "invalid_correlation");
    if (correlation.accountRef !== null) assertReference(correlation.accountRef, "invalid_correlation");
    if (correlation.contactRef !== null) assertReference(correlation.contactRef, "invalid_correlation");
    if (correlation.meetingOccurrenceRef !== null)
      assertReference(correlation.meetingOccurrenceRef, "invalid_correlation");
    const accountContactSubject = new Set(["candidate", "deal", "acceptance"]).has(correlation.subjectType);
    if (
      (accountContactSubject &&
        (correlation.accountRef === null ||
          correlation.contactRef === null ||
          correlation.meetingOccurrenceRef !== null)) ||
      (correlation.subjectType === "meeting" &&
        (correlation.accountRef === null ||
          correlation.contactRef !== null ||
          correlation.meetingOccurrenceRef === null)) ||
      (correlation.subjectType === "artifact" &&
        (correlation.accountRef !== null ||
          correlation.contactRef !== null ||
          correlation.meetingOccurrenceRef !== null)) ||
      (correlation.subjectType === "visitor_account" &&
        (correlation.accountRef === null ||
          correlation.contactRef !== null ||
          correlation.meetingOccurrenceRef !== null))
    )
      fail("invalid_correlation");
    assertReference(correlation.providerAccountRef, "invalid_correlation");
    assertReference(correlation.sourceRecordRef, "invalid_correlation");
    assertHash(correlation.evidenceHash, "invalid_correlation");
    if (
      !Array.isArray(correlation.factCitationRefs) ||
      correlation.factCitationRefs.length < 1 ||
      new Set(correlation.factCitationRefs).size !== correlation.factCitationRefs.length
    )
      fail("invalid_correlation");
    for (const citationRef of correlation.factCitationRefs) assertReference(citationRef, "invalid_correlation");
  }
  if (refs.size !== correlations.length) fail("duplicate_correlation");
  return refs;
};

const validateProgram = (program, context) => {
  assertExactKeys(program, programKeys, "invalid_program");
  assertExactKeys(program.safety, safetyKeys, "invalid_program");
  assertFixedPrincipalBinding(program.principalBinding, context);
  if (
    program.version !== revenueProgramPolicy.version ||
    program.safety.disposition !== "unresolved_proposals" ||
    program.safety.commandCenterAccess !== "read_only" ||
    program.safety.gmailAccess !== "draft_proposal_only" ||
    program.safety.linkedinAccess !== "proposal_only" ||
    program.safety.crmAccess !== "read_only" ||
    program.safety.notionAccess !== "artifact_proposal_only" ||
    program.safety.demoRepositoryAccess !== "read_only" ||
    !Array.isArray(program.proposals) ||
    program.proposals.length > revenueProgramPolicy.maximumProgramProposals ||
    !Array.isArray(program.selectedCandidateRefs)
  )
    fail("invalid_program");
  assertReference(program.programRef, "invalid_program");
  assertInteger(program.programRevision, 0, 1_000_000, "invalid_program");
  assertDate(program.goalDate, "invalid_program");
  assertTimeZone(program.timeZone, "invalid_program");
  const createdAt = assertInstant(program.createdAt, "invalid_program");
  if (dateInTimeZone(createdAt, program.timeZone) !== program.goalDate) fail("invalid_program");
  assertHash(program.inputHash, "invalid_program");
  if (program.programHash !== sha256Canonical(withoutHash(program, "programHash"))) fail("invalid_program_hash");
  const connectionRefs = assertConnectionBindings(program.connectionBindings, program.principalBinding, context);
  validateSourceHealth(program.sourceHealth);
  validateAccounting(program.accounting);
  const correlationRefs = validateCorrelations(program.correlations, program);
  const correlationEvidence = new Map(
    program.correlations.map((correlation) => [correlation.correlationRef, correlation.evidenceHash]),
  );
  for (const proposal of program.proposals) validateProposal(proposal, program, connectionRefs, context);
  for (const selectedCandidateRef of program.selectedCandidateRefs)
    assertReference(selectedCandidateRef, "invalid_program");
  const proposalCount = (type) => program.proposals.filter((proposal) => proposal.type === type).length;
  const coldSubjects = program.proposals
    .filter((proposal) => proposal.type === "gmail.cold_email_draft")
    .map((proposal) => proposal.subjectRef)
    .sort(compareCodepoints);
  const selectedSubjects = [...program.selectedCandidateRefs].sort(compareCodepoints);
  if (
    new Set(program.proposals.map((proposal) => proposal.proposalRef)).size !== program.proposals.length ||
    new Set(program.proposals.map((proposal) => proposal.idempotencyKey)).size !== program.proposals.length ||
    new Set(program.proposals.map((proposal) => proposal.effectKey)).size !== program.proposals.length ||
    program.proposals.some((proposal) =>
      proposal.correlationRefs.some((reference) => !correlationRefs.has(reference)),
    ) ||
    program.proposals.some((proposal) => {
      const citedEvidence = new Set(proposal.correlationRefs.map((reference) => correlationEvidence.get(reference)));
      return proposal.evidenceHashes.some((evidenceHash) => !citedEvidence.has(evidenceHash));
    }) ||
    new Set(program.selectedCandidateRefs).size !== program.selectedCandidateRefs.length ||
    coldSubjects.length !== selectedSubjects.length ||
    coldSubjects.some((subject, index) => subject !== selectedSubjects[index]) ||
    proposalCount("gmail.cold_email_draft") !== program.accounting.email.coldProposed ||
    proposalCount("gmail.stale_deal_followup_draft") !== program.accounting.email.staleProposed ||
    proposalCount("linkedin.connection_request") !== program.accounting.linkedinConnection.proposed
  )
    fail("invalid_program");
};

const validateState = (record, context) => {
  assertNoForbiddenControls(record);
  assertExactKeys(record, stateKeys, "invalid_state_record");
  assertExactKeys(record.reconciliation, reconciliationKeys, "invalid_state_record");
  assertFixedPrincipalBinding(record.principalBinding, context);
  if (
    record.version !== revenueProgramPolicy.version ||
    record.state !== "uncommitted_initialization" ||
    record.revision !== 0 ||
    record.durableFenceRef !== "durable-fence:unresolved" ||
    record.commitDisposition !== "uncommitted" ||
    record.safetyDisposition !== "hard_disabled" ||
    record.reconciliation.status !== "not_attempted" ||
    record.reconciliation.attemptRef !== null ||
    record.reconciliation.receiptRef !== null ||
    record.recordHash !== stateHash(record)
  )
    fail("invalid_state_record");
  assertHash(record.programHash, "invalid_state_record");
  assertInteger(record.programRevision, 0, 1_000_000, "invalid_state_record");
  assertDate(record.goalDate, "invalid_state_record");
  assertTimeZone(record.timeZone, "invalid_state_record");
  const createdAt = assertInstant(record.createdAt, "invalid_state_record");
  if (dateInTimeZone(createdAt, record.timeZone) !== record.goalDate) fail("invalid_state_record");
  if (
    !Array.isArray(record.proposals) ||
    !Array.isArray(record.correlations) ||
    !Array.isArray(record.connectionBindings)
  )
    fail("invalid_state_record");
  if (record.proposals.length > revenueProgramPolicy.maximumProgramProposals) fail("invalid_state_record");
  const programEnvelope = {
    programRef: record.programRef,
    programRevision: record.programRevision,
    programHash: record.programHash,
    goalDate: record.goalDate,
    principalBinding: record.principalBinding,
    connectionBindings: record.connectionBindings,
  };
  const connectionRefs = assertConnectionBindings(record.connectionBindings, record.principalBinding, context);
  const correlationRefs = validateCorrelations(record.correlations, programEnvelope);
  const correlationEvidence = new Map(
    record.correlations.map((correlation) => [correlation.correlationRef, correlation.evidenceHash]),
  );
  for (const proposal of record.proposals) validateProposal(proposal, programEnvelope, connectionRefs, context);
  if (
    new Set(record.proposals.map((proposal) => proposal.proposalRef)).size !== record.proposals.length ||
    new Set(record.proposals.map((proposal) => proposal.idempotencyKey)).size !== record.proposals.length ||
    new Set(record.proposals.map((proposal) => proposal.effectKey)).size !== record.proposals.length ||
    record.proposals.some((proposal) =>
      proposal.correlationRefs.some((reference) => !correlationRefs.has(reference)),
    ) ||
    record.proposals.some((proposal) => {
      const citedEvidence = new Set(proposal.correlationRefs.map((reference) => correlationEvidence.get(reference)));
      return proposal.evidenceHashes.some((evidenceHash) => !citedEvidence.has(evidenceHash));
    })
  )
    fail("invalid_state_record");
};

const initializeRevenueProgramStateForContext = (context, rawProgram) => {
  const program = snapshotWithoutCallerControls(rawProgram);
  assertBuiltRevenueProgramForContractSuite(context.contracts, rawProgram);
  validateProgram(program, context);
  const base = Object.freeze({
    version: revenueProgramPolicy.version,
    programRef: program.programRef,
    programHash: program.programHash,
    programRevision: program.programRevision,
    goalDate: program.goalDate,
    timeZone: program.timeZone,
    principalBinding: program.principalBinding,
    createdAt: program.createdAt,
    state: "uncommitted_initialization",
    revision: 0,
    durableFenceRef: "durable-fence:unresolved",
    commitDisposition: "uncommitted",
    proposals: program.proposals,
    correlations: program.correlations,
    connectionBindings: program.connectionBindings,
    safetyDisposition: "hard_disabled",
    reconciliation: Object.freeze({ status: "not_attempted", attemptRef: null, receiptRef: null }),
  });
  const record = Object.freeze({ ...base, recordHash: stateHash(base) });
  validateState(snapshotPlainJson(record), context);
  context.issuedRevenueStates.add(record);
  return record;
};

const transitionCas = (record) =>
  Object.freeze({
    status: "unresolved",
    externalCommitRequired: true,
    exactExpectedRevision: record.revision,
    exactExpectedFenceRef: record.durableFenceRef,
    durableReceiptRequired: true,
  });

const evaluationLineage = (record) =>
  Object.freeze(
    [...record.proposals]
      .sort((left, right) => compareCodepoints(left.proposalRef, right.proposalRef))
      .map((proposal) =>
        Object.freeze({
          proposalRef: proposal.proposalRef,
          contentHash: proposal.contentHash,
          evidenceDigest: sha256Canonical(proposal.evidenceHashes),
          correlationDigest: sha256Canonical(proposal.correlationRefs),
        }),
      ),
  );

const requestRevenueProgramEvaluationForContext = (context, rawRecord, rawRequest) => {
  const record = snapshotWithoutCallerControls(rawRecord);
  const request = snapshotWithoutCallerControls(rawRequest);
  if (!rawRecord || typeof rawRecord !== "object" || !context.issuedRevenueStates.has(rawRecord))
    fail("untrusted_state_record");
  validateState(record, context);
  assertExactKeys(request, evaluationRequestKeys, "invalid_evaluation_request");
  if (
    assertInteger(request.expectedRevision, 0, Number.MAX_SAFE_INTEGER, "revision_mismatch") !== record.revision ||
    assertReference(request.expectedFenceRef, "fence_mismatch") !== record.durableFenceRef ||
    assertHash(request.programHash, "program_hash_mismatch") !== record.programHash
  )
    fail("cas_binding_mismatch");
  const requestRef = assertReference(request.requestRef, "invalid_evaluation_request");
  const lineage = evaluationLineage(record);
  if (
    lineage.length !== record.proposals.length ||
    new Set(lineage.map((entry) => entry.proposalRef)).size !== record.proposals.length
  )
    fail("evaluation_lineage_mismatch");
  const artifactDigest = sha256Canonical(lineage);
  const runs = Object.freeze(
    requiredEvaluationGates.flatMap((gate) =>
      Object.entries(prospectiveEvaluatorRegistry).map(([evaluatorRef, evaluator]) => {
        const criterionRef =
          evaluator.originClass === "deterministic"
            ? evaluationGateCriteria[gate].deterministicCriterionRef
            : evaluationGateCriteria[gate].llmCriterionRef;
        return Object.freeze({
          runRef: `evalrun:${sha256Canonical({ requestRef, programHash: record.programHash, artifactDigest, gate, evaluatorRef, criterionRef })}`,
          gate,
          evaluatorRef,
          originClass: evaluator.originClass,
          criterionRef,
          programHash: record.programHash,
          artifactDigest,
        });
      }),
    ),
  );
  const operation = Object.freeze({
    requestRef,
    programHash: record.programHash,
    programRevision: record.programRevision,
    artifactDigest,
    lineage,
    runs,
    resolution: "unresolved",
    evaluatorReceiptRequired: true,
    timeBinding: Object.freeze({
      status: "unresolved",
      expiryPolicyRef: "expiry-policy:evaluation:24h",
      trustedServerTimeRequired: true,
    }),
  });
  const transitionRef = `transition:${sha256Canonical({
    kind: "evaluation_request",
    requestRef,
    baseRecordHash: record.recordHash,
    expectedRevision: record.revision,
    expectedFenceRef: record.durableFenceRef,
    operation,
  })}`;
  const transition = Object.freeze({
    transitionRef,
    transitionKind: "evaluation_request",
    baseRecordHash: record.recordHash,
    expectedRevision: record.revision,
    expectedFenceRef: record.durableFenceRef,
    proposedRevision: record.revision + 1,
    programHash: record.programHash,
    operation,
    cas: transitionCas(record),
    safetyDisposition: "hard_disabled",
  });
  assertExactKeys(transition, transitionKeys, "invalid_transition");
  return transition;
};

const requestRevenueProgramApprovalForContext = (context, rawRecord, rawRequest) => {
  const record = snapshotWithoutCallerControls(rawRecord);
  const request = snapshotWithoutCallerControls(rawRequest);
  if (!rawRecord || typeof rawRecord !== "object" || !context.issuedRevenueStates.has(rawRecord))
    fail("untrusted_state_record");
  validateState(record, context);
  assertExactKeys(request, approvalRequestKeys, "invalid_approval_request");
  if (
    assertInteger(request.expectedRevision, 0, Number.MAX_SAFE_INTEGER, "revision_mismatch") !== record.revision ||
    assertReference(request.expectedFenceRef, "fence_mismatch") !== record.durableFenceRef ||
    assertHash(request.programHash, "program_hash_mismatch") !== record.programHash
  )
    fail("cas_binding_mismatch");
  if (
    request.teamRef !== context.contracts.deploymentSlackAudience.teamRef ||
    request.userRef !== context.contracts.deploymentSlackAudience.userRef ||
    request.audienceRef !== context.contracts.deploymentSlackAudience.audienceRef ||
    !slackActionRegistry.includes(request.actionId)
  )
    fail("untrusted_slack_audience_or_action");
  const proposalRef = assertReference(request.proposalRef, "invalid_approval_request");
  const proposal = record.proposals.find((candidate) => candidate.proposalRef === proposalRef);
  if (!proposal) fail("invalid_approval_target");
  const requestRef = assertReference(request.requestRef, "invalid_approval_request");
  const messageRef = assertReference(request.messageRef, "invalid_approval_request");
  const interactionRef = assertReference(request.interactionRef, "invalid_approval_request");
  const payloadHash = sha256Canonical({
    programHash: record.programHash,
    programRevision: record.programRevision,
    expectedRevision: record.revision,
    expectedFenceRef: record.durableFenceRef,
    proposalRef,
    proposalContentHash: proposal.contentHash,
    teamRef: context.contracts.deploymentSlackAudience.teamRef,
    userRef: context.contracts.deploymentSlackAudience.userRef,
    audienceRef: context.contracts.deploymentSlackAudience.audienceRef,
    messageRef,
    interactionRef,
    actionId: request.actionId,
  });
  if (request.payloadHash !== payloadHash) fail("approval_payload_mismatch");
  const operation = Object.freeze({
    requestRef,
    programHash: record.programHash,
    programRevision: record.programRevision,
    proposalRef,
    proposalContentHash: proposal.contentHash,
    teamRef: context.contracts.deploymentSlackAudience.teamRef,
    userRef: context.contracts.deploymentSlackAudience.userRef,
    audienceRef: context.contracts.deploymentSlackAudience.audienceRef,
    messageRef,
    interactionRef,
    actionId: request.actionId,
    payloadHash,
    resolution: "unresolved",
    slackReceiptRequired: true,
    timeBinding: Object.freeze({
      status: "unresolved",
      expiryPolicyRef: "expiry-policy:slack-approval:15m",
      trustedServerTimeRequired: true,
    }),
  });
  const transitionRef = `transition:${sha256Canonical({
    kind: "approval_request",
    requestRef,
    baseRecordHash: record.recordHash,
    expectedRevision: record.revision,
    expectedFenceRef: record.durableFenceRef,
    operation,
  })}`;
  const transition = Object.freeze({
    transitionRef,
    transitionKind: "approval_request",
    baseRecordHash: record.recordHash,
    expectedRevision: record.revision,
    expectedFenceRef: record.durableFenceRef,
    proposedRevision: record.revision + 1,
    programHash: record.programHash,
    operation,
    cas: transitionCas(record),
    safetyDisposition: "hard_disabled",
  });
  assertExactKeys(transition, transitionKeys, "invalid_transition");
  return transition;
};

const recordRevenueProgramEvaluationForContext = (context, record, receipt) => {
  if (!context.issuedRevenueStates.has(record)) fail("untrusted_state_record");
  snapshotWithoutCallerControls(record);
  snapshotWithoutCallerControls(receipt);
  fail("untrusted_evaluation_receipt");
};

const recordRevenueProgramApprovalForContext = (context, record, receipt) => {
  if (!context.issuedRevenueStates.has(record)) fail("untrusted_state_record");
  snapshotWithoutCallerControls(record);
  snapshotWithoutCallerControls(receipt);
  fail("untrusted_approval_receipt");
};

export const createRevenueProgramStateMachine = (contractSuite) => {
  const contracts = assertRevenueProgramContractSuite(contractSuite);
  if (
    contracts.profile.evalPolicy.requiredGates.length !== requiredEvaluationGates.length ||
    requiredEvaluationGates.some((gate) => !contracts.profile.evalPolicy.requiredGates.includes(gate))
  ) {
    fail("unsupported_revenue_profile");
  }
  const context = Object.freeze({ contracts, issuedRevenueStates: new WeakSet() });
  return Object.freeze({
    evaluationGateCriteria,
    prospectiveEvaluatorRegistry,
    prospectiveReconciliationContract,
    initializeRevenueProgramState: (program) => initializeRevenueProgramStateForContext(context, program),
    requestRevenueProgramEvaluation: (record, request) =>
      requestRevenueProgramEvaluationForContext(context, record, request),
    requestRevenueProgramApproval: (record, request) =>
      requestRevenueProgramApprovalForContext(context, record, request),
    recordRevenueProgramEvaluation: (record, receipt) =>
      recordRevenueProgramEvaluationForContext(context, record, receipt),
    recordRevenueProgramApproval: (record, receipt) => recordRevenueProgramApprovalForContext(context, record, receipt),
  });
};

const ceoRevenueProgramStateMachine = createRevenueProgramStateMachine(ceoRevenueProgramContractSuite);
export const initializeRevenueProgramState = ceoRevenueProgramStateMachine.initializeRevenueProgramState;
export const requestRevenueProgramEvaluation = ceoRevenueProgramStateMachine.requestRevenueProgramEvaluation;
export const requestRevenueProgramApproval = ceoRevenueProgramStateMachine.requestRevenueProgramApproval;
export const recordRevenueProgramEvaluation = ceoRevenueProgramStateMachine.recordRevenueProgramEvaluation;
export const recordRevenueProgramApproval = ceoRevenueProgramStateMachine.recordRevenueProgramApproval;
