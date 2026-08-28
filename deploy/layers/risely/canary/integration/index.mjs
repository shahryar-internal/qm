import { types } from "node:util";
import {
  deploymentConnectionAnchors,
  deploymentPrincipalBindingAnchor,
  deploymentSlackAudience,
  verifyRevenueProgramOutput,
} from "../revenue-program/index.mjs";
import { marketingBindingAnchor, marketingProgramHash } from "../marketing-program/index.mjs";
import {
  EvalRelease,
  EvidenceBundle,
  OutboxEvent,
  PrincipalBinding,
  WorkflowArtifact,
} from "../shared-contracts/index.mjs";
import { buildPrivateCeoSurface, buildQmRendererFromSurface } from "../presentation/index.mjs";
import { renderPrivateCeoSlackBlockKitFromSurface } from "../slack/index.mjs";
import { buildNotionPageTemplateFromSurface } from "../notion-templates/index.mjs";
import { derivePublicationEnvelope } from "./publication-envelope.mjs";

export { buildDormantGmailDraftProposal, createDormantGmailDraftProposalCompiler } from "./gmail-draft.mjs";

const buildEvidenceBundle = EvidenceBundle.create;
const buildOutboxEvent = OutboxEvent.create;
const buildWorkflowArtifact = WorkflowArtifact.create;
const ceoIdentity = PrincipalBinding.identity;
const deepFreeze = PrincipalBinding.freeze;
const principalBinding = PrincipalBinding.value;
const sha256Canonical = PrincipalBinding.hash;
const snapshotPlainData = PrincipalBinding.snapshot;
const validateEvalRelease = EvalRelease.validate;
const validateOutboxEvent = OutboxEvent.validate;
const validateWorkflowArtifact = WorkflowArtifact.validate;

function assertEqual(actual, expected, label) {
  if (actual !== expected) throw new TypeError(`${label} does not match the canonical CEO binding`);
}

function assertLaneBinding(value, expected, label) {
  for (const [field, canonical] of Object.entries(expected)) assertEqual(value[field], canonical, `${label}.${field}`);
}

function recordRef(value) {
  if (typeof value === "string" && /^source-record:[a-f0-9]{64}$/u.test(value)) return value;
  return `source-record:${sha256Canonical(value)}`;
}

function claimRef(value) {
  if (typeof value === "string" && /^source-citation:[a-f0-9]{64}$/u.test(value)) {
    return `claim:${value.slice("source-citation:".length)}`;
  }
  return `claim:${sha256Canonical(value)}`;
}

function availableEvidence(
  source,
  sourceRecord,
  contentSha256,
  observedAt,
  status,
  claimRefs = [],
  trust = "untrusted_source_data",
  relatedContentSha256 = [],
  sourceTrust = trust,
  sourceAvailability = "available",
) {
  return {
    source,
    sourceRecordRef: recordRef(sourceRecord),
    contentSha256,
    relatedContentSha256,
    observedAt,
    fetchedAt: observedAt,
    status,
    trust,
    availability: "available",
    sourceTrust,
    sourceAvailability,
    claimRefs,
  };
}

function unavailableEvidence(
  source,
  sourceRecord,
  contentSha256,
  observedAt,
  status,
  claimRefs = [],
  relatedContentSha256 = [],
  sourceTrust = "unavailable_source",
  sourceAvailability = "unavailable",
) {
  return {
    source,
    sourceRecordRef: recordRef(sourceRecord),
    contentSha256,
    relatedContentSha256,
    observedAt,
    fetchedAt: observedAt,
    status,
    trust: "unavailable_source",
    availability: "unavailable",
    sourceTrust,
    sourceAvailability,
    claimRefs,
  };
}

export function adaptChiefOfStaffMeetingArtifact(value) {
  const source = snapshotPlainData(value, "Chief of Staff meeting artifact");
  const required = [
    "schemaVersion",
    "meetingKey",
    "generatedAt",
    "calendarEvidenceHash",
    "sources",
    "evidence",
    "sections",
    "missingContext",
    "providerContentTrust",
    "presentationSinkAllowed",
    "artifactHash",
  ];
  if (
    !source ||
    typeof source !== "object" ||
    Array.isArray(source) ||
    Object.keys(source).some((key) => !required.includes(key)) ||
    required.some((key) => !Object.hasOwn(source, key))
  ) {
    throw new TypeError("Chief of Staff meeting artifact has an unsupported shape");
  }
  if (
    source.schemaVersion !== 1 ||
    source.providerContentTrust !== "untrusted_data_only" ||
    source.presentationSinkAllowed !== false ||
    source.artifactHash !==
      sha256Canonical(Object.fromEntries(required.slice(0, -1).map((field) => [field, source[field]])))
  ) {
    throw new TypeError("Chief of Staff meeting artifact integrity does not match");
  }
  const requiredSources = ["calendar", "clarify", "command_center_brain", "gmail", "notion"];
  if (
    !/^[a-f0-9]{64}$/u.test(source.meetingKey) ||
    !Array.isArray(source.sources) ||
    source.sources.length !== requiredSources.length ||
    source.sources.some(
      (entry, index) =>
        Object.keys(entry).sort().join("\n") !== ["availability", "source"].sort().join("\n") ||
        entry.source !== requiredSources[index] ||
        !["available", "unavailable", "not_connected"].includes(entry.availability),
    ) ||
    source.sources.find((entry) => entry.source === "calendar")?.availability !== "available" ||
    !Array.isArray(source.evidence) ||
    source.evidence.length < 1 ||
    !Array.isArray(source.missingContext) ||
    sha256Canonical(source.missingContext) !==
      sha256Canonical(source.sources.filter((entry) => entry.availability !== "available").map((entry) => entry.source))
  ) {
    throw new TypeError("Chief of Staff meeting artifact inventory is incomplete");
  }
  const sectionNames = ["accountOverview", "contactBackground", "recommendedPositioning"];
  if (Object.keys(source.sections).sort().join("\n") !== [...sectionNames].sort().join("\n")) {
    throw new TypeError("Chief of Staff meeting artifact sections are incomplete");
  }
  const claims = sectionNames.flatMap((section) => source.sections[section]);
  if (
    sectionNames.some((section) => !Array.isArray(source.sections[section]) || source.sections[section].length < 1) ||
    claims.some(
      (entry) =>
        Object.keys(entry).sort().join("\n") !== ["claimId", "citations", "text", "trust"].sort().join("\n") ||
        entry.trust !== "generated_claim" ||
        typeof entry.claimId !== "string" ||
        typeof entry.text !== "string" ||
        !entry.text ||
        !Array.isArray(entry.citations) ||
        entry.citations.length < 1,
    )
  ) {
    throw new TypeError("Chief of Staff meeting artifact has no cited claims");
  }
  if (
    new Set(claims.map((entry) => entry.claimId)).size !== claims.length ||
    new Set(source.evidence.map((entry) => entry.evidenceRef)).size !== source.evidence.length
  ) {
    throw new TypeError("Chief of Staff claim or evidence identity is duplicated");
  }
  const claimsByCitation = new Map();
  for (const entry of claims) {
    const linkedClaim = claimRef({ claimId: entry.claimId, text: entry.text, trust: entry.trust });
    for (const citation of entry.citations) {
      const current = claimsByCitation.get(citation) ?? [];
      current.push(linkedClaim);
      claimsByCitation.set(citation, current);
    }
  }
  const records = source.evidence.map((entry) => {
    const sourceInventory = source.sources.find((candidate) => candidate.source === entry.source);
    if (
      Object.keys(entry).sort().join("\n") !==
        ["capturedAt", "evidenceHash", "evidenceRef", "source", "trust"].sort().join("\n") ||
      entry.trust !== "untrusted_source_data" ||
      sourceInventory?.availability !== "available" ||
      !/^[a-f0-9]{64}$/u.test(entry.evidenceHash) ||
      new Date(entry.capturedAt).toISOString() !== entry.capturedAt ||
      Date.parse(entry.capturedAt) > Date.parse(source.generatedAt)
    ) {
      throw new TypeError("Chief of Staff evidence record is invalid");
    }
    const linkedClaims = claimsByCitation.get(entry.evidenceRef) ?? [];
    if (linkedClaims.length < 1) throw new TypeError("Chief of Staff evidence is not linked to a claim");
    return availableEvidence(
      entry.source,
      entry,
      entry.evidenceHash,
      entry.capturedAt,
      "cited",
      linkedClaims,
      entry.trust,
    );
  });
  if (
    claims.some((entry) =>
      entry.citations.some((citation) => !source.evidence.some((evidence) => evidence.evidenceRef === citation)),
    )
  ) {
    throw new TypeError("Chief of Staff claim cites an unknown record");
  }
  if (
    !source.evidence.some((entry) => entry.source === "calendar" && entry.evidenceHash === source.calendarEvidenceHash)
  ) {
    throw new TypeError("Chief of Staff Calendar evidence does not match");
  }
  const evidenceBundle = buildEvidenceBundle({ principalBinding, evidence: records });
  return buildWorkflowArtifact({
    principalBinding,
    sourceLane: "chief_of_staff",
    sourceArtifactRef: `source:${sha256Canonical({ lane: "chief_of_staff", meetingKey: source.meetingKey })}`,
    sourceArtifactSha256: source.artifactHash,
    sourceRevision: sha256Canonical({ artifactHash: source.artifactHash, generatedAt: source.generatedAt }),
    workflowKind: "meeting_prep",
    state: "ready",
    evidenceBundle,
    updatedAt: source.generatedAt,
  });
}

function adaptVerifiedRevenueProgramArtifact(value) {
  const source = strictShape(
    value,
    [
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
    ],
    "Revenue program artifact",
  );
  if (
    source?.version !== "revenue-program.v1" ||
    source.programHash !==
      sha256Canonical(Object.fromEntries(Object.entries(source).filter(([field]) => field !== "programHash")))
  ) {
    throw new TypeError("Revenue program artifact integrity does not match");
  }
  assertLaneBinding(source.principalBinding, deploymentPrincipalBindingAnchor, "Revenue program binding");
  assertEqual(deploymentSlackAudience.audienceRef, ceoIdentity.audienceRef, "Revenue Slack audience");
  strictShape(
    source.safety,
    [
      "disposition",
      "commandCenterAccess",
      "gmailAccess",
      "linkedinAccess",
      "crmAccess",
      "notionAccess",
      "demoRepositoryAccess",
    ],
    "Revenue program safety",
  );
  if (
    source.safety.disposition !== "unresolved_proposals" ||
    source.safety.commandCenterAccess !== "read_only" ||
    source.safety.gmailAccess !== "draft_proposal_only" ||
    source.safety.linkedinAccess !== "proposal_only" ||
    source.safety.crmAccess !== "read_only" ||
    source.safety.notionAccess !== "artifact_proposal_only" ||
    source.safety.demoRepositoryAccess !== "read_only" ||
    !Array.isArray(source.connectionBindings) ||
    source.connectionBindings.length !== 10 ||
    !Array.isArray(source.proposals) ||
    !Array.isArray(source.selectedCandidateRefs)
  ) {
    throw new TypeError("Revenue program boundary is incomplete");
  }
  if (!Array.isArray(source.correlations) || source.correlations.length < 1 || source.correlations.length > 256) {
    throw new TypeError("Revenue program must contain its cited correlations");
  }
  const healthBySource = new Map(source.sourceHealth.sources.map((entry) => [entry.source, entry.status]));
  const providerAccounts = new Set(source.connectionBindings.map((entry) => entry.providerAccountRef));
  const evidence = source.correlations.map((entry) => {
    strictShape(
      entry,
      [
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
      ],
      "Revenue correlation",
    );
    if (
      !/^correlation:[a-f0-9]{64}$/u.test(entry.correlationRef) ||
      entry.deploymentRef !== ceoIdentity.deploymentRef ||
      entry.anchorRef !== ceoIdentity.principalBindingRef ||
      entry.tenantRef !== ceoIdentity.tenantRef ||
      entry.workspaceRef !== ceoIdentity.workspaceRef ||
      entry.principalRef !== ceoIdentity.principalRef ||
      entry.credentialOwnerRef !== ceoIdentity.credentialOwnerRef ||
      !providerAccounts.has(entry.providerAccountRef) ||
      !/^source-record:[a-f0-9]{64}$/u.test(entry.sourceRecordRef) ||
      !/^[a-f0-9]{64}$/u.test(entry.evidenceHash) ||
      !Array.isArray(entry.factCitationRefs) ||
      entry.factCitationRefs.length < 1 ||
      entry.factCitationRefs.some((citation) => !/^source-citation:[a-f0-9]{64}$/u.test(citation))
    ) {
      throw new TypeError("Revenue correlation lineage is incomplete");
    }
    const status = healthBySource.get(entry.source);
    if (!status) throw new TypeError("Revenue correlation has no source-health status");
    const claims = entry.factCitationRefs.map(claimRef);
    return status === "available"
      ? availableEvidence(entry.source, entry.sourceRecordRef, entry.evidenceHash, source.createdAt, status, claims)
      : unavailableEvidence(entry.source, entry.sourceRecordRef, entry.evidenceHash, source.createdAt, status, claims);
  });
  const evidenceBundle = buildEvidenceBundle({ principalBinding, evidence });
  return buildWorkflowArtifact({
    principalBinding,
    sourceLane: "revenue_program",
    sourceArtifactRef: `source:${sha256Canonical({ lane: "revenue_program", programRef: source.programRef })}`,
    sourceArtifactSha256: source.programHash,
    sourceRevision: sha256Canonical({ programHash: source.programHash, programRevision: source.programRevision }),
    workflowKind: "outreach_linkedin_demo",
    state: source.sourceHealth.blockers.length === 0 ? "ready" : "unavailable",
    evidenceBundle,
    updatedAt: source.createdAt,
  });
}

export function adaptRevenueProgramArtifact(value) {
  return adaptVerifiedRevenueProgramArtifact(verifyRevenueProgramOutput(value));
}

export function adaptMarketingProgramArtifact(value) {
  const source = strictShape(
    snapshotPlainData(value, "Marketing program artifact"),
    [
      "version",
      "kind",
      "programRef",
      "programRevision",
      "goalDate",
      "timeZone",
      "principalBinding",
      "rolePolicy",
      "weeklyPlan",
      "planHash",
      "rubric",
      "rubricHash",
      "research",
      "researchHash",
      "artifact",
      "safety",
      "requiredEvaluationGates",
      "programHash",
    ],
    "Marketing program artifact",
  );
  if (
    !["weekly_plan", "daily_draft"].includes(source?.kind) ||
    source.version !== "marketing-program.v4" ||
    source.programHash !== source.artifact?.programHash ||
    source.programHash !== marketingProgramHash(source) ||
    source.planHash !== sha256Canonical(source.weeklyPlan) ||
    source.rubricHash !== sha256Canonical(source.rubric) ||
    source.researchHash !== sha256Canonical(source.research)
  ) {
    throw new TypeError("Marketing program artifact integrity does not match");
  }
  assertLaneBinding(source.principalBinding, marketingBindingAnchor, "Marketing program binding");
  strictShape(
    source.safety,
    ["disposition", "executionDisposition", "providerAccess", "socialExecution", "trustedReceiptRequired"],
    "Marketing program safety",
  );
  if (
    source.safety.disposition !== "unresolved_proposals" ||
    source.safety.executionDisposition !== "hard_disabled" ||
    source.safety.providerAccess !== "none" ||
    source.safety.socialExecution !== "not_available" ||
    source.safety.trustedReceiptRequired !== true
  ) {
    throw new TypeError("Marketing program safety is invalid");
  }
  if (!Array.isArray(source.artifact.sourceRefs) || source.artifact.sourceRefs.length < 1) {
    throw new TypeError("Marketing program has no cited source records");
  }
  const evidence = source.artifact.sourceRefs.map((entry) => {
    const research = source.research.find((candidate) => candidate.citationRef === entry.citationRef);
    if (
      !research ||
      research.researchHash !== entry.researchHash ||
      research.sourceReceiptHash !== entry.sourceReceiptHash
    ) {
      throw new TypeError("Marketing source evidence does not match");
    }
    return unavailableEvidence(
      "marketing_research",
      research,
      research.sourceReceiptHash,
      research.fetchedAt,
      research.receiptDisposition,
      [claimRef({ artifactRef: source.artifact.artifactRef, citationRef: research.citationRef })],
      [research.researchHash, research.exactCitationHash],
      research.trust,
      research.availability,
    );
  });
  const evidenceBundle = buildEvidenceBundle({ principalBinding, evidence });
  return buildWorkflowArtifact({
    principalBinding,
    sourceLane: "marketing_program",
    sourceArtifactRef: `source:${sha256Canonical({ artifactRef: source.artifact.artifactRef, lane: "marketing_program" })}`,
    sourceArtifactSha256: sha256Canonical(source.artifact),
    sourceRevision: sha256Canonical({ programHash: source.programHash, programRevision: source.programRevision }),
    workflowKind: source.kind === "weekly_plan" ? "marketing_plan" : "marketing_draft",
    state: "unavailable",
    evidenceBundle,
    updatedAt: source.research.reduce(
      (latest, entry) => (Date.parse(entry.fetchedAt) > Date.parse(latest) ? entry.fetchedAt : latest),
      source.research[0].fetchedAt,
    ),
  });
}

export function workflowArtifactToSurfaceArtifact(value) {
  const artifact = validateWorkflowArtifact(value);
  return Object.freeze({
    schemaVersion: 1,
    artifactRef: artifact.artifactRef,
    revision: artifact.revision,
    kind: artifact.workflowKind,
    state: artifact.state,
    evidence: Object.freeze(
      artifact.evidenceBundle.evidence.map((entry) =>
        Object.freeze({ evidenceRef: entry.evidenceRef, trust: entry.trust, availability: entry.availability }),
      ),
    ),
    links: Object.freeze([]),
  });
}

export function buildActionlessPublication(value) {
  const event = validateOutboxEvent(value);
  const surface = buildPrivateCeoSurface(workflowArtifactToSurfaceArtifact(event.artifact));
  let rendered;
  if (event.surface === "slack") rendered = renderPrivateCeoSlackBlockKitFromSurface(surface);
  else if (event.surface === "qm") rendered = buildQmRendererFromSurface(surface);
  else rendered = buildNotionPageTemplateFromSurface(surface);
  if (rendered.actionless === false || JSON.stringify(rendered).includes('"actions"')) {
    throw new TypeError("Surface publication must remain actionless");
  }
  const envelope = derivePublicationEnvelope(event);
  return deepFreeze({
    outboxEvent: event,
    publicationEnvelope: envelope,
    publication: {
      surface: event.surface,
      audienceRef: event.audienceRef,
      artifactRef: event.artifact.artifactRef,
      artifactRevision: event.artifact.revision,
      artifactSha256: event.artifact.artifactSha256,
      evalReleaseSha256: event.evalRelease.releaseSha256,
      eventId: event.eventId,
      eventSha256: event.eventSha256,
      envelopeSha256: envelope.envelopeSha256,
      renderedSha256: sha256Canonical(rendered),
      actionless: true,
      providerInvocationAllowed: false,
    },
  });
}

export function buildActionlessPublicationSet(value) {
  const input = snapshotPlainData(value, "Publication set input");
  const fields = ["artifact", "evalRelease", "queuedAt"];
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).some((key) => !fields.includes(key)) ||
    fields.some((key) => !Object.hasOwn(input, key))
  ) {
    throw new TypeError("Publication set input has an unsupported shape");
  }
  const artifact = validateWorkflowArtifact(input.artifact);
  const evalRelease = validateEvalRelease(input.evalRelease, artifact);
  return Object.freeze(
    Object.fromEntries(
      ["slack", "qm", "notion"].map((surface) => {
        const event = buildOutboxEvent({ principalBinding, artifact, evalRelease, surface, queuedAt: input.queuedAt });
        return [surface, buildActionlessPublication(event)];
      }),
    ),
  );
}

function selfHash(value, field) {
  const projection = { ...value };
  delete projection[field];
  return sha256Canonical(projection);
}

const referencePattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const digestPattern = /^[a-f0-9]{64}$/u;

function reference(value, label) {
  if (typeof value !== "string" || !referencePattern.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

function digestValue(value, label) {
  if (typeof value !== "string" || !digestPattern.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

function strictShape(value, fields, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => !fields.includes(key)) ||
    fields.some((key) => !Object.hasOwn(value, key))
  ) {
    throw new TypeError(`${label} has an unsupported shape`);
  }
  return value;
}

const calendarBindingFields = Object.freeze([
  "contractType",
  "contractVersion",
  "brokerOrigin",
  "logicalGoogleAnchorRef",
  "connectionRef",
  "calendarAccountRef",
  "providerAccountSubject",
  "principalRef",
  "credentialOwnerRef",
  "receiptDisposition",
  "receiptSha256",
]);

export function validateCalendarBindingResolutionReceipt(value) {
  const receipt = strictShape(
    snapshotPlainData(value, "Calendar binding resolution receipt"),
    calendarBindingFields,
    "Calendar binding resolution receipt",
  );
  if (
    receipt.contractType !== "CalendarBindingResolutionReceipt" ||
    receipt.contractVersion !== 1 ||
    receipt.brokerOrigin !== "future_qm_connector_binding_broker" ||
    receipt.logicalGoogleAnchorRef !== deploymentConnectionAnchors.googleAccountRef ||
    receipt.principalRef !== ceoIdentity.principalRef ||
    receipt.credentialOwnerRef !== ceoIdentity.credentialOwnerRef ||
    receipt.receiptDisposition !== "unresolved" ||
    receipt.receiptSha256 !== selfHash(receipt, "receiptSha256")
  ) {
    throw new TypeError("Calendar binding resolution receipt does not match the prospective broker contract");
  }
  for (const field of ["connectionRef", "calendarAccountRef", "providerAccountSubject"]) {
    reference(receipt[field], `Calendar binding ${field}`);
  }
  if (
    [receipt.connectionRef, receipt.calendarAccountRef, receipt.providerAccountSubject].includes(
      receipt.logicalGoogleAnchorRef,
    )
  ) {
    throw new TypeError("Calendar logical and resolved identities must remain distinct");
  }
  return deepFreeze(receipt);
}

const occurrenceFields = Object.freeze([
  "providerEventId",
  "originalStartAt",
  "startAt",
  "endAt",
  "status",
  "allDay",
  "visibility",
  "seriesId",
  "attendees",
]);
const calendarProjections = new WeakSet();
const revenueTranscriptArtifacts = new WeakSet();

export function adaptCalendarOccurrenceForLanes(value) {
  const input = strictShape(
    snapshotPlainData(value, "Calendar occurrence adapter input"),
    ["bindingResolutionReceipt", "occurrence"],
    "Calendar occurrence adapter input",
  );
  const binding = validateCalendarBindingResolutionReceipt(input.bindingResolutionReceipt);
  const occurrence = strictShape(input.occurrence, occurrenceFields, "Calendar occurrence");
  if (
    !["confirmed", "cancelled"].includes(occurrence.status) ||
    typeof occurrence.allDay !== "boolean" ||
    !["default", "private", "public"].includes(occurrence.visibility) ||
    (occurrence.seriesId !== null && (typeof occurrence.seriesId !== "string" || !occurrence.seriesId)) ||
    !Array.isArray(occurrence.attendees) ||
    occurrence.attendees.length > 250
  ) {
    throw new TypeError("Calendar occurrence semantics are invalid");
  }
  const attendees = occurrence.attendees.map((entry, index) => {
    const attendee = strictShape(entry, ["attendeeRef", "role", "response"], `Calendar attendee ${index}`);
    if (
      !/^attendee:[a-f0-9]{64}$/u.test(attendee.attendeeRef) ||
      !["ceo", "internal", "external"].includes(attendee.role) ||
      !["accepted", "declined", "tentative", "needs_action"].includes(attendee.response)
    ) {
      throw new TypeError(`Calendar attendee ${index} is invalid`);
    }
    return Object.freeze(attendee);
  });
  const normalized = Object.freeze({
    providerEventId: reference(occurrence.providerEventId, "Calendar occurrence providerEventId"),
    originalStartAt: reference(occurrence.originalStartAt, "Calendar occurrence originalStartAt"),
    startAt: reference(occurrence.startAt, "Calendar occurrence startAt"),
    endAt: reference(occurrence.endAt, "Calendar occurrence endAt"),
    status: occurrence.status,
    allDay: occurrence.allDay,
    visibility: occurrence.visibility,
    seriesId: occurrence.seriesId === null ? null : reference(occurrence.seriesId, "Calendar occurrence seriesId"),
    attendees: Object.freeze(attendees),
  });
  for (const field of ["originalStartAt", "startAt", "endAt"]) {
    if (new Date(normalized[field]).toISOString() !== normalized[field])
      throw new TypeError(`Calendar occurrence ${field} is invalid`);
  }
  if (Date.parse(normalized.endAt) <= Date.parse(normalized.startAt))
    throw new TypeError("Calendar occurrence end must follow start");
  const occurrenceRef = `occurrence:${sha256Canonical({
    principalBindingSha256: principalBinding.bindingSha256,
    calendarAccountRef: binding.calendarAccountRef,
    providerIdentity:
      normalized.seriesId === null
        ? { providerEventId: normalized.providerEventId }
        : { seriesId: normalized.seriesId, originalStartAt: normalized.originalStartAt },
  })}`;
  const canonicalOccurrence = Object.freeze({ ...normalized, occurrenceRef });
  const evidenceSha256 = sha256Canonical(canonicalOccurrence);
  const evidence = Object.freeze({
    evidenceSha256,
    source: "google_calendar",
    providerAccountSubject: binding.providerAccountSubject,
    calendarAccountRef: binding.calendarAccountRef,
    occurrenceRef,
  });
  const shared = Object.freeze({ ...canonicalOccurrence, evidence });
  const revenue = Object.freeze({
    lane: "revenue_program",
    logicalGoogleAnchorRef: binding.logicalGoogleAnchorRef,
    calendarAccountRef: binding.calendarAccountRef,
    providerAccountSubject: binding.providerAccountSubject,
    principalRef: binding.principalRef,
    occurrence: shared,
    evidence,
    disposition: "prospective_unverified",
    providerEffectAllowed: false,
  });
  const chiefOfStaff = Object.freeze({
    lane: "chief_of_staff",
    connectionRef: binding.connectionRef,
    calendarAccountRef: binding.calendarAccountRef,
    providerAccountSubject: binding.providerAccountSubject,
    principalRef: binding.principalRef,
    occurrence: shared,
    evidence,
    disposition: "prospective_unverified",
    providerEffectAllowed: false,
  });
  calendarProjections.add(revenue);
  calendarProjections.add(chiefOfStaff);
  return Object.freeze({
    bindingResolution: binding,
    revenue,
    chiefOfStaff,
    receiptAuthenticated: false,
    disposition: "prospective_unverified",
  });
}

export function normalizeLaneSourceResult(value) {
  const input = strictShape(
    snapshotPlainData(value, "Lane source result"),
    ["lane", "status", "records"],
    "Lane source result",
  );
  if (!Array.isArray(input.records) || !["revenue_program", "chief_of_staff"].includes(input.lane)) {
    throw new TypeError("Lane source result is invalid");
  }
  if (input.lane === "revenue_program" && input.status === "none") {
    if (input.records.length !== 0) throw new TypeError("Revenue none result must be empty");
    return Object.freeze({
      lane: input.lane,
      availability: "available",
      records: Object.freeze([]),
      successfulEmpty: true,
    });
  }
  if (!["available", "unavailable", "not_connected"].includes(input.status))
    throw new TypeError("Lane source status is unsupported");
  return deepFreeze({ lane: input.lane, availability: input.status, records: input.records, successfulEmpty: false });
}

export function adaptRevenueTranscriptArtifact(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    throw new TypeError("Revenue transcript adapter input is invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Object.keys(descriptors).sort().join("\n") !== ["calendarProjection", "revenueProgram"].sort().join("\n") ||
    Object.values(descriptors).some(
      (descriptor) => descriptor.get || descriptor.set || !descriptor.enumerable || !Object.hasOwn(descriptor, "value"),
    )
  ) {
    throw new TypeError("Revenue transcript adapter input has an unsupported shape");
  }
  const originalCalendar = descriptors.calendarProjection.value;
  if (!calendarProjections.has(originalCalendar) || originalCalendar.lane !== "revenue_program") {
    throw new TypeError("Revenue transcript requires an adapter-issued Calendar projection");
  }
  const calendar = originalCalendar;
  const revenueProgram = verifyRevenueProgramOutput(descriptors.revenueProgram.value);
  const revenueArtifact = adaptVerifiedRevenueProgramArtifact(revenueProgram);
  const correlation = revenueProgram.correlations.find((entry) => entry.source === "transcripts");
  if (!correlation || !/^source-record:[a-f0-9]{64}$/u.test(correlation.sourceRecordRef)) {
    throw new TypeError("Revenue program has no validated transcript correlation");
  }
  const projection = {
    contractType: "RevenueTranscriptArtifact",
    contractVersion: 1,
    revenueArtifactRef: revenueArtifact.artifactRef,
    revenueArtifactRevision: revenueArtifact.revision,
    revenueArtifactSha256: revenueArtifact.artifactSha256,
    transcriptProviderAnchorRef: correlation.providerAccountRef,
    transcriptSourceRecordRef: correlation.sourceRecordRef,
    transcriptEvidenceSha256: correlation.evidenceHash,
    calendarAccountRef: calendar.calendarAccountRef,
    providerAccountSubject: calendar.providerAccountSubject,
    providerEventId: calendar.occurrence.providerEventId,
    occurrenceRef: calendar.occurrence.occurrenceRef,
    principalRef: calendar.principalRef,
    participantsSha256: sha256Canonical(calendar.occurrence.attendees),
    bindingDisposition: "prospective_unverified",
    recipientsDerivable: false,
  };
  const artifact = deepFreeze({
    ...projection,
    transcriptArtifactRef: `revenue-transcript:${sha256Canonical(projection)}`,
  });
  revenueTranscriptArtifacts.add(artifact);
  return artifact;
}

export function buildTranscriptVerificationRequest(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  )
    throw new TypeError("Transcript verification input is invalid");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Object.keys(descriptors).sort().join("\n") !==
      ["calendarProjection", "revenueTranscriptArtifact"].sort().join("\n") ||
    Object.values(descriptors).some(
      (descriptor) => descriptor.get || descriptor.set || !descriptor.enumerable || !Object.hasOwn(descriptor, "value"),
    )
  ) {
    throw new TypeError("Transcript verification input has an unsupported shape");
  }
  const calendar = descriptors.calendarProjection.value;
  const transcript = descriptors.revenueTranscriptArtifact.value;
  if (!calendarProjections.has(calendar) || !revenueTranscriptArtifacts.has(transcript)) {
    throw new TypeError("Transcript verification requires adapter-issued artifacts");
  }
  if (
    calendar.calendarAccountRef !== transcript.calendarAccountRef ||
    calendar.providerAccountSubject !== transcript.providerAccountSubject ||
    calendar.occurrence.providerEventId !== transcript.providerEventId ||
    calendar.occurrence.occurrenceRef !== transcript.occurrenceRef ||
    calendar.principalRef !== transcript.principalRef ||
    calendar.principalRef !== ceoIdentity.principalRef ||
    sha256Canonical(calendar.occurrence.attendees) !== transcript.participantsSha256 ||
    calendar.evidence.evidenceSha256 !== calendar.occurrence.evidence.evidenceSha256
  ) {
    throw new TypeError("Transcript Calendar and Revenue bindings do not match");
  }
  const projection = {
    contractType: "TranscriptVerificationRequest",
    contractVersion: 1,
    brokerOrigin: "future_qm_source_verification_broker",
    providerEventId: calendar.occurrence.providerEventId,
    occurrenceRef: calendar.occurrence.occurrenceRef,
    calendarAccountRef: calendar.calendarAccountRef,
    providerAccountSubject: calendar.providerAccountSubject,
    principalRef: calendar.principalRef,
    revenueTranscriptArtifactRef: transcript.transcriptArtifactRef,
    revenueArtifactRef: transcript.revenueArtifactRef,
    revenueArtifactRevision: transcript.revenueArtifactRevision,
    transcriptSourceRecordRef: transcript.transcriptSourceRecordRef,
    transcriptEvidenceSha256: transcript.transcriptEvidenceSha256,
    participantsSha256: transcript.participantsSha256,
    calendarEvidenceSha256: calendar.evidence.evidenceSha256,
    disposition: "verification_required",
    recipientDerivationAllowed: false,
    sourceVerificationSatisfied: false,
  };
  return deepFreeze({ ...projection, requestSha256: sha256Canonical(projection) });
}

export function buildLifecycleSupersessionTransaction(value) {
  const input = strictShape(
    snapshotPlainData(value, "Lifecycle supersession input"),
    [
      "reason",
      "occurrenceRef",
      "previousRevision",
      "nextRevision",
      "claimFence",
      "revenueProposals",
      "revenueLedger",
      "chiefJobs",
    ],
    "Lifecycle supersession input",
  );
  if (
    !["moved", "cancelled"].includes(input.reason) ||
    (input.reason === "moved" && input.nextRevision === null) ||
    (input.reason === "cancelled" && input.nextRevision !== null)
  ) {
    throw new TypeError("Lifecycle supersession reason or revision is invalid");
  }
  const groups = [
    [input.revenueProposals, "revenue:proposal:"],
    [input.revenueLedger, "revenue:ledger:"],
    [input.chiefJobs, "chief_of_staff:job:"],
  ];
  const normalizeRecords = (values, prefix) => {
    if (!Array.isArray(values) || values.length < 1 || values.length > 256) {
      throw new TypeError(`Lifecycle references must use the ${prefix} namespace`);
    }
    const records = values.map((entry) => {
      const record = strictShape(
        entry,
        ["recordRef", "occurrenceRef", "expectedRevision", "claimFence"],
        "Lifecycle related record",
      );
      if (
        !record.recordRef.startsWith(prefix) ||
        record.occurrenceRef !== input.occurrenceRef ||
        record.claimFence !== input.claimFence
      ) {
        throw new TypeError("Lifecycle related record does not match the occurrence fence");
      }
      digestValue(record.expectedRevision, "Lifecycle related record revision");
      return Object.freeze(record);
    });
    if (new Set(records.map((entry) => entry.recordRef)).size !== records.length) {
      throw new TypeError("Lifecycle related records contain duplicates");
    }
    return Object.freeze(records.sort((left, right) => left.recordRef.localeCompare(right.recordRef)));
  };
  const identity = {
    reason: input.reason,
    occurrenceRef: reference(input.occurrenceRef, "Lifecycle occurrenceRef"),
    previousRevision: digestValue(input.previousRevision, "Lifecycle previousRevision"),
    nextRevision: input.nextRevision === null ? null : digestValue(input.nextRevision, "Lifecycle nextRevision"),
    claimFence: reference(input.claimFence, "Lifecycle claimFence"),
    revenueProposals: normalizeRecords(groups[0][0], groups[0][1]),
    revenueLedger: normalizeRecords(groups[1][0], groups[1][1]),
    chiefJobs: normalizeRecords(groups[2][0], groups[2][1]),
  };
  return deepFreeze({
    contractType: "LifecycleSupersessionTransaction",
    contractVersion: 1,
    transactionId: `lifecycle:${sha256Canonical(identity)}`,
    ...identity,
    atomicCommitRequired: true,
    compareAndSwapRequired: true,
    disposition: "prospective_unreserved",
    approved: false,
    reserved: false,
    durableCommitAvailable: false,
    providerEffectAllowed: false,
  });
}

const globalGmailDraftPolicy = Object.freeze({
  globalMaximum: 250,
  outreachMinimum: 100,
  outreachMaximum: 200,
});

export function buildProspectiveGlobalGmailDraftQuota(value) {
  const input = strictShape(
    snapshotPlainData(value, "Global Gmail quota input"),
    ["quotaDate", "effects"],
    "Global Gmail quota input",
  );
  const quotaInstant = new Date(`${input.quotaDate}T00:00:00.000Z`);
  if (
    !/^\d{4}-\d{2}-\d{2}$/u.test(input.quotaDate) ||
    Number.isNaN(quotaInstant.valueOf()) ||
    quotaInstant.toISOString().slice(0, 10) !== input.quotaDate ||
    !Array.isArray(input.effects)
  ) {
    throw new TypeError("Global Gmail quota configuration is invalid");
  }
  const effects = input.effects.map((entry, index) => {
    const effect = strictShape(
      entry,
      ["kind", "providerAccountRef", "credentialOwnerRef", "recipientRef", "businessKey", "effectKey", "contentSha256"],
      `Global Gmail quota effect ${index}`,
    );
    if (
      !["outreach", "transactional_post_meeting"].includes(effect.kind) ||
      effect.credentialOwnerRef !== ceoIdentity.credentialOwnerRef
    ) {
      throw new TypeError(`Global Gmail quota effect ${index} is invalid`);
    }
    return Object.freeze({
      kind: effect.kind,
      providerAccountRef: reference(effect.providerAccountRef, `Global Gmail quota effect ${index} providerAccountRef`),
      credentialOwnerRef: effect.credentialOwnerRef,
      recipientRef: reference(effect.recipientRef, `Global Gmail quota effect ${index} recipientRef`),
      businessKey: reference(effect.businessKey, `Global Gmail quota effect ${index} businessKey`),
      effectKey: digestValue(effect.effectKey, `Global Gmail quota effect ${index} effectKey`),
      contentSha256: digestValue(effect.contentSha256, `Global Gmail quota effect ${index} contentSha256`),
    });
  });
  const dedupeKeys = effects.map((effect) =>
    sha256Canonical({
      providerAccountRef: effect.providerAccountRef,
      credentialOwnerRef: effect.credentialOwnerRef,
      recipientRef: effect.recipientRef,
      businessKey: effect.businessKey,
      effectKey: effect.effectKey,
      contentSha256: effect.contentSha256,
    }),
  );
  if (new Set(dedupeKeys).size !== dedupeKeys.length)
    throw new TypeError("Global Gmail quota contains a duplicate effect");
  const reservationKeys = effects.map((effect) =>
    sha256Canonical({
      providerAccountRef: effect.providerAccountRef,
      credentialOwnerRef: effect.credentialOwnerRef,
      quotaDate: input.quotaDate,
      effectKey: effect.effectKey,
    }),
  );
  if (new Set(reservationKeys).size !== reservationKeys.length)
    throw new TypeError("Global Gmail quota contains a duplicate reservation identity");
  const outreachCount = effects.filter((effect) => effect.kind === "outreach").length;
  const transactionalCount = effects.length - outreachCount;
  const projection = {
    contractType: "ProspectiveGlobalGmailDraftQuota",
    contractVersion: 1,
    quotaDate: input.quotaDate,
    globalMaximum: globalGmailDraftPolicy.globalMaximum,
    outreachMinimum: globalGmailDraftPolicy.outreachMinimum,
    outreachMaximum: globalGmailDraftPolicy.outreachMaximum,
    outreachCount,
    transactionalCount,
    globalCount: effects.length,
    effects: Object.freeze(effects),
    dedupeKeys: Object.freeze(dedupeKeys),
    reservationKeys: Object.freeze(reservationKeys),
    withinPolicy:
      outreachCount >= globalGmailDraftPolicy.outreachMinimum &&
      outreachCount <= globalGmailDraftPolicy.outreachMaximum &&
      effects.length <= globalGmailDraftPolicy.globalMaximum,
    disposition: "prospective_unreserved",
    atomicReservationRequired: true,
    reservationStoreAvailable: false,
    approved: false,
    reserved: false,
    providerExecutionAllowed: false,
  };
  return deepFreeze({ ...projection, quotaSha256: sha256Canonical(projection) });
}

export function deriveProvenanceStorageKey(value) {
  const artifact = validateWorkflowArtifact(value);
  if (!["chief_of_staff", "revenue_program", "marketing_program"].includes(artifact.sourceLane)) {
    throw new TypeError("Provenance source lane is invalid");
  }
  return `storage:${sha256Canonical({
    sourceLane: artifact.sourceLane,
    sourceArtifactRef: artifact.sourceArtifactRef,
    sourceArtifactSha256: artifact.sourceArtifactSha256,
    artifactRef: artifact.artifactRef,
    revision: artifact.revision,
  })}`;
}
