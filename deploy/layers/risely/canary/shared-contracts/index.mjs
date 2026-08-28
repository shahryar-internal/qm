import {
  deepFreeze,
  digest,
  exactRecord,
  identifier,
  instant,
  sha256Canonical,
  snapshotPlainData,
  sortedUnique,
} from "./validation.mjs";
import { assertProfileAuthority } from "../deployment-profiles/contract.mjs";
import { ceoDeploymentProfile } from "../deployment-profiles/index.mjs";

const SHARED_CONTRACT_VERSION = 1;
const PRINCIPAL_BINDING_VERSION = 2;

const contractDigestRevisions = Object.freeze({
  PrincipalBinding: "PrincipalBinding.sha256.v2",
  EvidenceBundle: "EvidenceBundle.sha256.v1",
  EvalRelease: "EvalRelease.sha256.v2",
  WorkflowArtifact: "WorkflowArtifact.sha256.v1",
  OutboxEvent: "OutboxEvent.sha256.v1",
  PublicationEnvelope: "PublicationEnvelope.sha256.v1",
});

function identityFromProfile(profile) {
  return Object.freeze({
    profileRef: profile.profileRef,
    profileSha256: profile.profileSha256,
    organizationRef: profile.anchors.organizationRef,
    deploymentRef: profile.anchors.deploymentRef,
    principalBindingRef: profile.anchors.principalBindingRef,
    tenantRef: profile.anchors.tenantRef,
    workspaceRef: profile.anchors.workspaceRef,
    agentId: profile.agent.agentId,
    agentVersion: profile.agent.agentVersion,
    principalRef: profile.identity.humanPrincipalRef,
    principalEmail: profile.identity.humanEmail,
    qmPrincipalRef: profile.identity.qmPrincipalRef,
    externalIdentityRef: profile.identity.externalIdentityRef,
    credentialOwnerRef: profile.identity.credentialOwnerRef,
    audienceRef: profile.audiences.slack.audienceRef,
    audienceClass: profile.agent.agentScope,
    slackTeamRef: profile.anchors.slackTeamRef,
    slackUserRef: profile.audiences.slack.principalRef,
  });
}

function principalProjection(value) {
  const { bindingSha256: _bindingSha256, ...projection } = value;
  return projection;
}

function buildPrincipalBinding(state) {
  const projection = {
    contractType: "PrincipalBinding",
    contractVersion: PRINCIPAL_BINDING_VERSION,
    digestRevision: contractDigestRevisions.PrincipalBinding,
    ...state.identity,
  };
  return deepFreeze({ ...projection, bindingSha256: sha256Canonical(projection) });
}

function validatePrincipalBinding(state, value) {
  const principalFields = [
    "contractType",
    "contractVersion",
    "digestRevision",
    ...Object.keys(state.identity),
    "bindingSha256",
  ];
  const input = exactRecord(
    snapshotPlainData(value, "PrincipalBinding"),
    principalFields,
    principalFields,
    "PrincipalBinding",
  );
  if (
    input.contractType !== "PrincipalBinding" ||
    input.contractVersion !== PRINCIPAL_BINDING_VERSION ||
    input.digestRevision !== contractDigestRevisions.PrincipalBinding
  ) {
    throw new TypeError("PrincipalBinding contract is not supported");
  }
  for (const [field, expected] of Object.entries(state.identity)) {
    if (input[field] !== expected)
      throw new TypeError(`PrincipalBinding.${field} does not match the deployment profile`);
  }
  digest(input.bindingSha256, "PrincipalBinding.bindingSha256");
  if (input.bindingSha256 !== sha256Canonical(principalProjection(input))) {
    throw new TypeError("PrincipalBinding.bindingSha256 does not match");
  }
  return deepFreeze(input);
}

const evidenceInputFields = Object.freeze([
  "source",
  "sourceRecordRef",
  "contentSha256",
  "relatedContentSha256",
  "observedAt",
  "fetchedAt",
  "status",
  "trust",
  "availability",
  "sourceTrust",
  "sourceAvailability",
  "claimRefs",
]);
const evidenceFields = Object.freeze(["evidenceRef", ...evidenceInputFields]);
const evidenceTrust = new Set([
  "verified_source",
  "untrusted_source_data",
  "generated_evidence_cited_update",
  "unavailable_source",
]);
const evidenceSources = new Set([
  "apollo",
  "calendar",
  "clarify",
  "command_center_brain",
  "gmail",
  "google_analytics",
  "linkedin",
  "marketing_research",
  "notion",
  "posthog",
  "rb2b",
  "transcripts",
]);
const evidenceStatuses = new Set(["available", "cited", "none", "partial_or_unavailable", "unavailable", "unresolved"]);
const evidenceSourceTrust = new Set(["verified_source", "untrusted_source_data", "unavailable_source", "unresolved"]);
const evidenceSourceAvailability = new Set(["available", "unavailable", "unresolved"]);

function normalizeEvidenceInput(value, index) {
  const label = `EvidenceBundle.evidence[${index}]`;
  const input = exactRecord(value, evidenceInputFields, evidenceInputFields, label);
  const observedAt = instant(input.observedAt, `${label}.observedAt`);
  const fetchedAt = instant(input.fetchedAt, `${label}.fetchedAt`);
  if (Date.parse(observedAt) > Date.parse(fetchedAt)) throw new TypeError(`${label} observation postdates fetch`);
  const availability = input.availability;
  const trust = input.trust;
  if (!evidenceTrust.has(trust) || !["available", "unavailable"].includes(availability)) {
    throw new TypeError(`${label} trust or availability is unsupported`);
  }
  if ((availability === "unavailable") !== (trust === "unavailable_source")) {
    throw new TypeError(`${label} availability does not match trust`);
  }
  if (!/^source-record:[a-f0-9]{64}$/u.test(input.sourceRecordRef)) {
    throw new TypeError(`${label}.sourceRecordRef must be a content-addressed source record`);
  }
  if (!evidenceSources.has(input.source)) throw new TypeError(`${label}.source is unsupported`);
  if (!evidenceStatuses.has(input.status)) throw new TypeError(`${label}.status is unsupported`);
  if (!evidenceSourceTrust.has(input.sourceTrust)) throw new TypeError(`${label}.sourceTrust is unsupported`);
  if (!evidenceSourceAvailability.has(input.sourceAvailability)) {
    throw new TypeError(`${label}.sourceAvailability is unsupported`);
  }
  const claimRefs = sortedUnique(
    input.claimRefs,
    `${label}.claimRefs`,
    (entry, entryLabel) => {
      if (typeof entry !== "string" || !/^claim:[a-f0-9]{64}$/u.test(entry)) {
        throw new TypeError(`${entryLabel} must be a content-addressed claim`);
      }
      return entry;
    },
    0,
    256,
  );
  const relatedContentSha256 = sortedUnique(input.relatedContentSha256, `${label}.relatedContentSha256`, digest, 0, 16);
  const record = {
    source: input.source,
    sourceRecordRef: input.sourceRecordRef,
    contentSha256: digest(input.contentSha256, `${label}.contentSha256`),
    relatedContentSha256,
    observedAt,
    fetchedAt,
    status: input.status,
    trust,
    availability,
    sourceTrust: input.sourceTrust,
    sourceAvailability: input.sourceAvailability,
    claimRefs,
  };
  return Object.freeze({ evidenceRef: `evidence:${sha256Canonical(record)}`, ...record });
}

function normalizeEvidenceRecord(value, index) {
  const label = `EvidenceBundle.evidence[${index}]`;
  const input = exactRecord(value, evidenceFields, evidenceFields, label);
  const { evidenceRef, ...record } = input;
  const normalized = normalizeEvidenceInput(record, index);
  if (evidenceRef !== normalized.evidenceRef) throw new TypeError(`${label}.evidenceRef does not match`);
  return normalized;
}

function evidenceBundleProjection(value) {
  const { bundleSha256: _bundleSha256, ...projection } = value;
  return projection;
}

function buildEvidenceBundle(state, value) {
  const input = exactRecord(
    snapshotPlainData(value, "EvidenceBundle input"),
    ["principalBinding", "evidence"],
    ["principalBinding", "evidence"],
    "EvidenceBundle input",
  );
  const binding = validatePrincipalBinding(state, input.principalBinding);
  if (!Array.isArray(input.evidence) || input.evidence.length < 1 || input.evidence.length > 256)
    throw new TypeError("EvidenceBundle.evidence is invalid");
  const evidence = input.evidence
    .map(normalizeEvidenceInput)
    .sort((left, right) => left.evidenceRef.localeCompare(right.evidenceRef));
  if (new Set(evidence.map((entry) => entry.evidenceRef)).size !== evidence.length) {
    throw new TypeError("EvidenceBundle.evidence contains duplicates");
  }
  const projection = {
    contractType: "EvidenceBundle",
    contractVersion: SHARED_CONTRACT_VERSION,
    digestRevision: contractDigestRevisions.EvidenceBundle,
    principalBindingSha256: binding.bindingSha256,
    evidence: Object.freeze(evidence),
  };
  return deepFreeze({ ...projection, bundleSha256: sha256Canonical(projection) });
}

function validateEvidenceBundle(state, value) {
  const fields = [
    "contractType",
    "contractVersion",
    "digestRevision",
    "principalBindingSha256",
    "evidence",
    "bundleSha256",
  ];
  const input = exactRecord(snapshotPlainData(value, "EvidenceBundle"), fields, fields, "EvidenceBundle");
  if (
    input.contractType !== "EvidenceBundle" ||
    input.contractVersion !== SHARED_CONTRACT_VERSION ||
    input.digestRevision !== contractDigestRevisions.EvidenceBundle ||
    input.principalBindingSha256 !== state.principalBinding.bindingSha256 ||
    !Array.isArray(input.evidence) ||
    input.evidence.length < 1 ||
    input.evidence.length > 256
  ) {
    throw new TypeError("EvidenceBundle contract is not supported");
  }
  const evidence = input.evidence.map(normalizeEvidenceRecord);
  if (evidence.some((entry, index) => index > 0 && evidence[index - 1].evidenceRef >= entry.evidenceRef)) {
    throw new TypeError("EvidenceBundle.evidence must be uniquely sorted");
  }
  const result = { ...input, evidence: Object.freeze(evidence) };
  digest(result.bundleSha256, "EvidenceBundle.bundleSha256");
  if (result.bundleSha256 !== sha256Canonical(evidenceBundleProjection(result))) {
    throw new TypeError("EvidenceBundle.bundleSha256 does not match");
  }
  return deepFreeze(result);
}

const workflowKinds = new Set([
  "meeting_prep",
  "post_meeting",
  "stale_revenue_digest",
  "goals_eod",
  "outreach_linkedin_demo",
  "marketing_plan",
  "marketing_draft",
]);
const workflowStates = new Set(["ready", "waiting", "unavailable", "failed", "superseded"]);

function workflowProjection(value) {
  const { artifactSha256: _artifactSha256, ...projection } = value;
  return projection;
}

function buildWorkflowArtifact(state, value) {
  const fields = [
    "principalBinding",
    "sourceLane",
    "sourceArtifactRef",
    "sourceArtifactSha256",
    "sourceRevision",
    "workflowKind",
    "state",
    "evidenceBundle",
    "updatedAt",
  ];
  const input = exactRecord(
    snapshotPlainData(value, "WorkflowArtifact input"),
    fields,
    fields,
    "WorkflowArtifact input",
  );
  const binding = validatePrincipalBinding(state, input.principalBinding);
  const evidenceBundle = validateEvidenceBundle(state, input.evidenceBundle);
  if (evidenceBundle.principalBindingSha256 !== binding.bindingSha256) {
    throw new TypeError("WorkflowArtifact evidence binding does not match");
  }
  const sourceLane = identifier(input.sourceLane, "WorkflowArtifact.sourceLane");
  if (typeof input.sourceArtifactRef !== "string" || !/^source:[a-f0-9]{64}$/u.test(input.sourceArtifactRef)) {
    throw new TypeError("WorkflowArtifact.sourceArtifactRef must be content addressed");
  }
  const sourceArtifactRef = input.sourceArtifactRef;
  const sourceArtifactSha256 = digest(input.sourceArtifactSha256, "WorkflowArtifact.sourceArtifactSha256");
  const sourceRevision = digest(input.sourceRevision, "WorkflowArtifact.sourceRevision");
  if (!workflowKinds.has(input.workflowKind) || !workflowStates.has(input.state)) {
    throw new TypeError("WorkflowArtifact kind or state is unsupported");
  }
  const artifactRef = `artifact:${sha256Canonical({
    digestRevision: contractDigestRevisions.WorkflowArtifact,
    principalBindingSha256: binding.bindingSha256,
    sourceLane,
    sourceArtifactRef,
    workflowKind: input.workflowKind,
  })}`;
  const revision = sha256Canonical({
    digestRevision: contractDigestRevisions.WorkflowArtifact,
    artifactRef,
    sourceArtifactSha256,
    sourceRevision,
    evidenceBundleSha256: evidenceBundle.bundleSha256,
  });
  const projection = {
    contractType: "WorkflowArtifact",
    contractVersion: SHARED_CONTRACT_VERSION,
    digestRevision: contractDigestRevisions.WorkflowArtifact,
    principalBindingSha256: binding.bindingSha256,
    artifactRef,
    revision,
    sourceLane,
    sourceArtifactRef,
    sourceArtifactSha256,
    sourceRevision,
    workflowKind: input.workflowKind,
    state: input.state,
    evidenceBundle,
    updatedAt: instant(input.updatedAt, "WorkflowArtifact.updatedAt"),
  };
  return deepFreeze({ ...projection, artifactSha256: sha256Canonical(projection) });
}

function validateWorkflowArtifact(state, value) {
  const fields = [
    "contractType",
    "contractVersion",
    "digestRevision",
    "principalBindingSha256",
    "artifactRef",
    "revision",
    "sourceLane",
    "sourceArtifactRef",
    "sourceArtifactSha256",
    "sourceRevision",
    "workflowKind",
    "state",
    "evidenceBundle",
    "updatedAt",
    "artifactSha256",
  ];
  const input = exactRecord(snapshotPlainData(value, "WorkflowArtifact"), fields, fields, "WorkflowArtifact");
  if (
    input.contractType !== "WorkflowArtifact" ||
    input.contractVersion !== SHARED_CONTRACT_VERSION ||
    input.digestRevision !== contractDigestRevisions.WorkflowArtifact ||
    input.principalBindingSha256 !== state.principalBinding.bindingSha256
  ) {
    throw new TypeError("WorkflowArtifact contract is not supported");
  }
  const rebuilt = buildWorkflowArtifact(state, {
    principalBinding: state.principalBinding,
    sourceLane: input.sourceLane,
    sourceArtifactRef: input.sourceArtifactRef,
    sourceArtifactSha256: input.sourceArtifactSha256,
    sourceRevision: input.sourceRevision,
    workflowKind: input.workflowKind,
    state: input.state,
    evidenceBundle: input.evidenceBundle,
    updatedAt: input.updatedAt,
  });
  for (const field of ["artifactRef", "revision", "artifactSha256"]) {
    if (input[field] !== rebuilt[field]) throw new TypeError(`WorkflowArtifact.${field} does not match`);
  }
  return rebuilt;
}

function evalProjection(value) {
  const { releaseSha256: _releaseSha256, ...projection } = value;
  return projection;
}

function buildEvalRelease(state, value) {
  const fields = [
    "principalBinding",
    "artifact",
    "candidateId",
    "evalAuthorityRef",
    "policyRef",
    "policySha256",
    "deterministicCheckIds",
    "judges",
    "evaluatedAt",
    "expiresAt",
  ];
  const input = exactRecord(snapshotPlainData(value, "EvalRelease input"), fields, fields, "EvalRelease input");
  const binding = validatePrincipalBinding(state, input.principalBinding);
  const artifact = validateWorkflowArtifact(state, input.artifact);
  if (artifact.principalBindingSha256 !== binding.bindingSha256)
    throw new TypeError("EvalRelease artifact binding does not match");
  const checks = sortedUnique(input.deterministicCheckIds, "EvalRelease.deterministicCheckIds", identifier, 1, 100);
  if (!Array.isArray(input.judges) || input.judges.length < 2 || input.judges.length > 10) {
    throw new TypeError("EvalRelease.judges must contain independent judges");
  }
  const judges = input.judges
    .map((entry, index) => {
      const item = exactRecord(
        entry,
        ["judgeRef", "independenceKey", "receiptSha256"],
        ["judgeRef", "independenceKey", "receiptSha256"],
        `EvalRelease.judges[${index}]`,
      );
      return Object.freeze({
        judgeRef: identifier(item.judgeRef, `EvalRelease.judges[${index}].judgeRef`),
        independenceKey: identifier(item.independenceKey, `EvalRelease.judges[${index}].independenceKey`),
        receiptSha256: digest(item.receiptSha256, `EvalRelease.judges[${index}].receiptSha256`),
      });
    })
    .sort((left, right) => left.judgeRef.localeCompare(right.judgeRef));
  if (
    new Set(judges.map((entry) => entry.judgeRef)).size !== judges.length ||
    new Set(judges.map((entry) => entry.independenceKey)).size !== judges.length ||
    new Set(judges.map((entry) => entry.receiptSha256)).size !== judges.length
  ) {
    throw new TypeError("EvalRelease judges must have unique identities and origins");
  }
  const evaluatedAt = instant(input.evaluatedAt, "EvalRelease.evaluatedAt");
  const expiresAt = instant(input.expiresAt, "EvalRelease.expiresAt");
  if (
    Date.parse(evaluatedAt) < Date.parse(artifact.updatedAt) ||
    Date.parse(expiresAt) <= Date.parse(evaluatedAt) ||
    Date.parse(expiresAt) - Date.parse(evaluatedAt) > 86_400_000
  ) {
    throw new TypeError("EvalRelease time bounds are invalid");
  }
  const projection = {
    contractType: "EvalRelease",
    contractVersion: SHARED_CONTRACT_VERSION,
    digestRevision: contractDigestRevisions.EvalRelease,
    deploymentProfileRef: binding.profileRef,
    deploymentProfileSha256: binding.profileSha256,
    principalBindingSha256: binding.bindingSha256,
    artifactRef: artifact.artifactRef,
    artifactRevision: artifact.revision,
    artifactSha256: artifact.artifactSha256,
    candidateId: identifier(input.candidateId, "EvalRelease.candidateId"),
    evalAuthorityRef: identifier(input.evalAuthorityRef, "EvalRelease.evalAuthorityRef"),
    policyRef: identifier(input.policyRef, "EvalRelease.policyRef"),
    policySha256: digest(input.policySha256, "EvalRelease.policySha256"),
    mode: "shadow",
    passed: true,
    release: true,
    sideEffectCount: 0,
    deterministicCheckIds: checks,
    judges: Object.freeze(judges),
    evaluatedAt,
    expiresAt,
  };
  return deepFreeze({ ...projection, releaseSha256: sha256Canonical(projection) });
}

function validateEvalRelease(state, value, artifactValue) {
  const fields = [
    "contractType",
    "contractVersion",
    "digestRevision",
    "deploymentProfileRef",
    "deploymentProfileSha256",
    "principalBindingSha256",
    "artifactRef",
    "artifactRevision",
    "artifactSha256",
    "candidateId",
    "evalAuthorityRef",
    "policyRef",
    "policySha256",
    "mode",
    "passed",
    "release",
    "sideEffectCount",
    "deterministicCheckIds",
    "judges",
    "evaluatedAt",
    "expiresAt",
    "releaseSha256",
  ];
  const input = exactRecord(snapshotPlainData(value, "EvalRelease"), fields, fields, "EvalRelease");
  const artifact = validateWorkflowArtifact(state, artifactValue);
  if (
    input.contractType !== "EvalRelease" ||
    input.contractVersion !== SHARED_CONTRACT_VERSION ||
    input.digestRevision !== contractDigestRevisions.EvalRelease ||
    input.deploymentProfileRef !== state.identity.profileRef ||
    input.deploymentProfileSha256 !== state.identity.profileSha256 ||
    input.mode !== "shadow" ||
    input.passed !== true ||
    input.release !== true ||
    input.sideEffectCount !== 0
  ) {
    throw new TypeError("EvalRelease contract is not supported");
  }
  const rebuilt = buildEvalRelease(state, {
    principalBinding: state.principalBinding,
    artifact,
    candidateId: input.candidateId,
    evalAuthorityRef: input.evalAuthorityRef,
    policyRef: input.policyRef,
    policySha256: input.policySha256,
    deterministicCheckIds: input.deterministicCheckIds,
    judges: input.judges,
    evaluatedAt: input.evaluatedAt,
    expiresAt: input.expiresAt,
  });
  if (sha256Canonical(input) !== sha256Canonical(rebuilt)) throw new TypeError("EvalRelease bindings do not match");
  return rebuilt;
}

const publicationSurfaces = Object.freeze(["slack", "qm", "notion"]);

function deriveOutboxEventId(state, value) {
  const fields = [
    "profileRef",
    "profileSha256",
    "deploymentRef",
    "principalRef",
    "artifactRef",
    "revision",
    "surface",
    "audienceRef",
  ];
  const input = exactRecord(snapshotPlainData(value, "OutboxEvent identity"), fields, fields, "OutboxEvent identity");
  const { profileRef, profileSha256, deploymentRef, principalRef, artifactRef, revision, surface, audienceRef } = input;
  if (
    profileRef !== state.identity.profileRef ||
    profileSha256 !== state.identity.profileSha256 ||
    deploymentRef !== state.identity.deploymentRef ||
    principalRef !== state.identity.principalRef ||
    audienceRef !== state.identity.audienceRef
  ) {
    throw new TypeError("OutboxEvent identity does not match the deployment profile");
  }
  identifier(artifactRef, "OutboxEvent.artifactRef");
  digest(revision, "OutboxEvent.revision");
  if (!publicationSurfaces.includes(surface)) throw new TypeError("OutboxEvent.surface is unsupported");
  return `event:${sha256Canonical({
    digestRevision: contractDigestRevisions.OutboxEvent,
    profileRef,
    profileSha256,
    deploymentRef,
    principalRef,
    artifactRef,
    revision,
    surface,
    audienceRef,
  })}`;
}

function outboxProjection(value) {
  const { eventSha256: _eventSha256, ...projection } = value;
  return projection;
}

function buildOutboxEvent(state, value) {
  const fields = ["principalBinding", "artifact", "evalRelease", "surface", "queuedAt"];
  const input = exactRecord(snapshotPlainData(value, "OutboxEvent input"), fields, fields, "OutboxEvent input");
  const binding = validatePrincipalBinding(state, input.principalBinding);
  const artifact = validateWorkflowArtifact(state, input.artifact);
  const evalRelease = validateEvalRelease(state, input.evalRelease, artifact);
  if (
    artifact.principalBindingSha256 !== binding.bindingSha256 ||
    evalRelease.principalBindingSha256 !== binding.bindingSha256
  ) {
    throw new TypeError("OutboxEvent principal binding does not match");
  }
  if (!publicationSurfaces.includes(input.surface)) throw new TypeError("OutboxEvent.surface is unsupported");
  const queuedAt = instant(input.queuedAt, "OutboxEvent.queuedAt");
  if (Date.parse(queuedAt) < Date.parse(evalRelease.evaluatedAt))
    throw new TypeError("OutboxEvent predates evaluation");
  const eventId = deriveOutboxEventId(state, {
    profileRef: binding.profileRef,
    profileSha256: binding.profileSha256,
    deploymentRef: binding.deploymentRef,
    principalRef: binding.principalRef,
    artifactRef: artifact.artifactRef,
    revision: artifact.revision,
    surface: input.surface,
    audienceRef: binding.audienceRef,
  });
  const projection = {
    contractType: "OutboxEvent",
    contractVersion: SHARED_CONTRACT_VERSION,
    digestRevision: contractDigestRevisions.OutboxEvent,
    eventId,
    profileRef: binding.profileRef,
    profileSha256: binding.profileSha256,
    principalBindingSha256: binding.bindingSha256,
    deploymentRef: binding.deploymentRef,
    principalRef: binding.principalRef,
    audienceRef: binding.audienceRef,
    surface: input.surface,
    artifact,
    evalRelease,
    queuedAt,
  };
  return deepFreeze({ ...projection, eventSha256: sha256Canonical(projection) });
}

function validateOutboxEvent(state, value) {
  const fields = [
    "contractType",
    "contractVersion",
    "digestRevision",
    "eventId",
    "profileRef",
    "profileSha256",
    "principalBindingSha256",
    "deploymentRef",
    "principalRef",
    "audienceRef",
    "surface",
    "artifact",
    "evalRelease",
    "queuedAt",
    "eventSha256",
  ];
  const input = exactRecord(snapshotPlainData(value, "OutboxEvent"), fields, fields, "OutboxEvent");
  if (
    input.contractType !== "OutboxEvent" ||
    input.contractVersion !== SHARED_CONTRACT_VERSION ||
    input.digestRevision !== contractDigestRevisions.OutboxEvent
  ) {
    throw new TypeError("OutboxEvent contract is not supported");
  }
  const rebuilt = buildOutboxEvent(state, {
    principalBinding: state.principalBinding,
    artifact: input.artifact,
    evalRelease: input.evalRelease,
    surface: input.surface,
    queuedAt: input.queuedAt,
  });
  if (sha256Canonical(input) !== sha256Canonical(rebuilt)) throw new TypeError("OutboxEvent bindings do not match");
  return rebuilt;
}

function publicationProjection(value) {
  const { envelopeSha256: _envelopeSha256, ...projection } = value;
  return projection;
}

function canonicalPublicationPayload(event) {
  return deepFreeze({
    schemaVersion: 1,
    surface: event.surface,
    audienceRef: event.audienceRef,
    artifactRef: event.artifact.artifactRef,
    artifactRevision: event.artifact.revision,
    artifactSha256: event.artifact.artifactSha256,
    evalReleaseSha256: event.evalRelease.releaseSha256,
    evidenceBundleSha256: event.artifact.evidenceBundle.bundleSha256,
    evidenceCount: event.artifact.evidenceBundle.evidence.length,
    evidence: event.artifact.evidenceBundle.evidence.map((entry) => ({
      evidenceRef: entry.evidenceRef,
      status: entry.status,
      trust: entry.trust,
      availability: entry.availability,
    })),
    actionless: true,
  });
}

function buildPublicationEnvelope(state, value) {
  const fields = ["outboxEvent"];
  const input = exactRecord(
    snapshotPlainData(value, "PublicationEnvelope input"),
    fields,
    fields,
    "PublicationEnvelope input",
  );
  const event = validateOutboxEvent(state, input.outboxEvent);
  const payload = canonicalPublicationPayload(event);
  const payloadSha256 = sha256Canonical(payload);
  const deliveryIdentitySha256 = sha256Canonical({
    digestRevision: contractDigestRevisions.PublicationEnvelope,
    profileRef: event.profileRef,
    profileSha256: event.profileSha256,
    deploymentRef: event.deploymentRef,
    principalRef: event.principalRef,
    artifactRef: event.artifact.artifactRef,
    revision: event.artifact.revision,
    surface: event.surface,
    audienceRef: event.audienceRef,
  });
  const projection = {
    contractType: "PublicationEnvelope",
    contractVersion: SHARED_CONTRACT_VERSION,
    digestRevision: contractDigestRevisions.PublicationEnvelope,
    eventId: event.eventId,
    profileRef: event.profileRef,
    profileSha256: event.profileSha256,
    eventSha256: event.eventSha256,
    principalBindingSha256: event.principalBindingSha256,
    deploymentRef: event.deploymentRef,
    principalRef: event.principalRef,
    audienceRef: event.audienceRef,
    surface: event.surface,
    artifactRef: event.artifact.artifactRef,
    artifactRevision: event.artifact.revision,
    artifactSha256: event.artifact.artifactSha256,
    evalReleaseSha256: event.evalRelease.releaseSha256,
    deliveryIdentitySha256,
    actionless: true,
    providerInvocationAllowed: false,
    payload,
    payloadSha256,
  };
  return deepFreeze({ ...projection, envelopeSha256: sha256Canonical(projection) });
}

function validatePublicationEnvelope(state, value, eventValue) {
  const fields = [
    "contractType",
    "contractVersion",
    "digestRevision",
    "eventId",
    "profileRef",
    "profileSha256",
    "eventSha256",
    "principalBindingSha256",
    "deploymentRef",
    "principalRef",
    "audienceRef",
    "surface",
    "artifactRef",
    "artifactRevision",
    "artifactSha256",
    "evalReleaseSha256",
    "deliveryIdentitySha256",
    "actionless",
    "providerInvocationAllowed",
    "payload",
    "payloadSha256",
    "envelopeSha256",
  ];
  const input = exactRecord(snapshotPlainData(value, "PublicationEnvelope"), fields, fields, "PublicationEnvelope");
  const event = validateOutboxEvent(state, eventValue);
  if (
    input.contractType !== "PublicationEnvelope" ||
    input.contractVersion !== SHARED_CONTRACT_VERSION ||
    input.digestRevision !== contractDigestRevisions.PublicationEnvelope ||
    input.actionless !== true ||
    input.providerInvocationAllowed !== false ||
    input.profileRef !== state.identity.profileRef ||
    input.profileSha256 !== state.identity.profileSha256 ||
    input.principalBindingSha256 !== state.principalBinding.bindingSha256 ||
    input.deploymentRef !== state.identity.deploymentRef ||
    input.principalRef !== state.identity.principalRef ||
    input.audienceRef !== state.identity.audienceRef ||
    !publicationSurfaces.includes(input.surface) ||
    !/^artifact:[a-f0-9]{64}$/u.test(input.artifactRef)
  ) {
    throw new TypeError("PublicationEnvelope contract is not supported");
  }
  for (const field of [
    "eventSha256",
    "artifactRevision",
    "artifactSha256",
    "evalReleaseSha256",
    "deliveryIdentitySha256",
    "payloadSha256",
  ]) {
    digest(input[field], `PublicationEnvelope.${field}`);
  }
  digest(input.envelopeSha256, "PublicationEnvelope.envelopeSha256");
  if (
    input.payloadSha256 !== sha256Canonical(input.payload) ||
    input.envelopeSha256 !== sha256Canonical(publicationProjection(input))
  ) {
    throw new TypeError("PublicationEnvelope digest does not match");
  }
  const expectedEventId = deriveOutboxEventId(state, {
    profileRef: input.profileRef,
    profileSha256: input.profileSha256,
    deploymentRef: input.deploymentRef,
    principalRef: input.principalRef,
    artifactRef: input.artifactRef,
    revision: input.artifactRevision,
    surface: input.surface,
    audienceRef: input.audienceRef,
  });
  if (input.eventId !== expectedEventId) throw new TypeError("PublicationEnvelope event identity does not match");
  const expectedDeliveryIdentity = sha256Canonical({
    digestRevision: contractDigestRevisions.PublicationEnvelope,
    profileRef: input.profileRef,
    profileSha256: input.profileSha256,
    deploymentRef: input.deploymentRef,
    principalRef: input.principalRef,
    artifactRef: input.artifactRef,
    revision: input.artifactRevision,
    surface: input.surface,
    audienceRef: input.audienceRef,
  });
  if (input.deliveryIdentitySha256 !== expectedDeliveryIdentity) {
    throw new TypeError("PublicationEnvelope delivery identity does not match");
  }
  const rebuilt = buildPublicationEnvelope(state, { outboxEvent: event });
  if (sha256Canonical(input) !== sha256Canonical(rebuilt)) {
    throw new TypeError("PublicationEnvelope is not derived from the canonical event");
  }
  return rebuilt;
}

export function createSharedContractSuite(profile) {
  const authority = assertProfileAuthority(profile);
  const identity = identityFromProfile(authority);
  const state = { authority, identity, principalBinding: null };
  state.principalBinding = buildPrincipalBinding(state);
  const PrincipalBinding = Object.freeze({
    version: PRINCIPAL_BINDING_VERSION,
    digestRevision: contractDigestRevisions.PrincipalBinding,
    identity,
    value: state.principalBinding,
    create: () => buildPrincipalBinding(state),
    validate: (value) => validatePrincipalBinding(state, value),
    snapshot: snapshotPlainData,
    hash: sha256Canonical,
    freeze: deepFreeze,
  });
  const EvidenceBundle = Object.freeze({
    version: SHARED_CONTRACT_VERSION,
    digestRevision: contractDigestRevisions.EvidenceBundle,
    create: (value) => buildEvidenceBundle(state, value),
    validate: (value) => validateEvidenceBundle(state, value),
  });
  const WorkflowArtifact = Object.freeze({
    version: SHARED_CONTRACT_VERSION,
    digestRevision: contractDigestRevisions.WorkflowArtifact,
    create: (value) => buildWorkflowArtifact(state, value),
    validate: (value) => validateWorkflowArtifact(state, value),
  });
  const EvalRelease = Object.freeze({
    version: SHARED_CONTRACT_VERSION,
    digestRevision: contractDigestRevisions.EvalRelease,
    validate: (value, artifact) => validateEvalRelease(state, value, artifact),
  });
  const OutboxEvent = Object.freeze({
    version: SHARED_CONTRACT_VERSION,
    digestRevision: contractDigestRevisions.OutboxEvent,
    surfaces: publicationSurfaces,
    create: (value) => buildOutboxEvent(state, value),
    validate: (value) => validateOutboxEvent(state, value),
    deriveId: (value) => deriveOutboxEventId(state, value),
  });
  const PublicationEnvelope = Object.freeze({
    version: SHARED_CONTRACT_VERSION,
    digestRevision: contractDigestRevisions.PublicationEnvelope,
    create: (value) => buildPublicationEnvelope(state, value),
    validate: (value, event) => validatePublicationEnvelope(state, value, event),
  });
  return deepFreeze({
    profile: authority,
    PrincipalBinding,
    EvidenceBundle,
    WorkflowArtifact,
    EvalRelease,
    OutboxEvent,
    PublicationEnvelope,
  });
}

const ceoSharedContractSuite = createSharedContractSuite(ceoDeploymentProfile);

export const PrincipalBinding = ceoSharedContractSuite.PrincipalBinding;
export const EvidenceBundle = ceoSharedContractSuite.EvidenceBundle;
export const WorkflowArtifact = ceoSharedContractSuite.WorkflowArtifact;
export const EvalRelease = ceoSharedContractSuite.EvalRelease;
export const OutboxEvent = ceoSharedContractSuite.OutboxEvent;
export const PublicationEnvelope = ceoSharedContractSuite.PublicationEnvelope;
