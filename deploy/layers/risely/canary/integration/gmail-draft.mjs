import { buildActionProposal } from "../contracts/index.mjs";
import { createProposalContractSuite } from "../proposal-contracts/index.mjs";
import { ceoDeploymentProfile } from "../deployment-profiles/index.mjs";
import { assertRuntimeScope, createRuntimeScope } from "../runtime-scope/index.mjs";

const sourceMap = Object.freeze({
  calendar: "calendar",
  gmail: "gmail",
  clarify: "clarify",
  command_center_brain: "brain",
  notion: "notion",
});

function instant(value, label) {
  if (typeof value !== "string" || new Date(value).toISOString() !== value) throw new TypeError(`${label} is invalid`);
  return value;
}

function text(value, label, maximum) {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > maximum ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function email(value) {
  if (typeof value !== "string" || value !== value.toLowerCase() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(value)) {
    throw new TypeError("Gmail draft recipient is invalid");
  }
  return value;
}

function buildScopedDormantGmailDraftProposal(runtimeScope, value) {
  const scope = assertRuntimeScope(runtimeScope);
  const { PrincipalBinding, WorkflowArtifact } = scope.contracts;
  const proposalContracts = createProposalContractSuite(scope);
  const input = PrincipalBinding.snapshot(value, "Gmail draft proposal input");
  const fields = ["artifact", "recipients", "subject", "body", "createdAt", "expiresAt"];
  if (
    !input ||
    Array.isArray(input) ||
    Object.keys(input).some((field) => !fields.includes(field)) ||
    fields.some((field) => !Object.hasOwn(input, field))
  ) {
    throw new TypeError("Gmail draft proposal input has an unsupported shape");
  }
  const artifact = WorkflowArtifact.validate(input.artifact);
  const recipients = [...input.recipients].map(email).sort();
  if (recipients.length < 1 || recipients.length > 20 || new Set(recipients).size !== recipients.length) {
    throw new TypeError("Gmail draft recipients are invalid");
  }
  const createdAt = instant(input.createdAt, "Gmail draft createdAt");
  const expiresAt = instant(input.expiresAt, "Gmail draft expiresAt");
  if (
    Date.parse(expiresAt) <= Date.parse(createdAt) ||
    Date.parse(expiresAt) - Date.parse(createdAt) > scope.profile.grantPolicy.maximumApprovalLifetimeMs
  ) {
    throw new TypeError("Gmail draft lifetime is invalid");
  }
  const identity = PrincipalBinding.identity;
  const providerOwnerRef = scope.profile.providerOwners.find((entry) => entry.provider === "google")?.providerOwnerRef;
  if (!providerOwnerRef) throw new TypeError("Google provider owner is unavailable");
  const actor = {
    contractType: "actor",
    contractVersion: 1,
    principalRef: identity.principalRef,
    qmPrincipalId: identity.qmPrincipalRef,
    externalPrincipalRef: scope.profile.identity.externalIdentityRef,
    agent: { id: identity.agentId, version: identity.agentVersion },
    surface: "system",
    scopeRef: scope.profile.anchors.principalBindingRef,
    audienceRef: identity.audienceRef,
    credentialOwnerRef: identity.credentialOwnerRef,
  };
  const evidenceRefs = artifact.evidenceBundle.evidence.map((entry) => {
    const source = sourceMap[entry.source];
    if (!source) throw new TypeError("Gmail draft evidence source is not approved by the dormant domain");
    return {
      contractType: "evidence-ref",
      contractVersion: 1,
      evidenceId: entry.evidenceRef,
      source,
      sourceRecordRef: entry.sourceRecordRef,
      observedAt: entry.observedAt,
      fetchedAt: entry.fetchedAt,
      contentSha256: entry.contentSha256,
      audienceRef: identity.audienceRef,
      sensitivity: "commercial",
      trust: "untrusted_external",
    };
  });
  const target = {
    providerOwnerRef,
    mailbox: identity.principalEmail,
    to: recipients,
  };
  const subject = text(input.subject, "Gmail draft subject", 200);
  const body = text(input.body, "Gmail draft body", 100_000);
  const evidenceSha256 = PrincipalBinding.hash(evidenceRefs);
  const payload = {
    body,
    evidenceSha256,
    payloadSha256: PrincipalBinding.hash({ target, payload: { body, evidenceSha256, subject } }),
    subject,
  };
  const proposal = buildActionProposal({
    contractType: "action-proposal",
    contractVersion: 1,
    proposalId: `proposal:${PrincipalBinding.hash({ artifactRef: artifact.artifactRef, artifactRevision: artifact.revision, target, payload })}`,
    runId: `run:${PrincipalBinding.hash({ artifactRef: artifact.artifactRef, artifactRevision: artifact.revision, createdAt })}`,
    actor,
    capability: "google.gmail.drafts.create",
    capabilityVersion: 1,
    provider: "google",
    credentialRef: identity.credentialOwnerRef,
    subjectRef: artifact.artifactRef,
    target,
    payload,
    artifactRefs: [{ artifactId: artifact.artifactRef, sha256: artifact.artifactSha256 }],
    evidenceRefs,
    capturedState: {},
    preconditions: [],
    createdAt,
    expiresAt,
  });
  const authority = {
    principalRef: identity.principalRef,
    qmPrincipalId: identity.qmPrincipalRef,
    externalPrincipalRef: scope.profile.identity.externalIdentityRef,
    agentId: identity.agentId,
    agentVersion: identity.agentVersion,
    scopeRef: scope.profile.anchors.principalBindingRef,
    audienceRef: identity.audienceRef,
    credentialOwnerRef: identity.credentialOwnerRef,
  };
  return PrincipalBinding.freeze({
    proposal: proposalContracts.assertDormantGmailDraftProposal(proposal, authority),
    executionAvailable: proposalContracts.providerExecutionAvailable,
  });
}

export function createDormantGmailDraftProposalCompiler(runtimeScope) {
  const scope = assertRuntimeScope(runtimeScope);
  if (
    !scope.profile.allowedCapabilities.includes("google.gmail.drafts.create") ||
    !scope.profile.providerOwners.some((entry) => entry.provider === "google")
  ) {
    throw new TypeError("Deployment profile does not support dormant Gmail draft proposals");
  }
  return Object.freeze({
    runtimeScope: scope,
    build: (value) => buildScopedDormantGmailDraftProposal(scope, value),
    providerExecutionAllowed: false,
  });
}

export const ceoDormantGmailDraftProposalCompiler = createDormantGmailDraftProposalCompiler(
  createRuntimeScope(ceoDeploymentProfile),
);
export const buildDormantGmailDraftProposal = ceoDormantGmailDraftProposalCompiler.build;
