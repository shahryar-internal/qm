import { buildActionProposal, sha256Canonical } from "../../canary/contracts/index.mjs";

export const HASH_A = "a".repeat(64);
export const HASH_B = "b".repeat(64);

export function actor(overrides = {}) {
  return {
    contractType: "actor",
    contractVersion: 1,
    principalRef: "principal:ceo",
    qmPrincipalId: "qm:principal:ceo-canary",
    externalPrincipalRef: "external-identity:risely:ceo",
    agent: { id: "agent:risely:ceo-team", version: "1.0.0" },
    surface: "slack",
    scopeRef: "principal-binding:risely:ceo:v1",
    audienceRef: "slack-audience:ceo-private",
    credentialOwnerRef: "credential-owner:ceo",
    ...overrides,
  };
}

export function evidenceRef(overrides = {}) {
  return {
    contractType: "evidence-ref",
    contractVersion: 1,
    evidenceId: "evidence:meeting-1",
    source: "clarify",
    sourceRecordRef: "clarify:meeting-1",
    sourceUrl: "https://example.invalid/meeting-1",
    observedAt: "2026-08-26T09:00:00Z",
    fetchedAt: "2026-08-26T10:00:00Z",
    contentSha256: HASH_A,
    audienceRef: "slack-audience:ceo-private",
    sensitivity: "customer",
    trust: "untrusted_external",
    ...overrides,
  };
}

export function artifact(overrides = {}) {
  return {
    contractType: "artifact",
    contractVersion: 1,
    artifactId: "artifact:follow-up-1",
    kind: "email-draft",
    runId: "run:1",
    ownerScopeRef: "principal-binding:risely:ceo:v1",
    audienceRef: "slack-audience:ceo-private",
    storageRef: "s3:objects/artifact-1",
    mediaType: "text/plain",
    sizeBytes: 128,
    sha256: HASH_B,
    evidenceIds: ["evidence:meeting-1"],
    createdAt: "2026-08-26T10:00:01Z",
    ...overrides,
  };
}

export function run(overrides = {}) {
  return {
    contractType: "run",
    contractVersion: 1,
    runId: "run:1",
    sessionId: "session:1",
    actor: actor(),
    trigger: "human",
    agentVersion: "1.0.0",
    policySnapshotHash: HASH_A,
    inputHash: HASH_B,
    startedAt: "2026-08-26T10:00:00Z",
    ...overrides,
  };
}

export function workflowArtifact(overrides = {}) {
  return {
    contractType: "workflow-artifact",
    contractVersion: 1,
    workflowArtifactId: "workflow-artifact:1",
    runId: "run:1",
    workflow: "sales-deal-follow-up",
    title: "Meeting follow-up",
    status: "draft",
    artifact: artifact(),
    evidenceRefs: [evidenceRef()],
    createdAt: "2026-08-26T10:00:02Z",
    ...overrides,
  };
}

export function actionProposalInput(overrides = {}) {
  const base = {
    contractType: "action-proposal",
    contractVersion: 1,
    proposalId: "proposal:1",
    runId: "run:1",
    actor: actor(),
    capability: "google.gmail.drafts.create",
    capabilityVersion: 1,
    provider: "google",
    credentialRef: "credential-owner:ceo",
    subjectRef: "thread:customer-1",
    target: {
      providerOwnerRef: "provider-owner:google:ceo",
      mailbox: "shahryar@risely.ai",
      to: ["customer@example.com"],
    },
    payload: {
      subject: "Follow-up",
      body: "Thanks for your time.",
      evidenceSha256: sha256Canonical([evidenceRef()]),
    },
    artifactRefs: [{ artifactId: "artifact:follow-up-1", sha256: HASH_B }],
    evidenceRefs: [evidenceRef()],
    capturedState: { latestMessageId: "message:before-1" },
    preconditions: [{ kind: "no-new-reply", threadRef: "thread:customer-1" }],
    createdAt: "2026-08-26T10:00:00Z",
    expiresAt: "2099-08-26T11:00:00Z",
  };
  const merged = {
    ...base,
    ...overrides,
    target: { ...base.target, ...(overrides.target ?? {}) },
    payload: { ...base.payload, ...(overrides.payload ?? {}) },
  };
  merged.payload.evidenceSha256 = sha256Canonical(merged.evidenceRefs);
  merged.payload.payloadSha256 = sha256Canonical({
    target: merged.target,
    payload: {
      body: merged.payload.body,
      evidenceSha256: merged.payload.evidenceSha256,
      subject: merged.payload.subject,
    },
  });
  return merged;
}

export function actionProposal(overrides = {}) {
  return buildActionProposal(actionProposalInput(overrides));
}

export function approval(proposal, decision = "approve_once", overrides = {}) {
  return {
    contractType: "approval",
    contractVersion: 1,
    approvalId: `approval:${decision}`,
    proposalId: proposal.proposalId,
    proposalHash: proposal.proposalHash,
    decision,
    approverPrincipalRef: "principal:ceo",
    surface: "slack",
    decidedAt: "2026-08-26T10:01:00Z",
    expiresAt: "2098-08-26T11:00:00Z",
    ...overrides,
  };
}

export function receipt(proposal, status = "verified", overrides = {}) {
  return {
    contractType: "receipt",
    contractVersion: 1,
    receiptId: `receipt:${status}`,
    proposalId: proposal.proposalId,
    proposalHash: proposal.proposalHash,
    effectKey: proposal.effectKey,
    claimId: "claim:1",
    credentialRef: proposal.credentialRef,
    status,
    provider: "google",
    providerAccountRef: proposal.target.providerOwnerRef,
    providerOperationIds: status === "verified" ? { draftId: "gmail:draft-1" } : {},
    attemptedAt: "2026-08-26T10:02:30Z",
    ...(status === "outcome_unknown" ? {} : { completedAt: "2026-08-26T10:02:31Z" }),
    responseHash: HASH_A,
    preflightResults: { accountMatched: true, noNewReply: true },
    ...(status === "verified" ? {} : { errorCode: status }),
    ...overrides,
  };
}
