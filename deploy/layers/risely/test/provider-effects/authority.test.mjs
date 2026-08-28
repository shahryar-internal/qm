import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { buildActionProposal } from "../../canary/contracts/index.mjs";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import {
  createProviderEffectExecutionAuthority,
  inspectProviderEffectProductionReadiness,
  providerEffectProductionPortContract,
} from "../../canary/provider-effects/authority.mjs";
import * as productionAuthority from "../../canary/provider-effects/authority.mjs";
import { createProviderEffectPolicySuite } from "../../canary/provider-effects/index.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import { canonicalJson } from "../../canary/shared-contracts/validation.mjs";
import { createInertProviderEffectExecutionAuthorityForTesting } from "./testing.mjs";

const runtimeScope = createRuntimeScope(ceoDeploymentProfile);
const suite = createProviderEffectPolicySuite(runtimeScope);
const hash = runtimeScope.contracts.PrincipalBinding.hash;
const proofClasses = [
  "kill_switch",
  "evaluation_release",
  "provider_identity",
  "resource_ownership",
  "approval",
  "reconciliation_identity",
  "durable_receipt",
];
const proofSigners = new Map(
  proofClasses.map((proofClass) => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    return [
      proofClass,
      {
        privateKey,
        issuer: {
          keyId: `proof-key:${proofClass}:test`,
          issuerRef: `proof-issuer:${proofClass}:test`,
          proofClass,
          capabilities: suite.capabilities,
          publicKey: publicKey.export({ format: "jwk" }),
        },
      },
    ];
  }),
);
const trustedProofIssuers = [...proofSigners.values()].map((entry) => entry.issuer);
const reconcilerPrincipalRef = "reconciler:provider-effects:test";
const allowedReconcilerPrincipals = suite.capabilities.map((capability) => ({
  capability,
  reconcilerPrincipalRef: `${reconcilerPrincipalRef}:${capability}`,
}));
const actor = {
  contractType: "actor",
  contractVersion: 1,
  principalRef: runtimeScope.domainAuthority.principalRef,
  qmPrincipalId: runtimeScope.domainAuthority.qmPrincipalId,
  externalPrincipalRef: runtimeScope.domainAuthority.externalPrincipalRef,
  agent: {
    id: runtimeScope.domainAuthority.agentId,
    version: runtimeScope.domainAuthority.agentVersion,
  },
  surface: "system",
  scopeRef: runtimeScope.domainAuthority.scopeRef,
  audienceRef: runtimeScope.domainAuthority.audienceRef,
  credentialOwnerRef: runtimeScope.domainAuthority.credentialOwnerRef,
};

const withHash = (value, field) => {
  const projection = structuredClone(value);
  delete projection[field];
  return { ...value, [field]: hash(projection) };
};

const signedProof = (value, digestField, proofClass) => {
  const signer = proofSigners.get(proofClass);
  const record = {
    ...value,
    keyId: signer.issuer.keyId,
    issuerRef: signer.issuer.issuerRef,
    signature: "",
  };
  const hashProjection = structuredClone(record);
  delete hashProjection[digestField];
  delete hashProjection.signature;
  record[digestField] = hash(hashProjection);
  const signingProjection = structuredClone(record);
  delete signingProjection.signature;
  return {
    ...record,
    signature: sign(null, Buffer.from(canonicalJson(signingProjection), "utf8"), signer.privateKey).toString(
      "base64url",
    ),
  };
};

const gmailDraftProposal = () => {
  const target = {
    providerOwnerRef: "provider-owner:google:ceo",
    mailbox: ceoDeploymentProfile.identity.humanEmail,
    to: ["recipient@example.com"],
  };
  const subject = "Provider effect authority test";
  const body = "A bounded test draft.";
  const evidenceSha256 = hash([]);
  return buildActionProposal({
    contractType: "action-proposal",
    contractVersion: 1,
    proposalId: "proposal:provider-effect-authority-test",
    runId: "run:provider-effect-authority-test",
    actor,
    capability: "google.gmail.drafts.create",
    capabilityVersion: 1,
    provider: "google",
    credentialRef: actor.credentialOwnerRef,
    subjectRef: "artifact:provider-effect-authority-test",
    target,
    payload: {
      body,
      evidenceSha256,
      payloadSha256: hash({ target, payload: { body, evidenceSha256, subject } }),
      subject,
    },
    artifactRefs: [{ artifactId: "artifact:provider-effect-authority-test", sha256: "a".repeat(64) }],
    evidenceRefs: [],
    capturedState: {},
    preconditions: [],
    createdAt: "2026-08-27T20:00:00.000Z",
    expiresAt: "2026-08-27T20:05:00.000Z",
  });
};

const gmailSendProposal = () => {
  const revision = "9".repeat(64);
  return buildActionProposal({
    contractType: "action-proposal",
    contractVersion: 1,
    proposalId: "proposal:provider-effect-send-test",
    runId: "run:provider-effect-authority-test",
    actor,
    capability: "google.gmail.drafts.send",
    capabilityVersion: 1,
    provider: "google",
    credentialRef: actor.credentialOwnerRef,
    subjectRef: "artifact:provider-effect-authority-test",
    target: {
      providerOwnerRef: "provider-owner:google:ceo",
      mailbox: ceoDeploymentProfile.identity.humanEmail,
      draftId: "gmail-draft:managed-test",
      draftRevisionSha256: revision,
    },
    payload: { expectedContentSha256: revision },
    artifactRefs: [{ artifactId: "artifact:provider-effect-authority-test", sha256: "a".repeat(64) }],
    evidenceRefs: [],
    capturedState: {},
    preconditions: [],
    createdAt: "2026-08-27T20:00:00.000Z",
    expiresAt: "2026-08-27T20:05:00.000Z",
  });
};

const authorizationFor = (proposal, overrides = {}) => {
  const checked = suite.assertProposal(proposal);
  const policy = checked.policy;
  const databaseNow = "2026-08-27T20:01:00.000Z";
  const killSwitch = signedProof(
    {
      profileRef: runtimeScope.profileRef,
      profileSha256: runtimeScope.profileSha256,
      engaged: false,
      revision: 7,
      checkedAt: databaseNow,
      stateSha256: "",
    },
    "stateSha256",
    "kill_switch",
  );
  const evaluationRelease = signedProof(
    {
      releaseId: "evaluation-release:provider-effect-test",
      releaseSha256: "",
      profileRef: runtimeScope.profileRef,
      profileSha256: runtimeScope.profileSha256,
      proposalHash: proposal.proposalHash,
      intentSha256: checked.intent.intentSha256,
      policySha256: policy.policySha256,
      passed: true,
      providerReleaseEligible: true,
      evaluatedAt: "2026-08-27T20:00:30.000Z",
      expiresAt: "2026-08-27T20:04:00.000Z",
    },
    "releaseSha256",
    "evaluation_release",
  );
  const providerIdentity = signedProof(
    {
      receiptId: "provider-identity:google:ceo:test",
      receiptSha256: "",
      verificationSha256: "b".repeat(64),
      profileRef: runtimeScope.profileRef,
      profileSha256: runtimeScope.profileSha256,
      provider: policy.provider,
      providerOwnerRef: policy.providerOwnerRef,
      providerAccountRef: "google-account:ceo:test",
      credentialOwnerRef: proposal.actor.credentialOwnerRef,
      verifiedBy: proofSigners.get("provider_identity").issuer.issuerRef,
      verifiedAt: "2026-08-27T20:00:20.000Z",
      expiresAt: "2026-08-27T20:04:00.000Z",
    },
    "receiptSha256",
    "provider_identity",
  );
  const resourceOwnership = signedProof(
    {
      receiptId: "provider-resource:google:mailbox:test",
      receiptSha256: "",
      verificationSha256: "c".repeat(64),
      profileRef: runtimeScope.profileRef,
      profileSha256: runtimeScope.profileSha256,
      provider: policy.provider,
      providerOwnerRef: policy.providerOwnerRef,
      providerAccountRef: providerIdentity.providerAccountRef,
      targetClass: policy.targetClass,
      resourceKey: hash({
        digestRevision: "ProviderEffectTargetBinding.sha256.v1",
        targetClass: policy.targetClass,
        target: proposal.target,
      }),
      providerResourceRef: "google-mailbox:ceo:test",
      verifiedBy: proofSigners.get("resource_ownership").issuer.issuerRef,
      verifiedAt: "2026-08-27T20:00:25.000Z",
      expiresAt: "2026-08-27T20:04:00.000Z",
    },
    "receiptSha256",
    "resource_ownership",
  );
  return {
    profileRef: runtimeScope.profileRef,
    profileSha256: runtimeScope.profileSha256,
    proposal,
    intentSha256: checked.intent.intentSha256,
    prospectiveEffectKey: checked.intent.prospectiveEffectKey,
    policyRef: policy.policyRef,
    policySha256: policy.policySha256,
    capability: policy.capability,
    capabilityVersion: policy.capabilityVersion,
    provider: policy.provider,
    operation: policy.operation,
    providerOwnerRef: policy.providerOwnerRef,
    revision: 4,
    attempts: 0,
    databaseNow,
    killSwitch,
    evaluationRelease,
    providerIdentity,
    resourceOwnership,
    approval: null,
    ...overrides,
  };
};

const attemptFor = (authorization) => ({
  profileRef: authorization.profileRef,
  profileSha256: authorization.profileSha256,
  proposalId: authorization.proposal.proposalId,
  proposalHash: authorization.proposal.proposalHash,
  intentSha256: authorization.intentSha256,
  prospectiveEffectKey: authorization.prospectiveEffectKey,
  policySha256: authorization.policySha256,
  capability: authorization.capability,
  capabilityVersion: authorization.capabilityVersion,
  provider: authorization.provider,
  operation: authorization.operation,
  providerOwnerRef: authorization.providerOwnerRef,
  authorizationSha256: hash(authorization),
  killSwitchRevision: authorization.killSwitch.revision,
  evaluationReleaseSha256: authorization.evaluationRelease.releaseSha256,
  providerIdentityReceiptSha256: authorization.providerIdentity.receiptSha256,
  resourceOwnershipReceiptSha256: authorization.resourceOwnership.receiptSha256,
  approvalSha256: authorization.approval?.approvalSha256 ?? null,
  approvalConsumedAt: authorization.approval === null ? null : "2026-08-27T20:01:01.000Z",
  attemptRef: "provider-attempt:gmail-draft:test",
  attemptNumber: 1,
  status: "attempting",
  attemptedAt: "2026-08-27T20:01:01.000Z",
  leaseExpiresAt: "2026-08-27T20:03:01.000Z",
  revision: authorization.revision + 1,
});

const approvalFor = (authorization, consumedAt = null) =>
  signedProof(
    {
      approvalId: "approval:gmail-send:test",
      approvalSha256: "",
      proposalId: authorization.proposal.proposalId,
      proposalHash: authorization.proposal.proposalHash,
      intentSha256: authorization.intentSha256,
      approverPrincipalRef: actor.principalRef,
      decision: "approve_once",
      decidedAt: "2026-08-27T20:00:30.000Z",
      expiresAt: "2026-08-27T20:04:00.000Z",
      consumedAt,
    },
    "approvalSha256",
    "approval",
  );

const receiptFor = ({ attempt, proposal, result, reconciliationRef = null, priorReceiptSha256 = null }) =>
  signedProof(
    {
      receiptId: `provider-receipt:${result.status}:test`,
      receiptSha256: "",
      profileRef: attempt.profileRef,
      profileSha256: attempt.profileSha256,
      proposalId: proposal.proposalId,
      proposalHash: attempt.proposalHash ?? proposal.proposalHash,
      intentSha256: attempt.intentSha256,
      prospectiveEffectKey: attempt.prospectiveEffectKey,
      attemptRef: attempt.attemptRef,
      attemptNumber: 1,
      status: result.status,
      provider: result.provider,
      operation: result.operation,
      providerOwnerRef: result.providerOwnerRef,
      providerResourceRef: result.providerResourceRef,
      responseSha256: result.responseSha256,
      errorCode: result.errorCode,
      observationMode: result.observationMode,
      providerMutationCount: result.providerMutationCount,
      attemptedAt: attempt.attemptedAt,
      completedAt:
        result.status === "outcome_unknown"
          ? null
          : reconciliationRef === null
            ? "2026-08-27T20:01:02.000Z"
            : "2026-08-27T20:03:04.000Z",
      reconciliationRef,
      priorReceiptSha256,
      authenticatedBy: proofSigners.get("durable_receipt").issuer.issuerRef,
      authenticationSha256: "d".repeat(64),
    },
    "receiptSha256",
    "durable_receipt",
  );

const adaptersFor = (
  events,
  targetInvoke,
  targetReconcile = async () => assert.fail("unexpected reconciliation"),
  targetCapability = "google.gmail.drafts.create",
  isActive = () => true,
) =>
  Object.freeze({
    effectAdapters: Object.freeze({
      [targetCapability]: Object.freeze({ invoke: targetInvoke, isActive }),
    }),
    reconciliationPorts: Object.freeze({
      [targetCapability]: Object.freeze({
        queryStatus: targetReconcile,
        isActive,
        reconcilerPrincipalRef: `${reconcilerPrincipalRef}:${targetCapability}`,
      }),
    }),
  });

const storeFor = ({
  authorization,
  events,
  reconciliation = null,
  isActive = () => true,
  afterRead = () => {},
  reserveGuard = () => {},
  alterAttempt = (value) => value,
  alterLease = (value) => value,
}) => {
  const attempt = attemptFor(authorization);
  const store = {
    async readAuthorization(proposalId) {
      events.push("read_authorization");
      assert.equal(proposalId, authorization.proposal.proposalId);
      const result = structuredClone(authorization);
      afterRead();
      return result;
    },
    async reserveAttempt(value) {
      events.push("reserve_attempt");
      reserveGuard(value);
      assert.equal(value.proposalId, authorization.proposal.proposalId);
      assert.equal(value.expectedRevision, authorization.revision);
      assert.equal(value.killSwitchRevision, authorization.killSwitch.revision);
      assert.equal(value.evaluationReleaseSha256, authorization.evaluationRelease.releaseSha256);
      assert.equal(value.providerIdentityReceiptSha256, authorization.providerIdentity.receiptSha256);
      assert.equal(value.resourceOwnershipReceiptSha256, authorization.resourceOwnership.receiptSha256);
      assert.equal(value.approvalSha256, authorization.approval?.approvalSha256 ?? null);
      return alterAttempt(structuredClone(attempt));
    },
    async completeAttempt({ attempt: storedAttempt, result }) {
      events.push(`complete_attempt:${result.status}`);
      assert.deepEqual(storedAttempt, attempt);
      return receiptFor({ attempt, proposal: authorization.proposal, result });
    },
    async readReconciliation(proposalId) {
      events.push("read_reconciliation");
      assert.equal(proposalId, authorization.proposal.proposalId);
      return structuredClone(reconciliation);
    },
    async reserveReconciliation(value) {
      events.push("reserve_reconciliation");
      assert.equal(value.priorReceiptSha256, reconciliation.priorReceiptSha256);
      return alterLease({
        profileRef: reconciliation.profileRef,
        profileSha256: reconciliation.profileSha256,
        proposalId: reconciliation.proposal.proposalId,
        proposalHash: reconciliation.proposal.proposalHash,
        intentSha256: reconciliation.intentSha256,
        prospectiveEffectKey: reconciliation.prospectiveEffectKey,
        attemptRef: reconciliation.attemptRef,
        priorReceiptSha256: reconciliation.priorReceiptSha256,
        authenticationSha256: reconciliation.reconciliationIdentity.authenticationSha256,
        killSwitchRevision: reconciliation.killSwitch.revision,
        reconciliationRef: "provider-reconciliation:gmail-draft:test",
        reconcilerPrincipalRef: reconciliation.reconciliationIdentity.reconcilerPrincipalRef,
        mode: "read_only_status_lookup",
        acquiredAt: "2026-08-27T20:03:03.000Z",
        expiresAt: "2026-08-27T20:04:03.000Z",
        revision: reconciliation.revision,
      });
    },
    async completeReconciliation({ reconciliation: current, lease, result }) {
      events.push(`complete_reconciliation:${result.status}`);
      return receiptFor({
        attempt: current,
        proposal: current.proposal,
        result,
        reconciliationRef: lease.reconciliationRef,
        priorReceiptSha256: current.priorReceiptSha256,
      });
    },
    isActive,
  };
  return Object.freeze(store);
};

test("production authority has immutable blockers and accepts no caller ports or proof roots", () => {
  const readiness = inspectProviderEffectProductionReadiness(runtimeScope);
  assert.equal(readiness.callerBindingAllowed, false);
  assert.equal(readiness.constructionAvailable, false);
  assert.equal(readiness.providerInvocationAllowed, false);
  assert.equal(readiness.blockers.includes("provider_grant_not_activated"), true);
  assert.equal(readiness.blockers.includes("immutable_provider_effect_proof_registry_unavailable"), true);
  assert.equal(readiness.blockers.includes("production_provider_effect_durable_port_unavailable"), true);
  assert.equal(providerEffectProductionPortContract.callerBindingAllowed, false);
  assert.deepEqual(providerEffectProductionPortContract.effectAdapterMethods, ["invoke"]);
  assert.deepEqual(providerEffectProductionPortContract.reconciliationPortMethods, ["queryStatus"]);
  assert.throws(() => createProviderEffectExecutionAuthority(runtimeScope), {
    code: "provider_effect_execution_unavailable",
  });
  assert.throws(() => createProviderEffectExecutionAuthority({ runtimeScope, store: {}, trustedProofIssuers }));
});

test("attempt reservation is durably validated before the one provider invocation", async () => {
  const proposal = gmailDraftProposal();
  const authorization = authorizationFor(proposal);
  const events = [];
  const result = {
    status: "verified",
    provider: authorization.provider,
    operation: authorization.operation,
    providerOwnerRef: authorization.providerOwnerRef,
    providerResourceRef: "gmail-draft:provider-created:test",
    responseSha256: "e".repeat(64),
    errorCode: null,
    observationMode: "effect_execution",
    providerMutationCount: 1,
  };
  const store = storeFor({ authorization, events });
  const adapters = adaptersFor(events, async ({ proposal: invokedProposal, attempt }) => {
    events.push("provider_invoke");
    assert.deepEqual(invokedProposal, proposal);
    assert.equal(attempt.status, "attempting");
    return result;
  });
  const authority = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store,
    ...adapters,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  const receipt = await authority.execute(proposal.proposalId);
  assert.equal(receipt.status, "verified");
  assert.deepEqual(events, ["read_authorization", "reserve_attempt", "provider_invoke", "complete_attempt:verified"]);
});

test("an indeterminate adapter failure is held as outcome unknown without retry", async () => {
  const proposal = gmailDraftProposal();
  const authorization = authorizationFor(proposal);
  const events = [];
  let calls = 0;
  const store = storeFor({ authorization, events });
  const adapters = adaptersFor(events, async () => {
    calls += 1;
    events.push("provider_invoke");
    throw new Error("socket closed after write");
  });
  const authority = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store,
    ...adapters,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  const receipt = await authority.execute(proposal.proposalId);
  assert.equal(receipt.status, "outcome_unknown");
  assert.equal(receipt.errorCode, "provider_transport_indeterminate");
  assert.equal(calls, 1);
  assert.deepEqual(events, [
    "read_authorization",
    "reserve_attempt",
    "provider_invoke",
    "complete_attempt:outcome_unknown",
  ]);
});

test("approval-once execution requires the exact unconsumed approval and consumes it in reservation", async () => {
  const proposal = gmailSendProposal();
  const base = authorizationFor(proposal);
  const authorization = { ...base, approval: approvalFor(base) };
  const events = [];
  const result = {
    status: "verified",
    provider: authorization.provider,
    operation: authorization.operation,
    providerOwnerRef: authorization.providerOwnerRef,
    providerResourceRef: proposal.target.draftId,
    responseSha256: "8".repeat(64),
    errorCode: null,
    observationMode: "effect_execution",
    providerMutationCount: 1,
  };
  const store = storeFor({ authorization, events });
  const adapters = adaptersFor(
    events,
    async () => {
      events.push("provider_invoke");
      return result;
    },
    undefined,
    "google.gmail.drafts.send",
  );
  const authority = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store,
    ...adapters,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  assert.equal((await authority.execute(proposal.proposalId)).status, "verified");
  assert.deepEqual(events, ["read_authorization", "reserve_attempt", "provider_invoke", "complete_attempt:verified"]);

  const consumed = authorizationFor(proposal);
  consumed.approval = approvalFor(consumed, "2026-08-27T20:01:01.000Z");
  const deniedEvents = [];
  const deniedStore = storeFor({ authorization: consumed, events: deniedEvents });
  const deniedAdapters = adaptersFor(
    deniedEvents,
    async () => assert.fail("unreachable"),
    undefined,
    "google.gmail.drafts.send",
  );
  const denied = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store: deniedStore,
    ...deniedAdapters,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  await assert.rejects(() => denied.execute(proposal.proposalId), { code: "provider_effect_approval_invalid" });
  assert.deepEqual(deniedEvents, ["read_authorization"]);
});

test("kill switch, release, identity, ownership, and approval substitutions fail before reservation", async () => {
  const proposal = gmailDraftProposal();
  for (const mutate of [
    (value) => {
      value.killSwitch.engaged = true;
      value.killSwitch = withHash(value.killSwitch, "stateSha256");
    },
    (value) => {
      value.evaluationRelease.providerReleaseEligible = false;
      value.evaluationRelease = withHash(value.evaluationRelease, "releaseSha256");
    },
    (value) => {
      value.providerIdentity.providerAccountRef = "google-account:attacker:test";
    },
    (value) => {
      value.resourceOwnership.resourceKey = "f".repeat(64);
      value.resourceOwnership = withHash(value.resourceOwnership, "receiptSha256");
    },
    (value) => {
      value.approval = {
        approvalId: "approval:unexpected:test",
        approvalSha256: "0".repeat(64),
        proposalId: proposal.proposalId,
        proposalHash: proposal.proposalHash,
        intentSha256: value.intentSha256,
        approverPrincipalRef: actor.principalRef,
        decision: "approve_once",
        decidedAt: "2026-08-27T20:00:30.000Z",
        expiresAt: "2026-08-27T20:04:00.000Z",
        consumedAt: null,
      };
    },
  ]) {
    const authorization = authorizationFor(proposal);
    mutate(authorization);
    const events = [];
    const store = storeFor({ authorization, events });
    const adapters = adaptersFor(events, async () => assert.fail("unreachable"));
    const authority = createInertProviderEffectExecutionAuthorityForTesting({
      runtimeScope,
      store,
      ...adapters,
      trustedProofIssuers,
      allowedReconcilerPrincipals,
    });
    await assert.rejects(() => authority.execute(proposal.proposalId));
    assert.deepEqual(events, ["read_authorization"]);
  }
});

test("proof signatures, issuer classes, allowlists, and ownership lifetime are enforced", async () => {
  const proposal = gmailDraftProposal();
  for (const mutate of [
    (value) => {
      value.providerIdentity.signature = value.resourceOwnership.signature;
    },
    (value) => {
      value.evaluationRelease.keyId = "proof-key:unknown:test";
    },
    (value) => {
      value.resourceOwnership.expiresAt = "2026-08-27T20:10:00.000Z";
      value.resourceOwnership = signedProof(value.resourceOwnership, "receiptSha256", "resource_ownership");
    },
    (value) => {
      value.killSwitch.issuerRef = "proof-issuer:attacker:test";
    },
  ]) {
    const authorization = authorizationFor(proposal);
    mutate(authorization);
    const events = [];
    const store = storeFor({ authorization, events });
    const adapters = adaptersFor(events, async () => assert.fail("unreachable"));
    const authority = createInertProviderEffectExecutionAuthorityForTesting({
      runtimeScope,
      store,
      ...adapters,
      trustedProofIssuers,
      allowedReconcilerPrincipals,
    });
    await assert.rejects(() => authority.execute(proposal.proposalId));
    assert.deepEqual(events, ["read_authorization"]);
  }
});

test("atomic reservation rejects kill-switch and proof races through returned CAS bindings", async () => {
  const proposal = gmailDraftProposal();
  const authorization = authorizationFor(proposal);
  for (const alterAttempt of [
    (value) => ({ ...value, authorizationSha256: "0".repeat(64) }),
    (value) => ({ ...value, killSwitchRevision: value.killSwitchRevision + 1 }),
    (value) => ({ ...value, providerIdentityReceiptSha256: "1".repeat(64) }),
    (value) => ({ ...value, resourceOwnershipReceiptSha256: "2".repeat(64) }),
    (value) => ({ ...value, approvalConsumedAt: value.attemptedAt }),
  ]) {
    const events = [];
    const store = storeFor({ authorization, events, alterAttempt });
    const adapters = adaptersFor(events, async () => assert.fail("unreachable"));
    const authority = createInertProviderEffectExecutionAuthorityForTesting({
      runtimeScope,
      store,
      ...adapters,
      trustedProofIssuers,
      allowedReconcilerPrincipals,
    });
    await assert.rejects(() => authority.execute(proposal.proposalId), {
      code: "provider_effect_attempt_invalid",
    });
    assert.deepEqual(events, ["read_authorization", "reserve_attempt"]);
  }
});

test("a kill switch change while authorization is awaited is denied by atomic reservation", async () => {
  const proposal = gmailDraftProposal();
  const authorization = authorizationFor(proposal);
  const events = [];
  let killSwitchChanged = false;
  let providerCalls = 0;
  const store = storeFor({
    authorization,
    events,
    afterRead: () => {
      killSwitchChanged = true;
    },
    reserveGuard: () => {
      if (killSwitchChanged) throw new Error("kill_switch_revision_conflict");
    },
  });
  const adapters = adaptersFor(events, async () => {
    providerCalls += 1;
    assert.fail("unreachable");
  });
  const authority = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store,
    ...adapters,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  await assert.rejects(() => authority.execute(proposal.proposalId), /kill_switch_revision_conflict/);
  assert.equal(providerCalls, 0);
  assert.deepEqual(events, ["read_authorization", "reserve_attempt"]);
});

test("store and adapter activation are rechecked at every authority call boundary", async () => {
  const proposal = gmailDraftProposal();
  const authorization = authorizationFor(proposal);
  let storeActive = true;
  const storeEvents = [];
  const revokedStore = storeFor({
    authorization,
    events: storeEvents,
    isActive: () => storeActive,
    afterRead: () => {
      storeActive = false;
    },
  });
  const storeAdapters = adaptersFor(storeEvents, async () => assert.fail("unreachable"));
  const storeAuthority = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store: revokedStore,
    ...storeAdapters,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  await assert.rejects(() => storeAuthority.execute(proposal.proposalId), {
    code: "provider_effect_store_unavailable",
  });
  assert.deepEqual(storeEvents, ["read_authorization"]);

  let adapterActive = true;
  let providerCalls = 0;
  const adapterEvents = [];
  const revokedAdapterStore = storeFor({
    authorization,
    events: adapterEvents,
    alterAttempt: (value) => {
      adapterActive = false;
      return value;
    },
  });
  const revokedAdapters = adaptersFor(
    adapterEvents,
    async () => {
      providerCalls += 1;
      assert.fail("unreachable");
    },
    undefined,
    "google.gmail.drafts.create",
    () => adapterActive,
  );
  const adapterAuthority = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store: revokedAdapterStore,
    ...revokedAdapters,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  const receipt = await adapterAuthority.execute(proposal.proposalId);
  assert.equal(receipt.status, "outcome_unknown");
  assert.equal(providerCalls, 0);
  assert.deepEqual(adapterEvents, ["read_authorization", "reserve_attempt", "complete_attempt:outcome_unknown"]);

  let duringAwaitActive = true;
  let completedNetworkCalls = 0;
  const duringAwaitEvents = [];
  const duringAwaitStore = storeFor({ authorization, events: duringAwaitEvents });
  const duringAwaitAdapters = adaptersFor(
    duringAwaitEvents,
    async () => {
      duringAwaitEvents.push("provider_invoke");
      completedNetworkCalls += 1;
      duringAwaitActive = false;
      return {
        status: "verified",
        provider: authorization.provider,
        operation: authorization.operation,
        providerOwnerRef: authorization.providerOwnerRef,
        providerResourceRef: "gmail-draft:completed-before-revocation:test",
        responseSha256: "7".repeat(64),
        errorCode: null,
        observationMode: "effect_execution",
        providerMutationCount: 1,
      };
    },
    undefined,
    "google.gmail.drafts.create",
    () => duringAwaitActive,
  );
  const duringAwaitAuthority = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store: duringAwaitStore,
    ...duringAwaitAdapters,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  const heldReceipt = await duringAwaitAuthority.execute(proposal.proposalId);
  assert.equal(heldReceipt.status, "outcome_unknown");
  assert.equal(completedNetworkCalls, 1);
  assert.deepEqual(duringAwaitEvents, [
    "read_authorization",
    "reserve_attempt",
    "provider_invoke",
    "complete_attempt:outcome_unknown",
  ]);
});

test("authenticated reconciliation resolves only the original unknown attempt", async () => {
  const proposal = gmailDraftProposal();
  const authorization = authorizationFor(proposal);
  const attempt = attemptFor(authorization);
  const events = [];
  const reconciliation = {
    profileRef: authorization.profileRef,
    profileSha256: authorization.profileSha256,
    proposal,
    intentSha256: authorization.intentSha256,
    prospectiveEffectKey: authorization.prospectiveEffectKey,
    policySha256: authorization.policySha256,
    capability: authorization.capability,
    capabilityVersion: authorization.capabilityVersion,
    provider: authorization.provider,
    operation: authorization.operation,
    providerOwnerRef: authorization.providerOwnerRef,
    providerAccountRef: authorization.providerIdentity.providerAccountRef,
    providerResourceRef: "gmail-draft:reconciled:test",
    attemptRef: attempt.attemptRef,
    attemptNumber: 1,
    attemptedAt: attempt.attemptedAt,
    attemptLeaseExpiresAt: attempt.leaseExpiresAt,
    priorStatus: "outcome_unknown",
    priorReceiptSha256: "1".repeat(64),
    databaseNow: "2026-08-27T20:03:02.000Z",
    killSwitch: signedProof(
      {
        profileRef: authorization.profileRef,
        profileSha256: authorization.profileSha256,
        engaged: false,
        revision: 7,
        checkedAt: "2026-08-27T20:03:02.000Z",
        stateSha256: "",
      },
      "stateSha256",
      "kill_switch",
    ),
    reconciliationIdentity: null,
    revision: attempt.revision + 1,
  };
  reconciliation.reconciliationIdentity = signedProof(
    {
      profileRef: authorization.profileRef,
      profileSha256: authorization.profileSha256,
      capability: authorization.capability,
      attemptRef: attempt.attemptRef,
      priorReceiptSha256: reconciliation.priorReceiptSha256,
      reconcilerPrincipalRef: `${reconcilerPrincipalRef}:${authorization.capability}`,
      authenticationSha256: "",
      authenticatedAt: "2026-08-27T20:03:00.000Z",
      expiresAt: "2026-08-27T20:04:00.000Z",
    },
    "authenticationSha256",
    "reconciliation_identity",
  );
  const result = {
    status: "verified",
    provider: authorization.provider,
    operation: authorization.operation,
    providerOwnerRef: authorization.providerOwnerRef,
    providerResourceRef: "gmail-draft:reconciled:test",
    responseSha256: "3".repeat(64),
    errorCode: null,
    observationMode: "read_only_status_lookup",
    providerMutationCount: 0,
  };
  const store = storeFor({ authorization, events, reconciliation });
  const adapters = adaptersFor(
    events,
    async () => assert.fail("unexpected invocation"),
    async (query) => {
      events.push("provider_reconcile");
      assert.equal(query.attemptRef, reconciliation.attemptRef);
      assert.equal(query.mode, "read_only_status_lookup");
      assert.equal(Object.hasOwn(query, "proposal"), false);
      assert.equal(Object.isFrozen(query), true);
      return result;
    },
  );
  const authority = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store,
    ...adapters,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  const receipt = await authority.reconcile(proposal.proposalId);
  assert.equal(receipt.status, "verified");
  assert.equal(receipt.priorReceiptSha256, reconciliation.priorReceiptSha256);
  assert.deepEqual(events, [
    "read_reconciliation",
    "reserve_reconciliation",
    "provider_reconcile",
    "complete_reconciliation:verified",
  ]);

  for (const alterLease of [
    (value) => ({ ...value, priorReceiptSha256: "4".repeat(64) }),
    (value) => ({ ...value, authenticationSha256: "5".repeat(64) }),
    (value) => ({ ...value, killSwitchRevision: value.killSwitchRevision + 1 }),
    (value) => ({ ...value, mode: "read_write" }),
  ]) {
    const deniedEvents = [];
    const deniedStore = storeFor({ authorization, events: deniedEvents, reconciliation, alterLease });
    const deniedAdapters = adaptersFor(
      deniedEvents,
      async () => assert.fail("unexpected invocation"),
      async () => assert.fail("unexpected reconciliation"),
    );
    const deniedAuthority = createInertProviderEffectExecutionAuthorityForTesting({
      runtimeScope,
      store: deniedStore,
      ...deniedAdapters,
      trustedProofIssuers,
      allowedReconcilerPrincipals,
    });
    await assert.rejects(() => deniedAuthority.reconcile(proposal.proposalId), {
      code: "provider_effect_reconciliation_lease_invalid",
    });
    assert.deepEqual(deniedEvents, ["read_reconciliation", "reserve_reconciliation"]);
  }

  const mutationEvents = [];
  const mutationStore = storeFor({ authorization, events: mutationEvents, reconciliation });
  const mutationAdapters = adaptersFor(
    mutationEvents,
    async () => assert.fail("unexpected invocation"),
    async () => {
      mutationEvents.push("provider_reconcile");
      return { ...result, providerMutationCount: 1 };
    },
  );
  const mutationAuthority = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store: mutationStore,
    ...mutationAdapters,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  await assert.rejects(() => mutationAuthority.reconcile(proposal.proposalId), {
    code: "provider_effect_reconciliation_indeterminate",
  });
  assert.deepEqual(mutationEvents, ["read_reconciliation", "reserve_reconciliation", "provider_reconcile"]);

  let reconciliationActive = true;
  const revokedEvents = [];
  const revokedStore = storeFor({ authorization, events: revokedEvents, reconciliation });
  const revokedPorts = adaptersFor(
    revokedEvents,
    async () => assert.fail("unexpected invocation"),
    async () => {
      revokedEvents.push("provider_reconcile");
      reconciliationActive = false;
      return result;
    },
    "google.gmail.drafts.create",
    () => reconciliationActive,
  );
  const revokedAuthority = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store: revokedStore,
    ...revokedPorts,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  await assert.rejects(() => revokedAuthority.reconcile(proposal.proposalId), {
    code: "provider_effect_reconciliation_indeterminate",
  });
  assert.deepEqual(revokedEvents, ["read_reconciliation", "reserve_reconciliation", "provider_reconcile"]);
});

test("test ports are exact, separated by effect class, and bind the allowlisted reconciler", () => {
  const proposal = gmailDraftProposal();
  const authorization = authorizationFor(proposal);
  const events = [];
  const store = storeFor({ authorization, events });
  const adapters = adaptersFor(events, async () => assert.fail("unreachable"));
  const rawStore = Object.fromEntries(
    [
      "readAuthorization",
      "reserveAttempt",
      "completeAttempt",
      "readReconciliation",
      "reserveReconciliation",
      "completeReconciliation",
    ].map((name) => [name, async () => null]),
  );
  assert.throws(
    () =>
      createInertProviderEffectExecutionAuthorityForTesting({
        runtimeScope,
        store: rawStore,
        ...adapters,
        trustedProofIssuers,
        allowedReconcilerPrincipals,
      }),
    { code: "provider_effect_store_invalid" },
  );
  assert.throws(
    () =>
      createInertProviderEffectExecutionAuthorityForTesting({
        runtimeScope,
        store,
        effectAdapters: { "google.gmail.drafts.create": rawStore },
        reconciliationPorts: adapters.reconciliationPorts,
        trustedProofIssuers,
        allowedReconcilerPrincipals,
      }),
    { code: "provider_effect_adapters_unavailable" },
  );
  assert.throws(
    () =>
      createInertProviderEffectExecutionAuthorityForTesting({
        runtimeScope,
        store: new Proxy(store, {}),
        ...adapters,
        trustedProofIssuers,
        allowedReconcilerPrincipals,
      }),
    { code: "provider_effect_store_invalid" },
  );
  const wrongReconciler = {
    ...adapters,
    reconciliationPorts: {
      "google.gmail.drafts.create": {
        ...adapters.reconciliationPorts["google.gmail.drafts.create"],
        reconcilerPrincipalRef: "reconciler:attacker:test",
      },
    },
  };
  assert.throws(
    () =>
      createInertProviderEffectExecutionAuthorityForTesting({
        runtimeScope,
        store,
        ...wrongReconciler,
        trustedProofIssuers,
        allowedReconcilerPrincipals,
      }),
    { code: "provider_effect_reconciler_registry_invalid" },
  );
  const duplicateKeyIssuers = structuredClone(trustedProofIssuers);
  duplicateKeyIssuers[1].publicKey = structuredClone(duplicateKeyIssuers[0].publicKey);
  assert.throws(
    () =>
      createInertProviderEffectExecutionAuthorityForTesting({
        runtimeScope,
        store,
        ...adapters,
        trustedProofIssuers: duplicateKeyIssuers,
        allowedReconcilerPrincipals,
      }),
    { code: "provider_effect_proof_issuers_invalid" },
  );
  const authority = createInertProviderEffectExecutionAuthorityForTesting({
    runtimeScope,
    store,
    ...adapters,
    trustedProofIssuers,
    allowedReconcilerPrincipals,
  });
  assert.equal(authority.execute.length, 1);
  assert.equal(authority.reconcile.length, 1);
  assert.equal(Object.hasOwn(productionAuthority, "createInertProviderEffectExecutionAuthorityForTesting"), false);
  assert.equal(Object.hasOwn(productionAuthority, "bindDurableProviderEffectStore"), false);
  assert.equal(Object.hasOwn(productionAuthority, "bindTrustedProviderEffectAdapter"), false);
  assert.deepEqual(Object.keys(adapters.effectAdapters), ["google.gmail.drafts.create"]);
  assert.deepEqual(Object.keys(adapters.reconciliationPorts), ["google.gmail.drafts.create"]);
});
