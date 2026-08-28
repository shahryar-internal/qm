import { assertActionProposalHashes } from "../contracts/index.mjs";
import { ceoDeploymentProfile } from "../deployment-profiles/index.mjs";
import { createRuntimeScope, assertRuntimeScope } from "../runtime-scope/index.mjs";

export const CANARY_PROVIDER_EXECUTION_AVAILABLE = false;

const authorityFields = Object.freeze([
  "principalRef",
  "qmPrincipalId",
  "externalPrincipalRef",
  "agentId",
  "agentVersion",
  "scopeRef",
  "audienceRef",
  "credentialOwnerRef",
]);

function exact(value, fields, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  ) {
    throw new TypeError(`${label} has an unsupported shape`);
  }
  return value;
}

function assertAuthority(scope, proposal, value) {
  const authority = exact(
    scope.contracts.PrincipalBinding.snapshot(value, "proposal authority"),
    authorityFields,
    "Proposal authority",
  );
  const expected = scope.domainAuthority;
  if (
    authorityFields.some((field) => authority[field] !== expected[field]) ||
    proposal.actor.principalRef !== authority.principalRef ||
    proposal.actor.qmPrincipalId !== authority.qmPrincipalId ||
    proposal.actor.externalPrincipalRef !== authority.externalPrincipalRef ||
    proposal.actor.agent.id !== authority.agentId ||
    proposal.actor.agent.version !== authority.agentVersion ||
    proposal.actor.scopeRef !== authority.scopeRef ||
    proposal.actor.audienceRef !== authority.audienceRef ||
    proposal.actor.credentialOwnerRef !== authority.credentialOwnerRef
  ) {
    throw new TypeError("Proposal authority does not match the deployment profile");
  }
}

function assertScopedProposal(scope, value, authority) {
  const proposal = assertActionProposalHashes(value);
  const profile = scope.profile;
  const identity = scope.contracts.PrincipalBinding.identity;
  const providerOwnerRef = profile.providerOwners.find(
    (entry) => entry.provider === proposal.provider,
  )?.providerOwnerRef;
  assertAuthority(scope, proposal, authority);
  if (
    !profile.allowedCapabilities.includes(proposal.capability) ||
    proposal.provider !== proposal.capability.split(".", 1)[0] ||
    !providerOwnerRef ||
    profile.providerExecutionAllowed !== false ||
    profile.grantPolicy.approvalRequired !== true ||
    profile.grantPolicy.delegationAllowed !== false ||
    profile.grantPolicy.maximumProviderGrantLifetimeMs !== 0 ||
    Date.parse(proposal.expiresAt) <= Date.parse(proposal.createdAt) ||
    Date.parse(proposal.expiresAt) - Date.parse(proposal.createdAt) > profile.grantPolicy.maximumApprovalLifetimeMs ||
    proposal.actor.principalRef !== identity.principalRef ||
    proposal.actor.audienceRef !== identity.audienceRef ||
    proposal.actor.credentialOwnerRef !== identity.credentialOwnerRef ||
    proposal.evidenceRefs.some((entry) => entry.audienceRef !== identity.audienceRef)
  ) {
    throw new TypeError("Proposal is outside deployment profile authority");
  }
  if (proposal.capability === "google.gmail.drafts.create") {
    exact(proposal.target, ["providerOwnerRef", "mailbox", "to"], "Gmail target");
    exact(proposal.payload, ["body", "evidenceSha256", "payloadSha256", "subject"], "Gmail payload");
    const evidenceSha256 = scope.contracts.PrincipalBinding.hash(proposal.evidenceRefs);
    const payloadSha256 = scope.contracts.PrincipalBinding.hash({
      target: proposal.target,
      payload: {
        body: proposal.payload.body,
        evidenceSha256,
        subject: proposal.payload.subject,
      },
    });
    if (
      proposal.target.providerOwnerRef !== providerOwnerRef ||
      proposal.target.mailbox !== identity.principalEmail ||
      proposal.payload.evidenceSha256 !== evidenceSha256 ||
      proposal.payload.payloadSha256 !== payloadSha256
    ) {
      throw new TypeError("Gmail proposal owner binding is invalid");
    }
  } else {
    throw new TypeError("Proposal capability has no closed public contract");
  }
  return proposal;
}

export function createProposalContractSuite(runtimeScope) {
  const scope = assertRuntimeScope(runtimeScope);
  return Object.freeze({
    runtimeScope: scope,
    providerExecutionAvailable: false,
    assertProposal: (value, authority = scope.domainAuthority) => assertScopedProposal(scope, value, authority),
    assertDormantGmailDraftProposal: (value, authority = scope.domainAuthority) => {
      const proposal = assertScopedProposal(scope, value, authority);
      if (proposal.capability !== "google.gmail.drafts.create") {
        throw new TypeError("Only dormant Gmail draft proposals are supported");
      }
      return proposal;
    },
  });
}

export const ceoProposalContractSuite = createProposalContractSuite(createRuntimeScope(ceoDeploymentProfile));
export const assertDormantGmailDraftProposal = ceoProposalContractSuite.assertDormantGmailDraftProposal;
