import { assertProfileAuthority } from "../deployment-profiles/contract.mjs";
import { resolveProductionDeploymentProfile } from "../deployment-profiles/index.mjs";
import { createSharedContractSuite } from "../shared-contracts/index.mjs";

const runtimeScopes = new WeakSet();

export function createRuntimeScope(profile) {
  const authority = assertProfileAuthority(profile);
  const contracts = createSharedContractSuite(authority);
  const domainAuthority = Object.freeze({
    principalRef: authority.identity.humanPrincipalRef,
    qmPrincipalId: authority.identity.qmPrincipalRef,
    externalPrincipalRef: authority.identity.externalIdentityRef,
    agentId: authority.agent.agentId,
    agentVersion: authority.agent.agentVersion,
    scopeRef: authority.anchors.principalBindingRef,
    audienceRef: authority.audiences.slack.audienceRef,
    credentialOwnerRef: authority.identity.credentialOwnerRef,
  });
  const scope = Object.freeze({
    profile: authority,
    profileRef: authority.profileRef,
    profileSha256: authority.profileSha256,
    contracts,
    principalBinding: contracts.PrincipalBinding.value,
    domainAuthority,
  });
  runtimeScopes.add(scope);
  return scope;
}

export function assertRuntimeScope(value) {
  if (!runtimeScopes.has(value) || !Object.isFrozen(value)) throw new TypeError("Runtime scope authority is invalid");
  assertProfileAuthority(value.profile);
  return value;
}

export function productionRuntimeScopeFromEnv(env = process.env) {
  const profile = resolveProductionDeploymentProfile(env.CANARY_DEPLOYMENT_PROFILE_REF);
  return createRuntimeScope(profile);
}
