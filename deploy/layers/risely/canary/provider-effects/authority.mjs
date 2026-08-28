import { assertRuntimeScope } from "../runtime-scope/index.mjs";
import { providerEffectPolicyCatalog, providerEffectPolicyCatalogSha256 } from "../deployment-profiles/index.mjs";

const requiredProofClasses = Object.freeze([
  "kill_switch",
  "evaluation_release",
  "provider_identity",
  "resource_ownership",
  "approval",
  "reconciliation_identity",
  "durable_receipt",
]);

export const providerEffectProductionPortContract = Object.freeze({
  contractVersion: 1,
  callerBindingAllowed: false,
  portLivenessMethod: "isActive",
  distinctKeyPerProofClass: true,
  durableStoreMethods: Object.freeze([
    "readAuthorization",
    "reserveAttempt",
    "completeAttempt",
    "readReconciliation",
    "reserveReconciliation",
    "completeReconciliation",
  ]),
  effectAdapterMethods: Object.freeze(["invoke"]),
  reconciliationPortMethods: Object.freeze(["queryStatus"]),
  reconciliationMode: "read_only_status_lookup",
  requiredProofClasses,
});

export class ProviderEffectAuthorityError extends Error {
  constructor(code, blockers) {
    super(code);
    this.name = "ProviderEffectAuthorityError";
    this.code = code;
    this.blockers = Object.freeze([...blockers]);
  }
}

export function inspectProviderEffectProductionReadiness(runtimeScope) {
  const scope = assertRuntimeScope(runtimeScope);
  const blockers = [
    ...(scope.profile.providerExecutionAllowed ? [] : ["provider_execution_not_activated"]),
    ...(scope.profile.grantPolicy.maximumProviderGrantLifetimeMs > 0 ? [] : ["provider_grant_not_activated"]),
    "immutable_provider_effect_proof_registry_unavailable",
    "production_provider_effect_durable_port_unavailable",
    "production_provider_effect_adapters_unavailable",
    "production_provider_effect_reconciliation_ports_unavailable",
  ].sort();
  const projection = {
    contractType: "ProviderEffectProductionReadiness",
    contractVersion: 1,
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    policySha256: providerEffectPolicyCatalogSha256,
    trustRegistrySource: "immutable_deployment_profile_and_provider_effect_policy_catalog",
    capabilities: providerEffectPolicyCatalog.capabilities.map((entry) => entry.capability),
    callerBindingAllowed: false,
    constructionAvailable: false,
    providerInvocationAllowed: false,
    requiredProofClasses,
    configuredProofClasses: Object.freeze([]),
    blockers: Object.freeze(blockers),
  };
  return scope.contracts.PrincipalBinding.freeze({
    ...projection,
    readinessSha256: scope.contracts.PrincipalBinding.hash(projection),
  });
}

export function createProviderEffectExecutionAuthority(runtimeScope) {
  const readiness = inspectProviderEffectProductionReadiness(runtimeScope);
  throw new ProviderEffectAuthorityError("provider_effect_execution_unavailable", readiness.blockers);
}
