import { PrincipalBinding } from "./index.mjs";

const aliases = PrincipalBinding.freeze({
  organizationRef: { organization_risely: PrincipalBinding.identity.organizationRef },
  deploymentRef: {
    deployment_risely_ceo: PrincipalBinding.identity.deploymentRef,
    "risely-ceo-surface": PrincipalBinding.identity.deploymentRef,
  },
  principalRef: {
    usr_ceo_00000001: PrincipalBinding.identity.principalRef,
    "qm:principal:ceo-canary": PrincipalBinding.identity.principalRef,
    "user:risely:ceo": PrincipalBinding.identity.principalRef,
  },
  credentialOwnerRef: {
    "provider:subject:ceo-canary": PrincipalBinding.identity.credentialOwnerRef,
    "credential:slack:risely-ceo-surface": PrincipalBinding.identity.credentialOwnerRef,
  },
  audienceRef: {
    audience_ceo_private: PrincipalBinding.identity.audienceRef,
    "audience:ceo-private": PrincipalBinding.identity.audienceRef,
    "audience:risely:ceo-private": PrincipalBinding.identity.audienceRef,
    "personal:ceo-canary": PrincipalBinding.identity.audienceRef,
  },
  audienceClass: { private_ceo: PrincipalBinding.identity.audienceClass },
});

export function mapLegacyIdentityAtMigrationIngress(field, value) {
  if (typeof field !== "string" || typeof value !== "string")
    throw new TypeError("legacy identity mapping requires strings");
  if (!Object.hasOwn(aliases, field)) throw new TypeError(`legacy identity field ${field} is not supported`);
  if (value === PrincipalBinding.identity[field]) return value;
  const fieldAliases = aliases[field];
  if (!Object.hasOwn(fieldAliases, value)) throw new TypeError(`${field} is not an explicitly mapped CEO identity`);
  return fieldAliases[value];
}
