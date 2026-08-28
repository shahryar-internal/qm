import {
  DeploymentProfileContractError,
  assertProfileAuthority,
  createProfileAuthority,
  freezeProfileData,
  hashProfileData,
  snapshotProfileData,
} from "./contract.mjs";
import { providerEffectPolicyCatalog, providerEffectPolicyCatalogSha256 } from "./provider-effect-policy.mjs";

export { providerEffectPolicyCatalog, providerEffectPolicyCatalogSha256 };

const maximumTrustedIdentityLifetimeMs = 60 * 60 * 1000;
const maximumResolutionRequestLifetimeMs = 5 * 60 * 1000;
const resolutionBlocker = "trusted_qm_profile_resolution_authority_unavailable";
const digestPattern = /^[a-f0-9]{64}$/u;
const identifierPattern = /^[a-z0-9][a-z0-9._:/-]{0,255}$/u;
const emailPattern =
  /^(?=.{3,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/u;

export { DeploymentProfileContractError as DeploymentProfileError };

const fail = (code) => {
  throw new DeploymentProfileContractError(code);
};

const exact = (value, fields, code) => {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  ) {
    fail(code);
  }
  return value;
};

const assertIdentifier = (value, code) => {
  if (typeof value !== "string" || !identifierPattern.test(value)) fail(code);
  return value;
};

const assertDigest = (value, code) => {
  if (typeof value !== "string" || !digestPattern.test(value)) fail(code);
  return value;
};

const assertInstant = (value, code) => {
  if (typeof value !== "string") fail(code);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString() !== value) fail(code);
  return value;
};

const assertEmail = (value, code) => {
  if (typeof value !== "string" || value !== value.toLowerCase() || !emailPattern.test(value)) fail(code);
  return value;
};

const selfHash = (value, field) => {
  const projection = { ...value };
  delete projection[field];
  return hashProfileData(projection);
};

const profileProjection = {
  contractType: "risely-deployment-profile",
  contractVersion: 1,
  digestRevision: "DeploymentProfile.sha256.v1",
  profileRef: "deployment-profile:risely:ceo:v1",
  profileVersion: 1,
  activationMode: "shadow",
  providerExecutionAllowed: false,
  anchors: {
    organizationRef: "organization:risely",
    deploymentRef: "deployment:risely:ceo-canary:v1",
    tenantRef: "tenant:risely",
    workspaceRef: "workspace:risely",
    principalBindingRef: "principal-binding:risely:ceo:v1",
    slackTeamRef: "slack-team:risely",
  },
  identity: {
    humanPrincipalRef: "principal:ceo",
    humanEmail: "shahryar@risely.ai",
    qmPrincipalRef: "qm:principal:ceo-canary",
    externalIdentityRef: "external-identity:risely:ceo",
    externalOrganizationRole: "ceo",
    credentialOwnerRef: "credential-owner:ceo",
  },
  agent: {
    agentId: "agent:risely:ceo-team",
    agentVersion: "1.0.0",
    agentScope: "ceo_private",
  },
  allowedCapabilities: [
    "brain.read",
    "calendar.read",
    "clarify.read",
    "demo_repository.read",
    "google.calendar.events.create",
    "google.calendar.events.update",
    "google.gmail.drafts.create",
    "google.gmail.drafts.send",
    "linkedin.connection_propose",
    "linkedin.dm_propose",
    "marketing.content_propose",
    "mercury.invoices.create",
    "notion.artifact_propose",
    "notion.pages.upsert",
    "proposal.generate_propose",
    "sales.outreach_propose",
    "slack.chat.post",
    "slack.surface_compile",
  ],
  providerEffectPolicyRef: providerEffectPolicyCatalog.policyRef,
  providerEffectPolicySha256: providerEffectPolicyCatalogSha256,
  providerOwners: [
    { provider: "apollo", providerOwnerRef: "provider-owner:apollo:risely" },
    { provider: "clarify", providerOwnerRef: "provider-owner:clarify:risely" },
    { provider: "command_center_brain", providerOwnerRef: "provider-owner:command-center-brain:risely" },
    { provider: "demo_repository", providerOwnerRef: "provider-owner:demo-repository:risely" },
    { provider: "gmail", providerOwnerRef: "provider-owner:gmail:ceo" },
    { provider: "google", providerOwnerRef: "provider-owner:google:ceo" },
    { provider: "linkedin", providerOwnerRef: "provider-owner:linkedin:ceo" },
    { provider: "mercury", providerOwnerRef: "provider-owner:mercury:risely" },
    { provider: "notion", providerOwnerRef: "provider-owner:notion:ceo" },
    { provider: "posthog", providerOwnerRef: "provider-owner:posthog:risely" },
    { provider: "rb2b", providerOwnerRef: "provider-owner:rb2b:risely" },
    { provider: "slack", providerOwnerRef: "provider-owner:slack:risely" },
  ],
  audiences: {
    slack: {
      audienceRef: "slack-audience:ceo-private",
      principalRef: "slack-user:ceo",
      scope: "direct_message",
    },
    qm: {
      audienceRef: "qm-audience:ceo-private",
      principalRef: "qm:principal:ceo-canary",
      scope: "private_principal",
    },
    notion: {
      audienceRef: "audience:ceo-private",
      parentRef: "notion:ceo-private-root-v1",
      scope: "private_ceo",
    },
  },
  grantPolicy: {
    policyRef: "grant-policy:risely:ceo-shadow:v1",
    approvalRequired: true,
    delegationAllowed: false,
    maximumApprovalLifetimeMs: 86_400_000,
    maximumIdentityLifetimeMs: maximumTrustedIdentityLifetimeMs,
    maximumEvalReleaseLifetimeMs: 86_400_000,
    maximumProviderGrantLifetimeMs: 0,
  },
  evalPolicy: {
    policyRef: "eval-policy:risely:ceo-shadow:v1",
    requiredGates: [
      "ownership",
      "quality",
      "rate_limit",
      "recipient_safety",
      "research_depth",
      "source_integrity",
      "suppression",
      "voice_accuracy",
    ],
    requiredDeterministicCheckIds: [
      "release:artifact-ready",
      "release:evidence-grounded",
      "release:identity-profile-bound",
      "release:payload-content-addressed",
      "release:privacy-sanitized",
      "release:provider-capability-absent",
    ],
    minimumIndependentJudges: 2,
    judgeClasses: ["quality", "safety"],
    independentOriginsRequired: true,
    selfReviewAllowed: false,
    maximumRepairAttempts: 2,
    sideEffectBudget: 0,
    minimumScore: 4,
    maximumScoreSpread: 1,
    maximumEvaluationRuntimeMs: 900_000,
    trustedJudgeRoots: [
      {
        keyId: "shadow-judge-key:quality:v2",
        judgeRef: "judge:risely:quality:v2",
        judgeClass: "quality",
        originRef: "judge-origin:risely:quality:v2",
        publicKey: { crv: "Ed25519", x: "QLtK7FZX48wEvWfvqUyk08TX9rmHlp4ECpge8IqmcUc", kty: "OKP" },
      },
      {
        keyId: "shadow-judge-key:safety:v2",
        judgeRef: "judge:risely:safety:v2",
        judgeClass: "safety",
        originRef: "judge-origin:risely:safety:v2",
        publicKey: { crv: "Ed25519", x: "5QJxmRPbmz2m7UgvauW5E3sPQ5eF8Zrld37wtmpAjSU", kty: "OKP" },
      },
    ],
  },
};

export const ceoDeploymentProfile = createProfileAuthority(profileProjection);
export const bundledCeoProfileSha256 = ceoDeploymentProfile.profileSha256;

const expansionPolicy = freezeProfileData({
  secondProfileState: "test_only",
  durableCompositeScopeVerified: true,
  requiredDurableColumns: ["profile_ref", "profile_sha256"],
  blocker: null,
});

const registryProjection = freezeProfileData({
  contractType: "risely-deployment-profile-registry",
  contractVersion: 2,
  digestRevision: "DeploymentProfileRegistry.sha256.v2",
  registryRef: "deployment-profile-registry:risely:v2",
  profiles: [ceoDeploymentProfile],
  expansionPolicy,
});

export const bundledDeploymentProfileRegistrySha256 = hashProfileData(registryProjection);
export const deploymentProfileRegistry = freezeProfileData({
  ...registryProjection,
  registrySha256: bundledDeploymentProfileRegistrySha256,
});

export function resolveProductionDeploymentProfile(profileRef) {
  if (profileRef !== ceoDeploymentProfile.profileRef) fail("unsupported_deployment_profile");
  return ceoDeploymentProfile;
}

export function validateDeploymentProfile(value) {
  try {
    const profile = assertProfileAuthority(value);
    if (profile !== ceoDeploymentProfile) fail("unsupported_deployment_profile");
    return profile;
  } catch (error) {
    if (error?.code === "unsupported_deployment_profile") throw error;
    fail("unsupported_deployment_profile");
  }
}

export function validateDeploymentProfileRegistry(value) {
  if (value !== deploymentProfileRegistry) fail("unsupported_profile_registry");
  return deploymentProfileRegistry;
}

export function toCeoPrincipalBinding(value = ceoDeploymentProfile) {
  const profile = validateDeploymentProfile(value);
  const projection = {
    contractType: "PrincipalBinding",
    contractVersion: 2,
    digestRevision: "PrincipalBinding.sha256.v2",
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
  };
  return freezeProfileData({ ...projection, bindingSha256: hashProfileData(projection) });
}

const trustedIdentityFields = Object.freeze([
  "contractType",
  "contractVersion",
  "digestRevision",
  "verificationState",
  "verificationAuthorityRef",
  "organizationRef",
  "deploymentRef",
  "tenantRef",
  "workspaceRef",
  "humanPrincipalRef",
  "humanEmail",
  "qmPrincipalRef",
  "externalIdentityRef",
  "externalOrganizationRole",
  "verifiedAt",
  "expiresAt",
  "verificationEvidenceSha256",
  "identitySha256",
]);
const requestFields = Object.freeze([
  "contractType",
  "contractVersion",
  "digestRevision",
  "resolutionState",
  "trustedQmIdentitySha256",
  "profileRef",
  "profileSha256",
  "activationMode",
  "providerExecutionAllowed",
  "blocker",
  "requestedAt",
  "expiresAt",
  "requestSha256",
]);

const validateTrustedIdentityShape = (value, now) => {
  const input = exact(
    snapshotProfileData(value, "trustedQmIdentity"),
    trustedIdentityFields,
    "invalid_trusted_qm_identity_schema",
  );
  if (
    input.contractType !== "trusted-qm-identity" ||
    input.contractVersion !== 1 ||
    input.digestRevision !== "TrustedQmIdentity.sha256.v1" ||
    input.verificationState !== "verified" ||
    input.verificationAuthorityRef !== "qm-identity-verifier:risely:v1"
  ) {
    fail("untrusted_qm_identity");
  }
  const expected = {
    organizationRef: ceoDeploymentProfile.anchors.organizationRef,
    deploymentRef: ceoDeploymentProfile.anchors.deploymentRef,
    tenantRef: ceoDeploymentProfile.anchors.tenantRef,
    workspaceRef: ceoDeploymentProfile.anchors.workspaceRef,
    humanPrincipalRef: ceoDeploymentProfile.identity.humanPrincipalRef,
    humanEmail: ceoDeploymentProfile.identity.humanEmail,
    qmPrincipalRef: ceoDeploymentProfile.identity.qmPrincipalRef,
    externalIdentityRef: ceoDeploymentProfile.identity.externalIdentityRef,
    externalOrganizationRole: ceoDeploymentProfile.identity.externalOrganizationRole,
  };
  for (const [field, expectedValue] of Object.entries(expected)) {
    const actual =
      field === "humanEmail"
        ? assertEmail(input[field], `invalid_${field}`)
        : assertIdentifier(input[field], `invalid_${field}`);
    if (actual !== expectedValue) fail("mixed_or_unknown_qm_identity");
  }
  const verifiedAt = Date.parse(assertInstant(input.verifiedAt, "invalid_identity_verified_at"));
  const expiresAt = Date.parse(assertInstant(input.expiresAt, "invalid_identity_expires_at"));
  const nowMs = Date.parse(assertInstant(now, "invalid_identity_validation_time"));
  if (
    verifiedAt > nowMs ||
    expiresAt <= nowMs ||
    expiresAt - verifiedAt > ceoDeploymentProfile.grantPolicy.maximumIdentityLifetimeMs
  ) {
    fail("trusted_qm_identity_outside_lifetime");
  }
  assertDigest(input.verificationEvidenceSha256, "invalid_identity_verification_evidence");
  assertDigest(input.identitySha256, "invalid_identity_sha256");
  if (input.identitySha256 !== selfHash(input, "identitySha256")) fail("identity_sha256_mismatch");
  return freezeProfileData(input);
};

export function validateTrustedQmIdentityInput(value, now = new Date().toISOString()) {
  return validateTrustedIdentityShape(value, now);
}

export function validateUnresolvedProfileResolutionRequest(value) {
  const input = exact(
    snapshotProfileData(value, "profileResolutionRequest"),
    requestFields,
    "invalid_resolution_request_schema",
  );
  if (
    input.contractType !== "deployment-profile-resolution-request" ||
    input.contractVersion !== 1 ||
    input.digestRevision !== "DeploymentProfileResolutionRequest.sha256.v1" ||
    input.resolutionState !== "unresolved" ||
    input.profileRef !== null ||
    input.profileSha256 !== null ||
    input.activationMode !== "shadow" ||
    input.providerExecutionAllowed !== false ||
    input.blocker !== resolutionBlocker
  ) {
    fail("resolution_request_must_remain_inert");
  }
  assertDigest(input.trustedQmIdentitySha256, "invalid_resolution_identity_sha256");
  const requestedAt = Date.parse(assertInstant(input.requestedAt, "invalid_resolution_requested_at"));
  const expiresAt = Date.parse(assertInstant(input.expiresAt, "invalid_resolution_expires_at"));
  if (
    expiresAt <= requestedAt ||
    expiresAt - requestedAt >
      Math.min(maximumResolutionRequestLifetimeMs, ceoDeploymentProfile.grantPolicy.maximumIdentityLifetimeMs)
  ) {
    fail("invalid_resolution_request_lifetime");
  }
  assertDigest(input.requestSha256, "invalid_resolution_request_sha256");
  if (input.requestSha256 !== selfHash(input, "requestSha256")) fail("resolution_request_sha256_mismatch");
  return freezeProfileData(input);
}

export function requestDeploymentProfileResolution(trustedQmIdentity, requestedAt = new Date().toISOString()) {
  const identity = validateTrustedIdentityShape(trustedQmIdentity, requestedAt);
  const requestedAtMs = Date.parse(requestedAt);
  const expiresAtMs = Math.min(
    Date.parse(identity.expiresAt),
    requestedAtMs + maximumResolutionRequestLifetimeMs,
    requestedAtMs + ceoDeploymentProfile.grantPolicy.maximumIdentityLifetimeMs,
  );
  if (expiresAtMs <= requestedAtMs) fail("trusted_qm_identity_outside_lifetime");
  const projection = {
    contractType: "deployment-profile-resolution-request",
    contractVersion: 1,
    digestRevision: "DeploymentProfileResolutionRequest.sha256.v1",
    resolutionState: "unresolved",
    trustedQmIdentitySha256: identity.identitySha256,
    profileRef: null,
    profileSha256: null,
    activationMode: "shadow",
    providerExecutionAllowed: false,
    blocker: resolutionBlocker,
    requestedAt,
    expiresAt: new Date(expiresAtMs).toISOString(),
  };
  return validateUnresolvedProfileResolutionRequest({ ...projection, requestSha256: hashProfileData(projection) });
}

export const profileExpansionAvailability = expansionPolicy;
