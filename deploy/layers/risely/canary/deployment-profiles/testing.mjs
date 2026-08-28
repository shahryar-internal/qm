import { createProfileAuthority, freezeProfileData } from "./contract.mjs";
import { ceoDeploymentProfile } from "./index.mjs";

export const syntheticTestJudgeRoots = freezeProfileData([
  {
    keyId: "shadow-judge-key:quality:test:v1",
    judgeRef: "judge:risely:quality:test:v1",
    judgeClass: "quality",
    originRef: "judge-origin:risely:quality:test:v1",
    publicKey: { crv: "Ed25519", x: "O_mBEVj8m8GN4RKbNP-5KZlxykRmIJpcsY1mQeCqdqk", kty: "OKP" },
  },
  {
    keyId: "shadow-judge-key:safety:test:v1",
    judgeRef: "judge:risely:safety:test:v1",
    judgeClass: "safety",
    originRef: "judge-origin:risely:safety:test:v1",
    publicKey: { crv: "Ed25519", x: "k1nXE1qjyyrW0ZxmvMAKTvF3oyNeK1A7Vv-s0gKpGu8", kty: "OKP" },
  },
]);

export const syntheticTestJudgePrivateKeys = freezeProfileData({
  "shadow-judge-key:quality:test:v1": {
    crv: "Ed25519",
    d: "e8r7J1z3K5eM2qQFHNhX8f3dOfYZyzv9Up0LTw9XOrA",
    x: "O_mBEVj8m8GN4RKbNP-5KZlxykRmIJpcsY1mQeCqdqk",
    kty: "OKP",
  },
  "shadow-judge-key:safety:test:v1": {
    crv: "Ed25519",
    d: "urrw8LxAXbNRAeIJri7OgCxH8x9E44ZOwMg0kx4QwmY",
    x: "k1nXE1qjyyrW0ZxmvMAKTvF3oyNeK1A7Vv-s0gKpGu8",
    kty: "OKP",
  },
});

const syntheticProjection = {
  ...structuredClone(ceoDeploymentProfile),
  profileRef: "deployment-profile:risely:synthetic:v1",
  anchors: {
    organizationRef: "organization:risely:synthetic",
    deploymentRef: "deployment:risely:synthetic:v1",
    tenantRef: "tenant:risely:synthetic",
    workspaceRef: "workspace:risely:synthetic",
    principalBindingRef: "principal-binding:risely:synthetic:v1",
    slackTeamRef: "slack-team:risely:synthetic",
  },
  identity: {
    humanPrincipalRef: "principal:synthetic",
    humanEmail: "synthetic@risely.invalid",
    qmPrincipalRef: "qm:principal:synthetic",
    externalIdentityRef: "external-identity:risely:synthetic",
    externalOrganizationRole: "synthetic",
    credentialOwnerRef: "credential-owner:synthetic",
  },
  agent: {
    agentId: "agent:risely:synthetic",
    agentVersion: "1.0.0",
    agentScope: "synthetic_inert",
  },
  providerOwners: ceoDeploymentProfile.providerOwners.map(({ provider }) => ({
    provider,
    providerOwnerRef: `provider-owner:${provider}:synthetic`,
  })),
  audiences: {
    slack: {
      audienceRef: "slack-audience:synthetic",
      principalRef: "slack-user:synthetic",
      scope: "synthetic_inert",
    },
    qm: {
      audienceRef: "qm-audience:synthetic",
      principalRef: "qm:principal:synthetic",
      scope: "synthetic_inert",
    },
    notion: {
      audienceRef: "audience:synthetic",
      parentRef: "notion:synthetic-root",
      scope: "synthetic_inert",
    },
  },
  grantPolicy: {
    ...ceoDeploymentProfile.grantPolicy,
    policyRef: "grant-policy:risely:synthetic-inert:v1",
  },
  evalPolicy: {
    ...ceoDeploymentProfile.evalPolicy,
    policyRef: "eval-policy:risely:synthetic-inert:v1",
    trustedJudgeRoots: syntheticTestJudgeRoots,
  },
};

delete syntheticProjection.profileSha256;

export const syntheticDeploymentProfile = createProfileAuthority(syntheticProjection);
export const testDeploymentProfiles = freezeProfileData([ceoDeploymentProfile, syntheticDeploymentProfile]);
