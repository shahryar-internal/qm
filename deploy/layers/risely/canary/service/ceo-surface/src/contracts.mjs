import { validateArtifact } from "../../../presentation/index.mjs";
import { OutboxEvent, PrincipalBinding, PublicationEnvelope } from "../../../shared-contracts/index.mjs";
import { fixedCeoSurface } from "./constants.mjs";
import { assertRuntimeScope } from "../../../runtime-scope/index.mjs";
import { ceoDeploymentProfile } from "../../../deployment-profiles/index.mjs";
import {
  boolean,
  deepFreeze,
  email,
  exactKeys,
  hash,
  identifier,
  integer,
  sha256Canonical,
  slackDirectMessageId,
  slackTeamId,
  slackUserId,
  text,
  timestamp,
  uniqueIdentifiers,
} from "./validation.mjs";

const ceoIdentity = PrincipalBinding.identity;
const snapshot = PrincipalBinding.snapshot;
const deploymentStates = new WeakMap();
const ceoState = Object.freeze({
  identity: ceoIdentity,
  contracts: Object.freeze({ OutboxEvent, PublicationEnvelope }),
  maximumEvalReleaseLifetimeMs: ceoDeploymentProfile.grantPolicy.maximumEvalReleaseLifetimeMs,
  maximumIdentityLifetimeMs: ceoDeploymentProfile.grantPolicy.maximumIdentityLifetimeMs,
});

const deploymentKeys = [
  "contractType",
  "contractVersion",
  "ceoUserRef",
  "ceoEmail",
  "qmPrincipalRef",
  "credentialOwnerRef",
  "slackTeamId",
  "evalAuthorityRef",
  "evalPolicySha256",
  "identityResolverAuthorityRef",
];
const evalKeys = [
  "contractType",
  "contractVersion",
  "evalRunId",
  "evalAuthorityRef",
  "deploymentBindingSha256",
  "artifactId",
  "artifactRevision",
  "artifactSha256",
  "mode",
  "passed",
  "release",
  "sideEffects",
  "deterministicCheckIds",
  "judgeIds",
  "judgeIndependenceKeys",
  "policySha256",
  "rubricVersion",
  "evaluatedAt",
  "expiresAt",
  "receiptSha256",
];
const outboxKeys = [
  "contractType",
  "contractVersion",
  "eventId",
  "deploymentBindingSha256",
  "artifact",
  "artifactSha256",
  "evalRelease",
  "queuedAt",
  "payloadSha256",
];
const canonicalOutboxKeys = [...outboxKeys, "canonicalEvent", "publicationEnvelope"];
const identityKeys = [
  "contractType",
  "contractVersion",
  "resolverReceiptRef",
  "resolverAuthorityRef",
  "deploymentBindingSha256",
  "teamRef",
  "ceoUserRef",
  "ceoEmail",
  "qmPrincipalRef",
  "credentialOwnerRef",
  "slackTeamId",
  "slackUserId",
  "slackDirectMessageId",
  "resolvedAt",
  "expiresAt",
  "resolutionSha256",
];

function selfHash(value, field) {
  const payload = { ...value };
  delete payload[field];
  return sha256Canonical(payload);
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) throw new TypeError(`${label} does not match its bound value`);
}

function compileDeploymentBindingForState(value, state) {
  const input = exactKeys(snapshot(value, "deploymentBinding"), deploymentKeys, deploymentKeys, "deploymentBinding");
  const identity = state.identity;
  if (input.contractType !== "ceo-surface-deployment")
    throw new TypeError("deploymentBinding.contractType is not supported");
  if (input.contractVersion !== fixedCeoSurface.contractVersion)
    throw new TypeError("deploymentBinding.contractVersion is not supported");
  const binding = Object.freeze({
    contractType: "ceo-surface-deployment",
    contractVersion: fixedCeoSurface.contractVersion,
    profileRef: identity.profileRef,
    profileSha256: identity.profileSha256,
    organizationRef: identity.organizationRef,
    deploymentId: identity.deploymentRef,
    deploymentRef: identity.deploymentRef,
    principalBindingRef: identity.principalBindingRef,
    principalRef: identity.principalRef,
    teamRef: identity.slackTeamRef,
    audienceRef: identity.audienceRef,
    ceoUserRef: identifier(input.ceoUserRef, "deploymentBinding.ceoUserRef"),
    ceoEmail: email(input.ceoEmail, "deploymentBinding.ceoEmail"),
    qmPrincipalRef: identifier(input.qmPrincipalRef, "deploymentBinding.qmPrincipalRef"),
    credentialOwnerRef: identifier(input.credentialOwnerRef, "deploymentBinding.credentialOwnerRef"),
    slackTeamId: slackTeamId(input.slackTeamId, "deploymentBinding.slackTeamId"),
    evalAuthorityRef: identifier(input.evalAuthorityRef, "deploymentBinding.evalAuthorityRef"),
    evalPolicySha256: hash(input.evalPolicySha256, "deploymentBinding.evalPolicySha256"),
    identityResolverAuthorityRef: identifier(
      input.identityResolverAuthorityRef,
      "deploymentBinding.identityResolverAuthorityRef",
    ),
    qmRootUrl: fixedCeoSurface.qmRootUrl,
    qmAuthenticationMode: fixedCeoSurface.qmAuthenticationMode,
    deliveryMode: fixedCeoSurface.deliveryMode,
  });
  assertEqual(binding.ceoUserRef, identity.slackUserRef, "deploymentBinding.ceoUserRef");
  assertEqual(binding.ceoEmail, identity.principalEmail, "deploymentBinding.ceoEmail");
  assertEqual(binding.qmPrincipalRef, identity.qmPrincipalRef, "deploymentBinding.qmPrincipalRef");
  assertEqual(binding.credentialOwnerRef, identity.credentialOwnerRef, "deploymentBinding.credentialOwnerRef");
  const compiled = Object.freeze({ ...binding, bindingSha256: sha256Canonical(binding) });
  deploymentStates.set(compiled, state);
  return compiled;
}

export function compileDeploymentBinding(value) {
  return compileDeploymentBindingForState(value, ceoState);
}

export function createSurfaceContractSuite(runtimeScope) {
  const scope = assertRuntimeScope(runtimeScope);
  const state = Object.freeze({
    identity: scope.contracts.PrincipalBinding.identity,
    contracts: scope.contracts,
    maximumEvalReleaseLifetimeMs: scope.profile.grantPolicy.maximumEvalReleaseLifetimeMs,
    maximumIdentityLifetimeMs: scope.profile.grantPolicy.maximumIdentityLifetimeMs,
  });
  const assertDeployment = (deployment) => {
    if (deploymentStates.get(deployment) !== state)
      throw new TypeError("deploymentBinding does not belong to this runtime scope");
    return deployment;
  };
  return Object.freeze({
    compileDeploymentBinding: (value) => compileDeploymentBindingForState(value, state),
    validateOutboxItem: (value, deployment, now) => validateOutboxItem(value, assertDeployment(deployment), now),
    validateIdentityResolution: (value, deployment, now) =>
      validateIdentityResolution(value, assertDeployment(deployment), now),
  });
}

export function deriveSurfaceOutboxEventId(artifact, deployment) {
  const state = deploymentStates.get(deployment) ?? ceoState;
  return state.contracts.OutboxEvent.deriveId({
    profileRef: deployment.profileRef,
    profileSha256: deployment.profileSha256,
    deploymentRef: deployment.deploymentRef,
    principalRef: deployment.principalRef,
    artifactRef: artifact.id,
    revision: artifact.revision,
    surface: "slack",
    audienceRef: deployment.audienceRef,
  });
}

export function evalReleaseReceiptHash(value) {
  return selfHash(snapshot(value, "evalRelease"), "receiptSha256");
}

export function outboxPayloadHash(value) {
  return selfHash(snapshot(value, "outboxItem"), "payloadSha256");
}

export function identityResolutionHash(value) {
  return selfHash(snapshot(value, "identityResolution"), "resolutionSha256");
}

export function validateEvalRelease(value, artifact, artifactSha256, deployment, now) {
  const state = deploymentStates.get(deployment) ?? ceoState;
  const input = exactKeys(snapshot(value, "evalRelease"), evalKeys, evalKeys, "evalRelease");
  if (input.contractType !== "eval-release" || input.contractVersion !== 1)
    throw new TypeError("evalRelease contract is not supported");
  const receipt = Object.freeze({
    contractType: "eval-release",
    contractVersion: 1,
    evalRunId: identifier(input.evalRunId, "evalRelease.evalRunId"),
    evalAuthorityRef: identifier(input.evalAuthorityRef, "evalRelease.evalAuthorityRef"),
    deploymentBindingSha256: hash(input.deploymentBindingSha256, "evalRelease.deploymentBindingSha256"),
    artifactId: identifier(input.artifactId, "evalRelease.artifactId"),
    artifactRevision: text(input.artifactRevision, "evalRelease.artifactRevision", 64),
    artifactSha256: hash(input.artifactSha256, "evalRelease.artifactSha256"),
    mode: text(input.mode, "evalRelease.mode", 16),
    passed: boolean(input.passed, "evalRelease.passed"),
    release: boolean(input.release, "evalRelease.release"),
    sideEffects: integer(input.sideEffects, "evalRelease.sideEffects", 0, 0),
    deterministicCheckIds: uniqueIdentifiers(input.deterministicCheckIds, "evalRelease.deterministicCheckIds", 1, 100),
    judgeIds: uniqueIdentifiers(input.judgeIds, "evalRelease.judgeIds", 2, 10),
    judgeIndependenceKeys: uniqueIdentifiers(input.judgeIndependenceKeys, "evalRelease.judgeIndependenceKeys", 2, 10),
    policySha256: hash(input.policySha256, "evalRelease.policySha256"),
    rubricVersion: identifier(input.rubricVersion, "evalRelease.rubricVersion"),
    evaluatedAt: timestamp(input.evaluatedAt, "evalRelease.evaluatedAt"),
    expiresAt: timestamp(input.expiresAt, "evalRelease.expiresAt"),
    receiptSha256: hash(input.receiptSha256, "evalRelease.receiptSha256"),
  });
  if (receipt.mode !== "shadow" || !receipt.passed || !receipt.release)
    throw new TypeError("evalRelease must be an eval-passed shadow release");
  if (receipt.judgeIds.length !== receipt.judgeIndependenceKeys.length)
    throw new TypeError("evalRelease judges must have exact independent origins");
  assertEqual(receipt.artifactId, artifact.id, "evalRelease.artifactId");
  assertEqual(receipt.artifactRevision, artifact.revision, "evalRelease.artifactRevision");
  assertEqual(receipt.artifactSha256, artifactSha256, "evalRelease.artifactSha256");
  assertEqual(receipt.deploymentBindingSha256, deployment.bindingSha256, "evalRelease.deploymentBindingSha256");
  assertEqual(receipt.evalAuthorityRef, deployment.evalAuthorityRef, "evalRelease.evalAuthorityRef");
  assertEqual(receipt.policySha256, deployment.evalPolicySha256, "evalRelease.policySha256");
  if (Date.parse(receipt.evaluatedAt) > Date.parse(now))
    throw new TypeError("evalRelease.evaluatedAt cannot be in the future");
  if (Date.parse(receipt.expiresAt) <= Date.parse(now)) throw new TypeError("evalRelease is expired");
  if (Date.parse(receipt.expiresAt) - Date.parse(receipt.evaluatedAt) > state.maximumEvalReleaseLifetimeMs)
    throw new TypeError("evalRelease lifetime exceeds the deployment policy");
  assertEqual(receipt.receiptSha256, selfHash(receipt, "receiptSha256"), "evalRelease.receiptSha256");
  return receipt;
}

export function validateOutboxItem(value, deployment, now = new Date().toISOString()) {
  const state = deploymentStates.get(deployment) ?? ceoState;
  const source = snapshot(value, "outboxItem");
  if (source.contractType === "ceo-surface-canonical-outbox") {
    const input = exactKeys(source, canonicalOutboxKeys, canonicalOutboxKeys, "outboxItem");
    if (input.contractVersion !== 1) throw new TypeError("outboxItem contract is not supported");
    const event = state.contracts.OutboxEvent.validate(input.canonicalEvent);
    const envelope = state.contracts.PublicationEnvelope.validate(input.publicationEnvelope, event);
    const artifact = exactKeys(input.artifact, ["id", "revision"], ["id", "revision"], "outboxItem.artifact");
    const evalRelease = exactKeys(
      input.evalRelease,
      ["evaluatedAt", "expiresAt", "receiptSha256"],
      ["evaluatedAt", "expiresAt", "receiptSha256"],
      "outboxItem.evalRelease",
    );
    const result = deepFreeze({
      contractType: "ceo-surface-canonical-outbox",
      contractVersion: 1,
      eventId: event.eventId,
      deploymentBindingSha256: hash(input.deploymentBindingSha256, "outboxItem.deploymentBindingSha256"),
      artifact: {
        id: identifier(artifact.id, "outboxItem.artifact.id"),
        revision: hash(artifact.revision, "outboxItem.artifact.revision"),
      },
      artifactSha256: hash(input.artifactSha256, "outboxItem.artifactSha256"),
      evalRelease: {
        evaluatedAt: timestamp(evalRelease.evaluatedAt, "outboxItem.evalRelease.evaluatedAt"),
        expiresAt: timestamp(evalRelease.expiresAt, "outboxItem.evalRelease.expiresAt"),
        receiptSha256: hash(evalRelease.receiptSha256, "outboxItem.evalRelease.receiptSha256"),
      },
      queuedAt: timestamp(input.queuedAt, "outboxItem.queuedAt"),
      payloadSha256: hash(input.payloadSha256, "outboxItem.payloadSha256"),
      canonicalEvent: event,
      publicationEnvelope: envelope,
    });
    assertEqual(result.deploymentBindingSha256, deployment.bindingSha256, "outboxItem.deploymentBindingSha256");
    assertEqual(result.artifact.id, event.artifact.artifactRef, "outboxItem.artifact.id");
    assertEqual(result.artifact.revision, event.artifact.revision, "outboxItem.artifact.revision");
    assertEqual(result.artifactSha256, event.artifact.artifactSha256, "outboxItem.artifactSha256");
    assertEqual(result.evalRelease.evaluatedAt, event.evalRelease.evaluatedAt, "outboxItem.evalRelease.evaluatedAt");
    assertEqual(result.evalRelease.expiresAt, event.evalRelease.expiresAt, "outboxItem.evalRelease.expiresAt");
    assertEqual(
      result.evalRelease.receiptSha256,
      event.evalRelease.releaseSha256,
      "outboxItem.evalRelease.receiptSha256",
    );
    assertEqual(result.queuedAt, event.queuedAt, "outboxItem.queuedAt");
    assertEqual(result.payloadSha256, envelope.envelopeSha256, "outboxItem.payloadSha256");
    if (Date.parse(result.evalRelease.expiresAt) <= Date.parse(now)) throw new TypeError("evalRelease is expired");
    if (Date.parse(result.queuedAt) > Date.parse(now))
      throw new TypeError("outboxItem.queuedAt cannot be in the future");
    return result;
  }
  const input = exactKeys(source, outboxKeys, outboxKeys, "outboxItem");
  if (input.contractType !== "ceo-surface-outbox" || input.contractVersion !== 1)
    throw new TypeError("outboxItem contract is not supported");
  if (input.artifact?.version !== 1) throw new TypeError("outboxItem.artifact must be an explicitly typed v1 artifact");
  const artifact = validateArtifact(input.artifact);
  timestamp(artifact.updatedAt, "outboxItem.artifact.updatedAt");
  for (let index = 0; index < artifact.evidence.length; index += 1) {
    if (artifact.evidence[index].occurredAt !== undefined)
      timestamp(artifact.evidence[index].occurredAt, `outboxItem.artifact.evidence[${index}].occurredAt`);
  }
  const artifactSha256 = sha256Canonical(artifact);
  const queuedAt = timestamp(input.queuedAt, "outboxItem.queuedAt");
  const evalRelease = validateEvalRelease(input.evalRelease, artifact, artifactSha256, deployment, now);
  if (Date.parse(artifact.updatedAt) > Date.parse(evalRelease.evaluatedAt))
    throw new TypeError("outboxItem.artifact.updatedAt cannot postdate evaluation");
  const result = deepFreeze({
    contractType: "ceo-surface-outbox",
    contractVersion: 1,
    eventId: identifier(input.eventId, "outboxItem.eventId"),
    deploymentBindingSha256: hash(input.deploymentBindingSha256, "outboxItem.deploymentBindingSha256"),
    artifact,
    artifactSha256: hash(input.artifactSha256, "outboxItem.artifactSha256"),
    evalRelease,
    queuedAt,
    payloadSha256: hash(input.payloadSha256, "outboxItem.payloadSha256"),
  });
  assertEqual(result.deploymentBindingSha256, deployment.bindingSha256, "outboxItem.deploymentBindingSha256");
  assertEqual(result.artifactSha256, artifactSha256, "outboxItem.artifactSha256");
  assertEqual(result.eventId, deriveSurfaceOutboxEventId(artifact, deployment), "outboxItem.eventId");
  if (Date.parse(result.evalRelease.evaluatedAt) > Date.parse(queuedAt))
    throw new TypeError("outboxItem cannot precede evaluation");
  if (Date.parse(queuedAt) > Date.parse(now)) throw new TypeError("outboxItem.queuedAt cannot be in the future");
  assertEqual(result.payloadSha256, selfHash(result, "payloadSha256"), "outboxItem.payloadSha256");
  return result;
}

export function validateIdentityResolution(value, deployment, now = new Date().toISOString()) {
  const state = deploymentStates.get(deployment) ?? ceoState;
  const input = exactKeys(snapshot(value, "identityResolution"), identityKeys, identityKeys, "identityResolution");
  if (input.contractType !== "ceo-surface-identity-resolution" || input.contractVersion !== 1)
    throw new TypeError("identityResolution contract is not supported");
  const result = Object.freeze({
    contractType: "ceo-surface-identity-resolution",
    contractVersion: 1,
    resolverReceiptRef: identifier(input.resolverReceiptRef, "identityResolution.resolverReceiptRef"),
    resolverAuthorityRef: identifier(input.resolverAuthorityRef, "identityResolution.resolverAuthorityRef"),
    deploymentBindingSha256: hash(input.deploymentBindingSha256, "identityResolution.deploymentBindingSha256"),
    teamRef: identifier(input.teamRef, "identityResolution.teamRef"),
    ceoUserRef: identifier(input.ceoUserRef, "identityResolution.ceoUserRef"),
    ceoEmail: email(input.ceoEmail, "identityResolution.ceoEmail"),
    qmPrincipalRef: identifier(input.qmPrincipalRef, "identityResolution.qmPrincipalRef"),
    credentialOwnerRef: identifier(input.credentialOwnerRef, "identityResolution.credentialOwnerRef"),
    slackTeamId: slackTeamId(input.slackTeamId, "identityResolution.slackTeamId"),
    slackUserId: slackUserId(input.slackUserId, "identityResolution.slackUserId"),
    slackDirectMessageId: slackDirectMessageId(input.slackDirectMessageId, "identityResolution.slackDirectMessageId"),
    resolvedAt: timestamp(input.resolvedAt, "identityResolution.resolvedAt"),
    expiresAt: timestamp(input.expiresAt, "identityResolution.expiresAt"),
    resolutionSha256: hash(input.resolutionSha256, "identityResolution.resolutionSha256"),
  });
  for (const key of [
    "deploymentBindingSha256",
    "teamRef",
    "ceoUserRef",
    "ceoEmail",
    "qmPrincipalRef",
    "credentialOwnerRef",
    "slackTeamId",
  ]) {
    const expected = key === "deploymentBindingSha256" ? deployment.bindingSha256 : deployment[key];
    assertEqual(result[key], expected, `identityResolution.${key}`);
  }
  assertEqual(
    result.resolverAuthorityRef,
    deployment.identityResolverAuthorityRef,
    "identityResolution.resolverAuthorityRef",
  );
  if (Date.parse(result.resolvedAt) > Date.parse(now))
    throw new TypeError("identityResolution.resolvedAt cannot be in the future");
  if (Date.parse(result.expiresAt) <= Date.parse(now)) throw new TypeError("identityResolution is expired");
  if (Date.parse(result.expiresAt) - Date.parse(result.resolvedAt) > state.maximumIdentityLifetimeMs)
    throw new TypeError("identityResolution lifetime exceeds the deployment policy");
  assertEqual(result.resolutionSha256, selfHash(result, "resolutionSha256"), "identityResolution.resolutionSha256");
  return result;
}
