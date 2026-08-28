import { createPublicKey, verify } from "node:crypto";
import { types } from "node:util";
import { createProviderEffectPolicySuite } from "../../canary/provider-effects/index.mjs";
import { assertRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import { canonicalJson } from "../../canary/shared-contracts/validation.mjs";

const authorities = new WeakMap();
const digestPattern = /^[0-9a-f]{64}$/u;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const errorCodePattern = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const base64urlPattern = /^[A-Za-z0-9_-]+$/u;
const proofClasses = Object.freeze([
  "kill_switch",
  "evaluation_release",
  "provider_identity",
  "resource_ownership",
  "approval",
  "reconciliation_identity",
  "durable_receipt",
]);
const storeMethods = Object.freeze([
  "readAuthorization",
  "reserveAttempt",
  "completeAttempt",
  "readReconciliation",
  "reserveReconciliation",
  "completeReconciliation",
  "isActive",
]);
const effectAdapterMethods = Object.freeze(["invoke", "isActive"]);
const reconciliationPortMethods = Object.freeze(["queryStatus", "isActive", "reconcilerPrincipalRef"]);
const authorizationFields = Object.freeze([
  "profileRef",
  "profileSha256",
  "proposal",
  "intentSha256",
  "prospectiveEffectKey",
  "policyRef",
  "policySha256",
  "capability",
  "capabilityVersion",
  "provider",
  "operation",
  "providerOwnerRef",
  "revision",
  "attempts",
  "databaseNow",
  "killSwitch",
  "evaluationRelease",
  "providerIdentity",
  "resourceOwnership",
  "approval",
]);
const attemptFields = Object.freeze([
  "profileRef",
  "profileSha256",
  "proposalId",
  "proposalHash",
  "intentSha256",
  "prospectiveEffectKey",
  "policySha256",
  "capability",
  "capabilityVersion",
  "provider",
  "operation",
  "providerOwnerRef",
  "authorizationSha256",
  "killSwitchRevision",
  "evaluationReleaseSha256",
  "providerIdentityReceiptSha256",
  "resourceOwnershipReceiptSha256",
  "approvalSha256",
  "approvalConsumedAt",
  "attemptRef",
  "attemptNumber",
  "status",
  "attemptedAt",
  "leaseExpiresAt",
  "revision",
]);
const resultFields = Object.freeze([
  "status",
  "provider",
  "operation",
  "providerOwnerRef",
  "providerResourceRef",
  "responseSha256",
  "errorCode",
  "observationMode",
  "providerMutationCount",
]);
const receiptFields = Object.freeze([
  "receiptId",
  "receiptSha256",
  "profileRef",
  "profileSha256",
  "proposalId",
  "proposalHash",
  "intentSha256",
  "prospectiveEffectKey",
  "attemptRef",
  "attemptNumber",
  "status",
  "provider",
  "operation",
  "providerOwnerRef",
  "providerResourceRef",
  "responseSha256",
  "errorCode",
  "observationMode",
  "providerMutationCount",
  "attemptedAt",
  "completedAt",
  "reconciliationRef",
  "priorReceiptSha256",
  "authenticatedBy",
  "authenticationSha256",
  "keyId",
  "issuerRef",
  "signature",
]);
const reconciliationFields = Object.freeze([
  "profileRef",
  "profileSha256",
  "proposal",
  "intentSha256",
  "prospectiveEffectKey",
  "policySha256",
  "capability",
  "capabilityVersion",
  "provider",
  "operation",
  "providerOwnerRef",
  "providerAccountRef",
  "providerResourceRef",
  "attemptRef",
  "attemptNumber",
  "attemptedAt",
  "attemptLeaseExpiresAt",
  "priorStatus",
  "priorReceiptSha256",
  "databaseNow",
  "killSwitch",
  "reconciliationIdentity",
  "revision",
]);
const reconciliationLeaseFields = Object.freeze([
  "profileRef",
  "profileSha256",
  "proposalId",
  "proposalHash",
  "intentSha256",
  "prospectiveEffectKey",
  "attemptRef",
  "priorReceiptSha256",
  "authenticationSha256",
  "killSwitchRevision",
  "reconciliationRef",
  "reconcilerPrincipalRef",
  "mode",
  "acquiredAt",
  "expiresAt",
  "revision",
]);

export class ProviderEffectAuthorityError extends Error {
  constructor(code) {
    super(code);
    this.name = "ProviderEffectAuthorityError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new ProviderEffectAuthorityError(code);
};

const exactPort = (value, fields, code) => {
  if (
    !value ||
    typeof value !== "object" ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(code);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Object.getOwnPropertySymbols(value).length !== 0 ||
    Object.keys(descriptors).length !== fields.length ||
    fields.some((field) => {
      const descriptor = descriptors[field];
      return !descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value");
    })
  ) {
    fail(code);
  }
  return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]));
};

const snapshot = (scope, value, fields, code) => {
  let input;
  try {
    input = scope.contracts.PrincipalBinding.snapshot(value, code);
  } catch {
    fail(code);
  }
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(input, field))
  ) {
    fail(code);
  }
  return input;
};

const identifier = (value, code) => {
  if (typeof value !== "string" || !identifierPattern.test(value)) fail(code);
  return value;
};

const digest = (value, code) => {
  if (typeof value !== "string" || !digestPattern.test(value)) fail(code);
  return value;
};

const instant = (value, code) => {
  if (typeof value !== "string" || new Date(value).toISOString() !== value) fail(code);
  return value;
};

const errorCode = (value, code) => {
  if (value !== null && (typeof value !== "string" || !errorCodePattern.test(value))) fail(code);
  return value;
};

const normalizeProofIssuers = (value, capabilities) => {
  if (!Array.isArray(value) || value.length < proofClasses.length) fail("provider_effect_proof_issuers_invalid");
  const issuers = value.map((entry) => {
    const input = exactPort(
      entry,
      ["keyId", "issuerRef", "proofClass", "capabilities", "publicKey"],
      "provider_effect_proof_issuers_invalid",
    );
    identifier(input.keyId, "provider_effect_proof_issuers_invalid");
    identifier(input.issuerRef, "provider_effect_proof_issuers_invalid");
    if (!proofClasses.includes(input.proofClass)) fail("provider_effect_proof_issuers_invalid");
    if (
      !Array.isArray(input.capabilities) ||
      input.capabilities.length < 1 ||
      new Set(input.capabilities).size !== input.capabilities.length ||
      input.capabilities.some((capability) => !capabilities.includes(capability))
    ) {
      fail("provider_effect_proof_issuers_invalid");
    }
    const publicKey = exactPort(input.publicKey, ["crv", "x", "kty"], "provider_effect_proof_issuers_invalid");
    if (
      publicKey.crv !== "Ed25519" ||
      publicKey.kty !== "OKP" ||
      typeof publicKey.x !== "string" ||
      !base64urlPattern.test(publicKey.x)
    ) {
      fail("provider_effect_proof_issuers_invalid");
    }
    let verifier;
    try {
      verifier = createPublicKey({ key: publicKey, format: "jwk" });
    } catch {
      fail("provider_effect_proof_issuers_invalid");
    }
    return Object.freeze({ ...input, capabilities: Object.freeze([...input.capabilities]), publicKey, verifier });
  });
  if (
    new Set(issuers.map((issuer) => issuer.keyId)).size !== issuers.length ||
    new Set(issuers.map((issuer) => issuer.issuerRef)).size !== issuers.length ||
    new Set(issuers.map((issuer) => issuer.publicKey.x)).size !== issuers.length ||
    proofClasses.some((proofClass) => !issuers.some((issuer) => issuer.proofClass === proofClass))
  ) {
    fail("provider_effect_proof_issuers_invalid");
  }
  return new Map(issuers.map((issuer) => [`${issuer.proofClass}\n${issuer.keyId}`, issuer]));
};

const normalizeReconcilerPrincipals = (value, capabilities) => {
  if (!Array.isArray(value) || value.length < 1) fail("provider_effect_reconciler_registry_invalid");
  const entries = value.map((entry) => {
    const input = exactPort(
      entry,
      ["capability", "reconcilerPrincipalRef"],
      "provider_effect_reconciler_registry_invalid",
    );
    if (!capabilities.includes(input.capability)) fail("provider_effect_reconciler_registry_invalid");
    identifier(input.reconcilerPrincipalRef, "provider_effect_reconciler_registry_invalid");
    return Object.freeze(input);
  });
  if (
    new Set(entries.map((entry) => entry.capability)).size !== entries.length ||
    new Set(entries.map((entry) => entry.reconcilerPrincipalRef)).size !== entries.length
  ) {
    fail("provider_effect_reconciler_registry_invalid");
  }
  return new Map(entries.map((entry) => [entry.capability, entry.reconcilerPrincipalRef]));
};

const assertSignedProof = (state, input, proofClass, capability, digestField, code) => {
  identifier(input.keyId, code);
  identifier(input.issuerRef, code);
  if (typeof input.signature !== "string" || !base64urlPattern.test(input.signature)) fail(code);
  const issuer = state.proofIssuers.get(`${proofClass}\n${input.keyId}`);
  if (!issuer || issuer.issuerRef !== input.issuerRef || !issuer.capabilities.includes(capability)) fail(code);
  const hashProjection = { ...input };
  delete hashProjection[digestField];
  delete hashProjection.signature;
  if (input[digestField] !== state.scope.contracts.PrincipalBinding.hash(hashProjection)) fail(code);
  const signingProjection = { ...input };
  delete signingProjection.signature;
  let valid = false;
  try {
    valid = verify(
      null,
      Buffer.from(canonicalJson(signingProjection), "utf8"),
      issuer.verifier,
      Buffer.from(input.signature, "base64url"),
    );
  } catch {
    valid = false;
  }
  if (!valid) fail(code);
  return input;
};

const assertBoundPort = (value, methods, code) => {
  const port = exactPort(value, methods, code);
  if (
    methods
      .filter((method) => method !== "reconcilerPrincipalRef")
      .some((method) => typeof port[method] !== "function" || types.isProxy(port[method]))
  ) {
    fail(code);
  }
  return value;
};

const assertStore = (value) => Object.freeze(assertBoundPort(value, storeMethods, "provider_effect_store_invalid"));

const normalizeCapabilityPorts = (value, capabilities, methods, code) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) {
    fail(code);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0 ||
    Object.keys(descriptors).length < 1 ||
    Object.keys(descriptors).some((capability) => {
      if (!capabilities.includes(capability)) return true;
      const descriptor = descriptors[capability];
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) return true;
      try {
        assertBoundPort(descriptor.value, methods, code);
        return false;
      } catch {
        return true;
      }
    })
  ) {
    fail(code);
  }
  return Object.freeze(
    Object.fromEntries(
      Object.keys(descriptors).map((capability) => [capability, Object.freeze(descriptors[capability].value)]),
    ),
  );
};

const storeCall = async (state, method, value) => {
  if (state.store.isActive() !== true) fail("provider_effect_store_unavailable");
  const result = await state.store[method](value);
  if (state.store.isActive() !== true) fail("provider_effect_store_unavailable");
  return result;
};

const effectAdapterFor = (state, capability) => {
  const adapter = state.effectAdapters[capability];
  if (!adapter || adapter.isActive() !== true) fail("provider_effect_adapter_unavailable");
  return adapter;
};

const reconciliationPortFor = (state, capability) => {
  const port = state.reconciliationPorts[capability];
  if (!port || port.isActive() !== true || port.reconcilerPrincipalRef !== state.reconcilerPrincipals.get(capability)) {
    fail("provider_effect_reconciliation_port_unavailable");
  }
  return port;
};

const assertKillSwitch = (state, value, expectedProfileRef, expectedProfileSha256, capability) => {
  const { scope } = state;
  const input = snapshot(
    scope,
    value,
    [
      "profileRef",
      "profileSha256",
      "engaged",
      "revision",
      "checkedAt",
      "stateSha256",
      "keyId",
      "issuerRef",
      "signature",
    ],
    "provider_effect_kill_switch_invalid",
  );
  if (
    input.profileRef !== expectedProfileRef ||
    input.profileSha256 !== expectedProfileSha256 ||
    input.engaged !== false ||
    !Number.isSafeInteger(input.revision) ||
    input.revision < 0
  ) {
    fail(input.engaged === true ? "provider_effect_kill_switch_engaged" : "provider_effect_kill_switch_invalid");
  }
  instant(input.checkedAt, "provider_effect_kill_switch_invalid");
  return assertSignedProof(
    state,
    input,
    "kill_switch",
    capability,
    "stateSha256",
    "provider_effect_kill_switch_invalid",
  );
};

const assertEvaluationRelease = (state, value, authorization, now) => {
  const { scope } = state;
  const input = snapshot(
    scope,
    value,
    [
      "releaseId",
      "releaseSha256",
      "profileRef",
      "profileSha256",
      "proposalHash",
      "intentSha256",
      "policySha256",
      "passed",
      "providerReleaseEligible",
      "evaluatedAt",
      "expiresAt",
      "keyId",
      "issuerRef",
      "signature",
    ],
    "provider_effect_evaluation_release_invalid",
  );
  identifier(input.releaseId, "provider_effect_evaluation_release_invalid");
  digest(input.releaseSha256, "provider_effect_evaluation_release_invalid");
  if (
    input.profileRef !== authorization.profileRef ||
    input.profileSha256 !== authorization.profileSha256 ||
    input.proposalHash !== authorization.proposal.proposalHash ||
    input.intentSha256 !== authorization.intentSha256 ||
    input.policySha256 !== authorization.policySha256 ||
    input.passed !== true ||
    input.providerReleaseEligible !== true
  ) {
    fail("provider_effect_evaluation_release_invalid");
  }
  assertSignedProof(
    state,
    input,
    "evaluation_release",
    authorization.capability,
    "releaseSha256",
    "provider_effect_evaluation_release_invalid",
  );
  instant(input.evaluatedAt, "provider_effect_evaluation_release_invalid");
  instant(input.expiresAt, "provider_effect_evaluation_release_invalid");
  if (Date.parse(now) < Date.parse(input.evaluatedAt) || Date.parse(now) >= Date.parse(input.expiresAt)) {
    fail("provider_effect_evaluation_release_expired");
  }
  return input;
};

const assertProviderIdentity = (state, value, authorization, policy, now) => {
  const { scope } = state;
  const input = snapshot(
    scope,
    value,
    [
      "receiptId",
      "receiptSha256",
      "verificationSha256",
      "profileRef",
      "profileSha256",
      "provider",
      "providerOwnerRef",
      "providerAccountRef",
      "credentialOwnerRef",
      "verifiedBy",
      "verifiedAt",
      "expiresAt",
      "keyId",
      "issuerRef",
      "signature",
    ],
    "provider_effect_identity_receipt_invalid",
  );
  for (const field of ["receiptId", "providerAccountRef", "credentialOwnerRef", "verifiedBy"]) {
    identifier(input[field], "provider_effect_identity_receipt_invalid");
  }
  digest(input.receiptSha256, "provider_effect_identity_receipt_invalid");
  digest(input.verificationSha256, "provider_effect_identity_receipt_invalid");
  if (
    input.profileRef !== authorization.profileRef ||
    input.profileSha256 !== authorization.profileSha256 ||
    input.provider !== authorization.provider ||
    input.providerOwnerRef !== authorization.providerOwnerRef ||
    input.credentialOwnerRef !== authorization.proposal.actor.credentialOwnerRef ||
    input.verifiedBy !== input.issuerRef
  ) {
    fail("provider_effect_identity_receipt_invalid");
  }
  assertSignedProof(
    state,
    input,
    "provider_identity",
    authorization.capability,
    "receiptSha256",
    "provider_effect_identity_receipt_invalid",
  );
  instant(input.verifiedAt, "provider_effect_identity_receipt_invalid");
  instant(input.expiresAt, "provider_effect_identity_receipt_invalid");
  if (Date.parse(now) < Date.parse(input.verifiedAt) || Date.parse(now) >= Date.parse(input.expiresAt)) {
    fail("provider_effect_identity_receipt_expired");
  }
  if (
    policy.maximumGrantLifetimeMs > 0 &&
    Date.parse(input.expiresAt) - Date.parse(input.verifiedAt) > policy.maximumGrantLifetimeMs
  ) {
    fail("provider_effect_identity_receipt_invalid");
  }
  return input;
};

const assertResourceOwnership = (state, value, authorization, policy, identity, now) => {
  const { scope } = state;
  const input = snapshot(
    scope,
    value,
    [
      "receiptId",
      "receiptSha256",
      "verificationSha256",
      "profileRef",
      "profileSha256",
      "provider",
      "providerOwnerRef",
      "providerAccountRef",
      "targetClass",
      "resourceKey",
      "providerResourceRef",
      "verifiedBy",
      "verifiedAt",
      "expiresAt",
      "keyId",
      "issuerRef",
      "signature",
    ],
    "provider_effect_ownership_receipt_invalid",
  );
  for (const field of [
    "receiptId",
    "providerAccountRef",
    "targetClass",
    "resourceKey",
    "providerResourceRef",
    "verifiedBy",
  ]) {
    identifier(input[field], "provider_effect_ownership_receipt_invalid");
  }
  digest(input.receiptSha256, "provider_effect_ownership_receipt_invalid");
  digest(input.verificationSha256, "provider_effect_ownership_receipt_invalid");
  if (
    input.profileRef !== authorization.profileRef ||
    input.profileSha256 !== authorization.profileSha256 ||
    input.provider !== authorization.provider ||
    input.providerOwnerRef !== authorization.providerOwnerRef ||
    input.providerAccountRef !== identity.providerAccountRef ||
    input.targetClass !== policy.targetClass ||
    input.verifiedBy !== input.issuerRef ||
    input.resourceKey !==
      scope.contracts.PrincipalBinding.hash({
        digestRevision: "ProviderEffectTargetBinding.sha256.v1",
        targetClass: policy.targetClass,
        target: authorization.proposal.target,
      })
  ) {
    fail("provider_effect_ownership_receipt_invalid");
  }
  assertSignedProof(
    state,
    input,
    "resource_ownership",
    authorization.capability,
    "receiptSha256",
    "provider_effect_ownership_receipt_invalid",
  );
  instant(input.verifiedAt, "provider_effect_ownership_receipt_invalid");
  instant(input.expiresAt, "provider_effect_ownership_receipt_invalid");
  if (Date.parse(now) < Date.parse(input.verifiedAt) || Date.parse(now) >= Date.parse(input.expiresAt)) {
    fail("provider_effect_ownership_receipt_expired");
  }
  if (Date.parse(input.expiresAt) - Date.parse(input.verifiedAt) > policy.maximumLeaseLifetimeMs) {
    fail("provider_effect_ownership_receipt_invalid");
  }
  return input;
};

const assertApproval = (state, value, authorization, policy, now) => {
  const { scope } = state;
  if (policy.authorizationMode === "automatic") {
    if (value !== null) fail("provider_effect_approval_invalid");
    return null;
  }
  const input = snapshot(
    scope,
    value,
    [
      "approvalId",
      "approvalSha256",
      "proposalId",
      "proposalHash",
      "intentSha256",
      "approverPrincipalRef",
      "decision",
      "decidedAt",
      "expiresAt",
      "consumedAt",
      "keyId",
      "issuerRef",
      "signature",
    ],
    "provider_effect_approval_invalid",
  );
  identifier(input.approvalId, "provider_effect_approval_invalid");
  digest(input.approvalSha256, "provider_effect_approval_invalid");
  if (
    input.proposalId !== authorization.proposal.proposalId ||
    input.proposalHash !== authorization.proposal.proposalHash ||
    input.intentSha256 !== authorization.intentSha256 ||
    input.approverPrincipalRef !== authorization.proposal.actor.principalRef ||
    input.decision !== "approve_once" ||
    input.consumedAt !== null
  ) {
    fail("provider_effect_approval_invalid");
  }
  assertSignedProof(
    state,
    input,
    "approval",
    authorization.capability,
    "approvalSha256",
    "provider_effect_approval_invalid",
  );
  instant(input.decidedAt, "provider_effect_approval_invalid");
  instant(input.expiresAt, "provider_effect_approval_invalid");
  if (Date.parse(now) < Date.parse(input.decidedAt) || Date.parse(now) >= Date.parse(input.expiresAt)) {
    fail("provider_effect_approval_expired");
  }
  if (
    Date.parse(input.decidedAt) < Date.parse(authorization.proposal.createdAt) ||
    Date.parse(input.expiresAt) > Date.parse(authorization.proposal.expiresAt) ||
    Date.parse(input.expiresAt) - Date.parse(input.decidedAt) > policy.maximumApprovalLifetimeMs
  ) {
    fail("provider_effect_approval_invalid");
  }
  return input;
};

const assertAuthorization = (state, value) => {
  const { scope, suite } = state;
  const input = snapshot(scope, value, authorizationFields, "provider_effect_authorization_invalid");
  const checked = suite.assertProposal(input.proposal);
  const policy = checked.policy;
  const now = instant(input.databaseNow, "provider_effect_authorization_invalid");
  if (
    input.profileRef !== scope.profileRef ||
    input.profileSha256 !== scope.profileSha256 ||
    input.intentSha256 !== checked.intent.intentSha256 ||
    input.prospectiveEffectKey !== checked.intent.prospectiveEffectKey ||
    input.policyRef !== policy.policyRef ||
    input.policySha256 !== policy.policySha256 ||
    input.capability !== policy.capability ||
    input.capabilityVersion !== policy.capabilityVersion ||
    input.provider !== policy.provider ||
    input.operation !== policy.operation ||
    input.providerOwnerRef !== policy.providerOwnerRef ||
    !Number.isSafeInteger(input.revision) ||
    input.revision < 0 ||
    input.attempts !== 0
  ) {
    fail("provider_effect_authorization_invalid");
  }
  const killSwitch = assertKillSwitch(state, input.killSwitch, input.profileRef, input.profileSha256, input.capability);
  if (
    killSwitch.checkedAt !== now ||
    Date.parse(now) < Date.parse(checked.proposal.createdAt) ||
    Date.parse(now) >= Date.parse(checked.proposal.expiresAt)
  ) {
    fail("provider_effect_authorization_expired");
  }
  const evaluationRelease = assertEvaluationRelease(state, input.evaluationRelease, input, now);
  const providerIdentity = assertProviderIdentity(state, input.providerIdentity, input, policy, now);
  const resourceOwnership = assertResourceOwnership(
    state,
    input.resourceOwnership,
    input,
    policy,
    providerIdentity,
    now,
  );
  const approval = assertApproval(state, input.approval, input, policy, now);
  return scope.contracts.PrincipalBinding.freeze({
    ...input,
    proposal: checked.proposal,
    killSwitch,
    evaluationRelease,
    providerIdentity,
    resourceOwnership,
    approval,
    authorizationSha256: scope.contracts.PrincipalBinding.hash(input),
  });
};

const assertAttempt = (state, value, authorization) => {
  const { scope } = state;
  const input = snapshot(scope, value, attemptFields, "provider_effect_attempt_invalid");
  for (const field of ["proposalId", "attemptRef"]) identifier(input[field], "provider_effect_attempt_invalid");
  for (const field of [
    "proposalHash",
    "intentSha256",
    "prospectiveEffectKey",
    "policySha256",
    "authorizationSha256",
    "evaluationReleaseSha256",
    "providerIdentityReceiptSha256",
    "resourceOwnershipReceiptSha256",
  ]) {
    digest(input[field], "provider_effect_attempt_invalid");
  }
  if (input.approvalSha256 !== null) digest(input.approvalSha256, "provider_effect_attempt_invalid");
  instant(input.attemptedAt, "provider_effect_attempt_invalid");
  instant(input.leaseExpiresAt, "provider_effect_attempt_invalid");
  if (input.approvalConsumedAt !== null) instant(input.approvalConsumedAt, "provider_effect_attempt_invalid");
  const expected = {
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
  };
  if (
    Object.entries(expected).some(([field, expectedValue]) => input[field] !== expectedValue) ||
    input.attemptNumber !== 1 ||
    input.status !== "attempting" ||
    input.authorizationSha256 !== authorization.authorizationSha256 ||
    input.killSwitchRevision !== authorization.killSwitch.revision ||
    input.evaluationReleaseSha256 !== authorization.evaluationRelease.releaseSha256 ||
    input.providerIdentityReceiptSha256 !== authorization.providerIdentity.receiptSha256 ||
    input.resourceOwnershipReceiptSha256 !== authorization.resourceOwnership.receiptSha256 ||
    input.approvalSha256 !== (authorization.approval?.approvalSha256 ?? null) ||
    input.approvalConsumedAt !== (authorization.approval === null ? null : input.attemptedAt) ||
    input.revision !== authorization.revision + 1 ||
    Date.parse(input.attemptedAt) < Date.parse(authorization.databaseNow) ||
    Date.parse(input.attemptedAt) >= Date.parse(authorization.proposal.expiresAt) ||
    Date.parse(input.leaseExpiresAt) <= Date.parse(input.attemptedAt) ||
    Date.parse(input.leaseExpiresAt) > Date.parse(authorization.proposal.expiresAt) ||
    Date.parse(input.leaseExpiresAt) - Date.parse(input.attemptedAt) >
      state.suite.policy(authorization.capability).maximumLeaseLifetimeMs
  ) {
    fail("provider_effect_attempt_invalid");
  }
  return scope.contracts.PrincipalBinding.freeze(input);
};

const assertAdapterResult = (state, value, attempt, allowUnknown, observationMode) => {
  const { scope } = state;
  const input = snapshot(scope, value, resultFields, "provider_effect_result_invalid");
  const statuses = allowUnknown ? ["verified", "failed", "outcome_unknown"] : ["verified", "failed"];
  if (
    !statuses.includes(input.status) ||
    input.provider !== attempt.provider ||
    input.operation !== attempt.operation ||
    input.providerOwnerRef !== attempt.providerOwnerRef ||
    (input.providerResourceRef !== null && !identifierPattern.test(input.providerResourceRef)) ||
    (input.status === "verified" && input.providerResourceRef === null) ||
    (observationMode === "read_only_status_lookup" &&
      input.status === "verified" &&
      input.providerResourceRef !== attempt.providerResourceRef) ||
    input.observationMode !== observationMode ||
    (observationMode === "read_only_status_lookup"
      ? input.providerMutationCount !== 0
      : ![0, 1, null].includes(input.providerMutationCount))
  ) {
    fail("provider_effect_result_invalid");
  }
  digest(input.responseSha256, "provider_effect_result_invalid");
  errorCode(input.errorCode, "provider_effect_result_invalid");
  if ((input.status === "verified") !== (input.errorCode === null)) fail("provider_effect_result_invalid");
  return scope.contracts.PrincipalBinding.freeze(input);
};

const unknownResult = (state, attempt, code) =>
  state.scope.contracts.PrincipalBinding.freeze({
    status: "outcome_unknown",
    provider: attempt.provider,
    operation: attempt.operation,
    providerOwnerRef: attempt.providerOwnerRef,
    providerResourceRef: null,
    responseSha256: state.scope.contracts.PrincipalBinding.hash({
      digestRevision: "ProviderEffectUnknownOutcome.sha256.v1",
      attemptRef: attempt.attemptRef,
      code,
    }),
    errorCode: code,
    observationMode: "effect_execution",
    providerMutationCount: null,
  });

const completionResult = (state, value, attempt, attemptedResult) => {
  const receipt = snapshot(state.scope, value, receiptFields, "provider_effect_receipt_invalid");
  if (receipt.status === attemptedResult.status) return attemptedResult;
  if (
    attemptedResult.status === "outcome_unknown" ||
    receipt.status !== "outcome_unknown" ||
    !["provider_kill_switch_changed_after_reservation", "provider_attempt_lease_expired"].includes(receipt.errorCode)
  ) {
    fail("provider_effect_receipt_invalid");
  }
  return assertAdapterResult(
    state,
    {
      status: receipt.status,
      provider: receipt.provider,
      operation: receipt.operation,
      providerOwnerRef: receipt.providerOwnerRef,
      providerResourceRef: receipt.providerResourceRef,
      responseSha256: receipt.responseSha256,
      errorCode: receipt.errorCode,
      observationMode: receipt.observationMode,
      providerMutationCount: receipt.providerMutationCount,
    },
    attempt,
    true,
    "effect_execution",
  );
};

const assertReceipt = (state, value, attempt, result, reconciliation = null) => {
  const { scope } = state;
  const input = snapshot(scope, value, receiptFields, "provider_effect_receipt_invalid");
  for (const field of ["receiptId", "attemptRef", "authenticatedBy"]) {
    identifier(input[field], "provider_effect_receipt_invalid");
  }
  for (const field of [
    "receiptSha256",
    "proposalHash",
    "intentSha256",
    "prospectiveEffectKey",
    "responseSha256",
    "authenticationSha256",
  ]) {
    digest(input[field], "provider_effect_receipt_invalid");
  }
  if (input.priorReceiptSha256 !== null) digest(input.priorReceiptSha256, "provider_effect_receipt_invalid");
  if (input.reconciliationRef !== null) identifier(input.reconciliationRef, "provider_effect_receipt_invalid");
  instant(input.attemptedAt, "provider_effect_receipt_invalid");
  if (input.completedAt !== null) instant(input.completedAt, "provider_effect_receipt_invalid");
  const proposal = reconciliation?.proposal ?? attempt.proposal;
  if (
    input.profileRef !== attempt.profileRef ||
    input.profileSha256 !== attempt.profileSha256 ||
    input.proposalId !== proposal?.proposalId ||
    input.proposalHash !== (attempt.proposalHash ?? proposal?.proposalHash) ||
    input.intentSha256 !== attempt.intentSha256 ||
    input.prospectiveEffectKey !== attempt.prospectiveEffectKey ||
    input.attemptRef !== attempt.attemptRef ||
    input.attemptNumber !== 1 ||
    input.status !== result.status ||
    input.provider !== result.provider ||
    input.operation !== result.operation ||
    input.providerOwnerRef !== result.providerOwnerRef ||
    input.providerResourceRef !== result.providerResourceRef ||
    input.responseSha256 !== result.responseSha256 ||
    input.errorCode !== result.errorCode ||
    input.observationMode !== result.observationMode ||
    input.providerMutationCount !== result.providerMutationCount ||
    input.authenticatedBy !== input.issuerRef ||
    input.attemptedAt !== attempt.attemptedAt ||
    (input.status === "outcome_unknown" ? input.completedAt !== null : input.completedAt === null)
  ) {
    fail("provider_effect_receipt_invalid");
  }
  if (
    reconciliation === null
      ? input.reconciliationRef !== null || input.priorReceiptSha256 !== null
      : input.reconciliationRef !== reconciliation.reconciliationRef ||
        input.priorReceiptSha256 !== reconciliation.priorReceiptSha256
  ) {
    fail("provider_effect_receipt_invalid");
  }
  if (input.completedAt !== null && Date.parse(input.completedAt) < Date.parse(input.attemptedAt)) {
    fail("provider_effect_receipt_invalid");
  }
  if (
    reconciliation !== null &&
    input.completedAt !== null &&
    Date.parse(input.completedAt) < Date.parse(reconciliation.databaseNow)
  ) {
    fail("provider_effect_receipt_invalid");
  }
  assertSignedProof(
    state,
    input,
    "durable_receipt",
    attempt.capability,
    "receiptSha256",
    "provider_effect_receipt_invalid",
  );
  return scope.contracts.PrincipalBinding.freeze(input);
};

const execute = async (authority, proposalId) => {
  const state = authorities.get(authority);
  identifier(proposalId, "provider_effect_proposal_id_invalid");
  const authorization = assertAuthorization(state, await storeCall(state, "readAuthorization", proposalId));
  effectAdapterFor(state, authorization.capability);
  const attempt = assertAttempt(
    state,
    await storeCall(state, "reserveAttempt", {
      proposalId,
      authorizationSha256: authorization.authorizationSha256,
      expectedRevision: authorization.revision,
      killSwitchRevision: authorization.killSwitch.revision,
      evaluationReleaseSha256: authorization.evaluationRelease.releaseSha256,
      providerIdentityReceiptSha256: authorization.providerIdentity.receiptSha256,
      resourceOwnershipReceiptSha256: authorization.resourceOwnership?.receiptSha256 ?? null,
      approvalSha256: authorization.approval?.approvalSha256 ?? null,
    }),
    authorization,
  );
  let result;
  try {
    const adapter = effectAdapterFor(state, authorization.capability);
    const adapterResult = await adapter.invoke({ proposal: authorization.proposal, attempt });
    if (effectAdapterFor(state, authorization.capability) !== adapter) fail("provider_effect_adapter_unavailable");
    result = assertAdapterResult(state, adapterResult, attempt, true, "effect_execution");
  } catch {
    result = unknownResult(state, attempt, "provider_transport_indeterminate");
  }
  const persisted = await storeCall(state, "completeAttempt", { attempt, result });
  const persistedResult = completionResult(state, persisted, attempt, result);
  return assertReceipt(state, persisted, { ...attempt, proposal: authorization.proposal }, persistedResult);
};

const assertReconciliation = (state, value) => {
  const { scope, suite } = state;
  const input = snapshot(scope, value, reconciliationFields, "provider_effect_reconciliation_invalid");
  const checked = suite.assertProposal(input.proposal);
  const policy = checked.policy;
  identifier(input.providerAccountRef, "provider_effect_reconciliation_invalid");
  identifier(input.providerResourceRef, "provider_effect_reconciliation_invalid");
  for (const field of ["attemptRef", "priorReceiptSha256"]) {
    if (field.endsWith("Sha256")) digest(input[field], "provider_effect_reconciliation_invalid");
    else identifier(input[field], "provider_effect_reconciliation_invalid");
  }
  instant(input.attemptedAt, "provider_effect_reconciliation_invalid");
  instant(input.attemptLeaseExpiresAt, "provider_effect_reconciliation_invalid");
  instant(input.databaseNow, "provider_effect_reconciliation_invalid");
  if (
    input.profileRef !== scope.profileRef ||
    input.profileSha256 !== scope.profileSha256 ||
    input.intentSha256 !== checked.intent.intentSha256 ||
    input.prospectiveEffectKey !== checked.intent.prospectiveEffectKey ||
    input.policySha256 !== policy.policySha256 ||
    input.capability !== policy.capability ||
    input.capabilityVersion !== policy.capabilityVersion ||
    input.provider !== policy.provider ||
    input.operation !== policy.operation ||
    input.providerOwnerRef !== policy.providerOwnerRef ||
    input.attemptNumber !== 1 ||
    !["attempting", "outcome_unknown"].includes(input.priorStatus) ||
    !Number.isSafeInteger(input.revision) ||
    input.revision < 1 ||
    Date.parse(input.databaseNow) < Date.parse(input.attemptedAt) ||
    Date.parse(input.attemptLeaseExpiresAt) <= Date.parse(input.attemptedAt) ||
    Date.parse(input.databaseNow) < Date.parse(input.attemptLeaseExpiresAt)
  ) {
    fail("provider_effect_reconciliation_invalid");
  }
  const killSwitch = assertKillSwitch(state, input.killSwitch, input.profileRef, input.profileSha256, input.capability);
  if (killSwitch.checkedAt !== input.databaseNow) fail("provider_effect_reconciliation_invalid");
  const identity = snapshot(
    scope,
    input.reconciliationIdentity,
    [
      "profileRef",
      "profileSha256",
      "capability",
      "attemptRef",
      "priorReceiptSha256",
      "reconcilerPrincipalRef",
      "authenticationSha256",
      "authenticatedAt",
      "expiresAt",
      "keyId",
      "issuerRef",
      "signature",
    ],
    "provider_effect_reconciliation_identity_invalid",
  );
  identifier(identity.reconcilerPrincipalRef, "provider_effect_reconciliation_identity_invalid");
  digest(identity.authenticationSha256, "provider_effect_reconciliation_identity_invalid");
  digest(identity.priorReceiptSha256, "provider_effect_reconciliation_identity_invalid");
  instant(identity.authenticatedAt, "provider_effect_reconciliation_identity_invalid");
  instant(identity.expiresAt, "provider_effect_reconciliation_identity_invalid");
  if (
    identity.profileRef !== input.profileRef ||
    identity.profileSha256 !== input.profileSha256 ||
    identity.capability !== input.capability ||
    identity.attemptRef !== input.attemptRef ||
    identity.priorReceiptSha256 !== input.priorReceiptSha256 ||
    identity.reconcilerPrincipalRef !== state.reconcilerPrincipals.get(input.capability) ||
    Date.parse(identity.expiresAt) - Date.parse(identity.authenticatedAt) > policy.maximumLeaseLifetimeMs
  ) {
    fail("provider_effect_reconciliation_identity_invalid");
  }
  if (
    Date.parse(input.databaseNow) < Date.parse(identity.authenticatedAt) ||
    Date.parse(input.databaseNow) >= Date.parse(identity.expiresAt)
  ) {
    fail("provider_effect_reconciliation_identity_expired");
  }
  assertSignedProof(
    state,
    identity,
    "reconciliation_identity",
    input.capability,
    "authenticationSha256",
    "provider_effect_reconciliation_identity_invalid",
  );
  return scope.contracts.PrincipalBinding.freeze({
    ...input,
    proposal: checked.proposal,
    killSwitch,
    reconciliationIdentity: identity,
  });
};

const assertReconciliationLease = (state, value, reconciliation) => {
  const { scope } = state;
  const input = snapshot(scope, value, reconciliationLeaseFields, "provider_effect_reconciliation_lease_invalid");
  for (const field of ["proposalId", "attemptRef", "reconciliationRef", "reconcilerPrincipalRef"]) {
    identifier(input[field], "provider_effect_reconciliation_lease_invalid");
  }
  for (const field of [
    "proposalHash",
    "intentSha256",
    "prospectiveEffectKey",
    "priorReceiptSha256",
    "authenticationSha256",
  ]) {
    digest(input[field], "provider_effect_reconciliation_lease_invalid");
  }
  instant(input.acquiredAt, "provider_effect_reconciliation_lease_invalid");
  instant(input.expiresAt, "provider_effect_reconciliation_lease_invalid");
  if (
    input.profileRef !== reconciliation.profileRef ||
    input.profileSha256 !== reconciliation.profileSha256 ||
    input.proposalId !== reconciliation.proposal.proposalId ||
    input.proposalHash !== reconciliation.proposal.proposalHash ||
    input.intentSha256 !== reconciliation.intentSha256 ||
    input.prospectiveEffectKey !== reconciliation.prospectiveEffectKey ||
    input.attemptRef !== reconciliation.attemptRef ||
    input.priorReceiptSha256 !== reconciliation.priorReceiptSha256 ||
    input.authenticationSha256 !== reconciliation.reconciliationIdentity.authenticationSha256 ||
    input.killSwitchRevision !== reconciliation.killSwitch.revision ||
    input.reconcilerPrincipalRef !== reconciliation.reconciliationIdentity.reconcilerPrincipalRef ||
    input.mode !== "read_only_status_lookup" ||
    input.revision !== reconciliation.revision ||
    Date.parse(input.acquiredAt) < Date.parse(reconciliation.databaseNow) ||
    Date.parse(input.expiresAt) <= Date.parse(input.acquiredAt) ||
    Date.parse(input.expiresAt) - Date.parse(input.acquiredAt) >
      state.suite.policy(reconciliation.capability).maximumLeaseLifetimeMs
  ) {
    fail("provider_effect_reconciliation_lease_invalid");
  }
  return scope.contracts.PrincipalBinding.freeze(input);
};

const reconcile = async (authority, proposalId) => {
  const state = authorities.get(authority);
  identifier(proposalId, "provider_effect_proposal_id_invalid");
  const reconciliation = assertReconciliation(state, await storeCall(state, "readReconciliation", proposalId));
  reconciliationPortFor(state, reconciliation.capability);
  const lease = assertReconciliationLease(
    state,
    await storeCall(state, "reserveReconciliation", {
      proposalId,
      proposalHash: reconciliation.proposal.proposalHash,
      intentSha256: reconciliation.intentSha256,
      prospectiveEffectKey: reconciliation.prospectiveEffectKey,
      attemptRef: reconciliation.attemptRef,
      priorReceiptSha256: reconciliation.priorReceiptSha256,
      expectedRevision: reconciliation.revision,
      authenticationSha256: reconciliation.reconciliationIdentity.authenticationSha256,
      killSwitchRevision: reconciliation.killSwitch.revision,
      mode: "read_only_status_lookup",
    }),
    reconciliation,
  );
  let result;
  try {
    const reconciliationPort = reconciliationPortFor(state, reconciliation.capability);
    const adapterResult = await reconciliationPort.queryStatus(
      state.scope.contracts.PrincipalBinding.freeze({
        profileRef: reconciliation.profileRef,
        profileSha256: reconciliation.profileSha256,
        capability: reconciliation.capability,
        provider: reconciliation.provider,
        operation: reconciliation.operation,
        providerOwnerRef: reconciliation.providerOwnerRef,
        providerAccountRef: reconciliation.providerAccountRef,
        providerResourceRef: reconciliation.providerResourceRef,
        attemptRef: reconciliation.attemptRef,
        priorReceiptSha256: reconciliation.priorReceiptSha256,
        reconciliationRef: lease.reconciliationRef,
        mode: "read_only_status_lookup",
      }),
    );
    if (reconciliationPortFor(state, reconciliation.capability) !== reconciliationPort) {
      fail("provider_effect_reconciliation_port_unavailable");
    }
    result = assertAdapterResult(state, adapterResult, reconciliation, false, "read_only_status_lookup");
  } catch {
    fail("provider_effect_reconciliation_indeterminate");
  }
  const persisted = await storeCall(state, "completeReconciliation", { reconciliation, lease, result });
  return assertReceipt(state, persisted, { ...reconciliation, reconciliationRef: lease.reconciliationRef }, result, {
    ...reconciliation,
    reconciliationRef: lease.reconciliationRef,
  });
};

export function createProviderEffectProtocolHarness(value) {
  const input = exactPort(
    value,
    [
      "runtimeScope",
      "store",
      "effectAdapters",
      "reconciliationPorts",
      "trustedProofIssuers",
      "allowedReconcilerPrincipals",
    ],
    "provider_effect_authority_invalid",
  );
  const scope = assertRuntimeScope(input.runtimeScope);
  const suite = createProviderEffectPolicySuite(scope);
  const effectAdapters = normalizeCapabilityPorts(
    input.effectAdapters,
    suite.capabilities,
    effectAdapterMethods,
    "provider_effect_adapters_unavailable",
  );
  const reconciliationPorts = normalizeCapabilityPorts(
    input.reconciliationPorts,
    suite.capabilities,
    reconciliationPortMethods,
    "provider_effect_reconciliation_ports_unavailable",
  );
  if (
    Object.keys(effectAdapters).length !== Object.keys(reconciliationPorts).length ||
    Object.keys(effectAdapters).some((capability) => !Object.hasOwn(reconciliationPorts, capability))
  ) {
    fail("provider_effect_reconciliation_ports_unavailable");
  }
  const state = Object.freeze({
    scope,
    suite,
    store: assertStore(input.store),
    effectAdapters,
    reconciliationPorts,
    proofIssuers: normalizeProofIssuers(input.trustedProofIssuers, suite.capabilities),
    reconcilerPrincipals: normalizeReconcilerPrincipals(input.allowedReconcilerPrincipals, suite.capabilities),
  });
  if (
    Object.keys(effectAdapters).some(
      (capability) =>
        !state.reconcilerPrincipals.has(capability) ||
        reconciliationPorts[capability].reconcilerPrincipalRef !== state.reconcilerPrincipals.get(capability) ||
        suite.policy(capability).maximumAttempts !== 1,
    )
  ) {
    fail("provider_effect_reconciler_registry_invalid");
  }
  const authority = Object.freeze({
    authorityType: "ProviderEffectProtocolHarness",
    profileRef: scope.profileRef,
    profileSha256: scope.profileSha256,
    execute: (proposalId) => execute(authority, proposalId),
    reconcile: (proposalId) => reconcile(authority, proposalId),
  });
  authorities.set(authority, state);
  return authority;
}
