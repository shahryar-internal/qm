import { createHash } from "node:crypto";
import { types } from "node:util";

const forbiddenKeys = new Set(["__proto__", "constructor", "prototype"]);
const authorities = new WeakSet();
const profileFields = Object.freeze([
  "contractType",
  "contractVersion",
  "digestRevision",
  "profileRef",
  "profileVersion",
  "activationMode",
  "providerExecutionAllowed",
  "anchors",
  "identity",
  "agent",
  "allowedCapabilities",
  "providerEffectPolicyRef",
  "providerEffectPolicySha256",
  "providerOwners",
  "audiences",
  "grantPolicy",
  "evalPolicy",
  "profileSha256",
]);
const anchorFields = Object.freeze([
  "organizationRef",
  "deploymentRef",
  "tenantRef",
  "workspaceRef",
  "principalBindingRef",
  "slackTeamRef",
]);
const identityFields = Object.freeze([
  "humanPrincipalRef",
  "humanEmail",
  "qmPrincipalRef",
  "externalIdentityRef",
  "externalOrganizationRole",
  "credentialOwnerRef",
]);
const agentFields = Object.freeze(["agentId", "agentVersion", "agentScope"]);
const providerOwnerFields = Object.freeze(["provider", "providerOwnerRef"]);
const audienceSurfaceFields = Object.freeze(["audienceRef", "principalRef", "scope"]);
const notionAudienceFields = Object.freeze(["audienceRef", "parentRef", "scope"]);
const grantPolicyFields = Object.freeze([
  "policyRef",
  "approvalRequired",
  "delegationAllowed",
  "maximumApprovalLifetimeMs",
  "maximumIdentityLifetimeMs",
  "maximumEvalReleaseLifetimeMs",
  "maximumProviderGrantLifetimeMs",
]);
const evalPolicyFields = Object.freeze([
  "policyRef",
  "requiredGates",
  "requiredDeterministicCheckIds",
  "minimumIndependentJudges",
  "judgeClasses",
  "independentOriginsRequired",
  "selfReviewAllowed",
  "maximumRepairAttempts",
  "sideEffectBudget",
  "minimumScore",
  "maximumScoreSpread",
  "maximumEvaluationRuntimeMs",
  "trustedJudgeRoots",
]);
const trustedJudgeRootFields = Object.freeze(["keyId", "judgeRef", "judgeClass", "originRef", "publicKey"]);
const publicKeyFields = Object.freeze(["crv", "x", "kty"]);
const identifierPattern = /^[a-z0-9][a-z0-9._:/-]{0,255}$/u;
const capabilityPattern = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/u;
const versionPattern = /^\d+\.\d+\.\d+$/u;
const digestPattern = /^[a-f0-9]{64}$/u;
const emailPattern =
  /^(?=.{3,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/u;
const maximumTrustedIdentityLifetimeMs = 60 * 60 * 1000;

export class DeploymentProfileContractError extends Error {
  constructor(code) {
    super(code);
    this.name = "DeploymentProfileError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new DeploymentProfileContractError(code);
};

function clonePlain(value, label, stack) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("untrusted_plain_data");
    return value;
  }
  if (!value || typeof value !== "object" || types.isProxy(value) || stack.has(value)) fail("untrusted_plain_data");
  const array = Array.isArray(value);
  if (Object.getPrototypeOf(value) !== (array ? Array.prototype : Object.prototype)) fail("untrusted_plain_data");
  if (Object.getOwnPropertySymbols(value).length !== 0) fail("untrusted_plain_data");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Object.getOwnPropertyNames(value);
  if (names.some((name) => forbiddenKeys.has(name))) fail("untrusted_plain_data");
  if (array) {
    if (
      names.some((name) => name !== "length" && !/^(?:0|[1-9]\d*)$/u.test(name)) ||
      !Object.hasOwn(descriptors, "length") ||
      descriptors.length.enumerable ||
      !Object.hasOwn(descriptors.length, "value") ||
      names.length !== value.length + 1
    ) {
      fail("untrusted_plain_data");
    }
  } else if (names.some((name) => !descriptors[name].enumerable)) {
    fail("untrusted_plain_data");
  }
  for (const name of names) {
    if (name === "length") continue;
    const descriptor = descriptors[name];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail("untrusted_plain_data");
  }
  stack.add(value);
  try {
    if (array) return names.slice(0, -1).map((name) => clonePlain(descriptors[name].value, `${label}.${name}`, stack));
    return Object.fromEntries(
      names.map((name) => [name, clonePlain(descriptors[name].value, `${label}.${name}`, stack)]),
    );
  } finally {
    stack.delete(value);
  }
}

export function snapshotProfileData(value, label = "deploymentProfile") {
  return clonePlain(value, label, new Set());
}

function canonical(value) {
  if (value === null) return "null";
  if (["string", "boolean", "number"].includes(typeof value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

export function hashProfileData(value) {
  return createHash("sha256")
    .update(canonical(snapshotProfileData(value)))
    .digest("hex");
}

export function freezeProfileData(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const entry of Object.values(value)) freezeProfileData(entry);
  return Object.freeze(value);
}

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

const assertInteger = (value, minimum, maximum, code) => {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(code);
  return value;
};

const assertBoolean = (value, expected, code) => {
  if (value !== expected) fail(code);
  return value;
};

const assertDigest = (value, code) => {
  if (typeof value !== "string" || !digestPattern.test(value)) fail(code);
  return value;
};

const assertSortedUnique = (values, validate, minimum, maximum, code) => {
  if (!Array.isArray(values) || values.length < minimum || values.length > maximum) fail(code);
  const normalized = values.map((value, index) => validate(value, `${code}_${index}`));
  if (new Set(normalized).size !== normalized.length) fail(code);
  if (normalized.some((value, index) => index > 0 && normalized[index - 1] >= value)) fail(code);
  return normalized;
};

export function validateProfileShape(value) {
  const input = exact(snapshotProfileData(value), profileFields, "invalid_profile_schema");
  if (
    input.contractType !== "risely-deployment-profile" ||
    input.contractVersion !== 1 ||
    input.digestRevision !== "DeploymentProfile.sha256.v1"
  ) {
    fail("invalid_profile_contract");
  }
  assertIdentifier(input.profileRef, "invalid_profile_ref");
  assertInteger(input.profileVersion, 1, Number.MAX_SAFE_INTEGER, "invalid_profile_version");
  if (input.activationMode !== "shadow") fail("profile_activation_must_be_shadow");
  assertBoolean(input.providerExecutionAllowed, false, "profile_provider_execution_forbidden");
  const anchors = exact(input.anchors, anchorFields, "invalid_profile_anchors");
  for (const field of anchorFields) assertIdentifier(anchors[field], `invalid_profile_anchor_${field}`);
  const identity = exact(input.identity, identityFields, "invalid_profile_identity");
  assertIdentifier(identity.humanPrincipalRef, "invalid_human_principal_ref");
  if (
    typeof identity.humanEmail !== "string" ||
    identity.humanEmail !== identity.humanEmail.toLowerCase() ||
    !emailPattern.test(identity.humanEmail)
  ) {
    fail("invalid_human_email");
  }
  for (const field of identityFields.filter((field) => !["humanPrincipalRef", "humanEmail"].includes(field))) {
    assertIdentifier(identity[field], `invalid_profile_identity_${field}`);
  }
  const agent = exact(input.agent, agentFields, "invalid_profile_agent");
  assertIdentifier(agent.agentId, "invalid_agent_id");
  if (typeof agent.agentVersion !== "string" || !versionPattern.test(agent.agentVersion)) fail("invalid_agent_version");
  assertIdentifier(agent.agentScope, "invalid_agent_scope");
  assertSortedUnique(
    input.allowedCapabilities,
    (entry, code) => {
      if (typeof entry !== "string" || !capabilityPattern.test(entry)) fail(code);
      return entry;
    },
    1,
    64,
    "invalid_allowed_capabilities",
  );
  assertIdentifier(input.providerEffectPolicyRef, "invalid_provider_effect_policy_ref");
  assertDigest(input.providerEffectPolicySha256, "invalid_provider_effect_policy_sha256");
  if (!Array.isArray(input.providerOwners) || input.providerOwners.length < 1 || input.providerOwners.length > 32) {
    fail("invalid_provider_owners");
  }
  let previousProvider = "";
  const ownerRefs = new Set();
  for (const owner of input.providerOwners) {
    const record = exact(owner, providerOwnerFields, "invalid_provider_owner");
    const provider = assertIdentifier(record.provider, "invalid_provider");
    const providerOwnerRef = assertIdentifier(record.providerOwnerRef, "invalid_provider_owner_ref");
    if (provider <= previousProvider || ownerRefs.has(providerOwnerRef)) fail("invalid_provider_owners");
    previousProvider = provider;
    ownerRefs.add(providerOwnerRef);
  }
  const audiences = exact(input.audiences, ["slack", "qm", "notion"], "invalid_profile_audiences");
  for (const surface of ["slack", "qm"]) {
    const audience = exact(audiences[surface], audienceSurfaceFields, `invalid_${surface}_audience`);
    for (const field of audienceSurfaceFields)
      assertIdentifier(audience[field], `invalid_${surface}_audience_${field}`);
  }
  const notion = exact(audiences.notion, notionAudienceFields, "invalid_notion_audience");
  for (const field of notionAudienceFields) assertIdentifier(notion[field], `invalid_notion_audience_${field}`);
  const audienceRefs = [audiences.slack.audienceRef, audiences.qm.audienceRef, notion.audienceRef];
  if (new Set(audienceRefs).size !== audienceRefs.length) fail("invalid_profile_audiences");
  const grantPolicy = exact(input.grantPolicy, grantPolicyFields, "invalid_grant_policy");
  assertIdentifier(grantPolicy.policyRef, "invalid_grant_policy_ref");
  assertBoolean(grantPolicy.approvalRequired, true, "grant_approval_required");
  assertBoolean(grantPolicy.delegationAllowed, false, "grant_delegation_forbidden");
  assertInteger(grantPolicy.maximumApprovalLifetimeMs, 0, 86_400_000, "invalid_approval_lifetime");
  assertInteger(
    grantPolicy.maximumIdentityLifetimeMs,
    0,
    maximumTrustedIdentityLifetimeMs,
    "invalid_identity_lifetime",
  );
  assertInteger(grantPolicy.maximumEvalReleaseLifetimeMs, 0, 86_400_000, "invalid_eval_lifetime");
  assertInteger(grantPolicy.maximumProviderGrantLifetimeMs, 0, 0, "provider_grant_forbidden");
  const evalPolicy = exact(input.evalPolicy, evalPolicyFields, "invalid_eval_policy");
  assertIdentifier(evalPolicy.policyRef, "invalid_eval_policy_ref");
  assertSortedUnique(evalPolicy.requiredGates, assertIdentifier, 1, 32, "invalid_eval_gates");
  assertSortedUnique(
    evalPolicy.requiredDeterministicCheckIds,
    assertIdentifier,
    1,
    32,
    "invalid_eval_deterministic_checks",
  );
  assertInteger(evalPolicy.minimumIndependentJudges, 2, 10, "invalid_independent_judge_count");
  assertSortedUnique(evalPolicy.judgeClasses, assertIdentifier, 2, 10, "invalid_judge_classes");
  assertBoolean(evalPolicy.independentOriginsRequired, true, "independent_judges_required");
  assertBoolean(evalPolicy.selfReviewAllowed, false, "self_review_forbidden");
  assertInteger(evalPolicy.maximumRepairAttempts, 0, 2, "invalid_repair_budget");
  assertInteger(evalPolicy.sideEffectBudget, 0, 0, "eval_side_effects_forbidden");
  assertInteger(evalPolicy.minimumScore, 4, 5, "invalid_eval_minimum_score");
  assertInteger(evalPolicy.maximumScoreSpread, 0, 1, "invalid_eval_score_spread");
  assertInteger(evalPolicy.maximumEvaluationRuntimeMs, 1, 900_000, "invalid_eval_runtime");
  if (
    !Array.isArray(evalPolicy.trustedJudgeRoots) ||
    evalPolicy.trustedJudgeRoots.length !== evalPolicy.minimumIndependentJudges
  ) {
    fail("invalid_eval_trust_roots");
  }
  const trustedRootKeys = new Set();
  const trustedRootJudges = new Set();
  const trustedRootOrigins = new Set();
  const trustedRootClasses = new Set();
  for (const root of evalPolicy.trustedJudgeRoots) {
    const trustedRoot = exact(root, trustedJudgeRootFields, "invalid_eval_trust_root");
    assertIdentifier(trustedRoot.keyId, "invalid_eval_trust_root_key");
    assertIdentifier(trustedRoot.judgeRef, "invalid_eval_trust_root_judge");
    assertIdentifier(trustedRoot.judgeClass, "invalid_eval_trust_root_class");
    assertIdentifier(trustedRoot.originRef, "invalid_eval_trust_root_origin");
    const publicKey = exact(trustedRoot.publicKey, publicKeyFields, "invalid_eval_trust_root_public_key");
    if (
      publicKey.crv !== "Ed25519" ||
      publicKey.kty !== "OKP" ||
      typeof publicKey.x !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/u.test(publicKey.x)
    ) {
      fail("invalid_eval_trust_root_public_key");
    }
    if (
      trustedRootKeys.has(trustedRoot.keyId) ||
      trustedRootJudges.has(trustedRoot.judgeRef) ||
      trustedRootOrigins.has(trustedRoot.originRef) ||
      trustedRootClasses.has(trustedRoot.judgeClass)
    ) {
      fail("invalid_eval_trust_roots");
    }
    trustedRootKeys.add(trustedRoot.keyId);
    trustedRootJudges.add(trustedRoot.judgeRef);
    trustedRootOrigins.add(trustedRoot.originRef);
    trustedRootClasses.add(trustedRoot.judgeClass);
  }
  if (
    evalPolicy.judgeClasses.some((judgeClass) => !trustedRootClasses.has(judgeClass)) ||
    evalPolicy.trustedJudgeRoots.some(
      (root, index) => index > 0 && evalPolicy.trustedJudgeRoots[index - 1].judgeClass >= root.judgeClass,
    )
  ) {
    fail("invalid_eval_trust_roots");
  }
  assertDigest(input.profileSha256, "invalid_profile_sha256");
  const projection = { ...input };
  delete projection.profileSha256;
  if (input.profileSha256 !== hashProfileData(projection)) fail("profile_sha256_mismatch");
  return input;
}

export function createProfileAuthority(projection) {
  const plain = snapshotProfileData(projection);
  if (Object.hasOwn(plain, "profileSha256")) fail("invalid_profile_schema");
  const authority = freezeProfileData({ ...plain, profileSha256: hashProfileData(plain) });
  validateProfileShape(authority);
  authorities.add(authority);
  return authority;
}

export function assertProfileAuthority(value) {
  if (!authorities.has(value) || !Object.isFrozen(value)) fail("unsupported_deployment_profile_authority");
  validateProfileShape(value);
  return value;
}
