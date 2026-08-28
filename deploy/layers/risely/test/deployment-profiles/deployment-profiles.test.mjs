import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  bundledCeoProfileSha256,
  bundledDeploymentProfileRegistrySha256,
  ceoDeploymentProfile,
  deploymentProfileRegistry,
  providerEffectPolicyCatalog,
  providerEffectPolicyCatalogSha256,
  profileExpansionAvailability,
  requestDeploymentProfileResolution,
  toCeoPrincipalBinding,
  validateDeploymentProfile,
  validateDeploymentProfileRegistry,
  validateTrustedQmIdentityInput,
  validateUnresolvedProfileResolutionRequest,
} from "../../canary/deployment-profiles/index.mjs";
import { syntheticDeploymentProfile } from "../../canary/deployment-profiles/testing.mjs";
import { createProfileAuthority } from "../../canary/deployment-profiles/contract.mjs";
import { createDormantGmailDraftProposalCompiler } from "../../canary/integration/index.mjs";
import { createMarketingProgramWorkflow, initializeMarketingState } from "../../canary/marketing-program/index.mjs";
import { createRevenueProgramWorkflow, initializeRevenueProgramState } from "../../canary/revenue-program/index.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import { PrincipalBinding } from "../../canary/shared-contracts/index.mjs";

const now = "2026-08-26T19:05:00.000Z";
const sha256Canonical = PrincipalBinding.hash;

const selfHash = (value, field) => {
  const projection = structuredClone(value);
  delete projection[field];
  return sha256Canonical(projection);
};

const rehashProfile = (value) => {
  value.profileSha256 = selfHash(value, "profileSha256");
  return value;
};

const rehashRegistry = (value) => {
  value.registrySha256 = selfHash(value, "registrySha256");
  return value;
};

const trustedIdentity = (overrides = {}) => {
  const projection = {
    contractType: "trusted-qm-identity",
    contractVersion: 1,
    digestRevision: "TrustedQmIdentity.sha256.v1",
    verificationState: "verified",
    verificationAuthorityRef: "qm-identity-verifier:risely:v1",
    organizationRef: ceoDeploymentProfile.anchors.organizationRef,
    deploymentRef: ceoDeploymentProfile.anchors.deploymentRef,
    tenantRef: ceoDeploymentProfile.anchors.tenantRef,
    workspaceRef: ceoDeploymentProfile.anchors.workspaceRef,
    humanPrincipalRef: ceoDeploymentProfile.identity.humanPrincipalRef,
    humanEmail: ceoDeploymentProfile.identity.humanEmail,
    qmPrincipalRef: ceoDeploymentProfile.identity.qmPrincipalRef,
    externalIdentityRef: ceoDeploymentProfile.identity.externalIdentityRef,
    externalOrganizationRole: ceoDeploymentProfile.identity.externalOrganizationRole,
    verifiedAt: "2026-08-26T19:00:00.000Z",
    expiresAt: "2026-08-26T19:30:00.000Z",
    verificationEvidenceSha256: "a".repeat(64),
    ...overrides,
  };
  return { ...projection, identitySha256: sha256Canonical(projection) };
};

const expectCode = (operation, code) => {
  assert.throws(operation, (error) => error?.code === code);
};

const recursivelyFrozen = (value, seen = new Set()) => {
  if (!value || typeof value !== "object" || seen.has(value)) return true;
  seen.add(value);
  return Object.isFrozen(value) && Object.values(value).every((entry) => recursivelyFrozen(entry, seen));
};

test("the closed registry contains one immutable pinned CEO shadow profile", () => {
  assert.equal(validateDeploymentProfile(ceoDeploymentProfile), ceoDeploymentProfile);
  assert.equal(validateDeploymentProfileRegistry(deploymentProfileRegistry), deploymentProfileRegistry);
  assert.equal(ceoDeploymentProfile.profileSha256, bundledCeoProfileSha256);
  assert.equal(deploymentProfileRegistry.registrySha256, bundledDeploymentProfileRegistrySha256);
  assert.equal(deploymentProfileRegistry.profiles.length, 1);
  assert.equal(ceoDeploymentProfile.activationMode, "shadow");
  assert.equal(ceoDeploymentProfile.providerExecutionAllowed, false);
  assert.equal(ceoDeploymentProfile.providerEffectPolicyRef, providerEffectPolicyCatalog.policyRef);
  assert.equal(ceoDeploymentProfile.providerEffectPolicySha256, providerEffectPolicyCatalogSha256);
  assert.equal(providerEffectPolicyCatalog.capabilities.length, 6);
  assert.deepEqual(providerEffectPolicyCatalog.sourceAliases, [
    {
      source: "gmail",
      provider: "google",
      accountBinding: "signed-google-subject-mailbox-required",
    },
  ]);
  assert.equal(ceoDeploymentProfile.grantPolicy.maximumProviderGrantLifetimeMs, 0);
  assert.equal(recursivelyFrozen(deploymentProfileRegistry), true);
});

test("the CEO adapter is byte-compatible with the fixed branded PrincipalBinding only", () => {
  const adapted = toCeoPrincipalBinding();
  assert.deepEqual(adapted, PrincipalBinding.value);
  assert.equal(adapted.bindingSha256, PrincipalBinding.value.bindingSha256);
  expectCode(() => toCeoPrincipalBinding(structuredClone(ceoDeploymentProfile)), "unsupported_deployment_profile");
  expectCode(
    () =>
      toCeoPrincipalBinding(
        rehashProfile({ ...structuredClone(ceoDeploymentProfile), profileRef: "deployment-profile:risely:other:v1" }),
      ),
    "unsupported_deployment_profile",
  );
  assert.throws(() => PrincipalBinding.validate({ ...PrincipalBinding.value, principalRef: "principal:other" }));
});

test("trusted QM identity can produce only a short-lived unresolved inert request", () => {
  const identity = validateTrustedQmIdentityInput(trustedIdentity(), now);
  const request = requestDeploymentProfileResolution(identity, now);
  assert.equal(validateUnresolvedProfileResolutionRequest(request).requestSha256, request.requestSha256);
  assert.equal(request.resolutionState, "unresolved");
  assert.equal(request.profileRef, null);
  assert.equal(request.profileSha256, null);
  assert.equal(request.activationMode, "shadow");
  assert.equal(request.providerExecutionAllowed, false);
  assert.equal(request.blocker, "trusted_qm_profile_resolution_authority_unavailable");
  assert.equal(Date.parse(request.expiresAt) - Date.parse(request.requestedAt), 5 * 60 * 1000);
});

test("request and Slack fields cannot select or influence a profile", () => {
  for (const [field, value] of [
    ["profileRef", ceoDeploymentProfile.profileRef],
    ["slackUserId", "U0123456789"],
    ["allowedCapabilities", ["gmail.send"]],
  ]) {
    const identity = trustedIdentity();
    identity[field] = value;
    identity.identitySha256 = selfHash(identity, "identitySha256");
    expectCode(() => requestDeploymentProfileResolution(identity, now), "invalid_trusted_qm_identity_schema");
  }
  const request = requestDeploymentProfileResolution(trustedIdentity(), now);
  for (const mutation of [
    { profileRef: ceoDeploymentProfile.profileRef },
    { profileSha256: ceoDeploymentProfile.profileSha256 },
    { resolutionState: "resolved" },
  ]) {
    const forged = { ...request, ...mutation };
    forged.requestSha256 = selfHash(forged, "requestSha256");
    expectCode(() => validateUnresolvedProfileResolutionRequest(forged), "resolution_request_must_remain_inert");
  }
});

test("mixed human, QM, and external identities fail closed", () => {
  for (const overrides of [
    { humanEmail: "someone@risely.ai" },
    { qmPrincipalRef: "qm:principal:someone" },
    { externalIdentityRef: "external-identity:risely:someone", externalOrganizationRole: "ceo" },
  ]) {
    expectCode(() => validateTrustedQmIdentityInput(trustedIdentity(overrides), now), "mixed_or_unknown_qm_identity");
  }
  for (const overrides of [
    { organizationRef: "organization:other" },
    { workspaceRef: "workspace:other" },
    { externalOrganizationRole: "admin" },
  ]) {
    expectCode(
      () => requestDeploymentProfileResolution(trustedIdentity(overrides), now),
      "mixed_or_unknown_qm_identity",
    );
  }
});

test("capability and grant escalation survives rehashing but not profile validation", () => {
  const mutations = [
    (profile) => profile.allowedCapabilities.unshift("admin.execute"),
    (profile) => profile.allowedCapabilities.push("gmail.send"),
    (profile) => {
      profile.grantPolicy.delegationAllowed = true;
    },
    (profile) => {
      profile.grantPolicy.maximumProviderGrantLifetimeMs = 1;
    },
  ];
  for (const mutate of mutations) {
    const profile = structuredClone(ceoDeploymentProfile);
    mutate(profile);
    rehashProfile(profile);
    assert.throws(() => validateDeploymentProfile(profile));
  }
  for (const mutate of [
    (profile) => {
      profile.providerExecutionAllowed = true;
    },
    (profile) => {
      profile.activationMode = "live";
    },
    (profile) => {
      profile.grantPolicy.approvalRequired = false;
    },
  ]) {
    const profile = structuredClone(ceoDeploymentProfile);
    mutate(profile);
    rehashProfile(profile);
    assert.throws(() => validateDeploymentProfile(profile));
  }
});

test("provider effect modes and operations are pinned by the profile digest", () => {
  const changedPolicy = structuredClone(ceoDeploymentProfile);
  changedPolicy.providerEffectPolicySha256 = "0".repeat(64);
  rehashProfile(changedPolicy);
  expectCode(() => validateDeploymentProfile(changedPolicy), "unsupported_deployment_profile");
  const send = providerEffectPolicyCatalog.capabilities.find(
    (entry) => entry.capability === "google.gmail.drafts.send",
  );
  assert.deepEqual(
    {
      capabilityVersion: send.capabilityVersion,
      provider: send.provider,
      operation: send.operation,
      authorizationMode: send.authorizationMode,
    },
    {
      capabilityVersion: 1,
      provider: "google",
      operation: "google.gmail.drafts.send",
      authorizationMode: "approval-once",
    },
  );
});

test("provider-owner replay and provider identity injection fail closed", () => {
  const replayed = structuredClone(ceoDeploymentProfile);
  replayed.providerOwners[3].providerOwnerRef = replayed.providerOwners[4].providerOwnerRef;
  rehashProfile(replayed);
  expectCode(() => validateDeploymentProfile(replayed), "unsupported_deployment_profile");

  const swapped = structuredClone(ceoDeploymentProfile);
  [swapped.providerOwners[0].providerOwnerRef, swapped.providerOwners[1].providerOwnerRef] = [
    swapped.providerOwners[1].providerOwnerRef,
    swapped.providerOwners[0].providerOwnerRef,
  ];
  rehashProfile(swapped);
  expectCode(() => validateDeploymentProfile(swapped), "unsupported_deployment_profile");

  const injected = structuredClone(ceoDeploymentProfile);
  injected.providerOwners[3].oauthSubject = "provider-subject-value";
  rehashProfile(injected);
  expectCode(() => validateDeploymentProfile(injected), "unsupported_deployment_profile");
});

test("surface audiences cannot leak, cross-bind, or accept raw provider IDs", () => {
  const mutations = [
    (profile) => {
      profile.audiences.notion.audienceRef = profile.audiences.slack.audienceRef;
    },
    (profile) => {
      profile.audiences.qm.principalRef = profile.audiences.slack.principalRef;
    },
    (profile) => {
      profile.audiences.slack.providerUserId = "U0123456789";
    },
  ];
  for (const mutate of mutations) {
    const profile = structuredClone(ceoDeploymentProfile);
    mutate(profile);
    rehashProfile(profile);
    assert.throws(() => validateDeploymentProfile(profile));
  }
  assert.notEqual(ceoDeploymentProfile.audiences.slack.audienceRef, ceoDeploymentProfile.audiences.qm.audienceRef);
  assert.notEqual(ceoDeploymentProfile.audiences.slack.audienceRef, ceoDeploymentProfile.audiences.notion.audienceRef);
  assert.notEqual(ceoDeploymentProfile.audiences.qm.audienceRef, ceoDeploymentProfile.audiences.notion.audienceRef);
});

test("evaluation policy drift cannot weaken independent quality gates", () => {
  const mutations = [
    (profile) => {
      profile.evalPolicy.minimumIndependentJudges = 1;
    },
    (profile) => {
      profile.evalPolicy.independentOriginsRequired = false;
      profile.evalPolicy.selfReviewAllowed = true;
    },
    (profile) => {
      profile.evalPolicy.requiredGates = profile.evalPolicy.requiredGates.filter((gate) => gate !== "recipient_safety");
      profile.evalPolicy.sideEffectBudget = 1;
    },
  ];
  for (const mutate of mutations) {
    const profile = structuredClone(ceoDeploymentProfile);
    mutate(profile);
    rehashProfile(profile);
    assert.throws(() => validateDeploymentProfile(profile));
  }
  for (const mutate of [
    (profile) => {
      profile.evalPolicy.minimumScore = 3;
    },
    (profile) => {
      profile.evalPolicy.maximumScoreSpread = 2;
    },
    (profile) => {
      profile.evalPolicy.maximumEvaluationRuntimeMs = 900_001;
    },
  ]) {
    const profile = structuredClone(ceoDeploymentProfile);
    delete profile.profileSha256;
    mutate(profile);
    assert.throws(() => createProfileAuthority(profile));
  }
  assert.equal(ceoDeploymentProfile.evalPolicy.minimumIndependentJudges, 2);
  assert.deepEqual(ceoDeploymentProfile.evalPolicy.judgeClasses, ["quality", "safety"]);
  assert.equal(ceoDeploymentProfile.evalPolicy.sideEffectBudget, 0);
  assert.equal(ceoDeploymentProfile.evalPolicy.minimumScore, 4);
  assert.equal(ceoDeploymentProfile.evalPolicy.maximumScoreSpread, 1);
  assert.equal(ceoDeploymentProfile.evalPolicy.maximumEvaluationRuntimeMs, 900_000);
});

test("cloned self-hashed profile and registry forgeries remain unsupported", () => {
  for (const mutate of [
    (profile) => {
      profile.anchors.organizationRef = "organization:other";
    },
    (profile) => {
      profile.agent.agentId = "agent:risely:other";
    },
    (profile) => {
      profile.identity.externalOrganizationRole = "owner";
    },
  ]) {
    const profile = structuredClone(ceoDeploymentProfile);
    mutate(profile);
    rehashProfile(profile);
    expectCode(() => validateDeploymentProfile(profile), "unsupported_deployment_profile");
    const registry = structuredClone(deploymentProfileRegistry);
    registry.profiles = [profile];
    rehashRegistry(registry);
    expectCode(() => validateDeploymentProfileRegistry(registry), "unsupported_profile_registry");
  }
});

test("proxies, accessors, and hidden fields never reach hashing or resolution", () => {
  const proxiedProfile = structuredClone(ceoDeploymentProfile);
  proxiedProfile.agent = new Proxy(proxiedProfile.agent, {});
  expectCode(() => validateDeploymentProfile(proxiedProfile), "unsupported_deployment_profile");

  const proxiedIdentity = trustedIdentity();
  proxiedIdentity.externalIdentityRef = new Proxy({ value: proxiedIdentity.externalIdentityRef }, {});
  expectCode(() => requestDeploymentProfileResolution(proxiedIdentity, now), "untrusted_plain_data");

  const accessorIdentity = trustedIdentity();
  Object.defineProperty(accessorIdentity, "humanEmail", { enumerable: true, get: () => "shahryar@risely.ai" });
  expectCode(() => validateTrustedQmIdentityInput(accessorIdentity, now), "untrusted_plain_data");

  const hiddenProfile = structuredClone(ceoDeploymentProfile);
  Object.defineProperty(hiddenProfile.identity, "providerUserId", { enumerable: false, value: "U0123456789" });
  expectCode(() => validateDeploymentProfile(hiddenProfile), "unsupported_deployment_profile");
});

test("unknown, duplicate, and second profiles are unavailable", () => {
  const unknown = structuredClone(ceoDeploymentProfile);
  unknown.profileRef = "deployment-profile:risely:unknown:v1";
  rehashProfile(unknown);
  expectCode(() => validateDeploymentProfile(unknown), "unsupported_deployment_profile");

  const duplicate = structuredClone(deploymentProfileRegistry);
  duplicate.profiles.push(structuredClone(duplicate.profiles[0]));
  rehashRegistry(duplicate);
  expectCode(() => validateDeploymentProfileRegistry(duplicate), "unsupported_profile_registry");

  const second = structuredClone(deploymentProfileRegistry);
  const other = structuredClone(ceoDeploymentProfile);
  other.profileRef = "deployment-profile:risely:staff:v1";
  rehashProfile(other);
  second.profiles.push(other);
  rehashRegistry(second);
  expectCode(() => validateDeploymentProfileRegistry(second), "unsupported_profile_registry");

  assert.equal(profileExpansionAvailability.secondProfileState, "test_only");
  assert.equal(profileExpansionAvailability.durableCompositeScopeVerified, true);
  assert.deepEqual(profileExpansionAvailability.requiredDurableColumns, ["profile_ref", "profile_sha256"]);
  expectCode(() => validateDeploymentProfile(syntheticDeploymentProfile), "unsupported_deployment_profile");
  assert.notEqual(
    createRuntimeScope(syntheticDeploymentProfile).profileRef,
    createRuntimeScope(ceoDeploymentProfile).profileRef,
  );
});

test("the inert synthetic profile reuses revenue marketing and Gmail workflow factories without authority", () => {
  const revenue = createRevenueProgramWorkflow(syntheticDeploymentProfile);
  const revenueProgram = revenue.buildRevenueProgram(revenue.createBoundaryFixture({ candidateCount: 1 }));
  const revenueState = revenue.initializeRevenueProgramState(revenueProgram);
  assert.equal(revenueProgram.principalBinding.principalRef, syntheticDeploymentProfile.identity.humanPrincipalRef);
  assert.equal(revenueProgram.safety.disposition, "unresolved_proposals");
  assert.equal(revenueState.safetyDisposition, "hard_disabled");
  assert.throws(() => initializeRevenueProgramState(revenueProgram), /untrusted_program_instance/);
  for (const binding of revenueProgram.connectionBindings) {
    assert.equal(binding.providerOwnerRef.startsWith("provider-owner:"), true);
    assert.equal(binding.providerOwnerRef.endsWith(":synthetic"), true);
  }
  const marketing = createMarketingProgramWorkflow(syntheticDeploymentProfile);
  const marketingProgram = marketing.buildWeeklyMarketingPlan(marketing.createBoundaryFixture());
  const marketingState = marketing.initializeMarketingState(marketingProgram);
  assert.equal(marketingProgram.principalBinding.principalRef, syntheticDeploymentProfile.identity.humanPrincipalRef);
  assert.equal(marketingProgram.rolePolicy.profileRef, syntheticDeploymentProfile.profileRef);
  assert.equal(marketingProgram.rubric.principalRef, syntheticDeploymentProfile.identity.humanPrincipalRef);
  assert.equal(marketingState.executionDisposition, "hard_disabled");
  assert.throws(() => initializeMarketingState(marketingProgram), /untrusted_program/);
  assert.notEqual(
    marketing.contracts.policy.policySha256,
    createMarketingProgramWorkflow(ceoDeploymentProfile).contracts.policy.policySha256,
  );
  assert.notEqual(
    marketing.contracts.voice.voiceSha256,
    createMarketingProgramWorkflow(ceoDeploymentProfile).contracts.voice.voiceSha256,
  );
  const daily = marketing.createBoundaryFixture({ daily: true });
  assert.equal(marketing.inspectDailyMarketingDraft(daily).copyDisposition, "untrusted_candidate");
  const dailyProgram = marketing.buildDailyMarketingDraft(daily);
  const dailyState = marketing.initializeMarketingState(dailyProgram);
  assert.equal(dailyProgram.kind, "daily_draft");
  assert.equal(dailyProgram.rolePolicy.profileRef, syntheticDeploymentProfile.profileRef);
  assert.equal(dailyProgram.rubric.principalRef, syntheticDeploymentProfile.identity.humanPrincipalRef);
  assert.equal(dailyState.executionDisposition, "hard_disabled");
  assert.throws(() => initializeMarketingState(dailyProgram), /untrusted_program/);
  assert.throws(() => marketing.buildDailyMarketingDraft(daily, {}), /caller_approval_context_unsupported/);
  const scope = createRuntimeScope(syntheticDeploymentProfile);
  const { PrincipalBinding: binding, EvidenceBundle, WorkflowArtifact } = scope.contracts;
  const evidenceBundle = EvidenceBundle.create({
    principalBinding: binding.value,
    evidence: [
      {
        source: "gmail",
        sourceRecordRef: `source-record:${"1".repeat(64)}`,
        contentSha256: "2".repeat(64),
        relatedContentSha256: [],
        observedAt: "2026-08-26T16:00:00.000Z",
        fetchedAt: "2026-08-26T16:00:00.000Z",
        status: "cited",
        trust: "untrusted_source_data",
        availability: "available",
        sourceTrust: "untrusted_source_data",
        sourceAvailability: "available",
        claimRefs: [`claim:${"6".repeat(64)}`],
      },
    ],
  });
  const artifact = WorkflowArtifact.create({
    principalBinding: binding.value,
    sourceLane: "chief_of_staff",
    sourceArtifactRef: `source:${"3".repeat(64)}`,
    sourceArtifactSha256: "4".repeat(64),
    sourceRevision: "5".repeat(64),
    workflowKind: "meeting_prep",
    state: "ready",
    evidenceBundle,
    updatedAt: "2026-08-26T16:01:00.000Z",
  });
  const gmail = createDormantGmailDraftProposalCompiler(scope).build({
    artifact,
    recipients: ["synthetic-recipient@example.invalid"],
    subject: "Synthetic review draft",
    body: "This remains a dormant proposal.",
    createdAt: "2026-08-26T16:02:00.000Z",
    expiresAt: "2026-08-26T17:02:00.000Z",
  });
  assert.equal(gmail.proposal.actor.externalPrincipalRef, syntheticDeploymentProfile.identity.externalIdentityRef);
  assert.equal(gmail.proposal.actor.scopeRef, syntheticDeploymentProfile.anchors.principalBindingRef);
  assert.equal(gmail.executionAvailable, false);
  assert.equal(revenue.providerExecutionAllowed, false);
  assert.equal(marketing.providerExecutionAllowed, false);
});

test("workflow factories reject branded profiles missing required capability or provider ownership", () => {
  const withoutCapability = structuredClone(syntheticDeploymentProfile);
  delete withoutCapability.profileSha256;
  withoutCapability.allowedCapabilities = withoutCapability.allowedCapabilities.filter(
    (capability) => capability !== "google.gmail.drafts.create",
  );
  const capabilityProfile = createProfileAuthority(withoutCapability);
  assert.throws(
    () => createDormantGmailDraftProposalCompiler(createRuntimeScope(capabilityProfile)),
    /does not support/,
  );
  assert.throws(
    () => createRevenueProgramWorkflow(capabilityProfile),
    (error) => error?.code === "revenue_program_unsupported_revenue_profile",
  );
  const withoutProvider = structuredClone(syntheticDeploymentProfile);
  delete withoutProvider.profileSha256;
  withoutProvider.providerOwners = withoutProvider.providerOwners.filter((entry) => entry.provider !== "google");
  const providerProfile = createProfileAuthority(withoutProvider);
  assert.throws(() => createDormantGmailDraftProposalCompiler(createRuntimeScope(providerProfile)), /does not support/);
  assert.throws(
    () => createRevenueProgramWorkflow(providerProfile),
    (error) => error?.code === "revenue_program_unsupported_revenue_profile",
  );

  for (const field of ["capability", "provider"]) {
    const withoutDemoAuthority = structuredClone(syntheticDeploymentProfile);
    delete withoutDemoAuthority.profileSha256;
    if (field === "capability") {
      withoutDemoAuthority.allowedCapabilities = withoutDemoAuthority.allowedCapabilities.filter(
        (capability) => capability !== "demo_repository.read",
      );
    } else {
      withoutDemoAuthority.providerOwners = withoutDemoAuthority.providerOwners.filter(
        (entry) => entry.provider !== "demo_repository",
      );
    }
    assert.throws(
      () => createRevenueProgramWorkflow(createProfileAuthority(withoutDemoAuthority)),
      (error) => error?.code === "revenue_program_unsupported_revenue_profile",
    );
  }

  const withoutMarketingCapability = structuredClone(syntheticDeploymentProfile);
  delete withoutMarketingCapability.profileSha256;
  withoutMarketingCapability.allowedCapabilities = withoutMarketingCapability.allowedCapabilities.filter(
    (capability) => capability !== "marketing.content_propose",
  );
  assert.throws(
    () => createMarketingProgramWorkflow(createProfileAuthority(withoutMarketingCapability)),
    (error) => error?.code === "unsupported_marketing_profile",
  );

  const withoutSlackProvider = structuredClone(syntheticDeploymentProfile);
  delete withoutSlackProvider.profileSha256;
  withoutSlackProvider.providerOwners = withoutSlackProvider.providerOwners.filter(
    (entry) => entry.provider !== "slack",
  );
  assert.throws(
    () => createMarketingProgramWorkflow(createProfileAuthority(withoutSlackProvider)),
    (error) => error?.code === "unsupported_marketing_profile",
  );
});

test("the deployment-profile seam has no provider, environment, database, network, or receipt authority", async () => {
  const source = await readFile(new URL("../../canary/deployment-profiles/index.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(
    source,
    /process\.env|node:net|node:http|node:https|\bfetch\s*\(|\bpg\b|postgres|oauthSubject|accessToken|refreshToken|clientSecret/u,
  );
  assert.doesNotMatch(source, /create[A-Za-z]*Receipt|mint[A-Za-z]*Receipt|issue[A-Za-z]*Receipt/u);
  assert.equal(
    Object.keys(await import("../../canary/deployment-profiles/index.mjs")).some((name) => /receipt/iu.test(name)),
    false,
  );
  assert.equal(
    ceoDeploymentProfile.providerOwners.every((entry) => Object.keys(entry).length === 2),
    true,
  );
  assert.equal(
    ceoDeploymentProfile.providerOwners.every((entry) => entry.providerOwnerRef.startsWith("provider-owner:")),
    true,
  );
});

test("deployment-profile production authority depends only on its cycle-free contract", async () => {
  const source = await readFile(new URL("../../canary/deployment-profiles/index.mjs", import.meta.url), "utf8");
  const imports = [...source.matchAll(/from\s+"([^"]+)"/gu)].map((match) => match[1]);
  assert.deepEqual(imports, ["./contract.mjs", "./provider-effect-policy.mjs"]);
  assert.doesNotMatch(source, /shared-contracts|runtime-scope|process\.env/u);
});
