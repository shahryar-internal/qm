import assert from "node:assert/strict";
import test from "node:test";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { buildActionProposal, deriveProposalHashes } from "../../canary/contracts/index.mjs";
import { buildDormantGmailDraftProposal } from "../../canary/integration/index.mjs";
import { createProviderEffectPolicySuite, providerEffectCapabilities } from "../../canary/provider-effects/index.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import { createRuntimeDomain } from "../../canary/service/ceo-canary/src/domain.mjs";

const suite = createProviderEffectPolicySuite(createRuntimeScope(ceoDeploymentProfile));
const runtimeDomain = createRuntimeDomain(suite.runtimeScope);

const actor = {
  contractType: "actor",
  contractVersion: 1,
  principalRef: suite.runtimeScope.domainAuthority.principalRef,
  qmPrincipalId: suite.runtimeScope.domainAuthority.qmPrincipalId,
  externalPrincipalRef: suite.runtimeScope.domainAuthority.externalPrincipalRef,
  agent: {
    id: suite.runtimeScope.domainAuthority.agentId,
    version: suite.runtimeScope.domainAuthority.agentVersion,
  },
  surface: "system",
  scopeRef: suite.runtimeScope.domainAuthority.scopeRef,
  audienceRef: suite.runtimeScope.domainAuthority.audienceRef,
  credentialOwnerRef: suite.runtimeScope.domainAuthority.credentialOwnerRef,
};

const proposal = (capability, provider, target, payload) =>
  buildActionProposal({
    contractType: "action-proposal",
    contractVersion: 1,
    proposalId: "proposal:provider-effect-test",
    runId: "run:provider-effect-test",
    actor,
    capability,
    capabilityVersion: 1,
    provider,
    credentialRef: actor.credentialOwnerRef,
    subjectRef: "artifact:provider-effect-test",
    target,
    payload,
    artifactRefs: [{ artifactId: "artifact:provider-effect-test", sha256: "a".repeat(64) }],
    evidenceRefs: [],
    capturedState: {},
    preconditions: [],
    createdAt: "2026-08-27T20:00:00.000Z",
    expiresAt: "2026-08-27T20:05:00.000Z",
  });

test("the common effect policy closes every declared provider-write class", () => {
  assert.deepEqual(providerEffectCapabilities, [
    "google.calendar.events.create",
    "google.calendar.events.update",
    "google.gmail.drafts.create",
    "google.gmail.drafts.send",
    "notion.pages.upsert",
    "slack.chat.post",
  ]);
  const policies = suite.policies();
  assert.equal(policies.length, providerEffectCapabilities.length);
  assert.equal(
    policies.every((policy) => policy.maximumAttempts === 1),
    true,
  );
  assert.equal(
    policies.every((policy) => policy.reconciliationRequired),
    true,
  );
  assert.equal(
    policies.every((policy) => policy.profileRef === ceoDeploymentProfile.profileRef),
    true,
  );
  assert.equal(
    policies.every((policy) => policy.profileSha256 === ceoDeploymentProfile.profileSha256),
    true,
  );
  assert.equal(Object.isFrozen(policies), true);
  assert.equal(policies.every(Object.isFrozen), true);
});

test("prospective policy distinguishes declared automatic writes from approval-bound send", () => {
  for (const capability of [
    "google.gmail.drafts.create",
    "google.calendar.events.create",
    "google.calendar.events.update",
    "notion.pages.upsert",
    "slack.chat.post",
  ]) {
    const policy = suite.policy(capability);
    assert.equal(policy.authorizationMode, "automatic");
    assert.equal(policy.maximumApprovalLifetimeMs, 0);
  }
  const send = suite.policy("google.gmail.drafts.send");
  assert.equal(send.authorizationMode, "approval-once");
  assert.equal(send.maximumApprovalLifetimeMs, ceoDeploymentProfile.grantPolicy.maximumApprovalLifetimeMs);
});

test("the catalog declares Calendar and Notion resource ownership and a fixed Slack destination", () => {
  assert.equal(suite.policy("google.calendar.events.create").ownershipMode, "agent-managed-resource");
  assert.equal(suite.policy("google.calendar.events.update").ownershipMode, "agent-managed-resource");
  assert.equal(suite.policy("notion.pages.upsert").targetClass, "attested-private-ceo-root");
  assert.equal(suite.policy("slack.chat.post").targetClass, "verified-ceo-direct-message");
});

test("the current shadow profile cannot execute any provider effect", () => {
  assert.equal(suite.executionAvailable, false);
  for (const policy of suite.policies()) {
    assert.equal(policy.executionAvailable, false);
    assert.equal(policy.blockers.includes("provider_execution_not_activated"), true);
    assert.equal(policy.blockers.includes("provider_grant_not_activated"), true);
    assert.equal(policy.blockers.includes("provider_identity_receipt_unavailable"), true);
    assert.equal(policy.blockers.includes("durable_effect_authority_unavailable"), true);
    assert.equal(policy.blockers.includes("evaluation_release_unavailable"), true);
  }
  assert.equal(suite.policy("google.gmail.drafts.create").profileCapabilityDeclared, true);
  assert.equal(suite.policy("google.calendar.events.create").profileCapabilityDeclared, true);
});

test("unknown capability and forged scope fail before policy construction", () => {
  assert.throws(() => suite.policy("gmail.messages.send"), /unsupported/);
  assert.throws(() => createProviderEffectPolicySuite({ ...suite.runtimeScope }), /authority is invalid/);
});

test("the existing Gmail draft compiler enters the common effect contract", () => {
  const artifact = suite.runtimeScope.contracts.WorkflowArtifact.create({
    principalBinding: suite.runtimeScope.contracts.PrincipalBinding.value,
    sourceLane: "chief_of_staff",
    sourceArtifactRef: `source:${"b".repeat(64)}`,
    sourceArtifactSha256: "c".repeat(64),
    sourceRevision: "d".repeat(64),
    workflowKind: "meeting_prep",
    state: "ready",
    evidenceBundle: suite.runtimeScope.contracts.EvidenceBundle.create({
      principalBinding: suite.runtimeScope.contracts.PrincipalBinding.value,
      evidence: [
        {
          source: "gmail",
          sourceRecordRef: `source-record:${"e".repeat(64)}`,
          contentSha256: "f".repeat(64),
          relatedContentSha256: [],
          observedAt: "2026-08-27T19:58:00.000Z",
          fetchedAt: "2026-08-27T19:59:00.000Z",
          status: "cited",
          trust: "untrusted_source_data",
          availability: "available",
          sourceTrust: "untrusted_source_data",
          sourceAvailability: "available",
          claimRefs: [`claim:${"1".repeat(64)}`],
        },
      ],
    }),
    updatedAt: "2026-08-27T20:00:00.000Z",
  });
  const compiled = buildDormantGmailDraftProposal({
    artifact,
    recipients: ["recipient@example.com"],
    subject: "Follow-up",
    body: "Thank you for the conversation.",
    createdAt: "2026-08-27T20:00:00.000Z",
    expiresAt: "2026-08-27T20:05:00.000Z",
  });
  const checked = suite.assertProposal(compiled.proposal);
  assert.deepEqual(checked.proposal, compiled.proposal);
  assert.equal(checked.policy.capability, "google.gmail.drafts.create");
  assert.equal(checked.policy.authorizationMode, "automatic");
  assert.equal(checked.policy.executionAvailable, false);
  assert.deepEqual(runtimeDomain.assertProposal(compiled.proposal), compiled.proposal);
});

test("every prospective write shape is exact, content-addressed, and still inert", () => {
  const assertProspective = (value) => {
    assert.doesNotThrow(() => suite.assertProposal(value));
    assert.deepEqual(runtimeDomain.assertProposal(value), value);
  };
  const googleOwner = "provider-owner:google:ceo";
  const sendRevision = "2".repeat(64);
  assertProspective(
    proposal(
      "google.gmail.drafts.send",
      "google",
      {
        providerOwnerRef: googleOwner,
        mailbox: "shahryar@risely.ai",
        draftId: "gmail-draft:managed-test",
        draftRevisionSha256: sendRevision,
      },
      { expectedContentSha256: sendRevision },
    ),
  );

  const calendarTarget = {
    providerOwnerRef: googleOwner,
    calendarRef: "google-calendar:primary",
    resourceKey: "3".repeat(64),
  };
  const calendarPayload = {
    summary: "CEO review",
    description: "Review the weekly operating plan.",
    startAt: "2026-08-28T18:00:00.000Z",
    endAt: "2026-08-28T18:30:00.000Z",
    timeZone: "America/Los_Angeles",
    location: null,
    privateOwnershipKey: suite.runtimeScope.contracts.PrincipalBinding.hash({
      profileRef: suite.runtimeScope.profileRef,
      profileSha256: suite.runtimeScope.profileSha256,
      providerOwnerRef: googleOwner,
      calendarRef: calendarTarget.calendarRef,
      resourceKey: calendarTarget.resourceKey,
    }),
  };
  assertProspective(proposal("google.calendar.events.create", "google", calendarTarget, calendarPayload));
  assertProspective(
    proposal(
      "google.calendar.events.update",
      "google",
      {
        ...calendarTarget,
        providerEventId: "managed-event-1",
        expectedEtag: "etag-managed-event-1",
        ownershipReceiptSha256: "4".repeat(64),
      },
      calendarPayload,
    ),
  );

  const notionTarget = {
    providerOwnerRef: "provider-owner:notion:ceo",
    parentRef: suite.runtimeScope.profile.audiences.notion.parentRef,
    audienceRef: suite.runtimeScope.profile.audiences.notion.audienceRef,
    resourceKey: "",
  };
  const notionPayload = {
    title: "CEO operating brief",
    artifactRef: "artifact:provider-effect-test",
    artifactRevision: 1,
    artifactSha256: "5".repeat(64),
    renderSha256: "6".repeat(64),
  };
  notionTarget.resourceKey = suite.runtimeScope.contracts.PrincipalBinding.hash({
    profileRef: suite.runtimeScope.profileRef,
    profileSha256: suite.runtimeScope.profileSha256,
    parentRef: notionTarget.parentRef,
    audienceRef: notionTarget.audienceRef,
    artifactRef: notionPayload.artifactRef,
  });
  assertProspective(proposal("notion.pages.upsert", "notion", notionTarget, notionPayload));

  const slackTarget = {
    providerOwnerRef: "provider-owner:slack:risely",
    teamRef: suite.runtimeScope.profile.anchors.slackTeamRef,
    principalRef: suite.runtimeScope.profile.audiences.slack.principalRef,
    audienceRef: suite.runtimeScope.profile.audiences.slack.audienceRef,
  };
  const slackPayload = {
    text: "The CEO brief is ready.",
    artifactSha256: "7".repeat(64),
    outboxEventId: "outbox-event:provider-effect-test",
    messageSha256: "",
  };
  slackPayload.messageSha256 = suite.runtimeScope.contracts.PrincipalBinding.hash({
    target: slackTarget,
    text: slackPayload.text,
    artifactSha256: slackPayload.artifactSha256,
    outboxEventId: slackPayload.outboxEventId,
  });
  assertProspective(proposal("slack.chat.post", "slack", slackTarget, slackPayload));
});

test("provider, owner, actor, payload and lifetime substitutions are rejected", () => {
  const target = {
    providerOwnerRef: "provider-owner:google:ceo",
    mailbox: "shahryar@risely.ai",
    to: ["recipient@example.com"],
  };
  const body = "Hello";
  const subject = "Hello";
  const evidenceSha256 = suite.runtimeScope.contracts.PrincipalBinding.hash([]);
  const base = proposal("google.gmail.drafts.create", "google", target, {
    body,
    evidenceSha256,
    payloadSha256: suite.runtimeScope.contracts.PrincipalBinding.hash({
      target,
      payload: { body, evidenceSha256, subject },
    }),
    subject,
  });
  assert.doesNotThrow(() => suite.assertProposal(base));
  for (const mutate of [
    (value) => {
      value.provider = "gmail";
    },
    (value) => {
      value.capabilityVersion = 2;
    },
    (value) => {
      value.target.providerOwnerRef = "provider-owner:gmail:other";
    },
    (value) => {
      value.actor.principalRef = "principal:other";
    },
    (value) => {
      value.target.to = ["UPPER@example.com"];
    },
    (value) => {
      value.expiresAt = "2026-08-29T20:00:00.000Z";
    },
  ]) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => suite.assertProposal(buildActionProposalWithoutDerived(candidate)));
  }
});

test("profile policy, evidence audience, and strengthened effect intent cannot drift", () => {
  const target = {
    providerOwnerRef: "provider-owner:google:ceo",
    mailbox: "shahryar@risely.ai",
    to: ["recipient@example.com"],
  };
  const subject = "Hello";
  const body = "Hello";
  const foreignEvidence = [
    {
      contractType: "evidence-ref",
      contractVersion: 1,
      evidenceId: "evidence:foreign-audience",
      source: "gmail",
      sourceRecordRef: "source-record:foreign-audience",
      observedAt: "2026-08-27T19:58:00.000Z",
      fetchedAt: "2026-08-27T19:59:00.000Z",
      contentSha256: "8".repeat(64),
      audienceRef: "slack-audience:other",
      sensitivity: "commercial",
      trust: "untrusted_external",
    },
  ];
  const evidenceSha256 = suite.runtimeScope.contracts.PrincipalBinding.hash(foreignEvidence);
  const input = {
    contractType: "action-proposal",
    contractVersion: 1,
    proposalId: "proposal:provider-effect-foreign-evidence",
    runId: "run:provider-effect-test",
    actor,
    capability: "google.gmail.drafts.create",
    capabilityVersion: 1,
    provider: "google",
    credentialRef: actor.credentialOwnerRef,
    subjectRef: "artifact:provider-effect-test",
    target,
    payload: {
      body,
      evidenceSha256,
      payloadSha256: suite.runtimeScope.contracts.PrincipalBinding.hash({
        target,
        payload: { body, evidenceSha256, subject },
      }),
      subject,
    },
    artifactRefs: [{ artifactId: "artifact:provider-effect-test", sha256: "a".repeat(64) }],
    evidenceRefs: foreignEvidence,
    capturedState: {},
    preconditions: [],
    createdAt: "2026-08-27T20:00:00.000Z",
    expiresAt: "2026-08-27T20:05:00.000Z",
  };
  const foreign = buildActionProposal(input);
  assert.throws(() => suite.assertProposal(foreign), /outside the profile audience/);

  const accepted = suite.assertProposal(
    proposal("google.gmail.drafts.create", "google", target, {
      body,
      evidenceSha256: suite.runtimeScope.contracts.PrincipalBinding.hash([]),
      payloadSha256: suite.runtimeScope.contracts.PrincipalBinding.hash({
        target,
        payload: {
          body,
          evidenceSha256: suite.runtimeScope.contracts.PrincipalBinding.hash([]),
          subject,
        },
      }),
      subject,
    }),
  );
  assert.equal(accepted.intent.policySha256, accepted.policy.policySha256);
  assert.equal(accepted.intent.operation, accepted.policy.operation);
  assert.notEqual(accepted.intent.prospectiveEffectKey, accepted.proposal.effectKey);
  const { intentSha256, ...intentProjection } = accepted.intent;
  assert.equal(intentSha256, suite.runtimeScope.contracts.PrincipalBinding.hash(intentProjection));
});

test("descriptor attacks reject before any trap getter or JSON hook executes", () => {
  const target = {
    providerOwnerRef: "provider-owner:google:ceo",
    mailbox: "shahryar@risely.ai",
    to: ["recipient@example.com"],
  };
  const evidenceSha256 = suite.runtimeScope.contracts.PrincipalBinding.hash([]);
  const base = proposal("google.gmail.drafts.create", "google", target, {
    body: "Hello",
    evidenceSha256,
    payloadSha256: suite.runtimeScope.contracts.PrincipalBinding.hash({
      target,
      payload: { body: "Hello", evidenceSha256, subject: "Hello" },
    }),
    subject: "Hello",
  });
  let calls = 0;
  const traps = {
    get() {
      calls += 1;
      return undefined;
    },
    ownKeys() {
      calls += 1;
      return [];
    },
    getOwnPropertyDescriptor() {
      calls += 1;
      return undefined;
    },
    getPrototypeOf() {
      calls += 1;
      return Object.prototype;
    },
  };
  assert.throws(() => suite.assertProposal(new Proxy(base, traps)));
  assert.equal(calls, 0);
  const nested = structuredClone(base);
  nested.target = new Proxy(nested.target, traps);
  assert.throws(() => suite.assertProposal(nested));
  assert.equal(calls, 0);
  for (const mutate of [
    (value) =>
      Object.defineProperty(value.target, "mailbox", {
        enumerable: true,
        get() {
          calls += 1;
          return "shahryar@risely.ai";
        },
      }),
    (value) =>
      Object.defineProperty(value.target, "toJSON", {
        enumerable: true,
        value() {
          calls += 1;
          return target;
        },
      }),
    (value) => Object.defineProperty(value.target, Symbol("hidden"), { value: "hidden" }),
    (value) => Object.setPrototypeOf(value.target, { inherited: true }),
  ]) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => suite.assertProposal(candidate));
    assert.equal(calls, 0);
  }
});

test("policy and runtime reject future evidence header injection and malformed recipients", () => {
  const target = {
    providerOwnerRef: "provider-owner:google:ceo",
    mailbox: "shahryar@risely.ai",
    to: ["recipient@example.com"],
  };
  const subject = "Hello";
  const body = "Hello";
  const base = proposal("google.gmail.drafts.create", "google", target, {
    body,
    evidenceSha256: suite.runtimeScope.contracts.PrincipalBinding.hash([]),
    payloadSha256: suite.runtimeScope.contracts.PrincipalBinding.hash({
      target,
      payload: {
        body,
        evidenceSha256: suite.runtimeScope.contracts.PrincipalBinding.hash([]),
        subject,
      },
    }),
    subject,
  });
  const rebuild = (mutate) => {
    const candidate = structuredClone(base);
    mutate(candidate);
    candidate.payload.evidenceSha256 = suite.runtimeScope.contracts.PrincipalBinding.hash(candidate.evidenceRefs);
    candidate.payload.payloadSha256 = suite.runtimeScope.contracts.PrincipalBinding.hash({
      target: candidate.target,
      payload: {
        body: candidate.payload.body,
        evidenceSha256: candidate.payload.evidenceSha256,
        subject: candidate.payload.subject,
      },
    });
    delete candidate.semanticFingerprint;
    delete candidate.effectKey;
    delete candidate.proposalHash;
    return { ...candidate, ...deriveProposalHashes(candidate) };
  };
  const variants = [
    rebuild((value) => {
      value.evidenceRefs = [
        {
          contractType: "evidence-ref",
          contractVersion: 1,
          evidenceId: "evidence:future",
          source: "gmail",
          sourceRecordRef: "source-record:future",
          observedAt: "2026-08-27T20:06:00.000Z",
          fetchedAt: "2026-08-27T20:07:00.000Z",
          contentSha256: "9".repeat(64),
          audienceRef: actor.audienceRef,
          sensitivity: "commercial",
          trust: "untrusted_external",
        },
      ];
    }),
    rebuild((value) => {
      value.payload.subject = "Hello\r\nBcc: victim@example.com";
    }),
    rebuild((value) => {
      value.target.to = [`${"a".repeat(250)}@example.com`];
    }),
    rebuild((value) => {
      value.target.to = ["a@b..com"];
    }),
  ];
  for (const value of variants) {
    assert.throws(() => suite.assertProposal(value));
    assert.throws(() => runtimeDomain.assertProposal(value));
  }
});

const buildActionProposalWithoutDerived = (value) => {
  const candidate = structuredClone(value);
  delete candidate.semanticFingerprint;
  delete candidate.effectKey;
  delete candidate.proposalHash;
  return buildActionProposal(candidate);
};
