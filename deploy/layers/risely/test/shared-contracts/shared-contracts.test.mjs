import assert from "node:assert/strict";
import { test } from "node:test";
import * as contracts from "../../canary/shared-contracts/index.mjs";
import { syntheticDeploymentProfile } from "../../canary/deployment-profiles/testing.mjs";
import { mapLegacyIdentityAtMigrationIngress } from "../../canary/shared-contracts/migration-ingress.mjs";
import { buildActionlessPublication } from "../../canary/integration/index.mjs";

const {
  EvalRelease,
  EvidenceBundle,
  OutboxEvent,
  PrincipalBinding,
  PublicationEnvelope,
  WorkflowArtifact,
  createSharedContractSuite,
} = contracts;
const hash = (character) => character.repeat(64);

function evidenceInput(overrides = {}) {
  return {
    source: "calendar",
    sourceRecordRef: `source-record:${hash("1")}`,
    contentSha256: hash("2"),
    relatedContentSha256: [hash("3")],
    observedAt: "2026-08-26T16:55:00.000Z",
    fetchedAt: "2026-08-26T16:56:00.000Z",
    status: "available",
    trust: "untrusted_source_data",
    availability: "available",
    sourceTrust: "untrusted_source_data",
    sourceAvailability: "available",
    claimRefs: [`claim:${hash("4")}`],
    ...overrides,
  };
}

function artifact() {
  const evidenceBundle = EvidenceBundle.create({
    principalBinding: PrincipalBinding.value,
    evidence: [evidenceInput()],
  });
  return WorkflowArtifact.create({
    principalBinding: PrincipalBinding.value,
    sourceLane: "chief_of_staff",
    sourceArtifactRef: `source:${hash("5")}`,
    sourceArtifactSha256: hash("6"),
    sourceRevision: hash("7"),
    workflowKind: "meeting_prep",
    state: "ready",
    evidenceBundle,
    updatedAt: "2026-08-26T17:00:00.000Z",
  });
}

function releaseFor(contractSuite, workflowArtifact) {
  const binding = contractSuite.PrincipalBinding.value;
  const projection = {
    contractType: "EvalRelease",
    contractVersion: contractSuite.EvalRelease.version,
    digestRevision: contractSuite.EvalRelease.digestRevision,
    deploymentProfileRef: binding.profileRef,
    deploymentProfileSha256: binding.profileSha256,
    principalBindingSha256: binding.bindingSha256,
    artifactRef: workflowArtifact.artifactRef,
    artifactRevision: workflowArtifact.revision,
    artifactSha256: workflowArtifact.artifactSha256,
    candidateId: `evaluation-run:${hash("a")}`,
    evalAuthorityRef: "evaluation:ceo-shadow",
    policyRef: "evaluation-policy:ceo-shadow",
    policySha256: hash("8"),
    mode: "shadow",
    passed: true,
    release: true,
    sideEffectCount: 0,
    deterministicCheckIds: ["check:actionless", "check:evidence"],
    judges: [
      { judgeRef: "judge:quality", independenceKey: "origin:quality", receiptSha256: hash("b") },
      { judgeRef: "judge:safety", independenceKey: "origin:safety", receiptSha256: hash("c") },
    ],
    evaluatedAt: "2026-08-26T17:01:00.000Z",
    expiresAt: "2026-08-26T18:01:00.000Z",
  };
  return contractSuite.EvalRelease.validate(
    { ...projection, releaseSha256: contractSuite.PrincipalBinding.hash(projection) },
    workflowArtifact,
  );
}

function release(workflowArtifact) {
  return releaseFor(contracts, workflowArtifact);
}

function event(surface = "slack") {
  const workflowArtifact = artifact();
  return OutboxEvent.create({
    principalBinding: PrincipalBinding.value,
    artifact: workflowArtifact,
    evalRelease: release(workflowArtifact),
    surface,
    queuedAt: "2026-08-26T17:02:00.000Z",
  });
}

test("shared public barrel exposes the CEO facade and scoped suite factory", () => {
  assert.deepEqual(Object.keys(contracts).sort(), [
    "EvalRelease",
    "EvidenceBundle",
    "OutboxEvent",
    "PrincipalBinding",
    "PublicationEnvelope",
    "WorkflowArtifact",
    "createSharedContractSuite",
  ]);
  assert.equal(PrincipalBinding.version, 2);
  assert.equal(PrincipalBinding.value.profileRef, PrincipalBinding.identity.profileRef);
  assert.equal(PrincipalBinding.value.profileSha256, PrincipalBinding.identity.profileSha256);
  assert.equal(PrincipalBinding.identity.principalRef, "principal:ceo");
  assert.equal(PrincipalBinding.identity.agentId, "agent:risely:ceo-team");
  assert.equal(PrincipalBinding.identity.agentVersion, "1.0.0");
  assert.equal(PrincipalBinding.identity.credentialOwnerRef, "credential-owner:ceo");
  assert.equal(PrincipalBinding.identity.audienceRef, "slack-audience:ceo-private");
});

test("synthetic and CEO suites reject cross-profile objects with the same raw IDs", () => {
  const synthetic = createSharedContractSuite(syntheticDeploymentProfile);
  const ceoArtifact = artifact();
  const syntheticEvidence = synthetic.EvidenceBundle.create({
    principalBinding: synthetic.PrincipalBinding.value,
    evidence: [evidenceInput()],
  });
  const syntheticArtifact = synthetic.WorkflowArtifact.create({
    principalBinding: synthetic.PrincipalBinding.value,
    sourceLane: "chief_of_staff",
    sourceArtifactRef: ceoArtifact.sourceArtifactRef,
    sourceArtifactSha256: ceoArtifact.sourceArtifactSha256,
    sourceRevision: ceoArtifact.sourceRevision,
    workflowKind: ceoArtifact.workflowKind,
    state: ceoArtifact.state,
    evidenceBundle: syntheticEvidence,
    updatedAt: ceoArtifact.updatedAt,
  });
  assert.notEqual(syntheticArtifact.artifactRef, ceoArtifact.artifactRef);
  assert.throws(() => synthetic.WorkflowArtifact.validate(ceoArtifact));
  assert.throws(() => WorkflowArtifact.validate(syntheticArtifact));
  assert.throws(() => synthetic.PrincipalBinding.validate(PrincipalBinding.value));
  const ceoRelease = releaseFor(contracts, ceoArtifact);
  const syntheticRelease = releaseFor(synthetic, syntheticArtifact);
  assert.notEqual(syntheticRelease.releaseSha256, ceoRelease.releaseSha256);
  assert.throws(() => synthetic.EvalRelease.validate(ceoRelease, syntheticArtifact));
  assert.throws(() => EvalRelease.validate(syntheticRelease, ceoArtifact));
});

test("strict validators reject empty evidence, non-digests, and unsupported versions", () => {
  assert.throws(() => EvidenceBundle.create({ principalBinding: PrincipalBinding.value, evidence: [] }));
  const valid = artifact();
  assert.throws(() => WorkflowArtifact.validate({ ...valid, contractVersion: 999 }));
  assert.throws(() =>
    WorkflowArtifact.create({
      principalBinding: PrincipalBinding.value,
      sourceLane: "chief_of_staff",
      sourceArtifactRef: "meeting:caller-chosen",
      sourceArtifactSha256: hash("6"),
      sourceRevision: "v999",
      workflowKind: "meeting_prep",
      state: "ready",
      evidenceBundle: valid.evidenceBundle,
      updatedAt: valid.updatedAt,
    }),
  );
});

test("evidence metadata is closed to non-personal source, status, trust, and availability enums", () => {
  const create = (entry) => EvidenceBundle.create({ principalBinding: PrincipalBinding.value, evidence: [entry] });
  assert.throws(() => create(evidenceInput({ status: "Alice Smith" })), /status is unsupported/);
  assert.throws(() => create(evidenceInput({ trust: "alice@example.com" })), /trust or availability is unsupported/);
  assert.throws(() => create(evidenceInput({ source: "+1-415-555-0199" })), /source is unsupported/);
  assert.throws(() => create(evidenceInput({ sourceTrust: "123-45-6789" })), /sourceTrust is unsupported/);
  assert.throws(() => create(evidenceInput({ sourceAvailability: "person:ceo" })), /sourceAvailability is unsupported/);
});

test("one descriptor snapshot rejects nested proxies and accessors without invoking traps or getters", () => {
  let traps = 0;
  const nestedProxy = new Proxy(
    {},
    {
      getOwnPropertyDescriptor() {
        traps += 1;
        return undefined;
      },
      ownKeys() {
        traps += 1;
        return [];
      },
      getPrototypeOf() {
        traps += 1;
        return Object.prototype;
      },
      get() {
        traps += 1;
        return undefined;
      },
    },
  );
  assert.throws(() => PrincipalBinding.validate({ ...PrincipalBinding.value, nested: nestedProxy }));
  assert.equal(traps, 0);
  let getters = 0;
  const value = { ...PrincipalBinding.value };
  Object.defineProperty(value, "principalRef", {
    enumerable: true,
    get() {
      getters += 1;
      return "principal:ceo";
    },
  });
  assert.throws(() => PrincipalBinding.validate(value));
  assert.equal(getters, 0);
});

test("event and delivery identity are derived and reject alternate caller identities", () => {
  const first = event();
  const rebuilt = event();
  assert.equal(first.eventId, rebuilt.eventId);
  assert.throws(() => OutboxEvent.validate({ ...first, eventId: `event:${hash("9")}` }));
  assert.throws(() => OutboxEvent.validate({ ...first, audienceRef: "personal:ceo-canary" }));
});

test("PublicationEnvelope is closed to its event and rejects an alternate self-hashed payload", () => {
  const outboxEvent = event();
  const envelope = buildActionlessPublication(outboxEvent).publicationEnvelope;
  assert.equal(PublicationEnvelope.validate(envelope, outboxEvent).envelopeSha256, envelope.envelopeSha256);
  const payload = { ...envelope.payload, actions: [{ type: "button" }] };
  const projection = { ...envelope, payload, payloadSha256: PrincipalBinding.hash(payload) };
  delete projection.envelopeSha256;
  const alternate = { ...projection, envelopeSha256: PrincipalBinding.hash(projection) };
  assert.throws(() => PublicationEnvelope.validate(alternate, outboxEvent));
  assert.deepEqual(Object.keys(envelope.payload).sort(), [
    "actionless",
    "artifactRef",
    "artifactRevision",
    "artifactSha256",
    "audienceRef",
    "evalReleaseSha256",
    "evidence",
    "evidenceBundleSha256",
    "evidenceCount",
    "schemaVersion",
    "surface",
  ]);
  assert.deepEqual(Object.keys(envelope.payload.evidence[0]).sort(), [
    "availability",
    "evidenceRef",
    "status",
    "trust",
  ]);
  for (const personal of [
    { displayName: "Alice Smith" },
    { email: "alice@example.com" },
    { phone: "+1-415-555-0199", ssn: "123-45-6789" },
  ]) {
    const personalPayload = { ...envelope.payload, ...personal };
    const personalProjection = {
      ...envelope,
      payload: personalPayload,
      payloadSha256: PrincipalBinding.hash(personalPayload),
    };
    delete personalProjection.envelopeSha256;
    assert.throws(() =>
      PublicationEnvelope.validate(
        {
          ...personalProjection,
          envelopeSha256: PrincipalBinding.hash(personalProjection),
        },
        outboxEvent,
      ),
    );
  }
  for (const metadata of [
    { status: "Alice Smith" },
    { trust: "alice@example.com" },
    { availability: "+1-415-555-0199" },
  ]) {
    const metadataPayload = {
      ...envelope.payload,
      evidence: [{ ...envelope.payload.evidence[0], ...metadata }],
    };
    const metadataProjection = {
      ...envelope,
      payload: metadataPayload,
      payloadSha256: PrincipalBinding.hash(metadataPayload),
    };
    delete metadataProjection.envelopeSha256;
    assert.throws(() =>
      PublicationEnvelope.validate(
        {
          ...metadataProjection,
          envelopeSha256: PrincipalBinding.hash(metadataProjection),
        },
        outboxEvent,
      ),
    );
  }
});

test("legacy aliases exist only at migration ingress and inherited aliases are rejected", () => {
  assert.equal(
    mapLegacyIdentityAtMigrationIngress("audienceRef", "personal:ceo-canary"),
    PrincipalBinding.identity.audienceRef,
  );
  assert.throws(() => mapLegacyIdentityAtMigrationIngress("audienceRef", "toString"));
  assert.equal(Object.hasOwn(contracts, "mapLegacyIdentity"), false);
});
