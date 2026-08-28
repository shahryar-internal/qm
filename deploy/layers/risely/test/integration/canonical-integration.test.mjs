import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { normalizeMeetingDossier } from "../../canary/chief-of-staff/index.mjs";
import {
  adaptCalendarOccurrenceForLanes,
  adaptChiefOfStaffMeetingArtifact,
  adaptMarketingProgramArtifact,
  adaptRevenueProgramArtifact,
  adaptRevenueTranscriptArtifact,
  buildActionlessPublicationSet,
  createDormantGmailDraftProposalCompiler,
  buildLifecycleSupersessionTransaction,
  buildProspectiveGlobalGmailDraftQuota,
  buildTranscriptVerificationRequest,
  deriveProvenanceStorageKey,
  normalizeLaneSourceResult,
  validateCalendarBindingResolutionReceipt,
} from "../../canary/integration/index.mjs";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import { buildWeeklyMarketingPlan, createMarketingBoundaryFixture } from "../../canary/marketing-program/index.mjs";
import { privateCeoNotionBinding } from "../../canary/notion-templates/index.mjs";
import {
  buildRevenueProgram,
  createRevenueProgramBoundaryFixture,
  deploymentConnectionAnchors,
} from "../../canary/revenue-program/index.mjs";
import { EvalRelease, PrincipalBinding } from "../../canary/shared-contracts/index.mjs";
import { bindCanonicalCeoSurfaceStoreForProviderFreeTest } from "../../canary/service/ceo-surface/src/postgres-adapter.mjs";
import { compileDeploymentBinding, validateOutboxItem } from "../../canary/service/ceo-surface/src/contracts.mjs";
import { CanonicalCeoSurfaceStore } from "../../canary/service/ceo-surface/src/index.mjs";

const canaryRoot = fileURLToPath(new URL("../../canary/", import.meta.url));
const hash = (character) => character.repeat(64);
const deploymentBinding = Object.freeze({
  contractType: "ceo-surface-deployment",
  contractVersion: 1,
  ceoUserRef: "slack-user:ceo",
  ceoEmail: "shahryar@risely.ai",
  qmPrincipalRef: "qm:principal:ceo-canary",
  credentialOwnerRef: "credential-owner:ceo",
  slackTeamId: "T123456789",
  evalAuthorityRef: "evaluator:risely:shadow-gate",
  evalPolicySha256: hash("a"),
  identityResolverAuthorityRef: "resolver:risely:slack-identity",
});

function meetingArtifact() {
  return normalizeMeetingDossier({
    meetingKey: hash("1"),
    generatedAt: "2026-08-26T17:00:00.000Z",
    calendarEvidenceHash: hash("2"),
    sources: [
      { source: "calendar", availability: "available" },
      { source: "gmail", availability: "available" },
      { source: "clarify", availability: "not_connected" },
      { source: "command_center_brain", availability: "available" },
      { source: "notion", availability: "unavailable" },
    ],
    evidence: [
      {
        evidenceRef: "calendar:event:one",
        source: "calendar",
        evidenceHash: hash("2"),
        capturedAt: "2026-08-26T16:55:00.000Z",
      },
      {
        evidenceRef: "gmail:thread:one",
        source: "gmail",
        evidenceHash: hash("3"),
        capturedAt: "2026-08-26T16:54:00.000Z",
      },
      {
        evidenceRef: "brain:account:one",
        source: "command_center_brain",
        evidenceHash: hash("4"),
        capturedAt: "2026-08-26T16:53:00.000Z",
      },
    ],
    sections: {
      accountOverview: [{ claimId: "claim:account", text: "Institution context.", citations: ["brain:account:one"] }],
      contactBackground: [{ claimId: "claim:contact", text: "Buyer context.", citations: ["gmail:thread:one"] }],
      recommendedPositioning: [
        {
          claimId: "claim:position",
          text: "Meeting position.",
          citations: ["calendar:event:one", "brain:account:one"],
        },
      ],
    },
  });
}

function release(artifact) {
  const projection = {
    contractType: "EvalRelease",
    contractVersion: EvalRelease.version,
    digestRevision: EvalRelease.digestRevision,
    deploymentProfileRef: PrincipalBinding.value.profileRef,
    deploymentProfileSha256: PrincipalBinding.value.profileSha256,
    principalBindingSha256: PrincipalBinding.value.bindingSha256,
    artifactRef: artifact.artifactRef,
    artifactRevision: artifact.revision,
    artifactSha256: artifact.artifactSha256,
    candidateId: `evaluation-run:${hash("c")}`,
    evalAuthorityRef: "evaluation:ceo-shadow",
    policyRef: "evaluation-policy:ceo-shadow",
    policySha256: hash("e"),
    mode: "shadow",
    passed: true,
    release: true,
    sideEffectCount: 0,
    deterministicCheckIds: ["check:actionless", "check:evidence", "check:identity"],
    judges: [
      { judgeRef: "judge:quality", independenceKey: "origin:quality", receiptSha256: hash("1") },
      { judgeRef: "judge:safety", independenceKey: "origin:safety", receiptSha256: hash("2") },
    ],
    evaluatedAt: "2026-08-26T17:01:00.000Z",
    expiresAt: "2026-08-26T18:01:00.000Z",
  };
  return EvalRelease.validate({ ...projection, releaseSha256: PrincipalBinding.hash(projection) }, artifact);
}

class ProviderFreeV5Store {
  constructor() {
    this.deployment = compileDeploymentBinding(deploymentBinding);
    this.records = new Map();
    this.payloads = new Map();
  }

  async initialize() {
    return true;
  }

  async enqueueEvaluatedArtifactRevision(value) {
    const item = validateOutboxItem(value, this.deployment, "2026-08-26T17:03:00.000Z");
    const existing = this.records.get(item.eventId);
    if (existing && PrincipalBinding.hash(existing.outboxItem) !== PrincipalBinding.hash(item))
      throw new Error("outbox_conflict");
    const payloadOwner = this.payloads.get(item.payloadSha256);
    if (payloadOwner && payloadOwner !== item.eventId) throw new Error("outbox_conflict");
    const record = existing ?? Object.freeze({ outboxItem: item, status: "pending", revision: 0 });
    this.records.set(item.eventId, record);
    this.payloads.set(item.payloadSha256, item.eventId);
    return record;
  }

  async readOutboxEvent(eventId) {
    return this.records.get(eventId) ?? null;
  }
}

function bindingReceipt(calendarAccountRef = "calendar-account:ceo") {
  const projection = {
    contractType: "CalendarBindingResolutionReceipt",
    contractVersion: 1,
    brokerOrigin: "future_qm_connector_binding_broker",
    logicalGoogleAnchorRef: deploymentConnectionAnchors.googleAccountRef,
    connectionRef: "connection:google-calendar",
    calendarAccountRef,
    providerAccountSubject: `${calendarAccountRef}:subject`,
    principalRef: PrincipalBinding.identity.principalRef,
    credentialOwnerRef: PrincipalBinding.identity.credentialOwnerRef,
    receiptDisposition: "unresolved",
  };
  return { ...projection, receiptSha256: PrincipalBinding.hash(projection) };
}

function calendarSet(calendarAccountRef = "calendar-account:ceo") {
  return adaptCalendarOccurrenceForLanes({
    bindingResolutionReceipt: bindingReceipt(calendarAccountRef),
    occurrence: {
      providerEventId: "provider-event:meeting-1",
      originalStartAt: "2026-08-27T17:00:00.000Z",
      startAt: "2026-08-27T17:00:00.000Z",
      endAt: "2026-08-27T17:30:00.000Z",
      status: "confirmed",
      allDay: false,
      visibility: "private",
      seriesId: null,
      attendees: [
        { attendeeRef: `attendee:${hash("1")}`, role: "ceo", response: "accepted" },
        { attendeeRef: `attendee:${hash("2")}`, role: "external", response: "accepted" },
      ],
    },
  });
}

test("CoS artifact traverses the canonical facade into v5 storage and preserves every surface identity", async () => {
  const artifact = adaptChiefOfStaffMeetingArtifact(meetingArtifact());
  assert.equal(privateCeoNotionBinding.audienceRef, "audience:ceo-private");
  assert.equal(privateCeoNotionBinding.scope, "private_ceo");
  assert.notEqual(privateCeoNotionBinding.audienceRef, PrincipalBinding.identity.audienceRef);
  const publications = buildActionlessPublicationSet({
    artifact,
    evalRelease: release(artifact),
    queuedAt: "2026-08-26T17:02:00.000Z",
  });
  const v5 = new ProviderFreeV5Store();
  const facade = bindCanonicalCeoSurfaceStoreForProviderFreeTest(v5, deploymentBinding);
  assert.ok(facade instanceof CanonicalCeoSurfaceStore);
  await facade.initialize();
  for (const [surface, item] of Object.entries(publications)) {
    const stored = await facade.enqueuePublication({
      outboxEvent: item.outboxEvent,
      publicationEnvelope: item.publicationEnvelope,
    });
    assert.equal(stored.outboxEvent.surface, surface);
    assert.equal(stored.outboxEvent.artifact.artifactRef, artifact.artifactRef);
    assert.equal(stored.outboxEvent.artifact.revision, artifact.revision);
    assert.equal(stored.outboxEvent.artifact.artifactSha256, artifact.artifactSha256);
    assert.equal(stored.publicationEnvelope.evalReleaseSha256, item.outboxEvent.evalRelease.releaseSha256);
    assert.equal(item.publication.artifactRef, artifact.artifactRef);
    assert.equal(item.publication.artifactRevision, artifact.revision);
    assert.equal(item.publication.artifactSha256, artifact.artifactSha256);
    assert.equal(item.publication.audienceRef, PrincipalBinding.identity.audienceRef);
    assert.equal(item.publication.actionless, true);
    const v5Item = v5.records.get(item.outboxEvent.eventId).outboxItem;
    assert.equal(v5Item.contractType, "ceo-surface-canonical-outbox");
    assert.equal(v5Item.payloadSha256, item.publicationEnvelope.envelopeSha256);
    assert.equal(
      (await facade.readPublication(item.outboxEvent.eventId)).publicationEnvelope.envelopeSha256,
      item.publicationEnvelope.envelopeSha256,
    );
  }
});

test("facade rejects alternate event ids, alternate payloads, accessors, and nested proxies before durable access", async () => {
  const artifact = adaptChiefOfStaffMeetingArtifact(meetingArtifact());
  const item = buildActionlessPublicationSet({
    artifact,
    evalRelease: release(artifact),
    queuedAt: "2026-08-26T17:02:00.000Z",
  }).slack;
  const v5 = new ProviderFreeV5Store();
  const facade = bindCanonicalCeoSurfaceStoreForProviderFreeTest(v5, deploymentBinding);
  await facade.initialize();
  await facade.enqueuePublication({ outboxEvent: item.outboxEvent, publicationEnvelope: item.publicationEnvelope });
  await assert.rejects(() =>
    facade.enqueuePublication({
      outboxEvent: { ...item.outboxEvent, eventId: `event:${hash("f")}` },
      publicationEnvelope: item.publicationEnvelope,
    }),
  );
  const payload = { ...item.publicationEnvelope.payload, arbitrary: "CEO personal data" };
  const envelopeProjection = { ...item.publicationEnvelope, payload, payloadSha256: PrincipalBinding.hash(payload) };
  delete envelopeProjection.envelopeSha256;
  await assert.rejects(() =>
    facade.enqueuePublication({
      outboxEvent: item.outboxEvent,
      publicationEnvelope: { ...envelopeProjection, envelopeSha256: PrincipalBinding.hash(envelopeProjection) },
    }),
  );
  let getters = 0;
  const accessor = { outboxEvent: item.outboxEvent };
  Object.defineProperty(accessor, "publicationEnvelope", {
    enumerable: true,
    get() {
      getters += 1;
      return item.publicationEnvelope;
    },
  });
  await assert.rejects(() => facade.enqueuePublication(accessor));
  assert.equal(getters, 0);
  let traps = 0;
  const proxy = new Proxy(
    {},
    {
      ownKeys() {
        traps += 1;
        return [];
      },
      getPrototypeOf() {
        traps += 1;
        return Object.prototype;
      },
    },
  );
  await assert.rejects(() => facade.enqueuePublication({ outboxEvent: item.outboxEvent, publicationEnvelope: proxy }));
  assert.equal(traps, 0);
  assert.equal(v5.records.size, 1);
  assert.equal(
    v5.records.get(item.outboxEvent.eventId).outboxItem.payloadSha256,
    item.publicationEnvelope.envelopeSha256,
  );
});

test("Revenue and Marketing public outputs require full cited lineage at the integration boundary", () => {
  const revenue = buildRevenueProgram(createRevenueProgramBoundaryFixture());
  const revenueArtifact = adaptRevenueProgramArtifact(revenue);
  assert.match(deriveProvenanceStorageKey(revenueArtifact), /^storage:[a-f0-9]{64}$/u);
  assert.equal(revenueArtifact.evidenceBundle.evidence.length, revenue.correlations.length);
  assert.ok(revenueArtifact.evidenceBundle.evidence.every((entry) => entry.claimRefs.length > 0));
  const marketing = buildWeeklyMarketingPlan(createMarketingBoundaryFixture());
  const marketingArtifact = adaptMarketingProgramArtifact(marketing);
  assert.equal(marketingArtifact.evidenceBundle.evidence.length, marketing.artifact.sourceRefs.length);
  assert.ok(marketingArtifact.evidenceBundle.evidence.every((entry) => entry.relatedContentSha256.length === 2));
  assert.ok(
    marketingArtifact.evidenceBundle.evidence.every(
      (entry) => entry.sourceTrust === "unresolved" && entry.sourceAvailability === "unresolved",
    ),
  );
  assert.throws(() => adaptRevenueProgramArtifact({ version: "revenue-program.v999", programHash: hash("1") }));
  assert.throws(() => adaptMarketingProgramArtifact({ ...marketing, research: [] }));
  const minimal = meetingArtifact();
  const selfHashedMinimal = {
    ...minimal,
    sections: { accountOverview: [], contactBackground: [], recommendedPositioning: [] },
  };
  delete selfHashedMinimal.artifactHash;
  selfHashedMinimal.artifactHash = PrincipalBinding.hash(selfHashedMinimal);
  assert.throws(() => adaptChiefOfStaffMeetingArtifact(selfHashedMinimal));
});

test("one provider occurrence derives both lane projections with identical evidence and no caller occurrence identity", () => {
  const set = calendarSet();
  assert.equal(set.disposition, "prospective_unverified");
  assert.equal(set.receiptAuthenticated, false);
  assert.equal(set.revenue.occurrence.occurrenceRef, set.chiefOfStaff.occurrence.occurrenceRef);
  assert.equal(set.revenue.evidence, set.chiefOfStaff.evidence);
  assert.equal(set.revenue.occurrence.endAt, "2026-08-27T17:30:00.000Z");
  assert.equal(set.revenue.occurrence.attendees[1].role, "external");
  assert.equal(validateCalendarBindingResolutionReceipt(bindingReceipt()).receiptDisposition, "unresolved");
  assert.throws(() =>
    adaptCalendarOccurrenceForLanes({
      bindingResolutionReceipt: bindingReceipt(),
      occurrence: { ...calendarSet().revenue.occurrence, occurrenceRef: `occurrence:${hash("f")}` },
    }),
  );
});

test("transcript verification binds adapter-issued Revenue and Calendar artifacts and rejects two-account mismatch", () => {
  const revenue = buildRevenueProgram(createRevenueProgramBoundaryFixture());
  const first = calendarSet("calendar-account:first");
  const transcript = adaptRevenueTranscriptArtifact({ calendarProjection: first.revenue, revenueProgram: revenue });
  const request = buildTranscriptVerificationRequest({
    calendarProjection: first.revenue,
    revenueTranscriptArtifact: transcript,
  });
  assert.equal(request.calendarAccountRef, "calendar-account:first");
  assert.equal(request.occurrenceRef, first.revenue.occurrence.occurrenceRef);
  assert.equal(request.participantsSha256, PrincipalBinding.hash(first.revenue.occurrence.attendees));
  assert.equal(request.recipientDerivationAllowed, false);
  const second = calendarSet("calendar-account:second");
  assert.throws(() =>
    buildTranscriptVerificationRequest({ calendarProjection: second.revenue, revenueTranscriptArtifact: transcript }),
  );
});

test("quota and lifecycle helpers remain prospective and cannot report approval or reservation", () => {
  const effects = ["outreach", "transactional_post_meeting"].map((kind, index) => ({
    kind,
    providerAccountRef: "gmail-account:ceo",
    credentialOwnerRef: PrincipalBinding.identity.credentialOwnerRef,
    recipientRef: `recipient:${index}`,
    businessKey: `business:${index}`,
    effectKey: String(index + 1).repeat(64),
    contentSha256: String(index + 3).repeat(64),
  }));
  const quota = buildProspectiveGlobalGmailDraftQuota({ quotaDate: "2026-08-26", effects });
  assert.equal(quota.globalCount, 2);
  assert.equal(quota.transactionalCount, 1);
  assert.equal(quota.approved, false);
  assert.equal(quota.reserved, false);
  assert.equal(quota.reservationStoreAvailable, false);
  assert.throws(() => buildProspectiveGlobalGmailDraftQuota({ quotaDate: "2026-02-30", effects }));
  const claimFence = "claim-fence:one";
  const occurrenceRef = `occurrence:${hash("7")}`;
  const record = (recordRef) => ({ recordRef, occurrenceRef, expectedRevision: hash("8"), claimFence });
  const lifecycle = buildLifecycleSupersessionTransaction({
    reason: "cancelled",
    occurrenceRef,
    previousRevision: hash("9"),
    nextRevision: null,
    claimFence,
    revenueProposals: [record("revenue:proposal:one")],
    revenueLedger: [record("revenue:ledger:one")],
    chiefJobs: [record("chief_of_staff:job:one")],
  });
  assert.equal(lifecycle.disposition, "prospective_unreserved");
  assert.equal(lifecycle.durableCommitAvailable, false);
  assert.equal(lifecycle.approved, false);
});

test("Gmail adapter produces only an exact dormant drafts.create proposal", () => {
  const artifact = adaptChiefOfStaffMeetingArtifact(meetingArtifact());
  const runtimeScope = createRuntimeScope(ceoDeploymentProfile);
  const result = createDormantGmailDraftProposalCompiler(runtimeScope).build({
    artifact,
    recipients: ["buyer@example.edu"],
    subject: "Meeting follow-up draft",
    body: "Thank you for the conversation.",
    createdAt: "2026-08-26T17:03:00.000Z",
    expiresAt: "2026-08-26T18:03:00.000Z",
  });
  assert.equal(result.proposal.capability, "google.gmail.drafts.create");
  assert.equal(result.proposal.target.providerOwnerRef, "provider-owner:google:ceo");
  assert.equal(result.proposal.actor.externalPrincipalRef, ceoDeploymentProfile.identity.externalIdentityRef);
  assert.equal(result.proposal.actor.scopeRef, ceoDeploymentProfile.anchors.principalBindingRef);
  assert.equal(result.proposal.target.mailbox, PrincipalBinding.identity.principalEmail);
  assert.deepEqual(result.proposal.target.to, ["buyer@example.edu"]);
  assert.equal(result.executionAvailable, false);
});

async function modules(path) {
  const entries = await readdir(path, { withFileTypes: true });
  const children = await Promise.all(
    entries.map((entry) => (entry.isDirectory() ? modules(join(path, entry.name)) : [join(path, entry.name)])),
  );
  return children.flat().filter((pathName) => extname(pathName) === ".mjs");
}

function compositionPackage(pathName) {
  const parts = relative(canaryRoot, pathName).split("/");
  if (["actions", "contracts", "workflows"].includes(parts[0])) return "legacy-runtime-foundation";
  return parts[0] === "service" ? parts.slice(0, 2).join("/") : parts[0];
}

function assertPublicCrossPackageEdge(sourcePath, targetPath) {
  if (
    relative(canaryRoot, targetPath) === "deployment-profiles/contract.mjs" &&
    ["shared-contracts", "runtime-scope"].includes(compositionPackage(sourcePath))
  ) {
    return;
  }
  if (
    relative(canaryRoot, sourcePath) === "service/ceo-canary/src/evaluation-writer.mjs" &&
    relative(canaryRoot, targetPath) === "evals/result-store.mjs"
  ) {
    return;
  }
  if (compositionPackage(sourcePath) !== compositionPackage(targetPath) && basename(targetPath) !== "index.mjs") {
    assert.fail(`${relative(canaryRoot, sourcePath)} bypasses ${relative(canaryRoot, targetPath)}`);
  }
}

async function publicCompositionGraph() {
  const roots = (await modules(canaryRoot)).filter((candidate) => basename(candidate) === "index.mjs");
  const visited = new Set();
  const visit = async (pathName) => {
    if (visited.has(pathName)) return;
    visited.add(pathName);
    const source = await readFile(pathName, "utf8");
    const imports = [...source.matchAll(/\b(?:from\s+|import\s*)["'](\.[^"']+)["']/gu)];
    for (const match of imports) {
      const unresolved = resolve(dirname(pathName), match[1]);
      const target = extname(unresolved) ? unresolved : `${unresolved}.mjs`;
      if (!target.startsWith(canaryRoot)) continue;
      assertPublicCrossPackageEdge(pathName, target);
      await visit(target);
    }
  };
  for (const root of roots) await visit(root);
  return { roots, visited };
}

test("canonical composition crosses public barrels without legacy Gmail send vocabulary", async () => {
  const graph = await publicCompositionGraph();
  assert.ok(graph.roots.length > 10);
  assert.ok(graph.visited.size > graph.roots.length);
  for (const pathName of (await modules(canaryRoot)).filter((candidate) => candidate.endsWith("/index.mjs"))) {
    const source = await readFile(pathName, "utf8");
    assert.doesNotMatch(source, /\bgmail\.(?:message\.send|send)\b|draft-send/iu);
  }
  assert.equal(
    normalizeLaneSourceResult({ lane: "revenue_program", status: "none", records: [] }).successfulEmpty,
    true,
  );
});

test("module graph policy independently rejects private cross-package edges", () => {
  assert.throws(
    () =>
      assertPublicCrossPackageEdge(join(canaryRoot, "slack/index.mjs"), join(canaryRoot, "presentation/builders.mjs")),
    /bypasses presentation\/builders\.mjs/,
  );
  assert.throws(
    () =>
      assertPublicCrossPackageEdge(
        join(canaryRoot, "service/ceo-surface/src/index.mjs"),
        join(canaryRoot, "shared-contracts/validation.mjs"),
      ),
    /bypasses shared-contracts\/validation\.mjs/,
  );
  assert.throws(
    () =>
      assertPublicCrossPackageEdge(
        join(canaryRoot, "chief-of-staff/index.mjs"),
        join(canaryRoot, "contracts/canonicalize.mjs"),
      ),
    /bypasses contracts\/canonicalize\.mjs/,
  );
});

test("module graph policy allows same-package internals and the documented legacy foundation group", () => {
  assert.doesNotThrow(() =>
    assertPublicCrossPackageEdge(
      join(canaryRoot, "integration/index.mjs"),
      join(canaryRoot, "integration/publication-envelope.mjs"),
    ),
  );
  assert.doesNotThrow(() =>
    assertPublicCrossPackageEdge(
      join(canaryRoot, "actions/state-machine.mjs"),
      join(canaryRoot, "contracts/canonicalize.mjs"),
    ),
  );
  assert.doesNotThrow(() =>
    assertPublicCrossPackageEdge(join(canaryRoot, "slack/index.mjs"), join(canaryRoot, "presentation/index.mjs")),
  );
});
