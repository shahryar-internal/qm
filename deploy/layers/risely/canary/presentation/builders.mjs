import { surfacePresentationCodeForState, validateArtifact, validateSurfaceArtifact } from "./schema.mjs";

const surfaceSnapshots = new WeakSet();

const stateLabels = Object.freeze({
  ready: "Ready for review",
  waiting: "Waiting for context",
  unavailable: "Source unavailable",
  failed: "Preparation failed",
  expired: "No longer current",
  superseded: "Superseded",
});

const kindLabels = Object.freeze({
  meeting_prep: "Meeting prep",
  meeting_followup: "Post-meeting",
  post_meeting: "Post-meeting",
  stale_deals: "Stale revenue digest",
  stale_revenue_digest: "Stale revenue digest",
  goals_eod: "Goals and EOD",
  outreach_linkedin_demo: "Outreach, LinkedIn, and demo",
  proposal: "Revenue proposal",
  marketing_plan: "Marketing plan",
  marketing_draft: "Marketing draft",
  demo_reminder: "Demo reminder",
});

const presentationTemplates = Object.freeze({
  private_ceo_review: Object.freeze({
    title: "Private CEO work record",
    summary: "A reviewed record is available in the future authenticated artifact view.",
  }),
  private_ceo_waiting: Object.freeze({
    title: "Private CEO work record",
    summary: "Context is pending in the future authenticated artifact view.",
  }),
  private_ceo_unavailable: Object.freeze({
    title: "Private CEO work record",
    summary: "Source context is unavailable in the future authenticated artifact view.",
  }),
  private_ceo_failed: Object.freeze({
    title: "Private CEO work record",
    summary: "Preparation is unavailable in the future authenticated artifact view.",
  }),
  private_ceo_superseded: Object.freeze({
    title: "Private CEO work record",
    summary: "A newer revision is available in the future authenticated artifact view.",
  }),
});

const legacyTemplate = Object.freeze({
  title: "Private CEO work record",
  summary: "A reviewed record is available in the future authenticated artifact view.",
});

const legacyQmRootUrl = "https://qm.riselyinternal.ai/";

function statusFor(artifact) {
  return Object.freeze({
    state: artifact.state,
    label: stateLabels[artifact.state],
    detail:
      artifact.state === "ready"
        ? "Evidence is prepared for private CEO review."
        : "This revision is actionless while its status is resolved.",
  });
}

function compactFallback(artifact) {
  return `Private CEO review · ${kindLabels[artifact.kind]} · ${stateLabels[artifact.state]} · revision ${artifact.revision} · actionless preview.`;
}

function freezeSnapshot(artifact) {
  const presentationCode = surfacePresentationCodeForState[artifact.state];
  const template = presentationTemplates[presentationCode];
  const snapshot = Object.freeze({
    version: 1,
    audience: Object.freeze({ scope: "private_ceo", delivery: "actionless_preview" }),
    artifact: Object.freeze({
      artifactRef: artifact.artifactRef,
      revision: artifact.revision,
      kind: artifact.kind,
      kindLabel: kindLabels[artifact.kind],
      presentationCode,
      title: template.title,
      summary: template.summary,
    }),
    status: statusFor(artifact),
    evidence: artifact.evidence,
    links: artifact.links,
    fallbackText: compactFallback(artifact),
  });
  surfaceSnapshots.add(snapshot);
  return snapshot;
}

export function buildPrivateCeoSurface(input) {
  return freezeSnapshot(validateSurfaceArtifact(input));
}

export function assertPrivateCeoSurface(snapshot) {
  if (!surfaceSnapshots.has(snapshot))
    throw new TypeError("surface snapshot must be created by the private CEO composition boundary");
  return snapshot;
}

function legacySurface(input) {
  const artifact = validateArtifact(input);
  const evidence = Object.freeze(
    artifact.evidence.map((_item, index) =>
      Object.freeze({
        evidenceRef: `evidence:legacy-${index + 1}`,
        trust: "untrusted_source_data",
        availability: "available",
      }),
    ),
  );
  const links = artifact.links.some((item) => item.url === legacyQmRootUrl)
    ? Object.freeze([Object.freeze({ label: "Open in QM", url: legacyQmRootUrl })])
    : Object.freeze([]);
  return Object.freeze({
    version: 1,
    audience: Object.freeze({ scope: "private_ceo", delivery: "actionless_preview" }),
    artifact: Object.freeze({
      artifactRef: "artifact:legacy-record",
      revision: "recorded",
      kind: artifact.kind,
      kindLabel: kindLabels[artifact.kind],
      title: legacyTemplate.title,
      summary: legacyTemplate.summary,
    }),
    status: statusFor(artifact),
    evidence,
    links,
    fallbackText: compactFallback({ kind: artifact.kind, state: artifact.state, revision: "recorded" }),
  });
}

export function buildSlackCardFromSurface(snapshot) {
  const value = assertPrivateCeoSurface(snapshot);
  return Object.freeze({
    version: 1,
    surface: "slack",
    audience: value.audience,
    artifact: value.artifact,
    status: value.status,
    evidence: value.evidence,
    fallbackText: value.fallbackText,
  });
}

export function buildSlackCard(input) {
  return buildSlackCardFromSurface(buildPrivateCeoSurface(input));
}

export function buildLegacySlackCard(input) {
  const value = legacySurface(input);
  return Object.freeze({
    version: 1,
    surface: "slack",
    audience: value.audience,
    artifact: value.artifact,
    status: value.status,
    evidence: value.evidence,
    links: value.links,
    fallbackText: value.fallbackText,
  });
}

export function buildQmRendererFromSurface(snapshot) {
  const value = assertPrivateCeoSurface(snapshot);
  return Object.freeze({
    version: 1,
    type: "qm_work_card",
    audience: value.audience,
    artifact: value.artifact,
    status: value.status,
    sections: Object.freeze([
      Object.freeze({
        key: "executive_brief",
        label: "Executive brief",
        items: Object.freeze([
          Object.freeze({ label: "Summary", value: value.artifact.summary, trust: "generated_evidence_cited_update" }),
        ]),
      }),
      Object.freeze({
        key: "status_and_trust",
        label: "Status and trust",
        items: Object.freeze([
          Object.freeze({ label: "Status", value: value.status.label, trust: "verified_source" }),
          Object.freeze({ label: "Evidence count", value: String(value.evidence.length), trust: "verified_source" }),
          Object.freeze({ label: "Trust boundary", value: "No external action can run.", trust: "verified_source" }),
        ]),
      }),
      Object.freeze({ key: "evidence", label: "Evidence", items: value.evidence }),
      Object.freeze({
        key: "cross_surface_record",
        label: "Cross-surface record",
        items: Object.freeze([
          Object.freeze({ label: "Artifact", value: value.artifact.artifactRef, trust: "verified_source" }),
          Object.freeze({ label: "Revision", value: value.artifact.revision, trust: "verified_source" }),
        ]),
      }),
    ]),
    links: value.links,
    actionless: true,
  });
}

export function buildQmRenderer(input) {
  return buildQmRendererFromSurface(buildPrivateCeoSurface(input));
}

export function buildPresentation(input) {
  const snapshot = buildPrivateCeoSurface(input);
  return Object.freeze({
    artifact: snapshot.artifact,
    slack: buildSlackCardFromSurface(snapshot),
    qm: buildQmRendererFromSurface(snapshot),
    actionless: true,
  });
}
