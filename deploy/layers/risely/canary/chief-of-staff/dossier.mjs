import { sha256Canonical } from "../contracts/index.mjs";
import {
  assertHash,
  assertRecord,
  assertRef,
  assertText,
  assertUnique,
  compareCodepoints,
  fail,
  parseInstant,
  snapshotPlainJson,
} from "./validation.mjs";

const sourceNames = new Set(["calendar", "gmail", "clarify", "command_center_brain", "notion"]);
const sectionNames = Object.freeze(["accountOverview", "contactBackground", "recommendedPositioning"]);

const normalizeEvidence = (input, generatedAt) => {
  assertRecord(input, ["evidenceRef", "source", "evidenceHash", "capturedAt"], "invalid_dossier_evidence");
  if (!sourceNames.has(input.source)) fail("invalid_dossier_evidence");
  const capturedAt = parseInstant(input.capturedAt);
  if (capturedAt > generatedAt) fail("future_dossier_evidence");
  return Object.freeze({
    evidenceRef: assertRef(input.evidenceRef),
    source: input.source,
    evidenceHash: assertHash(input.evidenceHash),
    capturedAt: capturedAt.toISOString(),
    trust: "untrusted_source_data",
  });
};

const normalizeSource = (input) => {
  assertRecord(input, ["source", "availability"], "invalid_dossier_source");
  if (!sourceNames.has(input.source) || !["available", "unavailable", "not_connected"].includes(input.availability)) {
    fail("invalid_dossier_source");
  }
  return Object.freeze({ source: input.source, availability: input.availability });
};

const normalizeClaim = (input, evidenceByRef) => {
  assertRecord(input, ["claimId", "text", "citations"], "invalid_dossier_claim");
  if (!Array.isArray(input.citations) || input.citations.length < 1 || input.citations.length > 8) {
    fail("uncited_dossier_claim");
  }
  const citations = input.citations.map(assertRef).sort(compareCodepoints);
  assertUnique(citations, (citation) => citation, "duplicate_dossier_citation");
  if (citations.some((citation) => !evidenceByRef.has(citation))) fail("unknown_dossier_citation");
  return Object.freeze({
    claimId: assertRef(input.claimId),
    text: assertText(input.text, 2_048),
    trust: "generated_claim",
    citations: Object.freeze(citations),
  });
};

export const normalizeMeetingDossier = (input) => {
  const value = snapshotPlainJson(input);
  assertRecord(
    value,
    ["meetingKey", "generatedAt", "calendarEvidenceHash", "sources", "evidence", "sections"],
    "invalid_dossier",
  );
  const generatedAt = parseInstant(value.generatedAt);
  if (
    !Array.isArray(value.sources) ||
    value.sources.length > sourceNames.size ||
    !Array.isArray(value.evidence) ||
    value.evidence.length > 256
  ) {
    fail("invalid_dossier");
  }
  const sources = value.sources
    .map(normalizeSource)
    .sort((left, right) => compareCodepoints(left.source, right.source));
  assertUnique(sources, (source) => source.source, "duplicate_dossier_source");
  const sourceByName = new Map(sources.map((source) => [source.source, source]));
  if (
    sources.length !== sourceNames.size ||
    [...sourceNames].some((source) => !sourceByName.has(source)) ||
    sourceByName.get("calendar").availability !== "available"
  ) {
    fail("incomplete_dossier_source_inventory");
  }
  const evidence = value.evidence
    .map((entry) => normalizeEvidence(entry, generatedAt))
    .sort((left, right) => compareCodepoints(left.evidenceRef, right.evidenceRef));
  assertUnique(evidence, (entry) => entry.evidenceRef, "duplicate_dossier_evidence");
  if (evidence.some((entry) => sourceByName.get(entry.source)?.availability !== "available")) {
    fail("dossier_evidence_source_unavailable");
  }
  if (
    !evidence.some(
      (entry) => entry.source === "calendar" && entry.evidenceHash === assertHash(value.calendarEvidenceHash),
    )
  ) {
    fail("calendar_evidence_mismatch");
  }
  const evidenceByRef = new Map(evidence.map((entry) => [entry.evidenceRef, entry]));
  assertRecord(value.sections, sectionNames, "invalid_dossier_sections");
  const sections = Object.fromEntries(
    sectionNames.map((section) => {
      const claims = value.sections[section];
      if (!Array.isArray(claims) || claims.length > 32) fail("invalid_dossier_sections");
      const normalized = claims.map((claim) => normalizeClaim(claim, evidenceByRef));
      assertUnique(normalized, (claim) => claim.claimId, "duplicate_dossier_claim");
      return [section, Object.freeze(normalized)];
    }),
  );
  const normalized = Object.freeze({
    schemaVersion: 1,
    meetingKey: assertHash(value.meetingKey),
    generatedAt: generatedAt.toISOString(),
    calendarEvidenceHash: value.calendarEvidenceHash,
    sources: Object.freeze(sources),
    evidence: Object.freeze(evidence),
    sections: Object.freeze(sections),
    missingContext: Object.freeze(
      sources.filter((source) => source.availability !== "available").map((source) => source.source),
    ),
    providerContentTrust: "untrusted_data_only",
    presentationSinkAllowed: false,
  });
  return Object.freeze({
    ...normalized,
    artifactHash: sha256Canonical(normalized),
  });
};
