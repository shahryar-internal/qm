import { createHash } from "node:crypto";
import { canonicalJson } from "../cron/schedule-authority.ts";

const HASH = /^[a-f0-9]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SECTION_KEYS = [
  "executive_summary",
  "customer_need",
  "proposed_solution",
  "outcomes",
  "scope",
  "delivery",
  "commercial",
  "next_steps",
] as const;
const SOURCE_KINDS = ["analytics", "brain", "google", "manual", "notion"] as const;
const EVIDENCE_STATUSES = ["available", "cited", "partial_or_unavailable", "unavailable"] as const;
const EVIDENCE_TRUST = [
  "verified_source",
  "untrusted_source_data",
  "generated_evidence_cited_update",
  "unavailable_source",
] as const;
const SOURCE_TRUST = ["verified_source", "untrusted_source_data", "unavailable_source", "unresolved"] as const;
const AVAILABILITY = ["available", "unavailable"] as const;
const SOURCE_AVAILABILITY = ["available", "unavailable", "unresolved"] as const;

type RiselyProposalSectionKey = (typeof SECTION_KEYS)[number];
type RiselyProposalEvidenceSource = (typeof SOURCE_KINDS)[number];
type RiselyProposalEvidenceStatus = (typeof EVIDENCE_STATUSES)[number];
type RiselyProposalEvidenceTrust = (typeof EVIDENCE_TRUST)[number];
type RiselyProposalSourceTrust = (typeof SOURCE_TRUST)[number];

interface RiselyProposalEvidence {
  id: string;
  source: RiselyProposalEvidenceSource;
  sourceRecordRef: string;
  sourceRecord: string;
  contentSha256: string;
  relatedContentSha256: readonly string[];
  revision: string;
  observedAt: string;
  fetchedAt: string;
  status: RiselyProposalEvidenceStatus;
  trust: RiselyProposalEvidenceTrust;
  availability: (typeof AVAILABILITY)[number];
  sourceTrust: RiselyProposalSourceTrust;
  sourceAvailability: (typeof SOURCE_AVAILABILITY)[number];
  citation: string;
  summary: string;
}

interface RiselyProposalSection {
  key: RiselyProposalSectionKey;
  heading: string;
  content: string;
  evidenceRefs: readonly string[];
}

interface RiselyProposalEmailDraft {
  to: string;
  subject: string;
  body: string;
}

export interface RiselyProposalInput {
  proposalId: string;
  title: string;
  client: string;
  revision: number;
  validUntil: string;
  evidence: readonly Readonly<RiselyProposalEvidence>[];
  sections: readonly Readonly<RiselyProposalSection>[];
  emailDraft?: Readonly<RiselyProposalEmailDraft>;
}

export const riselyProposalInputSchema = Object.freeze({
  type: "object",
  additionalProperties: false,
  properties: {
    proposalId: { type: "string", minLength: 1, maxLength: 128 },
    title: { type: "string", minLength: 1, maxLength: 200 },
    client: { type: "string", minLength: 1, maxLength: 160 },
    revision: { type: "integer", minimum: 1, maximum: 10000 },
    validUntil: { type: "string", format: "date-time", maxLength: 40 },
    evidence: {
      type: "array",
      minItems: 1,
      maxItems: 64,
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          id: { type: "string", minLength: 1, maxLength: 128 },
          source: { type: "string", enum: [...SOURCE_KINDS] },
          sourceRecordRef: { type: "string", minLength: 78, maxLength: 78 },
          sourceRecord: { type: "string", minLength: 2, maxLength: 20000 },
          contentSha256: { type: "string", minLength: 64, maxLength: 64 },
          relatedContentSha256: {
            type: "array",
            minItems: 0,
            maxItems: 16,
            items: { type: "string", minLength: 64, maxLength: 64 },
          },
          revision: { type: "string", minLength: 1, maxLength: 160 },
          observedAt: { type: "string", format: "date-time", maxLength: 40 },
          fetchedAt: { type: "string", format: "date-time", maxLength: 40 },
          status: { type: "string", enum: [...EVIDENCE_STATUSES] },
          trust: { type: "string", enum: [...EVIDENCE_TRUST] },
          availability: { type: "string", enum: [...AVAILABILITY] },
          sourceTrust: { type: "string", enum: [...SOURCE_TRUST] },
          sourceAvailability: { type: "string", enum: [...SOURCE_AVAILABILITY] },
          citation: { type: "string", minLength: 1, maxLength: 1000 },
          summary: { type: "string", minLength: 1, maxLength: 2000 },
        },
        required: [
          "id",
          "source",
          "sourceRecordRef",
          "sourceRecord",
          "contentSha256",
          "relatedContentSha256",
          "revision",
          "observedAt",
          "fetchedAt",
          "status",
          "trust",
          "availability",
          "sourceTrust",
          "sourceAvailability",
          "citation",
          "summary",
        ],
      },
    },
    sections: {
      type: "array",
      minItems: 8,
      maxItems: 8,
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          key: { type: "string", enum: [...SECTION_KEYS] },
          heading: { type: "string", minLength: 1, maxLength: 120 },
          content: { type: "string", minLength: 1, maxLength: 12000 },
          evidenceRefs: {
            type: "array",
            minItems: 1,
            maxItems: 32,
            items: { type: "string", minLength: 1, maxLength: 128 },
          },
        },
        required: ["key", "heading", "content", "evidenceRefs"],
      },
    },
    emailDraft: {
      type: "object",
      additionalProperties: false,
      properties: {
        to: { type: "string", format: "email", maxLength: 320 },
        subject: { type: "string", minLength: 1, maxLength: 200 },
        body: { type: "string", minLength: 1, maxLength: 20000 },
      },
      required: ["to", "subject", "body"],
    },
  },
  required: ["proposalId", "title", "client", "revision", "validUntil", "evidence", "sections"],
});

function object(value: unknown, name: string): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${name} is invalid`);
  }
  return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): void {
  const allowed = new Set([...required, ...optional]);
  if (!required.every((key) => Object.hasOwn(value, key)) || Object.keys(value).some((key) => !allowed.has(key))) {
    throw new TypeError("proposal input has unexpected fields");
  }
}

function text(value: unknown, name: string, maximum: number, pattern?: RegExp): string {
  if (typeof value !== "string" || value.trim() !== value || value.length < 1 || value.length > maximum) {
    throw new TypeError(`${name} is invalid`);
  }
  if (pattern && !pattern.test(value)) throw new TypeError(`${name} is invalid`);
  return value;
}

function instant(value: unknown, name: string): string {
  const resolved = text(value, name, 40);
  const time = Date.parse(resolved);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== resolved) throw new TypeError(`${name} is invalid`);
  return resolved;
}

function evidence(value: unknown): RiselyProposalEvidence {
  const item = object(value, "evidence");
  exact(item, [
    "id",
    "source",
    "sourceRecordRef",
    "sourceRecord",
    "contentSha256",
    "relatedContentSha256",
    "revision",
    "observedAt",
    "fetchedAt",
    "status",
    "trust",
    "availability",
    "sourceTrust",
    "sourceAvailability",
    "citation",
    "summary",
  ]);
  const source = text(item.source, "evidence source", 32);
  if (!(SOURCE_KINDS as readonly string[]).includes(source)) throw new TypeError("evidence source is invalid");
  const sourceRecord = text(item.sourceRecord, "evidence source record", 20000);
  let sourceValue: unknown;
  try {
    sourceValue = JSON.parse(sourceRecord);
  } catch {
    throw new TypeError("evidence source record is invalid");
  }
  if (canonicalJson(sourceValue) !== sourceRecord) throw new TypeError("evidence source record is invalid");
  const contentSha256 = createHash("sha256").update(sourceRecord).digest("hex");
  const sourceRecordRef = text(item.sourceRecordRef, "evidence source record reference", 78);
  if (item.contentSha256 !== contentSha256 || sourceRecordRef !== `source-record:${contentSha256}`) {
    throw new TypeError("evidence source record hash is invalid");
  }
  if (!Array.isArray(item.relatedContentSha256) || item.relatedContentSha256.length > 16) {
    throw new TypeError("evidence related content is invalid");
  }
  const relatedContentSha256 = item.relatedContentSha256.map((entry) =>
    text(entry, "evidence related content hash", 64, HASH),
  );
  if (
    new Set(relatedContentSha256).size !== relatedContentSha256.length ||
    relatedContentSha256.some((entry, index) => index > 0 && relatedContentSha256[index - 1]! >= entry)
  ) {
    throw new TypeError("evidence related content is invalid");
  }
  const observedAt = instant(item.observedAt, "evidence observedAt");
  const fetchedAt = instant(item.fetchedAt, "evidence fetchedAt");
  if (Date.parse(observedAt) > Date.parse(fetchedAt)) throw new TypeError("evidence observation postdates fetch");
  const status = text(item.status, "evidence status", 32);
  const trust = text(item.trust, "evidence trust", 48);
  const availability = text(item.availability, "evidence availability", 16);
  const sourceTrust = text(item.sourceTrust, "evidence source trust", 32);
  const sourceAvailability = text(item.sourceAvailability, "evidence source availability", 16);
  if (
    !(EVIDENCE_STATUSES as readonly string[]).includes(status) ||
    !(EVIDENCE_TRUST as readonly string[]).includes(trust) ||
    !(AVAILABILITY as readonly string[]).includes(availability) ||
    !(SOURCE_TRUST as readonly string[]).includes(sourceTrust) ||
    !(SOURCE_AVAILABILITY as readonly string[]).includes(sourceAvailability) ||
    (availability === "unavailable") !== (trust === "unavailable_source") ||
    (sourceAvailability === "unavailable") !== (sourceTrust === "unavailable_source") ||
    (sourceAvailability === "unresolved") !== (sourceTrust === "unresolved") ||
    (status === "unavailable") !== (availability === "unavailable") ||
    (source === "manual" && (trust === "verified_source" || sourceTrust === "verified_source"))
  ) {
    throw new TypeError("evidence provenance is invalid");
  }
  return Object.freeze({
    id: text(item.id, "evidence id", 128, IDENTIFIER),
    source: source as RiselyProposalEvidenceSource,
    sourceRecordRef,
    sourceRecord,
    contentSha256,
    relatedContentSha256: Object.freeze(relatedContentSha256),
    revision: text(item.revision, "evidence revision", 160),
    observedAt,
    fetchedAt,
    status: status as RiselyProposalEvidenceStatus,
    trust: trust as RiselyProposalEvidenceTrust,
    availability: availability as (typeof AVAILABILITY)[number],
    sourceTrust: sourceTrust as RiselyProposalSourceTrust,
    sourceAvailability: sourceAvailability as (typeof SOURCE_AVAILABILITY)[number],
    citation: text(item.citation, "evidence citation", 1000),
    summary: text(item.summary, "evidence summary", 2000),
  });
}

function section(value: unknown, evidenceIds: ReadonlySet<string>): RiselyProposalSection {
  const item = object(value, "section");
  exact(item, ["key", "heading", "content", "evidenceRefs"]);
  const key = text(item.key, "section key", 64);
  if (!(SECTION_KEYS as readonly string[]).includes(key)) throw new TypeError("section key is invalid");
  if (!Array.isArray(item.evidenceRefs) || item.evidenceRefs.length < 1 || item.evidenceRefs.length > 32) {
    throw new TypeError("section evidence references are invalid");
  }
  const evidenceRefs = item.evidenceRefs.map((entry) => text(entry, "section evidence reference", 128, IDENTIFIER));
  if (new Set(evidenceRefs).size !== evidenceRefs.length || evidenceRefs.some((entry) => !evidenceIds.has(entry))) {
    throw new TypeError("section evidence references are invalid");
  }
  return Object.freeze({
    key: key as RiselyProposalSectionKey,
    heading: text(item.heading, "section heading", 120),
    content: text(item.content, "section content", 12000),
    evidenceRefs: Object.freeze(evidenceRefs),
  });
}

function emailDraft(value: unknown): RiselyProposalEmailDraft {
  const item = object(value, "email draft");
  exact(item, ["to", "subject", "body"]);
  return Object.freeze({
    to: text(item.to, "email recipient", 320, /^[^\s@]+@[^\s@]+\.[^\s@]+$/),
    subject: text(item.subject, "email subject", 200),
    body: text(item.body, "email body", 20000),
  });
}

export function parseRiselyProposalInput(value: unknown): RiselyProposalInput {
  const root = object(value, "proposal input");
  exact(root, ["proposalId", "title", "client", "revision", "validUntil", "evidence", "sections"], ["emailDraft"]);
  if (!Number.isSafeInteger(root.revision) || (root.revision as number) < 1 || (root.revision as number) > 10000) {
    throw new TypeError("proposal revision is invalid");
  }
  if (!Array.isArray(root.evidence) || root.evidence.length < 1 || root.evidence.length > 64) {
    throw new TypeError("proposal evidence is invalid");
  }
  const evidenceItems = root.evidence.map(evidence);
  const evidenceIds = new Set(evidenceItems.map((item) => item.id));
  if (evidenceIds.size !== evidenceItems.length) throw new TypeError("proposal evidence is invalid");
  if (!Array.isArray(root.sections) || root.sections.length !== SECTION_KEYS.length) {
    throw new TypeError("proposal sections are invalid");
  }
  const sections = root.sections.map((item) => section(item, evidenceIds));
  const sectionKeys = new Set(sections.map((item) => item.key));
  if (SECTION_KEYS.some((key) => !sectionKeys.has(key))) throw new TypeError("proposal sections are invalid");
  return Object.freeze({
    proposalId: text(root.proposalId, "proposal id", 128, IDENTIFIER),
    title: text(root.title, "proposal title", 200),
    client: text(root.client, "proposal client", 160),
    revision: root.revision as number,
    validUntil: instant(root.validUntil, "proposal validUntil"),
    evidence: Object.freeze(evidenceItems),
    sections: Object.freeze(sections),
    ...(root.emailDraft === undefined ? {} : { emailDraft: emailDraft(root.emailDraft) }),
  });
}

export function riselyProposalSchemaSha256(): string {
  return createHash("sha256").update(canonicalJson(riselyProposalInputSchema)).digest("hex");
}
