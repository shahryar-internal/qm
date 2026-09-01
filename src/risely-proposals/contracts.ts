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

export type RiselyProposalSectionKey = (typeof SECTION_KEYS)[number];
export type RiselyProposalEvidenceSource = (typeof SOURCE_KINDS)[number];

export interface RiselyProposalEvidence {
  id: string;
  source: RiselyProposalEvidenceSource;
  recordRef: string;
  revision: string;
  sha256: string;
  observedAt: string;
  citation: string;
  summary: string;
}

export interface RiselyProposalSection {
  key: RiselyProposalSectionKey;
  heading: string;
  content: string;
  evidenceRefs: readonly string[];
}

export interface RiselyProposalEmailDraft {
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
          recordRef: { type: "string", minLength: 1, maxLength: 300 },
          revision: { type: "string", minLength: 1, maxLength: 160 },
          sha256: { type: "string", minLength: 64, maxLength: 64 },
          observedAt: { type: "string", format: "date-time", maxLength: 40 },
          citation: { type: "string", minLength: 1, maxLength: 1000 },
          summary: { type: "string", minLength: 1, maxLength: 2000 },
        },
        required: ["id", "source", "recordRef", "revision", "sha256", "observedAt", "citation", "summary"],
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
  exact(item, ["id", "source", "recordRef", "revision", "sha256", "observedAt", "citation", "summary"]);
  const source = text(item.source, "evidence source", 32);
  if (!(SOURCE_KINDS as readonly string[]).includes(source)) throw new TypeError("evidence source is invalid");
  return Object.freeze({
    id: text(item.id, "evidence id", 128, IDENTIFIER),
    source: source as RiselyProposalEvidenceSource,
    recordRef: text(item.recordRef, "evidence record", 300),
    revision: text(item.revision, "evidence revision", 160),
    sha256: text(item.sha256, "evidence hash", 64, HASH),
    observedAt: instant(item.observedAt, "evidence observedAt"),
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
