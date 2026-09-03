import { safeGroundedCitationUrl } from "../model/grounded-web-search.ts";
import type { McpEvidenceContract } from "../mcp/mcp-server-store.ts";

const MAX_LINKS = 64;
const MAX_RESULT_LENGTH = 512 * 1024;
const CREDENTIAL_QUERY_KEY = /(?:auth|authorization|bearer|credential|key|oauth|password|secret|signature|sig|token)/iu;
const CREDENTIAL_FRAGMENT =
  /(?:access[_ -]?token|api[_ -]?key|auth(?:orization)?|bearer|credential|oauth|password|secret|signature)/iu;
type EvidencePath = readonly string[];
const CREDENTIAL_READ_OPERATIONS = new Map<string, string>([
  ["calendar-calendars", "Calendar"],
  ["calendar-event", "Calendar"],
  ["calendar-events", "Calendar"],
  ["calendar-timezone", "Calendar"],
  ["docs-read", "Drive"],
  ["drive-download", "Drive"],
  ["drive-export", "Drive"],
  ["drive-metadata", "Drive"],
  ["drive-search", "Drive"],
  ["gmail-draft-read", "Gmail"],
  ["gmail-read", "Gmail"],
  ["gmail-reply-preview", "Gmail"],
  ["gmail-search", "Gmail"],
  ["gmail-thread", "Gmail"],
  ["sheets-metadata", "Drive"],
  ["sheets-read", "Drive"],
  ["slides-read", "Drive"],
  ["tasks-list", "Google Tasks"],
  ["tasks-lists", "Google Tasks"],
]);
const GOOGLE_CREDENTIAL_SERVICES = new Set([
  "docs.googleapis.com",
  "gmail.googleapis.com",
  "google",
  "google-workspace",
  "sheets.googleapis.com",
  "slides.googleapis.com",
  "www.googleapis.com",
]);
const EVIDENCE_SOURCE_TYPES = new Set([
  "Analytics",
  "Brain",
  "Calendar",
  "Clarify",
  "Command Center",
  "CRM",
  "Drive",
  "Gmail",
  "Google Tasks",
  "Notion",
  "Public web",
]);
const ACKNOWLEDGEMENT = /^(?:ok(?:ay)?|thanks?(?: you)?|got it|sounds good|great|perfect|understood)[!.\s]*$/iu;

export interface PersistedEvidenceSource {
  version: "qm.typed-tool-evidence.v1";
  sourceType: string;
  links: string[];
}

export interface DeliveryEvidenceSource {
  sourceType: string;
  links: string[];
  observedAt: string;
}

function safeCurrentTurnEvidenceLink(value: string): string | undefined {
  const safe = safeGroundedCitationUrl(value);
  if (!safe) return undefined;
  const parsed = new URL(safe);
  if ([...parsed.searchParams.keys()].some((key) => CREDENTIAL_QUERY_KEY.test(key.replace(/[^a-z0-9]/giu, "")))) {
    return undefined;
  }
  let fragment: string;
  try {
    fragment = decodeURIComponent(parsed.hash);
  } catch {
    return undefined;
  }
  if (CREDENTIAL_FRAGMENT.test(fragment)) return undefined;
  return parsed.href;
}

function record(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null ? (value as Record<string, unknown>) : undefined;
}

function sourceType(name: string): string | undefined {
  return EVIDENCE_SOURCE_TYPES.has(name) ? name : undefined;
}

function addLink(found: Set<string>, value: unknown): void {
  if (typeof value !== "string" || found.size >= MAX_LINKS) return;
  const safe = safeCurrentTurnEvidenceLink(value);
  if (safe) found.add(safe);
}

function parseJson(text: string): unknown {
  if (text.length > MAX_RESULT_LENGTH) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function collectPathLinks(value: unknown, paths: readonly EvidencePath[]): string[] {
  const found = new Set<string>();
  const inspect = (item: unknown, path: EvidencePath, offset: number): void => {
    if (found.size >= MAX_LINKS) return;
    if (offset === path.length) {
      addLink(found, item);
      return;
    }
    const segment = path[offset];
    if (segment === "*") {
      if (!Array.isArray(item)) return;
      for (const child of item.slice(0, MAX_LINKS)) inspect(child, path, offset + 1);
    } else {
      const itemRecord = record(item);
      if (itemRecord) inspect(itemRecord[segment!], path, offset + 1);
    }
  };
  for (const path of paths) inspect(value, path, 0);
  return [...found].sort();
}

export function webSearchEvidence(citations: readonly { url: string }[]): PersistedEvidenceSource {
  const links = new Set<string>();
  for (const citation of citations.slice(0, MAX_LINKS)) addLink(links, citation.url);
  return { version: "qm.typed-tool-evidence.v1", sourceType: "Public web", links: [...links].sort() };
}

export function mcpReadEvidence(input: {
  readOnly: boolean;
  output: string;
  evidence?: McpEvidenceContract;
}): PersistedEvidenceSource | undefined {
  if (!input.readOnly || !input.evidence) return undefined;
  const parsed = parseJson(input.output);
  return {
    version: "qm.typed-tool-evidence.v1",
    sourceType: input.evidence.sourceType,
    links: parsed === undefined ? [] : collectPathLinks(parsed, input.evidence.linkPaths),
  };
}

export function credentialReadEvidence(service: string, args: readonly string[]): PersistedEvidenceSource | undefined {
  if (!GOOGLE_CREDENTIAL_SERVICES.has(service)) return undefined;
  const type = CREDENTIAL_READ_OPERATIONS.get(args[0] ?? "");
  if (!type) return undefined;
  return { version: "qm.typed-tool-evidence.v1", sourceType: type, links: [] };
}

export function persistedEvidenceFromToolResult(payload: unknown): PersistedEvidenceSource | undefined {
  const payloadRecord = record(payload);
  if (
    !payloadRecord ||
    payloadRecord.isError === true ||
    payloadRecord.quarantined === true ||
    payloadRecord.securityBlocked === true
  )
    return undefined;
  const evidence = record(payloadRecord.evidence);
  if (
    !evidence ||
    evidence.version !== "qm.typed-tool-evidence.v1" ||
    typeof evidence.sourceType !== "string" ||
    !Array.isArray(evidence.links)
  )
    return undefined;
  const type = sourceType(evidence.sourceType);
  if (!type || type !== evidence.sourceType || evidence.links.length > MAX_LINKS) return undefined;
  const links = evidence.links.flatMap((value) => {
    if (typeof value !== "string") return [];
    const safe = safeCurrentTurnEvidenceLink(value);
    return safe ? [safe] : [];
  });
  if (links.length !== evidence.links.length) return undefined;
  return {
    version: "qm.typed-tool-evidence.v1",
    sourceType: type,
    links: [...new Set(links)].sort(),
  };
}

export function canonicalEvidenceLink(value: string): string | undefined {
  return safeCurrentTurnEvidenceLink(value);
}

export function slackTurnRequiresEvidenceBuffer(requestText: string): boolean {
  const bounded = requestText.trim().slice(0, 8_192);
  return !bounded.startsWith("!") && !ACKNOWLEDGEMENT.test(bounded);
}

export function slackEvidenceRequestText(inputText: string, displayText?: string): string {
  return inputText.trimStart().startsWith("!") && displayText !== undefined && displayText !== inputText
    ? displayText
    : inputText;
}
