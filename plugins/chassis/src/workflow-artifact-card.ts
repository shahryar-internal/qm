import { WORKFLOW_ARTIFACT_MIME } from "./workflow-artifact.ts";

export { WORKFLOW_ARTIFACT_MIME };
export const WORKFLOW_ARTIFACT_CARD_RENDERER = "qm.card.v1";

const MAX_DEPTH = 8;
const MAX_NODES = 512;
const MAX_STRING = 8_192;
const MAX_TOTAL_STRING = 65_536;
const MAX_OBJECT_KEYS = 64;
const MAX_ARRAY_ITEMS = 64;
const MAX_SECTIONS = 12;
const MAX_SECTION_ITEMS = 32;
const MAX_LINKS = 16;
const MAX_HREF = 2_048;
const MAX_HEADING = 150;
export const WORKFLOW_ARTIFACT_SLACK_TEXT_MAX = 3_000;
const MAX_ARTIFACT_BYTES = 128 * 1024;
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const RENDERER_NAME = /^[a-z0-9](?:[a-z0-9._/-]{0,62}[a-z0-9])?$/;
const SECTION_KEY = /^[a-zA-Z0-9](?:[a-zA-Z0-9._-]{0,62}[a-zA-Z0-9])?$/;
const TONES = new Set(["neutral", "info", "success", "warning", "danger"]);
const CREDENTIAL_QUERY_TERMS = new Set([
  "auth",
  "authentication",
  "authentications",
  "authorization",
  "authorizations",
  "credential",
  "credentialid",
  "credentialids",
  "credentials",
  "key",
  "keys",
  "oauth",
  "secret",
  "secrets",
  "sig",
  "sigs",
  "signature",
  "signatures",
  "token",
  "tokens",
]);
const CREDENTIAL_QUERY_COMPACT =
  /^(?:(?:id|access|refresh|session|auth|oauth|bearer|security|xamzsecurity)tokens?|(?:api|access|secret|private|signing|auth|oauth|client)keys?|awsaccesskeyids?|keypairids?|clientsecrets?|(?:xamz|xgoog)?signatures?(?:versions?)?|sigs?|(?:xamz|client)?credentials?(?:ids?)?|o?auth(?:entication|orization)?s?(?:tokens?|keys?)?)$/;

export interface WorkflowArtifactEnvelope {
  version: 1;
  renderer: string;
  fallbackText: string;
  payload: unknown;
}

export interface WorkflowArtifactCard {
  heading: string;
  summary?: string;
  status?: {
    label: string;
    tone: "neutral" | "info" | "success" | "warning" | "danger";
  };
  sections?: readonly {
    key: string;
    label: string;
    items: readonly { label?: string; value: string; href?: string }[];
  }[];
  links?: readonly { label: string; href: string }[];
}

export type WorkflowArtifactSection = NonNullable<WorkflowArtifactCard["sections"]>[number];
export type WorkflowArtifactLinks = NonNullable<WorkflowArtifactCard["links"]>;

interface Budget {
  nodes: number;
  stringUnits: number;
}

function ownRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string" || FORBIDDEN_KEYS.has(key)) return false;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  return required.every((key) => Object.hasOwn(value, key)) && keys.every((key) => allowed.has(key));
}

function boundedString(value: unknown, max: number, allowEmpty = true): value is string {
  return typeof value === "string" && value.length <= max && (allowEmpty || value.trim().length > 0);
}

function validateJsonValue(value: unknown, depth: number, budget: Budget): void {
  budget.nodes++;
  if (budget.nodes > MAX_NODES || depth > MAX_DEPTH) throw new Error("invalid workflow artifact payload");
  if (typeof value === "string") {
    if (value.length > MAX_STRING) throw new Error("invalid workflow artifact payload");
    budget.stringUnits += value.length;
    if (budget.stringUnits > MAX_TOTAL_STRING) throw new Error("invalid workflow artifact payload");
    return;
  }
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("invalid workflow artifact payload");
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_ITEMS) throw new Error("invalid workflow artifact payload");
    for (const item of value) validateJsonValue(item, depth + 1, budget);
    return;
  }
  if (!ownRecord(value)) throw new Error("invalid workflow artifact payload");
  const keys = Object.keys(value);
  if (keys.length > MAX_OBJECT_KEYS) throw new Error("invalid workflow artifact payload");
  for (const key of keys) {
    if (key.length > 128) throw new Error("invalid workflow artifact payload");
    validateJsonValue(value[key], depth + 1, budget);
  }
}

export function validateWorkflowArtifactEnvelope(value: unknown): WorkflowArtifactEnvelope {
  if (!ownRecord(value) || !exactKeys(value, ["version", "renderer", "fallbackText", "payload"])) {
    throw new Error("invalid workflow artifact envelope");
  }
  if (value.version !== 1 || !boundedString(value.renderer, 64, false) || !RENDERER_NAME.test(value.renderer)) {
    throw new Error("invalid workflow artifact envelope");
  }
  if (!boundedString(value.fallbackText, 2_000, false)) throw new Error("invalid workflow artifact envelope");
  validateJsonValue(value.payload, 0, { nodes: 0, stringUnits: 0 });
  return {
    version: 1,
    renderer: value.renderer,
    fallbackText: value.fallbackText,
    payload: value.payload,
  };
}

function credentialQueryKey(value: string): boolean {
  const words =
    value
      .normalize("NFKC")
      .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
      .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
      .toLowerCase()
      .match(/[a-z0-9]+/g) ?? [];
  if (words.some((word) => CREDENTIAL_QUERY_TERMS.has(word))) return true;
  return CREDENTIAL_QUERY_COMPACT.test(words.join(""));
}

export function safeWorkflowArtifactHref(value: string, baseUrl: string): string | null {
  if (!boundedString(value, MAX_HREF, false)) return null;
  try {
    const base = new URL(baseUrl);
    const url = new URL(value, base);
    if (url.username || url.password) return null;
    for (const key of url.searchParams.keys()) {
      if (credentialQueryKey(key)) return null;
    }
    if (url.origin !== base.origin && url.protocol !== "https:") return null;
    if (url.origin === base.origin && url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url.href;
  } catch {
    return null;
  }
}

export function workflowArtifactSlackMrkdwn(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function workflowArtifactSlackHref(href: string, baseUrl: string): string | undefined {
  if (new URL(href).origin === new URL(baseUrl).origin) return undefined;
  return href.replace(/\|/g, "%7C").replace(/</g, "%3C").replace(/>/g, "%3E");
}

function workflowArtifactSlackLinkedValue(value: string, href: string | undefined, baseUrl: string): string {
  const label = workflowArtifactSlackMrkdwn(value);
  const safe = href ? workflowArtifactSlackHref(href, baseUrl) : undefined;
  return safe ? `<${safe}|${label}>` : label;
}

export function workflowArtifactSlackSectionText(section: WorkflowArtifactSection, baseUrl: string): string {
  const rows = section.items.map((item) => {
    const value = workflowArtifactSlackLinkedValue(item.value, item.href, baseUrl);
    return item.label ? `• *${workflowArtifactSlackMrkdwn(item.label)}:* ${value}` : `• ${value}`;
  });
  return `*${workflowArtifactSlackMrkdwn(section.label)}*${rows.length ? `\n${rows.join("\n")}` : ""}`;
}

export function workflowArtifactSlackLinksText(links: WorkflowArtifactLinks, baseUrl: string): string {
  return links
    .map((link) => {
      const href = workflowArtifactSlackHref(link.href, baseUrl);
      return href ? `<${href}|${workflowArtifactSlackMrkdwn(link.label)}>` : workflowArtifactSlackMrkdwn(link.label);
    })
    .join(" · ");
}

export function workflowArtifactSlackTextFits(value: string): boolean {
  return value.length <= WORKFLOW_ARTIFACT_SLACK_TEXT_MAX;
}

function validateLink(value: unknown, baseUrl: string): { label: string; href: string } {
  if (!ownRecord(value) || !exactKeys(value, ["label", "href"])) throw new Error("invalid workflow artifact card");
  if (!boundedString(value.label, 120, false) || typeof value.href !== "string") {
    throw new Error("invalid workflow artifact card");
  }
  const href = safeWorkflowArtifactHref(value.href, baseUrl);
  if (!href) throw new Error("invalid workflow artifact card");
  return { label: value.label, href };
}

export function validateWorkflowArtifactCard(value: unknown, baseUrl: string): WorkflowArtifactCard {
  if (!ownRecord(value) || !exactKeys(value, ["heading"], ["summary", "status", "sections", "links"])) {
    throw new Error("invalid workflow artifact card");
  }
  if (!boundedString(value.heading, MAX_HEADING, false)) throw new Error("invalid workflow artifact card");
  const card: WorkflowArtifactCard = { heading: value.heading };
  if (Object.hasOwn(value, "summary")) {
    if (!boundedString(value.summary, 2_000, false)) throw new Error("invalid workflow artifact card");
    if (!workflowArtifactSlackTextFits(workflowArtifactSlackMrkdwn(value.summary))) {
      throw new Error("invalid workflow artifact card");
    }
    card.summary = value.summary;
  }
  if (Object.hasOwn(value, "status")) {
    if (!ownRecord(value.status) || !exactKeys(value.status, ["label", "tone"])) {
      throw new Error("invalid workflow artifact card");
    }
    if (
      !boundedString(value.status.label, 80, false) ||
      typeof value.status.tone !== "string" ||
      !TONES.has(value.status.tone)
    ) {
      throw new Error("invalid workflow artifact card");
    }
    card.status = {
      label: value.status.label,
      tone: value.status.tone as "neutral" | "info" | "success" | "warning" | "danger",
    };
  }
  if (Object.hasOwn(value, "sections")) {
    if (!Array.isArray(value.sections) || value.sections.length > MAX_SECTIONS) {
      throw new Error("invalid workflow artifact card");
    }
    const keys = new Set<string>();
    card.sections = value.sections.map((section) => {
      if (!ownRecord(section) || !exactKeys(section, ["key", "label", "items"])) {
        throw new Error("invalid workflow artifact card");
      }
      if (
        !boundedString(section.key, 64, false) ||
        !SECTION_KEY.test(section.key) ||
        keys.has(section.key) ||
        !boundedString(section.label, 120, false) ||
        !Array.isArray(section.items) ||
        section.items.length > MAX_SECTION_ITEMS
      ) {
        throw new Error("invalid workflow artifact card");
      }
      keys.add(section.key);
      const normalized = {
        key: section.key,
        label: section.label,
        items: section.items.map((item) => {
          if (!ownRecord(item) || !exactKeys(item, ["value"], ["label", "href"])) {
            throw new Error("invalid workflow artifact card");
          }
          if (!boundedString(item.value, 2_000, false)) throw new Error("invalid workflow artifact card");
          const normalized: { label?: string; value: string; href?: string } = { value: item.value };
          if (Object.hasOwn(item, "label")) {
            if (!boundedString(item.label, 120, false)) throw new Error("invalid workflow artifact card");
            normalized.label = item.label;
          }
          if (Object.hasOwn(item, "href")) {
            if (typeof item.href !== "string") throw new Error("invalid workflow artifact card");
            const href = safeWorkflowArtifactHref(item.href, baseUrl);
            if (!href) throw new Error("invalid workflow artifact card");
            normalized.href = href;
          }
          return normalized;
        }),
      };
      if (!workflowArtifactSlackTextFits(workflowArtifactSlackSectionText(normalized, baseUrl))) {
        throw new Error("invalid workflow artifact card");
      }
      return normalized;
    });
  }
  if (Object.hasOwn(value, "links")) {
    if (!Array.isArray(value.links) || value.links.length > MAX_LINKS)
      throw new Error("invalid workflow artifact card");
    card.links = value.links.map((link) => validateLink(link, baseUrl));
    if (!workflowArtifactSlackTextFits(workflowArtifactSlackLinksText(card.links, baseUrl))) {
      throw new Error("invalid workflow artifact card");
    }
  }
  validateJsonValue(card, 0, { nodes: 0, stringUnits: 0 });
  return card;
}

export function decodeWorkflowArtifactCard(
  bytes: Uint8Array,
  baseUrl: string,
): { envelope: WorkflowArtifactEnvelope; card: WorkflowArtifactCard } {
  if (bytes.byteLength > MAX_ARTIFACT_BYTES) throw new Error("workflow artifact is too large");
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("invalid workflow artifact JSON");
  }
  const envelope = validateWorkflowArtifactEnvelope(value);
  if (envelope.renderer !== WORKFLOW_ARTIFACT_CARD_RENDERER) throw new Error("unknown workflow artifact renderer");
  return { envelope, card: validateWorkflowArtifactCard(envelope.payload, baseUrl) };
}
