import {
  decodeWorkflowArtifactCard,
  safeWorkflowArtifactHref,
  WORKFLOW_ARTIFACT_MIME,
  type WorkflowArtifactCard,
} from "../../plugins/chassis/src/workflow-artifact-card.ts";
import { WORKFLOW_ARTIFACT_SUFFIX, workflowArtifactMime } from "../../plugins/chassis/src/workflow-artifact.ts";
import {
  canonicalEvidenceLink,
  slackTurnRequiresEvidenceBuffer,
  type DeliveryEvidenceSource,
} from "../core/evidence-links.ts";
import type { OutgoingAttachment, TurnResult } from "../types.ts";

const FAIL_SAFE_REPLY =
  "I couldn't safely deliver that evidence-based answer because one or more claims were missing verified current-turn source provenance. Please retry.";
const ACKNOWLEDGEMENT =
  /^(?:ok(?:ay)?(?: sounds good(?: to me)?)?|thanks?(?: you)?|got it|sounds good(?: to me)?|great|perfect|understood)[!.\s]*$/iu;
const SELF_REQUEST =
  /^(?:are you still working|how are you|how are you doing|how are we doing on (?:this|the) (?:build|task|work)|how(?:'s| is) it going|who are you|what are you working on|what are your(?: [\p{L}-]+){0,3} capabilities|what can you do)[?!.\s]*$/iu;
const STRONG_EVIDENCE_REQUEST =
  /\b(?:account health|account update|meeting prep(?:aration)?|prep(?:are)? me for|public research|market (?:research|analysis)|competitor (?:research|review|analysis|comparison)|competitive (?:research|review|analysis|comparison)|strategic recommendation|what changed|how .{1,80} (?:is|are) doing|(?:current|latest|recent).{0,60}(?:analytics|metrics|pricing|results?|status))\b/iu;
const TRANSFORMATION_INSTRUCTION =
  /^(?:(?:can|could|would) you (?:please\s+)?)?(?:(?:edit|proofread|rewrite|summari[sz]e) (?:this|that|the following) (?:document|draft|e-?mail|message|text)|check (?:this|that|the following) (?:document|draft|e-?mail|message|text) for (?:clarity|grammar|spelling|tone)|make (?:it|that|this) more concise|repeat(?: (?:this|that|the following|the words?))?)$/iu;
const TRANSFORMATION_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u;
const CREATIVE_REQUESTS = [
  /^(?:please\s+)?brainstorm\s+(?:(?:brand|campaign|feature|product)\s+)?(?:buttons?|copy|greetings?|headlines?|ideas?|interfaces?|invitations?|messages?|mockups?|names?|taglines?)(?:\s+for\s+(?:customer success|engineering|finance|marketing|product|sales|support)(?:\s+and\s+(?:customer success|engineering|finance|marketing|product|sales|support))?)?\s*[.!?]*$/iu,
  /^(?:(?:please\s+)?|(?:can|could|would) you (?:please\s+)?)(?:compose|draft|write)\s+(?:(?:a|an|the)\s+)?(?:(?:brief|clear|concise|creative|friendly|polite|professional|short|warm)(?:\s+(?:and\s+)?(?:brief|clear|concise|creative|friendly|polite|professional|short|warm))?\s+)?(?:copy|e-?mail|greeting|headline|invitation|limerick|message|note|poem|post|tagline)\s*[.!?]*$/iu,
  /^(?:(?:please\s+)?|(?:can|could|would) you (?:please\s+)?)(?:compose|draft|write)\s+(?:(?:a|an|the)\s+)?(?:(?:brief|clear|concise|friendly|polite|professional|short|warm)\s+)?(?:e-?mail|invitation|message)\s+(?:to|for)\s+[\p{Lu}][\p{L}.'-]{0,40}(?:\s+and\s+[\p{Lu}][\p{L}.'-]{0,40})?\s*[.!?]*$/iu,
  /^(?:(?:please\s+)?|(?:can|could|would) you (?:please\s+)?)(?:compose|draft|write)\s+(?:(?:a|an|the)\s+)?(?:(?:brief|clear|concise|friendly|polite|professional|short|warm)\s+)?(?:e-?mail|invitation|message)\s+inviting\s+[\p{Lu}][\p{L}.'-]{0,40}\s+to\s+(?:breakfast|coffee|dinner|lunch)\s*[.!?]*$/iu,
  /^(?:(?:please\s+)?|(?:can|could|would) you (?:please\s+)?)(?:compose|draft|write)\s+(?:(?:a|an|the)\s+)?(?:e-?mail|message)\s+saying\s+hello(?:\s+and\s+tell\s+[\p{Lu}][\p{L}.'-]{0,40}\s+(?:i(?:'m|'ll| am| will)|we(?:'re|'ll| are| will))\s+[\p{L}\p{N} .,'-]{1,60})?\s*[.!?]*$/iu,
  /^(?:(?:please\s+)?|(?:can|could|would) you (?:please\s+)?)(?:compose|draft|write)\s+(?:calendar invite copy(?:\s+for\s+(?:breakfast|coffee|dinner|lunch))?|copy for (?:a|the) pricing page)\s*[.!?]*$/iu,
  /^(?:(?:please\s+)?|(?:can|could|would) you (?:please\s+)?)(?:write\s+(?:(?:a|the)\s+)?story\s+about\s+[\p{L}\p{N} .,'-]{0,80}\bfictional\b[\p{L}\p{N} .,'-]{0,40}|write\s+(?:(?:a|the)\s+)?(?:limerick|poem)\s+about\s+[\p{L}\p{N} .,'-]{0,80}\brobot\b[\p{L}\p{N} .,'-]{0,40}|write\s+(?:(?:a|the)\s+)?post\s+and\s+show\s+(?:our|the|this|that)\s+(?:design|image|logo|mockup|photo))\s*[.!?]*$/iu,
  /^(?:(?:please\s+)?|(?:can|could|would) you (?:please\s+)?)(?:create|design)\s+(?:(?:a|an|the)\s+)?(?:(?:(?:black|blue|green|orange|purple|red|white|yellow)(?:\s+and\s+(?:black|blue|green|orange|purple|red|white|yellow))?|chat counter)\s+)?(?:button|design|image|interface|logo|mockup)\s*[.!?]*$/iu,
  /^(?:(?:please\s+)?|(?:can|could|would) you (?:please\s+)?)(?:create|design)\s+(?:(?:a|an|the)\s+)?visual card with (?:a |an |the )?(?:friendly|short|warm) greeting\s*[.!?]*$/iu,
  /^(?:can|could|would) you (?:help me think through|make (?:it|that|this) more concise)\s*[.!?]*$/iu,
  /^(?:how (?:can|do|should) i (?:draft|phrase|write) (?:a |an |the )?(?:friendly )?(?:e-?mail|invitation|message|note|post)|should i prioritize (?:it|that|this)|what should i (?:call|name) (?:a |an |the )?(?:new )?(?:company|feature|product|project)|what should i write|what should i do with (?:it|that|this)|would you help me think through (?:it|that|this))\s*[.!?]*$/iu,
  /^(?:@\S+\s+)?is this possible\s*[.!?]*$/iu,
  /^(?:please\s+)?(?:list|suggest|give me)\s+(?:(?:a|some|the|up to \d{1,2})\s+)?(?:headlines?|ideas?|names?|taglines?)\s*[.!?]*$/iu,
];
const ACTION_REQUEST =
  /^(?:(?:please\s+)?|(?:can|could|would) you (?:please\s+)?)(?:(?:schedule|reschedule|cancel)\s+(?:(?:a|the)\s+)?(?:calendar event|invite|meeting)(?:\s+with\s+[\p{Lu}][\p{L}.'-]{0,40}(?:\s+and\s+[\p{Lu}][\p{L}.'-]{0,40})?)?|(?:send|post|upload)\s+(?:(?:a|an|the)\s+)?(?:(?:approved|reviewed)\s+)?(?:card|draft|e-?mail|file|message)|update\s+(?:(?:a|the)\s+)?(?:Notion plan|page|record|setting|task)|(?:run|execute|perform)\s+(?:(?:a|an|the)\s+)?(?:(?:approved|reviewed)\s+)?(?:internal\s+)?(?:maintenance\s+)?(?:command|operation|test(?:\s+command)?)|deploy\s+(?:(?:a|the)\s+)?(?:(?:approved|reviewed)\s+)?(?:deployment|release)|create\s+(?:(?:a|an|the)\s+)?(?:calendar event|draft|invite|sample JSON file|task))\s*[.!?]*$/iu;
const SOCIAL_REQUEST =
  /^(?:good (?:afternoon|evening|morning)|hello|hey|hi|howdy)(?:[ ,]+(?:agent|assistant|bot|there))?[?!.\s]*$|^(?:nice to meet you|tell me a joke)[?!.\s]*$/iu;
const BOUNDED_OPERATIONAL_REQUEST =
  /^(?:and also this|ask [\p{L}\p{N}_.-]{1,80}|collaborate|first ask|(?:continue|finish|resume|retry) (?:it|this|the (?:job|task|work))(?: after restart)?|(?:new )?work|(?:prepare|retry) (?:a |an |the )?(?:delayed |private )?export)$/iu;
const SUBSTANTIAL_REQUEST =
  /\b(?:account health|account update|doing|update|meeting prep(?:aration)?|prep(?:are)? me for|brief me on.*(?:calendar|e-?mail|gmail)|strateg(?:y|ic)|public research|market research|competitive (?:research|analysis)|recommend(?:ation)?|synthesi[sz]e)\b/iu;
const SOURCE_SUFFIX =
  /Source:\s*([^·\n]{1,80})\s*·\s*(Observed|As[ -]?of|Checked):\s*(\d{4}-\d{2}-\d{2})(?:T[^·\s]+)?\s*·\s*Link:\s*(https:\/\/[^\s<>]+|unavailable)\s*$/iu;
const PUBLIC_FRESHNESS = /\bPublication date unavailable\s*·\s*Freshness:\s*unverified\b/iu;
const PUBLIC_DATE_TOKEN = /\b(?:publication(?:\s+date)?|published|updated)\b/iu;
const RAW_INTERNAL =
  /(?:\bhogql\b|\bsql\b|\bselect\s+(?:\*|count\s*\(|[a-z_][a-z0-9_]*)|posthog[_ -]?(?:event|property)|\$session_id|boxplot[_ -]?data|cache[_ -]?target[_ -]?age|calculation[_ -]?trigger|has[_ -]?more|(?:next|previous)[_ -]?(?:page|cursor|offset)|page[_ -]?(?:token|cursor|offset)|query[_ -]?id|cache(?:[_ =-]?(?:hit|miss|key)|\s*=\s*(?:true|false|hit|miss))|receipt(?:[_ -]?(?:sha256|hash|handle)|\s*[=:])|oauth[_ -]?scope|request[_ -]?trace|provider payload|tool arguments?|auth(?:entication)? metadata|(?:\{|\[)\s*"(?:data|results?|query|cache|receipt)"\s*:)/iu;
const DATE = /\d{4}-\d{2}-\d{2}/u;
const SOURCE_TYPE =
  /\b(?:Analytics|Brain|Calendar|Clarify|Command Center|CRM|Drive|Email|Gmail|Google Docs|Google Sheets|Google Slides|Google Tasks|Meeting notes|Notion|PostHog|Public web|Transcript|Web)\b/iu;
const PRESENTATION_LABEL =
  /^(?:account health(?: brief)?|analysis|business signals?|commitments?(?: due)?|decision(?: or ask)?|evidence|executive brief|facts?|gaps?|inferences?|internal evidence|meeting brief|meeting objective|momentum and risk|next steps?|public context|public evidence|recommendations?|recommended next steps?|risks?(?: and unknowns)?|source coverage|sources?|summary|unknowns?)$/iu;
const ARTIFACT_HEADING =
  /^(?:Account Health|Executive Brief|Meeting Brief|Public Research|Recommendation|Strategic Brief)(?: — ([\p{L}\p{N}][\p{L}\p{N} .,'&()/-]{0,100}))?$/u;
const FACTUAL_HEADING_SUFFIX =
  /(?:\b(?:are|blocked|decreased|fell|grew|has|have|increased|is|needs|ready|rose|was|were)\b|\bat risk\b|[+-]?\d+(?:\.\d+)?%)/iu;
const STATUS_LABEL = /^(Ready|Partially ready|Blocked|Insufficient evidence|On track|At risk|Needs attention)$/u;
const STATUS_TONE = new Map<string, NonNullable<WorkflowArtifactCard["status"]>["tone"]>([
  ["at risk", "warning"],
  ["blocked", "danger"],
  ["insufficient evidence", "neutral"],
  ["needs attention", "warning"],
  ["on track", "success"],
  ["partially ready", "warning"],
  ["ready", "success"],
]);

function canonicalSourceType(value: string): string | undefined {
  const source = value.trim().toLowerCase();
  if (source === "web" || source === "public web") return "Public web";
  if (source === "email" || source === "gmail") return "Gmail";
  if (source === "posthog" || source === "analytics") return "Analytics";
  if (source === "google tasks") return "Google Tasks";
  if (source === "transcript" || source === "meeting notes" || source === "clarify") return "Clarify";
  if (["brain", "calendar", "command center", "crm", "drive", "notion"].includes(source)) {
    return source.replace(/\b\w/gu, (letter) => letter.toUpperCase());
  }
  if (["google docs", "google sheets", "google slides"].includes(source)) return "Drive";
  return undefined;
}

function sourceRegistry(result: TurnResult): Map<string, DeliveryEvidenceSource> {
  const registry = new Map<string, DeliveryEvidenceSource>();
  for (const source of result.deliveryEvidenceSources ?? []) {
    const type = canonicalSourceType(source.sourceType);
    if (!type || type !== source.sourceType || !DATE.test(source.observedAt) || source.links.length > 64) continue;
    const links = source.links.flatMap((href) => {
      const canonical = canonicalEvidenceLink(href);
      return canonical ? [canonical] : [];
    });
    if (links.length !== source.links.length) continue;
    registry.set(type, { sourceType: type, observedAt: source.observedAt, links: [...new Set(links)].sort() });
  }
  return registry;
}

function workflowAttachment(attachment: Pick<OutgoingAttachment, "name" | "mimetype">): boolean {
  return (
    workflowArtifactMime(attachment.mimetype) === WORKFLOW_ARTIFACT_MIME ||
    attachment.name.toLowerCase().endsWith(WORKFLOW_ARTIFACT_SUFFIX)
  );
}

function verifiedHttps(value: string, source: DeliveryEvidenceSource): boolean {
  const href = safeWorkflowArtifactHref(value, "https://workflow-artifact.invalid/");
  if (!href || new URL(href).protocol !== "https:" || new URL(href).origin === "https://workflow-artifact.invalid") {
    return false;
  }
  const canonical = canonicalEvidenceLink(href);
  return canonical !== undefined && source.links.includes(canonical);
}

function verifiedClaimSuffix(text: string, registry: ReadonlyMap<string, DeliveryEvidenceSource>): boolean {
  const match = text.trim().match(SOURCE_SUFFIX);
  if (!match) return false;
  const type = canonicalSourceType(match[1] ?? "");
  const source = type ? registry.get(type) : undefined;
  if (!source || match[3] !== source.observedAt.slice(0, 10)) return false;
  if (source.sourceType === "Public web" && !publicFreshnessComplete(text)) return false;
  const link = match[4];
  if (link === "unavailable") return source.links.length === 0;
  return typeof link === "string" && verifiedHttps(link.replace(/[.,;:!?]+$/u, ""), source);
}

function publicFreshnessComplete(text: string): boolean {
  const matches = text.match(new RegExp(PUBLIC_FRESHNESS.source, "giu"));
  if (matches?.length !== 1) return false;
  return !PUBLIC_DATE_TOKEN.test(text.replace(PUBLIC_FRESHNESS, ""));
}

function presentationLabel(text: string): boolean {
  const normalized = text
    .trim()
    .replace(/^#{1,6}\s+/u, "")
    .replace(/^\*\*([^*]+)\*\*$/u, "$1")
    .replace(/:$/u, "")
    .trim();
  return PRESENTATION_LABEL.test(normalized);
}

function artifactHeading(text: string): boolean {
  const match = text.trim().match(ARTIFACT_HEADING);
  return !!match && (!match[1] || !FACTUAL_HEADING_SUFFIX.test(match[1]));
}

function statusTone(label: string): NonNullable<WorkflowArtifactCard["status"]>["tone"] | undefined {
  const match = label.trim().match(STATUS_LABEL);
  return match ? STATUS_TONE.get(match[1]!.toLowerCase()) : undefined;
}

function replySourcesComplete(reply: string, registry: ReadonlyMap<string, DeliveryEvidenceSource>): boolean {
  if (!reply.trim() || RAW_INTERNAL.test(reply)) return false;
  const groups = reply
    .trim()
    .split(/\n\s*\n|\n(?=\s*(?:[-*•]|\d+[.)])\s+)/u)
    .map((group) => group.trim())
    .filter(Boolean);
  if (!groups.length) return false;
  return groups.every((group) => presentationLabel(group) || verifiedClaimSuffix(group, registry));
}

function itemSource(
  text: string,
  registry: ReadonlyMap<string, DeliveryEvidenceSource>,
): DeliveryEvidenceSource | undefined {
  const typeText = text.match(SOURCE_TYPE)?.[0];
  const type = typeText ? canonicalSourceType(typeText) : undefined;
  const source = type ? registry.get(type) : undefined;
  return source && text.includes(source.observedAt.slice(0, 10)) ? source : undefined;
}

function cardSourcesComplete(
  envelopeFallback: string,
  card: WorkflowArtifactCard,
  registry: ReadonlyMap<string, DeliveryEvidenceSource>,
): boolean {
  const allText = [
    envelopeFallback,
    card.heading,
    card.summary ?? "",
    card.status?.label ?? "",
    ...(card.sections ?? []).flatMap((section) => [
      section.label,
      ...section.items.flatMap((item) => [item.label ?? "", item.value]),
    ]),
    ...(card.links ?? []).map((link) => link.label),
  ].join("\n");
  if (RAW_INTERNAL.test(allText) || !envelopeFallback.trim() || !card.heading.trim() || !card.summary?.trim())
    return false;
  if (!artifactHeading(card.heading) && !presentationLabel(card.heading)) return false;
  if (
    !artifactHeading(envelopeFallback) &&
    !presentationLabel(envelopeFallback) &&
    !verifiedClaimSuffix(envelopeFallback, registry)
  )
    return false;
  if (card.status && statusTone(card.status.label) !== card.status.tone) return false;
  if (!verifiedClaimSuffix(card.summary, registry)) return false;
  const sections = card.sections ?? [];
  if (sections.some((section) => !presentationLabel(section.label))) return false;
  const factualItems = sections.flatMap((section) => section.items);
  if (!factualItems.length) return false;
  for (const item of factualItems) {
    const text = `${item.label ?? ""} ${item.value}`;
    const source = itemSource(text, registry);
    if (!source) return false;
    if (source.sourceType === "Public web" && !publicFreshnessComplete(text)) return false;
    if (item.href !== undefined) {
      if (!verifiedHttps(item.href, source)) return false;
    } else if (source.links.length !== 0 || !/Links? unavailable\b/iu.test(text)) return false;
  }
  for (const link of card.links ?? []) {
    const source = itemSource(link.label, registry);
    if (!source || !verifiedHttps(link.href, source)) return false;
  }
  return true;
}

export async function enforceSlackEvidenceDelivery(
  requestText: string,
  result: TurnResult,
  fetchBlob: (blobId: string) => Promise<Buffer>,
  fetchArtifact?: (artifactId: string, viewerId: string) => Promise<Buffer>,
): Promise<{ result: TurnResult; blocked: boolean; reason?: string }> {
  if (
    result.status !== "ok" ||
    result.pendingApprovals?.length ||
    ACKNOWLEDGEMENT.test(requestText.trim()) ||
    (!result.deliveryEvidenceSources?.length && !explicitEvidenceRequest(requestText))
  ) {
    return { result, blocked: false };
  }
  const registry = sourceRegistry(result);
  const reply = result.reply ?? "";
  if (!replySourcesComplete(reply, registry)) {
    return { result: { ...result, reply: FAIL_SAFE_REPLY, attachments: undefined }, blocked: true, reason: "reply" };
  }
  const substantial = SUBSTANTIAL_REQUEST.test(requestText.slice(0, 8_192));
  const workflow = (result.attachments ?? []).filter(workflowAttachment);
  if (workflow.length !== (result.attachments ?? []).length) {
    return {
      result: { ...result, reply: FAIL_SAFE_REPLY, attachments: undefined },
      blocked: true,
      reason: "attachment",
    };
  }
  if ((substantial && workflow.length !== 1) || workflow.length > 1) {
    return {
      result: { ...result, reply: FAIL_SAFE_REPLY, attachments: undefined },
      blocked: true,
      reason: "card_count",
    };
  }
  for (const attachment of workflow) {
    let file: Buffer | undefined;
    try {
      file = await fetchBlob(attachment.blobId);
    } catch {
      if (fetchArtifact && attachment.artifactId && attachment.artifactViewerId) {
        file = await fetchArtifact(attachment.artifactId, attachment.artifactViewerId).catch(() => undefined);
      }
    }
    if (!file) {
      return { result: { ...result, reply: FAIL_SAFE_REPLY, attachments: undefined }, blocked: true, reason: "card" };
    }
    try {
      const { envelope, card } = decodeWorkflowArtifactCard(file, "https://workflow-artifact.invalid/");
      if (!cardSourcesComplete(envelope.fallbackText, card, registry)) throw new Error("incomplete evidence card");
    } catch {
      return { result: { ...result, reply: FAIL_SAFE_REPLY, attachments: undefined }, blocked: true, reason: "card" };
    }
  }
  return { result, blocked: false };
}

function explicitEvidenceRequest(requestText: string): boolean {
  const trimmed = requestText.trim();
  if (!trimmed) return false;
  if (
    SELF_REQUEST.test(trimmed) ||
    SOCIAL_REQUEST.test(trimmed) ||
    BOUNDED_OPERATIONAL_REQUEST.test(trimmed) ||
    transformationRequest(trimmed)
  )
    return false;
  if (STRONG_EVIDENCE_REQUEST.test(trimmed)) return true;
  const boundedExemption = CREATIVE_REQUESTS.some((request) => request.test(trimmed)) || ACTION_REQUEST.test(trimmed);
  return !boundedExemption;
}

function transformationRequest(requestText: string): boolean {
  if (requestText.length > 8_192 || TRANSFORMATION_CONTROL.test(requestText)) return false;
  const normalizedInstruction = (value: string) =>
    value
      .trim()
      .replace(/[.!?]+$/u, "")
      .trim();
  if (TRANSFORMATION_INSTRUCTION.test(normalizedInstruction(requestText))) return true;
  const delimiter = requestText.search(/[:\n]/u);
  if (delimiter <= 0 || !TRANSFORMATION_INSTRUCTION.test(normalizedInstruction(requestText.slice(0, delimiter)))) {
    return false;
  }
  const payload = requestText.slice(delimiter + 1).trim();
  if (fencedTransformationPayload(payload)) return true;
  try {
    return typeof JSON.parse(payload) === "string";
  } catch {
    return false;
  }
}

function fencedTransformationPayload(payload: string): boolean {
  const opening = /^(?<fence>`{3,}|~{3,})(?:text)?[ \t]*\r?\n/u.exec(payload);
  const fence = opening?.groups?.fence;
  if (!opening || !fence) return false;
  let offset = opening[0].length;
  let hasContent = false;
  while (offset < payload.length) {
    const newline = payload.indexOf("\n", offset);
    const next = newline < 0 ? payload.length : newline + 1;
    const line = payload.slice(offset, newline < 0 ? payload.length : newline).replace(/\r$/u, "");
    const closing = fence[0] === "`" ? /^ {0,3}(`+)[ \t]*$/u.exec(line) : /^ {0,3}(~+)[ \t]*$/u.exec(line);
    const closingFence = closing?.[1];
    if (closingFence && closingFence[0] === fence[0] && closingFence.length >= fence.length) {
      return hasContent && payload.slice(next).trim().length === 0;
    }
    if (line.trim()) hasContent = true;
    if (newline < 0) break;
    offset = next;
  }
  return false;
}

export function slackEvidenceRequest(requestText: string): boolean {
  return slackTurnRequiresEvidenceBuffer(requestText);
}
