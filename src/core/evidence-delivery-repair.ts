import { WORKFLOW_ARTIFACT_MIME } from "../../plugins/chassis/src/workflow-artifact-card.ts";
import { WORKFLOW_ARTIFACT_SUFFIX, workflowArtifactMime } from "../../plugins/chassis/src/workflow-artifact.ts";
import { enforceSlackEvidenceDelivery } from "../slack/evidence-delivery.ts";
import type { OutgoingAttachment, TurnResult } from "../types.ts";

const MAX_CORRECTION_OUTPUT = 160 * 1024;
const MAX_DRAFT = 16_000;
const MAX_CARD_CONTEXT = 128 * 1024;

function workflowAttachment(attachment: Pick<OutgoingAttachment, "name" | "mimetype">): boolean {
  return (
    workflowArtifactMime(attachment.mimetype) === WORKFLOW_ARTIFACT_MIME ||
    attachment.name.toLowerCase().endsWith(WORKFLOW_ARTIFACT_SUFFIX)
  );
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function correction(value: string): { reply: string; card: Record<string, unknown> | null } | undefined {
  if (!value || value.length > MAX_CORRECTION_OUTPUT) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return undefined;
  }
  if (!plainRecord(parsed) || Object.keys(parsed).some((key) => key !== "reply" && key !== "card")) return undefined;
  if (typeof parsed.reply !== "string" || !parsed.reply.trim() || parsed.reply.length > MAX_DRAFT) return undefined;
  if (parsed.card !== null && !plainRecord(parsed.card)) return undefined;
  return { reply: parsed.reply, card: parsed.card };
}

export async function enforceAndRepairEvidenceDelivery(input: {
  requestText: string;
  result: TurnResult;
  fetchBlob: (blobId: string) => Promise<Buffer>;
  stageBlob: (bytes: Buffer) => Promise<{ blobId: string; sizeBytes: number }>;
  oneShot?: (systemPrompt: string, prompt: string) => Promise<string | undefined>;
}): Promise<{ result: TurnResult; repairAttempted: boolean; repaired: boolean }> {
  const first = await enforceSlackEvidenceDelivery(input.requestText, input.result, input.fetchBlob);
  if (!first.blocked || !input.oneShot || input.result.status !== "ok" || input.result.pendingApprovals?.length) {
    return { result: first.result, repairAttempted: false, repaired: false };
  }

  const cardContext: string[] = [];
  for (const attachment of (input.result.attachments ?? []).filter(workflowAttachment).slice(0, 1)) {
    const bytes = await input.fetchBlob(attachment.blobId).catch(() => undefined);
    if (bytes && bytes.byteLength <= MAX_CARD_CONTEXT) cardContext.push(bytes.toString("utf8"));
  }
  const systemPrompt =
    "You repair presentation only. Return exact JSON with only reply and card keys. Do not retrieve data, call tools, " +
    "change facts, add claims, or construct URLs. Every factual prose paragraph and card summary must end with " +
    "Source: <type> · Observed: YYYY-MM-DD · Link: <an exact registered URL or unavailable>. Card is a complete " +
    "The registered evidence does not carry trusted publication dates, so every Public web claim must state exactly once Publication date unavailable · Freshness: unverified and include no other Published, Updated, or Publication date text. " +
    "qm.card.v1 envelope or null. Heading and fallback are a generic nonfactual label or Account Health, Executive " +
    "Brief, Meeting Brief, Public Research, Recommendation, or Strategic Brief, optionally followed by ` — <entity>`. " +
    "Section labels are nonfactual categories such as Meeting objective, Internal evidence, Business signals, Public " +
    "context, Risks and unknowns, Recommended next steps, or Source coverage. Status, when present, is exactly " +
    "Ready, Partially ready, Blocked, Insufficient evidence, On track, At risk, or Needs attention and uses the matching tone. " +
    "Put all supported status detail in sourced summary or items. Every card item names its registered source and date and uses that source's exact URL or " +
    "Link unavailable. Use unavailable only for a registered source whose links list is empty. Remove raw JSON, " +
    "SQL/HogQL, query/cache/receipt/auth metadata.";
  const prompt = JSON.stringify({
    request: input.requestText.slice(0, 8_192),
    draft: (input.result.reply ?? "").slice(0, MAX_DRAFT),
    card: cardContext[0] ?? null,
    evidence: input.result.deliveryEvidenceSources ?? [],
  });
  const generated = await input.oneShot(systemPrompt, prompt).catch(() => undefined);
  const fixed = generated ? correction(generated) : undefined;
  if (!fixed) return { result: first.result, repairAttempted: true, repaired: false };

  const candidateBlobId = "repair-candidate";
  let cardBytes: Buffer | undefined;
  let attachments: OutgoingAttachment[] | undefined;
  if (fixed.card) {
    const bytes = Buffer.from(JSON.stringify(fixed.card));
    if (bytes.byteLength <= MAX_CARD_CONTEXT) {
      cardBytes = bytes;
      attachments = [
        {
          name: "evidence-brief.workflow.json",
          mimetype: WORKFLOW_ARTIFACT_MIME,
          sizeBytes: bytes.length,
          blobId: candidateBlobId,
          renderOnly: true,
        },
      ];
    }
  }
  const candidate: TurnResult = { ...input.result, reply: fixed.reply, attachments };
  const checked = await enforceSlackEvidenceDelivery(input.requestText, candidate, async (blobId) => {
    if (blobId === candidateBlobId && cardBytes) return cardBytes;
    return input.fetchBlob(blobId);
  });
  if (checked.blocked || !cardBytes || !checked.result.attachments?.length) {
    return { result: checked.result, repairAttempted: true, repaired: !checked.blocked };
  }
  const stored = await input.stageBlob(cardBytes);
  return {
    result: {
      ...checked.result,
      attachments: checked.result.attachments.map((attachment) =>
        attachment.blobId === candidateBlobId
          ? { ...attachment, blobId: stored.blobId, sizeBytes: stored.sizeBytes }
          : attachment,
      ),
    },
    repairAttempted: true,
    repaired: true,
  };
}
