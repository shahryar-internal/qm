import type {
  SlackReactionCleanupClaim,
  SlackReactionCleanupInput,
  SlackReactionCleanupRecord,
} from "../surfaces/slack-reaction-cleanup.ts";

const RETRY_DELAYS_MS = [1_000, 5_000, 15_000, 60_000, 300_000, 900_000, 3_600_000] as const;
const CONFIRMED_ABSENT_CODES = new Set(["no_reaction", "message_not_found"]);
const SAFE_PROVIDER_ERROR_CODES = new Set([
  ...CONFIRMED_ABSENT_CODES,
  "internal_error",
  "invalid_auth",
  "missing_scope",
  "not_allowed_token_type",
  "not_authed",
  "ratelimited",
  "restricted_action",
  "service_unavailable",
  "timeout",
]);

export interface SlackReactionCleanupBridge {
  enqueueSlackReactionCleanup(input: SlackReactionCleanupInput): Promise<SlackReactionCleanupRecord>;
  claimSlackReactionCleanups(input: {
    teamId: string;
    agentId: string;
    limit: number;
  }): Promise<SlackReactionCleanupClaim[]>;
  slackReactionCleanupAction(claim: SlackReactionCleanupClaim): Promise<SlackReactionCleanupDecision | "stale">;
  completeSlackReactionCleanup(
    claim: SlackReactionCleanupClaim,
    decision: SlackReactionCleanupDecision,
  ): Promise<boolean>;
  failSlackReactionCleanup(
    claim: SlackReactionCleanupClaim,
    input: { retryAt: number; errorCode: string },
  ): Promise<SlackReactionCleanupRecord | null>;
  reopenSlackReactionCleanupAfterStaleEffect(
    claim: SlackReactionCleanupClaim,
    input: { retryAt: number },
  ): Promise<SlackReactionCleanupRecord | null>;
  getSlackReactionCleanup(input: {
    teamId: string;
    agentId: string;
    id: string;
  }): Promise<SlackReactionCleanupRecord | null>;
}

export interface SlackReactionCleanupDecision {
  action: "remove" | "preserve";
  desireGeneration: number;
  desireEffectId: string | null;
}

export interface SlackReactionRemovalClient {
  reactions: {
    add(args: { channel: string; timestamp: string; name: string }): Promise<unknown>;
    remove(args: { channel: string; timestamp: string; name: string }): Promise<unknown>;
  };
}

function providerErrorCode(error: unknown): string {
  const code = (error as { data?: { error?: unknown } })?.data?.error;
  const normalized = typeof code === "string" ? code.toLowerCase() : "";
  return SAFE_PROVIDER_ERROR_CODES.has(normalized) ? normalized : "provider_error";
}

function retryAt(error: unknown, claim: SlackReactionCleanupClaim, now: number): number {
  const rawRetryAfter =
    (error as { retryAfter?: unknown })?.retryAfter ??
    (error as { data?: { retryAfter?: unknown; retry_after?: unknown } })?.data?.retryAfter ??
    (error as { data?: { retry_after?: unknown } })?.data?.retry_after;
  const retryAfterSeconds = typeof rawRetryAfter === "number" ? rawRetryAfter : Number(rawRetryAfter);
  if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0 && retryAfterSeconds <= 86_400) {
    return now + Math.ceil(retryAfterSeconds * 1_000);
  }
  const delay = RETRY_DELAYS_MS[Math.min(claim.attempts, RETRY_DELAYS_MS.length - 1)]!;
  return now + delay;
}

export async function drainSlackReactionCleanups(
  bridge: SlackReactionCleanupBridge,
  client: SlackReactionRemovalClient,
  scope: { teamId: string; agentId: string },
  now: () => number = Date.now,
): Promise<void> {
  const claims = await bridge.claimSlackReactionCleanups({ ...scope, limit: 25 });
  for (const claim of claims) {
    const fail = async (error: unknown): Promise<void> => {
      const errorCode = providerErrorCode(error);
      const failed = await bridge.failSlackReactionCleanup(claim, {
        retryAt: retryAt(error, claim, now()),
        errorCode,
      });
      if (failed && (failed.attempts === 8 || failed.attempts % 24 === 0)) {
        console.error(`[slack-plugin] reaction cleanup still pending ${claim.id} (${errorCode})`);
      }
    };
    const applyAction = async (action: "remove" | "preserve"): Promise<boolean> => {
      try {
        if (action === "preserve") {
          await client.reactions.add({ channel: claim.channelId, timestamp: claim.messageTs, name: claim.name });
        } else {
          await client.reactions.remove({ channel: claim.channelId, timestamp: claim.messageTs, name: claim.name });
        }
        return true;
      } catch (error) {
        const errorCode = providerErrorCode(error);
        if (action === "preserve" && (error as { data?: { error?: unknown } })?.data?.error === "already_reacted") {
          return true;
        }
        if (action === "remove" && CONFIRMED_ABSENT_CODES.has(errorCode)) return true;
        await fail(error);
        return false;
      }
    };
    let settled = false;
    for (let transition = 0; transition < 4; transition++) {
      let decision: SlackReactionCleanupDecision | "stale";
      try {
        decision = await bridge.slackReactionCleanupAction(claim);
      } catch (error) {
        await fail(error);
        settled = true;
        break;
      }
      if (decision === "stale") {
        settled = true;
        break;
      }
      if (!(await applyAction(decision.action))) {
        settled = true;
        break;
      }
      let confirmed: SlackReactionCleanupDecision | "stale";
      try {
        confirmed = await bridge.slackReactionCleanupAction(claim);
      } catch (error) {
        await fail(error);
        settled = true;
        break;
      }
      if (confirmed === "stale") {
        await bridge.reopenSlackReactionCleanupAfterStaleEffect(claim, { retryAt: now() });
        settled = true;
        break;
      }
      if (
        confirmed.action !== decision.action ||
        confirmed.desireGeneration !== decision.desireGeneration ||
        confirmed.desireEffectId !== decision.desireEffectId
      ) {
        continue;
      }
      if (!(await bridge.completeSlackReactionCleanup(claim, confirmed))) {
        await fail(new Error("Slack reaction desired state changed before durable completion"));
      }
      settled = true;
      break;
    }
    if (!settled) await fail(new Error("Slack reaction desired state changed too frequently"));
  }
}

export async function requestSlackReactionCleanup(
  bridge: SlackReactionCleanupBridge,
  client: SlackReactionRemovalClient,
  input: SlackReactionCleanupInput,
  now: () => number = Date.now,
): Promise<"confirmed" | "pending"> {
  const enqueued = await bridge.enqueueSlackReactionCleanup(input);
  if (enqueued.status !== "resolved") {
    await drainSlackReactionCleanups(bridge, client, { teamId: input.teamId, agentId: input.agentId }, now);
  }
  const current = await bridge.getSlackReactionCleanup({
    teamId: input.teamId,
    agentId: input.agentId,
    id: enqueued.id,
  });
  if (current?.status === "resolved") return "confirmed";
  return "pending";
}
