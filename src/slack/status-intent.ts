import type {
  SlackAgentStatusIntentClaim,
  SlackAgentStatusIntentInput,
  SlackAgentStatusIntentRecord,
} from "../surfaces/slack-agent-status-intent.ts";
import type {
  SlackAgentProviderWriteClaim,
  SlackAgentProviderWriteClaimResult,
  SlackAgentSessionKey,
} from "../surfaces/slack-agent-session.ts";
import { botIdentityArgs } from "./delivery.ts";
import { setNativeAgentSessionStatus, SlackAgentWriteDeferredError } from "./presenters.ts";

const RETRY_DELAYS_MS = [1_000, 5_000, 15_000, 60_000, 300_000, 900_000, 3_600_000] as const;
const SAFE_PROVIDER_ERROR_CODES = new Set([
  "internal_error",
  "invalid_auth",
  "missing_scope",
  "not_allowed_token_type",
  "not_authed",
  "provider_error",
  "ratelimited",
  "restricted_action",
  "service_unavailable",
  "timeout",
]);

export interface SlackAgentStatusIntentBridge {
  enqueueSlackAgentStatusIntent(input: SlackAgentStatusIntentInput): Promise<{
    disposition: "accepted" | "replayed" | "superseded";
    record: SlackAgentStatusIntentRecord;
  }>;
  claimSlackAgentStatusIntents(input: {
    teamId: string;
    agentId: string;
    limit: number;
  }): Promise<SlackAgentStatusIntentClaim[]>;
  slackAgentStatusIntentClaimActive(claim: SlackAgentStatusIntentClaim): Promise<boolean>;
  completeSlackAgentStatusIntent(claim: SlackAgentStatusIntentClaim): Promise<boolean>;
  deferSlackAgentStatusIntent(
    claim: SlackAgentStatusIntentClaim,
    input: { retryAt: number; errorCode: string },
  ): Promise<SlackAgentStatusIntentRecord | null>;
  failSlackAgentStatusIntent(
    claim: SlackAgentStatusIntentClaim,
    input: { retryAt: number; errorCode: string },
  ): Promise<SlackAgentStatusIntentRecord | null>;
  reopenSlackAgentStatusIntentAfterStaleEffect(
    claim: SlackAgentStatusIntentClaim,
    input: { retryAt: number },
  ): Promise<SlackAgentStatusIntentRecord | null>;
  getSlackAgentStatusIntent(input: SlackAgentSessionKey): Promise<SlackAgentStatusIntentRecord | null>;
  claimSlackAgentProviderWrite(
    input: SlackAgentSessionKey & { method: string },
  ): Promise<SlackAgentProviderWriteClaimResult>;
  deferSlackAgentProviderWrite(
    input: SlackAgentProviderWriteClaim & { notBefore: number },
  ): Promise<{ applied: boolean }>;
  completeSlackAgentProviderWrite(input: SlackAgentProviderWriteClaim): Promise<boolean>;
  releaseSlackAgentProviderWrite(input: SlackAgentProviderWriteClaim): Promise<boolean>;
}

export interface SlackAgentStatusClient {
  agents?: { sessions?: { setStatus?: (args: Record<string, unknown>) => Promise<unknown> } };
  apiCall?: (method: string, args: Record<string, unknown>) => Promise<unknown>;
}

function providerErrorCode(error: unknown): string {
  const value = error as { data?: { error?: unknown }; code?: unknown };
  const candidate = typeof value.data?.error === "string" ? value.data.error : value.code;
  const normalized = typeof candidate === "string" ? candidate.toLowerCase() : "";
  return SAFE_PROVIDER_ERROR_CODES.has(normalized) ? normalized : "provider_error";
}

function providerRetryAt(error: unknown, claim: SlackAgentStatusIntentClaim, now: number): number {
  const value = error as { retryAfter?: unknown; data?: { retry_after?: unknown } };
  const seconds = Number(value.retryAfter ?? value.data?.retry_after);
  if (Number.isFinite(seconds) && seconds > 0 && seconds <= 86_400) return now + Math.ceil(seconds * 1_000);
  return now + RETRY_DELAYS_MS[Math.min(claim.attempts, RETRY_DELAYS_MS.length - 1)]!;
}

function statusArgs(claim: SlackAgentStatusIntentClaim): Record<string, unknown> {
  return {
    channel_id: claim.channelId,
    thread_ts: claim.threadTs,
    status: claim.status,
    ...(claim.createSession
      ? {
          initiator_user_id: claim.createSession.initiatorUserId,
          title: claim.createSession.title,
        }
      : {}),
    ...botIdentityArgs(),
  };
}

async function deferClaim(
  bridge: SlackAgentStatusIntentBridge,
  claim: SlackAgentStatusIntentClaim,
  providerClaim: SlackAgentProviderWriteClaim | undefined,
  error: unknown,
  retryAt: number,
): Promise<void> {
  if (providerClaim) {
    if (error instanceof SlackAgentWriteDeferredError) {
      await bridge.deferSlackAgentProviderWrite({ ...providerClaim, notBefore: retryAt });
    } else {
      await bridge.releaseSlackAgentProviderWrite(providerClaim);
    }
  }
  const errorCode = providerErrorCode(error);
  if (error instanceof SlackAgentWriteDeferredError || errorCode === "ratelimited") {
    await bridge.deferSlackAgentStatusIntent(claim, { retryAt, errorCode });
  } else {
    await bridge.failSlackAgentStatusIntent(claim, { retryAt, errorCode });
  }
}

export async function drainSlackAgentStatusIntents(
  bridge: SlackAgentStatusIntentBridge,
  client: SlackAgentStatusClient,
  scope: { teamId: string; agentId: string },
  now: () => number = Date.now,
): Promise<void> {
  const claims = await bridge.claimSlackAgentStatusIntents({ ...scope, limit: 25 });
  for (const claim of claims) {
    if (!(await bridge.slackAgentStatusIntentClaimActive(claim))) {
      await bridge.failSlackAgentStatusIntent(claim, { retryAt: now() + 1_000, errorCode: "authority_stale" });
      continue;
    }
    const provider = await bridge.claimSlackAgentProviderWrite({ ...claim, method: "agents.sessions.setStatus" });
    if (!provider.acquired) {
      await bridge.deferSlackAgentStatusIntent(claim, {
        retryAt: Math.max(now(), provider.notBefore),
        errorCode: provider.reason,
      });
      continue;
    }
    try {
      await setNativeAgentSessionStatus(client, statusArgs(claim));
    } catch (error) {
      const retryAt =
        error instanceof SlackAgentWriteDeferredError
          ? now() + error.retryAfterMs
          : providerRetryAt(error, claim, now());
      await deferClaim(bridge, claim, provider.claim, error, retryAt);
      continue;
    }
    if (!(await bridge.completeSlackAgentProviderWrite(provider.claim))) {
      await bridge.failSlackAgentStatusIntent(claim, {
        retryAt: now(),
        errorCode: "stale_provider_claim",
      });
      await bridge.reopenSlackAgentStatusIntentAfterStaleEffect(claim, { retryAt: now() });
      continue;
    }
    if (!(await bridge.completeSlackAgentStatusIntent(claim))) {
      await bridge.reopenSlackAgentStatusIntentAfterStaleEffect(claim, { retryAt: now() });
    }
  }
}

export async function requestSlackAgentStatusIntent(
  bridge: SlackAgentStatusIntentBridge,
  client: SlackAgentStatusClient,
  input: SlackAgentStatusIntentInput,
  now: () => number = Date.now,
): Promise<{ verdict: "confirmed" | "pending"; retryAt?: number }> {
  const admitted = await bridge.enqueueSlackAgentStatusIntent(input);
  if (admitted.disposition !== "superseded" && admitted.record.state !== "resolved") {
    await drainSlackAgentStatusIntents(bridge, client, { teamId: input.teamId, agentId: input.agentId }, now);
  }
  const current = await bridge.getSlackAgentStatusIntent(input);
  if (!current) throw new Error("Slack Agent status intent durable read failed");
  if (current.intentId !== admitted.record.intentId) return { verdict: "confirmed" };
  if (current.state === "resolved") return { verdict: "confirmed" };
  return { verdict: "pending", retryAt: Math.max(now() + 1, current.nextAttemptAt) };
}
