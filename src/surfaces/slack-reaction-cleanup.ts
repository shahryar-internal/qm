import { createHash, randomUUID } from "node:crypto";
import type { DurableMap } from "../persistence/durable-map.ts";
import type { SlackReactionDesireStore } from "./slack-reaction-desire.ts";
import type { SlackAgentSessionStore } from "./slack-agent-session.ts";

const MAX_ID = 256;
const CLAIM_LEASE_MS = 60_000;
const SAFE_PROVIDER_ERROR_CODES = new Set([
  "channel_not_found",
  "internal_error",
  "invalid_auth",
  "message_not_found",
  "missing_scope",
  "no_reaction",
  "not_allowed_token_type",
  "not_authed",
  "provider_error",
  "ratelimited",
  "restricted_action",
  "service_unavailable",
  "timeout",
]);

export type SlackReactionCleanupStatus = "pending" | "claimed" | "resolved";

export interface SlackReactionCleanupInput {
  teamId: string;
  agentId: string;
  sessionChannelId: string;
  sessionThreadTs: string;
  sessionToken: string;
  effectId: string;
  sourceTs: string;
  sequence: number;
  channelId: string;
  messageTs: string;
  name: string;
}

export interface SlackReactionCleanupRecord extends SlackReactionCleanupInput {
  id: string;
  status: SlackReactionCleanupStatus;
  attempts: number;
  revision: number;
  nextAttemptAt: number;
  createdAt: number;
  updatedAt: number;
  completedAt?: number;
  lastErrorCode?: string;
  lease?: {
    claimId: string;
    revision: number;
    expiresAt: number;
  };
}

export interface SlackReactionCleanupClaim extends SlackReactionCleanupInput {
  id: string;
  attempts: number;
  claimId: string;
  revision: number;
  leaseExpiresAt: number;
}

export interface SlackReactionCleanupStore {
  enqueue(input: SlackReactionCleanupInput): Promise<SlackReactionCleanupRecord>;
  claimDue(input: { teamId: string; agentId: string; limit: number }): Promise<SlackReactionCleanupClaim[]>;
  claimActive(claim: SlackReactionCleanupClaim): Promise<boolean>;
  complete(claim: SlackReactionCleanupClaim): Promise<boolean>;
  fail(
    claim: SlackReactionCleanupClaim,
    input: { retryAt: number; errorCode: string },
  ): Promise<SlackReactionCleanupRecord | null>;
  reopenAfterDecisionChange(
    claim: SlackReactionCleanupClaim,
    input: { retryAt: number },
  ): Promise<SlackReactionCleanupRecord | null>;
  reopenAfterStaleEffect(
    claim: SlackReactionCleanupClaim,
    input: { retryAt: number },
  ): Promise<SlackReactionCleanupRecord | null>;
  get(input: { teamId: string; agentId: string; id: string }): Promise<SlackReactionCleanupRecord | null>;
}

export async function recoverSlackReactionCleanupAdmissions(
  desires: SlackReactionDesireStore,
  cleanups: SlackReactionCleanupStore,
  scope: { teamId: string; agentId: string; limit: number },
  sessions?: SlackAgentSessionStore,
): Promise<void> {
  if (sessions) {
    for (const input of await desires.desired(scope)) {
      const cancelled = await sessions.cancellationLatched({
        teamId: input.teamId,
        agentId: input.agentId,
        channelId: input.sessionChannelId,
        threadTs: input.sessionThreadTs,
        token: input.sessionToken,
      });
      if (cancelled) await desires.cancel(input, { admitCleanup: true });
    }
  }
  const pending = await desires.pendingCleanupAdmissions(scope);
  for (const input of pending) {
    await cleanups.enqueue(input);
    await desires.completeCleanupAdmission(input);
  }
}

function bounded(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed && trimmed.length <= MAX_ID ? trimmed : null;
}

function timestamp(value: unknown): string | null {
  const parsed = bounded(value);
  return parsed && /^\d+(?:\.\d+)?$/.test(parsed) ? parsed : null;
}

function channel(value: unknown): string | null {
  const parsed = bounded(value);
  return parsed && /^[CDG][A-Z0-9]+$/.test(parsed) ? parsed : null;
}

function reaction(value: unknown): string | null {
  const parsed = bounded(value)?.toLowerCase();
  return parsed && /^[a-z0-9_+'-]+(?:::skin-tone-[2-6])?$/.test(parsed) ? parsed : null;
}

function normalizeInput(input: SlackReactionCleanupInput): SlackReactionCleanupInput | null {
  const teamId = bounded(input.teamId);
  const agentId = bounded(input.agentId);
  const sessionChannelId = channel(input.sessionChannelId);
  const sessionThreadTs = timestamp(input.sessionThreadTs);
  const sessionToken = bounded(input.sessionToken);
  const effectId = bounded(input.effectId);
  const sourceTs = timestamp(input.sourceTs);
  const channelId = channel(input.channelId);
  const messageTs = timestamp(input.messageTs);
  const name = reaction(input.name);
  return teamId &&
    agentId &&
    sessionChannelId &&
    sessionThreadTs &&
    sessionToken &&
    effectId &&
    sourceTs &&
    Number.isSafeInteger(input.sequence) &&
    input.sequence >= 0 &&
    input.sequence <= 1_000_000 &&
    channelId &&
    messageTs &&
    name
    ? {
        teamId,
        agentId,
        sessionChannelId,
        sessionThreadTs,
        sessionToken,
        effectId,
        sourceTs,
        sequence: input.sequence,
        channelId,
        messageTs,
        name,
      }
    : null;
}

function cleanupId(input: SlackReactionCleanupInput): string {
  const digest = createHash("sha256")
    .update(
      JSON.stringify([
        input.teamId,
        input.agentId,
        input.sessionChannelId,
        input.sessionThreadTs,
        input.sessionToken,
        input.effectId,
        input.sourceTs,
        input.sequence,
        input.channelId,
        input.messageTs,
        input.name,
      ]),
    )
    .digest("hex");
  return `reaction-cleanup:${digest}`;
}

function exactInput(record: SlackReactionCleanupRecord, input: SlackReactionCleanupInput): boolean {
  return (
    record.teamId === input.teamId &&
    record.agentId === input.agentId &&
    record.sessionChannelId === input.sessionChannelId &&
    record.sessionThreadTs === input.sessionThreadTs &&
    record.sessionToken === input.sessionToken &&
    record.effectId === input.effectId &&
    record.sourceTs === input.sourceTs &&
    record.sequence === input.sequence &&
    record.channelId === input.channelId &&
    record.messageTs === input.messageTs &&
    record.name === input.name
  );
}

function exactClaim(record: SlackReactionCleanupRecord, claim: SlackReactionCleanupClaim): boolean {
  return (
    record.id === claim.id &&
    record.teamId === claim.teamId &&
    record.agentId === claim.agentId &&
    record.sessionChannelId === claim.sessionChannelId &&
    record.sessionThreadTs === claim.sessionThreadTs &&
    record.sessionToken === claim.sessionToken &&
    record.effectId === claim.effectId &&
    record.sourceTs === claim.sourceTs &&
    record.sequence === claim.sequence &&
    record.channelId === claim.channelId &&
    record.messageTs === claim.messageTs &&
    record.name === claim.name &&
    record.status === "claimed" &&
    record.revision === claim.revision &&
    record.lease?.claimId === claim.claimId &&
    record.lease.revision === claim.revision &&
    record.lease.expiresAt === claim.leaseExpiresAt
  );
}

function safeErrorCode(value: unknown): string {
  const parsed = bounded(value)?.toLowerCase();
  return parsed && SAFE_PROVIDER_ERROR_CODES.has(parsed) ? parsed : "provider_error";
}

export function createSlackReactionCleanupStore(
  backing: DurableMap<SlackReactionCleanupRecord>,
  now: () => number = Date.now,
): SlackReactionCleanupStore {
  const update = backing.update?.bind(backing);
  if (!update) throw new Error("Slack reaction cleanup storage requires atomic durable updates");

  return {
    async enqueue(raw) {
      const input = normalizeInput(raw);
      if (!input) throw new Error("invalid Slack reaction cleanup authority");
      const id = cleanupId(input);
      const createdAt = now();
      const initial: SlackReactionCleanupRecord = {
        ...input,
        id,
        status: "pending",
        attempts: 0,
        revision: 0,
        nextAttemptAt: createdAt,
        createdAt,
        updatedAt: createdAt,
      };
      const stored = await backing.putIfAbsent(id, initial);
      if (!exactInput(stored, input)) throw new Error("Slack reaction cleanup identity collision");
      return stored;
    },

    async claimDue(input) {
      const teamId = bounded(input.teamId);
      const agentId = bounded(input.agentId);
      if (!teamId || !agentId || !Number.isSafeInteger(input.limit) || input.limit < 1) return [];
      const claimed: SlackReactionCleanupClaim[] = [];
      const scanAt = now();
      for (const [id, candidate] of await backing.entries()) {
        if (claimed.length >= Math.min(100, input.limit)) break;
        if (candidate.teamId !== teamId || candidate.agentId !== agentId) continue;
        if (candidate.status === "resolved") continue;
        if (candidate.status === "pending" && candidate.nextAttemptAt > scanAt) continue;
        if (candidate.status === "claimed" && (candidate.lease?.expiresAt ?? 0) > scanAt) continue;
        const claimId = randomUUID();
        let acquired = false;
        const stored = await update(id, (current) => {
          if (current.teamId !== teamId || current.agentId !== agentId) return current;
          if (current.status === "resolved") return current;
          if (current.status === "pending" && current.nextAttemptAt > scanAt) return current;
          if (current.status === "claimed" && (current.lease?.expiresAt ?? 0) > scanAt) return current;
          acquired = true;
          const revision = current.revision + 1;
          return {
            ...current,
            status: "claimed" as const,
            revision,
            lease: { claimId, revision, expiresAt: scanAt + CLAIM_LEASE_MS },
            updatedAt: scanAt,
          };
        });
        if (!acquired || !stored?.lease || stored.lease.claimId !== claimId) continue;
        claimed.push({
          id: stored.id,
          teamId: stored.teamId,
          agentId: stored.agentId,
          sessionChannelId: stored.sessionChannelId,
          sessionThreadTs: stored.sessionThreadTs,
          sessionToken: stored.sessionToken,
          effectId: stored.effectId,
          sourceTs: stored.sourceTs,
          sequence: stored.sequence,
          channelId: stored.channelId,
          messageTs: stored.messageTs,
          name: stored.name,
          attempts: stored.attempts,
          claimId,
          revision: stored.revision,
          leaseExpiresAt: stored.lease.expiresAt,
        });
      }
      return claimed;
    },

    async claimActive(claim) {
      const record = await backing.get(claim.id);
      return !!record && exactClaim(record, claim);
    },

    async complete(claim) {
      let completed = false;
      const completedAt = now();
      await update(claim.id, (record) => {
        if (!exactClaim(record, claim)) return record;
        completed = true;
        return {
          ...record,
          status: "resolved" as const,
          lease: undefined,
          completedAt,
          updatedAt: completedAt,
        };
      });
      return completed;
    },

    async fail(claim, input) {
      if (!Number.isSafeInteger(input.retryAt) || input.retryAt < 0) return null;
      let failed = false;
      const failedAt = now();
      const stored = await update(claim.id, (record) => {
        if (!exactClaim(record, claim)) return record;
        failed = true;
        const attempts = Math.min(Number.MAX_SAFE_INTEGER, record.attempts + 1);
        return {
          ...record,
          status: "pending" as const,
          attempts,
          nextAttemptAt: Math.max(failedAt, input.retryAt),
          lease: undefined,
          lastErrorCode: safeErrorCode(input.errorCode),
          updatedAt: failedAt,
        };
      });
      return failed ? (stored ?? null) : null;
    },

    async reopenAfterDecisionChange(claim, input) {
      if (!Number.isSafeInteger(input.retryAt) || input.retryAt < 0) return null;
      let reopened = false;
      const reopenedAt = now();
      const stored = await update(claim.id, (record) => {
        if (!exactInput(record, claim) || record.revision !== claim.revision || record.status !== "resolved") {
          return record;
        }
        reopened = true;
        return {
          ...record,
          status: "pending" as const,
          revision: record.revision + 1,
          nextAttemptAt: Math.max(reopenedAt, input.retryAt),
          lease: undefined,
          completedAt: undefined,
          lastErrorCode: "desired_state_changed",
          updatedAt: reopenedAt,
        };
      });
      return reopened ? (stored ?? null) : null;
    },

    async reopenAfterStaleEffect(claim, input) {
      if (!Number.isSafeInteger(input.retryAt) || input.retryAt < 0) return null;
      let reopened = false;
      const reopenedAt = now();
      const stored = await update(claim.id, (record) => {
        if (!exactInput(record, claim) || record.revision <= claim.revision || exactClaim(record, claim)) return record;
        reopened = true;
        return {
          ...record,
          status: "pending" as const,
          revision: record.revision + 1,
          nextAttemptAt: Math.max(reopenedAt, input.retryAt),
          lease: undefined,
          completedAt: undefined,
          lastErrorCode: "provider_error",
          updatedAt: reopenedAt,
        };
      });
      return reopened ? (stored ?? null) : null;
    },

    async get(input) {
      const teamId = bounded(input.teamId);
      const agentId = bounded(input.agentId);
      const id = bounded(input.id);
      if (!teamId || !agentId || !id) return null;
      const record = await backing.get(id);
      return record?.teamId === teamId && record.agentId === agentId ? record : null;
    },
  };
}
