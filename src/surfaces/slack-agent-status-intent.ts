import { createHash, randomUUID } from "node:crypto";
import type { DurableMap } from "../persistence/durable-map.ts";
import type { SlackAgentSessionKey, SlackAgentSessionStatus } from "./slack-agent-session.ts";

const MAX_ID = 256;
const MAX_TITLE = 200;
const CLAIM_LEASE_MS = 60_000;
const SAFE_ERROR_CODES = new Set([
  "authority_stale",
  "internal_error",
  "invalid_auth",
  "lease_held",
  "missing_scope",
  "not_allowed_token_type",
  "not_authed",
  "provider_error",
  "ratelimited",
  "restricted_action",
  "retry_window",
  "service_unavailable",
  "stale_provider_claim",
  "stale_provider_effect",
  "timeout",
]);

export type SlackAgentStatusIntentAuthority =
  | { kind: "binding"; token: string }
  | { kind: "stop"; eventId: string }
  | {
      kind: "approval";
      requestId: string;
      requesterUserId: string;
      channelId: string;
      messageTs: string;
    };

export interface SlackAgentStatusIntentInput extends SlackAgentSessionKey {
  authority: SlackAgentStatusIntentAuthority;
  sourceTs: string;
  sequence: number;
  status: SlackAgentSessionStatus;
  createSession?: {
    initiatorUserId: string;
    title: string;
  };
}

export type SlackAgentStatusIntentState = "pending" | "claimed" | "resolved";

export interface SlackAgentStatusIntentRecord extends SlackAgentStatusIntentInput {
  id: string;
  intentId: string;
  state: SlackAgentStatusIntentState;
  generation: number;
  attempts: number;
  nextAttemptAt: number;
  createdAt: number;
  updatedAt: number;
  completedAt?: number;
  lastErrorCode?: string;
  lease?: {
    claimId: string;
    generation: number;
    expiresAt: number;
  };
}

export interface SlackAgentStatusIntentClaim extends SlackAgentStatusIntentInput {
  id: string;
  intentId: string;
  generation: number;
  attempts: number;
  claimId: string;
  leaseExpiresAt: number;
}

export interface SlackAgentStatusIntentStore {
  enqueue(input: SlackAgentStatusIntentInput): Promise<{
    disposition: "accepted" | "replayed" | "superseded";
    record: SlackAgentStatusIntentRecord;
  }>;
  claimDue(input: { teamId: string; agentId: string; limit: number }): Promise<SlackAgentStatusIntentClaim[]>;
  claimActive(claim: SlackAgentStatusIntentClaim): Promise<boolean>;
  complete(claim: SlackAgentStatusIntentClaim): Promise<boolean>;
  defer(
    claim: SlackAgentStatusIntentClaim,
    input: { retryAt: number; errorCode: string },
  ): Promise<SlackAgentStatusIntentRecord | null>;
  fail(
    claim: SlackAgentStatusIntentClaim,
    input: { retryAt: number; errorCode: string },
  ): Promise<SlackAgentStatusIntentRecord | null>;
  reopenCurrentAfterStaleEffect(
    claim: SlackAgentStatusIntentClaim,
    input: { retryAt: number },
  ): Promise<SlackAgentStatusIntentRecord | null>;
  get(input: SlackAgentSessionKey): Promise<SlackAgentStatusIntentRecord | null>;
}

function bounded(value: unknown, max = MAX_ID): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed && trimmed.length <= max ? trimmed : null;
}

function timestamp(value: unknown): string | null {
  const parsed = bounded(value);
  return parsed && /^\d+(?:\.\d{1,6})?$/.test(parsed) ? parsed : null;
}

function channel(value: unknown): string | null {
  const parsed = bounded(value);
  return parsed && /^[CDG][A-Z0-9]+$/.test(parsed) ? parsed : null;
}

function normalizeAuthority(value: SlackAgentStatusIntentAuthority): SlackAgentStatusIntentAuthority | null {
  if (value?.kind === "binding") {
    const token = bounded(value.token);
    return token ? { kind: "binding", token } : null;
  }
  if (value?.kind === "stop") {
    const eventId = bounded(value.eventId);
    return eventId ? { kind: "stop", eventId } : null;
  }
  if (value?.kind === "approval") {
    const requestId = bounded(value.requestId);
    const requesterUserId = bounded(value.requesterUserId);
    const channelId = channel(value.channelId);
    const messageTs = timestamp(value.messageTs);
    return requestId && requesterUserId && channelId && messageTs
      ? { kind: "approval", requestId, requesterUserId, channelId, messageTs }
      : null;
  }
  return null;
}

function normalizeInput(input: SlackAgentStatusIntentInput): SlackAgentStatusIntentInput | null {
  const teamId = bounded(input.teamId);
  const agentId = bounded(input.agentId);
  const channelId = channel(input.channelId);
  const threadTs = timestamp(input.threadTs);
  const sourceTs = timestamp(input.sourceTs);
  const authority = normalizeAuthority(input.authority);
  if (
    !teamId ||
    !agentId ||
    !channelId ||
    !threadTs ||
    !sourceTs ||
    !authority ||
    !Number.isSafeInteger(input.sequence) ||
    input.sequence < 0 ||
    input.sequence > 1_000 ||
    !["processing", "active", "suspended", "closed"].includes(input.status)
  ) {
    return null;
  }
  let createSession: SlackAgentStatusIntentInput["createSession"];
  if (input.createSession) {
    const initiatorUserId = bounded(input.createSession.initiatorUserId);
    const title = bounded(input.createSession.title, MAX_TITLE);
    if (!initiatorUserId || !title || input.status !== "processing") return null;
    createSession = { initiatorUserId, title };
  }
  return {
    teamId,
    agentId,
    channelId,
    threadTs,
    authority,
    sourceTs,
    sequence: input.sequence,
    status: input.status,
    ...(createSession ? { createSession } : {}),
  };
}

function hash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function recordId(input: SlackAgentSessionKey): string {
  return `agent-status:${hash([input.teamId, input.agentId, input.channelId, input.threadTs])}`;
}

function intentId(input: SlackAgentStatusIntentInput): string {
  return `status-intent:${hash([
    input.teamId,
    input.agentId,
    input.channelId,
    input.threadTs,
    input.authority,
    input.sourceTs,
    input.sequence,
    input.status,
    input.createSession ?? null,
  ])}`;
}

function sourceOrder(input: Pick<SlackAgentStatusIntentInput, "sourceTs" | "sequence">): [bigint, number] {
  const [seconds = "0", fraction = ""] = input.sourceTs.split(".");
  return [BigInt(seconds) * 1_000_000n + BigInt(fraction.padEnd(6, "0")), input.sequence];
}

function compareSource(
  left: Pick<SlackAgentStatusIntentInput, "sourceTs" | "sequence">,
  right: Pick<SlackAgentStatusIntentInput, "sourceTs" | "sequence">,
): number {
  const [leftTs, leftSequence] = sourceOrder(left);
  const [rightTs, rightSequence] = sourceOrder(right);
  if (leftTs === rightTs) return leftSequence - rightSequence;
  return leftTs < rightTs ? -1 : 1;
}

function sameSession(record: SlackAgentStatusIntentRecord, input: SlackAgentSessionKey): boolean {
  return (
    record.teamId === input.teamId &&
    record.agentId === input.agentId &&
    record.channelId === input.channelId &&
    record.threadTs === input.threadTs
  );
}

function exactClaim(record: SlackAgentStatusIntentRecord, claim: SlackAgentStatusIntentClaim): boolean {
  return (
    sameSession(record, claim) &&
    record.intentId === claim.intentId &&
    record.generation === claim.generation &&
    record.state === "claimed" &&
    record.lease?.claimId === claim.claimId &&
    record.lease.generation === claim.generation &&
    record.lease.expiresAt === claim.leaseExpiresAt
  );
}

function safeErrorCode(value: unknown): string {
  const parsed = bounded(value)?.toLowerCase();
  return parsed && SAFE_ERROR_CODES.has(parsed) ? parsed : "provider_error";
}

export function createSlackAgentStatusIntentStore(
  backing: DurableMap<SlackAgentStatusIntentRecord>,
  now: () => number = Date.now,
): SlackAgentStatusIntentStore {
  const update = backing.update?.bind(backing);
  const insertIfAbsent = backing.insertIfAbsent?.bind(backing);
  if (!update || !insertIfAbsent) throw new Error("Slack Agent status intent storage requires atomic durable updates");

  return {
    async enqueue(raw) {
      const input = normalizeInput(raw);
      if (!input) throw new Error("invalid Slack Agent status intent");
      const id = recordId(input);
      const nextIntentId = intentId(input);
      const createdAt = now();
      const initial: SlackAgentStatusIntentRecord = {
        ...input,
        id,
        intentId: nextIntentId,
        state: "pending",
        generation: 1,
        attempts: 0,
        nextAttemptAt: createdAt,
        createdAt,
        updatedAt: createdAt,
      };
      if (await insertIfAbsent(id, initial)) return { disposition: "accepted", record: initial };
      let disposition: "accepted" | "replayed" | "superseded" = "accepted";
      const stored = await update(id, (current) => {
        if (!sameSession(current, input)) throw new Error("Slack Agent status intent identity collision");
        const order = compareSource(input, current);
        if (order < 0) {
          disposition = "superseded";
          return current;
        }
        if (order === 0) {
          if (current.intentId !== nextIntentId) throw new Error("Slack Agent status intent source collision");
          disposition = "replayed";
          return current.state === "pending" && current.nextAttemptAt > createdAt
            ? { ...current, nextAttemptAt: createdAt, updatedAt: createdAt }
            : current;
        }
        return {
          ...input,
          id,
          intentId: nextIntentId,
          state: "pending" as const,
          generation: current.generation + 1,
          attempts: 0,
          nextAttemptAt: createdAt,
          createdAt: current.createdAt,
          updatedAt: createdAt,
        };
      });
      if (!stored) throw new Error("Slack Agent status intent disappeared during admission");
      return { disposition, record: stored };
    },

    async claimDue(input) {
      const teamId = bounded(input.teamId);
      const agentId = bounded(input.agentId);
      if (!teamId || !agentId || !Number.isSafeInteger(input.limit) || input.limit < 1) return [];
      const scanAt = now();
      const claims: SlackAgentStatusIntentClaim[] = [];
      for (const [id, candidate] of await backing.entries()) {
        if (claims.length >= Math.min(100, input.limit)) break;
        if (candidate.teamId !== teamId || candidate.agentId !== agentId) continue;
        if (candidate.state === "resolved") continue;
        if (candidate.state === "pending" && candidate.nextAttemptAt > scanAt) continue;
        if (candidate.state === "claimed" && (candidate.lease?.expiresAt ?? 0) > scanAt) continue;
        const claimId = randomUUID();
        let acquired = false;
        const stored = await update(id, (current) => {
          if (current.teamId !== teamId || current.agentId !== agentId) return current;
          if (current.state === "resolved") return current;
          if (current.state === "pending" && current.nextAttemptAt > scanAt) return current;
          if (current.state === "claimed" && (current.lease?.expiresAt ?? 0) > scanAt) return current;
          acquired = true;
          return {
            ...current,
            state: "claimed" as const,
            lease: { claimId, generation: current.generation, expiresAt: scanAt + CLAIM_LEASE_MS },
            updatedAt: scanAt,
          };
        });
        if (!acquired || !stored?.lease || stored.lease.claimId !== claimId) continue;
        claims.push({
          teamId: stored.teamId,
          agentId: stored.agentId,
          channelId: stored.channelId,
          threadTs: stored.threadTs,
          authority: stored.authority,
          sourceTs: stored.sourceTs,
          sequence: stored.sequence,
          status: stored.status,
          ...(stored.createSession ? { createSession: stored.createSession } : {}),
          id: stored.id,
          intentId: stored.intentId,
          generation: stored.generation,
          attempts: stored.attempts,
          claimId,
          leaseExpiresAt: stored.lease.expiresAt,
        });
      }
      return claims;
    },

    async complete(claim) {
      let completed = false;
      const completedAt = now();
      await update(claim.id, (record) => {
        if (!exactClaim(record, claim)) return record;
        completed = true;
        return {
          ...record,
          state: "resolved" as const,
          lease: undefined,
          completedAt,
          updatedAt: completedAt,
        };
      });
      return completed;
    },

    async defer(claim, input) {
      if (!Number.isSafeInteger(input.retryAt) || input.retryAt < 0) return null;
      let applied = false;
      const deferredAt = now();
      const stored = await update(claim.id, (record) => {
        if (!exactClaim(record, claim)) return record;
        applied = true;
        return {
          ...record,
          state: "pending" as const,
          nextAttemptAt: Math.max(deferredAt, input.retryAt),
          lease: undefined,
          lastErrorCode: safeErrorCode(input.errorCode),
          updatedAt: deferredAt,
        };
      });
      return applied ? (stored ?? null) : null;
    },

    async claimActive(claim) {
      const record = await backing.get(claim.id);
      return !!record && exactClaim(record, claim);
    },

    async fail(claim, input) {
      if (!Number.isSafeInteger(input.retryAt) || input.retryAt < 0) return null;
      let applied = false;
      const failedAt = now();
      const stored = await update(claim.id, (record) => {
        if (!exactClaim(record, claim)) return record;
        applied = true;
        const attempts = Math.min(Number.MAX_SAFE_INTEGER, record.attempts + 1);
        return {
          ...record,
          state: "pending" as const,
          attempts,
          nextAttemptAt: Math.max(failedAt, input.retryAt),
          lease: undefined,
          lastErrorCode: safeErrorCode(input.errorCode),
          updatedAt: failedAt,
        };
      });
      return applied ? (stored ?? null) : null;
    },

    async reopenCurrentAfterStaleEffect(claim, input) {
      if (!Number.isSafeInteger(input.retryAt) || input.retryAt < 0) return null;
      let reopened = false;
      const reopenedAt = now();
      const stored = await update(claim.id, (record) => {
        if (!sameSession(record, claim) || record.generation <= claim.generation) return record;
        if (record.state === "pending" || record.state === "claimed") {
          reopened = true;
          return record;
        }
        reopened = true;
        return {
          ...record,
          state: "pending" as const,
          generation: record.generation + 1,
          attempts: 0,
          nextAttemptAt: Math.max(reopenedAt, input.retryAt),
          lease: undefined,
          completedAt: undefined,
          lastErrorCode: "stale_provider_effect",
          updatedAt: reopenedAt,
        };
      });
      return reopened ? (stored ?? null) : null;
    },

    async get(input) {
      const normalized = normalizeInput({
        teamId: input.teamId,
        agentId: input.agentId,
        channelId: input.channelId,
        threadTs: input.threadTs,
        authority: { kind: "binding", token: "lookup" },
        sourceTs: input.threadTs,
        sequence: 0,
        status: "active",
      });
      if (!normalized) return null;
      const record = await backing.get(recordId(normalized));
      return record && sameSession(record, normalized) ? record : null;
    },
  };
}
