import { createHash, randomUUID } from "node:crypto";
import type { DurableMap } from "../persistence/durable-map.ts";

const MAX_ID = 256;
const CONTINUATION_LEASE_MS = 60_000;

export type SlackApprovalActionId = "hilo_allow_once" | "hilo_allow_session" | "hilo_allow_always" | "hilo_deny";

export interface SlackApprovalAuthorityKey {
  teamId: string;
  agentId: string;
  requesterUserId: string;
  requestId: string;
}

export interface SlackApprovalAuthority extends SlackApprovalAuthorityKey {
  channelId: string;
  messageTs: string;
  createdAt: number;
  recovery?: SlackApprovalRecoveryContext;
  continuation?: SlackApprovalContinuation;
}

export interface SlackApprovalRecoveryContext {
  command: string;
  reason?: string;
  purpose?: string;
  summary?: string;
  grantModes?: { session: boolean; always: boolean };
  approvalRequesterUserId?: string;
  nativeAgentSession?: SlackApprovalNativeAgentSession;
  agentRequest?: SlackApprovalAgentRequestRecovery;
  request: Record<string, unknown>;
}

export interface SlackApprovalNativeAgentSession {
  teamId: string;
  agentId: string;
  channelId: string;
  threadTs: string;
}

export interface SlackApprovalAgentRequestRecovery {
  requesterId: string;
  targetUserId: string;
  targetDisplayName?: string;
  originChannel: string;
  originConversationKind?: "dm" | "channel" | "group";
  originThreadTs?: string;
  originThreadOnly: boolean;
  originChannelName?: string;
  originStatusTs?: string;
  dmChannel: string;
  dmMessageTs?: string;
  task: string;
  originAgentLabel: string;
  targetAgentLabel: string;
  originResultIdempotencyKey?: string;
}

export interface SlackApprovalContinuation {
  actionId: SlackApprovalActionId;
  actionTs: string;
  clickerUserId: string;
  idempotencyKey: string;
  state: "admitted" | "submitted" | "settled";
  claimId?: string;
  leaseExpiresAt?: number;
  generation: number;
  runId?: string;
  createdAt: number;
  updatedAt: number;
}

export interface SlackApprovalContinuationClaim extends SlackApprovalAuthorityKey {
  channelId: string;
  messageTs: string;
  actionId: SlackApprovalActionId;
  actionTs: string;
  clickerUserId: string;
  idempotencyKey: string;
  claimId: string;
  generation: number;
  leaseExpiresAt: number;
  runId?: string;
}

export type SlackApprovalContinuationAdmission =
  | { acquired: true; resumed: boolean; claim: SlackApprovalContinuationClaim }
  | { acquired: false; reason: "busy" | "conflict" | "settled"; continuation: SlackApprovalContinuation };

export interface SlackApprovalContinuationInput extends SlackApprovalAuthorityKey {
  channelId: string;
  messageTs: string;
  actionId: SlackApprovalActionId;
  actionTs: string;
  clickerUserId: string;
}

export interface SlackApprovalSubmittedContinuation extends SlackApprovalContinuationInput {
  runId: string;
  leaseExpiresAt: number;
}

export interface SlackApprovalPendingContinuation {
  kind: "slack_approval_continuation";
  key: SlackApprovalAuthorityKey;
  generation: number;
  createdAt: number;
  provisionalId?: string;
  claim?: SlackApprovalContinuationClaim;
  runId?: string;
}

export interface SlackApprovalContinuationMigration {
  kind: "slack_approval_continuation_migration";
  teamId: string;
  agentId: string;
  startedAt: number;
  nextScanAt: number;
  scanUntil: number;
  scanClaimId?: string;
  scanLeaseExpiresAt?: number;
}

export type SlackApprovalContinuationRecord = SlackApprovalPendingContinuation | SlackApprovalContinuationMigration;

export interface SlackApprovalAuthorityStore {
  bind(input: Omit<SlackApprovalAuthority, "createdAt">): Promise<boolean>;
  get(input: SlackApprovalAuthorityKey): Promise<SlackApprovalAuthority | null>;
  admitContinuation(input: SlackApprovalContinuationInput): Promise<SlackApprovalContinuationAdmission>;
  markContinuationSubmitted(input: SlackApprovalContinuationClaim & { runId: string }): Promise<boolean>;
  renewContinuation(input: SlackApprovalContinuationClaim): Promise<boolean>;
  settleContinuation(input: SlackApprovalContinuationClaim): Promise<boolean>;
  releaseContinuation(input: SlackApprovalContinuationClaim): Promise<boolean>;
  recoverableContinuations(input: {
    teamId: string;
    agentId: string;
    limit: number;
  }): Promise<SlackApprovalContinuationInput[]>;
  submittedContinuations(input: { teamId: string; agentId: string }): Promise<SlackApprovalSubmittedContinuation[]>;
}

function bounded(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed && trimmed.length <= MAX_ID ? trimmed : null;
}

function normalizeKey(input: SlackApprovalAuthorityKey): SlackApprovalAuthorityKey | null {
  const teamId = bounded(input.teamId);
  const agentId = bounded(input.agentId);
  const requesterUserId = bounded(input.requesterUserId);
  const requestId = bounded(input.requestId);
  return teamId && agentId && requesterUserId && requestId ? { teamId, agentId, requesterUserId, requestId } : null;
}

function channel(value: unknown): string | null {
  const parsed = bounded(value);
  return parsed && /^[CDG][A-Z0-9]+$/.test(parsed) ? parsed : null;
}

function timestamp(value: unknown): string | null {
  const parsed = bounded(value);
  return parsed && /^\d+(?:\.\d{1,6})?$/.test(parsed) ? parsed : null;
}

function recordKey(key: SlackApprovalAuthorityKey): string {
  return `approval:${createHash("sha256")
    .update(JSON.stringify([key.teamId, key.agentId, key.requesterUserId, key.requestId]))
    .digest("hex")}`;
}

function pendingKey(key: SlackApprovalAuthorityKey): string {
  return `submitted-approval:${createHash("sha256")
    .update(JSON.stringify([key.teamId, key.agentId, key.requesterUserId, key.requestId]))
    .digest("hex")}`;
}

function sameKey(record: SlackApprovalAuthority, key: SlackApprovalAuthorityKey): boolean {
  return (
    record.teamId === key.teamId &&
    record.agentId === key.agentId &&
    record.requesterUserId === key.requesterUserId &&
    record.requestId === key.requestId
  );
}

function sameAuthorityKey(left: SlackApprovalAuthorityKey, right: SlackApprovalAuthorityKey): boolean {
  return (
    left.teamId === right.teamId &&
    left.agentId === right.agentId &&
    left.requesterUserId === right.requesterUserId &&
    left.requestId === right.requestId
  );
}

function actionId(value: unknown): SlackApprovalActionId | null {
  return value === "hilo_allow_once" ||
    value === "hilo_allow_session" ||
    value === "hilo_allow_always" ||
    value === "hilo_deny"
    ? value
    : null;
}

function continuationIdempotencyKey(key: SlackApprovalAuthorityKey, channelId: string, messageTs: string): string {
  return `slack-approval:${createHash("sha256")
    .update(JSON.stringify([key.teamId, key.agentId, key.requesterUserId, key.requestId, channelId, messageTs]))
    .digest("hex")}`;
}

function exactContinuationClaim(
  record: SlackApprovalAuthority,
  claim: SlackApprovalContinuationClaim,
): record is SlackApprovalAuthority & { continuation: SlackApprovalContinuation } {
  const continuation = record.continuation;
  return (
    sameKey(record, claim) &&
    record.channelId === claim.channelId &&
    record.messageTs === claim.messageTs &&
    continuation?.actionId === claim.actionId &&
    continuation.actionTs === claim.actionTs &&
    continuation.clickerUserId === claim.clickerUserId &&
    continuation.idempotencyKey === claim.idempotencyKey &&
    continuation.claimId === claim.claimId &&
    continuation.generation === claim.generation
  );
}

export function createSlackApprovalAuthorityStore(
  backing: DurableMap<SlackApprovalAuthority>,
  now: () => number = Date.now,
  pendingBacking: DurableMap<SlackApprovalContinuationRecord> = backing as unknown as DurableMap<SlackApprovalContinuationRecord>,
): SlackApprovalAuthorityStore {
  if (!backing.update) throw new Error("Slack approval authority storage requires atomic durable updates");
  const update = backing.update.bind(backing);
  if (!pendingBacking.update) throw new Error("Slack approval continuation storage requires atomic durable updates");
  const updatePending = pendingBacking.update.bind(pendingBacking);
  async function migrateLegacyContinuations(teamId: string, agentId: string): Promise<void> {
    const migrationId = `approval-continuation-migration:${createHash("sha256")
      .update(JSON.stringify([teamId, agentId]))
      .digest("hex")}`;
    const startedAt = now();
    await pendingBacking.putIfAbsent(migrationId, {
      kind: "slack_approval_continuation_migration",
      teamId,
      agentId,
      startedAt,
      nextScanAt: 0,
      scanUntil: startedAt + 86_400_000,
    });
    while (true) {
      const attemptedAt = now();
      const scanClaimId = randomUUID();
      let claimed = false;
      let waiting = false;
      let done = false;
      await updatePending(migrationId, (record) => {
        if (
          record.kind !== "slack_approval_continuation_migration" ||
          record.teamId !== teamId ||
          record.agentId !== agentId
        ) {
          done = true;
          return record;
        }
        if (record.scanClaimId && (record.scanLeaseExpiresAt ?? 0) > attemptedAt) {
          waiting = true;
          return record;
        }
        if (record.scanUntil < attemptedAt || record.nextScanAt > attemptedAt) {
          done = true;
          return record;
        }
        claimed = true;
        return { ...record, scanClaimId, scanLeaseExpiresAt: attemptedAt + 60_000 };
      });
      if (done) return;
      if (!claimed) {
        if (!waiting) return;
        await new Promise((resolve) => setTimeout(resolve, 25));
        continue;
      }
      try {
        for (const authority of await backing.all()) {
          if (
            authority.teamId !== teamId ||
            authority.agentId !== agentId ||
            !authority.continuation ||
            authority.continuation.state === "settled"
          ) {
            continue;
          }
          const key = {
            teamId: authority.teamId,
            agentId: authority.agentId,
            requesterUserId: authority.requesterUserId,
            requestId: authority.requestId,
          };
          await pendingBacking.putIfAbsent(pendingKey(key), {
            kind: "slack_approval_continuation",
            key,
            generation: Number.isSafeInteger(authority.continuation.generation) ? authority.continuation.generation : 0,
            createdAt: attemptedAt,
          });
        }
      } catch (error) {
        await updatePending(migrationId, (record) => {
          if (record.kind !== "slack_approval_continuation_migration" || record.scanClaimId !== scanClaimId)
            return record;
          const { scanClaimId: _claim, scanLeaseExpiresAt: _lease, ...rest } = record;
          return { ...rest, nextScanAt: 0 };
        });
        throw error;
      }
      await updatePending(migrationId, (record) => {
        if (record.kind !== "slack_approval_continuation_migration" || record.scanClaimId !== scanClaimId)
          return record;
        const { scanClaimId: _claim, scanLeaseExpiresAt: _lease, ...rest } = record;
        return { ...rest, nextScanAt: now() + 60_000 };
      });
      return;
    }
  }
  async function activeContinuations(
    teamId: string,
    agentId: string,
  ): Promise<
    Array<SlackApprovalContinuationInput & { state: "admitted" | "submitted"; leaseExpiresAt: number; runId?: string }>
  > {
    await migrateLegacyContinuations(teamId, agentId);
    const active: Array<
      SlackApprovalContinuationInput & { state: "admitted" | "submitted"; leaseExpiresAt: number; runId?: string }
    > = [];
    for (const pending of await pendingBacking.all()) {
      if (
        pending.kind !== "slack_approval_continuation" ||
        pending.key.teamId !== teamId ||
        pending.key.agentId !== agentId
      ) {
        continue;
      }
      const id = recordKey(pending.key);
      let authority = await backing.get(id);
      if (
        authority &&
        pending.claim &&
        pending.runId &&
        exactContinuationClaim(authority, pending.claim) &&
        authority.continuation.state === "admitted" &&
        !authority.continuation.runId
      ) {
        authority = await update(id, (record) =>
          exactContinuationClaim(record, pending.claim!) &&
          record.continuation.state === "admitted" &&
          !record.continuation.runId
            ? {
                ...record,
                continuation: {
                  ...record.continuation,
                  state: "submitted",
                  runId: pending.runId,
                  leaseExpiresAt: pending.claim!.leaseExpiresAt,
                  updatedAt: now(),
                },
              }
            : record,
        );
      }
      const current = authority?.continuation;
      if (
        !authority ||
        !current ||
        !sameKey(authority, pending.key) ||
        current.state === "settled" ||
        (current.state === "submitted" && !current.runId)
      ) {
        if (!current && pending.provisionalId && now() - pending.createdAt <= CONTINUATION_LEASE_MS) continue;
        await pendingBacking.deleteIf?.(
          pendingKey(pending.key),
          (record) =>
            record.kind === "slack_approval_continuation" &&
            sameAuthorityKey(record.key, pending.key) &&
            record.generation === pending.generation &&
            record.provisionalId === pending.provisionalId &&
            record.claim?.claimId === pending.claim?.claimId &&
            record.runId === pending.runId,
        );
        continue;
      }
      active.push({
        teamId: authority.teamId,
        agentId: authority.agentId,
        requesterUserId: authority.requesterUserId,
        requestId: authority.requestId,
        channelId: authority.channelId,
        messageTs: authority.messageTs,
        actionId: current.actionId,
        actionTs: current.actionTs,
        clickerUserId: current.clickerUserId,
        state: current.state,
        leaseExpiresAt: current.leaseExpiresAt ?? 0,
        ...(current.runId ? { runId: current.runId } : {}),
      });
    }
    return active.sort((left, right) => left.leaseExpiresAt - right.leaseExpiresAt);
  }
  return {
    async bind(input) {
      const key = normalizeKey(input);
      const channelId = channel(input.channelId);
      const messageTs = timestamp(input.messageTs);
      if (!key || !channelId || !messageTs) return false;
      const candidate: SlackApprovalAuthority = { ...key, channelId, messageTs, createdAt: now() };
      if (input.recovery) candidate.recovery = input.recovery;
      const id = recordKey(key);
      let stored = await backing.putIfAbsent(id, candidate);
      if (
        input.recovery &&
        sameKey(stored, key) &&
        stored.channelId === channelId &&
        stored.messageTs === messageTs &&
        !stored.recovery
      ) {
        const enriched = await update(id, (record) =>
          sameKey(record, key) && record.channelId === channelId && record.messageTs === messageTs && !record.recovery
            ? { ...record, recovery: input.recovery }
            : record,
        );
        if (enriched) stored = enriched;
      }
      return sameKey(stored, key) && stored.channelId === channelId && stored.messageTs === messageTs;
    },
    async get(input) {
      const key = normalizeKey(input);
      if (!key) return null;
      const stored = await backing.get(recordKey(key));
      return stored && sameKey(stored, key) ? stored : null;
    },
    async admitContinuation(input) {
      const key = normalizeKey(input);
      const channelId = channel(input.channelId);
      const messageTs = timestamp(input.messageTs);
      const selectedAction = actionId(input.actionId);
      const actionTs = timestamp(input.actionTs);
      const clickerUserId = bounded(input.clickerUserId);
      if (!key || !channelId || !messageTs || !selectedAction || !actionTs || !clickerUserId) {
        throw new Error("invalid Slack approval continuation authority");
      }
      const pendingId = pendingKey(key);
      const claimId = randomUUID();
      const admittedAt = now();
      const provisionalId = randomUUID();
      await pendingBacking.putIfAbsent(pendingId, {
        kind: "slack_approval_continuation",
        key,
        generation: 0,
        createdAt: admittedAt,
        provisionalId,
      });
      let acquired = false;
      let resumed = false;
      let blocked: SlackApprovalContinuation | undefined;
      const stored = await update(recordKey(key), (record) => {
        if (!sameKey(record, key) || record.channelId !== channelId || record.messageTs !== messageTs) return record;
        const current = record.continuation;
        if (current) {
          if (current.actionId !== selectedAction || current.clickerUserId !== clickerUserId) {
            blocked = current;
            return record;
          }
          if (current.state === "settled") {
            blocked = current;
            return record;
          }
          if ((current.leaseExpiresAt ?? 0) > admittedAt) {
            blocked = current;
            return record;
          }
          acquired = true;
          resumed = true;
          return {
            ...record,
            continuation: {
              ...current,
              ...(current.state === "admitted" ? { actionTs } : {}),
              claimId,
              generation: (Number.isSafeInteger(current.generation) ? current.generation : 0) + 1,
              leaseExpiresAt: admittedAt + CONTINUATION_LEASE_MS,
              updatedAt: admittedAt,
            },
          };
        }
        acquired = true;
        const continuation: SlackApprovalContinuation = {
          actionId: selectedAction,
          actionTs,
          clickerUserId,
          idempotencyKey: continuationIdempotencyKey(key, channelId, messageTs),
          state: "admitted",
          claimId,
          generation: 1,
          leaseExpiresAt: admittedAt + CONTINUATION_LEASE_MS,
          createdAt: admittedAt,
          updatedAt: admittedAt,
        };
        return { ...record, continuation };
      });
      const continuation = stored?.continuation ?? blocked;
      if (!stored || !continuation || !sameKey(stored, key)) {
        await pendingBacking.deleteIf?.(
          pendingId,
          (record) => record.kind === "slack_approval_continuation" && record.provisionalId === provisionalId,
        );
        throw new Error("Slack approval continuation authority was not bound to this message");
      }
      if (continuation.state !== "settled") {
        await updatePending(pendingId, (record) => {
          if (record.kind !== "slack_approval_continuation" || !sameAuthorityKey(record.key, key)) return record;
          if (record.generation > continuation.generation) return record;
          if (record.generation === continuation.generation && record.runId) return record;
          return {
            kind: "slack_approval_continuation",
            key,
            generation: continuation.generation,
            createdAt: record.createdAt,
          };
        });
      }
      if (!acquired || continuation.claimId !== claimId || continuation.leaseExpiresAt === undefined) {
        let reason: "busy" | "conflict" | "settled" = "busy";
        if (continuation.actionId !== selectedAction || continuation.clickerUserId !== clickerUserId)
          reason = "conflict";
        else if (continuation.state === "settled") reason = "settled";
        if (reason === "settled") {
          await pendingBacking.deleteIf?.(
            pendingId,
            (record) =>
              record.kind === "slack_approval_continuation" &&
              sameAuthorityKey(record.key, key) &&
              record.generation <= continuation.generation,
          );
        }
        return { acquired: false, reason, continuation };
      }
      return {
        acquired: true,
        resumed,
        claim: {
          ...key,
          channelId,
          messageTs,
          actionId: continuation.actionId,
          actionTs: continuation.actionTs,
          clickerUserId,
          idempotencyKey: continuation.idempotencyKey,
          claimId,
          generation: continuation.generation,
          leaseExpiresAt: continuation.leaseExpiresAt,
          ...(continuation.runId ? { runId: continuation.runId } : {}),
        },
      };
    },
    async markContinuationSubmitted(input) {
      const runId = bounded(input.runId);
      if (!runId) return false;
      const pending: SlackApprovalPendingContinuation = {
        kind: "slack_approval_continuation",
        key: {
          teamId: input.teamId,
          agentId: input.agentId,
          requesterUserId: input.requesterUserId,
          requestId: input.requestId,
        },
        generation: input.generation,
        createdAt: now(),
        claim: input,
        runId,
      };
      const pendingId = pendingKey(input);
      const existingPending = await pendingBacking.putIfAbsent(pendingId, pending);
      if (existingPending.kind !== "slack_approval_continuation") {
        throw new Error("Slack approval continuation storage key was superseded");
      }
      if ((existingPending.claim?.generation ?? 0) <= input.generation) {
        await updatePending(pendingId, (record) =>
          record.kind === "slack_approval_continuation" && record.generation <= input.generation ? pending : record,
        );
      }
      let submitted = false;
      await update(recordKey(input), (record) => {
        if (!exactContinuationClaim(record, input)) return record;
        if (record.continuation.runId && record.continuation.runId !== runId) return record;
        submitted = true;
        return {
          ...record,
          continuation: {
            ...record.continuation,
            state: "submitted",
            runId,
            leaseExpiresAt: now() + CONTINUATION_LEASE_MS,
            updatedAt: now(),
          },
        };
      });
      if (!submitted) {
        await pendingBacking.deleteIf?.(
          pendingId,
          (record) =>
            record.kind === "slack_approval_continuation" &&
            record.runId === runId &&
            record.claim?.claimId === input.claimId &&
            record.claim.generation === input.generation,
        );
      }
      return submitted;
    },
    async renewContinuation(input) {
      let renewed = false;
      const renewedAt = now();
      await update(recordKey(input), (record) => {
        if (!exactContinuationClaim(record, input) || record.continuation.state === "settled") return record;
        renewed = true;
        return {
          ...record,
          continuation: {
            ...record.continuation,
            leaseExpiresAt: renewedAt + CONTINUATION_LEASE_MS,
            updatedAt: renewedAt,
          },
        };
      });
      return renewed;
    },
    async settleContinuation(input) {
      let settled = false;
      await update(recordKey(input), (record) => {
        if (!exactContinuationClaim(record, input)) return record;
        settled = true;
        return {
          ...record,
          continuation: {
            ...record.continuation,
            state: "settled",
            claimId: undefined,
            leaseExpiresAt: undefined,
            updatedAt: now(),
          },
        };
      });
      if (settled) await pendingBacking.delete(pendingKey(input)).catch(() => undefined);
      return settled;
    },
    async releaseContinuation(input) {
      let released = false;
      await update(recordKey(input), (record) => {
        if (!exactContinuationClaim(record, input) || record.continuation.state !== "admitted") return record;
        released = true;
        return {
          ...record,
          continuation: {
            ...record.continuation,
            claimId: undefined,
            leaseExpiresAt: undefined,
            updatedAt: now(),
          },
        };
      });
      return released;
    },
    async recoverableContinuations(input) {
      const teamId = bounded(input.teamId);
      const agentId = bounded(input.agentId);
      if (!teamId || !agentId || !Number.isSafeInteger(input.limit) || input.limit <= 0) return [];
      return (await activeContinuations(teamId, agentId))
        .filter((record) => record.leaseExpiresAt <= now())
        .slice(0, input.limit)
        .map(({ runId: _runId, state: _state, leaseExpiresAt: _leaseExpiresAt, ...record }) => record);
    },
    async submittedContinuations(input) {
      const teamId = bounded(input.teamId);
      const agentId = bounded(input.agentId);
      if (!teamId || !agentId) return [];
      return (await activeContinuations(teamId, agentId))
        .filter(
          (record): record is typeof record & { state: "submitted"; runId: string } =>
            record.state === "submitted" && !!record.runId,
        )
        .map(({ state: _state, ...record }) => record);
    },
  };
}
