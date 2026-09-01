import { createHash, randomUUID } from "node:crypto";
import type { DurableMap } from "../persistence/durable-map.ts";

const MAX_ID = 256;
const MAX_RUNS = 16;
const MAX_BINDINGS = 16;
const MAX_STOPS = 16;
const MAX_TITLE = 200;
const SUBMISSION_PENDING_MS = 300_000;
const PROVIDER_WRITE_LEASE_MS = 60_000;
const PRESENTATION_LEASE_MS = 60_000;

export type SlackAgentSessionStatus = "processing" | "active" | "suspended" | "closed";

export interface SlackAgentSessionKey {
  teamId: string;
  agentId: string;
  channelId: string;
  threadTs: string;
}

export interface SlackAgentSessionBinding {
  token: string;
  ownerUserId: string;
  status: SlackAgentSessionStatus;
  triggerTs: string;
  coreThreadRef: string;
  authorityMessageTs: string;
  runIds: string[];
  submissionState?: "idle" | "pending" | "submitted" | "settled";
  submissionPendingUntil?: number;
  streamTs?: string;
  cancelEventId?: string;
  cancelRequestedAt?: string;
  finishedAt?: number;
  streamStopState?: "listed" | "late";
  approvalClaim?: { claimId: string; generation: number };
  presentation?: {
    runId: string;
    state: "pending" | "claimed" | "settled";
    generation: number;
    claimId?: string;
    leaseExpiresAt?: number;
  };
}

export interface SlackAgentPresentationClaim extends SlackAgentSessionKey {
  token: string;
  runId: string;
  ownerUserId: string;
  triggerTs: string;
  authorityMessageTs: string;
  coreThreadRef: string;
  claimId: string;
  generation: number;
  leaseExpiresAt: number;
}

export interface SlackAgentRetryWindow {
  method: string;
  notBefore: number;
  attempts: number;
  generation: number;
}

export interface SlackAgentProviderWriteClaim {
  teamId: string;
  agentId: string;
  channelId: string;
  threadTs: string;
  method: string;
  claimId: string;
  generation: number;
  leaseExpiresAt: number;
}

export type SlackAgentProviderWriteClaimResult =
  | { acquired: true; claim: SlackAgentProviderWriteClaim }
  | { acquired: false; notBefore: number; reason: "retry_window" | "lease_held"; sameSession: boolean };

interface SlackAgentProviderWriteLease {
  claimId: string;
  generation: number;
  expiresAt: number;
  channelId: string;
  threadTs: string;
}

export interface SlackAgentStopEvent {
  eventId: string;
  eventTs: string;
  stoppedByUserId: string;
  streamingMessageTs: string[];
  bindingTokens: string[];
  applicable: boolean;
  state: "pending" | "acknowledged";
  confirmationTs?: string;
}

interface SlackAgentStopBoundary {
  eventId: string;
  eventTs: string;
}

export interface SlackAgentSessionRecord extends SlackAgentSessionKey {
  status: SlackAgentSessionStatus;
  bindings: SlackAgentSessionBinding[];
  stopEvents: SlackAgentStopEvent[];
  stopThrough?: SlackAgentStopBoundary;
  title?: string;
  titleChangedBy?: string;
  titleEventTs?: string;
  sessionInitialized?: boolean;
  updatedAt: number;
}

export interface SlackAgentBindingResult {
  accepted: boolean;
  cancelled: boolean;
  created: boolean;
  binding: SlackAgentSessionBinding | null;
  record: SlackAgentSessionRecord | null;
}

export interface SlackAgentStopResult {
  record: SlackAgentSessionRecord;
  event: SlackAgentStopEvent;
  replay: boolean;
}

export interface SlackAgentSessionStore {
  begin(
    input: SlackAgentSessionKey & {
      ownerUserId: string;
      token: string;
      triggerTs: string;
      coreThreadRef: string;
      authorityMessageTs: string;
      approvalClaim?: { claimId: string; generation: number };
    },
  ): Promise<SlackAgentBindingResult>;
  prepareSubmission(input: SlackAgentSessionKey & { token: string }): Promise<SlackAgentBindingResult>;
  bindRun(input: SlackAgentSessionKey & { token: string; runId: string }): Promise<SlackAgentBindingResult>;
  claimPresentation(
    input: SlackAgentSessionKey & { token: string; runId: string },
  ): Promise<SlackAgentPresentationClaim | null>;
  claimDuePresentations(input: {
    teamId: string;
    agentId: string;
    limit: number;
  }): Promise<SlackAgentPresentationClaim[]>;
  presentationClaimActive(claim: SlackAgentPresentationClaim): Promise<boolean>;
  renewPresentation(claim: SlackAgentPresentationClaim): Promise<SlackAgentPresentationClaim | null>;
  settlePresentation(claim: SlackAgentPresentationClaim, outcome: "delivered" | "cancelled_clean"): Promise<boolean>;
  releasePresentation(claim: SlackAgentPresentationClaim): Promise<boolean>;
  bindStream(input: SlackAgentSessionKey & { token: string; streamTs: string }): Promise<SlackAgentBindingResult>;
  cancelled(input: SlackAgentSessionKey & { token: string; runId?: string }): Promise<boolean>;
  cancellationLatched(input: SlackAgentSessionKey & { token: string }): Promise<boolean>;
  finish(
    input: SlackAgentSessionKey & {
      token: string;
      status: SlackAgentSessionStatus;
      approvalClaim?: { claimId: string; generation: number };
    },
  ): Promise<boolean>;
  complete(
    input: SlackAgentSessionKey & { token: string; approvalClaim?: { claimId: string; generation: number } },
  ): Promise<boolean>;
  retryWindow(input: SlackAgentSessionKey & { method: string }): Promise<SlackAgentRetryWindow | null>;
  claimProviderWrite(input: SlackAgentSessionKey & { method: string }): Promise<SlackAgentProviderWriteClaimResult>;
  deferProviderWrite(
    input: SlackAgentProviderWriteClaim & { notBefore: number },
  ): Promise<{ applied: boolean; window: SlackAgentRetryWindow | null }>;
  completeProviderWrite(input: SlackAgentProviderWriteClaim): Promise<boolean>;
  releaseProviderWrite(input: SlackAgentProviderWriteClaim): Promise<boolean>;
  recordStop(
    input: SlackAgentSessionKey & {
      eventId: string;
      eventTs: string;
      stoppedByUserId: string;
      streamingMessageTs: string[];
    },
  ): Promise<SlackAgentStopResult>;
  acknowledgeStop(input: SlackAgentSessionKey & { eventId: string; confirmationTs?: string }): Promise<boolean>;
  get(input: SlackAgentSessionKey): Promise<SlackAgentSessionRecord | null>;
  rename(input: {
    teamId: string;
    agentId: string;
    channelId: string;
    threadTs: string;
    changedByUserId: string;
    title: string;
    eventTs: string;
  }): Promise<boolean>;
}

interface StoredSlackAgentSession {
  record: SlackAgentSessionRecord;
}

interface StoredSlackAgentProviderRetry {
  providerRetry: SlackAgentRetryWindow & {
    teamId: string;
    agentId: string;
    updatedAt: number;
    lease?: SlackAgentProviderWriteLease;
  };
}

function bounded(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed && trimmed.length <= MAX_ID ? trimmed : null;
}

function eventTime(value: string): number {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : -1;
}

function timestamp(value: unknown): string | null {
  const parsed = bounded(value);
  return parsed && eventTime(parsed) >= 0 ? parsed : null;
}

function validChannel(value: unknown): string | null {
  const parsed = bounded(value);
  return parsed && /^[CDG][A-Z0-9]+$/.test(parsed) ? parsed : null;
}

function normalizeKey(input: SlackAgentSessionKey): SlackAgentSessionKey | null {
  const teamId = bounded(input.teamId);
  const agentId = bounded(input.agentId);
  const channelId = validChannel(input.channelId);
  const threadTs = timestamp(input.threadTs);
  return teamId && agentId && channelId && threadTs ? { teamId, agentId, channelId, threadTs } : null;
}

function hash(parts: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

export function slackAgentBindingToken(
  key: SlackAgentSessionKey,
  ownerUserId: string,
  triggerTs: string,
  authorityMessageTs: string,
): string {
  return `binding:${hash([
    key.teamId,
    key.agentId,
    ownerUserId,
    key.channelId,
    key.threadTs,
    triggerTs,
    authorityMessageTs,
  ])}`;
}

function recordKey(key: SlackAgentSessionKey): string {
  return `session:${hash([key.teamId, key.agentId, key.channelId, key.threadTs])}`;
}

function providerRetryKey(key: SlackAgentSessionKey, method: string): string {
  return `provider-retry:${hash([key.teamId, key.agentId, method])}`;
}

function normalizeProviderClaim(input: SlackAgentProviderWriteClaim): SlackAgentProviderWriteClaim | null {
  const teamId = bounded(input.teamId);
  const agentId = bounded(input.agentId);
  const method = bounded(input.method);
  const channelId = validChannel(input.channelId);
  const threadTs = timestamp(input.threadTs);
  const claimId = bounded(input.claimId);
  if (
    !teamId ||
    !agentId ||
    !method ||
    !channelId ||
    !threadTs ||
    !claimId ||
    !Number.isSafeInteger(input.generation) ||
    input.generation < 0 ||
    !Number.isSafeInteger(input.leaseExpiresAt) ||
    input.leaseExpiresAt < 0
  ) {
    return null;
  }
  return {
    teamId,
    agentId,
    channelId,
    threadTs,
    method,
    claimId,
    generation: input.generation,
    leaseExpiresAt: input.leaseExpiresAt,
  };
}

function currentGeneration(record: StoredSlackAgentProviderRetry["providerRetry"]): number {
  return Number.isSafeInteger(record.generation) && record.generation >= 0 ? record.generation : 0;
}

function exactProviderLease(
  record: StoredSlackAgentProviderRetry["providerRetry"],
  claim: SlackAgentProviderWriteClaim,
): boolean {
  return (
    record.teamId === claim.teamId &&
    record.agentId === claim.agentId &&
    record.method === claim.method &&
    currentGeneration(record) === claim.generation &&
    record.lease?.claimId === claim.claimId &&
    record.lease.generation === claim.generation &&
    record.lease.expiresAt === claim.leaseExpiresAt &&
    record.lease.channelId === claim.channelId &&
    record.lease.threadTs === claim.threadTs
  );
}

function publicRetryWindow(
  record: StoredSlackAgentProviderRetry["providerRetry"] | undefined,
): SlackAgentRetryWindow | null {
  if (!record || !Number.isSafeInteger(record.notBefore) || record.notBefore <= 0) return null;
  return {
    method: record.method,
    notBefore: record.notBefore,
    attempts: Number.isSafeInteger(record.attempts) && record.attempts >= 0 ? record.attempts : 0,
    generation: currentGeneration(record),
  };
}

function sameKey(record: SlackAgentSessionRecord, key: SlackAgentSessionKey): boolean {
  return (
    record.teamId === key.teamId &&
    record.agentId === key.agentId &&
    record.channelId === key.channelId &&
    record.threadTs === key.threadTs
  );
}

function stopApplies(binding: SlackAgentSessionBinding | undefined, eventTs: string): boolean {
  if (!binding) return false;
  if (binding.cancelRequestedAt) return false;
  if (eventTime(eventTs) < eventTime(binding.triggerTs)) return false;
  if (binding.finishedAt !== undefined && eventTime(eventTs) * 1_000 > binding.finishedAt) return false;
  return true;
}

function latestStopBoundary(record: SlackAgentSessionRecord): SlackAgentStopBoundary | undefined {
  return [
    ...(record.stopThrough ? [record.stopThrough] : []),
    ...record.stopEvents.map(({ eventId, eventTs }) => ({ eventId, eventTs })),
  ].sort((left, right) => eventTime(right.eventTs) - eventTime(left.eventTs))[0];
}

function retainedStopEvents(events: SlackAgentStopEvent[]): SlackAgentStopEvent[] {
  const retainedAcknowledged = new Set(
    events
      .filter((event) => event.state === "acknowledged")
      .slice(-MAX_STOPS)
      .map((event) => event.eventId),
  );
  return events.filter((event) => event.state === "pending" || retainedAcknowledged.has(event.eventId));
}

function sessionStatus(bindings: readonly SlackAgentSessionBinding[]): SlackAgentSessionStatus {
  const live = bindings.filter((binding) => binding.finishedAt === undefined && !binding.cancelRequestedAt);
  if (live.some((binding) => binding.status === "processing")) return "processing";
  if (live.some((binding) => binding.status === "suspended")) return "suspended";
  if (live.some((binding) => binding.status === "active")) return "active";
  if (live.some((binding) => binding.status === "closed")) return "closed";
  return bindings.length > 0 && bindings.every((binding) => binding.status === "closed") ? "closed" : "active";
}

function result(record: SlackAgentSessionRecord | null, token: string, runId?: string): SlackAgentBindingResult {
  const binding = record?.bindings.find((candidate) => candidate.token === token);
  const accepted = !!binding && binding.token === token && (!runId || binding.runIds.includes(runId));
  return {
    accepted,
    cancelled: !accepted || !!binding.cancelRequestedAt,
    created: accepted && record?.sessionInitialized !== true,
    binding: binding ?? null,
    record,
  };
}

function exactPresentationClaim(
  record: SlackAgentSessionRecord,
  claim: SlackAgentPresentationClaim,
): SlackAgentSessionBinding | undefined {
  if (!sameKey(record, claim)) return undefined;
  const binding = record.bindings.find((candidate) => candidate.token === claim.token);
  const presentation = binding?.presentation;
  if (
    !binding ||
    !presentation ||
    presentation.runId !== claim.runId ||
    presentation.state !== "claimed" ||
    presentation.claimId !== claim.claimId ||
    presentation.generation !== claim.generation ||
    presentation.leaseExpiresAt !== claim.leaseExpiresAt
  ) {
    return undefined;
  }
  return binding;
}

function presentationClaim(
  key: SlackAgentSessionKey,
  binding: SlackAgentSessionBinding,
): SlackAgentPresentationClaim | null {
  const presentation = binding.presentation;
  if (
    !presentation ||
    presentation.state !== "claimed" ||
    !presentation.claimId ||
    !Number.isSafeInteger(presentation.generation) ||
    presentation.generation < 1 ||
    !Number.isSafeInteger(presentation.leaseExpiresAt) ||
    presentation.leaseExpiresAt! < 0
  ) {
    return null;
  }
  return {
    ...key,
    token: binding.token,
    runId: presentation.runId,
    ownerUserId: binding.ownerUserId,
    triggerTs: binding.triggerTs,
    authorityMessageTs: binding.authorityMessageTs,
    coreThreadRef: binding.coreThreadRef,
    claimId: presentation.claimId,
    generation: presentation.generation,
    leaseExpiresAt: presentation.leaseExpiresAt!,
  };
}

export function createSlackAgentSessionStore(
  backing: DurableMap<StoredSlackAgentSession | StoredSlackAgentProviderRetry>,
  now: () => number = Date.now,
): SlackAgentSessionStore {
  const sessionBacking = backing as unknown as DurableMap<StoredSlackAgentSession>;
  const retryBacking = backing as unknown as DurableMap<StoredSlackAgentProviderRetry>;
  const update = sessionBacking.update?.bind(sessionBacking);
  if (!update) throw new Error("Slack agent session storage requires atomic durable updates");

  const rejected = (): SlackAgentBindingResult => ({
    accepted: false,
    cancelled: true,
    created: false,
    binding: null,
    record: null,
  });

  return {
    async begin(input) {
      const key = normalizeKey(input);
      const ownerUserId = bounded(input.ownerUserId);
      const token = bounded(input.token);
      const triggerTs = timestamp(input.triggerTs);
      const coreThreadRef = bounded(input.coreThreadRef);
      const authorityMessageTs = timestamp(input.authorityMessageTs);
      const approvalClaim = input.approvalClaim;
      const normalizedApprovalClaim = approvalClaim
        ? {
            claimId: bounded(approvalClaim.claimId),
            generation: approvalClaim.generation,
          }
        : undefined;
      if (
        !key ||
        !ownerUserId ||
        !token ||
        !triggerTs ||
        !coreThreadRef ||
        !authorityMessageTs ||
        (normalizedApprovalClaim &&
          (!normalizedApprovalClaim.claimId ||
            !Number.isSafeInteger(normalizedApprovalClaim.generation) ||
            normalizedApprovalClaim.generation < 1))
      )
        return rejected();
      const id = recordKey(key);
      const initialBinding: SlackAgentSessionBinding = {
        token,
        ownerUserId,
        status: "processing",
        triggerTs,
        coreThreadRef,
        authorityMessageTs,
        runIds: [],
        submissionState: "idle",
        ...(normalizedApprovalClaim
          ? {
              approvalClaim: {
                claimId: normalizedApprovalClaim.claimId!,
                generation: normalizedApprovalClaim.generation,
              },
            }
          : {}),
      };
      const initial: SlackAgentSessionRecord = {
        ...key,
        status: "processing",
        bindings: [initialBinding],
        stopEvents: [],
        updatedAt: now(),
      };
      await sessionBacking.putIfAbsent(id, { record: initial });
      const selectedToken = token;
      let accepted = false;
      const stored = await update(id, (value) => {
        if (!sameKey(value.record, key)) return value;
        const exact = value.record.bindings.find((binding) => binding.token === token);
        if (exact) {
          const currentClaim = exact.approvalClaim;
          if (
            currentClaim &&
            (!normalizedApprovalClaim ||
              normalizedApprovalClaim.generation < currentClaim.generation ||
              (normalizedApprovalClaim.generation === currentClaim.generation &&
                normalizedApprovalClaim.claimId !== currentClaim.claimId))
          ) {
            return value;
          }
          accepted = true;
          const claimed = normalizedApprovalClaim
            ? {
                ...exact,
                approvalClaim: {
                  claimId: normalizedApprovalClaim.claimId!,
                  generation: normalizedApprovalClaim.generation,
                },
              }
            : exact;
          if (
            claimed.finishedAt === undefined ||
            claimed.cancelRequestedAt ||
            claimed.presentation?.state === "settled"
          ) {
            if (claimed === exact) return value;
            const bindings = value.record.bindings.map((binding) => (binding.token === token ? claimed : binding));
            return { record: { ...value.record, bindings, updatedAt: now() } };
          }
          const { finishedAt: _finishedAt, ...reopened } = claimed;
          const bindings = value.record.bindings.map((binding) =>
            binding.token === token
              ? {
                  ...reopened,
                  status: "processing" as const,
                  submissionState: reopened.runIds.length ? ("submitted" as const) : ("idle" as const),
                }
              : binding,
          );
          return { record: { ...value.record, status: sessionStatus(bindings), bindings, updatedAt: now() } };
        }
        const live = value.record.bindings.filter((binding) => binding.finishedAt === undefined);
        if (live.length >= MAX_BINDINGS) return value;
        const pendingStopTokens = new Set(
          value.record.stopEvents.filter((event) => event.state === "pending").flatMap((event) => event.bindingTokens),
        );
        const protectedFinished = value.record.bindings.filter(
          (binding) =>
            binding.finishedAt !== undefined &&
            (pendingStopTokens.has(binding.token) ||
              (binding.presentation !== undefined && binding.presentation.state !== "settled")),
        );
        const finished = value.record.bindings.filter(
          (binding) =>
            binding.finishedAt !== undefined &&
            !pendingStopTokens.has(binding.token) &&
            (!binding.presentation || binding.presentation.state === "settled"),
        );
        const finishedSlots = Math.max(0, MAX_BINDINGS - live.length - protectedFinished.length - 1);
        accepted = true;
        const stopBoundary = latestStopBoundary(value.record);
        const causalStop =
          stopBoundary && eventTime(stopBoundary.eventTs) >= eventTime(triggerTs) ? stopBoundary : undefined;
        const admittedAt = now();
        const reconciledBinding: SlackAgentSessionBinding = causalStop
          ? {
              ...initialBinding,
              status: "active",
              cancelEventId: causalStop.eventId,
              cancelRequestedAt: causalStop.eventTs,
              finishedAt: admittedAt,
            }
          : initialBinding;
        const bindings = [
          ...protectedFinished,
          ...(finishedSlots ? finished.slice(-finishedSlots) : []),
          ...live,
          reconciledBinding,
        ];
        return {
          record: {
            ...value.record,
            status: sessionStatus(bindings),
            bindings,
            stopEvents: causalStop
              ? value.record.stopEvents.map((event) =>
                  event.eventId === causalStop.eventId
                    ? {
                        ...event,
                        applicable: true,
                        bindingTokens: [...new Set([...event.bindingTokens, token])],
                      }
                    : event,
                )
              : value.record.stopEvents,
            updatedAt: admittedAt,
          },
        };
      });
      return accepted ? result(stored?.record ?? null, selectedToken) : rejected();
    },
    async prepareSubmission(input) {
      const key = normalizeKey(input);
      const token = bounded(input.token);
      if (!key || !token) return rejected();
      let prepared = false;
      const stored = await update(recordKey(key), (value) => {
        const binding = value.record.bindings.find((candidate) => candidate.token === token);
        if (!sameKey(value.record, key) || !binding || binding.cancelRequestedAt || binding.finishedAt !== undefined)
          return value;
        prepared = true;
        return {
          record: {
            ...value.record,
            bindings: value.record.bindings.map((candidate) =>
              candidate.token === token
                ? {
                    ...candidate,
                    submissionState: "pending" as const,
                    submissionPendingUntil: now() + SUBMISSION_PENDING_MS,
                  }
                : candidate,
            ),
            updatedAt: now(),
          },
        };
      });
      const selected = result(stored?.record ?? null, token);
      return prepared || selected.cancelled ? selected : rejected();
    },
    async bindRun(input) {
      const key = normalizeKey(input);
      const token = bounded(input.token);
      const runId = bounded(input.runId);
      if (!key || !token || !runId) return rejected();
      const stored = await update(recordKey(key), (value) => {
        if (!sameKey(value.record, key) || !value.record.bindings.some((binding) => binding.token === token))
          return value;
        return {
          record: {
            ...value.record,
            bindings: value.record.bindings.map((binding) => {
              if (binding.token !== token) return binding;
              let presentation = binding.presentation;
              if (!binding.approvalClaim && (binding.submissionState === "pending" || presentation)) {
                if (presentation?.runId !== runId) {
                  presentation = {
                    runId,
                    state: "pending" as const,
                    generation: (presentation?.generation ?? 0) + 1,
                  };
                }
              }
              return {
                ...binding,
                runIds: [...new Set([...binding.runIds, runId])].slice(-MAX_RUNS),
                submissionState: "submitted" as const,
                ...(presentation ? { presentation } : {}),
              };
            }),
            updatedAt: now(),
          },
        };
      });
      return result(stored?.record ?? null, token, runId);
    },
    async claimPresentation(input) {
      const key = normalizeKey(input);
      const token = bounded(input.token);
      const runId = bounded(input.runId);
      if (!key || !token || !runId) return null;
      const claimedAt = now();
      const claimId = randomUUID();
      let claim: SlackAgentPresentationClaim | null = null;
      const stored = await update(recordKey(key), (value) => {
        if (!sameKey(value.record, key)) return value;
        const binding = value.record.bindings.find((candidate) => candidate.token === token);
        const presentation = binding?.presentation;
        if (
          !binding ||
          binding.approvalClaim ||
          !presentation ||
          presentation.runId !== runId ||
          presentation.state === "settled" ||
          (presentation.state === "claimed" && (presentation.leaseExpiresAt ?? 0) > claimedAt)
        ) {
          return value;
        }
        const generation = Math.max(1, presentation.generation + 1);
        const leaseExpiresAt = claimedAt + PRESENTATION_LEASE_MS;
        const bindings = value.record.bindings.map((candidate) =>
          candidate.token === token
            ? {
                ...candidate,
                presentation: {
                  runId,
                  state: "claimed" as const,
                  generation,
                  claimId,
                  leaseExpiresAt,
                },
              }
            : candidate,
        );
        claim = {
          ...key,
          token,
          runId,
          ownerUserId: binding.ownerUserId,
          triggerTs: binding.triggerTs,
          authorityMessageTs: binding.authorityMessageTs,
          coreThreadRef: binding.coreThreadRef,
          claimId,
          generation,
          leaseExpiresAt,
        };
        return { record: { ...value.record, bindings, updatedAt: claimedAt } };
      });
      if (!claim || !stored?.record) return null;
      const selected = exactPresentationClaim(stored.record, claim);
      return selected ? presentationClaim(key, selected) : null;
    },
    async claimDuePresentations(input) {
      const teamId = bounded(input.teamId);
      const agentId = bounded(input.agentId);
      const limit = Number.isSafeInteger(input.limit) ? Math.max(0, Math.min(100, input.limit)) : 0;
      if (!teamId || !agentId || !limit) return [];
      const due: Array<SlackAgentSessionKey & { token: string; runId: string }> = [];
      for (const [, stored] of await sessionBacking.entries()) {
        const record = (stored as Partial<StoredSlackAgentSession>)?.record;
        if (!record || record.teamId !== teamId || record.agentId !== agentId) continue;
        for (const binding of record.bindings) {
          const presentation = binding.presentation;
          if (
            binding.approvalClaim ||
            !presentation ||
            presentation.state === "settled" ||
            (presentation.state === "claimed" && (presentation.leaseExpiresAt ?? 0) > now())
          ) {
            continue;
          }
          due.push({
            teamId: record.teamId,
            agentId: record.agentId,
            channelId: record.channelId,
            threadTs: record.threadTs,
            token: binding.token,
            runId: presentation.runId,
          });
          if (due.length >= limit) break;
        }
        if (due.length >= limit) break;
      }
      const claims: SlackAgentPresentationClaim[] = [];
      for (const candidate of due) {
        const claimed = await this.claimPresentation(candidate);
        if (claimed) claims.push(claimed);
      }
      return claims;
    },
    async presentationClaimActive(claim) {
      const key = normalizeKey(claim);
      if (!key) return false;
      const stored = await sessionBacking.get(recordKey(key));
      return !!stored?.record && !!exactPresentationClaim(stored.record, claim);
    },
    async renewPresentation(claim) {
      const key = normalizeKey(claim);
      if (!key) return null;
      const renewedAt = now();
      const leaseExpiresAt = renewedAt + PRESENTATION_LEASE_MS;
      let renewed: SlackAgentPresentationClaim | null = null;
      await update(recordKey(key), (value) => {
        const binding = exactPresentationClaim(value.record, claim);
        if (!binding) return value;
        const bindings = value.record.bindings.map((candidate) =>
          candidate.token === claim.token
            ? {
                ...candidate,
                presentation: { ...candidate.presentation!, leaseExpiresAt },
              }
            : candidate,
        );
        renewed = { ...claim, leaseExpiresAt };
        return { record: { ...value.record, bindings, updatedAt: renewedAt } };
      });
      return renewed;
    },
    async settlePresentation(claim, outcome) {
      const key = normalizeKey(claim);
      if (!key || (outcome !== "delivered" && outcome !== "cancelled_clean")) return false;
      let settled = false;
      await update(recordKey(key), (value) => {
        const binding = exactPresentationClaim(value.record, claim);
        if (
          !binding ||
          (outcome === "delivered" && binding.cancelRequestedAt !== undefined) ||
          (outcome === "cancelled_clean" && binding.cancelRequestedAt === undefined)
        ) {
          return value;
        }
        settled = true;
        const finishedAt = now();
        const bindings = value.record.bindings.map((candidate) =>
          candidate.token === claim.token
            ? {
                ...candidate,
                finishedAt: candidate.finishedAt ?? finishedAt,
                submissionState: "settled" as const,
                presentation: {
                  runId: claim.runId,
                  state: "settled" as const,
                  generation: claim.generation,
                },
              }
            : candidate,
        );
        return {
          record: {
            ...value.record,
            status: sessionStatus(bindings),
            bindings,
            updatedAt: finishedAt,
          },
        };
      });
      return settled;
    },
    async releasePresentation(claim) {
      const key = normalizeKey(claim);
      if (!key) return false;
      let released = false;
      await update(recordKey(key), (value) => {
        if (!exactPresentationClaim(value.record, claim)) return value;
        released = true;
        const bindings = value.record.bindings.map((candidate) =>
          candidate.token === claim.token
            ? {
                ...candidate,
                presentation: {
                  runId: claim.runId,
                  state: "pending" as const,
                  generation: claim.generation,
                },
              }
            : candidate,
        );
        return { record: { ...value.record, bindings, updatedAt: now() } };
      });
      return released;
    },
    async bindStream(input) {
      const key = normalizeKey(input);
      const token = bounded(input.token);
      const streamTs = timestamp(input.streamTs);
      if (!key || !token || !streamTs) return rejected();
      const stored = await update(recordKey(key), (value) => {
        const selected = value.record.bindings.find((binding) => binding.token === token);
        if (!sameKey(value.record, key) || !selected) return value;
        const stop = value.record.stopEvents.find((event) => event.eventId === selected.cancelEventId);
        let streamStopState: SlackAgentSessionBinding["streamStopState"];
        if (stop) streamStopState = stop.streamingMessageTs.includes(streamTs) ? "listed" : "late";
        return {
          record: {
            ...value.record,
            bindings: value.record.bindings.map((binding) =>
              binding.token === token
                ? { ...binding, streamTs, ...(streamStopState ? { streamStopState } : {}) }
                : binding,
            ),
            updatedAt: now(),
          },
        };
      });
      return result(stored?.record ?? null, token);
    },
    async cancelled(input) {
      const key = normalizeKey(input);
      const token = bounded(input.token);
      const runId = input.runId === undefined ? undefined : bounded(input.runId);
      if (!key || !token || (input.runId !== undefined && !runId)) return true;
      const stored = await sessionBacking.get(recordKey(key));
      return result(stored?.record ?? null, token, runId ?? undefined).cancelled;
    },
    async cancellationLatched(input) {
      const key = normalizeKey(input);
      const token = bounded(input.token);
      if (!key || !token) return false;
      const stored = await sessionBacking.get(recordKey(key));
      const binding = stored?.record.bindings.find((candidate) => candidate.token === token);
      return !!binding?.cancelEventId && !!binding.cancelRequestedAt;
    },
    async finish(input) {
      const key = normalizeKey(input);
      const token = bounded(input.token);
      if (!key || !token || !["processing", "active", "suspended", "closed"].includes(input.status)) return false;
      let accepted = false;
      await update(recordKey(key), (value) => {
        const binding = value.record.bindings.find((candidate) => candidate.token === token);
        if (
          !sameKey(value.record, key) ||
          !binding ||
          binding.cancelRequestedAt ||
          (binding.approvalClaim &&
            (!input.approvalClaim ||
              binding.approvalClaim.claimId !== input.approvalClaim.claimId ||
              binding.approvalClaim.generation !== input.approvalClaim.generation))
        )
          return value;
        accepted = true;
        const bindings = value.record.bindings.map((candidate) =>
          candidate.token === token ? { ...candidate, status: input.status } : candidate,
        );
        return {
          record: {
            ...value.record,
            status: sessionStatus(bindings),
            ...(input.status === "processing" ? { sessionInitialized: true } : {}),
            bindings,
            updatedAt: now(),
          },
        };
      });
      return accepted;
    },
    async complete(input) {
      const key = normalizeKey(input);
      const token = bounded(input.token);
      if (!key || !token) return false;
      const finishedAt = now();
      let accepted = false;
      await update(recordKey(key), (value) => {
        const binding = value.record.bindings.find((candidate) => candidate.token === token);
        if (
          !sameKey(value.record, key) ||
          !binding ||
          (binding.presentation && binding.presentation.state !== "settled") ||
          (binding.approvalClaim &&
            (!input.approvalClaim ||
              binding.approvalClaim.claimId !== input.approvalClaim.claimId ||
              binding.approvalClaim.generation !== input.approvalClaim.generation))
        )
          return value;
        accepted = true;
        const bindings = value.record.bindings.map((candidate) =>
          candidate.token === token
            ? { ...candidate, finishedAt: candidate.finishedAt ?? finishedAt, submissionState: "settled" as const }
            : candidate,
        );
        return {
          record: {
            ...value.record,
            status: sessionStatus(bindings),
            bindings,
            updatedAt: finishedAt,
          },
        };
      });
      return accepted;
    },
    async retryWindow(input) {
      const key = normalizeKey(input);
      const method = bounded(input.method);
      if (!key || !method) return null;
      const stored = await retryBacking.get(providerRetryKey(key, method));
      return publicRetryWindow(stored?.providerRetry);
    },
    async claimProviderWrite(input) {
      const key = normalizeKey(input);
      const method = bounded(input.method);
      if (!key || !method) {
        return {
          acquired: false,
          notBefore: Number.MAX_SAFE_INTEGER,
          reason: "retry_window",
          sameSession: false,
        };
      }
      const id = providerRetryKey(key, method);
      await retryBacking.putIfAbsent(id, {
        providerRetry: {
          teamId: key.teamId,
          agentId: key.agentId,
          method,
          notBefore: 0,
          attempts: 0,
          generation: 0,
          updatedAt: now(),
        },
      });
      const retryUpdate = retryBacking.update?.bind(retryBacking);
      if (!retryUpdate) throw new Error("Slack agent provider retry storage requires atomic durable updates");
      const claimId = randomUUID();
      const claimedAt = now();
      let acquired = false;
      let blockedUntil = claimedAt;
      let blockedReason: "retry_window" | "lease_held" = "retry_window";
      let blockedBySameSession = false;
      const stored = await retryUpdate(id, (value) => {
        const current = value.providerRetry;
        const generation = currentGeneration(current);
        if (current.notBefore > claimedAt) {
          blockedUntil = current.notBefore;
          return value;
        }
        if (current.lease && current.lease.expiresAt > claimedAt) {
          blockedUntil = current.lease.expiresAt;
          blockedReason = "lease_held";
          blockedBySameSession = current.lease.channelId === key.channelId && current.lease.threadTs === key.threadTs;
          return value;
        }
        acquired = true;
        const leaseExpiresAt = claimedAt + PROVIDER_WRITE_LEASE_MS;
        return {
          providerRetry: {
            ...current,
            generation,
            lease: {
              claimId,
              generation,
              expiresAt: leaseExpiresAt,
              channelId: key.channelId,
              threadTs: key.threadTs,
            },
            updatedAt: claimedAt,
          },
        };
      });
      if (!acquired || !stored?.providerRetry.lease || stored.providerRetry.lease.claimId !== claimId) {
        return {
          acquired: false,
          notBefore: blockedUntil,
          reason: blockedReason,
          sameSession: blockedBySameSession,
        };
      }
      return {
        acquired: true,
        claim: {
          teamId: key.teamId,
          agentId: key.agentId,
          channelId: key.channelId,
          threadTs: key.threadTs,
          method,
          claimId,
          generation: stored.providerRetry.lease.generation,
          leaseExpiresAt: stored.providerRetry.lease.expiresAt,
        },
      };
    },
    async deferProviderWrite(input) {
      const claim = normalizeProviderClaim(input);
      if (!claim || !Number.isSafeInteger(input.notBefore) || input.notBefore < 0) {
        return { applied: false, window: null };
      }
      const id = `provider-retry:${hash([claim.teamId, claim.agentId, claim.method])}`;
      const retryUpdate = retryBacking.update?.bind(retryBacking);
      if (!retryUpdate) throw new Error("Slack agent provider retry storage requires atomic durable updates");
      let applied = false;
      const stored = await retryUpdate(id, (value) => {
        const current = value.providerRetry;
        if (!exactProviderLease(current, claim)) return value;
        applied = true;
        return {
          providerRetry: {
            ...current,
            notBefore: Math.max(current.notBefore, input.notBefore),
            attempts: Math.min(Number.MAX_SAFE_INTEGER, Math.max(0, current.attempts) + 1),
            generation: currentGeneration(current) + 1,
            lease: undefined,
            updatedAt: now(),
          },
        };
      });
      return { applied, window: publicRetryWindow(stored?.providerRetry) };
    },
    async completeProviderWrite(input) {
      const claim = normalizeProviderClaim(input);
      if (!claim) return false;
      const id = `provider-retry:${hash([claim.teamId, claim.agentId, claim.method])}`;
      const retryUpdate = retryBacking.update?.bind(retryBacking);
      if (!retryUpdate) throw new Error("Slack agent provider retry storage requires atomic durable updates");
      let completed = false;
      await retryUpdate(id, (value) => {
        const current = value.providerRetry;
        if (!exactProviderLease(current, claim)) return value;
        completed = true;
        return {
          providerRetry: {
            ...current,
            notBefore: 0,
            attempts: 0,
            generation: currentGeneration(current) + 1,
            lease: undefined,
            updatedAt: now(),
          },
        };
      });
      return completed;
    },
    async releaseProviderWrite(input) {
      const claim = normalizeProviderClaim(input);
      if (!claim) return false;
      const id = `provider-retry:${hash([claim.teamId, claim.agentId, claim.method])}`;
      const retryUpdate = retryBacking.update?.bind(retryBacking);
      if (!retryUpdate) throw new Error("Slack agent provider retry storage requires atomic durable updates");
      let released = false;
      await retryUpdate(id, (value) => {
        const current = value.providerRetry;
        if (!exactProviderLease(current, claim)) return value;
        released = true;
        return {
          providerRetry: {
            ...current,
            generation: currentGeneration(current) + 1,
            lease: undefined,
            updatedAt: now(),
          },
        };
      });
      return released;
    },
    async recordStop(input) {
      const key = normalizeKey(input);
      const eventId = bounded(input.eventId);
      const eventTs = timestamp(input.eventTs);
      const stoppedByUserId = bounded(input.stoppedByUserId);
      const streams = [
        ...new Set(input.streamingMessageTs.map(timestamp).filter((value): value is string => !!value)),
      ].slice(0, MAX_RUNS);
      if (!key || !eventId || !eventTs || !stoppedByUserId) throw new Error("invalid Slack agent stop authority");
      const id = recordKey(key);
      const orphan: SlackAgentStopEvent = {
        eventId,
        eventTs,
        stoppedByUserId,
        streamingMessageTs: streams,
        bindingTokens: [],
        applicable: false,
        state: "acknowledged",
      };
      const initial: SlackAgentSessionRecord = {
        ...key,
        status: "active",
        bindings: [],
        stopEvents: [orphan],
        stopThrough: { eventId, eventTs },
        updatedAt: now(),
      };
      await sessionBacking.putIfAbsent(id, { record: initial });
      let replay = false;
      const stored = await update(id, (value) => {
        if (!sameKey(value.record, key)) return value;
        const duplicate = value.record.stopEvents.find((candidate) => candidate.eventId === eventId);
        if (duplicate) {
          replay = true;
          const boundary = latestStopBoundary(value.record);
          if (boundary && value.record.stopThrough?.eventId === boundary.eventId) return value;
          return { record: { ...value.record, ...(boundary ? { stopThrough: boundary } : {}) } };
        }
        const bindingTokens = value.record.bindings
          .filter((binding) => stopApplies(binding, eventTs))
          .map((binding) => binding.token);
        const applicable = bindingTokens.length > 0;
        const event: SlackAgentStopEvent = {
          eventId,
          eventTs,
          stoppedByUserId,
          streamingMessageTs: streams,
          bindingTokens,
          applicable,
          state: applicable ? "pending" : "acknowledged",
        };
        const latchAt = now();
        const boundary = latestStopBoundary(value.record);
        const stopThrough =
          !boundary || eventTime(eventTs) > eventTime(boundary.eventTs) ? { eventId, eventTs } : boundary;
        const bindings = value.record.bindings.map((binding) =>
          bindingTokens.includes(binding.token)
            ? {
                ...binding,
                status: "active" as const,
                cancelEventId: eventId,
                cancelRequestedAt: eventTs,
                finishedAt: binding.finishedAt ?? latchAt,
                ...(binding.presentation?.state === "settled"
                  ? {
                      presentation: {
                        runId: binding.presentation.runId,
                        state: "pending" as const,
                        generation: binding.presentation.generation + 1,
                      },
                    }
                  : {}),
              }
            : binding,
        );
        return {
          record: {
            ...value.record,
            status: sessionStatus(bindings),
            bindings,
            stopEvents: retainedStopEvents([...value.record.stopEvents, event]),
            stopThrough,
            updatedAt: latchAt,
          },
        };
      });
      if (!stored) throw new Error("Slack agent stop state disappeared during update");
      const persisted = stored.record.stopEvents.find((candidate) => candidate.eventId === eventId);
      if (!persisted) throw new Error("Slack agent stop event was not persisted");
      return { record: stored.record, event: persisted, replay };
    },
    async acknowledgeStop(input) {
      const key = normalizeKey(input);
      const eventId = bounded(input.eventId);
      const confirmationTs = input.confirmationTs === undefined ? undefined : timestamp(input.confirmationTs);
      if (!key || !eventId || (input.confirmationTs !== undefined && !confirmationTs)) return false;
      const stored = await update(recordKey(key), (value) => {
        if (!sameKey(value.record, key)) return value;
        const found = value.record.stopEvents.find((event) => event.eventId === eventId);
        if (!found) return value;
        return {
          record: {
            ...value.record,
            status: sessionStatus(value.record.bindings),
            stopEvents: retainedStopEvents(
              value.record.stopEvents.map((event) =>
                event.eventId === eventId
                  ? { ...event, state: "acknowledged", ...(confirmationTs ? { confirmationTs } : {}) }
                  : event,
              ),
            ),
            updatedAt: now(),
          },
        };
      });
      return (
        stored?.record.stopEvents.some((event) => event.eventId === eventId && event.state === "acknowledged") === true
      );
    },
    async get(input) {
      const key = normalizeKey(input);
      if (!key) return null;
      const stored = await sessionBacking.get(recordKey(key));
      return stored && sameKey(stored.record, key) ? stored.record : null;
    },
    async rename(input) {
      const key = normalizeKey(input);
      const changedByUserId = bounded(input.changedByUserId);
      const eventTs = timestamp(input.eventTs);
      const title = typeof input.title === "string" ? input.title.replace(/\s+/g, " ").trim().slice(0, MAX_TITLE) : "";
      if (!key || !changedByUserId || !eventTs || !title) return false;
      const stored = await update(recordKey(key), (value) => {
        if (!sameKey(value.record, key)) return value;
        const previous = value.record.titleEventTs;
        if (previous && eventTime(eventTs) <= eventTime(previous)) return value;
        return {
          record: {
            ...value.record,
            title,
            titleChangedBy: changedByUserId,
            titleEventTs: eventTs,
            updatedAt: now(),
          },
        };
      });
      return stored?.record.title === title && stored.record.titleEventTs === eventTs;
    },
  };
}
