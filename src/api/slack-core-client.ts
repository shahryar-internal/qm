import { orgId as configOrgId } from "../config.ts";
import { resolveBranding } from "../resolution/branding.ts";
import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { buffer } from "node:stream/consumers";
import type { App } from "./app.ts";
import type {
  Delivery,
  ScopeId,
  SurfaceContextRequest,
  SurfaceContextResult,
  TurnRequest,
  TurnResult,
} from "../types.ts";
import { scopeId } from "../types.ts";
import type { IngestEvent } from "../surface-cache/surface-cache.ts";
import type { AckEmojiPickStore } from "../surface-cache/ack-emoji-pick-store.ts";
import type { OrgBranding, ScopedConfigStore } from "../resolution/config-store.ts";
import type { BlobTransferStore } from "../persistence/blob-transfer.ts";
import { MAX_BLOB_BYTES } from "../persistence/blob-transfer.ts";
import type { DeliveryStore } from "../delivery/delivery-store.ts";
import type { MetricsSink } from "../admin/metrics-sink.ts";
import type { Run, RunStore } from "../runs/run-store.ts";
import { isTerminal } from "../runs/run-store.ts";
import { replayableRequest } from "../core/orchestrator/turn-helpers.ts";
import type { TurnStream } from "../runs/turn-stream.ts";
import type { TaskStore, TaskStatus } from "../tasks/task-store.ts";
import { swallowAs } from "../util/errors.ts";
import { resolveRuntimeChoiceDurable, type RuntimeChoice } from "../harness/harness-router.ts";
import { modelDisplayName, resolveModel } from "../model/pi-models.ts";
import type { McpAuthoritySigner } from "../mcp/mcp-authority.ts";
import type { QmAnalyticsNativeCard } from "../types.ts";
import type {
  SlackAgentContextEntity,
  SlackAgentContextStore,
  SlackAgentThreadContext,
} from "../surfaces/slack-agent-context.ts";
import type {
  SlackAgentBindingResult,
  SlackAgentPresentationClaim,
  SlackAgentProviderWriteClaim,
  SlackAgentProviderWriteClaimResult,
  SlackAgentSessionKey,
  SlackAgentSessionRecord,
  SlackAgentSessionStatus,
  SlackAgentSessionStore,
} from "../surfaces/slack-agent-session.ts";
import type {
  SlackAgentStatusIntentClaim,
  SlackAgentStatusIntentInput,
  SlackAgentStatusIntentRecord,
  SlackAgentStatusIntentStore,
} from "../surfaces/slack-agent-status-intent.ts";
import type {
  SlackApprovalAuthority,
  SlackApprovalAuthorityKey,
  SlackApprovalAuthorityStore,
  SlackApprovalContinuationAdmission,
  SlackApprovalContinuationClaim,
  SlackApprovalContinuationInput,
  SlackApprovalRecoveryContext,
  SlackApprovalSubmittedContinuation,
} from "../surfaces/slack-approval-authority.ts";
import type {
  SlackReactionCleanupClaim,
  SlackReactionCleanupInput,
  SlackReactionCleanupRecord,
  SlackReactionCleanupStore,
} from "../surfaces/slack-reaction-cleanup.ts";
import { recoverSlackReactionCleanupAdmissions } from "../surfaces/slack-reaction-cleanup.ts";
import type { SlackReactionCleanupDecision } from "../slack/reaction-cleanup.ts";
import type {
  SlackReactionDesireInput,
  SlackReactionDesireRecord,
  SlackReactionDesireStore,
} from "../surfaces/slack-reaction-desire.ts";

interface SlackRunHooks {
  onDelta?(delta: string): void;
  onFirstBlock?(text: string): void;
  onSurfacePosted?(): void;
  onTasks?(tasks: Array<{ id: string; title: string; status: TaskStatus }>): void | Promise<void>;
}

interface StoredApprovalView {
  requestId: string;
  command: string;
  reason?: string;
  purpose?: string;
  summary?: string;
  grantModes?: { session: boolean; always: boolean };
  request?: Record<string, unknown>;
}

interface DirectoryPush {
  members?: Array<{ principalId: string; displayName: string; type: "internal"; slackId?: string }>;
  channels?: Array<{ channelId: string; name: string; isPrivate?: boolean; isExternal?: boolean }>;
  channelMembers?: Array<{ channelId: string; principalId: string }>;
  channelRosterIds?: string[];
  channelRevocations?: Array<{ channelId: string; principalId: string }>;
  groupMembers?: Array<{ groupId: string; principalId: string }>;
  groupIds?: string[];
  groupRosterIds?: string[];
  workspaceUrl?: string;
  membersSyncedAt?: number;
  channelsSyncedAt?: number;
  groupsSyncedAt?: number;
}

export interface SlackAgentStopInput extends SlackAgentSessionKey {
  eventId: string;
  eventTs: string;
  stoppedByUserId: string;
  streamingMessageTs: string[];
}

export function selectSlackAgentStopRuns(
  runs: readonly Run[],
  input: SlackAgentStopInput,
  session: SlackAgentSessionRecord,
): Run[] {
  const stoppedAt = Number.parseFloat(input.eventTs) * 1000;
  if (!Number.isFinite(stoppedAt) || stoppedAt < 0) return [];
  const event = session.stopEvents.find((candidate) => candidate.eventId === input.eventId);
  const bindingTokens = new Set(event?.bindingTokens ?? []);
  const bindings = session.bindings.filter((binding) => bindingTokens.has(binding.token));
  return runs.filter((run) => {
    const verified = run.request.verifiedSlack;
    if (!verified || verified.teamId !== input.teamId) return false;
    return bindings.some((binding) => {
      const session = run.request.slackAgentSession;
      const exactSession =
        session?.teamId === input.teamId &&
        session.agentId === input.agentId &&
        session.channelId === input.channelId &&
        session.threadTs === input.threadTs &&
        session.token === binding.token;
      const durableToken = run.request.slackAgentSessionToken;
      if (binding.runIds.includes(run.id) || exactSession) {
        return run.request.conversation.threadRef === binding.coreThreadRef;
      }
      if (durableToken === binding.token) {
        return run.request.conversation.threadRef === binding.coreThreadRef;
      }
      if (run.createdAt > stoppedAt) return false;
      return (
        verified.userId === binding.ownerUserId &&
        !binding.streamTs &&
        !run.deliveryState?.editRef &&
        verified.channelId === input.channelId &&
        verified.threadTs === input.threadTs &&
        verified.messageTs === binding.authorityMessageTs &&
        run.request.conversation.threadRef === binding.coreThreadRef
      );
    });
  });
}

export function slackAgentPresentationRequest(
  run: Run | null | undefined,
  claim: SlackAgentPresentationClaim,
): Omit<TurnRequest, "surface"> | null {
  const request = run?.request;
  const session = request?.slackAgentSession;
  const verified = request?.verifiedSlack;
  if (
    !request ||
    run.id !== claim.runId ||
    request.surface !== "slack" ||
    !!request.approval ||
    !session ||
    session.teamId !== claim.teamId ||
    session.agentId !== claim.agentId ||
    session.channelId !== claim.channelId ||
    session.threadTs !== claim.threadTs ||
    session.token !== claim.token ||
    request.slackAgentSessionToken !== claim.token ||
    request.conversation.threadRef !== claim.coreThreadRef ||
    !verified ||
    verified.teamId !== claim.teamId ||
    verified.userId !== claim.ownerUserId ||
    verified.channelId !== claim.channelId ||
    verified.messageTs !== claim.authorityMessageTs ||
    verified.threadTs !== claim.threadTs
  ) {
    return null;
  }
  const { surface: _surface, ...body } = replayableRequest(request);
  return body;
}

export interface SlackCoreClient {
  externalSlackParticipants(): Promise<boolean>;
  ackEmojiOverride(): Promise<string[] | null>;
  surfaceHeaderFacts(scope: ScopeId): Promise<{ agentLabel?: string; modelName: string }>;
  channelHeaderPinEnabled(scope: ScopeId): Promise<boolean>;
  onScopeModelChanged(listener: (scope: ScopeId) => void): void;
  onChannelHeaderPinChanged(listener: (scope: ScopeId) => void): void;
  stageBlob(bytes: Uint8Array): Promise<{ blobId: string; sizeBytes: number }>;
  readBlob(blobId: string): Promise<Buffer>;
  readFileArtifact(artifactId: string, viewerId: string): Promise<Buffer>;
  ingestSurfaceEvents(events: IngestEvent[], self?: { name?: string; mentionId?: string }): Promise<void>;
  submitTurn(body: Omit<TurnRequest, "surface">): Promise<TurnResult>;
  waitRun(runId: string, hooks?: SlackRunHooks): Promise<TurnResult | null>;
  activeRunForThread(threadRef: string): Promise<string | undefined>;
  signalRunAbort(runId: string): Promise<void>;
  beginSlackAgentSession(
    input: SlackAgentSessionKey & {
      ownerUserId: string;
      token: string;
      triggerTs: string;
      coreThreadRef: string;
      authorityMessageTs: string;
      approvalClaim?: { claimId: string; generation: number };
    },
  ): Promise<SlackAgentBindingResult>;
  prepareSlackAgentSubmission(input: SlackAgentSessionKey & { token: string }): Promise<SlackAgentBindingResult>;
  bindSlackAgentRun(input: SlackAgentSessionKey & { token: string; runId: string }): Promise<SlackAgentBindingResult>;
  claimSlackAgentPresentation(
    input: SlackAgentSessionKey & { token: string; runId: string },
  ): Promise<SlackAgentPresentationClaim | null>;
  claimSlackAgentPresentations(input: {
    teamId: string;
    agentId: string;
    limit: number;
  }): Promise<SlackAgentPresentationClaim[]>;
  renewSlackAgentPresentation(claim: SlackAgentPresentationClaim): Promise<SlackAgentPresentationClaim | null>;
  settleSlackAgentPresentation(
    claim: SlackAgentPresentationClaim,
    outcome: "delivered" | "cancelled_clean",
  ): Promise<boolean>;
  releaseSlackAgentPresentation(claim: SlackAgentPresentationClaim): Promise<boolean>;
  slackAgentPresentationRun(claim: SlackAgentPresentationClaim): Promise<Omit<TurnRequest, "surface"> | null>;
  bindSlackAgentStream(
    input: SlackAgentSessionKey & { token: string; streamTs: string },
  ): Promise<SlackAgentBindingResult>;
  slackAgentSessionCancelled(input: SlackAgentSessionKey & { token: string; runId?: string }): Promise<boolean>;
  finishSlackAgentSession(
    input: SlackAgentSessionKey & {
      token: string;
      status: SlackAgentSessionStatus;
      approvalClaim?: { claimId: string; generation: number };
    },
  ): Promise<boolean>;
  completeSlackAgentSession(
    input: SlackAgentSessionKey & { token: string; approvalClaim?: { claimId: string; generation: number } },
  ): Promise<boolean>;
  slackAgentSessionStatus(input: SlackAgentSessionKey): Promise<SlackAgentSessionStatus | null>;
  claimSlackAgentProviderWrite(
    input: SlackAgentSessionKey & { method: string },
  ): Promise<SlackAgentProviderWriteClaimResult>;
  deferSlackAgentProviderWrite(
    input: SlackAgentProviderWriteClaim & { notBefore: number },
  ): ReturnType<SlackAgentSessionStore["deferProviderWrite"]>;
  completeSlackAgentProviderWrite(input: SlackAgentProviderWriteClaim): Promise<boolean>;
  releaseSlackAgentProviderWrite(input: SlackAgentProviderWriteClaim): Promise<boolean>;
  enqueueSlackAgentStatusIntent(input: SlackAgentStatusIntentInput): ReturnType<SlackAgentStatusIntentStore["enqueue"]>;
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
  admitSlackReactionDesire(
    input: SlackReactionDesireInput,
  ): Promise<{ disposition: "accepted" | "replayed" | "superseded"; record: SlackReactionDesireRecord }>;
  withdrawSlackReactionDesire(input: SlackReactionDesireInput): Promise<SlackReactionDesireRecord | null>;
  cancelSlackReactionDesire(input: SlackReactionDesireInput): Promise<SlackReactionDesireRecord | null>;
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
  stopSlackAgentSession(input: SlackAgentStopInput): Promise<{
    applicable: boolean;
    acknowledged: boolean;
    deferred?: boolean;
    runIds: string[];
    status?: SlackAgentSessionStatus;
  }>;
  acknowledgeSlackAgentStop(
    input: SlackAgentSessionKey & { eventId: string; confirmationTs?: string },
  ): Promise<boolean>;
  bindSlackApprovalAuthority(input: Omit<SlackApprovalAuthority, "createdAt">): Promise<boolean>;
  getSlackApprovalAuthority(input: SlackApprovalAuthorityKey): Promise<SlackApprovalAuthority | null>;
  admitSlackApprovalContinuation(input: SlackApprovalContinuationInput): Promise<SlackApprovalContinuationAdmission>;
  markSlackApprovalContinuationSubmitted(input: SlackApprovalContinuationClaim & { runId: string }): Promise<boolean>;
  renewSlackApprovalContinuation(input: SlackApprovalContinuationClaim): Promise<boolean>;
  settleSlackApprovalContinuation(input: SlackApprovalContinuationClaim): Promise<boolean>;
  releaseSlackApprovalContinuation(input: SlackApprovalContinuationClaim): Promise<boolean>;
  recoverableSlackApprovalContinuations(input: {
    teamId: string;
    agentId: string;
    limit: number;
  }): Promise<SlackApprovalContinuationInput[]>;
  submittedSlackApprovalContinuations(input: {
    teamId: string;
    agentId: string;
  }): Promise<SlackApprovalSubmittedContinuation[]>;
  slackApprovalRunRecovery(
    runId: string,
    input: { teamId: string; agentId: string },
  ): Promise<SlackApprovalRecoveryContext | null>;
  ackRunDelivery(runId: string): Promise<void>;
  reportTurnMetrics(runId: string, patch: { deliverMs?: number; slackInflightMs?: number }): Promise<void>;
  reportRunEditRef(runId: string, editRef: string): Promise<void>;
  getApproval(requestId: string): Promise<StoredApprovalView | null>;
  pushDirectory(body: DirectoryPush): Promise<void>;
  claimDeliveries(type: string, claimMs: number): Promise<Delivery[]>;
  analyticsNativeCard?(delivery: Delivery): QmAnalyticsNativeCard | null;
  ackDelivery(id: string, body?: { recipientThreadRef?: string; slackApiMs?: number }): Promise<void>;
  onDeliveryEnqueued(listener: () => void): () => void;
  pendingContextRequests(): Promise<SurfaceContextRequest[]>;
  onContextRequest(listener: (request: SurfaceContextRequest) => void): () => void;
  fulfillContextRequest(id: string, outcome: { result?: SurfaceContextResult; error?: string }): Promise<void>;
  pickAckEmoji(text: string, candidates: readonly string[]): Promise<string | undefined>;
  recordAckPick(pick: AckPickInput): Promise<void>;
  saveSlackAgentContext(input: {
    teamId: string;
    ownerUserId: string;
    context: unknown;
    source: SlackAgentThreadContext["source"];
    eventTs: string;
  }): Promise<SlackAgentContextEntity[]>;
  bindSlackAgentThread(input: {
    teamId: string;
    ownerUserId: string;
    channelId: string;
    threadTs: string;
    context: unknown;
    source: SlackAgentThreadContext["source"];
    eventTs: string;
  }): Promise<SlackAgentThreadContext | null>;
  getSlackAgentThread(input: {
    teamId: string;
    ownerUserId: string;
    channelId: string;
    threadTs: string;
  }): Promise<SlackAgentThreadContext | null>;
  renameSlackAgentSession(input: {
    teamId: string;
    agentId: string;
    channelId: string;
    threadTs: string;
    changedByUserId: string;
    title: string;
    eventTs: string;
  }): Promise<boolean>;
}

type AckPickInput = {
  channel: string;
  ts: string;
  outcome: "picked" | "declined";
  picked?: string;
  icon?: string;
  message?: string;
  candidates?: string;
  latencyMs?: number;
};

export type { SurfaceContextRequest };

export interface SlackCoreClientDeps {
  app: App;
  config: ScopedConfigStore;
  runtimeFallback: RuntimeChoice;
  runtimeChoiceOverride?: RuntimeChoice;
  blobTransfer: BlobTransferStore;
  deliveries: DeliveryStore;
  metrics: MetricsSink;
  runs: RunStore;
  turnStream: TurnStream;
  tasks: TaskStore;
  pickAckEmoji?(text: string, candidates: readonly string[]): Promise<string | undefined>;
  ackPicks?: AckEmojiPickStore;
  ackModelId?: () => string | undefined;
  brandingDefault?: OrgBranding;
  analyticsCardVerifier?: Pick<McpAuthoritySigner, "verifyAnalyticsCard">;
  slackAgentContexts: SlackAgentContextStore;
  slackAgentSessions: SlackAgentSessionStore;
  slackAgentStatusIntents: SlackAgentStatusIntentStore;
  slackReactionDesires: SlackReactionDesireStore;
  slackReactionCleanups: SlackReactionCleanupStore;
  slackApprovalAuthorities: SlackApprovalAuthorityStore;
}

const RUN_FALLBACK_POLL_MS = 1_000;
const RUN_STALL_BUDGET_MS = 300_000;

export function createSlackCoreClient(deps: SlackCoreClientDeps): SlackCoreClient {
  const orgScope: ScopeId = scopeId("org", configOrgId());
  const terminalWaiters = new Map<string, Set<() => void>>();
  deps.runs.onTerminal((run) => {
    for (const wake of terminalWaiters.get(run.id) ?? []) wake();
  });

  return {
    async externalSlackParticipants() {
      return (await deps.config.getExternalSlackParticipantsDurable(orgScope)) === true;
    },

    saveSlackAgentContext(input) {
      return deps.slackAgentContexts.saveCurrent(input);
    },

    bindSlackAgentThread(input) {
      return deps.slackAgentContexts.bindThread(input);
    },

    getSlackAgentThread(input) {
      return deps.slackAgentContexts.getThread(input);
    },

    renameSlackAgentSession(input) {
      return deps.slackAgentSessions.rename(input);
    },

    async ackEmojiOverride() {
      return await deps.config.getAckEmojiDurable(orgScope);
    },

    async surfaceHeaderFacts(scope) {
      const [choice, branding] = await Promise.all([
        resolveRuntimeChoiceDurable(
          deps.config,
          orgScope,
          scope,
          deps.runtimeFallback,
          undefined,
          undefined,
          deps.runtimeChoiceOverride,
        ),
        resolveBranding(deps.config, orgScope, deps.brandingDefault),
      ]);
      return {
        ...(branding.selfLabel ? { agentLabel: branding.selfLabel } : {}),
        modelName: deps.runtimeChoiceOverride
          ? (resolveModel(choice.modelId)?.name ?? modelDisplayName(choice.modelId))
          : modelDisplayName(choice.modelId),
      };
    },

    async channelHeaderPinEnabled(scope) {
      return deps.config.getChannelHeaderPinDurable(scope);
    },

    onScopeModelChanged(listener) {
      deps.config.onRuntimeSelectionChanged((scope) => listener(scope));
    },

    onChannelHeaderPinChanged(listener) {
      deps.config.onChannelHeaderPinChanged((scope) => listener(scope));
    },

    async stageBlob(bytes) {
      const sha256 = createHash("sha256").update(bytes).digest("hex");
      const info = await deps.blobTransfer.put(Readable.from([Buffer.from(bytes)]), {
        maxBytes: MAX_BLOB_BYTES,
        expectedSha256: sha256,
      });
      return { blobId: info.blobId, sizeBytes: info.sizeBytes };
    },

    async readBlob(blobId) {
      const blob = await deps.blobTransfer.open(blobId);
      if (!blob) throw new Error(`blob ${blobId} not found`);
      return buffer(blob.stream);
    },

    async readFileArtifact(artifactId, viewerId) {
      const opened = await deps.app.openFileForViewer(artifactId, viewerId);
      if (!opened) throw new Error(`file artifact ${artifactId} not found (or not visible to ${viewerId})`);
      return buffer(opened.stream);
    },

    async ingestSurfaceEvents(events, self) {
      if (!events.length) return;
      await deps.app.ingestSurfaceEvents(events, "slack", self);
    },

    async submitTurn(body) {
      const queued = await deps.app.turn({ ...body, surface: "slack" });
      const session = body.slackAgentSession;
      if (!session || queued.status !== "queued" || !queued.runId) return queued;
      if (body.slackAgentSessionToken !== session.token) {
        const aborted = await deps.app.signalRun(queued.runId, { kind: "abort" });
        if (!aborted.accepted && aborted.reason !== "terminal") {
          throw new Error(`signal abort not accepted: ${aborted.reason ?? "unknown"}`);
        }
        throw new Error("Slack Agent Session submission token mismatch");
      }
      const bound = await deps.slackAgentSessions.bindRun({ ...session, runId: queued.runId });
      if (!bound.accepted || bound.cancelled) {
        const aborted = await deps.app.signalRun(queued.runId, { kind: "abort" });
        if (!aborted.accepted && aborted.reason !== "terminal") {
          throw new Error(`signal abort not accepted: ${aborted.reason ?? "unknown"}`);
        }
      }
      if (!bound.accepted) throw new Error("Slack Agent Session submission binding was rejected");
      return queued;
    },

    async waitRun(runId, hooks = {}) {
      let streamedChars = 0;
      let firstBlockSignaled = false;
      let surfaceSignaled = false;
      const signalFirstBlock = (text: string): void => {
        if (firstBlockSignaled || !text.trim()) return;
        firstBlockSignaled = true;
        hooks.onFirstBlock?.(text);
      };
      const signalSurface = (): void => {
        if (surfaceSignaled) return;
        surfaceSignaled = true;
        hooks.onSurfacePosted?.();
      };
      const signalDelta = (delta: string): void => {
        if (!delta) return;
        streamedChars += delta.length;
        hooks.onDelta?.(delta);
      };
      const waiters = terminalWaiters.get(runId) ?? new Set();
      terminalWaiters.set(runId, waiters);
      const unsubscribe = deps.turnStream.subscribe(runId, {
        onDelta: signalDelta,
        onFirstBlock: signalFirstBlock,
        onSurfacePosted: signalSurface,
      });
      const initialSnapshot = deps.turnStream.snapshot(runId);
      if (initialSnapshot && streamedChars === 0) signalDelta(initialSnapshot);
      let lastProgressAt = Date.now();
      let lastMark = "";
      let taskSnapshot = "";
      const emitTasks = async (): Promise<void> => {
        if (!hooks.onTasks) return;
        const tasks = (await deps.tasks.list({ originRunId: runId })).map(({ id, title, status }) => ({
          id,
          title,
          status,
        }));
        if (!tasks.length) return;
        const next = JSON.stringify(tasks);
        if (next === taskSnapshot) return;
        taskSnapshot = next;
        await hooks.onTasks(tasks);
      };
      try {
        for (;;) {
          let run;
          try {
            run = await deps.runs.get(runId);
          } catch (err) {
            if (Date.now() - lastProgressAt >= RUN_STALL_BUDGET_MS) throw err;
            run = undefined;
          }
          if (run !== undefined) {
            if (!run) throw new Error(`run ${runId} not found`);
            if (deps.turnStream.surfacePosted(runId)) signalSurface();
            if (isTerminal(run.status)) {
              const view = await deps.app.getRun(runId);
              await emitTasks().catch(swallowAs("slack-core-client: terminal task refresh", undefined));
              if (view?.surfacePosted) signalSurface();
              return (view?.result as TurnResult | null | undefined) ?? null;
            }
            await emitTasks();
            const fb = deps.turnStream.firstBlock(runId);
            if (fb?.closed) signalFirstBlock(fb.text);
            const mark = `${run.status}:${run.attempts}:${run.leaseExpiresAt ?? ""}`;
            if (mark !== lastMark) {
              lastMark = mark;
              lastProgressAt = Date.now();
            }
            if (Date.now() - lastProgressAt >= RUN_STALL_BUDGET_MS) {
              throw Object.assign(
                new Error(`run ${runId} made no progress for ${Math.round(RUN_STALL_BUDGET_MS / 1000)}s — giving up`),
                { code: "run_stalled" },
              );
            }
          }
          await new Promise<void>((resolve) => {
            const timer = setTimeout(done, RUN_FALLBACK_POLL_MS);
            function done(): void {
              clearTimeout(timer);
              waiters.delete(done);
              resolve();
            }
            waiters.add(done);
          });
        }
      } finally {
        unsubscribe();
        if (waiters.size === 0) terminalWaiters.delete(runId);
      }
    },

    async activeRunForThread(threadRef) {
      return (await deps.app.activeRunForThread(threadRef))?.runId;
    },

    async signalRunAbort(runId) {
      const outcome = await deps.app.signalRun(runId, { kind: "abort" });
      if (!outcome.accepted) throw new Error(`signal abort not accepted: ${outcome.reason ?? "unknown"}`);
    },

    beginSlackAgentSession(input) {
      return deps.slackAgentSessions.begin(input);
    },

    prepareSlackAgentSubmission(input) {
      return deps.slackAgentSessions.prepareSubmission(input);
    },

    bindSlackAgentRun(input) {
      return deps.slackAgentSessions.bindRun(input);
    },

    claimSlackAgentPresentation(input) {
      return deps.slackAgentSessions.claimPresentation(input);
    },

    claimSlackAgentPresentations(input) {
      return deps.slackAgentSessions.claimDuePresentations(input);
    },

    renewSlackAgentPresentation(claim) {
      return deps.slackAgentSessions.renewPresentation(claim);
    },

    settleSlackAgentPresentation(claim, outcome) {
      return deps.slackAgentSessions.settlePresentation(claim, outcome);
    },

    releaseSlackAgentPresentation(claim) {
      return deps.slackAgentSessions.releasePresentation(claim);
    },

    async slackAgentPresentationRun(claim) {
      if (!(await deps.slackAgentSessions.presentationClaimActive(claim))) return null;
      const run = await deps.runs.get(claim.runId);
      const body = slackAgentPresentationRequest(run, claim);
      if (!body) return null;
      if (!(await deps.slackAgentSessions.presentationClaimActive(claim))) return null;
      return body;
    },

    bindSlackAgentStream(input) {
      return deps.slackAgentSessions.bindStream(input);
    },

    slackAgentSessionCancelled(input) {
      return deps.slackAgentSessions.cancelled(input);
    },

    finishSlackAgentSession(input) {
      return deps.slackAgentSessions.finish(input);
    },

    completeSlackAgentSession(input) {
      return deps.slackAgentSessions.complete(input);
    },

    async slackAgentSessionStatus(input) {
      return (await deps.slackAgentSessions.get(input))?.status ?? null;
    },

    claimSlackAgentProviderWrite(input) {
      return deps.slackAgentSessions.claimProviderWrite(input);
    },

    deferSlackAgentProviderWrite(input) {
      return deps.slackAgentSessions.deferProviderWrite(input);
    },

    completeSlackAgentProviderWrite(input) {
      return deps.slackAgentSessions.completeProviderWrite(input);
    },

    releaseSlackAgentProviderWrite(input) {
      return deps.slackAgentSessions.releaseProviderWrite(input);
    },

    async enqueueSlackAgentStatusIntent(input) {
      const session = await deps.slackAgentSessions.get(input);
      const authority = input.authority;
      let authorized: boolean;
      if (authority.kind === "binding") {
        authorized = session?.bindings.some((binding) => binding.token === authority.token) === true;
      } else if (authority.kind === "stop") {
        authorized =
          session?.stopEvents.some(
            (event) => event.eventId === authority.eventId && event.applicable && event.state === "pending",
          ) === true;
      } else {
        const approval = await deps.slackApprovalAuthorities.get({
          teamId: input.teamId,
          agentId: input.agentId,
          requesterUserId: authority.requesterUserId,
          requestId: authority.requestId,
        });
        authorized = approval?.channelId === authority.channelId && approval.messageTs === authority.messageTs;
      }
      if (!authorized) throw new Error("Slack Agent status intent authority was not accepted");
      return deps.slackAgentStatusIntents.enqueue(input);
    },

    claimSlackAgentStatusIntents(input) {
      return deps.slackAgentStatusIntents.claimDue(input);
    },

    async slackAgentStatusIntentClaimActive(claim) {
      if (!(await deps.slackAgentStatusIntents.claimActive(claim))) return false;
      const session = await deps.slackAgentSessions.get(claim);
      const authority = claim.authority;
      if (authority.kind === "binding") {
        const binding = session?.bindings.find((candidate) => candidate.token === authority.token);
        return !!binding && !binding.cancelEventId && !binding.cancelRequestedAt;
      }
      if (authority.kind === "stop") {
        return (
          session?.stopEvents.some(
            (event) => event.eventId === authority.eventId && event.applicable && event.state === "pending",
          ) === true
        );
      }
      const approval = await deps.slackApprovalAuthorities.get({
        teamId: claim.teamId,
        agentId: claim.agentId,
        requesterUserId: authority.requesterUserId,
        requestId: authority.requestId,
      });
      return approval?.channelId === authority.channelId && approval.messageTs === authority.messageTs;
    },

    completeSlackAgentStatusIntent(claim) {
      return deps.slackAgentStatusIntents.complete(claim);
    },

    deferSlackAgentStatusIntent(claim, input) {
      return deps.slackAgentStatusIntents.defer(claim, input);
    },

    failSlackAgentStatusIntent(claim, input) {
      return deps.slackAgentStatusIntents.fail(claim, input);
    },

    reopenSlackAgentStatusIntentAfterStaleEffect(claim, input) {
      return deps.slackAgentStatusIntents.reopenCurrentAfterStaleEffect(claim, input);
    },

    getSlackAgentStatusIntent(input) {
      return deps.slackAgentStatusIntents.get(input);
    },

    async admitSlackReactionDesire(input) {
      const session = await deps.slackAgentSessions.get({
        teamId: input.teamId,
        agentId: input.agentId,
        channelId: input.sessionChannelId,
        threadTs: input.sessionThreadTs,
      });
      const binding = session?.bindings.find((candidate) => candidate.token === input.sessionToken);
      if (!binding || binding.cancelEventId || binding.cancelRequestedAt) {
        throw new Error("Slack reaction desire requires an exact active Agent Session binding");
      }
      return deps.slackReactionDesires.admit(input);
    },

    async cancelSlackReactionDesire(input) {
      const authorized = await deps.slackAgentSessions.cancellationLatched({
        teamId: input.teamId,
        agentId: input.agentId,
        channelId: input.sessionChannelId,
        threadTs: input.sessionThreadTs,
        token: input.sessionToken,
      });
      if (!authorized) throw new Error("Slack reaction desire cancellation requires an exact cancellation latch");
      return deps.slackReactionDesires.cancel(input, { admitCleanup: true });
    },

    async withdrawSlackReactionDesire(input) {
      const session = await deps.slackAgentSessions.get({
        teamId: input.teamId,
        agentId: input.agentId,
        channelId: input.sessionChannelId,
        threadTs: input.sessionThreadTs,
      });
      const binding = session?.bindings.find((candidate) => candidate.token === input.sessionToken);
      if (!binding) throw new Error("Slack reaction desire withdrawal requires an exact Agent Session binding");
      return deps.slackReactionDesires.cancel(input);
    },

    async enqueueSlackReactionCleanup(input) {
      const authorized = await deps.slackAgentSessions.cancellationLatched({
        teamId: input.teamId,
        agentId: input.agentId,
        channelId: input.sessionChannelId,
        threadTs: input.sessionThreadTs,
        token: input.sessionToken,
      });
      if (!authorized) {
        throw new Error("Slack reaction cleanup requires an exact accepted canceled Agent Session binding");
      }
      await deps.slackReactionDesires.cancel(input, { admitCleanup: true });
      const cleanup = await deps.slackReactionCleanups.enqueue(input);
      await deps.slackReactionDesires.completeCleanupAdmission(input);
      return cleanup;
    },

    async claimSlackReactionCleanups(input) {
      await recoverSlackReactionCleanupAdmissions(
        deps.slackReactionDesires,
        deps.slackReactionCleanups,
        input,
        deps.slackAgentSessions,
      );
      return deps.slackReactionCleanups.claimDue(input);
    },

    async slackReactionCleanupAction(claim) {
      if (!(await deps.slackReactionCleanups.claimActive(claim))) return "stale";
      const current = await deps.slackReactionDesires.get(claim);
      if (!current?.desired) {
        return {
          action: "remove",
          desireGeneration: current?.generation ?? 0,
          desireEffectId: current?.effectId ?? null,
        };
      }
      if (current.effectId === claim.effectId) {
        throw new Error("Slack reaction cleanup conflicts with its current desired effect");
      }
      return { action: "preserve", desireGeneration: current.generation, desireEffectId: current.effectId };
    },

    async completeSlackReactionCleanup(claim, decision) {
      if (!(await deps.slackReactionCleanups.claimActive(claim))) return false;
      const readDecision = async (): Promise<SlackReactionCleanupDecision> => {
        const current = await deps.slackReactionDesires.get(claim);
        return current?.desired
          ? { action: "preserve", desireGeneration: current.generation, desireEffectId: current.effectId }
          : {
              action: "remove",
              desireGeneration: current?.generation ?? 0,
              desireEffectId: current?.effectId ?? null,
            };
      };
      const exact = (current: SlackReactionCleanupDecision): boolean =>
        current.action === decision.action &&
        current.desireGeneration === decision.desireGeneration &&
        current.desireEffectId === decision.desireEffectId;
      if (!exact(await readDecision())) return false;
      if (!(await deps.slackReactionCleanups.complete(claim))) return false;
      if (exact(await readDecision())) return true;
      await deps.slackReactionCleanups.reopenAfterDecisionChange(claim, { retryAt: Date.now() });
      return false;
    },

    failSlackReactionCleanup(claim, input) {
      return deps.slackReactionCleanups.fail(claim, input);
    },

    reopenSlackReactionCleanupAfterStaleEffect(claim, input) {
      return deps.slackReactionCleanups.reopenAfterStaleEffect(claim, input);
    },

    getSlackReactionCleanup(input) {
      return deps.slackReactionCleanups.get(input);
    },

    async stopSlackAgentSession(input) {
      const stopped = await deps.slackAgentSessions.recordStop(input);
      if (!stopped.event.applicable || stopped.event.state === "acknowledged") {
        return { applicable: false, acknowledged: true, runIds: [], status: stopped.record.status };
      }
      const bindingTokens = new Set(stopped.event.bindingTokens);
      const bindings = stopped.record.bindings.filter((binding) => bindingTokens.has(binding.token));
      const active = await Promise.all(
        [...new Set(bindings.map((binding) => binding.coreThreadRef))].map((threadRef) =>
          deps.runs.inFlightForThread(threadRef),
        ),
      );
      const recent = await deps.runs.list({ limit: 200 });
      const candidates = [...new Map([...active.flat(), ...recent].map((run) => [run.id, run])).values()];
      const runs = selectSlackAgentStopRuns(candidates, input, stopped.record);
      await Promise.all(
        runs.map((run) => {
          const session = run.request.slackAgentSession;
          return session ? deps.slackAgentSessions.bindRun({ ...session, runId: run.id }) : Promise.resolve(null);
        }),
      );
      const outcomes = await Promise.all(
        runs.filter((run) => !isTerminal(run.status)).map((run) => deps.app.signalRun(run.id, { kind: "abort" })),
      );
      const rejected = outcomes.find((outcome) => !outcome.accepted && outcome.reason !== "terminal");
      if (rejected) throw new Error(`signal abort not accepted: ${rejected.reason ?? "unknown"}`);
      const selectedRunIds = new Set(runs.map((run) => run.id));
      const deferred = bindings.some(
        (binding) =>
          binding.submissionState === "pending" &&
          (binding.submissionPendingUntil ?? 0) > Date.now() &&
          !binding.runIds.some((runId) => selectedRunIds.has(runId)) &&
          !runs.some((run) => run.request.slackAgentSession?.token === binding.token),
      );
      return {
        applicable: true,
        acknowledged: false,
        ...(deferred ? { deferred: true } : {}),
        runIds: runs.map((run) => run.id),
        status: stopped.record.status,
      };
    },

    acknowledgeSlackAgentStop(input) {
      return deps.slackAgentSessions.acknowledgeStop(input);
    },

    bindSlackApprovalAuthority(input) {
      return deps.slackApprovalAuthorities.bind(input);
    },

    getSlackApprovalAuthority(input) {
      return deps.slackApprovalAuthorities.get(input);
    },

    admitSlackApprovalContinuation(input) {
      return deps.slackApprovalAuthorities.admitContinuation(input);
    },

    markSlackApprovalContinuationSubmitted(input) {
      return deps.slackApprovalAuthorities.markContinuationSubmitted(input);
    },

    renewSlackApprovalContinuation(input) {
      return deps.slackApprovalAuthorities.renewContinuation(input);
    },

    settleSlackApprovalContinuation(input) {
      return deps.slackApprovalAuthorities.settleContinuation(input);
    },

    releaseSlackApprovalContinuation(input) {
      return deps.slackApprovalAuthorities.releaseContinuation(input);
    },

    recoverableSlackApprovalContinuations(input) {
      return deps.slackApprovalAuthorities.recoverableContinuations(input);
    },

    submittedSlackApprovalContinuations(input) {
      return deps.slackApprovalAuthorities.submittedContinuations(input);
    },

    async slackApprovalRunRecovery(runId, input) {
      const run = await deps.runs.get(runId);
      const request = run?.request;
      if (!request?.approval || request.surface !== "slack") return null;
      const verified = request.verifiedSlack;
      const deliveryTarget = request.deliveryTarget;
      const splitAt = deliveryTarget?.indexOf(":") ?? -1;
      const targetChannel = splitAt >= 0 ? deliveryTarget?.slice(0, splitAt) : deliveryTarget;
      const targetThreadTs = splitAt >= 0 ? deliveryTarget?.slice(splitAt + 1) : undefined;
      const sessionThreadTs =
        targetThreadTs ??
        (request.origin.kind === "human" &&
        typeof request.origin.messageTs === "string" &&
        /^\d+(?:\.\d+)?$/.test(request.origin.messageTs)
          ? request.origin.messageTs
          : undefined);
      const recoveredSession =
        !request.slackAgentSession && targetChannel && sessionThreadTs
          ? await deps.slackAgentSessions.get({
              teamId: input.teamId,
              agentId: input.agentId,
              channelId: targetChannel,
              threadTs: sessionThreadTs,
            })
          : null;
      const native =
        request.slackAgentSession ??
        (recoveredSession
          ? {
              teamId: input.teamId,
              agentId: input.agentId,
              channelId: targetChannel!,
              threadTs: sessionThreadTs!,
            }
          : undefined);
      const details = request.gatewayContext?.details;
      const requestedByChannel =
        typeof details?.requested_by_channel === "string" ? details.requested_by_channel : undefined;
      const requestedByThreadTs =
        typeof details?.requested_by_thread_ts === "string" ? details.requested_by_thread_ts : undefined;
      let requesterUserId: string | undefined;
      if (typeof verified?.userId === "string") requesterUserId = verified.userId;
      else if (typeof request.actor.id === "string") requesterUserId = request.actor.id;
      return {
        command: "the approved request",
        reason: "requires approval",
        ...(requesterUserId ? { approvalRequesterUserId: requesterUserId } : {}),
        ...(native
          ? {
              nativeAgentSession: {
                teamId: native.teamId,
                agentId: native.agentId,
                channelId: native.channelId,
                threadTs: native.threadTs,
              },
            }
          : {}),
        ...(requestedByChannel && targetChannel && requesterUserId
          ? {
              agentRequest: {
                requesterId: requesterUserId,
                targetUserId: requesterUserId,
                originChannel: requestedByChannel,
                originConversationKind: "channel" as const,
                ...(requestedByThreadTs ? { originThreadTs: requestedByThreadTs } : {}),
                originThreadOnly: !!requestedByThreadTs,
                dmChannel: targetChannel,
                task: request.text,
                originAgentLabel: "the channel agent",
                targetAgentLabel: "the personal agent",
                originResultIdempotencyKey: `run:${runId}:agent-request`,
              },
            }
          : {}),
        request: { ...request, actor: { ...request.actor, externalId: request.actor.id } } as Record<string, unknown>,
      };
    },

    async ackRunDelivery(runId) {
      await deps.app.ackDeliveryByKey(`run:${runId}`);
    },

    async reportTurnMetrics(runId, patch) {
      await deps.metrics.updateByRunId(runId, patch);
    },

    async reportRunEditRef(runId, editRef) {
      const found = await deps.app.setRunDeliveryState(runId, { editRef });
      if (!found) throw new Error(`run ${runId} not found`);
    },

    async getApproval(requestId) {
      const record = await deps.app.getApproval(requestId);
      if (!record) return null;
      return {
        requestId: record.requestId,
        command: record.command,
        ...(record.reason !== undefined ? { reason: record.reason } : {}),
        ...(record.purpose !== undefined ? { purpose: record.purpose } : {}),
        ...(record.summary !== undefined ? { summary: record.summary } : {}),
        ...(record.grantModes !== undefined ? { grantModes: record.grantModes } : {}),
        ...(record.request !== undefined ? { request: record.request as unknown as Record<string, unknown> } : {}),
      };
    },

    async pushDirectory(body) {
      if (body.workspaceUrl) await deps.app.setDirectoryWorkspaceUrl(body.workspaceUrl);
      if (body.members) await deps.app.upsertDirectory(body.members, body.membersSyncedAt);
      if (body.channels)
        await deps.app.upsertChannels(
          body.channels,
          body.channelMembers,
          body.channelsSyncedAt,
          body.channelRosterIds,
          body.channelRevocations,
        );
      if (body.groupMembers)
        await deps.app.upsertGroups(body.groupMembers, body.groupsSyncedAt, body.groupIds, body.groupRosterIds);
    },

    claimDeliveries(type, claimMs) {
      return deps.app.pendingDeliveries(type, claimMs);
    },

    analyticsNativeCard(delivery) {
      return (
        deps.analyticsCardVerifier?.verifyAnalyticsCard(delivery.trustedAnalyticsCard, delivery.destination.target) ??
        null
      );
    },

    async ackDelivery(id, body) {
      if (body?.recipientThreadRef) await deps.app.recordPrincipalDelivery(id, body.recipientThreadRef);
      await deps.app.ackDelivery(id, body?.slackApiMs);
    },

    onDeliveryEnqueued(listener) {
      return deps.deliveries.onEnqueue(listener);
    },

    pendingContextRequests() {
      return deps.app.pendingContextRequests("slack");
    },

    onContextRequest(listener) {
      return deps.app.onContextRequestCreated((request) => {
        if (request.source === "slack") listener(request);
      });
    },

    pickAckEmoji(text, candidates) {
      return deps.pickAckEmoji?.(text, candidates) ?? Promise.resolve(undefined);
    },

    async recordAckPick(pick) {
      if (!deps.ackPicks) return;
      const ackModel = deps.ackModelId?.();
      await deps.ackPicks
        .record({
          surface: "slack",
          channel: pick.channel,
          ts: pick.ts,
          outcome: pick.outcome,
          ...(pick.picked ? { picked: pick.picked } : {}),
          ...(pick.icon ? { icon: pick.icon } : {}),
          ...(pick.message ? { message: pick.message } : {}),
          ...(pick.candidates ? { candidates: pick.candidates } : {}),
          ...(ackModel ? { model: ackModel } : {}),
          ...(pick.latencyMs != null ? { latencyMs: pick.latencyMs } : {}),
          createdAt: Date.now(),
        })
        .catch(() => {});
    },

    async fulfillContextRequest(id, outcome) {
      await deps.app
        .fulfillContextRequest(id, outcome)
        .then((ok) => {
          if (!ok) return;
        })
        .catch(swallowAs("slack-core-client: fulfill context request", undefined));
    },
  };
}
