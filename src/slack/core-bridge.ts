import { swallow } from "../util/errors.ts";
import { sleep, createInFlightThreadMap, type RunTaskView } from "./lib.ts";
import type { SlackAgentStopInput, SlackCoreClient } from "../api/slack-core-client.ts";
import type {
  SlackAgentBindingResult,
  SlackAgentPresentationClaim,
  SlackAgentProviderWriteClaim,
  SlackAgentProviderWriteClaimResult,
  SlackAgentSessionKey,
  SlackAgentSessionStatus,
} from "../surfaces/slack-agent-session.ts";
import type {
  SlackAgentStatusIntentClaim,
  SlackAgentStatusIntentInput,
  SlackAgentStatusIntentRecord,
} from "../surfaces/slack-agent-status-intent.ts";
import type {
  SlackApprovalAuthority,
  SlackApprovalAuthorityKey,
  SlackApprovalContinuationAdmission,
  SlackApprovalContinuationClaim,
  SlackApprovalContinuationInput,
  SlackApprovalSubmittedContinuation,
} from "../surfaces/slack-approval-authority.ts";
import type {
  SlackReactionCleanupClaim,
  SlackReactionCleanupInput,
  SlackReactionCleanupRecord,
} from "../surfaces/slack-reaction-cleanup.ts";
import type { SlackReactionDesireInput, SlackReactionDesireRecord } from "../surfaces/slack-reaction-desire.ts";
import type { SlackReactionCleanupDecision } from "./reaction-cleanup.ts";
import type { TurnRequest, TurnResult } from "../types.ts";

export type CoreTurnBody = Omit<TurnRequest, "surface">;

export interface CoreCallHooks {
  onQueued?: (runId: string) => void | Promise<void>;
  /** The turn was folded into a run that was ALREADY live (a mid-turn steer), so this handler
   *  owns nothing: the envelope is durably accepted, but the reply belongs to the run's owner. */
  onSteered?: (runId: string) => void;
  onDelta?: (delta: string) => void;
  onFirstBlock?: (text: string) => void;
  onSurfacePosted?: () => void;
  onTasks?: (tasks: RunTaskView[]) => void;
  resumeReplay?: boolean;
  deferDeliveryAck?: boolean;
}

export interface CoreBridge {
  callCore(body: CoreTurnBody, hooks?: CoreCallHooks): Promise<TurnResult>;
  inFlightRuns: { add(runId: string): void; delete(runId: string): void; has(runId: string): boolean };
  inFlightRunByThread: ReturnType<typeof createInFlightThreadMap>;
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
  slackAgentPresentationRun(claim: SlackAgentPresentationClaim): Promise<CoreTurnBody | null>;
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
  ): ReturnType<SlackCoreClient["deferSlackAgentProviderWrite"]>;
  completeSlackAgentProviderWrite(input: SlackAgentProviderWriteClaim): Promise<boolean>;
  releaseSlackAgentProviderWrite(input: SlackAgentProviderWriteClaim): Promise<boolean>;
  enqueueSlackAgentStatusIntent(
    input: SlackAgentStatusIntentInput,
  ): ReturnType<SlackCoreClient["enqueueSlackAgentStatusIntent"]>;
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
  resumeRun(runId: string, hooks?: CoreCallHooks): Promise<TurnResult>;
  fetchActiveRunForThread(threadRef: string): Promise<string | undefined>;
  ackRunDelivery(runId: string): Promise<void>;
  ackRunDeliveryWithRetry(runId: string): void;
  reportTurnMetrics(runId: string, patch: { deliverMs?: number; slackInflightMs?: number }): void;
  checkpointRunEditRef(runId: string, editRef: string): Promise<void>;
  reportRunEditRef(runId: string, editRef: string): void;
  stageBlobInCore(bytes: Uint8Array): Promise<{ blobId: string; sizeBytes: number }>;
  fetchBlobFromCore(blobId: string): Promise<Buffer>;
  fetchFileArtifactFromCore(artifactId: string, viewerId: string): Promise<Buffer>;
}

export function createCoreBridge(core: SlackCoreClient): CoreBridge {
  const stageBlobInCore = async (bytes: Uint8Array): Promise<{ blobId: string; sizeBytes: number }> => {
    try {
      return await core.stageBlob(bytes);
    } catch (err) {
      if ((err as Error)?.name === "BlobTooLargeError")
        throw new Error("that request was too large — try fewer or smaller files", { cause: err });
      throw err;
    }
  };
  const fetchBlobFromCore = (blobId: string): Promise<Buffer> => core.readBlob(blobId);
  const fetchFileArtifactFromCore = (artifactId: string, viewerId: string): Promise<Buffer> =>
    core.readFileArtifact(artifactId, viewerId);

  const inFlightRunPins = new Map<string, number>();
  const inFlightRuns = {
    add: (runId: string): void => void inFlightRunPins.set(runId, (inFlightRunPins.get(runId) ?? 0) + 1),
    delete: (runId: string): void => {
      const held = inFlightRunPins.get(runId) ?? 0;
      if (held <= 1) inFlightRunPins.delete(runId);
      else inFlightRunPins.set(runId, held - 1);
    },
    has: (runId: string): boolean => inFlightRunPins.has(runId),
  };

  const inFlightRunByThread = createInFlightThreadMap();

  const signalRunAbort = (runId: string): Promise<void> => core.signalRunAbort(runId);
  const beginSlackAgentSession = (
    input: SlackAgentSessionKey & {
      ownerUserId: string;
      token: string;
      triggerTs: string;
      coreThreadRef: string;
      authorityMessageTs: string;
    },
  ): Promise<SlackAgentBindingResult> => core.beginSlackAgentSession(input);
  const bindSlackAgentRun = (
    input: SlackAgentSessionKey & { token: string; runId: string },
  ): Promise<SlackAgentBindingResult> => core.bindSlackAgentRun(input);
  const claimSlackAgentPresentation = (
    input: SlackAgentSessionKey & { token: string; runId: string },
  ): Promise<SlackAgentPresentationClaim | null> => core.claimSlackAgentPresentation(input);
  const claimSlackAgentPresentations = (input: { teamId: string; agentId: string; limit: number }) =>
    core.claimSlackAgentPresentations(input);
  const renewSlackAgentPresentation = (claim: SlackAgentPresentationClaim) => core.renewSlackAgentPresentation(claim);
  const settleSlackAgentPresentation = (
    claim: SlackAgentPresentationClaim,
    outcome: "delivered" | "cancelled_clean",
  ): Promise<boolean> => core.settleSlackAgentPresentation(claim, outcome);
  const releaseSlackAgentPresentation = (claim: SlackAgentPresentationClaim): Promise<boolean> =>
    core.releaseSlackAgentPresentation(claim);
  const slackAgentPresentationRun = (claim: SlackAgentPresentationClaim): Promise<CoreTurnBody | null> =>
    core.slackAgentPresentationRun(claim);
  const prepareSlackAgentSubmission = (
    input: SlackAgentSessionKey & { token: string },
  ): Promise<SlackAgentBindingResult> => core.prepareSlackAgentSubmission(input);
  const bindSlackAgentStream = (
    input: SlackAgentSessionKey & { token: string; streamTs: string },
  ): Promise<SlackAgentBindingResult> => core.bindSlackAgentStream(input);
  const slackAgentSessionCancelled = (
    input: SlackAgentSessionKey & { token: string; runId?: string },
  ): Promise<boolean> => core.slackAgentSessionCancelled(input);
  const finishSlackAgentSession = (
    input: SlackAgentSessionKey & {
      token: string;
      status: SlackAgentSessionStatus;
      approvalClaim?: { claimId: string; generation: number };
    },
  ): Promise<boolean> => core.finishSlackAgentSession(input);
  const completeSlackAgentSession = (
    input: SlackAgentSessionKey & { token: string; approvalClaim?: { claimId: string; generation: number } },
  ): Promise<boolean> => core.completeSlackAgentSession(input);
  const slackAgentSessionStatus = (input: SlackAgentSessionKey): Promise<SlackAgentSessionStatus | null> =>
    core.slackAgentSessionStatus(input);
  const claimSlackAgentProviderWrite = (
    input: SlackAgentSessionKey & { method: string },
  ): Promise<SlackAgentProviderWriteClaimResult> => core.claimSlackAgentProviderWrite(input);
  const deferSlackAgentProviderWrite = (input: SlackAgentProviderWriteClaim & { notBefore: number }) =>
    core.deferSlackAgentProviderWrite(input);
  const completeSlackAgentProviderWrite = (input: SlackAgentProviderWriteClaim): Promise<boolean> =>
    core.completeSlackAgentProviderWrite(input);
  const releaseSlackAgentProviderWrite = (input: SlackAgentProviderWriteClaim): Promise<boolean> =>
    core.releaseSlackAgentProviderWrite(input);
  const enqueueSlackAgentStatusIntent = (input: SlackAgentStatusIntentInput) =>
    core.enqueueSlackAgentStatusIntent(input);
  const claimSlackAgentStatusIntents = (input: { teamId: string; agentId: string; limit: number }) =>
    core.claimSlackAgentStatusIntents(input);
  const slackAgentStatusIntentClaimActive = (claim: SlackAgentStatusIntentClaim): Promise<boolean> =>
    core.slackAgentStatusIntentClaimActive(claim);
  const completeSlackAgentStatusIntent = (claim: SlackAgentStatusIntentClaim): Promise<boolean> =>
    core.completeSlackAgentStatusIntent(claim);
  const deferSlackAgentStatusIntent = (
    claim: SlackAgentStatusIntentClaim,
    input: { retryAt: number; errorCode: string },
  ): Promise<SlackAgentStatusIntentRecord | null> => core.deferSlackAgentStatusIntent(claim, input);
  const failSlackAgentStatusIntent = (
    claim: SlackAgentStatusIntentClaim,
    input: { retryAt: number; errorCode: string },
  ): Promise<SlackAgentStatusIntentRecord | null> => core.failSlackAgentStatusIntent(claim, input);
  const reopenSlackAgentStatusIntentAfterStaleEffect = (
    claim: SlackAgentStatusIntentClaim,
    input: { retryAt: number },
  ): Promise<SlackAgentStatusIntentRecord | null> => core.reopenSlackAgentStatusIntentAfterStaleEffect(claim, input);
  const getSlackAgentStatusIntent = (input: SlackAgentSessionKey): Promise<SlackAgentStatusIntentRecord | null> =>
    core.getSlackAgentStatusIntent(input);
  const admitSlackReactionDesire = (input: SlackReactionDesireInput) => core.admitSlackReactionDesire(input);
  const withdrawSlackReactionDesire = (input: SlackReactionDesireInput) => core.withdrawSlackReactionDesire(input);
  const cancelSlackReactionDesire = (input: SlackReactionDesireInput) => core.cancelSlackReactionDesire(input);
  const enqueueSlackReactionCleanup = (input: SlackReactionCleanupInput): Promise<SlackReactionCleanupRecord> =>
    core.enqueueSlackReactionCleanup(input);
  const claimSlackReactionCleanups = (input: { teamId: string; agentId: string; limit: number }) =>
    core.claimSlackReactionCleanups(input);
  const slackReactionCleanupAction = (claim: SlackReactionCleanupClaim) => core.slackReactionCleanupAction(claim);
  const completeSlackReactionCleanup = (
    claim: SlackReactionCleanupClaim,
    decision: SlackReactionCleanupDecision,
  ): Promise<boolean> => core.completeSlackReactionCleanup(claim, decision);
  const failSlackReactionCleanup = (
    claim: SlackReactionCleanupClaim,
    input: { retryAt: number; errorCode: string },
  ): Promise<SlackReactionCleanupRecord | null> => core.failSlackReactionCleanup(claim, input);
  const reopenSlackReactionCleanupAfterStaleEffect = (
    claim: SlackReactionCleanupClaim,
    input: { retryAt: number },
  ): Promise<SlackReactionCleanupRecord | null> => core.reopenSlackReactionCleanupAfterStaleEffect(claim, input);
  const getSlackReactionCleanup = (input: { teamId: string; agentId: string; id: string }) =>
    core.getSlackReactionCleanup(input);
  const stopSlackAgentSession = (
    input: SlackAgentStopInput,
  ): Promise<{
    applicable: boolean;
    acknowledged: boolean;
    deferred?: boolean;
    runIds: string[];
    status?: SlackAgentSessionStatus;
  }> => core.stopSlackAgentSession(input);
  const acknowledgeSlackAgentStop = (
    input: SlackAgentSessionKey & { eventId: string; confirmationTs?: string },
  ): Promise<boolean> => core.acknowledgeSlackAgentStop(input);
  const bindSlackApprovalAuthority = (input: Omit<SlackApprovalAuthority, "createdAt">): Promise<boolean> =>
    core.bindSlackApprovalAuthority(input);
  const getSlackApprovalAuthority = (input: SlackApprovalAuthorityKey): Promise<SlackApprovalAuthority | null> =>
    core.getSlackApprovalAuthority(input);
  const admitSlackApprovalContinuation = (input: SlackApprovalContinuationInput) =>
    core.admitSlackApprovalContinuation(input);
  const markSlackApprovalContinuationSubmitted = (input: SlackApprovalContinuationClaim & { runId: string }) =>
    core.markSlackApprovalContinuationSubmitted(input);
  const renewSlackApprovalContinuation = (input: SlackApprovalContinuationClaim) =>
    core.renewSlackApprovalContinuation(input);
  const settleSlackApprovalContinuation = (input: SlackApprovalContinuationClaim) =>
    core.settleSlackApprovalContinuation(input);
  const releaseSlackApprovalContinuation = (input: SlackApprovalContinuationClaim) =>
    core.releaseSlackApprovalContinuation(input);
  const recoverableSlackApprovalContinuations = (input: { teamId: string; agentId: string; limit: number }) =>
    core.recoverableSlackApprovalContinuations(input);
  const submittedSlackApprovalContinuations = (input: { teamId: string; agentId: string }) =>
    core.submittedSlackApprovalContinuations(input);

  const fetchActiveRunForThread = (threadRef: string): Promise<string | undefined> =>
    core.activeRunForThread(threadRef);

  const ackRunDelivery = (runId: string): Promise<void> => core.ackRunDelivery(runId);

  const ACK_RETRY_DELAYS_MS = [2_000, 5_000, 15_000, 30_000];
  function ackRunDeliveryWithRetry(runId: string): void {
    void (async () => {
      for (let attempt = 0; ; attempt++) {
        try {
          await ackRunDelivery(runId);
          return;
        } catch (err) {
          if (attempt >= ACK_RETRY_DELAYS_MS.length) {
            console.error(
              `[slack-plugin] recovery-copy ack failed for run ${runId} (giving up — the poller may re-deliver):`,
              (err as Error).message,
            );
            return;
          }
          await sleep(ACK_RETRY_DELAYS_MS[attempt]!);
        }
      }
    })().finally(() => inFlightRuns.delete(runId));
  }

  function reportTurnMetrics(runId: string, patch: { deliverMs?: number; slackInflightMs?: number }): void {
    if (patch.deliverMs === undefined && patch.slackInflightMs === undefined) return;
    void core
      .reportTurnMetrics(runId, patch)
      .catch((err) =>
        console.error(`[slack-plugin] turn-metrics report failed for run ${runId}:`, (err as Error).message),
      );
  }

  async function checkpointRunEditRef(runId: string, editRef: string): Promise<void> {
    await core.reportRunEditRef(runId, editRef);
  }

  function reportRunEditRef(runId: string, editRef: string): void {
    void checkpointRunEditRef(runId, editRef).catch((err) =>
      console.error(`[slack-plugin] delivery-state checkpoint failed for run ${runId}:`, (err as Error).message),
    );
  }

  function coreFailure(err: unknown): Error {
    swallow("slack: core call", err);
    if ((err as { code?: string })?.code === "run_stalled") {
      return new Error(
        "this request is taking unusually long — I'm still on it and will post the result here as soon as it finishes",
        { cause: err },
      );
    }
    return new Error("I couldn't reach the agent core — it may be busy or deploying; please try again in a moment", {
      cause: err,
    });
  }

  async function callCore(body: CoreTurnBody, hooks: CoreCallHooks = {}): Promise<TurnResult> {
    let queued: TurnResult;
    try {
      queued = await core.submitTurn({ async: true, ...body });
    } catch (err) {
      throw coreFailure(err);
    }
    if (queued.status !== "queued" || !queued.runId) return queued;
    if (queued.replayed) {
      if (hooks.resumeReplay) {
        await hooks.onQueued?.(queued.runId);
        return pollRun(queued.runId, hooks);
      }
      hooks.onSteered?.(queued.runId);
      return { status: "silent", replayed: true, steered: true };
    }
    // A steered turn JOINED a run another handler started; core hands back that LIVE run's id.
    // Polling it here would resolve the same result in both handlers and post the reply twice.
    if (queued.steered) {
      hooks.onSteered?.(queued.runId);
      return { status: "silent", steered: true };
    }
    await hooks.onQueued?.(queued.runId);
    return pollRun(queued.runId, hooks);
  }

  async function pollRun(runId: string, hooks: CoreCallHooks = {}): Promise<TurnResult> {
    inFlightRuns.add(runId);
    let result: TurnResult | null;
    try {
      result = await core.waitRun(runId, {
        ...(hooks.onDelta ? { onDelta: hooks.onDelta } : {}),
        ...(hooks.onFirstBlock ? { onFirstBlock: hooks.onFirstBlock } : {}),
        ...(hooks.onSurfacePosted ? { onSurfacePosted: hooks.onSurfacePosted } : {}),
        ...(hooks.onTasks ? { onTasks: hooks.onTasks } : {}),
      });
    } catch (err) {
      inFlightRuns.delete(runId);
      throw coreFailure(err);
    }
    if (result?.status === "refused" && result.refusalKind === "security_quarantine") {
      return result;
    }
    if (result && (result.status === "ok" || result.status === "refused" || result.status === "failed")) {
      if (!hooks.deferDeliveryAck) ackRunDeliveryWithRetry(runId);
    } else {
      inFlightRuns.delete(runId);
    }
    if (result) return result;
    throw new Error("the agent finished without producing a reply");
  }

  const resumeRun = (runId: string, hooks: CoreCallHooks = {}): Promise<TurnResult> => pollRun(runId, hooks);

  return {
    callCore,
    inFlightRuns,
    inFlightRunByThread,
    signalRunAbort,
    beginSlackAgentSession,
    prepareSlackAgentSubmission,
    bindSlackAgentRun,
    claimSlackAgentPresentation,
    claimSlackAgentPresentations,
    renewSlackAgentPresentation,
    settleSlackAgentPresentation,
    releaseSlackAgentPresentation,
    slackAgentPresentationRun,
    bindSlackAgentStream,
    slackAgentSessionCancelled,
    finishSlackAgentSession,
    completeSlackAgentSession,
    slackAgentSessionStatus,
    claimSlackAgentProviderWrite,
    deferSlackAgentProviderWrite,
    completeSlackAgentProviderWrite,
    releaseSlackAgentProviderWrite,
    enqueueSlackAgentStatusIntent,
    claimSlackAgentStatusIntents,
    slackAgentStatusIntentClaimActive,
    completeSlackAgentStatusIntent,
    deferSlackAgentStatusIntent,
    failSlackAgentStatusIntent,
    reopenSlackAgentStatusIntentAfterStaleEffect,
    getSlackAgentStatusIntent,
    admitSlackReactionDesire,
    withdrawSlackReactionDesire,
    cancelSlackReactionDesire,
    enqueueSlackReactionCleanup,
    claimSlackReactionCleanups,
    slackReactionCleanupAction,
    completeSlackReactionCleanup,
    failSlackReactionCleanup,
    reopenSlackReactionCleanupAfterStaleEffect,
    getSlackReactionCleanup,
    stopSlackAgentSession,
    acknowledgeSlackAgentStop,
    bindSlackApprovalAuthority,
    getSlackApprovalAuthority,
    admitSlackApprovalContinuation,
    markSlackApprovalContinuationSubmitted,
    renewSlackApprovalContinuation,
    settleSlackApprovalContinuation,
    releaseSlackApprovalContinuation,
    recoverableSlackApprovalContinuations,
    submittedSlackApprovalContinuations,
    resumeRun,
    fetchActiveRunForThread,
    ackRunDelivery,
    ackRunDeliveryWithRetry,
    reportTurnMetrics,
    checkpointRunEditRef,
    reportRunEditRef,
    stageBlobInCore,
    fetchBlobFromCore,
    fetchFileArtifactFromCore,
  };
}
