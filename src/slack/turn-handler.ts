import { performance } from "node:perf_hooks";
import { errMessage, swallowAs } from "../util/errors.ts";
import {
  type ActorAssertion,
  type ChannelMeta,
  type ConversationTurn,
  type OverheardMessage,
  type ReactionTally,
  type RunTaskView,
  type AckPresenter,
  type NativeAgentPresenter,
  type NativeAgentStatusIntentRequest,
  type SlackFile,
  type TaskListPresenter,
  DEFAULT_ACK_REACTIONS,
  REACTION_DETECT_GUIDANCE,
  botIdentityArgs,
  buildReactionTurnText,
  createAckPresenter,
  createDeduper,
  createTaskListPresenter,
  createNativeAgentPresenter,
  SlackAgentWriteDeferredError,
  createThreadTracker,
  decodeSlackEntities,
  dedupeKey,
  dedupedRun,
  deliveryCandidatesFor,
  dmThreadRef,
  downloadSlackFile,
  encodeDeliveryTarget,
  groupDmDisplayName,
  hasContent,
  hydrateSlackFiles,
  isExternallyShared,
  isMpim,
  type SurfaceHeaderClient,
  maybeInterceptStop,
  postThenAckRunDelivery,
  postWithVerify,
  processInboundFiles,
  refusalDelivery,
  refusalNote,
  renderConversationView,
  resolveReactionTargets,
  shouldSurfaceReaction,
  slackReplyArgs,
  stripMention,
  threadHasBotStake,
  toSlackMrkdwn,
  uploadAttachments,
  uploadFailureNote,
} from "./lib.ts";
import type { GatewayContext, TurnResult } from "../types.ts";
import type { SlackAgentContextEntity } from "../surfaces/slack-agent-context.ts";
import {
  slackAgentBindingToken,
  type SlackAgentProviderWriteClaim,
  type SlackAgentSessionKey,
} from "../surfaces/slack-agent-session.ts";
import type { AckGate } from "./deferred-ack.ts";
import type { CoreBridge, CoreTurnBody } from "./core-bridge.ts";
import type { BotIdentity, Directory } from "./directory.ts";
import type { Mirror } from "./mirror.ts";
import type { ConversationSerializer } from "./conversation-view.ts";
import { reactionTallies } from "./conversation-view.ts";
import type { Approvals } from "./approvals.ts";
import type { AckEmojiPicker } from "./ack-emoji.ts";
import { drainSlackReactionCleanups, requestSlackReactionCleanup } from "./reaction-cleanup.ts";
import { drainSlackAgentStatusIntents, requestSlackAgentStatusIntent } from "./status-intent.ts";
import {
  type SlackConversationKind,
  applyAndLogReactions,
  cleanAgentReplyForSlack,
  conversationPlaceLabel,
  slackSurfaceInstructions,
  stripSlackDirectives,
} from "./messaging.ts";

interface Incoming {
  kind: "dm" | "channel";
  channel: string;
  userId: string;
  actor?: ActorAssertion;
  authorName?: string;
  rawText: string;
  files: SlackFile[];
  threadTs?: string;
  ts: string;
  unprompted?: boolean;
  botAuthored?: boolean;
  synthetic?: boolean;
  recvAt?: number;
  recvWall?: number;
  ackGate?: AckGate;
  eventTs?: number;
  idempotencyKey?: string;
  agentContext?: SlackAgentContextEntity[];
  prefetched?: {
    actor: ActorAssertion;
    timezone?: string;
    info: ChannelMeta | undefined;
    audience: ActorAssertion[];
    publishMembers?: ActorAssertion[];
    slackIdsByPrincipal?: Map<string, string>;
  };
}

export interface SlackReactionEvent {
  user?: string;
  reaction?: string;
  item_user?: string;
  item?: { type?: string; channel?: string; ts?: string };
  event_ts?: string;
}

export interface SlackAgentSessionStoppedEvent {
  channel_id?: string;
  channel?: string;
  thread_ts?: string;
  message_ts?: string;
  streaming_message_ts?: string[];
  event_id?: string;
  event_ts?: string;
  user?: string;
  team_id?: string;
}

export interface TurnHandler {
  handleIncoming(inc: Incoming, client: any): Promise<void>;
  dispatch(key: string, inc: Incoming, client: any): Promise<void>;
  handleReactionEvent(evt: SlackReactionEvent, body: any, client: any, added: boolean): Promise<void>;
  handleAgentSessionStopped(evt: SlackAgentSessionStoppedEvent, client: any): Promise<void>;
  drainReactionCleanups(client: any): Promise<void>;
  drainStatusIntents(client: any): Promise<void>;
  botHasStakeInThread(client: any, channel: string, threadTs: string): Promise<boolean>;
}

function channelType(kind: SlackConversationKind, conversationKind: SlackConversationKind): string {
  if (kind === "dm") return "im";
  return conversationKind === "group" ? "mpim" : "channel";
}

function channelLocation(
  conversationKind: SlackConversationKind,
  channelName: string | undefined,
  channel: string,
): string {
  if (conversationKind === "group") return "a group direct message";
  return channelName ? `#${channelName}` : `channel ${channel}`;
}

export function createTurnHandler(deps: {
  bridge: CoreBridge;
  directory: Directory;
  mirror: Mirror;
  serializer: ConversationSerializer;
  approvals: Approvals;
  ackEmoji: AckEmojiPicker;
  ackEmojiCandidates?: () => readonly string[] | null;
  ids: BotIdentity;
  threads: ReturnType<typeof createThreadTracker>;
  deduper: ReturnType<typeof createDeduper>;
  externalParticipantsEnabled(): Promise<boolean>;
  markEvent?: () => void;
  botToken: string;
  trustedFileHost?: string;
  ensureHeader?: (
    client: SurfaceHeaderClient,
    channel: string,
    scopeId: string,
    kind: "dm" | "channel",
    ensureOpts?: { pinNew?: boolean },
  ) => void;
}): TurnHandler {
  const {
    bridge,
    directory,
    mirror,
    serializer,
    approvals,
    ackEmoji,
    ids,
    threads,
    deduper,
    externalParticipantsEnabled,
  } = deps;
  const { classifyUserCached, classifyActor, getChannelInfo, channelMembership } = directory;
  const { mirrorSelfPost, mirrorMessageEvent } = mirror;
  const {
    callCore,
    inFlightRuns,
    inFlightRunByThread,
    signalRunAbort,
    beginSlackAgentSession,
    prepareSlackAgentSubmission,
    bindSlackAgentRun,
    bindSlackAgentStream,
    slackAgentSessionCancelled,
    finishSlackAgentSession,
    completeSlackAgentSession,
    slackAgentSessionStatus,
    admitSlackReactionDesire,
    withdrawSlackReactionDesire,
    cancelSlackReactionDesire,
    claimSlackAgentProviderWrite,
    deferSlackAgentProviderWrite,
    completeSlackAgentProviderWrite,
    releaseSlackAgentProviderWrite,
    stopSlackAgentSession,
    acknowledgeSlackAgentStop,
    fetchActiveRunForThread,
    ackRunDeliveryWithRetry,
    reportTurnMetrics,
    checkpointRunEditRef,
    stageBlobInCore,
    fetchBlobFromCore,
    fetchFileArtifactFromCore,
  } = bridge;

  const reactionsInFlight = new Set<string>();
  const incomingDispatches = new Map<string, Promise<boolean>>();
  let reactionCleanupDrain: Promise<void> | undefined;
  let statusIntentDrain: Promise<void> | undefined;
  async function drainStatusIntents(client: any): Promise<void> {
    if (!ids.ownTeamId || !ids.agentId) return;
    if (!statusIntentDrain) {
      statusIntentDrain = drainSlackAgentStatusIntents(bridge, client, {
        teamId: ids.ownTeamId,
        agentId: ids.agentId,
      }).finally(() => {
        statusIntentDrain = undefined;
      });
    }
    await statusIntentDrain;
  }
  async function drainReactionCleanups(client: any): Promise<void> {
    if (!ids.ownTeamId || !ids.agentId) return;
    if (!reactionCleanupDrain) {
      reactionCleanupDrain = drainSlackReactionCleanups(bridge, client, {
        teamId: ids.ownTeamId,
        agentId: ids.agentId,
      }).finally(() => {
        reactionCleanupDrain = undefined;
      });
    }
    await reactionCleanupDrain;
  }
  async function botHasStakeInThread(client: any, channel: string, threadTs: string): Promise<boolean> {
    const cached = threads.get(channel, threadTs);
    if (cached !== undefined) return cached;
    try {
      const res = await client.conversations.replies({ channel, ts: threadTs, limit: 200 });
      const present = threadHasBotStake(res.messages ?? [], ids.botUserId, ids.ownBotId);
      threads.mark(channel, threadTs, present);
      return present;
    } catch {
      return false;
    }
  }

  async function handleIncoming(inc: Incoming, client: any): Promise<void> {
    const t0 = inc.recvAt ?? performance.now();
    const slackInflightMs =
      inc.recvWall !== undefined && inc.eventTs !== undefined
        ? Math.max(0, Math.round(inc.recvWall - inc.eventTs * 1000))
        : undefined;
    let classified: { actor: ActorAssertion; timezone?: string };
    if (inc.actor) classified = { actor: inc.actor };
    else if (inc.prefetched)
      classified = {
        actor: inc.prefetched.actor,
        ...(inc.prefetched.timezone ? { timezone: inc.prefetched.timezone } : {}),
      };
    else classified = await classifyUserCached(client, inc.userId);
    const actor = classified.actor;
    const timezone = classified.timezone;
    const text = stripMention(inc.rawText, ids.botUserId);
    if (!hasContent(text, inc.files)) return;

    let audience: ActorAssertion[] = [actor];
    let channelRef: string | undefined;
    let channelName: string | undefined;
    let threadRef: string;
    let replyThreadTs: string | undefined;
    let isPrivate: boolean | undefined;
    let isMpimChannel: boolean | undefined;
    let publishMembers: ActorAssertion[] | undefined;
    let channelInfo: ChannelMeta | undefined;
    let slackIdsByPrincipal: Map<string, string> | undefined;
    let conversationKind: SlackConversationKind = inc.kind;
    let allowedTs: Set<string> = new Set();
    let deliveryCancelled = async (): Promise<boolean> => false;
    const postReply = async (msg: string, blocks?: Array<Record<string, unknown>>): Promise<string | undefined> => {
      if (await deliveryCancelled()) return undefined;
      const posted = await client.chat.postMessage({
        ...slackReplyArgs(inc.channel, msg, replyThreadTs, { threadOnly: inc.kind === "channel", unfurlLinks: false }),
        ...(blocks ? { blocks } : {}),
      });
      const ts = posted.ts as string | undefined;
      if (ts && (await deliveryCancelled())) {
        await client.chat.delete?.({ channel: inc.channel, ts }).catch(() => undefined);
        return undefined;
      }
      mirrorSelfPost(inc.channel, ts, msg, { sub: replyThreadTs });
      return ts;
    };

    const ephemeralOrSay = async (msg: string): Promise<void> => {
      if (inc.kind === "channel") {
        await client.chat
          .postEphemeral({ channel: inc.channel, user: inc.userId, text: msg })
          .catch(swallowAs("slack: chat.postEphemeral", undefined));
      } else {
        await postReply(msg);
      }
    };

    if (inc.kind === "dm") {
      threadRef = dmThreadRef(inc.channel, inc.threadTs);
      replyThreadTs = inc.threadTs;
      if (!actor.isBot && !actor.isExternalGuest)
        deps.ensureHeader?.(client, inc.channel, `personal:${actor.externalId}`, "dm");
    } else {
      channelRef = inc.channel;
      const info = inc.prefetched ? inc.prefetched.info : await getChannelInfo(client, inc.channel);
      channelInfo = info;
      isPrivate = info?.is_private;
      isMpimChannel = isMpim(info);
      if (isMpimChannel) conversationKind = "group";
      channelName = info?.name;
      if (!isMpimChannel && !isExternallyShared(info) && !actor.isBot && !actor.isExternalGuest)
        deps.ensureHeader?.(client, inc.channel, `channel:${inc.channel}`, "channel");
      const root = inc.threadTs ?? inc.ts;
      threadRef = `${conversationKind === "group" ? "grp" : "ch"}:${inc.channel}:${root}`;
      replyThreadTs = root;
    }

    let queuedRunId: string | undefined;
    let ack: AckPresenter | undefined;
    let taskList: TaskListPresenter | undefined;
    let nativeAgent: NativeAgentPresenter | undefined;

    if (inc.kind === "channel") {
      const membership = inc.prefetched
        ? {
            audience: inc.prefetched.audience,
            publishMembers: inc.prefetched.publishMembers,
            slackIdsByPrincipal: inc.prefetched.slackIdsByPrincipal,
          }
        : await channelMembership(client, inc.channel, actor, inc.userId, channelInfo);
      audience = membership.audience;
      publishMembers = membership.publishMembers;
      slackIdsByPrincipal = membership.slackIdsByPrincipal;
      if (conversationKind === "group") channelName = groupDmDisplayName(audience) ?? channelName;
    }

    const gatewayContext: GatewayContext =
      inc.kind === "dm"
        ? {
            location: "a direct message with the user",
            details: { channel: inc.channel, ...(inc.threadTs ? { thread_ts: inc.threadTs } : {}) },
            instructions: slackSurfaceInstructions(inc.kind),
            reactionGuidance: REACTION_DETECT_GUIDANCE,
            ...(ids.botHandle ? { botHandle: ids.botHandle } : {}),
          }
        : {
            location: channelLocation(conversationKind, channelName, inc.channel),
            details: {
              channel: inc.channel,
              ...(channelName
                ? { channel_name: conversationPlaceLabel(conversationKind, channelName, inc.channel) }
                : {}),
              ...(replyThreadTs ? { thread_ts: replyThreadTs } : {}),
            },
            instructions: slackSurfaceInstructions(inc.kind),
            reactionGuidance: REACTION_DETECT_GUIDANCE,
            ...(ids.botHandle ? { botHandle: ids.botHandle } : {}),
          };
    if (inc.agentContext?.length) {
      const values = inc.agentContext.slice(0, 12).map((entity) => {
        const value =
          typeof entity.value === "string" ? entity.value : `${entity.value.channelId}:${entity.value.messageTs}`;
        return `${entity.type.replace("slack#/types/", "")}:${value}`;
      });
      gatewayContext.details = { ...gatewayContext.details, active_slack_view: values.join(", ") };
    }

    if (audience.some((a) => a.isExternalGuest) && !(await externalParticipantsEnabled())) {
      if (!inc.unprompted) {
        await ephemeralOrSay(
          "I can't respond here — this conversation isn't fully internal. Try a DM or a fully-internal channel.",
        );
      }
      return;
    }

    if (!inc.unprompted) {
      const intercepted = await maybeInterceptStop({
        text,
        threadRef,
        getInFlightRun: (ref) =>
          inFlightRunByThread.get(ref) ??
          fetchActiveRunForThread(ref).catch(swallowAs("slack: active-run lookup", undefined)),
        signalAbort: signalRunAbort,
      }).catch(swallowAs("slack: abort signal", true));
      if (intercepted) return;
    }

    const settleAck = async (): Promise<void> => {
      await ack?.settle().catch(swallowAs("slack: ack settle", undefined));
    };

    {
      const containerName = inc.kind === "dm" ? actor.displayName?.trim() || undefined : channelName;
      void mirrorMessageEvent(
        {
          channel: inc.channel,
          ts: inc.ts,
          text: inc.rawText,
          user: inc.userId,
          thread_ts: inc.threadTs,
          channel_type: channelType(inc.kind, conversationKind),
        },
        client,
        { kind: conversationKind, handled: true, ...(containerName ? { containerName } : {}) },
      );
    }

    if (inc.kind === "channel" && replyThreadTs) threads.mark(inc.channel, replyThreadTs, true);

    let conversationHeader: string | undefined;
    let priorTurns: ConversationTurn[] | undefined;
    let overheard: OverheardMessage[] | undefined;
    let detectContext: string | undefined;
    let detectOpener: string | undefined;
    let earlierFiles: SlackFile[] = [];
    if (inc.kind === "channel" || (inc.kind === "dm" && inc.threadTs)) {
      const serialized = await serializer.serializeSlackConversation(client, inc, {
        audience,
        ...(channelName ? { channelName } : {}),
        ...(isPrivate !== undefined ? { isPrivate } : {}),
        kind: conversationKind,
        ...(slackIdsByPrincipal ? { slackIdsByPrincipal } : {}),
      });
      earlierFiles = serialized.earlierFiles;
      const rendered = renderConversationView(serialized.view);
      if (rendered.header) conversationHeader = rendered.header;
      if (rendered.priorTurns.length) priorTurns = rendered.priorTurns;
      if (rendered.overheard.length) overheard = rendered.overheard;
      if (rendered.detectContext) detectContext = rendered.detectContext;
      if (rendered.detectOpener) detectOpener = rendered.detectOpener;
      allowedTs = rendered.allowedTs;
    }

    const ownFiles = inc.files.map((f) => (f.user || !inc.userId ? f : { ...f, user: inc.userId }));
    const inboundFiles = await hydrateSlackFiles(
      earlierFiles.length ? [...ownFiles, ...earlierFiles] : ownFiles,
      async (id) => {
        const response = await client.files.info({ file: id });
        return response?.file as SlackFile | undefined;
      },
    );
    const resolveFileAuthor = async (userId: string | undefined): Promise<string | undefined> =>
      userId ? (await classifyUserCached(client, userId)).actor.displayName : undefined;
    const { attachments, issues } = await processInboundFiles(
      inboundFiles,
      (f) =>
        downloadSlackFile(f, {
          token: deps.botToken,
          ...(deps.trustedFileHost ? { trustedHost: deps.trustedFileHost } : {}),
        }),
      (bytes) => stageBlobInCore(bytes),
      resolveFileAuthor,
    );

    if (inc.unprompted && !text.trim() && attachments.length === 0) return;

    const turn: Omit<CoreTurnBody, "approval"> = {
      trustedSlackTeamId: ids.ownTeamId,
      trustedSlackUserId: inc.userId,
      actor,
      conversation: {
        kind: conversationKind,
        threadRef,
        ...(channelRef ? { channelRef } : {}),
        ...(channelName ? { channelName } : {}),
        audience,
        ...(isPrivate !== undefined ? { isPrivate } : {}),
        ...(isMpimChannel !== undefined ? { isMpim: isMpimChannel } : {}),
        ...(publishMembers ? { publishMembers } : {}),
      },
      deliveryTarget: encodeDeliveryTarget(inc.channel, replyThreadTs),
      ...(() => {
        const candidates = deliveryCandidatesFor(conversationKind, inc.channel, replyThreadTs, channelName);
        return candidates ? { deliveryCandidates: candidates } : {};
      })(),
      text,
      gatewayContext,
      ...(inc.unprompted
        ? {
            unprompted: true,
            ...(inc.synthetic
              ? {}
              : { entryTs: inc.ts, ...(actor.isBot || inc.botAuthored ? {} : { liveActor: true }) }),
          }
        : { liveActor: true, triggerTs: inc.ts }),
      ...(!inc.unprompted && !inc.synthetic && !actor.isBot && !actor.isExternalGuest
        ? {
            verifiedSlack: {
              teamId: ids.ownTeamId,
              userId: inc.userId,
              channelId: inc.channel,
              messageTs: inc.ts,
              threadTs: inc.threadTs ?? inc.ts,
              threaded: inc.threadTs !== undefined,
              liveHuman: true as const,
            },
          }
        : {}),
      ...(actor.isBot ? { botActor: true } : {}),
      ...(conversationHeader ? { conversationHeader } : {}),
      ...(priorTurns ? { priorTurns } : {}),
      ...(overheard ? { overheard } : {}),
      ...(detectContext ? { detectContext } : {}),
      ...(detectOpener ? { detectOpener } : {}),
      ...(attachments.length ? { attachments } : {}),
      ...(issues.length ? { inboundNotes: issues } : {}),
      ...(timezone ? { timezone } : {}),
      ...(inc.idempotencyKey ? { idempotencyKey: inc.idempotencyKey } : {}),
    };
    const nativeSessionKey: SlackAgentSessionKey = {
      teamId: ids.ownTeamId,
      agentId: ids.agentId,
      channelId: inc.channel,
      threadTs: replyThreadTs ?? inc.ts,
    };
    let nativeRunToken: string | undefined;
    const alreadyStoppedStreams = new Set<string>();
    const beforeProviderWrite = async (method: string): Promise<SlackAgentProviderWriteClaim> => {
      const claimed = await claimSlackAgentProviderWrite({ ...nativeSessionKey, method });
      if (!claimed.acquired) {
        throw new SlackAgentWriteDeferredError(
          Math.max(1, claimed.notBefore - Date.now()),
          new Error(`durable Slack provider ${claimed.reason}`),
        );
      }
      return claimed.claim;
    };
    const onProviderDeferred = async (
      _method: string,
      error: SlackAgentWriteDeferredError,
      claim: SlackAgentProviderWriteClaim | undefined,
    ): Promise<void> => {
      if (!claim) throw new Error("Slack provider retry is missing its durable write claim");
      const deferred = await deferSlackAgentProviderWrite({ ...claim, notBefore: Date.now() + error.retryAfterMs });
      if (!deferred.applied) throw new Error("Slack provider retry claim is stale");
    };
    const onProviderWriteSucceeded = async (
      _method: string,
      claim: SlackAgentProviderWriteClaim | undefined,
    ): Promise<void> => {
      if (!claim || !(await completeSlackAgentProviderWrite(claim))) {
        throw new Error("Slack provider success claim is stale");
      }
    };
    const onProviderWriteFailed = async (
      _method: string,
      _error: unknown,
      claim: SlackAgentProviderWriteClaim | undefined,
    ): Promise<void> => {
      if (claim) await releaseSlackAgentProviderWrite(claim);
    };
    const nativeRunWasStopped = async (): Promise<boolean> => {
      if (!nativeRunToken) return false;
      try {
        return await slackAgentSessionCancelled({
          ...nativeSessionKey,
          token: nativeRunToken,
          ...(queuedRunId ? { runId: queuedRunId } : {}),
        });
      } catch {
        return true;
      }
    };
    const compensateCreatedReaction = async (input: {
      channel: string;
      timestamp: string;
      name: string;
      effectId: string;
      sequence: number;
    }): Promise<"confirmed" | "pending" | "manual_attention"> => {
      if (!nativeRunToken) return "manual_attention";
      return requestSlackReactionCleanup(bridge, client, {
        teamId: nativeSessionKey.teamId,
        agentId: nativeSessionKey.agentId,
        sessionChannelId: nativeSessionKey.channelId,
        sessionThreadTs: nativeSessionKey.threadTs,
        sessionToken: nativeRunToken,
        effectId: input.effectId,
        sourceTs: inc.ts,
        sequence: input.sequence,
        channelId: input.channel,
        messageTs: input.timestamp,
        name: input.name,
      });
    };
    const admitDesiredReaction = async (input: {
      channel: string;
      timestamp: string;
      name: string;
      effectId: string;
      sequence: number;
    }): Promise<boolean> => {
      if (!nativeRunToken) return false;
      const admitted = await admitSlackReactionDesire({
        teamId: nativeSessionKey.teamId,
        agentId: nativeSessionKey.agentId,
        sessionChannelId: nativeSessionKey.channelId,
        sessionThreadTs: nativeSessionKey.threadTs,
        sessionToken: nativeRunToken,
        effectId: input.effectId,
        sourceTs: inc.ts,
        sequence: input.sequence,
        channelId: input.channel,
        messageTs: input.timestamp,
        name: input.name,
      });
      return admitted.disposition !== "superseded" && admitted.record.desired;
    };
    const cancelDesiredReaction = async (input: {
      channel: string;
      timestamp: string;
      name: string;
      effectId: string;
      sequence: number;
    }): Promise<void> => {
      if (!nativeRunToken) return;
      await cancelSlackReactionDesire({
        teamId: nativeSessionKey.teamId,
        agentId: nativeSessionKey.agentId,
        sessionChannelId: nativeSessionKey.channelId,
        sessionThreadTs: nativeSessionKey.threadTs,
        sessionToken: nativeRunToken,
        effectId: input.effectId,
        sourceTs: inc.ts,
        sequence: input.sequence,
        channelId: input.channel,
        messageTs: input.timestamp,
        name: input.name,
      });
    };
    const withdrawDesiredReaction = async (input: {
      channel: string;
      timestamp: string;
      name: string;
      effectId: string;
      sequence: number;
    }): Promise<void> => {
      if (!nativeRunToken) return;
      await withdrawSlackReactionDesire({
        teamId: nativeSessionKey.teamId,
        agentId: nativeSessionKey.agentId,
        sessionChannelId: nativeSessionKey.channelId,
        sessionThreadTs: nativeSessionKey.threadTs,
        sessionToken: nativeRunToken,
        effectId: input.effectId,
        sourceTs: inc.ts,
        sequence: input.sequence,
        channelId: input.channel,
        messageTs: input.timestamp,
        name: input.name,
      });
    };
    const consumeStoppedRun = nativeRunWasStopped;
    const writeStatusIntent = async (input: NativeAgentStatusIntentRequest): Promise<void> => {
      if (!nativeRunToken) throw new Error("Slack Agent status intent is missing its exact binding token");
      const sequence = {
        begin_processing: 0,
        begin_cancelled: 1,
        begin_failed: 2,
        finish: 10,
      }[input.phase];
      const result = await requestSlackAgentStatusIntent(bridge, client, {
        ...nativeSessionKey,
        authority: { kind: "binding", token: nativeRunToken },
        sourceTs: inc.ts,
        sequence,
        status: input.status,
        ...(input.createSession ? { createSession: input.createSession } : {}),
      });
      if (result.verdict === "confirmed") return;
      throw new SlackAgentWriteDeferredError(
        Math.max(1, (result.retryAt ?? Date.now() + 1_000) - Date.now()),
        new Error("durable Slack Agent status intent is pending"),
      );
    };
    if (!inc.unprompted) {
      const prospectiveThreadRef = inc.kind === "dm" && !inc.threadTs ? dmThreadRef(inc.channel, inc.ts) : threadRef;
      const proposedToken = slackAgentBindingToken(nativeSessionKey, inc.userId, inc.ts, inc.ts);
      const begun = await beginSlackAgentSession({
        ...nativeSessionKey,
        ownerUserId: inc.userId,
        token: proposedToken,
        triggerTs: inc.ts,
        coreThreadRef: prospectiveThreadRef,
        authorityMessageTs: inc.ts,
      });
      nativeRunToken = begun.binding?.token;
      if (!begun.accepted || !nativeRunToken || begun.cancelled) return;
      turn.slackAgentSessionToken = nativeRunToken;
      turn.slackAgentSession = { ...nativeSessionKey, token: nativeRunToken };
      deliveryCancelled = nativeRunWasStopped;
      const candidate = createNativeAgentPresenter({
        client,
        channel: inc.channel,
        threadTs: replyThreadTs ?? inc.ts,
        initiatorUserId: inc.userId,
        recipientTeamId: ids.ownTeamId,
        createSession: begun.created,
        title: text,
        sanitize: stripSlackDirectives,
        checkpoint: async (ts) => {
          const bound = await bindSlackAgentStream({ ...nativeSessionKey, token: nativeRunToken!, streamTs: ts });
          if (bound.binding?.streamStopState === "listed") alreadyStoppedStreams.add(ts);
          if (queuedRunId) await checkpointRunEditRef(queuedRunId, ts);
          return bound.cancelled;
        },
        alreadyStopped: async (ts) => alreadyStoppedStreams.has(ts),
        beforeProviderWrite,
        onProviderDeferred,
        onProviderWriteSucceeded,
        onProviderWriteFailed,
        resolveStatus: async (status) => {
          const persisted = await finishSlackAgentSession({ ...nativeSessionKey, token: nativeRunToken!, status });
          if (!persisted) throw new Error("Slack Agent Session status was not persisted");
          return (await slackAgentSessionStatus(nativeSessionKey)) ?? status;
        },
        onSurfacePosted: () => {},
        writeStatusIntent,
        isCancelled: nativeRunWasStopped,
        onError: (error) => console.error("[slack-plugin] native agent presentation failed:", (error as Error).message),
      });
      if (await candidate.begin()) {
        nativeAgent = candidate;
        if (inc.kind === "dm" && !inc.threadTs) {
          replyThreadTs = inc.ts;
          threadRef = dmThreadRef(inc.channel, inc.ts);
          turn.conversation.threadRef = threadRef;
          turn.deliveryTarget = encodeDeliveryTarget(inc.channel, replyThreadTs);
          const candidates = deliveryCandidatesFor(conversationKind, inc.channel, replyThreadTs, channelName);
          if (candidates) turn.deliveryCandidates = candidates;
          turn.gatewayContext = {
            ...turn.gatewayContext,
            details: { ...turn.gatewayContext?.details, thread_ts: inc.ts },
          };
        }
      } else {
        if (await consumeStoppedRun()) return;
        await finishSlackAgentSession({ ...nativeSessionKey, token: nativeRunToken, status: "active" });
        await completeSlackAgentSession({ ...nativeSessionKey, token: nativeRunToken });
        nativeRunToken = undefined;
        delete turn.slackAgentSessionToken;
        delete turn.slackAgentSession;
        deliveryCancelled = async () => false;
      }
      if (await consumeStoppedRun()) return;
    }
    if (!inc.unprompted && !nativeAgent) {
      ack = createAckPresenter({
        postAck: async (ackText) => {
          const rendered = toSlackMrkdwn(ackText);
          if (await taskList?.addLead(rendered)) return;
          const ts = await postReply(rendered);
          if (ts) await taskList?.attach(ts, rendered);
        },
        addReaction: (name) => client.reactions.add({ channel: inc.channel, timestamp: inc.ts, name }).then(() => {}),
        removeReaction: (name) =>
          client.reactions.remove({ channel: inc.channel, timestamp: inc.ts, name }).then(() => {}),
        emojiCandidates: (() => {
          const override = deps.ackEmojiCandidates?.();
          return override?.length ? [...override] : [...DEFAULT_ACK_REACTIONS];
        })(),
        emojiPick: ackEmoji.requestAckEmoji(text, ackEmoji.ackPickCandidates(client), {
          channel: inc.channel,
          ts: inc.ts,
        }),
      });
      taskList = createTaskListPresenter({
        post: (taskText, blocks) => postReply(taskText, blocks),
        update: (ts, taskText, blocks) =>
          client.chat.update({ channel: inc.channel, ts, text: taskText, blocks, ...botIdentityArgs() }).then(() => {
            mirrorSelfPost(inc.channel, ts, taskText, { sub: replyThreadTs, editedAt: Date.now() });
          }),
        checkpoint: async (ts) => {
          if (queuedRunId) await checkpointRunEditRef(queuedRunId, ts);
        },
        remove: (ts) => client.chat.delete({ channel: inc.channel, ts }).then(() => {}),
        onSurfacePosted: () => ack?.onSurfacePosted(),
        onError: (error) => console.error("[slack-plugin] task-list update failed:", (error as Error).message),
      });
    }
    const finishNative = async (nativeText: string, status: "active" | "suspended" = "active"): Promise<boolean> => {
      if (!nativeAgent) return false;
      if (await nativeRunWasStopped()) return true;
      try {
        await nativeAgent.finish(nativeText, status);
      } catch (error) {
        console.error("[slack-plugin] native final delivery failed:", (error as Error).message);
        if (nativeText && !(await nativeRunWasStopped())) await postReply(toSlackMrkdwn(nativeText));
      }
      return true;
    };
    if (nativeRunToken) {
      const prepared = await prepareSlackAgentSubmission({ ...nativeSessionKey, token: nativeRunToken });
      if (!prepared.accepted) throw new Error("Slack Agent Session submission preparation was rejected");
      if (prepared.cancelled) return;
    }
    const tSubmit = performance.now();
    let result: TurnResult;
    try {
      result = await callCore(
        { ...turn, intakePreambleMs: Math.round(tSubmit - t0), clientSentAt: Date.now() },
        {
          onQueued: async (runId) => {
            queuedRunId = runId;
            inFlightRunByThread.set(threadRef, runId);
            if (nativeRunToken) {
              let binding;
              try {
                binding = await bindSlackAgentRun({ ...nativeSessionKey, token: nativeRunToken, runId });
              } catch (error) {
                await signalRunAbort(runId).catch(swallowAs("slack: abort unbound native run", undefined));
                throw error;
              }
              if (binding.cancelled) {
                await signalRunAbort(runId).catch(swallowAs("slack: abort stopped native run", undefined));
              }
            }
            inc.ackGate?.persisted();
          },
          // Folded into a live run: the envelope is durably accepted just the same, but the run
          // stays pinned to its own handler — claiming it here would unpin it on the way out.
          onSteered: () => inc.ackGate?.persisted(),
          ...(ack
            ? {
                onFirstBlock: (blockText: string) => {
                  ack.onFirstBlock(cleanAgentReplyForSlack(blockText).text);
                },
                onSurfacePosted: () => ack.onSurfacePosted(),
              }
            : {}),
          ...(nativeAgent
            ? {
                onDelta: (delta: string) => {
                  nativeAgent?.onDelta(delta);
                },
              }
            : {}),
          ...(taskList
            ? {
                onTasks: async (tasks: RunTaskView[]) => {
                  await ack?.drain();
                  await taskList?.onTasks(tasks);
                },
              }
            : {}),
          ...(nativeAgent
            ? {
                onTasks: async (tasks: RunTaskView[]) => {
                  if (!(await nativeRunWasStopped())) await nativeAgent?.onTasks(tasks);
                },
              }
            : {}),
        },
      );
      await taskList?.settle();
    } catch (err) {
      try {
        if (!queuedRunId) inc.ackGate?.failed("turn was not durably accepted");
        await settleAck();
        const failureText = `⚠️ ${(err as Error).message}`;
        if (inc.unprompted)
          console.error(
            `[slack-plugin] unprompted turn errored (staying quiet) ch=${inc.channel} ts=${inc.ts}: ${(err as Error).message}`,
          );
        else if (nativeAgent && (await consumeStoppedRun())) {
          return;
        } else if (nativeAgent) {
          await finishNative(failureText);
        } else if (ack?.postedAck()) await postReply(failureText);
        else await ephemeralOrSay(failureText);
        return;
      } finally {
        if (nativeRunToken && !nativeAgent) {
          await finishSlackAgentSession({ ...nativeSessionKey, token: nativeRunToken, status: "active" }).catch(
            () => false,
          );
        }
        if (nativeRunToken) {
          await completeSlackAgentSession({ ...nativeSessionKey, token: nativeRunToken }).catch(() => false);
        }
      }
    } finally {
      if (queuedRunId) inFlightRunByThread.clear(threadRef, queuedRunId);
    }

    try {
      // This message was folded into a run that was already live. The handler that OWNS that run
      // delivers its reply; delivering here too is how one answer got posted twice. Settle this
      // trigger's own ack and stand down.
      if (result.steered) {
        await settleAck();
        return;
      }

      if (nativeAgent && (await consumeStoppedRun())) {
        await settleAck();
        return;
      }

      if (result.status === "silent") {
        if (inc.unprompted) console.error(`[slack-plugin] turn.silent (no reply) ch=${inc.channel} ts=${inc.ts}`);
        await settleAck();
        if (nativeAgent && (await consumeStoppedRun())) return;
        await finishNative("");
        return;
      }

      if (result.status === "react") {
        await settleAck();
        if (nativeAgent && (await consumeStoppedRun())) return;
        await finishNative("");
        if (nativeAgent && (await consumeStoppedRun())) return;
        const names = result.reactions ?? [];
        if (names.length)
          await applyAndLogReactions(client, inc.channel, inc.ts, [{ names }], {
            isCancelled: nativeRunWasStopped,
            ...(nativeRunToken
              ? {
                  compensateCreatedReaction,
                  reactionEffectScopeId: `${nativeRunToken}:react-result`,
                  reactionEffectSequenceBase: 0,
                  admitDesiredReaction,
                  withdrawDesiredReaction,
                  cancelDesiredReaction,
                }
              : {}),
          });
        console.error(
          `[slack-plugin] turn.react (acknowledged) ch=${inc.channel} ts=${inc.ts} emoji=${names.join(",")}`,
        );
        return;
      }

      if (result.status === "ok") {
        if (inc.kind === "channel" && replyThreadTs) threads.mark(inc.channel, replyThreadTs, true);
        const { text: replyBody, reactions, agentRequests } = cleanAgentReplyForSlack(result.reply ?? "");
        const actionableAgentRequests = inc.kind === "channel" ? agentRequests : [];
        const hasNonText = !!(
          result.attachments?.length ||
          reactions.length ||
          actionableAgentRequests.length ||
          result.pendingApprovals?.length
        );
        let reply = "(no response)";
        if (replyBody) reply = toSlackMrkdwn(replyBody);
        else if (hasNonText) reply = "";
        const postText = reply;
        const tDeliverStart = performance.now();
        let finalizedTaskList = false;
        if (nativeAgent && (await consumeStoppedRun())) return;
        if (result.attachments?.length) {
          let uploadError: unknown;
          try {
            await uploadAttachments(
              client,
              inc.channel,
              replyThreadTs,
              result.attachments,
              fetchBlobFromCore,
              fetchFileArtifactFromCore,
              { isCancelled: nativeRunWasStopped },
            );
          } catch (err) {
            uploadError = err;
            console.error("[slack-plugin] file upload failed:", (err as Error).message);
          }
          if (nativeAgent && (await consumeStoppedRun())) {
            await settleAck();
            return;
          }
          await settleAck();
          if (postText && nativeAgent) {
            await finishNative(replyBody, result.pendingApprovals?.length ? "suspended" : "active");
          } else if (postText) {
            finalizedTaskList = (await taskList?.finalize(postText)) ?? false;
            if (!finalizedTaskList) await postReply(postText);
          } else if (nativeAgent) {
            await finishNative("", result.pendingApprovals?.length ? "suspended" : "active");
          }
          if (uploadError && !(await nativeRunWasStopped())) await postReply(uploadFailureNote(uploadError));
        } else {
          await settleAck();
          if (nativeAgent && (await consumeStoppedRun())) return;
          if (postText && nativeAgent) {
            await finishNative(replyBody, result.pendingApprovals?.length ? "suspended" : "active");
          } else if (postText) {
            finalizedTaskList = (await taskList?.finalize(postText)) ?? false;
            if (!finalizedTaskList) await postReply(postText);
          } else if (nativeAgent) {
            await finishNative("", result.pendingApprovals?.length ? "suspended" : "active");
          }
        }
        if (nativeAgent && (await consumeStoppedRun())) return;
        if (queuedRunId) {
          reportTurnMetrics(queuedRunId, {
            deliverMs: Math.round(performance.now() - tDeliverStart),
            ...(slackInflightMs !== undefined ? { slackInflightMs } : {}),
          });
        }
        const { directives, dropped } = resolveReactionTargets(reactions, allowedTs);
        if (dropped) console.error(`[slack-plugin] dropped ${dropped} reaction(s) with an unresolvable message id`);
        if (nativeAgent && (await consumeStoppedRun())) return;
        await applyAndLogReactions(client, inc.channel, inc.ts, directives, {
          isCancelled: nativeRunWasStopped,
          ...(nativeRunToken
            ? {
                compensateCreatedReaction,
                reactionEffectScopeId: `${nativeRunToken}:reply-result`,
                reactionEffectSequenceBase: 100,
                admitDesiredReaction,
                withdrawDesiredReaction,
                cancelDesiredReaction,
              }
            : {}),
        });
        if (nativeAgent && (await consumeStoppedRun())) return;
        if (actionableAgentRequests.length) {
          await approvals.postAgentRequests(
            client,
            {
              requesterId: inc.userId,
              channel: inc.channel,
              ...(replyThreadTs ? { replyThreadTs } : {}),
              threadOnly: true,
              kind: conversationKind,
              ...(channelName ? { channelName } : {}),
              audience,
              ...(slackIdsByPrincipal ? { slackIdsByPrincipal } : {}),
              isCancelled: nativeRunWasStopped,
            },
            actionableAgentRequests,
          );
        }
        if (nativeAgent && (await consumeStoppedRun())) return;
        if (result.pendingApprovals?.length) {
          await approvals.postApprovalButtons(
            client,
            {
              requesterId: inc.userId,
              channel: inc.channel,
              ...(replyThreadTs ? { replyThreadTs } : {}),
              triggerTs: inc.ts,
              threadOnly: inc.kind === "channel",
              turn,
              ...(allowedTs.size ? { allowedTs } : {}),
              ...(slackIdsByPrincipal ? { slackIdsByPrincipal } : {}),
              ...(ack?.postedAck() ? { ackedFirstBlock: ack.postedAck() } : {}),
              ...(nativeAgent ? { nativeAgentSession: nativeSessionKey } : {}),
              isCancelled: nativeRunWasStopped,
            },
            result.pendingApprovals,
          );
        }
      } else if (result.status === "pending_approval") {
        const pendingApprovals = result.pendingApprovals ?? [];
        const baseCtx = {
          requesterId: inc.userId,
          channel: inc.channel,
          ...(replyThreadTs ? { replyThreadTs } : {}),
          triggerTs: inc.ts,
          threadOnly: inc.kind === "channel",
          turn,
          ...(allowedTs.size ? { allowedTs } : {}),
          ...(slackIdsByPrincipal ? { slackIdsByPrincipal } : {}),
          ...(ack?.postedAck() ? { ackedFirstBlock: ack.postedAck() } : {}),
          ...(nativeAgent ? { nativeAgentSession: nativeSessionKey } : {}),
          isCancelled: nativeRunWasStopped,
        };
        await settleAck();
        if (nativeAgent && (await consumeStoppedRun())) return;
        await finishNative("", "suspended");
        if (nativeAgent && (await consumeStoppedRun())) return;
        await approvals.postApprovalButtons(client, baseCtx, pendingApprovals);
      } else {
        await settleAck();
        if (nativeAgent && (await consumeStoppedRun())) return;
        const delivery = refusalDelivery(result, inc.unprompted === true);
        if (delivery === "thread") {
          if (nativeAgent) {
            await finishNative(refusalNote(result, inc.kind));
            if (await consumeStoppedRun()) return;
            return;
          }
          if (queuedRunId) {
            const runId = queuedRunId;
            const text = refusalNote(result, inc.kind);
            const post = async () => {
              const posted = await postWithVerify(
                client,
                {
                  ...slackReplyArgs(inc.channel, text, replyThreadTs, {
                    threadOnly: inc.kind === "channel",
                    unfurlLinks: false,
                  }),
                },
                `run:${runId}`,
              );
              mirrorSelfPost(inc.channel, posted.ts, text, { sub: replyThreadTs });
            };
            await postThenAckRunDelivery({
              post,
              ack: () => ackRunDeliveryWithRetry(runId),
              release: () => inFlightRuns.delete(runId),
            });
          } else {
            await postReply(refusalNote(result, inc.kind));
          }
          return;
        }
        if (delivery === "silent") {
          await finishNative("");
          if (nativeAgent && (await consumeStoppedRun())) return;
          if (queuedRunId && result.refusalKind === "security_quarantine") inFlightRuns.delete(queuedRunId);
          console.error(
            `[slack-plugin] unprompted turn ${result.status} (staying quiet) ch=${inc.channel} ts=${inc.ts}: ${result.reason ?? "refused"}`,
          );
          return;
        }
        if (nativeAgent) {
          await finishNative(refusalNote(result, inc.kind));
          if (await consumeStoppedRun()) return;
        } else if (ack?.postedAck()) await postReply(refusalNote(result, inc.kind));
        else await ephemeralOrSay(refusalNote(result, inc.kind));
      }
    } finally {
      if (nativeRunToken && !nativeAgent) {
        await finishSlackAgentSession({ ...nativeSessionKey, token: nativeRunToken, status: "active" }).catch(
          () => false,
        );
      }
      if (nativeRunToken) {
        await completeSlackAgentSession({ ...nativeSessionKey, token: nativeRunToken }).catch(() => false);
      }
    }
  }

  async function dispatch(key: string, inc: Incoming, client: any): Promise<void> {
    const existing = incomingDispatches.get(key);
    if (existing) {
      if (await existing) inc.ackGate?.persisted();
      else inc.ackGate?.failed("matching delivery was not durably accepted");
      return;
    }
    let acceptanceSettled = false;
    let settleAcceptance: (accepted: boolean) => void = () => {};
    const acceptance = new Promise<boolean>((resolve) => {
      settleAcceptance = (accepted) => {
        if (acceptanceSettled) return;
        acceptanceSettled = true;
        resolve(accepted);
      };
    });
    incomingDispatches.set(key, acceptance);
    const coordinatedGate: AckGate = {
      persisted: () => {
        settleAcceptance(true);
        inc.ackGate?.persisted();
      },
      failed: (reason?: string) => {
        settleAcceptance(false);
        inc.ackGate?.failed(reason);
      },
    };
    const eventTs = Number.parseFloat(inc.ts);
    const stamped: Incoming = {
      ...inc,
      ackGate: coordinatedGate,
      recvAt: performance.now(),
      recvWall: Date.now(),
      ...(Number.isFinite(eventTs) && eventTs > 0 ? { eventTs } : {}),
    };
    deps.markEvent?.();
    try {
      await dedupedRun(
        deduper,
        key,
        () => handleIncoming(stamped, client),
        (err) => {
          coordinatedGate.failed(errMessage(err));
          console.error("[slack-plugin] handler error:", errMessage(err));
        },
      );
      if (!acceptanceSettled) coordinatedGate.persisted();
    } finally {
      if (!acceptanceSettled) coordinatedGate.failed("handler ended before acceptance");
      if (incomingDispatches.get(key) === acceptance) incomingDispatches.delete(key);
    }
  }

  async function getReactedMessage(
    client: any,
    channel: string,
    ts: string,
    full: boolean,
  ): Promise<{ text: string; threadTs?: string; reactions: ReactionTally[]; authorId?: string } | undefined> {
    try {
      const res = await client.reactions.get({ channel, timestamp: ts, full });
      const m = res?.message;
      if (!m) return undefined;
      return {
        text: decodeSlackEntities(String(m.text ?? "").trim()),
        ...(m.thread_ts && m.thread_ts !== ts ? { threadTs: String(m.thread_ts) } : {}),
        reactions: reactionTallies(m.reactions),
        ...(m.user ? { authorId: String(m.user) } : {}),
      };
    } catch {
      return undefined;
    }
  }

  async function handleReactionEvent(evt: SlackReactionEvent, body: any, client: any, added: boolean): Promise<void> {
    const reactorId = evt.user;
    const channel = evt.item?.channel;
    const messageTs = evt.item?.ts;
    const emoji = evt.reaction;
    if (!reactorId || !channel || !messageTs || !emoji) return;

    const isDM = channel.startsWith("D");
    const onBotMessage = Boolean(ids.botUserId && evt.item_user === ids.botUserId);
    const onFollowedRoot = threads.get(channel, messageTs) === true;
    if (
      !shouldSurfaceReaction({
        itemType: evt.item?.type,
        reactorId,
        botUserId: ids.botUserId,
        isDM,
        onBotMessage,
        onFollowedRoot,
      })
    ) {
      return;
    }

    const flightKey = `${channel}:${messageTs}:${emoji}:${reactorId}:${added ? "+" : "-"}`;
    if (reactionsInFlight.has(flightKey)) return;
    reactionsInFlight.add(flightKey);
    try {
      const key = dedupeKey({
        event_id: body?.event_id,
        channel,
        ts: `${messageTs}:${emoji}:${added ? "+" : "-"}:${reactorId}:${evt.event_ts ?? ""}`,
      });
      await dedupedRun(
        deduper,
        key,
        async () => {
          const reactorUser = await classifyUserCached(client, reactorId);
          const reactor = reactorUser.actor;
          if (reactor.isExternalGuest) return;
          let prefetched: Incoming["prefetched"];
          if (!isDM) {
            const info = await getChannelInfo(client, channel);
            const membership = await channelMembership(client, channel, reactor, reactorId, info);
            if (membership.audience.some((a) => a.isExternalGuest) && !(await externalParticipantsEnabled())) return;
            prefetched = {
              actor: reactor,
              ...(reactorUser.timezone ? { timezone: reactorUser.timezone } : {}),
              info,
              audience: membership.audience,
              ...(membership.publishMembers ? { publishMembers: membership.publishMembers } : {}),
              ...(membership.slackIdsByPrincipal ? { slackIdsByPrincipal: membership.slackIdsByPrincipal } : {}),
            };
          }
          const reactorName = reactor.displayName || "Someone";

          const msg = await getReactedMessage(client, channel, messageTs, added);
          let authorName: string | undefined;
          if (!onBotMessage && msg?.authorId && msg.authorId !== reactorId) {
            authorName = (await classifyActor(client, msg.authorId)).displayName;
          }

          const inc: Incoming = {
            kind: isDM ? "dm" : "channel",
            channel,
            userId: reactorId,
            rawText: buildReactionTurnText({
              reactorName,
              emoji,
              added,
              onBotMessage,
              ...(authorName ? { authorName } : {}),
              ...(msg?.text ? { messageText: msg.text } : {}),
              ...(msg?.reactions?.length ? { reactions: msg.reactions } : {}),
            }),
            files: [],
            ...(msg?.threadTs ? { threadTs: msg.threadTs } : {}),
            ts: messageTs,
            unprompted: true,
            synthetic: true,
            ...(prefetched ? { prefetched } : {}),
          };
          let heardWhere = "followed thread";
          if (isDM) heardWhere = "dm";
          else if (onBotMessage) heardWhere = "on my message";
          console.log(
            `[slack-plugin] heard reaction ${added ? "+" : "-"}:${emoji}: from ${reactorName} (${heardWhere}) → turn`,
          );
          await handleIncoming(inc, client);
        },
        (err) => console.error("[slack-plugin] handler error:", errMessage(err)),
      );
    } finally {
      reactionsInFlight.delete(flightKey);
    }
  }

  async function handleAgentSessionStopped(evt: SlackAgentSessionStoppedEvent, client: any): Promise<void> {
    const channel = evt.channel_id ?? evt.channel;
    const threadTs = evt.thread_ts;
    const teamId = evt.team_id ?? ids.ownTeamId;
    if (!channel || !threadTs || !teamId || !ids.agentId || !evt.user || !evt.event_ts || !evt.event_id) return;
    const session: SlackAgentSessionKey = {
      teamId,
      agentId: ids.agentId,
      channelId: channel,
      threadTs,
    };
    const streamingMessageTs = [
      ...(Array.isArray(evt.streaming_message_ts) ? evt.streaming_message_ts : []),
      ...(evt.message_ts ? [evt.message_ts] : []),
    ];
    const stopped = await stopSlackAgentSession({
      ...session,
      eventId: evt.event_id,
      eventTs: evt.event_ts,
      stoppedByUserId: evt.user,
      streamingMessageTs,
    });
    if (stopped.deferred) throw new Error("Slack Agent Session stop is waiting for durable submission binding");
    if (!stopped.applicable || stopped.acknowledged) return;
    const currentStatus = (await slackAgentSessionStatus(session)) ?? stopped.status ?? "active";
    const statusIntent = await requestSlackAgentStatusIntent(bridge, client, {
      ...session,
      authority: { kind: "stop", eventId: evt.event_id },
      sourceTs: evt.event_ts,
      sequence: 100,
      status: currentStatus,
    });
    if (statusIntent.verdict !== "confirmed") {
      throw new SlackAgentWriteDeferredError(
        Math.max(1, (statusIntent.retryAt ?? Date.now() + 1_000) - Date.now()),
        new Error("durable Slack Agent stop status intent is pending"),
      );
    }
    const latestStatus = await slackAgentSessionStatus(session);
    if (latestStatus && latestStatus !== currentStatus) {
      const latestIntent = await requestSlackAgentStatusIntent(bridge, client, {
        ...session,
        authority: { kind: "stop", eventId: evt.event_id },
        sourceTs: evt.event_ts,
        sequence: 101,
        status: latestStatus,
      });
      if (latestIntent.verdict !== "confirmed") {
        throw new SlackAgentWriteDeferredError(
          Math.max(1, (latestIntent.retryAt ?? Date.now() + 1_000) - Date.now()),
          new Error("durable Slack Agent stop reconciliation is pending"),
        );
      }
    }
    const idempotencyKey = `slack-agent-stop:${evt.event_id}`;
    const posted = await postWithVerify(
      client,
      {
        channel,
        thread_ts: threadTs,
        reply_broadcast: false,
        text: "Stopped.",
        unfurl_links: false,
        unfurl_media: false,
        ...botIdentityArgs(),
      },
      idempotencyKey,
      { verifyFirst: true, verifyOldest: String(Math.max(0, Number.parseFloat(evt.event_ts) - 300)) },
    );
    const acknowledged = await acknowledgeSlackAgentStop({
      ...session,
      eventId: evt.event_id,
      confirmationTs: posted.ts,
    });
    if (!acknowledged) throw new Error("Slack agent stop acknowledgment was not persisted");
    mirrorSelfPost(channel, posted.ts, "Stopped.", { sub: threadTs });
  }

  return {
    handleIncoming,
    dispatch,
    handleReactionEvent,
    handleAgentSessionStopped,
    drainReactionCleanups,
    drainStatusIntents,
    botHasStakeInThread,
  };
}
