import { swallowAs } from "../util/errors.ts";
import { createHash, randomUUID } from "node:crypto";
import {
  type ActorAssertion,
  type AgentRequestActionId,
  type AgentRequestDirective,
  type ApprovalActionId,
  type StoredApproval,
  agentRequestMessage,
  approvalCardDestination,
  approvalMessage,
  botIdentityArgs,
  clip,
  createNativeAgentPresenter,
  createApprovalRegistry,
  createThreadTracker,
  deletePostedByKey,
  dmThreadRef,
  encodeDeliveryTarget,
  inlineCode,
  isBoundaryRefusal,
  postWithVerify,
  recoveredApprovalContext,
  refusalNote,
  resolveReactionTargets,
  slackReplyArgs,
  stripAckPrefix,
  SlackAgentWriteDeferredError,
  type NativeAgentPresenter,
  type NativeAgentStatusIntentRequest,
  toSlackMrkdwn,
  uploadAttachments,
  uploadFailureNote,
} from "./lib.ts";
import {
  slackAgentBindingToken,
  type SlackAgentProviderWriteClaim,
  type SlackAgentSessionKey,
} from "../surfaces/slack-agent-session.ts";
import type {
  SlackApprovalAuthority,
  SlackApprovalContinuationClaim,
  SlackApprovalRecoveryContext,
} from "../surfaces/slack-approval-authority.ts";
import { resolveAgentRequestTarget } from "./approval-context.ts";
import type { SlackCoreClient } from "../api/slack-core-client.ts";
import type { TurnResult } from "../types.ts";
import { requestSlackReactionCleanup } from "./reaction-cleanup.ts";
import { requestSlackAgentStatusIntent } from "./status-intent.ts";
import type { CoreBridge, CoreCallHooks, CoreTurnBody } from "./core-bridge.ts";
import type { BotIdentity, Directory } from "./directory.ts";
import {
  type SlackConversationKind,
  applyAndLogReactions,
  channelAgentLabel,
  cleanAgentReplyForSlack,
  conversationPlaceLabel,
  personalAgentLabel,
  stripSlackDirectives,
  tryUpdateSlackMessage,
  updateSlackMessage,
} from "./messaging.ts";

interface SlackApprovalContext {
  requesterId: string;
  approvalRequesterUserId?: string;
  channel: string;
  replyThreadTs?: string;
  triggerTs?: string;
  threadOnly: boolean;
  approvalChannel: string;
  approvalMessageTs?: string;
  command: string;
  reason: string;
  purpose?: string;
  summary?: string;
  grantModes?: { session: boolean; always: boolean };
  turn: Omit<CoreTurnBody, "approval">;
  allowedTs?: Set<string>;
  slackIdsByPrincipal?: ReadonlyMap<string, string>;
  agentRequest?: SlackAgentRequestContext;
  ackedFirstBlock?: string;
  nativeAgentSession?: SlackAgentSessionKey;
  isCancelled?: () => Promise<boolean>;
  effectScopeId?: string;
  recovered?: boolean;
}

interface SlackAgentRequestContext {
  requesterId: string;
  targetUserId: string;
  targetDisplayName?: string;
  originChannel: string;
  originConversationKind?: SlackConversationKind;
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

type ApprovalScope = "once" | "session" | "always";

function approvalScope(actionId: ApprovalActionId): ApprovalScope | "deny" {
  if (actionId === "hilo_allow_once") return "once";
  if (actionId === "hilo_allow_session") return "session";
  if (actionId === "hilo_allow_always") return "always";
  return "deny";
}

function agentRequestAction(actionId: AgentRequestActionId): "run" | "deny" {
  return actionId === "agent_request_run" ? "run" : "deny";
}

export interface Approvals {
  rememberSlackApprovals(
    approvals: NonNullable<TurnResult["pendingApprovals"]>,
    ctx: Omit<SlackApprovalContext, "command" | "reason">,
  ): Promise<void>;
  postApprovalButtons(
    client: any,
    ctx: Omit<SlackApprovalContext, "command" | "reason" | "approvalChannel">,
    approvals: NonNullable<TurnResult["pendingApprovals"]>,
  ): Promise<void>;
  postAgentRequests(
    client: any,
    ctx: {
      requesterId: string;
      channel: string;
      replyThreadTs?: string;
      threadOnly: boolean;
      kind: SlackConversationKind;
      channelName?: string;
      audience: ActorAssertion[];
      slackIdsByPrincipal?: ReadonlyMap<string, string>;
      isCancelled?: () => Promise<boolean>;
      effectScopeId?: string;
    },
    requests: readonly AgentRequestDirective[],
  ): Promise<void>;
  registerActions(app: { action(pattern: RegExp, handler: (args: any) => Promise<void>): void }): void;
  pinSubmittedContinuations(): Promise<void>;
  drainSubmittedContinuations(client: any): Promise<void>;
}

export function createApprovals(deps: {
  core: SlackCoreClient;
  bridge: CoreBridge;
  directory: Directory;
  threads: ReturnType<typeof createThreadTracker>;
  ids: BotIdentity;
}): Approvals {
  const { core, bridge, directory, threads, ids } = deps;
  const {
    callCore,
    fetchBlobFromCore,
    fetchFileArtifactFromCore,
    beginSlackAgentSession,
    prepareSlackAgentSubmission,
    bindSlackAgentRun,
    bindSlackAgentStream,
    slackAgentSessionCancelled,
    finishSlackAgentSession,
    completeSlackAgentSession,
    slackAgentSessionStatus,
    claimSlackAgentProviderWrite,
    deferSlackAgentProviderWrite,
    completeSlackAgentProviderWrite,
    releaseSlackAgentProviderWrite,
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
  } = bridge;

  const pendingSlackApprovals = createApprovalRegistry<SlackApprovalContext>();
  const pendingSlackAgentRequests = new Map<string, SlackAgentRequestContext>();
  const submittedRunPins = new Set<string>();
  const pinSubmittedRun = (runId: string): void => {
    if (submittedRunPins.has(runId)) return;
    submittedRunPins.add(runId);
    bridge.inFlightRuns.add(runId);
  };
  const unpinSubmittedRun = (runId: string | undefined): void => {
    if (!runId || !submittedRunPins.delete(runId)) return;
    bridge.inFlightRuns.delete(runId);
  };

  function durableRecoveryContext(
    ctx: Omit<SlackApprovalContext, "command" | "reason">,
    approval: {
      command: string;
      reason?: string;
      purpose?: string;
      summary?: string;
      grantModes?: { session: boolean; always: boolean };
    },
  ): SlackApprovalRecoveryContext {
    const verifiedSlack = (ctx.turn as { verifiedSlack?: { userId?: unknown } }).verifiedSlack;
    const approvalRequesterUserId =
      ctx.approvalRequesterUserId ??
      (typeof verifiedSlack?.userId === "string" ? verifiedSlack.userId : undefined) ??
      ctx.requesterId;
    return {
      command: approval.command,
      ...(approval.reason ? { reason: approval.reason } : {}),
      ...(approval.purpose ? { purpose: approval.purpose } : {}),
      ...(approval.summary ? { summary: approval.summary } : {}),
      ...(approval.grantModes ? { grantModes: approval.grantModes } : {}),
      approvalRequesterUserId,
      ...(ctx.nativeAgentSession ? { nativeAgentSession: { ...ctx.nativeAgentSession } } : {}),
      ...(ctx.agentRequest ? { agentRequest: { ...ctx.agentRequest } } : {}),
      request: { ...ctx.turn } as Record<string, unknown>,
    };
  }

  function rebuildApprovalContext(
    stored: Pick<SlackApprovalRecoveryContext, "command" | "reason" | "purpose" | "summary" | "grantModes"> & {
      request?: Record<string, unknown>;
    } & Partial<Pick<SlackApprovalRecoveryContext, "approvalRequesterUserId" | "nativeAgentSession" | "agentRequest">>,
    click: { channel: string; threadTs?: string },
  ): SlackApprovalContext | null {
    const rebuilt = recoveredApprovalContext(stored, click);
    if (!rebuilt) return null;
    const nativeAgentSession = stored.nativeAgentSession ?? rebuilt.nativeAgentSession;
    const approvalRequesterUserId = stored.approvalRequesterUserId ?? rebuilt.approvalRequesterUserId;
    return {
      ...rebuilt,
      ...(approvalRequesterUserId ? { approvalRequesterUserId } : {}),
      ...(nativeAgentSession ? { nativeAgentSession: { ...nativeAgentSession, agentId: ids.agentId } } : {}),
      ...(stored.agentRequest ? { agentRequest: { ...stored.agentRequest } } : {}),
      recovered: true,
    } as SlackApprovalContext;
  }

  async function cancellablePost(
    client: any,
    args: any,
    isCancelled?: () => Promise<boolean>,
    idempotencyKey?: string,
  ): Promise<{ ts?: unknown } | null> {
    if (await isCancelled?.()) {
      if (idempotencyKey) await deletePostedByKey(client, args, idempotencyKey, "0");
      return null;
    }
    const posted = idempotencyKey
      ? await postWithVerify(client, args, idempotencyKey, { verifyFirst: true, verifyOldest: "0" })
      : ((await client.chat.postMessage(args)) as { ts?: unknown });
    if ((await isCancelled?.()) && posted.ts) {
      await deleteSlackMessage(client, String(args.channel), String(posted.ts), !!idempotencyKey);
      return null;
    }
    return posted;
  }

  function slackDeleteAlreadyApplied(error: unknown): boolean {
    if (typeof error !== "object" || error === null) return false;
    const value = error as { code?: unknown; data?: { error?: unknown } };
    const code = typeof value.data?.error === "string" ? value.data.error : value.code;
    return code === "not_found" || code === "message_not_found" || code === "already_deleted";
  }

  async function deleteSlackMessage(client: any, channel: string, ts: string, required: boolean): Promise<void> {
    if (!client.chat?.delete) {
      if (required) throw new Error("Slack message cleanup transport unavailable");
      return;
    }
    try {
      await client.chat.delete({ channel, ts });
    } catch (error) {
      if (!slackDeleteAlreadyApplied(error) && required) throw error;
    }
  }

  async function rememberSlackApprovals(
    approvals: NonNullable<TurnResult["pendingApprovals"]>,
    ctx: Omit<SlackApprovalContext, "command" | "reason">,
  ): Promise<void> {
    if (!ctx.approvalMessageTs) throw new Error("Slack approval message authority is missing");
    const persisted = await Promise.all(
      approvals.map((approval) =>
        bindSlackApprovalAuthority({
          teamId: ids.ownTeamId,
          agentId: ids.agentId,
          requesterUserId: ctx.approvalRequesterUserId ?? ctx.requesterId,
          requestId: approval.requestId,
          channelId: ctx.approvalChannel,
          messageTs: ctx.approvalMessageTs!,
          recovery: durableRecoveryContext(ctx, approval),
        }),
      ),
    );
    if (persisted.some((accepted) => !accepted)) throw new Error("Slack approval message authority was superseded");
    const {
      verifiedSlack: _verifiedSlack,
      slackAgentSessionToken: _slackAgentSessionToken,
      slackAgentSession: _slackAgentSession,
      idempotencyKey: _idempotencyKey,
      ...replayTurn
    } = ctx.turn as typeof ctx.turn & {
      verifiedSlack?: unknown;
      slackAgentSessionToken?: unknown;
      slackAgentSession?: unknown;
      idempotencyKey?: unknown;
    };
    for (const approval of approvals) {
      pendingSlackApprovals.remember(approval.requestId, {
        ...ctx,
        turn: replayTurn,
        command: approval.command,
        reason: approval.reason,
        ...(approval.purpose ? { purpose: approval.purpose } : {}),
        ...(approval.summary ? { summary: approval.summary } : {}),
        ...(approval.grantModes ? { grantModes: approval.grantModes } : {}),
      });
    }
  }

  async function resolveApprovalCardChannel(
    client: any,
    ctx: { channel: string; requesterId: string; threadOnly: boolean },
  ): Promise<{ approvalChannel?: string; toDm: boolean; channelPointer: string }> {
    const { toDm, channelPointer } = approvalCardDestination(ctx.threadOnly);
    if (!toDm) return { approvalChannel: ctx.channel, toDm: false, channelPointer };
    try {
      const opened = await client.conversations.open({ users: ctx.requesterId });
      const dm = String(opened?.channel?.id ?? "");
      if (dm) return { approvalChannel: dm, toDm: true, channelPointer };
    } catch (err) {
      console.error("[slack-plugin] couldn't open approval DM:", (err as Error).message);
    }
    return { toDm: true, channelPointer };
  }

  async function postApprovalButtons(
    client: any,
    ctx: Omit<SlackApprovalContext, "command" | "reason" | "approvalChannel">,
    approvals: NonNullable<TurnResult["pendingApprovals"]>,
  ): Promise<void> {
    const { approvalChannel, toDm, channelPointer } = await resolveApprovalCardChannel(client, ctx);
    if ((await ctx.isCancelled?.()) && !ctx.effectScopeId) return;
    if (!approvalChannel) {
      if (await ctx.isCancelled?.()) return;
      await client.chat
        .postEphemeral({
          channel: ctx.channel,
          user: ctx.requesterId,
          text: "I couldn't open a private approval message. No command was run; try again after direct messages are available.",
        })
        .catch(swallowAs("slack: post private approval failure", undefined));
      return;
    }
    if ((await ctx.isCancelled?.()) && ctx.effectScopeId) {
      await deletePostedByKey(
        client,
        slackReplyArgs(approvalChannel, "", toDm ? undefined : ctx.replyThreadTs, { threadOnly: !toDm }),
        `${ctx.effectScopeId}:approval-card`,
        "0",
      );
      if (toDm && channelPointer) {
        await deletePostedByKey(
          client,
          slackReplyArgs(ctx.channel, "", ctx.replyThreadTs, { threadOnly: true }),
          `${ctx.effectScopeId}:approval-pointer`,
          "0",
        );
      }
      return;
    }
    const msg = approvalMessage(approvals);
    const posted = await cancellablePost(
      client,
      {
        ...slackReplyArgs(approvalChannel, msg.text, toDm ? undefined : ctx.replyThreadTs, { threadOnly: !toDm }),
        blocks: msg.blocks,
      },
      ctx.isCancelled,
      ctx.effectScopeId ? `${ctx.effectScopeId}:approval-card` : undefined,
    );
    if (!posted) return;
    try {
      await rememberSlackApprovals(approvals, {
        ...ctx,
        approvalChannel,
        ...(posted.ts ? { approvalMessageTs: String(posted.ts) } : {}),
      });
    } catch (error) {
      if (posted.ts) await deleteSlackMessage(client, approvalChannel, String(posted.ts), !!ctx.effectScopeId);
      throw error;
    }
    if (await ctx.isCancelled?.()) {
      if (posted.ts) await deleteSlackMessage(client, approvalChannel, String(posted.ts), !!ctx.effectScopeId);
      if (toDm && channelPointer && ctx.effectScopeId) {
        await deletePostedByKey(
          client,
          slackReplyArgs(ctx.channel, "", ctx.replyThreadTs, { threadOnly: true }),
          `${ctx.effectScopeId}:approval-pointer`,
          "0",
        );
      }
      return;
    }
    if (toDm && channelPointer) {
      const pointerPost = cancellablePost(
        client,
        slackReplyArgs(ctx.channel, channelPointer, ctx.replyThreadTs, { threadOnly: true }),
        ctx.isCancelled,
        ctx.effectScopeId ? `${ctx.effectScopeId}:approval-pointer` : undefined,
      );
      if (ctx.effectScopeId) await pointerPost;
      else await pointerPost.catch(swallowAs("slack: post approval pointer", undefined));
    }
  }

  type StoredApprovalFetch = { state: "found"; stored: StoredApproval } | { state: "gone" } | { state: "unavailable" };

  async function fetchStoredApproval(requestId: string): Promise<StoredApprovalFetch> {
    try {
      const stored = await core.getApproval(requestId);
      if (!stored) return { state: "gone" };
      return { state: "found", stored: stored as StoredApproval };
    } catch (err) {
      console.error("[slack-plugin] approval recovery fetch failed:", (err as Error).message);
      return { state: "unavailable" };
    }
  }

  function agentRequestStatusText(
    ctx: SlackAgentRequestContext,
    state: "waiting" | "running" | "declined" | "failed",
  ): string {
    const arrow = `*${ctx.originAgentLabel} → ${ctx.targetAgentLabel}*`;
    if (state === "waiting")
      return `${arrow}\nWaiting for ${ctx.targetDisplayName ?? ctx.targetUserId} to approve running this in their personal setup.`;
    if (state === "running") return `${arrow}\nApproved. Running with ${ctx.targetAgentLabel} now.`;
    if (state === "declined")
      return `${arrow}\n${ctx.targetDisplayName ?? ctx.targetUserId} declined the personal-agent handoff.`;
    return `${arrow}\nThe personal-agent handoff could not be completed.`;
  }

  async function failAgentRequest(
    client: any,
    ctx: SlackAgentRequestContext,
    reason: string,
    dmMessageTs?: string,
  ): Promise<void> {
    const originText = `${agentRequestStatusText(ctx, "failed")}\n${reason}`;
    if (!(await tryUpdateSlackMessage(client, ctx.originChannel, ctx.originStatusTs, originText))) {
      const args = slackReplyArgs(ctx.originChannel, originText, ctx.originThreadTs, {
        threadOnly: ctx.originThreadOnly,
      });
      await (ctx.originResultIdempotencyKey
        ? postWithVerify(client, args, ctx.originResultIdempotencyKey, { verifyFirst: true, verifyOldest: "0" })
        : client.chat.postMessage(args));
    }
    await tryUpdateSlackMessage(
      client,
      ctx.dmChannel,
      dmMessageTs ?? ctx.dmMessageTs,
      `I couldn't finish the handoff: ${reason}`,
    );
  }

  async function completeAgentRequest(
    client: any,
    ctx: SlackAgentRequestContext,
    result: TurnResult,
    dmMessageTs?: string,
  ): Promise<void> {
    const { text: replyBody } = cleanAgentReplyForSlack(result.reply ?? "");
    let bodyText = "Completed.";
    if (replyBody) bodyText = toSlackMrkdwn(replyBody);
    else if (result.attachments?.length) bodyText = "Completed; attached file(s) below.";
    const posted = `*${ctx.targetAgentLabel} → ${ctx.originAgentLabel}*\n${bodyText}`;
    if (!(await tryUpdateSlackMessage(client, ctx.originChannel, ctx.originStatusTs, posted))) {
      const args = slackReplyArgs(ctx.originChannel, posted, ctx.originThreadTs, {
        threadOnly: ctx.originThreadOnly,
        unfurlLinks: false,
      });
      if (ctx.originResultIdempotencyKey) {
        await postWithVerify(client, args, ctx.originResultIdempotencyKey, { verifyFirst: true, verifyOldest: "0" });
      } else {
        await client.chat.postMessage(args);
      }
    }
    if (result.attachments?.length) {
      try {
        await uploadAttachments(
          client,
          ctx.originChannel,
          ctx.originThreadTs,
          result.attachments,
          fetchBlobFromCore,
          fetchFileArtifactFromCore,
          ctx.originResultIdempotencyKey
            ? { idempotencyKey: `${ctx.originResultIdempotencyKey}:attachments`, verifyOldest: "0" }
            : undefined,
        );
      } catch (err) {
        console.error("[slack-plugin] file upload failed:", (err as Error).message);
        await client.chat.postMessage(
          slackReplyArgs(ctx.originChannel, uploadFailureNote(err), ctx.originThreadTs, {
            threadOnly: ctx.originThreadOnly,
          }),
        );
      }
    }
    await tryUpdateSlackMessage(
      client,
      ctx.dmChannel,
      dmMessageTs ?? ctx.dmMessageTs,
      `Posted the result from ${ctx.targetAgentLabel} back to ${ctx.originAgentLabel}.`,
    );
  }

  async function askForAgentRequestCommandApproval(
    client: any,
    ctx: SlackAgentRequestContext,
    turn: Omit<CoreTurnBody, "approval">,
    approvals: NonNullable<TurnResult["pendingApprovals"]>,
    opts: { approvalMessageTs?: string; handoffMessageTs?: string } = {},
  ): Promise<void> {
    if (!approvals.length) {
      await failAgentRequest(
        client,
        ctx,
        `${ctx.targetAgentLabel} asked for command approval but did not return an approval request.`,
        opts.handoffMessageTs,
      );
      return;
    }

    const msg = approvalMessage(approvals);
    let approvalMessageTs = opts.approvalMessageTs;
    let postedNew = false;
    if (opts.approvalMessageTs) {
      await updateSlackMessage(client, ctx.dmChannel, opts.approvalMessageTs, msg.text, msg.blocks);
    } else {
      const posted = (await client.chat.postMessage({
        ...slackReplyArgs(ctx.dmChannel, msg.text, undefined),
        blocks: msg.blocks,
      })) as { ts?: unknown };
      if (posted.ts) {
        approvalMessageTs = String(posted.ts);
        postedNew = true;
      }
    }
    try {
      await rememberSlackApprovals(approvals, {
        requesterId: ctx.targetUserId,
        channel: ctx.dmChannel,
        approvalChannel: ctx.dmChannel,
        ...(approvalMessageTs ? { approvalMessageTs } : {}),
        ...(ctx.dmMessageTs ? { triggerTs: ctx.dmMessageTs } : {}),
        threadOnly: false,
        turn,
        agentRequest: ctx,
      });
    } catch (error) {
      if (approvalMessageTs) {
        if (postedNew)
          await client.chat.delete?.({ channel: ctx.dmChannel, ts: approvalMessageTs }).catch(() => undefined);
        else await tryUpdateSlackMessage(client, ctx.dmChannel, approvalMessageTs, "Approval unavailable; try again.");
      }
      throw error;
    }
    await tryUpdateSlackMessage(
      client,
      ctx.originChannel,
      ctx.originStatusTs,
      `${agentRequestStatusText(ctx, "running")}\nWaiting for ${ctx.targetDisplayName ?? ctx.targetUserId} to approve a command in their personal setup.`,
    );
    await tryUpdateSlackMessage(
      client,
      ctx.dmChannel,
      opts.handoffMessageTs ?? ctx.dmMessageTs,
      `This handoff needs command approval before ${ctx.targetAgentLabel} can finish.`,
    );
  }

  async function handleAgentRequestResult(
    client: any,
    ctx: SlackAgentRequestContext,
    turn: Omit<CoreTurnBody, "approval">,
    result: TurnResult,
    opts: { approvalMessageTs?: string; handoffMessageTs?: string } = {},
  ): Promise<void> {
    const approvals = result.pendingApprovals ?? [];
    if (approvals.length || result.status === "pending_approval") {
      await askForAgentRequestCommandApproval(client, ctx, turn, approvals, opts);
      return;
    }
    if (result.status === "ok") {
      await completeAgentRequest(client, ctx, result, opts.handoffMessageTs ?? opts.approvalMessageTs);
      if (opts.approvalMessageTs && opts.handoffMessageTs && opts.approvalMessageTs !== opts.handoffMessageTs) {
        await tryUpdateSlackMessage(
          client,
          ctx.dmChannel,
          opts.approvalMessageTs,
          `Posted the result from ${ctx.targetAgentLabel} back to ${ctx.originAgentLabel}.`,
        );
      }
      return;
    }
    await failAgentRequest(
      client,
      ctx,
      result.reason ?? result.status,
      opts.handoffMessageTs ?? opts.approvalMessageTs,
    );
  }

  async function postAgentRequests(
    client: any,
    ctx: {
      requesterId: string;
      channel: string;
      replyThreadTs?: string;
      threadOnly: boolean;
      kind: SlackConversationKind;
      channelName?: string;
      audience: ActorAssertion[];
      slackIdsByPrincipal?: ReadonlyMap<string, string>;
      isCancelled?: () => Promise<boolean>;
      effectScopeId?: string;
    },
    requests: readonly AgentRequestDirective[],
  ): Promise<void> {
    const cleanupDurableEffects = async (): Promise<void> => {
      if (!ctx.effectScopeId) return;
      const originArgs = slackReplyArgs(ctx.channel, "", ctx.replyThreadTs, { threadOnly: ctx.threadOnly });
      for (const [requestIndex, req] of requests.entries()) {
        for (const suffix of ["invalid-target", "bot-target", "dm-failed", "request-failed", "status"]) {
          await deletePostedByKey(client, originArgs, `${ctx.effectScopeId}:${requestIndex}:${suffix}`, "0");
        }
        const target = resolveAgentRequestTarget(ctx.audience, req.targetUserId, ctx.slackIdsByPrincipal);
        if (!target || target.isExternalGuest || target.isBot) continue;
        const opened = await client.conversations.open({ users: req.targetUserId });
        const dmChannel = String(opened?.channel?.id ?? "");
        if (!dmChannel) continue;
        await deletePostedByKey(
          client,
          { channel: dmChannel, text: "", ...botIdentityArgs() },
          `${ctx.effectScopeId}:${requestIndex}:dm`,
          "0",
        );
      }
    };
    const cancelledAndCleaned = async (): Promise<boolean> => {
      if (!(await ctx.isCancelled?.())) return false;
      await cleanupDurableEffects();
      return true;
    };
    for (const [requestIndex, req] of requests.entries()) {
      if (await cancelledAndCleaned()) return;
      const target = resolveAgentRequestTarget(ctx.audience, req.targetUserId, ctx.slackIdsByPrincipal);
      const originAgentLabel = channelAgentLabel(ctx.kind, ctx.channelName, ctx.channel);
      if (!target || target.isExternalGuest) {
        await cancellablePost(
          client,
          slackReplyArgs(
            ctx.channel,
            `${originAgentLabel} can only ask personal agents for internal people who are already in this conversation.`,
            ctx.replyThreadTs,
            { threadOnly: ctx.threadOnly },
          ),
          ctx.isCancelled,
          ctx.effectScopeId ? `${ctx.effectScopeId}:${requestIndex}:invalid-target` : undefined,
        );
        continue;
      }

      if (target.isBot) {
        await cancellablePost(
          client,
          slackReplyArgs(
            ctx.channel,
            `${originAgentLabel}: ${target.displayName ?? "that"} is another agent — just @mention it in your reply to reach it; ask-agent is only for a person's private setup.`,
            ctx.replyThreadTs,
            { threadOnly: ctx.threadOnly },
          ),
          ctx.isCancelled,
          ctx.effectScopeId ? `${ctx.effectScopeId}:${requestIndex}:bot-target` : undefined,
        );
        continue;
      }

      const requestId = ctx.effectScopeId
        ? `agent-request-${createHash("sha256")
            .update(JSON.stringify([ctx.effectScopeId, requestIndex, req.targetUserId, req.task]))
            .digest("hex")
            .slice(0, 32)}`
        : randomUUID();
      const targetAgentLabel = personalAgentLabel(target, req.targetUserId);
      const base: Omit<SlackAgentRequestContext, "originStatusTs" | "dmChannel" | "dmMessageTs"> = {
        requesterId: ctx.requesterId,
        targetUserId: req.targetUserId,
        ...(target.displayName ? { targetDisplayName: target.displayName } : {}),
        originChannel: ctx.channel,
        originConversationKind: ctx.kind,
        ...(ctx.replyThreadTs ? { originThreadTs: ctx.replyThreadTs } : {}),
        originThreadOnly: ctx.threadOnly,
        ...(ctx.channelName ? { originChannelName: ctx.channelName } : {}),
        task: req.task,
        originAgentLabel,
        targetAgentLabel,
      };

      let pendingCtx: SlackAgentRequestContext | undefined;
      try {
        const opened = await client.conversations.open({ users: req.targetUserId });
        if (await cancelledAndCleaned()) return;
        const dmChannel = String(opened?.channel?.id ?? "");
        if (!dmChannel) {
          await cancellablePost(
            client,
            slackReplyArgs(
              ctx.channel,
              `${originAgentLabel} couldn't open a DM to ${target.displayName ?? req.targetUserId}.`,
              ctx.replyThreadTs,
              {
                threadOnly: ctx.threadOnly,
              },
            ),
            ctx.isCancelled,
            ctx.effectScopeId ? `${ctx.effectScopeId}:${requestIndex}:dm-failed` : undefined,
          );
          continue;
        }

        pendingCtx = { ...base, dmChannel };
        const statusKey = ctx.effectScopeId ? `${ctx.effectScopeId}:${requestIndex}:status` : undefined;
        const dmKey = ctx.effectScopeId ? `${ctx.effectScopeId}:${requestIndex}:dm` : undefined;
        const statusArgs = slackReplyArgs(
          ctx.channel,
          agentRequestStatusText(pendingCtx, "waiting"),
          ctx.replyThreadTs,
          { threadOnly: ctx.threadOnly },
        );
        if (await cancelledAndCleaned()) return;
        const status = ctx.effectScopeId
          ? await postWithVerify(client, statusArgs, statusKey!, {
              verifyFirst: true,
              verifyOldest: "0",
            })
          : await cancellablePost(client, statusArgs, ctx.isCancelled);
        if (!status) return;
        if (await cancelledAndCleaned()) return;
        if (status?.ts) pendingCtx.originStatusTs = String(status.ts);

        const prompt = agentRequestMessage({
          requestId,
          originAgentLabel,
          targetAgentLabel,
          task: req.task,
        });
        const dmArgs = {
          channel: dmChannel,
          text: prompt.text,
          ...botIdentityArgs(),
          blocks: prompt.blocks,
        };
        const dm = ctx.effectScopeId
          ? await postWithVerify(client, dmArgs, dmKey!, {
              verifyFirst: true,
              verifyOldest: "0",
            })
          : await cancellablePost(client, dmArgs, ctx.isCancelled);
        if (!dm) {
          if (pendingCtx.originStatusTs)
            await deleteSlackMessage(client, ctx.channel, pendingCtx.originStatusTs, !!ctx.effectScopeId);
          return;
        }
        if (await cancelledAndCleaned()) return;
        if (dm?.ts) pendingCtx.dmMessageTs = String(dm.ts);
        pendingSlackAgentRequests.set(requestId, pendingCtx);
        if (await cancelledAndCleaned()) {
          pendingSlackAgentRequests.delete(requestId);
          return;
        }
      } catch (err) {
        if (await ctx.isCancelled?.()) {
          await cleanupDurableEffects();
          if (pendingCtx) pendingSlackAgentRequests.delete(requestId);
          return;
        }
        if (ctx.effectScopeId) throw err;
        const reason = `Slack couldn't send the personal-agent request to ${target.displayName ?? req.targetUserId}: ${(err as Error).message}`;
        if (pendingCtx?.originStatusTs) {
          await failAgentRequest(client, pendingCtx, reason);
        } else {
          await cancellablePost(
            client,
            slackReplyArgs(
              ctx.channel,
              `${originAgentLabel} couldn't ask ${targetAgentLabel}: ${(err as Error).message}`,
              ctx.replyThreadTs,
              {
                threadOnly: ctx.threadOnly,
              },
            ),
            ctx.isCancelled,
            ctx.effectScopeId ? `${ctx.effectScopeId}:${requestIndex}:request-failed` : undefined,
          );
        }
      }
    }
    await cancelledAndCleaned();
  }

  async function postApprovalFollowup(
    client: any,
    ctx: SlackApprovalContext,
    text: string,
    isCancelled?: () => Promise<boolean>,
    idempotencyKey?: string,
    verifyOldest?: string,
  ): Promise<void> {
    const args = slackReplyArgs(ctx.channel, text, ctx.replyThreadTs, { threadOnly: ctx.threadOnly });
    if (await isCancelled?.()) {
      if (idempotencyKey) await deletePostedByKey(client, args, idempotencyKey, verifyOldest ?? "0");
      return;
    }
    const posted = idempotencyKey
      ? await postWithVerify(client, args, idempotencyKey, {
          verifyFirst: true,
          ...(verifyOldest ? { verifyOldest } : {}),
        })
      : ((await client.chat.postMessage(args)) as { ts?: unknown });
    if ((await isCancelled?.()) && posted.ts) {
      await deleteSlackMessage(client, ctx.channel, String(posted.ts), !!idempotencyKey);
    }
  }

  function personalAgentTurnText(ctx: SlackAgentRequestContext): string {
    const destination = conversationPlaceLabel(
      ctx.originConversationKind ?? "channel",
      ctx.originChannelName,
      ctx.originChannel,
    );
    return [
      "[Agent-to-agent request]",
      `${ctx.originAgentLabel} asked ${ctx.targetAgentLabel} to help with a task that may require this user's personal setup.`,
      "",
      "Task:",
      ctx.task,
      "",
      `Run this in the user's personal context if appropriate. Do not reveal API keys, credentials, tokens, or other secrets. Return only the concrete outcome, evidence, or blocker that is safe to share back to ${destination}.`,
    ].join("\n");
  }

  async function handleApprovalAction({ ack, body, action, client, recoveringSubmitted = false }: any): Promise<void> {
    let acknowledged = false;
    const acknowledge = async (): Promise<void> => {
      if (acknowledged) return;
      await ack();
      acknowledged = true;
    };
    const a = action as any;
    const actionId = a.action_id as ApprovalActionId | undefined;
    if (
      actionId !== "hilo_allow_once" &&
      actionId !== "hilo_allow_session" &&
      actionId !== "hilo_allow_always" &&
      actionId !== "hilo_deny"
    ) {
      await acknowledge();
      return;
    }

    const requestId = String(a.value ?? "");
    let ctx = pendingSlackApprovals.get(requestId);
    const clickerId = String((body as any)?.user?.id ?? "");
    const channel = String((body as any)?.channel?.id ?? ctx?.channel ?? "");
    const messageTs = (body as any)?.message?.ts as string | undefined;
    const messageThreadTs = (body as any)?.message?.thread_ts as string | undefined;
    let durableAuthority: SlackApprovalAuthority | null | undefined;
    const readDurableAuthority = async (requesterUserId: string): Promise<SlackApprovalAuthority | null> => {
      try {
        return await getSlackApprovalAuthority({
          teamId: ids.ownTeamId,
          agentId: ids.agentId,
          requesterUserId,
          requestId,
        });
      } catch (error) {
        if (channel && clickerId) {
          await client.chat
            .postEphemeral({
              channel,
              user: clickerId,
              text: "I couldn't verify that approval message just now — try the button again in a moment.",
            })
            .catch(swallowAs("slack: chat.postEphemeral", undefined));
        }
        throw new Error("Slack approval authority is temporarily unavailable", { cause: error });
      }
    };

    if (!ctx && channel) {
      const fetched = await fetchStoredApproval(requestId);
      if (fetched.state === "unavailable") {
        if (clickerId) {
          await client.chat
            .postEphemeral({
              channel,
              user: clickerId,
              text: "I couldn't check on that approval just now — try the button again in a moment.",
            })
            .catch(swallowAs("slack: chat.postEphemeral", undefined));
        }
        throw new Error("Slack approval recovery is temporarily unavailable");
      }
      const rebuilt =
        fetched.state === "found"
          ? rebuildApprovalContext(fetched.stored, {
              channel,
              ...(messageThreadTs ? { threadTs: messageThreadTs } : {}),
            })
          : null;
      if (rebuilt) {
        pendingSlackApprovals.remember(requestId, rebuilt);
        ctx = pendingSlackApprovals.get(requestId);
        console.log(`[slack-plugin] recovered approval ${requestId} from core (in-memory context was lost)`);
      }
      if (!ctx && clickerId) {
        durableAuthority = await readDurableAuthority(clickerId);
        const runRecovery =
          !durableAuthority?.recovery && durableAuthority?.continuation?.runId
            ? await core.slackApprovalRunRecovery(durableAuthority.continuation.runId, {
                teamId: ids.ownTeamId,
                agentId: ids.agentId,
              })
            : null;
        const recovery =
          durableAuthority?.recovery ??
          (runRecovery && durableAuthority
            ? { ...runRecovery, approvalRequesterUserId: durableAuthority.requesterUserId }
            : null);
        const authorityRebuilt = recovery
          ? rebuildApprovalContext(recovery, {
              channel,
              ...(messageThreadTs ? { threadTs: messageThreadTs } : {}),
            })
          : null;
        if (authorityRebuilt) {
          pendingSlackApprovals.remember(requestId, authorityRebuilt);
          ctx = pendingSlackApprovals.get(requestId);
          console.log(`[slack-plugin] recovered approval ${requestId} from durable Slack authority`);
        }
      }
    }

    if (!ctx) {
      await acknowledge();
      if (channel && messageTs) {
        await updateSlackMessage(
          client,
          channel,
          messageTs,
          "_That approval request expired — let me know when you want to try again._",
        ).catch(swallowAs("slack: update approval message", undefined));
      } else if (channel && clickerId) {
        await client.chat
          .postEphemeral({
            channel,
            user: clickerId,
            text: "That approval request expired — let me know when you want to try again.",
          })
          .catch(swallowAs("slack: chat.postEphemeral", undefined));
      }
      return;
    }

    if (!durableAuthority) {
      durableAuthority = await readDurableAuthority(ctx.approvalRequesterUserId ?? ctx.requesterId);
    }

    if (
      !durableAuthority ||
      !channel ||
      channel !== durableAuthority.channelId ||
      messageTs !== durableAuthority.messageTs ||
      channel !== ctx.approvalChannel ||
      (ctx.approvalMessageTs !== undefined && messageTs !== ctx.approvalMessageTs)
    ) {
      await acknowledge();
      if (channel && clickerId) {
        await client.chat
          .postEphemeral({
            channel,
            user: clickerId,
            text: "That approval button is not attached to the active approval message.",
          })
          .catch(swallowAs("slack: chat.postEphemeral", undefined));
      }
      return;
    }

    const requesterMatches =
      recoveringSubmitted ||
      (ctx.recovered
        ? (await directory.classifyActor(client, clickerId)).externalId === ctx.requesterId
        : clickerId === ctx.requesterId);
    if (!requesterMatches) {
      await acknowledge();
      await client.chat
        .postEphemeral({
          channel,
          user: clickerId,
          text: "Only the person who requested this command can approve or deny it.",
        })
        .catch(swallowAs("slack: chat.postEphemeral", undefined));
      return;
    }

    if (
      !(await bindSlackApprovalAuthority({
        teamId: ids.ownTeamId,
        agentId: ids.agentId,
        requesterUserId: ctx.approvalRequesterUserId ?? ctx.requesterId,
        requestId,
        channelId: channel,
        messageTs,
        recovery: durableRecoveryContext(ctx, ctx),
      }))
    ) {
      throw new Error("Slack approval recovery authority was superseded");
    }

    const selected = approvalScope(actionId);
    const admitted = await admitSlackApprovalContinuation({
      teamId: ids.ownTeamId,
      agentId: ids.agentId,
      requesterUserId: ctx.approvalRequesterUserId ?? ctx.requesterId,
      requestId,
      channelId: channel,
      messageTs,
      actionId,
      actionTs,
      clickerUserId: clickerId,
    });
    if (!admitted.acquired) {
      if (admitted.reason !== "busy" || admitted.continuation.state !== "admitted") {
        await acknowledge();
      }
      let blockedText = "Still working on your previous click — give it a moment.";
      if (admitted.reason === "conflict") blockedText = "This approval already has a different durable decision.";
      else if (admitted.reason === "settled") blockedText = "That approval was already handled.";
      await client.chat
        .postEphemeral({
          channel,
          user: clickerId,
          text: blockedText,
        })
        .catch(swallowAs("slack: chat.postEphemeral", undefined));
      return;
    }
    const continuationClaim: SlackApprovalContinuationClaim = admitted.claim;
    const resumedSubmittedRunId = continuationClaim.runId;
    pendingSlackApprovals.begin(requestId);
    let scopeLabel = "Allowed always";
    if (selected === "once") scopeLabel = "Allowed once";
    else if (selected === "session") scopeLabel = "Allowed for this conversation";
    const approval = {
      requestId,
      approved: selected !== "deny",
      ...(selected !== "deny" ? { scope: selected } : {}),
    };
    const nativeApprovalClaim = {
      claimId: continuationClaim.claimId,
      generation: continuationClaim.generation,
    };

    let settled = false;
    let released = false;
    const settle = async (): Promise<void> => {
      if (settled) return;
      if (nativeBindingAccepted && nativeSessionKey && nativeRunToken && !nativeBindingCompleted) {
        if (!(await renewSlackApprovalContinuation(continuationClaim))) {
          throw new Error("Slack approval continuation claim was superseded");
        }
        if (
          !(await completeSlackAgentSession({
            ...nativeSessionKey,
            token: nativeRunToken,
            approvalClaim: nativeApprovalClaim,
          }))
        ) {
          throw new Error("Slack Agent approval completion was not persisted");
        }
        nativeBindingCompleted = true;
      }
      if (!(await settleSlackApprovalContinuation(continuationClaim))) {
        throw new Error("Slack approval continuation settlement was not persisted");
      }
      pendingSlackApprovals.settle(requestId);
      settled = true;
      unpinSubmittedRun(nativeRunId);
    };
    const retainClaim = async (): Promise<void> => {
      if (!(await renewSlackApprovalContinuation(continuationClaim))) {
        throw new Error("Slack approval continuation claim was superseded");
      }
    };

    const cardChannel = ctx.approvalChannel;
    const cardIsRemote = cardChannel !== ctx.channel;
    const nativeSessionKey = ctx.nativeAgentSession;
    const continuationTriggerTs = continuationClaim.actionTs;
    let nativeRunToken =
      nativeSessionKey && continuationTriggerTs
        ? slackAgentBindingToken(
            nativeSessionKey,
            ctx.approvalRequesterUserId ?? ctx.requesterId,
            continuationTriggerTs,
            nativeSessionKey.threadTs,
          )
        : undefined;
    let nativeContinuation: NativeAgentPresenter | undefined;
    let nativeContinuationResumed = false;
    let nativeRunId: string | undefined = resumedSubmittedRunId;
    let nativeBindingAccepted = false;
    let nativeBindingCompleted = false;
    let continuationSubmitted = !!resumedSubmittedRunId;
    const resultAgentRequest = (): SlackAgentRequestContext | undefined =>
      ctx.agentRequest && nativeRunId
        ? { ...ctx.agentRequest, originResultIdempotencyKey: `run:${nativeRunId}:agent-request` }
        : ctx.agentRequest;
    const leaseHeartbeat = setInterval(() => {
      void renewSlackApprovalContinuation(continuationClaim).catch(
        swallowAs("slack: renew approval continuation", false),
      );
    }, 20_000);
    leaseHeartbeat.unref?.();
    const alreadyStoppedStreams = new Set<string>();
    const beforeProviderWrite = async (method: string): Promise<SlackAgentProviderWriteClaim | undefined> => {
      if (!nativeSessionKey) return undefined;
      await retainClaim();
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
      if (!claim) return;
      const deferred = await deferSlackAgentProviderWrite({ ...claim, notBefore: Date.now() + error.retryAfterMs });
      if (!deferred.applied) throw new Error("Slack provider retry claim is stale");
    };
    const onProviderWriteSucceeded = async (
      _method: string,
      claim: SlackAgentProviderWriteClaim | undefined,
    ): Promise<void> => {
      if (claim && !(await completeSlackAgentProviderWrite(claim))) {
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
    const nativeContinuationWasStopped = async (): Promise<boolean> => {
      if (!nativeSessionKey || !nativeRunToken || !nativeBindingAccepted) return false;
      try {
        return await slackAgentSessionCancelled({
          ...nativeSessionKey,
          token: nativeRunToken,
          ...(nativeRunId ? { runId: nativeRunId } : {}),
        });
      } catch (error) {
        console.error("[slack-plugin] native approval cancellation check failed:", (error as Error).message);
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
      if (!nativeSessionKey || !nativeRunToken || !continuationTriggerTs) return "manual_attention";
      return requestSlackReactionCleanup(bridge, client, {
        teamId: nativeSessionKey.teamId,
        agentId: nativeSessionKey.agentId,
        sessionChannelId: nativeSessionKey.channelId,
        sessionThreadTs: nativeSessionKey.threadTs,
        sessionToken: nativeRunToken,
        effectId: input.effectId,
        sourceTs: continuationTriggerTs,
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
      if (!nativeSessionKey || !nativeRunToken || !continuationTriggerTs) return false;
      const admitted = await bridge.admitSlackReactionDesire({
        teamId: nativeSessionKey.teamId,
        agentId: nativeSessionKey.agentId,
        sessionChannelId: nativeSessionKey.channelId,
        sessionThreadTs: nativeSessionKey.threadTs,
        sessionToken: nativeRunToken,
        effectId: input.effectId,
        sourceTs: continuationTriggerTs,
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
      if (!nativeSessionKey || !nativeRunToken || !continuationTriggerTs) return;
      await bridge.cancelSlackReactionDesire({
        teamId: nativeSessionKey.teamId,
        agentId: nativeSessionKey.agentId,
        sessionChannelId: nativeSessionKey.channelId,
        sessionThreadTs: nativeSessionKey.threadTs,
        sessionToken: nativeRunToken,
        effectId: input.effectId,
        sourceTs: continuationTriggerTs,
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
      if (!nativeSessionKey || !nativeRunToken || !continuationTriggerTs) return;
      await bridge.withdrawSlackReactionDesire({
        teamId: nativeSessionKey.teamId,
        agentId: nativeSessionKey.agentId,
        sessionChannelId: nativeSessionKey.channelId,
        sessionThreadTs: nativeSessionKey.threadTs,
        sessionToken: nativeRunToken,
        effectId: input.effectId,
        sourceTs: continuationTriggerTs,
        sequence: input.sequence,
        channelId: input.channel,
        messageTs: input.timestamp,
        name: input.name,
      });
    };
    const writeStatusIntent = async (input: NativeAgentStatusIntentRequest): Promise<void> => {
      if (!nativeSessionKey || !nativeRunToken || !continuationTriggerTs) {
        throw new Error("Slack Agent approval status intent is missing its exact binding authority");
      }
      const sequence = {
        begin_processing: 0,
        begin_cancelled: 1,
        begin_failed: 2,
        finish: 10,
      }[input.phase];
      const result = await requestSlackAgentStatusIntent(bridge, client, {
        ...nativeSessionKey,
        authority: { kind: "binding", token: nativeRunToken },
        sourceTs: continuationTriggerTs,
        sequence,
        status: input.status,
        ...(input.createSession ? { createSession: input.createSession } : {}),
      });
      if (result.verdict === "confirmed") return;
      throw new SlackAgentWriteDeferredError(
        Math.max(1, (result.retryAt ?? Date.now() + 1_000) - Date.now()),
        new Error("durable Slack Agent approval status intent is pending"),
      );
    };
    let continuationAttachments: TurnResult["attachments"];
    let continuationResultResolved = false;
    let attachmentCompensationFailed = false;
    let stoppedAttachmentCleanupComplete = false;
    let stoppedResultCleanupComplete = false;
    const resultDeliveryKey = (): string =>
      nativeRunId ? `run:${nativeRunId}` : `${continuationClaim.idempotencyKey}:result`;
    const resultDeliveryOldest = String(Math.max(0, Number(continuationClaim.actionTs) - 300));
    const attachmentDeliveryOptions = () => ({
      isCancelled: nativeContinuationWasStopped,
      idempotencyKey: nativeRunId
        ? `run:${nativeRunId}:attachments`
        : `${continuationClaim.idempotencyKey}:attachments`,
      verifyOldest: String(Math.max(0, Number(continuationClaim.actionTs) - 300)),
    });
    const compensateStoppedAttachments = async (): Promise<void> => {
      if (stoppedAttachmentCleanupComplete) return;
      try {
        if (resumedSubmittedRunId && !continuationResultResolved) {
          throw new Error("Stopped Slack attachment compensation requires the recovered result");
        }
        if (!continuationAttachments?.length) {
          stoppedAttachmentCleanupComplete = true;
          return;
        }
        const compensated = await uploadAttachments(
          client,
          ctx.channel,
          ctx.replyThreadTs,
          continuationAttachments,
          fetchBlobFromCore,
          fetchFileArtifactFromCore,
          attachmentDeliveryOptions(),
        );
        if (compensated.uploaded) throw new Error("Stopped Slack attachment compensation did not cancel");
        stoppedAttachmentCleanupComplete = true;
      } catch (error) {
        attachmentCompensationFailed = true;
        throw error;
      }
    };
    const compensateStoppedResult = async (): Promise<void> => {
      if (stoppedResultCleanupComplete) return;
      try {
        await deletePostedByKey(
          client,
          slackReplyArgs(ctx.channel, "", ctx.replyThreadTs, { threadOnly: ctx.threadOnly }),
          resultDeliveryKey(),
          resultDeliveryOldest,
        );
        stoppedResultCleanupComplete = true;
      } catch (error) {
        attachmentCompensationFailed = true;
        throw error;
      }
    };
    const consumeStoppedContinuation = async (): Promise<boolean> => {
      if (!(await nativeContinuationWasStopped())) return false;
      if (settled) return true;
      await compensateStoppedResult();
      await compensateStoppedAttachments();
      await acknowledge();
      await retainClaim();
      await updateSlackMessage(client, cardChannel, messageTs, "Canceled.");
      await settle();
      return true;
    };
    const finishNativeContinuation = async (text: string, status: "active" | "suspended"): Promise<boolean> => {
      if (!nativeContinuation) return false;
      try {
        const surfaceTs = await nativeContinuation.finish(text, status);
        if (text && !surfaceTs) {
          await postApprovalFollowup(
            client,
            ctx,
            toSlackMrkdwn(text),
            nativeContinuationWasStopped,
            resultDeliveryKey(),
            resultDeliveryOldest,
          );
        }
        return true;
      } catch (error) {
        console.error("[slack-plugin] native approval continuation failed:", (error as Error).message);
        if (nativeContinuationResumed) throw error;
        return false;
      }
    };
    const setNativeApprovalStatus = async (status: "active" | "suspended"): Promise<void> => {
      if (!ctx.nativeAgentSession || !messageTs) return;
      const aggregateStatus =
        status === "active" && !nativeBindingAccepted
          ? status
          : ((await slackAgentSessionStatus(ctx.nativeAgentSession)) ?? status);
      const result = await requestSlackAgentStatusIntent(bridge, client, {
        ...ctx.nativeAgentSession,
        authority: {
          kind: "approval",
          requestId,
          requesterUserId: ctx.approvalRequesterUserId ?? ctx.requesterId,
          channelId: cardChannel,
          messageTs,
        },
        sourceTs: continuationTriggerTs,
        sequence: status === "active" ? 20 : 21,
        status: aggregateStatus,
      });
      if (result.verdict !== "confirmed") {
        console.error(`[slack-plugin] native approval status ${result.verdict}: ${requestId}`);
      }
    };
    try {
      const approver = resumedSubmittedRunId ? undefined : await directory.classifyActor(client, clickerId);
      const onQueued = async (runId: string): Promise<void> => {
        if (!(await markSlackApprovalContinuationSubmitted({ ...continuationClaim, runId }))) {
          throw new Error("Slack approval continuation submission was not persisted");
        }
        continuationSubmitted = true;
        nativeRunId = runId;
        pinSubmittedRun(runId);
        bridge.inFlightRunByThread.set(ctx.turn.conversation.threadRef, runId);
        if (nativeSessionKey && nativeRunToken && nativeBindingAccepted) {
          const bound = await bindSlackAgentRun({ ...nativeSessionKey, token: nativeRunToken, runId });
          if (!bound.accepted) {
            await bridge.signalRunAbort(runId);
            throw new Error("Slack Agent continuation binding was superseded");
          }
          if (bound.cancelled) await bridge.signalRunAbort(runId);
        }
        if (messageTs && !cardIsRemote) await bridge.checkpointRunEditRef(runId, messageTs);
        await acknowledge();
        if (selected !== "deny") {
          await updateSlackMessage(
            client,
            cardChannel,
            messageTs,
            `${scopeLabel}; running ${inlineCode(ctx.command)}...`,
          );
        }
      };
      if (selected === "deny") {
        try {
          if (resumedSubmittedRunId) {
            bridge.inFlightRunByThread.set(ctx.turn.conversation.threadRef, resumedSubmittedRunId);
            await acknowledge();
            const deniedResult = await resumeRun(resumedSubmittedRunId);
            continuationResultResolved = true;
            continuationAttachments = deniedResult.attachments;
          } else {
            await callCore(
              { ...ctx.turn, actor: approver!, approval, idempotencyKey: continuationClaim.idempotencyKey },
              { onQueued, resumeReplay: true },
            );
          }
          await acknowledge();
        } finally {
          if (nativeRunId) bridge.inFlightRunByThread.clear(ctx.turn.conversation.threadRef, nativeRunId);
        }
        if (await consumeStoppedContinuation()) return;
        await setNativeApprovalStatus("active");
        await retainClaim();
        const agentRequest = resultAgentRequest();
        if (agentRequest) {
          await failAgentRequest(
            client,
            agentRequest,
            `${inlineCode(ctx.command)} was denied.`,
            agentRequest.dmMessageTs,
          );
        }
        await updateSlackMessage(client, cardChannel, messageTs, `Denied ${inlineCode(ctx.command)}.`);
        await settle();
        return;
      }

      if (nativeSessionKey && nativeRunToken && continuationTriggerTs) {
        let begun = await beginSlackAgentSession({
          ...nativeSessionKey,
          ownerUserId: ctx.approvalRequesterUserId ?? ctx.requesterId,
          token: nativeRunToken,
          triggerTs: continuationTriggerTs,
          coreThreadRef: ctx.turn.conversation.threadRef,
          authorityMessageTs: nativeSessionKey.threadTs,
          approvalClaim: nativeApprovalClaim,
        });
        if (resumedSubmittedRunId && begun.accepted && begun.binding?.token) {
          begun = await bindSlackAgentRun({
            ...nativeSessionKey,
            token: begun.binding.token,
            runId: resumedSubmittedRunId,
          });
          if (begun.cancelled) await bridge.signalRunAbort(resumedSubmittedRunId);
        }
        nativeRunToken = begun.binding?.token;
        nativeBindingAccepted = begun.accepted;
        if (!begun.accepted || !nativeRunToken || (begun.cancelled && !resumedSubmittedRunId)) {
          await consumeStoppedContinuation();
          return;
        }
        if (!begun.cancelled) {
          const continuationToken = nativeRunToken;
          const resumeStreamTs = resumedSubmittedRunId ? begun.binding?.streamTs : undefined;
          if (resumeStreamTs && begun.binding?.streamStopState === "listed") alreadyStoppedStreams.add(resumeStreamTs);
          const candidate = createNativeAgentPresenter({
            client,
            channel: nativeSessionKey.channelId,
            threadTs: nativeSessionKey.threadTs,
            initiatorUserId: clickerId,
            recipientTeamId: ids.ownTeamId,
            createSession: begun.created,
            streaming: false,
            ...(resumeStreamTs ? { resumeStreamTs } : {}),
            title: `Continue: ${ctx.turn.text}`,
            sanitize: stripSlackDirectives,
            checkpoint: async (ts) => {
              const bound = await bindSlackAgentStream({ ...nativeSessionKey, token: continuationToken, streamTs: ts });
              if (bound.binding?.streamStopState === "listed") alreadyStoppedStreams.add(ts);
              if (!bound.accepted || bound.cancelled) return true;
              if (nativeRunId) await bridge.checkpointRunEditRef(nativeRunId, ts);
              return false;
            },
            onSurfacePosted: () => {},
            writeStatusIntent,
            alreadyStopped: async (ts) => alreadyStoppedStreams.has(ts),
            beforeProviderWrite,
            onProviderDeferred,
            onProviderWriteSucceeded,
            onProviderWriteFailed,
            isCancelled: nativeContinuationWasStopped,
            resolveStatus: async (status) => {
              const persisted = await finishSlackAgentSession({
                ...nativeSessionKey,
                token: continuationToken,
                status,
                approvalClaim: nativeApprovalClaim,
              });
              if (!persisted) throw new Error("Slack Agent approval session status was not persisted");
              return (await slackAgentSessionStatus(nativeSessionKey)) ?? status;
            },
            onError: (error) =>
              console.error("[slack-plugin] native approval presentation failed:", (error as Error).message),
          });
          if (resumeStreamTs || (!resumedSubmittedRunId && (await candidate.begin()))) {
            nativeContinuation = candidate;
            nativeContinuationResumed = !!resumeStreamTs;
          } else if (!resumedSubmittedRunId) {
            if (await consumeStoppedContinuation()) return;
            await finishSlackAgentSession({
              ...nativeSessionKey,
              token: nativeRunToken,
              status: "active",
              approvalClaim: nativeApprovalClaim,
            });
            await completeSlackAgentSession({
              ...nativeSessionKey,
              token: nativeRunToken,
              approvalClaim: nativeApprovalClaim,
            });
            nativeBindingAccepted = false;
            nativeRunToken = undefined;
          }
        }
      }
      if (!resumedSubmittedRunId && (await consumeStoppedContinuation())) return;
      if (!resumedSubmittedRunId && nativeSessionKey && nativeRunToken && nativeBindingAccepted) {
        const prepared = await prepareSlackAgentSubmission({ ...nativeSessionKey, token: nativeRunToken });
        if (!prepared.accepted) throw new Error("Slack Agent continuation submission preparation was rejected");
        if (prepared.cancelled) {
          await consumeStoppedContinuation();
          return;
        }
      }
      let result: TurnResult;
      try {
        const verifiedTs = (value: unknown): value is string =>
          typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value);
        const verifiedSlack =
          verifiedTs(continuationTriggerTs) &&
          verifiedTs(messageTs) &&
          (messageThreadTs === undefined || verifiedTs(messageThreadTs))
            ? {
                teamId: String((body as any)?.team?.id ?? ids.ownTeamId),
                userId: clickerId,
                channelId: channel,
                messageTs,
                threadTs: messageThreadTs ?? messageTs,
                threaded: messageThreadTs !== undefined,
                liveHuman: true as const,
                actionTs: continuationTriggerTs,
              }
            : undefined;
        const runHooks: CoreCallHooks = {
          onQueued,
          resumeReplay: true,
          ...(nativeContinuation
            ? {
                onDelta: (delta: string) => {
                  nativeContinuation?.onDelta(delta);
                },
                onTasks: async (tasks) => {
                  if (!(await nativeContinuationWasStopped())) await nativeContinuation?.onTasks(tasks);
                },
              }
            : {}),
        };
        if (resumedSubmittedRunId) {
          bridge.inFlightRunByThread.set(ctx.turn.conversation.threadRef, resumedSubmittedRunId);
          await acknowledge();
          result = await resumeRun(resumedSubmittedRunId, runHooks);
        } else {
          result = await callCore(
            {
              ...ctx.turn,
              actor: approver!,
              approval,
              ...(nativeRunToken ? { slackAgentSessionToken: nativeRunToken } : {}),
              ...(nativeRunToken && nativeSessionKey
                ? { slackAgentSession: { ...nativeSessionKey, token: nativeRunToken } }
                : {}),
              origin: { kind: "human", messageTs: messageTs ?? continuationTriggerTs },
              triggerTs: messageTs ?? continuationTriggerTs,
              ...(verifiedSlack ? { verifiedSlack } : {}),
              idempotencyKey: continuationClaim.idempotencyKey,
            },
            runHooks,
          );
        }
        continuationResultResolved = true;
        continuationAttachments = result.attachments;
        await acknowledge();
      } finally {
        if (nativeRunId) bridge.inFlightRunByThread.clear(ctx.turn.conversation.threadRef, nativeRunId);
      }
      if (await consumeStoppedContinuation()) return;

      if (ctx.agentRequest) {
        const quarantineText = result.refusalKind === "security_quarantine" ? refusalNote(result, "dm") : undefined;
        const routedResult = quarantineText ? { ...result, reason: quarantineText, adminUrl: undefined } : result;
        const agentRequest = resultAgentRequest()!;
        await retainClaim();
        await handleAgentRequestResult(client, agentRequest, ctx.turn, routedResult, {
          approvalMessageTs: messageTs,
          handoffMessageTs: agentRequest.dmMessageTs,
        });
        if (result.status !== "ok" && result.status !== "pending_approval") {
          await updateSlackMessage(
            client,
            cardChannel,
            messageTs,
            quarantineText ?? `I can't continue — ${result.reason ?? "refused"}.`,
          );
        }
        if (quarantineText && nativeRunId) {
          try {
            await bridge.ackRunDelivery(nativeRunId);
          } finally {
            bridge.inFlightRuns.delete(nativeRunId);
          }
        }
        await settle();
        return;
      }

      if (result.status === "ok") {
        if (ctx.threadOnly && ctx.replyThreadTs) threads.mark(ctx.channel, ctx.replyThreadTs, true);
        const cleanedContinuation = cleanAgentReplyForSlack(result.reply ?? "");
        const replyBody = stripAckPrefix(cleanedContinuation.text, ctx.ackedFirstBlock);
        const { reactions, agentRequests } = cleanedContinuation;
        const actionableAgentRequests = ctx.threadOnly ? agentRequests : [];
        let reply = "(no response)";
        if (replyBody) reply = toSlackMrkdwn(replyBody);
        else if (result.attachments?.length || reactions.length || actionableAgentRequests.length) reply = "Done.";
        if (await consumeStoppedContinuation()) return;
        const deliveredNatively = await finishNativeContinuation(replyBody || reply, "active");
        if (await consumeStoppedContinuation()) return;
        if (!nativeContinuation) await setNativeApprovalStatus("active");
        if (await consumeStoppedContinuation()) return;
        if (cardIsRemote) {
          await retainClaim();
          if (!deliveredNatively) {
            await postApprovalFollowup(
              client,
              ctx,
              reply,
              nativeContinuationWasStopped,
              nativeRunId ? `run:${nativeRunId}` : `${continuationClaim.idempotencyKey}:result`,
              String(Math.max(0, Number(continuationClaim.actionTs) - 300)),
            );
            if (await consumeStoppedContinuation()) return;
          }
          await updateSlackMessage(client, cardChannel, messageTs, `Approved; ran ${inlineCode(ctx.command)}.`);
        } else {
          await retainClaim();
          await updateSlackMessage(
            client,
            cardChannel,
            messageTs,
            deliveredNatively ? `Approved; ran ${inlineCode(ctx.command)}.` : reply,
          );
        }
        if (await consumeStoppedContinuation()) return;
        if (result.attachments?.length) {
          try {
            const uploaded = await uploadAttachments(
              client,
              ctx.channel,
              ctx.replyThreadTs,
              result.attachments,
              fetchBlobFromCore,
              fetchFileArtifactFromCore,
              attachmentDeliveryOptions(),
            );
            if (!uploaded.uploaded && (await nativeContinuationWasStopped())) {
              stoppedAttachmentCleanupComplete = true;
            }
          } catch (err) {
            console.error("[slack-plugin] file upload failed:", (err as Error).message);
            if (await nativeContinuationWasStopped()) {
              attachmentCompensationFailed = true;
              throw err;
            }
            await postApprovalFollowup(client, ctx, uploadFailureNote(err), nativeContinuationWasStopped);
          }
        }
        if (await consumeStoppedContinuation()) return;
        const { directives } = resolveReactionTargets(reactions, ctx.allowedTs ?? new Set());
        await applyAndLogReactions(client, ctx.channel, ctx.triggerTs, directives, {
          isCancelled: nativeContinuationWasStopped,
          ...(nativeSessionKey && nativeRunToken && continuationTriggerTs
            ? {
                compensateCreatedReaction,
                reactionEffectScopeId: `${nativeRunToken}:approval-result:${requestId}`,
                reactionEffectSequenceBase: 200,
                admitDesiredReaction,
                withdrawDesiredReaction,
                cancelDesiredReaction,
              }
            : {}),
        });
        if (await consumeStoppedContinuation()) return;
        if (actionableAgentRequests.length) {
          await postAgentRequests(
            client,
            {
              requesterId: ctx.requesterId,
              channel: ctx.channel,
              ...(ctx.replyThreadTs ? { replyThreadTs: ctx.replyThreadTs } : {}),
              threadOnly: ctx.threadOnly,
              kind: ctx.turn.conversation.kind,
              ...(ctx.turn.conversation.channelName ? { channelName: ctx.turn.conversation.channelName } : {}),
              audience: ctx.turn.conversation.audience ?? [],
              ...(ctx.slackIdsByPrincipal ? { slackIdsByPrincipal: ctx.slackIdsByPrincipal } : {}),
              isCancelled: nativeContinuationWasStopped,
              effectScopeId: nativeRunId
                ? `run:${nativeRunId}:agent-requests`
                : `${continuationClaim.idempotencyKey}:agent-requests`,
            },
            actionableAgentRequests,
          );
        }
        await settle();
        return;
      }

      if (result.status === "pending_approval") {
        if (await consumeStoppedContinuation()) return;
        await finishNativeContinuation("", "suspended");
        if (await consumeStoppedContinuation()) return;
        const approvals = result.pendingApprovals ?? [];
        await rememberSlackApprovals(approvals, {
          requesterId: ctx.requesterId,
          channel: ctx.channel,
          approvalChannel: cardChannel,
          approvalMessageTs: messageTs,
          ...(ctx.replyThreadTs ? { replyThreadTs: ctx.replyThreadTs } : {}),
          ...(ctx.triggerTs ? { triggerTs: ctx.triggerTs } : {}),
          threadOnly: ctx.threadOnly,
          turn: ctx.turn,
          ...(ctx.allowedTs ? { allowedTs: ctx.allowedTs } : {}),
          ...(ctx.slackIdsByPrincipal ? { slackIdsByPrincipal: ctx.slackIdsByPrincipal } : {}),
          ...(ctx.nativeAgentSession ? { nativeAgentSession: ctx.nativeAgentSession } : {}),
          ...(ctx.agentRequest ? { agentRequest: ctx.agentRequest } : {}),
          ...(ctx.recovered ? { recovered: true } : {}),
        });
        const msg = approvalMessage(approvals);
        await retainClaim();
        await updateSlackMessage(client, cardChannel, messageTs, msg.text, msg.blocks);
        await settle();
        await consumeStoppedContinuation();
        return;
      }

      const quarantineText = result.refusalKind === "security_quarantine" ? refusalNote(result, "dm") : undefined;
      const failLink = quarantineText || isBoundaryRefusal(result.reason) ? null : (result.adminUrl ?? null);
      const failDetail = failLink ? ` Full error: ${failLink}` : "";
      const refusalText = quarantineText ?? `I can't continue — ${result.reason ?? "refused"}.${failDetail}`;
      if (await consumeStoppedContinuation()) return;
      const deliveredNatively = await finishNativeContinuation(refusalText, "active");
      if (await consumeStoppedContinuation()) return;
      if (!nativeContinuation) await setNativeApprovalStatus("active");
      await retainClaim();
      if (quarantineText && cardIsRemote && !deliveredNatively) {
        await postApprovalFollowup(
          client,
          ctx,
          quarantineText,
          nativeContinuationWasStopped,
          nativeRunId ? `run:${nativeRunId}` : `${continuationClaim.idempotencyKey}:result`,
          String(Math.max(0, Number(continuationClaim.actionTs) - 300)),
        );
        if (await consumeStoppedContinuation()) return;
      }
      await updateSlackMessage(client, cardChannel, messageTs, refusalText);
      if (result.refusalKind === "security_quarantine" && nativeRunId) {
        try {
          await bridge.ackRunDelivery(nativeRunId);
        } finally {
          bridge.inFlightRuns.delete(nativeRunId);
        }
      }
      await settle();
    } catch (err) {
      if (
        (!resumedSubmittedRunId || continuationResultResolved) &&
        !attachmentCompensationFailed &&
        (await consumeStoppedContinuation())
      )
        return;
      const msg = (err as Error).message;
      if (settled) {
        await updateSlackMessage(client, cardChannel, messageTs, `⚠️ ${msg}`).catch(
          swallowAs("slack: update approval message", undefined),
        );
        const agentRequest = resultAgentRequest();
        if (agentRequest) {
          await failAgentRequest(client, agentRequest, msg, agentRequest.dmMessageTs);
        }
        return;
      }
      pendingSlackApprovals.release(requestId);
      if (continuationSubmitted) {
        if (!(await renewSlackApprovalContinuation(continuationClaim).catch(() => false))) return;
        await finishNativeContinuation("", "suspended");
        await updateSlackMessage(
          client,
          cardChannel,
          messageTs,
          selected === "deny"
            ? `Denied ${inlineCode(ctx.command)}; the durable decision is still being finalized.`
            : `Approved; ${inlineCode(ctx.command)} is still running and its durable result will be delivered here.`,
        ).catch(swallowAs("slack: update accepted approval", undefined));
        return;
      }
      if (!(await releaseSlackApprovalContinuation(continuationClaim).catch(() => false))) return;
      released = true;
      await finishNativeContinuation("", "suspended");
      const retry = approvalMessage([
        {
          requestId,
          command: ctx.command,
          reason: ctx.reason,
          ...(ctx.purpose ? { purpose: ctx.purpose } : {}),
          ...(ctx.summary ? { summary: ctx.summary } : {}),
          ...(ctx.grantModes ? { grantModes: ctx.grantModes } : {}),
        },
      ]);
      await updateSlackMessage(
        client,
        cardChannel,
        messageTs,
        `⚠️ ${clip(msg, 300)} — the approval is still pending; use the buttons to try again.`,
        [
          {
            type: "section",
            text: { type: "mrkdwn", text: `⚠️ ${clip(msg, 300)} — the approval is still pending; try again:` },
          },
          ...retry.blocks,
        ],
      ).catch(swallowAs("slack: update approval message", undefined));
    } finally {
      clearInterval(leaseHeartbeat);
      if (nativeRunId) bridge.inFlightRunByThread.clear(ctx.turn.conversation.threadRef, nativeRunId);
      if (released && nativeSessionKey && nativeRunToken && nativeBindingAccepted && !nativeBindingCompleted) {
        await completeSlackAgentSession({
          ...nativeSessionKey,
          token: nativeRunToken,
          approvalClaim: nativeApprovalClaim,
        }).catch(() => false);
      }
    }
  }

  async function handleAgentRequestAction({ ack, body, action, client }: any): Promise<void> {
    await ack();
    const a = action as any;
    const actionId = a.action_id as AgentRequestActionId | undefined;
    if (actionId !== "agent_request_run" && actionId !== "agent_request_deny") return;

    const requestId = String(a.value ?? "");
    const ctx = pendingSlackAgentRequests.get(requestId);
    const clickerId = String((body as any)?.user?.id ?? "");
    const channel = String((body as any)?.channel?.id ?? ctx?.dmChannel ?? "");
    const messageTs = (body as any)?.message?.ts as string | undefined;

    if (!ctx) {
      if (channel && messageTs) {
        await updateSlackMessage(
          client,
          channel,
          messageTs,
          "_That agent request expired — ask the channel agent to send it again._",
        ).catch(swallowAs("slack: update agent-request message", undefined));
      } else if (channel && clickerId) {
        await client.chat
          .postEphemeral({
            channel,
            user: clickerId,
            text: "That agent request expired — ask the channel agent to send it again.",
          })
          .catch(swallowAs("slack: chat.postEphemeral", undefined));
      }
      return;
    }

    if (clickerId !== ctx.targetUserId) {
      await client.chat
        .postEphemeral({
          channel: ctx.dmChannel,
          user: clickerId,
          text: "Only the person whose personal agent was asked can approve or decline this request.",
        })
        .catch(swallowAs("slack: chat.postEphemeral", undefined));
      return;
    }

    pendingSlackAgentRequests.delete(requestId);
    const decision = agentRequestAction(actionId);
    if (decision === "deny") {
      await updateSlackMessage(
        client,
        ctx.dmChannel,
        messageTs ?? ctx.dmMessageTs,
        `Declined. I won't run this in ${ctx.targetAgentLabel}.`,
      );
      await updateSlackMessage(client, ctx.originChannel, ctx.originStatusTs, agentRequestStatusText(ctx, "declined"));
      return;
    }

    await updateSlackMessage(
      client,
      ctx.dmChannel,
      messageTs ?? ctx.dmMessageTs,
      `Approved. Running with ${ctx.targetAgentLabel} now...`,
    );
    await updateSlackMessage(client, ctx.originChannel, ctx.originStatusTs, agentRequestStatusText(ctx, "running"));

    try {
      const classified = await directory.classifyUserCached(client, ctx.targetUserId);
      const actor = classified.actor;
      if (actor.isExternalGuest) throw new Error("the target user is not internal");
      const personalTurn: Omit<CoreTurnBody, "approval"> = {
        actor,
        conversation: {
          kind: "dm",
          threadRef: dmThreadRef(ctx.dmChannel),
          audience: [actor],
        },
        deliveryTarget: encodeDeliveryTarget(ctx.dmChannel),
        text: personalAgentTurnText(ctx),
        gatewayContext: {
          location: `an agent-to-agent handoff in a direct message with ${actor.displayName ?? ctx.targetUserId}`,
          details: {
            channel: ctx.dmChannel,
            requested_by_channel: ctx.originChannel,
            ...(ctx.originThreadTs ? { requested_by_thread_ts: ctx.originThreadTs } : {}),
          },
          instructions:
            "You are answering an agent-to-agent handoff. Work only with this user's personal context and return a concise result safe to share back to the originating Slack thread.",
          ...(ids.botHandle ? { botHandle: ids.botHandle } : {}),
        },
        ...(classified.timezone ? { timezone: classified.timezone } : {}),
      };
      const result = await callCore(personalTurn);
      await handleAgentRequestResult(client, ctx, personalTurn, result, {
        handoffMessageTs: messageTs ?? ctx.dmMessageTs,
      });
    } catch (err) {
      const msg = (err as Error).message;
      await failAgentRequest(client, ctx, msg, messageTs ?? ctx.dmMessageTs);
    }
  }

  let submittedDrain: Promise<void> | undefined;
  async function pinSubmittedContinuations(): Promise<void> {
    const submitted = await submittedSlackApprovalContinuations({ teamId: ids.ownTeamId, agentId: ids.agentId });
    const currentRunIds = new Set(submitted.map((continuation) => continuation.runId));
    for (const runId of currentRunIds) pinSubmittedRun(runId);
    for (const runId of submittedRunPins) {
      if (!currentRunIds.has(runId)) unpinSubmittedRun(runId);
    }
  }

  function drainSubmittedContinuations(client: any): Promise<void> {
    if (submittedDrain) return submittedDrain;
    const drain = (async () => {
      await pinSubmittedContinuations();
      const recoverable = await recoverableSlackApprovalContinuations({
        teamId: ids.ownTeamId,
        agentId: ids.agentId,
        limit: 16,
      });
      for (const continuation of recoverable) {
        void handleApprovalAction({
          ack: async () => {},
          body: {
            team: { id: continuation.teamId },
            user: { id: continuation.clickerUserId },
            channel: { id: continuation.channelId },
            message: { ts: continuation.messageTs },
          },
          action: {
            action_id: continuation.actionId,
            action_ts: continuation.actionTs,
            value: continuation.requestId,
          },
          client,
          recoveringSubmitted: true,
        }).catch((error) =>
          console.error(
            `[slack-plugin] submitted approval recovery failed for ${continuation.requestId}:`,
            (error as Error).message,
          ),
        );
      }
    })();
    const tracked = drain.finally(() => {
      submittedDrain = undefined;
    });
    submittedDrain = tracked;
    return tracked;
  }

  function registerActions(app: { action(pattern: RegExp, handler: (args: any) => Promise<void>): void }): void {
    app.action(/^hilo_/, handleApprovalAction);
    app.action(/^agent_request_/, handleAgentRequestAction);
  }

  return {
    rememberSlackApprovals,
    postApprovalButtons,
    postAgentRequests,
    registerActions,
    pinSubmittedContinuations,
    drainSubmittedContinuations,
  };
}
