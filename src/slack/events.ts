import {
  channelPrivacyChange,
  createDeduper,
  dedupeKey,
  isGroupMembershipMessage,
  isThreadReply,
  mentionsBot,
  onBotJoinedChannel,
  type SurfaceHeaderClient,
  shouldProcessMessage,
} from "./lib.ts";
import type { AckGate } from "./deferred-ack.ts";
import { messageWithForwardedContent } from "./forwards.ts";
import type { BotIdentity, Directory } from "./directory.ts";
import type { Mirror } from "./mirror.ts";
import type { SlackReactionEvent, TurnHandler } from "./turn-handler.ts";
import type { SlackAgentContextEntity } from "../surfaces/slack-agent-context.ts";

export function registerSlackEvents(
  app: {
    event(name: string, handler: (args: any) => Promise<void>): void;
    message(handler: (args: any) => Promise<void>): void;
  },
  deps: {
    handler: TurnHandler;
    mirror: Mirror;
    directory: Directory;
    ids: BotIdentity;
    deduper: ReturnType<typeof createDeduper>;
    webUiPublicUrl?: string;
    ensureHeader?: (
      client: SurfaceHeaderClient,
      channel: string,
      scopeId: string,
      kind: "dm" | "channel",
      ensureOpts?: { pinNew?: boolean },
    ) => void;
    saveAgentContext(input: {
      teamId: string;
      ownerUserId: string;
      context: unknown;
      source: "message" | "app_home" | "app_context" | "assistant_thread";
      eventTs: string;
    }): Promise<SlackAgentContextEntity[]>;
    bindAgentThread(input: {
      teamId: string;
      ownerUserId: string;
      channelId: string;
      threadTs: string;
      context: unknown;
      source: "message" | "app_home" | "app_context" | "assistant_thread";
      eventTs: string;
    }): Promise<{ entities: SlackAgentContextEntity[] } | null>;
    getAgentThread(input: { teamId: string; ownerUserId: string; channelId: string; threadTs: string }): Promise<{
      entities: SlackAgentContextEntity[];
      source: "message" | "app_home" | "app_context" | "assistant_thread";
    } | null>;
    renameAgentSession(input: {
      teamId: string;
      agentId: string;
      channelId: string;
      threadTs: string;
      changedByUserId: string;
      title: string;
      eventTs: string;
    }): Promise<boolean>;
  },
): void {
  const { handler, mirror, directory, ids, deduper } = deps;
  const { dispatch, handleReactionEvent, handleAgentSessionStopped, botHasStakeInThread } = handler;
  const { mirrorMessageEvent, pushSurfaceEvents } = mirror;
  const { syncForUnseenGroup, forceDirectorySync } = directory;
  const teamId = (body: any): string => String(body?.team_id ?? ids.ownTeamId ?? "");
  const intakeIdempotencyKey = (body: any): string | undefined => {
    const workspace = teamId(body);
    const eventId = typeof body?.event_id === "string" ? body.event_id : "";
    if (!/^[A-Za-z0-9_-]{1,256}$/.test(workspace) || !/^[A-Za-z0-9_-]{1,256}$/.test(eventId)) return undefined;
    return `slack-event:${workspace}:${ids.agentId}:${eventId}`;
  };
  const legacyContext = (value: unknown): unknown => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return { entities: [] };
    const context = value as { channel_id?: unknown; team_id?: unknown };
    if (typeof context.channel_id !== "string") return { entities: [] };
    return {
      entities: [
        {
          type: "slack#/types/channel_id",
          value: context.channel_id,
          ...(typeof context.team_id === "string" ? { team_id: context.team_id } : {}),
        },
      ],
    };
  };
  const messageAgentContext = async (body: any, message: any): Promise<SlackAgentContextEntity[]> => {
    if (!message?.user || !message?.channel || !message?.ts) return [];
    const workspace = teamId(body);
    if (!workspace) return [];
    const threadTs = String(message.thread_ts ?? message.ts);
    if (message.app_context !== undefined) {
      return (
        (
          await deps.bindAgentThread({
            teamId: workspace,
            ownerUserId: String(message.user),
            channelId: String(message.channel),
            threadTs,
            context: message.app_context,
            source: "message",
            eventTs: String(message.event_ts ?? message.ts),
          })
        )?.entities ?? []
      );
    }
    const existing = await deps.getAgentThread({
      teamId: workspace,
      ownerUserId: String(message.user),
      channelId: String(message.channel),
      threadTs,
    });
    if (existing?.source === "assistant_thread") return existing.entities;
    return (
      (
        await deps.bindAgentThread({
          teamId: workspace,
          ownerUserId: String(message.user),
          channelId: String(message.channel),
          threadTs,
          context: { entities: [] },
          source: "message",
          eventTs: String(message.event_ts ?? message.ts),
        })
      )?.entities ?? []
    );
  };
  const eventIdentity = async (
    client: any,
    event: { user?: string; bot_id?: string },
  ): Promise<{ userId: string; actor?: { externalId: string; isBot: true; displayName?: string } }> => {
    if (event.user) return { userId: event.user };
    if (!event.bot_id) return { userId: "" };
    try {
      const bot = (await client.bots.info({ bot: event.bot_id })).bot;
      if (bot?.user_id) return { userId: String(bot.user_id) };
      if (bot?.id === event.bot_id && bot.deleted !== true) {
        return {
          userId: event.bot_id,
          actor: {
            externalId: event.bot_id,
            isBot: true,
            ...(bot.name ? { displayName: String(bot.name) } : {}),
          },
        };
      }
    } catch {
      return { userId: event.bot_id };
    }
    return { userId: event.bot_id };
  };

  app.event("app_mention", async ({ event, body, client, context }: any) => {
    const e = event as any;
    const identity = await eventIdentity(client, e);
    const agentContext = await messageAgentContext(body, e);
    const key = dedupeKey({
      event_id: (body as any)?.event_id,
      client_msg_id: e.client_msg_id,
      channel: e.channel,
      ts: e.ts,
    });
    const content = messageWithForwardedContent(e);
    await dispatch(
      key,
      {
        kind: "channel",
        channel: e.channel,
        userId: identity.userId,
        ...(identity.actor ? { actor: identity.actor } : {}),
        rawText: content.text,
        files: content.files,
        threadTs: e.thread_ts,
        ts: e.ts,
        ...(e.bot_id || e.subtype === "bot_message" ? { botAuthored: true } : {}),
        ...(agentContext.length ? { agentContext } : {}),
        ...(intakeIdempotencyKey(body) ? { idempotencyKey: intakeIdempotencyKey(body) } : {}),
        ackGate: context.ackGate as AckGate | undefined,
      },
      client,
    );
  });

  app.message(async ({ message, body, client, context }: any) => {
    const m = message as any;
    if (channelPrivacyChange(m)) {
      await forceDirectorySync(client, m.channel);
      return;
    }
    if (isGroupMembershipMessage(m)) {
      await forceDirectorySync(client);
      return;
    }
    const ackGate = context.ackGate as AckGate | undefined;
    if (m.subtype === "message_changed" && m.message) {
      if (shouldProcessMessage(m.message, ids.botUserId, ids.ownBotId))
        await mirrorMessageEvent({ ...m.message, channel: m.channel, channel_type: m.channel_type }, client, {
          editedAt: Date.now(),
          ...(m.channel_type === "im" ? { kind: "dm" as const } : {}),
        });
      return;
    }
    if (m.subtype === "message_deleted" && m.deleted_ts) {
      const type = m.channel_type;
      const prev = m.previous_message;
      const selfDelete = Boolean(
        prev && ((ids.botUserId && prev.user === ids.botUserId) || (ids.ownBotId && prev.bot_id === ids.ownBotId)),
      );
      if (m.channel && (type === "channel" || type === "group" || type === "mpim" || type === "im"))
        await pushSurfaceEvents([
          {
            container: String(m.channel),
            ts: String(m.deleted_ts),
            deleted: true,
            ...(selfDelete ? { self: true } : {}),
          },
        ]);
      return;
    }
    if (!shouldProcessMessage(m, ids.botUserId, ids.ownBotId)) return;

    if (m.channel_type === "im") {
      const identity = await eventIdentity(client, m);
      const agentContext = await messageAgentContext(body, m);
      const key = dedupeKey({
        event_id: (body as any)?.event_id,
        client_msg_id: m.client_msg_id,
        channel: m.channel,
        ts: m.ts,
      });
      const content = messageWithForwardedContent(m);
      await dispatch(
        key,
        {
          kind: "dm",
          channel: m.channel,
          userId: identity.userId,
          ...(identity.actor ? { actor: identity.actor } : {}),
          ...(m.bot_profile?.name || m.username ? { authorName: String(m.bot_profile?.name || m.username) } : {}),
          rawText: content.text,
          files: content.files,
          threadTs: m.thread_ts,
          ts: m.ts,
          ...(m.bot_id || m.subtype === "bot_message" ? { botAuthored: true } : {}),
          ...(agentContext.length ? { agentContext } : {}),
          ...(intakeIdempotencyKey(body) ? { idempotencyKey: intakeIdempotencyKey(body) } : {}),
          ackGate,
        },
        client,
      );
      return;
    }

    if (m.channel_type === "channel" || m.channel_type === "group" || m.channel_type === "mpim") {
      if (m.channel_type === "mpim" && m.channel) syncForUnseenGroup(client, String(m.channel));
      const threadReply = isThreadReply(m);
      const isMention = mentionsBot(m.text ?? "", ids.botUserId);
      const willDispatch = threadReply && !isMention && (await botHasStakeInThread(client, m.channel, m.thread_ts));
      await mirrorMessageEvent(m, client, willDispatch ? { handled: true } : {});
      if (!threadReply) return;
      if (isMention) return;
      if (!willDispatch) {
        console.error(
          `[slack-plugin] thread-follow skipped: no bot stake detected in thread ch=${m.channel} thread_ts=${m.thread_ts} ts=${m.ts}`,
        );
        return;
      }
      const key = dedupeKey({
        event_id: (body as any)?.event_id,
        client_msg_id: m.client_msg_id,
        channel: m.channel,
        ts: m.ts,
      });
      const identity = await eventIdentity(client, m);
      const content = messageWithForwardedContent(m);
      await dispatch(
        key,
        {
          kind: "channel",
          channel: m.channel,
          userId: identity.userId,
          ...(identity.actor ? { actor: identity.actor } : {}),
          ...(m.bot_profile?.name || m.username ? { authorName: String(m.bot_profile?.name || m.username) } : {}),
          rawText: content.text,
          files: content.files,
          threadTs: m.thread_ts,
          ts: m.ts,
          unprompted: true,
          ...(m.bot_id || m.subtype === "bot_message" ? { botAuthored: true } : {}),
          ...(intakeIdempotencyKey(body) ? { idempotencyKey: intakeIdempotencyKey(body) } : {}),
          ackGate,
        },
        client,
      );
    }
  });

  app.event("member_joined_channel", async ({ event, body, client }: any) => {
    const e = event as { user?: string; channel?: string; event_ts?: string };
    if (
      deduper.seen(
        dedupeKey({ event_id: (body as { event_id?: string })?.event_id, channel: e.channel, ts: e.event_ts }),
      )
    )
      return;
    if (e.user === ids.botUserId) {
      await onBotJoinedChannel({
        client,
        channel: e.channel,
        joinerUserId: e.user,
        botUserId: ids.botUserId,
        webUiPublicUrl: deps.webUiPublicUrl,
        syncDirectory: () => forceDirectorySync(client),
        ...(deps.ensureHeader
          ? {
              ensureHeader: (channel: string) =>
                deps.ensureHeader!(client as SurfaceHeaderClient, channel, `channel:${channel}`, "channel", {
                  pinNew: true,
                }),
            }
          : {}),
      });
    } else {
      await forceDirectorySync(client, e.channel);
    }
  });

  for (const evt of ["channel_created", "channel_rename", "channel_unarchive"] as const) {
    app.event(evt, async ({ event, body, client }: any) => {
      const e = event as { channel?: { id?: string } | string; event_ts?: string };
      const channel = typeof e.channel === "string" ? e.channel : e.channel?.id;
      if (deduper.seen(dedupeKey({ event_id: (body as { event_id?: string })?.event_id, channel, ts: e.event_ts })))
        return;
      await forceDirectorySync(client, channel);
    });
  }

  app.event("member_left_channel", async ({ event, body, client }: any) => {
    const e = event as { channel?: string; user?: string; event_ts?: string };
    if (
      deduper.seen(
        dedupeKey({ event_id: (body as { event_id?: string })?.event_id, channel: e.channel, ts: e.event_ts }),
      )
    )
      return;
    const principalId = e.user ? (await directory.classifyUserCached(client, e.user)).actor.externalId : undefined;
    await forceDirectorySync(client, e.channel, principalId);
  });

  app.event("app_home_opened", async ({ event, body }: any) => {
    const e = event as { user?: string; tab?: string; context?: unknown; event_ts?: string };
    const workspace = teamId(body);
    if (e.tab !== "messages" || !workspace || !e.user || !e.event_ts) return;
    await deps.saveAgentContext({
      teamId: workspace,
      ownerUserId: e.user,
      context: e.context ?? { entities: [] },
      source: "app_home",
      eventTs: e.event_ts,
    });
  });
  app.event("app_context_changed", async ({ event, body }: any) => {
    const e = event as { user?: string; context?: unknown; event_ts?: string };
    const workspace = teamId(body);
    if (!workspace || !e.user || !e.event_ts) return;
    await deps.saveAgentContext({
      teamId: workspace,
      ownerUserId: e.user,
      context: e.context ?? { entities: [] },
      source: "app_context",
      eventTs: e.event_ts,
    });
  });
  for (const name of ["assistant_thread_started", "assistant_thread_context_changed"] as const) {
    app.event(name, async ({ event, body }: any) => {
      const e = event as {
        assistant_thread?: {
          user_id?: string;
          channel_id?: string;
          thread_ts?: string;
          context?: unknown;
        };
        event_ts?: string;
      };
      const thread = e.assistant_thread;
      const workspace = teamId(body);
      if (!workspace || !thread?.user_id || !thread.channel_id || !thread.thread_ts || !e.event_ts) return;
      await deps.bindAgentThread({
        teamId: workspace,
        ownerUserId: thread.user_id,
        channelId: thread.channel_id,
        threadTs: thread.thread_ts,
        context: legacyContext(thread.context),
        source: "assistant_thread",
        eventTs: e.event_ts,
      });
    });
  }
  app.event("agent_session_title_changed", async ({ event, body }: any) => {
    const e = event as {
      user?: string;
      channel?: string;
      thread_ts?: string;
      title?: string;
      event_ts?: string;
    };
    const workspace = teamId(body);
    if (!workspace || !e.user || !e.channel || !e.thread_ts || !e.title || !e.event_ts) return;
    await deps.renameAgentSession({
      teamId: workspace,
      agentId: ids.agentId,
      channelId: e.channel,
      threadTs: e.thread_ts,
      changedByUserId: e.user,
      title: e.title,
      eventTs: e.event_ts,
    });
  });
  app.event("agent_session_stopped", async ({ event, body, client }: any) => {
    const e = event as {
      channel_id?: string;
      channel?: string;
      thread_ts?: string;
      event_ts?: string;
      user?: string;
      streaming_message_ts?: string[];
    };
    await handleAgentSessionStopped(
      { ...e, event_id: (body as { event_id?: string })?.event_id, team_id: teamId(body) },
      client,
    );
  });

  app.event("reaction_added", async ({ event, body, client }: any) => {
    await handleReactionEvent(event as SlackReactionEvent, body as any, client, true);
  });
  app.event("reaction_removed", async ({ event, body, client }: any) => {
    await handleReactionEvent(event as SlackReactionEvent, body as any, client, false);
  });
}
