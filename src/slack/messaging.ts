import { createHash } from "node:crypto";
import {
  type ActorAssertion,
  type AgentRequestDirective,
  type ReactionDirective,
  type ReactionCompensationVerdict,
  AGENT_REQUEST_INSTRUCTION,
  MAX_REACTIONS_PER_TURN,
  REACTION_INSTRUCTION,
  applyReactions,
  botIdentityArgs,
  extractAgentRequests,
  extractReactions,
  stripAgentRequestDirectives,
  stripReactionDirectives,
} from "./lib.ts";

export type SlackConversationKind = "dm" | "channel" | "group";

const SLACK_TEXT_LIMIT = 40000;

export async function updateSlackMessage(
  client: any,
  channel: string,
  ts: string | undefined,
  text: string,
  blocks?: Array<Record<string, unknown>>,
): Promise<boolean> {
  if (!ts) return false;
  await client.chat.update({
    channel,
    ts,
    text: text.length > SLACK_TEXT_LIMIT ? `${text.slice(0, SLACK_TEXT_LIMIT - 1)}…` : text,
    ...botIdentityArgs(),
    unfurl_links: false,
    unfurl_media: false,
    blocks: blocks ?? [],
  });
  return true;
}

export async function tryUpdateSlackMessage(
  client: any,
  channel: string,
  ts: string | undefined,
  text: string,
  blocks?: Array<Record<string, unknown>>,
): Promise<boolean> {
  try {
    return await updateSlackMessage(client, channel, ts, text, blocks);
  } catch (err) {
    console.error("[slack-plugin] chat.update failed:", (err as Error).message);
    return false;
  }
}

export function cleanAgentReplyForSlack(text: string): {
  text: string;
  reactions: ReactionDirective[];
  agentRequests: AgentRequestDirective[];
} {
  const extractedReactions = extractReactions(text);
  const extractedRequests = extractAgentRequests(extractedReactions.text);
  return {
    text: extractedRequests.text,
    reactions: extractedReactions.reactions,
    agentRequests: extractedRequests.requests,
  };
}

export function slackSurfaceInstructions(kind: SlackConversationKind): string {
  return kind === "dm" ? REACTION_INSTRUCTION : `${REACTION_INSTRUCTION}\n\n${AGENT_REQUEST_INSTRUCTION}`;
}

export function stripSlackDirectives(text: string): string {
  return stripAgentRequestDirectives(stripReactionDirectives(text));
}

export async function applyAndLogReactions(
  client: any,
  channel: string,
  defaultTs: string | undefined,
  directives: readonly ReactionDirective[],
  opts: {
    isCancelled?: () => boolean | Promise<boolean>;
    compensateCreatedReaction?: (input: {
      channel: string;
      timestamp: string;
      name: string;
      effectId: string;
      sequence: number;
    }) => Promise<ReactionCompensationVerdict>;
    reactionEffectScopeId?: string;
    reactionEffectSequenceBase?: number;
    admitDesiredReaction?: (input: {
      channel: string;
      timestamp: string;
      name: string;
      effectId: string;
      sequence: number;
    }) => Promise<boolean>;
    withdrawDesiredReaction?: (input: {
      channel: string;
      timestamp: string;
      name: string;
      effectId: string;
      sequence: number;
    }) => Promise<void>;
    cancelDesiredReaction?: (input: {
      channel: string;
      timestamp: string;
      name: string;
      effectId: string;
      sequence: number;
    }) => Promise<void>;
  } = {},
): Promise<void> {
  const hasEffectLifecycle =
    !!opts.reactionEffectScopeId ||
    !!opts.compensateCreatedReaction ||
    !!opts.admitDesiredReaction ||
    !!opts.withdrawDesiredReaction ||
    !!opts.cancelDesiredReaction;
  if (
    hasEffectLifecycle &&
    (!opts.reactionEffectScopeId ||
      !opts.compensateCreatedReaction ||
      !opts.admitDesiredReaction ||
      !opts.withdrawDesiredReaction ||
      !opts.cancelDesiredReaction)
  ) {
    throw new Error(
      "Slack reaction effect lifecycle requires identity, desire, withdrawal, cancellation, and cleanup adapters",
    );
  }
  let budget = MAX_REACTIONS_PER_TURN;
  for (const [directiveOrdinal, d] of directives.entries()) {
    if (budget <= 0) break;
    const timestamp = d.target ?? defaultTs;
    if (!d.names.length || !timestamp) continue;
    const { added, failed, pendingRemoval } = await applyReactions(
      client,
      channel,
      timestamp,
      d.names.slice(0, budget),
      {
        ...opts,
        compensateCreatedReaction: opts.compensateCreatedReaction
          ? (input) =>
              opts.compensateCreatedReaction!({
                ...input,
                sequence:
                  (opts.reactionEffectSequenceBase ?? 0) + directiveOrdinal * MAX_REACTIONS_PER_TURN + input.ordinal,
              })
          : undefined,
        compensationEffectId: opts.reactionEffectScopeId
          ? ({ channel: effectChannel, timestamp, name, ordinal }) =>
              `reaction-effect:${createHash("sha256")
                .update(
                  JSON.stringify([
                    opts.reactionEffectScopeId,
                    directiveOrdinal,
                    ordinal,
                    effectChannel,
                    timestamp,
                    name,
                  ]),
                )
                .digest("hex")}`
          : undefined,
        admitDesiredReaction: opts.admitDesiredReaction
          ? (input) =>
              opts.admitDesiredReaction!({
                ...input,
                sequence:
                  (opts.reactionEffectSequenceBase ?? 0) + directiveOrdinal * MAX_REACTIONS_PER_TURN + input.ordinal,
              })
          : undefined,
        withdrawDesiredReaction: opts.withdrawDesiredReaction
          ? (input) =>
              opts.withdrawDesiredReaction!({
                ...input,
                sequence:
                  (opts.reactionEffectSequenceBase ?? 0) + directiveOrdinal * MAX_REACTIONS_PER_TURN + input.ordinal,
              })
          : undefined,
        cancelDesiredReaction: opts.cancelDesiredReaction
          ? (input) =>
              opts.cancelDesiredReaction!({
                ...input,
                sequence:
                  (opts.reactionEffectSequenceBase ?? 0) + directiveOrdinal * MAX_REACTIONS_PER_TURN + input.ordinal,
              })
          : undefined,
      },
    );
    budget -= added.length + failed.length;
    if (failed.length) {
      console.error(
        `[slack-plugin] couldn't add reaction(s): ${failed.join(", ")} on ${timestamp} (check the reactions:write scope / message ts)`,
      );
    }
    if (pendingRemoval?.length) {
      console.error(
        `[slack-plugin] cancellation cleanup pending for reaction(s): ${pendingRemoval.join(", ")} on ${timestamp}`,
      );
    }
  }
}

function possessive(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) return "Their";
  return trimmed.endsWith("s") || trimmed.endsWith("S") ? `${trimmed}'` : `${trimmed}'s`;
}

export function conversationPlaceLabel(
  kind: SlackConversationKind,
  channelName: string | undefined,
  channel: string,
): string {
  if (kind === "group") return channelName ? `group DM (${channelName})` : "group DM";
  return channelName ? `#${channelName}` : `channel ${channel}`;
}

export function channelAgentLabel(
  kind: SlackConversationKind,
  channelName: string | undefined,
  channel: string,
): string {
  if (kind === "group") return channelName ? `group DM (${channelName}) agent` : "group DM agent";
  return channelName ? `#${channelName} agent` : `channel ${channel} agent`;
}

export function personalAgentLabel(actor: ActorAssertion | undefined, userId: string): string {
  const name = actor?.displayName?.trim() || userId;
  return `${possessive(name)} personal agent`;
}
