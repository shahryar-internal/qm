import { createHash } from "node:crypto";
import type { DurableMap } from "../persistence/durable-map.ts";

const MAX_ENTITIES = 12;
const MAX_ID = 256;
const ENTITY_TYPES = new Set([
  "slack#/types/channel_id",
  "slack#/types/canvas_id",
  "slack#/types/list_id",
  "slack#/types/message_context",
]);

export interface SlackAgentContextEntity {
  type: string;
  teamId: string;
  value: string | { channelId: string; messageTs: string };
}

export interface SlackAgentThreadContext {
  teamId: string;
  ownerUserId: string;
  channelId: string;
  threadTs: string;
  entities: SlackAgentContextEntity[];
  source: "message" | "app_home" | "app_context" | "assistant_thread";
  eventTs: string;
  updatedAt: number;
}

export interface SlackAgentContextStore {
  saveCurrent(input: {
    teamId: string;
    ownerUserId: string;
    context: unknown;
    source: SlackAgentThreadContext["source"];
    eventTs: string;
  }): Promise<SlackAgentContextEntity[]>;
  bindThread(input: {
    teamId: string;
    ownerUserId: string;
    channelId: string;
    threadTs: string;
    context: unknown;
    source: SlackAgentThreadContext["source"];
    eventTs: string;
  }): Promise<SlackAgentThreadContext | null>;
  getThread(input: {
    teamId: string;
    ownerUserId: string;
    channelId: string;
    threadTs: string;
  }): Promise<SlackAgentThreadContext | null>;
}

interface CurrentSlackAgentContext {
  teamId: string;
  ownerUserId: string;
  entities: SlackAgentContextEntity[];
  source: SlackAgentThreadContext["source"];
  eventTs: string;
  updatedAt: number;
}

interface StoredSlackAgentContext {
  kind: "current" | "thread";
  current?: CurrentSlackAgentContext;
  thread?: SlackAgentThreadContext;
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

function boundedEvent(value: unknown): string | null {
  const eventTs = bounded(value);
  return eventTs && eventTime(eventTs) >= 0 ? eventTs : null;
}

function key(parts: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

function currentKey(teamId: string, ownerUserId: string): string {
  return `current:${key([teamId, ownerUserId])}`;
}

function threadKey(teamId: string, ownerUserId: string, channelId: string, threadTs: string): string {
  return `thread:${key([teamId, ownerUserId, channelId, threadTs])}`;
}

function entitiesFrom(context: unknown, ownerTeamId: string): SlackAgentContextEntity[] {
  if (!context || typeof context !== "object" || Array.isArray(context)) return [];
  const raw = (context as { entities?: unknown }).entities;
  if (!Array.isArray(raw)) return [];
  const entities: SlackAgentContextEntity[] = [];
  for (const candidate of raw.slice(0, MAX_ENTITIES)) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue;
    const item = candidate as { type?: unknown; team_id?: unknown; value?: unknown };
    const type = bounded(item.type);
    const teamId = bounded(item.team_id) ?? ownerTeamId;
    if (!type || !ENTITY_TYPES.has(type) || teamId !== ownerTeamId) continue;
    if (type === "slack#/types/message_context") {
      if (!item.value || typeof item.value !== "object" || Array.isArray(item.value)) continue;
      const value = item.value as { channel_id?: unknown; message_ts?: unknown };
      const channelId = bounded(value.channel_id);
      const messageTs = bounded(value.message_ts);
      if (!channelId || !messageTs) continue;
      entities.push({ type, teamId, value: { channelId, messageTs } });
      continue;
    }
    const value = bounded(item.value);
    if (value) entities.push({ type, teamId, value });
  }
  return entities;
}

function isNewer(candidate: string, existing: string): boolean {
  return eventTime(candidate) > eventTime(existing);
}

export function createSlackAgentContextStore(
  backing: DurableMap<StoredSlackAgentContext>,
  now: () => number = Date.now,
): SlackAgentContextStore {
  const update = backing.update?.bind(backing);
  if (!update) throw new Error("Slack agent context storage requires atomic durable updates");
  const writeCurrent = async (input: {
    teamId: string;
    ownerUserId: string;
    context: unknown;
    source: SlackAgentThreadContext["source"];
    eventTs: string;
  }): Promise<SlackAgentContextEntity[]> => {
    const teamId = bounded(input.teamId);
    const ownerUserId = bounded(input.ownerUserId);
    const eventTs = boundedEvent(input.eventTs);
    if (!teamId || !ownerUserId || !eventTs) return [];
    const entities = entitiesFrom(input.context, teamId);
    const id = currentKey(teamId, ownerUserId);
    const next: StoredSlackAgentContext = {
      kind: "current",
      current: { teamId, ownerUserId, entities, source: input.source, eventTs, updatedAt: now() },
    };
    await backing.putIfAbsent(id, next);
    const updated = await update(id, (value) => {
      if (value.kind !== "current" || !value.current) return value;
      return isNewer(eventTs, value.current.eventTs) ? next : value;
    });
    return updated?.current?.entities ?? [];
  };

  return {
    saveCurrent: writeCurrent,
    async bindThread(input) {
      const teamId = bounded(input.teamId);
      const ownerUserId = bounded(input.ownerUserId);
      const channelId = bounded(input.channelId);
      const threadTs = bounded(input.threadTs);
      const eventTs = boundedEvent(input.eventTs);
      if (!teamId || !ownerUserId || !channelId || !threadTs || !eventTs) return null;
      const entities = entitiesFrom(input.context, teamId);
      const id = threadKey(teamId, ownerUserId, channelId, threadTs);
      const next: SlackAgentThreadContext = {
        teamId,
        ownerUserId,
        channelId,
        threadTs,
        entities,
        source: input.source,
        eventTs,
        updatedAt: now(),
      };
      await backing.putIfAbsent(id, { kind: "thread", thread: next });
      const updated = await update(id, (value) => {
        if (value.kind !== "thread" || !value.thread || !isNewer(eventTs, value.thread.eventTs)) return value;
        return {
          kind: "thread",
          thread: next,
        };
      });
      return updated?.kind === "thread" ? (updated.thread ?? null) : null;
    },
    async getThread(input) {
      const teamId = bounded(input.teamId);
      const ownerUserId = bounded(input.ownerUserId);
      const channelId = bounded(input.channelId);
      const threadTs = bounded(input.threadTs);
      if (!teamId || !ownerUserId || !channelId || !threadTs) return null;
      const stored = await backing.get(threadKey(teamId, ownerUserId, channelId, threadTs));
      const record = stored?.kind === "thread" ? stored.thread : undefined;
      if (
        !record ||
        record.teamId !== teamId ||
        record.ownerUserId !== ownerUserId ||
        record.channelId !== channelId ||
        record.threadTs !== threadTs
      ) {
        return null;
      }
      return record;
    },
  };
}
