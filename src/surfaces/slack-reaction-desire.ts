import { createHash } from "node:crypto";
import type { DurableMap } from "../persistence/durable-map.ts";

const MAX_ID = 256;

export interface SlackReactionDesireInput {
  teamId: string;
  agentId: string;
  sessionChannelId: string;
  sessionThreadTs: string;
  sessionToken: string;
  effectId: string;
  sourceTs: string;
  sequence: number;
  channelId: string;
  messageTs: string;
  name: string;
}

export interface SlackReactionDesireRecord extends SlackReactionDesireInput {
  id: string;
  desired: boolean;
  generation: number;
  cleanupAdmissions?: SlackReactionDesireInput[];
  createdAt: number;
  updatedAt: number;
  cancelledAt?: number;
}

export interface SlackReactionDesireStore {
  admit(input: SlackReactionDesireInput): Promise<{
    disposition: "accepted" | "replayed" | "superseded";
    record: SlackReactionDesireRecord;
  }>;
  cancel(
    input: SlackReactionDesireInput,
    options?: { admitCleanup?: boolean },
  ): Promise<SlackReactionDesireRecord | null>;
  pendingCleanupAdmissions(input: {
    teamId: string;
    agentId: string;
    limit: number;
  }): Promise<SlackReactionDesireInput[]>;
  desired(input: { teamId: string; agentId: string }): Promise<SlackReactionDesireInput[]>;
  completeCleanupAdmission(input: SlackReactionDesireInput): Promise<boolean>;
  get(input: {
    teamId: string;
    agentId: string;
    channelId: string;
    messageTs: string;
    name: string;
  }): Promise<SlackReactionDesireRecord | null>;
}

function bounded(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed && trimmed.length <= MAX_ID ? trimmed : null;
}

function timestamp(value: unknown): string | null {
  const parsed = bounded(value);
  return parsed && /^\d+(?:\.\d{1,6})?$/.test(parsed) ? parsed : null;
}

function channel(value: unknown): string | null {
  const parsed = bounded(value);
  return parsed && /^[CDG][A-Z0-9]+$/.test(parsed) ? parsed : null;
}

function reaction(value: unknown): string | null {
  const parsed = bounded(value)?.toLowerCase();
  return parsed && /^[a-z0-9_+'-]+(?:::skin-tone-[2-6])?$/.test(parsed) ? parsed : null;
}

function normalizeInput(input: SlackReactionDesireInput): SlackReactionDesireInput | null {
  const teamId = bounded(input.teamId);
  const agentId = bounded(input.agentId);
  const sessionChannelId = channel(input.sessionChannelId);
  const sessionThreadTs = timestamp(input.sessionThreadTs);
  const sessionToken = bounded(input.sessionToken);
  const effectId = bounded(input.effectId);
  const sourceTs = timestamp(input.sourceTs);
  const channelId = channel(input.channelId);
  const messageTs = timestamp(input.messageTs);
  const name = reaction(input.name);
  return teamId &&
    agentId &&
    sessionChannelId &&
    sessionThreadTs &&
    sessionToken &&
    effectId &&
    sourceTs &&
    Number.isSafeInteger(input.sequence) &&
    input.sequence >= 0 &&
    input.sequence <= 1_000_000 &&
    channelId &&
    messageTs &&
    name
    ? {
        teamId,
        agentId,
        sessionChannelId,
        sessionThreadTs,
        sessionToken,
        effectId,
        sourceTs,
        sequence: input.sequence,
        channelId,
        messageTs,
        name,
      }
    : null;
}

function targetId(input: {
  teamId: string;
  agentId: string;
  channelId: string;
  messageTs: string;
  name: string;
}): string {
  const digest = createHash("sha256")
    .update(JSON.stringify([input.teamId, input.agentId, input.channelId, input.messageTs, input.name]))
    .digest("hex");
  return `reaction-desire:${digest}`;
}

function sourceOrder(input: Pick<SlackReactionDesireInput, "sourceTs" | "sequence">): [bigint, number] {
  const [seconds = "0", fraction = ""] = input.sourceTs.split(".");
  return [BigInt(seconds) * 1_000_000n + BigInt(fraction.padEnd(6, "0")), input.sequence];
}

function compareSource(
  left: Pick<SlackReactionDesireInput, "sourceTs" | "sequence">,
  right: Pick<SlackReactionDesireInput, "sourceTs" | "sequence">,
): number {
  const [leftTs, leftSequence] = sourceOrder(left);
  const [rightTs, rightSequence] = sourceOrder(right);
  if (leftTs === rightTs) return leftSequence - rightSequence;
  return leftTs < rightTs ? -1 : 1;
}

function sameTarget(
  record: SlackReactionDesireRecord,
  input: { teamId: string; agentId: string; channelId: string; messageTs: string; name: string },
): boolean {
  return (
    record.teamId === input.teamId &&
    record.agentId === input.agentId &&
    record.channelId === input.channelId &&
    record.messageTs === input.messageTs &&
    record.name === input.name
  );
}

function exactEffect(record: SlackReactionDesireRecord, input: SlackReactionDesireInput): boolean {
  return (
    sameTarget(record, input) &&
    record.sessionChannelId === input.sessionChannelId &&
    record.sessionThreadTs === input.sessionThreadTs &&
    record.sessionToken === input.sessionToken &&
    record.effectId === input.effectId &&
    record.sourceTs === input.sourceTs &&
    record.sequence === input.sequence
  );
}

function exactInput(left: SlackReactionDesireInput, right: SlackReactionDesireInput): boolean {
  return (
    left.teamId === right.teamId &&
    left.agentId === right.agentId &&
    left.sessionChannelId === right.sessionChannelId &&
    left.sessionThreadTs === right.sessionThreadTs &&
    left.sessionToken === right.sessionToken &&
    left.effectId === right.effectId &&
    left.sourceTs === right.sourceTs &&
    left.sequence === right.sequence &&
    left.channelId === right.channelId &&
    left.messageTs === right.messageTs &&
    left.name === right.name
  );
}

function cleanupAdmissions(record: SlackReactionDesireRecord): SlackReactionDesireInput[] {
  return Array.isArray(record.cleanupAdmissions)
    ? record.cleanupAdmissions.map(normalizeInput).filter((value): value is SlackReactionDesireInput => !!value)
    : [];
}

export function createSlackReactionDesireStore(
  backing: DurableMap<SlackReactionDesireRecord>,
  now: () => number = Date.now,
): SlackReactionDesireStore {
  const update = backing.update?.bind(backing);
  const insertIfAbsent = backing.insertIfAbsent?.bind(backing);
  if (!update || !insertIfAbsent) throw new Error("Slack reaction desire storage requires atomic durable updates");

  return {
    async admit(raw) {
      const input = normalizeInput(raw);
      if (!input) throw new Error("invalid Slack reaction desire");
      const id = targetId(input);
      const admittedAt = now();
      const initial: SlackReactionDesireRecord = {
        ...input,
        id,
        desired: true,
        generation: 1,
        cleanupAdmissions: [],
        createdAt: admittedAt,
        updatedAt: admittedAt,
      };
      if (await insertIfAbsent(id, initial)) return { disposition: "accepted", record: initial };
      let disposition: "accepted" | "replayed" | "superseded" = "accepted";
      const stored = await update(id, (current) => {
        if (!sameTarget(current, input)) throw new Error("Slack reaction desire target collision");
        const order = compareSource(input, current);
        if (order < 0) {
          disposition = "superseded";
          return current;
        }
        if (order === 0) {
          if (!exactEffect(current, input)) throw new Error("Slack reaction desire source collision");
          disposition = "replayed";
          return current;
        }
        return {
          ...input,
          id,
          desired: true,
          generation: current.generation + 1,
          cleanupAdmissions: cleanupAdmissions(current),
          createdAt: current.createdAt,
          updatedAt: admittedAt,
        };
      });
      if (!stored) throw new Error("Slack reaction desire disappeared during admission");
      return { disposition, record: stored };
    },

    async cancel(raw, options) {
      const input = normalizeInput(raw);
      if (!input) throw new Error("invalid Slack reaction desire cancellation");
      const cancelledAt = now();
      let applied = false;
      const stored = await update(targetId(input), (current) => {
        if (!sameTarget(current, input)) throw new Error("Slack reaction desire target collision");
        const admissions = cleanupAdmissions(current);
        const nextAdmissions =
          options?.admitCleanup && !admissions.some((candidate) => exactInput(candidate, input))
            ? [...admissions, input]
            : admissions;
        if (!exactEffect(current, input)) {
          if (nextAdmissions === admissions) return current;
          applied = true;
          return { ...current, cleanupAdmissions: nextAdmissions, updatedAt: cancelledAt };
        }
        if (!current.desired && nextAdmissions === admissions) return current;
        applied = true;
        return {
          ...current,
          desired: false,
          cleanupAdmissions: nextAdmissions,
          cancelledAt: current.cancelledAt ?? cancelledAt,
          updatedAt: cancelledAt,
        };
      });
      return applied ? (stored ?? null) : stored;
    },

    async pendingCleanupAdmissions(raw) {
      const teamId = bounded(raw.teamId);
      const agentId = bounded(raw.agentId);
      if (!teamId || !agentId || !Number.isSafeInteger(raw.limit) || raw.limit < 1) return [];
      const pending: SlackReactionDesireInput[] = [];
      for (const [, record] of await backing.entries()) {
        if (record.teamId !== teamId || record.agentId !== agentId) continue;
        for (const admission of cleanupAdmissions(record)) {
          pending.push(admission);
          if (pending.length >= Math.min(100, raw.limit)) return pending;
        }
      }
      return pending;
    },

    async desired(raw) {
      const teamId = bounded(raw.teamId);
      const agentId = bounded(raw.agentId);
      if (!teamId || !agentId) return [];
      const desired: SlackReactionDesireInput[] = [];
      for (const [, record] of await backing.entries()) {
        if (record.teamId !== teamId || record.agentId !== agentId || !record.desired) continue;
        const input = normalizeInput(record);
        if (input) desired.push(input);
      }
      return desired;
    },

    async completeCleanupAdmission(raw) {
      const input = normalizeInput(raw);
      if (!input) return false;
      let completed = false;
      await update(targetId(input), (current) => {
        if (!sameTarget(current, input)) return current;
        const admissions = cleanupAdmissions(current);
        if (!admissions.some((candidate) => exactInput(candidate, input))) return current;
        completed = true;
        return {
          ...current,
          cleanupAdmissions: admissions.filter((candidate) => !exactInput(candidate, input)),
          updatedAt: now(),
        };
      });
      return completed;
    },

    async get(raw) {
      const teamId = bounded(raw.teamId);
      const agentId = bounded(raw.agentId);
      const channelId = channel(raw.channelId);
      const messageTs = timestamp(raw.messageTs);
      const name = reaction(raw.name);
      if (!teamId || !agentId || !channelId || !messageTs || !name) return null;
      const input = { teamId, agentId, channelId, messageTs, name };
      const stored = await backing.get(targetId(input));
      return stored && sameTarget(stored, input) ? stored : null;
    },
  };
}
