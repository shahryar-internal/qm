import { createHash, randomUUID } from "node:crypto";
import { types } from "node:util";
import type { DurableMap } from "../persistence/durable-map.ts";
import {
  observePrivateTurn,
  snapshotPrivateTurnObservation,
  type PrivateTurnObservation,
  type PrivateTurnObservationSink,
} from "./private-turn-observer.ts";

export interface PrivateTurnObservationOutboxRecord {
  contractVersion: 1;
  observationSha256: string;
  observation: PrivateTurnObservation;
  state: "pending" | "delivering" | "delivered";
  attempts: number;
  createdAt: number;
  updatedAt: number;
  nextAttemptAt: number;
  leaseToken?: string;
  leaseExpiresAt?: number;
  lastOutcome?: "accepted" | "duplicate" | "unconfirmed";
}

export interface PrivateTurnObservationOutbox extends PrivateTurnObservationSink {
  sweep(limit?: number): Promise<{ attempted: number; delivered: number; pending: number }>;
}

interface OutboxOptions {
  backing: DurableMap<PrivateTurnObservationOutboxRecord>;
  downstream: PrivateTurnObservationSink;
  timeoutMs: number;
  now?: () => number;
  leaseToken?: () => string;
  retryBaseMs?: number;
  retryMaximumMs?: number;
}

const FIELD_ORDER = [
  "source",
  "eventRef",
  "conversationRef",
  "principalRef",
  "audienceRef",
  "workspaceRef",
  "observedAt",
  "inputSha256",
] as const;

function observationSha256(value: PrivateTurnObservation): string {
  const hash = createHash("sha256");
  for (const field of FIELD_ORDER) {
    const item = value[field];
    hash.update(field).update("\0").update(String(item).length.toString(10)).update("\0").update(String(item));
  }
  return hash.digest("hex");
}

function sameObservation(left: PrivateTurnObservation, right: PrivateTurnObservation): boolean {
  return FIELD_ORDER.every((field) => left[field] === right[field]);
}

function checkedRecord(value: PrivateTurnObservationOutboxRecord): PrivateTurnObservationOutboxRecord {
  if (!value || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) {
    throw new TypeError("private turn observation outbox record is invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  const required = [
    "contractVersion",
    "observationSha256",
    "observation",
    "state",
    "attempts",
    "createdAt",
    "updatedAt",
    "nextAttemptAt",
  ] as const;
  const allowed = new Set([...required, "leaseToken", "leaseExpiresAt", "lastOutcome"]);
  if (
    keys.some((key) => typeof key !== "string" || !allowed.has(key)) ||
    required.some((key) => !Object.hasOwn(descriptors, key)) ||
    Object.values(descriptors).some((descriptor) => !("value" in descriptor) || !descriptor.enumerable)
  ) {
    throw new TypeError("private turn observation outbox record is invalid");
  }
  const read = (key: string): unknown => descriptors[key]?.value;
  const contractVersion = read("contractVersion");
  const observationSha = read("observationSha256");
  const observation = snapshotPrivateTurnObservation(read("observation"));
  const state = read("state");
  const attempts = read("attempts");
  const createdAt = read("createdAt");
  const updatedAt = read("updatedAt");
  const nextAttemptAt = read("nextAttemptAt");
  const leaseToken = read("leaseToken");
  const leaseExpiresAt = read("leaseExpiresAt");
  const lastOutcome = read("lastOutcome");
  if (
    contractVersion !== 1 ||
    observationSha !== observationSha256(observation) ||
    (state !== "pending" && state !== "delivering" && state !== "delivered") ||
    !Number.isSafeInteger(attempts) ||
    (attempts as number) < 0 ||
    !Number.isSafeInteger(createdAt) ||
    !Number.isSafeInteger(updatedAt) ||
    !Number.isSafeInteger(nextAttemptAt) ||
    (lastOutcome !== undefined &&
      lastOutcome !== "accepted" &&
      lastOutcome !== "duplicate" &&
      lastOutcome !== "unconfirmed") ||
    (state === "delivering" &&
      (typeof leaseToken !== "string" || leaseToken.length < 1 || !Number.isSafeInteger(leaseExpiresAt))) ||
    (state !== "delivering" && (leaseToken !== undefined || leaseExpiresAt !== undefined))
  ) {
    throw new TypeError("private turn observation outbox record is invalid");
  }
  return Object.freeze({
    contractVersion: 1,
    observationSha256: observationSha as string,
    observation,
    state,
    attempts: attempts as number,
    createdAt: createdAt as number,
    updatedAt: updatedAt as number,
    nextAttemptAt: nextAttemptAt as number,
    ...(leaseToken !== undefined ? { leaseToken: leaseToken as string } : {}),
    ...(leaseExpiresAt !== undefined ? { leaseExpiresAt: leaseExpiresAt as number } : {}),
    ...(lastOutcome !== undefined ? { lastOutcome } : {}),
  });
}

export function createPrivateTurnObservationOutbox(options: OutboxOptions): PrivateTurnObservationOutbox {
  const { backing, downstream } = options;
  if (!backing.update) throw new TypeError("private turn observation outbox requires atomic durable updates");
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 10_000) {
    throw new TypeError("private turn observation outbox timeoutMs must be an integer from 1 through 10000");
  }
  const now = options.now ?? Date.now;
  const nextLeaseToken = options.leaseToken ?? randomUUID;
  const retryBaseMs = options.retryBaseMs ?? 1_000;
  const retryMaximumMs = options.retryMaximumMs ?? 30_000;
  if (
    !Number.isSafeInteger(retryBaseMs) ||
    retryBaseMs < 1 ||
    !Number.isSafeInteger(retryMaximumMs) ||
    retryMaximumMs < retryBaseMs
  ) {
    throw new TypeError("private turn observation retry interval is invalid");
  }
  const leaseMs = Math.max(options.timeoutMs * 2, 1_000);

  const deliver = async (id: string): Promise<"accepted" | "duplicate" | "unconfirmed"> => {
    const leaseToken = nextLeaseToken();
    const claimedAt = now();
    let claimed = false;
    const claimedRecord = await backing.update!(id, (raw) => {
      const record = checkedRecord(raw);
      if (record.state === "delivered") return record;
      if (record.state === "delivering" && (record.leaseExpiresAt ?? 0) > claimedAt) return record;
      if (record.nextAttemptAt > claimedAt) return record;
      claimed = true;
      return {
        ...record,
        state: "delivering",
        attempts: record.attempts + 1,
        updatedAt: claimedAt,
        leaseToken,
        leaseExpiresAt: claimedAt + leaseMs,
      };
    });
    if (!claimedRecord) return "unconfirmed";
    const checked = checkedRecord(claimedRecord);
    if (!claimed) return checked.state === "delivered" ? "duplicate" : "unconfirmed";

    const outcome = await observePrivateTurn(downstream, checked.observation, options.timeoutMs);
    const completedAt = now();
    await backing.update!(id, (raw) => {
      const current = checkedRecord(raw);
      if (current.state !== "delivering" || current.leaseToken !== leaseToken) return current;
      if (outcome === "accepted" || outcome === "duplicate") {
        const { leaseToken: _leaseToken, leaseExpiresAt: _leaseExpiresAt, ...rest } = current;
        return {
          ...rest,
          state: "delivered",
          updatedAt: completedAt,
          nextAttemptAt: completedAt,
          lastOutcome: outcome,
        };
      }
      const delay = Math.min(retryMaximumMs, retryBaseMs * 2 ** Math.min(current.attempts - 1, 20));
      const { leaseToken: _leaseToken, leaseExpiresAt: _leaseExpiresAt, ...rest } = current;
      return {
        ...rest,
        state: "pending",
        updatedAt: completedAt,
        nextAttemptAt: completedAt + delay,
        lastOutcome: "unconfirmed",
      };
    });
    return outcome;
  };

  const outbox: PrivateTurnObservationOutbox = {
    async observe(value: PrivateTurnObservation) {
      const observation = snapshotPrivateTurnObservation(value);
      const createdAt = now();
      const candidate: PrivateTurnObservationOutboxRecord = {
        contractVersion: 1,
        observationSha256: observationSha256(observation),
        observation,
        state: "pending",
        attempts: 0,
        createdAt,
        updatedAt: createdAt,
        nextAttemptAt: createdAt,
      };
      const stored = checkedRecord(await backing.putIfAbsent(observation.eventRef, candidate));
      if (!sameObservation(stored.observation, observation)) {
        throw new Error("private turn event identity is already bound to a different observation");
      }
      if (stored.state === "delivered") return "duplicate";
      return deliver(observation.eventRef);
    },
    async sweep(limit = 25) {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
        throw new TypeError("private turn observation sweep limit must be an integer from 1 through 100");
      }
      const currentTime = now();
      const due = (await backing.entries())
        .map(([id, raw]) => [id, checkedRecord(raw)] as const)
        .filter(([, record]) =>
          record.state === "pending"
            ? record.nextAttemptAt <= currentTime
            : record.state === "delivering" && (record.leaseExpiresAt ?? 0) <= currentTime,
        )
        .slice(0, limit);
      let delivered = 0;
      for (const [id] of due) {
        const outcome = await deliver(id);
        if (outcome === "accepted" || outcome === "duplicate") delivered += 1;
      }
      return { attempted: due.length, delivered, pending: due.length - delivered };
    },
  };
  return Object.freeze(outbox);
}
