import { createHash } from "node:crypto";
import { canonicalJson } from "../cron/schedule-authority.ts";
import type { DurableMap } from "../persistence/durable-map.ts";
import type {
  BackgroundJobAdmission,
  BackgroundJobAdmissionIntent,
  BackgroundJobAdmissionLease,
  BackgroundJobCompletionLease,
  BackgroundJobCompletionReceiptStore,
  BackgroundJobControlIntent,
  BackgroundJobControlLease,
  BackgroundJobDeliveryIntent,
  BackgroundJobDeliveryOutbox,
  BackgroundJobManualAttention,
  BackgroundJobOwner,
  BackgroundJobReceipt,
  BackgroundJobReceiptStore,
  BackgroundJobDeploymentProfile,
} from "./types.ts";
import { identifier } from "./validation.ts";

type WorkState = "pending" | "leased" | "succeeded" | "terminal";

interface AdmissionRecord {
  kind: "admission";
  intent: BackgroundJobAdmissionIntent;
  state: WorkState;
  attempt: number;
  nextAttemptAt: number;
  leaseId?: string;
  leaseExpiresAt?: number;
  admission?: BackgroundJobAdmission;
  receipt?: BackgroundJobReceipt;
  completionState?: "pending" | "leased" | "terminal";
  completionAttempt?: number;
  completionFailureAttempt?: number;
  completionNextAttemptAt?: number;
  completionLeaseId?: string;
  completionLeaseExpiresAt?: number;
  completionTerminalState?: "complete" | "failed" | "cancelled";
  completionDeliveryKey?: string;
  attentionRequiredAt?: number;
  completionAttentionRequiredAt?: number;
}

interface ControlRecord {
  kind: "control";
  intent: BackgroundJobControlIntent;
  state: WorkState;
  attempt: number;
  nextAttemptAt: number;
  leaseId?: string;
  leaseExpiresAt?: number;
  completedAt?: number;
  attentionRequiredAt?: number;
}

export type BackgroundJobDurableRecord = AdmissionRecord | ControlRecord;

interface DeliveryRecord {
  intent: BackgroundJobDeliveryIntent;
  state: "pending" | "leased" | "sent" | "terminal";
  attempt: number;
  nextAttemptAt: number;
  leaseId?: string;
  leaseExpiresAt?: number;
  sentAt?: number;
  attentionRequiredAt?: number;
}

export type BackgroundJobDeliveryRecord = DeliveryRecord;

export async function backgroundJobTerminalAndExpired(
  backing: DurableMap<BackgroundJobDurableRecord>,
  profile: Readonly<BackgroundJobDeploymentProfile>,
  now: number,
): Promise<boolean> {
  exactTime(now, "retirement time");
  for (const record of await backing.all()) {
    if (record.intent.jobId !== profile.definition.id) continue;
    if (record.intent.descriptorSha256 !== profile.binding.descriptorSha256) return false;
    if (record.kind === "control") {
      if (record.state !== "succeeded") return false;
      if (record.intent.approvalGrant.expiresAt > now) return false;
      continue;
    }
    if (record.state !== "succeeded") return false;
    if (record.intent.approvalGrant.expiresAt > now) return false;
    if (
      record.receipt &&
      (record.completionState !== "terminal" || !record.completionTerminalState || !record.completionDeliveryKey)
    )
      return false;
  }
  return true;
}

function digest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function exactTime(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${name} is invalid`);
  return value;
}

function exactLimit(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 100) throw new TypeError("lease limit is invalid");
  return value;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function owned(receipt: Readonly<BackgroundJobReceipt>, jobId: string, owner: Readonly<BackgroundJobOwner>): boolean {
  return (
    receipt.jobId === jobId &&
    receipt.organizationId === owner.organizationId &&
    receipt.actorPrincipalId === owner.actorPrincipalId &&
    receipt.actorSlackId === owner.actorSlackId &&
    receipt.audienceScopeId === owner.audienceScopeId &&
    receipt.slackTeamId === owner.slackTeamId &&
    receipt.channelId === owner.channelId &&
    receipt.threadTs === owner.threadTs &&
    receipt.conversationThreadRef === owner.conversationThreadRef
  );
}

function admissionReceipt(
  intent: Readonly<BackgroundJobAdmissionIntent>,
  admission: Readonly<BackgroundJobAdmission>,
): BackgroundJobReceipt {
  identifier(admission.authorityId, "authority id");
  identifier(admission.runId, "run id");
  const grant = intent.approvalGrant;
  return {
    intentId: intent.intentId,
    jobId: intent.jobId,
    authorityId: admission.authorityId,
    runId: admission.runId,
    organizationId: intent.organizationId,
    actorPrincipalId: intent.actorPrincipalId,
    actorSlackId: intent.actorSlackId,
    audienceScopeId: intent.audienceScopeId,
    slackTeamId: intent.slackTeamId,
    channelId: intent.channelId,
    threadTs: intent.threadTs,
    conversationThreadRef: intent.conversationThreadRef,
    messageTs: intent.messageTs,
    descriptorSha256: intent.descriptorSha256,
    profileSha256: intent.profileSha256,
    schemaSha256: intent.schemaSha256,
    payloadSha256: intent.payloadSha256,
    approvalId: grant.approvalId,
    approvalDigest: grant.digest,
    approvalEffect: "background_job_start",
    approvalKey: grant.approvalKey,
    approvalActionTs: grant.actionTs,
    approvalMessageTs: grant.messageTs,
    approvalThreadTs: grant.threadTs,
    idempotencyKey: intent.idempotencyKey,
    createdAt: intent.createdAt,
  };
}

export function createDurableBackgroundJobStore(
  backing: DurableMap<BackgroundJobDurableRecord>,
  durable: boolean,
): BackgroundJobReceiptStore & BackgroundJobCompletionReceiptStore {
  const ready = durable && typeof backing.update === "function" && typeof backing.insertIfAbsent === "function";
  const leaseAdmissions = async (
    jobId: string,
    now: number,
    limit: number,
    leaseId: string,
    leaseExpiresAt: number,
  ): Promise<BackgroundJobAdmissionLease[]> => {
    identifier(jobId, "job id");
    identifier(leaseId, "lease id");
    exactTime(now, "lease time");
    exactLimit(limit);
    if (leaseExpiresAt <= now) throw new TypeError("lease expiry is invalid");
    const leased: BackgroundJobAdmissionLease[] = [];
    for (const [key, candidate] of await backing.entries()) {
      if (leased.length >= limit || candidate.kind !== "admission" || candidate.intent.jobId !== jobId) continue;
      if (
        candidate.state === "succeeded" ||
        candidate.nextAttemptAt > now ||
        (candidate.state === "leased" && (candidate.leaseExpiresAt ?? 0) > now)
      ) {
        continue;
      }
      const updated = await backing.update!(key, (current) => {
        if (
          current.kind !== "admission" ||
          current.intent.jobId !== jobId ||
          current.state === "succeeded" ||
          current.nextAttemptAt > now ||
          (current.state === "leased" && (current.leaseExpiresAt ?? 0) > now)
        ) {
          return current;
        }
        return {
          ...current,
          state: "leased",
          attempt: current.attempt + 1,
          leaseId,
          leaseExpiresAt,
        };
      });
      if (updated?.kind === "admission" && updated.state === "leased" && updated.leaseId === leaseId) {
        leased.push({
          intent: clone(updated.intent),
          leaseId,
          leaseExpiresAt,
          attempt: updated.attempt,
        });
      }
    }
    return leased;
  };
  const leaseControls = async (
    jobId: string,
    now: number,
    limit: number,
    leaseId: string,
    leaseExpiresAt: number,
  ): Promise<BackgroundJobControlLease[]> => {
    identifier(jobId, "job id");
    identifier(leaseId, "lease id");
    exactTime(now, "lease time");
    exactLimit(limit);
    if (leaseExpiresAt <= now) throw new TypeError("lease expiry is invalid");
    const leased: BackgroundJobControlLease[] = [];
    for (const [key, candidate] of await backing.entries()) {
      if (leased.length >= limit || candidate.kind !== "control" || candidate.intent.jobId !== jobId) continue;
      if (
        candidate.state === "succeeded" ||
        candidate.nextAttemptAt > now ||
        (candidate.state === "leased" && (candidate.leaseExpiresAt ?? 0) > now)
      ) {
        continue;
      }
      const updated = await backing.update!(key, (current) => {
        if (
          current.kind !== "control" ||
          current.intent.jobId !== jobId ||
          current.state === "succeeded" ||
          current.nextAttemptAt > now ||
          (current.state === "leased" && (current.leaseExpiresAt ?? 0) > now)
        ) {
          return current;
        }
        return {
          ...current,
          state: "leased",
          attempt: current.attempt + 1,
          leaseId,
          leaseExpiresAt,
        };
      });
      if (updated?.kind === "control" && updated.state === "leased" && updated.leaseId === leaseId) {
        leased.push({ intent: clone(updated.intent), leaseId, leaseExpiresAt, attempt: updated.attempt });
      }
    }
    return leased;
  };
  const store: BackgroundJobReceiptStore & BackgroundJobCompletionReceiptStore = {
    durability: "durable" as const,
    admission: "durable_intent_outbox" as const,
    reconciliation: "automatic_idempotent" as const,
    controls: "durable_intent_outbox" as const,
    polling: "bounded_active_only" as const,
    terminalTransition: "after_delivery_outbox" as const,
    readiness: () => (ready ? Object.freeze({ ready: true as const }) : Object.freeze({ ready: false as const })),
    async enqueueAdmission(intent) {
      if (!ready) throw new Error("background job store is unavailable");
      identifier(intent.intentId, "intent id");
      const key = `admission:${intent.intentId}`;
      const value: AdmissionRecord = {
        kind: "admission",
        intent: clone(intent),
        state: "pending",
        attempt: 0,
        nextAttemptAt: intent.createdAt,
      };
      const inserted = await backing.insertIfAbsent!(key, value);
      const existing = inserted ? value : await backing.get(key);
      if (!existing) throw new Error("background job admission intent disappeared");
      if (existing.kind !== "admission" || digest(existing.intent) !== digest(intent)) {
        throw new Error("background job admission intent conflict");
      }
      return inserted ? "persisted" : "already_persisted";
    },
    leaseAdmissions,
    async completeAdmission(intentId, leaseId, admission, completedAt) {
      if (!ready) throw new Error("background job store is unavailable");
      identifier(intentId, "intent id");
      identifier(leaseId, "lease id");
      exactTime(completedAt, "completion time");
      const updated = await backing.update!(`admission:${intentId}`, (current) => {
        if (current.kind !== "admission") throw new Error("background job admission record is invalid");
        if (current.state === "succeeded" && current.receipt) return current;
        if (current.state !== "leased" || current.leaseId !== leaseId) {
          throw new Error("background job admission lease was lost");
        }
        const receipt = admissionReceipt(current.intent, admission);
        return {
          ...current,
          state: "succeeded",
          admission: clone(admission),
          receipt,
          completionState: "pending",
          completionAttempt: 0,
          completionFailureAttempt: 0,
          completionNextAttemptAt: completedAt,
          leaseId: undefined,
          leaseExpiresAt: undefined,
          attentionRequiredAt: undefined,
        };
      });
      if (updated?.kind !== "admission" || !updated.receipt) {
        throw new Error("background job admission record disappeared");
      }
      return Object.freeze(clone(updated.receipt));
    },
    async retryAdmission(intentId, leaseId, nextAttemptAt, requiresAttention) {
      exactTime(nextAttemptAt, "next attempt time");
      const updated = await backing.update!(`admission:${intentId}`, (current) => {
        if (current.kind === "admission" && current.state === "succeeded") return current;
        if (current.kind !== "admission" || current.state !== "leased" || current.leaseId !== leaseId) {
          throw new Error("background job admission lease was lost");
        }
        return {
          ...current,
          state: "pending",
          nextAttemptAt,
          ...(requiresAttention && !current.attentionRequiredAt ? { attentionRequiredAt: nextAttemptAt } : {}),
          leaseId: undefined,
          leaseExpiresAt: undefined,
        };
      });
      if (!updated) throw new Error("background job admission record disappeared");
    },
    async latestOwned(jobId, owner) {
      const receipts = (await backing.all()).flatMap((record) =>
        record.kind === "admission" && record.receipt && owned(record.receipt, jobId, owner) ? [record.receipt] : [],
      );
      receipts.sort((left, right) => right.createdAt - left.createdAt || right.intentId.localeCompare(left.intentId));
      return receipts[0] ? Object.freeze(clone(receipts[0])) : null;
    },
    async ownedRun(jobId, owner, authorityId, runId) {
      const receipt = (await backing.all()).find(
        (record) =>
          record.kind === "admission" &&
          !!record.receipt &&
          owned(record.receipt, jobId, owner) &&
          record.receipt.authorityId === authorityId &&
          record.receipt.runId === runId,
      );
      return receipt?.kind === "admission" && receipt.receipt ? Object.freeze(clone(receipt.receipt)) : null;
    },
    async enqueueControl(intent) {
      if (!ready) throw new Error("background job store is unavailable");
      identifier(intent.intentId, "intent id");
      const key = `control:${intent.intentId}`;
      const value: ControlRecord = {
        kind: "control",
        intent: clone(intent),
        state: "pending",
        attempt: 0,
        nextAttemptAt: intent.createdAt,
      };
      const inserted = await backing.insertIfAbsent!(key, value);
      const existing = inserted ? value : await backing.get(key);
      if (!existing) throw new Error("background job control intent disappeared");
      if (existing.kind !== "control" || digest(existing.intent) !== digest(intent)) {
        throw new Error("background job control intent conflict");
      }
      return inserted ? "persisted" : "already_persisted";
    },
    leaseControls,
    async completeControl(intentId, leaseId, completedAt) {
      exactTime(completedAt, "completion time");
      const updated = await backing.update!(`control:${intentId}`, (current) => {
        if (current.kind !== "control") throw new Error("background job control record is invalid");
        if (current.state === "succeeded") return current;
        if (current.state !== "leased" || current.leaseId !== leaseId) {
          throw new Error("background job control lease was lost");
        }
        return {
          ...current,
          state: "succeeded",
          completedAt,
          leaseId: undefined,
          leaseExpiresAt: undefined,
          attentionRequiredAt: undefined,
        };
      });
      if (!updated) throw new Error("background job control record disappeared");
    },
    async retryControl(intentId, leaseId, nextAttemptAt, requiresAttention) {
      exactTime(nextAttemptAt, "next attempt time");
      const updated = await backing.update!(`control:${intentId}`, (current) => {
        if (current.kind === "control" && current.state === "succeeded") return current;
        if (current.kind !== "control" || current.state !== "leased" || current.leaseId !== leaseId) {
          throw new Error("background job control lease was lost");
        }
        return {
          ...current,
          state: "pending",
          nextAttemptAt,
          ...(requiresAttention && !current.attentionRequiredAt ? { attentionRequiredAt: nextAttemptAt } : {}),
          leaseId: undefined,
          leaseExpiresAt: undefined,
        };
      });
      if (!updated) throw new Error("background job control record disappeared");
    },
    async leaseActive(jobId, now, limit, leaseId, leaseExpiresAt) {
      identifier(jobId, "job id");
      identifier(leaseId, "lease id");
      exactTime(now, "lease time");
      exactLimit(limit);
      if (leaseExpiresAt <= now) throw new TypeError("lease expiry is invalid");
      const leased: BackgroundJobCompletionLease[] = [];
      for (const [key, candidate] of await backing.entries()) {
        if (
          leased.length >= limit ||
          candidate.kind !== "admission" ||
          candidate.intent.jobId !== jobId ||
          !candidate.receipt ||
          candidate.state !== "succeeded" ||
          (candidate.completionState === "terminal" &&
            !!candidate.completionTerminalState &&
            !!candidate.completionDeliveryKey) ||
          (candidate.completionNextAttemptAt ?? 0) > now ||
          (candidate.completionState === "leased" && (candidate.completionLeaseExpiresAt ?? 0) > now)
        ) {
          continue;
        }
        const updated = await backing.update!(key, (current) => {
          if (
            current.kind !== "admission" ||
            !current.receipt ||
            current.state !== "succeeded" ||
            (current.completionState === "terminal" &&
              !!current.completionTerminalState &&
              !!current.completionDeliveryKey) ||
            (current.completionNextAttemptAt ?? 0) > now ||
            (current.completionState === "leased" && (current.completionLeaseExpiresAt ?? 0) > now)
          ) {
            return current;
          }
          return {
            ...current,
            completionState: "leased",
            completionAttempt: (current.completionAttempt ?? 0) + 1,
            completionLeaseId: leaseId,
            completionLeaseExpiresAt: leaseExpiresAt,
          };
        });
        if (
          updated?.kind === "admission" &&
          updated.receipt &&
          updated.completionState === "leased" &&
          updated.completionLeaseId === leaseId
        ) {
          leased.push({
            receipt: Object.freeze(clone(updated.receipt)),
            leaseId,
            leaseExpiresAt,
            attempt: updated.completionAttempt ?? 1,
            failureAttempt: updated.completionFailureAttempt ?? 0,
          });
        }
      }
      return leased;
    },
    async retry(receipt, leaseId, nextAttemptAt, requiresAttention, failed) {
      exactTime(nextAttemptAt, "next attempt time");
      const updated = await backing.update!(`admission:${receipt.intentId}`, (current) => {
        if (
          current.kind === "admission" &&
          current.completionState === "terminal" &&
          current.completionTerminalState &&
          current.completionDeliveryKey
        )
          return current;
        if (
          current.kind !== "admission" ||
          current.completionState !== "leased" ||
          current.completionLeaseId !== leaseId
        ) {
          throw new Error("background job completion lease was lost");
        }
        let attention: Pick<AdmissionRecord, "completionAttentionRequiredAt"> | Record<string, never> = {};
        if (requiresAttention && !current.completionAttentionRequiredAt) {
          attention = { completionAttentionRequiredAt: nextAttemptAt };
        } else if (!failed) {
          attention = { completionAttentionRequiredAt: undefined };
        }
        return {
          ...current,
          completionState: "pending",
          completionFailureAttempt: failed ? (current.completionFailureAttempt ?? 0) + 1 : 0,
          completionNextAttemptAt: nextAttemptAt,
          ...attention,
          completionLeaseId: undefined,
          completionLeaseExpiresAt: undefined,
        };
      });
      if (!updated) throw new Error("background job completion record disappeared");
    },
    async manualAttention() {
      const result: BackgroundJobManualAttention[] = [];
      for (const [key, record] of await backing.entries()) {
        if (record.attentionRequiredAt) {
          result.push({
            kind: record.kind,
            key,
            jobId: record.intent.jobId,
            attempt: record.attempt,
            requiredAt: record.attentionRequiredAt,
          });
        }
        if (record.kind === "admission" && record.completionAttentionRequiredAt) {
          result.push({
            kind: "completion",
            key,
            jobId: record.intent.jobId,
            attempt: record.completionFailureAttempt ?? 0,
            requiredAt: record.completionAttentionRequiredAt,
          });
        }
      }
      return Object.freeze(result.map((entry) => Object.freeze(entry)));
    },
    async terminal(receipt, leaseId, state, deliveryKey) {
      const updated = await backing.update!(`admission:${receipt.intentId}`, (current) => {
        if (current.kind !== "admission") {
          throw new Error("background job completion record is invalid");
        }
        if (current.completionState === "terminal") {
          if (current.completionTerminalState === state && current.completionDeliveryKey === deliveryKey)
            return current;
          throw new Error("background job completion terminal state changed");
        }
        if (current.completionState !== "leased" || current.completionLeaseId !== leaseId) {
          throw new Error("background job completion lease was lost");
        }
        return {
          ...current,
          completionState: "terminal",
          completionTerminalState: state,
          completionDeliveryKey: deliveryKey,
          completionLeaseId: undefined,
          completionLeaseExpiresAt: undefined,
          completionAttentionRequiredAt: undefined,
        };
      });
      if (!updated) throw new Error("background job completion record disappeared");
    },
  };
  return Object.freeze(store);
}

export function createDurableBackgroundJobDeliveryOutbox(
  backing: DurableMap<BackgroundJobDeliveryRecord>,
  durable: boolean,
): BackgroundJobDeliveryOutbox {
  const ready = durable && typeof backing.update === "function" && typeof backing.insertIfAbsent === "function";
  const outbox: BackgroundJobDeliveryOutbox = {
    durability: "durable" as const,
    admission: "persist_before_send" as const,
    reconciliation: "automatic_idempotent_delivery" as const,
    transport: "slack_first_party_render_only" as const,
    rawFallback: "forbidden" as const,
    readiness: () => (ready ? Object.freeze({ ready: true as const }) : Object.freeze({ ready: false as const })),
    async enqueue(intent) {
      if (!ready) throw new Error("background job delivery outbox is unavailable");
      identifier(intent.deliveryKey, "delivery key");
      const value: DeliveryRecord = {
        intent: clone(intent),
        state: "pending",
        attempt: 0,
        nextAttemptAt: intent.createdAt,
      };
      const inserted = await backing.insertIfAbsent!(intent.deliveryKey, value);
      const existing = inserted ? value : await backing.get(intent.deliveryKey);
      if (!existing) throw new Error("background job delivery intent disappeared");
      if (digest(existing.intent) !== digest(intent)) throw new Error("background job delivery intent conflict");
      return inserted ? "persisted" : "already_persisted";
    },
    async lease(now, limit, leaseId, leaseExpiresAt) {
      exactTime(now, "lease time");
      exactLimit(limit);
      identifier(leaseId, "lease id");
      if (leaseExpiresAt <= now) throw new TypeError("lease expiry is invalid");
      const leased: Array<{ intent: BackgroundJobDeliveryIntent; leaseId: string; attempt: number }> = [];
      for (const [key, candidate] of await backing.entries()) {
        if (
          leased.length >= limit ||
          candidate.state === "sent" ||
          candidate.nextAttemptAt > now ||
          (candidate.state === "leased" && (candidate.leaseExpiresAt ?? 0) > now)
        ) {
          continue;
        }
        const updated = await backing.update!(key, (current) => {
          if (
            current.state === "sent" ||
            current.nextAttemptAt > now ||
            (current.state === "leased" && (current.leaseExpiresAt ?? 0) > now)
          ) {
            return current;
          }
          return {
            ...current,
            state: "leased",
            attempt: current.attempt + 1,
            leaseId,
            leaseExpiresAt,
          };
        });
        if (updated?.state === "leased" && updated.leaseId === leaseId) {
          leased.push({ intent: Object.freeze(clone(updated.intent)), leaseId, attempt: updated.attempt });
        }
      }
      return leased;
    },
    async sent(deliveryKey, leaseId, sentAt) {
      exactTime(sentAt, "sent time");
      const updated = await backing.update!(deliveryKey, (current) => {
        if (current.state === "sent") return current;
        if (current.state !== "leased" || current.leaseId !== leaseId) {
          throw new Error("background job delivery lease was lost");
        }
        return {
          ...current,
          state: "sent",
          sentAt,
          leaseId: undefined,
          leaseExpiresAt: undefined,
          attentionRequiredAt: undefined,
        };
      });
      if (!updated) throw new Error("background job delivery record disappeared");
    },
    async retry(deliveryKey, leaseId, nextAttemptAt, requiresAttention) {
      exactTime(nextAttemptAt, "next attempt time");
      const updated = await backing.update!(deliveryKey, (current) => {
        if (current.state === "sent") return current;
        if (current.state !== "leased" || current.leaseId !== leaseId) {
          throw new Error("background job delivery lease was lost");
        }
        return {
          ...current,
          state: "pending",
          nextAttemptAt,
          ...(requiresAttention && !current.attentionRequiredAt ? { attentionRequiredAt: nextAttemptAt } : {}),
          leaseId: undefined,
          leaseExpiresAt: undefined,
        };
      });
      if (!updated) throw new Error("background job delivery record disappeared");
    },
    async manualAttention() {
      const result: BackgroundJobManualAttention[] = [];
      for (const [key, record] of await backing.entries()) {
        if (!record.attentionRequiredAt) continue;
        result.push({
          kind: "delivery",
          key,
          jobId: record.intent.jobId,
          attempt: record.attempt,
          requiredAt: record.attentionRequiredAt,
        });
      }
      return Object.freeze(result.map((entry) => Object.freeze(entry)));
    },
  };
  return Object.freeze(outbox);
}
