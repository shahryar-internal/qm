import { createHash, randomUUID } from "node:crypto";
import { canonicalJson } from "../cron/schedule-authority.ts";
import type { RetiredBackgroundJob, BackgroundJobRetirementStore } from "../deployment/deployment-layer-store.ts";
import type { DurableMap } from "../persistence/durable-map.ts";
import { backgroundJobApprovalDigest } from "./service.ts";
import type {
  BackgroundJobApprovalGrant,
  BackgroundJobApprovalStore,
  BackgroundJobDeploymentProfile,
} from "./types.ts";
import { identifier, validateSlackTimestamp } from "./validation.ts";

interface UsedApproval {
  reservationId: string;
  approvalId: string;
  approvalKey: string;
  actionTs: string;
  digest: string;
  expiresAt: number;
}

interface BackgroundJobApprovalJobRecord {
  kind: "job";
  jobId: string;
  used: UsedApproval[];
  retirement?: RetiredBackgroundJob;
}

interface BackgroundJobApprovalReplayRecord {
  kind: "replay";
  jobId: string;
  used: [];
  approvalId: string;
  actionTs: string;
  digest: string;
  retirement?: undefined;
}

export type BackgroundJobApprovalLedgerRecord = BackgroundJobApprovalJobRecord | BackgroundJobApprovalReplayRecord;

function hash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function slackTime(value: string): number {
  validateSlackTimestamp(value, "actionTs");
  const milliseconds = Number(value.replace(".", "").slice(0, -3));
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 1) throw new TypeError("actionTs is invalid");
  return milliseconds;
}

function replayKeys(jobId: string, approvalId: string, actionTs: string): readonly [string, string] {
  return [`approval-id:${hash({ approvalId, jobId })}`, `approval-action:${hash({ actionTs, jobId })}`];
}

function replayRecord(jobId: string, used: Readonly<UsedApproval>): BackgroundJobApprovalReplayRecord {
  return {
    kind: "replay",
    jobId,
    used: [],
    approvalId: used.approvalId,
    actionTs: used.actionTs,
    digest: used.digest,
  };
}

export function createDurableBackgroundJobApprovalLedger(options: {
  backing: DurableMap<BackgroundJobApprovalLedgerRecord>;
  durable: boolean;
  now?: () => number;
  randomId?: () => string;
  terminalAndExpired: (profile: Readonly<BackgroundJobDeploymentProfile>, now: number) => Promise<boolean>;
}): BackgroundJobApprovalStore & BackgroundJobRetirementStore {
  const now = options.now ?? Date.now;
  const randomId = options.randomId ?? randomUUID;
  const ready = options.durable && typeof options.backing.update === "function";
  const ensure = async (jobId: string): Promise<BackgroundJobApprovalJobRecord> => {
    const existing = await options.backing.putIfAbsent(jobId, { kind: "job", jobId, used: [] });
    if (existing.kind !== "job" || existing.jobId !== jobId || !Array.isArray(existing.used)) {
      throw new Error("background job approval ledger is invalid");
    }
    return existing;
  };
  const markerMatches = (value: BackgroundJobApprovalLedgerRecord | null, used: Readonly<UsedApproval>): boolean =>
    value?.kind === "replay" &&
    value.jobId !== "" &&
    value.approvalId === used.approvalId &&
    value.actionTs === used.actionTs &&
    value.digest === used.digest;
  const persistReplay = async (jobId: string, used: Readonly<UsedApproval>): Promise<void> => {
    const marker = replayRecord(jobId, used);
    for (const key of replayKeys(jobId, used.approvalId, used.actionTs)) {
      const stored = await options.backing.putIfAbsent(key, marker);
      if (!markerMatches(stored, used) || stored.jobId !== jobId) {
        throw new Error("background job approval replay fence conflicted");
      }
    }
  };
  const compact = async (jobId: string, at: number): Promise<void> => {
    const current = await ensure(jobId);
    const expired = current.used.filter((entry) => entry.expiresAt <= at);
    for (const entry of expired) await persistReplay(jobId, entry);
    if (!expired.length) return;
    const ids = new Set(expired.map((entry) => entry.reservationId));
    await options.backing.update!(jobId, (value) =>
      value.kind === "job" ? { ...value, used: value.used.filter((entry) => !ids.has(entry.reservationId)) } : value,
    );
  };
  const replayed = async (jobId: string, approvalId: string, actionTs: string): Promise<boolean> => {
    for (const key of replayKeys(jobId, approvalId, actionTs)) {
      if (await options.backing.get(key)) return true;
    }
    return false;
  };
  const ledger: BackgroundJobApprovalStore & BackgroundJobRetirementStore = {
    durability: "durable" as const,
    consumption: "one_time" as const,
    grants: "verified_immutable" as const,
    retirementFence: "atomic_permanent" as const,
    receiptCoverage: "all_owned" as const,
    approvalCoverage: "all_unused" as const,
    retiredIdLedger: "permanent" as const,
    approvalIssuanceFence: "atomic" as const,
    readiness: () => (ready ? Object.freeze({ ready: true as const }) : Object.freeze({ ready: false as const })),
    async consume(authority, expected) {
      if (!ready) return null;
      try {
        identifier(authority.receiptId, "approval id");
        identifier(authority.approvalKey, "approval key");
        validateSlackTimestamp(authority.actionTs, "actionTs");
        if (
          authority.approvalKey !== expected.approvalKey ||
          authority.actionTs !== expected.actionTs ||
          authority.slack.messageTs !== expected.messageTs ||
          authority.slack.threadTs !== expected.threadTs ||
          !authority.slack.liveHuman
        ) {
          return null;
        }
        const at = now();
        const actedAt = slackTime(authority.actionTs);
        if (actedAt > at + 30_000 || at - actedAt > 5 * 60_000) return null;
        await compact(expected.jobId, at);
        if (await replayed(expected.jobId, authority.receiptId, authority.actionTs)) return null;
        const unsigned = {
          approvalId: authority.receiptId,
          approvalKey: authority.approvalKey,
          actionTs: authority.actionTs,
          effect: expected.effect,
          jobId: expected.jobId,
          organizationId: expected.organizationId,
          actorPrincipalId: expected.actorPrincipalId,
          actorSlackId: expected.actorSlackId,
          audienceScopeId: expected.audienceScopeId,
          slackTeamId: expected.slackTeamId,
          channelId: expected.channelId,
          conversationThreadRef: expected.conversationThreadRef,
          threadTs: expected.threadTs,
          messageTs: expected.messageTs,
          descriptorSha256: expected.descriptorSha256,
          profileSha256: expected.profileSha256,
          schemaSha256: expected.schemaSha256,
          payloadSha256: expected.payloadSha256,
          idempotencyKey: expected.idempotencyKey,
          issuedAt: at,
          expiresAt: Math.min(expected.maximumExpiresAt, at + 5 * 60_000),
        } as const;
        const issued: BackgroundJobApprovalGrant = Object.freeze({
          ...unsigned,
          digest: backgroundJobApprovalDigest(unsigned),
        });
        const reservation: UsedApproval = {
          reservationId: `background-job-approval-reservation:${randomId()}`,
          approvalId: authority.receiptId,
          approvalKey: authority.approvalKey,
          actionTs: authority.actionTs,
          digest: issued.digest,
          expiresAt: issued.expiresAt,
        };
        const updated = await options.backing.update!(expected.jobId, (current) => {
          if (
            current.kind !== "job" ||
            current.retirement ||
            current.used.some(
              (entry) => entry.approvalId === authority.receiptId || entry.actionTs === authority.actionTs,
            )
          )
            return current;
          return { ...current, used: [...current.used, reservation] };
        });
        if (updated?.kind !== "job" || !updated.used.some((entry) => entry.reservationId === reservation.reservationId))
          return null;
        await persistReplay(expected.jobId, reservation);
        await options.backing.update!(expected.jobId, (current) =>
          current.kind === "job"
            ? {
                ...current,
                used: current.used.filter((entry) => entry.reservationId !== reservation.reservationId),
              }
            : current,
        );
        return issued;
      } catch {
        return null;
      }
    },
    async retireAndFenceApprovalIssuance(profile) {
      if (!ready) throw new Error("background job approval ledger is unavailable");
      await ensure(profile.definition.id);
      const at = now();
      const fenced = await options.backing.update!(profile.definition.id, (current) => {
        if (current.kind !== "job") throw new Error("background job approval ledger is invalid");
        if (current.retirement) return current;
        const retiredAt = at;
        const approvalFenceDigest = hash({
          descriptorSha256: profile.binding.descriptorSha256,
          jobId: profile.definition.id,
          retiredAt,
        });
        return {
          ...current,
          retirement: {
            jobId: profile.definition.id,
            descriptorSha256: profile.binding.descriptorSha256,
            approvalFenceDigest,
            retiredAt,
            terminalAndExpired: false,
          },
        };
      });
      if (fenced?.kind !== "job" || !fenced.retirement) {
        throw new Error("background job retirement fence failed");
      }
      if (fenced.retirement.descriptorSha256 !== profile.binding.descriptorSha256) {
        throw new Error("background job retirement descriptor changed");
      }
      const checkedAt = now();
      await compact(profile.definition.id, checkedAt);
      const terminalAndExpired = await options.terminalAndExpired(profile, checkedAt);
      const updated = terminalAndExpired
        ? await options.backing.update!(profile.definition.id, (current) =>
            current.kind === "job" &&
            current.retirement &&
            !current.retirement.terminalAndExpired &&
            current.used.every((entry) => entry.expiresAt <= checkedAt)
              ? { ...current, retirement: { ...current.retirement, terminalAndExpired: true } }
              : current,
          )
        : fenced;
      if (updated?.kind !== "job" || !updated.retirement) {
        throw new Error("background job retirement fence disappeared");
      }
      return Object.freeze(structuredClone(updated.retirement));
    },
  };
  return Object.freeze(ledger);
}
