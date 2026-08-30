import { createHash } from "node:crypto";
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
  approvalId: string;
  approvalKey: string;
  actionTs: string;
  digest: string;
  expiresAt: number;
}

export interface BackgroundJobApprovalLedgerRecord {
  jobId: string;
  used: UsedApproval[];
  retirement?: RetiredBackgroundJob;
}

function hash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function slackTime(value: string): number {
  validateSlackTimestamp(value, "actionTs");
  const milliseconds = Number(value.replace(".", "").slice(0, -3));
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 1) throw new TypeError("actionTs is invalid");
  return milliseconds;
}

export function createDurableBackgroundJobApprovalLedger(options: {
  backing: DurableMap<BackgroundJobApprovalLedgerRecord>;
  durable: boolean;
  now?: () => number;
  terminalAndExpired: (profile: Readonly<BackgroundJobDeploymentProfile>, now: number) => Promise<boolean>;
}): BackgroundJobApprovalStore & BackgroundJobRetirementStore {
  const now = options.now ?? Date.now;
  const ready = options.durable && typeof options.backing.update === "function";
  const ensure = async (jobId: string): Promise<void> => {
    const existing = await options.backing.putIfAbsent(jobId, { jobId, used: [] });
    if (existing.jobId !== jobId || !Array.isArray(existing.used)) {
      throw new Error("background job approval ledger is invalid");
    }
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
        await ensure(expected.jobId);
        let issued: BackgroundJobApprovalGrant | null = null;
        const updated = await options.backing.update!(expected.jobId, (current) => {
          if (current.jobId !== expected.jobId || current.retirement || current.used.length >= 10_000) return current;
          if (
            current.used.some(
              (entry) => entry.approvalId === authority.receiptId || entry.actionTs === authority.actionTs,
            )
          )
            return current;
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
          issued = Object.freeze({ ...unsigned, digest: backgroundJobApprovalDigest(unsigned) });
          return {
            ...current,
            used: [
              ...current.used,
              {
                approvalId: authority.receiptId,
                approvalKey: authority.approvalKey,
                actionTs: authority.actionTs,
                digest: issued.digest,
                expiresAt: issued.expiresAt,
              },
            ],
          };
        });
        if (!updated || !issued) return null;
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
      if (!fenced?.retirement) throw new Error("background job retirement fence failed");
      if (fenced.retirement.descriptorSha256 !== profile.binding.descriptorSha256) {
        throw new Error("background job retirement descriptor changed");
      }
      const checkedAt = now();
      const terminalAndExpired = await options.terminalAndExpired(profile, checkedAt);
      const updated = terminalAndExpired
        ? await options.backing.update!(profile.definition.id, (current) =>
            current.retirement &&
            !current.retirement.terminalAndExpired &&
            current.used.every((entry) => entry.expiresAt <= checkedAt)
              ? { ...current, retirement: { ...current.retirement, terminalAndExpired: true } }
              : current,
          )
        : fenced;
      if (!updated?.retirement) throw new Error("background job retirement fence disappeared");
      return Object.freeze(structuredClone(updated.retirement));
    },
  };
  return Object.freeze(ledger);
}
