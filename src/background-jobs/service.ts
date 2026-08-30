import type {
  BackgroundJobAdapter,
  BackgroundJobAudienceProfile,
  BackgroundJobClient,
  BackgroundJobDefinition,
  BackgroundJobOutcome,
  BackgroundJobOwner,
  BackgroundJobReceipt,
  BackgroundJobReceiptStore,
  BackgroundJobService,
  BackgroundJobTurnBinding,
  BoundBackgroundJobTools,
} from "./types.ts";
import { identifier, validateBackgroundJobProfile, validateDefinition, validateSlackTimestamp } from "./validation.ts";

interface BackgroundJobServiceDependencies<TInput, TStatus, TCancellation> {
  definition: Readonly<BackgroundJobDefinition>;
  profile: Readonly<BackgroundJobAudienceProfile>;
  adapter: BackgroundJobAdapter<TInput, TStatus, TCancellation>;
  receipts: BackgroundJobReceiptStore;
  client: BackgroundJobClient<TStatus, TCancellation>;
  authorityReady: () => boolean;
  now?: () => number;
}

function unavailable(): BackgroundJobOutcome {
  return Object.freeze({
    ok: false,
    state: "unavailable",
    message: "The background job service is unavailable right now.",
  });
}

function invalid(): BackgroundJobOutcome {
  return Object.freeze({ ok: false, state: "invalid", message: "The background job request is invalid." });
}

function owner(profile: Readonly<BackgroundJobAudienceProfile>, threadTs: string): Readonly<BackgroundJobOwner> {
  return Object.freeze({ ...profile, threadTs });
}

function receiptOwned(
  receipt: Readonly<BackgroundJobReceipt>,
  expected: Readonly<BackgroundJobOwner>,
  jobId: string,
): boolean {
  return (
    receipt.jobId === jobId &&
    receipt.organizationId === expected.organizationId &&
    receipt.actorPrincipalId === expected.actorPrincipalId &&
    receipt.actorSlackId === expected.actorSlackId &&
    receipt.audienceScopeId === expected.audienceScopeId &&
    receipt.slackTeamId === expected.slackTeamId &&
    receipt.channelId === expected.channelId &&
    receipt.threadTs === expected.threadTs
  );
}

function bindable(profile: Readonly<BackgroundJobAudienceProfile>, turn: Readonly<BackgroundJobTurnBinding>): boolean {
  const slack = turn.verifiedSlack;
  if (
    !slack ||
    !slack.liveHuman ||
    turn.surface !== "slack" ||
    turn.originKind !== "human" ||
    turn.actorType !== "internal" ||
    turn.actorId !== profile.actorPrincipalId ||
    turn.conversationKind !== "dm" ||
    turn.conversationAudienceIds.length !== 1 ||
    turn.conversationAudienceIds[0] !== turn.actorId ||
    slack.teamId !== profile.slackTeamId ||
    slack.userId !== profile.actorSlackId ||
    slack.channelId !== profile.channelId ||
    slack.messageTs !== turn.originMessageTs
  )
    return false;
  try {
    validateSlackTimestamp(slack.messageTs, "messageTs");
    validateSlackTimestamp(slack.threadTs, "threadTs");
  } catch {
    return false;
  }
  const refs = slack.threaded
    ? [`dm:${slack.channelId}:${slack.threadTs}`]
    : [`dm:${slack.channelId}`, `dm:${slack.channelId}:${slack.messageTs}`];
  return (
    refs.includes(turn.conversationThreadRef) &&
    (slack.threaded ? slack.threadTs !== slack.messageTs : slack.threadTs === slack.messageTs)
  );
}

export function createBackgroundJobService<TInput, TStatus, TCancellation>(
  dependencies: Readonly<BackgroundJobServiceDependencies<TInput, TStatus, TCancellation>>,
): BackgroundJobService {
  validateDefinition(dependencies.definition);
  validateBackgroundJobProfile(dependencies.profile);
  const now = dependencies.now ?? Date.now;
  const readiness = (): ReturnType<BackgroundJobService["readiness"]> => {
    try {
      const adapter = dependencies.adapter.readiness();
      if (!adapter.ready) return Object.freeze({ ready: false, reason: adapter.reason });
    } catch {
      return Object.freeze({ ready: false, reason: "background_job_adapter_unavailable" });
    }
    try {
      if (dependencies.receipts.durability !== "durable" || !dependencies.receipts.readiness().ready) {
        return Object.freeze({ ready: false, reason: "background_job_receipt_store_unavailable" });
      }
    } catch {
      return Object.freeze({ ready: false, reason: "background_job_receipt_store_unavailable" });
    }
    try {
      if (!dependencies.authorityReady())
        return Object.freeze({ ready: false, reason: "background_job_authority_unavailable" });
    } catch {
      return Object.freeze({ ready: false, reason: "background_job_authority_unavailable" });
    }
    return Object.freeze({ ready: true });
  };
  return Object.freeze({
    readiness,
    bind(turn: Readonly<BackgroundJobTurnBinding>): BoundBackgroundJobTools | undefined {
      if (!readiness().ready || !bindable(dependencies.profile, turn)) return undefined;
      const slack = turn.verifiedSlack!;
      const expectedOwner = owner(dependencies.profile, slack.threadTs);
      const owned = async () => {
        const receipt = await dependencies.receipts.latestOwned(dependencies.definition.id, expectedOwner);
        return receipt && receiptOwned(receipt, expectedOwner, dependencies.definition.id) ? receipt : null;
      };
      return Object.freeze({
        async start(raw: unknown): Promise<BackgroundJobOutcome> {
          let input: TInput;
          try {
            input = dependencies.adapter.parseInput(raw);
          } catch {
            return invalid();
          }
          try {
            const compiled = await dependencies.adapter.prepare(
              input,
              Object.freeze({
                jobId: dependencies.definition.id,
                ...expectedOwner,
              }),
            );
            if (
              !(compiled.bodyBytes instanceof Uint8Array) ||
              compiled.bodyBytes.byteLength < 2 ||
              compiled.bodyBytes.byteLength > dependencies.definition.start.maxRequestBytes
            ) {
              return unavailable();
            }
            identifier(compiled.idempotencyKey, "idempotency key");
            const admission = await dependencies.client.start(
              compiled.bodyBytes,
              slack.threadTs,
              compiled.idempotencyKey,
            );
            identifier(admission.authorityId, "authority id");
            identifier(admission.runId, "run id");
            await dependencies.receipts.save(
              Object.freeze({
                jobId: dependencies.definition.id,
                authorityId: admission.authorityId,
                runId: admission.runId,
                ...expectedOwner,
                idempotencyKey: compiled.idempotencyKey,
                createdAt: now(),
              }),
            );
            return dependencies.adapter.admissionOutcome(admission);
          } catch {
            return unavailable();
          }
        },
        async status(): Promise<BackgroundJobOutcome> {
          try {
            const receipt = await owned();
            if (!receipt)
              return Object.freeze({
                ok: false,
                state: "not_found",
                message: "No background job is bound to this thread.",
              });
            return dependencies.adapter.statusOutcome(await dependencies.client.status(receipt), receipt);
          } catch {
            return unavailable();
          }
        },
        async cancel(): Promise<BackgroundJobOutcome> {
          try {
            const receipt = await owned();
            if (!receipt)
              return Object.freeze({
                ok: false,
                state: "not_found",
                message: "No background job is bound to this thread.",
              });
            return dependencies.adapter.cancellationOutcome(await dependencies.client.cancel(receipt), receipt);
          } catch {
            return unavailable();
          }
        },
      });
    },
  });
}
