import { createHash } from "node:crypto";
import { canonicalJson } from "../cron/schedule-authority.ts";
import { validateBackgroundJobSchemaValue } from "./deployment-profile.ts";
import type {
  BackgroundJobAdapter,
  BackgroundJobAdmissionIntent,
  BackgroundJobApprovalExpectation,
  BackgroundJobApprovalStore,
  BackgroundJobClient,
  BackgroundJobDeploymentProfile,
  BackgroundJobInvocationAuthority,
  BackgroundJobOutcome,
  BackgroundJobOwner,
  BackgroundJobProfileService,
  BackgroundJobReceipt,
  BackgroundJobReceiptStore,
  BackgroundJobService,
  BackgroundJobStatusView,
  BackgroundJobTurnBinding,
  BoundBackgroundJobTools,
  WorkflowCardEnvelope,
} from "./types.ts";
import {
  identifier,
  parseStrictHttpsUrl,
  validateBackgroundJobProfile,
  validateContractBinding,
  validateDefinition,
  validateSlackTimestamp,
} from "./validation.ts";

interface BackgroundJobProfileServiceDependencies<TInput, TStatus, TCancellation> {
  deployment: Readonly<BackgroundJobDeploymentProfile>;
  adapter: BackgroundJobAdapter<TInput, TStatus, TCancellation>;
  receipts: BackgroundJobReceiptStore;
  approvals: BackgroundJobApprovalStore;
  client: BackgroundJobClient<TStatus, TCancellation>;
  authorityReady: () => boolean;
  active: () => boolean;
  now?: () => number;
}

interface BackgroundJobRegistryDependencies {
  profiles: () => readonly Readonly<BackgroundJobDeploymentProfile>[];
  resolve(profile: Readonly<BackgroundJobDeploymentProfile>): BackgroundJobProfileService | undefined;
}

const APPROVAL_LIFETIME_MS = 5 * 60 * 1000;
const SHA256 = /^[a-f0-9]{64}$/;
const STATES = new Set(["queued", "running", "complete", "failed", "cancelled"]);

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

function denied(): BackgroundJobOutcome {
  return Object.freeze({ ok: false, state: "denied", message: "A fresh approval is required for this action." });
}

function owner(profile: Readonly<BackgroundJobDeploymentProfile>, threadTs: string): Readonly<BackgroundJobOwner> {
  return Object.freeze({ ...profile.profile, threadTs });
}

function hash(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function validateCompiledBody(profile: Readonly<BackgroundJobDeploymentProfile>, bytes: Uint8Array): void {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new TypeError("compiled background job payload is invalid");
  }
  if (!Buffer.from(canonicalJson(value), "utf8").equals(Buffer.from(bytes))) {
    throw new TypeError("compiled background job payload is not canonical");
  }
  validateBackgroundJobSchemaValue(profile.schema.json, value);
}

function receiptOwned(
  receipt: Readonly<BackgroundJobReceipt>,
  expected: Readonly<BackgroundJobOwner>,
  profile: Readonly<BackgroundJobDeploymentProfile>,
): boolean {
  if (
    !receipt ||
    typeof receipt !== "object" ||
    Array.isArray(receipt) ||
    Object.keys(receipt).sort().join(",") !==
      "actorPrincipalId,actorSlackId,audienceScopeId,authorityId,channelId,createdAt,descriptorSha256,idempotencyKey,jobId,messageTs,organizationId,payloadSha256,profileSha256,runId,schemaSha256,slackTeamId,threadTs" ||
    !identifierOrFalse(receipt.authorityId) ||
    !identifierOrFalse(receipt.runId) ||
    !identifierOrFalse(receipt.idempotencyKey) ||
    !Number.isSafeInteger(receipt.createdAt) ||
    receipt.createdAt < 1
  ) {
    return false;
  }
  try {
    validateSlackTimestamp(receipt.messageTs, "messageTs");
    validateSlackTimestamp(receipt.threadTs, "threadTs");
  } catch {
    return false;
  }
  return (
    receipt.jobId === profile.definition.id &&
    receipt.organizationId === expected.organizationId &&
    receipt.actorPrincipalId === expected.actorPrincipalId &&
    receipt.actorSlackId === expected.actorSlackId &&
    receipt.audienceScopeId === expected.audienceScopeId &&
    receipt.slackTeamId === expected.slackTeamId &&
    receipt.channelId === expected.channelId &&
    receipt.threadTs === expected.threadTs &&
    receipt.descriptorSha256 === profile.binding.descriptorSha256 &&
    receipt.profileSha256 === profile.binding.profileSha256 &&
    receipt.schemaSha256 === profile.binding.schemaSha256 &&
    SHA256.test(receipt.payloadSha256)
  );
}

function admissionIntentMatches(
  actual: Readonly<BackgroundJobAdmissionIntent>,
  expected: Readonly<BackgroundJobAdmissionIntent>,
): boolean {
  return (
    actual &&
    typeof actual === "object" &&
    !Array.isArray(actual) &&
    Object.keys(actual).sort().join(",") ===
      "actorPrincipalId,actorSlackId,audienceScopeId,bodyBytes,channelId,createdAt,descriptorSha256,idempotencyKey,jobId,messageTs,organizationId,payloadSha256,profileSha256,schemaSha256,slackTeamId,threadTs" &&
    actual.bodyBytes instanceof Uint8Array &&
    actual.jobId === expected.jobId &&
    actual.organizationId === expected.organizationId &&
    actual.actorPrincipalId === expected.actorPrincipalId &&
    actual.actorSlackId === expected.actorSlackId &&
    actual.audienceScopeId === expected.audienceScopeId &&
    actual.slackTeamId === expected.slackTeamId &&
    actual.channelId === expected.channelId &&
    actual.threadTs === expected.threadTs &&
    actual.messageTs === expected.messageTs &&
    actual.descriptorSha256 === expected.descriptorSha256 &&
    actual.profileSha256 === expected.profileSha256 &&
    actual.schemaSha256 === expected.schemaSha256 &&
    actual.payloadSha256 === expected.payloadSha256 &&
    actual.idempotencyKey === expected.idempotencyKey &&
    actual.createdAt === expected.createdAt &&
    hash(actual.bodyBytes) === expected.payloadSha256
  );
}

function bindable(
  profile: Readonly<BackgroundJobDeploymentProfile>,
  turn: Readonly<BackgroundJobTurnBinding>,
): boolean {
  const slack = turn.verifiedSlack;
  if (
    !slack ||
    !slack.liveHuman ||
    turn.surface !== "slack" ||
    turn.originKind !== "human" ||
    turn.actorType !== "internal" ||
    turn.actorId !== profile.profile.actorPrincipalId ||
    turn.conversationKind !== "dm" ||
    turn.conversationAudienceIds.length !== 1 ||
    turn.conversationAudienceIds[0] !== turn.actorId ||
    slack.teamId !== profile.profile.slackTeamId ||
    slack.userId !== profile.profile.actorSlackId ||
    slack.channelId !== profile.profile.channelId ||
    slack.messageTs !== turn.originMessageTs
  ) {
    return false;
  }
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

function invocationMatches(
  profile: Readonly<BackgroundJobDeploymentProfile>,
  expectedOwner: Readonly<BackgroundJobOwner>,
  authority: Readonly<BackgroundJobInvocationAuthority> | undefined,
): authority is Readonly<BackgroundJobInvocationAuthority> {
  if (!authority || !identifierOrFalse(authority.receiptId)) return false;
  const slack = authority.slack;
  try {
    validateSlackTimestamp(slack.messageTs, "messageTs");
    validateSlackTimestamp(slack.threadTs, "threadTs");
  } catch {
    return false;
  }
  return (
    slack.liveHuman &&
    slack.teamId === profile.profile.slackTeamId &&
    slack.userId === profile.profile.actorSlackId &&
    slack.channelId === profile.profile.channelId &&
    slack.threadTs === expectedOwner.threadTs &&
    (slack.threaded ? slack.threadTs !== slack.messageTs : slack.threadTs === slack.messageTs)
  );
}

function identifierOrFalse(value: unknown): boolean {
  try {
    identifier(value, "approval receipt id");
    return true;
  } catch {
    return false;
  }
}

function expectation(
  profile: Readonly<BackgroundJobDeploymentProfile>,
  expectedOwner: Readonly<BackgroundJobOwner>,
  authority: Readonly<BackgroundJobInvocationAuthority>,
  effect: BackgroundJobApprovalExpectation["effect"],
  payloadSha256: string,
  idempotencyKey: string,
  now: number,
): Readonly<BackgroundJobApprovalExpectation> {
  return Object.freeze({
    effect,
    jobId: profile.definition.id,
    ...expectedOwner,
    messageTs: authority.slack.messageTs,
    ...profile.binding,
    payloadSha256,
    idempotencyKey,
    now,
    maximumExpiresAt: now + APPROVAL_LIFETIME_MS,
  });
}

function validateStatusView(value: Readonly<BackgroundJobStatusView>): BackgroundJobStatusView {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("status view is invalid");
  const keys = Object.keys(value);
  if (keys.some((key) => key !== "state" && key !== "artifacts") || !STATES.has(value.state)) {
    throw new TypeError("status view is invalid");
  }
  if (value.artifacts !== undefined && !Array.isArray(value.artifacts)) throw new TypeError("status view is invalid");
  return value;
}

function resultCard(
  profile: Readonly<BackgroundJobDeploymentProfile>,
  receipt: Readonly<BackgroundJobReceipt>,
  view: Readonly<BackgroundJobStatusView>,
): Readonly<WorkflowCardEnvelope> | undefined {
  if (view.state !== "complete") {
    if (view.artifacts !== undefined) throw new TypeError("result artifacts are invalid");
    return undefined;
  }
  if (!view.artifacts || view.artifacts.length !== profile.artifacts.length) {
    throw new TypeError("result artifacts are invalid");
  }
  const byKind = new Map<string, { href: string; sha256: string }>();
  for (const artifact of view.artifacts) {
    if (
      !artifact ||
      typeof artifact !== "object" ||
      Array.isArray(artifact) ||
      Object.keys(artifact).sort().join(",") !== "href,kind,sha256" ||
      typeof artifact.kind !== "string" ||
      typeof artifact.href !== "string" ||
      typeof artifact.sha256 !== "string" ||
      !SHA256.test(artifact.sha256) ||
      byKind.has(artifact.kind)
    ) {
      throw new TypeError("result artifacts are invalid");
    }
    const configured = profile.artifacts.find((item) => item.kind === artifact.kind);
    if (!configured) throw new TypeError("result artifacts are invalid");
    const url = parseStrictHttpsUrl(artifact.href, "artifact href", false);
    if (
      url.origin !== profile.origin ||
      !url.pathname.startsWith(profile.artifactPathPrefix) ||
      url.pathname.length <= profile.artifactPathPrefix.length ||
      url.toString() !== artifact.href
    ) {
      throw new TypeError("result artifact link is invalid");
    }
    byKind.set(artifact.kind, { href: artifact.href, sha256: artifact.sha256 });
  }
  const items = profile.artifacts.flatMap((configured) => {
    if (configured.visibility !== "primary") return [];
    const artifact = byKind.get(configured.kind)!;
    return [Object.freeze({ label: configured.label, value: "Open", href: artifact.href })];
  });
  return Object.freeze({
    version: 1,
    renderer: "qm.card.v1",
    fallbackText: `${profile.tools.start.label} is ready`,
    payload: Object.freeze({
      heading: `${profile.tools.start.label} is ready`,
      summary: "The requested background job completed successfully.",
      status: Object.freeze({ label: "Completed", tone: "success" }),
      sections: Object.freeze([Object.freeze({ key: "artifacts", label: "Artifacts", items: Object.freeze(items) })]),
      links: Object.freeze([]),
    }),
  });
}

function statusOutcome(
  profile: Readonly<BackgroundJobDeploymentProfile>,
  receipt: Readonly<BackgroundJobReceipt>,
  view: Readonly<BackgroundJobStatusView>,
): BackgroundJobOutcome {
  const card = resultCard(profile, receipt, view);
  const messages: Record<BackgroundJobStatusView["state"], string> = {
    queued: "The background job is queued.",
    running: "The background job is still running.",
    complete: "The background job result is ready.",
    failed: "The background job did not complete successfully.",
    cancelled: "The background job was cancelled.",
  };
  return Object.freeze({
    ok: true,
    state: view.state,
    message: messages[view.state],
    ...(card
      ? {
          card,
          cardDeliveryKey: `background-job-card:${profile.definition.id}:${receipt.runId}`,
        }
      : {}),
  });
}

export function createBackgroundJobProfileService<TInput, TStatus, TCancellation>(
  dependencies: Readonly<BackgroundJobProfileServiceDependencies<TInput, TStatus, TCancellation>>,
): BackgroundJobProfileService {
  const profile = dependencies.deployment;
  validateDefinition(profile.definition);
  validateBackgroundJobProfile(profile.profile);
  validateContractBinding(profile.binding);
  const now = dependencies.now ?? Date.now;
  const readiness = (): ReturnType<BackgroundJobProfileService["readiness"]> => {
    try {
      const adapter = dependencies.adapter.readiness();
      if (!adapter.ready) return Object.freeze({ ready: false, reason: "background_job_adapter_unavailable" });
      if (
        dependencies.receipts.durability !== "durable" ||
        dependencies.receipts.admission !== "durable_intent_outbox" ||
        dependencies.receipts.reconciliation !== "automatic_idempotent" ||
        !dependencies.receipts.readiness().ready
      ) {
        return Object.freeze({ ready: false, reason: "background_job_receipt_store_unavailable" });
      }
      if (
        dependencies.approvals.durability !== "durable" ||
        dependencies.approvals.consumption !== "one_time" ||
        !dependencies.approvals.readiness().ready
      ) {
        return Object.freeze({ ready: false, reason: "background_job_approval_store_unavailable" });
      }
      if (!dependencies.authorityReady()) {
        return Object.freeze({ ready: false, reason: "background_job_authority_unavailable" });
      }
      return Object.freeze({ ready: true });
    } catch {
      return Object.freeze({ ready: false, reason: "background_job_dependency_unavailable" });
    }
  };
  const ready = () => readiness().ready;
  const canStart = () => ready() && profile.enabled && dependencies.active();
  return Object.freeze({
    profileId: profile.definition.id,
    binding: profile.binding,
    readiness,
    bind(turn: Readonly<BackgroundJobTurnBinding>): BoundBackgroundJobTools | undefined {
      if (!ready() || !bindable(profile, turn)) return undefined;
      const audienceSlack = turn.verifiedSlack!;
      const expectedOwner = owner(profile, audienceSlack.threadTs);
      const owned = async () => {
        if (!ready()) return null;
        const receipt = await dependencies.receipts.latestOwned(profile.definition.id, expectedOwner);
        return receipt && receiptOwned(receipt, expectedOwner, profile) ? receipt : null;
      };
      return Object.freeze({
        profileId: profile.definition.id,
        canStart,
        async start(
          raw: unknown,
          authority: Readonly<BackgroundJobInvocationAuthority> | undefined,
        ): Promise<BackgroundJobOutcome> {
          if (!canStart() || !invocationMatches(profile, expectedOwner, authority)) return denied();
          let input: TInput;
          try {
            input = dependencies.adapter.parseInput(raw);
          } catch {
            return invalid();
          }
          try {
            const compiled = await dependencies.adapter.prepare(
              input,
              Object.freeze({ jobId: profile.definition.id, ...expectedOwner }),
            );
            if (
              !(compiled.bodyBytes instanceof Uint8Array) ||
              compiled.bodyBytes.byteLength < 2 ||
              compiled.bodyBytes.byteLength > profile.definition.start.maxRequestBytes
            ) {
              return unavailable();
            }
            identifier(compiled.idempotencyKey, "idempotency key");
            const bodyBytes = Uint8Array.from(compiled.bodyBytes);
            validateCompiledBody(profile, bodyBytes);
            const payloadSha256 = hash(bodyBytes);
            const at = now();
            const approved = await dependencies.approvals.consume(
              authority,
              expectation(
                profile,
                expectedOwner,
                authority,
                "background_job_start",
                payloadSha256,
                compiled.idempotencyKey,
                at,
              ),
            );
            if (!approved || !canStart()) return denied();
            const intent: Readonly<BackgroundJobAdmissionIntent> = Object.freeze({
              jobId: profile.definition.id,
              ...expectedOwner,
              messageTs: authority.slack.messageTs,
              ...profile.binding,
              bodyBytes,
              payloadSha256,
              idempotencyKey: compiled.idempotencyKey,
              createdAt: at,
            });
            const receipt = await dependencies.receipts.admit(intent, (durable) => {
              if (!canStart() || !admissionIntentMatches(durable, intent)) {
                throw new Error("background job admission intent is invalid");
              }
              return dependencies.client.start(
                durable.bodyBytes,
                { messageTs: durable.messageTs, threadTs: durable.threadTs },
                durable.idempotencyKey,
              );
            });
            if (
              !receiptOwned(receipt, expectedOwner, profile) ||
              receipt.messageTs !== intent.messageTs ||
              receipt.idempotencyKey !== intent.idempotencyKey ||
              receipt.payloadSha256 !== intent.payloadSha256 ||
              receipt.createdAt !== intent.createdAt
            ) {
              return unavailable();
            }
            identifier(receipt.authorityId, "authority id");
            identifier(receipt.runId, "run id");
            return Object.freeze({ ok: true, state: "accepted", message: "The background job is queued." });
          } catch {
            return unavailable();
          }
        },
        async status(): Promise<BackgroundJobOutcome> {
          try {
            const receipt = await owned();
            if (!receipt) {
              return Object.freeze({
                ok: false,
                state: "not_found",
                message: "No active background job is bound to this thread.",
              });
            }
            const view = validateStatusView(dependencies.adapter.statusView(await dependencies.client.status(receipt)));
            return statusOutcome(profile, receipt, view);
          } catch {
            return unavailable();
          }
        },
        async cancel(authority: Readonly<BackgroundJobInvocationAuthority> | undefined): Promise<BackgroundJobOutcome> {
          try {
            const receipt = await owned();
            if (!receipt) {
              return Object.freeze({
                ok: false,
                state: "not_found",
                message: "No active background job is bound to this thread.",
              });
            }
            if (!invocationMatches(profile, expectedOwner, authority)) return denied();
            const controlBytes = Buffer.from(
              canonicalJson({ authorityId: receipt.authorityId, runId: receipt.runId }),
              "utf8",
            );
            const payloadSha256 = hash(controlBytes);
            const idempotencyKey = `${profile.definition.id}-cancel:${payloadSha256}`;
            const at = now();
            const approved = await dependencies.approvals.consume(
              authority,
              expectation(
                profile,
                expectedOwner,
                authority,
                "background_job_cancel",
                payloadSha256,
                idempotencyKey,
                at,
              ),
            );
            if (!approved || !ready()) return denied();
            const state = dependencies.adapter.cancellationState(await dependencies.client.cancel(receipt));
            if (state !== "cancel_requested" && state !== "cancelled") return unavailable();
            return Object.freeze({
              ok: true,
              state,
              message: state === "cancelled" ? "The background job was cancelled." : "Cancellation was requested.",
            });
          } catch {
            return unavailable();
          }
        },
      });
    },
  });
}

export function createBackgroundJobRegistry(
  dependencies: Readonly<BackgroundJobRegistryDependencies>,
): BackgroundJobService {
  const activeServices = (): BackgroundJobProfileService[] => {
    const services: BackgroundJobProfileService[] = [];
    const ids = new Set<string>();
    for (const profile of dependencies.profiles()) {
      if (ids.has(profile.definition.id)) continue;
      ids.add(profile.definition.id);
      const service = dependencies.resolve(profile);
      if (
        service?.profileId === profile.definition.id &&
        service.binding.descriptorSha256 === profile.binding.descriptorSha256 &&
        service.binding.profileSha256 === profile.binding.profileSha256 &&
        service.binding.schemaSha256 === profile.binding.schemaSha256 &&
        service.readiness().ready
      ) {
        services.push(service);
      }
    }
    return services;
  };
  return Object.freeze({
    readiness: () =>
      activeServices().length > 0
        ? Object.freeze({ ready: true as const })
        : Object.freeze({ ready: false as const, reason: "background_job_profiles_unavailable" }),
    bind: (turn: Readonly<BackgroundJobTurnBinding>) =>
      Object.freeze(activeServices().flatMap((service) => service.bind(turn) ?? [])),
  });
}
