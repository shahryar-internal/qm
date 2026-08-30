import { createHash } from "node:crypto";
import { canonicalJson } from "../cron/schedule-authority.ts";
import { validateBackgroundJobSchemaValue } from "./deployment-profile.ts";
import type {
  BackgroundJobAdapter,
  BackgroundJobAdmissionIntent,
  BackgroundJobApprovalGrant,
  BackgroundJobApprovalExpectation,
  BackgroundJobApprovalStore,
  BackgroundJobClient,
  BackgroundJobControlIntent,
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

export interface BackgroundJobProfileServiceDependencies<TInput, TStatus, TCancellation> {
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

function denied(approvalKey?: string): BackgroundJobOutcome {
  return Object.freeze({
    ok: false,
    state: "denied",
    message: "A fresh approval is required for this action.",
    ...(approvalKey ? { approvalKey } : {}),
  });
}

function owner(
  profile: Readonly<BackgroundJobDeploymentProfile>,
  threadTs: string,
  conversationThreadRef: string,
): Readonly<BackgroundJobOwner> {
  return Object.freeze({ ...profile.profile, threadTs, conversationThreadRef });
}

function hash(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function backgroundJobApprovalDigest(grant: Readonly<Omit<BackgroundJobApprovalGrant, "digest">>): string {
  return hash(Buffer.from(canonicalJson(grant), "utf8"));
}

export function backgroundJobEffectApprovalKey(
  profile: Readonly<BackgroundJobDeploymentProfile>,
  effect: "background_job_start" | "background_job_cancel",
  value: unknown,
): string {
  return `background-job-approval:${hash(
    Buffer.from(
      canonicalJson({
        descriptorSha256: profile.binding.descriptorSha256,
        effect,
        jobId: profile.definition.id,
        value,
      }),
      "utf8",
    ),
  )}`;
}

function validatedApprovalGrant(
  profile: Readonly<BackgroundJobDeploymentProfile>,
  authority: Readonly<BackgroundJobInvocationAuthority>,
  expected: Readonly<BackgroundJobApprovalExpectation>,
  value: Readonly<BackgroundJobApprovalGrant> | null,
): Readonly<BackgroundJobApprovalGrant> | null {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      "actionTs,actorPrincipalId,actorSlackId,approvalId,approvalKey,audienceScopeId,channelId,conversationThreadRef,descriptorSha256,digest,effect,expiresAt,idempotencyKey,issuedAt,jobId,messageTs,organizationId,payloadSha256,profileSha256,schemaSha256,slackTeamId,threadTs" ||
    value.approvalId !== authority.receiptId ||
    value.effect !== expected.effect ||
    value.approvalKey !== expected.approvalKey ||
    value.actionTs !== expected.actionTs ||
    value.jobId !== expected.jobId ||
    value.organizationId !== expected.organizationId ||
    value.actorPrincipalId !== expected.actorPrincipalId ||
    value.actorSlackId !== expected.actorSlackId ||
    value.audienceScopeId !== expected.audienceScopeId ||
    value.slackTeamId !== expected.slackTeamId ||
    value.channelId !== expected.channelId ||
    value.conversationThreadRef !== expected.conversationThreadRef ||
    value.threadTs !== expected.threadTs ||
    value.messageTs !== expected.messageTs ||
    value.descriptorSha256 !== profile.binding.descriptorSha256 ||
    value.profileSha256 !== profile.binding.profileSha256 ||
    value.schemaSha256 !== profile.binding.schemaSha256 ||
    value.payloadSha256 !== expected.payloadSha256 ||
    value.idempotencyKey !== expected.idempotencyKey ||
    !Number.isSafeInteger(value.issuedAt) ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.issuedAt < expected.now ||
    value.issuedAt >= value.expiresAt ||
    value.expiresAt <= expected.now ||
    value.expiresAt > expected.maximumExpiresAt ||
    !SHA256.test(value.digest)
  ) {
    return null;
  }
  try {
    identifier(value.approvalId, "approval id");
    identifier(value.approvalKey, "approval key");
    validateSlackTimestamp(value.actionTs, "actionTs");
    validateSlackTimestamp(value.messageTs, "messageTs");
    validateSlackTimestamp(value.threadTs, "threadTs");
  } catch {
    return null;
  }
  const { digest, ...unsigned } = value;
  if (backgroundJobApprovalDigest(unsigned) !== digest) return null;
  return Object.freeze(structuredClone(value));
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

export function backgroundJobReceiptOwned(
  receipt: Readonly<BackgroundJobReceipt>,
  expected: Readonly<BackgroundJobOwner>,
  profile: Readonly<BackgroundJobDeploymentProfile>,
): boolean {
  if (
    !receipt ||
    typeof receipt !== "object" ||
    Array.isArray(receipt) ||
    Object.keys(receipt).sort().join(",") !==
      "actorPrincipalId,actorSlackId,approvalActionTs,approvalDigest,approvalEffect,approvalId,approvalKey,approvalMessageTs,approvalThreadTs,audienceScopeId,authorityId,channelId,conversationThreadRef,createdAt,descriptorSha256,idempotencyKey,intentId,jobId,messageTs,organizationId,payloadSha256,profileSha256,runId,schemaSha256,slackTeamId,threadTs" ||
    !identifierOrFalse(receipt.authorityId) ||
    !identifierOrFalse(receipt.runId) ||
    !identifierOrFalse(receipt.idempotencyKey) ||
    !Number.isSafeInteger(receipt.createdAt) ||
    receipt.createdAt < 1 ||
    !identifierOrFalse(receipt.intentId) ||
    !identifierOrFalse(receipt.approvalId) ||
    !identifierOrFalse(receipt.approvalKey) ||
    !SHA256.test(receipt.approvalDigest) ||
    receipt.approvalEffect !== "background_job_start"
  ) {
    return false;
  }
  try {
    validateSlackTimestamp(receipt.messageTs, "messageTs");
    validateSlackTimestamp(receipt.threadTs, "threadTs");
    validateSlackTimestamp(receipt.approvalMessageTs, "approvalMessageTs");
    validateSlackTimestamp(receipt.approvalThreadTs, "approvalThreadTs");
    validateSlackTimestamp(receipt.approvalActionTs, "approvalActionTs");
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
    receipt.conversationThreadRef === expected.conversationThreadRef &&
    receipt.approvalThreadTs === receipt.threadTs &&
    receipt.approvalMessageTs === receipt.messageTs &&
    validateSlackTimestampOrFalse(receipt.approvalActionTs) &&
    receipt.descriptorSha256 === profile.binding.descriptorSha256 &&
    receipt.profileSha256 === profile.binding.profileSha256 &&
    receipt.schemaSha256 === profile.binding.schemaSha256 &&
    SHA256.test(receipt.payloadSha256)
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
  currentSlack: Readonly<BackgroundJobInvocationAuthority["slack"]>,
  authority: Readonly<BackgroundJobInvocationAuthority> | undefined,
): authority is Readonly<BackgroundJobInvocationAuthority> {
  if (
    !authority ||
    !identifierOrFalse(authority.receiptId) ||
    !identifierOrFalse(authority.approvalKey) ||
    authority.actionTs !== currentSlack.actionTs
  ) {
    return false;
  }
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
    slack.teamId === currentSlack.teamId &&
    slack.userId === currentSlack.userId &&
    slack.channelId === currentSlack.channelId &&
    slack.messageTs === currentSlack.messageTs &&
    slack.threadTs === currentSlack.threadTs &&
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

function validateSlackTimestampOrFalse(value: unknown): boolean {
  try {
    validateSlackTimestamp(value, "Slack timestamp");
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
    approvalKey: authority.approvalKey,
    actionTs: authority.actionTs,
    ...profile.binding,
    payloadSha256,
    idempotencyKey,
    now,
    maximumExpiresAt: now + APPROVAL_LIFETIME_MS,
  });
}

export function validateBackgroundJobStatusView(value: Readonly<BackgroundJobStatusView>): BackgroundJobStatusView {
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

export function backgroundJobStatusOutcome(
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
          cardDeliveryKey: `background-job-card:${hash(
            Buffer.from(
              canonicalJson({
                descriptorSha256: profile.binding.descriptorSha256,
                jobId: profile.definition.id,
                runId: receipt.runId,
              }),
              "utf8",
            ),
          )}`,
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
        dependencies.receipts.controls !== "durable_intent_outbox" ||
        !dependencies.receipts.readiness().ready
      ) {
        return Object.freeze({ ready: false, reason: "background_job_receipt_store_unavailable" });
      }
      if (
        dependencies.approvals.durability !== "durable" ||
        dependencies.approvals.consumption !== "one_time" ||
        dependencies.approvals.grants !== "verified_immutable" ||
        dependencies.approvals.retirementFence !== "atomic_permanent" ||
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
      const expectedOwner = owner(
        profile,
        audienceSlack.threadTs,
        `dm:${audienceSlack.channelId}:${audienceSlack.threadTs}`,
      );
      const owned = async () => {
        if (!ready()) return null;
        const receipt = await dependencies.receipts.latestOwned(profile.definition.id, expectedOwner);
        return receipt && backgroundJobReceiptOwned(receipt, expectedOwner, profile) ? receipt : null;
      };
      return Object.freeze({
        profileId: profile.definition.id,
        canStart,
        async start(
          raw: unknown,
          authority: Readonly<BackgroundJobInvocationAuthority> | undefined,
        ): Promise<BackgroundJobOutcome> {
          if (!canStart()) return denied();
          let approvalKey: string;
          try {
            approvalKey = backgroundJobEffectApprovalKey(profile, "background_job_start", raw);
          } catch {
            return invalid();
          }
          if (
            !invocationMatches(profile, expectedOwner, audienceSlack, authority) ||
            authority.approvalKey !== approvalKey
          ) {
            return denied(approvalKey);
          }
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
            const expected = expectation(
              profile,
              expectedOwner,
              authority,
              "background_job_start",
              payloadSha256,
              compiled.idempotencyKey,
              at,
            );
            const grant = validatedApprovalGrant(
              profile,
              authority,
              expected,
              await dependencies.approvals.consume(authority, expected),
            );
            if (!grant || !canStart()) return denied();
            const intent: Readonly<BackgroundJobAdmissionIntent> = Object.freeze({
              intentId: `background-job-intent:${hash(
                Buffer.from(
                  canonicalJson({
                    approvalId: grant.approvalId,
                    descriptorSha256: profile.binding.descriptorSha256,
                    effect: "background_job_start",
                    idempotencyKey: compiled.idempotencyKey,
                    payloadSha256,
                    threadTs: expectedOwner.threadTs,
                  }),
                  "utf8",
                ),
              )}`,
              jobId: profile.definition.id,
              ...expectedOwner,
              messageTs: grant.messageTs,
              ...profile.binding,
              bodyBase64: Buffer.from(bodyBytes).toString("base64"),
              payloadSha256,
              approvalGrant: grant,
              idempotencyKey: compiled.idempotencyKey,
              createdAt: grant.issuedAt,
            });
            await dependencies.receipts.enqueueAdmission(intent);
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
            const view = validateBackgroundJobStatusView(
              dependencies.adapter.statusView(await dependencies.client.status(receipt)),
            );
            return backgroundJobStatusOutcome(profile, receipt, view);
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
            const controlBytes = Buffer.from(
              canonicalJson({ authorityId: receipt.authorityId, runId: receipt.runId }),
              "utf8",
            );
            const payloadSha256 = hash(controlBytes);
            const idempotencyKey = `${profile.definition.id}-cancel:${payloadSha256}`;
            const approvalKey = backgroundJobEffectApprovalKey(profile, "background_job_cancel", {
              authorityId: receipt.authorityId,
              runId: receipt.runId,
            });
            if (
              !invocationMatches(profile, expectedOwner, audienceSlack, authority) ||
              authority.approvalKey !== approvalKey
            ) {
              return denied(approvalKey);
            }
            const at = now();
            const expected = expectation(
              profile,
              expectedOwner,
              authority,
              "background_job_cancel",
              payloadSha256,
              idempotencyKey,
              at,
            );
            const grant = validatedApprovalGrant(
              profile,
              authority,
              expected,
              await dependencies.approvals.consume(authority, expected),
            );
            if (!grant || !ready()) return denied();
            const intent: Readonly<BackgroundJobControlIntent> = Object.freeze({
              intentId: `background-job-control:${hash(
                Buffer.from(
                  canonicalJson({
                    approvalId: grant.approvalId,
                    authorityId: receipt.authorityId,
                    descriptorSha256: profile.binding.descriptorSha256,
                    effect: "background_job_cancel",
                    runId: receipt.runId,
                    threadTs: expectedOwner.threadTs,
                  }),
                  "utf8",
                ),
              )}`,
              effect: "background_job_cancel",
              jobId: profile.definition.id,
              ...expectedOwner,
              ...profile.binding,
              authorityId: receipt.authorityId,
              runId: receipt.runId,
              approvalGrant: grant,
              payloadSha256,
              idempotencyKey,
              createdAt: grant.issuedAt,
            });
            await dependencies.receipts.enqueueControl(intent);
            return Object.freeze({
              ok: true,
              state: "cancel_requested",
              message: "Cancellation was requested.",
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
