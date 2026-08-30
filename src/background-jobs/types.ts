import type { JsonWebKey } from "node:crypto";

export interface VerifiedSlackTurn {
  teamId: string;
  userId: string;
  channelId: string;
  messageTs: string;
  threadTs: string;
  threaded: boolean;
  liveHuman: true;
  actionTs?: string;
}

export interface BackgroundJobAudienceProfile {
  organizationId: string;
  actorPrincipalId: string;
  actorSlackId: string;
  audienceScopeId: string;
  slackTeamId: string;
  channelId: string;
}

export interface BackgroundJobRoute {
  path: string;
  maxRequestBytes: number;
}

export interface BackgroundJobDefinition {
  id: string;
  operation: string;
  capability: string;
  scope: string;
  tokenType: string;
  authorityHeader: string;
  prepare?: Readonly<BackgroundJobRoute>;
  start: Readonly<BackgroundJobRoute>;
  status: Readonly<BackgroundJobRoute>;
  cancel: Readonly<BackgroundJobRoute>;
}

export interface BackgroundJobContractBinding {
  descriptorSha256: string;
  profileSha256: string;
  schemaSha256: string;
}

export interface BackgroundJobDeploymentProfile {
  contract: 1;
  enabled: boolean;
  definition: Readonly<BackgroundJobDefinition>;
  issuer: string;
  audience: string;
  origin: string;
  artifactPathPrefix: string;
  artifactAccess: "owner_authenticated";
  profile: Readonly<BackgroundJobAudienceProfile>;
  tools: Readonly<{
    start: Readonly<{ id: string; label: string }>;
    status: Readonly<{ id: string; label: string }>;
    cancel: Readonly<{ id: string; label: string }>;
  }>;
  approval: Readonly<{
    start: "invocation_receipt";
    cancel: "invocation_receipt";
  }>;
  schema: Readonly<{ sha256: string; json: unknown }>;
  binding: Readonly<BackgroundJobContractBinding>;
  artifacts: readonly Readonly<{ kind: string; label: string; visibility: "primary" | "private_review" }>[];
  dependencies: Readonly<{
    adapter: string;
    receiptStore: string;
    approvalStore: string;
    authority: "kms-rs256-v1";
  }>;
}

export interface BackgroundJobAuthoritySignerConfig {
  issuer: string;
  audience: string;
  keyId: string;
  tokenKid: string;
  publicJwk: JsonWebKey;
  previousPublicJwk?: JsonWebKey;
  previousKeyRetireAt?: number;
  profile: Readonly<BackgroundJobAudienceProfile>;
  definition: Readonly<BackgroundJobDefinition>;
  binding: Readonly<BackgroundJobContractBinding>;
  region?: string;
  lifetimeSeconds?: number;
}

export interface BackgroundJobAuthoritySigner {
  ready(): Promise<void>;
  signPrepare(
    bodyBytes: Uint8Array,
    slack: Readonly<Pick<VerifiedSlackTurn, "messageTs" | "threadTs">>,
    idempotencyKey: string,
  ): Promise<string>;
  signStart(
    bodyBytes: Uint8Array,
    grant: Readonly<BackgroundJobApprovalGrant>,
    idempotencyKey: string,
    authorizedAt: number,
  ): Promise<string>;
  signStatus(bodyBytes: Uint8Array, receipt: Readonly<BackgroundJobReceipt>): Promise<string>;
  signCancel(
    bodyBytes: Uint8Array,
    receipt: Readonly<BackgroundJobReceipt>,
    grant: Readonly<BackgroundJobApprovalGrant>,
    authorizedAt: number,
  ): Promise<string>;
  jwks(): Readonly<{ keys: readonly Readonly<JsonWebKey>[] }>;
}

export interface BackgroundJobAdmission {
  authorityId: string;
  runId: string;
}

export interface BackgroundJobReceipt extends BackgroundJobAudienceProfile, BackgroundJobContractBinding {
  intentId: string;
  jobId: string;
  authorityId: string;
  runId: string;
  threadTs: string;
  conversationThreadRef: string;
  messageTs: string;
  idempotencyKey: string;
  payloadSha256: string;
  approvalId: string;
  approvalDigest: string;
  approvalEffect: "background_job_start";
  approvalKey: string;
  approvalActionTs: string;
  approvalMessageTs: string;
  approvalThreadTs: string;
  createdAt: number;
}

export interface BackgroundJobOwner extends BackgroundJobAudienceProfile {
  threadTs: string;
  conversationThreadRef: string;
}

export interface BackgroundJobAdmissionIntent extends BackgroundJobOwner, BackgroundJobContractBinding {
  intentId: string;
  jobId: string;
  messageTs: string;
  bodyBase64: string;
  payloadSha256: string;
  approvalGrant: Readonly<BackgroundJobApprovalGrant>;
  idempotencyKey: string;
  createdAt: number;
}

export interface BackgroundJobControlIntent extends BackgroundJobOwner, BackgroundJobContractBinding {
  intentId: string;
  effect: "background_job_cancel";
  jobId: string;
  authorityId: string;
  runId: string;
  approvalGrant: Readonly<BackgroundJobApprovalGrant>;
  payloadSha256: string;
  idempotencyKey: string;
  createdAt: number;
}

export interface BackgroundJobAdmissionLease {
  intent: Readonly<BackgroundJobAdmissionIntent>;
  leaseId: string;
  leaseExpiresAt: number;
  attempt: number;
}

export interface BackgroundJobControlLease {
  intent: Readonly<BackgroundJobControlIntent>;
  leaseId: string;
  leaseExpiresAt: number;
  attempt: number;
}

export interface BackgroundJobManualAttention {
  kind: "admission" | "control" | "completion" | "delivery";
  key: string;
  jobId: string;
  attempt: number;
  requiredAt: number;
}

export interface BackgroundJobReceiptStore {
  durability: "durable";
  admission: "durable_intent_outbox";
  reconciliation: "automatic_idempotent";
  controls: "durable_intent_outbox";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false }>;
  enqueueAdmission(intent: Readonly<BackgroundJobAdmissionIntent>): Promise<"persisted" | "already_persisted">;
  leaseAdmissions(
    jobId: string,
    now: number,
    limit: number,
    leaseId: string,
    leaseExpiresAt: number,
  ): Promise<readonly Readonly<BackgroundJobAdmissionLease>[]>;
  completeAdmission(
    intentId: string,
    leaseId: string,
    admission: Readonly<BackgroundJobAdmission>,
    completedAt: number,
  ): Promise<Readonly<BackgroundJobReceipt>>;
  retryAdmission(intentId: string, leaseId: string, nextAttemptAt: number, requiresAttention: boolean): Promise<void>;
  latestOwned(jobId: string, owner: Readonly<BackgroundJobOwner>): Promise<Readonly<BackgroundJobReceipt> | null>;
  ownedRun(
    jobId: string,
    owner: Readonly<BackgroundJobOwner>,
    authorityId: string,
    runId: string,
  ): Promise<Readonly<BackgroundJobReceipt> | null>;
  enqueueControl(intent: Readonly<BackgroundJobControlIntent>): Promise<"persisted" | "already_persisted">;
  leaseControls(
    jobId: string,
    now: number,
    limit: number,
    leaseId: string,
    leaseExpiresAt: number,
  ): Promise<readonly Readonly<BackgroundJobControlLease>[]>;
  completeControl(intentId: string, leaseId: string, completedAt: number): Promise<void>;
  retryControl(intentId: string, leaseId: string, nextAttemptAt: number, requiresAttention: boolean): Promise<void>;
  manualAttention(): Promise<readonly Readonly<BackgroundJobManualAttention>[]>;
}

export interface BackgroundJobCompletionLease {
  receipt: Readonly<BackgroundJobReceipt>;
  leaseId: string;
  leaseExpiresAt: number;
  attempt: number;
  failureAttempt: number;
}

export interface BackgroundJobCompletionReceiptStore {
  durability: "durable";
  polling: "bounded_active_only";
  terminalTransition: "after_delivery_outbox";
  leaseActive(
    jobId: string,
    now: number,
    limit: number,
    leaseId: string,
    leaseExpiresAt: number,
  ): Promise<readonly Readonly<BackgroundJobCompletionLease>[]>;
  retry(
    receipt: Readonly<BackgroundJobReceipt>,
    leaseId: string,
    nextAttemptAt: number,
    requiresAttention: boolean,
    failed: boolean,
  ): Promise<void>;
  manualAttention(): Promise<readonly Readonly<BackgroundJobManualAttention>[]>;
  terminal(
    receipt: Readonly<BackgroundJobReceipt>,
    leaseId: string,
    state: "complete" | "failed" | "cancelled",
    deliveryKey: string,
  ): Promise<void>;
}

export interface BackgroundJobDeliveryIntent extends BackgroundJobAudienceProfile, BackgroundJobContractBinding {
  deliveryKey: string;
  jobId: string;
  authorityId: string;
  runId: string;
  messageTs: string;
  threadTs: string;
  conversationThreadRef: string;
  state: "complete" | "failed" | "cancelled";
  text: string;
  card?: Readonly<WorkflowCardEnvelope>;
  createdAt: number;
}

export interface BackgroundJobDeliveryOutbox {
  durability: "durable";
  admission: "persist_before_send";
  reconciliation: "automatic_idempotent_delivery";
  transport: "slack_first_party_render_only";
  rawFallback: "forbidden";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false }>;
  enqueue(intent: Readonly<BackgroundJobDeliveryIntent>): Promise<"persisted" | "already_persisted">;
  lease(
    now: number,
    limit: number,
    leaseId: string,
    leaseExpiresAt: number,
  ): Promise<readonly Readonly<{ intent: BackgroundJobDeliveryIntent; leaseId: string; attempt: number }>[]>;
  sent(deliveryKey: string, leaseId: string, sentAt: number): Promise<void>;
  retry(deliveryKey: string, leaseId: string, nextAttemptAt: number, requiresAttention: boolean): Promise<void>;
  manualAttention(): Promise<readonly Readonly<BackgroundJobManualAttention>[]>;
}

export interface BackgroundJobRenderOnlySender {
  transport: "slack_first_party_render_only";
  rawFallback: "forbidden";
  idempotency: "durable_delivery_key";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false }>;
  send(intent: Readonly<BackgroundJobDeliveryIntent>, deliveryKey: string): Promise<void>;
}

export interface BackgroundJobCompletionRuntime<TStatus = unknown> {
  receipts: BackgroundJobCompletionReceiptStore;
  client: Readonly<Pick<BackgroundJobClient<TStatus, unknown>, "status">>;
  adapter: Readonly<Pick<BackgroundJobAdapter<unknown, TStatus, unknown>, "statusView">>;
}

export interface BackgroundJobEffectRuntime<TStatus = unknown, TCancellation = unknown> {
  receipts: BackgroundJobReceiptStore;
  client: BackgroundJobClient<TStatus, TCancellation>;
  adapter: Readonly<Pick<BackgroundJobAdapter<unknown, TStatus, TCancellation>, "cancellationState">>;
}

export interface BackgroundJobInvocationAuthority {
  receiptId: string;
  approvalKey: string;
  actionTs: string;
  slack: Readonly<VerifiedSlackTurn>;
}

export interface BackgroundJobApprovalExpectation extends BackgroundJobOwner, BackgroundJobContractBinding {
  effect: "background_job_start" | "background_job_cancel";
  jobId: string;
  messageTs: string;
  approvalKey: string;
  actionTs: string;
  payloadSha256: string;
  idempotencyKey: string;
  now: number;
  maximumExpiresAt: number;
}

export interface BackgroundJobApprovalGrant extends BackgroundJobOwner, BackgroundJobContractBinding {
  approvalId: string;
  digest: string;
  effect: "background_job_start" | "background_job_cancel";
  approvalKey: string;
  actionTs: string;
  jobId: string;
  messageTs: string;
  payloadSha256: string;
  idempotencyKey: string;
  issuedAt: number;
  expiresAt: number;
}

export interface BackgroundJobApprovalStore {
  durability: "durable";
  consumption: "one_time";
  grants: "verified_immutable";
  retirementFence: "atomic_permanent";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false }>;
  consume(
    authority: Readonly<BackgroundJobInvocationAuthority>,
    expected: Readonly<BackgroundJobApprovalExpectation>,
  ): Promise<Readonly<BackgroundJobApprovalGrant> | null>;
}

export interface WorkflowCardEnvelope {
  version: 1;
  renderer: "qm.card.v1";
  fallbackText: string;
  payload: unknown;
}

export type BackgroundJobOutcome =
  | Readonly<{
      ok: true;
      state: string;
      message: string;
      card?: Readonly<WorkflowCardEnvelope>;
      cardDeliveryKey?: string;
    }>
  | Readonly<{
      ok: false;
      state: "denied" | "unavailable" | "invalid" | "not_found";
      message: string;
      approvalKey?: string;
    }>;

export interface CompiledBackgroundJob {
  bodyBytes: Uint8Array;
  idempotencyKey: string;
}

export interface BackgroundJobCompilerContext extends BackgroundJobOwner {
  jobId: string;
}

export interface BackgroundJobAdapter<TInput = unknown, TStatus = unknown, TCancellation = unknown> {
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
  parseInput(value: unknown): TInput;
  prepare(input: TInput, context: Readonly<BackgroundJobCompilerContext>): Promise<Readonly<CompiledBackgroundJob>>;
  statusView(status: Readonly<TStatus>): Readonly<BackgroundJobStatusView>;
  cancellationState(cancellation: Readonly<TCancellation>): "cancel_requested" | "cancelled";
}

export interface BackgroundJobResultArtifact {
  kind: string;
  href: string;
  sha256: string;
}

export interface BackgroundJobStatusView {
  state: "queued" | "running" | "complete" | "failed" | "cancelled";
  artifacts?: readonly Readonly<BackgroundJobResultArtifact>[];
}

export interface BackgroundJobClient<TStatus = unknown, TCancellation = unknown> {
  start(
    bodyBytes: Uint8Array,
    grant: Readonly<BackgroundJobApprovalGrant>,
    idempotencyKey: string,
    authorizedAt: number,
  ): Promise<Readonly<BackgroundJobAdmission>>;
  status(receipt: Readonly<BackgroundJobReceipt>): Promise<Readonly<TStatus>>;
  cancel(
    receipt: Readonly<BackgroundJobReceipt>,
    grant: Readonly<BackgroundJobApprovalGrant>,
    authorizedAt: number,
  ): Promise<Readonly<TCancellation>>;
}

export interface BackgroundJobTurnBinding {
  surface: string | undefined;
  actorId: string;
  actorType: "internal" | "guest";
  conversationKind: "dm" | "channel" | "group";
  conversationThreadRef: string;
  conversationAudienceIds: readonly string[];
  originKind: "direct" | "human" | "ambient" | "automation";
  originMessageTs: string | undefined;
  verifiedSlack: Readonly<VerifiedSlackTurn> | undefined;
}

export interface BoundBackgroundJobTools {
  profileId: string;
  label: string;
  actions: readonly ("start" | "status" | "cancel")[];
  visible?(): Promise<boolean>;
  canStart(): boolean;
  start(
    input: unknown,
    authority: Readonly<BackgroundJobInvocationAuthority> | undefined,
  ): Promise<BackgroundJobOutcome>;
  status(): Promise<BackgroundJobOutcome>;
  cancel(authority: Readonly<BackgroundJobInvocationAuthority> | undefined): Promise<BackgroundJobOutcome>;
}

export interface BackgroundJobService {
  bind(turn: Readonly<BackgroundJobTurnBinding>): Promise<readonly Readonly<BoundBackgroundJobTools>[]>;
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
}

export interface BackgroundJobProfileService {
  profileId: string;
  binding: Readonly<BackgroundJobContractBinding>;
  bind(turn: Readonly<BackgroundJobTurnBinding>): BoundBackgroundJobTools | undefined;
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
}
