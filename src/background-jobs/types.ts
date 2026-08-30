import type { JsonWebKey } from "node:crypto";

export interface VerifiedSlackTurn {
  teamId: string;
  userId: string;
  channelId: string;
  messageTs: string;
  threadTs: string;
  threaded: boolean;
  liveHuman: true;
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
  ): Promise<string>;
  signStatus(bodyBytes: Uint8Array, receipt: Readonly<BackgroundJobReceipt>): Promise<string>;
  signCancel(
    bodyBytes: Uint8Array,
    receipt: Readonly<BackgroundJobReceipt>,
    grant: Readonly<BackgroundJobApprovalGrant>,
  ): Promise<string>;
  jwks(): Readonly<{ keys: readonly Readonly<JsonWebKey>[] }>;
}

export interface BackgroundJobAdmission {
  authorityId: string;
  runId: string;
}

export interface BackgroundJobReceipt extends BackgroundJobAudienceProfile, BackgroundJobContractBinding {
  jobId: string;
  authorityId: string;
  runId: string;
  threadTs: string;
  messageTs: string;
  idempotencyKey: string;
  payloadSha256: string;
  approvalId: string;
  approvalDigest: string;
  approvalEffect: "background_job_start";
  approvalMessageTs: string;
  approvalThreadTs: string;
  createdAt: number;
}

export interface BackgroundJobOwner extends BackgroundJobAudienceProfile {
  threadTs: string;
}

export interface BackgroundJobAdmissionIntent extends BackgroundJobOwner, BackgroundJobContractBinding {
  jobId: string;
  messageTs: string;
  bodyBytes: Uint8Array;
  payloadSha256: string;
  approvalId: string;
  approvalDigest: string;
  approvalEffect: "background_job_start";
  approvalMessageTs: string;
  approvalThreadTs: string;
  idempotencyKey: string;
  createdAt: number;
}

export interface BackgroundJobControlIntent extends BackgroundJobOwner, BackgroundJobContractBinding {
  effect: "background_job_cancel";
  jobId: string;
  authorityId: string;
  runId: string;
  approvalId: string;
  approvalDigest: string;
  approvalMessageTs: string;
  approvalThreadTs: string;
  payloadSha256: string;
  idempotencyKey: string;
  createdAt: number;
}

export interface BackgroundJobReceiptStore {
  durability: "durable";
  admission: "durable_intent_outbox";
  reconciliation: "automatic_idempotent";
  controls: "durable_intent_outbox";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false }>;
  admit(
    intent: Readonly<BackgroundJobAdmissionIntent>,
    start: (intent: Readonly<BackgroundJobAdmissionIntent>) => Promise<Readonly<BackgroundJobAdmission>>,
  ): Promise<Readonly<BackgroundJobReceipt>>;
  latestOwned(jobId: string, owner: Readonly<BackgroundJobOwner>): Promise<Readonly<BackgroundJobReceipt> | null>;
  control<T>(intent: Readonly<BackgroundJobControlIntent>, execute: () => Promise<T>): Promise<T>;
}

export interface BackgroundJobCompletionReceiptStore {
  durability: "durable";
  polling: "bounded_active_only";
  terminalTransition: "after_delivery_outbox";
  active(jobId: string, limit: number): Promise<readonly Readonly<BackgroundJobReceipt>[]>;
  terminal(
    receipt: Readonly<BackgroundJobReceipt>,
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
  enqueue(intent: Readonly<BackgroundJobDeliveryIntent>): Promise<"persisted" | "already_persisted">;
}

export interface BackgroundJobCompletionRuntime<TStatus = unknown> {
  receipts: BackgroundJobCompletionReceiptStore;
  client: Readonly<Pick<BackgroundJobClient<TStatus, unknown>, "status">>;
  adapter: Readonly<Pick<BackgroundJobAdapter<unknown, TStatus, unknown>, "statusView">>;
}

export interface BackgroundJobInvocationAuthority {
  receiptId: string;
  slack: Readonly<VerifiedSlackTurn>;
}

export interface BackgroundJobApprovalExpectation extends BackgroundJobOwner, BackgroundJobContractBinding {
  effect: "background_job_start" | "background_job_cancel";
  jobId: string;
  messageTs: string;
  payloadSha256: string;
  idempotencyKey: string;
  now: number;
  maximumExpiresAt: number;
}

export interface BackgroundJobApprovalGrant extends BackgroundJobOwner, BackgroundJobContractBinding {
  approvalId: string;
  digest: string;
  effect: "background_job_start" | "background_job_cancel";
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
  ): Promise<Readonly<BackgroundJobAdmission>>;
  status(receipt: Readonly<BackgroundJobReceipt>): Promise<Readonly<TStatus>>;
  cancel(
    receipt: Readonly<BackgroundJobReceipt>,
    grant: Readonly<BackgroundJobApprovalGrant>,
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
  canStart(): boolean;
  start(
    input: unknown,
    authority: Readonly<BackgroundJobInvocationAuthority> | undefined,
  ): Promise<BackgroundJobOutcome>;
  status(): Promise<BackgroundJobOutcome>;
  cancel(authority: Readonly<BackgroundJobInvocationAuthority> | undefined): Promise<BackgroundJobOutcome>;
}

export interface BackgroundJobService {
  bind(turn: Readonly<BackgroundJobTurnBinding>): readonly Readonly<BoundBackgroundJobTools>[];
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
}

export interface BackgroundJobProfileService {
  profileId: string;
  binding: Readonly<BackgroundJobContractBinding>;
  bind(turn: Readonly<BackgroundJobTurnBinding>): BoundBackgroundJobTools | undefined;
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
}
