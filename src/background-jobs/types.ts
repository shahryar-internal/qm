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

export interface BackgroundJobDeploymentProfile {
  contract: 1;
  enabled: boolean;
  definition: Readonly<BackgroundJobDefinition>;
  issuer: string;
  audience: string;
  origin: string;
  profile: Readonly<BackgroundJobAudienceProfile>;
  tools: Readonly<{
    start: Readonly<{ id: string; label: string }>;
    status: Readonly<{ id: string; label: string }>;
    cancel: Readonly<{ id: string; label: string }>;
  }>;
  schema: Readonly<{ sha256: string; json: unknown }>;
  artifacts: readonly Readonly<{ kind: string; label: string; visibility: "primary" | "private_review" }>[];
  dependencies: Readonly<{
    adapter: string;
    receiptStore: string;
    authority: "kms-rs256-v1";
  }>;
}

export interface BackgroundJobAuthoritySignerConfig {
  issuer: string;
  audience: string;
  keyId: string;
  tokenKid: string;
  publicJwk: JsonWebKey;
  profile: Readonly<BackgroundJobAudienceProfile>;
  definition: Readonly<BackgroundJobDefinition>;
  region?: string;
  lifetimeSeconds?: number;
}

export interface BackgroundJobAuthoritySigner {
  ready(): Promise<void>;
  signPrepare(bodyBytes: Uint8Array, threadTs: string, idempotencyKey: string): Promise<string>;
  signStart(bodyBytes: Uint8Array, threadTs: string, idempotencyKey: string): Promise<string>;
  signStatus(bodyBytes: Uint8Array, threadTs: string): Promise<string>;
  signCancel(bodyBytes: Uint8Array, threadTs: string): Promise<string>;
  jwks(): Readonly<{ keys: readonly Readonly<JsonWebKey>[] }>;
}

export interface BackgroundJobAdmission {
  authorityId: string;
  runId: string;
}

export interface BackgroundJobReceipt extends BackgroundJobAudienceProfile {
  jobId: string;
  authorityId: string;
  runId: string;
  threadTs: string;
  idempotencyKey: string;
  createdAt: number;
}

export interface BackgroundJobOwner extends BackgroundJobAudienceProfile {
  threadTs: string;
}

export interface BackgroundJobReceiptStore {
  durability: "durable";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false }>;
  save(receipt: Readonly<BackgroundJobReceipt>): Promise<void>;
  latestOwned(jobId: string, owner: Readonly<BackgroundJobOwner>): Promise<Readonly<BackgroundJobReceipt> | null>;
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
  admissionOutcome(admission: Readonly<BackgroundJobAdmission>): BackgroundJobOutcome;
  statusOutcome(status: Readonly<TStatus>, receipt: Readonly<BackgroundJobReceipt>): BackgroundJobOutcome;
  cancellationOutcome(
    cancellation: Readonly<TCancellation>,
    receipt: Readonly<BackgroundJobReceipt>,
  ): BackgroundJobOutcome;
}

export interface BackgroundJobClient<TStatus = unknown, TCancellation = unknown> {
  start(bodyBytes: Uint8Array, threadTs: string, idempotencyKey: string): Promise<Readonly<BackgroundJobAdmission>>;
  status(receipt: Readonly<BackgroundJobReceipt>): Promise<Readonly<TStatus>>;
  cancel(receipt: Readonly<BackgroundJobReceipt>): Promise<Readonly<TCancellation>>;
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
  start(input: unknown): Promise<BackgroundJobOutcome>;
  status(): Promise<BackgroundJobOutcome>;
  cancel(): Promise<BackgroundJobOutcome>;
}

export interface BackgroundJobService {
  bind(turn: Readonly<BackgroundJobTurnBinding>): BoundBackgroundJobTools | undefined;
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
}
