import type { JsonWebKey } from "node:crypto";
import {
  createBackgroundJobProductionComposition,
  type BackgroundJobProductionComposition,
} from "../background-jobs/composition.ts";
import { parseBackgroundJobDeploymentProfile } from "../background-jobs/deployment-profile.ts";
import type { BackgroundJobNativeDependency } from "../background-jobs/runtime.ts";
import type {
  BackgroundJobAuthoritySigner,
  BackgroundJobDeliveryIntent,
  BackgroundJobDeploymentProfile,
  BackgroundJobRenderOnlySender,
} from "../background-jobs/types.ts";
import type { BackgroundJobCompositionContext } from "../wiring.ts";
import { riselyProposalInputSchema, riselyProposalSchemaSha256 } from "./contracts.ts";
import {
  createRiselyProposalAdapter,
  createRiselyProposalClient,
  RISELY_PROPOSAL_ARTIFACTS,
  type RiselyProposalRunRecord,
} from "./runtime.ts";

const PROFILE_ENV = [
  "RISELY_PROPOSAL_ACTOR_PRINCIPAL_ID",
  "RISELY_PROPOSAL_SLACK_USER_ID",
  "RISELY_PROPOSAL_SLACK_TEAM_ID",
  "RISELY_PROPOSAL_SLACK_DM_ID",
  "RISELY_PROPOSAL_KMS_KEY_ID",
  "RISELY_PROPOSAL_TOKEN_KID",
  "RISELY_PROPOSAL_PUBLIC_JWK",
] as const;

function configuredProfile(
  context: Readonly<BackgroundJobCompositionContext>,
): Readonly<BackgroundJobDeploymentProfile> | undefined {
  if (context.env.RISELY_PROPOSAL_ENABLED !== "1") return undefined;
  const values = Object.fromEntries(PROFILE_ENV.map((name) => [name, context.env[name]?.trim()]));
  const missing = PROFILE_ENV.filter((name) => !values[name]);
  if (!context.publicUrl) missing.push("RISELY_PROPOSAL_PUBLIC_URL" as (typeof PROFILE_ENV)[number]);
  if (missing.length) throw new TypeError(`Risely proposal configuration is incomplete: ${missing.join(", ")}`);
  const origin = new URL(context.publicUrl!).origin;
  const actorPrincipalId = values.RISELY_PROPOSAL_ACTOR_PRINCIPAL_ID!;
  const profile = {
    contract: 1,
    definition: {
      id: "risely-proposal",
      operation: "proposal_compile",
      capability: "proposals.private.compile",
      scope: "jobs:submit",
      tokenType: "job-authority+jwt",
      authorityHeader: "x-job-authority",
      start: { path: "/v1/private-proposals/start", maxRequestBytes: 512 * 1024 },
      status: { path: "/v1/private-proposals/status", maxRequestBytes: 1024 },
      cancel: { path: "/v1/private-proposals/cancel", maxRequestBytes: 1024 },
    },
    issuer: `${origin}/v1/job-authority`,
    audience: `${origin}/v1/private-proposals`,
    origin,
    artifactPathPrefix: "/v1/files/",
    artifactAccess: "owner_authenticated",
    profile: {
      organizationId: context.orgId,
      actorPrincipalId,
      actorSlackId: values.RISELY_PROPOSAL_SLACK_USER_ID,
      audienceScopeId: `personal:${actorPrincipalId}`,
      slackTeamId: values.RISELY_PROPOSAL_SLACK_TEAM_ID,
      channelId: values.RISELY_PROPOSAL_SLACK_DM_ID,
    },
    tools: {
      start: { id: "risely-proposal", label: "Create private proposal" },
      status: { id: "risely-proposal-status", label: "Check private proposal" },
      cancel: { id: "risely-proposal-cancel", label: "Cancel private proposal" },
    },
    approval: { start: "invocation_receipt", cancel: "invocation_receipt" },
    schema: { sha256: riselyProposalSchemaSha256(), json: riselyProposalInputSchema },
    artifacts: RISELY_PROPOSAL_ARTIFACTS,
    dependencies: {
      adapter: "risely-proposal-compiler-v1",
      receiptStore: "background_job_records",
      approvalStore: "background_job_approval_ledger",
      authority: "kms-rs256-v1",
    },
  };
  return parseBackgroundJobDeploymentProfile(JSON.stringify(profile), "background-jobs/risely-proposal/job.json");
}

function publicJwk(value: string): JsonWebKey {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new TypeError("RISELY_PROPOSAL_PUBLIC_JWK is invalid");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeError("RISELY_PROPOSAL_PUBLIC_JWK is invalid");
  }
  return parsed as JsonWebKey;
}

function sender(context: Readonly<BackgroundJobCompositionContext>): BackgroundJobRenderOnlySender {
  return Object.freeze({
    transport: "slack_first_party_render_only" as const,
    rawFallback: "forbidden" as const,
    idempotency: "durable_delivery_key" as const,
    readiness: () => Object.freeze(context.durable ? { ready: true as const } : { ready: false as const }),
    async send(intent: Readonly<BackgroundJobDeliveryIntent>, deliveryKey: string) {
      if (!intent.card || intent.state !== "complete") throw new Error("proposal result card is unavailable");
      const bytes = Buffer.from(JSON.stringify(intent.card), "utf8");
      const stored = await context.blobTransfer.put(bytes, { maxBytes: 256 * 1024 });
      await context.deliveries.enqueue({
        destination: {
          type: "slack",
          target: intent.channelId,
          audienceScopeId: intent.audienceScopeId,
          threadTs: intent.threadTs,
        },
        text: "",
        attachments: [
          {
            name: "risely-proposal.workflow.json",
            mimetype: "application/vnd.qm.workflow-card+json",
            sizeBytes: stored.sizeBytes,
            blobId: stored.blobId,
            renderOnly: true,
          },
        ],
        idempotencyKey: deliveryKey,
      });
    },
  });
}

export function createRiselyProposalComposition(
  context: Readonly<BackgroundJobCompositionContext>,
): Readonly<BackgroundJobProductionComposition> {
  const profile = configuredProfile(context);
  if (!profile) return createBackgroundJobProductionComposition();
  const records = context.artifactMap<RiselyProposalRunRecord>("risely_proposal_runs");
  const adapter = createRiselyProposalAdapter();
  const dependency: BackgroundJobNativeDependency = Object.freeze({
    adapter: adapter as BackgroundJobNativeDependency["adapter"],
    parsers: Object.freeze({}) as BackgroundJobNativeDependency["parsers"],
    createClient: (deployment: Readonly<BackgroundJobDeploymentProfile>, authority: BackgroundJobAuthoritySigner) =>
      createRiselyProposalClient({ profile: deployment, authority, records, files: context.files }),
  });
  const kmsKeyId = context.env.RISELY_PROPOSAL_KMS_KEY_ID!.trim();
  const tokenKid = context.env.RISELY_PROPOSAL_TOKEN_KID!.trim();
  const jwk = publicJwk(context.env.RISELY_PROPOSAL_PUBLIC_JWK!);
  return createBackgroundJobProductionComposition({
    adapters: { "risely-proposal-compiler-v1": dependency },
    profiles: () => Object.freeze([profile]),
    sender: sender(context),
    resolveAuthority: (candidate) =>
      candidate.definition.id === profile.definition.id
        ? Object.freeze({
            active: Object.freeze({
              keyId: kmsKeyId,
              tokenKid,
              publicJwk: jwk,
              ...(context.region ? { region: context.region } : {}),
            }),
          })
        : undefined,
  });
}
