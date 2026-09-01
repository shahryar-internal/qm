import { createHash } from "node:crypto";
import { canonicalJson } from "../../src/cron/schedule-authority.ts";

export function backgroundJobProfileJson(id: string): string {
  const schema = {
    type: "object",
    additionalProperties: false,
    properties: { decisionId: { type: "string", maxLength: 100 } },
    required: ["decisionId"],
  };
  return JSON.stringify({
    contract: 1,
    definition: {
      id,
      operation: "proposal_create",
      capability: "proposals.create",
      scope: "jobs:submit",
      tokenType: "job-authority+jwt",
      authorityHeader: "x-job-authority",
      start: { path: "/jobs/start", maxRequestBytes: 1024 },
      status: { path: "/jobs/status", maxRequestBytes: 512 },
      cancel: { path: "/jobs/cancel", maxRequestBytes: 512 },
    },
    issuer: "https://gateway.example.com/authority",
    audience: "https://jobs.example.com/authority",
    origin: "https://jobs.example.com",
    artifactPathPrefix: "/artifacts/",
    artifactAccess: "owner_authenticated",
    profile: {
      organizationId: "org_example",
      actorPrincipalId: "principal_owner",
      actorSlackId: "UOWNER1",
      audienceScopeId: "personal:principal_owner",
      slackTeamId: "TTEAM01",
      channelId: "DOWNER1",
    },
    tools: {
      start: { id, label: "Create proposal" },
      status: { id: `${id}-status`, label: "Check proposal" },
      cancel: { id: `${id}-cancel`, label: "Cancel proposal" },
    },
    approval: { start: "invocation_receipt", cancel: "invocation_receipt" },
    schema: { sha256: createHash("sha256").update(canonicalJson(schema)).digest("hex"), json: schema },
    artifacts: [{ kind: "proposal", label: "Proposal", visibility: "primary" }],
    dependencies: {
      adapter: "proposal-compiler",
      receiptStore: "durable-receipts",
      approvalStore: "durable-approvals",
      authority: "kms-rs256-v1",
    },
  });
}
