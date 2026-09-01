import { createHash, createPublicKey, verify, type JsonWebKey } from "node:crypto";
import { artifactPath, type FileArtifactStore } from "../files/file-artifact-store.ts";
import type { DurableMap } from "../persistence/durable-map.ts";
import { canonicalJson } from "../cron/schedule-authority.ts";
import type {
  BackgroundJobAdapter,
  BackgroundJobApprovalGrant,
  BackgroundJobAuthoritySigner,
  BackgroundJobClient,
  BackgroundJobCompilerContext,
  BackgroundJobDeploymentProfile,
  BackgroundJobReceipt,
  BackgroundJobResultArtifact,
  BackgroundJobStatusView,
} from "../background-jobs/types.ts";
import { parseRiselyProposalInput, type RiselyProposalInput } from "./contracts.ts";
import { renderEmailDraft, renderEvidenceManifest, renderProposalHtml, renderProposalPdf } from "./render.ts";

export const RISELY_PROPOSAL_ARTIFACTS = Object.freeze([
  Object.freeze({ kind: "proposal_pdf", label: "Open proposal", visibility: "primary" as const }),
  Object.freeze({ kind: "proposal_html", label: "Proposal HTML", visibility: "private_review" as const }),
  Object.freeze({ kind: "evidence_manifest", label: "Evidence manifest", visibility: "private_review" as const }),
  Object.freeze({ kind: "decision_receipts", label: "Decision receipts", visibility: "private_review" as const }),
  Object.freeze({ kind: "email_draft", label: "Email draft", visibility: "private_review" as const }),
]);

interface PreparedProposal {
  contract: 1;
  jobId: string;
  owner: Readonly<BackgroundJobCompilerContext>;
  input: Readonly<RiselyProposalInput>;
}

interface ProposalDecisionReceipt {
  receiptId: string;
  proposalId: string;
  revision: number;
  sectionKey: string;
  sectionSha256: string;
  evidenceSha256: readonly string[];
  approvalId: string;
  approvalDigest: string;
  approvalActionTs: string;
  decision: "approved_for_private_compile";
  releaseEligible: false;
  decidedAt: string;
}

export interface RiselyProposalRunRecord {
  runId: string;
  authorityId: string;
  idempotencyKey: string;
  proposalId: string;
  revision: number;
  state: "complete" | "cancelled";
  artifacts: readonly Readonly<BackgroundJobResultArtifact>[];
  decisions: readonly Readonly<ProposalDecisionReceipt>[];
  releaseEligible: false;
  createdAt: number;
  completedAt: number;
}

export interface RiselyProposalStatus {
  runId: string;
  state: "complete" | "cancelled";
  artifacts?: readonly Readonly<BackgroundJobResultArtifact>[];
}

export interface RiselyProposalCancellation {
  runId: string;
  state: "cancel_requested" | "cancelled";
}

interface ArtifactDefinition {
  kind: string;
  name: string;
  mimetype: string;
  bytes: Buffer;
}

function hash(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function decodePrepared(body: Uint8Array, profile: Readonly<BackgroundJobDeploymentProfile>): PreparedProposal {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new TypeError("prepared proposal body is invalid");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new TypeError("prepared proposal body is invalid");
  const root = parsed as Record<string, unknown>;
  if (Object.keys(root).sort().join(",") !== "contract,input,jobId,owner" || root.contract !== 1) {
    throw new TypeError("prepared proposal body is invalid");
  }
  const owner = root.owner as Record<string, unknown>;
  const expectedOwner = profile.profile;
  if (
    !owner ||
    typeof owner !== "object" ||
    Array.isArray(owner) ||
    root.jobId !== profile.definition.id ||
    owner.jobId !== profile.definition.id ||
    owner.organizationId !== expectedOwner.organizationId ||
    owner.actorPrincipalId !== expectedOwner.actorPrincipalId ||
    owner.actorSlackId !== expectedOwner.actorSlackId ||
    owner.audienceScopeId !== expectedOwner.audienceScopeId ||
    owner.slackTeamId !== expectedOwner.slackTeamId ||
    owner.channelId !== expectedOwner.channelId ||
    typeof owner.threadTs !== "string" ||
    typeof owner.conversationThreadRef !== "string"
  ) {
    throw new TypeError("prepared proposal owner is invalid");
  }
  return Object.freeze({
    contract: 1,
    jobId: profile.definition.id,
    owner: Object.freeze({ ...(owner as unknown as BackgroundJobCompilerContext) }),
    input: parseRiselyProposalInput(root.input),
  });
}

function verifySignedToken(token: string, authority: BackgroundJobAuthoritySigner): void {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("proposal authority token is invalid");
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
  } catch {
    throw new Error("proposal authority token is invalid");
  }
  const kid = (header as { kid?: unknown }).kid;
  const algorithm = (header as { alg?: unknown }).alg;
  const key = authority.jwks().keys.find((candidate) => candidate.kid === kid);
  const now = Math.floor(Date.now() / 1000);
  const claims = payload as { iat?: unknown; exp?: unknown };
  if (
    algorithm !== "RS256" ||
    !key ||
    typeof claims.iat !== "number" ||
    typeof claims.exp !== "number" ||
    claims.iat > now + 30 ||
    claims.exp < now - 30 ||
    !verify(
      "RSA-SHA256",
      Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"),
      createPublicKey({ key: key as JsonWebKey, format: "jwk" }),
      Buffer.from(parts[2]!, "base64url"),
    )
  ) {
    throw new Error("proposal authority token is invalid");
  }
}

function decisionReceipts(
  input: Readonly<RiselyProposalInput>,
  grant: Readonly<BackgroundJobApprovalGrant>,
  authorizedAt: number,
): readonly Readonly<ProposalDecisionReceipt>[] {
  const byEvidence = new Map(input.evidence.map((item) => [item.id, item]));
  return Object.freeze(
    input.sections.map((section) => {
      const sectionSha256 = hash(canonicalJson(section));
      const evidenceSha256 = Object.freeze(section.evidenceRefs.map((id) => byEvidence.get(id)!.sha256));
      const receiptId = `proposal-decision:${hash(
        canonicalJson({
          approvalDigest: grant.digest,
          evidenceSha256,
          proposalId: input.proposalId,
          revision: input.revision,
          sectionKey: section.key,
          sectionSha256,
        }),
      )}`;
      return Object.freeze({
        receiptId,
        proposalId: input.proposalId,
        revision: input.revision,
        sectionKey: section.key,
        sectionSha256,
        evidenceSha256,
        approvalId: grant.approvalId,
        approvalDigest: grant.digest,
        approvalActionTs: grant.actionTs,
        decision: "approved_for_private_compile" as const,
        releaseEligible: false as const,
        decidedAt: new Date(authorizedAt).toISOString(),
      });
    }),
  );
}

function artifactDefinitions(
  input: Readonly<RiselyProposalInput>,
  decisions: readonly Readonly<ProposalDecisionReceipt>[],
): readonly Readonly<ArtifactDefinition>[] {
  return Object.freeze([
    Object.freeze({
      kind: "proposal_pdf",
      name: `${input.proposalId}-r${input.revision}.pdf`,
      mimetype: "application/pdf",
      bytes: renderProposalPdf(input),
    }),
    Object.freeze({
      kind: "proposal_html",
      name: `${input.proposalId}-r${input.revision}.html`,
      mimetype: "text/html",
      bytes: renderProposalHtml(input),
    }),
    Object.freeze({
      kind: "evidence_manifest",
      name: `${input.proposalId}-r${input.revision}-evidence.json`,
      mimetype: "application/json",
      bytes: renderEvidenceManifest(input),
    }),
    Object.freeze({
      kind: "decision_receipts",
      name: `${input.proposalId}-r${input.revision}-decisions.json`,
      mimetype: "application/json",
      bytes: Buffer.from(canonicalJson({ contract: 1, releaseEligible: false, receipts: decisions }), "utf8"),
    }),
    Object.freeze({
      kind: "email_draft",
      name: `${input.proposalId}-r${input.revision}-email-draft.json`,
      mimetype: "application/json",
      bytes: renderEmailDraft(input),
    }),
  ]);
}

async function storeArtifacts(
  profile: Readonly<BackgroundJobDeploymentProfile>,
  files: FileArtifactStore,
  runId: string,
  definitions: readonly Readonly<ArtifactDefinition>[],
  createdAt: number,
): Promise<readonly Readonly<BackgroundJobResultArtifact>[]> {
  const artifacts: BackgroundJobResultArtifact[] = [];
  for (const definition of definitions) {
    const id = hash(`${runId}:${definition.kind}`).slice(0, 32);
    const stored = await files.put({
      id,
      ownerScopeId: profile.profile.audienceScopeId,
      createdBy: profile.profile.actorPrincipalId,
      name: definition.name,
      path: artifactPath(id, definition.name),
      mimetype: definition.mimetype,
      data: definition.bytes,
      direction: "out",
      createdInScope: profile.profile.audienceScopeId,
      createdAt,
      maxBytes: 8 * 1024 * 1024,
    });
    if (stored.artifact.sha256 !== hash(definition.bytes)) throw new Error("proposal artifact hash is invalid");
    artifacts.push(
      Object.freeze({
        kind: definition.kind,
        href: `${profile.origin}/v1/files/${id}/content?viewer=${encodeURIComponent(profile.profile.actorPrincipalId)}`,
        sha256: stored.artifact.sha256,
      }),
    );
  }
  return Object.freeze(artifacts);
}

export function createRiselyProposalAdapter(): BackgroundJobAdapter<
  RiselyProposalInput,
  RiselyProposalStatus,
  RiselyProposalCancellation
> {
  return Object.freeze({
    readiness: () => Object.freeze({ ready: true as const }),
    parseInput: parseRiselyProposalInput,
    async prepare(input: RiselyProposalInput, context: Readonly<BackgroundJobCompilerContext>) {
      const bodyBytes = Buffer.from(
        canonicalJson({ contract: 1, jobId: context.jobId, owner: context, input }),
        "utf8",
      );
      return Object.freeze({
        bodyBytes,
        idempotencyKey: `risely-proposal:${hash(bodyBytes)}`,
      });
    },
    statusView(status: Readonly<RiselyProposalStatus>): Readonly<BackgroundJobStatusView> {
      return Object.freeze({
        state: status.state,
        ...(status.state === "complete" && status.artifacts ? { artifacts: status.artifacts } : {}),
      });
    },
    cancellationState: (cancellation: Readonly<RiselyProposalCancellation>) => cancellation.state,
  });
}

export function createRiselyProposalClient(dependencies: {
  profile: Readonly<BackgroundJobDeploymentProfile>;
  authority: BackgroundJobAuthoritySigner;
  records: DurableMap<RiselyProposalRunRecord>;
  files: FileArtifactStore;
  now?: () => number;
}): BackgroundJobClient<RiselyProposalStatus, RiselyProposalCancellation> {
  const now = dependencies.now ?? Date.now;
  return Object.freeze({
    async start(
      body: Uint8Array,
      grant: Readonly<BackgroundJobApprovalGrant>,
      idempotencyKey: string,
      authorizedAt: number,
    ) {
      const exactBody = Uint8Array.from(body);
      const token = await dependencies.authority.signStart(exactBody, grant, idempotencyKey, authorizedAt);
      verifySignedToken(token, dependencies.authority);
      const prepared = decodePrepared(exactBody, dependencies.profile);
      const runId = `proposal-run:${hash(idempotencyKey).slice(0, 40)}`;
      const existing = await dependencies.records.get(runId);
      if (existing) {
        if (existing.idempotencyKey !== idempotencyKey) throw new Error("proposal idempotency binding changed");
        return Object.freeze({ authorityId: existing.authorityId, runId: existing.runId });
      }
      const decisions = decisionReceipts(prepared.input, grant, authorizedAt);
      const artifacts = await storeArtifacts(
        dependencies.profile,
        dependencies.files,
        runId,
        artifactDefinitions(prepared.input, decisions),
        authorizedAt,
      );
      const authorityId = `proposal-authority:${hash(token).slice(0, 40)}`;
      const record: RiselyProposalRunRecord = Object.freeze({
        runId,
        authorityId,
        idempotencyKey,
        proposalId: prepared.input.proposalId,
        revision: prepared.input.revision,
        state: "complete",
        artifacts,
        decisions,
        releaseEligible: false,
        createdAt: authorizedAt,
        completedAt: now(),
      });
      const retained = await dependencies.records.putIfAbsent(runId, record);
      if (retained.idempotencyKey !== idempotencyKey) throw new Error("proposal idempotency binding changed");
      return Object.freeze({ authorityId: retained.authorityId, runId: retained.runId });
    },
    async status(receipt: Readonly<BackgroundJobReceipt>) {
      const body = Buffer.from(canonicalJson({ authorityId: receipt.authorityId, runId: receipt.runId }), "utf8");
      verifySignedToken(await dependencies.authority.signStatus(body, receipt), dependencies.authority);
      const record = await dependencies.records.get(receipt.runId);
      if (!record || record.authorityId !== receipt.authorityId) throw new Error("proposal run is unavailable");
      return Object.freeze({
        runId: record.runId,
        state: record.state,
        ...(record.state === "complete" ? { artifacts: record.artifacts } : {}),
      });
    },
    async cancel(
      receipt: Readonly<BackgroundJobReceipt>,
      grant: Readonly<BackgroundJobApprovalGrant>,
      authorizedAt: number,
    ) {
      const body = Buffer.from(canonicalJson({ authorityId: receipt.authorityId, runId: receipt.runId }), "utf8");
      verifySignedToken(
        await dependencies.authority.signCancel(body, receipt, grant, authorizedAt),
        dependencies.authority,
      );
      const record = await dependencies.records.get(receipt.runId);
      if (!record || record.authorityId !== receipt.authorityId) throw new Error("proposal run is unavailable");
      if (record.state === "complete") return Object.freeze({ runId: record.runId, state: "cancel_requested" });
      const cancelled = await dependencies.records.merge(record.runId, { state: "cancelled" });
      if (!cancelled) throw new Error("proposal run is unavailable");
      return Object.freeze({ runId: cancelled.runId, state: "cancelled" });
    },
  });
}
