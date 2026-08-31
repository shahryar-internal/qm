import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  GMAIL_COMPOSE_SCOPE,
  GMAIL_DRAFT_BODY_MAX_BYTES,
  GMAIL_DRAFT_RESPONSE_MAX_BYTES,
  gmailDraftEffectPayload,
  sha256Bytes,
  sha256Canonical,
  validateEffectProposal,
} from "../src/gmail-drafts/contracts.ts";
import { buildPlainTextGmailDraftMime } from "../src/gmail-drafts/mime.ts";
import { GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST } from "../src/gmail-drafts/provider-client.ts";
import {
  GMAIL_DRAFT_BROKER_MISSING_PRIVATE_PORTS,
  assertGmailDraftBrokerProductionReady,
  gmailDraftBrokerProductionReadiness,
  gmailDraftBrokerStartupDoctor,
  type GmailDraftPrivateRuntimeDependencies,
} from "../src/gmail-drafts/runtime.ts";
import { GMAIL_TEST_NOW, gmailDraftProposal } from "./gmail-draft-fixture.ts";

test("effect proposal binds exact content, connection, owner DM approval, and current click", () => {
  const proposal = gmailDraftProposal();
  const validated = validateEffectProposal(proposal, GMAIL_TEST_NOW);
  assert.deepEqual(validated, proposal);
  assert(Object.isFrozen(validated));
  assert(Object.isFrozen(validated.approval));
  const mutations: Array<(value: typeof proposal) => void> = [
    (value) => {
      value.bodyText = "substituted";
    },
    (value) => {
      value.to = ["attacker@example.com"];
    },
    (value) => {
      value.logicalConnectionId = "fallback-account";
    },
    (value) => {
      value.googleSubject = "other-google-user";
    },
    (value) => {
      value.grantedScopes = ["https://mail.google.com/"] as unknown as [typeof GMAIL_COMPOSE_SCOPE];
    },
    (value) => {
      value.approval.actorPrincipalId = "other-owner";
    },
    (value) => {
      value.approval.channelId = "C12345678";
    },
    (value) => {
      value.approval.actionTs = "1799999000.000001";
    },
    (value) => {
      value.approval.messageTs = "1800000000.000003";
    },
    (value) => {
      value.approval.threadTs = "1800000000.000003";
    },
    (value) => {
      value.approval.approvedPayloadSha256 = "0".repeat(64);
    },
  ];
  for (const mutate of mutations) {
    const candidate = gmailDraftProposal();
    mutate(candidate);
    assert.throws(() => validateEffectProposal(candidate, GMAIL_TEST_NOW));
  }
  assert.throws(() => validateEffectProposal(gmailDraftProposal(), GMAIL_TEST_NOW + 120_000));
});

test("effect proposal rejects payload substitution even after a caller recomputes the outer effect hash", () => {
  const candidate = gmailDraftProposal();
  candidate.bodyText = "FORGED BODY";
  candidate.effectPayloadSha256 = sha256Canonical(gmailDraftEffectPayload(candidate));
  candidate.approval.approvedPayloadSha256 = candidate.effectPayloadSha256;
  assert.throws(() => validateEffectProposal(candidate, GMAIL_TEST_NOW), /content hash mismatch/u);
});

test("plain text MIME is deterministic, bounded, header-safe, and carries no hidden recipient", () => {
  const proposal = gmailDraftProposal({ subject: "Résumé follow-up", bodyText: "Hello\nLine two" });
  const first = buildPlainTextGmailDraftMime(validateEffectProposal(proposal, GMAIL_TEST_NOW));
  const second = buildPlainTextGmailDraftMime(validateEffectProposal(proposal, GMAIL_TEST_NOW));
  assert.deepEqual(first, second);
  assert.match(first.mimeSource, /^From: owner@example\.com\r\nTo: recipient@example\.edu\r\n/u);
  assert.match(first.mimeSource, /Subject: =\?UTF-8\?B\?/u);
  assert.match(first.markerMessageId, /^<qm\.[a-f0-9]{64}@drafts\.invalid>$/u);
  assert(!/\nBcc:/iu.test(first.mimeSource));
  assert(!/\nCc:/iu.test(first.mimeSource));
  for (const line of first.mimeSource.split("\r\n")) assert(Buffer.byteLength(line, "utf8") <= 998);
  const parsed = JSON.parse(first.requestBody) as { message: { raw: string } };
  assert.equal(Buffer.from(parsed.message.raw, "base64url").toString("utf8"), first.mimeSource);
});

test("long Unicode MIME subjects use codepoint-safe RFC 2047 words and folded lines", () => {
  for (const subject of ["é".repeat(100), "Launch 🚀 résumé ".repeat(14), "=?UTF-8?B?QXR0YWNr?="]) {
    const proposal = gmailDraftProposal({ subject });
    const mime = buildPlainTextGmailDraftMime(validateEffectProposal(proposal, GMAIL_TEST_NOW));
    const lines = mime.mimeSource.split("\r\n");
    const start = lines.findIndex((line) => line.startsWith("Subject: "));
    const subjectLines = lines.slice(
      start,
      lines.findIndex((line, index) => index > start && !line.startsWith(" ")),
    );
    const words = subjectLines.flatMap((line) => line.match(/=\?UTF-8\?B\?[^?]+\?=/gu) ?? []);
    assert(words.length > 0);
    assert(words.every((word) => word.length <= 75));
    assert(subjectLines.every((line) => Buffer.byteLength(line, "utf8") <= 76));
    assert.equal(
      words.map((word) => Buffer.from(word.slice("=?UTF-8?B?".length, -2), "base64").toString("utf8")).join(""),
      subject,
    );
  }
});

test("MIME rejects header injection and binds update draft and thread IDs", () => {
  assert.throws(() => buildPlainTextGmailDraftMime(gmailDraftProposal({ subject: "hello\r\nBcc: x@example.com" })));
  assert.throws(() => buildPlainTextGmailDraftMime(gmailDraftProposal({ to: ["x@example.com\r\nBcc:y@example.com"] })));
  const proposal = gmailDraftProposal({
    operation: "update",
    draftRevision: 2,
    draftId: "draft_1",
    priorDraftReceiptSha256: "a".repeat(64),
    gmailThreadId: "thread_1",
    replyAuthority: {
      contractType: "qm-gmail-draft-reply-authority",
      contractVersion: 1,
      sourceReceiptSha256: sha256Bytes("thread-source"),
      gmailThreadId: "thread_1",
      parentMessageId: "<message@example.com>",
      referenceMessageIds: ["<earlier@example.com>", "<message@example.com>"],
      subjectSha256: sha256Bytes("Next steps from our working session"),
    },
    sourceReceiptSha256s: [sha256Bytes("meeting-receipt"), sha256Bytes("thread-source")],
  });
  const mime = buildPlainTextGmailDraftMime(validateEffectProposal(proposal, GMAIL_TEST_NOW));
  const request = JSON.parse(mime.requestBody) as { id: string; message: { threadId: string } };
  assert.equal(request.id, "draft_1");
  assert.equal(request.message.threadId, "thread_1");
  assert.match(mime.mimeSource, /In-Reply-To: <message@example\.com>/u);
  assert.match(mime.mimeSource, /References: <earlier@example\.com> <message@example\.com>/u);
});

test("exported MIME builder independently rejects reply header injection", () => {
  const sourceReceiptSha256 = sha256Bytes("thread-source");
  const replyAuthority = {
    contractType: "qm-gmail-draft-reply-authority" as const,
    contractVersion: 1 as const,
    sourceReceiptSha256,
    gmailThreadId: "thread_1",
    parentMessageId: "<message@example.com>",
    referenceMessageIds: ["<message@example.com>"] as readonly string[],
    subjectSha256: sha256Bytes("Next steps from our working session"),
  };
  for (const injected of [
    { ...replyAuthority, parentMessageId: "<message@example.com>\n" },
    {
      ...replyAuthority,
      referenceMessageIds: ["<message@example.com>\r\nBcc: attacker@example.com"],
    },
  ]) {
    const proposal = gmailDraftProposal({
      gmailThreadId: "thread_1",
      replyAuthority: injected,
      sourceReceiptSha256s: [sourceReceiptSha256],
    });
    assert.throws(() => buildPlainTextGmailDraftMime(proposal), /invalid/u);
  }
});

test("thread contracts reject missing parent references, detached references, and prior-subject mismatch", () => {
  const source = sha256Bytes("thread-source");
  assert.throws(() =>
    validateEffectProposal(
      gmailDraftProposal({
        gmailThreadId: "thread_1",
        replyAuthority: {
          contractType: "qm-gmail-draft-reply-authority",
          contractVersion: 1,
          sourceReceiptSha256: source,
          gmailThreadId: "thread_1",
          parentMessageId: "<message@example.com>",
          referenceMessageIds: [],
          subjectSha256: sha256Bytes("Next steps from our working session"),
        },
        sourceReceiptSha256s: [sha256Bytes("meeting-receipt"), source],
      }),
      GMAIL_TEST_NOW,
    ),
  );
  assert.throws(() => validateEffectProposal(gmailDraftProposal({ gmailThreadId: "thread_1" }), GMAIL_TEST_NOW));
  assert.throws(() =>
    validateEffectProposal(
      gmailDraftProposal({
        gmailThreadId: "thread_1",
        replyAuthority: {
          contractType: "qm-gmail-draft-reply-authority",
          contractVersion: 1,
          sourceReceiptSha256: source,
          gmailThreadId: "thread_1",
          parentMessageId: "<message@example.com>",
          referenceMessageIds: ["<message@example.com>", "<unrelated@example.com>"],
          subjectSha256: sha256Bytes("Next steps from our working session"),
        },
        sourceReceiptSha256s: [sha256Bytes("meeting-receipt"), source],
      }),
      GMAIL_TEST_NOW,
    ),
  );
  assert.throws(() =>
    validateEffectProposal(
      gmailDraftProposal({
        gmailThreadId: "thread_1",
        replyAuthority: {
          contractType: "qm-gmail-draft-reply-authority",
          contractVersion: 1,
          sourceReceiptSha256: source,
          gmailThreadId: "thread_1",
          parentMessageId: "<message@example.com>",
          referenceMessageIds: ["<message@example.com>"],
          subjectSha256: sha256Bytes("different subject"),
        },
        sourceReceiptSha256s: [sha256Bytes("meeting-receipt"), source],
      }),
      GMAIL_TEST_NOW,
    ),
  );
});

test("provider thread binding on update does not invent reply headers without reply authority", () => {
  const proposal = gmailDraftProposal({
    operation: "update",
    draftRevision: 2,
    draftId: "draft_1",
    priorDraftReceiptSha256: "a".repeat(64),
    gmailThreadId: "thread_1",
    replyAuthority: null,
  });
  const mime = buildPlainTextGmailDraftMime(validateEffectProposal(proposal, GMAIL_TEST_NOW));
  const request = JSON.parse(mime.requestBody) as { message: { threadId: string } };
  assert.equal(request.message.threadId, "thread_1");
  assert(!mime.mimeSource.includes("In-Reply-To:"));
  assert(!mime.mimeSource.includes("References:"));
});

test("largest accepted body produces a raw reconciliation payload below the response cap", () => {
  const proposal = gmailDraftProposal({ bodyText: "x".repeat(GMAIL_DRAFT_BODY_MAX_BYTES) });
  const mime = buildPlainTextGmailDraftMime(validateEffectProposal(proposal, GMAIL_TEST_NOW));
  const responseBytes = Buffer.byteLength(
    JSON.stringify({
      id: "draft_1",
      message: { id: "message_1", raw: mime.raw },
    }),
    "utf8",
  );
  assert(responseBytes < GMAIL_DRAFT_RESPONSE_MAX_BYTES);
  assert.throws(() =>
    validateEffectProposal(
      gmailDraftProposal({ bodyText: "x".repeat(GMAIL_DRAFT_BODY_MAX_BYTES + 1) }),
      GMAIL_TEST_NOW,
    ),
  );
});

test("public runtime stays inert until every private port is present", async () => {
  assert.deepEqual(GMAIL_DRAFT_BROKER_MISSING_PRIVATE_PORTS, [
    "private_gmail_draft_owner_dm_approval_signer",
    "private_gmail_draft_thread_source_verifier",
    "private_verified_slack_owner_dm_approval_store",
    "private_gmail_oauth_connection_credential_adapter",
    "private_gmail_draft_intent_cipher",
    "private_gmail_draft_owner_dm_publisher",
    "private_gmail_draft_review_route",
  ]);
  assert.equal(gmailDraftBrokerProductionReadiness().ready, false);
  assert.equal((await gmailDraftBrokerStartupDoctor()).ready, false);
  assert.throws(() => assertGmailDraftBrokerProductionReady(), /disabled/u);
});

function privateRuntimeDependencies(
  options: {
    admissionDoctor?: () => Promise<unknown>;
    executionDoctor?: () => Promise<unknown>;
    approvalSignerReadiness?: () => unknown;
    executionReadiness?: () => unknown;
  } = {},
): GmailDraftPrivateRuntimeDependencies {
  const ready = () => ({ ready: true as const });
  const admissionDoctor =
    options.admissionDoctor ??
    (async () => ({
      ready: true,
      provider: "postgresql",
      providerMajorVersion: 16,
      schema: "gmail_draft_broker",
      runtimeRole: "qm_gmail_draft_admission",
    }));
  const executionDoctor =
    options.executionDoctor ??
    (async () => ({
      ready: true,
      provider: "postgresql",
      providerMajorVersion: 16,
      schema: "gmail_draft_broker",
      runtimeRole: "qm_gmail_draft_broker",
    }));
  return {
    approvalSigner: {
      boundary: "private_gmail_draft_owner_dm_approval_signer",
      readiness: options.approvalSignerReadiness ?? ready,
      verifyCurrentClickAndSeal: async () => null,
    },
    threadSourceVerifier: {
      boundary: "private_gmail_draft_thread_source_verifier",
      readiness: ready,
      verifyAndNormalize: async () => null,
    },
    approvalAdmission: {
      boundary: "private_verified_slack_owner_dm_approval_store",
      durability: "postgres",
      readiness: ready,
      startupDoctor: admissionDoctor,
      admitOwnerSlackBinding: async () => ({ status: "rejected", code: "approval_invalid" }),
      admitThreadSource: async () => ({ status: "rejected", code: "approval_invalid" }),
      admit: async () => ({ status: "rejected", code: "approval_invalid" }),
    },
    credentials: {
      boundary: "private_gmail_draft_broker_only",
      transportAllowlist: GMAIL_DRAFT_PRIVATE_TRANSPORT_ALLOWLIST,
      readiness: ready,
      request: async () => ({ status: "connection_unavailable" }),
      refreshAfterUnauthorized: async () => ({ status: "connection_unavailable" }),
    },
    intentCipher: {
      boundary: "private_gmail_draft_intent_cipher",
      readiness: ready,
      open: async () => "{}",
    },
    ownerDmPublisher: {
      boundary: "private_gmail_draft_owner_dm_publisher",
      readiness: ready,
      publish: async () => ({ publicationId: "publication-1" }),
    },
    reviewRoute: {
      boundary: "private_gmail_draft_review_route",
      readiness: ready,
      issue: async () => {
        throw new Error("not exercised");
      },
    },
    executionStore: {
      readiness: options.executionReadiness ?? ready,
      startupDoctor: executionDoctor,
    },
  } as unknown as GmailDraftPrivateRuntimeDependencies;
}

test("aggregate startup doctor strictly validates both database attestations", async () => {
  let admissionCalls = 0;
  let executionCalls = 0;
  assert.equal(
    (
      await gmailDraftBrokerStartupDoctor(
        privateRuntimeDependencies({
          admissionDoctor: async () => {
            admissionCalls += 1;
            return {
              ready: true,
              provider: "postgresql",
              providerMajorVersion: 16,
              schema: "gmail_draft_broker",
              runtimeRole: "qm_gmail_draft_admission",
            };
          },
          executionDoctor: async () => {
            executionCalls += 1;
            return {
              ready: true,
              provider: "postgresql",
              providerMajorVersion: 16,
              schema: "gmail_draft_broker",
              runtimeRole: "qm_gmail_draft_broker",
            };
          },
        }),
      )
    ).ready,
    true,
  );
  assert.equal(admissionCalls, 1);
  assert.equal(executionCalls, 1);
  const admission = {
    ready: true,
    provider: "postgresql",
    providerMajorVersion: 16,
    schema: "gmail_draft_broker",
    runtimeRole: "qm_gmail_draft_admission",
  };
  const execution = { ...admission, runtimeRole: "qm_gmail_draft_broker" };
  const invalid = [
    { admissionDoctor: async () => ({ ready: true }) },
    { admissionDoctor: async () => ({ ...admission, provider: "postgres" }) },
    { admissionDoctor: async () => ({ ...admission, providerMajorVersion: 15 }) },
    { admissionDoctor: async () => ({ ...admission, schema: "public" }) },
    { admissionDoctor: async () => ({ ...admission, runtimeRole: "qm_gmail_draft_broker" }) },
    { executionDoctor: async () => ({ ...execution, runtimeRole: "qm_gmail_draft_admission" }) },
    { executionDoctor: async () => ({ ...execution, extra: true }) },
  ];
  for (const options of invalid) {
    assert.equal((await gmailDraftBrokerStartupDoctor(privateRuntimeDependencies(options))).ready, false);
  }
});

test("aggregate startup doctor never substitutes synchronous readiness for a missing mandatory doctor", async () => {
  const dependencies = privateRuntimeDependencies();
  Reflect.deleteProperty(dependencies.approvalAdmission, "startupDoctor");
  assert.equal(gmailDraftBrokerProductionReadiness(dependencies).ready, true);
  assert.deepEqual(await gmailDraftBrokerStartupDoctor(dependencies), {
    ready: false,
    reason: "missing:approvalAdmission.startupDoctor",
  });
  const missingExecutionDoctor = privateRuntimeDependencies();
  Reflect.deleteProperty(missingExecutionDoctor.executionStore, "startupDoctor");
  assert.deepEqual(await gmailDraftBrokerStartupDoctor(missingExecutionDoctor), {
    ready: false,
    reason: "missing:executionStore.startupDoctor",
  });
});

test("aggregate parsers reject comma-collision keys backed by inherited attestation fields", async () => {
  const forgedDoctor = Object.create({
    ready: true,
    provider: "postgresql",
    providerMajorVersion: 16,
    schema: "gmail_draft_broker",
    runtimeRole: "qm_gmail_draft_admission",
  }) as Record<string, unknown>;
  Object.defineProperty(forgedDoctor, "provider,providerMajorVersion,ready,runtimeRole,schema", {
    enumerable: true,
    value: true,
  });
  assert.equal(
    (await gmailDraftBrokerStartupDoctor(privateRuntimeDependencies({ admissionDoctor: async () => forgedDoctor })))
      .ready,
    false,
  );
  const forgedReadiness = Object.create({ ready: false, reason: "forged ready state" }) as Record<string, unknown>;
  Object.defineProperty(forgedReadiness, "ready,reason", { enumerable: true, value: true });
  assert.equal(
    gmailDraftBrokerProductionReadiness(privateRuntimeDependencies({ approvalSignerReadiness: () => forgedReadiness }))
      .ready,
    false,
  );
});

test("aggregate readiness contains thrown and malformed private dependencies", async () => {
  assert.equal(
    gmailDraftBrokerProductionReadiness(
      privateRuntimeDependencies({ approvalSignerReadiness: () => ({ ready: true, extra: true }) }),
    ).ready,
    false,
  );
  assert.equal(
    gmailDraftBrokerProductionReadiness(
      privateRuntimeDependencies({
        executionReadiness: () => {
          throw new Error("secret database failure");
        },
      }),
    ).ready,
    false,
  );
  let executionCalls = 0;
  assert.equal(
    (
      await gmailDraftBrokerStartupDoctor(
        privateRuntimeDependencies({
          admissionDoctor: async () => {
            throw new Error("secret database failure");
          },
          executionDoctor: async () => {
            executionCalls += 1;
            return {
              ready: true,
              provider: "postgresql",
              providerMajorVersion: 16,
              schema: "gmail_draft_broker",
              runtimeRole: "qm_gmail_draft_broker",
            };
          },
        }),
      )
    ).ready,
    false,
  );
  assert.equal(executionCalls, 1);
  const throwingDependencies = new Proxy(
    {},
    {
      get() {
        throw new Error("secret dependency failure");
      },
    },
  ) as GmailDraftPrivateRuntimeDependencies;
  assert.equal(gmailDraftBrokerProductionReadiness(throwingDependencies).ready, false);
  assert.equal((await gmailDraftBrokerStartupDoctor(throwingDependencies)).ready, false);
});

test("Gmail draft core has no provider send surface or generic credential dependency", async () => {
  const sourceRoot = fileURLToPath(new URL("../src/gmail-drafts/", import.meta.url));
  const files = [
    "contracts.ts",
    "mime.ts",
    "provider-client.ts",
    "broker.ts",
    "card.ts",
    "runtime.ts",
    "postgres-store.ts",
  ];
  const source = (await Promise.all(files.map((file) => readFile(`${sourceRoot}${file}`, "utf8")))).join("\n");
  const sendPath = ["drafts", "send"].join("/");
  const sendCapability = ["gmail", "send"].join(".");
  const genericTokenStore = ["Connector", "TokenStore"].join("");
  const rawTokenField = ["access", "Token"].join("");
  assert(!source.includes(sendPath));
  assert(!source.includes(sendCapability));
  assert(!source.includes(genericTokenStore));
  assert(!source.includes(rawTokenField));
  assert(!source.includes("messages/"));
  assert(!source.includes("sandbox"));
  assert(!source.includes("skill"));
});

test("runtime performs no DDL and additive migration separates admission from mutation authority", async () => {
  const storeSource = await readFile(
    fileURLToPath(new URL("../src/gmail-drafts/postgres-store.ts", import.meta.url)),
    "utf8",
  );
  const migration = await readFile(
    fileURLToPath(new URL("../src/gmail-drafts/migration.sql", import.meta.url)),
    "utf8",
  );
  const migrationChecksum = await readFile(
    fileURLToPath(new URL("../src/gmail-drafts/migration.sha256", import.meta.url)),
    "utf8",
  );
  const runtimeRoleBindings = await readFile(
    fileURLToPath(new URL("../src/gmail-drafts/runtime-role-bindings.sql", import.meta.url)),
    "utf8",
  );
  const operations = await readFile(
    fileURLToPath(new URL("../src/gmail-drafts/OPERATIONS.md", import.meta.url)),
    "utf8",
  );
  assert.equal(migrationChecksum.trim(), sha256Bytes(migration));
  assert(!/CREATE\s+(?:TABLE|SCHEMA|ROLE|FUNCTION)/iu.test(storeSource));
  assert(storeSource.includes("createPgPool(options.connectionString, [])"));
  assert(migration.startsWith("BEGIN;\n"));
  assert(migration.endsWith("COMMIT;\n"));
  assert(migration.includes("CREATE TABLE IF NOT EXISTS gmail_draft_broker.approved_intents"));
  assert(migration.includes("approval_jti TEXT NOT NULL UNIQUE"));
  assert(migration.includes("SECURITY DEFINER"));
  assert(migration.includes("SET search_path = pg_catalog, gmail_draft_broker"));
  assert(migration.includes("ALTER SCHEMA gmail_draft_broker OWNER TO qm_gmail_draft_owner"));
  assert(migration.includes("REVOKE ALL ON ALL TABLES IN SCHEMA gmail_draft_broker FROM PUBLIC"));
  assert(migration.includes("TO qm_gmail_draft_admission"));
  assert(migration.includes("TO qm_gmail_draft_broker"));
  const grants = [
    ...migration.matchAll(
      /GRANT EXECUTE ON FUNCTION gmail_draft_broker\.([a-z_]+)\([^;]+ TO (qm_gmail_draft_[a-z]+);/gu,
    ),
  ];
  assert.deepEqual(
    grants.filter((entry) => entry[2] === "qm_gmail_draft_admission").map((entry) => entry[1]),
    ["admit_owner_slack_binding", "admit_thread_source", "admit_intent"],
  );
  assert.deepEqual(
    grants.filter((entry) => entry[2] === "qm_gmail_draft_broker").map((entry) => entry[1]),
    [
      "claim_effect",
      "claim_reconciliation",
      "arm_effect",
      "record_created",
      "record_unknown",
      "retain_unknown",
      "reject_before_effect",
      "reject_definitive_no_write",
    ],
  );
  assert.equal((migration.match(/SECURITY DEFINER/gu) ?? []).length, 11);
  assert.equal((migration.match(/SET search_path = pg_catalog, gmail_draft_broker/gu) ?? []).length, 11);
  assert(migration.includes(") ON CONFLICT DO NOTHING"));
  assert(migration.includes("WHERE effect_proposal_id = p_effect_proposal_id FOR UPDATE"));
  assert(migration.includes("AND attempt_id = p_attempt_id AND status = 'pre_effect'"));
  assert(migration.includes("CREATE TABLE IF NOT EXISTS gmail_draft_broker.active_lineage_claims"));
  assert(migration.includes("DELETE FROM gmail_draft_broker.active_lineage_claims claim USING changed"));
  assert(!migration.includes("gmail_draft_one_child_per_receipt_idx"));
  assert(migration.includes("prior.terminal_receipt_sha256 = p_prior_draft_receipt_sha256"));
  assert(!migration.includes("lineage_consumed_by_effect_proposal_id"));
  const rejectBefore = migration.slice(
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.reject_before_effect"),
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.reject_definitive_no_write"),
  );
  const rejectDefinitive = migration.slice(
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.reject_definitive_no_write"),
    migration.indexOf("INSERT INTO gmail_draft_broker.migration_versions"),
  );
  assert(rejectBefore.includes("attempt_id = p_attempt_id AND status = 'pre_effect'"));
  assert(!rejectBefore.includes("status = 'effect_started'"));
  assert(rejectDefinitive.includes("attempt_id = p_attempt_id AND status = 'effect_started'"));
  assert(!rejectDefinitive.includes("status = 'unknown'"));
  const preflightAt = migration.indexOf("DO $preflight$");
  const schemaCreateAt = migration.indexOf("CREATE SCHEMA IF NOT EXISTS gmail_draft_broker");
  assert(preflightAt > 0 && preflightAt < schemaCreateAt);
  assert(migration.includes("preexisting Gmail draft schema is not versioned"));
  assert(migration.includes("preexisting Gmail draft schema has unexpected indexes"));
  assert(migration.includes("trigger.tgisinternal IS FALSE"));
  assert(migration.includes("gmail-draft-broker-active-lineage-v1"));
  assert(migration.includes("gmail-draft-broker-reconciliation-fence-v2"));
  assert(migration.includes("ADD COLUMN IF NOT EXISTS reconciliation_nonce TEXT"));
  assert(migration.includes("LOCK TABLE gmail_draft_broker.approved_intents IN ACCESS EXCLUSIVE MODE"));
  assert(migration.includes("source.reference_message_ids = p_reply_reference_message_ids"));
  assert(migration.includes("terminal_receipt_sha256 TEXT"));
  assert(!migration.includes("terminal_receipt JSONB"));
  assert(!migration.includes("p_receipt JSONB"));
  assert(!storeSource.includes("JSON.stringify(receipt)"));
  assert(migration.includes("approval_expires_at > (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT"));
  const bindingAdmission = migration.slice(
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.admit_owner_slack_binding"),
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.admit_thread_source"),
  );
  assert(bindingAdmission.includes("owner_slack_bindings.issued_at < EXCLUDED.issued_at"));
  assert(bindingAdmission.includes("IF v_changed THEN RETURN 'admitted'; END IF"));
  assert(bindingAdmission.includes("v_existing.issued_at = p_issued_at"));
  const intentAdmission = migration.slice(
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.admit_intent"),
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.claim_effect"),
  );
  assert(intentAdmission.includes("v_active_child_row.status NOT IN ('approved','pre_effect')"));
  assert(intentAdmission.includes("v_active_child_row.approval_expires_at > v_now"));
  assert(!intentAdmission.includes("v_active_child_row.status IN ('effect_started','unknown')"));
  const claimReconciliation = migration.slice(
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.claim_reconciliation"),
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.arm_effect"),
  );
  assert(claimReconciliation.includes("reconciliation_nonce = pg_catalog.gen_random_uuid()::TEXT"));
  assert(claimReconciliation.includes("'_claimAcquired', v_claim_acquired"));
  const recordCreated = migration.slice(
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.record_created"),
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.record_unknown"),
  );
  assert(recordCreated.includes("reconciliation_nonce = p_reconciliation_nonce"));
  assert(
    recordCreated.includes("claim_expires_at > (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT"),
  );
  const retainUnknown = migration.slice(
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.retain_unknown"),
    migration.indexOf("CREATE OR REPLACE FUNCTION gmail_draft_broker.reject_before_effect"),
  );
  assert(retainUnknown.includes("reconciliation_nonce = p_reconciliation_nonce"));
  assert(migration.includes("v_role.rolinherit"));
  assert(migration.includes("membership.admin_option"));
  assert(migration.includes("membership.inherit_option"));
  assert(migration.includes("membership.set_option"));
  assert(migration.includes("requires PostgreSQL 16 membership semantics"));
  assert(migration.includes("preexisting Gmail draft schema has privilege drift"));
  assert(migration.includes("attribute.attacl"));
  assert(migration.includes("REVOKE ALL (%s) ON TABLE %I.%I"));
  assert(migration.includes("REVOKE ALL ON TYPE %I.%I"));
  assert(migration.includes("REVOKE USAGE ON TYPES FROM PUBLIC"));
  assert(migration.includes("defaults.defaclnamespace = 0"));
  assert(migration.includes("database_record.datacl"));
  assert(migration.includes("type_record.typacl"));
  assert(migration.includes("relation.relpersistence <> 'p'"));
  assert(migration.includes("trigger.tgenabled <> 'O'"));
  assert(migration.includes("constraint_record.contype IS DISTINCT FROM 'f'"));
  assert(migration.includes("trigger.tgtype = 17"));
  assert(migration.includes("DO $catalog_postflight$"));
  assert(migration.includes("SELECT pg_temp.assert_gmail_draft_definitions(FALSE)"));
  assert(migration.includes("IN ACCESS EXCLUSIVE MODE"));
  assert(migration.includes("CREATE TEMPORARY TABLE approved_intents"));
  assert(migration.includes("preexisting Gmail draft schema has unexpected table columns"));
  assert(migration.includes("preexisting Gmail draft schema has unexpected constraints"));
  assert(migration.includes("preexisting Gmail draft schema has unexpected index definitions"));
  assert(migration.includes("Gmail draft routines do not match the authoritative definitions"));
  assert(runtimeRoleBindings.includes("REVOKE %I FROM %I CASCADE"));
  assert(runtimeRoleBindings.includes("GRANT qm_gmail_draft_owner TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"));
  assert(
    runtimeRoleBindings.includes("GRANT qm_gmail_draft_admission TO %I WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"),
  );
  assert(runtimeRoleBindings.includes("GRANT qm_gmail_draft_broker TO %I WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"));
  assert(runtimeRoleBindings.includes("membership.admin_option"));
  assert(runtimeRoleBindings.includes("membership.inherit_option"));
  assert(runtimeRoleBindings.includes("membership.set_option"));
  assert(runtimeRoleBindings.includes("gmail_draft_broker.owner_login_role"));
  assert(runtimeRoleBindings.includes("attribute.attacl"));
  assert(runtimeRoleBindings.includes("defaults.defaclnamespace = 0"));
  assert(runtimeRoleBindings.includes("database_record.datacl"));
  assert(runtimeRoleBindings.includes("type_record.typacl"));
  assert(runtimeRoleBindings.includes("relation.relpersistence <> 'p'"));
  assert(runtimeRoleBindings.includes("trigger.tgenabled <> 'O'"));
  assert(runtimeRoleBindings.includes("trigger.tgtype = 17"));
  assert(runtimeRoleBindings.includes("DO $binding_catalog_postflight$"));
  assert(operations.includes("drain all admission, broker, and reconciliation workers"));
  assert(operations.includes("PostgreSQL 16 is the only supported major version"));
  assert(operations.includes("ADMIN FALSE, INHERIT FALSE, SET TRUE"));
  assert(operations.includes("exact `gmail-draft-broker-active-lineage-v1` predecessor"));
  assert(storeSource.includes('terminalUnknownPolicy: "reconcile_only_no_automatic_mutation_retry"'));
});
