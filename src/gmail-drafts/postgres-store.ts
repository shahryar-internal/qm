import { createPgPool, type PgPool } from "../persistence/pg-pool.ts";
import {
  assertIdentifier,
  assertProviderIdentifier,
  assertSha256,
  gmailDraftReceiptDigest,
  normalizedMailbox,
  sha256Canonical,
  validateEffectProposal,
  type GmailDraftAttempt,
  type GmailDraftBeginResult,
  type GmailDraftEffectProposal,
  type GmailDraftExecutionStore,
  type GmailDraftNoWriteRejectionProof,
  type GmailDraftReceipt,
  type GmailDraftReconcileBeginResult,
  type GmailDraftReconciliationLease,
  type GmailDraftRejectionCode,
  type GmailDraftUnknownReceipt,
} from "./contracts.ts";

export const GMAIL_DRAFT_SCHEMA = "gmail_draft_broker";
export const GMAIL_DRAFT_APPROVED_INTENT_TABLE = `${GMAIL_DRAFT_SCHEMA}.approved_intents`;

type GmailDraftPostgresRuntimeRole = "qm_gmail_draft_admission" | "qm_gmail_draft_broker";
export type GmailDraftPostgresStartupDoctorResult =
  | Readonly<{
      ready: true;
      provider: "postgresql";
      providerMajorVersion: 16;
      schema: typeof GMAIL_DRAFT_SCHEMA;
      runtimeRole: GmailDraftPostgresRuntimeRole;
    }>
  | Readonly<{ ready: false; reason: string }>;

const GMAIL_DRAFT_ADMISSION_ROUTINES = Object.freeze([
  "admit_owner_slack_binding",
  "admit_thread_source",
  "admit_intent",
] as const);
const GMAIL_DRAFT_EXECUTION_ROUTINES = Object.freeze([
  "claim_effect",
  "claim_reconciliation",
  "arm_effect",
  "record_created",
  "record_unknown",
  "retain_unknown",
  "reject_before_effect",
  "reject_definitive_no_write",
] as const);
const GMAIL_DRAFT_ROUTINE_SIGNATURES = Object.freeze([
  "gmail_draft_broker.admit_owner_slack_binding(text,text,text,text,text,text,text,text,bigint,bigint,text,text)",
  "gmail_draft_broker.admit_thread_source(text,text,text,text,text,text,text,integer,text,text,text,text,text[],text,bigint,bigint,text,text)",
  "gmail_draft_broker.admit_intent(text,integer,integer,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,text,integer,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text[],text,jsonb)",
  "gmail_draft_broker.claim_effect(text,integer)",
  "gmail_draft_broker.claim_reconciliation(text,integer)",
  "gmail_draft_broker.arm_effect(text,integer,text,text,text,text,text,bigint)",
  "gmail_draft_broker.record_created(text,integer,text,text,text,text,text,text,text,text,text,bigint,boolean,text)",
  "gmail_draft_broker.record_unknown(text,integer,text,text,text,text,text,bigint)",
  "gmail_draft_broker.retain_unknown(text,integer,text,text,text,text,text,bigint,text)",
  "gmail_draft_broker.reject_before_effect(text,integer,text,text)",
  "gmail_draft_broker.reject_definitive_no_write(text,integer,text,text)",
] as const);

const GMAIL_DRAFT_POSTGRES_ATTESTATION_SQL = `WITH current_login AS (
  SELECT role.oid, role.rolcanlogin, role.rolinherit, role.rolsuper, role.rolcreaterole,
    role.rolcreatedb, role.rolreplication, role.rolbypassrls
  FROM pg_catalog.pg_roles role
  WHERE role.rolname = CURRENT_USER
), direct_memberships AS (
  SELECT granted.rolname, membership.admin_option, membership.inherit_option, membership.set_option
  FROM current_login login
  JOIN pg_catalog.pg_auth_members membership ON membership.member = login.oid
  JOIN pg_catalog.pg_roles granted ON granted.oid = membership.roleid
), protected_memberships AS (
  SELECT granted.rolname AS granted_role, granted.rolcanlogin AS granted_canlogin,
    granted.rolinherit AS granted_inherit, granted.rolsuper AS granted_super,
    granted.rolcreaterole AS granted_createrole, granted.rolcreatedb AS granted_createdb,
    granted.rolreplication AS granted_replication, granted.rolbypassrls AS granted_bypassrls,
    member.oid AS member_oid, member.rolcanlogin, member.rolinherit,
    member.rolsuper, member.rolcreaterole, member.rolcreatedb, member.rolreplication, member.rolbypassrls,
    membership.admin_option, membership.inherit_option, membership.set_option
  FROM pg_catalog.pg_auth_members membership
  JOIN pg_catalog.pg_roles granted ON granted.oid = membership.roleid
  JOIN pg_catalog.pg_roles member ON member.oid = membership.member
  WHERE granted.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
), schema_routines AS (
  SELECT routine.oid, routine.proname
  FROM pg_catalog.pg_proc routine
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
  WHERE namespace.nspname = 'gmail_draft_broker'
), schema_relations AS (
  SELECT relation.oid, relation.relname, relation.relkind, relation.relpersistence, owner.rolname AS owner_name
  FROM pg_catalog.pg_class relation
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
  JOIN pg_catalog.pg_roles owner ON owner.oid = relation.relowner
  WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind IN ('r','p','v','m','f','S')
)
SELECT
  CURRENT_USER = SESSION_USER AS session_identity_exact,
  pg_catalog.current_setting('server_version_num')::INTEGER BETWEEN 160000 AND 169999 AS provider_exact,
  (SELECT count(*) = 1 AND pg_catalog.bool_and(rolcanlogin AND rolinherit AND NOT rolsuper
    AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls)
    FROM current_login) AS login_posture_exact,
  (SELECT count(*) = 1 AND pg_catalog.bool_and(rolname = $1 AND NOT admin_option
    AND inherit_option AND NOT set_option) FROM direct_memberships) AS membership_exact,
  (SELECT count(*) = 3 AND count(DISTINCT granted_role) = 3 AND count(DISTINCT member_oid) = 3
    AND pg_catalog.bool_and(NOT granted_canlogin AND NOT granted_inherit AND NOT granted_super
      AND NOT granted_createrole AND NOT granted_createdb AND NOT granted_replication
      AND NOT granted_bypassrls AND rolcanlogin AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb
      AND NOT rolreplication AND NOT rolbypassrls AND NOT admin_option
      AND ((granted_role = 'qm_gmail_draft_owner' AND NOT rolinherit AND NOT inherit_option AND set_option)
        OR (granted_role IN ('qm_gmail_draft_admission','qm_gmail_draft_broker')
          AND rolinherit AND inherit_option AND NOT set_option)))
    AND NOT EXISTS (SELECT 1 FROM protected_memberships protected
      JOIN pg_catalog.pg_auth_members other ON other.member = protected.member_oid
      WHERE other.roleid NOT IN (SELECT expected.oid FROM pg_catalog.pg_roles expected
        WHERE expected.rolname = protected.granted_role))
    AND NOT EXISTS (SELECT 1 FROM protected_memberships protected
      JOIN pg_catalog.pg_auth_members nested ON nested.roleid = protected.member_oid)
    AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members nested
      JOIN pg_catalog.pg_roles protected_role ON protected_role.oid = nested.member
      WHERE protected_role.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker'))
    FROM protected_memberships) AS protected_bindings_exact,
  (SELECT count(*) = 1 AND pg_catalog.bool_and(owner.rolname = 'qm_gmail_draft_owner')
    FROM pg_catalog.pg_namespace namespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
    WHERE namespace.nspname = 'gmail_draft_broker') AS schema_identity_exact,
  pg_catalog.has_schema_privilege(CURRENT_USER, 'gmail_draft_broker', 'USAGE')
    AND NOT pg_catalog.has_schema_privilege(CURRENT_USER, 'gmail_draft_broker', 'CREATE')
    AS schema_privileges_exact,
  (SELECT count(*) = 5
    AND pg_catalog.array_agg(relname ORDER BY relname) = ARRAY[
      'active_lineage_claims','approved_intents','migration_versions','owner_slack_bindings','thread_sources'
    ]::TEXT[]
    AND pg_catalog.bool_and(relkind = 'r' AND relpersistence = 'p' AND owner_name = 'qm_gmail_draft_owner')
    FROM schema_relations) AS relation_shape_exact,
  NOT EXISTS (SELECT 1 FROM schema_relations relation WHERE
    pg_catalog.has_table_privilege(CURRENT_USER, relation.oid, 'SELECT')
    OR pg_catalog.has_table_privilege(CURRENT_USER, relation.oid, 'INSERT')
    OR pg_catalog.has_table_privilege(CURRENT_USER, relation.oid, 'UPDATE')
    OR pg_catalog.has_table_privilege(CURRENT_USER, relation.oid, 'DELETE')
    OR pg_catalog.has_table_privilege(CURRENT_USER, relation.oid, 'TRUNCATE')
    OR pg_catalog.has_table_privilege(CURRENT_USER, relation.oid, 'REFERENCES')
    OR pg_catalog.has_table_privilege(CURRENT_USER, relation.oid, 'TRIGGER')
    OR pg_catalog.has_any_column_privilege(CURRENT_USER, relation.oid, 'SELECT,INSERT,UPDATE,REFERENCES'))
    AS relation_privileges_exact,
  (SELECT count(*) = 11 AND pg_catalog.bool_and(
    pg_catalog.has_function_privilege(CURRENT_USER, routine.oid, 'EXECUTE')
      IS NOT DISTINCT FROM (routine.proname = ANY($2::TEXT[])))
    FROM schema_routines routine) AS routine_privileges_exact,
  NOT EXISTS (SELECT 1 FROM pg_catalog.unnest($3::TEXT[]) signature
    WHERE pg_catalog.to_regprocedure(signature) IS NULL) AS routine_signatures_exact`;

function failedDoctor(reason: string): Readonly<{ ready: false; reason: string }> {
  return Object.freeze({ ready: false, reason });
}

async function attestGmailDraftPostgresRuntime(
  pg: PgPool,
  runtimeRole: GmailDraftPostgresRuntimeRole,
  allowedRoutines: readonly string[],
): Promise<GmailDraftPostgresStartupDoctorResult> {
  try {
    const result = await pg.query(GMAIL_DRAFT_POSTGRES_ATTESTATION_SQL, [
      runtimeRole,
      [...allowedRoutines],
      [...GMAIL_DRAFT_ROUTINE_SIGNATURES],
    ]);
    const row = result.rowCount === 1 ? result.rows[0] : undefined;
    const checks = [
      ["database session identity mismatch", row?.session_identity_exact],
      ["database provider mismatch", row?.provider_exact],
      ["database login posture mismatch", row?.login_posture_exact],
      ["database runtime role mismatch", row?.membership_exact],
      ["database protected role bindings mismatch", row?.protected_bindings_exact],
      ["database schema identity mismatch", row?.schema_identity_exact],
      ["database schema privileges mismatch", row?.schema_privileges_exact],
      ["database relation shape mismatch", row?.relation_shape_exact],
      ["database relation privileges mismatch", row?.relation_privileges_exact],
      ["database routine privileges mismatch", row?.routine_privileges_exact],
      ["database routine signatures mismatch", row?.routine_signatures_exact],
    ] as const;
    const failure = checks.find(([, passed]) => passed !== true);
    if (failure) return failedDoctor(failure[0]);
    return Object.freeze({
      ready: true,
      provider: "postgresql" as const,
      providerMajorVersion: 16 as const,
      schema: GMAIL_DRAFT_SCHEMA,
      runtimeRole,
    });
  } catch {
    return failedDoctor("database attestation failed");
  }
}

function postgresStartupDoctor(
  pg: PgPool,
  runtimeRole: GmailDraftPostgresRuntimeRole,
  allowedRoutines: readonly string[],
): Readonly<{
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
  startupDoctor(): Promise<GmailDraftPostgresStartupDoctorResult>;
}> {
  let state: Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }> = failedDoctor(
    "database startup doctor has not passed",
  );
  let pending: Promise<GmailDraftPostgresStartupDoctorResult> | null = null;
  const startupDoctor = () => {
    if (pending) return pending;
    state = failedDoctor("database startup doctor is running");
    pending = attestGmailDraftPostgresRuntime(pg, runtimeRole, allowedRoutines)
      .then((result) => {
        state = result.ready ? Object.freeze({ ready: true as const }) : result;
        return result;
      })
      .finally(() => {
        pending = null;
      });
    return pending;
  };
  return Object.freeze({ readiness: () => state, startupDoctor });
}

export interface GmailDraftPrivateIntentCipherPort {
  boundary: "private_gmail_draft_intent_cipher";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
  open(input: {
    ciphertext: unknown;
    aad: Readonly<{ effectProposalId: string; proposalRevision: number; proposalSha256: string }>;
  }): Promise<string>;
}

export interface GmailDraftSealedApprovedIntent {
  proposal: GmailDraftEffectProposal;
  proposalCiphertext: Readonly<Record<string, unknown>>;
}

export interface GmailDraftVerifiedOwnerSlackBinding {
  contractType: "qm-gmail-draft-owner-slack-binding";
  contractVersion: 1;
  issuer: string;
  keyId: string;
  bindingJti: string;
  receiptId: string;
  organizationId: string;
  ownerPrincipalId: string;
  slackTeamId: string;
  slackUserId: string;
  issuedAt: number;
  expiresAt: number;
  signedReceiptSha256: string;
  verifiedReceiptSha256: string;
}

export interface GmailDraftVerifiedThreadSource {
  contractType: "qm-gmail-draft-thread-source";
  contractVersion: 1;
  issuer: string;
  keyId: string;
  sourceJti: string;
  sourceReceiptSha256: string;
  organizationId: string;
  ownerPrincipalId: string;
  logicalConnectionId: string;
  connectionVersion: number;
  googleSubject: string;
  mailbox: string;
  gmailThreadId: string;
  parentMessageId: string;
  referenceMessageIds: readonly string[];
  subjectSha256: string;
  issuedAt: number;
  expiresAt: number;
  signedReceiptSha256: string;
  verifiedReceiptSha256: string;
}

export type GmailDraftAdmissionResult =
  | Readonly<{ status: "admitted" | "replayed" }>
  | Readonly<{ status: "rejected"; code: "approval_invalid" | "lineage_invalid" }>;

export interface GmailDraftPrivateApprovalAdmissionStore {
  boundary: "private_verified_slack_owner_dm_approval_store";
  durability: "postgres";
  readiness(): Readonly<{ ready: true }> | Readonly<{ ready: false; reason: string }>;
  startupDoctor(): Promise<GmailDraftPostgresStartupDoctorResult>;
  admitOwnerSlackBinding(input: GmailDraftVerifiedOwnerSlackBinding): Promise<GmailDraftAdmissionResult>;
  admitThreadSource(input: GmailDraftVerifiedThreadSource): Promise<GmailDraftAdmissionResult>;
  admit(input: GmailDraftSealedApprovedIntent): Promise<GmailDraftAdmissionResult>;
}

interface IntentRow {
  effect_proposal_id: string;
  proposal_revision: number | string;
  draft_revision: number | string;
  proposal_sha256: string;
  approval_jti: string;
  approval_receipt_id: string;
  approval_issuer: string;
  approval_key_id: string;
  approval_signed_receipt_sha256: string;
  approval_verified_receipt_sha256: string;
  organization_id: string;
  owner_principal_id: string;
  actor_principal_id: string;
  actor_slack_id: string;
  slack_team_id: string;
  slack_user_id: string;
  channel_id: string;
  message_ts: string;
  thread_ts: string;
  action_ts: string;
  approval_issued_at: number | string;
  approval_expires_at: number | string;
  operation: "create" | "update";
  logical_connection_id: string;
  connection_version: number | string;
  google_subject: string;
  mailbox: string;
  approved_payload_sha256: string;
  recipients_sha256: string;
  subject_sha256: string;
  body_sha256: string;
  thread_binding_sha256: string;
  business_context_sha256: string;
  source_bundle_sha256: string;
  draft_id: string | null;
  prior_draft_receipt_sha256: string | null;
  gmail_thread_id: string | null;
  reply_source_receipt_sha256: string | null;
  reply_parent_message_id: string | null;
  reply_reference_message_ids: readonly string[] | null;
  reply_subject_sha256: string | null;
  status: "approved" | "pre_effect" | "effect_started" | "unknown" | "reconciling" | "created" | "rejected";
  attempt_id: string | null;
  attempt_started_at: number | string | null;
  claim_expires_at: number | string | null;
  reconciliation_nonce: string | null;
  proposal_ciphertext: unknown;
  terminal_receipt_sha256: string | null;
  terminal_draft_id: string | null;
  terminal_message_id: string | null;
  terminal_thread_id: string | null;
  terminal_mime_sha256: string | null;
  terminal_request_sha256: string | null;
  terminal_response_sha256: string | null;
  terminal_credential_receipt_sha256: string | null;
  terminal_marker_message_id: string | null;
  terminal_unknown_code: GmailDraftUnknownReceipt["code"] | null;
  terminal_at: number | string | null;
  terminal_reconciled: boolean | null;
  rejection_code: GmailDraftRejectionCode | null;
  _approvalCurrent: boolean;
  _claimCurrent: boolean;
  _claimAcquired: boolean;
}

const SLACK_TEAM = /^T[A-Z0-9]{8,31}$/u;
const SLACK_USER = /^U[A-Z0-9]{8,31}$/u;
const MESSAGE_ID = /^<[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+>$/u;

function exactRecordKeys(
  value: unknown,
  expected: readonly string[],
  name: string,
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${name} is invalid`);
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  if (actual.length !== keys.length || actual.some((entry, index) => entry !== keys[index])) {
    throw new TypeError(`${name} fields are invalid`);
  }
}

function currentAuthorityTimes(issuedAt: number, expiresAt: number, now: number, maxDuration: number): void {
  if (
    !Number.isSafeInteger(issuedAt) ||
    !Number.isSafeInteger(expiresAt) ||
    issuedAt > now + 30_000 ||
    expiresAt <= now ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > maxDuration
  ) {
    throw new TypeError("authority is not current");
  }
}

function validateOwnerSlackBinding(
  value: GmailDraftVerifiedOwnerSlackBinding,
  now: number,
): GmailDraftVerifiedOwnerSlackBinding {
  exactRecordKeys(
    value,
    [
      "contractType",
      "contractVersion",
      "issuer",
      "keyId",
      "bindingJti",
      "receiptId",
      "organizationId",
      "ownerPrincipalId",
      "slackTeamId",
      "slackUserId",
      "issuedAt",
      "expiresAt",
      "signedReceiptSha256",
      "verifiedReceiptSha256",
    ],
    "owner Slack binding",
  );
  if (value.contractType !== "qm-gmail-draft-owner-slack-binding" || value.contractVersion !== 1) {
    throw new TypeError("owner Slack binding contract is invalid");
  }
  for (const [name, entry] of Object.entries({
    issuer: value.issuer,
    keyId: value.keyId,
    bindingJti: value.bindingJti,
    receiptId: value.receiptId,
    organizationId: value.organizationId,
    ownerPrincipalId: value.ownerPrincipalId,
  })) {
    assertIdentifier(entry, `owner Slack binding ${name}`);
  }
  if (!SLACK_TEAM.test(value.slackTeamId) || !SLACK_USER.test(value.slackUserId)) {
    throw new TypeError("owner Slack identity is invalid");
  }
  assertSha256(value.signedReceiptSha256, "owner Slack binding signedReceiptSha256");
  assertSha256(value.verifiedReceiptSha256, "owner Slack binding verifiedReceiptSha256");
  currentAuthorityTimes(value.issuedAt, value.expiresAt, now, 366 * 24 * 60 * 60_000);
  return Object.freeze(structuredClone(value));
}

function validateThreadSource(value: GmailDraftVerifiedThreadSource, now: number): GmailDraftVerifiedThreadSource {
  exactRecordKeys(
    value,
    [
      "contractType",
      "contractVersion",
      "issuer",
      "keyId",
      "sourceJti",
      "sourceReceiptSha256",
      "organizationId",
      "ownerPrincipalId",
      "logicalConnectionId",
      "connectionVersion",
      "googleSubject",
      "mailbox",
      "gmailThreadId",
      "parentMessageId",
      "referenceMessageIds",
      "subjectSha256",
      "issuedAt",
      "expiresAt",
      "signedReceiptSha256",
      "verifiedReceiptSha256",
    ],
    "thread source",
  );
  if (value.contractType !== "qm-gmail-draft-thread-source" || value.contractVersion !== 1) {
    throw new TypeError("thread source contract is invalid");
  }
  for (const [name, entry] of Object.entries({
    issuer: value.issuer,
    keyId: value.keyId,
    sourceJti: value.sourceJti,
    organizationId: value.organizationId,
    ownerPrincipalId: value.ownerPrincipalId,
    logicalConnectionId: value.logicalConnectionId,
    googleSubject: value.googleSubject,
  })) {
    assertIdentifier(entry, `thread source ${name}`);
  }
  if (!Number.isSafeInteger(value.connectionVersion) || value.connectionVersion < 1) {
    throw new TypeError("thread source connectionVersion is invalid");
  }
  if (normalizedMailbox(value.mailbox, "thread source mailbox") !== value.mailbox) {
    throw new TypeError("thread source mailbox is not canonical");
  }
  assertProviderIdentifier(value.gmailThreadId, "thread source gmailThreadId");
  if (!MESSAGE_ID.test(value.parentMessageId)) throw new TypeError("thread source parentMessageId is invalid");
  if (
    !Array.isArray(value.referenceMessageIds) ||
    value.referenceMessageIds.length < 1 ||
    value.referenceMessageIds.length > 20 ||
    new Set(value.referenceMessageIds).size !== value.referenceMessageIds.length ||
    value.referenceMessageIds.some((entry) => !MESSAGE_ID.test(entry)) ||
    value.referenceMessageIds.at(-1) !== value.parentMessageId
  ) {
    throw new TypeError("thread source references are invalid");
  }
  assertSha256(value.sourceReceiptSha256, "thread source sourceReceiptSha256");
  assertSha256(value.subjectSha256, "thread source subjectSha256");
  assertSha256(value.signedReceiptSha256, "thread source signedReceiptSha256");
  assertSha256(value.verifiedReceiptSha256, "thread source verifiedReceiptSha256");
  if (value.sourceReceiptSha256 !== value.verifiedReceiptSha256) {
    throw new TypeError("thread source receipt binding is invalid");
  }
  currentAuthorityTimes(value.issuedAt, value.expiresAt, now, 31 * 24 * 60 * 60_000);
  return Object.freeze(structuredClone(value));
}

function rowReceipt(row: IntentRow): GmailDraftReceipt | GmailDraftUnknownReceipt | null {
  if (row.status === "created") {
    if (
      !row.attempt_id ||
      !row.terminal_receipt_sha256 ||
      !row.terminal_draft_id ||
      !row.terminal_message_id ||
      !row.terminal_mime_sha256 ||
      !row.terminal_request_sha256 ||
      !row.terminal_response_sha256 ||
      !row.terminal_credential_receipt_sha256 ||
      row.terminal_at === null ||
      row.terminal_reconciled === null
    ) {
      return null;
    }
    const unsigned = {
      contractType: "qm-gmail-draft-receipt" as const,
      contractVersion: 1 as const,
      operation: row.operation,
      effectProposalId: row.effect_proposal_id,
      proposalRevision: Number(row.proposal_revision),
      draftRevision: Number(row.draft_revision),
      attemptId: row.attempt_id,
      organizationId: row.organization_id,
      ownerPrincipalId: row.owner_principal_id,
      logicalConnectionId: row.logical_connection_id,
      connectionVersion: Number(row.connection_version),
      googleSubject: row.google_subject,
      mailbox: row.mailbox,
      approvalJti: row.approval_jti,
      draftId: row.terminal_draft_id,
      messageId: row.terminal_message_id,
      threadId: row.terminal_thread_id,
      recipientsSha256: row.recipients_sha256,
      subjectSha256: row.subject_sha256,
      bodySha256: row.body_sha256,
      threadBindingSha256: row.thread_binding_sha256,
      businessContextSha256: row.business_context_sha256,
      sourceBundleSha256: row.source_bundle_sha256,
      effectPayloadSha256: row.approved_payload_sha256,
      mimeSha256: row.terminal_mime_sha256,
      requestSha256: row.terminal_request_sha256,
      responseSha256: row.terminal_response_sha256,
      credentialReceiptSha256: row.terminal_credential_receipt_sha256,
      createdAt: Number(row.terminal_at),
      reconciled: row.terminal_reconciled,
    };
    return gmailDraftReceiptDigest(unsigned) === row.terminal_receipt_sha256
      ? Object.freeze({ ...unsigned, receiptSha256: row.terminal_receipt_sha256 })
      : null;
  }
  if (row.status === "effect_started" || row.status === "unknown" || row.status === "reconciling") {
    if (
      !row.attempt_id ||
      !row.terminal_receipt_sha256 ||
      !row.terminal_request_sha256 ||
      !row.terminal_marker_message_id ||
      !row.terminal_unknown_code ||
      row.terminal_at === null
    ) {
      return null;
    }
    const unsigned = {
      contractType: "qm-gmail-draft-outcome-unknown" as const,
      contractVersion: 1 as const,
      operation: row.operation,
      effectProposalId: row.effect_proposal_id,
      proposalRevision: Number(row.proposal_revision),
      draftRevision: Number(row.draft_revision),
      attemptId: row.attempt_id,
      effectPayloadSha256: row.approved_payload_sha256,
      requestSha256: row.terminal_request_sha256,
      markerMessageId: row.terminal_marker_message_id,
      draftId: row.draft_id,
      code: row.terminal_unknown_code,
      recordedAt: Number(row.terminal_at),
    };
    return gmailDraftReceiptDigest(unsigned) === row.terminal_receipt_sha256
      ? Object.freeze({ ...unsigned, receiptSha256: row.terminal_receipt_sha256 })
      : null;
  }
  return null;
}

function intentRow(value: unknown): IntentRow | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Partial<IntentRow>;
  return typeof row.effect_proposal_id === "string" && typeof row.status === "string" ? (row as IntentRow) : null;
}

async function proposalFromRow(
  row: IntentRow,
  cipher: GmailDraftPrivateIntentCipherPort,
): Promise<GmailDraftEffectProposal> {
  const proposalRevision = Number(row.proposal_revision);
  const plaintext = await cipher.open({
    ciphertext: row.proposal_ciphertext,
    aad: { effectProposalId: row.effect_proposal_id, proposalRevision, proposalSha256: row.proposal_sha256 },
  });
  const value: unknown = JSON.parse(plaintext);
  if (sha256Canonical(value) !== row.proposal_sha256 || !value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("gmail draft approved intent integrity failure");
  }
  const proposal = structuredClone(value) as GmailDraftEffectProposal;
  const approval = proposal.approval;
  if (
    proposal.effectProposalId !== row.effect_proposal_id ||
    proposal.revision !== proposalRevision ||
    proposal.draftRevision !== Number(row.draft_revision) ||
    proposal.operation !== row.operation ||
    proposal.organizationId !== row.organization_id ||
    proposal.ownerPrincipalId !== row.owner_principal_id ||
    proposal.logicalConnectionId !== row.logical_connection_id ||
    proposal.connectionVersion !== Number(row.connection_version) ||
    proposal.googleSubject !== row.google_subject ||
    proposal.mailbox !== row.mailbox ||
    proposal.effectPayloadSha256 !== row.approved_payload_sha256 ||
    proposal.recipientsSha256 !== row.recipients_sha256 ||
    proposal.subjectSha256 !== row.subject_sha256 ||
    proposal.bodySha256 !== row.body_sha256 ||
    proposal.threadBindingSha256 !== row.thread_binding_sha256 ||
    proposal.businessContextSha256 !== row.business_context_sha256 ||
    proposal.sourceBundleSha256 !== row.source_bundle_sha256 ||
    proposal.draftId !== row.draft_id ||
    proposal.priorDraftReceiptSha256 !== row.prior_draft_receipt_sha256 ||
    proposal.gmailThreadId !== row.gmail_thread_id ||
    (proposal.replyAuthority?.sourceReceiptSha256 ?? null) !== row.reply_source_receipt_sha256 ||
    (proposal.replyAuthority?.parentMessageId ?? null) !== row.reply_parent_message_id ||
    JSON.stringify(proposal.replyAuthority?.referenceMessageIds ?? null) !==
      JSON.stringify(row.reply_reference_message_ids) ||
    (proposal.replyAuthority?.subjectSha256 ?? null) !== row.reply_subject_sha256 ||
    approval.jti !== row.approval_jti ||
    approval.receiptId !== row.approval_receipt_id ||
    approval.issuer !== row.approval_issuer ||
    approval.keyId !== row.approval_key_id ||
    approval.signedReceiptSha256 !== row.approval_signed_receipt_sha256 ||
    approval.verifiedReceiptSha256 !== row.approval_verified_receipt_sha256 ||
    approval.actorPrincipalId !== row.actor_principal_id ||
    approval.actorSlackId !== row.actor_slack_id ||
    approval.slackTeamId !== row.slack_team_id ||
    approval.slackUserId !== row.slack_user_id ||
    approval.channelId !== row.channel_id ||
    approval.messageTs !== row.message_ts ||
    approval.threadTs !== row.thread_ts ||
    approval.actionTs !== row.action_ts ||
    approval.draftRevision !== Number(row.draft_revision) ||
    approval.issuedAt !== Number(row.approval_issued_at) ||
    approval.expiresAt !== Number(row.approval_expires_at)
  ) {
    throw new Error("gmail draft approved intent binding failure");
  }
  return proposal;
}

function attemptFrom(row: IntentRow, proposal: GmailDraftEffectProposal): GmailDraftAttempt {
  if (!row.attempt_id || row.attempt_started_at === null) throw new Error("gmail draft attempt is incomplete");
  return Object.freeze({
    attemptId: row.attempt_id,
    effectProposalId: row.effect_proposal_id,
    proposalRevision: Number(row.proposal_revision),
    draftRevision: Number(row.draft_revision),
    startedAt: Number(row.attempt_started_at),
    proposal,
  });
}

function reconciliationLeaseFrom(row: IntentRow): GmailDraftReconciliationLease {
  if (!row.reconciliation_nonce || row.claim_expires_at === null) {
    throw new Error("gmail draft reconciliation lease is incomplete");
  }
  assertIdentifier(row.reconciliation_nonce, "gmail draft reconciliation nonce");
  const expiresAt = Number(row.claim_expires_at);
  if (!Number.isSafeInteger(expiresAt)) throw new Error("gmail draft reconciliation lease expiry is invalid");
  return Object.freeze({ nonce: row.reconciliation_nonce, expiresAt });
}

function validateCreatedReceiptForAttempt(attempt: GmailDraftAttempt, receipt: GmailDraftReceipt): void {
  exactRecordKeys(
    receipt,
    [
      "contractType",
      "contractVersion",
      "operation",
      "effectProposalId",
      "proposalRevision",
      "draftRevision",
      "attemptId",
      "organizationId",
      "ownerPrincipalId",
      "logicalConnectionId",
      "connectionVersion",
      "googleSubject",
      "mailbox",
      "approvalJti",
      "draftId",
      "messageId",
      "threadId",
      "recipientsSha256",
      "subjectSha256",
      "bodySha256",
      "threadBindingSha256",
      "businessContextSha256",
      "sourceBundleSha256",
      "effectPayloadSha256",
      "mimeSha256",
      "requestSha256",
      "responseSha256",
      "credentialReceiptSha256",
      "createdAt",
      "reconciled",
      "receiptSha256",
    ],
    "created receipt",
  );
  const proposal = attempt.proposal;
  const { receiptSha256, ...unsigned } = receipt;
  if (
    receipt.contractType !== "qm-gmail-draft-receipt" ||
    receipt.contractVersion !== 1 ||
    receipt.operation !== proposal.operation ||
    receipt.effectProposalId !== attempt.effectProposalId ||
    receipt.proposalRevision !== attempt.proposalRevision ||
    receipt.draftRevision !== attempt.draftRevision ||
    receipt.attemptId !== attempt.attemptId ||
    receipt.organizationId !== proposal.organizationId ||
    receipt.ownerPrincipalId !== proposal.ownerPrincipalId ||
    receipt.logicalConnectionId !== proposal.logicalConnectionId ||
    receipt.connectionVersion !== proposal.connectionVersion ||
    receipt.googleSubject !== proposal.googleSubject ||
    receipt.mailbox !== proposal.mailbox ||
    receipt.approvalJti !== proposal.approval.jti ||
    (proposal.operation === "update" && receipt.draftId !== proposal.draftId) ||
    (proposal.gmailThreadId !== null && receipt.threadId !== proposal.gmailThreadId) ||
    receipt.recipientsSha256 !== proposal.recipientsSha256 ||
    receipt.subjectSha256 !== proposal.subjectSha256 ||
    receipt.bodySha256 !== proposal.bodySha256 ||
    receipt.threadBindingSha256 !== proposal.threadBindingSha256 ||
    receipt.businessContextSha256 !== proposal.businessContextSha256 ||
    receipt.sourceBundleSha256 !== proposal.sourceBundleSha256 ||
    receipt.effectPayloadSha256 !== proposal.effectPayloadSha256 ||
    gmailDraftReceiptDigest(unsigned) !== receiptSha256
  ) {
    throw new TypeError("created receipt binding is invalid");
  }
  assertProviderIdentifier(receipt.draftId, "created receipt draftId");
  assertProviderIdentifier(receipt.messageId, "created receipt messageId");
  if (receipt.threadId !== null) assertProviderIdentifier(receipt.threadId, "created receipt threadId");
  for (const [name, digest] of Object.entries({
    receiptSha256,
    mimeSha256: receipt.mimeSha256,
    requestSha256: receipt.requestSha256,
    responseSha256: receipt.responseSha256,
    credentialReceiptSha256: receipt.credentialReceiptSha256,
  })) {
    assertSha256(digest, `created receipt ${name}`);
  }
  if (!Number.isSafeInteger(receipt.createdAt)) throw new TypeError("created receipt time is invalid");
}

function validateUnknownReceiptForAttempt(attempt: GmailDraftAttempt, receipt: GmailDraftUnknownReceipt): void {
  exactRecordKeys(
    receipt,
    [
      "contractType",
      "contractVersion",
      "operation",
      "effectProposalId",
      "proposalRevision",
      "draftRevision",
      "attemptId",
      "effectPayloadSha256",
      "requestSha256",
      "markerMessageId",
      "draftId",
      "code",
      "recordedAt",
      "receiptSha256",
    ],
    "unknown receipt",
  );
  const proposal = attempt.proposal;
  const { receiptSha256, ...unsigned } = receipt;
  if (
    receipt.contractType !== "qm-gmail-draft-outcome-unknown" ||
    receipt.contractVersion !== 1 ||
    receipt.operation !== proposal.operation ||
    receipt.effectProposalId !== attempt.effectProposalId ||
    receipt.proposalRevision !== attempt.proposalRevision ||
    receipt.draftRevision !== attempt.draftRevision ||
    receipt.attemptId !== attempt.attemptId ||
    receipt.effectPayloadSha256 !== proposal.effectPayloadSha256 ||
    receipt.draftId !== proposal.draftId ||
    receipt.markerMessageId !== `<qm.${proposal.effectPayloadSha256}@drafts.invalid>` ||
    gmailDraftReceiptDigest(unsigned) !== receiptSha256
  ) {
    throw new TypeError("unknown receipt binding is invalid");
  }
  assertSha256(receiptSha256, "unknown receipt receiptSha256");
  assertSha256(receipt.requestSha256, "unknown receipt requestSha256");
  if (!Number.isSafeInteger(receipt.recordedAt)) throw new TypeError("unknown receipt time is invalid");
}

export function createPostgresGmailDraftApprovalAdmissionStore(options: {
  connectionString: string;
  now?: () => number;
}): GmailDraftPrivateApprovalAdmissionStore {
  const pg = createPgPool(options.connectionString, []);
  const now = options.now ?? Date.now;
  const doctor = postgresStartupDoctor(pg, "qm_gmail_draft_admission", GMAIL_DRAFT_ADMISSION_ROUTINES);
  const readiness = doctor.readiness;
  const outcome = (value: unknown, code: "approval_invalid" | "lineage_invalid"): GmailDraftAdmissionResult =>
    value === "admitted" || value === "replayed" ? { status: value } : { status: "rejected", code };
  return Object.freeze({
    boundary: "private_verified_slack_owner_dm_approval_store" as const,
    durability: "postgres" as const,
    readiness,
    startupDoctor: doctor.startupDoctor,
    async admitOwnerSlackBinding(input: GmailDraftVerifiedOwnerSlackBinding): Promise<GmailDraftAdmissionResult> {
      if (!readiness().ready) return { status: "rejected", code: "approval_invalid" };
      let binding: GmailDraftVerifiedOwnerSlackBinding;
      try {
        binding = validateOwnerSlackBinding(input, now());
      } catch {
        return { status: "rejected", code: "approval_invalid" };
      }
      const result = await pg.query(
        `SELECT gmail_draft_broker.admit_owner_slack_binding($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) AS outcome`,
        [
          binding.issuer,
          binding.keyId,
          binding.bindingJti,
          binding.receiptId,
          binding.organizationId,
          binding.ownerPrincipalId,
          binding.slackTeamId,
          binding.slackUserId,
          binding.issuedAt,
          binding.expiresAt,
          binding.signedReceiptSha256,
          binding.verifiedReceiptSha256,
        ],
      );
      return outcome(result.rows[0]?.outcome, "approval_invalid");
    },
    async admitThreadSource(input: GmailDraftVerifiedThreadSource): Promise<GmailDraftAdmissionResult> {
      if (!readiness().ready) return { status: "rejected", code: "approval_invalid" };
      let source: GmailDraftVerifiedThreadSource;
      try {
        source = validateThreadSource(input, now());
      } catch {
        return { status: "rejected", code: "approval_invalid" };
      }
      const result = await pg.query(
        `SELECT gmail_draft_broker.admit_thread_source($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::text[],$14,$15,$16,$17,$18) AS outcome`,
        [
          source.issuer,
          source.keyId,
          source.sourceJti,
          source.sourceReceiptSha256,
          source.organizationId,
          source.ownerPrincipalId,
          source.logicalConnectionId,
          source.connectionVersion,
          source.googleSubject,
          source.mailbox,
          source.gmailThreadId,
          source.parentMessageId,
          [...source.referenceMessageIds],
          source.subjectSha256,
          source.issuedAt,
          source.expiresAt,
          source.signedReceiptSha256,
          source.verifiedReceiptSha256,
        ],
      );
      return outcome(result.rows[0]?.outcome, "approval_invalid");
    },
    async admit(input: GmailDraftSealedApprovedIntent): Promise<GmailDraftAdmissionResult> {
      if (!readiness().ready) return { status: "rejected", code: "approval_invalid" };
      let proposal: GmailDraftEffectProposal;
      try {
        proposal = validateEffectProposal(input.proposal, now());
        if (
          !input.proposalCiphertext ||
          typeof input.proposalCiphertext !== "object" ||
          Array.isArray(input.proposalCiphertext)
        ) {
          throw new TypeError("proposal ciphertext is invalid");
        }
      } catch {
        return { status: "rejected", code: "approval_invalid" };
      }
      const approval = proposal.approval;
      const reply = proposal.replyAuthority;
      const result = await pg.query(
        `SELECT gmail_draft_broker.admit_intent($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40::text[],$41,$42::jsonb) AS outcome`,
        [
          proposal.effectProposalId,
          proposal.revision,
          proposal.draftRevision,
          sha256Canonical(proposal),
          approval.jti,
          approval.receiptId,
          approval.issuer,
          approval.keyId,
          approval.signedReceiptSha256,
          approval.verifiedReceiptSha256,
          proposal.organizationId,
          proposal.ownerPrincipalId,
          approval.actorPrincipalId,
          approval.actorSlackId,
          approval.slackTeamId,
          approval.slackUserId,
          approval.channelId,
          approval.messageTs,
          approval.threadTs,
          approval.actionTs,
          approval.issuedAt,
          approval.expiresAt,
          proposal.operation,
          proposal.logicalConnectionId,
          proposal.connectionVersion,
          proposal.googleSubject,
          proposal.mailbox,
          proposal.effectPayloadSha256,
          proposal.recipientsSha256,
          proposal.subjectSha256,
          proposal.bodySha256,
          proposal.threadBindingSha256,
          proposal.businessContextSha256,
          proposal.sourceBundleSha256,
          proposal.draftId,
          proposal.priorDraftReceiptSha256,
          proposal.gmailThreadId,
          reply?.sourceReceiptSha256 ?? null,
          reply?.parentMessageId ?? null,
          reply ? [...reply.referenceMessageIds] : null,
          reply?.subjectSha256 ?? null,
          JSON.stringify(input.proposalCiphertext),
        ],
      );
      return outcome(result.rows[0]?.outcome, proposal.operation === "update" ? "lineage_invalid" : "approval_invalid");
    },
  });
}

export function createPostgresGmailDraftExecutionStore(options: {
  connectionString: string;
  cipher: GmailDraftPrivateIntentCipherPort;
  approvalAdmission: GmailDraftPrivateApprovalAdmissionStore;
  claimMs?: number;
}): GmailDraftExecutionStore & {
  startupDoctor(): Promise<GmailDraftPostgresStartupDoctorResult>;
} {
  const pg = createPgPool(options.connectionString, []);
  const claimMs = options.claimMs ?? 30_000;
  if (!Number.isSafeInteger(claimMs) || claimMs < 1_000 || claimMs > 10 * 60_000) {
    throw new TypeError("Gmail draft claim duration is invalid");
  }
  const doctor = postgresStartupDoctor(pg, "qm_gmail_draft_broker", GMAIL_DRAFT_EXECUTION_ROUTINES);
  const ready = () => {
    const database = doctor.readiness();
    if (!database.ready) return database;
    const cipher = options.cipher.readiness();
    if (!cipher.ready) return cipher;
    return options.approvalAdmission.readiness();
  };
  const claim = async (method: "claim_effect" | "claim_reconciliation", effectProposalId: string) => {
    const result = await pg.query(`SELECT gmail_draft_broker.${method}($1,$2) AS intent`, [effectProposalId, claimMs]);
    return intentRow(result.rows[0]?.intent);
  };
  const rejectInvalid = async (row: IntentRow): Promise<void> => {
    if (!row.attempt_id) return;
    await pg
      .query(`SELECT gmail_draft_broker.reject_before_effect($1,$2,$3,'proposal_invalid') AS accepted`, [
        row.effect_proposal_id,
        Number(row.proposal_revision),
        row.attempt_id,
      ])
      .catch(() => undefined);
  };
  const begin = async (effectProposalId: string): Promise<GmailDraftBeginResult> => {
    assertIdentifier(effectProposalId, "effectProposalId");
    if (!ready().ready) return { status: "rejected", code: "approval_invalid" };
    const row = await claim("claim_effect", effectProposalId);
    if (!row) return { status: "rejected", code: "approval_invalid" };
    if (row.status === "created") {
      const receipt = rowReceipt(row);
      return receipt?.contractType === "qm-gmail-draft-receipt"
        ? { status: "created", receipt }
        : { status: "rejected", code: "proposal_invalid" };
    }
    if (row.status === "effect_started" || row.status === "unknown" || row.status === "reconciling") {
      const receipt = rowReceipt(row);
      return receipt?.contractType === "qm-gmail-draft-outcome-unknown"
        ? { status: "outcome_unknown", receipt }
        : { status: "rejected", code: "proposal_invalid" };
    }
    if (row.status === "rejected") return { status: "rejected", code: row.rejection_code ?? "approval_invalid" };
    if (row.status !== "pre_effect" || !row._claimCurrent || !row._claimAcquired) return { status: "in_progress" };
    try {
      return { status: "claimed", attempt: attemptFrom(row, await proposalFromRow(row, options.cipher)) };
    } catch {
      await rejectInvalid(row);
      return { status: "rejected", code: "proposal_invalid" };
    }
  };
  const beginReconciliation = async (effectProposalId: string): Promise<GmailDraftReconcileBeginResult> => {
    assertIdentifier(effectProposalId, "effectProposalId");
    if (!ready().ready) return { status: "rejected", code: "approval_invalid" };
    const row = await claim("claim_reconciliation", effectProposalId);
    if (!row) return { status: "rejected", code: "approval_invalid" };
    if (row.status === "created") {
      const receipt = rowReceipt(row);
      return receipt?.contractType === "qm-gmail-draft-receipt"
        ? { status: "created", receipt }
        : { status: "rejected", code: "proposal_invalid" };
    }
    if (row.status === "rejected") return { status: "rejected", code: row.rejection_code ?? "approval_invalid" };
    const unknown = rowReceipt(row);
    if (
      row.status !== "reconciling" ||
      !row._claimCurrent ||
      !row._claimAcquired ||
      unknown?.contractType !== "qm-gmail-draft-outcome-unknown"
    ) {
      return unknown?.contractType === "qm-gmail-draft-outcome-unknown"
        ? { status: "outcome_unknown", receipt: unknown }
        : { status: "in_progress" };
    }
    try {
      return {
        status: "claimed",
        attempt: attemptFrom(row, await proposalFromRow(row, options.cipher)),
        unknown,
        lease: reconciliationLeaseFrom(row),
      };
    } catch {
      return { status: "outcome_unknown", receipt: unknown };
    }
  };
  const recordUnknown = async (
    method: "record_unknown",
    attempt: GmailDraftAttempt,
    receipt: GmailDraftUnknownReceipt,
  ): Promise<boolean> => {
    validateUnknownReceiptForAttempt(attempt, receipt);
    const result = await pg.query(`SELECT gmail_draft_broker.${method}($1,$2,$3,$4,$5,$6,$7,$8) AS accepted`, [
      attempt.effectProposalId,
      attempt.proposalRevision,
      attempt.attemptId,
      receipt.receiptSha256,
      receipt.requestSha256,
      receipt.markerMessageId,
      receipt.code,
      receipt.recordedAt,
    ]);
    return result.rows[0]?.accepted === true;
  };
  return Object.freeze({
    durability: "postgres" as const,
    idempotency: "single_effect_proposal" as const,
    approvalAdmission: "signature_verified_current_click_one_time" as const,
    terminalUnknownPolicy: "reconcile_only_no_automatic_mutation_retry" as const,
    readiness: ready,
    async startupDoctor() {
      const database = await doctor.startupDoctor();
      if (!database.ready) return database;
      const combined = ready();
      return combined.ready ? database : combined;
    },
    begin,
    beginReconciliation,
    async armEffect(attempt: GmailDraftAttempt, crashReceipt: GmailDraftUnknownReceipt) {
      validateUnknownReceiptForAttempt(attempt, crashReceipt);
      const result = await pg.query(`SELECT gmail_draft_broker.arm_effect($1,$2,$3,$4,$5,$6,$7,$8) AS accepted`, [
        attempt.effectProposalId,
        attempt.proposalRevision,
        attempt.attemptId,
        crashReceipt.receiptSha256,
        crashReceipt.requestSha256,
        crashReceipt.markerMessageId,
        crashReceipt.code,
        crashReceipt.recordedAt,
      ]);
      return result.rows[0]?.accepted === true;
    },
    async reject(attempt: GmailDraftAttempt, code: GmailDraftRejectionCode, proof: GmailDraftNoWriteRejectionProof) {
      const method = proof === "before_effect" ? "reject_before_effect" : "reject_definitive_no_write";
      const result = await pg.query(`SELECT gmail_draft_broker.${method}($1,$2,$3,$4) AS accepted`, [
        attempt.effectProposalId,
        attempt.proposalRevision,
        attempt.attemptId,
        code,
      ]);
      return result.rows[0]?.accepted === true;
    },
    async recordCreated(
      attempt: GmailDraftAttempt,
      receipt: GmailDraftReceipt,
      reconciliationLease: GmailDraftReconciliationLease | null,
    ) {
      validateCreatedReceiptForAttempt(attempt, receipt);
      const result = await pg.query(
        `SELECT gmail_draft_broker.record_created($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) AS accepted`,
        [
          attempt.effectProposalId,
          attempt.proposalRevision,
          attempt.attemptId,
          receipt.receiptSha256,
          receipt.draftId,
          receipt.messageId,
          receipt.threadId,
          receipt.mimeSha256,
          receipt.requestSha256,
          receipt.responseSha256,
          receipt.credentialReceiptSha256,
          receipt.createdAt,
          receipt.reconciled,
          reconciliationLease?.nonce ?? null,
        ],
      );
      if (result.rows[0]?.accepted !== true) {
        throw new Error("gmail draft receipt commit lost authority");
      }
      return receipt;
    },
    async recordUnknown(attempt: GmailDraftAttempt, receipt: GmailDraftUnknownReceipt) {
      if (!(await recordUnknown("record_unknown", attempt, receipt))) {
        throw new Error("gmail draft unknown commit lost authority");
      }
      return receipt;
    },
    async retainUnknown(
      attempt: GmailDraftAttempt,
      receipt: GmailDraftUnknownReceipt,
      reconciliationLease: GmailDraftReconciliationLease,
    ) {
      validateUnknownReceiptForAttempt(attempt, receipt);
      const result = await pg.query(
        `SELECT gmail_draft_broker.retain_unknown($1,$2,$3,$4,$5,$6,$7,$8,$9) AS accepted`,
        [
          attempt.effectProposalId,
          attempt.proposalRevision,
          attempt.attemptId,
          receipt.receiptSha256,
          receipt.requestSha256,
          receipt.markerMessageId,
          receipt.code,
          receipt.recordedAt,
          reconciliationLease.nonce,
        ],
      );
      if (result.rows[0]?.accepted !== true) {
        throw new Error("gmail draft reconciliation release lost authority");
      }
      return receipt;
    },
  });
}
