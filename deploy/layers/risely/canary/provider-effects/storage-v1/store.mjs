import { createPublicKey, randomUUID, verify } from "node:crypto";
import { types } from "node:util";
import { createProviderEffectPolicySuite } from "../index.mjs";
import { assertRuntimeScope } from "../../runtime-scope/index.mjs";
import { canonicalJson } from "../../shared-contracts/validation.mjs";
import {
  PROVIDER_EFFECT_AUTHORITY_ED25519_SIGNATURE_PATTERN,
  PROVIDER_EFFECT_AUTHORITY_MIGRATION_SHA256,
  PROVIDER_EFFECT_AUTHORITY_SCHEMA,
  PROVIDER_EFFECT_AUTHORITY_SCHEMA_VERSION,
} from "./schema.mjs";

const digestPattern = /^[0-9a-f]{64}$/u;
const canonicalEd25519SignaturePattern = new RegExp(PROVIDER_EFFECT_AUTHORITY_ED25519_SIGNATURE_PATTERN, "u");
const receiptIssueTimeoutMs = 10_000;
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const errorCodePattern = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const receiptFields = Object.freeze([
  "receiptId",
  "receiptSha256",
  "profileRef",
  "profileSha256",
  "proposalId",
  "proposalHash",
  "intentSha256",
  "prospectiveEffectKey",
  "attemptRef",
  "attemptNumber",
  "status",
  "provider",
  "operation",
  "providerOwnerRef",
  "providerResourceRef",
  "responseSha256",
  "errorCode",
  "observationMode",
  "providerMutationCount",
  "attemptedAt",
  "completedAt",
  "reconciliationRef",
  "priorReceiptSha256",
  "authenticatedBy",
  "authenticationSha256",
  "keyId",
  "issuerRef",
  "signature",
]);

export class ProviderEffectStoreError extends Error {
  constructor(code, cause) {
    super(code, cause === undefined ? undefined : { cause });
    this.name = "ProviderEffectStoreError";
    this.code = code;
  }
}

const fail = (code, cause) => {
  throw new ProviderEffectStoreError(code, cause);
};

const exact = (value, fields, code) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0 ||
    Object.keys(descriptors).length !== fields.length ||
    fields.some((field) => {
      const descriptor = descriptors[field];
      return !descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value");
    })
  ) {
    fail(code);
  }
  return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]));
};

const identifier = (value, code) => {
  if (typeof value !== "string" || !identifierPattern.test(value)) fail(code);
  return value;
};

const digest = (value, code) => {
  if (typeof value !== "string" || !digestPattern.test(value)) fail(code);
  return value;
};

const instant = (value, code) => {
  if (typeof value !== "string" || new Date(value).toISOString() !== value) fail(code);
  return value;
};

const databaseInstant = (value, code) => {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.toISOString();
  return instant(value, code);
};

const signature = (value, code) => {
  if (typeof value !== "string" || !canonicalEd25519SignaturePattern.test(value)) fail(code);
  let decoded;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    fail(code);
  }
  if (decoded.length !== 64 || decoded.toString("base64url") !== value) fail(code);
  return value;
};

const clone = (value) => structuredClone(value);

const freeze = (scope, value) => scope.contracts.PrincipalBinding.freeze(value);

const compare = (left, right) => canonicalJson(left) === canonicalJson(right);

const assertResult = (scope, value, attempt, reconciliation) => {
  const result = exact(
    clone(value),
    [
      "status",
      "provider",
      "operation",
      "providerOwnerRef",
      "providerResourceRef",
      "responseSha256",
      "errorCode",
      "observationMode",
      "providerMutationCount",
    ],
    "provider_effect_result_invalid",
  );
  const allowedStatuses = reconciliation ? ["verified", "failed"] : ["verified", "failed", "outcome_unknown"];
  if (
    !allowedStatuses.includes(result.status) ||
    result.provider !== attempt.provider ||
    result.operation !== attempt.operation ||
    result.providerOwnerRef !== attempt.providerOwnerRef ||
    (result.providerResourceRef !== null && !identifierPattern.test(result.providerResourceRef)) ||
    (result.status === "verified" && result.providerResourceRef === null) ||
    result.observationMode !== (reconciliation ? "read_only_status_lookup" : "effect_execution") ||
    (reconciliation ? result.providerMutationCount !== 0 : ![0, 1, null].includes(result.providerMutationCount)) ||
    (result.errorCode !== null && (typeof result.errorCode !== "string" || !errorCodePattern.test(result.errorCode))) ||
    (result.status === "verified") !== (result.errorCode === null)
  ) {
    fail("provider_effect_result_invalid");
  }
  digest(result.responseSha256, "provider_effect_result_invalid");
  return freeze(scope, result);
};

const assertReceiptAuthority = (value) => {
  const input = exact(
    value,
    ["keyId", "issuerRef", "authenticationSha256", "publicKey", "issue", "isActive"],
    "provider_effect_receipt_authority_invalid",
  );
  identifier(input.keyId, "provider_effect_receipt_authority_invalid");
  identifier(input.issuerRef, "provider_effect_receipt_authority_invalid");
  digest(input.authenticationSha256, "provider_effect_receipt_authority_invalid");
  if (typeof input.issue !== "function" || typeof input.isActive !== "function") {
    fail("provider_effect_receipt_authority_invalid");
  }
  const publicKey = exact(input.publicKey, ["crv", "x", "kty"], "provider_effect_receipt_authority_invalid");
  if (publicKey.crv !== "Ed25519" || publicKey.kty !== "OKP" || typeof publicKey.x !== "string") {
    fail("provider_effect_receipt_authority_invalid");
  }
  let verifier;
  try {
    verifier = createPublicKey({ key: publicKey, format: "jwk" });
  } catch (error) {
    fail("provider_effect_receipt_authority_invalid", error);
  }
  return Object.freeze({ ...input, publicKey: Object.freeze(publicKey), verifier });
};

const assertReceipt = (scope, authority, value, expected) => {
  const receipt = exact(clone(value), receiptFields, "provider_effect_receipt_invalid");
  signature(receipt.signature, "provider_effect_receipt_invalid");
  for (const field of ["receiptId", "attemptRef", "authenticatedBy", "keyId", "issuerRef"]) {
    identifier(receipt[field], "provider_effect_receipt_invalid");
  }
  for (const field of [
    "receiptSha256",
    "profileSha256",
    "proposalHash",
    "intentSha256",
    "prospectiveEffectKey",
    "responseSha256",
    "authenticationSha256",
  ]) {
    digest(receipt[field], "provider_effect_receipt_invalid");
  }
  if (receipt.priorReceiptSha256 !== null) digest(receipt.priorReceiptSha256, "provider_effect_receipt_invalid");
  instant(receipt.attemptedAt, "provider_effect_receipt_invalid");
  if (receipt.completedAt !== null) instant(receipt.completedAt, "provider_effect_receipt_invalid");
  const comparable = { ...receipt };
  delete comparable.receiptSha256;
  delete comparable.keyId;
  delete comparable.issuerRef;
  delete comparable.signature;
  if (
    !compare(comparable, expected) ||
    receipt.keyId !== authority.keyId ||
    receipt.issuerRef !== authority.issuerRef ||
    receipt.authenticatedBy !== authority.issuerRef ||
    receipt.authenticationSha256 !== authority.authenticationSha256
  ) {
    fail("provider_effect_receipt_invalid");
  }
  const hashProjection = { ...receipt };
  delete hashProjection.receiptSha256;
  delete hashProjection.signature;
  if (receipt.receiptSha256 !== scope.contracts.PrincipalBinding.hash(hashProjection)) {
    fail("provider_effect_receipt_invalid");
  }
  const signingProjection = { ...receipt };
  delete signingProjection.signature;
  let valid = false;
  try {
    valid = verify(
      null,
      Buffer.from(canonicalJson(signingProjection), "utf8"),
      authority.verifier,
      Buffer.from(receipt.signature, "base64url"),
    );
  } catch {
    valid = false;
  }
  if (!valid) fail("provider_effect_receipt_invalid");
  return freeze(scope, receipt);
};

const attemptFields = Object.freeze([
  "profileRef",
  "profileSha256",
  "proposalId",
  "proposalHash",
  "intentSha256",
  "prospectiveEffectKey",
  "policySha256",
  "capability",
  "capabilityVersion",
  "provider",
  "operation",
  "providerOwnerRef",
  "authorizationSha256",
  "killSwitchRevision",
  "evaluationReleaseSha256",
  "providerIdentityReceiptSha256",
  "resourceOwnershipReceiptSha256",
  "approvalSha256",
  "approvalConsumedAt",
  "attemptRef",
  "attemptNumber",
  "status",
  "attemptedAt",
  "leaseExpiresAt",
  "revision",
]);

const attemptFromRow = (scope, row) => {
  const attempt = {
    profileRef: row.profile_ref,
    profileSha256: row.profile_sha256,
    proposalId: row.proposal_id,
    proposalHash: row.proposal_hash,
    intentSha256: row.intent_sha256,
    prospectiveEffectKey: row.prospective_effect_key,
    policySha256: row.policy_sha256,
    capability: row.capability,
    capabilityVersion: row.capability_version,
    provider: row.provider,
    operation: row.operation,
    providerOwnerRef: row.provider_owner_ref,
    authorizationSha256: row.authorization_sha256,
    killSwitchRevision: Number(row.kill_switch_revision),
    evaluationReleaseSha256: row.evaluation_release_sha256,
    providerIdentityReceiptSha256: row.provider_identity_receipt_sha256,
    resourceOwnershipReceiptSha256: row.resource_ownership_receipt_sha256,
    approvalSha256: row.approval_sha256,
    approvalConsumedAt:
      row.approval_consumed_at === null
        ? null
        : databaseInstant(row.approval_consumed_at, "provider_effect_store_corrupt"),
    attemptRef: row.attempt_ref,
    attemptNumber: row.attempt_number,
    status: "attempting",
    attemptedAt: databaseInstant(row.attempted_at, "provider_effect_store_corrupt"),
    leaseExpiresAt: databaseInstant(row.lease_expires_at, "provider_effect_store_corrupt"),
    revision: Number(row.revision),
  };
  if (row.attempt_sha256 !== scope.contracts.PrincipalBinding.hash(attempt)) fail("provider_effect_store_corrupt");
  return freeze(scope, attempt);
};

const leaseFields = Object.freeze([
  "profileRef",
  "profileSha256",
  "proposalId",
  "proposalHash",
  "intentSha256",
  "prospectiveEffectKey",
  "attemptRef",
  "priorReceiptSha256",
  "authenticationSha256",
  "killSwitchRevision",
  "reconciliationRef",
  "reconcilerPrincipalRef",
  "mode",
  "acquiredAt",
  "expiresAt",
  "revision",
]);

const leaseFromRow = (scope, row, attempt) => {
  const lease = {
    profileRef: row.profile_ref,
    profileSha256: row.profile_sha256,
    proposalId: attempt.proposalId,
    proposalHash: attempt.proposalHash,
    intentSha256: attempt.intentSha256,
    prospectiveEffectKey: attempt.prospectiveEffectKey,
    attemptRef: row.attempt_ref,
    priorReceiptSha256: row.prior_receipt_sha256,
    authenticationSha256: row.authentication_sha256,
    killSwitchRevision: Number(row.kill_switch_revision),
    reconciliationRef: row.reconciliation_ref,
    reconcilerPrincipalRef: row.reconciler_principal_ref,
    mode: row.mode,
    acquiredAt: databaseInstant(row.acquired_at, "provider_effect_store_corrupt"),
    expiresAt: databaseInstant(row.expires_at, "provider_effect_store_corrupt"),
    revision: Number(row.revision),
  };
  if (row.lease_sha256 !== scope.contracts.PrincipalBinding.hash(lease)) fail("provider_effect_store_corrupt");
  return freeze(scope, lease);
};

export function createProviderEffectAuthorityStore({ pool, runtimeScope, receiptAuthority, activation }) {
  if (!pool || typeof pool.connect !== "function") fail("provider_effect_store_pool_invalid");
  const scope = assertRuntimeScope(runtimeScope);
  const suite = createProviderEffectPolicySuite(scope);
  const signer = assertReceiptAuthority(receiptAuthority);
  const active = exact(activation, ["isActive"], "provider_effect_store_activation_invalid");
  if (typeof active.isActive !== "function") fail("provider_effect_store_activation_invalid");

  const ensureActive = () => {
    let available = false;
    try {
      available = active.isActive() === true;
    } catch {
      available = false;
    }
    if (!available) fail("provider_effect_store_unavailable");
  };

  const assertProofDigest = (proof, digestField) => {
    if (!proof || typeof proof !== "object" || Array.isArray(proof)) fail("provider_effect_store_corrupt");
    const projection = clone(proof);
    delete projection[digestField];
    delete projection.signature;
    if (proof[digestField] !== scope.contracts.PrincipalBinding.hash(projection)) {
      fail("provider_effect_store_corrupt");
    }
  };

  const assertSchema = async (client) => {
    const result = await client.query(
      `SELECT version, migration_sha256
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.schema_versions
       WHERE singleton = true`,
    );
    if (
      result.rowCount !== 1 ||
      result.rows[0].version !== PROVIDER_EFFECT_AUTHORITY_SCHEMA_VERSION ||
      result.rows[0].migration_sha256 !== PROVIDER_EFFECT_AUTHORITY_MIGRATION_SHA256
    ) {
      fail("provider_effect_store_schema_invalid");
    }
  };

  const transaction = async (operation, readOnly = false, enforceActivation = true) => {
    if (enforceActivation) ensureActive();
    const client = await pool.connect();
    try {
      await client.query(
        readOnly ? "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY" : "BEGIN ISOLATION LEVEL READ COMMITTED",
      );
      await client.query("SET LOCAL search_path = pg_catalog");
      await client.query("SET LOCAL statement_timeout = '10s'");
      await assertSchema(client);
      const result = await operation(client);
      await client.query("COMMIT");
      if (enforceActivation) ensureActive();
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      if (error instanceof ProviderEffectStoreError) throw error;
      if (error?.code === "40001" || error?.code === "40P01") fail("provider_effect_store_transaction_conflict", error);
      if (error?.code === "23505") fail("provider_effect_store_reservation_conflict", error);
      fail("provider_effect_store_failure", error);
    } finally {
      client.release();
    }
  };

  const currentKillSwitch = async (client, lock = false) => {
    const result = await client.query(
      `SELECT revision, engaged, checked_at, state_sha256, proof_json
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.kill_switch_states
       WHERE profile_ref = $1 AND profile_sha256 = $2
       ORDER BY revision DESC
       LIMIT 1${lock ? " FOR SHARE" : ""}`,
      [scope.profileRef, scope.profileSha256],
    );
    if (result.rowCount !== 1) fail("provider_effect_kill_switch_unavailable");
    const row = result.rows[0];
    assertProofDigest(row.proof_json, "stateSha256");
    if (
      row.proof_json.profileRef !== scope.profileRef ||
      row.proof_json.profileSha256 !== scope.profileSha256 ||
      row.proof_json.revision !== Number(row.revision) ||
      row.proof_json.engaged !== row.engaged ||
      row.proof_json.checkedAt !== databaseInstant(row.checked_at, "provider_effect_store_corrupt") ||
      row.proof_json.stateSha256 !== row.state_sha256
    ) {
      fail("provider_effect_store_corrupt");
    }
    return row;
  };

  const lockProfile = async (client) => {
    const result = await client.query(
      `SELECT lock_revision
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.profile_serialization_locks
       WHERE profile_ref = $1 AND profile_sha256 = $2
       FOR UPDATE`,
      [scope.profileRef, scope.profileSha256],
    );
    if (result.rowCount !== 1 || result.rows[0].lock_revision !== 1) {
      fail("provider_effect_profile_lock_unavailable");
    }
  };

  const selectAuthorization = async (client, proposalId, lock = false) => {
    const result = await client.query(
      `SELECT
         auth.*,
         profile.policy_ref AS profile_policy_ref,
         profile.policy_sha256 AS profile_policy_sha256,
         kill_switch.checked_at AS kill_switch_checked_at,
         kill_switch.state_sha256,
         kill_switch.proof_json AS kill_switch_json,
         release.proposal_hash AS release_proposal_hash,
         release.intent_sha256 AS release_intent_sha256,
         release.policy_sha256 AS release_policy_sha256,
         release.passed AS release_passed,
         release.provider_release_eligible AS release_provider_eligible,
         release.evaluated_at AS release_evaluated_at,
         release.expires_at AS release_expires_at,
         release.proof_json AS evaluation_release_json,
         identity.provider AS identity_provider,
         identity.provider_owner_ref AS identity_provider_owner_ref,
         identity.provider_account_ref AS identity_provider_account_ref,
         identity.credential_owner_ref AS identity_credential_owner_ref,
         identity.verified_at AS identity_verified_at,
         identity.expires_at AS identity_expires_at,
         identity.proof_json AS provider_identity_json,
         ownership.provider AS ownership_provider,
         ownership.provider_owner_ref AS ownership_provider_owner_ref,
         ownership.provider_account_ref AS ownership_provider_account_ref,
         ownership.target_class AS ownership_target_class,
         ownership.resource_key AS ownership_resource_key,
         ownership.provider_resource_ref,
         ownership.verified_at AS ownership_verified_at,
         ownership.expires_at AS ownership_expires_at,
         ownership.proof_json AS resource_ownership_json,
         approval.proposal_id AS approval_proposal_id,
         approval.proposal_hash AS approval_proposal_hash,
         approval.intent_sha256 AS approval_intent_sha256,
         approval.decided_at AS approval_decided_at,
         approval.expires_at AS approval_expires_at,
         approval.proof_json AS approval_json,
         (
           SELECT count(*)::integer
           FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts attempts
           WHERE attempts.profile_ref = auth.profile_ref
             AND attempts.profile_sha256 = auth.profile_sha256
             AND attempts.proposal_id = auth.proposal_id
         ) AS attempts
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.authorization_snapshots auth
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles profile
         USING (profile_ref, profile_sha256)
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.kill_switch_states kill_switch
         ON kill_switch.profile_ref = auth.profile_ref
        AND kill_switch.profile_sha256 = auth.profile_sha256
        AND kill_switch.revision = auth.kill_switch_revision
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.evaluation_releases release
         ON release.profile_ref = auth.profile_ref
        AND release.profile_sha256 = auth.profile_sha256
        AND release.release_sha256 = auth.evaluation_release_sha256
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.provider_identities identity
         ON identity.profile_ref = auth.profile_ref
        AND identity.profile_sha256 = auth.profile_sha256
        AND identity.receipt_sha256 = auth.provider_identity_receipt_sha256
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.resource_ownership_receipts ownership
         ON ownership.profile_ref = auth.profile_ref
        AND ownership.profile_sha256 = auth.profile_sha256
        AND ownership.receipt_sha256 = auth.resource_ownership_receipt_sha256
       LEFT JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.approvals approval
         ON approval.profile_ref = auth.profile_ref
        AND approval.profile_sha256 = auth.profile_sha256
        AND approval.approval_sha256 = auth.approval_sha256
       WHERE auth.profile_ref = $1
         AND auth.profile_sha256 = $2
         AND auth.proposal_id = $3
       ORDER BY auth.revision DESC
       LIMIT 1${lock ? " FOR SHARE OF auth" : ""}`,
      [scope.profileRef, scope.profileSha256, proposalId],
    );
    if (result.rowCount !== 1) fail("provider_effect_authorization_unavailable");
    const row = result.rows[0];
    const authorizedAt = databaseInstant(row.authorized_at, "provider_effect_store_corrupt");
    const createdAt = databaseInstant(row.proposal_created_at, "provider_effect_store_corrupt");
    const expiresAt = databaseInstant(row.proposal_expires_at, "provider_effect_store_corrupt");
    const releaseEvaluatedAt = databaseInstant(row.release_evaluated_at, "provider_effect_store_corrupt");
    const releaseExpiresAt = databaseInstant(row.release_expires_at, "provider_effect_store_corrupt");
    const identityVerifiedAt = databaseInstant(row.identity_verified_at, "provider_effect_store_corrupt");
    const identityExpiresAt = databaseInstant(row.identity_expires_at, "provider_effect_store_corrupt");
    const ownershipVerifiedAt = databaseInstant(row.ownership_verified_at, "provider_effect_store_corrupt");
    const ownershipExpiresAt = databaseInstant(row.ownership_expires_at, "provider_effect_store_corrupt");
    const approvalDecidedAt =
      row.approval_decided_at === null
        ? null
        : databaseInstant(row.approval_decided_at, "provider_effect_store_corrupt");
    const approvalExpiresAt =
      row.approval_expires_at === null
        ? null
        : databaseInstant(row.approval_expires_at, "provider_effect_store_corrupt");
    assertProofDigest(row.kill_switch_json, "stateSha256");
    assertProofDigest(row.evaluation_release_json, "releaseSha256");
    assertProofDigest(row.provider_identity_json, "receiptSha256");
    assertProofDigest(row.resource_ownership_json, "receiptSha256");
    if (row.approval_json !== null) assertProofDigest(row.approval_json, "approvalSha256");
    let checked;
    try {
      checked = suite.assertProposal(row.proposal_json);
    } catch {
      fail("provider_effect_store_corrupt");
    }
    const expectedResourceKey = scope.contracts.PrincipalBinding.hash({
      digestRevision: "ProviderEffectTargetBinding.sha256.v1",
      targetClass: checked.policy.targetClass,
      target: row.proposal_json.target,
    });
    if (
      row.profile_policy_ref !== row.policy_ref ||
      row.profile_policy_sha256 !== row.policy_sha256 ||
      row.proposal_json.proposalId !== row.proposal_id ||
      row.proposal_json.proposalHash !== row.proposal_hash ||
      row.proposal_json.capability !== row.capability ||
      row.proposal_json.capabilityVersion !== row.capability_version ||
      row.proposal_json.provider !== row.provider ||
      row.proposal_json.createdAt !== createdAt ||
      row.proposal_json.expiresAt !== expiresAt ||
      row.kill_switch_json.stateSha256 !== row.state_sha256 ||
      row.kill_switch_json.revision !== Number(row.kill_switch_revision) ||
      row.kill_switch_json.checkedAt !== databaseInstant(row.kill_switch_checked_at, "provider_effect_store_corrupt") ||
      row.kill_switch_json.checkedAt !== authorizedAt ||
      row.evaluation_release_json.releaseSha256 !== row.evaluation_release_sha256 ||
      row.evaluation_release_json.profileRef !== row.profile_ref ||
      row.evaluation_release_json.profileSha256 !== row.profile_sha256 ||
      row.release_proposal_hash !== row.proposal_hash ||
      row.evaluation_release_json.proposalHash !== row.release_proposal_hash ||
      row.release_intent_sha256 !== row.intent_sha256 ||
      row.evaluation_release_json.intentSha256 !== row.release_intent_sha256 ||
      row.release_policy_sha256 !== row.policy_sha256 ||
      row.evaluation_release_json.policySha256 !== row.release_policy_sha256 ||
      row.release_passed !== true ||
      row.evaluation_release_json.passed !== row.release_passed ||
      row.release_provider_eligible !== true ||
      row.evaluation_release_json.providerReleaseEligible !== row.release_provider_eligible ||
      row.evaluation_release_json.evaluatedAt !== releaseEvaluatedAt ||
      row.evaluation_release_json.expiresAt !== releaseExpiresAt ||
      row.provider_identity_json.receiptSha256 !== row.provider_identity_receipt_sha256 ||
      row.provider_identity_json.profileRef !== row.profile_ref ||
      row.provider_identity_json.profileSha256 !== row.profile_sha256 ||
      row.identity_provider !== row.provider ||
      row.provider_identity_json.provider !== row.identity_provider ||
      row.identity_provider_owner_ref !== row.provider_owner_ref ||
      row.provider_identity_json.providerOwnerRef !== row.identity_provider_owner_ref ||
      row.identity_provider_account_ref !== row.provider_account_ref ||
      row.provider_identity_json.providerAccountRef !== row.identity_provider_account_ref ||
      row.provider_identity_json.credentialOwnerRef !== row.identity_credential_owner_ref ||
      row.identity_credential_owner_ref !== row.proposal_json.actor.credentialOwnerRef ||
      row.provider_identity_json.verifiedAt !== identityVerifiedAt ||
      row.provider_identity_json.expiresAt !== identityExpiresAt ||
      row.resource_ownership_json.receiptSha256 !== row.resource_ownership_receipt_sha256 ||
      row.resource_ownership_json.profileRef !== row.profile_ref ||
      row.resource_ownership_json.profileSha256 !== row.profile_sha256 ||
      row.ownership_provider !== row.provider ||
      row.resource_ownership_json.provider !== row.ownership_provider ||
      row.ownership_provider_owner_ref !== row.provider_owner_ref ||
      row.resource_ownership_json.providerOwnerRef !== row.ownership_provider_owner_ref ||
      row.ownership_provider_account_ref !== row.provider_account_ref ||
      row.resource_ownership_json.providerAccountRef !== row.ownership_provider_account_ref ||
      row.resource_ownership_json.targetClass !== row.ownership_target_class ||
      row.ownership_target_class !== checked.policy.targetClass ||
      row.resource_ownership_json.resourceKey !== row.ownership_resource_key ||
      row.ownership_resource_key !== expectedResourceKey ||
      row.resource_ownership_json.providerResourceRef !== row.provider_resource_ref ||
      row.resource_ownership_json.verifiedAt !== ownershipVerifiedAt ||
      row.resource_ownership_json.expiresAt !== ownershipExpiresAt ||
      checked.intent.intentSha256 !== row.intent_sha256 ||
      checked.intent.prospectiveEffectKey !== row.prospective_effect_key ||
      checked.policy.policyRef !== row.policy_ref ||
      checked.policy.policySha256 !== row.policy_sha256 ||
      checked.policy.capability !== row.capability ||
      checked.policy.capabilityVersion !== row.capability_version ||
      checked.policy.provider !== row.provider ||
      checked.policy.operation !== row.operation ||
      checked.policy.providerOwnerRef !== row.provider_owner_ref ||
      checked.policy.authorizationMode !== row.authorization_mode ||
      (row.authorization_mode === "approval-once" &&
        (row.approval_json?.approvalSha256 !== row.approval_sha256 ||
          row.approval_proposal_id !== row.proposal_id ||
          row.approval_json.proposalId !== row.approval_proposal_id ||
          row.approval_proposal_hash !== row.proposal_hash ||
          row.approval_json.proposalHash !== row.approval_proposal_hash ||
          row.approval_intent_sha256 !== row.intent_sha256)) ||
      (row.authorization_mode === "approval-once" &&
        (row.approval_json.intentSha256 !== row.approval_intent_sha256 ||
          row.approval_json.approverPrincipalRef !== row.proposal_json.actor.principalRef ||
          row.approval_json.decision !== "approve_once" ||
          row.approval_json.decidedAt !== approvalDecidedAt ||
          row.approval_json.expiresAt !== approvalExpiresAt ||
          row.approval_json.consumedAt !== null)) ||
      (row.authorization_mode === "automatic" && row.approval_json !== null)
    ) {
      fail("provider_effect_store_corrupt");
    }
    const authorization = {
      profileRef: row.profile_ref,
      profileSha256: row.profile_sha256,
      proposal: row.proposal_json,
      intentSha256: row.intent_sha256,
      prospectiveEffectKey: row.prospective_effect_key,
      policyRef: row.policy_ref,
      policySha256: row.policy_sha256,
      capability: row.capability,
      capabilityVersion: row.capability_version,
      provider: row.provider,
      operation: row.operation,
      providerOwnerRef: row.provider_owner_ref,
      revision: Number(row.revision),
      attempts: row.attempts,
      databaseNow: authorizedAt,
      killSwitch: row.kill_switch_json,
      evaluationRelease: row.evaluation_release_json,
      providerIdentity: row.provider_identity_json,
      resourceOwnership: row.resource_ownership_json,
      approval: row.approval_json,
    };
    if (row.authorization_sha256 !== scope.contracts.PrincipalBinding.hash({ ...authorization, attempts: 0 })) {
      fail("provider_effect_store_corrupt");
    }
    return { authorization: freeze(scope, authorization), row };
  };

  const readAuthorization = (proposalId) => {
    identifier(proposalId, "provider_effect_proposal_id_invalid");
    return transaction(async (client) => (await selectAuthorization(client, proposalId)).authorization, true);
  };

  const assertReservationAuthority = (request, authorization, row, killSwitch) => {
    if (
      request.authorizationSha256 !== row.authorization_sha256 ||
      request.expectedRevision !== authorization.revision ||
      request.killSwitchRevision !== Number(row.kill_switch_revision) ||
      request.killSwitchRevision !== Number(killSwitch.revision) ||
      request.evaluationReleaseSha256 !== row.evaluation_release_sha256 ||
      request.providerIdentityReceiptSha256 !== row.provider_identity_receipt_sha256 ||
      request.resourceOwnershipReceiptSha256 !== row.resource_ownership_receipt_sha256 ||
      request.approvalSha256 !== row.approval_sha256 ||
      killSwitch.engaged
    ) {
      fail(killSwitch.engaged ? "provider_effect_kill_switch_engaged" : "provider_effect_attempt_conflict");
    }
  };

  const assertReservationTime = (authorization, row, databaseNow) => {
    const expiryValues = [
      row.proposal_expires_at,
      row.release_expires_at,
      row.identity_expires_at,
      row.ownership_expires_at,
      ...(row.approval_expires_at === null ? [] : [row.approval_expires_at]),
    ].map((entry) => Date.parse(databaseInstant(entry, "provider_effect_store_corrupt")));
    if (
      Date.parse(databaseNow) < Date.parse(authorization.databaseNow) ||
      expiryValues.some((expiry) => Date.parse(databaseNow) >= expiry)
    ) {
      fail("provider_effect_authorization_expired");
    }
    if (authorization.attempts !== 0) fail("provider_effect_already_reserved");
  };

  const attemptFor = (authorization, request, attemptedAt) => {
    const policy = suite.policy(authorization.capability);
    const leaseExpiresAt = new Date(
      Math.min(Date.parse(authorization.proposal.expiresAt), Date.parse(attemptedAt) + policy.maximumLeaseLifetimeMs),
    ).toISOString();
    if (leaseExpiresAt <= attemptedAt) fail("provider_effect_authorization_expired");
    return freeze(scope, {
      profileRef: authorization.profileRef,
      profileSha256: authorization.profileSha256,
      proposalId: authorization.proposal.proposalId,
      proposalHash: authorization.proposal.proposalHash,
      intentSha256: authorization.intentSha256,
      prospectiveEffectKey: authorization.prospectiveEffectKey,
      policySha256: authorization.policySha256,
      capability: authorization.capability,
      capabilityVersion: authorization.capabilityVersion,
      provider: authorization.provider,
      operation: authorization.operation,
      providerOwnerRef: authorization.providerOwnerRef,
      authorizationSha256: request.authorizationSha256,
      killSwitchRevision: request.killSwitchRevision,
      evaluationReleaseSha256: request.evaluationReleaseSha256,
      providerIdentityReceiptSha256: request.providerIdentityReceiptSha256,
      resourceOwnershipReceiptSha256: request.resourceOwnershipReceiptSha256,
      approvalSha256: request.approvalSha256,
      approvalConsumedAt: request.approvalSha256 === null ? null : attemptedAt,
      attemptRef: `provider-attempt:${authorization.prospectiveEffectKey}`,
      attemptNumber: 1,
      status: "attempting",
      attemptedAt,
      leaseExpiresAt,
      revision: authorization.revision + 1,
    });
  };

  const reserveAttempt = async (value) => {
    const request = exact(
      clone(value),
      [
        "proposalId",
        "authorizationSha256",
        "expectedRevision",
        "killSwitchRevision",
        "evaluationReleaseSha256",
        "providerIdentityReceiptSha256",
        "resourceOwnershipReceiptSha256",
        "approvalSha256",
      ],
      "provider_effect_attempt_request_invalid",
    );
    identifier(request.proposalId, "provider_effect_attempt_request_invalid");
    for (const field of [
      "authorizationSha256",
      "evaluationReleaseSha256",
      "providerIdentityReceiptSha256",
      "resourceOwnershipReceiptSha256",
    ]) {
      digest(request[field], "provider_effect_attempt_request_invalid");
    }
    if (request.approvalSha256 !== null) digest(request.approvalSha256, "provider_effect_attempt_request_invalid");
    if (!Number.isSafeInteger(request.expectedRevision) || !Number.isSafeInteger(request.killSwitchRevision)) {
      fail("provider_effect_attempt_request_invalid");
    }
    const attempt = await transaction(async (client) => {
      const { authorization, row } = await selectAuthorization(client, request.proposalId);
      const killSwitch = await currentKillSwitch(client);
      assertReservationAuthority(request, authorization, row, killSwitch);
      const nowResult = await client.query("SELECT clock_timestamp() AS now");
      const attemptedAt = databaseInstant(nowResult.rows[0].now, "provider_effect_store_failure");
      assertReservationTime(authorization, row, attemptedAt);
      return attemptFor(authorization, request, attemptedAt);
    }, true);
    const holdResult = unknownResult(attempt, "provider_completion_unavailable");
    const holdReceipt = await issueReceipt(
      receiptSemantic({
        attempt,
        result: holdResult,
        completedAt: null,
        reconciliationRef: null,
        priorReceiptSha256: null,
      }),
    );
    return transaction(async (client) => {
      await lockProfile(client);
      const { authorization, row } = await selectAuthorization(client, request.proposalId, true);
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
        `${scope.profileRef}\n${scope.profileSha256}\n${authorization.prospectiveEffectKey}`,
      ]);
      const killSwitch = await currentKillSwitch(client, true);
      assertReservationAuthority(request, authorization, row, killSwitch);
      const nowResult = await client.query("SELECT clock_timestamp() AS now");
      const committedAt = databaseInstant(nowResult.rows[0].now, "provider_effect_store_failure");
      assertReservationTime(authorization, row, committedAt);
      if (
        Date.parse(committedAt) < Date.parse(attempt.attemptedAt) ||
        Date.parse(committedAt) >= Date.parse(attempt.leaseExpiresAt) ||
        !compare(attemptFor(authorization, request, attempt.attemptedAt), attempt)
      ) {
        fail("provider_effect_authorization_expired");
      }
      const attemptSha256 = scope.contracts.PrincipalBinding.hash(attempt);
      await client.query(
        `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts (
           profile_ref, profile_sha256, proposal_id, proposal_hash, intent_sha256,
           prospective_effect_key, policy_sha256, capability, capability_version,
           provider, operation, provider_owner_ref, authorization_revision,
           authorization_sha256, kill_switch_revision, evaluation_release_sha256,
           provider_identity_receipt_sha256, resource_ownership_receipt_sha256,
           approval_sha256, approval_consumed_at, attempt_ref, attempt_number,
           attempted_at, lease_expires_at, revision, attempt_sha256
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
           $14, $15, $16, $17, $18, $19, $20, $21, 1, $22::timestamptz,
           $23::timestamptz, $24, $25
         )`,
        [
          attempt.profileRef,
          attempt.profileSha256,
          attempt.proposalId,
          attempt.proposalHash,
          attempt.intentSha256,
          attempt.prospectiveEffectKey,
          attempt.policySha256,
          attempt.capability,
          attempt.capabilityVersion,
          attempt.provider,
          attempt.operation,
          attempt.providerOwnerRef,
          authorization.revision,
          attempt.authorizationSha256,
          attempt.killSwitchRevision,
          attempt.evaluationReleaseSha256,
          attempt.providerIdentityReceiptSha256,
          attempt.resourceOwnershipReceiptSha256,
          attempt.approvalSha256,
          attempt.approvalConsumedAt,
          attempt.attemptRef,
          attempt.attemptedAt,
          attempt.leaseExpiresAt,
          attempt.revision,
          attemptSha256,
        ],
      );
      if (attempt.approvalSha256 !== null) {
        await client.query(
          `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.approval_consumptions
             (profile_ref, profile_sha256, approval_sha256, attempt_ref, consumed_at)
           VALUES ($1, $2, $3, $4, $5::timestamptz)`,
          [scope.profileRef, scope.profileSha256, attempt.approvalSha256, attempt.attemptRef, attempt.attemptedAt],
        );
      }
      await persistAttemptHold(client, attempt, holdResult, holdReceipt);
      return attempt;
    });
  };

  const selectAttempt = async (client, attemptRef, lock = false) => {
    const result = await client.query(
      `SELECT *
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND attempt_ref = $3${lock ? " FOR SHARE" : ""}`,
      [scope.profileRef, scope.profileSha256, attemptRef],
    );
    if (result.rowCount !== 1) fail("provider_effect_attempt_unavailable");
    return { attempt: attemptFromRow(scope, result.rows[0]), row: result.rows[0] };
  };

  const existingReceipt = async (client, attempt, kind, submittedResultSha256) => {
    const result = await client.query(
      `SELECT *
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_receipts
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND attempt_ref = $3 AND receipt_kind = $4`,
      [scope.profileRef, scope.profileSha256, attempt.attemptRef, kind],
    );
    if (result.rowCount === 0) return null;
    const row = result.rows[0];
    if (row.submitted_result_sha256 !== submittedResultSha256) {
      fail("provider_effect_receipt_result_conflict");
    }
    const receipt = row.receipt_json;
    const storedResult = assertResult(
      scope,
      {
        status: receipt.status,
        provider: receipt.provider,
        operation: receipt.operation,
        providerOwnerRef: receipt.providerOwnerRef,
        providerResourceRef: receipt.providerResourceRef,
        responseSha256: receipt.responseSha256,
        errorCode: receipt.errorCode,
        observationMode: receipt.observationMode,
        providerMutationCount: receipt.providerMutationCount,
      },
      attempt,
      kind === "reconciliation",
    );
    const completedAt =
      row.completed_at === null ? null : databaseInstant(row.completed_at, "provider_effect_store_corrupt");
    const validated = assertReceipt(
      scope,
      signer,
      receipt,
      receiptSemantic({
        attempt,
        result: storedResult,
        completedAt,
        reconciliationRef: row.reconciliation_ref,
        priorReceiptSha256: row.prior_receipt_sha256,
      }),
    );
    if (
      row.receipt_id !== validated.receiptId ||
      row.receipt_sha256 !== validated.receiptSha256 ||
      row.status !== validated.status ||
      row.provider_resource_ref !== validated.providerResourceRef ||
      databaseInstant(row.attempted_at, "provider_effect_store_corrupt") !== validated.attemptedAt ||
      completedAt !== validated.completedAt ||
      row.reconciliation_ref !== validated.reconciliationRef ||
      row.prior_receipt_sha256 !== validated.priorReceiptSha256
    ) {
      fail("provider_effect_store_corrupt");
    }
    return validated;
  };

  const issueReceipt = async (semantic) => {
    let available = false;
    try {
      available = signer.isActive() === true;
    } catch {
      available = false;
    }
    if (!available) fail("provider_effect_receipt_authority_unavailable");
    let timeout;
    const timeoutResult = new Promise((_, reject) => {
      timeout = setTimeout(
        () => reject(new ProviderEffectStoreError("provider_effect_receipt_authority_timeout")),
        receiptIssueTimeoutMs,
      );
    });
    let value;
    try {
      value = await Promise.race([Promise.resolve().then(() => signer.issue(freeze(scope, semantic))), timeoutResult]);
    } finally {
      clearTimeout(timeout);
    }
    try {
      available = signer.isActive() === true;
    } catch {
      available = false;
    }
    if (!available) fail("provider_effect_receipt_authority_unavailable");
    return assertReceipt(scope, signer, value, semantic);
  };

  const persistReceipt = async (client, kind, attempt, result, submittedResultSha256, receipt) => {
    await client.query(
      `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_receipts (
         profile_ref, profile_sha256, attempt_ref, receipt_kind, receipt_id,
         receipt_sha256, status, submitted_result_sha256, provider_resource_ref,
         attempted_at, completed_at, reconciliation_ref, prior_receipt_sha256, receipt_json
       ) VALUES (
         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz,
         $11::timestamptz, $12, $13, $14::jsonb
       )`,
      [
        scope.profileRef,
        scope.profileSha256,
        attempt.attemptRef,
        kind,
        receipt.receiptId,
        receipt.receiptSha256,
        result.status,
        submittedResultSha256,
        result.providerResourceRef,
        attempt.attemptedAt,
        receipt.completedAt,
        receipt.reconciliationRef,
        receipt.priorReceiptSha256,
        canonicalJson(receipt),
      ],
    );
  };

  const unknownResult = (attempt, code) =>
    freeze(scope, {
      status: "outcome_unknown",
      provider: attempt.provider,
      operation: attempt.operation,
      providerOwnerRef: attempt.providerOwnerRef,
      providerResourceRef: null,
      responseSha256: scope.contracts.PrincipalBinding.hash({
        digestRevision: "ProviderEffectUnknownOutcome.sha256.v1",
        attemptRef: attempt.attemptRef,
        code,
      }),
      errorCode: code,
      observationMode: "effect_execution",
      providerMutationCount: null,
    });

  const receiptSemantic = ({ attempt, result, completedAt, reconciliationRef, priorReceiptSha256 }) => ({
    receiptId: `provider-receipt:${reconciliationRef === null ? "execution" : "reconciliation"}:${attempt.attemptRef}`,
    profileRef: attempt.profileRef,
    profileSha256: attempt.profileSha256,
    proposalId: attempt.proposalId,
    proposalHash: attempt.proposalHash,
    intentSha256: attempt.intentSha256,
    prospectiveEffectKey: attempt.prospectiveEffectKey,
    attemptRef: attempt.attemptRef,
    attemptNumber: 1,
    status: result.status,
    provider: result.provider,
    operation: result.operation,
    providerOwnerRef: result.providerOwnerRef,
    providerResourceRef: result.providerResourceRef,
    responseSha256: result.responseSha256,
    errorCode: result.errorCode,
    observationMode: result.observationMode,
    providerMutationCount: result.providerMutationCount,
    attemptedAt: attempt.attemptedAt,
    completedAt,
    reconciliationRef,
    priorReceiptSha256,
    authenticatedBy: signer.issuerRef,
    authenticationSha256: signer.authenticationSha256,
  });

  const persistAttemptHold = async (client, attempt, result, receipt) => {
    await client.query(
      `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.attempt_unknown_holds (
         profile_ref, profile_sha256, attempt_ref, receipt_id,
         receipt_sha256, result_sha256, status, error_code, receipt_json
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
      [
        scope.profileRef,
        scope.profileSha256,
        attempt.attemptRef,
        receipt.receiptId,
        receipt.receiptSha256,
        scope.contracts.PrincipalBinding.hash(result),
        result.status,
        result.errorCode,
        canonicalJson(receipt),
      ],
    );
  };

  const selectAttemptHold = async (client, attempt) => {
    const selected = await client.query(
      `SELECT *
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.attempt_unknown_holds
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND attempt_ref = $3`,
      [scope.profileRef, scope.profileSha256, attempt.attemptRef],
    );
    if (selected.rowCount !== 1) fail("provider_effect_attempt_hold_unavailable");
    const row = selected.rows[0];
    const result = unknownResult(attempt, row.error_code);
    const receipt = assertReceipt(
      scope,
      signer,
      row.receipt_json,
      receiptSemantic({
        attempt,
        result,
        completedAt: null,
        reconciliationRef: null,
        priorReceiptSha256: null,
      }),
    );
    if (
      row.receipt_id !== receipt.receiptId ||
      row.receipt_sha256 !== receipt.receiptSha256 ||
      row.result_sha256 !== scope.contracts.PrincipalBinding.hash(result) ||
      row.status !== result.status ||
      row.error_code !== result.errorCode
    ) {
      fail("provider_effect_store_corrupt");
    }
    return { result, receipt };
  };

  const activateAttemptHold = async (client, attempt, submittedResultSha256) => {
    const prior = await existingReceipt(client, attempt, "execution", submittedResultSha256);
    if (prior) return prior;
    const hold = await selectAttemptHold(client, attempt);
    await persistReceipt(client, "execution", attempt, hold.result, submittedResultSha256, hold.receipt);
    return hold.receipt;
  };

  const recoverAttemptCompletion = async (suppliedAttempt, submittedResultSha256) => {
    let failure;
    for (let recoveryAttempt = 0; recoveryAttempt < 4; recoveryAttempt += 1) {
      try {
        return await transaction(
          async (client) => {
            await lockProfile(client);
            const selected = await selectAttempt(client, suppliedAttempt.attemptRef, true);
            if (!compare(selected.attempt, suppliedAttempt)) fail("provider_effect_attempt_conflict");
            return activateAttemptHold(client, selected.attempt, submittedResultSha256);
          },
          false,
          false,
        );
      } catch (error) {
        if (
          error?.code === "provider_effect_attempt_conflict" ||
          error?.code === "provider_effect_receipt_result_conflict" ||
          error?.code === "provider_effect_store_corrupt"
        ) {
          throw error;
        }
        failure = error;
      }
    }
    throw failure;
  };

  const completionCandidate = async (attempt, result, completedAt) => {
    const receipt = await issueReceipt(
      receiptSemantic({
        attempt,
        result,
        completedAt,
        reconciliationRef: null,
        priorReceiptSha256: null,
      }),
    );
    return { result, receipt };
  };

  const completeAttempt = async (value) => {
    const input = exact(clone(value), ["attempt", "result"], "provider_effect_completion_invalid");
    const suppliedAttempt = exact(input.attempt, attemptFields, "provider_effect_attempt_invalid");
    identifier(suppliedAttempt.attemptRef, "provider_effect_attempt_invalid");
    const submitted = assertResult(scope, input.result, suppliedAttempt, false);
    const submittedResultSha256 = scope.contracts.PrincipalBinding.hash(submitted);
    let preparation;
    try {
      preparation = await transaction(async (client) => {
        const selected = await selectAttempt(client, suppliedAttempt.attemptRef);
        if (!compare(selected.attempt, suppliedAttempt)) fail("provider_effect_attempt_conflict");
        const prior = await existingReceipt(client, selected.attempt, "execution", submittedResultSha256);
        if (prior) return { prior };
        const nowResult = await client.query("SELECT clock_timestamp() AS now");
        return {
          attempt: selected.attempt,
          completedAt: databaseInstant(nowResult.rows[0].now, "provider_effect_store_failure"),
        };
      }, true);
    } catch {
      return recoverAttemptCompletion(suppliedAttempt, submittedResultSha256);
    }
    if (preparation.prior) return preparation.prior;
    let candidates;
    try {
      candidates = {
        submitted: await completionCandidate(
          preparation.attempt,
          submitted,
          submitted.status === "outcome_unknown" ? null : preparation.completedAt,
        ),
        killSwitch: await completionCandidate(
          preparation.attempt,
          unknownResult(preparation.attempt, "provider_kill_switch_changed_after_reservation"),
          null,
        ),
        lease: await completionCandidate(
          preparation.attempt,
          unknownResult(preparation.attempt, "provider_attempt_lease_expired"),
          null,
        ),
      };
      ensureActive();
    } catch {
      return recoverAttemptCompletion(suppliedAttempt, submittedResultSha256);
    }
    try {
      return await transaction(
        async (client) => {
          await lockProfile(client);
          const selected = await selectAttempt(client, suppliedAttempt.attemptRef, true);
          if (!compare(selected.attempt, suppliedAttempt)) fail("provider_effect_attempt_conflict");
          const prior = await existingReceipt(client, selected.attempt, "execution", submittedResultSha256);
          if (prior) return prior;
          const killSwitch = await currentKillSwitch(client, true);
          const nowResult = await client.query("SELECT clock_timestamp() AS now");
          const now = databaseInstant(nowResult.rows[0].now, "provider_effect_store_failure");
          const candidate =
            killSwitch.engaged || Number(killSwitch.revision) !== selected.attempt.killSwitchRevision
              ? candidates.killSwitch
              : Date.parse(now) >= Date.parse(selected.attempt.leaseExpiresAt)
                ? candidates.lease
                : candidates.submitted;
          if (
            candidate.receipt.completedAt !== null &&
            (Date.parse(candidate.receipt.completedAt) < Date.parse(selected.attempt.attemptedAt) ||
              Date.parse(candidate.receipt.completedAt) > Date.parse(now))
          ) {
            fail("provider_effect_receipt_invalid");
          }
          await persistReceipt(
            client,
            "execution",
            selected.attempt,
            candidate.result,
            submittedResultSha256,
            candidate.receipt,
          );
          return candidate.receipt;
        },
        false,
        false,
      );
    } catch {
      return recoverAttemptCompletion(suppliedAttempt, submittedResultSha256);
    }
  };

  const selectReconciliation = async (client, proposalId, revision = null, lock = false, includeResolved = false) => {
    const parameters = [scope.profileRef, scope.profileSha256, proposalId];
    const revisionFilter = revision === null ? "" : ` AND reconciliation.revision = $${parameters.push(revision)}`;
    const result = await client.query(
      `SELECT
         attempt.*,
         reconciliation.prior_receipt_sha256 AS reconciliation_prior_receipt_sha256,
         reconciliation.authentication_sha256 AS reconciliation_authentication_sha256,
         reconciliation.kill_switch_revision AS reconciliation_kill_switch_revision,
         reconciliation.database_now,
         reconciliation.revision AS reconciliation_revision,
         auth.proposal_json,
         identity.provider AS identity_provider,
         identity.provider_owner_ref AS identity_provider_owner_ref,
         identity.provider_account_ref AS identity_provider_account_ref,
         identity.credential_owner_ref AS identity_credential_owner_ref,
         identity.verified_at AS identity_verified_at,
         identity.expires_at AS provider_identity_expires_at,
         identity.proof_json AS provider_identity_json,
         ownership.provider AS ownership_provider,
         ownership.provider_owner_ref AS ownership_provider_owner_ref,
         ownership.provider_account_ref AS ownership_provider_account_ref,
         ownership.target_class AS ownership_target_class,
         ownership.resource_key AS ownership_resource_key,
         ownership.provider_resource_ref AS ownership_provider_resource_ref,
         ownership.verified_at AS ownership_verified_at,
         ownership.expires_at AS ownership_expires_at,
         ownership.proof_json AS resource_ownership_json,
         execution_receipt.receipt_sha256 AS prior_receipt_digest,
         execution_receipt.submitted_result_sha256 AS execution_submitted_result_sha256,
         execution_receipt.receipt_json AS prior_receipt_json,
         kill_switch.engaged AS kill_switch_engaged,
         kill_switch.checked_at AS kill_switch_checked_at,
         kill_switch.state_sha256,
         kill_switch.proof_json AS kill_switch_json,
         reconciliation_identity.reconciler_principal_ref,
         reconciliation_identity.authenticated_at,
         reconciliation_identity.expires_at AS identity_expires_at,
         reconciliation_identity.proof_json AS reconciliation_identity_json
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_authorizations reconciliation
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts attempt
         ON attempt.profile_ref = reconciliation.profile_ref
        AND attempt.profile_sha256 = reconciliation.profile_sha256
        AND attempt.attempt_ref = reconciliation.attempt_ref
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.authorization_snapshots auth
         ON auth.profile_ref = attempt.profile_ref
        AND auth.profile_sha256 = attempt.profile_sha256
        AND auth.proposal_id = attempt.proposal_id
        AND auth.revision = attempt.authorization_revision
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.provider_identities identity
         ON identity.profile_ref = attempt.profile_ref
        AND identity.profile_sha256 = attempt.profile_sha256
        AND identity.receipt_sha256 = attempt.provider_identity_receipt_sha256
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.resource_ownership_receipts ownership
         ON ownership.profile_ref = attempt.profile_ref
        AND ownership.profile_sha256 = attempt.profile_sha256
        AND ownership.receipt_sha256 = attempt.resource_ownership_receipt_sha256
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_receipts execution_receipt
         ON execution_receipt.profile_ref = attempt.profile_ref
        AND execution_receipt.profile_sha256 = attempt.profile_sha256
        AND execution_receipt.attempt_ref = attempt.attempt_ref
        AND execution_receipt.receipt_kind = 'execution'
        AND execution_receipt.status = 'outcome_unknown'
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.kill_switch_states kill_switch
         ON kill_switch.profile_ref = reconciliation.profile_ref
        AND kill_switch.profile_sha256 = reconciliation.profile_sha256
        AND kill_switch.revision = reconciliation.kill_switch_revision
       JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_identities reconciliation_identity
         ON reconciliation_identity.profile_ref = reconciliation.profile_ref
        AND reconciliation_identity.profile_sha256 = reconciliation.profile_sha256
        AND reconciliation_identity.attempt_ref = reconciliation.attempt_ref
        AND reconciliation_identity.prior_receipt_sha256 = reconciliation.prior_receipt_sha256
        AND reconciliation_identity.authentication_sha256 = reconciliation.authentication_sha256
       LEFT JOIN ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_receipts resolved
         ON resolved.profile_ref = attempt.profile_ref
        AND resolved.profile_sha256 = attempt.profile_sha256
        AND resolved.attempt_ref = attempt.attempt_ref
        AND resolved.receipt_kind = 'reconciliation'
       WHERE reconciliation.profile_ref = $1
         AND reconciliation.profile_sha256 = $2
         AND reconciliation.proposal_id = $3
         ${includeResolved ? "" : "AND resolved.attempt_ref IS NULL"}${revisionFilter}
       ORDER BY reconciliation.revision DESC
       LIMIT 1${lock ? " FOR SHARE OF reconciliation, attempt" : ""}`,
      parameters,
    );
    if (result.rowCount !== 1) fail("provider_effect_reconciliation_unavailable");
    const row = result.rows[0];
    const attempt = attemptFromRow(scope, row);
    const reconciliationDatabaseNow = databaseInstant(row.database_now, "provider_effect_store_corrupt");
    const killSwitchCheckedAt = databaseInstant(row.kill_switch_checked_at, "provider_effect_store_corrupt");
    const identityAuthenticatedAt = databaseInstant(row.authenticated_at, "provider_effect_store_corrupt");
    const identityExpiresAt = databaseInstant(row.identity_expires_at, "provider_effect_store_corrupt");
    const providerIdentityVerifiedAt = databaseInstant(row.identity_verified_at, "provider_effect_store_corrupt");
    const providerIdentityExpiresAt = databaseInstant(
      row.provider_identity_expires_at,
      "provider_effect_store_corrupt",
    );
    const ownershipVerifiedAt = databaseInstant(row.ownership_verified_at, "provider_effect_store_corrupt");
    const ownershipExpiresAt = databaseInstant(row.ownership_expires_at, "provider_effect_store_corrupt");
    let checked;
    try {
      checked = suite.assertProposal(row.proposal_json);
    } catch {
      fail("provider_effect_store_corrupt");
    }
    const expectedResourceKey = scope.contracts.PrincipalBinding.hash({
      digestRevision: "ProviderEffectTargetBinding.sha256.v1",
      targetClass: checked.policy.targetClass,
      target: row.proposal_json.target,
    });
    const priorReceipt = await existingReceipt(client, attempt, "execution", row.execution_submitted_result_sha256);
    assertProofDigest(row.kill_switch_json, "stateSha256");
    assertProofDigest(row.reconciliation_identity_json, "authenticationSha256");
    assertProofDigest(row.provider_identity_json, "receiptSha256");
    assertProofDigest(row.resource_ownership_json, "receiptSha256");
    if (
      row.reconciliation_prior_receipt_sha256 !== row.prior_receipt_digest ||
      !compare(priorReceipt, row.prior_receipt_json) ||
      row.prior_receipt_json.receiptSha256 !== row.prior_receipt_digest ||
      row.prior_receipt_json.status !== "outcome_unknown" ||
      row.prior_receipt_json.attemptRef !== row.attempt_ref ||
      row.kill_switch_json.stateSha256 !== row.state_sha256 ||
      row.kill_switch_json.profileRef !== row.profile_ref ||
      row.kill_switch_json.profileSha256 !== row.profile_sha256 ||
      row.kill_switch_json.engaged !== row.kill_switch_engaged ||
      row.kill_switch_json.revision !== Number(row.reconciliation_kill_switch_revision) ||
      row.kill_switch_json.checkedAt !== killSwitchCheckedAt ||
      Date.parse(row.kill_switch_json.checkedAt) > Date.parse(reconciliationDatabaseNow) ||
      row.provider_identity_json.receiptSha256 !== row.provider_identity_receipt_sha256 ||
      row.provider_identity_json.profileRef !== row.profile_ref ||
      row.provider_identity_json.profileSha256 !== row.profile_sha256 ||
      row.provider_identity_json.provider !== row.identity_provider ||
      row.identity_provider !== row.provider ||
      row.provider_identity_json.providerOwnerRef !== row.identity_provider_owner_ref ||
      row.identity_provider_owner_ref !== row.provider_owner_ref ||
      row.provider_identity_json.providerAccountRef !== row.identity_provider_account_ref ||
      row.provider_identity_json.credentialOwnerRef !== row.identity_credential_owner_ref ||
      row.identity_credential_owner_ref !== row.proposal_json.actor.credentialOwnerRef ||
      row.provider_identity_json.verifiedAt !== providerIdentityVerifiedAt ||
      row.provider_identity_json.expiresAt !== providerIdentityExpiresAt ||
      row.resource_ownership_json.receiptSha256 !== row.resource_ownership_receipt_sha256 ||
      row.resource_ownership_json.profileRef !== row.profile_ref ||
      row.resource_ownership_json.profileSha256 !== row.profile_sha256 ||
      row.resource_ownership_json.provider !== row.ownership_provider ||
      row.ownership_provider !== row.provider ||
      row.resource_ownership_json.providerOwnerRef !== row.ownership_provider_owner_ref ||
      row.ownership_provider_owner_ref !== row.provider_owner_ref ||
      row.resource_ownership_json.providerAccountRef !== row.ownership_provider_account_ref ||
      row.ownership_provider_account_ref !== row.identity_provider_account_ref ||
      row.resource_ownership_json.targetClass !== row.ownership_target_class ||
      row.ownership_target_class !== checked.policy.targetClass ||
      row.resource_ownership_json.resourceKey !== row.ownership_resource_key ||
      row.ownership_resource_key !== expectedResourceKey ||
      row.resource_ownership_json.providerResourceRef !== row.ownership_provider_resource_ref ||
      row.resource_ownership_json.verifiedAt !== ownershipVerifiedAt ||
      row.resource_ownership_json.expiresAt !== ownershipExpiresAt ||
      row.reconciliation_identity_json.authenticationSha256 !== row.reconciliation_authentication_sha256 ||
      row.reconciliation_identity_json.profileRef !== row.profile_ref ||
      row.reconciliation_identity_json.profileSha256 !== row.profile_sha256 ||
      row.reconciliation_identity_json.capability !== row.capability ||
      row.reconciliation_identity_json.attemptRef !== row.attempt_ref ||
      row.reconciliation_identity_json.priorReceiptSha256 !== row.reconciliation_prior_receipt_sha256 ||
      row.reconciliation_identity_json.reconcilerPrincipalRef !== row.reconciler_principal_ref ||
      row.reconciliation_identity_json.authenticatedAt !== identityAuthenticatedAt ||
      row.reconciliation_identity_json.expiresAt !== identityExpiresAt ||
      Date.parse(reconciliationDatabaseNow) < Date.parse(attempt.leaseExpiresAt) ||
      Date.parse(reconciliationDatabaseNow) < Date.parse(identityAuthenticatedAt) ||
      Date.parse(reconciliationDatabaseNow) >= Date.parse(identityExpiresAt)
    ) {
      fail("provider_effect_store_corrupt");
    }
    const reconciliation = {
      profileRef: attempt.profileRef,
      profileSha256: attempt.profileSha256,
      proposal: row.proposal_json,
      intentSha256: attempt.intentSha256,
      prospectiveEffectKey: attempt.prospectiveEffectKey,
      policySha256: attempt.policySha256,
      capability: attempt.capability,
      capabilityVersion: attempt.capabilityVersion,
      provider: attempt.provider,
      operation: attempt.operation,
      providerOwnerRef: attempt.providerOwnerRef,
      providerAccountRef: row.identity_provider_account_ref,
      providerResourceRef: row.ownership_provider_resource_ref,
      attemptRef: attempt.attemptRef,
      attemptNumber: 1,
      attemptedAt: attempt.attemptedAt,
      attemptLeaseExpiresAt: attempt.leaseExpiresAt,
      priorStatus: "outcome_unknown",
      priorReceiptSha256: row.reconciliation_prior_receipt_sha256,
      databaseNow: reconciliationDatabaseNow,
      killSwitch: row.kill_switch_json,
      reconciliationIdentity: row.reconciliation_identity_json,
      revision: Number(row.reconciliation_revision),
    };
    return { reconciliation: freeze(scope, reconciliation), attempt, row };
  };

  const readReconciliation = (proposalId) => {
    identifier(proposalId, "provider_effect_proposal_id_invalid");
    return transaction(async (client) => {
      const selected = await selectReconciliation(client, proposalId);
      const current = await currentKillSwitch(client);
      if (Number(current.revision) !== Number(selected.row.reconciliation_kill_switch_revision) || current.engaged) {
        fail(current.engaged ? "provider_effect_kill_switch_engaged" : "provider_effect_reconciliation_conflict");
      }
      return selected.reconciliation;
    }, true);
  };

  const reserveReconciliation = (value) => {
    const request = exact(
      clone(value),
      [
        "proposalId",
        "proposalHash",
        "intentSha256",
        "prospectiveEffectKey",
        "attemptRef",
        "priorReceiptSha256",
        "expectedRevision",
        "authenticationSha256",
        "killSwitchRevision",
        "mode",
      ],
      "provider_effect_reconciliation_request_invalid",
    );
    for (const field of ["proposalId", "attemptRef"])
      identifier(request[field], "provider_effect_reconciliation_request_invalid");
    for (const field of [
      "proposalHash",
      "intentSha256",
      "prospectiveEffectKey",
      "priorReceiptSha256",
      "authenticationSha256",
    ]) {
      digest(request[field], "provider_effect_reconciliation_request_invalid");
    }
    if (
      !Number.isSafeInteger(request.expectedRevision) ||
      !Number.isSafeInteger(request.killSwitchRevision) ||
      request.mode !== "read_only_status_lookup"
    ) {
      fail("provider_effect_reconciliation_request_invalid");
    }
    return transaction(async (client) => {
      await lockProfile(client);
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
        `${scope.profileRef}\n${scope.profileSha256}\n${request.attemptRef}\nreconciliation`,
      ]);
      const selected = await selectReconciliation(client, request.proposalId, request.expectedRevision, true);
      const { reconciliation, attempt, row } = selected;
      const current = await currentKillSwitch(client, true);
      if (
        request.proposalHash !== reconciliation.proposal.proposalHash ||
        request.intentSha256 !== reconciliation.intentSha256 ||
        request.prospectiveEffectKey !== reconciliation.prospectiveEffectKey ||
        request.attemptRef !== reconciliation.attemptRef ||
        request.priorReceiptSha256 !== reconciliation.priorReceiptSha256 ||
        request.authenticationSha256 !== reconciliation.reconciliationIdentity.authenticationSha256 ||
        request.killSwitchRevision !== reconciliation.killSwitch.revision ||
        request.killSwitchRevision !== Number(current.revision) ||
        current.engaged
      ) {
        fail(current.engaged ? "provider_effect_kill_switch_engaged" : "provider_effect_reconciliation_conflict");
      }
      const nowResult = await client.query("SELECT clock_timestamp() AS now");
      const acquiredAt = databaseInstant(nowResult.rows[0].now, "provider_effect_store_failure");
      if (
        Date.parse(acquiredAt) < Date.parse(attempt.leaseExpiresAt) ||
        Date.parse(acquiredAt) >= Date.parse(databaseInstant(row.identity_expires_at, "provider_effect_store_corrupt"))
      ) {
        fail("provider_effect_reconciliation_not_available");
      }
      const currentLease = await client.query(
        `SELECT expires_at
         FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_leases
         WHERE profile_ref = $1 AND profile_sha256 = $2 AND attempt_ref = $3
         ORDER BY acquired_at DESC, reconciliation_ref DESC
         LIMIT 1 FOR SHARE`,
        [scope.profileRef, scope.profileSha256, attempt.attemptRef],
      );
      if (
        currentLease.rowCount === 1 &&
        Date.parse(acquiredAt) <
          Date.parse(databaseInstant(currentLease.rows[0].expires_at, "provider_effect_store_corrupt"))
      ) {
        fail("provider_effect_reconciliation_lease_conflict");
      }
      const maximumLeaseLifetimeMs = suite.policy(reconciliation.capability).maximumLeaseLifetimeMs;
      const expiresAt = new Date(
        Math.min(
          Date.parse(acquiredAt) + maximumLeaseLifetimeMs,
          Date.parse(databaseInstant(row.identity_expires_at, "provider_effect_store_corrupt")),
        ),
      ).toISOString();
      if (expiresAt <= acquiredAt) fail("provider_effect_reconciliation_not_available");
      const lease = {
        profileRef: reconciliation.profileRef,
        profileSha256: reconciliation.profileSha256,
        proposalId: reconciliation.proposal.proposalId,
        proposalHash: reconciliation.proposal.proposalHash,
        intentSha256: reconciliation.intentSha256,
        prospectiveEffectKey: reconciliation.prospectiveEffectKey,
        attemptRef: reconciliation.attemptRef,
        priorReceiptSha256: reconciliation.priorReceiptSha256,
        authenticationSha256: reconciliation.reconciliationIdentity.authenticationSha256,
        killSwitchRevision: reconciliation.killSwitch.revision,
        reconciliationRef: `provider-reconciliation:${randomUUID()}`,
        reconcilerPrincipalRef: reconciliation.reconciliationIdentity.reconcilerPrincipalRef,
        mode: "read_only_status_lookup",
        acquiredAt,
        expiresAt,
        revision: reconciliation.revision,
      };
      const leaseSha256 = scope.contracts.PrincipalBinding.hash(lease);
      await client.query(
        `INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_leases (
           profile_ref, profile_sha256, attempt_ref, prior_receipt_sha256,
           authentication_sha256, kill_switch_revision, reconciliation_ref,
           reconciler_principal_ref, mode, acquired_at, expires_at, revision, lease_sha256
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, 'read_only_status_lookup',
           $9::timestamptz, $10::timestamptz, $11, $12
         )`,
        [
          scope.profileRef,
          scope.profileSha256,
          lease.attemptRef,
          lease.priorReceiptSha256,
          lease.authenticationSha256,
          lease.killSwitchRevision,
          lease.reconciliationRef,
          lease.reconcilerPrincipalRef,
          lease.acquiredAt,
          lease.expiresAt,
          lease.revision,
          leaseSha256,
        ],
      );
      return freeze(scope, lease);
    });
  };

  const selectReconciliationCompletion = async (client, input, suppliedLease, lock) => {
    const leaseResult = await client.query(
      `SELECT *
       FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_leases
       WHERE profile_ref = $1 AND profile_sha256 = $2 AND reconciliation_ref = $3${lock ? " FOR SHARE" : ""}`,
      [scope.profileRef, scope.profileSha256, suppliedLease.reconciliationRef],
    );
    if (leaseResult.rowCount !== 1) fail("provider_effect_reconciliation_lease_unavailable");
    const selected = await selectReconciliation(client, suppliedLease.proposalId, suppliedLease.revision, lock, true);
    const lease = leaseFromRow(scope, leaseResult.rows[0], selected.attempt);
    if (!compare(lease, suppliedLease) || !compare(selected.reconciliation, input.reconciliation)) {
      fail("provider_effect_reconciliation_conflict");
    }
    const result = assertResult(scope, input.result, selected.attempt, true);
    const submittedResultSha256 = scope.contracts.PrincipalBinding.hash(result);
    const prior = await existingReceipt(client, selected.attempt, "reconciliation", submittedResultSha256);
    return { reconciliationSelection: selected, lease, result, submittedResultSha256, prior };
  };

  const completeReconciliation = async (value) => {
    const input = exact(
      clone(value),
      ["reconciliation", "lease", "result"],
      "provider_effect_reconciliation_completion_invalid",
    );
    const suppliedLease = exact(input.lease, leaseFields, "provider_effect_reconciliation_lease_invalid");
    identifier(suppliedLease.reconciliationRef, "provider_effect_reconciliation_lease_invalid");
    const preparation = await transaction(async (client) => {
      const selected = await selectReconciliationCompletion(client, input, suppliedLease, false);
      if (selected.prior) return selected;
      const nowResult = await client.query("SELECT clock_timestamp() AS now");
      return {
        ...selected,
        completedAt: databaseInstant(nowResult.rows[0].now, "provider_effect_store_failure"),
      };
    }, true);
    if (preparation.prior) return preparation.prior;
    const receipt = await issueReceipt(
      receiptSemantic({
        attempt: preparation.reconciliationSelection.attempt,
        result: preparation.result,
        completedAt: preparation.completedAt,
        reconciliationRef: preparation.lease.reconciliationRef,
        priorReceiptSha256: preparation.reconciliationSelection.reconciliation.priorReceiptSha256,
      }),
    );
    ensureActive();
    let failure;
    for (let commitAttempt = 0; commitAttempt < 4; commitAttempt += 1) {
      try {
        return await transaction(
          async (client) => {
            await lockProfile(client);
            const completion = await selectReconciliationCompletion(client, input, suppliedLease, true);
            if (completion.prior) return completion.prior;
            const current = await currentKillSwitch(client, true);
            const nowResult = await client.query("SELECT clock_timestamp() AS now");
            const databaseNow = databaseInstant(nowResult.rows[0].now, "provider_effect_store_failure");
            if (
              current.engaged ||
              Number(current.revision) !== completion.lease.killSwitchRevision ||
              Date.parse(databaseNow) >= Date.parse(completion.lease.expiresAt) ||
              completion.result.providerResourceRef !==
                completion.reconciliationSelection.reconciliation.providerResourceRef ||
              Date.parse(receipt.completedAt) <
                Date.parse(completion.reconciliationSelection.reconciliation.databaseNow) ||
              Date.parse(receipt.completedAt) > Date.parse(databaseNow)
            ) {
              fail(current.engaged ? "provider_effect_kill_switch_engaged" : "provider_effect_reconciliation_conflict");
            }
            await persistReceipt(
              client,
              "reconciliation",
              completion.reconciliationSelection.attempt,
              completion.result,
              completion.submittedResultSha256,
              receipt,
            );
            return receipt;
          },
          false,
          false,
        );
      } catch (error) {
        if (
          error?.code === "provider_effect_kill_switch_engaged" ||
          error?.code === "provider_effect_reconciliation_conflict" ||
          error?.code === "provider_effect_receipt_result_conflict" ||
          error?.code === "provider_effect_store_corrupt"
        ) {
          throw error;
        }
        failure = error;
      }
    }
    throw failure;
  };

  const port = {
    readAuthorization,
    reserveAttempt,
    completeAttempt,
    readReconciliation,
    reserveReconciliation,
    completeReconciliation,
    isActive: () => {
      try {
        return active.isActive() === true;
      } catch {
        return false;
      }
    },
  };
  return Object.freeze(port);
}
