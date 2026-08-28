import { createHash } from "node:crypto";

export const PROVIDER_EFFECT_AUTHORITY_SCHEMA = "risely_provider_effect_authority_future_v1";
export const PROVIDER_EFFECT_AUTHORITY_SCHEMA_VERSION = 1;

const body = `
CREATE SCHEMA ${PROVIDER_EFFECT_AUTHORITY_SCHEMA};

CREATE FUNCTION ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reject_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'provider_effect_authority_append_only' USING ERRCODE = '55000';
END;
$$;

REVOKE ALL ON FUNCTION ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reject_mutation() FROM PUBLIC;

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.schema_versions (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  version integer NOT NULL CHECK (version = ${PROVIDER_EFFECT_AUTHORITY_SCHEMA_VERSION}),
  migration_sha256 text NOT NULL CHECK (migration_sha256 ~ '^[0-9a-f]{64}$'),
  installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL CHECK (profile_sha256 ~ '^[0-9a-f]{64}$'),
  policy_ref text NOT NULL,
  policy_sha256 text NOT NULL CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
  profile_json jsonb NOT NULL CHECK (jsonb_typeof(profile_json) = 'object'),
  provider_execution_allowed boolean NOT NULL CHECK (provider_execution_allowed = false),
  PRIMARY KEY (profile_ref, profile_sha256),
  UNIQUE (profile_ref),
  UNIQUE (profile_sha256)
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.profile_serialization_locks (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  lock_revision integer NOT NULL CHECK (lock_revision = 1),
  PRIMARY KEY (profile_ref, profile_sha256),
  FOREIGN KEY (profile_ref, profile_sha256)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles (profile_ref, profile_sha256)
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.kill_switch_states (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  revision bigint NOT NULL CHECK (revision >= 0),
  engaged boolean NOT NULL,
  checked_at timestamptz NOT NULL,
  state_sha256 text NOT NULL CHECK (state_sha256 ~ '^[0-9a-f]{64}$'),
  proof_json jsonb NOT NULL CHECK (jsonb_typeof(proof_json) = 'object'),
  PRIMARY KEY (profile_ref, profile_sha256, revision),
  UNIQUE (profile_ref, profile_sha256, revision, checked_at),
  UNIQUE (profile_ref, profile_sha256, state_sha256),
  FOREIGN KEY (profile_ref, profile_sha256)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles (profile_ref, profile_sha256)
);

CREATE FUNCTION ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.register_deployment_profile(p_profile jsonb) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_profile_ref text := p_profile->>'profileRef';
  v_profile_sha256 text := p_profile->>'profileSha256';
  v_policy_ref text := p_profile->>'providerEffectPolicyRef';
  v_policy_sha256 text := p_profile->>'providerEffectPolicySha256';
BEGIN
  IF jsonb_typeof(p_profile) <> 'object'
    OR v_profile_ref IS NULL
    OR v_profile_sha256 !~ '^[0-9a-f]{64}$'
    OR v_policy_ref IS NULL
    OR v_policy_sha256 !~ '^[0-9a-f]{64}$'
    OR p_profile->'providerExecutionAllowed' <> 'false'::jsonb THEN
    RAISE EXCEPTION 'provider_effect_profile_invalid' USING ERRCODE = '22023';
  END IF;

  INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles
    (profile_ref, profile_sha256, policy_ref, policy_sha256, profile_json, provider_execution_allowed)
  VALUES (v_profile_ref, v_profile_sha256, v_policy_ref, v_policy_sha256, p_profile, false);

  INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.profile_serialization_locks
    (profile_ref, profile_sha256, lock_revision)
  VALUES (v_profile_ref, v_profile_sha256, 1);
END;
$$;

CREATE FUNCTION ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.append_kill_switch(
  p_profile_ref text,
  p_profile_sha256 text,
  p_expected_previous_revision bigint,
  p_proof jsonb
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_current_revision bigint;
  v_revision bigint;
  v_engaged boolean;
  v_checked_at timestamptz;
  v_state_sha256 text;
BEGIN
  PERFORM 1
  FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.profile_serialization_locks
  WHERE profile_ref = p_profile_ref AND profile_sha256 = p_profile_sha256
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'provider_effect_profile_lock_unavailable' USING ERRCODE = '55000';
  END IF;

  SELECT max(revision) INTO v_current_revision
  FROM ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.kill_switch_states
  WHERE profile_ref = p_profile_ref AND profile_sha256 = p_profile_sha256;

  IF COALESCE(v_current_revision, 0) <> p_expected_previous_revision THEN
    RAISE EXCEPTION 'provider_effect_kill_switch_head_conflict' USING ERRCODE = '40001';
  END IF;

  IF jsonb_typeof(p_proof) <> 'object'
    OR (SELECT count(*) FROM jsonb_object_keys(p_proof)) <> 9
    OR jsonb_typeof(p_proof->'profileRef') <> 'string'
    OR p_proof->>'profileRef' <> p_profile_ref
    OR jsonb_typeof(p_proof->'profileSha256') <> 'string'
    OR p_proof->>'profileSha256' <> p_profile_sha256
    OR jsonb_typeof(p_proof->'revision') <> 'number'
    OR jsonb_typeof(p_proof->'engaged') <> 'boolean'
    OR jsonb_typeof(p_proof->'checkedAt') <> 'string'
    OR p_proof->>'stateSha256' IS NULL
    OR jsonb_typeof(p_proof->'stateSha256') <> 'string'
    OR p_proof->>'stateSha256' !~ '^[0-9a-f]{64}$'
    OR jsonb_typeof(p_proof->'keyId') <> 'string'
    OR jsonb_typeof(p_proof->'issuerRef') <> 'string'
    OR jsonb_typeof(p_proof->'signature') <> 'string' THEN
    RAISE EXCEPTION 'provider_effect_kill_switch_proof_invalid' USING ERRCODE = '22023';
  END IF;

  BEGIN
    v_revision := (p_proof->>'revision')::bigint;
    v_engaged := (p_proof->>'engaged')::boolean;
    v_checked_at := (p_proof->>'checkedAt')::timestamptz;
    v_state_sha256 := p_proof->>'stateSha256';
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'provider_effect_kill_switch_proof_invalid' USING ERRCODE = '22023';
  END;

  IF v_revision <> p_expected_previous_revision + 1 THEN
    RAISE EXCEPTION 'provider_effect_kill_switch_revision_invalid' USING ERRCODE = '22023';
  END IF;

  INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.kill_switch_states
    (profile_ref, profile_sha256, revision, engaged, checked_at, state_sha256, proof_json)
  VALUES (p_profile_ref, p_profile_sha256, v_revision, v_engaged, v_checked_at, v_state_sha256, p_proof);
END;
$$;

REVOKE ALL ON FUNCTION ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.register_deployment_profile(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.append_kill_switch(text, text, bigint, jsonb) FROM PUBLIC;

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.evaluation_releases (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  release_sha256 text NOT NULL CHECK (release_sha256 ~ '^[0-9a-f]{64}$'),
  proposal_hash text NOT NULL CHECK (proposal_hash ~ '^[0-9a-f]{64}$'),
  intent_sha256 text NOT NULL CHECK (intent_sha256 ~ '^[0-9a-f]{64}$'),
  policy_sha256 text NOT NULL CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
  passed boolean NOT NULL CHECK (passed),
  provider_release_eligible boolean NOT NULL CHECK (provider_release_eligible),
  evaluated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > evaluated_at),
  proof_json jsonb NOT NULL CHECK (jsonb_typeof(proof_json) = 'object'),
  PRIMARY KEY (profile_ref, profile_sha256, release_sha256),
  UNIQUE (profile_ref, profile_sha256, release_sha256, proposal_hash, intent_sha256, policy_sha256),
  FOREIGN KEY (profile_ref, profile_sha256)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles (profile_ref, profile_sha256)
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.provider_identities (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  receipt_sha256 text NOT NULL CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
  provider text NOT NULL,
  provider_owner_ref text NOT NULL,
  provider_account_ref text NOT NULL,
  credential_owner_ref text NOT NULL,
  verified_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > verified_at),
  proof_json jsonb NOT NULL CHECK (jsonb_typeof(proof_json) = 'object'),
  PRIMARY KEY (profile_ref, profile_sha256, receipt_sha256),
  UNIQUE (profile_ref, profile_sha256, receipt_sha256, provider, provider_owner_ref, provider_account_ref),
  FOREIGN KEY (profile_ref, profile_sha256)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles (profile_ref, profile_sha256)
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.resource_ownership_receipts (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  receipt_sha256 text NOT NULL CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
  provider text NOT NULL,
  provider_owner_ref text NOT NULL,
  provider_account_ref text NOT NULL,
  target_class text NOT NULL,
  resource_key text NOT NULL CHECK (resource_key ~ '^[0-9a-f]{64}$'),
  provider_resource_ref text NOT NULL,
  verified_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > verified_at),
  proof_json jsonb NOT NULL CHECK (jsonb_typeof(proof_json) = 'object'),
  PRIMARY KEY (profile_ref, profile_sha256, receipt_sha256),
  UNIQUE (profile_ref, profile_sha256, receipt_sha256, provider, provider_owner_ref, provider_account_ref),
  FOREIGN KEY (profile_ref, profile_sha256)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles (profile_ref, profile_sha256)
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.approvals (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  approval_sha256 text NOT NULL CHECK (approval_sha256 ~ '^[0-9a-f]{64}$'),
  proposal_id text NOT NULL,
  proposal_hash text NOT NULL CHECK (proposal_hash ~ '^[0-9a-f]{64}$'),
  intent_sha256 text NOT NULL CHECK (intent_sha256 ~ '^[0-9a-f]{64}$'),
  decided_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > decided_at),
  proof_json jsonb NOT NULL CHECK (jsonb_typeof(proof_json) = 'object'),
  PRIMARY KEY (profile_ref, profile_sha256, approval_sha256),
  UNIQUE (profile_ref, profile_sha256, proposal_id, approval_sha256),
  UNIQUE (profile_ref, profile_sha256, approval_sha256, proposal_id, proposal_hash, intent_sha256),
  FOREIGN KEY (profile_ref, profile_sha256)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles (profile_ref, profile_sha256)
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.authorization_snapshots (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  proposal_id text NOT NULL,
  proposal_hash text NOT NULL CHECK (proposal_hash ~ '^[0-9a-f]{64}$'),
  intent_sha256 text NOT NULL CHECK (intent_sha256 ~ '^[0-9a-f]{64}$'),
  prospective_effect_key text NOT NULL CHECK (prospective_effect_key ~ '^[0-9a-f]{64}$'),
  policy_ref text NOT NULL,
  policy_sha256 text NOT NULL CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
  capability text NOT NULL,
  capability_version integer NOT NULL CHECK (capability_version > 0),
  provider text NOT NULL,
  operation text NOT NULL,
  provider_owner_ref text NOT NULL,
  provider_account_ref text NOT NULL,
  authorization_mode text NOT NULL CHECK (authorization_mode IN ('automatic', 'approval-once')),
  revision bigint NOT NULL CHECK (revision >= 0),
  authorized_at timestamptz NOT NULL,
  proposal_created_at timestamptz NOT NULL,
  proposal_expires_at timestamptz NOT NULL CHECK (proposal_expires_at > proposal_created_at),
  proposal_json jsonb NOT NULL CHECK (jsonb_typeof(proposal_json) = 'object'),
  authorization_sha256 text NOT NULL CHECK (authorization_sha256 ~ '^[0-9a-f]{64}$'),
  kill_switch_revision bigint NOT NULL,
  evaluation_release_sha256 text NOT NULL,
  provider_identity_receipt_sha256 text NOT NULL,
  resource_ownership_receipt_sha256 text NOT NULL,
  approval_sha256 text,
  PRIMARY KEY (profile_ref, profile_sha256, proposal_id, revision),
  UNIQUE (profile_ref, profile_sha256, proposal_hash, revision),
  FOREIGN KEY (profile_ref, profile_sha256)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.deployment_profiles (profile_ref, profile_sha256),
  FOREIGN KEY (profile_ref, profile_sha256, kill_switch_revision, authorized_at)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.kill_switch_states
      (profile_ref, profile_sha256, revision, checked_at),
  FOREIGN KEY (
    profile_ref, profile_sha256, evaluation_release_sha256,
    proposal_hash, intent_sha256, policy_sha256
  ) REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.evaluation_releases
      (profile_ref, profile_sha256, release_sha256, proposal_hash, intent_sha256, policy_sha256),
  FOREIGN KEY (
    profile_ref, profile_sha256, provider_identity_receipt_sha256,
    provider, provider_owner_ref, provider_account_ref
  ) REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.provider_identities
      (profile_ref, profile_sha256, receipt_sha256, provider, provider_owner_ref, provider_account_ref),
  FOREIGN KEY (
    profile_ref, profile_sha256, resource_ownership_receipt_sha256,
    provider, provider_owner_ref, provider_account_ref
  ) REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.resource_ownership_receipts
      (profile_ref, profile_sha256, receipt_sha256, provider, provider_owner_ref, provider_account_ref),
  FOREIGN KEY (
    profile_ref, profile_sha256, approval_sha256,
    proposal_id, proposal_hash, intent_sha256
  ) REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.approvals
      (profile_ref, profile_sha256, approval_sha256, proposal_id, proposal_hash, intent_sha256),
  CHECK (
    (authorization_mode = 'automatic' AND approval_sha256 IS NULL)
    OR (authorization_mode = 'approval-once' AND approval_sha256 IS NOT NULL)
  ),
  CHECK (authorized_at >= proposal_created_at AND authorized_at < proposal_expires_at)
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  proposal_id text NOT NULL,
  proposal_hash text NOT NULL CHECK (proposal_hash ~ '^[0-9a-f]{64}$'),
  intent_sha256 text NOT NULL CHECK (intent_sha256 ~ '^[0-9a-f]{64}$'),
  prospective_effect_key text NOT NULL CHECK (prospective_effect_key ~ '^[0-9a-f]{64}$'),
  policy_sha256 text NOT NULL CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
  capability text NOT NULL,
  capability_version integer NOT NULL CHECK (capability_version > 0),
  provider text NOT NULL,
  operation text NOT NULL,
  provider_owner_ref text NOT NULL,
  authorization_revision bigint NOT NULL,
  authorization_sha256 text NOT NULL CHECK (authorization_sha256 ~ '^[0-9a-f]{64}$'),
  kill_switch_revision bigint NOT NULL CHECK (kill_switch_revision >= 0),
  evaluation_release_sha256 text NOT NULL CHECK (evaluation_release_sha256 ~ '^[0-9a-f]{64}$'),
  provider_identity_receipt_sha256 text NOT NULL CHECK (provider_identity_receipt_sha256 ~ '^[0-9a-f]{64}$'),
  resource_ownership_receipt_sha256 text NOT NULL CHECK (resource_ownership_receipt_sha256 ~ '^[0-9a-f]{64}$'),
  approval_sha256 text CHECK (approval_sha256 IS NULL OR approval_sha256 ~ '^[0-9a-f]{64}$'),
  approval_consumed_at timestamptz,
  attempt_ref text NOT NULL,
  attempt_number integer NOT NULL CHECK (attempt_number = 1),
  attempted_at timestamptz NOT NULL,
  lease_expires_at timestamptz NOT NULL CHECK (lease_expires_at > attempted_at),
  revision bigint NOT NULL,
  attempt_sha256 text NOT NULL CHECK (attempt_sha256 ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (profile_ref, profile_sha256, attempt_ref),
  UNIQUE (profile_ref, profile_sha256, proposal_id),
  UNIQUE (profile_ref, profile_sha256, prospective_effect_key),
  UNIQUE (profile_ref, profile_sha256, attempt_sha256),
  UNIQUE (profile_ref, profile_sha256, attempt_ref, proposal_id),
  FOREIGN KEY (profile_ref, profile_sha256, proposal_id, authorization_revision)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.authorization_snapshots (profile_ref, profile_sha256, proposal_id, revision),
  CHECK ((approval_sha256 IS NULL) = (approval_consumed_at IS NULL)),
  CHECK (revision = authorization_revision + 1)
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.approval_consumptions (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  approval_sha256 text NOT NULL,
  attempt_ref text NOT NULL,
  consumed_at timestamptz NOT NULL,
  PRIMARY KEY (profile_ref, profile_sha256, approval_sha256),
  UNIQUE (profile_ref, profile_sha256, attempt_ref),
  FOREIGN KEY (profile_ref, profile_sha256, approval_sha256)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.approvals (profile_ref, profile_sha256, approval_sha256),
  FOREIGN KEY (profile_ref, profile_sha256, attempt_ref)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts (profile_ref, profile_sha256, attempt_ref)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_receipts (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  attempt_ref text NOT NULL,
  receipt_kind text NOT NULL CHECK (receipt_kind IN ('execution', 'reconciliation')),
  receipt_id text NOT NULL,
  receipt_sha256 text NOT NULL CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('verified', 'failed', 'outcome_unknown')),
  submitted_result_sha256 text NOT NULL CHECK (submitted_result_sha256 ~ '^[0-9a-f]{64}$'),
  provider_resource_ref text,
  attempted_at timestamptz NOT NULL,
  completed_at timestamptz,
  reconciliation_ref text,
  prior_receipt_sha256 text,
  receipt_json jsonb NOT NULL CHECK (jsonb_typeof(receipt_json) = 'object'),
  PRIMARY KEY (profile_ref, profile_sha256, attempt_ref, receipt_kind),
  UNIQUE (profile_ref, profile_sha256, receipt_id),
  UNIQUE (profile_ref, profile_sha256, receipt_sha256),
  UNIQUE (profile_ref, profile_sha256, attempt_ref, receipt_sha256),
  FOREIGN KEY (profile_ref, profile_sha256, attempt_ref)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts (profile_ref, profile_sha256, attempt_ref),
  FOREIGN KEY (profile_ref, profile_sha256, attempt_ref, prior_receipt_sha256)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_receipts
      (profile_ref, profile_sha256, attempt_ref, receipt_sha256),
  CHECK ((status = 'outcome_unknown') = (completed_at IS NULL)),
  CHECK (
    (receipt_kind = 'execution' AND reconciliation_ref IS NULL AND prior_receipt_sha256 IS NULL)
    OR (receipt_kind = 'reconciliation' AND reconciliation_ref IS NOT NULL AND prior_receipt_sha256 IS NOT NULL AND status <> 'outcome_unknown')
  )
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_identities (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  attempt_ref text NOT NULL,
  prior_receipt_sha256 text NOT NULL CHECK (prior_receipt_sha256 ~ '^[0-9a-f]{64}$'),
  authentication_sha256 text NOT NULL CHECK (authentication_sha256 ~ '^[0-9a-f]{64}$'),
  reconciler_principal_ref text NOT NULL,
  authenticated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > authenticated_at),
  proof_json jsonb NOT NULL CHECK (jsonb_typeof(proof_json) = 'object'),
  PRIMARY KEY (profile_ref, profile_sha256, attempt_ref, prior_receipt_sha256, authentication_sha256),
  FOREIGN KEY (profile_ref, profile_sha256, attempt_ref)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts (profile_ref, profile_sha256, attempt_ref),
  FOREIGN KEY (profile_ref, profile_sha256, attempt_ref, prior_receipt_sha256)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_receipts
      (profile_ref, profile_sha256, attempt_ref, receipt_sha256)
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_authorizations (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  proposal_id text NOT NULL,
  attempt_ref text NOT NULL,
  prior_receipt_sha256 text NOT NULL,
  authentication_sha256 text NOT NULL,
  kill_switch_revision bigint NOT NULL,
  database_now timestamptz NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  PRIMARY KEY (profile_ref, profile_sha256, attempt_ref, prior_receipt_sha256, revision),
  UNIQUE (
    profile_ref, profile_sha256, attempt_ref, prior_receipt_sha256,
    authentication_sha256, kill_switch_revision, revision
  ),
  FOREIGN KEY (profile_ref, profile_sha256, attempt_ref, prior_receipt_sha256, authentication_sha256)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_identities
      (profile_ref, profile_sha256, attempt_ref, prior_receipt_sha256, authentication_sha256),
  FOREIGN KEY (profile_ref, profile_sha256, kill_switch_revision)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.kill_switch_states (profile_ref, profile_sha256, revision),
  FOREIGN KEY (profile_ref, profile_sha256, attempt_ref, proposal_id)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts
      (profile_ref, profile_sha256, attempt_ref, proposal_id),
  CHECK (database_now IS NOT NULL)
);

CREATE TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_leases (
  profile_ref text NOT NULL,
  profile_sha256 text NOT NULL,
  attempt_ref text NOT NULL,
  prior_receipt_sha256 text NOT NULL CHECK (prior_receipt_sha256 ~ '^[0-9a-f]{64}$'),
  authentication_sha256 text NOT NULL CHECK (authentication_sha256 ~ '^[0-9a-f]{64}$'),
  kill_switch_revision bigint NOT NULL CHECK (kill_switch_revision >= 0),
  reconciliation_ref text NOT NULL,
  reconciler_principal_ref text NOT NULL,
  mode text NOT NULL CHECK (mode = 'read_only_status_lookup'),
  acquired_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > acquired_at),
  revision bigint NOT NULL CHECK (revision > 0),
  lease_sha256 text NOT NULL CHECK (lease_sha256 ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (profile_ref, profile_sha256, reconciliation_ref),
  UNIQUE (profile_ref, profile_sha256, lease_sha256),
  FOREIGN KEY (profile_ref, profile_sha256, attempt_ref)
    REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_attempts (profile_ref, profile_sha256, attempt_ref),
  FOREIGN KEY (
    profile_ref, profile_sha256, attempt_ref, prior_receipt_sha256,
    authentication_sha256, kill_switch_revision, revision
  ) REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_authorizations
      (profile_ref, profile_sha256, attempt_ref, prior_receipt_sha256,
       authentication_sha256, kill_switch_revision, revision)
);

ALTER TABLE ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.effect_receipts
ADD CONSTRAINT effect_receipts_reconciliation_lease_fkey
FOREIGN KEY (profile_ref, profile_sha256, reconciliation_ref)
REFERENCES ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_leases
  (profile_ref, profile_sha256, reconciliation_ref);

CREATE INDEX reconciliation_leases_attempt_order
ON ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reconciliation_leases
  (profile_ref, profile_sha256, attempt_ref, acquired_at DESC, reconciliation_ref DESC);

${[
  "schema_versions",
  "deployment_profiles",
  "profile_serialization_locks",
  "kill_switch_states",
  "evaluation_releases",
  "provider_identities",
  "resource_ownership_receipts",
  "approvals",
  "authorization_snapshots",
  "effect_attempts",
  "approval_consumptions",
  "effect_receipts",
  "reconciliation_identities",
  "reconciliation_authorizations",
  "reconciliation_leases",
]
  .map(
    (table) => `CREATE TRIGGER ${table}_append_only
BEFORE UPDATE OR DELETE ON ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.${table}
FOR EACH ROW EXECUTE FUNCTION ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.reject_mutation();`,
  )
  .join("\n\n")}

REVOKE ALL ON SCHEMA ${PROVIDER_EFFECT_AUTHORITY_SCHEMA} FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA ${PROVIDER_EFFECT_AUTHORITY_SCHEMA} FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA ${PROVIDER_EFFECT_AUTHORITY_SCHEMA} FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ${PROVIDER_EFFECT_AUTHORITY_SCHEMA} FROM PUBLIC;
`;

export const PROVIDER_EFFECT_AUTHORITY_MIGRATION_SHA256 = createHash("sha256").update(body).digest("hex");

export function providerEffectAuthoritySchemaSql() {
  return `${body}
INSERT INTO ${PROVIDER_EFFECT_AUTHORITY_SCHEMA}.schema_versions (version, migration_sha256)
VALUES (${PROVIDER_EFFECT_AUTHORITY_SCHEMA_VERSION}, '${PROVIDER_EFFECT_AUTHORITY_MIGRATION_SHA256}');
`;
}
