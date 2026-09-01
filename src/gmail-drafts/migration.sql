BEGIN;

DO $bootstrap$
DECLARE
  v_superuser BOOLEAN;
  v_membership_columns TEXT[];
  v_owner_login TEXT := NULLIF(pg_catalog.current_setting('gmail_draft_broker.owner_login_role', TRUE), '');
  v_admission_login TEXT := NULLIF(pg_catalog.current_setting('gmail_draft_broker.admission_login_role', TRUE), '');
  v_broker_login TEXT := NULLIF(pg_catalog.current_setting('gmail_draft_broker.broker_login_role', TRUE), '');
  v_binding_count INTEGER;
  v_role RECORD;
BEGIN
  SELECT pg_catalog.array_agg(attribute.attname ORDER BY attribute.attname)
    FILTER (WHERE attribute.attname IN ('admin_option','inherit_option','set_option'))
  INTO v_membership_columns
  FROM pg_catalog.pg_attribute attribute
  WHERE attribute.attrelid = 'pg_catalog.pg_auth_members'::pg_catalog.regclass
    AND NOT attribute.attisdropped;
  IF pg_catalog.current_setting('server_version_num')::INTEGER NOT BETWEEN 160000 AND 169999
    OR v_membership_columns IS DISTINCT FROM ARRAY['admin_option','inherit_option','set_option']::TEXT[]
  THEN
    RAISE EXCEPTION 'Gmail draft migration requires PostgreSQL 16 membership semantics';
  END IF;
  SELECT rolsuper INTO v_superuser FROM pg_catalog.pg_roles WHERE rolname = current_user;
  IF v_superuser IS NOT TRUE THEN
    RAISE EXCEPTION 'Gmail draft migration requires a superuser';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'qm_gmail_draft_owner') THEN
    CREATE ROLE qm_gmail_draft_owner NOLOGIN NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'qm_gmail_draft_admission') THEN
    CREATE ROLE qm_gmail_draft_admission NOLOGIN NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'qm_gmail_draft_broker') THEN
    CREATE ROLE qm_gmail_draft_broker NOLOGIN NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION;
  END IF;
  FOR v_role IN
    SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
    FROM pg_catalog.pg_roles
    WHERE rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
  LOOP
    IF v_role.rolcanlogin OR v_role.rolinherit OR v_role.rolsuper OR v_role.rolcreaterole OR v_role.rolcreatedb
      OR v_role.rolreplication OR v_role.rolbypassrls
    THEN
      RAISE EXCEPTION 'Gmail draft role % violates the NOLOGIN least-privilege precondition', v_role.rolname;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members membership
    JOIN pg_catalog.pg_roles member ON member.oid = membership.member
    WHERE member.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
  )
  THEN
    RAISE EXCEPTION 'Gmail draft protected roles must not be members of any role';
  END IF;
  SELECT count(*) INTO v_binding_count
  FROM pg_catalog.pg_auth_members membership
  JOIN pg_catalog.pg_roles granted ON granted.oid = membership.roleid
  WHERE granted.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker');
  IF v_binding_count = 0 THEN
    IF v_owner_login IS NOT NULL OR v_admission_login IS NOT NULL OR v_broker_login IS NOT NULL THEN
      RAISE EXCEPTION 'Gmail draft login settings require all three exact protected-role bindings';
    END IF;
  ELSIF v_owner_login IS NULL OR v_admission_login IS NULL OR v_broker_login IS NULL
    OR v_owner_login = v_admission_login OR v_owner_login = v_broker_login OR v_admission_login = v_broker_login
  THEN
    RAISE EXCEPTION 'set three distinct Gmail draft login settings to audit existing protected-role bindings';
  ELSIF v_binding_count <> 3 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members membership
    JOIN pg_catalog.pg_roles granted ON granted.oid = membership.roleid
    JOIN pg_catalog.pg_roles member ON member.oid = membership.member
    LEFT JOIN (VALUES
      ('qm_gmail_draft_owner', v_owner_login, FALSE, TRUE),
      ('qm_gmail_draft_admission', v_admission_login, TRUE, FALSE),
      ('qm_gmail_draft_broker', v_broker_login, TRUE, FALSE)
    ) expected(granted_role, member_role, inherit_option, set_option)
      ON expected.granted_role = granted.rolname AND expected.member_role = member.rolname
    WHERE granted.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND (expected.granted_role IS NULL OR membership.admin_option
        OR membership.inherit_option IS DISTINCT FROM expected.inherit_option
        OR membership.set_option IS DISTINCT FROM expected.set_option
        OR NOT member.rolcanlogin OR member.rolinherit IS DISTINCT FROM expected.inherit_option
        OR member.rolsuper OR member.rolcreaterole OR member.rolcreatedb OR member.rolreplication
        OR member.rolbypassrls)
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles member
    WHERE member.rolname IN (v_owner_login, v_admission_login, v_broker_login)
      AND (EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members nested WHERE nested.roleid = member.oid)
        OR (SELECT count(*) FROM pg_catalog.pg_auth_members other WHERE other.member = member.oid) <> 1)
  )
  THEN
    RAISE EXCEPTION 'Gmail draft protected roles require exactly one intended direct isolated login binding';
  END IF;
  IF v_binding_count <> 0 THEN
    FOR v_role IN
      SELECT role.oid, role.rolname FROM pg_catalog.pg_roles role
      WHERE role.rolname IN (v_owner_login, v_admission_login, v_broker_login)
    LOOP
      IF EXISTS (SELECT 1 FROM pg_catalog.pg_database database_record WHERE database_record.datdba = v_role.oid)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace namespace WHERE namespace.nspowner = v_role.oid)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_class relation WHERE relation.relowner = v_role.oid)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc routine WHERE routine.proowner = v_role.oid)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_type type_record WHERE type_record.typowner = v_role.oid)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_default_acl defaults WHERE defaults.defaclrole = v_role.oid)
        OR EXISTS (
          SELECT 1 FROM pg_catalog.pg_default_acl defaults
          CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
          WHERE acl.grantee = v_role.oid
        )
        OR EXISTS (
          SELECT 1 FROM pg_catalog.pg_database database_record
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(database_record.datacl, pg_catalog.acldefault('d', database_record.datdba))
          ) acl WHERE acl.grantee = v_role.oid
        )
        OR EXISTS (
          SELECT 1 FROM pg_catalog.pg_namespace namespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
          ) acl WHERE acl.grantee = v_role.oid
        )
        OR EXISTS (
          SELECT 1 FROM pg_catalog.pg_class relation
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(relation.relacl, pg_catalog.acldefault(
              CASE WHEN relation.relkind = 'S' THEN 's'::"char" ELSE 'r'::"char" END, relation.relowner
            ))
          ) acl WHERE acl.grantee = v_role.oid
        )
        OR EXISTS (
          SELECT 1 FROM pg_catalog.pg_attribute attribute
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(attribute.attacl, '{}'::pg_catalog.aclitem[])
          ) acl WHERE attribute.attnum > 0 AND NOT attribute.attisdropped AND acl.grantee = v_role.oid
        )
        OR EXISTS (
          SELECT 1 FROM pg_catalog.pg_proc routine
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(routine.proacl, pg_catalog.acldefault('f', routine.proowner))
          ) acl WHERE acl.grantee = v_role.oid
        )
        OR EXISTS (
          SELECT 1 FROM pg_catalog.pg_type type_record
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(type_record.typacl, pg_catalog.acldefault('T', type_record.typowner))
          ) acl WHERE acl.grantee = v_role.oid
        )
      THEN
        RAISE EXCEPTION 'Gmail draft intended login % owns objects or has direct or default privileges', v_role.rolname;
      END IF;
    END LOOP;
  END IF;
END
$bootstrap$;

DO $global_preflight$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_database database_record
    JOIN pg_catalog.pg_roles owner ON owner.oid = database_record.datdba
    WHERE owner.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_namespace namespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
    WHERE owner.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND (namespace.nspname <> 'gmail_draft_broker' OR owner.rolname <> 'qm_gmail_draft_owner')
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = relation.relowner
    WHERE owner.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND (namespace.nspname <> 'gmail_draft_broker' OR owner.rolname <> 'qm_gmail_draft_owner')
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc routine
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = routine.proowner
    WHERE owner.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND (namespace.nspname <> 'gmail_draft_broker' OR owner.rolname <> 'qm_gmail_draft_owner')
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_type type_record
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = type_record.typowner
    WHERE owner.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND (namespace.nspname <> 'gmail_draft_broker' OR owner.rolname <> 'qm_gmail_draft_owner')
  ) THEN
    RAISE EXCEPTION 'Gmail draft protected roles own objects outside the authoritative schema';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_database database_record
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(database_record.datacl, '{}'::pg_catalog.aclitem[])) acl
    JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
    WHERE grantee.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_namespace namespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(namespace.nspacl, '{}'::pg_catalog.aclitem[])) acl
    JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
    WHERE grantee.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND namespace.nspname <> 'gmail_draft_broker'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(relation.relacl, '{}'::pg_catalog.aclitem[])) acl
    JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
    WHERE grantee.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND namespace.nspname <> 'gmail_draft_broker'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_attribute attribute
    JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(attribute.attacl, '{}'::pg_catalog.aclitem[])) acl
    JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
    WHERE attribute.attnum > 0 AND NOT attribute.attisdropped
      AND grantee.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND namespace.nspname <> 'gmail_draft_broker'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc routine
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(routine.proacl, '{}'::pg_catalog.aclitem[])) acl
    JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
    WHERE grantee.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND namespace.nspname <> 'gmail_draft_broker'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_type type_record
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(type_record.typacl, '{}'::pg_catalog.aclitem[])) acl
    JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
    WHERE grantee.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND namespace.nspname <> 'gmail_draft_broker'
  ) THEN
    RAISE EXCEPTION 'Gmail draft protected roles have direct privileges outside the authoritative schema';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_default_acl defaults
    JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
    LEFT JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
    WHERE owner.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND (defaults.defaclnamespace = 0 OR owner.rolname <> 'qm_gmail_draft_owner'
        OR namespace.nspname IS DISTINCT FROM 'gmail_draft_broker'
        OR defaults.defaclobjtype NOT IN ('f','T'))
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_default_acl defaults
    CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
    JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
    JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
    LEFT JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
    WHERE grantee.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND (owner.rolname <> 'qm_gmail_draft_owner' OR defaults.defaclnamespace = 0
        OR namespace.nspname IS DISTINCT FROM 'gmail_draft_broker'
        OR defaults.defaclobjtype NOT IN ('f','T')
        OR grantee.rolname <> 'qm_gmail_draft_owner')
  ) THEN
    RAISE EXCEPTION 'Gmail draft protected roles have unrelated or owner-wide default ACLs';
  END IF;
END
$global_preflight$;

DO $preflight$
DECLARE
  v_schema_owner TEXT;
  v_tables TEXT[];
  v_indexes TEXT[];
  v_functions TEXT[];
  v_types TEXT[];
  v_versions TEXT[];
  v_version_digest TEXT;
  v_contract_version INTEGER;
BEGIN
  SELECT owner.rolname INTO v_schema_owner
  FROM pg_catalog.pg_namespace namespace
  JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
  WHERE namespace.nspname = 'gmail_draft_broker';
  IF NOT FOUND THEN RETURN; END IF;
  IF v_schema_owner <> 'qm_gmail_draft_owner' THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema is not owned by the dedicated owner';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind IN ('r','p','v','m','f','S','c')
  ) AND NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc routine
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
    WHERE namespace.nspname = 'gmail_draft_broker'
  ) THEN
    IF EXISTS (
      SELECT 1 FROM pg_catalog.pg_namespace namespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
      ) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
      WHERE namespace.nspname = 'gmail_draft_broker'
        AND COALESCE(grantee.rolname, 'public') <> 'qm_gmail_draft_owner'
    ) OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_default_acl defaults
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
      WHERE namespace.nspname = 'gmail_draft_broker'
    ) THEN
      RAISE EXCEPTION 'preexisting empty Gmail draft schema has privilege drift';
    END IF;
    RETURN;
  END IF;
  IF pg_catalog.to_regclass('gmail_draft_broker.migration_versions') IS NULL THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema is not versioned';
  END IF;
  LOCK TABLE gmail_draft_broker.migration_versions, gmail_draft_broker.owner_slack_bindings,
    gmail_draft_broker.thread_sources, gmail_draft_broker.approved_intents,
    gmail_draft_broker.active_lineage_claims IN ACCESS EXCLUSIVE MODE;
  EXECUTE 'SELECT contract_sha256 FROM gmail_draft_broker.migration_versions WHERE migration_id = $1'
    INTO v_version_digest USING 'gmail-draft-broker-reconciliation-fence-v2';
  IF v_version_digest = '52ce16312baeed1b8dccc84f0b1a50d23119e2c0566b99b713705ba34710f742' THEN
    v_contract_version := 2;
  ELSE
    EXECUTE 'SELECT contract_sha256 FROM gmail_draft_broker.migration_versions WHERE migration_id = $1'
      INTO v_version_digest USING 'gmail-draft-broker-active-lineage-v1';
    IF v_version_digest = '58ecaa5bc584f7266a8ef9fe150713d6371228f0a160b2d4773a4f1b3192217d' THEN
      v_contract_version := 1;
    END IF;
  END IF;
  IF v_contract_version IS NULL THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema version is not recognized';
  END IF;
  EXECUTE 'SELECT pg_catalog.array_agg(migration_id ORDER BY migration_id) FROM gmail_draft_broker.migration_versions'
    INTO v_versions;
  IF (v_contract_version = 1 AND v_versions <> ARRAY['gmail-draft-broker-active-lineage-v1']::TEXT[])
    OR (v_contract_version = 2 AND v_versions <>
      ARRAY['gmail-draft-broker-active-lineage-v1','gmail-draft-broker-reconciliation-fence-v2']::TEXT[])
  THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has unexpected migration history';
  END IF;
  SELECT pg_catalog.array_agg(relation.relname ORDER BY relation.relname) INTO v_tables
  FROM pg_catalog.pg_class relation
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
  WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind IN ('r','p','v','m','f','S','c');
  IF v_tables <> ARRAY['active_lineage_claims','approved_intents','migration_versions','owner_slack_bindings','thread_sources']::TEXT[] THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has unexpected relations';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind = 'r'
      AND relation.relpersistence <> 'p'
  ) THEN
    RAISE EXCEPTION 'preexisting Gmail draft tables must be permanent logged tables';
  END IF;
  SELECT pg_catalog.array_agg(relation.relname ORDER BY relation.relname) INTO v_indexes
  FROM pg_catalog.pg_class relation
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
  WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind IN ('i','I');
  IF v_indexes <> ARRAY['active_lineage_claims_child_effect_proposal_id_key',
    'active_lineage_claims_parent_effect_proposal_id_key','active_lineage_claims_pkey',
    'approved_intents_approval_jti_key','approved_intents_approval_verified_receipt_sha256_key',
    'approved_intents_pkey','gmail_draft_created_receipt_idx','gmail_draft_intents_status_idx',
    'migration_versions_pkey','owner_slack_bindings_binding_jti_key','owner_slack_bindings_pkey',
    'owner_slack_bindings_verified_receipt_sha256_key','thread_sources_pkey','thread_sources_source_jti_key',
    'thread_sources_verified_receipt_sha256_key']::TEXT[]
  THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has unexpected indexes';
  END IF;
  SELECT pg_catalog.array_agg(routine.proname ORDER BY routine.proname) INTO v_functions
  FROM pg_catalog.pg_proc routine
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
  WHERE namespace.nspname = 'gmail_draft_broker';
  IF v_functions <> ARRAY['admit_intent','admit_owner_slack_binding','admit_thread_source','arm_effect',
    'claim_effect','claim_reconciliation','record_created','record_unknown','reject_before_effect',
    'reject_definitive_no_write','retain_unknown']::TEXT[]
  THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has unexpected routines';
  END IF;
  SELECT pg_catalog.array_agg(type_record.typname ORDER BY type_record.typname COLLATE "C") INTO v_types
  FROM pg_catalog.pg_type type_record
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
  WHERE namespace.nspname = 'gmail_draft_broker';
  IF v_types <> ARRAY['_active_lineage_claims','_approved_intents','_migration_versions',
    '_owner_slack_bindings','_thread_sources','active_lineage_claims','approved_intents',
    'migration_versions','owner_slack_bindings','thread_sources']::TEXT[]
  THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has unexpected types';
  END IF;
  IF pg_catalog.to_regprocedure('gmail_draft_broker.admit_owner_slack_binding(text,text,text,text,text,text,text,text,bigint,bigint,text,text)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.admit_thread_source(text,text,text,text,text,text,text,integer,text,text,text,text,text[],text,bigint,bigint,text,text)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.admit_intent(text,integer,integer,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,text,integer,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text[],text,jsonb)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.claim_effect(text,integer)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.claim_reconciliation(text,integer)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.arm_effect(text,integer,text,text,text,text,text,bigint)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.record_unknown(text,integer,text,text,text,text,text,bigint)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.reject_before_effect(text,integer,text,text)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.reject_definitive_no_write(text,integer,text,text)') IS NULL
  THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has unexpected routine signatures';
  END IF;
  IF v_contract_version = 1 AND (
    pg_catalog.to_regprocedure('gmail_draft_broker.record_created(text,integer,text,text,text,text,text,text,text,text,text,bigint,boolean)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.retain_unknown(text,integer,text,text,text,text,text,bigint)') IS NULL
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_attribute attribute
      WHERE attribute.attrelid = 'gmail_draft_broker.approved_intents'::pg_catalog.regclass
        AND attribute.attname = 'reconciliation_nonce' AND NOT attribute.attisdropped
    )
  ) THEN
    RAISE EXCEPTION 'preexisting Gmail draft v1 schema does not match its upgrade source';
  END IF;
  IF v_contract_version = 2 AND (
    pg_catalog.to_regprocedure('gmail_draft_broker.record_created(text,integer,text,text,text,text,text,text,text,text,text,bigint,boolean,text)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.retain_unknown(text,integer,text,text,text,text,text,bigint,text)') IS NULL
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_attribute attribute
      WHERE attribute.attrelid = 'gmail_draft_broker.approved_intents'::pg_catalog.regclass
        AND attribute.attname = 'reconciliation_nonce' AND NOT attribute.attisdropped
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_constraint constraint_record
      WHERE constraint_record.conrelid = 'gmail_draft_broker.approved_intents'::pg_catalog.regclass
        AND constraint_record.conname = 'approved_intents_reconciliation_nonce_check'
        AND constraint_record.contype = 'c' AND constraint_record.convalidated
    )
  ) THEN
    RAISE EXCEPTION 'preexisting Gmail draft v2 schema is incomplete';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = relation.relowner
    WHERE namespace.nspname = 'gmail_draft_broker'
      AND relation.relkind IN ('r','p','v','m','f','S','c','i','I')
      AND owner.rolname <> 'qm_gmail_draft_owner'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc routine
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = routine.proowner
    WHERE namespace.nspname = 'gmail_draft_broker' AND owner.rolname <> 'qm_gmail_draft_owner'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_type type_record
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = type_record.typowner
    WHERE namespace.nspname = 'gmail_draft_broker' AND owner.rolname <> 'qm_gmail_draft_owner'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger trigger
    JOIN pg_catalog.pg_class relation ON relation.oid = trigger.tgrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    LEFT JOIN pg_catalog.pg_constraint constraint_record ON constraint_record.oid = trigger.tgconstraint
    WHERE namespace.nspname = 'gmail_draft_broker' AND (
      trigger.tgisinternal IS FALSE OR trigger.tgenabled <> 'O' OR trigger.tgparentid <> 0
      OR constraint_record.contype IS DISTINCT FROM 'f' OR trigger.tgdeferrable <> constraint_record.condeferrable
      OR trigger.tginitdeferred <> constraint_record.condeferred OR trigger.tgqual IS NOT NULL
      OR cardinality(trigger.tgattr) <> 0 OR pg_catalog.octet_length(trigger.tgargs) <> 0)
  ) OR (
    SELECT count(*) FROM pg_catalog.pg_trigger trigger
    JOIN pg_catalog.pg_class relation ON relation.oid = trigger.tgrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'gmail_draft_broker'
  ) <> 4 * (
    SELECT count(*) FROM pg_catalog.pg_constraint constraint_record
    JOIN pg_catalog.pg_class relation ON relation.oid = constraint_record.conrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'gmail_draft_broker' AND constraint_record.contype = 'f'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint constraint_record
    JOIN pg_catalog.pg_class relation ON relation.oid = constraint_record.conrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN LATERAL (
      SELECT count(*) total, count(*) FILTER (WHERE trigger.tgtype = 5) insert_row,
        count(*) FILTER (WHERE trigger.tgtype = 9) delete_row,
        count(*) FILTER (WHERE trigger.tgtype = 17) update_row
      FROM pg_catalog.pg_trigger trigger WHERE trigger.tgconstraint = constraint_record.oid
    ) trigger_shape ON TRUE
    WHERE namespace.nspname = 'gmail_draft_broker' AND constraint_record.contype = 'f'
      AND (trigger_shape.total <> 4 OR trigger_shape.insert_row <> 1
        OR trigger_shape.delete_row <> 1 OR trigger_shape.update_row <> 2)
  ) THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema violates owner or trigger preconditions';
  END IF;
  IF NOT pg_catalog.has_schema_privilege('qm_gmail_draft_admission', 'gmail_draft_broker', 'USAGE')
    OR pg_catalog.has_schema_privilege('qm_gmail_draft_admission', 'gmail_draft_broker', 'CREATE')
    OR NOT pg_catalog.has_schema_privilege('qm_gmail_draft_broker', 'gmail_draft_broker', 'USAGE')
    OR pg_catalog.has_schema_privilege('qm_gmail_draft_broker', 'gmail_draft_broker', 'CREATE')
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_namespace namespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
      ) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
      WHERE namespace.nspname = 'gmail_draft_broker'
        AND (COALESCE(grantee.rolname, 'public') NOT IN
            ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
          OR (grantee.rolname IN ('qm_gmail_draft_admission','qm_gmail_draft_broker') AND acl.is_grantable))
    )
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_class relation
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(relation.relacl, pg_catalog.acldefault(CASE WHEN relation.relkind = 'S' THEN 's'::"char" ELSE 'r'::"char" END, relation.relowner))
      ) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
      WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind IN ('r','p','v','m','f','S')
        AND COALESCE(grantee.rolname, 'public') <> 'qm_gmail_draft_owner'
    )
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_attribute attribute
      JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(attribute.attacl, '{}'::pg_catalog.aclitem[])) acl
      WHERE namespace.nspname = 'gmail_draft_broker' AND attribute.attnum > 0
        AND NOT attribute.attisdropped
    )
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc routine
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(routine.proacl, pg_catalog.acldefault('f', routine.proowner))
      ) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
      WHERE namespace.nspname = 'gmail_draft_broker'
        AND (COALESCE(grantee.rolname, 'public') NOT IN
            ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
          OR (grantee.rolname IN ('qm_gmail_draft_admission','qm_gmail_draft_broker') AND acl.is_grantable))
    )
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_type type_record
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(type_record.typacl, pg_catalog.acldefault('T', type_record.typowner))
      ) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
      WHERE namespace.nspname = 'gmail_draft_broker'
        AND (COALESCE(grantee.rolname, 'public') NOT IN ('qm_gmail_draft_owner','public')
          OR (COALESCE(grantee.rolname, 'public') = 'public'
            AND (acl.privilege_type <> 'USAGE' OR acl.is_grantable)))
    )
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_default_acl defaults
      JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
      WHERE defaults.defaclnamespace = 0
        AND owner.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_default_acl defaults
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
      JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
      WHERE namespace.nspname = 'gmail_draft_broker' AND owner.rolname = 'qm_gmail_draft_owner'
        AND defaults.defaclobjtype = 'f'
    )
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_default_acl defaults
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
      JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
      CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
      WHERE namespace.nspname = 'gmail_draft_broker'
        AND (owner.rolname <> 'qm_gmail_draft_owner' OR defaults.defaclobjtype NOT IN ('f','T')
          OR COALESCE(grantee.rolname, 'public') <> 'qm_gmail_draft_owner')
    )
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc routine
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
      WHERE namespace.nspname = 'gmail_draft_broker' AND (
        pg_catalog.has_function_privilege('qm_gmail_draft_admission', routine.oid, 'EXECUTE')
          IS DISTINCT FROM (routine.proname IN ('admit_owner_slack_binding','admit_thread_source','admit_intent'))
        OR pg_catalog.has_function_privilege('qm_gmail_draft_broker', routine.oid, 'EXECUTE')
          IS DISTINCT FROM (routine.proname IN ('claim_effect','claim_reconciliation','arm_effect','record_created',
            'record_unknown','retain_unknown','reject_before_effect','reject_definitive_no_write'))
      )
    )
  THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has privilege drift';
  END IF;
END
$preflight$;

CREATE TEMPORARY TABLE migration_versions(
  migration_id TEXT PRIMARY KEY,
  contract_sha256 TEXT NOT NULL CHECK (contract_sha256 ~ '^[a-f0-9]{64}$'),
  applied_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT)
) ON COMMIT DROP;

CREATE TEMPORARY TABLE owner_slack_bindings(
  organization_id TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL,
  slack_team_id TEXT NOT NULL,
  slack_user_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  key_id TEXT NOT NULL,
  binding_jti TEXT NOT NULL UNIQUE,
  receipt_id TEXT NOT NULL,
  signed_receipt_sha256 TEXT NOT NULL CHECK (signed_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  verified_receipt_sha256 TEXT NOT NULL UNIQUE CHECK (verified_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  issued_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  updated_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  PRIMARY KEY (organization_id, owner_principal_id),
  CHECK (slack_team_id ~ '^T[A-Z0-9]{8,31}$'),
  CHECK (slack_user_id ~ '^U[A-Z0-9]{8,31}$'),
  CHECK (expires_at > issued_at)
) ON COMMIT DROP;

CREATE TEMPORARY TABLE thread_sources(
  source_receipt_sha256 TEXT PRIMARY KEY CHECK (source_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  source_jti TEXT NOT NULL UNIQUE,
  issuer TEXT NOT NULL,
  key_id TEXT NOT NULL,
  organization_id TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL,
  logical_connection_id TEXT NOT NULL,
  connection_version INTEGER NOT NULL CHECK (connection_version > 0),
  google_subject TEXT NOT NULL,
  mailbox TEXT NOT NULL,
  gmail_thread_id TEXT NOT NULL,
  parent_message_id TEXT NOT NULL,
  reference_message_ids TEXT[] NOT NULL,
  subject_sha256 TEXT NOT NULL CHECK (subject_sha256 ~ '^[a-f0-9]{64}$'),
  issued_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  signed_receipt_sha256 TEXT NOT NULL CHECK (signed_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  verified_receipt_sha256 TEXT NOT NULL UNIQUE CHECK (verified_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  created_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  CHECK (source_receipt_sha256 = verified_receipt_sha256),
  CHECK (expires_at > issued_at),
  CHECK (cardinality(reference_message_ids) BETWEEN 1 AND 20)
) ON COMMIT DROP;

CREATE TEMPORARY TABLE approved_intents(
  effect_proposal_id TEXT PRIMARY KEY,
  proposal_revision INTEGER NOT NULL CHECK (proposal_revision > 0),
  draft_revision INTEGER NOT NULL CHECK (draft_revision > 0),
  proposal_sha256 TEXT NOT NULL CHECK (proposal_sha256 ~ '^[a-f0-9]{64}$'),
  approval_jti TEXT NOT NULL UNIQUE,
  approval_receipt_id TEXT NOT NULL,
  approval_issuer TEXT NOT NULL,
  approval_key_id TEXT NOT NULL,
  approval_signed_receipt_sha256 TEXT NOT NULL CHECK (approval_signed_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  approval_verified_receipt_sha256 TEXT NOT NULL UNIQUE CHECK (approval_verified_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  organization_id TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL,
  actor_principal_id TEXT NOT NULL,
  actor_slack_id TEXT NOT NULL,
  slack_team_id TEXT NOT NULL,
  slack_user_id TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  message_ts TEXT NOT NULL,
  thread_ts TEXT NOT NULL,
  action_ts TEXT NOT NULL,
  approval_issued_at BIGINT NOT NULL,
  approval_expires_at BIGINT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('create','update')),
  logical_connection_id TEXT NOT NULL,
  connection_version INTEGER NOT NULL CHECK (connection_version > 0),
  google_subject TEXT NOT NULL,
  mailbox TEXT NOT NULL,
  approved_payload_sha256 TEXT NOT NULL CHECK (approved_payload_sha256 ~ '^[a-f0-9]{64}$'),
  recipients_sha256 TEXT NOT NULL CHECK (recipients_sha256 ~ '^[a-f0-9]{64}$'),
  subject_sha256 TEXT NOT NULL CHECK (subject_sha256 ~ '^[a-f0-9]{64}$'),
  body_sha256 TEXT NOT NULL CHECK (body_sha256 ~ '^[a-f0-9]{64}$'),
  thread_binding_sha256 TEXT NOT NULL CHECK (thread_binding_sha256 ~ '^[a-f0-9]{64}$'),
  business_context_sha256 TEXT NOT NULL CHECK (business_context_sha256 ~ '^[a-f0-9]{64}$'),
  source_bundle_sha256 TEXT NOT NULL CHECK (source_bundle_sha256 ~ '^[a-f0-9]{64}$'),
  draft_id TEXT,
  prior_draft_receipt_sha256 TEXT,
  gmail_thread_id TEXT,
  reply_source_receipt_sha256 TEXT REFERENCES thread_sources(source_receipt_sha256),
  reply_parent_message_id TEXT,
  reply_reference_message_ids TEXT[],
  reply_subject_sha256 TEXT,
  proposal_ciphertext JSONB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('approved','pre_effect','effect_started','unknown','reconciling','created','rejected')),
  attempt_id TEXT,
  attempt_started_at BIGINT,
  claim_expires_at BIGINT,
  reconciliation_nonce TEXT,
  rejection_code TEXT CHECK (rejection_code IS NULL OR rejection_code IN ('approval_invalid','approval_expired','proposal_invalid',
    'connection_unavailable','connection_mismatch','scope_missing','gmail_unauthorized','gmail_rejected')),
  terminal_receipt_sha256 TEXT,
  terminal_draft_id TEXT,
  terminal_message_id TEXT,
  terminal_thread_id TEXT,
  terminal_mime_sha256 TEXT,
  terminal_request_sha256 TEXT,
  terminal_response_sha256 TEXT,
  terminal_credential_receipt_sha256 TEXT,
  terminal_marker_message_id TEXT,
  terminal_unknown_code TEXT CHECK (terminal_unknown_code IS NULL OR terminal_unknown_code IN ('network_failure',
    'deadline_exceeded','redirect_response','response_too_large','invalid_success_response','server_error')),
  terminal_at BIGINT,
  terminal_reconciled BOOLEAN,
  created_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  updated_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  CHECK (actor_principal_id = owner_principal_id),
  CHECK (actor_slack_id = slack_user_id),
  CHECK (channel_id ~ '^D[A-Z0-9]{8,31}$'),
  CHECK ((operation = 'create' AND draft_revision = 1 AND draft_id IS NULL AND prior_draft_receipt_sha256 IS NULL)
    OR (operation = 'update' AND draft_revision > 1 AND draft_id IS NOT NULL
      AND prior_draft_receipt_sha256 ~ '^[a-f0-9]{64}$')),
  CHECK ((reply_source_receipt_sha256 IS NULL AND reply_parent_message_id IS NULL
      AND reply_reference_message_ids IS NULL AND reply_subject_sha256 IS NULL)
    OR (reply_source_receipt_sha256 IS NOT NULL AND gmail_thread_id IS NOT NULL
      AND reply_parent_message_id IS NOT NULL AND cardinality(reply_reference_message_ids) BETWEEN 1 AND 20
      AND reply_subject_sha256 ~ '^[a-f0-9]{64}$')),
  CHECK ((status = 'approved' AND attempt_id IS NULL AND attempt_started_at IS NULL AND claim_expires_at IS NULL)
    OR (status IN ('pre_effect','effect_started','reconciling') AND attempt_id IS NOT NULL
      AND attempt_started_at IS NOT NULL AND claim_expires_at IS NOT NULL)
    OR (status IN ('unknown','created','rejected') AND attempt_id IS NOT NULL
      AND attempt_started_at IS NOT NULL AND claim_expires_at IS NULL)),
  CHECK ((status = 'rejected' AND rejection_code IS NOT NULL) OR (status <> 'rejected' AND rejection_code IS NULL)),
  CHECK ((status IN ('effect_started','unknown','reconciling')
      AND terminal_receipt_sha256 ~ '^[a-f0-9]{64}$' AND terminal_request_sha256 ~ '^[a-f0-9]{64}$'
      AND terminal_marker_message_id IS NOT NULL AND terminal_unknown_code IS NOT NULL AND terminal_at IS NOT NULL
      AND terminal_draft_id IS NULL AND terminal_message_id IS NULL AND terminal_thread_id IS NULL
      AND terminal_mime_sha256 IS NULL AND terminal_response_sha256 IS NULL
      AND terminal_credential_receipt_sha256 IS NULL AND terminal_reconciled IS NULL)
    OR (status = 'created'
      AND terminal_receipt_sha256 ~ '^[a-f0-9]{64}$' AND terminal_draft_id IS NOT NULL
      AND terminal_message_id IS NOT NULL AND terminal_mime_sha256 ~ '^[a-f0-9]{64}$'
      AND terminal_request_sha256 ~ '^[a-f0-9]{64}$' AND terminal_response_sha256 ~ '^[a-f0-9]{64}$'
      AND terminal_credential_receipt_sha256 ~ '^[a-f0-9]{64}$' AND terminal_at IS NOT NULL
      AND terminal_reconciled IS NOT NULL AND terminal_marker_message_id IS NULL AND terminal_unknown_code IS NULL)
    OR (status IN ('approved','pre_effect','rejected')
      AND terminal_receipt_sha256 IS NULL AND terminal_draft_id IS NULL AND terminal_message_id IS NULL
      AND terminal_thread_id IS NULL AND terminal_mime_sha256 IS NULL AND terminal_request_sha256 IS NULL
      AND terminal_response_sha256 IS NULL AND terminal_credential_receipt_sha256 IS NULL
      AND terminal_marker_message_id IS NULL AND terminal_unknown_code IS NULL AND terminal_at IS NULL
      AND terminal_reconciled IS NULL))
) ON COMMIT DROP;

ALTER TABLE approved_intents
  ADD CONSTRAINT approved_intents_reconciliation_nonce_check
  CHECK ((status = 'reconciling' AND reconciliation_nonce ~
      '^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$')
    OR (status <> 'reconciling' AND reconciliation_nonce IS NULL));

CREATE TEMPORARY TABLE active_lineage_claims(
  prior_draft_receipt_sha256 TEXT PRIMARY KEY CHECK (prior_draft_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  parent_effect_proposal_id TEXT NOT NULL UNIQUE
    REFERENCES approved_intents(effect_proposal_id) ON DELETE RESTRICT,
  child_effect_proposal_id TEXT NOT NULL UNIQUE
    REFERENCES approved_intents(effect_proposal_id) ON DELETE RESTRICT,
  acquired_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  CHECK (parent_effect_proposal_id <> child_effect_proposal_id)
) ON COMMIT DROP;

CREATE UNIQUE INDEX gmail_draft_created_receipt_idx
  ON approved_intents(terminal_receipt_sha256)
  WHERE status = 'created';

CREATE INDEX gmail_draft_intents_status_idx
  ON approved_intents(status, claim_expires_at, updated_at);

CREATE OR REPLACE FUNCTION pg_temp.assert_gmail_draft_definitions(p_allow_missing BOOLEAN) RETURNS VOID
LANGUAGE plpgsql
AS $definition_authority$
DECLARE
  v_actual TEXT[];
  v_contract_version INTEGER;
  v_expected TEXT[];
  v_version_digest TEXT;
BEGIN
  IF pg_catalog.to_regclass('gmail_draft_broker.migration_versions') IS NULL THEN
    IF p_allow_missing THEN RETURN; END IF;
    RAISE EXCEPTION 'Gmail draft definition postflight is missing the authoritative tables';
  END IF;
  EXECUTE 'SELECT contract_sha256 FROM gmail_draft_broker.migration_versions WHERE migration_id = $1'
    INTO v_version_digest USING 'gmail-draft-broker-reconciliation-fence-v2';
  IF v_version_digest = '52ce16312baeed1b8dccc84f0b1a50d23119e2c0566b99b713705ba34710f742' THEN
    v_contract_version := 2;
  ELSE
    EXECUTE 'SELECT contract_sha256 FROM gmail_draft_broker.migration_versions WHERE migration_id = $1'
      INTO v_version_digest USING 'gmail-draft-broker-active-lineage-v1';
    IF v_version_digest = '58ecaa5bc584f7266a8ef9fe150713d6371228f0a160b2d4773a4f1b3192217d' THEN
      v_contract_version := 1;
    END IF;
  END IF;
  IF v_contract_version IS NULL THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema version is not recognized';
  END IF;

  SELECT pg_catalog.array_agg(pg_catalog.format('%s|%s|%s|%s|%s|%s|%s|%s',
    relation.relname, attribute.attname,
    pg_catalog.format_type(attribute.atttypid, attribute.atttypmod), attribute.attnotnull,
    attribute.attidentity, attribute.attgenerated, attribute.attcollation,
    COALESCE(pg_catalog.pg_get_expr(default_value.adbin, default_value.adrelid, FALSE), ''))
    ORDER BY relation.relname, attribute.attname)
  INTO v_actual
  FROM pg_catalog.pg_class relation
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
  JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid = relation.oid
  LEFT JOIN pg_catalog.pg_attrdef default_value
    ON default_value.adrelid = relation.oid AND default_value.adnum = attribute.attnum
  WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind = 'r'
    AND attribute.attnum > 0 AND NOT attribute.attisdropped;
  SELECT pg_catalog.array_agg(pg_catalog.format('%s|%s|%s|%s|%s|%s|%s|%s',
    relation.relname, attribute.attname,
    pg_catalog.format_type(attribute.atttypid, attribute.atttypmod), attribute.attnotnull,
    attribute.attidentity, attribute.attgenerated, attribute.attcollation,
    COALESCE(pg_catalog.pg_get_expr(default_value.adbin, default_value.adrelid, FALSE), ''))
    ORDER BY relation.relname, attribute.attname)
  INTO v_expected
  FROM pg_catalog.pg_class relation
  JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid = relation.oid
  LEFT JOIN pg_catalog.pg_attrdef default_value
    ON default_value.adrelid = relation.oid AND default_value.adnum = attribute.attnum
  WHERE relation.relnamespace = pg_catalog.pg_my_temp_schema() AND relation.relkind = 'r'
    AND relation.relname IN ('migration_versions','owner_slack_bindings','thread_sources',
      'approved_intents','active_lineage_claims')
    AND attribute.attnum > 0 AND NOT attribute.attisdropped
    AND NOT (v_contract_version = 1 AND relation.relname = 'approved_intents'
      AND attribute.attname = 'reconciliation_nonce');
  IF v_actual IS DISTINCT FROM v_expected OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_attribute attribute
    JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind = 'r'
      AND attribute.attnum > 0 AND attribute.attisdropped
  ) THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has unexpected table columns';
  END IF;

  SELECT pg_catalog.array_agg(pg_catalog.format('%s|%s|%s|%s|%s|%s', relation.relname,
    relation.relkind, relation.relrowsecurity, relation.relforcerowsecurity,
    relation.relreplident, COALESCE(relation.reloptions::TEXT, '')) ORDER BY relation.relname)
  INTO v_actual
  FROM pg_catalog.pg_class relation
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
  WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind = 'r';
  SELECT pg_catalog.array_agg(pg_catalog.format('%s|%s|%s|%s|%s|%s', relation.relname,
    relation.relkind, relation.relrowsecurity, relation.relforcerowsecurity,
    relation.relreplident, COALESCE(relation.reloptions::TEXT, '')) ORDER BY relation.relname)
  INTO v_expected
  FROM pg_catalog.pg_class relation
  WHERE relation.relnamespace = pg_catalog.pg_my_temp_schema() AND relation.relkind = 'r'
    AND relation.relname IN ('migration_versions','owner_slack_bindings','thread_sources',
      'approved_intents','active_lineage_claims');
  IF v_actual IS DISTINCT FROM v_expected THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has unexpected table properties';
  END IF;

  SELECT pg_catalog.array_agg(pg_catalog.format(
    '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s',
    relation.relname, constraint_record.conname, constraint_record.contype,
    constraint_record.condeferrable, constraint_record.condeferred, constraint_record.convalidated,
    constraint_record.connoinherit, COALESCE(keys.names, ''), COALESCE(referenced_relation.relname, ''),
    COALESCE(referenced_keys.names, ''), constraint_record.confupdtype, constraint_record.confdeltype,
    constraint_record.confmatchtype, constraint_record.conislocal, constraint_record.coninhcount,
    constraint_record.conparentid, COALESCE(constraint_record.conpfeqop::TEXT, ''),
    COALESCE(constraint_record.conppeqop::TEXT, ''), COALESCE(constraint_record.conffeqop::TEXT, ''),
    COALESCE(constraint_record.conexclop::TEXT, ''), COALESCE(constraint_record.confdelsetcols::TEXT, ''),
    COALESCE(pg_catalog.pg_get_expr(constraint_record.conbin, constraint_record.conrelid, FALSE), ''))
    ORDER BY relation.relname, constraint_record.conname)
  INTO v_actual
  FROM pg_catalog.pg_constraint constraint_record
  JOIN pg_catalog.pg_class relation ON relation.oid = constraint_record.conrelid
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
  LEFT JOIN pg_catalog.pg_class referenced_relation ON referenced_relation.oid = constraint_record.confrelid
  LEFT JOIN LATERAL (
    SELECT pg_catalog.string_agg(attribute.attname, ',' ORDER BY key_position.ordinality) names
    FROM pg_catalog.unnest(constraint_record.conkey) WITH ORDINALITY key_position(attnum, ordinality)
    JOIN pg_catalog.pg_attribute attribute
      ON attribute.attrelid = constraint_record.conrelid AND attribute.attnum = key_position.attnum
  ) keys ON TRUE
  LEFT JOIN LATERAL (
    SELECT pg_catalog.string_agg(attribute.attname, ',' ORDER BY key_position.ordinality) names
    FROM pg_catalog.unnest(constraint_record.confkey) WITH ORDINALITY key_position(attnum, ordinality)
    JOIN pg_catalog.pg_attribute attribute
      ON attribute.attrelid = constraint_record.confrelid AND attribute.attnum = key_position.attnum
  ) referenced_keys ON TRUE
  WHERE namespace.nspname = 'gmail_draft_broker';
  SELECT pg_catalog.array_agg(pg_catalog.format(
    '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s',
    relation.relname, constraint_record.conname, constraint_record.contype,
    constraint_record.condeferrable, constraint_record.condeferred, constraint_record.convalidated,
    constraint_record.connoinherit, COALESCE(keys.names, ''), COALESCE(referenced_relation.relname, ''),
    COALESCE(referenced_keys.names, ''), constraint_record.confupdtype, constraint_record.confdeltype,
    constraint_record.confmatchtype, constraint_record.conislocal, constraint_record.coninhcount,
    constraint_record.conparentid, COALESCE(constraint_record.conpfeqop::TEXT, ''),
    COALESCE(constraint_record.conppeqop::TEXT, ''), COALESCE(constraint_record.conffeqop::TEXT, ''),
    COALESCE(constraint_record.conexclop::TEXT, ''), COALESCE(constraint_record.confdelsetcols::TEXT, ''),
    COALESCE(pg_catalog.pg_get_expr(constraint_record.conbin, constraint_record.conrelid, FALSE), ''))
    ORDER BY relation.relname, constraint_record.conname)
  INTO v_expected
  FROM pg_catalog.pg_constraint constraint_record
  JOIN pg_catalog.pg_class relation ON relation.oid = constraint_record.conrelid
  LEFT JOIN pg_catalog.pg_class referenced_relation ON referenced_relation.oid = constraint_record.confrelid
  LEFT JOIN LATERAL (
    SELECT pg_catalog.string_agg(attribute.attname, ',' ORDER BY key_position.ordinality) names
    FROM pg_catalog.unnest(constraint_record.conkey) WITH ORDINALITY key_position(attnum, ordinality)
    JOIN pg_catalog.pg_attribute attribute
      ON attribute.attrelid = constraint_record.conrelid AND attribute.attnum = key_position.attnum
  ) keys ON TRUE
  LEFT JOIN LATERAL (
    SELECT pg_catalog.string_agg(attribute.attname, ',' ORDER BY key_position.ordinality) names
    FROM pg_catalog.unnest(constraint_record.confkey) WITH ORDINALITY key_position(attnum, ordinality)
    JOIN pg_catalog.pg_attribute attribute
      ON attribute.attrelid = constraint_record.confrelid AND attribute.attnum = key_position.attnum
  ) referenced_keys ON TRUE
  WHERE relation.relnamespace = pg_catalog.pg_my_temp_schema()
    AND relation.relname IN ('migration_versions','owner_slack_bindings','thread_sources',
      'approved_intents','active_lineage_claims')
    AND NOT (v_contract_version = 1 AND relation.relname = 'approved_intents'
      AND constraint_record.conname = 'approved_intents_reconciliation_nonce_check');
  IF v_actual IS DISTINCT FROM v_expected THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has unexpected constraints';
  END IF;

  SELECT pg_catalog.array_agg(pg_catalog.format(
    '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s',
    index_relation.relname, table_relation.relname, access_method.amname,
    COALESCE(index_relation.reloptions::TEXT, ''), index_record.indnatts, index_record.indnkeyatts,
    index_record.indisunique, index_record.indnullsnotdistinct, index_record.indisprimary,
    index_record.indisexclusion, index_record.indimmediate, index_record.indisclustered,
    index_record.indisvalid, index_record.indcheckxmin, index_record.indisready, index_record.indislive,
    index_record.indisreplident, index_record.indcollation::TEXT, index_record.indclass::TEXT,
    index_record.indoption::TEXT, COALESCE(index_definition.columns, '') || '|' ||
      COALESCE(pg_catalog.pg_get_expr(index_record.indpred, index_record.indrelid, FALSE), ''))
    ORDER BY index_relation.relname)
  INTO v_actual
  FROM pg_catalog.pg_index index_record
  JOIN pg_catalog.pg_class index_relation ON index_relation.oid = index_record.indexrelid
  JOIN pg_catalog.pg_class table_relation ON table_relation.oid = index_record.indrelid
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = table_relation.relnamespace
  JOIN pg_catalog.pg_am access_method ON access_method.oid = index_relation.relam
  LEFT JOIN LATERAL (
    SELECT pg_catalog.string_agg(
      pg_catalog.pg_get_indexdef(index_record.indexrelid, position, FALSE), ',' ORDER BY position
    ) columns
    FROM pg_catalog.generate_series(1, index_record.indnatts) position
  ) index_definition ON TRUE
  WHERE namespace.nspname = 'gmail_draft_broker';
  SELECT pg_catalog.array_agg(pg_catalog.format(
    '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s',
    index_relation.relname, table_relation.relname, access_method.amname,
    COALESCE(index_relation.reloptions::TEXT, ''), index_record.indnatts, index_record.indnkeyatts,
    index_record.indisunique, index_record.indnullsnotdistinct, index_record.indisprimary,
    index_record.indisexclusion, index_record.indimmediate, index_record.indisclustered,
    index_record.indisvalid, index_record.indcheckxmin, index_record.indisready, index_record.indislive,
    index_record.indisreplident, index_record.indcollation::TEXT, index_record.indclass::TEXT,
    index_record.indoption::TEXT, COALESCE(index_definition.columns, '') || '|' ||
      COALESCE(pg_catalog.pg_get_expr(index_record.indpred, index_record.indrelid, FALSE), ''))
    ORDER BY index_relation.relname)
  INTO v_expected
  FROM pg_catalog.pg_index index_record
  JOIN pg_catalog.pg_class index_relation ON index_relation.oid = index_record.indexrelid
  JOIN pg_catalog.pg_class table_relation ON table_relation.oid = index_record.indrelid
  JOIN pg_catalog.pg_am access_method ON access_method.oid = index_relation.relam
  LEFT JOIN LATERAL (
    SELECT pg_catalog.string_agg(
      pg_catalog.pg_get_indexdef(index_record.indexrelid, position, FALSE), ',' ORDER BY position
    ) columns
    FROM pg_catalog.generate_series(1, index_record.indnatts) position
  ) index_definition ON TRUE
  WHERE table_relation.relnamespace = pg_catalog.pg_my_temp_schema()
    AND table_relation.relname IN ('migration_versions','owner_slack_bindings','thread_sources',
      'approved_intents','active_lineage_claims');
  IF v_actual IS DISTINCT FROM v_expected THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has unexpected index definitions';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_policy policy
    JOIN pg_catalog.pg_class relation ON relation.oid = policy.polrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'gmail_draft_broker'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_rewrite rewrite
    JOIN pg_catalog.pg_class relation ON relation.oid = rewrite.ev_class
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'gmail_draft_broker'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_inherits inheritance
    JOIN pg_catalog.pg_class relation ON relation.oid IN (inheritance.inhrelid, inheritance.inhparent)
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'gmail_draft_broker'
  ) THEN
    RAISE EXCEPTION 'preexisting Gmail draft schema has unexpected policies, rules, or inheritance';
  END IF;
END
$definition_authority$;

SELECT pg_temp.assert_gmail_draft_definitions(TRUE);

CREATE SCHEMA IF NOT EXISTS gmail_draft_broker;

CREATE TABLE IF NOT EXISTS gmail_draft_broker.migration_versions(
  migration_id TEXT PRIMARY KEY,
  contract_sha256 TEXT NOT NULL CHECK (contract_sha256 ~ '^[a-f0-9]{64}$'),
  applied_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT)
);

CREATE TABLE IF NOT EXISTS gmail_draft_broker.owner_slack_bindings(
  organization_id TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL,
  slack_team_id TEXT NOT NULL,
  slack_user_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  key_id TEXT NOT NULL,
  binding_jti TEXT NOT NULL UNIQUE,
  receipt_id TEXT NOT NULL,
  signed_receipt_sha256 TEXT NOT NULL CHECK (signed_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  verified_receipt_sha256 TEXT NOT NULL UNIQUE CHECK (verified_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  issued_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  updated_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  PRIMARY KEY (organization_id, owner_principal_id),
  CHECK (slack_team_id ~ '^T[A-Z0-9]{8,31}$'),
  CHECK (slack_user_id ~ '^U[A-Z0-9]{8,31}$'),
  CHECK (expires_at > issued_at)
);

CREATE TABLE IF NOT EXISTS gmail_draft_broker.thread_sources(
  source_receipt_sha256 TEXT PRIMARY KEY CHECK (source_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  source_jti TEXT NOT NULL UNIQUE,
  issuer TEXT NOT NULL,
  key_id TEXT NOT NULL,
  organization_id TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL,
  logical_connection_id TEXT NOT NULL,
  connection_version INTEGER NOT NULL CHECK (connection_version > 0),
  google_subject TEXT NOT NULL,
  mailbox TEXT NOT NULL,
  gmail_thread_id TEXT NOT NULL,
  parent_message_id TEXT NOT NULL,
  reference_message_ids TEXT[] NOT NULL,
  subject_sha256 TEXT NOT NULL CHECK (subject_sha256 ~ '^[a-f0-9]{64}$'),
  issued_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  signed_receipt_sha256 TEXT NOT NULL CHECK (signed_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  verified_receipt_sha256 TEXT NOT NULL UNIQUE CHECK (verified_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  created_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  CHECK (source_receipt_sha256 = verified_receipt_sha256),
  CHECK (expires_at > issued_at),
  CHECK (cardinality(reference_message_ids) BETWEEN 1 AND 20)
);

CREATE TABLE IF NOT EXISTS gmail_draft_broker.approved_intents(
  effect_proposal_id TEXT PRIMARY KEY,
  proposal_revision INTEGER NOT NULL CHECK (proposal_revision > 0),
  draft_revision INTEGER NOT NULL CHECK (draft_revision > 0),
  proposal_sha256 TEXT NOT NULL CHECK (proposal_sha256 ~ '^[a-f0-9]{64}$'),
  approval_jti TEXT NOT NULL UNIQUE,
  approval_receipt_id TEXT NOT NULL,
  approval_issuer TEXT NOT NULL,
  approval_key_id TEXT NOT NULL,
  approval_signed_receipt_sha256 TEXT NOT NULL CHECK (approval_signed_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  approval_verified_receipt_sha256 TEXT NOT NULL UNIQUE CHECK (approval_verified_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  organization_id TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL,
  actor_principal_id TEXT NOT NULL,
  actor_slack_id TEXT NOT NULL,
  slack_team_id TEXT NOT NULL,
  slack_user_id TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  message_ts TEXT NOT NULL,
  thread_ts TEXT NOT NULL,
  action_ts TEXT NOT NULL,
  approval_issued_at BIGINT NOT NULL,
  approval_expires_at BIGINT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('create','update')),
  logical_connection_id TEXT NOT NULL,
  connection_version INTEGER NOT NULL CHECK (connection_version > 0),
  google_subject TEXT NOT NULL,
  mailbox TEXT NOT NULL,
  approved_payload_sha256 TEXT NOT NULL CHECK (approved_payload_sha256 ~ '^[a-f0-9]{64}$'),
  recipients_sha256 TEXT NOT NULL CHECK (recipients_sha256 ~ '^[a-f0-9]{64}$'),
  subject_sha256 TEXT NOT NULL CHECK (subject_sha256 ~ '^[a-f0-9]{64}$'),
  body_sha256 TEXT NOT NULL CHECK (body_sha256 ~ '^[a-f0-9]{64}$'),
  thread_binding_sha256 TEXT NOT NULL CHECK (thread_binding_sha256 ~ '^[a-f0-9]{64}$'),
  business_context_sha256 TEXT NOT NULL CHECK (business_context_sha256 ~ '^[a-f0-9]{64}$'),
  source_bundle_sha256 TEXT NOT NULL CHECK (source_bundle_sha256 ~ '^[a-f0-9]{64}$'),
  draft_id TEXT,
  prior_draft_receipt_sha256 TEXT,
  gmail_thread_id TEXT,
  reply_source_receipt_sha256 TEXT REFERENCES gmail_draft_broker.thread_sources(source_receipt_sha256),
  reply_parent_message_id TEXT,
  reply_reference_message_ids TEXT[],
  reply_subject_sha256 TEXT,
  proposal_ciphertext JSONB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('approved','pre_effect','effect_started','unknown','reconciling','created','rejected')),
  attempt_id TEXT,
  attempt_started_at BIGINT,
  claim_expires_at BIGINT,
  reconciliation_nonce TEXT,
  rejection_code TEXT CHECK (rejection_code IS NULL OR rejection_code IN ('approval_invalid','approval_expired','proposal_invalid',
    'connection_unavailable','connection_mismatch','scope_missing','gmail_unauthorized','gmail_rejected')),
  terminal_receipt_sha256 TEXT,
  terminal_draft_id TEXT,
  terminal_message_id TEXT,
  terminal_thread_id TEXT,
  terminal_mime_sha256 TEXT,
  terminal_request_sha256 TEXT,
  terminal_response_sha256 TEXT,
  terminal_credential_receipt_sha256 TEXT,
  terminal_marker_message_id TEXT,
  terminal_unknown_code TEXT CHECK (terminal_unknown_code IS NULL OR terminal_unknown_code IN ('network_failure',
    'deadline_exceeded','redirect_response','response_too_large','invalid_success_response','server_error')),
  terminal_at BIGINT,
  terminal_reconciled BOOLEAN,
  created_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  updated_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  CHECK (actor_principal_id = owner_principal_id),
  CHECK (actor_slack_id = slack_user_id),
  CHECK (channel_id ~ '^D[A-Z0-9]{8,31}$'),
  CHECK ((operation = 'create' AND draft_revision = 1 AND draft_id IS NULL AND prior_draft_receipt_sha256 IS NULL)
    OR (operation = 'update' AND draft_revision > 1 AND draft_id IS NOT NULL
      AND prior_draft_receipt_sha256 ~ '^[a-f0-9]{64}$')),
  CHECK ((reply_source_receipt_sha256 IS NULL AND reply_parent_message_id IS NULL
      AND reply_reference_message_ids IS NULL AND reply_subject_sha256 IS NULL)
    OR (reply_source_receipt_sha256 IS NOT NULL AND gmail_thread_id IS NOT NULL
      AND reply_parent_message_id IS NOT NULL AND cardinality(reply_reference_message_ids) BETWEEN 1 AND 20
      AND reply_subject_sha256 ~ '^[a-f0-9]{64}$')),
  CHECK ((status = 'approved' AND attempt_id IS NULL AND attempt_started_at IS NULL AND claim_expires_at IS NULL)
    OR (status IN ('pre_effect','effect_started','reconciling') AND attempt_id IS NOT NULL
      AND attempt_started_at IS NOT NULL AND claim_expires_at IS NOT NULL)
    OR (status IN ('unknown','created','rejected') AND attempt_id IS NOT NULL
      AND attempt_started_at IS NOT NULL AND claim_expires_at IS NULL)),
  CHECK ((status = 'rejected' AND rejection_code IS NOT NULL) OR (status <> 'rejected' AND rejection_code IS NULL)),
  CHECK ((status IN ('effect_started','unknown','reconciling')
      AND terminal_receipt_sha256 ~ '^[a-f0-9]{64}$' AND terminal_request_sha256 ~ '^[a-f0-9]{64}$'
      AND terminal_marker_message_id IS NOT NULL AND terminal_unknown_code IS NOT NULL AND terminal_at IS NOT NULL
      AND terminal_draft_id IS NULL AND terminal_message_id IS NULL AND terminal_thread_id IS NULL
      AND terminal_mime_sha256 IS NULL AND terminal_response_sha256 IS NULL
      AND terminal_credential_receipt_sha256 IS NULL AND terminal_reconciled IS NULL)
    OR (status = 'created'
      AND terminal_receipt_sha256 ~ '^[a-f0-9]{64}$' AND terminal_draft_id IS NOT NULL
      AND terminal_message_id IS NOT NULL AND terminal_mime_sha256 ~ '^[a-f0-9]{64}$'
      AND terminal_request_sha256 ~ '^[a-f0-9]{64}$' AND terminal_response_sha256 ~ '^[a-f0-9]{64}$'
      AND terminal_credential_receipt_sha256 ~ '^[a-f0-9]{64}$' AND terminal_at IS NOT NULL
      AND terminal_reconciled IS NOT NULL AND terminal_marker_message_id IS NULL AND terminal_unknown_code IS NULL)
    OR (status IN ('approved','pre_effect','rejected')
      AND terminal_receipt_sha256 IS NULL AND terminal_draft_id IS NULL AND terminal_message_id IS NULL
      AND terminal_thread_id IS NULL AND terminal_mime_sha256 IS NULL AND terminal_request_sha256 IS NULL
      AND terminal_response_sha256 IS NULL AND terminal_credential_receipt_sha256 IS NULL
      AND terminal_marker_message_id IS NULL AND terminal_unknown_code IS NULL AND terminal_at IS NULL
      AND terminal_reconciled IS NULL))
);

LOCK TABLE gmail_draft_broker.approved_intents IN ACCESS EXCLUSIVE MODE;

ALTER TABLE gmail_draft_broker.approved_intents
  ADD COLUMN IF NOT EXISTS reconciliation_nonce TEXT;

UPDATE gmail_draft_broker.approved_intents
SET reconciliation_nonce = pg_catalog.gen_random_uuid()::TEXT
WHERE status = 'reconciling' AND reconciliation_nonce IS NULL;

DO $reconciliation_constraint$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid = 'gmail_draft_broker.approved_intents'::pg_catalog.regclass
      AND conname = 'approved_intents_reconciliation_nonce_check'
  ) THEN
    ALTER TABLE gmail_draft_broker.approved_intents
      ADD CONSTRAINT approved_intents_reconciliation_nonce_check
      CHECK ((status = 'reconciling' AND reconciliation_nonce ~
          '^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$')
        OR (status <> 'reconciling' AND reconciliation_nonce IS NULL));
  END IF;
END
$reconciliation_constraint$;

CREATE TABLE IF NOT EXISTS gmail_draft_broker.active_lineage_claims(
  prior_draft_receipt_sha256 TEXT PRIMARY KEY CHECK (prior_draft_receipt_sha256 ~ '^[a-f0-9]{64}$'),
  parent_effect_proposal_id TEXT NOT NULL UNIQUE
    REFERENCES gmail_draft_broker.approved_intents(effect_proposal_id) ON DELETE RESTRICT,
  child_effect_proposal_id TEXT NOT NULL UNIQUE
    REFERENCES gmail_draft_broker.approved_intents(effect_proposal_id) ON DELETE RESTRICT,
  acquired_at BIGINT NOT NULL DEFAULT ((EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT),
  CHECK (parent_effect_proposal_id <> child_effect_proposal_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS gmail_draft_created_receipt_idx
  ON gmail_draft_broker.approved_intents(terminal_receipt_sha256)
  WHERE status = 'created';

CREATE INDEX IF NOT EXISTS gmail_draft_intents_status_idx
  ON gmail_draft_broker.approved_intents(status, claim_expires_at, updated_at);

CREATE OR REPLACE FUNCTION gmail_draft_broker.admit_owner_slack_binding(
  p_issuer TEXT, p_key_id TEXT, p_binding_jti TEXT, p_receipt_id TEXT, p_organization_id TEXT,
  p_owner_principal_id TEXT, p_slack_team_id TEXT, p_slack_user_id TEXT, p_issued_at BIGINT,
  p_expires_at BIGINT, p_signed_receipt_sha256 TEXT, p_verified_receipt_sha256 TEXT
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gmail_draft_broker
AS $function$
DECLARE
  v_now BIGINT := (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
  v_existing gmail_draft_broker.owner_slack_bindings%ROWTYPE;
  v_changed BOOLEAN;
BEGIN
  IF p_issuer !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_binding_jti !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_receipt_id !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_organization_id !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_owner_principal_id !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_slack_team_id !~ '^T[A-Z0-9]{8,31}$' OR p_slack_user_id !~ '^U[A-Z0-9]{8,31}$'
    OR p_signed_receipt_sha256 !~ '^[a-f0-9]{64}$' OR p_verified_receipt_sha256 !~ '^[a-f0-9]{64}$'
    OR p_issued_at > v_now + 30000 OR p_expires_at <= v_now OR p_expires_at <= p_issued_at
    OR p_expires_at - p_issued_at > 31622400000
  THEN
    RETURN 'rejected';
  END IF;
  INSERT INTO gmail_draft_broker.owner_slack_bindings(
    organization_id, owner_principal_id, slack_team_id, slack_user_id, issuer, key_id, binding_jti,
    receipt_id, signed_receipt_sha256, verified_receipt_sha256, issued_at, expires_at
  ) SELECT
    p_organization_id, p_owner_principal_id, p_slack_team_id, p_slack_user_id, p_issuer, p_key_id,
    p_binding_jti, p_receipt_id, p_signed_receipt_sha256, p_verified_receipt_sha256, p_issued_at, p_expires_at
  WHERE p_expires_at > (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT
  ON CONFLICT (organization_id, owner_principal_id) DO UPDATE SET
    slack_team_id = EXCLUDED.slack_team_id, slack_user_id = EXCLUDED.slack_user_id,
    issuer = EXCLUDED.issuer, key_id = EXCLUDED.key_id, binding_jti = EXCLUDED.binding_jti,
    receipt_id = EXCLUDED.receipt_id, signed_receipt_sha256 = EXCLUDED.signed_receipt_sha256,
    verified_receipt_sha256 = EXCLUDED.verified_receipt_sha256, issued_at = EXCLUDED.issued_at,
    expires_at = EXCLUDED.expires_at, updated_at = v_now
  WHERE gmail_draft_broker.owner_slack_bindings.issued_at < EXCLUDED.issued_at
    AND EXCLUDED.expires_at > (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
  v_changed := FOUND;
  IF v_changed THEN RETURN 'admitted'; END IF;
  v_now := (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
  IF p_expires_at <= v_now THEN RETURN 'rejected'; END IF;
  SELECT * INTO v_existing FROM gmail_draft_broker.owner_slack_bindings
  WHERE organization_id = p_organization_id AND owner_principal_id = p_owner_principal_id;
  IF FOUND AND v_existing.binding_jti = p_binding_jti
    AND v_existing.verified_receipt_sha256 = p_verified_receipt_sha256
    AND v_existing.slack_team_id = p_slack_team_id AND v_existing.slack_user_id = p_slack_user_id
    AND v_existing.issuer = p_issuer AND v_existing.key_id = p_key_id
    AND v_existing.receipt_id = p_receipt_id
    AND v_existing.signed_receipt_sha256 = p_signed_receipt_sha256
    AND v_existing.issued_at = p_issued_at AND v_existing.expires_at = p_expires_at
  THEN
    RETURN 'replayed';
  END IF;
  RETURN 'rejected';
EXCEPTION WHEN unique_violation THEN
  RETURN 'rejected';
END
$function$;

CREATE OR REPLACE FUNCTION gmail_draft_broker.admit_thread_source(
  p_issuer TEXT, p_key_id TEXT, p_source_jti TEXT, p_source_receipt_sha256 TEXT, p_organization_id TEXT,
  p_owner_principal_id TEXT, p_logical_connection_id TEXT, p_connection_version INTEGER,
  p_google_subject TEXT, p_mailbox TEXT, p_gmail_thread_id TEXT, p_parent_message_id TEXT,
  p_reference_message_ids TEXT[], p_subject_sha256 TEXT, p_issued_at BIGINT, p_expires_at BIGINT,
  p_signed_receipt_sha256 TEXT, p_verified_receipt_sha256 TEXT
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gmail_draft_broker
AS $function$
DECLARE
  v_now BIGINT := (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
BEGIN
  IF p_issuer !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_source_jti !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_organization_id !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_owner_principal_id !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_logical_connection_id !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_google_subject !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_connection_version < 1 OR p_gmail_thread_id !~ '^[A-Za-z0-9_-]{1,256}$'
    OR p_parent_message_id !~ '^<[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+>$'
    OR p_source_receipt_sha256 !~ '^[a-f0-9]{64}$' OR p_subject_sha256 !~ '^[a-f0-9]{64}$'
    OR p_signed_receipt_sha256 !~ '^[a-f0-9]{64}$' OR p_verified_receipt_sha256 !~ '^[a-f0-9]{64}$'
    OR p_source_receipt_sha256 <> p_verified_receipt_sha256
    OR cardinality(p_reference_message_ids) NOT BETWEEN 1 AND 20
    OR p_reference_message_ids[cardinality(p_reference_message_ids)] <> p_parent_message_id
    OR EXISTS (SELECT 1 FROM unnest(p_reference_message_ids) entry
      WHERE entry !~ '^<[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+>$')
    OR (SELECT count(*) FROM unnest(p_reference_message_ids) entry)
      <> (SELECT count(DISTINCT entry) FROM unnest(p_reference_message_ids) entry)
    OR p_issued_at > v_now + 30000 OR p_expires_at <= v_now OR p_expires_at <= p_issued_at
    OR p_expires_at - p_issued_at > 2678400000
  THEN
    RETURN 'rejected';
  END IF;
  INSERT INTO gmail_draft_broker.thread_sources(
    source_receipt_sha256, source_jti, issuer, key_id, organization_id, owner_principal_id,
    logical_connection_id, connection_version, google_subject, mailbox, gmail_thread_id,
    parent_message_id, reference_message_ids, subject_sha256, issued_at, expires_at,
    signed_receipt_sha256, verified_receipt_sha256
  ) VALUES (
    p_source_receipt_sha256, p_source_jti, p_issuer, p_key_id, p_organization_id, p_owner_principal_id,
    p_logical_connection_id, p_connection_version, p_google_subject, p_mailbox, p_gmail_thread_id,
    p_parent_message_id, p_reference_message_ids, p_subject_sha256, p_issued_at, p_expires_at,
    p_signed_receipt_sha256, p_verified_receipt_sha256
  ) ON CONFLICT DO NOTHING;
  IF FOUND THEN
    RETURN 'admitted';
  END IF;
  IF EXISTS (
    SELECT 1 FROM gmail_draft_broker.thread_sources source
    WHERE source.source_receipt_sha256 = p_source_receipt_sha256 AND source.source_jti = p_source_jti
      AND source.organization_id = p_organization_id AND source.owner_principal_id = p_owner_principal_id
      AND source.logical_connection_id = p_logical_connection_id AND source.connection_version = p_connection_version
      AND source.google_subject = p_google_subject AND source.mailbox = p_mailbox
      AND source.gmail_thread_id = p_gmail_thread_id AND source.parent_message_id = p_parent_message_id
      AND source.reference_message_ids = p_reference_message_ids AND source.subject_sha256 = p_subject_sha256
      AND source.issuer = p_issuer AND source.key_id = p_key_id
      AND source.signed_receipt_sha256 = p_signed_receipt_sha256
      AND source.verified_receipt_sha256 = p_verified_receipt_sha256
      AND source.issued_at = p_issued_at AND source.expires_at = p_expires_at
  ) THEN
    RETURN 'replayed';
  END IF;
  RETURN 'rejected';
END
$function$;

CREATE OR REPLACE FUNCTION gmail_draft_broker.admit_intent(
  p_effect_proposal_id TEXT, p_proposal_revision INTEGER, p_draft_revision INTEGER, p_proposal_sha256 TEXT,
  p_approval_jti TEXT, p_approval_receipt_id TEXT, p_approval_issuer TEXT, p_approval_key_id TEXT,
  p_approval_signed_receipt_sha256 TEXT, p_approval_verified_receipt_sha256 TEXT, p_organization_id TEXT,
  p_owner_principal_id TEXT, p_actor_principal_id TEXT, p_actor_slack_id TEXT, p_slack_team_id TEXT,
  p_slack_user_id TEXT, p_channel_id TEXT, p_message_ts TEXT, p_thread_ts TEXT, p_action_ts TEXT,
  p_approval_issued_at BIGINT, p_approval_expires_at BIGINT, p_operation TEXT, p_logical_connection_id TEXT,
  p_connection_version INTEGER, p_google_subject TEXT, p_mailbox TEXT, p_approved_payload_sha256 TEXT,
  p_recipients_sha256 TEXT, p_subject_sha256 TEXT, p_body_sha256 TEXT, p_thread_binding_sha256 TEXT,
  p_business_context_sha256 TEXT, p_source_bundle_sha256 TEXT, p_draft_id TEXT,
  p_prior_draft_receipt_sha256 TEXT, p_gmail_thread_id TEXT, p_reply_source_receipt_sha256 TEXT,
  p_reply_parent_message_id TEXT, p_reply_reference_message_ids TEXT[], p_reply_subject_sha256 TEXT,
  p_proposal_ciphertext JSONB
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gmail_draft_broker
AS $function$
DECLARE
  v_now BIGINT := (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
  v_action_at BIGINT;
  v_action_sequence NUMERIC;
  v_message_sequence NUMERIC;
  v_thread_sequence NUMERIC;
  v_prior gmail_draft_broker.approved_intents%ROWTYPE;
  v_active_child TEXT;
  v_locked_active_child TEXT;
  v_active_child_row gmail_draft_broker.approved_intents%ROWTYPE;
  v_inserted BOOLEAN;
BEGIN
  IF p_effect_proposal_id !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_approval_jti !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_approval_receipt_id !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_approval_issuer !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_approval_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,254}$'
    OR p_proposal_revision < 1 OR p_draft_revision < 1 OR p_connection_version < 1
    OR p_proposal_sha256 !~ '^[a-f0-9]{64}$'
    OR p_approval_signed_receipt_sha256 !~ '^[a-f0-9]{64}$'
    OR p_approval_verified_receipt_sha256 !~ '^[a-f0-9]{64}$'
    OR p_approved_payload_sha256 !~ '^[a-f0-9]{64}$' OR p_recipients_sha256 !~ '^[a-f0-9]{64}$'
    OR p_subject_sha256 !~ '^[a-f0-9]{64}$' OR p_body_sha256 !~ '^[a-f0-9]{64}$'
    OR p_thread_binding_sha256 !~ '^[a-f0-9]{64}$' OR p_business_context_sha256 !~ '^[a-f0-9]{64}$'
    OR p_source_bundle_sha256 !~ '^[a-f0-9]{64}$'
    OR p_actor_principal_id <> p_owner_principal_id OR p_actor_slack_id <> p_slack_user_id
    OR p_slack_team_id !~ '^T[A-Z0-9]{8,31}$' OR p_slack_user_id !~ '^U[A-Z0-9]{8,31}$'
    OR p_channel_id !~ '^D[A-Z0-9]{8,31}$'
    OR p_message_ts !~ '^[0-9]{10,13}\.[0-9]{6}$' OR p_thread_ts !~ '^[0-9]{10,13}\.[0-9]{6}$'
    OR p_action_ts !~ '^[0-9]{10,13}\.[0-9]{6}$'
    OR p_approval_issued_at > v_now + 30000 OR p_approval_expires_at <= v_now
    OR p_approval_expires_at <= p_approval_issued_at OR p_approval_expires_at - p_approval_issued_at > 300000
    OR pg_catalog.jsonb_typeof(p_proposal_ciphertext) <> 'object'
    OR NOT EXISTS (
      SELECT 1 FROM gmail_draft_broker.owner_slack_bindings owner_binding
      WHERE owner_binding.organization_id = p_organization_id
        AND owner_binding.owner_principal_id = p_owner_principal_id
        AND owner_binding.slack_team_id = p_slack_team_id AND owner_binding.slack_user_id = p_slack_user_id
        AND owner_binding.issuer = p_approval_issuer AND owner_binding.key_id = p_approval_key_id
        AND owner_binding.issued_at <= p_approval_issued_at
        AND owner_binding.expires_at > v_now AND owner_binding.expires_at >= p_approval_issued_at
      FOR SHARE
    )
  THEN
    RETURN 'rejected';
  END IF;
  v_action_sequence := pg_catalog.split_part(p_action_ts, '.', 1)::NUMERIC * 1000000
    + pg_catalog.split_part(p_action_ts, '.', 2)::INTEGER;
  v_message_sequence := pg_catalog.split_part(p_message_ts, '.', 1)::NUMERIC * 1000000
    + pg_catalog.split_part(p_message_ts, '.', 2)::INTEGER;
  v_thread_sequence := pg_catalog.split_part(p_thread_ts, '.', 1)::NUMERIC * 1000000
    + pg_catalog.split_part(p_thread_ts, '.', 2)::INTEGER;
  IF v_action_sequence / 1000 > 9223372036854775807 THEN
    RETURN 'rejected';
  END IF;
  v_action_at := pg_catalog.trunc(v_action_sequence / 1000)::BIGINT;
  IF v_thread_sequence > v_message_sequence OR v_message_sequence > v_action_sequence
    OR v_action_at < p_approval_issued_at - 30000 OR v_action_at > p_approval_issued_at + 30000
  THEN
    RETURN 'rejected';
  END IF;
  IF p_reply_source_receipt_sha256 IS NULL THEN
    IF p_reply_parent_message_id IS NOT NULL OR p_reply_reference_message_ids IS NOT NULL
      OR p_reply_subject_sha256 IS NOT NULL OR (p_operation = 'create' AND p_gmail_thread_id IS NOT NULL)
    THEN
      RETURN 'rejected';
    END IF;
  ELSIF p_gmail_thread_id IS NULL OR p_reply_parent_message_id IS NULL
    OR cardinality(p_reply_reference_message_ids) NOT BETWEEN 1 AND 20
    OR p_reply_reference_message_ids[cardinality(p_reply_reference_message_ids)] <> p_reply_parent_message_id
    OR p_reply_subject_sha256 <> p_subject_sha256
    OR NOT EXISTS (
      SELECT 1 FROM gmail_draft_broker.thread_sources source
      WHERE source.source_receipt_sha256 = p_reply_source_receipt_sha256
        AND source.organization_id = p_organization_id AND source.owner_principal_id = p_owner_principal_id
        AND source.logical_connection_id = p_logical_connection_id
        AND source.connection_version = p_connection_version AND source.google_subject = p_google_subject
        AND source.mailbox = p_mailbox AND source.gmail_thread_id = p_gmail_thread_id
        AND source.parent_message_id = p_reply_parent_message_id
        AND source.reference_message_ids = p_reply_reference_message_ids
        AND source.subject_sha256 = p_reply_subject_sha256 AND source.expires_at > v_now
      FOR SHARE
    )
  THEN
    RETURN 'rejected';
  END IF;
  IF p_operation = 'create' THEN
    IF p_draft_revision <> 1 OR p_draft_id IS NOT NULL OR p_prior_draft_receipt_sha256 IS NOT NULL THEN
      RETURN 'rejected';
    END IF;
  ELSIF p_operation = 'update' THEN
    SELECT * INTO v_prior FROM gmail_draft_broker.approved_intents prior
    WHERE prior.status = 'created' AND prior.terminal_receipt_sha256 = p_prior_draft_receipt_sha256
      AND prior.organization_id = p_organization_id AND prior.owner_principal_id = p_owner_principal_id
      AND prior.logical_connection_id = p_logical_connection_id AND prior.connection_version = p_connection_version
      AND prior.google_subject = p_google_subject AND prior.mailbox = p_mailbox
      AND prior.terminal_draft_id = p_draft_id AND prior.terminal_thread_id IS NOT DISTINCT FROM p_gmail_thread_id
      AND p_draft_revision = prior.draft_revision + 1
    FOR UPDATE;
    IF NOT FOUND THEN
      RETURN 'rejected';
    END IF;
    v_now := (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
    IF p_approval_expires_at <= v_now THEN RETURN 'rejected'; END IF;
    SELECT claim.child_effect_proposal_id INTO v_active_child
    FROM gmail_draft_broker.active_lineage_claims claim
    WHERE claim.prior_draft_receipt_sha256 = p_prior_draft_receipt_sha256;
    IF FOUND THEN
      SELECT * INTO v_active_child_row FROM gmail_draft_broker.approved_intents child
      WHERE child.effect_proposal_id = v_active_child FOR UPDATE;
      SELECT claim.child_effect_proposal_id INTO v_locked_active_child
      FROM gmail_draft_broker.active_lineage_claims claim
      WHERE claim.prior_draft_receipt_sha256 = p_prior_draft_receipt_sha256
      FOR UPDATE;
      IF FOUND AND v_locked_active_child <> v_active_child THEN RETURN 'rejected'; END IF;
      v_now := (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
      IF p_approval_expires_at <= v_now THEN RETURN 'rejected'; END IF;
    END IF;
    IF v_locked_active_child IS NOT NULL AND v_locked_active_child <> p_effect_proposal_id THEN
      IF v_active_child_row.status NOT IN ('approved','pre_effect')
        OR v_active_child_row.approval_expires_at > v_now
      THEN
        RETURN 'rejected';
      END IF;
      UPDATE gmail_draft_broker.approved_intents SET status = 'rejected', rejection_code = 'approval_expired',
        attempt_id = COALESCE(attempt_id, pg_catalog.gen_random_uuid()::TEXT),
        attempt_started_at = COALESCE(attempt_started_at, v_now), claim_expires_at = NULL,
        reconciliation_nonce = NULL, updated_at = v_now
      WHERE effect_proposal_id = v_locked_active_child AND status = v_active_child_row.status
        AND approval_expires_at <= v_now;
      IF NOT FOUND THEN RETURN 'rejected'; END IF;
      DELETE FROM gmail_draft_broker.active_lineage_claims claim
      WHERE claim.prior_draft_receipt_sha256 = p_prior_draft_receipt_sha256
        AND claim.child_effect_proposal_id = v_locked_active_child;
      IF NOT FOUND THEN RETURN 'rejected'; END IF;
    END IF;
  ELSE
    RETURN 'rejected';
  END IF;
  v_now := (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
  IF p_approval_expires_at <= v_now OR NOT EXISTS (
    SELECT 1 FROM gmail_draft_broker.owner_slack_bindings owner_binding
    WHERE owner_binding.organization_id = p_organization_id
      AND owner_binding.owner_principal_id = p_owner_principal_id
      AND owner_binding.slack_team_id = p_slack_team_id AND owner_binding.slack_user_id = p_slack_user_id
      AND owner_binding.issuer = p_approval_issuer AND owner_binding.key_id = p_approval_key_id
      AND owner_binding.issued_at <= p_approval_issued_at
      AND owner_binding.expires_at > v_now AND owner_binding.expires_at >= p_approval_issued_at
  ) OR (p_reply_source_receipt_sha256 IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM gmail_draft_broker.thread_sources source
    WHERE source.source_receipt_sha256 = p_reply_source_receipt_sha256 AND source.expires_at > v_now
  )) THEN
    RETURN 'rejected';
  END IF;
  INSERT INTO gmail_draft_broker.approved_intents(
    effect_proposal_id, proposal_revision, draft_revision, proposal_sha256, approval_jti,
    approval_receipt_id, approval_issuer, approval_key_id, approval_signed_receipt_sha256,
    approval_verified_receipt_sha256, organization_id, owner_principal_id, actor_principal_id,
    actor_slack_id, slack_team_id, slack_user_id, channel_id, message_ts, thread_ts, action_ts,
    approval_issued_at, approval_expires_at, operation, logical_connection_id, connection_version,
    google_subject, mailbox, approved_payload_sha256, recipients_sha256, subject_sha256, body_sha256,
    thread_binding_sha256, business_context_sha256, source_bundle_sha256, draft_id,
    prior_draft_receipt_sha256, gmail_thread_id, reply_source_receipt_sha256,
    reply_parent_message_id, reply_reference_message_ids, reply_subject_sha256, proposal_ciphertext, status
  ) VALUES (
    p_effect_proposal_id, p_proposal_revision, p_draft_revision, p_proposal_sha256, p_approval_jti,
    p_approval_receipt_id, p_approval_issuer, p_approval_key_id, p_approval_signed_receipt_sha256,
    p_approval_verified_receipt_sha256, p_organization_id, p_owner_principal_id, p_actor_principal_id,
    p_actor_slack_id, p_slack_team_id, p_slack_user_id, p_channel_id, p_message_ts, p_thread_ts,
    p_action_ts, p_approval_issued_at, p_approval_expires_at, p_operation, p_logical_connection_id,
    p_connection_version, p_google_subject, p_mailbox, p_approved_payload_sha256, p_recipients_sha256,
    p_subject_sha256, p_body_sha256, p_thread_binding_sha256, p_business_context_sha256,
    p_source_bundle_sha256, p_draft_id, p_prior_draft_receipt_sha256, p_gmail_thread_id,
    p_reply_source_receipt_sha256, p_reply_parent_message_id, p_reply_reference_message_ids,
    p_reply_subject_sha256, p_proposal_ciphertext, 'approved'
  ) ON CONFLICT DO NOTHING;
  v_inserted := FOUND;
  IF v_inserted THEN
    IF p_operation = 'update' THEN
      INSERT INTO gmail_draft_broker.active_lineage_claims(
        prior_draft_receipt_sha256, parent_effect_proposal_id, child_effect_proposal_id, acquired_at
      ) VALUES (
        p_prior_draft_receipt_sha256, v_prior.effect_proposal_id, p_effect_proposal_id, v_now
      ) ON CONFLICT DO NOTHING;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'Gmail draft active lineage compare-and-set lost authority';
      END IF;
    END IF;
    RETURN 'admitted';
  END IF;
  IF EXISTS (
    SELECT 1 FROM gmail_draft_broker.approved_intents existing
    WHERE existing.effect_proposal_id = p_effect_proposal_id
      AND existing.proposal_revision = p_proposal_revision AND existing.draft_revision = p_draft_revision
      AND existing.proposal_sha256 = p_proposal_sha256 AND existing.approval_jti = p_approval_jti
      AND existing.approval_verified_receipt_sha256 = p_approval_verified_receipt_sha256
      AND existing.proposal_ciphertext = p_proposal_ciphertext
      AND (p_operation = 'create' OR EXISTS (
        SELECT 1 FROM gmail_draft_broker.active_lineage_claims claim
        WHERE claim.prior_draft_receipt_sha256 = p_prior_draft_receipt_sha256
          AND claim.parent_effect_proposal_id = v_prior.effect_proposal_id
          AND claim.child_effect_proposal_id = p_effect_proposal_id
      ))
  ) THEN
    RETURN 'replayed';
  END IF;
  RETURN 'rejected';
END
$function$;

CREATE OR REPLACE FUNCTION gmail_draft_broker.claim_effect(p_effect_proposal_id TEXT, p_claim_ms INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gmail_draft_broker
AS $function$
DECLARE
  v_now BIGINT := (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
  v_row gmail_draft_broker.approved_intents%ROWTYPE;
  v_claim_acquired BOOLEAN := FALSE;
BEGIN
  IF p_claim_ms < 1000 OR p_claim_ms > 600000 THEN RETURN NULL; END IF;
  SELECT * INTO v_row FROM gmail_draft_broker.approved_intents
  WHERE effect_proposal_id = p_effect_proposal_id FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF v_row.status IN ('approved','pre_effect') AND v_row.approval_expires_at <= v_now THEN
    UPDATE gmail_draft_broker.approved_intents SET status = 'rejected', rejection_code = 'approval_expired',
      attempt_id = COALESCE(attempt_id, pg_catalog.gen_random_uuid()::TEXT),
      attempt_started_at = COALESCE(attempt_started_at, v_now), claim_expires_at = NULL,
      reconciliation_nonce = NULL, updated_at = v_now
    WHERE effect_proposal_id = p_effect_proposal_id RETURNING * INTO v_row;
    DELETE FROM gmail_draft_broker.active_lineage_claims claim
    WHERE claim.child_effect_proposal_id = v_row.effect_proposal_id
      AND claim.prior_draft_receipt_sha256 = v_row.prior_draft_receipt_sha256;
  ELSIF v_row.status = 'approved' OR (v_row.status = 'pre_effect' AND COALESCE(v_row.claim_expires_at, 0) <= v_now) THEN
    UPDATE gmail_draft_broker.approved_intents SET status = 'pre_effect',
      attempt_id = pg_catalog.gen_random_uuid()::TEXT, attempt_started_at = v_now,
      claim_expires_at = v_now + p_claim_ms, reconciliation_nonce = NULL, updated_at = v_now
    WHERE effect_proposal_id = p_effect_proposal_id RETURNING * INTO v_row;
    v_claim_acquired := TRUE;
  END IF;
  RETURN pg_catalog.to_jsonb(v_row) || pg_catalog.jsonb_build_object('_approvalCurrent',
    v_row.approval_expires_at > v_now, '_claimCurrent',
    v_row.claim_expires_at IS NOT NULL AND v_row.claim_expires_at > v_now,
    '_claimAcquired', v_claim_acquired);
END
$function$;

CREATE OR REPLACE FUNCTION gmail_draft_broker.claim_reconciliation(p_effect_proposal_id TEXT, p_claim_ms INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gmail_draft_broker
AS $function$
DECLARE
  v_now BIGINT := (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
  v_row gmail_draft_broker.approved_intents%ROWTYPE;
  v_claim_acquired BOOLEAN := FALSE;
BEGIN
  IF p_claim_ms < 1000 OR p_claim_ms > 600000 THEN RETURN NULL; END IF;
  SELECT * INTO v_row FROM gmail_draft_broker.approved_intents
  WHERE effect_proposal_id = p_effect_proposal_id FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF v_row.status = 'unknown'
    OR (v_row.status = 'effect_started' AND COALESCE(v_row.claim_expires_at, 0) <= v_now)
    OR (v_row.status = 'reconciling' AND COALESCE(v_row.claim_expires_at, 0) <= v_now)
  THEN
    UPDATE gmail_draft_broker.approved_intents SET status = 'reconciling',
      claim_expires_at = v_now + p_claim_ms, reconciliation_nonce = pg_catalog.gen_random_uuid()::TEXT,
      updated_at = v_now
    WHERE effect_proposal_id = p_effect_proposal_id RETURNING * INTO v_row;
    v_claim_acquired := TRUE;
  END IF;
  RETURN pg_catalog.to_jsonb(v_row) || pg_catalog.jsonb_build_object('_approvalCurrent',
    v_row.approval_expires_at > v_now, '_claimCurrent',
    v_row.claim_expires_at IS NOT NULL AND v_row.claim_expires_at > v_now,
    '_claimAcquired', v_claim_acquired);
END
$function$;

CREATE OR REPLACE FUNCTION gmail_draft_broker.arm_effect(
  p_effect_proposal_id TEXT, p_proposal_revision INTEGER, p_attempt_id TEXT,
  p_receipt_sha256 TEXT, p_request_sha256 TEXT, p_marker_message_id TEXT,
  p_unknown_code TEXT, p_recorded_at BIGINT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, gmail_draft_broker
AS $function$
  WITH changed AS (
    UPDATE gmail_draft_broker.approved_intents SET status = 'effect_started',
      terminal_receipt_sha256 = p_receipt_sha256, terminal_request_sha256 = p_request_sha256,
      terminal_marker_message_id = p_marker_message_id, terminal_unknown_code = p_unknown_code,
      terminal_at = p_recorded_at, updated_at = (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT
    WHERE effect_proposal_id = p_effect_proposal_id AND proposal_revision = p_proposal_revision
      AND attempt_id = p_attempt_id AND status = 'pre_effect'
      AND claim_expires_at > (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT
      AND approval_expires_at > (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT
      AND p_receipt_sha256 ~ '^[a-f0-9]{64}$' AND p_request_sha256 ~ '^[a-f0-9]{64}$'
      AND p_marker_message_id = '<qm.' || approved_payload_sha256 || '@drafts.invalid>'
      AND p_unknown_code IN ('network_failure','deadline_exceeded','redirect_response','response_too_large',
        'invalid_success_response','server_error') AND p_recorded_at > 0
    RETURNING 1
  ) SELECT EXISTS(SELECT 1 FROM changed)
$function$;

DROP FUNCTION IF EXISTS gmail_draft_broker.record_created(
  TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,BOOLEAN
);

CREATE OR REPLACE FUNCTION gmail_draft_broker.record_created(
  p_effect_proposal_id TEXT, p_proposal_revision INTEGER, p_attempt_id TEXT,
  p_receipt_sha256 TEXT, p_draft_id TEXT, p_message_id TEXT, p_thread_id TEXT,
  p_mime_sha256 TEXT, p_request_sha256 TEXT, p_response_sha256 TEXT,
  p_credential_receipt_sha256 TEXT, p_created_at BIGINT, p_reconciled BOOLEAN,
  p_reconciliation_nonce TEXT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, gmail_draft_broker
AS $function$
  WITH changed AS (
    UPDATE gmail_draft_broker.approved_intents SET status = 'created',
      terminal_receipt_sha256 = p_receipt_sha256, terminal_draft_id = p_draft_id,
      terminal_message_id = p_message_id, terminal_thread_id = p_thread_id,
      terminal_mime_sha256 = p_mime_sha256, terminal_request_sha256 = p_request_sha256,
      terminal_response_sha256 = p_response_sha256,
      terminal_credential_receipt_sha256 = p_credential_receipt_sha256,
      terminal_marker_message_id = NULL, terminal_unknown_code = NULL,
      terminal_at = p_created_at, terminal_reconciled = p_reconciled,
      rejection_code = NULL, claim_expires_at = NULL,
      reconciliation_nonce = NULL,
      updated_at = (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT
    WHERE effect_proposal_id = p_effect_proposal_id AND proposal_revision = p_proposal_revision
      AND attempt_id = p_attempt_id AND ((status = 'effect_started' AND p_reconciled IS FALSE
          AND p_reconciliation_nonce IS NULL)
        OR (status = 'reconciling' AND p_reconciled IS TRUE
          AND reconciliation_nonce = p_reconciliation_nonce
          AND claim_expires_at > (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT))
      AND terminal_request_sha256 = p_request_sha256
      AND p_receipt_sha256 ~ '^[a-f0-9]{64}$' AND p_draft_id ~ '^[A-Za-z0-9_-]{1,256}$'
      AND p_message_id ~ '^[A-Za-z0-9_-]{1,256}$'
      AND (p_thread_id IS NULL OR p_thread_id ~ '^[A-Za-z0-9_-]{1,256}$')
      AND p_mime_sha256 ~ '^[a-f0-9]{64}$' AND p_request_sha256 ~ '^[a-f0-9]{64}$'
      AND p_response_sha256 ~ '^[a-f0-9]{64}$' AND p_credential_receipt_sha256 ~ '^[a-f0-9]{64}$'
      AND p_created_at > 0 AND (operation <> 'update' OR p_draft_id = draft_id)
      AND (gmail_thread_id IS NULL OR p_thread_id = gmail_thread_id)
    RETURNING 1
  ) SELECT EXISTS(SELECT 1 FROM changed)
$function$;

CREATE OR REPLACE FUNCTION gmail_draft_broker.record_unknown(
  p_effect_proposal_id TEXT, p_proposal_revision INTEGER, p_attempt_id TEXT,
  p_receipt_sha256 TEXT, p_request_sha256 TEXT, p_marker_message_id TEXT,
  p_unknown_code TEXT, p_recorded_at BIGINT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, gmail_draft_broker
AS $function$
  WITH changed AS (
    UPDATE gmail_draft_broker.approved_intents SET status = 'unknown',
      terminal_receipt_sha256 = p_receipt_sha256, terminal_unknown_code = p_unknown_code,
      terminal_at = p_recorded_at, claim_expires_at = NULL,
      updated_at = (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT
    WHERE effect_proposal_id = p_effect_proposal_id AND proposal_revision = p_proposal_revision
      AND attempt_id = p_attempt_id AND status = 'effect_started'
      AND terminal_request_sha256 = p_request_sha256 AND terminal_marker_message_id = p_marker_message_id
      AND p_receipt_sha256 ~ '^[a-f0-9]{64}$'
      AND p_unknown_code IN ('network_failure','deadline_exceeded','redirect_response','response_too_large',
        'invalid_success_response','server_error') AND p_recorded_at > 0
    RETURNING 1
  ) SELECT EXISTS(SELECT 1 FROM changed)
$function$;

DROP FUNCTION IF EXISTS gmail_draft_broker.retain_unknown(
  TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT
);

CREATE OR REPLACE FUNCTION gmail_draft_broker.retain_unknown(
  p_effect_proposal_id TEXT, p_proposal_revision INTEGER, p_attempt_id TEXT,
  p_receipt_sha256 TEXT, p_request_sha256 TEXT, p_marker_message_id TEXT,
  p_unknown_code TEXT, p_recorded_at BIGINT, p_reconciliation_nonce TEXT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, gmail_draft_broker
AS $function$
  WITH changed AS (
    UPDATE gmail_draft_broker.approved_intents SET status = 'unknown',
      terminal_receipt_sha256 = p_receipt_sha256, terminal_unknown_code = p_unknown_code,
      terminal_at = p_recorded_at, claim_expires_at = NULL, reconciliation_nonce = NULL,
      updated_at = (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT
    WHERE effect_proposal_id = p_effect_proposal_id AND proposal_revision = p_proposal_revision
      AND attempt_id = p_attempt_id AND status = 'reconciling'
      AND reconciliation_nonce = p_reconciliation_nonce
      AND claim_expires_at > (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT
      AND terminal_request_sha256 = p_request_sha256 AND terminal_marker_message_id = p_marker_message_id
      AND p_receipt_sha256 ~ '^[a-f0-9]{64}$'
      AND p_unknown_code IN ('network_failure','deadline_exceeded','redirect_response','response_too_large',
        'invalid_success_response','server_error') AND p_recorded_at > 0
    RETURNING 1
  ) SELECT EXISTS(SELECT 1 FROM changed)
$function$;

CREATE OR REPLACE FUNCTION gmail_draft_broker.reject_before_effect(
  p_effect_proposal_id TEXT, p_proposal_revision INTEGER, p_attempt_id TEXT, p_rejection_code TEXT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, gmail_draft_broker
AS $function$
  WITH changed AS (
    UPDATE gmail_draft_broker.approved_intents SET status = 'rejected', rejection_code = p_rejection_code,
      terminal_receipt_sha256 = NULL, terminal_draft_id = NULL, terminal_message_id = NULL,
      terminal_thread_id = NULL, terminal_mime_sha256 = NULL, terminal_request_sha256 = NULL,
      terminal_response_sha256 = NULL, terminal_credential_receipt_sha256 = NULL,
      terminal_marker_message_id = NULL, terminal_unknown_code = NULL, terminal_at = NULL,
      terminal_reconciled = NULL, claim_expires_at = NULL, reconciliation_nonce = NULL,
      updated_at = (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT
    WHERE effect_proposal_id = p_effect_proposal_id AND proposal_revision = p_proposal_revision
      AND attempt_id = p_attempt_id AND status = 'pre_effect'
      AND p_rejection_code IN ('approval_invalid','approval_expired','proposal_invalid')
    RETURNING effect_proposal_id, prior_draft_receipt_sha256
  ), released AS (
    DELETE FROM gmail_draft_broker.active_lineage_claims claim USING changed
    WHERE claim.child_effect_proposal_id = changed.effect_proposal_id
      AND claim.prior_draft_receipt_sha256 = changed.prior_draft_receipt_sha256
    RETURNING claim.child_effect_proposal_id
  ) SELECT EXISTS(SELECT 1 FROM changed)
$function$;

CREATE OR REPLACE FUNCTION gmail_draft_broker.reject_definitive_no_write(
  p_effect_proposal_id TEXT, p_proposal_revision INTEGER, p_attempt_id TEXT, p_rejection_code TEXT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, gmail_draft_broker
AS $function$
  WITH changed AS (
    UPDATE gmail_draft_broker.approved_intents SET status = 'rejected', rejection_code = p_rejection_code,
      terminal_receipt_sha256 = NULL, terminal_draft_id = NULL, terminal_message_id = NULL,
      terminal_thread_id = NULL, terminal_mime_sha256 = NULL, terminal_request_sha256 = NULL,
      terminal_response_sha256 = NULL, terminal_credential_receipt_sha256 = NULL,
      terminal_marker_message_id = NULL, terminal_unknown_code = NULL, terminal_at = NULL,
      terminal_reconciled = NULL, claim_expires_at = NULL, reconciliation_nonce = NULL,
      updated_at = (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT
    WHERE effect_proposal_id = p_effect_proposal_id AND proposal_revision = p_proposal_revision
      AND attempt_id = p_attempt_id AND status = 'effect_started'
      AND p_rejection_code IN ('connection_unavailable','connection_mismatch','scope_missing',
        'gmail_unauthorized','gmail_rejected')
    RETURNING effect_proposal_id, prior_draft_receipt_sha256
  ), released AS (
    DELETE FROM gmail_draft_broker.active_lineage_claims claim USING changed
    WHERE claim.child_effect_proposal_id = changed.effect_proposal_id
      AND claim.prior_draft_receipt_sha256 = changed.prior_draft_receipt_sha256
    RETURNING claim.child_effect_proposal_id
  ) SELECT EXISTS(SELECT 1 FROM changed)
$function$;

INSERT INTO gmail_draft_broker.migration_versions(migration_id, contract_sha256)
VALUES ('gmail-draft-broker-active-lineage-v1', '58ecaa5bc584f7266a8ef9fe150713d6371228f0a160b2d4773a4f1b3192217d')
ON CONFLICT DO NOTHING;

INSERT INTO gmail_draft_broker.migration_versions(migration_id, contract_sha256)
VALUES ('gmail-draft-broker-reconciliation-fence-v2', '52ce16312baeed1b8dccc84f0b1a50d23119e2c0566b99b713705ba34710f742')
ON CONFLICT DO NOTHING;

ALTER TABLE gmail_draft_broker.migration_versions OWNER TO qm_gmail_draft_owner;
ALTER TABLE gmail_draft_broker.owner_slack_bindings OWNER TO qm_gmail_draft_owner;
ALTER TABLE gmail_draft_broker.thread_sources OWNER TO qm_gmail_draft_owner;
ALTER TABLE gmail_draft_broker.approved_intents OWNER TO qm_gmail_draft_owner;
ALTER TABLE gmail_draft_broker.active_lineage_claims OWNER TO qm_gmail_draft_owner;
ALTER FUNCTION gmail_draft_broker.admit_owner_slack_binding(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT) OWNER TO qm_gmail_draft_owner;
ALTER FUNCTION gmail_draft_broker.admit_thread_source(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT[],TEXT,BIGINT,BIGINT,TEXT,TEXT) OWNER TO qm_gmail_draft_owner;
ALTER FUNCTION gmail_draft_broker.admit_intent(TEXT,INTEGER,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT[],TEXT,JSONB) OWNER TO qm_gmail_draft_owner;
ALTER FUNCTION gmail_draft_broker.claim_effect(TEXT,INTEGER) OWNER TO qm_gmail_draft_owner;
ALTER FUNCTION gmail_draft_broker.claim_reconciliation(TEXT,INTEGER) OWNER TO qm_gmail_draft_owner;
ALTER FUNCTION gmail_draft_broker.arm_effect(TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT) OWNER TO qm_gmail_draft_owner;
ALTER FUNCTION gmail_draft_broker.record_created(TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,BOOLEAN,TEXT) OWNER TO qm_gmail_draft_owner;
ALTER FUNCTION gmail_draft_broker.record_unknown(TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT) OWNER TO qm_gmail_draft_owner;
ALTER FUNCTION gmail_draft_broker.retain_unknown(TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,TEXT) OWNER TO qm_gmail_draft_owner;
ALTER FUNCTION gmail_draft_broker.reject_before_effect(TEXT,INTEGER,TEXT,TEXT) OWNER TO qm_gmail_draft_owner;
ALTER FUNCTION gmail_draft_broker.reject_definitive_no_write(TEXT,INTEGER,TEXT,TEXT) OWNER TO qm_gmail_draft_owner;
ALTER SCHEMA gmail_draft_broker OWNER TO qm_gmail_draft_owner;

REVOKE ALL ON SCHEMA gmail_draft_broker FROM PUBLIC;
GRANT USAGE ON SCHEMA gmail_draft_broker TO qm_gmail_draft_admission, qm_gmail_draft_broker;
REVOKE ALL ON ALL TABLES IN SCHEMA gmail_draft_broker FROM PUBLIC, qm_gmail_draft_admission, qm_gmail_draft_broker;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA gmail_draft_broker FROM PUBLIC, qm_gmail_draft_admission, qm_gmail_draft_broker;
DO $column_privilege_revoke$
DECLARE
  v_relation RECORD;
BEGIN
  FOR v_relation IN
    SELECT namespace.nspname, relation.relname,
      pg_catalog.string_agg(pg_catalog.quote_ident(attribute.attname), ',' ORDER BY attribute.attnum) columns
    FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid = relation.oid
    WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind IN ('r','p','v','m','f')
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
    GROUP BY namespace.nspname, relation.relname
  LOOP
    EXECUTE pg_catalog.format(
      'REVOKE ALL (%s) ON TABLE %I.%I FROM PUBLIC, qm_gmail_draft_admission, qm_gmail_draft_broker',
      v_relation.columns, v_relation.nspname, v_relation.relname
    );
  END LOOP;
  FOR v_relation IN
    SELECT namespace.nspname, type_record.typname
    FROM pg_catalog.pg_type type_record
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
    WHERE namespace.nspname = 'gmail_draft_broker'
  LOOP
    EXECUTE pg_catalog.format(
      'REVOKE ALL ON TYPE %I.%I FROM PUBLIC, qm_gmail_draft_admission, qm_gmail_draft_broker',
      v_relation.nspname, v_relation.typname
    );
  END LOOP;
END
$column_privilege_revoke$;
ALTER DEFAULT PRIVILEGES FOR ROLE qm_gmail_draft_owner IN SCHEMA gmail_draft_broker
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE qm_gmail_draft_owner IN SCHEMA gmail_draft_broker
  REVOKE USAGE ON TYPES FROM PUBLIC;

GRANT EXECUTE ON FUNCTION gmail_draft_broker.admit_owner_slack_binding(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT) TO qm_gmail_draft_admission;
GRANT EXECUTE ON FUNCTION gmail_draft_broker.admit_thread_source(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT[],TEXT,BIGINT,BIGINT,TEXT,TEXT) TO qm_gmail_draft_admission;
GRANT EXECUTE ON FUNCTION gmail_draft_broker.admit_intent(TEXT,INTEGER,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT,TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT[],TEXT,JSONB) TO qm_gmail_draft_admission;
GRANT EXECUTE ON FUNCTION gmail_draft_broker.claim_effect(TEXT,INTEGER) TO qm_gmail_draft_broker;
GRANT EXECUTE ON FUNCTION gmail_draft_broker.claim_reconciliation(TEXT,INTEGER) TO qm_gmail_draft_broker;
GRANT EXECUTE ON FUNCTION gmail_draft_broker.arm_effect(TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT) TO qm_gmail_draft_broker;
GRANT EXECUTE ON FUNCTION gmail_draft_broker.record_created(TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,BOOLEAN,TEXT) TO qm_gmail_draft_broker;
GRANT EXECUTE ON FUNCTION gmail_draft_broker.record_unknown(TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT) TO qm_gmail_draft_broker;
GRANT EXECUTE ON FUNCTION gmail_draft_broker.retain_unknown(TEXT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT,TEXT) TO qm_gmail_draft_broker;
GRANT EXECUTE ON FUNCTION gmail_draft_broker.reject_before_effect(TEXT,INTEGER,TEXT,TEXT) TO qm_gmail_draft_broker;
GRANT EXECUTE ON FUNCTION gmail_draft_broker.reject_definitive_no_write(TEXT,INTEGER,TEXT,TEXT) TO qm_gmail_draft_broker;

DO $catalog_postflight$
DECLARE
  v_relations TEXT[];
  v_types TEXT[];
BEGIN
  SELECT pg_catalog.array_agg(relation.relname ORDER BY relation.relname) INTO v_relations
  FROM pg_catalog.pg_class relation
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
  WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind IN ('r','p','v','m','f','S','c');
  IF v_relations <> ARRAY['active_lineage_claims','approved_intents','migration_versions','owner_slack_bindings','thread_sources']::TEXT[]
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_class relation
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
      JOIN pg_catalog.pg_roles owner ON owner.oid = relation.relowner
      WHERE namespace.nspname = 'gmail_draft_broker'
        AND relation.relkind IN ('r','p','v','m','f','S','c','i','I')
        AND (owner.rolname <> 'qm_gmail_draft_owner'
          OR (relation.relkind = 'r' AND relation.relpersistence <> 'p'))
    )
  THEN
    RAISE EXCEPTION 'Gmail draft table postflight failed';
  END IF;
  SELECT pg_catalog.array_agg(type_record.typname ORDER BY type_record.typname COLLATE "C") INTO v_types
  FROM pg_catalog.pg_type type_record
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
  WHERE namespace.nspname = 'gmail_draft_broker';
  IF v_types <> ARRAY['_active_lineage_claims','_approved_intents','_migration_versions',
    '_owner_slack_bindings','_thread_sources','active_lineage_claims','approved_intents',
    'migration_versions','owner_slack_bindings','thread_sources']::TEXT[] OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_type type_record
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
      JOIN pg_catalog.pg_roles owner ON owner.oid = type_record.typowner
      WHERE namespace.nspname = 'gmail_draft_broker' AND owner.rolname <> 'qm_gmail_draft_owner'
    )
  THEN
    RAISE EXCEPTION 'Gmail draft type postflight failed';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_attribute attribute
    JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(attribute.attacl, '{}'::pg_catalog.aclitem[])) acl
    WHERE namespace.nspname = 'gmail_draft_broker' AND attribute.attnum > 0
      AND NOT attribute.attisdropped
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_type type_record
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(type_record.typacl, pg_catalog.acldefault('T', type_record.typowner))
    ) acl
    LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
    WHERE namespace.nspname = 'gmail_draft_broker'
      AND COALESCE(grantee.rolname, 'public') <> 'qm_gmail_draft_owner'
  ) THEN
    RAISE EXCEPTION 'Gmail draft column or type ACL postflight failed';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger trigger
    JOIN pg_catalog.pg_class relation ON relation.oid = trigger.tgrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    LEFT JOIN pg_catalog.pg_constraint constraint_record ON constraint_record.oid = trigger.tgconstraint
    WHERE namespace.nspname = 'gmail_draft_broker' AND (
      NOT trigger.tgisinternal OR trigger.tgenabled <> 'O' OR trigger.tgparentid <> 0
      OR constraint_record.contype IS DISTINCT FROM 'f' OR trigger.tgdeferrable <> constraint_record.condeferrable
      OR trigger.tginitdeferred <> constraint_record.condeferred OR trigger.tgqual IS NOT NULL
      OR cardinality(trigger.tgattr) <> 0 OR pg_catalog.octet_length(trigger.tgargs) <> 0)
  ) OR (
    SELECT count(*) FROM pg_catalog.pg_trigger trigger
    JOIN pg_catalog.pg_class relation ON relation.oid = trigger.tgrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'gmail_draft_broker'
  ) <> 4 * (
    SELECT count(*) FROM pg_catalog.pg_constraint constraint_record
    JOIN pg_catalog.pg_class relation ON relation.oid = constraint_record.conrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'gmail_draft_broker' AND constraint_record.contype = 'f'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint constraint_record
    JOIN pg_catalog.pg_class relation ON relation.oid = constraint_record.conrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN LATERAL (
      SELECT count(*) total, count(*) FILTER (WHERE trigger.tgtype = 5) insert_row,
        count(*) FILTER (WHERE trigger.tgtype = 9) delete_row,
        count(*) FILTER (WHERE trigger.tgtype = 17) update_row
      FROM pg_catalog.pg_trigger trigger WHERE trigger.tgconstraint = constraint_record.oid
    ) trigger_shape ON TRUE
    WHERE namespace.nspname = 'gmail_draft_broker' AND constraint_record.contype = 'f'
      AND (trigger_shape.total <> 4 OR trigger_shape.insert_row <> 1
        OR trigger_shape.delete_row <> 1 OR trigger_shape.update_row <> 2)
  ) THEN
    RAISE EXCEPTION 'Gmail draft internal trigger postflight failed';
  END IF;
  IF NOT pg_catalog.has_schema_privilege('qm_gmail_draft_admission', 'gmail_draft_broker', 'USAGE')
    OR pg_catalog.has_schema_privilege('qm_gmail_draft_admission', 'gmail_draft_broker', 'CREATE')
    OR NOT pg_catalog.has_schema_privilege('qm_gmail_draft_broker', 'gmail_draft_broker', 'USAGE')
    OR pg_catalog.has_schema_privilege('qm_gmail_draft_broker', 'gmail_draft_broker', 'CREATE')
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_namespace namespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
      ) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
      WHERE namespace.nspname = 'gmail_draft_broker'
        AND (COALESCE(grantee.rolname, 'public') NOT IN
            ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
          OR (grantee.rolname IN ('qm_gmail_draft_admission','qm_gmail_draft_broker')
            AND (acl.privilege_type <> 'USAGE' OR acl.is_grantable)))
    )
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_class relation
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(relation.relacl, pg_catalog.acldefault(
          CASE WHEN relation.relkind = 'S' THEN 's'::"char" ELSE 'r'::"char" END, relation.relowner
        ))
      ) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
      WHERE namespace.nspname = 'gmail_draft_broker' AND relation.relkind IN ('r','p','v','m','f','S')
        AND COALESCE(grantee.rolname, 'public') <> 'qm_gmail_draft_owner'
    )
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc routine
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(routine.proacl, pg_catalog.acldefault('f', routine.proowner))
      ) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
      WHERE namespace.nspname = 'gmail_draft_broker'
        AND (COALESCE(grantee.rolname, 'public') NOT IN
            ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
          OR (grantee.rolname IN ('qm_gmail_draft_admission','qm_gmail_draft_broker') AND acl.is_grantable))
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_default_acl defaults
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
      JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
      WHERE namespace.nspname = 'gmail_draft_broker' AND owner.rolname = 'qm_gmail_draft_owner'
        AND defaults.defaclobjtype = 'f'
    )
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_default_acl defaults
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
      JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
      WHERE namespace.nspname = 'gmail_draft_broker' AND owner.rolname = 'qm_gmail_draft_owner'
        AND defaults.defaclobjtype = 'T'
    )
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_default_acl defaults
      JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
      LEFT JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
      WHERE owner.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
        AND (defaults.defaclnamespace = 0 OR owner.rolname <> 'qm_gmail_draft_owner'
          OR namespace.nspname IS DISTINCT FROM 'gmail_draft_broker'
          OR defaults.defaclobjtype NOT IN ('f','T')
          OR COALESCE(grantee.rolname, 'public') <> 'qm_gmail_draft_owner')
    )
    OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc routine
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
      WHERE namespace.nspname = 'gmail_draft_broker' AND (
        pg_catalog.has_function_privilege('qm_gmail_draft_admission', routine.oid, 'EXECUTE')
          IS DISTINCT FROM (routine.proname IN ('admit_owner_slack_binding','admit_thread_source','admit_intent'))
        OR pg_catalog.has_function_privilege('qm_gmail_draft_broker', routine.oid, 'EXECUTE')
          IS DISTINCT FROM (routine.proname IN ('claim_effect','claim_reconciliation','arm_effect','record_created',
            'record_unknown','retain_unknown','reject_before_effect','reject_definitive_no_write'))
      )
    )
  THEN
    RAISE EXCEPTION 'Gmail draft grant postflight failed';
  END IF;
END
$catalog_postflight$;

SELECT pg_temp.assert_gmail_draft_definitions(FALSE);
DROP FUNCTION pg_temp.assert_gmail_draft_definitions(BOOLEAN);

DO $function_authority$
BEGIN
  IF (SELECT count(*) FROM pg_catalog.pg_proc routine
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
    WHERE namespace.nspname = 'gmail_draft_broker') <> 11
    OR pg_catalog.to_regprocedure('gmail_draft_broker.admit_owner_slack_binding(text,text,text,text,text,text,text,text,bigint,bigint,text,text)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.admit_thread_source(text,text,text,text,text,text,text,integer,text,text,text,text,text[],text,bigint,bigint,text,text)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.admit_intent(text,integer,integer,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,text,integer,text,text,text,text,text,text,text,text,text,text,text,text,text,text,text[],text,jsonb)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.claim_effect(text,integer)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.claim_reconciliation(text,integer)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.arm_effect(text,integer,text,text,text,text,text,bigint)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.record_created(text,integer,text,text,text,text,text,text,text,text,text,bigint,boolean,text)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.record_unknown(text,integer,text,text,text,text,text,bigint)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.retain_unknown(text,integer,text,text,text,text,text,bigint,text)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.reject_before_effect(text,integer,text,text)') IS NULL
    OR pg_catalog.to_regprocedure('gmail_draft_broker.reject_definitive_no_write(text,integer,text,text)') IS NULL
    OR EXISTS (
      SELECT 1
      FROM pg_catalog.pg_proc routine
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
      JOIN pg_catalog.pg_roles owner ON owner.oid = routine.proowner
      JOIN pg_catalog.pg_language language_record ON language_record.oid = routine.prolang
      WHERE namespace.nspname = 'gmail_draft_broker' AND (
        owner.rolname <> 'qm_gmail_draft_owner' OR routine.prokind <> 'f' OR NOT routine.prosecdef
        OR routine.proleakproof OR routine.proisstrict OR routine.proretset OR routine.provolatile <> 'v'
        OR routine.proparallel <> 'u' OR routine.pronargdefaults <> 0 OR routine.provariadic <> 0
        OR routine.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, gmail_draft_broker']::TEXT[]
        OR language_record.lanname IS DISTINCT FROM CASE
          WHEN routine.proname IN ('admit_owner_slack_binding','admit_thread_source','admit_intent',
            'claim_effect','claim_reconciliation') THEN 'plpgsql' ELSE 'sql' END
        OR pg_catalog.format_type(routine.prorettype, NULL) IS DISTINCT FROM CASE
          WHEN routine.proname IN ('admit_owner_slack_binding','admit_thread_source','admit_intent') THEN 'text'
          WHEN routine.proname IN ('claim_effect','claim_reconciliation') THEN 'jsonb' ELSE 'boolean' END
      )
    )
  THEN
    RAISE EXCEPTION 'Gmail draft routines do not match the authoritative definitions';
  END IF;
END
$function_authority$;

COMMIT;
