BEGIN;

DO $runtime_role_bindings$
DECLARE
  v_owner_login TEXT := NULLIF(pg_catalog.current_setting('gmail_draft_broker.owner_login_role', TRUE), '');
  v_admission_login TEXT := NULLIF(pg_catalog.current_setting('gmail_draft_broker.admission_login_role', TRUE), '');
  v_broker_login TEXT := NULLIF(pg_catalog.current_setting('gmail_draft_broker.broker_login_role', TRUE), '');
  v_membership_columns TEXT[];
  v_login RECORD;
  v_membership RECORD;
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
    RAISE EXCEPTION 'Gmail draft runtime role bindings require PostgreSQL 16 membership semantics';
  END IF;
  IF NOT COALESCE((SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user), FALSE) THEN
    RAISE EXCEPTION 'Gmail draft runtime role bindings require a superuser';
  END IF;
  IF v_owner_login IS NULL OR v_admission_login IS NULL OR v_broker_login IS NULL
    OR v_owner_login = v_admission_login OR v_owner_login = v_broker_login OR v_admission_login = v_broker_login
  THEN
    RAISE EXCEPTION 'set distinct gmail_draft_broker.owner_login_role, admission_login_role, and broker_login_role settings';
  END IF;
  IF (SELECT count(*) FROM pg_catalog.pg_roles
    WHERE rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')) <> 3
  THEN
    RAISE EXCEPTION 'Gmail draft protected roles must already exist';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles role
    WHERE role.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
      AND (role.rolcanlogin OR role.rolinherit OR role.rolsuper OR role.rolcreaterole OR role.rolcreatedb
        OR role.rolreplication OR role.rolbypassrls)
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members membership
    JOIN pg_catalog.pg_roles member ON member.oid = membership.member
    WHERE member.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
  ) THEN
    RAISE EXCEPTION 'Gmail draft protected roles violate their isolated NOLOGIN posture';
  END IF;
  FOR v_login IN
    SELECT role.oid, role.rolname, role.rolcanlogin, role.rolinherit, role.rolsuper, role.rolcreaterole,
      role.rolcreatedb, role.rolreplication, role.rolbypassrls,
      CASE role.rolname
        WHEN v_owner_login THEN 'qm_gmail_draft_owner'
        WHEN v_admission_login THEN 'qm_gmail_draft_admission'
        ELSE 'qm_gmail_draft_broker'
      END target_role,
      role.rolname <> v_owner_login expected_inherit
    FROM pg_catalog.pg_roles role
    WHERE role.rolname IN (v_owner_login, v_admission_login, v_broker_login)
  LOOP
    IF NOT v_login.rolcanlogin OR v_login.rolinherit IS DISTINCT FROM v_login.expected_inherit
      OR v_login.rolsuper OR v_login.rolcreaterole
      OR v_login.rolcreatedb OR v_login.rolreplication OR v_login.rolbypassrls
    THEN
      RAISE EXCEPTION 'Gmail draft runtime login % violates least privilege', v_login.rolname;
    END IF;
    IF EXISTS (
      SELECT 1 FROM pg_catalog.pg_auth_members membership
      JOIN pg_catalog.pg_roles granted ON granted.oid = membership.roleid
      WHERE membership.member = v_login.oid AND granted.rolname <> v_login.target_role
    ) OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_auth_members membership WHERE membership.roleid = v_login.oid
    ) THEN
      RAISE EXCEPTION 'Gmail draft runtime login % has unrelated role membership', v_login.rolname;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_database database_record WHERE database_record.datdba = v_login.oid)
      OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace namespace WHERE namespace.nspowner = v_login.oid)
      OR EXISTS (SELECT 1 FROM pg_catalog.pg_class relation WHERE relation.relowner = v_login.oid)
      OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc routine WHERE routine.proowner = v_login.oid)
      OR EXISTS (SELECT 1 FROM pg_catalog.pg_type type_record WHERE type_record.typowner = v_login.oid)
      OR EXISTS (SELECT 1 FROM pg_catalog.pg_default_acl defaults WHERE defaults.defaclrole = v_login.oid)
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_default_acl defaults
        CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
        WHERE acl.grantee = v_login.oid
      )
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_database database_record
        CROSS JOIN LATERAL pg_catalog.aclexplode(
          COALESCE(database_record.datacl, pg_catalog.acldefault('d', database_record.datdba))
        ) acl WHERE acl.grantee = v_login.oid
      )
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace namespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
          COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
        ) acl WHERE acl.grantee = v_login.oid
      )
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_class relation
        CROSS JOIN LATERAL pg_catalog.aclexplode(
          COALESCE(relation.relacl, pg_catalog.acldefault(
            CASE WHEN relation.relkind = 'S' THEN 's'::"char" ELSE 'r'::"char" END,
            relation.relowner
          ))
        ) acl WHERE acl.grantee = v_login.oid
      )
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute attribute
        CROSS JOIN LATERAL pg_catalog.aclexplode(
          COALESCE(attribute.attacl, '{}'::pg_catalog.aclitem[])
        ) acl WHERE attribute.attnum > 0 AND NOT attribute.attisdropped AND acl.grantee = v_login.oid
      )
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc routine
        CROSS JOIN LATERAL pg_catalog.aclexplode(
          COALESCE(routine.proacl, pg_catalog.acldefault('f', routine.proowner))
        ) acl WHERE acl.grantee = v_login.oid
      )
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_type type_record
        CROSS JOIN LATERAL pg_catalog.aclexplode(
          COALESCE(type_record.typacl, '{}'::pg_catalog.aclitem[])
        ) acl WHERE acl.grantee = v_login.oid
      )
    THEN
      RAISE EXCEPTION 'Gmail draft runtime login % owns objects or has direct privileges', v_login.rolname;
    END IF;
  END LOOP;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_owner_login)
    OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_admission_login)
    OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_broker_login)
  THEN
    RAISE EXCEPTION 'all three Gmail draft login roles must already exist';
  END IF;
  FOR v_membership IN
    SELECT granted.rolname granted_role, member.rolname member_role
    FROM pg_catalog.pg_auth_members membership
    JOIN pg_catalog.pg_roles granted ON granted.oid = membership.roleid
    JOIN pg_catalog.pg_roles member ON member.oid = membership.member
    WHERE granted.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
  LOOP
    EXECUTE pg_catalog.format('REVOKE %I FROM %I CASCADE', v_membership.granted_role, v_membership.member_role);
  END LOOP;
  EXECUTE pg_catalog.format(
    'GRANT qm_gmail_draft_owner TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE',
    v_owner_login
  );
  EXECUTE pg_catalog.format(
    'GRANT qm_gmail_draft_admission TO %I WITH ADMIN FALSE, INHERIT TRUE, SET FALSE',
    v_admission_login
  );
  EXECUTE pg_catalog.format(
    'GRANT qm_gmail_draft_broker TO %I WITH ADMIN FALSE, INHERIT TRUE, SET FALSE',
    v_broker_login
  );
  IF EXISTS (
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
        OR membership.set_option IS DISTINCT FROM expected.set_option)
  ) OR (
    SELECT count(*)
    FROM pg_catalog.pg_auth_members membership
    JOIN pg_catalog.pg_roles granted ON granted.oid = membership.roleid
    WHERE granted.rolname IN ('qm_gmail_draft_owner','qm_gmail_draft_admission','qm_gmail_draft_broker')
  ) <> 3 OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles role
    WHERE role.rolname IN (v_owner_login, v_admission_login, v_broker_login)
      AND ((SELECT count(*) FROM pg_catalog.pg_auth_members membership WHERE membership.member = role.oid) <> 1
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members membership WHERE membership.roleid = role.oid))
  )
  THEN
    RAISE EXCEPTION 'Gmail draft exact role bindings could not be established safely';
  END IF;
END
$runtime_role_bindings$;

DO $binding_catalog_postflight$
DECLARE
  v_relations TEXT[];
  v_indexes TEXT[];
  v_routines TEXT[];
  v_types TEXT[];
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_namespace namespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
    WHERE namespace.nspname = 'gmail_draft_broker' AND owner.rolname = 'qm_gmail_draft_owner'
  ) THEN
    RAISE EXCEPTION 'Gmail draft authoritative schema is missing or has the wrong owner';
  END IF;
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
    RAISE EXCEPTION 'Gmail draft binding table postflight failed';
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
    RAISE EXCEPTION 'Gmail draft binding index postflight failed';
  END IF;
  SELECT pg_catalog.array_agg(routine.proname ORDER BY routine.proname) INTO v_routines
  FROM pg_catalog.pg_proc routine
  JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
  WHERE namespace.nspname = 'gmail_draft_broker';
  IF v_routines <> ARRAY['admit_intent','admit_owner_slack_binding','admit_thread_source','arm_effect',
    'claim_effect','claim_reconciliation','record_created','record_unknown','reject_before_effect',
    'reject_definitive_no_write','retain_unknown']::TEXT[]
  THEN
    RAISE EXCEPTION 'Gmail draft binding routine postflight failed';
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
    ) OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc routine
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = routine.pronamespace
      JOIN pg_catalog.pg_roles owner ON owner.oid = routine.proowner
      WHERE namespace.nspname = 'gmail_draft_broker' AND owner.rolname <> 'qm_gmail_draft_owner'
    )
  THEN
    RAISE EXCEPTION 'Gmail draft binding type postflight failed';
  END IF;
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
    RAISE EXCEPTION 'Gmail draft protected roles own objects outside the authoritative catalog';
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
    RAISE EXCEPTION 'Gmail draft protected roles have direct privileges outside the authoritative catalog';
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
    RAISE EXCEPTION 'Gmail draft binding column or type ACL postflight failed';
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
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_default_acl defaults
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
    WHERE namespace.nspname = 'gmail_draft_broker' AND owner.rolname = 'qm_gmail_draft_owner'
      AND defaults.defaclobjtype = 'f'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_default_acl defaults
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
    WHERE namespace.nspname = 'gmail_draft_broker' AND owner.rolname = 'qm_gmail_draft_owner'
      AND defaults.defaclobjtype = 'T'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_default_acl defaults
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = defaults.defaclrole
    CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
    LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
    WHERE namespace.nspname = 'gmail_draft_broker' AND owner.rolname = 'qm_gmail_draft_owner'
      AND (defaults.defaclobjtype NOT IN ('f','T')
        OR COALESCE(grantee.rolname, 'public') <> 'qm_gmail_draft_owner')
  ) THEN
    RAISE EXCEPTION 'Gmail draft protected roles have unrelated or owner-wide default ACLs';
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
    RAISE EXCEPTION 'Gmail draft binding grant postflight failed';
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
    RAISE EXCEPTION 'Gmail draft binding internal trigger postflight failed';
  END IF;
END
$binding_catalog_postflight$;

COMMIT;
