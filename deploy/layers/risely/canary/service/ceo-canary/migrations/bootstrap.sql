\set ON_ERROR_STOP on
SET search_path = pg_catalog;
\if :{?canary_bootstrap_admin_role}
\else
\echo 'canary_bootstrap_admin_role is required'
SELECT 'canary_bootstrap_admin_role_required'::pg_catalog.int4;
\endif
SELECT :'canary_bootstrap_admin_role' = 'qm'
  AND session_user = 'qm' AS canary_bootstrap_admin_matches \gset
\if :canary_bootstrap_admin_matches
\else
\echo 'canary_bootstrap_admin_role does not match session_user'
SELECT 'canary_bootstrap_admin_role_mismatch'::pg_catalog.int4;
\endif
BEGIN;
SET LOCAL createrole_self_grant = '';
DO $boundary$
BEGIN
  IF current_user <> session_user
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname = session_user
        AND rolcanlogin
        AND rolcreaterole
        AND NOT rolsuper
    )
    OR NOT pg_catalog.has_database_privilege(session_user, pg_catalog.current_database(), 'CREATE') THEN
    RAISE EXCEPTION 'canary_bootstrap_requires_direct_nonsuperuser_createrole_session';
  END IF;
  IF pg_catalog.current_database() <> 'qm' THEN
    RAISE EXCEPTION 'canary_bootstrap_requires_qm_database';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_database database_record
    WHERE database_record.datname = pg_catalog.current_database()
      AND database_record.datdba = session_user::pg_catalog.regrole
  ) THEN
    RAISE EXCEPTION 'canary_bootstrap_requires_exact_database_owner';
  END IF;
  IF (SELECT count(*)
      FROM pg_catalog.pg_database database_record
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(database_record.datacl, pg_catalog.acldefault('d', database_record.datdba))
      ) acl
      WHERE database_record.datname = pg_catalog.current_database()
        AND acl.grantee = 0) <> 2
    OR EXISTS (
      SELECT 1
      FROM pg_catalog.pg_database database_record
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(database_record.datacl, pg_catalog.acldefault('d', database_record.datdba))
      ) acl
      WHERE database_record.datname = pg_catalog.current_database()
        AND acl.grantee = 0
        AND (acl.grantor <> database_record.datdba
          OR acl.privilege_type NOT IN ('CONNECT', 'TEMPORARY')
          OR acl.is_grantable)
    ) THEN
    RAISE EXCEPTION 'canary_bootstrap_incompatible_public_database_acl';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_event_trigger event_trigger
    WHERE event_trigger.evtenabled <> 'D'
  ) THEN
    RAISE EXCEPTION 'canary_bootstrap_enabled_event_trigger';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_foreign_data_wrapper wrapper
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(wrapper.fdwacl, pg_catalog.acldefault('F', wrapper.fdwowner))
    ) acl
    WHERE acl.grantee = 0
      AND acl.privilege_type = 'USAGE'
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_foreign_data_wrapper wrapper
    JOIN pg_catalog.pg_roles owner ON owner.oid = wrapper.fdwowner
    WHERE owner.rolname IN (
      'risely_agent_runtime_owner',
      'risely_agent_runtime_migrator',
      'risely_agent_runtime_runtime',
      'risely_agent_runtime_evaluation_writer'
    )
  ) THEN
    RAISE EXCEPTION 'canary_bootstrap_foreign_data_wrapper_authority';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname IN (
      'risely_agent_runtime_owner',
      'risely_agent_runtime_migrator',
      'risely_agent_runtime_runtime',
      'risely_agent_runtime_evaluation_writer'
    )
  ) THEN
    RAISE EXCEPTION 'canary_bootstrap_fixed_role_preexists';
  END IF;
  IF pg_catalog.to_regnamespace('risely_agent_runtime') IS NOT NULL THEN
    RAISE EXCEPTION 'canary_bootstrap_schema_preexists';
  END IF;
  IF pg_catalog.to_regnamespace('risely_ceo_canary') IS NOT NULL THEN
    RAISE EXCEPTION 'legacy_ceo_canary_schema_requires_manual_review';
  END IF;
END;
$boundary$;

CREATE ROLE risely_agent_runtime_owner NOLOGIN PASSWORD NULL NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE risely_agent_runtime_migrator NOLOGIN PASSWORD NULL NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE risely_agent_runtime_runtime NOLOGIN PASSWORD NULL NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE risely_agent_runtime_evaluation_writer NOLOGIN PASSWORD NULL NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT risely_agent_runtime_owner TO risely_agent_runtime_migrator WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;
GRANT risely_agent_runtime_owner TO SESSION_USER WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;
GRANT CONNECT ON DATABASE qm TO risely_agent_runtime_migrator;
GRANT CONNECT ON DATABASE qm TO risely_agent_runtime_runtime;
GRANT CONNECT ON DATABASE qm TO risely_agent_runtime_evaluation_writer;
ALTER ROLE risely_agent_runtime_owner IN DATABASE qm SET search_path = pg_catalog;
ALTER ROLE risely_agent_runtime_migrator IN DATABASE qm SET search_path = pg_catalog;
ALTER ROLE risely_agent_runtime_runtime IN DATABASE qm SET search_path = pg_catalog;
ALTER ROLE risely_agent_runtime_evaluation_writer IN DATABASE qm SET search_path = pg_catalog;
CREATE SCHEMA risely_agent_runtime AUTHORIZATION risely_agent_runtime_owner;
SET ROLE risely_agent_runtime_owner;
REVOKE ALL ON SCHEMA risely_agent_runtime FROM PUBLIC;
REVOKE ALL ON SCHEMA risely_agent_runtime FROM risely_agent_runtime_runtime;
REVOKE ALL ON SCHEMA risely_agent_runtime FROM risely_agent_runtime_migrator;
REVOKE ALL ON SCHEMA risely_agent_runtime FROM risely_agent_runtime_evaluation_writer;
RESET ROLE;

DO $boundary$
DECLARE
  role_name text;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'risely_agent_runtime_owner'
      AND (rolcanlogin OR rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname IN ('risely_agent_runtime_migrator', 'risely_agent_runtime_runtime', 'risely_agent_runtime_evaluation_writer')
      AND (rolcanlogin OR rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_database database_record
    JOIN pg_catalog.pg_roles owner ON owner.oid = database_record.datdba
    WHERE database_record.datname = pg_catalog.current_database()
      AND owner.rolname IN ('risely_agent_runtime_owner', 'risely_agent_runtime_migrator', 'risely_agent_runtime_runtime', 'risely_agent_runtime_evaluation_writer')
  ) THEN
    RAISE EXCEPTION 'canary_bootstrap_role_attribute_mismatch';
  END IF;
  IF (SELECT count(*) FROM pg_catalog.pg_auth_members membership
      JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
      JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
      JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
      WHERE granted_role.rolname IN ('risely_agent_runtime_owner', 'risely_agent_runtime_migrator', 'risely_agent_runtime_runtime', 'risely_agent_runtime_evaluation_writer')
         OR member_role.rolname IN ('risely_agent_runtime_owner', 'risely_agent_runtime_migrator', 'risely_agent_runtime_runtime', 'risely_agent_runtime_evaluation_writer')) <> 6
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_auth_members membership
      JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
      JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
      JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
      WHERE granted_role.rolname = 'risely_agent_runtime_owner'
        AND member_role.rolname = 'risely_agent_runtime_migrator'
        AND grantor_role.rolname = session_user
        AND NOT membership.inherit_option
        AND membership.set_option
        AND NOT membership.admin_option
    )
    OR (SELECT count(*)
        FROM pg_catalog.pg_auth_members membership
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
        JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
        WHERE granted_role.rolname IN ('risely_agent_runtime_owner', 'risely_agent_runtime_migrator', 'risely_agent_runtime_runtime', 'risely_agent_runtime_evaluation_writer')
          AND member_role.rolname = session_user
          AND membership.grantor = 10
          AND grantor_role.rolsuper
          AND NOT membership.inherit_option
          AND NOT membership.set_option
          AND membership.admin_option) <> 4
    OR (SELECT count(DISTINCT membership.grantor)
        FROM pg_catalog.pg_auth_members membership
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
        JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
        WHERE granted_role.rolname IN ('risely_agent_runtime_owner', 'risely_agent_runtime_migrator', 'risely_agent_runtime_runtime', 'risely_agent_runtime_evaluation_writer')
          AND member_role.rolname = session_user
          AND membership.grantor = 10
          AND grantor_role.rolsuper
          AND NOT membership.inherit_option
          AND NOT membership.set_option
          AND membership.admin_option) <> 1
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_auth_members membership
      JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
      JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
      JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
      WHERE granted_role.rolname = 'risely_agent_runtime_owner'
        AND member_role.rolname = session_user
        AND grantor_role.rolname = session_user
        AND NOT membership.inherit_option
        AND membership.set_option
        AND NOT membership.admin_option
    ) THEN
    RAISE EXCEPTION 'canary_bootstrap_transient_role_topology_mismatch';
  END IF;
  IF (SELECT owner.rolname
      FROM pg_catalog.pg_namespace namespace
      JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
      WHERE namespace.nspname = 'risely_agent_runtime') <> 'risely_agent_runtime_owner' THEN
    RAISE EXCEPTION 'canary_bootstrap_schema_owner_mismatch';
  END IF;
  FOREACH role_name IN ARRAY ARRAY[
    'risely_agent_runtime_owner',
    'risely_agent_runtime_migrator',
    'risely_agent_runtime_runtime',
    'risely_agent_runtime_evaluation_writer'
  ] LOOP
    IF pg_catalog.has_database_privilege(role_name, pg_catalog.current_database(), 'CREATE')
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_database database_record
        CROSS JOIN LATERAL pg_catalog.aclexplode(
          COALESCE(database_record.datacl, pg_catalog.acldefault('d', database_record.datdba))
        ) acl
        JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
        WHERE database_record.datname = pg_catalog.current_database()
          AND grantee.rolname = role_name
          AND acl.privilege_type IN ('CREATE', 'TEMPORARY')
      )
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace namespace
        WHERE namespace.nspname <> 'risely_agent_runtime'
          AND namespace.nspname NOT LIKE 'pg\_%' ESCAPE '\'
          AND namespace.nspname <> 'information_schema'
          AND (namespace.nspowner = role_name::pg_catalog.regrole
            OR pg_catalog.has_schema_privilege(role_name, namespace.oid, 'CREATE'))
      )
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_foreign_data_wrapper wrapper
        WHERE wrapper.fdwowner = role_name::pg_catalog.regrole
          OR pg_catalog.has_foreign_data_wrapper_privilege(role_name, wrapper.oid, 'USAGE')
      )
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_class relation
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname <> 'risely_agent_runtime'
          AND namespace.nspname NOT LIKE 'pg\_%' ESCAPE '\'
          AND namespace.nspname <> 'information_schema'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND (pg_catalog.has_table_privilege(role_name, relation.oid, 'SELECT')
            OR pg_catalog.has_table_privilege(role_name, relation.oid, 'INSERT')
            OR pg_catalog.has_table_privilege(role_name, relation.oid, 'UPDATE')
            OR pg_catalog.has_table_privilege(role_name, relation.oid, 'DELETE')
            OR pg_catalog.has_table_privilege(role_name, relation.oid, 'TRUNCATE')
            OR pg_catalog.has_table_privilege(role_name, relation.oid, 'REFERENCES')
            OR pg_catalog.has_table_privilege(role_name, relation.oid, 'TRIGGER'))
      )
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_class relation
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname <> 'risely_agent_runtime'
          AND namespace.nspname NOT LIKE 'pg\_%' ESCAPE '\'
          AND namespace.nspname <> 'information_schema'
          AND relation.relkind = 'S'
          AND (pg_catalog.has_sequence_privilege(role_name, relation.oid, 'SELECT')
            OR pg_catalog.has_sequence_privilege(role_name, relation.oid, 'UPDATE')
            OR pg_catalog.has_sequence_privilege(role_name, relation.oid, 'USAGE'))
      )
      OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc procedure
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname <> 'risely_agent_runtime'
          AND namespace.nspname NOT LIKE 'pg\_%' ESCAPE '\'
          AND namespace.nspname <> 'information_schema'
          AND procedure.prosecdef
          AND pg_catalog.has_function_privilege(role_name, procedure.oid, 'EXECUTE')
      ) THEN
      RAISE EXCEPTION 'shared_qm_privilege_boundary_incompatible_for_%', role_name;
    END IF;
  END LOOP;
END;
$boundary$;

REVOKE risely_agent_runtime_owner FROM SESSION_USER GRANTED BY SESSION_USER;

DO $boundary$
BEGIN
  IF (SELECT count(*) FROM pg_catalog.pg_auth_members membership
      JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
      JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
      JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
      WHERE granted_role.rolname IN ('risely_agent_runtime_owner', 'risely_agent_runtime_migrator', 'risely_agent_runtime_runtime', 'risely_agent_runtime_evaluation_writer')
         OR member_role.rolname IN ('risely_agent_runtime_owner', 'risely_agent_runtime_migrator', 'risely_agent_runtime_runtime', 'risely_agent_runtime_evaluation_writer')) <> 5
    OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_auth_members membership
      JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
      JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
      JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
      WHERE granted_role.rolname = 'risely_agent_runtime_owner'
        AND member_role.rolname = 'risely_agent_runtime_migrator'
        AND grantor_role.rolname = session_user
        AND NOT membership.inherit_option
        AND membership.set_option
        AND NOT membership.admin_option
    )
    OR (SELECT count(*)
        FROM pg_catalog.pg_auth_members membership
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
        JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
        WHERE granted_role.rolname IN ('risely_agent_runtime_owner', 'risely_agent_runtime_migrator', 'risely_agent_runtime_runtime', 'risely_agent_runtime_evaluation_writer')
          AND member_role.rolname = session_user
          AND membership.grantor = 10
          AND grantor_role.rolsuper
          AND NOT membership.inherit_option
          AND NOT membership.set_option
          AND membership.admin_option) <> 4
    OR (SELECT count(DISTINCT membership.grantor)
        FROM pg_catalog.pg_auth_members membership
        JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
        JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
        WHERE granted_role.rolname IN ('risely_agent_runtime_owner', 'risely_agent_runtime_migrator', 'risely_agent_runtime_runtime', 'risely_agent_runtime_evaluation_writer')
          AND member_role.rolname = session_user
          AND membership.grantor = 10
          AND grantor_role.rolsuper
          AND NOT membership.inherit_option
          AND NOT membership.set_option
          AND membership.admin_option) <> 1 THEN
    RAISE EXCEPTION 'canary_bootstrap_role_topology_mismatch';
  END IF;
END;
$boundary$;
COMMIT;
