import {
  CANARY_BOOTSTRAP_ADMIN_ROLE,
  CANARY_DATABASE_NAME,
  CANARY_MIGRATION_DATABASE_USER,
  CANARY_OWNER_DATABASE_USER,
  CANARY_RUNTIME_DATABASE_USER,
  CANARY_EVALUATION_WRITER_DATABASE_USER,
  CANARY_SCHEMA_NAME,
  EXPECTED_CATALOG_AUTHORITY_SHA256,
  EXPECTED_CATALOG_AUTHORITY_V8,
  EXPECTED_CANARY_DATABASE_ACL,
  EXPECTED_DATABASE_ACL,
  SCHEMA_VERSION,
  catalogAuthoritySha256,
  catalogFingerprintSql,
  catalogStructure,
  migrationChecksum,
} from "./schema.mjs";

export { catalogStructure } from "./schema.mjs";

export function sameStructure(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

export async function loadExactCanaryDatabaseAcl(client) {
  const result = await client.query(
    `/* exact canary database ACL */ SELECT
       CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee,
       pg_catalog.pg_get_userbyid(acl.grantor) AS grantor,
       acl.privilege_type,
       acl.is_grantable
     FROM pg_catalog.pg_database database_record
     CROSS JOIN LATERAL pg_catalog.aclexplode(
       COALESCE(database_record.datacl, pg_catalog.acldefault('d', database_record.datdba))
     ) acl
     WHERE database_record.datname = pg_catalog.current_database()
       AND (
         acl.grantee = 0
         OR pg_catalog.pg_get_userbyid(acl.grantee) = ANY ($1::text[])
       )
     ORDER BY grantee, grantor, acl.privilege_type`,
    [
      [
        CANARY_OWNER_DATABASE_USER,
        CANARY_MIGRATION_DATABASE_USER,
        CANARY_RUNTIME_DATABASE_USER,
        CANARY_EVALUATION_WRITER_DATABASE_USER,
      ],
    ],
  );
  return result.rows.map((entry) => [entry.grantee, entry.grantor, entry.privilege_type, entry.is_grantable]);
}

export async function assertCanaryNamespaceBoundary(client) {
  const result = await client.query(
    `/* exact canary namespace boundary */ SELECT
       (SELECT count(*) FROM pg_catalog.pg_event_trigger event_trigger
        WHERE event_trigger.evtenabled <> 'D') AS enabled_event_triggers,
       (SELECT count(*) FROM pg_catalog.pg_rewrite rewrite
        JOIN pg_catalog.pg_class relation ON relation.oid = rewrite.ev_class
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = $1) AS rewrites,
       (SELECT count(*) FROM pg_catalog.pg_policy policy
        JOIN pg_catalog.pg_class relation ON relation.oid = policy.polrelid
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = $1) AS policies,
       (SELECT count(*) FROM pg_catalog.pg_inherits inheritance
        JOIN pg_catalog.pg_class child ON child.oid = inheritance.inhrelid
        JOIN pg_catalog.pg_namespace child_namespace ON child_namespace.oid = child.relnamespace
        JOIN pg_catalog.pg_class parent ON parent.oid = inheritance.inhparent
        JOIN pg_catalog.pg_namespace parent_namespace ON parent_namespace.oid = parent.relnamespace
        WHERE child_namespace.nspname = $1 OR parent_namespace.nspname = $1) AS inheritance,
       (SELECT count(*) FROM pg_catalog.pg_extension extension
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = extension.extnamespace
        WHERE namespace.nspname = $1) AS extensions,
       (SELECT count(*)
        FROM pg_catalog.pg_depend dependency
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = dependency.objid
        WHERE dependency.classid = 'pg_catalog.pg_namespace'::pg_catalog.regclass
          AND dependency.objsubid = 0
          AND dependency.deptype = 'e'
          AND namespace.nspname = $1) AS extension_owned_schema,
       (SELECT count(*)
        FROM pg_catalog.pg_depend dependency
        CROSS JOIN LATERAL pg_catalog.pg_identify_object(
          dependency.classid, dependency.objid, dependency.objsubid
        ) dependent_object
        WHERE dependency.deptype = 'e'
          AND dependent_object.schema = $1) AS extension_owned_objects,
       (SELECT count(*) FROM pg_catalog.pg_publication publication
        WHERE publication.puballtables) AS all_tables_publications,
       (SELECT count(*) FROM pg_catalog.pg_publication_rel publication_relation
        JOIN pg_catalog.pg_class relation ON relation.oid = publication_relation.prrelid
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = $1) AS publication_relations,
       (SELECT count(*) FROM pg_catalog.pg_publication_namespace publication_namespace
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = publication_namespace.pnnspid
        WHERE namespace.nspname = $1) AS publication_namespaces,
       (SELECT count(*) FROM pg_catalog.pg_subscription_rel subscription_relation
        JOIN pg_catalog.pg_class relation ON relation.oid = subscription_relation.srrelid
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = $1) AS subscription_relations,
       (SELECT count(*) FROM pg_catalog.pg_cast cast_record
        JOIN pg_catalog.pg_type source_type ON source_type.oid = cast_record.castsource
        JOIN pg_catalog.pg_namespace source_namespace ON source_namespace.oid = source_type.typnamespace
        JOIN pg_catalog.pg_type target_type ON target_type.oid = cast_record.casttarget
        JOIN pg_catalog.pg_namespace target_namespace ON target_namespace.oid = target_type.typnamespace
        WHERE source_namespace.nspname = $1 OR target_namespace.nspname = $1) AS schema_less_casts,
       (SELECT count(*) FROM pg_catalog.pg_transform transform_record
        JOIN pg_catalog.pg_type type_record ON type_record.oid = transform_record.trftype
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
        WHERE namespace.nspname = $1) AS schema_less_transforms,
       (SELECT count(*) FROM pg_catalog.pg_foreign_server foreign_server
        CROSS JOIN unnest(ARRAY[$2, $3, $4, $5]::text[]) fixed_role(role_name)
        WHERE pg_catalog.has_server_privilege(fixed_role.role_name, foreign_server.oid, 'USAGE')) AS foreign_server_usage,
       (SELECT count(*) FROM pg_catalog.pg_foreign_data_wrapper wrapper
        CROSS JOIN unnest(ARRAY[$2, $3, $4, $5]::text[]) fixed_role(role_name)
        WHERE wrapper.fdwowner = fixed_role.role_name::pg_catalog.regrole
          OR pg_catalog.has_foreign_data_wrapper_privilege(fixed_role.role_name, wrapper.oid, 'USAGE')) AS foreign_data_wrapper_authority,
       (SELECT count(*) FROM pg_catalog.pg_user_mappings user_mapping
        WHERE user_mapping.usename = 'public'
          OR user_mapping.usename = ANY (ARRAY[$2, $3, $4, $5]::text[])) AS foreign_user_mappings,
       (SELECT count(*) FROM pg_catalog.pg_default_acl default_acl
        JOIN pg_catalog.pg_roles owner ON owner.oid = default_acl.defaclrole
        LEFT JOIN pg_catalog.pg_namespace namespace ON namespace.oid = default_acl.defaclnamespace
        WHERE owner.rolname IN ($2, $3, $4, $5)
          AND (default_acl.defaclnamespace = 0 OR namespace.nspname = $1)) AS default_acls,
       (SELECT count(*)
        FROM pg_catalog.pg_depend dependency
        CROSS JOIN LATERAL pg_catalog.pg_identify_object(
          dependency.classid, dependency.objid, dependency.objsubid
        ) dependent_object
        CROSS JOIN LATERAL pg_catalog.pg_identify_object(
          dependency.refclassid, dependency.refobjid, dependency.refobjsubid
        ) referenced_object
        WHERE dependency.deptype <> 'e'
          AND (
            (dependent_object.schema = $1
              AND referenced_object.schema IS NOT NULL
              AND referenced_object.schema <> $1
              AND referenced_object.schema NOT LIKE 'pg\_%' ESCAPE '\')
            OR
            (referenced_object.schema = $1
              AND dependent_object.schema IS NOT NULL
              AND dependent_object.schema <> $1
              AND dependent_object.schema NOT LIKE 'pg\_%' ESCAPE '\')
          )) AS foreign_dependencies`,
    [
      CANARY_SCHEMA_NAME,
      CANARY_OWNER_DATABASE_USER,
      CANARY_MIGRATION_DATABASE_USER,
      CANARY_RUNTIME_DATABASE_USER,
      CANARY_EVALUATION_WRITER_DATABASE_USER,
    ],
  );
  const expectedFields = [
    "all_tables_publications",
    "default_acls",
    "enabled_event_triggers",
    "extension_owned_objects",
    "extension_owned_schema",
    "extensions",
    "foreign_data_wrapper_authority",
    "foreign_dependencies",
    "foreign_server_usage",
    "foreign_user_mappings",
    "inheritance",
    "policies",
    "publication_namespaces",
    "publication_relations",
    "rewrites",
    "schema_less_casts",
    "schema_less_transforms",
    "subscription_relations",
  ];
  const row = result.rows[0];
  const exactShape = row && Object.keys(row).sort().join("\n") === expectedFields.join("\n");
  const drift = Object.entries(row ?? {})
    .filter(([, value]) => Number(value) !== 0)
    .map(([name]) => name);
  if (!exactShape || drift.length > 0) {
    throw new Error(`Unexpected canary database namespace feature detected: ${drift.join(",") || "missing"}`);
  }
  return true;
}

function sortedTuples(values) {
  return [...values].sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

export function assertCanaryBootstrapAdminRole(value) {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(value) ||
    [
      CANARY_OWNER_DATABASE_USER,
      CANARY_MIGRATION_DATABASE_USER,
      CANARY_RUNTIME_DATABASE_USER,
      CANARY_EVALUATION_WRITER_DATABASE_USER,
    ].includes(value)
  ) {
    throw new Error("CANARY_BOOTSTRAP_ADMIN_ROLE must identify the deployment-owned QM bootstrap administrator");
  }
  return value;
}

export async function assertCanaryRoleTopology(
  client,
  bootstrapAdminRole = CANARY_BOOTSTRAP_ADMIN_ROLE,
  credentialState = "credentialed",
) {
  if (!["credentialed", "structural", "either"].includes(credentialState)) {
    throw new TypeError("Canary credential state is invalid");
  }
  const expectedBootstrapAdmin = assertCanaryBootstrapAdminRole(bootstrapAdminRole);
  const roles = await client.query(
    `/* exact canary role attributes */ SELECT role_record.rolname,
            role_record.rolcanlogin,
            role_record.rolinherit,
            role_record.rolsuper,
            role_record.rolcreaterole,
            role_record.rolcreatedb,
            role_record.rolreplication,
            role_record.rolbypassrls,
            role_record.oid = database_record.datdba AS owns_database,
            setting.setconfig AS database_settings
     FROM pg_catalog.pg_roles role_record
     CROSS JOIN pg_catalog.pg_database database_record
     LEFT JOIN pg_catalog.pg_db_role_setting setting
       ON setting.setrole = role_record.oid AND setting.setdatabase = database_record.oid
     WHERE database_record.datname = pg_catalog.current_database()
       AND role_record.rolname = ANY ($1::text[])
     ORDER BY role_record.rolname`,
    [
      [
        CANARY_OWNER_DATABASE_USER,
        CANARY_MIGRATION_DATABASE_USER,
        CANARY_RUNTIME_DATABASE_USER,
        CANARY_EVALUATION_WRITER_DATABASE_USER,
      ],
    ],
  );
  const actualRoles = roles.rows.map((entry) => [
    entry.rolname,
    entry.rolcanlogin,
    entry.rolinherit,
    entry.rolsuper,
    entry.rolcreaterole,
    entry.rolcreatedb,
    entry.rolreplication,
    entry.rolbypassrls,
    entry.owns_database,
    entry.database_settings,
  ]);
  const expectedRoles = [
    [
      CANARY_EVALUATION_WRITER_DATABASE_USER,
      false,
      false,
      false,
      false,
      false,
      false,
      false,
      false,
      ["search_path=pg_catalog"],
    ],
    [CANARY_MIGRATION_DATABASE_USER, true, false, false, false, false, false, false, false, ["search_path=pg_catalog"]],
    [CANARY_OWNER_DATABASE_USER, false, false, false, false, false, false, false, false, ["search_path=pg_catalog"]],
    [CANARY_RUNTIME_DATABASE_USER, true, false, false, false, false, false, false, false, ["search_path=pg_catalog"]],
  ].sort((left, right) => left[0].localeCompare(right[0]));
  const bootstrapAdmin = await client.query(
    `/* exact canary bootstrap administrator */ SELECT role_record.rolname,
            role_record.rolcanlogin,
            role_record.rolcreaterole,
            role_record.rolsuper,
            role_record.oid = database_record.datdba AS owns_database,
            pg_catalog.has_database_privilege(role_record.rolname, database_record.datname, 'CREATE') AS database_create
     FROM pg_catalog.pg_roles role_record
     CROSS JOIN pg_catalog.pg_database database_record
     WHERE database_record.datname = pg_catalog.current_database()
       AND role_record.rolname = $1`,
    [expectedBootstrapAdmin],
  );
  const edges = await client.query(
    `/* exact bidirectional canary role edges */ SELECT granted_role.rolname AS granted_role,
            member_role.rolname AS member_role,
            grantor_role.rolname AS grantor_role,
            membership.inherit_option,
            membership.set_option,
            membership.admin_option,
            grantor_role.rolsuper AS grantor_is_superuser,
            membership.grantor = 10 AS grantor_is_bootstrap_superuser
     FROM pg_catalog.pg_auth_members membership
     JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
     JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
     JOIN pg_catalog.pg_roles grantor_role ON grantor_role.oid = membership.grantor
     WHERE granted_role.rolname = ANY ($1::text[])
        OR member_role.rolname = ANY ($1::text[])
     ORDER BY granted_role.rolname, member_role.rolname`,
    [
      [
        CANARY_OWNER_DATABASE_USER,
        CANARY_MIGRATION_DATABASE_USER,
        CANARY_RUNTIME_DATABASE_USER,
        CANARY_EVALUATION_WRITER_DATABASE_USER,
      ],
    ],
  );
  const actualEdges = edges.rows.map((entry) => [
    entry.granted_role,
    entry.member_role,
    entry.grantor_role,
    entry.inherit_option,
    entry.set_option,
    entry.admin_option,
    entry.grantor_is_superuser,
    entry.grantor_is_bootstrap_superuser,
  ]);
  const administrativeEdges = actualEdges.filter(
    ([, memberRole, , inheritOption, setOption, adminOption]) =>
      memberRole === expectedBootstrapAdmin && !inheritOption && !setOption && adminOption,
  );
  const expectedAdministrativeRoles = [
    CANARY_EVALUATION_WRITER_DATABASE_USER,
    CANARY_MIGRATION_DATABASE_USER,
    CANARY_OWNER_DATABASE_USER,
    CANARY_RUNTIME_DATABASE_USER,
  ].sort();
  const durableEdges = actualEdges.filter(
    ([grantedRole, memberRole, grantorRole, inheritOption, setOption, adminOption, grantorIsSuperuser]) =>
      grantedRole === CANARY_OWNER_DATABASE_USER &&
      memberRole === CANARY_MIGRATION_DATABASE_USER &&
      grantorRole === expectedBootstrapAdmin &&
      !inheritOption &&
      setOption &&
      !adminOption &&
      !grantorIsSuperuser,
  );
  const bootstrapRole = bootstrapAdmin.rows[0];
  const expectedLoginState = credentialState === "credentialed";
  const migrationRole = actualRoles.find(([roleName]) => roleName === CANARY_MIGRATION_DATABASE_USER);
  const runtimeRole = actualRoles.find(([roleName]) => roleName === CANARY_RUNTIME_DATABASE_USER);
  const writerRole = actualRoles.find(([roleName]) => roleName === CANARY_EVALUATION_WRITER_DATABASE_USER);
  const effectiveLoginState = credentialState === "either" ? migrationRole?.[1] : expectedLoginState;
  const roleLoginStateMatches =
    credentialState === "either"
      ? actualRoles.length === 4 && migrationRole?.[1] === runtimeRole?.[1]
      : migrationRole?.[1] === expectedLoginState && runtimeRole?.[1] === expectedLoginState;
  const expectedRolesForState = expectedRoles.map((entry) => [
    entry[0],
    entry[0] === CANARY_OWNER_DATABASE_USER
      ? false
      : entry[0] === CANARY_EVALUATION_WRITER_DATABASE_USER
        ? writerRole?.[1]
        : effectiveLoginState,
    ...entry.slice(2),
  ]);
  if (
    !roleLoginStateMatches ||
    !sameStructure(actualRoles, expectedRolesForState) ||
    bootstrapAdmin.rows.length !== 1 ||
    bootstrapRole.rolname !== expectedBootstrapAdmin ||
    bootstrapRole.rolcanlogin !== true ||
    bootstrapRole.rolcreaterole !== true ||
    bootstrapRole.rolsuper !== false ||
    bootstrapRole.owns_database !== true ||
    bootstrapRole.database_create !== true ||
    actualEdges.length !== 5 ||
    durableEdges.length !== 1 ||
    administrativeEdges.length !== 4 ||
    !sameStructure(administrativeEdges.map(([grantedRole]) => grantedRole).sort(), expectedAdministrativeRoles) ||
    administrativeEdges.some((edge) => edge[6] !== true || edge[7] !== true) ||
    new Set(administrativeEdges.map((edge) => edge[2])).size !== 1
  )
    throw new Error("Canary database role topology drift detected");
  const databaseAcl = await loadExactCanaryDatabaseAcl(client);
  if (!sameStructure(databaseAcl, EXPECTED_CANARY_DATABASE_ACL)) {
    throw new Error("Canary database ACL drift detected");
  }
  return true;
}

async function databaseRoleBoundary(client, boundaryKind) {
  return client.query(
    `/* ${boundaryKind} role boundary */ SELECT
       pg_catalog.has_database_privilege(current_user, pg_catalog.current_database(), 'CONNECT') AS database_connect,
       pg_catalog.has_database_privilege(current_user, pg_catalog.current_database(), 'CREATE') AS database_create,
       pg_catalog.has_database_privilege(current_user, pg_catalog.current_database(), 'TEMP') AS database_temp,
       EXISTS (
         SELECT 1 FROM pg_catalog.pg_database database_record
         CROSS JOIN LATERAL pg_catalog.aclexplode(
           COALESCE(database_record.datacl, pg_catalog.acldefault('d', database_record.datdba))
         ) acl
         JOIN pg_catalog.pg_roles grantee ON grantee.oid = acl.grantee
         WHERE database_record.datname = pg_catalog.current_database()
           AND grantee.rolname = current_user
           AND acl.privilege_type IN ('CREATE', 'TEMPORARY')
       ) AS direct_database_create_or_temp,
       EXISTS (
         SELECT 1 FROM pg_catalog.pg_database database_record
         CROSS JOIN LATERAL pg_catalog.aclexplode(
           COALESCE(database_record.datacl, pg_catalog.acldefault('d', database_record.datdba))
         ) acl
         WHERE database_record.datname = pg_catalog.current_database()
           AND acl.grantee = 0
           AND acl.privilege_type = 'TEMPORARY'
       ) AS public_database_temp,
       pg_catalog.has_schema_privilege(current_user, $1, 'USAGE') AS schema_usage,
       pg_catalog.has_schema_privilege(current_user, $1, 'CREATE') AS schema_create,
       (SELECT schema_owner.rolname
        FROM pg_catalog.pg_namespace namespace
        JOIN pg_catalog.pg_roles schema_owner ON schema_owner.oid = namespace.nspowner
        WHERE namespace.nspname = $1) AS schema_owner,
       EXISTS (
         SELECT 1 FROM pg_catalog.pg_namespace namespace
         WHERE namespace.nspname <> $1
           AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND namespace.nspname <> 'information_schema'
           AND (namespace.nspowner = current_user::pg_catalog.regrole
             OR pg_catalog.has_schema_privilege(current_user, namespace.oid, 'CREATE'))
       ) AS cross_schema_create_or_owner,
       EXISTS (
         SELECT 1 FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = $1 AND relation.relowner <> $2::pg_catalog.regrole
       ) OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc procedure
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname = $1 AND procedure.proowner <> $2::pg_catalog.regrole
       ) OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_type type_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
         WHERE namespace.nspname = $1 AND type_record.typowner <> $2::pg_catalog.regrole
       ) AS wrong_canary_object_owner,
       EXISTS (
         SELECT 1 FROM pg_catalog.pg_constraint foreign_key
         JOIN pg_catalog.pg_class parent_relation ON parent_relation.oid = foreign_key.confrelid
         JOIN pg_catalog.pg_namespace parent_namespace ON parent_namespace.oid = parent_relation.relnamespace
         JOIN pg_catalog.pg_class child_relation ON child_relation.oid = foreign_key.conrelid
         JOIN pg_catalog.pg_namespace child_namespace ON child_namespace.oid = child_relation.relnamespace
         WHERE foreign_key.contype = 'f'
           AND parent_namespace.nspname = $1
           AND child_namespace.nspname <> $1
       ) AS cross_schema_incoming_foreign_key,
       EXISTS (
         SELECT 1 FROM pg_catalog.pg_collation object_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_record.collnamespace
         WHERE namespace.nspname = $1
       ) OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_operator object_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_record.oprnamespace
         WHERE namespace.nspname = $1
       ) OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_opclass object_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_record.opcnamespace
         WHERE namespace.nspname = $1
       ) OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_opfamily object_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_record.opfnamespace
         WHERE namespace.nspname = $1
       ) OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_conversion object_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_record.connamespace
         WHERE namespace.nspname = $1
       ) OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_ts_config object_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_record.cfgnamespace
         WHERE namespace.nspname = $1
       ) OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_ts_dict object_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_record.dictnamespace
         WHERE namespace.nspname = $1
       ) OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_ts_parser object_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_record.prsnamespace
         WHERE namespace.nspname = $1
       ) OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_ts_template object_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_record.tmplnamespace
         WHERE namespace.nspname = $1
       ) OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_statistic_ext object_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_record.stxnamespace
         WHERE namespace.nspname = $1
       ) AS exotic_canary_object,
       EXISTS (
         SELECT 1 FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname <> $1
           AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND namespace.nspname <> 'information_schema'
           AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
           AND (pg_catalog.has_table_privilege(current_user, relation.oid, 'SELECT')
             OR pg_catalog.has_table_privilege(current_user, relation.oid, 'INSERT')
             OR pg_catalog.has_table_privilege(current_user, relation.oid, 'UPDATE')
             OR pg_catalog.has_table_privilege(current_user, relation.oid, 'DELETE')
             OR pg_catalog.has_table_privilege(current_user, relation.oid, 'TRUNCATE')
             OR pg_catalog.has_table_privilege(current_user, relation.oid, 'REFERENCES')
             OR pg_catalog.has_table_privilege(current_user, relation.oid, 'TRIGGER'))
       ) AS cross_schema_table_access,
       EXISTS (
         SELECT 1 FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname <> $1
           AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND namespace.nspname <> 'information_schema'
           AND relation.relkind = 'S'
           AND (pg_catalog.has_sequence_privilege(current_user, relation.oid, 'SELECT')
             OR pg_catalog.has_sequence_privilege(current_user, relation.oid, 'UPDATE')
             OR pg_catalog.has_sequence_privilege(current_user, relation.oid, 'USAGE'))
       ) AS cross_schema_sequence_access,
       EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc procedure
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname <> $1
           AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
           AND namespace.nspname <> 'information_schema'
           AND procedure.prosecdef
           AND pg_catalog.has_function_privilege(current_user, procedure.oid, 'EXECUTE')
       ) AS cross_schema_security_definer_access`,
    [CANARY_SCHEMA_NAME, CANARY_OWNER_DATABASE_USER],
  );
}

function assertSharedBoundary(state) {
  if (
    !state ||
    state.database_create ||
    state.direct_database_create_or_temp ||
    state.database_temp !== state.public_database_temp ||
    state.schema_owner !== CANARY_OWNER_DATABASE_USER ||
    state.cross_schema_create_or_owner ||
    state.wrong_canary_object_owner ||
    state.cross_schema_incoming_foreign_key ||
    state.exotic_canary_object ||
    state.cross_schema_table_access ||
    state.cross_schema_sequence_access ||
    state.cross_schema_security_definer_access
  )
    throw new Error("Canary role exceeds its dedicated schema boundary");
}

export async function assertMigrationDatabaseBoundary(client, bootstrapAdminRole = CANARY_BOOTSTRAP_ADMIN_ROLE) {
  await assertCanaryRoleTopology(client, bootstrapAdminRole);
  await assertCanaryNamespaceBoundary(client);
  const identity = await client.query(
    `/* migration role identity */ SELECT current_user, pg_catalog.current_database() AS current_database
     FROM pg_catalog.pg_roles WHERE rolname = current_user`,
  );
  const role = identity.rows[0];
  if (role?.current_user !== CANARY_MIGRATION_DATABASE_USER || role.current_database !== CANARY_DATABASE_NAME) {
    throw new Error("Canary migration database identity does not match its deployment contract");
  }
  const state = (await databaseRoleBoundary(client, "migrator")).rows[0];
  assertSharedBoundary(state);
  if (state.database_connect !== true || state.schema_usage || state.schema_create) {
    throw new Error("Canary migration role exceeds its dedicated schema boundary");
  }
  return true;
}

export async function assertOwnerDatabaseBoundary(client, bootstrapAdminRole = CANARY_BOOTSTRAP_ADMIN_ROLE) {
  await assertCanaryRoleTopology(client, bootstrapAdminRole);
  await assertCanaryNamespaceBoundary(client);
  const identity = await client.query(
    `/* owner role identity */ SELECT current_user, session_user, pg_catalog.current_database() AS current_database
     FROM pg_catalog.pg_roles WHERE rolname = current_user`,
  );
  const role = identity.rows[0];
  if (
    role?.current_user !== CANARY_OWNER_DATABASE_USER ||
    role.session_user !== CANARY_MIGRATION_DATABASE_USER ||
    role.current_database !== CANARY_DATABASE_NAME
  )
    throw new Error("Canary owner database identity does not match its deployment contract");
  const state = (await databaseRoleBoundary(client, "owner")).rows[0];
  assertSharedBoundary(state);
  if (state.schema_usage !== true || state.schema_create !== true) {
    throw new Error("Canary owner role exceeds its dedicated schema boundary");
  }
  return true;
}

export async function assertRuntimeDatabaseBoundary(client, bootstrapAdminRole = CANARY_BOOTSTRAP_ADMIN_ROLE) {
  await assertCanaryRoleTopology(client, bootstrapAdminRole);
  await assertCanaryNamespaceBoundary(client);
  const state = (await databaseRoleBoundary(client, "runtime")).rows[0];
  assertSharedBoundary(state);
  if (state.database_connect !== true || state.schema_usage !== true || state.schema_create) {
    throw new Error("Canary runtime role exceeds its dedicated schema boundary");
  }
  return true;
}

export async function assertEvaluationWriterDatabaseBoundary(client, bootstrapAdminRole = CANARY_BOOTSTRAP_ADMIN_ROLE) {
  await assertCanaryRoleTopology(client, bootstrapAdminRole);
  await assertCanaryNamespaceBoundary(client);
  const identity = await client.query(
    `SELECT current_user, pg_catalog.current_database() AS current_database,
            pg_catalog.has_function_privilege(
              current_user,
              '${CANARY_SCHEMA_NAME}.persist_authorized_evaluation(text, character, character, jsonb, jsonb, text, jsonb)'::pg_catalog.regprocedure,
              'EXECUTE'
            ) AS persist_execute,
            EXISTS (
              SELECT 1 FROM pg_catalog.pg_class relation
              JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
              WHERE namespace.nspname = $1
                AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                AND (pg_catalog.has_table_privilege(current_user, relation.oid, 'SELECT')
                  OR pg_catalog.has_table_privilege(current_user, relation.oid, 'INSERT')
                  OR pg_catalog.has_table_privilege(current_user, relation.oid, 'UPDATE')
                  OR pg_catalog.has_table_privilege(current_user, relation.oid, 'DELETE')
                  OR pg_catalog.has_table_privilege(current_user, relation.oid, 'TRUNCATE')
                  OR pg_catalog.has_table_privilege(current_user, relation.oid, 'REFERENCES')
                  OR pg_catalog.has_table_privilege(current_user, relation.oid, 'TRIGGER'))
            ) AS table_access,
            EXISTS (
              SELECT 1 FROM pg_catalog.pg_proc procedure
              JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
              WHERE namespace.nspname = $1
                AND procedure.proname <> 'persist_authorized_evaluation'
                AND pg_catalog.has_function_privilege(current_user, procedure.oid, 'EXECUTE')
            ) AS other_routine_execute
     FROM pg_catalog.pg_roles WHERE rolname = current_user`,
    [CANARY_SCHEMA_NAME],
  );
  const role = identity.rows[0];
  const state = (await databaseRoleBoundary(client, "evaluation writer")).rows[0];
  assertSharedBoundary(state);
  if (
    role?.current_user !== CANARY_EVALUATION_WRITER_DATABASE_USER ||
    role.current_database !== CANARY_DATABASE_NAME ||
    role.persist_execute !== true ||
    role.other_routine_execute ||
    state.database_connect !== true ||
    state.schema_usage !== true ||
    state.schema_create
  ) {
    throw new Error("Canary evaluation writer exceeds its dedicated routine boundary");
  }
  return true;
}

export async function loadExactCanaryAcl(client) {
  const grants = await client.query(
    `WITH exact_acl AS (
       SELECT 'table'::text AS resource_type, relation.relname::text AS resource_name, ''::text AS subresource_name,
              CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee,
              CASE WHEN acl.grantor = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantor) END AS grantor,
              acl.privilege_type::text, acl.is_grantable
       FROM pg_catalog.pg_class relation
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner))
       ) acl
       WHERE namespace.nspname = $1 AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
       UNION ALL
       SELECT 'column', relation.relname, attribute.attname,
              CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantee) END,
              CASE WHEN acl.grantor = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantor) END,
              acl.privilege_type, acl.is_grantable
       FROM pg_catalog.pg_class relation
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
       JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid = relation.oid
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         COALESCE(attribute.attacl, pg_catalog.acldefault('c', relation.relowner))
       ) acl
       WHERE namespace.nspname = $1 AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
         AND attribute.attnum > 0 AND NOT attribute.attisdropped
       UNION ALL
       SELECT 'sequence', relation.relname, '',
              CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantee) END,
              CASE WHEN acl.grantor = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantor) END,
              acl.privilege_type, acl.is_grantable
       FROM pg_catalog.pg_class relation
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         COALESCE(relation.relacl, pg_catalog.acldefault('S', relation.relowner))
       ) acl
       WHERE namespace.nspname = $1 AND relation.relkind = 'S'
       UNION ALL
       SELECT 'schema', namespace.nspname, '',
              CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantee) END,
              CASE WHEN acl.grantor = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantor) END,
              acl.privilege_type, acl.is_grantable
       FROM pg_catalog.pg_namespace namespace
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
       ) acl
       WHERE namespace.nspname = $1
       UNION ALL
       SELECT 'function', procedure.proname || '(' || pg_catalog.pg_get_function_identity_arguments(procedure.oid) || ')', '',
              CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantee) END,
              CASE WHEN acl.grantor = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantor) END,
              acl.privilege_type, acl.is_grantable
       FROM pg_catalog.pg_proc procedure
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
       ) acl
       WHERE namespace.nspname = $1
       UNION ALL
       SELECT 'type', type_record.typname, '',
              CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantee) END,
              CASE WHEN acl.grantor = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(acl.grantor) END,
              acl.privilege_type, acl.is_grantable
       FROM pg_catalog.pg_type type_record
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         COALESCE(type_record.typacl, pg_catalog.acldefault('T', type_record.typowner))
       ) acl
       WHERE namespace.nspname = $1
     )
     SELECT resource_type, resource_name, subresource_name, grantee, grantor, privilege_type, is_grantable
     FROM exact_acl`,
    [CANARY_SCHEMA_NAME],
  );
  return grants.rows.map((row) => [
    row.resource_type,
    row.resource_name,
    row.subresource_name,
    row.grantee,
    row.grantor,
    row.privilege_type,
    row.is_grantable,
  ]);
}

function assertCompiledCatalog(catalog, storedCatalog) {
  const structure = catalogStructure(catalog);
  const checks = [
    ["catalog_shape", structure !== null],
    ["compiled_catalog_authority", catalogAuthoritySha256(catalog) === EXPECTED_CATALOG_AUTHORITY_SHA256],
    ["compiled_catalog_structure", sameStructure(structure, EXPECTED_CATALOG_AUTHORITY_V8)],
    ["stored_catalog", sameStructure(catalog, storedCatalog)],
  ];
  const drift = checks.filter(([, passed]) => !passed).map(([name]) => name);
  if (drift.length > 0) throw new Error(`Canary post-migration catalog drift detected: ${drift.join(",")}`);
}

export async function assertExactCanaryCatalog(client) {
  const migrations = await client.query(
    `SELECT version, checksum, catalog_fingerprint
     FROM ${CANARY_SCHEMA_NAME}.schema_migrations ORDER BY version`,
  );
  if (
    migrations.rows.length !== 1 ||
    migrations.rows[0].version !== SCHEMA_VERSION ||
    migrations.rows[0].checksum !== migrationChecksum()
  )
    throw new Error("Canary post-migration ancestry mismatch detected");
  const catalog = (await client.query(catalogFingerprintSql())).rows[0]?.catalog_fingerprint;
  assertCompiledCatalog(catalog, migrations.rows[0].catalog_fingerprint);
  const acl = await loadExactCanaryAcl(client);
  if (!sameStructure(sortedTuples(acl), sortedTuples(EXPECTED_DATABASE_ACL))) {
    const actual = new Set(acl.map((entry) => JSON.stringify(entry)));
    const expected = new Set(EXPECTED_DATABASE_ACL.map((entry) => JSON.stringify(entry)));
    const missing = [...expected].filter((entry) => !actual.has(entry));
    const unexpected = [...actual].filter((entry) => !expected.has(entry));
    throw new Error(`Canary post-migration ACL drift detected: ${JSON.stringify({ missing, unexpected })}`);
  }
  return true;
}

export async function assertPostMigrationDatabaseContract(client, bootstrapAdminRole = CANARY_BOOTSTRAP_ADMIN_ROLE) {
  await assertOwnerDatabaseBoundary(client, bootstrapAdminRole);
  return assertExactCanaryCatalog(client);
}
