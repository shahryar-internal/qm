import { createHash } from "node:crypto";
import { EXPECTED_CATALOG_AUTHORITY_V8 } from "./catalog-authority-v8.mjs";

export const CANARY_DATABASE_NAME = "qm";
export const CANARY_BOOTSTRAP_ADMIN_ROLE = "qm";
export const CANARY_SCHEMA_NAME = "risely_agent_runtime";
export const CANARY_OWNER_DATABASE_USER = "risely_agent_runtime_owner";
export const CANARY_RUNTIME_DATABASE_USER = "risely_agent_runtime_runtime";
export const CANARY_MIGRATION_DATABASE_USER = "risely_agent_runtime_migrator";
export const CANARY_EVALUATION_WRITER_DATABASE_USER = "risely_agent_runtime_evaluation_writer";
export const CANARY_MAINTENANCE_LOCK_KEY = "risely_agent_runtime:maintenance:v1";
export const SCHEMA_VERSION = 8;
export const EXPECTED_CATALOG_AUTHORITY_SHA256 = "6f3f857ff18d2945fcd01c205087a68ccfd938dfca15aabf22a0cb834618d4fd";
export { EXPECTED_CATALOG_AUTHORITY_V8 };
const compactAuthorityRows = (rows, indexes) =>
  Object.freeze(rows.map((row) => Object.freeze(indexes.map((index) => row[index]))));
export const EXPECTED_CONSTRAINTS = compactAuthorityRows(EXPECTED_CATALOG_AUTHORITY_V8.constraints, [0, 1, 2]);
export const EXPECTED_INDEXES = compactAuthorityRows(EXPECTED_CATALOG_AUTHORITY_V8.indexes, [0, 1]);
export const EXPECTED_TRIGGERS = Object.freeze(EXPECTED_CATALOG_AUTHORITY_V8.triggers.map((row) => row[0]));
export const EXPECTED_TRIGGER_TABLES = Object.freeze(
  Object.fromEntries(EXPECTED_CATALOG_AUTHORITY_V8.triggers.map((row) => [row[0], row[1]])),
);
const EXPECTED_TABLE_DEFINITIONS = compactAuthorityRows(
  EXPECTED_CATALOG_AUTHORITY_V8.relations.filter((row) => row[1] === "r"),
  [0, 1, 2],
);
export const EXPECTED_RELATION_DEFINITIONS = compactAuthorityRows(
  EXPECTED_CATALOG_AUTHORITY_V8.relations,
  [0, 1, 2, 3, 4, 5, 9, 10],
);
export const EXPECTED_ROUTINE_DEFINITIONS = EXPECTED_CATALOG_AUTHORITY_V8.routines;
export const EXPECTED_TYPE_DEFINITIONS = EXPECTED_CATALOG_AUTHORITY_V8.types;
export const EXPECTED_COLUMN_DEFINITIONS = EXPECTED_CATALOG_AUTHORITY_V8.columns;
const RUNTIME_ACL = [
  ["column", "action_states", "revision", "UPDATE"],
  ["column", "action_states", "state", "UPDATE"],
  ["column", "action_states", "state_hash", "UPDATE"],
  ["column", "action_states", "updated_at", "UPDATE"],
  ["column", "reconciliation_leases", "acquired_at", "UPDATE"],
  ["column", "reconciliation_leases", "expires_at", "UPDATE"],
  ["column", "reconciliation_leases", "lease_id", "UPDATE"],
  ["column", "reconciliation_leases", "principal_ref", "UPDATE"],
  ["column", "reconciliation_leases", "revision", "UPDATE"],
  ["column", "surface_delivery_reservations", "attempted_at", "UPDATE"],
  ["column", "surface_delivery_reservations", "completed_at", "UPDATE"],
  ["column", "surface_delivery_reservations", "reconciliation_acquired_at", "UPDATE"],
  ["column", "surface_delivery_reservations", "reconciliation_expires_at", "UPDATE"],
  ["column", "surface_delivery_reservations", "reconciliation_owner_ref", "UPDATE"],
  ["column", "surface_delivery_reservations", "reconciliation_ref", "UPDATE"],
  ["column", "surface_delivery_reservations", "revision", "UPDATE"],
  ["column", "surface_delivery_reservations", "status", "UPDATE"],
  ["column", "surface_delivery_reservations", "updated_at", "UPDATE"],
  ["column", "surface_outbox_states", "claim_acquired_at", "UPDATE"],
  ["column", "surface_outbox_states", "claim_expires_at", "UPDATE"],
  ["column", "surface_outbox_states", "claim_owner_ref", "UPDATE"],
  ["column", "surface_outbox_states", "claim_ref", "UPDATE"],
  ["column", "surface_outbox_states", "failure_code", "UPDATE"],
  ["column", "surface_outbox_states", "revision", "UPDATE"],
  ["column", "surface_outbox_states", "status", "UPDATE"],
  ["column", "surface_outbox_states", "updated_at", "UPDATE"],
  ["schema", "risely_agent_runtime", "", "USAGE"],
  ["sequence", "action_events_event_sequence_seq", "", "SELECT"],
  ["sequence", "action_events_event_sequence_seq", "", "USAGE"],
  ["sequence", "audit_events_audit_sequence_seq", "", "SELECT"],
  ["sequence", "audit_events_audit_sequence_seq", "", "USAGE"],
  ["sequence", "surface_delivery_receipts_receipt_sequence_seq", "", "SELECT"],
  ["sequence", "surface_delivery_receipts_receipt_sequence_seq", "", "USAGE"],
  ["table", "action_effect_reservations", "", "INSERT"],
  ["table", "action_effect_reservations", "", "SELECT"],
  ["table", "action_events", "", "INSERT"],
  ["table", "action_events", "", "SELECT"],
  ["table", "action_states", "", "INSERT"],
  ["table", "action_states", "", "SELECT"],
  ["table", "audit_events", "", "INSERT"],
  ["table", "deployment_profiles", "", "INSERT"],
  ["table", "deployment_profiles", "", "SELECT"],
  ["table", "evaluation_candidates", "", "SELECT"],
  ["table", "evaluation_judge_results", "", "SELECT"],
  ["table", "evaluation_release_judge_results", "", "SELECT"],
  ["table", "evaluation_releases", "", "SELECT"],
  ["table", "evaluation_replay_tombstones", "", "INSERT"],
  ["table", "evaluation_replay_tombstones", "", "SELECT"],
  ["table", "ingress_requests", "", "DELETE"],
  ["table", "ingress_requests", "", "INSERT"],
  ["table", "ingress_requests", "", "SELECT"],
  ["table", "reconciliation_leases", "", "DELETE"],
  ["table", "reconciliation_leases", "", "INSERT"],
  ["table", "reconciliation_leases", "", "SELECT"],
  ["table", "schema_migrations", "", "SELECT"],
  ["table", "surface_delivery_receipts", "", "INSERT"],
  ["table", "surface_delivery_receipts", "", "SELECT"],
  ["table", "surface_delivery_reservations", "", "INSERT"],
  ["table", "surface_delivery_reservations", "", "SELECT"],
  ["table", "surface_delivery_tombstones", "", "INSERT"],
  ["table", "surface_delivery_tombstones", "", "SELECT"],
  ["table", "surface_event_tombstones", "", "INSERT"],
  ["table", "surface_event_tombstones", "", "SELECT"],
  ["table", "surface_outbox_events", "", "INSERT"],
  ["table", "surface_outbox_events", "", "SELECT"],
  ["table", "surface_outbox_states", "", "INSERT"],
  ["table", "surface_outbox_states", "", "SELECT"],
  ["table", "workflow_runs", "", "INSERT"],
  ["table", "workflow_runs", "", "SELECT"],
];
const EVALUATION_WRITER_ACL = [
  ["schema", CANARY_SCHEMA_NAME, "", "USAGE"],
  ["table", "deployment_profiles", "", "SELECT"],
  ["table", "evaluation_candidates", "", "SELECT"],
  ["table", "evaluation_judge_results", "", "SELECT"],
  ["table", "evaluation_release_judge_results", "", "SELECT"],
  ["table", "evaluation_releases", "", "SELECT"],
  ["table", "evaluation_replay_tombstones", "", "INSERT"],
  ["table", "evaluation_replay_tombstones", "", "SELECT"],
  ["table", "schema_migrations", "", "SELECT"],
];
const OWNER_TABLE_PRIVILEGES = ["DELETE", "INSERT", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"];
const OWNER_SEQUENCE_PRIVILEGES = ["SELECT", "UPDATE", "USAGE"];
export const EXPECTED_DATABASE_ACL = Object.freeze([
  ...EXPECTED_TABLE_DEFINITIONS.flatMap(([table]) =>
    OWNER_TABLE_PRIVILEGES.map((privilege) => [
      "table",
      table,
      "",
      CANARY_OWNER_DATABASE_USER,
      CANARY_OWNER_DATABASE_USER,
      privilege,
      false,
    ]),
  ),
  ...RUNTIME_ACL.map(([resourceType, resourceName, subresourceName, privilege]) => [
    resourceType,
    resourceName,
    subresourceName,
    CANARY_RUNTIME_DATABASE_USER,
    CANARY_OWNER_DATABASE_USER,
    privilege,
    false,
  ]),
  ...EVALUATION_WRITER_ACL.map(([resourceType, resourceName, subresourceName, privilege]) => [
    resourceType,
    resourceName,
    subresourceName,
    CANARY_EVALUATION_WRITER_DATABASE_USER,
    CANARY_OWNER_DATABASE_USER,
    privilege,
    false,
  ]),
  ...["CREATE", "USAGE"].map((privilege) => [
    "schema",
    CANARY_SCHEMA_NAME,
    "",
    CANARY_OWNER_DATABASE_USER,
    CANARY_OWNER_DATABASE_USER,
    privilege,
    false,
  ]),
  ...[
    "action_events_event_sequence_seq",
    "audit_events_audit_sequence_seq",
    "surface_delivery_receipts_receipt_sequence_seq",
  ].flatMap((sequence) =>
    OWNER_SEQUENCE_PRIVILEGES.map((privilege) => [
      "sequence",
      sequence,
      "",
      CANARY_OWNER_DATABASE_USER,
      CANARY_OWNER_DATABASE_USER,
      privilege,
      false,
    ]),
  ),
  [
    "function",
    "canonical_jsonb(p_value jsonb)",
    "",
    CANARY_OWNER_DATABASE_USER,
    CANARY_OWNER_DATABASE_USER,
    "EXECUTE",
    false,
  ],
  [
    "function",
    "reject_runtime_mutation()",
    "",
    CANARY_OWNER_DATABASE_USER,
    CANARY_OWNER_DATABASE_USER,
    "EXECUTE",
    false,
  ],
  [
    "function",
    "persist_authorized_evaluation(p_profile_ref text, p_profile_sha256 character, p_candidate_sha256 character, p_candidate jsonb, p_judge_results jsonb, p_release_id text, p_release jsonb)",
    "",
    CANARY_OWNER_DATABASE_USER,
    CANARY_OWNER_DATABASE_USER,
    "EXECUTE",
    false,
  ],
  [
    "function",
    "persist_authorized_evaluation(p_profile_ref text, p_profile_sha256 character, p_candidate_sha256 character, p_candidate jsonb, p_judge_results jsonb, p_release_id text, p_release jsonb)",
    "",
    CANARY_EVALUATION_WRITER_DATABASE_USER,
    CANARY_OWNER_DATABASE_USER,
    "EXECUTE",
    false,
  ],
  ...EXPECTED_TYPE_DEFINITIONS.flatMap(([type]) => [
    ["type", type, "", CANARY_OWNER_DATABASE_USER, CANARY_OWNER_DATABASE_USER, "USAGE", false],
    ["type", type, "", "PUBLIC", CANARY_OWNER_DATABASE_USER, "USAGE", false],
  ]),
]);
export const EXPECTED_CANARY_DATABASE_ACL = Object.freeze([
  ["PUBLIC", CANARY_BOOTSTRAP_ADMIN_ROLE, "CONNECT", false],
  ["PUBLIC", CANARY_BOOTSTRAP_ADMIN_ROLE, "TEMPORARY", false],
  [CANARY_EVALUATION_WRITER_DATABASE_USER, CANARY_BOOTSTRAP_ADMIN_ROLE, "CONNECT", false],
  [CANARY_MIGRATION_DATABASE_USER, CANARY_BOOTSTRAP_ADMIN_ROLE, "CONNECT", false],
  [CANARY_RUNTIME_DATABASE_USER, CANARY_BOOTSTRAP_ADMIN_ROLE, "CONNECT", false],
]);
export function catalogFingerprintSql() {
  const schema = CANARY_SCHEMA_NAME;
  return `
SELECT jsonb_build_object(
  'constraints', COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'table', relation.relname,
        'name', constraint_record.conname,
        'type', constraint_record.contype,
        'validated', constraint_record.convalidated,
        'deferrable', constraint_record.condeferrable,
        'deferred', constraint_record.condeferred,
        'columns', COALESCE((
          SELECT jsonb_agg(attribute.attname ORDER BY key_position.ordinality)
          FROM unnest(constraint_record.conkey) WITH ORDINALITY key_position(attribute_number, ordinality)
          JOIN pg_catalog.pg_attribute attribute
            ON attribute.attrelid = constraint_record.conrelid
           AND attribute.attnum = key_position.attribute_number
        ), '[]'::jsonb),
        'referencedTable', referenced_relation.relname,
        'referencedColumns', COALESCE((
          SELECT jsonb_agg(attribute.attname ORDER BY key_position.ordinality)
          FROM unnest(constraint_record.confkey) WITH ORDINALITY key_position(attribute_number, ordinality)
          JOIN pg_catalog.pg_attribute attribute
            ON attribute.attrelid = constraint_record.confrelid
           AND attribute.attnum = key_position.attribute_number
        ), '[]'::jsonb),
        'matchType', constraint_record.confmatchtype,
        'updateType', constraint_record.confupdtype,
        'deleteType', constraint_record.confdeltype,
        'definition', pg_catalog.pg_get_constraintdef(constraint_record.oid, true)
      ) ORDER BY relation.relname, constraint_record.conname
    )
    FROM pg_catalog.pg_constraint constraint_record
    JOIN pg_catalog.pg_class relation ON relation.oid = constraint_record.conrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    LEFT JOIN pg_catalog.pg_class referenced_relation ON referenced_relation.oid = constraint_record.confrelid
    WHERE namespace.nspname = '${schema}'
      AND constraint_record.contype IN ('c', 'f', 'p', 'u')
  ), '[]'::jsonb),
  'indexes', COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'table', relation.relname,
        'name', index_relation.relname,
        'valid', index_record.indisvalid,
        'ready', index_record.indisready,
        'live', index_record.indislive,
        'unique', index_record.indisunique,
        'primary', index_record.indisprimary,
        'immediate', index_record.indimmediate,
        'clustered', index_record.indisclustered,
        'replicaIdentity', index_record.indisreplident,
        'nullsNotDistinct', index_record.indnullsnotdistinct,
        'accessMethod', access_method.amname,
        'keyColumns', COALESCE((
          SELECT jsonb_agg(pg_catalog.pg_get_indexdef(index_record.indexrelid, position, true) ORDER BY position)
          FROM generate_series(1, index_record.indnkeyatts) position
        ), '[]'::jsonb),
        'includedColumns', COALESCE((
          SELECT jsonb_agg(pg_catalog.pg_get_indexdef(index_record.indexrelid, position, true) ORDER BY position)
          FROM generate_series(index_record.indnkeyatts + 1, index_record.indnatts) position
        ), '[]'::jsonb),
        'expressions', pg_catalog.pg_get_expr(index_record.indexprs, index_record.indrelid, true),
        'predicate', pg_catalog.pg_get_expr(index_record.indpred, index_record.indrelid, true),
        'attributeOptions', index_record.indoption::text,
        'definition', pg_catalog.pg_get_indexdef(index_record.indexrelid, 0, true)
      ) ORDER BY relation.relname, index_relation.relname
    )
    FROM pg_catalog.pg_index index_record
    JOIN pg_catalog.pg_class relation ON relation.oid = index_record.indrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_class index_relation ON index_relation.oid = index_record.indexrelid
    JOIN pg_catalog.pg_am access_method ON access_method.oid = index_relation.relam
    WHERE namespace.nspname = '${schema}'
  ), '[]'::jsonb),
  'relations', COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'table', relation.relname,
        'kind', relation.relkind,
        'persistence', relation.relpersistence,
        'owner', owner.rolname,
        'rowSecurity', relation.relrowsecurity,
        'forceRowSecurity', relation.relforcerowsecurity,
        'replicaIdentity', relation.relreplident,
        'isPartition', relation.relispartition,
        'options', relation.reloptions,
        'accessMethod', access_method.amname,
        'extensionOwned', EXISTS (
          SELECT 1
          FROM pg_catalog.pg_depend dependency
          WHERE dependency.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
            AND dependency.objid = relation.oid
            AND dependency.deptype = 'e'
        )
      ) ORDER BY relation.relname
    )
    FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = relation.relowner
    LEFT JOIN pg_catalog.pg_am access_method ON access_method.oid = relation.relam
    WHERE namespace.nspname = '${schema}'
  ), '[]'::jsonb),
  'toast', COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'baseTable', base_relation.relname,
        'present', toast_relation.oid IS NOT NULL,
        'owner', toast_owner.rolname,
        'kind', toast_relation.relkind,
        'persistence', toast_relation.relpersistence,
        'accessMethod', toast_access_method.amname,
        'options', toast_relation.reloptions,
        'indexes', COALESCE((
          SELECT jsonb_agg(
            jsonb_build_object(
              'owner', index_owner.rolname,
              'kind', index_relation.relkind,
              'persistence', index_relation.relpersistence,
              'options', index_relation.reloptions,
              'accessMethod', index_access_method.amname,
              'valid', index_record.indisvalid,
              'ready', index_record.indisready,
              'live', index_record.indislive,
              'unique', index_record.indisunique,
              'primary', index_record.indisprimary,
              'immediate', index_record.indimmediate,
              'clustered', index_record.indisclustered,
              'replicaIdentity', index_record.indisreplident,
              'nullsNotDistinct', index_record.indnullsnotdistinct,
              'keyColumns', COALESCE((
                SELECT jsonb_agg(pg_catalog.pg_get_indexdef(index_record.indexrelid, position, true) ORDER BY position)
                FROM generate_series(1, index_record.indnkeyatts) position
              ), '[]'::jsonb),
              'includedColumns', COALESCE((
                SELECT jsonb_agg(pg_catalog.pg_get_indexdef(index_record.indexrelid, position, true) ORDER BY position)
                FROM generate_series(index_record.indnkeyatts + 1, index_record.indnatts) position
              ), '[]'::jsonb),
              'expressions', pg_catalog.pg_get_expr(index_record.indexprs, index_record.indrelid, true),
              'predicate', pg_catalog.pg_get_expr(index_record.indpred, index_record.indrelid, true),
              'attributeOptions', index_record.indoption::text
            ) ORDER BY index_relation.relname
          )
          FROM pg_catalog.pg_index index_record
          JOIN pg_catalog.pg_class index_relation ON index_relation.oid = index_record.indexrelid
          JOIN pg_catalog.pg_roles index_owner ON index_owner.oid = index_relation.relowner
          LEFT JOIN pg_catalog.pg_am index_access_method ON index_access_method.oid = index_relation.relam
          WHERE index_record.indrelid = toast_relation.oid
        ), '[]'::jsonb)
      ) ORDER BY base_relation.relname
    )
    FROM pg_catalog.pg_class base_relation
    JOIN pg_catalog.pg_namespace base_namespace ON base_namespace.oid = base_relation.relnamespace
    LEFT JOIN pg_catalog.pg_class toast_relation ON toast_relation.oid = base_relation.reltoastrelid
    LEFT JOIN pg_catalog.pg_roles toast_owner ON toast_owner.oid = toast_relation.relowner
    LEFT JOIN pg_catalog.pg_am toast_access_method ON toast_access_method.oid = toast_relation.relam
    WHERE base_namespace.nspname = '${schema}'
      AND base_relation.relkind IN ('r', 'p')
  ), '[]'::jsonb),
  'columns', COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'table', relation.relname,
        'name', attribute.attname,
        'ordinal', attribute.attnum,
        'type', pg_catalog.format_type(attribute.atttypid, attribute.atttypmod),
        'notNull', attribute.attnotnull,
        'identity', CASE attribute.attidentity WHEN 'a' THEN 'always' WHEN 'd' THEN 'by_default' ELSE 'none' END,
        'generated', CASE attribute.attgenerated WHEN 's' THEN 'stored' WHEN 'v' THEN 'virtual' ELSE 'none' END,
        'default', pg_catalog.pg_get_expr(default_record.adbin, default_record.adrelid),
        'collation', CASE
          WHEN attribute.attcollation = 0 THEN NULL
          ELSE pg_catalog.format('%I.%I', collation_namespace.nspname, collation_record.collname)
        END
      ) ORDER BY relation.relname, attribute.attnum
    )
    FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid = relation.oid
    LEFT JOIN pg_catalog.pg_attrdef default_record
      ON default_record.adrelid = relation.oid AND default_record.adnum = attribute.attnum
    LEFT JOIN pg_catalog.pg_collation collation_record ON collation_record.oid = attribute.attcollation
    LEFT JOIN pg_catalog.pg_namespace collation_namespace ON collation_namespace.oid = collation_record.collnamespace
    WHERE namespace.nspname = '${schema}'
      AND relation.relkind = 'r'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
  ), '[]'::jsonb),
  'routines', COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'name', procedure.proname,
        'kind', procedure.prokind,
        'owner', owner.rolname,
        'securityDefiner', procedure.prosecdef,
        'language', language.lanname,
        'config', procedure.proconfig,
        'arguments', pg_catalog.pg_get_function_identity_arguments(procedure.oid),
        'result', pg_catalog.pg_get_function_result(procedure.oid),
        'volatility', procedure.provolatile,
        'strict', procedure.proisstrict,
        'leakproof', procedure.proleakproof,
        'parallel', procedure.proparallel,
        'body', pg_catalog.btrim(pg_catalog.regexp_replace(procedure.prosrc, '[[:space:]]+', ' ', 'g'))
      ) ORDER BY procedure.proname, pg_catalog.pg_get_function_identity_arguments(procedure.oid)
    )
    FROM pg_catalog.pg_proc procedure
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = procedure.proowner
    JOIN pg_catalog.pg_language language ON language.oid = procedure.prolang
    WHERE namespace.nspname = '${schema}'
  ), '[]'::jsonb),
  'sequences', COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'name', sequence_relation.relname,
        'owner', sequence_owner.rolname,
        'dataType', pg_catalog.format_type(sequence_record.seqtypid, NULL),
        'start', sequence_record.seqstart::text,
        'increment', sequence_record.seqincrement::text,
        'maximum', sequence_record.seqmax::text,
        'minimum', sequence_record.seqmin::text,
        'cache', sequence_record.seqcache::text,
        'cycle', sequence_record.seqcycle,
        'ownedTable', owned_relation.relname,
        'ownedColumn', owned_attribute.attname,
        'ownershipDependency', ownership_dependency.deptype
      ) ORDER BY sequence_relation.relname
    )
    FROM pg_catalog.pg_sequence sequence_record
    JOIN pg_catalog.pg_class sequence_relation ON sequence_relation.oid = sequence_record.seqrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = sequence_relation.relnamespace
    JOIN pg_catalog.pg_roles sequence_owner ON sequence_owner.oid = sequence_relation.relowner
    LEFT JOIN pg_catalog.pg_depend ownership_dependency
      ON ownership_dependency.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
     AND ownership_dependency.objid = sequence_relation.oid
     AND ownership_dependency.objsubid = 0
     AND ownership_dependency.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
     AND ownership_dependency.deptype IN ('a', 'i')
    LEFT JOIN pg_catalog.pg_class owned_relation ON owned_relation.oid = ownership_dependency.refobjid
    LEFT JOIN pg_catalog.pg_attribute owned_attribute
      ON owned_attribute.attrelid = ownership_dependency.refobjid
     AND owned_attribute.attnum = ownership_dependency.refobjsubid
    WHERE namespace.nspname = '${schema}'
  ), '[]'::jsonb),
  'triggers', COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'name', trigger_record.tgname,
        'table', relation.relname,
        'enabled', trigger_record.tgenabled,
        'type', trigger_record.tgtype,
        'when', pg_catalog.pg_get_expr(trigger_record.tgqual, trigger_record.tgrelid, true),
        'definition', pg_catalog.pg_get_triggerdef(trigger_record.oid, true),
        'functionSchema', function_namespace.nspname,
        'functionName', procedure.proname,
        'functionOwner', function_owner.rolname,
        'functionLanguage', language.lanname,
        'functionSecurityDefiner', procedure.prosecdef,
        'functionConfig', procedure.proconfig,
        'functionVolatility', procedure.provolatile,
        'functionStrict', procedure.proisstrict,
        'functionBody', pg_catalog.btrim(pg_catalog.regexp_replace(procedure.prosrc, '[[:space:]]+', ' ', 'g'))
      ) ORDER BY trigger_record.tgname
    )
    FROM pg_catalog.pg_trigger trigger_record
    JOIN pg_catalog.pg_class relation ON relation.oid = trigger_record.tgrelid
    JOIN pg_catalog.pg_namespace relation_namespace ON relation_namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_proc procedure ON procedure.oid = trigger_record.tgfoid
    JOIN pg_catalog.pg_namespace function_namespace ON function_namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_roles function_owner ON function_owner.oid = procedure.proowner
    JOIN pg_catalog.pg_language language ON language.oid = procedure.prolang
    WHERE relation_namespace.nspname = '${schema}'
      AND NOT trigger_record.tgisinternal
  ), '[]'::jsonb),
  'types', COALESCE((
    SELECT jsonb_agg(
      jsonb_build_object(
        'name', type_record.typname,
        'kind', type_record.typtype,
        'category', type_record.typcategory,
        'owner', owner.rolname,
        'relation', relation.relname,
        'element', element_type.typname
      ) ORDER BY type_record.typname
    )
    FROM pg_catalog.pg_type type_record
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid = type_record.typowner
    LEFT JOIN pg_catalog.pg_class relation ON relation.oid = type_record.typrelid
    LEFT JOIN pg_catalog.pg_type element_type ON element_type.oid = type_record.typelem AND type_record.typelem <> 0
    WHERE namespace.nspname = '${schema}'
  ), '[]'::jsonb)
) AS catalog_fingerprint`;
}

export function catalogStructure(catalog) {
  if (
    !catalog ||
    !Array.isArray(catalog.constraints) ||
    !Array.isArray(catalog.indexes) ||
    !Array.isArray(catalog.relations) ||
    !Array.isArray(catalog.toast) ||
    !Array.isArray(catalog.columns) ||
    !Array.isArray(catalog.routines) ||
    !Array.isArray(catalog.sequences) ||
    !Array.isArray(catalog.triggers) ||
    !Array.isArray(catalog.types)
  )
    return null;
  if (catalog.constraints.some((entry) => entry.validated !== true)) return null;
  if (catalog.indexes.some((entry) => entry.valid !== true || entry.ready !== true || entry.live !== true)) return null;
  if (
    catalog.toast.some(
      (entry) =>
        !Array.isArray(entry.indexes) ||
        entry.indexes.some((index) => index.valid !== true || index.ready !== true || index.live !== true),
    )
  )
    return null;
  return {
    constraints: catalog.constraints.map((entry) => [
      entry.table,
      entry.name,
      entry.type,
      entry.validated,
      entry.deferrable,
      entry.deferred,
      entry.columns,
      entry.referencedTable,
      entry.referencedColumns,
      entry.matchType,
      entry.updateType,
      entry.deleteType,
      entry.definition,
    ]),
    indexes: catalog.indexes.map((entry) => [
      entry.table,
      entry.name,
      entry.valid,
      entry.ready,
      entry.live,
      entry.unique,
      entry.primary,
      entry.immediate,
      entry.clustered,
      entry.replicaIdentity,
      entry.nullsNotDistinct,
      entry.accessMethod,
      entry.keyColumns,
      entry.includedColumns,
      entry.expressions,
      entry.predicate,
      entry.attributeOptions,
      entry.definition,
    ]),
    relations: catalog.relations.map((entry) => [
      entry.table,
      entry.kind,
      entry.persistence,
      entry.owner,
      entry.rowSecurity,
      entry.forceRowSecurity,
      entry.replicaIdentity,
      entry.isPartition,
      entry.options,
      entry.accessMethod,
      entry.extensionOwned,
    ]),
    toast: catalog.toast.map((entry) => [
      entry.baseTable,
      entry.present,
      entry.owner,
      entry.kind,
      entry.persistence,
      entry.accessMethod,
      entry.options,
      entry.indexes.map((index) => [
        index.owner,
        index.kind,
        index.persistence,
        index.options,
        index.accessMethod,
        index.valid,
        index.ready,
        index.live,
        index.unique,
        index.primary,
        index.immediate,
        index.clustered,
        index.replicaIdentity,
        index.nullsNotDistinct,
        index.keyColumns,
        index.includedColumns,
        index.expressions,
        index.predicate,
        index.attributeOptions,
      ]),
    ]),
    columns: catalog.columns.map((entry) => [
      entry.table,
      entry.name,
      entry.ordinal,
      entry.type,
      entry.notNull,
      entry.identity,
      entry.generated,
      entry.default,
      entry.collation,
    ]),
    routines: catalog.routines.map((entry) => [
      entry.name,
      entry.kind,
      entry.owner,
      entry.securityDefiner,
      entry.language,
      entry.config,
      entry.arguments,
      entry.result,
      entry.volatility,
      entry.strict,
      entry.leakproof,
      entry.parallel,
      entry.body,
    ]),
    sequences: catalog.sequences.map((entry) => [
      entry.name,
      entry.owner,
      entry.dataType,
      entry.start,
      entry.increment,
      entry.minimum,
      entry.maximum,
      entry.cache,
      entry.cycle,
      entry.ownedTable,
      entry.ownedColumn,
      entry.ownershipDependency,
    ]),
    triggers: catalog.triggers.map((entry) => [
      entry.name,
      entry.table,
      entry.enabled,
      entry.type,
      entry.when,
      entry.definition,
      entry.functionSchema,
      entry.functionName,
      entry.functionOwner,
      entry.functionLanguage,
      entry.functionSecurityDefiner,
      entry.functionConfig,
      entry.functionVolatility,
      entry.functionStrict,
      entry.functionBody,
    ]),
    types: catalog.types.map((entry) => [
      entry.name,
      entry.kind,
      entry.category,
      entry.owner,
      entry.relation,
      entry.element,
    ]),
  };
}

export function catalogAuthoritySha256(catalog) {
  const structure = catalogStructure(catalog);
  if (!structure) return null;
  return createHash("sha256").update(JSON.stringify(structure)).digest("hex");
}

function migrationPreflightSql() {
  const schema = CANARY_SCHEMA_NAME;
  return `
DO $preflight$
BEGIN
  IF pg_catalog.to_regnamespace('${schema}') IS NULL THEN
    RAISE EXCEPTION 'canary_schema_not_bootstrapped';
  END IF;
  IF (SELECT owner.rolname
      FROM pg_catalog.pg_namespace namespace
      JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
      WHERE namespace.nspname = '${schema}') <> '${CANARY_OWNER_DATABASE_USER}' THEN
    RAISE EXCEPTION 'canary_schema_owner_mismatch';
  END IF;
  IF pg_catalog.to_regclass('${schema}.schema_migrations') IS NOT NULL THEN
    RAISE EXCEPTION 'preexisting_canary_migration_history';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint foreign_key
    JOIN pg_catalog.pg_class parent_relation ON parent_relation.oid = foreign_key.confrelid
    JOIN pg_catalog.pg_namespace parent_namespace ON parent_namespace.oid = parent_relation.relnamespace
    JOIN pg_catalog.pg_class child_relation ON child_relation.oid = foreign_key.conrelid
    JOIN pg_catalog.pg_namespace child_namespace ON child_namespace.oid = child_relation.relnamespace
    WHERE foreign_key.contype = 'f'
      AND parent_namespace.nspname = '${schema}'
      AND child_namespace.nspname <> '${schema}'
  ) THEN
    RAISE EXCEPTION 'cross_schema_incoming_foreign_key';
  END IF;
  IF EXISTS (
    SELECT 1 FROM (
      SELECT collnamespace AS namespace_oid FROM pg_catalog.pg_collation
      UNION ALL SELECT oprnamespace FROM pg_catalog.pg_operator
      UNION ALL SELECT opcnamespace FROM pg_catalog.pg_opclass
      UNION ALL SELECT opfnamespace FROM pg_catalog.pg_opfamily
      UNION ALL SELECT connamespace FROM pg_catalog.pg_conversion
      UNION ALL SELECT cfgnamespace FROM pg_catalog.pg_ts_config
      UNION ALL SELECT dictnamespace FROM pg_catalog.pg_ts_dict
      UNION ALL SELECT prsnamespace FROM pg_catalog.pg_ts_parser
      UNION ALL SELECT tmplnamespace FROM pg_catalog.pg_ts_template
      UNION ALL SELECT stxnamespace FROM pg_catalog.pg_statistic_ext
    ) object_record
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_record.namespace_oid
    WHERE namespace.nspname = '${schema}'
  ) THEN
    RAISE EXCEPTION 'unexpected_preexisting_canary_exotic_object';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_publication publication WHERE publication.puballtables) THEN
    RAISE EXCEPTION 'all_tables_publication_includes_canary_schema';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_depend dependency
    CROSS JOIN LATERAL pg_catalog.pg_identify_object(
      dependency.classid, dependency.objid, dependency.objsubid
    ) dependent_object
    WHERE dependency.deptype = 'e'
      AND dependent_object.schema = '${schema}'
  ) THEN
    RAISE EXCEPTION 'extension_owned_canary_object';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_depend dependency
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = dependency.objid
    WHERE dependency.classid = 'pg_catalog.pg_namespace'::pg_catalog.regclass
      AND dependency.objsubid = 0
      AND dependency.deptype = 'e'
      AND namespace.nspname = '${schema}'
  ) THEN
    RAISE EXCEPTION 'extension_owned_canary_schema';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_subscription_rel subscription_relation
    JOIN pg_catalog.pg_class relation ON relation.oid = subscription_relation.srrelid
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = '${schema}'
  ) THEN
    RAISE EXCEPTION 'canary_subscription_relation';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_cast cast_record
    JOIN pg_catalog.pg_type source_type ON source_type.oid = cast_record.castsource
    JOIN pg_catalog.pg_namespace source_namespace ON source_namespace.oid = source_type.typnamespace
    JOIN pg_catalog.pg_type target_type ON target_type.oid = cast_record.casttarget
    JOIN pg_catalog.pg_namespace target_namespace ON target_namespace.oid = target_type.typnamespace
    WHERE source_namespace.nspname = '${schema}' OR target_namespace.nspname = '${schema}'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_transform transform_record
    JOIN pg_catalog.pg_type type_record ON type_record.oid = transform_record.trftype
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
    WHERE namespace.nspname = '${schema}'
  ) THEN
    RAISE EXCEPTION 'canary_schema_less_catalog_mapping';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_event_trigger event_trigger
    WHERE event_trigger.evtenabled <> 'D'
  ) THEN
    RAISE EXCEPTION 'canary_enabled_event_trigger';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_foreign_data_wrapper wrapper
    CROSS JOIN unnest(ARRAY[
      '${CANARY_OWNER_DATABASE_USER}',
      '${CANARY_MIGRATION_DATABASE_USER}',
      '${CANARY_RUNTIME_DATABASE_USER}',
      '${CANARY_EVALUATION_WRITER_DATABASE_USER}'
    ]::text[]) fixed_role(role_name)
    WHERE wrapper.fdwowner = fixed_role.role_name::pg_catalog.regrole
      OR pg_catalog.has_foreign_data_wrapper_privilege(fixed_role.role_name, wrapper.oid, 'USAGE')
  ) THEN
    RAISE EXCEPTION 'canary_foreign_data_wrapper_authority';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_foreign_server foreign_server
    CROSS JOIN unnest(ARRAY[
      '${CANARY_OWNER_DATABASE_USER}',
      '${CANARY_MIGRATION_DATABASE_USER}',
      '${CANARY_RUNTIME_DATABASE_USER}',
      '${CANARY_EVALUATION_WRITER_DATABASE_USER}'
    ]::text[]) fixed_role(role_name)
    WHERE pg_catalog.has_server_privilege(fixed_role.role_name, foreign_server.oid, 'USAGE')
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_user_mappings user_mapping
    WHERE user_mapping.usename = 'public'
      OR user_mapping.usename = ANY (ARRAY[
        '${CANARY_OWNER_DATABASE_USER}',
        '${CANARY_MIGRATION_DATABASE_USER}',
        '${CANARY_RUNTIME_DATABASE_USER}',
        '${CANARY_EVALUATION_WRITER_DATABASE_USER}'
      ]::text[])
  ) THEN
    RAISE EXCEPTION 'canary_foreign_server_authority';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = '${schema}'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc procedure
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = '${schema}'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_type type_record
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
    WHERE namespace.nspname = '${schema}'
  ) THEN
    RAISE EXCEPTION 'unexpected_preexisting_canary_object';
  END IF;
  IF (SELECT count(*)
      FROM pg_catalog.pg_namespace namespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))) acl
      WHERE namespace.nspname = '${schema}'
        AND acl.grantee = '${CANARY_OWNER_DATABASE_USER}'::pg_catalog.regrole
        AND acl.grantor = '${CANARY_OWNER_DATABASE_USER}'::pg_catalog.regrole
        AND acl.privilege_type IN ('USAGE', 'CREATE')
        AND NOT acl.is_grantable) <> 2
    OR EXISTS (
      SELECT 1
      FROM pg_catalog.pg_namespace namespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))) acl
      WHERE namespace.nspname = '${schema}'
        AND (acl.grantee <> '${CANARY_OWNER_DATABASE_USER}'::pg_catalog.regrole
          OR acl.grantor <> '${CANARY_OWNER_DATABASE_USER}'::pg_catalog.regrole
          OR acl.privilege_type NOT IN ('USAGE', 'CREATE')
          OR acl.is_grantable)
    ) THEN
    RAISE EXCEPTION 'bootstrapped_canary_schema_acl_mismatch';
  END IF;
END;
$preflight$;
`;
}

function migrationBody() {
  const schema = CANARY_SCHEMA_NAME;
  const runtimeRole = CANARY_RUNTIME_DATABASE_USER;
  const evaluationWriterRole = CANARY_EVALUATION_WRITER_DATABASE_USER;
  return `
REVOKE ALL ON SCHEMA ${schema} FROM PUBLIC;
CREATE TABLE IF NOT EXISTS ${schema}.schema_migrations (
  version integer CONSTRAINT schema_migrations_pkey PRIMARY KEY,
  checksum character(64) NOT NULL,
  catalog_authority_sha256 character(64) NOT NULL,
  catalog_fingerprint jsonb NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT schema_migrations_version_check CHECK (version > 0),
  CONSTRAINT schema_migrations_checksum_check CHECK (checksum ~ '^[0-9a-f]{64}$'),
  CONSTRAINT schema_migrations_catalog_authority_sha256_check CHECK (catalog_authority_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ${schema}.deployment_profiles (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  profile jsonb NOT NULL,
  registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT deployment_profiles_pkey PRIMARY KEY (profile_ref, profile_sha256),
  CONSTRAINT deployment_profiles_sha256_check CHECK (profile_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ${schema}.ingress_requests (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  nonce text NOT NULL,
  request_hash character(64) NOT NULL,
  expires_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT ingress_requests_pkey PRIMARY KEY (profile_ref, profile_sha256, nonce),
  CONSTRAINT ingress_requests_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT ingress_requests_request_hash_check CHECK (request_hash ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ${schema}.workflow_runs (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  run_id text NOT NULL,
  principal_ref text NOT NULL,
  payload_hash character(64) NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT workflow_runs_pkey PRIMARY KEY (profile_ref, profile_sha256, run_id),
  CONSTRAINT workflow_runs_payload_hash_key UNIQUE (profile_ref, profile_sha256, payload_hash),
  CONSTRAINT workflow_runs_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT workflow_runs_payload_hash_check CHECK (payload_hash ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ${schema}.action_states (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  proposal_id text NOT NULL,
  run_id text NOT NULL,
  principal_ref text NOT NULL,
  proposal_hash character(64) NOT NULL,
  effect_key character(64) NOT NULL,
  proposal jsonb NOT NULL,
  state jsonb NOT NULL,
  state_hash character(64) NOT NULL,
  revision bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT action_states_pkey PRIMARY KEY (profile_ref, profile_sha256, proposal_id),
  CONSTRAINT action_states_run_id_fkey FOREIGN KEY (profile_ref, profile_sha256, run_id) REFERENCES ${schema}.workflow_runs(profile_ref, profile_sha256, run_id),
  CONSTRAINT action_states_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT action_states_proposal_hash_key UNIQUE (profile_ref, profile_sha256, proposal_hash),
  CONSTRAINT action_states_effect_key_key UNIQUE (profile_ref, profile_sha256, effect_key),
  CONSTRAINT action_states_proposal_hash_check CHECK (proposal_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT action_states_effect_key_check CHECK (effect_key ~ '^[0-9a-f]{64}$'),
  CONSTRAINT action_states_state_hash_check CHECK (state_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT action_states_revision_check CHECK (revision >= 0)
);
CREATE TABLE IF NOT EXISTS ${schema}.action_effect_reservations (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  effect_key character(64) NOT NULL,
  proposal_id text NOT NULL,
  proposal_hash character(64) NOT NULL,
  principal_ref text NOT NULL,
  reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT action_effect_reservations_pkey PRIMARY KEY (profile_ref, profile_sha256, effect_key),
  CONSTRAINT action_effect_reservations_proposal_id_key UNIQUE (profile_ref, profile_sha256, proposal_id),
  CONSTRAINT action_effect_reservations_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT action_effect_reservations_effect_key_check CHECK (effect_key ~ '^[0-9a-f]{64}$'),
  CONSTRAINT action_effect_reservations_proposal_hash_check CHECK (proposal_hash ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ${schema}.action_events (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  event_sequence bigint GENERATED ALWAYS AS IDENTITY,
  proposal_id text NOT NULL,
  revision bigint NOT NULL,
  principal_ref text NOT NULL,
  event_type text NOT NULL,
  event_hash character(64) NOT NULL,
  event jsonb NOT NULL,
  resulting_state_hash character(64) NOT NULL,
  resulting_state jsonb NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT action_events_pkey PRIMARY KEY (profile_ref, profile_sha256, event_sequence),
  CONSTRAINT action_events_proposal_id_fkey FOREIGN KEY (profile_ref, profile_sha256, proposal_id) REFERENCES ${schema}.action_states(profile_ref, profile_sha256, proposal_id),
  CONSTRAINT action_events_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT action_events_proposal_id_revision_key UNIQUE (profile_ref, profile_sha256, proposal_id, revision),
  CONSTRAINT action_events_revision_check CHECK (revision > 0),
  CONSTRAINT action_events_event_hash_check CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT action_events_resulting_state_hash_check CHECK (resulting_state_hash ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ${schema}.reconciliation_leases (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  proposal_id text NOT NULL,
  lease_id text NOT NULL,
  principal_ref text NOT NULL,
  acquired_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revision bigint NOT NULL,
  CONSTRAINT reconciliation_leases_pkey PRIMARY KEY (profile_ref, profile_sha256, proposal_id),
  CONSTRAINT reconciliation_leases_lease_id_key UNIQUE (profile_ref, profile_sha256, lease_id),
  CONSTRAINT reconciliation_leases_proposal_id_fkey FOREIGN KEY (profile_ref, profile_sha256, proposal_id) REFERENCES ${schema}.action_states(profile_ref, profile_sha256, proposal_id),
  CONSTRAINT reconciliation_leases_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT reconciliation_leases_check CHECK (expires_at > acquired_at),
  CONSTRAINT reconciliation_leases_revision_check CHECK (revision >= 0)
);
CREATE TABLE IF NOT EXISTS ${schema}.audit_events (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  audit_sequence bigint GENERATED ALWAYS AS IDENTITY,
  request_hash character(64) NOT NULL,
  principal_ref text NOT NULL,
  operation text NOT NULL,
  entity_type text NOT NULL,
  entity_id text NOT NULL,
  before_hash character(64),
  after_hash character(64),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT audit_events_pkey PRIMARY KEY (profile_ref, profile_sha256, audit_sequence),
  CONSTRAINT audit_events_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT audit_events_request_hash_check CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT audit_events_before_hash_check CHECK (before_hash IS NULL OR before_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT audit_events_after_hash_check CHECK (after_hash IS NULL OR after_hash ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ${schema}.evaluation_candidates (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  candidate_id text NOT NULL,
  artifact_id text NOT NULL,
  artifact_revision text NOT NULL,
  artifact_sha256 character(64) NOT NULL,
  candidate_sha256 character(64) NOT NULL,
  candidate jsonb NOT NULL,
  policy_snapshot jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  evaluation_profile_sha256 character(64) NOT NULL,
  evaluation_policy_sha256 character(64) NOT NULL,
  CONSTRAINT evaluation_candidates_pkey PRIMARY KEY (profile_ref, profile_sha256, candidate_id),
  CONSTRAINT evaluation_candidates_sha256_key UNIQUE (profile_ref, profile_sha256, candidate_sha256),
  CONSTRAINT evaluation_candidates_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT evaluation_candidates_artifact_sha256_check CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evaluation_candidates_evaluation_profile_sha256_check CHECK (evaluation_profile_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evaluation_candidates_evaluation_policy_sha256_check CHECK (evaluation_policy_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evaluation_candidates_sha256_check CHECK (candidate_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ${schema}.evaluation_judge_results (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  result_id text NOT NULL,
  candidate_id text NOT NULL,
  judge_ref text NOT NULL,
  independence_key text NOT NULL,
  judge_class text NOT NULL,
  passed boolean NOT NULL,
  result_sha256 character(64) NOT NULL,
  receipt_sha256 character(64) NOT NULL,
  result jsonb NOT NULL,
  evaluated_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  evaluation_profile_sha256 character(64) NOT NULL,
  evaluation_policy_sha256 character(64) NOT NULL,
  CONSTRAINT evaluation_judge_results_pkey PRIMARY KEY (profile_ref, profile_sha256, result_id),
  CONSTRAINT evaluation_judge_results_candidate_judge_key UNIQUE (profile_ref, profile_sha256, candidate_id, judge_ref),
  CONSTRAINT evaluation_judge_results_candidate_origin_key UNIQUE (profile_ref, profile_sha256, candidate_id, independence_key),
  CONSTRAINT evaluation_judge_results_candidate_result_key UNIQUE (profile_ref, profile_sha256, candidate_id, result_id),
  CONSTRAINT evaluation_judge_results_candidate_receipt_key UNIQUE (profile_ref, profile_sha256, candidate_id, receipt_sha256),
  CONSTRAINT evaluation_judge_results_sha256_key UNIQUE (profile_ref, profile_sha256, result_sha256),
  CONSTRAINT evaluation_judge_results_candidate_fkey FOREIGN KEY (profile_ref, profile_sha256, candidate_id) REFERENCES ${schema}.evaluation_candidates(profile_ref, profile_sha256, candidate_id),
  CONSTRAINT evaluation_judge_results_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT evaluation_judge_results_evaluation_profile_sha256_check CHECK (evaluation_profile_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evaluation_judge_results_evaluation_policy_sha256_check CHECK (evaluation_policy_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evaluation_judge_results_receipt_sha256_check CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evaluation_judge_results_sha256_check CHECK (result_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ${schema}.evaluation_releases (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  release_id text NOT NULL,
  candidate_id text NOT NULL,
  evaluation_policy_ref text NOT NULL,
  evaluation_policy_sha256 character(64) NOT NULL,
  release_sha256 character(64) NOT NULL,
  mode text NOT NULL,
  passed boolean NOT NULL,
  release boolean NOT NULL,
  provider_release_eligible boolean NOT NULL DEFAULT false,
  release_record jsonb NOT NULL,
  policy_snapshot jsonb NOT NULL,
  evaluated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT evaluation_releases_pkey PRIMARY KEY (profile_ref, profile_sha256, release_id),
  CONSTRAINT evaluation_releases_release_candidate_key UNIQUE (profile_ref, profile_sha256, release_id, candidate_id),
  CONSTRAINT evaluation_releases_candidate_key UNIQUE (profile_ref, profile_sha256, candidate_id),
  CONSTRAINT evaluation_releases_sha256_key UNIQUE (profile_ref, profile_sha256, release_sha256),
  CONSTRAINT evaluation_releases_candidate_fkey FOREIGN KEY (profile_ref, profile_sha256, candidate_id) REFERENCES ${schema}.evaluation_candidates(profile_ref, profile_sha256, candidate_id),
  CONSTRAINT evaluation_releases_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT evaluation_releases_policy_sha256_check CHECK (evaluation_policy_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evaluation_releases_sha256_check CHECK (release_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evaluation_releases_shadow_check CHECK (mode = 'synthetic_shadow' AND passed AND release AND NOT provider_release_eligible AND expires_at > evaluated_at)
);
CREATE TABLE IF NOT EXISTS ${schema}.evaluation_release_judge_results (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  release_id text NOT NULL,
  candidate_id text NOT NULL,
  result_id text NOT NULL,
  receipt_sha256 character(64) NOT NULL,
  linked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT evaluation_release_judge_results_pkey PRIMARY KEY (profile_ref, profile_sha256, release_id, result_id),
  CONSTRAINT evaluation_release_judge_results_release_receipt_key UNIQUE (profile_ref, profile_sha256, release_id, receipt_sha256),
  CONSTRAINT evaluation_release_judge_results_release_candidate_fkey FOREIGN KEY (profile_ref, profile_sha256, release_id, candidate_id) REFERENCES ${schema}.evaluation_releases(profile_ref, profile_sha256, release_id, candidate_id),
  CONSTRAINT evaluation_release_judge_results_candidate_result_fkey FOREIGN KEY (profile_ref, profile_sha256, candidate_id, result_id) REFERENCES ${schema}.evaluation_judge_results(profile_ref, profile_sha256, candidate_id, result_id),
  CONSTRAINT evaluation_release_judge_results_candidate_receipt_fkey FOREIGN KEY (profile_ref, profile_sha256, candidate_id, receipt_sha256) REFERENCES ${schema}.evaluation_judge_results(profile_ref, profile_sha256, candidate_id, receipt_sha256),
  CONSTRAINT evaluation_release_judge_results_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT evaluation_release_judge_results_receipt_sha256_check CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ${schema}.evaluation_replay_tombstones (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  replay_ref text NOT NULL,
  release_id text NOT NULL,
  release_sha256 character(64) NOT NULL,
  record_sha256 character(64) NOT NULL,
  terminal_record jsonb NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT evaluation_replay_tombstones_pkey PRIMARY KEY (profile_ref, profile_sha256, replay_ref),
  CONSTRAINT evaluation_replay_tombstones_release_key UNIQUE (profile_ref, profile_sha256, release_id),
  CONSTRAINT evaluation_replay_tombstones_record_key UNIQUE (profile_ref, profile_sha256, record_sha256),
  CONSTRAINT evaluation_replay_tombstones_release_fkey FOREIGN KEY (profile_ref, profile_sha256, release_id) REFERENCES ${schema}.evaluation_releases(profile_ref, profile_sha256, release_id),
  CONSTRAINT evaluation_replay_tombstones_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT evaluation_replay_tombstones_release_sha256_check CHECK (release_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT evaluation_replay_tombstones_record_sha256_check CHECK (record_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE OR REPLACE FUNCTION ${schema}.canonical_jsonb(p_value jsonb) RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
  result text;
BEGIN
  CASE pg_catalog.jsonb_typeof(p_value)
    WHEN 'object' THEN
      SELECT '{' || COALESCE(
        pg_catalog.string_agg(
          pg_catalog.to_jsonb(object_entry.key)::text || ':' || ${schema}.canonical_jsonb(object_entry.value),
          ',' ORDER BY object_entry.key COLLATE "C"
        ),
        ''
      ) || '}'
      INTO result
      FROM pg_catalog.jsonb_each(p_value) object_entry;
    WHEN 'array' THEN
      SELECT '[' || COALESCE(
        pg_catalog.string_agg(${schema}.canonical_jsonb(array_entry.value), ',' ORDER BY array_entry.ordinality),
        ''
      ) || ']'
      INTO result
      FROM pg_catalog.jsonb_array_elements(p_value) WITH ORDINALITY array_entry(value, ordinality);
    ELSE
      result := p_value::text;
  END CASE;
  RETURN result;
END;
$function$;
CREATE OR REPLACE FUNCTION ${schema}.persist_authorized_evaluation(
  p_profile_ref text,
  p_profile_sha256 character(64),
  p_candidate_sha256 character(64),
  p_candidate jsonb,
  p_judge_results jsonb,
  p_release_id text,
  p_release jsonb
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  judge_result jsonb;
  current_result_id text;
  current_receipt_sha256 character(64);
  required_gate text;
BEGIN
  IF session_user <> '${evaluationWriterRole}'
     OR pg_catalog.jsonb_typeof(p_candidate) <> 'object'
     OR pg_catalog.jsonb_typeof(p_judge_results) <> 'array'
     OR pg_catalog.jsonb_typeof(p_release) <> 'object'
     OR p_candidate_sha256 !~ '^[0-9a-f]{64}$'
     OR p_candidate->>'artifactSha256' !~ '^[0-9a-f]{64}$'
     OR p_candidate->>'evidenceSha256' !~ '^[0-9a-f]{64}$'
     OR p_candidate->>'evaluationPayloadSha256' !~ '^[0-9a-f]{64}$'
     OR p_candidate->>'evaluationProfileSha256' !~ '^[0-9a-f]{64}$'
     OR p_candidate->>'policySha256' !~ '^[0-9a-f]{64}$'
     OR p_candidate->>'deterministicResultsSha256' !~ '^[0-9a-f]{64}$'
     OR p_release->>'releaseSha256' !~ '^[0-9a-f]{64}$'
     OR p_candidate_sha256 <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       ${schema}.canonical_jsonb(pg_catalog.jsonb_build_object(
         'digestRevision', 'EvaluationCandidate.store.sha256.v1',
         'profileRef', p_profile_ref,
         'profileSha256', p_profile_sha256,
         'candidate', p_candidate
       )),
       'UTF8'
     )), 'hex')
     OR p_candidate->>'runRef' <> 'evaluation-run:' || pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       ${schema}.canonical_jsonb(
         p_candidate - 'runRef' - 'artifact' - 'evaluationPayload' - 'profile' - 'deterministic' - 'effectObservation' - 'policySnapshot'
       ),
       'UTF8'
     )), 'hex')
     OR p_candidate->>'evaluationPayloadSha256' <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       ${schema}.canonical_jsonb(p_candidate->'evaluationPayload'),
       'UTF8'
     )), 'hex')
     OR p_candidate->>'evaluationProfileSha256' <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       ${schema}.canonical_jsonb((p_candidate->'profile') - 'evaluationProfileSha256'),
       'UTF8'
     )), 'hex')
     OR p_candidate->>'deterministicResultsSha256' <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       ${schema}.canonical_jsonb(p_candidate->'deterministic'->'checks'),
       'UTF8'
     )), 'hex')
     OR p_candidate->'deterministic'->>'resultsSha256' <> p_candidate->>'deterministicResultsSha256'
     OR p_candidate->'deterministic'->'checkIds' <> p_candidate->'deterministicCheckIds'
     OR p_candidate->>'artifactSha256' <> p_candidate->'artifact'->>'artifactSha256'
     OR p_candidate->>'artifactSha256' <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       ${schema}.canonical_jsonb((p_candidate->'artifact') - 'artifactSha256'),
       'UTF8'
     )), 'hex')
     OR p_candidate->>'evidenceSha256' <> p_candidate->'artifact'->'evidenceBundle'->>'bundleSha256'
     OR p_candidate->>'evidenceSha256' <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       ${schema}.canonical_jsonb((p_candidate->'artifact'->'evidenceBundle') - 'bundleSha256'),
       'UTF8'
     )), 'hex')
     OR p_candidate->'profile'->>'deploymentProfileRef' <> p_profile_ref
     OR p_candidate->'profile'->>'deploymentProfileSha256' <> p_profile_sha256
     OR p_candidate->'effectObservation'->>'observationSha256' <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       ${schema}.canonical_jsonb((p_candidate->'effectObservation') - 'observationSha256'),
       'UTF8'
     )), 'hex')
     OR p_candidate->'policySnapshot'->>'policySha256' <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       ${schema}.canonical_jsonb((p_candidate->'policySnapshot') - 'policySha256'),
       'UTF8'
     )), 'hex')
     OR p_release->>'releaseSha256' <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       ${schema}.canonical_jsonb(p_release - 'releaseSha256'),
       'UTF8'
     )), 'hex')
     OR p_candidate->>'deploymentProfileRef' <> p_profile_ref
     OR p_candidate->>'deploymentProfileSha256' <> p_profile_sha256
     OR p_release->>'deploymentProfileRef' <> p_profile_ref
     OR p_release->>'deploymentProfileSha256' <> p_profile_sha256
     OR p_release->>'candidateId' <> p_candidate->>'runRef'
     OR p_release->>'policySha256' <> p_candidate->>'policySha256'
     OR p_candidate->'policySnapshot'->>'policySha256' <> p_candidate->>'policySha256'
     OR p_release->>'releaseSha256' <> pg_catalog.substr(p_release_id, 20)
     OR p_release->>'mode' <> 'shadow'
     OR p_release->>'passed' <> 'true'
     OR p_release->>'release' <> 'true'
     OR p_candidate->'policySnapshot'->>'selfReviewAllowed' <> 'false'
     OR p_candidate->>'sideEffectCount' <> '0'
     OR p_candidate->'deterministicCheckIds' <> p_candidate->'policySnapshot'->'requiredCheckIds'
     OR p_release->'deterministicCheckIds' <> p_candidate->'deterministicCheckIds'
     OR p_release->>'evaluatedAt' IS NULL
     OR p_release->>'expiresAt' <> p_candidate->>'expiresAt'
     OR (p_release->>'evaluatedAt')::timestamptz < (p_candidate->>'evaluationStartedAt')::timestamptz
     OR (p_release->>'evaluatedAt')::timestamptz >= (p_candidate->>'expiresAt')::timestamptz
     OR EXTRACT(epoch FROM ((p_release->>'evaluatedAt')::timestamptz - (p_candidate->>'evaluationStartedAt')::timestamptz)) * 1000 >
        (p_candidate->'policySnapshot'->>'maximumEvaluationRuntimeMs')::bigint
     OR EXTRACT(epoch FROM ((p_candidate->>'expiresAt')::timestamptz - (p_candidate->>'evaluationStartedAt')::timestamptz)) * 1000 >
        (p_candidate->'policySnapshot'->>'maximumReleaseLifetimeMs')::bigint
     OR NOT EXISTS (
       SELECT 1 FROM ${schema}.deployment_profiles deployment_profile
       WHERE deployment_profile.profile_ref = p_profile_ref
         AND deployment_profile.profile_sha256 = p_profile_sha256
         AND deployment_profile.profile->>'profileRef' = p_profile_ref
         AND deployment_profile.profile->>'profileSha256' = p_profile_sha256
         AND p_candidate->'policySnapshot'->>'policyRef' = deployment_profile.profile->'evalPolicy'->>'policyRef'
         AND p_candidate->'policySnapshot'->'requiredGates' = deployment_profile.profile->'evalPolicy'->'requiredGates'
         AND p_candidate->'policySnapshot'->'requiredCheckIds' = deployment_profile.profile->'evalPolicy'->'requiredDeterministicCheckIds'
         AND p_candidate->'policySnapshot'->'requiredJudgeClasses' = deployment_profile.profile->'evalPolicy'->'judgeClasses'
         AND p_candidate->'policySnapshot'->>'minimumIndependentJudges' = deployment_profile.profile->'evalPolicy'->>'minimumIndependentJudges'
         AND p_candidate->'policySnapshot'->>'independentOriginsRequired' = deployment_profile.profile->'evalPolicy'->>'independentOriginsRequired'
         AND p_candidate->'policySnapshot'->>'selfReviewAllowed' = deployment_profile.profile->'evalPolicy'->>'selfReviewAllowed'
         AND p_candidate->'policySnapshot'->>'sideEffectBudget' = deployment_profile.profile->'evalPolicy'->>'sideEffectBudget'
         AND p_candidate->'policySnapshot'->>'maximumRepairAttempts' = deployment_profile.profile->'evalPolicy'->>'maximumRepairAttempts'
         AND p_candidate->'policySnapshot'->>'minimumScore' = deployment_profile.profile->'evalPolicy'->>'minimumScore'
         AND p_candidate->'policySnapshot'->>'maximumScoreSpread' = deployment_profile.profile->'evalPolicy'->>'maximumScoreSpread'
         AND p_candidate->'policySnapshot'->>'maximumEvaluationRuntimeMs' = deployment_profile.profile->'evalPolicy'->>'maximumEvaluationRuntimeMs'
         AND p_candidate->'policySnapshot'->>'maximumReleaseLifetimeMs' = deployment_profile.profile->'grantPolicy'->>'maximumEvalReleaseLifetimeMs'
         AND p_candidate->'policySnapshot'->'trustedJudges' = deployment_profile.profile->'evalPolicy'->'trustedJudgeRoots'
     )
     OR pg_catalog.jsonb_array_length(p_judge_results) <> (p_candidate->'policySnapshot'->>'minimumIndependentJudges')::integer
     OR pg_catalog.jsonb_array_length(p_release->'judges') <> pg_catalog.jsonb_array_length(p_judge_results)
  THEN
    RAISE EXCEPTION 'invalid_authorized_evaluation';
  END IF;
  FOR required_gate IN SELECT pg_catalog.jsonb_array_elements_text(p_candidate->'policySnapshot'->'requiredGates') LOOP
    IF EXISTS (
      SELECT 1 FROM pg_catalog.jsonb_array_elements(p_judge_results) result
      WHERE result->'gateResults'->>required_gate <> 'true'
         OR NOT (result->'gateResults' ? required_gate)
    ) THEN
      RAISE EXCEPTION 'invalid_authorized_evaluation_gate';
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.jsonb_array_elements(p_judge_results) result
    WHERE result->>'runRef' <> p_candidate->>'runRef'
       OR result->>'artifactSha256' <> p_candidate->>'artifactSha256'
       OR result->>'evidenceSha256' <> p_candidate->>'evidenceSha256'
       OR result->>'evaluationPayloadSha256' <> p_candidate->>'evaluationPayloadSha256'
       OR result->>'policySha256' <> p_candidate->>'policySha256'
       OR result->>'deploymentProfileSha256' <> p_profile_sha256
       OR result->>'evaluationProfileSha256' <> p_candidate->>'evaluationProfileSha256'
       OR result->>'deterministicResultsSha256' <> p_candidate->>'deterministicResultsSha256'
       OR result->>'passed' <> 'true'
       OR result->>'sideEffectCount' <> '0'
       OR result->'failures' <> '[]'::jsonb
       OR result->>'receiptSha256' !~ '^[0-9a-f]{64}$'
       OR result->>'receiptSha256' <> pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
         ${schema}.canonical_jsonb(result - 'receiptSha256' - 'signature'),
         'UTF8'
       )), 'hex')
       OR pg_catalog.length(result->>'signature') < 80
       OR pg_catalog.length(result->>'signature') > 120
       OR result->>'signature' !~ '^[A-Za-z0-9_-]+$'
       OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(result->'scores')) <> 5
       OR EXISTS (
         SELECT 1 FROM pg_catalog.jsonb_each_text(result->'scores') score
         WHERE score.key <> ALL (ARRAY['accuracy','grounding','safety','voice','usefulness'])
            OR score.value !~ '^[1-5]$'
       )
       OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(result->'gateResults')) <>
          pg_catalog.jsonb_array_length(p_candidate->'policySnapshot'->'requiredGates')
       OR (result->>'issuedAt')::timestamptz < (p_candidate->>'evaluationStartedAt')::timestamptz
       OR (result->>'issuedAt')::timestamptz > (p_release->>'evaluatedAt')::timestamptz
       OR (result->>'expiresAt')::timestamptz < (p_candidate->>'expiresAt')::timestamptz
       OR NOT EXISTS (
         SELECT 1 FROM pg_catalog.jsonb_array_elements(p_candidate->'policySnapshot'->'trustedJudges') trusted_judge
         WHERE trusted_judge->>'keyId' = result->>'keyId'
           AND trusted_judge->>'judgeRef' = result->>'judgeRef'
           AND trusted_judge->>'judgeClass' = result->>'judgeClass'
           AND trusted_judge->>'originRef' = result->>'originRef'
       )
       OR EXISTS (
         SELECT 1 FROM ${schema}.deployment_profiles deployment_profile
         WHERE deployment_profile.profile_ref = p_profile_ref
           AND deployment_profile.profile_sha256 = p_profile_sha256
           AND result->>'judgeRef' IN (
             deployment_profile.profile->'identity'->>'humanPrincipalRef',
             deployment_profile.profile->'identity'->>'qmPrincipalRef',
             deployment_profile.profile->'agent'->>'agentId'
           )
       )
       OR NOT EXISTS (
         SELECT 1 FROM pg_catalog.jsonb_array_elements(p_release->'judges') release_judge
         WHERE release_judge->>'judgeRef' = result->>'judgeRef'
           AND release_judge->>'independenceKey' = result->>'originRef'
           AND release_judge->>'receiptSha256' = result->>'receiptSha256'
       )
  ) THEN
    RAISE EXCEPTION 'invalid_authorized_evaluation_judge_linkage';
  END IF;
  IF (SELECT count(DISTINCT result->>'judgeRef') FROM pg_catalog.jsonb_array_elements(p_judge_results) result) <>
       pg_catalog.jsonb_array_length(p_judge_results)
     OR (SELECT count(DISTINCT result->>'originRef') FROM pg_catalog.jsonb_array_elements(p_judge_results) result) <>
       pg_catalog.jsonb_array_length(p_judge_results)
     OR (SELECT count(DISTINCT result->>'judgeClass') FROM pg_catalog.jsonb_array_elements(p_judge_results) result) <>
       pg_catalog.jsonb_array_length(p_judge_results)
  THEN
    RAISE EXCEPTION 'invalid_authorized_evaluation_quorum';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.unnest(ARRAY['accuracy','grounding','safety','voice','usefulness']) AS score_name(value)
    WHERE (SELECT pg_catalog.avg((result->'scores'->>score_name.value)::numeric)
           FROM pg_catalog.jsonb_array_elements(p_judge_results) result) <
          (p_candidate->'policySnapshot'->>'minimumScore')::numeric
       OR (SELECT pg_catalog.max((result->'scores'->>score_name.value)::integer) -
                  pg_catalog.min((result->'scores'->>score_name.value)::integer)
           FROM pg_catalog.jsonb_array_elements(p_judge_results) result) >
          (p_candidate->'policySnapshot'->>'maximumScoreSpread')::integer
  ) THEN
    RAISE EXCEPTION 'invalid_authorized_evaluation_scores';
  END IF;
  INSERT INTO ${schema}.evaluation_candidates
    (profile_ref, profile_sha256, candidate_id, artifact_id, artifact_revision, artifact_sha256,
     evaluation_profile_sha256, evaluation_policy_sha256, candidate_sha256, candidate, policy_snapshot)
  VALUES
    (p_profile_ref, p_profile_sha256, p_candidate->>'runRef', p_candidate->>'artifactRef',
     p_candidate->>'artifactRevision', p_candidate->>'artifactSha256', p_candidate->>'evaluationProfileSha256',
     p_candidate->>'policySha256', p_candidate_sha256, p_candidate, p_candidate->'policySnapshot')
  ON CONFLICT ON CONSTRAINT evaluation_candidates_pkey DO NOTHING;
  IF NOT EXISTS (
    SELECT 1 FROM ${schema}.evaluation_candidates stored_candidate
    WHERE stored_candidate.profile_ref = p_profile_ref
      AND stored_candidate.profile_sha256 = p_profile_sha256
      AND stored_candidate.candidate_id = p_candidate->>'runRef'
      AND stored_candidate.candidate_sha256 = p_candidate_sha256
      AND stored_candidate.candidate = p_candidate
      AND stored_candidate.policy_snapshot = p_candidate->'policySnapshot'
  ) THEN
    RAISE EXCEPTION 'evaluation_candidate_conflict';
  END IF;
  FOR judge_result IN SELECT value FROM pg_catalog.jsonb_array_elements(p_judge_results) LOOP
    current_receipt_sha256 := judge_result->>'receiptSha256';
    current_result_id := 'evaluation-judge-result:' || current_receipt_sha256;
    INSERT INTO ${schema}.evaluation_judge_results
      (profile_ref, profile_sha256, result_id, candidate_id, judge_ref, independence_key, judge_class,
       passed, evaluation_profile_sha256, evaluation_policy_sha256, result_sha256, receipt_sha256, result, evaluated_at)
    VALUES
      (p_profile_ref, p_profile_sha256, current_result_id, p_candidate->>'runRef', judge_result->>'judgeRef',
       judge_result->>'originRef', judge_result->>'judgeClass', true, judge_result->>'evaluationProfileSha256',
       judge_result->>'policySha256', current_receipt_sha256, current_receipt_sha256, judge_result,
       (judge_result->>'issuedAt')::timestamptz)
    ON CONFLICT ON CONSTRAINT evaluation_judge_results_pkey DO NOTHING;
    IF NOT EXISTS (
      SELECT 1 FROM ${schema}.evaluation_judge_results stored_result
      WHERE stored_result.profile_ref = p_profile_ref
        AND stored_result.profile_sha256 = p_profile_sha256
        AND stored_result.result_id = current_result_id
        AND stored_result.candidate_id = p_candidate->>'runRef'
        AND stored_result.result_sha256 = current_receipt_sha256
        AND stored_result.receipt_sha256 = current_receipt_sha256
        AND stored_result.result = judge_result
    ) THEN
      RAISE EXCEPTION 'evaluation_judge_result_conflict';
    END IF;
  END LOOP;
  INSERT INTO ${schema}.evaluation_releases
    (profile_ref, profile_sha256, release_id, candidate_id, evaluation_policy_ref,
     evaluation_policy_sha256, release_sha256, mode, passed, release, provider_release_eligible,
     release_record, policy_snapshot, evaluated_at, expires_at)
  VALUES
    (p_profile_ref, p_profile_sha256, p_release_id, p_candidate->>'runRef', p_release->>'policyRef',
     p_release->>'policySha256', p_release->>'releaseSha256', 'synthetic_shadow', true, true, false,
     p_release, p_candidate->'policySnapshot', (p_release->>'evaluatedAt')::timestamptz,
     (p_release->>'expiresAt')::timestamptz)
  ON CONFLICT ON CONSTRAINT evaluation_releases_pkey DO NOTHING;
  IF NOT EXISTS (
    SELECT 1 FROM ${schema}.evaluation_releases stored_release
    WHERE stored_release.profile_ref = p_profile_ref
      AND stored_release.profile_sha256 = p_profile_sha256
      AND stored_release.release_id = p_release_id
      AND stored_release.candidate_id = p_candidate->>'runRef'
      AND stored_release.release_sha256 = p_release->>'releaseSha256'
      AND stored_release.release_record = p_release
      AND stored_release.policy_snapshot = p_candidate->'policySnapshot'
  ) THEN
    RAISE EXCEPTION 'evaluation_release_conflict';
  END IF;
  FOR judge_result IN SELECT value FROM pg_catalog.jsonb_array_elements(p_judge_results) LOOP
    current_receipt_sha256 := judge_result->>'receiptSha256';
    current_result_id := 'evaluation-judge-result:' || current_receipt_sha256;
    INSERT INTO ${schema}.evaluation_release_judge_results
      (profile_ref, profile_sha256, release_id, candidate_id, result_id, receipt_sha256)
    VALUES
      (p_profile_ref, p_profile_sha256, p_release_id, p_candidate->>'runRef', current_result_id, current_receipt_sha256)
    ON CONFLICT ON CONSTRAINT evaluation_release_judge_results_pkey DO NOTHING;
    IF NOT EXISTS (
      SELECT 1 FROM ${schema}.evaluation_release_judge_results stored_link
      WHERE stored_link.profile_ref = p_profile_ref
        AND stored_link.profile_sha256 = p_profile_sha256
        AND stored_link.release_id = p_release_id
        AND stored_link.candidate_id = p_candidate->>'runRef'
        AND stored_link.result_id = current_result_id
        AND stored_link.receipt_sha256 = current_receipt_sha256
    ) THEN
      RAISE EXCEPTION 'evaluation_release_linkage_conflict';
    END IF;
  END LOOP;
END;
$function$;
CREATE TABLE IF NOT EXISTS ${schema}.surface_outbox_events (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  event_id text NOT NULL,
  deployment_binding_sha256 character(64) NOT NULL,
  outbox_payload_sha256 character(64) NOT NULL,
  artifact_id text NOT NULL,
  artifact_revision text NOT NULL,
  artifact_sha256 character(64) NOT NULL,
  eval_receipt_sha256 character(64) NOT NULL,
  evaluation_release_id text NOT NULL,
  outbox_item jsonb NOT NULL,
  queued_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT surface_outbox_events_pkey PRIMARY KEY (profile_ref, profile_sha256, event_id),
  CONSTRAINT surface_outbox_events_outbox_payload_sha256_key UNIQUE (profile_ref, profile_sha256, outbox_payload_sha256),
  CONSTRAINT surface_outbox_events_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT surface_outbox_events_eval_release_fkey FOREIGN KEY (profile_ref, profile_sha256, evaluation_release_id) REFERENCES ${schema}.evaluation_releases(profile_ref, profile_sha256, release_id),
  CONSTRAINT surface_outbox_events_deployment_binding_sha256_check CHECK (deployment_binding_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_outbox_events_outbox_payload_sha256_check CHECK (outbox_payload_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_outbox_events_artifact_sha256_check CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_outbox_events_eval_receipt_sha256_check CHECK (eval_receipt_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ${schema}.surface_outbox_states (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  event_id text NOT NULL,
  status text NOT NULL,
  claim_ref text,
  claim_owner_ref text,
  claim_acquired_at timestamptz,
  claim_expires_at timestamptz,
  failure_code text,
  revision bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT surface_outbox_states_pkey PRIMARY KEY (profile_ref, profile_sha256, event_id),
  CONSTRAINT surface_outbox_states_event_id_fkey FOREIGN KEY (profile_ref, profile_sha256, event_id) REFERENCES ${schema}.surface_outbox_events(profile_ref, profile_sha256, event_id),
  CONSTRAINT surface_outbox_states_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT surface_outbox_states_revision_check CHECK (revision >= 0),
  CONSTRAINT surface_outbox_states_check CHECK (
    status IN ('pending', 'claimed', 'delivered', 'failed', 'outcome_unknown')
    AND ((status = 'claimed' AND claim_ref IS NOT NULL AND claim_owner_ref IS NOT NULL AND claim_acquired_at IS NOT NULL AND claim_expires_at > claim_acquired_at AND failure_code IS NULL)
      OR (status <> 'claimed' AND claim_ref IS NULL AND claim_owner_ref IS NULL AND claim_acquired_at IS NULL AND claim_expires_at IS NULL))
    AND ((status = 'failed' AND failure_code IS NOT NULL) OR (status <> 'failed' AND failure_code IS NULL))
  )
);
CREATE TABLE IF NOT EXISTS ${schema}.surface_delivery_reservations (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  delivery_key character(64) NOT NULL,
  outbox_event_id text NOT NULL,
  outbox_payload_sha256 character(64) NOT NULL,
  artifact_sha256 character(64) NOT NULL,
  deployment_binding_sha256 character(64) NOT NULL,
  identity_resolution_sha256 character(64) NOT NULL,
  target_binding_sha256 character(64) NOT NULL,
  message_sha256 character(64) NOT NULL,
  attempt_ref text NOT NULL,
  identity_resolution jsonb NOT NULL,
  publication jsonb NOT NULL,
  status text NOT NULL,
  revision bigint NOT NULL,
  reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  attempted_at timestamptz,
  completed_at timestamptz,
  reconciliation_ref text,
  reconciliation_owner_ref text,
  reconciliation_acquired_at timestamptz,
  reconciliation_expires_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT surface_delivery_reservations_pkey PRIMARY KEY (profile_ref, profile_sha256, delivery_key),
  CONSTRAINT surface_delivery_reservations_outbox_event_id_key UNIQUE (profile_ref, profile_sha256, outbox_event_id),
  CONSTRAINT surface_delivery_reservations_attempt_ref_key UNIQUE (profile_ref, profile_sha256, attempt_ref),
  CONSTRAINT surface_delivery_reservations_outbox_event_id_fkey FOREIGN KEY (profile_ref, profile_sha256, outbox_event_id) REFERENCES ${schema}.surface_outbox_events(profile_ref, profile_sha256, event_id),
  CONSTRAINT surface_delivery_reservations_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT surface_delivery_reservations_delivery_key_check CHECK (delivery_key ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_reservations_outbox_payload_sha256_check CHECK (outbox_payload_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_reservations_artifact_sha256_check CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_reservations_deployment_binding_sha256_check CHECK (deployment_binding_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_reservations_identity_resolution_sha256_check CHECK (identity_resolution_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_reservations_target_binding_sha256_check CHECK (target_binding_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_reservations_message_sha256_check CHECK (message_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_reservations_revision_check CHECK (revision >= 0),
  CONSTRAINT surface_delivery_reservations_check CHECK (
    status IN ('reserved', 'attempting', 'outcome_unknown', 'verified', 'failed')
    AND ((status = 'reserved' AND attempted_at IS NULL AND completed_at IS NULL)
      OR (status IN ('attempting', 'outcome_unknown') AND attempted_at IS NOT NULL AND completed_at IS NULL)
      OR (status IN ('verified', 'failed') AND attempted_at IS NOT NULL AND completed_at IS NOT NULL))
    AND ((reconciliation_ref IS NULL AND reconciliation_owner_ref IS NULL AND reconciliation_acquired_at IS NULL AND reconciliation_expires_at IS NULL)
      OR (status = 'outcome_unknown' AND reconciliation_ref IS NOT NULL AND reconciliation_owner_ref IS NOT NULL AND reconciliation_acquired_at IS NOT NULL AND reconciliation_expires_at > reconciliation_acquired_at))
  )
);
CREATE TABLE IF NOT EXISTS ${schema}.surface_delivery_receipts (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  receipt_sequence bigint GENERATED ALWAYS AS IDENTITY,
  delivery_key character(64) NOT NULL,
  revision bigint NOT NULL,
  status text NOT NULL,
  receipt_sha256 character(64) NOT NULL,
  receipt jsonb NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT surface_delivery_receipts_pkey PRIMARY KEY (profile_ref, profile_sha256, receipt_sequence),
  CONSTRAINT surface_delivery_receipts_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT surface_delivery_receipts_delivery_key_fkey FOREIGN KEY (profile_ref, profile_sha256, delivery_key) REFERENCES ${schema}.surface_delivery_reservations(profile_ref, profile_sha256, delivery_key),
  CONSTRAINT surface_delivery_receipts_delivery_key_revision_key UNIQUE (profile_ref, profile_sha256, delivery_key, revision),
  CONSTRAINT surface_delivery_receipts_receipt_sha256_key UNIQUE (profile_ref, profile_sha256, receipt_sha256),
  CONSTRAINT surface_delivery_receipts_revision_check CHECK (revision > 0),
  CONSTRAINT surface_delivery_receipts_receipt_sha256_check CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_receipts_status_check CHECK (status IN ('verified', 'failed', 'outcome_unknown'))
);
CREATE TABLE IF NOT EXISTS ${schema}.surface_delivery_tombstones (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  delivery_key character(64) NOT NULL,
  outbox_event_id text NOT NULL,
  outbox_payload_sha256 character(64) NOT NULL,
  deployment_binding_sha256 character(64) NOT NULL,
  artifact_sha256 character(64) NOT NULL,
  identity_resolution_sha256 character(64) NOT NULL,
  target_binding_sha256 character(64) NOT NULL,
  message_sha256 character(64) NOT NULL,
  terminal_status text NOT NULL,
  record_sha256 character(64) NOT NULL,
  terminal_record jsonb NOT NULL,
  completed_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT surface_delivery_tombstones_pkey PRIMARY KEY (profile_ref, profile_sha256, delivery_key),
  CONSTRAINT surface_delivery_tombstones_outbox_event_id_key UNIQUE (profile_ref, profile_sha256, outbox_event_id),
  CONSTRAINT surface_delivery_tombstones_outbox_payload_sha256_key UNIQUE (profile_ref, profile_sha256, outbox_payload_sha256),
  CONSTRAINT surface_delivery_tombstones_record_sha256_key UNIQUE (profile_ref, profile_sha256, record_sha256),
  CONSTRAINT surface_delivery_tombstones_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT surface_delivery_tombstones_delivery_key_check CHECK (delivery_key ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_tombstones_outbox_payload_sha256_check CHECK (outbox_payload_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_tombstones_deployment_binding_sha256_check CHECK (deployment_binding_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_tombstones_artifact_sha256_check CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_tombstones_identity_resolution_sha256_check CHECK (identity_resolution_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_tombstones_target_binding_sha256_check CHECK (target_binding_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_tombstones_message_sha256_check CHECK (message_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_tombstones_record_sha256_check CHECK (record_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_delivery_tombstones_status_check CHECK (terminal_status IN ('verified', 'failed'))
);
CREATE TABLE IF NOT EXISTS ${schema}.surface_event_tombstones (
  profile_ref text NOT NULL,
  profile_sha256 character(64) NOT NULL,
  event_id text NOT NULL,
  deployment_binding_sha256 character(64) NOT NULL,
  outbox_payload_sha256 character(64) NOT NULL,
  artifact_id text NOT NULL,
  artifact_revision text NOT NULL,
  artifact_sha256 character(64) NOT NULL,
  eval_receipt_sha256 character(64) NOT NULL,
  identity_resolution_sha256 character(64),
  target_binding_sha256 character(64),
  message_sha256 character(64),
  failure_code text NOT NULL,
  event_identity_sha256 character(64) NOT NULL,
  record_sha256 character(64) NOT NULL,
  terminal_record jsonb NOT NULL,
  completed_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT surface_event_tombstones_pkey PRIMARY KEY (profile_ref, profile_sha256, event_id),
  CONSTRAINT surface_event_tombstones_outbox_payload_sha256_key UNIQUE (profile_ref, profile_sha256, outbox_payload_sha256),
  CONSTRAINT surface_event_tombstones_event_identity_sha256_key UNIQUE (profile_ref, profile_sha256, event_identity_sha256),
  CONSTRAINT surface_event_tombstones_record_sha256_key UNIQUE (profile_ref, profile_sha256, record_sha256),
  CONSTRAINT surface_event_tombstones_profile_fkey FOREIGN KEY (profile_ref, profile_sha256) REFERENCES ${schema}.deployment_profiles(profile_ref, profile_sha256),
  CONSTRAINT surface_event_tombstones_deployment_binding_sha256_check CHECK (deployment_binding_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_event_tombstones_outbox_payload_sha256_check CHECK (outbox_payload_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_event_tombstones_artifact_sha256_check CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_event_tombstones_eval_receipt_sha256_check CHECK (eval_receipt_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_event_tombstones_identity_resolution_sha256_check CHECK (identity_resolution_sha256 IS NULL OR identity_resolution_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_event_tombstones_target_binding_sha256_check CHECK (target_binding_sha256 IS NULL OR target_binding_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_event_tombstones_message_sha256_check CHECK (message_sha256 IS NULL OR message_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_event_tombstones_event_identity_sha256_check CHECK (event_identity_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_event_tombstones_record_sha256_check CHECK (record_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT surface_event_tombstones_failure_check CHECK (
    (failure_code = 'eval_release_expired' AND identity_resolution_sha256 IS NULL AND target_binding_sha256 IS NULL AND message_sha256 IS NULL)
    OR (failure_code = 'identity_resolution_expired' AND identity_resolution_sha256 IS NOT NULL AND target_binding_sha256 IS NOT NULL AND message_sha256 IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS action_events_proposal_recorded_idx ON ${schema}.action_events (profile_ref, profile_sha256, proposal_id, recorded_at);
CREATE INDEX IF NOT EXISTS audit_events_entity_recorded_idx ON ${schema}.audit_events (profile_ref, profile_sha256, entity_type, entity_id, recorded_at);
CREATE INDEX IF NOT EXISTS ingress_requests_expires_idx ON ${schema}.ingress_requests (profile_ref, profile_sha256, expires_at);
CREATE INDEX IF NOT EXISTS evaluation_releases_claim_idx ON ${schema}.evaluation_releases (profile_ref, profile_sha256, expires_at, release_id) WHERE mode = 'synthetic_shadow' AND passed AND release AND NOT provider_release_eligible;
CREATE INDEX IF NOT EXISTS evaluation_release_judge_results_candidate_idx ON ${schema}.evaluation_release_judge_results (profile_ref, profile_sha256, candidate_id, release_id);
CREATE INDEX IF NOT EXISTS surface_outbox_claim_idx ON ${schema}.surface_outbox_states (profile_ref, profile_sha256, status, updated_at, event_id);
CREATE INDEX IF NOT EXISTS surface_delivery_reservations_reconcile_idx ON ${schema}.surface_delivery_reservations (profile_ref, profile_sha256, status, updated_at, delivery_key);
CREATE OR REPLACE FUNCTION ${schema}.reject_runtime_mutation() RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
BEGIN
  RAISE EXCEPTION 'runtime_immutable_relation';
END;
$function$;
DO $block$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'action_events_append_only' AND tgrelid = '${schema}.action_events'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER action_events_append_only BEFORE UPDATE OR DELETE ON ${schema}.action_events FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'audit_events_append_only' AND tgrelid = '${schema}.audit_events'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON ${schema}.audit_events FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'action_effect_reservations_immutable' AND tgrelid = '${schema}.action_effect_reservations'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER action_effect_reservations_immutable BEFORE UPDATE OR DELETE ON ${schema}.action_effect_reservations FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'workflow_runs_immutable' AND tgrelid = '${schema}.workflow_runs'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER workflow_runs_immutable BEFORE UPDATE OR DELETE ON ${schema}.workflow_runs FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'deployment_profiles_immutable' AND tgrelid = '${schema}.deployment_profiles'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER deployment_profiles_immutable BEFORE UPDATE OR DELETE ON ${schema}.deployment_profiles FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'evaluation_candidates_immutable' AND tgrelid = '${schema}.evaluation_candidates'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER evaluation_candidates_immutable BEFORE UPDATE OR DELETE ON ${schema}.evaluation_candidates FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'evaluation_judge_results_immutable' AND tgrelid = '${schema}.evaluation_judge_results'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER evaluation_judge_results_immutable BEFORE UPDATE OR DELETE ON ${schema}.evaluation_judge_results FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'evaluation_releases_immutable' AND tgrelid = '${schema}.evaluation_releases'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER evaluation_releases_immutable BEFORE UPDATE OR DELETE ON ${schema}.evaluation_releases FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'evaluation_release_judge_results_immutable' AND tgrelid = '${schema}.evaluation_release_judge_results'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER evaluation_release_judge_results_immutable BEFORE UPDATE OR DELETE ON ${schema}.evaluation_release_judge_results FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'evaluation_replay_tombstones_immutable' AND tgrelid = '${schema}.evaluation_replay_tombstones'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER evaluation_replay_tombstones_immutable BEFORE UPDATE OR DELETE ON ${schema}.evaluation_replay_tombstones FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'surface_outbox_events_immutable' AND tgrelid = '${schema}.surface_outbox_events'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER surface_outbox_events_immutable BEFORE UPDATE OR DELETE ON ${schema}.surface_outbox_events FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'surface_delivery_receipts_append_only' AND tgrelid = '${schema}.surface_delivery_receipts'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER surface_delivery_receipts_append_only BEFORE UPDATE OR DELETE ON ${schema}.surface_delivery_receipts FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'surface_delivery_tombstones_immutable' AND tgrelid = '${schema}.surface_delivery_tombstones'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER surface_delivery_tombstones_immutable BEFORE UPDATE OR DELETE ON ${schema}.surface_delivery_tombstones FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname = 'surface_event_tombstones_immutable' AND tgrelid = '${schema}.surface_event_tombstones'::pg_catalog.regclass AND NOT tgisinternal) THEN
    CREATE TRIGGER surface_event_tombstones_immutable BEFORE UPDATE OR DELETE ON ${schema}.surface_event_tombstones FOR EACH ROW EXECUTE FUNCTION ${schema}.reject_runtime_mutation();
  END IF;
END;
$block$;
REVOKE ALL ON ALL TABLES IN SCHEMA ${schema} FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA ${schema} FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ${schema} FROM PUBLIC;
GRANT USAGE ON SCHEMA ${schema} TO ${runtimeRole};
GRANT SELECT ON ${schema}.schema_migrations TO ${runtimeRole};
GRANT SELECT, INSERT ON ${schema}.deployment_profiles TO ${runtimeRole};
GRANT SELECT, INSERT, DELETE ON ${schema}.ingress_requests TO ${runtimeRole};
GRANT SELECT, INSERT ON ${schema}.workflow_runs TO ${runtimeRole};
GRANT SELECT, INSERT ON ${schema}.action_states TO ${runtimeRole};
GRANT UPDATE (state, state_hash, revision, updated_at) ON ${schema}.action_states TO ${runtimeRole};
GRANT SELECT, INSERT ON ${schema}.action_effect_reservations TO ${runtimeRole};
GRANT SELECT, INSERT ON ${schema}.action_events TO ${runtimeRole};
GRANT SELECT, INSERT, DELETE ON ${schema}.reconciliation_leases TO ${runtimeRole};
GRANT UPDATE (lease_id, principal_ref, acquired_at, expires_at, revision) ON ${schema}.reconciliation_leases TO ${runtimeRole};
GRANT INSERT ON ${schema}.audit_events TO ${runtimeRole};
GRANT SELECT ON ${schema}.evaluation_candidates TO ${runtimeRole};
GRANT SELECT ON ${schema}.evaluation_judge_results TO ${runtimeRole};
GRANT SELECT ON ${schema}.evaluation_releases TO ${runtimeRole};
GRANT SELECT ON ${schema}.evaluation_release_judge_results TO ${runtimeRole};
GRANT SELECT, INSERT ON ${schema}.evaluation_replay_tombstones TO ${runtimeRole};
GRANT USAGE ON SCHEMA ${schema} TO ${evaluationWriterRole};
GRANT SELECT ON ${schema}.schema_migrations TO ${evaluationWriterRole};
GRANT SELECT ON ${schema}.deployment_profiles TO ${evaluationWriterRole};
GRANT SELECT ON ${schema}.evaluation_candidates TO ${evaluationWriterRole};
GRANT SELECT ON ${schema}.evaluation_judge_results TO ${evaluationWriterRole};
GRANT SELECT ON ${schema}.evaluation_releases TO ${evaluationWriterRole};
GRANT SELECT ON ${schema}.evaluation_release_judge_results TO ${evaluationWriterRole};
GRANT SELECT, INSERT ON ${schema}.evaluation_replay_tombstones TO ${evaluationWriterRole};
GRANT EXECUTE ON FUNCTION ${schema}.persist_authorized_evaluation(text, character, character, jsonb, jsonb, text, jsonb) TO ${evaluationWriterRole};
GRANT SELECT, INSERT ON ${schema}.surface_outbox_events TO ${runtimeRole};
GRANT SELECT, INSERT ON ${schema}.surface_outbox_states TO ${runtimeRole};
GRANT UPDATE (status, claim_ref, claim_owner_ref, claim_acquired_at, claim_expires_at, failure_code, revision, updated_at) ON ${schema}.surface_outbox_states TO ${runtimeRole};
GRANT SELECT, INSERT ON ${schema}.surface_delivery_reservations TO ${runtimeRole};
GRANT UPDATE (status, revision, attempted_at, completed_at, reconciliation_ref, reconciliation_owner_ref, reconciliation_acquired_at, reconciliation_expires_at, updated_at) ON ${schema}.surface_delivery_reservations TO ${runtimeRole};
GRANT SELECT, INSERT ON ${schema}.surface_delivery_receipts TO ${runtimeRole};
GRANT SELECT, INSERT ON ${schema}.surface_delivery_tombstones TO ${runtimeRole};
GRANT SELECT, INSERT ON ${schema}.surface_event_tombstones TO ${runtimeRole};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${schema} TO ${runtimeRole};
`;
}

export function migrationChecksum() {
  const verifierContract = JSON.stringify({
    catalogAuthority: EXPECTED_CATALOG_AUTHORITY_V8,
    catalogAuthoritySha256: EXPECTED_CATALOG_AUTHORITY_SHA256,
    columns: EXPECTED_COLUMN_DEFINITIONS,
    constraints: EXPECTED_CONSTRAINTS,
    databaseAcl: EXPECTED_DATABASE_ACL,
    indexes: EXPECTED_INDEXES,
    relations: EXPECTED_RELATION_DEFINITIONS,
    routines: EXPECTED_ROUTINE_DEFINITIONS,
    triggerTables: EXPECTED_TRIGGER_TABLES,
    triggers: EXPECTED_TRIGGERS,
    types: EXPECTED_TYPE_DEFINITIONS,
  });
  return createHash("sha256")
    .update(
      `${SCHEMA_VERSION}\n${migrationPreflightSql()}\n${migrationBody()}\n${catalogFingerprintSql()}\n${catalogStructure.toString()}\n${catalogAuthoritySha256.toString()}\n${verifierContract}`,
    )
    .digest("hex");
}

export function migrationSql() {
  const schema = CANARY_SCHEMA_NAME;
  const body = migrationBody();
  const checksum = migrationChecksum();
  return `${migrationPreflightSql()}${body}
INSERT INTO ${schema}.schema_migrations (version, checksum, catalog_authority_sha256, catalog_fingerprint)
SELECT ${SCHEMA_VERSION}, '${checksum}', '${EXPECTED_CATALOG_AUTHORITY_SHA256}', catalog_fingerprint
FROM (${catalogFingerprintSql()}) fingerprint
;
DO $block$
BEGIN
  IF (SELECT count(*) FROM ${schema}.schema_migrations) <> 1
    OR NOT EXISTS (SELECT 1 FROM ${schema}.schema_migrations WHERE version = ${SCHEMA_VERSION} AND checksum = '${checksum}') THEN
    RAISE EXCEPTION 'schema_migration_checksum_mismatch';
  END IF;
END;
$block$;
`;
}
