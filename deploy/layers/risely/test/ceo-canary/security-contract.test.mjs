import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { sha256Canonical } from "../../canary/service/ceo-canary/src/canonical.mjs";
import { createActionState } from "../../canary/service/ceo-canary/src/domain.mjs";
import {
  assertMigrationDatabaseBoundary,
  assertOwnerDatabaseBoundary,
  PostgresCanaryStore,
} from "../../canary/service/ceo-canary/src/postgres-store.mjs";
import { assertPostMigrationDatabaseContract } from "../../canary/service/ceo-canary/src/database-security.mjs";
import {
  CANARY_BOOTSTRAP_ADMIN_ROLE,
  CANARY_DATABASE_NAME,
  CANARY_EVALUATION_WRITER_DATABASE_USER,
  CANARY_MAINTENANCE_LOCK_KEY,
  CANARY_MIGRATION_DATABASE_USER,
  CANARY_OWNER_DATABASE_USER,
  CANARY_RUNTIME_DATABASE_USER,
  CANARY_SCHEMA_NAME,
  EXPECTED_COLUMN_DEFINITIONS,
  EXPECTED_CANARY_DATABASE_ACL,
  EXPECTED_CATALOG_AUTHORITY_V8,
  EXPECTED_CATALOG_AUTHORITY_SHA256,
  EXPECTED_CONSTRAINTS,
  EXPECTED_DATABASE_ACL,
  EXPECTED_INDEXES,
  EXPECTED_RELATION_DEFINITIONS,
  EXPECTED_ROUTINE_DEFINITIONS,
  EXPECTED_TRIGGER_TABLES,
  EXPECTED_TRIGGERS,
  EXPECTED_TYPE_DEFINITIONS,
  SCHEMA_VERSION,
  catalogFingerprintSql,
  migrationChecksum,
  migrationSql,
} from "../../canary/service/ceo-canary/src/schema.mjs";
import { retentionSql } from "../../canary/service/ceo-canary/src/retention.mjs";
import { verifyCeoCanaryDatabaseClientBoundary } from "../../canary/service/ceo-canary/src/index.mjs";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import { actionProposal, run } from "../contracts/fixtures.mjs";

const TEST_DIR = fileURLToPath(new URL(".", import.meta.url));
const LAYER_DIR = fileURLToPath(new URL("../../", import.meta.url));
const SERVICE_DIR = fileURLToPath(new URL("../../canary/service/ceo-canary/", import.meta.url));
const RUNTIME_SCOPE = createRuntimeScope(ceoDeploymentProfile);
const AUTHORITY = Object.freeze({
  principalRef: "principal:ceo",
  qmPrincipalId: "qm:principal:ceo-canary",
  externalPrincipalRef: "external-identity:risely:ceo",
  agentId: "agent:risely:ceo-team",
  agentVersion: "1.0.0",
  scopeRef: "principal-binding:risely:ceo:v1",
  audienceRef: "slack-audience:ceo-private",
  credentialOwnerRef: "credential-owner:ceo",
});

function context(label) {
  return { principalRef: AUTHORITY.principalRef, requestHash: sha256Canonical(label) };
}

function rawCatalogFromAuthority(authority) {
  const mapRows = (rows, keys) => rows.map((row) => Object.fromEntries(keys.map((key, index) => [key, row[index]])));
  return {
    constraints: mapRows(authority.constraints, [
      "table",
      "name",
      "type",
      "validated",
      "deferrable",
      "deferred",
      "columns",
      "referencedTable",
      "referencedColumns",
      "matchType",
      "updateType",
      "deleteType",
      "definition",
    ]),
    indexes: mapRows(authority.indexes, [
      "table",
      "name",
      "valid",
      "ready",
      "live",
      "unique",
      "primary",
      "immediate",
      "clustered",
      "replicaIdentity",
      "nullsNotDistinct",
      "accessMethod",
      "keyColumns",
      "includedColumns",
      "expressions",
      "predicate",
      "attributeOptions",
      "definition",
    ]),
    relations: mapRows(authority.relations, [
      "table",
      "kind",
      "persistence",
      "owner",
      "rowSecurity",
      "forceRowSecurity",
      "replicaIdentity",
      "isPartition",
      "options",
      "accessMethod",
      "extensionOwned",
    ]),
    toast: authority.toast.map((row) => ({
      ...Object.fromEntries(
        ["baseTable", "present", "owner", "kind", "persistence", "accessMethod", "options"].map((key, index) => [
          key,
          row[index],
        ]),
      ),
      indexes: mapRows(row[7], [
        "owner",
        "kind",
        "persistence",
        "options",
        "accessMethod",
        "valid",
        "ready",
        "live",
        "unique",
        "primary",
        "immediate",
        "clustered",
        "replicaIdentity",
        "nullsNotDistinct",
        "keyColumns",
        "includedColumns",
        "expressions",
        "predicate",
        "attributeOptions",
      ]),
    })),
    columns: mapRows(authority.columns, [
      "table",
      "name",
      "ordinal",
      "type",
      "notNull",
      "identity",
      "generated",
      "default",
      "collation",
    ]),
    routines: mapRows(authority.routines, [
      "name",
      "kind",
      "owner",
      "securityDefiner",
      "language",
      "config",
      "arguments",
      "result",
      "volatility",
      "strict",
      "leakproof",
      "parallel",
      "body",
    ]),
    sequences: mapRows(authority.sequences, [
      "name",
      "owner",
      "dataType",
      "start",
      "increment",
      "minimum",
      "maximum",
      "cache",
      "cycle",
      "ownedTable",
      "ownedColumn",
      "ownershipDependency",
    ]),
    triggers: mapRows(authority.triggers, [
      "name",
      "table",
      "enabled",
      "type",
      "when",
      "definition",
      "functionSchema",
      "functionName",
      "functionOwner",
      "functionLanguage",
      "functionSecurityDefiner",
      "functionConfig",
      "functionVolatility",
      "functionStrict",
      "functionBody",
    ]),
    types: mapRows(authority.types, ["name", "kind", "category", "owner", "relation", "element"]),
  };
}

const CATALOG = Object.freeze(rawCatalogFromAuthority(EXPECTED_CATALOG_AUTHORITY_V8));

class MetadataPool {
  constructor({
    triggerEnabled = true,
    triggerWhen = false,
    catalogDrift = false,
    constraintDefinitionDrift = false,
    indexDefinitionDrift = false,
    columnDrift,
    tableDrift,
    relationDrift,
    sequenceDrift,
    toastDrift,
    routineDrift = false,
    typeDrift = false,
    namespaceDrift,
    excessPrivilege,
    privilegeOverrides,
    grantDrift = false,
    aclDrift,
    ownsDatabase = false,
    databaseSettings = ["search_path=pg_catalog"],
    databaseAclDrift,
    roleOverrides,
    topologyDrift,
    schemaOwner = CANARY_OWNER_DATABASE_USER,
    tableOwners = [CANARY_OWNER_DATABASE_USER],
    sequenceOwners = [CANARY_OWNER_DATABASE_USER],
    target = "canary",
  } = {}) {
    this.triggerEnabled = triggerEnabled;
    this.triggerWhen = triggerWhen;
    this.catalogDrift = catalogDrift;
    this.constraintDefinitionDrift = constraintDefinitionDrift;
    this.indexDefinitionDrift = indexDefinitionDrift;
    this.columnDrift = columnDrift;
    this.tableDrift = tableDrift;
    this.relationDrift = relationDrift;
    this.sequenceDrift = sequenceDrift;
    this.toastDrift = toastDrift;
    this.routineDrift = routineDrift;
    this.typeDrift = typeDrift;
    this.namespaceDrift = namespaceDrift;
    this.excessPrivilege = excessPrivilege;
    this.privilegeOverrides = privilegeOverrides;
    this.grantDrift = grantDrift;
    this.aclDrift = aclDrift;
    this.ownsDatabase = ownsDatabase;
    this.databaseSettings = databaseSettings;
    this.databaseAclDrift = databaseAclDrift;
    this.roleOverrides = roleOverrides;
    this.topologyDrift = topologyDrift;
    this.schemaOwner = schemaOwner;
    this.tableOwners = tableOwners;
    this.sequenceOwners = sequenceOwners;
    this.target = target;
    this.queries = [];
    this.businessQueries = 0;
  }

  async connect() {
    return {
      query: async (sql) => this.query(sql),
      release() {},
    };
  }

  async query(sql) {
    this.queries.push(sql);
    if (
      /(?:FROM|INSERT INTO|UPDATE|DELETE FROM) risely_agent_runtime\.(?:workflow_runs|action_states|action_events|audit_events)/.test(
        sql,
      )
    )
      this.businessQueries += 1;
    if (sql.includes("/* exact canary role attributes */")) {
      const rows = [
        {
          rolname: CANARY_EVALUATION_WRITER_DATABASE_USER,
          rolcanlogin: false,
          rolinherit: false,
          rolsuper: false,
          rolcreaterole: false,
          rolcreatedb: false,
          rolreplication: false,
          rolbypassrls: false,
          owns_database: false,
          database_settings: ["search_path=pg_catalog"],
        },
        {
          rolname: CANARY_MIGRATION_DATABASE_USER,
          rolcanlogin: true,
          rolinherit: false,
          rolsuper: false,
          rolcreaterole: false,
          rolcreatedb: false,
          rolreplication: false,
          rolbypassrls: false,
          owns_database: false,
          database_settings: ["search_path=pg_catalog"],
        },
        {
          rolname: CANARY_OWNER_DATABASE_USER,
          rolcanlogin: false,
          rolinherit: false,
          rolsuper: false,
          rolcreaterole: false,
          rolcreatedb: false,
          rolreplication: false,
          rolbypassrls: false,
          owns_database: false,
          database_settings: ["search_path=pg_catalog"],
        },
        {
          rolname: CANARY_RUNTIME_DATABASE_USER,
          rolcanlogin: true,
          rolinherit: false,
          rolsuper: false,
          rolcreaterole: false,
          rolcreatedb: false,
          rolreplication: false,
          rolbypassrls: false,
          owns_database: false,
          database_settings: ["search_path=pg_catalog"],
        },
      ].sort((left, right) => left.rolname.localeCompare(right.rolname));
      if (this.topologyDrift && !["bootstrap", "edges"].includes(this.topologyDrift.target)) {
        Object.assign(rows[this.topologyDrift.index ?? 0], this.topologyDrift.values);
      }
      return { rows };
    }
    if (sql.includes("/* exact canary bootstrap administrator */")) {
      const row = {
        rolname: CANARY_BOOTSTRAP_ADMIN_ROLE,
        rolcanlogin: true,
        rolcreaterole: true,
        rolsuper: false,
        owns_database: true,
        database_create: true,
      };
      if (this.topologyDrift?.target === "bootstrap") Object.assign(row, this.topologyDrift.values);
      return {
        rows: this.topologyDrift?.target === "bootstrap" && this.topologyDrift.missing ? [] : [row],
      };
    }
    if (sql.includes("/* exact bidirectional canary role edges */")) {
      const rows = [
        {
          granted_role: CANARY_EVALUATION_WRITER_DATABASE_USER,
          member_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
          grantor_role: "rdsadmin",
          inherit_option: false,
          set_option: false,
          admin_option: true,
          grantor_is_superuser: true,
          grantor_is_bootstrap_superuser: true,
        },
        {
          granted_role: CANARY_MIGRATION_DATABASE_USER,
          member_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
          grantor_role: "rdsadmin",
          inherit_option: false,
          set_option: false,
          admin_option: true,
          grantor_is_superuser: true,
          grantor_is_bootstrap_superuser: true,
        },
        {
          granted_role: CANARY_OWNER_DATABASE_USER,
          member_role: CANARY_MIGRATION_DATABASE_USER,
          grantor_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
          inherit_option: false,
          set_option: true,
          admin_option: false,
          grantor_is_superuser: false,
          grantor_is_bootstrap_superuser: false,
        },
        {
          granted_role: CANARY_OWNER_DATABASE_USER,
          member_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
          grantor_role: "rdsadmin",
          inherit_option: false,
          set_option: false,
          admin_option: true,
          grantor_is_superuser: true,
          grantor_is_bootstrap_superuser: true,
        },
        {
          granted_role: CANARY_RUNTIME_DATABASE_USER,
          member_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
          grantor_role: "rdsadmin",
          inherit_option: false,
          set_option: false,
          admin_option: true,
          grantor_is_superuser: true,
          grantor_is_bootstrap_superuser: true,
        },
      ];
      if (this.topologyDrift?.target === "edges") {
        if (this.topologyDrift.replace) return { rows: this.topologyDrift.replace };
        rows.push(this.topologyDrift.add);
      }
      return { rows };
    }
    if (sql.includes("/* exact canary database ACL */")) {
      const acl = this.databaseAclDrift
        ? [...EXPECTED_CANARY_DATABASE_ACL, this.databaseAclDrift]
        : EXPECTED_CANARY_DATABASE_ACL;
      return {
        rows: acl.map(([grantee, grantor, privilege_type, is_grantable]) => ({
          grantee,
          grantor,
          privilege_type,
          is_grantable,
        })),
      };
    }
    if (sql.includes("FROM pg_catalog.pg_roles")) {
      return {
        rows: [
          {
            current_user: this.target === "canary" ? CANARY_RUNTIME_DATABASE_USER : "attacker",
            current_database: this.target === "canary" ? CANARY_DATABASE_NAME : "qm_shadow",
            rolname: this.target === "canary" ? CANARY_RUNTIME_DATABASE_USER : "attacker",
            rolcanlogin: true,
            rolinherit: false,
            rolsuper: false,
            rolcreaterole: false,
            rolcreatedb: false,
            rolreplication: false,
            rolbypassrls: false,
            owns_database: this.ownsDatabase,
            has_role_membership: false,
            database_settings: this.databaseSettings,
            ...this.roleOverrides,
          },
        ],
      };
    }
    if (sql.includes("schema_migrations ORDER BY")) {
      return {
        rows: [
          {
            version: SCHEMA_VERSION,
            checksum: migrationChecksum(),
            catalog_fingerprint: CATALOG,
          },
        ],
      };
    }
    if (sql.includes("migration.catalog_authority_sha256")) {
      return {
        rows: [
          {
            current_user: this.target === "canary" ? CANARY_RUNTIME_DATABASE_USER : "attacker",
            current_database: this.target === "canary" ? CANARY_DATABASE_NAME : "qm_shadow",
            schema_name: this.target === "canary" ? CANARY_SCHEMA_NAME : null,
            version: SCHEMA_VERSION,
            checksum: migrationChecksum(),
            catalog_authority_sha256: EXPECTED_CATALOG_AUTHORITY_SHA256,
            stored_profile_sha256: ceoDeploymentProfile.profileSha256,
            stored_profile: ceoDeploymentProfile,
            candidate_insert: false,
            judge_insert: false,
            release_insert: false,
            evaluation_persist_execute: false,
          },
        ],
      };
    }
    if (sql.includes("AS catalog_fingerprint")) {
      const catalog = structuredClone(CATALOG);
      if (this.catalogDrift) {
        catalog.constraints = catalog.constraints.filter((entry) => entry.name !== "action_effect_reservations_pkey");
      }
      if (this.constraintDefinitionDrift === "check")
        catalog.constraints.find((entry) => entry.type === "c").definition = "CHECK (true)";
      if (this.constraintDefinitionDrift === "key")
        catalog.constraints.find((entry) => entry.type === "p").columns = [999];
      if (this.constraintDefinitionDrift === "foreign_key") {
        const foreignKey = catalog.constraints.find((entry) => entry.type === "f");
        foreignKey.referencedColumns = [999];
        foreignKey.deleteType = "c";
      }
      if (this.indexDefinitionDrift === "keys") catalog.indexes[0].keyColumns = ["attacker_column"];
      if (this.indexDefinitionDrift === "predicate") catalog.indexes[0].predicate = "true";
      if (this.indexDefinitionDrift === "definition") catalog.indexes[0].definition = "CREATE INDEX attacker";
      if (!this.triggerEnabled) catalog.triggers[0].enabled = "D";
      if (this.triggerWhen) catalog.triggers[0].when = "true";
      if (this.columnDrift) {
        const driftValues = {
          ordinal: 99,
          type: "bytea",
          notNull: false,
          identity: "always",
          generated: "stored",
          default: "now()",
          collation: "attacker.collation",
        };
        catalog.columns[0][this.columnDrift] = driftValues[this.columnDrift];
      }
      if (this.tableDrift) {
        const driftValues = {
          kind: "p",
          persistence: "u",
          owner: CANARY_RUNTIME_DATABASE_USER,
          rowSecurity: true,
          forceRowSecurity: true,
          accessMethod: "attacker_am",
          extensionOwned: true,
        };
        catalog.relations[0][this.tableDrift] = driftValues[this.tableDrift];
      }
      if (this.relationDrift) {
        catalog.relations.push({
          table: `unexpected_${this.relationDrift}`,
          kind: this.relationDrift,
          persistence: "p",
        });
        catalog.relations.sort((left, right) => left.table.localeCompare(right.table));
      }
      if (this.sequenceDrift) catalog.sequences[0].maximum = "9223372036854775806";
      if (this.toastDrift) catalog.toast[0].options = ["autovacuum_enabled=false"];
      if (this.routineDrift) catalog.routines.push({ ...catalog.routines[0], name: "audit_leak" });
      if (this.typeDrift) catalog.types.push({ ...catalog.types[0], name: "audit_leak" });
      return { rows: [{ catalog_fingerprint: catalog }] };
    }
    if (sql.includes("array_agg(DISTINCT tableowner")) {
      return {
        rows: [
          {
            schema_owner: this.schemaOwner,
            table_owners: this.tableOwners,
            sequence_owners: this.sequenceOwners,
          },
        ],
      };
    }
    if (sql.includes("FROM pg_catalog.pg_trigger")) {
      return {
        rows: EXPECTED_TRIGGERS.map((tgname, index) => ({
          tgname,
          tgenabled: index === 0 && !this.triggerEnabled ? "D" : "O",
          tgtype: 27,
          no_when: index !== 0 || !this.triggerWhen,
          table_name: EXPECTED_TRIGGER_TABLES[tgname],
          function_schema: CANARY_SCHEMA_NAME,
          function_name: "reject_runtime_mutation",
          function_owner: CANARY_OWNER_DATABASE_USER,
          function_language: "plpgsql",
          security_invoker: true,
          function_configured: true,
          prosrc: "BEGIN RAISE EXCEPTION 'runtime_immutable_relation'; END;",
        })),
      };
    }
    if (sql.includes("FROM pg_catalog.pg_rewrite rewrite")) {
      const row = {
        rewrites: 0,
        policies: 0,
        inheritance: 0,
        extensions: 0,
        extension_owned_schema: 0,
        extension_owned_objects: 0,
        enabled_event_triggers: 0,
        all_tables_publications: 0,
        publication_relations: 0,
        publication_namespaces: 0,
        subscription_relations: 0,
        schema_less_casts: 0,
        schema_less_transforms: 0,
        foreign_server_usage: 0,
        foreign_user_mappings: 0,
        default_acls: 0,
        foreign_dependencies: 0,
        foreign_data_wrapper_authority: 0,
      };
      if (this.namespaceDrift) row[this.namespaceDrift] = 1;
      return { rows: [row] };
    }
    if (sql.includes("role boundary */")) {
      const owner = sql.includes("/* owner role boundary */");
      const migrator = sql.includes("/* migrator role boundary */");
      return {
        rows: [
          {
            database_connect: true,
            database_create: false,
            database_temp: true,
            direct_database_create_or_temp: false,
            public_database_temp: true,
            schema_usage: !migrator,
            schema_create: owner,
            schema_owner: CANARY_OWNER_DATABASE_USER,
            cross_schema_create_or_owner: false,
            wrong_canary_object_owner: false,
            cross_schema_incoming_foreign_key: false,
            exotic_canary_object: false,
            cross_schema_table_access: false,
            cross_schema_sequence_access: false,
            cross_schema_security_definer_access: false,
            ...(this.excessPrivilege ? { [this.excessPrivilege]: true } : {}),
            ...this.privilegeOverrides,
          },
        ],
      };
    }
    if (sql.includes("has_database_privilege")) {
      return {
        rows: [
          {
            database_connect: true,
            database_create: false,
            database_temp: true,
            schema_create: false,
            cross_schema_table_access: false,
            cross_schema_sequence_access: false,
            cross_schema_security_definer_access: false,
            table_truncate: false,
            immutable_mutation: false,
            action_identity_update: false,
            reconciliation_identity_update: false,
            action_state_delete: false,
            schema_migration_write: false,
            audit_select: false,
            table_trigger: false,
            table_references: false,
            unauthorized_function_execute: false,
            evaluation_persist_execute: false,
            sequence_update: false,
            ...(this.excessPrivilege ? { [this.excessPrivilege]: true } : {}),
            ...this.privilegeOverrides,
          },
        ],
      };
    }
    if (sql.includes("WITH exact_acl AS")) {
      const grants = this.grantDrift ? EXPECTED_DATABASE_ACL.slice(1) : [...EXPECTED_DATABASE_ACL];
      if (this.aclDrift) grants.push(this.aclDrift);
      return {
        rows: grants.map(
          ([resource_type, resource_name, subresource_name, grantee, grantor, privilege_type, is_grantable]) => ({
            resource_type,
            resource_name,
            subresource_name,
            grantee,
            grantor,
            privilege_type,
            is_grantable,
          }),
        ),
      };
    }
    if (sql.includes(`INSERT INTO ${CANARY_SCHEMA_NAME}.deployment_profiles`)) return { rows: [], rowCount: 1 };
    if (sql.includes(`SELECT profile FROM ${CANARY_SCHEMA_NAME}.deployment_profiles`)) {
      return { rows: [{ profile: ceoDeploymentProfile }], rowCount: 1 };
    }
    if (sql.includes("count(*)::integer AS owned")) return { rows: [{ owned: 0 }] };
    return { rows: [], rowCount: 0 };
  }
}

class MigrationBoundaryClient {
  constructor({
    bootstrapAdminIdentity,
    migrationIdentity,
    migrationBoundary,
    ownerIdentity,
    ownerBoundary,
    topologyEdges,
  } = {}) {
    this.bootstrapAdminIdentity = bootstrapAdminIdentity;
    this.migrationIdentity = migrationIdentity;
    this.migrationBoundary = migrationBoundary;
    this.ownerIdentity = ownerIdentity;
    this.ownerBoundary = ownerBoundary;
    this.topologyEdges = topologyEdges;
  }

  async query(sql) {
    if (sql.includes("/* exact canary role attributes */")) {
      return {
        rows: [
          {
            rolname: CANARY_EVALUATION_WRITER_DATABASE_USER,
            rolcanlogin: false,
            rolinherit: false,
            rolsuper: false,
            rolcreaterole: false,
            rolcreatedb: false,
            rolreplication: false,
            rolbypassrls: false,
            owns_database: false,
            database_settings: ["search_path=pg_catalog"],
          },
          {
            rolname: CANARY_MIGRATION_DATABASE_USER,
            rolcanlogin: true,
            rolinherit: false,
            rolsuper: false,
            rolcreaterole: false,
            rolcreatedb: false,
            rolreplication: false,
            rolbypassrls: false,
            owns_database: false,
            database_settings: ["search_path=pg_catalog"],
            ...this.migrationIdentity,
          },
          {
            rolname: CANARY_OWNER_DATABASE_USER,
            rolcanlogin: false,
            rolinherit: false,
            rolsuper: false,
            rolcreaterole: false,
            rolcreatedb: false,
            rolreplication: false,
            rolbypassrls: false,
            owns_database: false,
            database_settings: ["search_path=pg_catalog"],
            ...this.ownerIdentity,
          },
          {
            rolname: CANARY_RUNTIME_DATABASE_USER,
            rolcanlogin: true,
            rolinherit: false,
            rolsuper: false,
            rolcreaterole: false,
            rolcreatedb: false,
            rolreplication: false,
            rolbypassrls: false,
            owns_database: false,
            database_settings: ["search_path=pg_catalog"],
          },
        ].sort((left, right) => left.rolname.localeCompare(right.rolname)),
      };
    }
    if (sql.includes("/* exact canary bootstrap administrator */")) {
      return {
        rows: [
          {
            rolname: CANARY_BOOTSTRAP_ADMIN_ROLE,
            rolcanlogin: true,
            rolcreaterole: true,
            rolsuper: false,
            owns_database: true,
            database_create: true,
            ...this.bootstrapAdminIdentity,
          },
        ],
      };
    }
    if (sql.includes("/* exact bidirectional canary role edges */")) {
      return {
        rows: this.topologyEdges ?? [
          {
            granted_role: CANARY_EVALUATION_WRITER_DATABASE_USER,
            member_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
            grantor_role: "rdsadmin",
            inherit_option: false,
            set_option: false,
            admin_option: true,
            grantor_is_superuser: true,
            grantor_is_bootstrap_superuser: true,
          },
          {
            granted_role: CANARY_MIGRATION_DATABASE_USER,
            member_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
            grantor_role: "rdsadmin",
            inherit_option: false,
            set_option: false,
            admin_option: true,
            grantor_is_superuser: true,
            grantor_is_bootstrap_superuser: true,
          },
          {
            granted_role: CANARY_OWNER_DATABASE_USER,
            member_role: CANARY_MIGRATION_DATABASE_USER,
            grantor_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
            inherit_option: false,
            set_option: true,
            admin_option: false,
            grantor_is_superuser: false,
            grantor_is_bootstrap_superuser: false,
          },
          {
            granted_role: CANARY_OWNER_DATABASE_USER,
            member_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
            grantor_role: "rdsadmin",
            inherit_option: false,
            set_option: false,
            admin_option: true,
            grantor_is_superuser: true,
            grantor_is_bootstrap_superuser: true,
          },
          {
            granted_role: CANARY_RUNTIME_DATABASE_USER,
            member_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
            grantor_role: "rdsadmin",
            inherit_option: false,
            set_option: false,
            admin_option: true,
            grantor_is_superuser: true,
            grantor_is_bootstrap_superuser: true,
          },
        ],
      };
    }
    if (sql.includes("/* owner role identity */")) {
      return {
        rows: [
          {
            current_user: CANARY_OWNER_DATABASE_USER,
            session_user: CANARY_MIGRATION_DATABASE_USER,
            current_database: CANARY_DATABASE_NAME,
            ...this.ownerIdentity,
          },
        ],
      };
    }
    if (sql.includes("/* migration role identity */")) {
      return {
        rows: [
          {
            current_user: CANARY_MIGRATION_DATABASE_USER,
            current_database: CANARY_DATABASE_NAME,
            ...this.migrationIdentity,
          },
        ],
      };
    }
    if (sql.includes("/* exact canary database ACL */")) {
      return {
        rows: EXPECTED_CANARY_DATABASE_ACL.map(([grantee, grantor, privilege_type, is_grantable]) => ({
          grantee,
          grantor,
          privilege_type,
          is_grantable,
        })),
      };
    }
    if (sql.includes("/* exact canary namespace boundary */")) {
      return {
        rows: [
          {
            rewrites: 0,
            policies: 0,
            inheritance: 0,
            extensions: 0,
            extension_owned_schema: 0,
            extension_owned_objects: 0,
            enabled_event_triggers: 0,
            all_tables_publications: 0,
            publication_relations: 0,
            publication_namespaces: 0,
            subscription_relations: 0,
            schema_less_casts: 0,
            schema_less_transforms: 0,
            foreign_server_usage: 0,
            foreign_user_mappings: 0,
            default_acls: 0,
            foreign_dependencies: 0,
            foreign_data_wrapper_authority: 0,
          },
        ],
      };
    }
    const owner = sql.includes("/* owner role boundary */");
    return {
      rows: [
        {
          database_connect: true,
          database_create: false,
          database_temp: true,
          direct_database_create_or_temp: false,
          public_database_temp: true,
          schema_usage: owner,
          schema_create: owner,
          schema_owner: CANARY_OWNER_DATABASE_USER,
          cross_schema_create_or_owner: false,
          wrong_canary_object_owner: false,
          cross_schema_incoming_foreign_key: false,
          exotic_canary_object: false,
          cross_schema_table_access: false,
          cross_schema_sequence_access: false,
          cross_schema_security_definer_access: false,
          ...(owner ? this.ownerBoundary : this.migrationBoundary),
        },
      ],
    };
  }
}

class PostMigrationClient extends MigrationBoundaryClient {
  constructor({ migrations, catalogDrift = false, triggerDrift = false, aclDrift = false, ...boundary } = {}) {
    super(boundary);
    this.migrations = migrations;
    this.catalogDrift = catalogDrift;
    this.triggerDrift = triggerDrift;
    this.aclDrift = aclDrift;
  }

  async query(sql) {
    if (sql.includes("schema_migrations ORDER BY version")) {
      return {
        rows: this.migrations ?? [
          { version: SCHEMA_VERSION, checksum: migrationChecksum(), catalog_fingerprint: CATALOG },
        ],
      };
    }
    if (sql.includes("AS catalog_fingerprint")) {
      const catalog = structuredClone(CATALOG);
      if (this.catalogDrift) catalog.relations[0].owner = CANARY_RUNTIME_DATABASE_USER;
      if (this.triggerDrift) catalog.triggers[0].enabled = "D";
      return { rows: [{ catalog_fingerprint: catalog }] };
    }
    if (sql.includes("FROM pg_catalog.pg_trigger")) {
      const rows = EXPECTED_TRIGGERS.map((tgname) => ({
        tgname,
        table_name: EXPECTED_TRIGGER_TABLES[tgname],
        tgenabled: "O",
        function_owner: CANARY_OWNER_DATABASE_USER,
        security_invoker: true,
        function_configured: true,
      }));
      if (this.triggerDrift) rows[0].tgenabled = "D";
      return { rows };
    }
    if (sql.includes("WITH exact_acl AS")) {
      const grants = this.aclDrift ? EXPECTED_DATABASE_ACL.slice(1) : EXPECTED_DATABASE_ACL;
      return {
        rows: grants.map(
          ([resource_type, resource_name, subresource_name, grantee, grantor, privilege_type, is_grantable]) => ({
            resource_type,
            resource_name,
            subresource_name,
            grantee,
            grantor,
            privilege_type,
            is_grantable,
          }),
        ),
      };
    }
    return super.query(sql);
  }
}

class StoredRowPool extends MetadataPool {
  constructor({ actionRow, runRow } = {}) {
    super();
    this.actionRow = actionRow;
    this.runRow = runRow;
    this.auditWrites = 0;
  }

  async query(sql) {
    if (sql.includes(`FROM ${CANARY_SCHEMA_NAME}.action_states`))
      return { rows: this.actionRow ? [this.actionRow] : [] };
    if (sql.includes(`FROM ${CANARY_SCHEMA_NAME}.workflow_runs`)) return { rows: this.runRow ? [this.runRow] : [] };
    if (sql.includes(`INSERT INTO ${CANARY_SCHEMA_NAME}.audit_events`)) {
      this.auditWrites += 1;
      return { rows: [], rowCount: 1 };
    }
    return super.query(sql);
  }
}

function metadataStore(pool) {
  return new PostgresCanaryStore({
    pool,
    scope: RUNTIME_SCOPE,
  });
}

test("runtime readiness verifies explicit migrations, exact ownership, schema shape, and enabled triggers without DDL", async () => {
  assert.equal(SCHEMA_VERSION, 8);
  assert.equal(migrationChecksum(), "146b986b931f97fa5304423c988604137f6705f17e4c0f2d446f92c4dbb0628c");
  assert.match(migrationSql(), /preexisting_canary_migration_history/);
  assert.doesNotMatch(migrationSql(), /latest_version|latest_checksum/);
  const healthyPool = new MetadataPool();
  assert.equal(await metadataStore(healthyPool).verifySchema(), true);
  const readinessSql = healthyPool.queries.join("\n");
  assert.doesNotMatch(readinessSql, /(?:^|\n)\s*(?:CREATE|ALTER|DROP|TRUNCATE)\b/);
  assert.match(readinessSql, /acl\.grantee = 0 THEN 'PUBLIC'/);
  assert.match(readinessSql, /FROM pg_catalog\.pg_proc procedure[\s\S]*aclexplode/);
  assert.match(readinessSql, /relation\.relkind IN \('r', 'p', 'v', 'm', 'f'\)/);
  assert.match(readinessSql, /SET LOCAL search_path = pg_catalog/);
  assert.match(readinessSql, /grantee\.rolname = current_user[\s\S]*direct_database_create_or_temp/);
  assert.match(readinessSql, /acl\.grantee = 0[\s\S]*public_database_temp/);
  const relationFingerprint = /'relations',[\s\S]*?(?='columns')/.exec(catalogFingerprintSql())?.[0] ?? "";
  const toastFingerprint = /'toast',[\s\S]*?(?='columns')/.exec(catalogFingerprintSql())?.[0] ?? "";
  const constraintFingerprint = /'constraints',[\s\S]*?(?='indexes')/.exec(catalogFingerprintSql())?.[0] ?? "";
  const indexFingerprint = /'indexes',[\s\S]*?(?='relations')/.exec(catalogFingerprintSql())?.[0] ?? "";
  for (const field of [
    "convalidated",
    "condeferrable",
    "condeferred",
    "conkey",
    "confkey",
    "confmatchtype",
    "confupdtype",
    "confdeltype",
    "pg_get_constraintdef",
  ])
    assert.match(constraintFingerprint, new RegExp(field));
  for (const field of [
    "indisvalid",
    "indisready",
    "indislive",
    "indisunique",
    "indisprimary",
    "indimmediate",
    "indnkeyatts",
    "indnatts",
    "pg_get_expr",
    "indpred",
    "pg_get_indexdef",
  ])
    assert.match(indexFingerprint, new RegExp(field));
  assert.match(relationFingerprint, /FROM pg_catalog\.pg_class relation/);
  assert.doesNotMatch(relationFingerprint, /relkind\s*=/);
  for (const field of ["reltoastrelid", "reloptions", "relam", "indisvalid", "indisready", "indislive"])
    assert.match(toastFingerprint, new RegExp(field));
  for (const field of ["seqstart", "seqincrement", "seqmax", "seqmin", "seqcache"])
    assert.match(catalogFingerprintSql(), new RegExp(`${field}::text`));
  await assert.rejects(
    () => metadataStore(new MetadataPool({ triggerEnabled: false })).verifySchema(),
    (error) => error.code === "schema_unhealthy",
  );
  await assert.rejects(
    () => metadataStore(new MetadataPool({ catalogDrift: true })).verifySchema(),
    (error) => error.code === "schema_unhealthy",
  );
  for (const constraintDefinitionDrift of ["check", "key", "foreign_key"])
    await assert.rejects(
      () => metadataStore(new MetadataPool({ constraintDefinitionDrift })).verifySchema(),
      (error) => error.code === "schema_unhealthy",
    );
  for (const indexDefinitionDrift of ["keys", "predicate", "definition"])
    await assert.rejects(
      () => metadataStore(new MetadataPool({ indexDefinitionDrift })).verifySchema(),
      (error) => error.code === "schema_unhealthy",
    );
  for (const drift of [
    ...["ordinal", "type", "notNull", "identity", "generated", "default", "collation"].map((columnDrift) => ({
      columnDrift,
    })),
    ...["kind", "persistence", "owner", "rowSecurity", "forceRowSecurity", "accessMethod", "extensionOwned"].map(
      (tableDrift) => ({ tableDrift }),
    ),
    ...["v", "m", "f", "p"].map((relationDrift) => ({ relationDrift })),
    { routineDrift: true },
    { typeDrift: true },
    { sequenceDrift: true },
    { toastDrift: true },
    ...[
      "rewrites",
      "policies",
      "inheritance",
      "extensions",
      "extension_owned_schema",
      "extension_owned_objects",
      "enabled_event_triggers",
      "all_tables_publications",
      "publication_relations",
      "publication_namespaces",
      "subscription_relations",
      "schema_less_casts",
      "schema_less_transforms",
      "foreign_server_usage",
      "foreign_user_mappings",
      "default_acls",
      "foreign_dependencies",
      "foreign_data_wrapper_authority",
    ].map((namespaceDrift) => ({ namespaceDrift })),
    { triggerWhen: true },
    { grantDrift: true },
    { ownsDatabase: true },
    { privilegeOverrides: { database_connect: false } },
    { excessPrivilege: "database_create" },
    { privilegeOverrides: { public_database_temp: false } },
    { databaseAclDrift: ["PUBLIC", CANARY_BOOTSTRAP_ADMIN_ROLE, "CREATE", false] },
    { databaseAclDrift: [CANARY_RUNTIME_DATABASE_USER, CANARY_BOOTSTRAP_ADMIN_ROLE, "CONNECT", true] },
    { databaseAclDrift: [CANARY_OWNER_DATABASE_USER, CANARY_BOOTSTRAP_ADMIN_ROLE, "CONNECT", false] },
    { excessPrivilege: "direct_database_create_or_temp" },
    { excessPrivilege: "cross_schema_create_or_owner" },
    { excessPrivilege: "cross_schema_incoming_foreign_key" },
    { excessPrivilege: "exotic_canary_object" },
    { excessPrivilege: "cross_schema_table_access" },
    { excessPrivilege: "cross_schema_sequence_access" },
    { schemaOwner: "attacker" },
    { tableOwners: [CANARY_MIGRATION_DATABASE_USER, "attacker"] },
    { sequenceOwners: ["attacker"] },
    { excessPrivilege: "action_state_delete" },
    { excessPrivilege: "schema_migration_write" },
    { excessPrivilege: "audit_select" },
    {
      aclDrift: ["table", "ingress_requests", "", "PUBLIC", CANARY_MIGRATION_DATABASE_USER, "UPDATE", false],
    },
    {
      excessPrivilege: "reconciliation_identity_update",
      aclDrift: [
        "table",
        "reconciliation_leases",
        "",
        CANARY_RUNTIME_DATABASE_USER,
        CANARY_MIGRATION_DATABASE_USER,
        "UPDATE",
        false,
      ],
    },
    {
      excessPrivilege: "reconciliation_identity_update",
      aclDrift: [
        "column",
        "reconciliation_leases",
        "proposal_id",
        "PUBLIC",
        CANARY_MIGRATION_DATABASE_USER,
        "UPDATE",
        false,
      ],
    },
    {
      excessPrivilege: "table_trigger",
      aclDrift: ["table", "workflow_runs", "", "PUBLIC", CANARY_MIGRATION_DATABASE_USER, "TRIGGER", false],
    },
    {
      excessPrivilege: "table_references",
      aclDrift: ["table", "action_states", "", "PUBLIC", CANARY_MIGRATION_DATABASE_USER, "REFERENCES", false],
    },
    {
      excessPrivilege: "function_execute",
      aclDrift: [
        "function",
        "reject_runtime_mutation()",
        "",
        "PUBLIC",
        CANARY_MIGRATION_DATABASE_USER,
        "EXECUTE",
        false,
      ],
    },
    {
      aclDrift: ["table", "audit_leak", "", "PUBLIC", CANARY_MIGRATION_DATABASE_USER, "SELECT", false],
    },
    {
      aclDrift: ["database", CANARY_DATABASE_NAME, "", "PUBLIC", CANARY_MIGRATION_DATABASE_USER, "CONNECT", false],
    },
    {
      aclDrift: ["schema", CANARY_SCHEMA_NAME, "", "PUBLIC", CANARY_MIGRATION_DATABASE_USER, "USAGE", false],
    },
  ]) {
    await assert.rejects(
      () => metadataStore(new MetadataPool(drift)).verifySchema(),
      (error) => error.code === "schema_unhealthy",
      JSON.stringify(drift),
    );
  }
});

test("core store initialization is private, full, immutable, and each client uses the exact sentinel", async () => {
  const uninitializedPool = new MetadataPool();
  const uninitializedStore = metadataStore(uninitializedPool);
  const publicMembers = Reflect.ownKeys(PostgresCanaryStore.prototype);
  for (const forbidden of ["transaction", "assertContext", "assertExpected", "audit", "databaseNow", "lockedAction"])
    assert.equal(publicMembers.includes(forbidden), false);
  assert.equal(Reflect.ownKeys(uninitializedStore).includes("pool"), false);
  assert.equal(Object.isExtensible(uninitializedStore), false);
  assert.equal(uninitializedStore.transaction, undefined);
  assert.throws(() => uninitializedStore.transaction(async () => undefined), TypeError);
  assert.throws(() => {
    uninitializedStore.initialized = true;
  }, TypeError);
  await assert.rejects(
    () => uninitializedStore.readRun("run:before-initialize", context("before-initialize")),
    (error) => error.code === "not_initialized",
  );
  assert.equal(uninitializedPool.queries.length, 0);
  assert.equal(uninitializedPool.businessQueries, 0);

  const failedPool = new MetadataPool({ target: "foreign" });
  const failedStore = metadataStore(failedPool);
  await assert.rejects(
    () => failedStore.initialize(),
    (error) => error.code === "schema_unhealthy",
  );
  failedPool.target = "canary";
  await assert.rejects(
    () => failedStore.readRun("run:failed-initialize", context("failed-initialize")),
    (error) => error.code === "not_initialized",
  );
  assert.equal(failedPool.businessQueries, 0);

  const switchablePool = new MetadataPool();
  const initializedStore = metadataStore(switchablePool);
  assert.equal(await initializedStore.initialize(), true);
  assert.throws(() => {
    initializedStore.initialized = false;
  }, TypeError);
  await assert.rejects(
    () => initializedStore.readRun("run:private-state", context("private-state")),
    (error) => error.code === "run_not_found",
  );
  const businessBeforeSwitch = switchablePool.businessQueries;
  const queriesBeforeSwitch = switchablePool.queries.length;
  switchablePool.target = "foreign";
  await assert.rejects(
    () => initializedStore.readRun("run:must-not-reach-qm", context("pool-switch")),
    (error) => error.code === "schema_unhealthy",
  );
  assert.equal(switchablePool.businessQueries, businessBeforeSwitch);
  assert.doesNotMatch(
    switchablePool.queries.slice(queriesBeforeSwitch).join("\n"),
    /(?:FROM|INSERT INTO|UPDATE|DELETE FROM) risely_agent_runtime\.(?:workflow_runs|action_states|action_events|audit_events)/,
  );
});

test("runtime rejects search-path shadowing and every canary role-topology escalation", async () => {
  for (const databaseSettings of [["search_path=public,pg_catalog"], ["search_path=risely_agent_runtime"], null]) {
    await assert.rejects(
      () => metadataStore(new MetadataPool({ databaseSettings })).verifySchema(),
      (error) => error.code === "schema_unhealthy",
    );
  }
  for (const roleOverrides of [{ rolsuper: true }, { rolinherit: true }, { has_role_membership: true }]) {
    await assert.rejects(
      () => metadataStore(new MetadataPool({ roleOverrides })).verifySchema(),
      (error) => error.code === "schema_unhealthy",
    );
  }
  for (const topologyDrift of [
    { index: 0, values: { rolinherit: true } },
    { index: 2, values: { rolcanlogin: true } },
    { index: 1, values: { database_settings: ["search_path=public"] } },
    { target: "bootstrap", values: { rolcreaterole: false } },
    { target: "bootstrap", values: { owns_database: false } },
    { target: "bootstrap", values: { rolsuper: true } },
    { target: "bootstrap", missing: true },
    {
      target: "edges",
      replace: [
        {
          granted_role: CANARY_MIGRATION_DATABASE_USER,
          member_role: CANARY_BOOTSTRAP_ADMIN_ROLE,
          grantor_role: "other_superuser",
          inherit_option: false,
          set_option: false,
          admin_option: true,
          grantor_is_superuser: true,
          grantor_is_bootstrap_superuser: false,
        },
      ],
    },
    {
      target: "edges",
      add: {
        granted_role: CANARY_RUNTIME_DATABASE_USER,
        member_role: "attacker",
        grantor_role: CANARY_RUNTIME_DATABASE_USER,
        inherit_option: false,
        set_option: true,
        admin_option: false,
      },
    },
    {
      target: "edges",
      replace: [
        {
          granted_role: CANARY_OWNER_DATABASE_USER,
          member_role: CANARY_MIGRATION_DATABASE_USER,
          grantor_role: "attacker",
          inherit_option: false,
          set_option: true,
          admin_option: false,
        },
      ],
    },
    { target: "edges", replace: [] },
  ]) {
    await assert.rejects(
      () => metadataStore(new MetadataPool({ topologyDrift })).verifySchema(),
      (error) => error.code === "schema_unhealthy",
    );
  }
});

test("migration and NOLOGIN owner boundaries refuse wrong identity ownership and cross-schema authority", async () => {
  assert.equal(await assertMigrationDatabaseBoundary(new MigrationBoundaryClient()), true);
  assert.equal(await assertOwnerDatabaseBoundary(new MigrationBoundaryClient()), true);
  for (const migrationIdentity of [
    { current_database: "qm_shadow" },
    { rolinherit: true },
    { database_settings: ["search_path=public"] },
    { owns_database: true },
  ]) {
    await assert.rejects(() => assertMigrationDatabaseBoundary(new MigrationBoundaryClient({ migrationIdentity })));
  }
  for (const migrationBoundary of [
    { database_create: true },
    { direct_database_create_or_temp: true },
    { public_database_temp: false },
    { cross_schema_create_or_owner: true },
    { cross_schema_incoming_foreign_key: true },
    { exotic_canary_object: true },
    { cross_schema_table_access: true },
    { cross_schema_sequence_access: true },
    { cross_schema_security_definer_access: true },
    { schema_owner: CANARY_MIGRATION_DATABASE_USER },
    { wrong_canary_object_owner: true },
  ]) {
    await assert.rejects(() => assertMigrationDatabaseBoundary(new MigrationBoundaryClient({ migrationBoundary })));
  }
  for (const ownerIdentity of [
    { rolcanlogin: true },
    { session_user: CANARY_RUNTIME_DATABASE_USER },
    { database_settings: ["search_path=public"] },
  ]) {
    await assert.rejects(() => assertOwnerDatabaseBoundary(new MigrationBoundaryClient({ ownerIdentity })));
  }
  for (const ownerBoundary of [
    { cross_schema_incoming_foreign_key: true },
    { exotic_canary_object: true },
    { cross_schema_table_access: true },
    { cross_schema_security_definer_access: true },
    { wrong_canary_object_owner: true },
  ]) {
    await assert.rejects(() => assertOwnerDatabaseBoundary(new MigrationBoundaryClient({ ownerBoundary })));
  }
});

test("post-migration verification rejects ancestry catalog trigger and ACL drift before commit", async () => {
  assert.equal(await assertPostMigrationDatabaseContract(new PostMigrationClient()), true);
  for (const drift of [
    { migrations: [] },
    {
      migrations: [
        { version: 6, checksum: "a".repeat(64), catalog_fingerprint: CATALOG },
        { version: 7, checksum: migrationChecksum(), catalog_fingerprint: CATALOG },
      ],
    },
    {
      migrations: [{ version: 7, checksum: "b".repeat(64), catalog_fingerprint: CATALOG }],
    },
    { catalogDrift: true },
    { triggerDrift: true },
    { aclDrift: true },
  ])
    await assert.rejects(() => assertPostMigrationDatabaseContract(new PostMigrationClient(drift)));
  const migrateSource = readFileSync(`${SERVICE_DIR}src/migrate.mjs`, "utf8");
  assert.ok(
    migrateSource.indexOf("await client.query(migrationSql())") <
      migrateSource.indexOf("await assertPostMigrationDatabaseContract(client)"),
  );
  assert.ok(
    migrateSource.indexOf("await assertPostMigrationDatabaseContract(client)") <
      migrateSource.indexOf('await client.query("COMMIT")'),
  );
});

test("store database identity is compiled and rejects caller substitution", () => {
  assert.throws(
    () =>
      new PostgresCanaryStore({
        pool: new MetadataPool(),
        authority: AUTHORITY,
        schemaName: "public",
      }),
    /database security settings cannot be supplied/,
  );
  assert.throws(
    () =>
      new PostgresCanaryStore({
        pool: new MetadataPool(),
        authority: AUTHORITY,
        expectedDatabaseName: "qm",
      }),
    /database security settings cannot be supplied/,
  );
});

test("exported client verifier pins pg_catalog before any catalog query under inherited PUBLIC TEMP", async () => {
  for (const [transactionOpen, expectedPrefix] of [
    [true, ["SET LOCAL search_path = pg_catalog"]],
    [false, ["BEGIN READ ONLY", "SET LOCAL search_path = pg_catalog"]],
  ]) {
    const pool = new MetadataPool();
    let pathPinned = false;
    const guardedClient = {
      async query(sql, values) {
        if (sql === "SET LOCAL search_path = pg_catalog") pathPinned = true;
        else if (/\bpg_catalog\./.test(sql)) assert.equal(pathPinned, true, "catalog query ran before search_path pin");
        return pool.query(sql, values);
      },
    };
    assert.equal(await verifyCeoCanaryDatabaseClientBoundary(guardedClient, transactionOpen), true);
    assert.deepEqual(pool.queries.slice(0, expectedPrefix.length), expectedPrefix);
    assert.equal(pathPinned, true);
  }
});

test("database verification SQL never resolves an unqualified PostgreSQL catalog relation", () => {
  for (const relativePath of [
    "src/index.mjs",
    "src/postgres-store.mjs",
    "src/database-security.mjs",
    "src/schema.mjs",
  ]) {
    const source = readFileSync(`${SERVICE_DIR}${relativePath}`, "utf8");
    assert.doesNotMatch(source, /\b(?:FROM|JOIN|CROSS JOIN|LEFT JOIN)\s+pg_(?!catalog\.)/);
  }
});

test("stored action and run rows reject independently valid but cross-lineage payloads before audit", async () => {
  const proposal = actionProposal();
  const state = createActionState(proposal);
  const forgedState = { ...state, credentialOwnerRef: "google:subject-other" };
  const actionPool = new StoredRowPool({
    actionRow: {
      proposal_id: proposal.proposalId,
      run_id: proposal.runId,
      principal_ref: proposal.actor.principalRef,
      proposal_hash: proposal.proposalHash,
      effect_key: proposal.effectKey,
      proposal,
      state: forgedState,
      state_hash: sha256Canonical(forgedState),
      revision: forgedState.revision,
    },
  });
  const actionStore = metadataStore(actionPool);
  await actionStore.initialize();
  await assert.rejects(
    () =>
      actionStore.readAction(proposal.proposalId, {
        principalRef: "principal:ceo",
        requestHash: "a".repeat(64),
      }),
    (error) => error.code === "stored_state_corrupt",
  );
  assert.equal(actionPool.auditWrites, 0);
  const forgedRun = run({ runId: "run:forged" });
  const runPool = new StoredRowPool({
    runRow: {
      run_id: "run:1",
      principal_ref: forgedRun.actor.principalRef,
      payload_hash: sha256Canonical(forgedRun),
      payload: forgedRun,
      created_at: new Date(),
    },
  });
  const runStore = metadataStore(runPool);
  await runStore.initialize();
  await assert.rejects(
    () => runStore.readRun("run:1", { principalRef: "principal:ceo", requestHash: "b".repeat(64) }),
    (error) => error.code === "stored_run_corrupt",
  );
  assert.equal(runPool.auditWrites, 0);
});

test("runtime grants exclude ownership, DDL, truncation, immutable deletes, and audit reads", () => {
  const sql = migrationSql();
  assert.match(sql, /unexpected_preexisting_canary_object/);
  assert.match(sql, /FROM pg_catalog\.pg_type type_record[\s\S]*unexpected_preexisting_canary_object/);
  assert.match(sql, /cross_schema_incoming_foreign_key/);
  assert.match(sql, /unexpected_preexisting_canary_exotic_object/);
  for (const catalog of [
    "pg_collation",
    "pg_operator",
    "pg_opclass",
    "pg_opfamily",
    "pg_conversion",
    "pg_ts_config",
    "pg_ts_dict",
    "pg_ts_parser",
    "pg_ts_template",
    "pg_statistic_ext",
  ])
    assert.match(sql, new RegExp(`pg_catalog\\.${catalog}`));
  assert.match(sql, /preexisting_canary_migration_history/);
  assert.match(sql, /bootstrapped_canary_schema_acl_mismatch/);
  assert.doesNotMatch(sql, /CREATE SCHEMA/);
  assert.match(sql, /GRANT SELECT, INSERT ON risely_agent_runtime\.action_states TO risely_agent_runtime_runtime/);
  assert.match(
    sql,
    /GRANT UPDATE \(state, state_hash, revision, updated_at\) ON risely_agent_runtime\.action_states TO risely_agent_runtime_runtime/,
  );
  assert.match(
    sql,
    /GRANT SELECT, INSERT ON risely_agent_runtime\.action_effect_reservations TO risely_agent_runtime_runtime/,
  );
  assert.match(sql, /GRANT INSERT ON risely_agent_runtime\.audit_events TO risely_agent_runtime_runtime/);
  assert.match(
    sql,
    /GRANT SELECT, INSERT ON risely_agent_runtime\.surface_outbox_events TO risely_agent_runtime_runtime/,
  );
  assert.match(
    sql,
    /GRANT SELECT, INSERT ON risely_agent_runtime\.surface_delivery_receipts TO risely_agent_runtime_runtime/,
  );
  assert.doesNotMatch(sql, /GRANT[^;]*(?:CREATE|TRUNCATE|ALTER|DROP)[^;]*TO risely_agent_runtime_runtime/);
  assert.doesNotMatch(
    sql,
    /GRANT[^;]*(?:UPDATE|DELETE)[^;]*action_(?:events|effect_reservations)[^;]*TO risely_agent_runtime_runtime/,
  );
  assert.doesNotMatch(sql, /GRANT DELETE[^;]*action_states[^;]*TO risely_agent_runtime_runtime/);
  assert.doesNotMatch(
    sql,
    /GRANT[^;]*(?:INSERT|UPDATE|DELETE|TRUNCATE)[^;]*schema_migrations[^;]*TO risely_agent_runtime_runtime/,
  );
  assert.doesNotMatch(sql, /GRANT SELECT[^;]*audit_events[^;]*TO risely_agent_runtime_runtime/);
  assert.doesNotMatch(
    sql,
    /GRANT[^;]*(?:UPDATE|DELETE)[^;]*surface_(?:outbox_events|delivery_receipts)[^;]*TO risely_agent_runtime_runtime/,
  );
});

test("retention bounds resolved records but preserves unresolved actions and permanent effect reservations", () => {
  const sql = retentionSql();
  const migration = migrationSql();
  const effectTable =
    /CREATE TABLE IF NOT EXISTS risely_agent_runtime\.action_effect_reservations \(([\s\S]*?)\n\);/.exec(
      migration,
    )?.[1] ?? "";
  const surfaceRetention = /FOR surface_candidate IN[\s\S]*?(?=FOR terminal_candidate IN)/.exec(sql)?.[0] ?? "";
  assert.match(sql, /updated_at < clock_timestamp\(\) - interval '180 days'/);
  assert.match(sql, /runs\.created_at < clock_timestamp\(\) - interval '365 days'/);
  assert.match(sql, /WITH RECURSIVE protected_runs\(profile_ref, profile_sha256, run_id\)/);
  assert.match(
    sql,
    /parent\.profile_ref = retained_child\.profile_ref[\s\S]*parent\.run_id = retained_child\.payload->>'parentRunId'/,
  );
  assert.match(sql, /protected\.profile_ref = runs\.profile_ref[\s\S]*protected\.run_id = runs\.run_id/);
  assert.match(sql, /audit\.recorded_at < clock_timestamp\(\) - interval '400 days'/);
  assert.doesNotMatch(sql, /\b(?:CREATE\s+)?TEMP(?:ORARY)?\b/i);
  assert.doesNotMatch(sql, /DELETE FROM risely_agent_runtime\.action_effect_reservations/);
  assert.doesNotMatch(sql, /state->>'status' IN \([^)]*outcome_unknown/);
  assert.match(sql, /states\.state->>'status' NOT IN/);
  assert.equal(
    EXPECTED_CONSTRAINTS.some(([table, , type]) => table === "action_effect_reservations" && type === "f"),
    true,
  );
  assert.match(
    effectTable,
    /action_effect_reservations_proposal_id_key UNIQUE \(profile_ref, profile_sha256, proposal_id\)/,
  );
  assert.match(effectTable, /action_effect_reservations_profile_fkey FOREIGN KEY \(profile_ref, profile_sha256\)/);
  assert.match(surfaceRetention, /states\.status = 'delivered' AND reservations\.status = 'verified'/);
  assert.match(surfaceRetention, /states\.failure_code = 'provider_refused' AND reservations\.status = 'failed'/);
  assert.match(surfaceRetention, /tombstones\.terminal_status = reservations\.status/);
  assert.match(surfaceRetention, /tombstones\.message_sha256 = reservations\.message_sha256/);
  assert.doesNotMatch(surfaceRetention, /status IN \([^)]*(?:outcome_unknown|attempting|reserved|claimed|pending)/);
  assert.match(surfaceRetention, /surface_delivery_receipts/);
  assert.match(surfaceRetention, /surface_delivery_reservations/);
  assert.match(surfaceRetention, /surface_outbox_states/);
  assert.match(surfaceRetention, /surface_outbox_events/);
  assert.doesNotMatch(sql, /DELETE FROM risely_agent_runtime\.surface_delivery_tombstones/);
  assert.doesNotMatch(sql, /DELETE FROM risely_agent_runtime\.surface_event_tombstones/);
  assert.match(migration, /surface_delivery_tombstones_immutable BEFORE UPDATE OR DELETE/);
  assert.match(migration, /surface_event_tombstones_immutable BEFORE UPDATE OR DELETE/);
});

test("migration retention and runtime SQL cannot target QM public or Command Center storage", () => {
  const migration = migrationSql();
  const retention = retentionSql();
  const storeSource = readFileSync(`${SERVICE_DIR}src/postgres-store.mjs`, "utf8");
  const migrationSource = readFileSync(`${SERVICE_DIR}src/migrate.mjs`, "utf8");
  const retentionSource = readFileSync(`${SERVICE_DIR}src/retention.mjs`, "utf8");
  const databaseSecuritySource = readFileSync(`${SERVICE_DIR}src/database-security.mjs`, "utf8");
  const bootstrap = readFileSync(`${SERVICE_DIR}migrations/bootstrap.sql`, "utf8");
  for (const sql of [migration, retention]) {
    assert.doesNotMatch(sql, /\b(?:public|qm)\.[A-Za-z_][A-Za-z0-9_]*/i);
    assert.doesNotMatch(sql, /\bcommand[_-]?center\b/i);
  }
  for (const source of [storeSource, migrationSource, retentionSource, bootstrap]) {
    assert.doesNotMatch(
      source,
      /COMMAND_CENTER_(?:DATABASE|DB|POSTGRES)|command-center[^\n]*(?:postgres|database_url)/i,
    );
    assert.doesNotMatch(source, /\bCREATE\s+TEMP(?:ORARY)?\b/i);
  }
  for (const statement of retention.matchAll(/(?:ALTER TABLE|DELETE FROM|UPDATE|INSERT INTO)\s+([^\s;]+)/g)) {
    assert.match(statement[1], /^risely_agent_runtime\./);
  }
  assert.doesNotMatch(bootstrap, /\b(?:ALTER|DROP|TRUNCATE)\s+(?:TABLE|SCHEMA)\s+(?:public|qm)\b/i);
  assert.doesNotMatch(bootstrap, /\b(?:INSERT INTO|UPDATE|DELETE FROM)\s+(?:public|qm)\./i);
  assert.match(storeSource, /namespace\.nspname <> \$1[\s\S]*cross_schema_table_access/);
  assert.match(storeSource, /procedure\.prosecdef[\s\S]*cross_schema_security_definer_access/);
  assert.match(databaseSecuritySource, /foreign_key\.confrelid[\s\S]*child_namespace\.nspname <> \$1/);
  assert.match(databaseSecuritySource, /cross_schema_incoming_foreign_key/);
  assert.match(databaseSecuritySource, /exotic_canary_object/);
  assert.match(databaseSecuritySource, /pg_catalog\.pg_event_trigger[\s\S]*evtenabled <> 'D'/);
  assert.match(databaseSecuritySource, /pg_catalog\.pg_foreign_data_wrapper[\s\S]*has_foreign_data_wrapper_privilege/);
  for (const catalog of ["pg_collation", "pg_operator", "pg_conversion", "pg_ts_config", "pg_statistic_ext"])
    assert.match(databaseSecuritySource, new RegExp(`pg_catalog\\.${catalog}`));
});

test("event-expiry tombstone schema permanently binds every conflict digest", () => {
  const migration = migrationSql();
  const table =
    /CREATE TABLE IF NOT EXISTS risely_agent_runtime\.surface_event_tombstones \(([\s\S]*?)\n\);/.exec(
      migration,
    )?.[1] ?? "";
  for (const field of [
    "event_id",
    "deployment_binding_sha256",
    "outbox_payload_sha256",
    "artifact_id",
    "artifact_revision",
    "artifact_sha256",
    "eval_receipt_sha256",
    "identity_resolution_sha256",
    "target_binding_sha256",
    "message_sha256",
    "failure_code",
    "event_identity_sha256",
    "record_sha256",
  ])
    assert.match(table, new RegExp(`\\b${field}\\b`));
  assert.match(table, /surface_event_tombstones_pkey PRIMARY KEY \(profile_ref, profile_sha256, event_id\)/);
  assert.match(table, /outbox_payload_sha256_key UNIQUE/);
  assert.match(table, /event_identity_sha256_key UNIQUE/);
  assert.match(table, /failure_code = 'eval_release_expired'[\s\S]*identity_resolution_sha256 IS NULL/);
  assert.match(table, /failure_code = 'identity_resolution_expired'[\s\S]*message_sha256 IS NOT NULL/);
  assert.match(migration, /surface_event_tombstones_immutable BEFORE UPDATE OR DELETE/);
  assert.doesNotMatch(
    migration,
    /GRANT[^;]*(?:UPDATE|DELETE)[^;]*surface_event_tombstones[^;]*TO risely_agent_runtime_runtime/,
  );
});

test("surface expiry atomically records both tombstone variants and rejects tuple reuse", () => {
  const surfaceSource = readFileSync(`${LAYER_DIR}canary/service/ceo-surface/src/postgres-adapter.mjs`, "utf8");
  assert.match(
    surfaceSource,
    /surface_event_tombstones[\s\S]*profile_ref = \$1 AND profile_sha256 = \$2[\s\S]*event_id = \$3 OR outbox_payload_sha256 = \$4 OR event_identity_sha256 = \$5/,
  );
  assert.match(
    surfaceSource,
    /INSERT INTO \$\{CANARY_SCHEMA_NAME\}\.surface_event_tombstones[\s\S]*ON CONFLICT \(profile_ref, profile_sha256, event_id\) DO NOTHING/,
  );
  assert.match(
    surfaceSource,
    /WHEN reservations\.delivery_key IS NOT NULL THEN 'identity_resolution_expired'[\s\S]*ELSE 'eval_release_expired'/,
  );
  assert.match(
    surfaceSource,
    /events\.eval_receipt_sha256[\s\S]*reservations\.identity_resolution_sha256[\s\S]*reservations\.target_binding_sha256[\s\S]*reservations\.message_sha256/,
  );
  assert.match(surfaceSource, /outbox_event_retired/);
  assert.match(surfaceSource, /outbox_event_retirement_conflict/);
});

test("post-180-day retention requires exact eval and identity tombstones and never removes them", () => {
  const retention = retentionSql();
  assert.match(
    retention,
    /failure_code = 'eval_release_expired'[\s\S]*event_tombstones\.eval_receipt_sha256 = events\.eval_receipt_sha256/,
  );
  assert.match(
    retention,
    /failure_code = 'identity_resolution_expired'[\s\S]*event_tombstones\.message_sha256 = reservations\.message_sha256/,
  );
  assert.match(retention, /event_tombstones\.completed_at = states\.updated_at/);
  assert.doesNotMatch(retention, /DELETE FROM risely_agent_runtime\.surface_event_tombstones/);
});

test("surface mutations serialize behind the shared maintenance lock used exclusively by migration and retention", () => {
  assert.equal(CANARY_MAINTENANCE_LOCK_KEY, "risely_agent_runtime:maintenance:v1");
  const migrationSource = readFileSync(`${SERVICE_DIR}src/migrate.mjs`, "utf8");
  const retentionSource = readFileSync(`${SERVICE_DIR}src/retention.mjs`, "utf8");
  for (const source of [migrationSource, retentionSource]) {
    assert.match(source, /pg_advisory_xact_lock\(hashtext\(\$1\)\)/);
    assert.match(source, /\[CANARY_MAINTENANCE_LOCK_KEY\]/);
  }
  assert.equal(retentionSource.match(/assertPostMigrationDatabaseContract\(client\)/g)?.length, 2);
  assert.ok(
    retentionSource.indexOf("assertPostMigrationDatabaseContract(client)") <
      retentionSource.indexOf("client.query(retentionSql())"),
  );
  assert.ok(
    retentionSource.lastIndexOf("assertPostMigrationDatabaseContract(client)") >
      retentionSource.indexOf("client.query(retentionSql())"),
  );
  const surfaceSource = readFileSync(`${LAYER_DIR}canary/service/ceo-surface/src/postgres-adapter.mjs`, "utf8");
  const sharedLockOffset = surfaceSource.indexOf("pg_advisory_xact_lock_shared(hashtext($1))");
  const readinessOffset = surfaceSource.indexOf("verifyCeoCanaryDatabaseClientSentinel(client, runtimeScope, true)");
  const serializationLockOffset = surfaceSource.indexOf("pg_advisory_xact_lock(hashtext($1), hashtext($2))");
  assert.notEqual(sharedLockOffset, -1);
  assert.notEqual(readinessOffset, -1);
  assert.notEqual(serializationLockOffset, -1);
  assert.ok(sharedLockOffset < readinessOffset);
  assert.ok(readinessOffset < serializationLockOffset);
  assert.match(surfaceSource, /BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY/);
});

test("every core canary mutation enters shared maintenance and entity locks before a lightweight sentinel", () => {
  const storeSource = readFileSync(`${SERVICE_DIR}src/postgres-store.mjs`, "utf8");
  const transaction =
    /async #transaction\(operation, entityRef = null, requireProfile = true\) \{([\s\S]*?)\n {2}\}/.exec(
      storeSource,
    )?.[1] ?? "";
  const beginOffset = transaction.indexOf('client.query("BEGIN")');
  const maintenanceOffset = transaction.indexOf("pg_advisory_xact_lock_shared(hashtext($1))");
  const entityOffset = transaction.indexOf("pg_advisory_xact_lock(hashtext($1), hashtext($2))");
  const readinessOffset = transaction.indexOf("#verifyTransactionSentinel(client, requireProfile)");
  const operationOffset = transaction.indexOf("operation(client)");
  assert.notEqual(beginOffset, -1);
  assert.notEqual(maintenanceOffset, -1);
  assert.notEqual(entityOffset, -1);
  assert.notEqual(readinessOffset, -1);
  assert.notEqual(operationOffset, -1);
  assert.ok(beginOffset < maintenanceOffset);
  assert.ok(maintenanceOffset < readinessOffset);
  assert.ok(readinessOffset < entityOffset);
  assert.ok(entityOffset < operationOffset);
  assert.match(storeSource, /this\.runtimeScope\.profileRef}:\$\{this\.runtimeScope\.profileSha256}/);
  assert.match(storeSource, /async claimIngress[\s\S]*return this\.#transaction\(async \(client\)/);
  assert.doesNotMatch(storeSource, /async transaction\(|this\.transaction\(|this\.pool\./);
});

test("service foundation is outside QM plugin auto-discovery and secrets are execution-role-only", () => {
  assert.equal(existsSync(`${SERVICE_DIR}Dockerfile`), true);
  assert.equal(existsSync(`${LAYER_DIR}plugins/ceo-canary/Dockerfile`), false);
  const config = readFileSync(`${LAYER_DIR}qm.config.jsonc`, "utf8");
  assert.doesNotMatch(config, /"plugins"\s*:\s*\[[^\]]*ceo-canary/s);
  const terraform = readFileSync(`${LAYER_DIR}infra/ceo-canary.tf`, "utf8");
  const taskContract = readFileSync(`${LAYER_DIR}canary/deployment/ceo-canary-task-contract.json`, "utf8");
  const outputs = readFileSync(`${LAYER_DIR}infra/outputs.tf`, "utf8");
  const policy = /resource "aws_iam_role_policy" "ceo_canary_secrets" \{([\s\S]*?)\n\}/.exec(terraform)?.[1] ?? "";
  assert.match(policy, /role = aws_iam_role\.ceo_canary_execution\.id/);
  assert.match(policy, /Resource = values\(local\.ceo_canary_secrets\)/);
  assert.match(taskContract, /"CANARY_DATABASE_URL"/);
  assert.match(taskContract, /"CANARY_INGRESS_SECRET"/);
  assert.match(taskContract, /"environmentName": "DATABASE_CA_CERT",\n      "secretName": "CANARY_DATABASE_CA_CERT"/);
  const genericTerraform = readFileSync(`${LAYER_DIR}infra/main.tf`, "utf8");
  assert.match(genericTerraform, /ManageContractSecrets[\s\S]*!startswith\(name, "CANARY_"\)/);
  assert.doesNotMatch(policy, /CANARY_MIGRATION_DATABASE_URL|CORE_SIGNING_SECRET/);
  assert.match(outputs, /output "ceo_canary_database_host" \{ value = aws_db_instance\.this\.address \}/);
  assert.match(
    outputs,
    /output "ceo_canary_database_environment"[\s\S]*CANARY_BOOTSTRAP_ADMIN_ROLE\s*=\s*var\.db_username[\s\S]*CANARY_DATABASE_HOST\s*=\s*aws_db_instance\.this\.address[\s\S]*CANARY_DATABASE_PORT\s*=\s*tostring\(aws_db_instance\.this\.port\)[\s\S]*CANARY_DATABASE_NAME\s*=\s*var\.db_name/,
  );
  const dockerfile = readFileSync(`${SERVICE_DIR}Dockerfile`, "utf8");
  assert.match(dockerfile, /FROM node:[^\n]+@sha256:[0-9a-f]{64}/);
  assert.match(dockerfile, /USER node/);
});

test("secure runtime rebuilds a patched package-indexed root filesystem without vulnerable parent history", () => {
  const dockerfile = readFileSync(`${SERVICE_DIR}Dockerfile.runtime`, "utf8");
  assert.match(
    dockerfile,
    /FROM alpine:3\.23\.3@sha256:59855d3dceb3ae53991193bd03301e082b2a7faa56a514b03527ae0ec2ce3a95 AS runtime-rootfs/,
  );
  assert.match(dockerfile, /musl=1\.2\.5-r23/);
  assert.match(dockerfile, /musl-utils=1\.2\.5-r23/);
  assert.match(dockerfile, /zlib=1\.3\.2-r0/);
  assert.match(dockerfile, /libcrypto3=3\.5\.8-r0 libssl3=3\.5\.8-r0/);
  assert.match(
    dockerfile,
    /FROM 075343201918\.dkr\.ecr\.us-west-2\.amazonaws\.com\/risely-qm-pilot-ceo-canary@sha256:e51548d47725f017313b80e4ba4b4b976fd6735e8ef3e64af6fbe536ad17388b AS proven-node/,
  );
  assert.match(dockerfile, /e8d2cd6aba8f30e3fc7e686d32d7d851f33a7e5dbbc9b16fd0c3b2e65601c506/);
  assert.match(dockerfile, /FROM scratch AS production-application/);
  assert.match(dockerfile, /COPY --from=runtime-rootfs \/ \/\n/);
  assert.match(dockerfile, /COPY --from=proven-node \/usr\/local\/bin\/node \/usr\/local\/bin\/node/);
  assert.match(dockerfile, /COPY --chown=1000:1000 qm-shadow-ingress \/app\/canary\/qm-shadow-ingress/);
  assert.match(dockerfile, /FROM production-application AS runtime\nUSER node/);
  assert.doesNotMatch(dockerfile, /FROM runtime-rootfs AS production-application/);
});

test("database bootstrap uses distinct non-administrative roles and remains operator-gated", () => {
  const bootstrap = readFileSync(`${SERVICE_DIR}migrations/bootstrap.sql`, "utf8");
  const provisioner = readFileSync(`${SERVICE_DIR}src/provision-credentials.mjs`, "utf8");
  const runbook = readFileSync(`${SERVICE_DIR}migrations/RUNBOOK.md`, "utf8");
  const security = readFileSync(`${SERVICE_DIR}SECURITY.md`, "utf8");
  const operatorRunbook = readFileSync(`${LAYER_DIR}canary/deployment/DB-OPERATOR-RUNBOOK.md`, "utf8");
  assert.match(bootstrap, /risely_agent_runtime_migrator/);
  assert.match(bootstrap, /risely_agent_runtime_runtime/);
  assert.match(bootstrap, /NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);
  assert.match(bootstrap, /current_database\(\) <> 'qm'/);
  assert.doesNotMatch(bootstrap, /CREATE DATABASE|\\connect risely_agent_runtime/);
  assert.match(bootstrap, /GRANT CONNECT ON DATABASE qm TO risely_agent_runtime_migrator/);
  assert.match(bootstrap, /GRANT CONNECT ON DATABASE qm TO risely_agent_runtime_runtime/);
  assert.doesNotMatch(bootstrap, /GRANT (?:CREATE|TEMPORARY) ON DATABASE qm/);
  assert.doesNotMatch(bootstrap, /GRANT CREATE ON DATABASE qm TO risely_agent_runtime_owner/);
  assert.match(bootstrap, /CREATE ROLE risely_agent_runtime_owner NOLOGIN PASSWORD NULL NOINHERIT/);
  assert.match(bootstrap, /canary_bootstrap_requires_direct_nonsuperuser_createrole_session/);
  assert.match(
    bootstrap,
    /pg_catalog\.has_database_privilege\(session_user, pg_catalog\.current_database\(\), 'CREATE'\)/,
  );
  assert.match(
    bootstrap,
    /CREATE ROLE risely_agent_runtime_migrator NOLOGIN PASSWORD NULL NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/,
  );
  assert.match(bootstrap, /:\{\?canary_bootstrap_admin_role\}/);
  assert.match(bootstrap, /:'canary_bootstrap_admin_role' = 'qm'[\s\S]*session_user = 'qm'/);
  assert.match(
    bootstrap,
    /GRANT risely_agent_runtime_owner TO risely_agent_runtime_migrator WITH INHERIT FALSE, SET TRUE, ADMIN FALSE/,
  );
  assert.match(bootstrap, /GRANT risely_agent_runtime_owner TO SESSION_USER WITH INHERIT FALSE, SET TRUE, ADMIN FALSE/);
  assert.doesNotMatch(
    bootstrap,
    /SET ROLE risely_agent_runtime_migrator|ALTER ROLE risely_agent_runtime_migrator NOCREATEROLE/,
  );
  assert.match(bootstrap, /CREATE SCHEMA risely_agent_runtime AUTHORIZATION risely_agent_runtime_owner/);
  assert.match(bootstrap, /REVOKE risely_agent_runtime_owner FROM SESSION_USER GRANTED BY SESSION_USER/);
  assert.match(bootstrap, /canary_bootstrap_fixed_role_preexists/);
  assert.match(bootstrap, /canary_bootstrap_schema_preexists/);
  assert.ok(bootstrap.indexOf("pg_catalog.pg_event_trigger") < bootstrap.indexOf("CREATE ROLE"));
  assert.ok(bootstrap.indexOf("pg_catalog.pg_foreign_data_wrapper") < bootstrap.indexOf("CREATE ROLE"));
  assert.ok(bootstrap.indexOf("BEGIN;") < bootstrap.indexOf("CREATE ROLE"));
  assert.ok(
    bootstrap.indexOf("CREATE ROLE risely_agent_runtime_owner") <
      bootstrap.indexOf("GRANT risely_agent_runtime_owner TO risely_agent_runtime_migrator"),
  );
  assert.ok(
    bootstrap.indexOf("GRANT risely_agent_runtime_owner TO risely_agent_runtime_migrator") <
      bootstrap.indexOf("CREATE SCHEMA risely_agent_runtime AUTHORIZATION risely_agent_runtime_owner"),
  );
  assert.doesNotMatch(bootstrap, /\\password|PASSWORD\s+'[^']+'/i);
  assert.match(provisioner, /CANARY_MIGRATION_PASSWORD_FILE/);
  assert.match(provisioner, /CANARY_RUNTIME_PASSWORD_FILE/);
  assert.match(provisioner, /CANARY_BOOTSTRAP_ADMIN_PASSFILE/);
  assert.match(provisioner, /PGSSLMODE: "verify-full"/);
  assert.match(provisioner, /BEGIN;[\s\S]*\\\\password \$\{CANARY_MIGRATION_DATABASE_USER\}[\s\S]*COMMIT;/);
  assert.doesNotMatch(provisioner, /PGPASSWORD|CANARY_BOOTSTRAP_DATABASE_URL/);
  assert.ok(
    bootstrap.indexOf("REVOKE risely_agent_runtime_owner FROM SESSION_USER") <
      bootstrap.indexOf("canary_bootstrap_role_topology_mismatch"),
  );
  assert.ok(bootstrap.indexOf("canary_bootstrap_role_topology_mismatch") < bootstrap.lastIndexOf("COMMIT;"));
  assert.match(bootstrap, /grantor_role\.rolname = session_user/);
  assert.match(bootstrap, /grantor_role\.rolsuper/);
  assert.doesNotMatch(bootstrap, /(?:ALTER|DROP|REVOKE|GRANT)[^;]*\bON (?:ALL [A-Z ]+ IN SCHEMA )?public\b/i);
  assert.doesNotMatch(bootstrap, /(?:ALTER|DROP|REVOKE|GRANT)[^;]*\bqm_(?:runs|sessions|users|connectors)\b/i);
  assert.match(runbook, /existing Risely QM PostgreSQL database named `qm`/);
  assert.match(
    runbook,
    /never alters, drops, grants on, or revokes from an existing QM role, schema, table, sequence, routine, or row/,
  );
  assert.match(runbook, /no direct `TEMPORARY` or `CREATE` grant/);
  assert.match(runbook, /accepts no caller database URL and removes every container, network, volume, image/);
  assert.match(runbook, /rejects every non-loopback host/);
  assert.match(runbook, /creates all four roles as `NOLOGIN PASSWORD NULL`/);
  assert.match(runbook, /exactly the four OID-10 automatic edges plus owner-to-migrator/);
  assert.match(runbook, /five-edge topology/);
  assert.doesNotMatch(runbook, /creates all three roles|three OID-10 automatic edges|four-edge topology/);
  assert.match(security, /creates all four roles with `PASSWORD NULL` and `NOLOGIN`/);
  assert.match(security, /those four automatic `ADMIN=true`/);
  assert.doesNotMatch(security, /creates all three roles|those three automatic `ADMIN=true`/);
  assert.match(security, /No runtime or database-operator image is currently approved for task execution/);
  assert.match(security, /reported zero active findings of any severity/);
  assert.match(security, /musl and musl-utils 1\.2\.5-r23/);
  assert.match(operatorRunbook, /requires the canary schema and four roles to be absent/);
  assert.equal(TEST_DIR.endsWith("test/ceo-canary/"), true);
});
