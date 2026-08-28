import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  activationRequirements,
  durableOutboxMethods,
  durableReceiptMethods,
  receiptOptionalFields,
  receiptRequiredFields,
} from "../../canary/service/ceo-surface/src/constants.mjs";
import {
  assertDurableOutboxAdapter,
  assertDurableReceiptStoreAdapter,
  deliveryReceiptHash,
  validateDeliveryReceipt,
} from "../../canary/service/ceo-surface/src/durability.mjs";
import {
  compileDeploymentBinding,
  createSurfaceContractSuite,
  identityResolutionHash,
} from "../../canary/service/ceo-surface/src/contracts.mjs";
import { PostgresCeoSurfaceStore } from "../../canary/service/ceo-surface/src/postgres-adapter.mjs";
import { productionStartup, startProduction } from "../../canary/service/ceo-surface/src/startup.mjs";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { syntheticDeploymentProfile } from "../../canary/deployment-profiles/testing.mjs";
import { createProfileAuthority } from "../../canary/deployment-profiles/contract.mjs";
import { createRuntimeScope } from "../../canary/runtime-scope/index.mjs";
import {
  CANARY_BOOTSTRAP_ADMIN_ROLE,
  CANARY_DATABASE_NAME,
  CANARY_EVALUATION_WRITER_DATABASE_USER,
  CANARY_MIGRATION_DATABASE_USER,
  CANARY_OWNER_DATABASE_USER,
  CANARY_RUNTIME_DATABASE_USER,
  CANARY_SCHEMA_NAME,
  EXPECTED_CANARY_DATABASE_ACL,
  EXPECTED_CATALOG_AUTHORITY_SHA256,
  EXPECTED_CATALOG_AUTHORITY_V8,
  EXPECTED_DATABASE_ACL,
  SCHEMA_VERSION,
  migrationChecksum,
} from "../../canary/service/ceo-canary/src/schema.mjs";

const sourceRoot = fileURLToPath(new URL("../../canary/service/ceo-surface/src/", import.meta.url));
const runtimeScope = createRuntimeScope(ceoDeploymentProfile);

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

const readinessCatalog = Object.freeze(rawCatalogFromAuthority(EXPECTED_CATALOG_AUTHORITY_V8));

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const result = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...(await sourceFiles(path)));
    else result.push(path);
  }
  return result;
}

function deploymentBindingInput() {
  return {
    contractType: "ceo-surface-deployment",
    contractVersion: 1,
    ceoUserRef: "slack-user:ceo",
    ceoEmail: "shahryar@risely.ai",
    qmPrincipalRef: "qm:principal:ceo-canary",
    credentialOwnerRef: "credential-owner:ceo",
    slackTeamId: "T123456789",
    evalAuthorityRef: "evaluator:risely:shadow-gate",
    evalPolicySha256: "a".repeat(64),
    identityResolverAuthorityRef: "resolver:risely:slack-identity",
  };
}

function deployment() {
  return compileDeploymentBinding(deploymentBindingInput());
}

test("surface contract suites reject bindings compiled under another deployment profile", () => {
  const ceoSuite = createSurfaceContractSuite(runtimeScope);
  const syntheticSuite = createSurfaceContractSuite(createRuntimeScope(syntheticDeploymentProfile));
  const ceoBinding = ceoSuite.compileDeploymentBinding(deploymentBindingInput());
  const syntheticBinding = syntheticSuite.compileDeploymentBinding({
    ...deploymentBindingInput(),
    ceoUserRef: syntheticDeploymentProfile.audiences.slack.principalRef,
    ceoEmail: syntheticDeploymentProfile.identity.humanEmail,
    qmPrincipalRef: syntheticDeploymentProfile.identity.qmPrincipalRef,
    credentialOwnerRef: syntheticDeploymentProfile.identity.credentialOwnerRef,
  });
  assert.throws(() => ceoSuite.validateOutboxItem({}, syntheticBinding), /does not belong to this runtime scope/);
  assert.throws(
    () => syntheticSuite.validateIdentityResolution({}, ceoBinding),
    /does not belong to this runtime scope/,
  );
});

test("identity resolution lifetime derives from the bound deployment profile", () => {
  const projection = structuredClone(syntheticDeploymentProfile);
  delete projection.profileSha256;
  projection.grantPolicy.maximumIdentityLifetimeMs = 1;
  const profile = createProfileAuthority(projection);
  const suite = createSurfaceContractSuite(createRuntimeScope(profile));
  const binding = suite.compileDeploymentBinding({
    ...deploymentBindingInput(),
    ceoUserRef: profile.audiences.slack.principalRef,
    ceoEmail: profile.identity.humanEmail,
    qmPrincipalRef: profile.identity.qmPrincipalRef,
    credentialOwnerRef: profile.identity.credentialOwnerRef,
  });
  const resolution = {
    contractType: "ceo-surface-identity-resolution",
    contractVersion: 1,
    resolverReceiptRef: "resolver-receipt:synthetic",
    resolverAuthorityRef: binding.identityResolverAuthorityRef,
    deploymentBindingSha256: binding.bindingSha256,
    teamRef: binding.teamRef,
    ceoUserRef: binding.ceoUserRef,
    ceoEmail: binding.ceoEmail,
    qmPrincipalRef: binding.qmPrincipalRef,
    credentialOwnerRef: binding.credentialOwnerRef,
    slackTeamId: binding.slackTeamId,
    slackUserId: "U123456789",
    slackDirectMessageId: "D123456789",
    resolvedAt: "2026-08-26T16:00:00.000Z",
    expiresAt: "2026-08-26T16:00:00.001Z",
  };
  resolution.resolutionSha256 = identityResolutionHash(resolution);
  assert.equal(
    suite.validateIdentityResolution(resolution, binding, resolution.resolvedAt).expiresAt,
    resolution.expiresAt,
  );
  const excessive = { ...resolution, expiresAt: "2026-08-26T16:00:00.002Z" };
  excessive.resolutionSha256 = identityResolutionHash(excessive);
  assert.throws(() => suite.validateIdentityResolution(excessive, binding, resolution.resolvedAt), /lifetime exceeds/);
});

function adapter(type, bindingSha256, methods, atomicField) {
  return {
    contractType: type,
    contractVersion: 1,
    durability: "postgres",
    [atomicField]: true,
    deploymentBindingSha256: bindingSha256,
    ...Object.fromEntries(methods.map((method) => [method, async () => undefined])),
  };
}

function canaryRoleRows() {
  return [
    [CANARY_EVALUATION_WRITER_DATABASE_USER, false],
    [CANARY_MIGRATION_DATABASE_USER, true],
    [CANARY_OWNER_DATABASE_USER, false],
    [CANARY_RUNTIME_DATABASE_USER, true],
  ]
    .sort((left, right) => left[0].localeCompare(right[0]))
    .map(([rolname, rolcanlogin]) => ({
      rolname,
      rolcanlogin,
      rolinherit: false,
      rolsuper: false,
      rolcreaterole: false,
      rolcreatedb: false,
      rolreplication: false,
      rolbypassrls: false,
      owns_database: false,
      database_settings: ["search_path=pg_catalog"],
    }));
}

function canaryRoleEdges() {
  return [
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
}

function canaryDatabaseAclRows() {
  return EXPECTED_CANARY_DATABASE_ACL.map(([grantee, grantor, privilege_type, is_grantable]) => ({
    grantee,
    grantor,
    privilege_type,
    is_grantable,
  }));
}

function canaryNamespaceBoundary() {
  return {
    enabled_event_triggers: 0,
    rewrites: 0,
    policies: 0,
    inheritance: 0,
    extensions: 0,
    extension_owned_schema: 0,
    extension_owned_objects: 0,
    all_tables_publications: 0,
    publication_relations: 0,
    publication_namespaces: 0,
    subscription_relations: 0,
    schema_less_casts: 0,
    schema_less_transforms: 0,
    foreign_server_usage: 0,
    foreign_data_wrapper_authority: 0,
    foreign_user_mappings: 0,
    default_acls: 0,
    foreign_dependencies: 0,
  };
}

function runtimeBoundary() {
  return {
    database_connect: true,
    database_create: false,
    database_temp: true,
    direct_database_create_or_temp: false,
    public_database_temp: true,
    schema_usage: true,
    schema_create: false,
    schema_owner: CANARY_OWNER_DATABASE_USER,
    cross_schema_create_or_owner: false,
    wrong_canary_object_owner: false,
    cross_schema_incoming_foreign_key: false,
    exotic_canary_object: false,
    cross_schema_table_access: false,
    cross_schema_sequence_access: false,
    cross_schema_security_definer_access: false,
  };
}

class ReadinessPool {
  constructor(database = CANARY_DATABASE_NAME, user = CANARY_RUNTIME_DATABASE_USER) {
    this.queries = [];
    this.database = database;
    this.user = user;
  }

  async connect() {
    return {
      query: async (sql) => {
        this.queries.push(sql);
        if (sql.includes("/* exact canary role attributes */")) return { rows: canaryRoleRows() };
        if (sql.includes("/* exact canary bootstrap administrator */"))
          return {
            rows: [
              {
                rolname: CANARY_BOOTSTRAP_ADMIN_ROLE,
                rolcanlogin: true,
                rolcreaterole: true,
                rolsuper: false,
                owns_database: true,
                database_create: true,
              },
            ],
          };
        if (sql.includes("/* exact bidirectional canary role edges */")) return { rows: canaryRoleEdges() };
        if (sql.includes("/* exact canary database ACL */")) return { rows: canaryDatabaseAclRows() };
        if (sql.includes("/* exact canary namespace boundary */")) return { rows: [canaryNamespaceBoundary()] };
        if (sql.includes("FROM pg_catalog.pg_roles"))
          return {
            rows: [
              {
                current_user: this.user,
                current_database: this.database,
                rolname: this.user,
                rolcanlogin: true,
                rolinherit: false,
                rolsuper: false,
                rolcreaterole: false,
                rolcreatedb: false,
                rolreplication: false,
                rolbypassrls: false,
                has_role_membership: false,
                database_settings: ["search_path=pg_catalog"],
              },
            ],
          };
        if (sql.includes("/* runtime role boundary */")) return { rows: [runtimeBoundary()] };
        if (sql.includes("schema_migrations ORDER BY"))
          return { rows: [{ version: SCHEMA_VERSION, checksum: migrationChecksum() }] };
        return { rows: [], rowCount: 0 };
      },
      release() {},
    };
  }

  async query() {
    return { rows: [], rowCount: 0 };
  }
}

class SwitchableReadinessPool {
  constructor() {
    this.options = { target: "canary" };
    this.queries = [];
    this.businessQueries = 0;
  }

  async connect() {
    const target = this.options.target;
    return {
      query: async (sql) => this.response(sql, target),
      release() {},
    };
  }

  async query(sql) {
    return this.response(sql, this.options.target);
  }

  response(sql, target) {
    this.queries.push({ sql, target });
    if (/risely_agent_runtime\.surface_(?:outbox|delivery)/.test(sql)) this.businessQueries += 1;
    if (sql.includes("/* exact canary role attributes */")) return { rows: canaryRoleRows() };
    if (sql.includes("/* exact canary bootstrap administrator */"))
      return {
        rows: [
          {
            rolname: CANARY_BOOTSTRAP_ADMIN_ROLE,
            rolcanlogin: true,
            rolcreaterole: true,
            rolsuper: false,
            owns_database: true,
            database_create: true,
          },
        ],
      };
    if (sql.includes("/* exact bidirectional canary role edges */")) return { rows: canaryRoleEdges() };
    if (sql.includes("/* exact canary database ACL */")) return { rows: canaryDatabaseAclRows() };
    if (sql.includes("/* exact canary namespace boundary */")) return { rows: [canaryNamespaceBoundary()] };
    if (sql.includes("FROM pg_catalog.pg_roles"))
      return {
        rows: [
          {
            current_user: target === "canary" ? CANARY_RUNTIME_DATABASE_USER : "qm",
            current_database: target === "canary" ? CANARY_DATABASE_NAME : "qm",
            rolname: target === "canary" ? CANARY_RUNTIME_DATABASE_USER : "qm",
            rolcanlogin: true,
            rolinherit: false,
            rolsuper: false,
            rolcreaterole: false,
            rolcreatedb: false,
            rolreplication: false,
            rolbypassrls: false,
            has_role_membership: false,
            database_settings: ["search_path=pg_catalog"],
          },
        ],
      };
    if (sql.includes("migration.catalog_authority_sha256"))
      return {
        rows: [
          {
            current_user: target === "canary" ? CANARY_RUNTIME_DATABASE_USER : "qm",
            current_database: target === "canary" ? CANARY_DATABASE_NAME : "qm",
            schema_name: target === "canary" ? CANARY_SCHEMA_NAME : null,
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
    if (target !== "canary") return { rows: [], rowCount: 0 };
    if (sql.includes("/* runtime role boundary */")) return { rows: [runtimeBoundary()] };
    if (sql.includes("schema_migrations ORDER BY"))
      return {
        rows: [{ version: SCHEMA_VERSION, checksum: migrationChecksum(), catalog_fingerprint: readinessCatalog }],
      };
    if (sql.includes("AS catalog_fingerprint"))
      return { rows: [{ catalog_fingerprint: structuredClone(readinessCatalog) }] };
    if (sql.includes("array_agg(DISTINCT tableowner"))
      return {
        rows: [
          {
            schema_owner: CANARY_OWNER_DATABASE_USER,
            table_owners: [CANARY_OWNER_DATABASE_USER],
            sequence_owners: [CANARY_OWNER_DATABASE_USER],
          },
        ],
      };
    if (sql.includes("has_database_privilege"))
      return {
        rows: [
          {
            database_connect: true,
            database_create: false,
            database_temp: false,
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
          },
        ],
      };
    if (sql.includes("WITH exact_acl AS"))
      return {
        rows: EXPECTED_DATABASE_ACL.map(
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
    if (sql.includes("count(*)::integer AS owned")) return { rows: [{ owned: 0 }] };
    return { rows: [], rowCount: 0 };
  }
}

class MissingReadinessPool extends SwitchableReadinessPool {
  constructor(marker) {
    super();
    this.marker = marker;
  }

  response(sql, target) {
    if (sql.includes(this.marker)) {
      this.queries.push({ sql, target });
      return { rows: [], rowCount: 0 };
    }
    return super.response(sql, target);
  }
}

class MissingNamespaceAuthorityFieldPool extends SwitchableReadinessPool {
  response(sql, target) {
    if (sql.includes("/* exact canary namespace boundary */")) {
      this.queries.push({ sql, target });
      const boundary = canaryNamespaceBoundary();
      delete boundary.extension_owned_schema;
      return { rows: [boundary] };
    }
    return super.response(sql, target);
  }
}

class NamespaceAuthorityDriftPool extends SwitchableReadinessPool {
  constructor(field, missing = false) {
    super();
    this.field = field;
    this.missing = missing;
  }

  response(sql, target) {
    if (sql.includes("/* exact canary namespace boundary */")) {
      this.queries.push({ sql, target });
      const boundary = canaryNamespaceBoundary();
      if (this.missing) delete boundary[this.field];
      else boundary[this.field] = 1;
      return { rows: [boundary] };
    }
    return super.response(sql, target);
  }
}

class ToastAuthorityDriftPool extends SwitchableReadinessPool {
  constructor(missing = false) {
    super();
    this.missing = missing;
  }

  response(sql, target) {
    if (sql.includes("AS catalog_fingerprint")) {
      this.queries.push({ sql, target });
      const catalog = structuredClone(readinessCatalog);
      if (this.missing) delete catalog.toast;
      else catalog.toast[0].options = ["autovacuum_enabled=false"];
      return { rows: [{ catalog_fingerprint: catalog }] };
    }
    return super.response(sql, target);
  }
}

class EmptyOutboxPool {
  async connect() {
    return {
      query: async () => ({ rows: [], rowCount: 0 }),
      release() {},
    };
  }

  async query() {
    return { rows: [], rowCount: 0 };
  }
}

test("production startup is unconditionally hard disabled", () => {
  assert.equal(productionStartup.enabled, false);
  assert.equal(productionStartup.mode, "shadow");
  assert.deepEqual(productionStartup.blockers, activationRequirements);
  assert.throws(() => startProduction(), /hard-disabled/);
  assert.throws(() => startProduction({ enabled: true, adapters: {} }), /hard-disabled/);
});

test("QM and arbitrary pools fail full readiness before any surface business query", async () => {
  for (const pool of [new ReadinessPool("qm", "qm"), new ReadinessPool("other", "other_runtime")]) {
    const store = new PostgresCeoSurfaceStore({
      pool,
      scope: runtimeScope,
      deploymentBinding: deploymentBindingInput(),
    });
    await assert.rejects(
      () => store.initialize(),
      (error) => error.code === "schema_unhealthy",
    );
    assert.doesNotMatch(pool.queries.join("\n"), /surface_(?:outbox|delivery)/);
    assert.throws(() => store.adapters(), /requires full database readiness/);
  }
});

test("every acquired client is sentinel-verified after pool target and option mutation", async () => {
  const pool = new SwitchableReadinessPool();
  const store = new PostgresCeoSurfaceStore({ pool, scope: runtimeScope, deploymentBinding: deploymentBindingInput() });
  assert.equal(await store.initialize(), true);
  const adapters = store.adapters();
  assert.equal(await adapters.outbox.readOutboxEvent("outbox:absent"), null);
  const businessQueriesBeforeSwitch = pool.businessQueries;
  pool.options.target = "qm";
  await assert.rejects(
    () => adapters.outbox.readOutboxEvent("outbox:must-not-reach-qm"),
    (error) => error.code === "schema_unhealthy",
  );
  assert.equal(pool.businessQueries, businessQueriesBeforeSwitch);
  assert.equal(pool.queries.at(-2).target, "qm");
  assert.doesNotMatch(
    pool.queries
      .filter(({ target }) => target === "qm")
      .map(({ sql }) => sql)
      .join("\n"),
    /risely_agent_runtime\.surface_/,
  );
});

test("missing exact readiness rows fail closed before surface queries", async () => {
  for (const marker of [
    "/* exact canary role attributes */",
    "/* exact canary bootstrap administrator */",
    "/* exact bidirectional canary role edges */",
    "/* exact canary database ACL */",
    "/* exact canary namespace boundary */",
    "/* runtime role boundary */",
  ]) {
    const pool = new MissingReadinessPool(marker);
    const store = new PostgresCeoSurfaceStore({
      pool,
      scope: runtimeScope,
      deploymentBinding: deploymentBindingInput(),
    });
    await assert.rejects(
      () => store.initialize(),
      (error) => error.code === "schema_unhealthy",
    );
    assert.equal(pool.businessQueries, 0);
    assert.equal(
      pool.queries.some(({ sql }) => sql.includes(marker)),
      true,
    );
    assert.throws(() => store.adapters(), /requires full database readiness/);
  }
});

test("missing centralized namespace fields or full catalog authority fail before surface queries", async () => {
  for (const [pool, marker] of [
    [new MissingNamespaceAuthorityFieldPool(), "/* exact canary namespace boundary */"],
    [new MissingReadinessPool("AS catalog_fingerprint"), "AS catalog_fingerprint"],
  ]) {
    const store = new PostgresCeoSurfaceStore({
      pool,
      scope: runtimeScope,
      deploymentBinding: deploymentBindingInput(),
    });
    await assert.rejects(
      () => store.initialize(),
      (error) => error.code === "schema_unhealthy",
    );
    assert.equal(pool.businessQueries, 0);
    assert.equal(
      pool.queries.some(({ sql }) => sql.includes(marker)),
      true,
    );
    assert.throws(() => store.adapters(), /requires full database readiness/);
  }
});

test("event-trigger FDW and TOAST authority drift fail before surface queries", async () => {
  for (const pool of [
    new NamespaceAuthorityDriftPool("enabled_event_triggers", true),
    new NamespaceAuthorityDriftPool("enabled_event_triggers"),
    new NamespaceAuthorityDriftPool("foreign_data_wrapper_authority", true),
    new NamespaceAuthorityDriftPool("foreign_data_wrapper_authority"),
    new ToastAuthorityDriftPool(true),
    new ToastAuthorityDriftPool(),
  ]) {
    const store = new PostgresCeoSurfaceStore({
      pool,
      scope: runtimeScope,
      deploymentBinding: deploymentBindingInput(),
    });
    await assert.rejects(
      () => store.initialize(),
      (error) => error.code === "schema_unhealthy",
    );
    assert.equal(pool.businessQueries, 0);
    assert.throws(() => store.adapters(), /requires full database readiness/);
  }
});

test("Postgres surface store is fixed to the deployment and captures an immutable pool boundary", async () => {
  const pool = new ReadinessPool();
  const store = new PostgresCeoSurfaceStore({ pool, scope: runtimeScope, deploymentBinding: deploymentBindingInput() });
  assert.throws(() => store.adapters(), /requires full database readiness/);
  pool.connect = async () => {
    throw new Error("mutated pool method reached");
  };
  await assert.rejects(
    () => store.initialize(),
    (error) => error.code === "schema_unhealthy",
  );
  assert.match(pool.queries.join("\n"), /schema_migrations ORDER BY/);
  assert.throws(() => store.adapters(), /requires full database readiness/);
  assert.throws(() => {
    store.pool = new EmptyOutboxPool();
  }, TypeError);
  assert.throws(
    () =>
      new PostgresCeoSurfaceStore({
        pool: new ReadinessPool(),
        scope: runtimeScope,
        deploymentBinding: deploymentBindingInput(),
        schema: "public",
      }),
    /security settings cannot be supplied/,
  );
  assert.throws(
    () =>
      new PostgresCeoSurfaceStore(
        new Proxy({ pool, scope: runtimeScope, deploymentBinding: deploymentBindingInput() }, {}),
      ),
    /must not be a Proxy/,
  );
  const accessorPool = {};
  Object.defineProperty(accessorPool, "connect", { get: () => async () => undefined });
  accessorPool.query = async () => undefined;
  assert.throws(
    () =>
      new PostgresCeoSurfaceStore({
        pool: accessorPool,
        scope: runtimeScope,
        deploymentBinding: deploymentBindingInput(),
      }),
    /requires a PostgreSQL pool connect method/,
  );
});

test("empty durable outbox claim is side-effect free and returns no work", async () => {
  const store = new PostgresCeoSurfaceStore({
    pool: new EmptyOutboxPool(),
    scope: runtimeScope,
    deploymentBinding: deploymentBindingInput(),
  });
  await assert.rejects(
    () =>
      store.claimEvaluatedArtifactRevision({
        claimRef: "claim:empty",
        claimOwnerRef: "worker:empty",
        leaseSeconds: 30,
      }),
    (error) => error.code === "not_initialized",
  );
});

test("source has no server network credential environment or live adapter path", async () => {
  const source = (await Promise.all((await sourceFiles(sourceRoot)).map((path) => readFile(path, "utf8")))).join("\n");
  assert.doesNotMatch(source, /process\.env|\bfetch\s*\(|node:http|node:https|WebSocket|SocketMode|chat\.postMessage/);
  assert.doesNotMatch(source, /CORE_SIGNING_SECRET|SLACK_(?:APP|BOT)_TOKEN|xapp-|xox[baprs]-/);
  assert.doesNotMatch(source, /new\s+Map\s*\(|createServer\s*\(|listen\s*\(|aws-sdk|@aws-sdk/);
  assert.doesNotMatch(source, /plugins\//);
});

test("durability interface returns immutable method snapshots that survive source mutation", async () => {
  const binding = deployment();
  const outboxMethods = durableOutboxMethods;
  const receiptMethods = durableReceiptMethods;
  const outbox = adapter("ceo-surface-outbox-adapter", binding.bindingSha256, outboxMethods, "atomicClaims");
  const receipts = adapter(
    "ceo-surface-receipt-store-adapter",
    binding.bindingSha256,
    receiptMethods,
    "atomicReservations",
  );
  outbox.claimEvaluatedArtifactRevision = async () => "captured-outbox-method";
  receipts.reserveDeliveryKey = async () => "captured-receipt-method";
  const safeOutbox = assertDurableOutboxAdapter(outbox, binding.bindingSha256);
  const safeReceipts = assertDurableReceiptStoreAdapter(receipts, binding.bindingSha256);
  assert.equal(Object.isFrozen(safeOutbox), true);
  assert.equal(Object.isFrozen(safeReceipts), true);
  assert.equal(Object.isFrozen(safeOutbox.claimEvaluatedArtifactRevision), true);
  assert.equal(Object.isFrozen(safeReceipts.reserveDeliveryKey), true);
  assert.throws(
    () => assertDurableOutboxAdapter({ ...outbox, durability: "memory" }, binding.bindingSha256),
    /durable contract/,
  );
  assert.throws(
    () => assertDurableReceiptStoreAdapter({ ...receipts, atomicReservations: false }, binding.bindingSha256),
    /durable contract/,
  );
  assert.throws(
    () => assertDurableOutboxAdapter({ ...outbox, deploymentBindingSha256: "b".repeat(64) }, binding.bindingSha256),
    /does not match/,
  );
  assert.throws(
    () => assertDurableReceiptStoreAdapter({ ...receipts, reserveDeliveryKey: undefined }, binding.bindingSha256),
    /must be a function/,
  );
  const accessor = { ...outbox };
  Object.defineProperty(accessor, "claimEvaluatedArtifactRevision", {
    enumerable: true,
    get: () => async () => undefined,
  });
  assert.throws(() => assertDurableOutboxAdapter(accessor, binding.bindingSha256), /enumerable data properties/);
  assert.throws(() => assertDurableOutboxAdapter(new Proxy(outbox, {}), binding.bindingSha256), /must not be a Proxy/);
  const proxiedMethod = { ...outbox, claimEvaluatedArtifactRevision: new Proxy(async () => undefined, {}) };
  assert.throws(() => assertDurableOutboxAdapter(proxiedMethod, binding.bindingSha256), /must not be a Proxy/);
  outbox.claimEvaluatedArtifactRevision = async () => "mutated-outbox-method";
  outbox.atomicClaims = false;
  receipts.reserveDeliveryKey = async () => "mutated-receipt-method";
  receipts.atomicReservations = false;
  assert.equal(await safeOutbox.claimEvaluatedArtifactRevision(), "captured-outbox-method");
  assert.equal(await safeReceipts.reserveDeliveryKey(), "captured-receipt-method");
  assert.equal(safeOutbox.atomicClaims, true);
  assert.equal(safeReceipts.atomicReservations, true);
  assert.throws(() => {
    safeOutbox.claimEvaluatedArtifactRevision = async () => undefined;
  }, TypeError);
});

test("shadow publication and caller-forged live flags cannot confer receipt authority", () => {
  const publication = Object.freeze({
    providerInvocationAllowed: false,
    deliveryKey: "a".repeat(64),
    outboxEventId: "outbox:1",
    outboxPayloadSha256: "b".repeat(64),
    artifactId: "artifact:1",
    artifactRevision: "1",
    artifactSha256: "c".repeat(64),
    deploymentBindingSha256: "d".repeat(64),
    identityResolutionSha256: "e".repeat(64),
    targetBindingSha256: "1".repeat(64),
    messageSha256: "f".repeat(64),
  });
  const receipt = {
    contractType: "ceo-surface-delivery-receipt",
    contractVersion: 1,
    deliveryKey: publication.deliveryKey,
    outboxEventId: publication.outboxEventId,
    outboxPayloadSha256: publication.outboxPayloadSha256,
    artifactId: publication.artifactId,
    artifactRevision: publication.artifactRevision,
    artifactSha256: publication.artifactSha256,
    deploymentBindingSha256: publication.deploymentBindingSha256,
    identityResolutionSha256: publication.identityResolutionSha256,
    targetBindingSha256: publication.targetBindingSha256,
    messageSha256: publication.messageSha256,
    attemptRef: "attempt:slack:1",
    providerReceiptRef: "slack:receipt:1",
    status: "verified",
    attemptedAt: "2026-08-26T16:00:00.000Z",
    completedAt: "2026-08-26T16:00:01.000Z",
  };
  assert.throws(() => validateDeliveryReceipt(receipt, publication), /live receipt authority is unavailable/);
  const forged = Object.freeze({ ...publication, providerInvocationAllowed: true, mode: "live" });
  assert.throws(() => validateDeliveryReceipt(receipt, forged), /live receipt authority is unavailable/);
});

test("prospective receipt serialization does not confer live authority", () => {
  const receipt = {
    contractType: "ceo-surface-delivery-receipt",
    contractVersion: 1,
    deliveryKey: "a".repeat(64),
    outboxEventId: "outbox:1",
    outboxPayloadSha256: "b".repeat(64),
    artifactId: "artifact:1",
    artifactRevision: "1",
    artifactSha256: "c".repeat(64),
    deploymentBindingSha256: "d".repeat(64),
    identityResolutionSha256: "e".repeat(64),
    targetBindingSha256: "1".repeat(64),
    messageSha256: "f".repeat(64),
    attemptRef: "attempt:slack:1",
    providerReceiptRef: "slack:receipt:1",
    status: "verified",
    attemptedAt: "2026-08-26T16:00:00.000Z",
    completedAt: "2026-08-26T16:00:01.000Z",
  };
  receipt.receiptSha256 = deliveryReceiptHash(receipt);
  assert.equal(deliveryReceiptHash(receipt), receipt.receiptSha256);
  assert.deepEqual(
    receiptRequiredFields,
    Object.keys(receipt).filter(
      (field) => !["contractType", "contractVersion", ...receiptOptionalFields].includes(field),
    ),
  );
  assert.deepEqual(receiptOptionalFields, ["providerReceiptRef"]);
  assert.notEqual(deliveryReceiptHash({ ...receipt, status: "outcome_unknown" }), receipt.receiptSha256);
  assert.throws(
    () => validateDeliveryReceipt(receipt, { providerInvocationAllowed: true }),
    /authority is unavailable/,
  );
});
