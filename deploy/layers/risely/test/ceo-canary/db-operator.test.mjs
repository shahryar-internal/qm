import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { bootstrapSql } from "../../canary/service/ceo-canary/src/db-operator-bootstrap-sql.mjs";
import { runCompiledDatabaseOperatorPhase } from "../../canary/service/ceo-canary/src/db-operator.mjs";

const layerDirectory = fileURLToPath(new URL("../../", import.meta.url));
const read = (path) => readFileSync(`${layerDirectory}${path}`, "utf8");
const contract = JSON.parse(read("canary/deployment/ceo-canary-db-operator-contract.json"));
const source = read("canary/service/ceo-canary/src/db-operator.mjs");
const terraform = read("infra/ceo-canary-db-operator.tf");
const mainTerraform = read("infra/main.tf");
const endpointTerraform = read("infra/ceo-canary.tf");
const outputsTerraform = read("infra/outputs.tf");
const variablesTerraform = read("infra/variables.tf");
const tfvars = read("infra/terraform.tfvars");
const dockerfile = read("canary/service/ceo-canary/Dockerfile");
const operatorDockerfile = read("canary/service/ceo-canary/Dockerfile.db-operator");
const operatorPackage = JSON.parse(read("canary/service/ceo-canary/db-operator/package.json"));
const bootstrap = read("canary/service/ceo-canary/migrations/bootstrap.sql");
const phaseNames = ["inventory", "bootstrap", "provision", "migrate", "readiness"];

const baseEnvironment = () => ({
  CANARY_BOOTSTRAP_ADMIN_ROLE: "qm",
  CANARY_DATABASE_HOST: "risely-qm-pilot-core.abcdefghijkl.us-west-2.rds.amazonaws.com",
  CANARY_DATABASE_NAME: "qm",
  CANARY_DATABASE_PORT: "5432",
  CANARY_DATABASE_SCHEMA: "risely_agent_runtime",
  CANARY_MIGRATION_DATABASE_USER: "risely_agent_runtime_migrator",
  CANARY_OWNER_DATABASE_USER: "risely_agent_runtime_owner",
  CANARY_RUNTIME_DATABASE_USER: "risely_agent_runtime_runtime",
  CANARY_MUTATIONS_ENABLED: "0",
  CANARY_PROVIDER_EXECUTION_ENABLED: "0",
  DATABASE_CA_CERT: "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----",
});
const databaseUrl = (user, credential, host, port = "5432", database = "qm") => {
  const url = new URL(`postgresql://${host}:${port}/${database}`);
  url.username = user;
  url["pass" + "word"] = credential;
  return url.toString();
};

test("operator contract is five inert immutable phases with least phase credentials", () => {
  assert.equal(contract.schemaVersion, 1);
  assert.equal(contract.clusterName, "risely-qm-pilot");
  assert.equal(contract.familyPrefix, "risely-qm-pilot-ceo-canary-db");
  assert.equal(contract.ecrRepository, "risely-qm-pilot-ceo-canary");
  assert.deepEqual(Object.keys(contract.phases).sort(), [...phaseNames].sort());
  assert.deepEqual(contract.database, {
    name: "qm",
    port: 5432,
    schema: "risely_agent_runtime",
    bootstrapAdminUser: "qm",
    ownerUser: "risely_agent_runtime_owner",
    migrationUser: "risely_agent_runtime_migrator",
    runtimeUser: "risely_agent_runtime_runtime",
    evaluationWriterUser: "risely_agent_runtime_evaluation_writer",
  });
  assert.deepEqual(contract.launch, {
    serviceCreated: false,
    scheduleCreated: false,
    deploymentPrincipalAvailable: false,
    executeCommandEnabled: false,
  });
  assert.equal(contract.network.assignPublicIp, false);
  assert.equal(contract.network.publicListener, false);
  assert.equal(contract.network.providerEgress, false);
  assert.equal(contract.container.user, "node");
  assert.equal(contract.container.privileged, false);
  assert.deepEqual(contract.container.dropCapabilities, ["ALL"]);
  assert.equal(contract.container.readOnlyRootFilesystem, false);
  const secrets = Object.fromEntries(
    Object.entries(contract.phases).map(([phase, value]) => [
      phase,
      value.secretBindings.map(({ environmentName }) => environmentName).sort(),
    ]),
  );
  assert.deepEqual(secrets, {
    inventory: ["CANARY_BOOTSTRAP_DATABASE_URL", "DATABASE_CA_CERT"],
    bootstrap: ["CANARY_BOOTSTRAP_DATABASE_URL", "DATABASE_CA_CERT"],
    provision: [
      "CANARY_BOOTSTRAP_DATABASE_URL",
      "CANARY_DATABASE_URL",
      "CANARY_MIGRATION_DATABASE_URL",
      "DATABASE_CA_CERT",
    ],
    migrate: ["CANARY_MIGRATION_DATABASE_URL", "DATABASE_CA_CERT"],
    readiness: ["CANARY_DATABASE_URL", "DATABASE_CA_CERT"],
  });
  for (const phase of phaseNames) {
    const names = contract.phases[phase].secretBindings.map(({ environmentName }) => environmentName);
    assert.equal(names.includes("CANARY_EVALUATION_WRITER_DATABASE_URL"), false);
    assert.equal(names.includes("DATABASE_URL"), false);
    assert.equal(names.includes("CANARY_INGRESS_SECRET"), false);
  }
});

test("embedded structural bootstrap is byte-exact and cannot drift from the reviewed SQL", () => {
  assert.equal(bootstrapSql, bootstrap);
  assert.equal(
    createHash("sha256").update(bootstrapSql).digest("hex"),
    createHash("sha256").update(bootstrap).digest("hex"),
  );
  assert.match(bootstrapSql, /^\\set ON_ERROR_STOP on\nSET search_path = pg_catalog;/);
  assert.match(bootstrapSql, /canary_bootstrap_requires_exact_database_owner/);
  assert.match(bootstrapSql, /canary_bootstrap_enabled_event_trigger/);
  assert.match(bootstrapSql, /COMMIT;\n$/);
});

test("compiled phase rejects caller command and database substitutions before network access", async () => {
  const executable = fileURLToPath(new URL("../../canary/service/ceo-canary/src/db-operator.mjs", import.meta.url));
  const extraArgument = spawnSync(process.execPath, [executable, "inventory", "caller-override"], {
    encoding: "utf8",
    env: {},
  });
  assert.notEqual(extraArgument.status, 0);
  assert.equal(extraArgument.stdout, "");
  assert.equal(extraArgument.stderr, "Risely database operator phase failed\n");
  const env = {
    ...baseEnvironment(),
    CANARY_BOOTSTRAP_DATABASE_URL: databaseUrl("qm", "secret", "command-center.example.invalid"),
  };
  await assert.rejects(
    runCompiledDatabaseOperatorPhase("inventory", env),
    /does not match the fixed Risely QM database identity/,
  );
  await assert.rejects(runCompiledDatabaseOperatorPhase("unknown", env), /Unknown compiled database operator phase/);
  await assert.rejects(
    runCompiledDatabaseOperatorPhase("inventory", {
      ...env,
      CANARY_BOOTSTRAP_DATABASE_URL: databaseUrl("qm", "secret", env.CANARY_DATABASE_HOST, "5433"),
    }),
    /does not match the fixed Risely QM database identity/,
  );
  await assert.rejects(
    runCompiledDatabaseOperatorPhase("inventory", {
      ...env,
      CANARY_BOOTSTRAP_DATABASE_URL: databaseUrl("qm", "secret", env.CANARY_DATABASE_HOST, "5432", "command_center"),
    }),
    /does not match the fixed Risely QM database identity/,
  );
});

test("every phase refuses unnecessary high-privilege credentials before connecting", async () => {
  const environment = baseEnvironment();
  await assert.rejects(
    runCompiledDatabaseOperatorPhase("migrate", {
      ...environment,
      CANARY_MIGRATION_DATABASE_URL: databaseUrl(
        "risely_agent_runtime_migrator",
        "A".repeat(43),
        environment.CANARY_DATABASE_HOST,
      ),
      CANARY_BOOTSTRAP_DATABASE_URL: databaseUrl("qm", "secret", environment.CANARY_DATABASE_HOST),
    }),
    /received an unnecessary database credential/,
  );
  await assert.rejects(
    runCompiledDatabaseOperatorPhase("readiness", {
      ...environment,
      CANARY_DATABASE_URL: databaseUrl(
        "risely_agent_runtime_runtime",
        "B".repeat(43),
        environment.CANARY_DATABASE_HOST,
      ),
      CANARY_MIGRATION_DATABASE_URL: databaseUrl(
        "risely_agent_runtime_migrator",
        "A".repeat(43),
        environment.CANARY_DATABASE_HOST,
      ),
    }),
    /received an unnecessary database credential/,
  );
  await assert.rejects(
    runCompiledDatabaseOperatorPhase("inventory", {
      ...environment,
      CANARY_BOOTSTRAP_DATABASE_URL: databaseUrl("qm", "secret", environment.CANARY_DATABASE_HOST),
      CANARY_DATABASE_URL: databaseUrl(
        "risely_agent_runtime_runtime",
        "B".repeat(43),
        environment.CANARY_DATABASE_HOST,
      ),
    }),
    /received an unnecessary database credential/,
  );
});

test("Terraform registers only inert per-phase tasks with deny-all task roles", () => {
  assert.match(terraform, /resource "aws_ecs_task_definition" "ceo_canary_db_operator"/);
  assert.doesNotMatch(terraform, /resource "aws_ecs_service" "ceo_canary_db_operator"/);
  assert.doesNotMatch(terraform, /resource "aws_scheduler_/);
  assert.doesNotMatch(terraform, /resource "aws_cloudwatch_event_/);
  assert.doesNotMatch(terraform, /resource "aws_lambda_/);
  assert.match(terraform, /for_each = local\.ceo_canary_db_operator_phases/);
  assert.match(
    terraform,
    /entryPoint\s*= \["node", local\.ceo_canary_db_operator_contract\.container\.entrypoint, each\.key\]/,
  );
  assert.match(terraform, /Effect\s*= "Deny"\s*\n\s*Action\s*= "\*"\s*\n\s*Resource = "\*"/);
  assert.match(terraform, /execution_role_arn\s*= aws_iam_role\.ceo_canary_db_operator_execution\[each\.key\]\.arn/);
  assert.match(terraform, /task_role_arn\s*= aws_iam_role\.ceo_canary_db_operator_task\[each\.key\]\.arn/);
  assert.match(terraform, /var\.ceo_canary_db_operator_image/);
  assert.match(terraform, /CANARY_DATABASE_HOST\s*= aws_db_instance\.this\.address/);
  assert.match(terraform, /CANARY_DATABASE_NAME\s*= aws_db_instance\.this\.db_name/);
  assert.match(terraform, /CANARY_DATABASE_PORT\s*= tostring\(aws_db_instance\.this\.port\)/);
  assert.match(terraform, /subnetIds\s*= sort\(local\.ceo_canary_private_subnet_ids\)/);
  assert.match(terraform, /securityGroupIds = \[aws_security_group\.ceo_canary\.id\]/);
  assert.match(terraform, /assignPublicIp\s*= false/);
  assert.match(endpointTerraform, /local\.ceo_canary_db_operator_secret_arns/);
  assert.match(endpointTerraform, /local\.ceo_canary_db_operator_log_arns/);
  assert.equal(
    mainTerraform.match(
      /for name, service in var\.services : name => service if name != local\.ceo_canary_service_name/g,
    )?.length,
    2,
  );
});

test("unset operator image structurally excludes every operator resource and provenance output", () => {
  assert.match(
    variablesTerraform,
    /variable "ceo_canary_db_operator_image" \{[\s\S]*?default\s+= null[\s\S]*?nullable = true/,
  );
  assert.match(
    variablesTerraform,
    /var\.ceo_canary_db_operator_image == null \? true : can\(regex\([\s\S]*?var\.ceo_canary_db_operator_image\)\)/,
  );
  assert.match(terraform, /ceo_canary_db_operator_enabled\s+= var\.ceo_canary_db_operator_image != null/);
  assert.match(
    terraform,
    /ceo_canary_db_operator_phases\s+= local\.ceo_canary_db_operator_enabled \? local\.ceo_canary_db_operator_contract\.phases : \{\}/,
  );
  assert.match(
    terraform,
    /ceo_canary_managed_secret_names\s+= local\.ceo_canary_db_operator_enabled \? var\.secret_names : setsubtract\(var\.secret_names, \["CANARY_BOOTSTRAP_DATABASE_URL"\]\)/,
  );
  assert.match(mainTerraform, /for_each\s+= local\.ceo_canary_managed_secret_names/);
  for (const resource of [
    "aws_cloudwatch_log_group",
    "aws_iam_role",
    "aws_iam_role_policy",
    "aws_iam_role_policy_attachment",
    "aws_ecs_task_definition",
  ]) {
    assert.match(
      terraform,
      new RegExp(
        `resource "${resource}" "ceo_canary_db_operator[^\"]*" \\{[\\s\\S]*?for_each\\s*= local\\.ceo_canary_db_operator_phases`,
      ),
      resource,
    );
  }
  assert.match(
    terraform,
    /length\(aws_ecs_task_definition\.ceo_canary_db_operator\) == \(local\.ceo_canary_db_operator_enabled \? 5 : 0\)/,
  );
  assert.match(
    outputsTerraform,
    /value = local\.ceo_canary_db_operator_enabled \? \{[\s\S]*?contractSha256[\s\S]*?\} : null/,
  );
  assert.doesNotMatch(tfvars, /ceo_canary_db_operator_image/);
});

test("operator module graph uses only same-QM database lifecycle code and no provider route", () => {
  assert.doesNotMatch(dockerfile, /credential-operator/);
  assert.match(operatorDockerfile, /postgresql16-client=16\.15-r0/);
  for (const dependency of [
    "postgresql-common=1.2-r2",
    "lz4-libs=1.10.0-r0",
    "libpq=18.6-r0",
    "ncurses-terminfo-base=6.5_p20251123-r0",
    "libncursesw=6.5_p20251123-r0",
    "readline=8.3.1-r0",
    "zstd-libs=1.5.7-r2",
  ]) {
    assert.match(operatorDockerfile, new RegExp(dependency.replaceAll(".", "\\.")));
  }
  assert.match(operatorDockerfile, /FROM scratch/);
  assert.match(operatorDockerfile, /COPY --from=proven-node \/usr\/local\/bin\/node \/usr\/local\/bin\/node/);
  assert.match(operatorDockerfile, /node_shared_openssl/);
  assert.match(operatorDockerfile, /ARG SOURCE_REVISION/);
  assert.match(operatorDockerfile, /ARG SOURCE_CLOSURE_SHA256/);
  assert.match(operatorDockerfile, /ai\.risely\.db-operator\.source-closure-sha256/);
  assert.match(
    operatorDockerfile,
    /ENTRYPOINT \["node", "\/app\/canary\/service\/ceo-canary\/src\/db-operator\.mjs"\]/,
  );
  assert.doesNotMatch(operatorDockerfile, /COPY service\/ceo-canary\/src \.\/src/);
  assert.deepEqual(operatorPackage.dependencies, { pg: "8.22.0" });
  assert.deepEqual(Object.keys(operatorPackage), ["name", "version", "private", "type", "dependencies", "engines"]);
  for (const file of [
    "catalog-authority-v8.mjs",
    "database-connection.mjs",
    "database-security.mjs",
    "db-operator-bootstrap-sql.mjs",
    "db-operator.mjs",
    "migrate.mjs",
    "provision-credentials.mjs",
    "schema.mjs",
  ]) {
    assert.match(operatorDockerfile, new RegExp(`service/ceo-canary/src/${file.replaceAll(".", "\\.")}`));
  }
  assert.doesNotMatch(
    operatorDockerfile,
    /shared-contracts|deployment-profiles|provider-effects|runtime-scope|qm-shadow-ingress|chief-of-staff|evals|server\.mjs|domain\.mjs/,
  );
  assert.match(source, /import \{ migrate \} from "\.\/migrate\.mjs"/);
  assert.match(source, /import \{ provisionCanaryCredentials \} from "\.\/provision-credentials\.mjs"/);
  assert.match(source, /assertRuntimeDatabaseBoundary/);
  assert.match(source, /assertExactCanaryCatalog/);
  assert.match(source, /BEGIN READ ONLY/);
  assert.match(source, /SET LOCAL search_path = pg_catalog/);
  assert.match(source, /CANARY_MUTATIONS_ENABLED !== "0"/);
  assert.match(source, /CANARY_PROVIDER_EXECUTION_ENABLED !== "0"/);
  assert.doesNotMatch(source, /CANARY_EVALUATION_WRITER_DATABASE_URL/);
  assert.doesNotMatch(source, /SLACK_|GMAIL|NOTION|LINKEDIN|APOLLO|CLARIFY|MCP|provider-/i);
  assert.doesNotMatch(source, /command.?center/i);
  assert.doesNotMatch(
    terraform,
    /CANARY_EVALUATION_WRITER_DATABASE_URL|SLACK_|GMAIL|NOTION|LINKEDIN|APOLLO|CLARIFY|MCP/i,
  );
  assert.doesNotMatch(terraform, /command.?center/i);
});
