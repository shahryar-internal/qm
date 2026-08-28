import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  assertCeoCanaryDeploymentProvenance,
  CEO_CANARY_TASK_CONTRACT,
} from "../../canary/deployment/task-definition.mjs";
import { sealedCeoCanaryTerraformProvenance } from "../../canary/deployment/sealed-provenance.mjs";

const LAYER_DIR = fileURLToPath(new URL("../../", import.meta.url));
const read = (path) => readFileSync(`${LAYER_DIR}${path}`, "utf8");
const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonical(value[key])]),
  );
};
const hash = (value) =>
  createHash("sha256")
    .update(JSON.stringify(canonical(value)))
    .digest("hex");
const rule = (protocol, fromPort, toPort, peerType, peerId) => ({ protocol, fromPort, toPort, peerType, peerId });

const provenanceFixture = () => {
  const ids = {
    task: "sg-00000001",
    endpoint: "sg-00000002",
    ingress: "sg-00000003",
    database: "sg-00000004",
    sharedDatabase: "sg-00000005",
    routeTable: "rtb-00000001",
    prefixList: "pl-00000001",
  };
  const host = "risely-qm-pilot-core.abcdefghijkl.us-west-2.rds.amazonaws.com";
  const routes = [
    { destinationType: "ipv4_cidr", destination: "10.42.0.0/16", targetType: "local", targetId: "local" },
    {
      destinationType: "prefix_list",
      destination: ids.prefixList,
      targetType: "vpc_endpoint",
      targetId: "vpce-00000005",
    },
  ];
  const network = {
    subnetIds: ["subnet-00000001", "subnet-00000002"],
    securityGroupIds: [ids.task],
    endpointSecurityGroupIds: [ids.endpoint],
    ingressSourceSecurityGroupId: ids.ingress,
    sharedDatabaseSecurityGroupId: ids.sharedDatabase,
    databaseSecurityGroupId: ids.database,
    securityGroups: {
      task: {
        id: ids.task,
        ingressRules: [rule("tcp", 8080, 8080, "security_group", ids.ingress)],
        egressRules: [
          rule("tcp", 5432, 5432, "security_group", ids.database),
          rule("tcp", 443, 443, "security_group", ids.endpoint),
          rule("tcp", 443, 443, "prefix_list", ids.prefixList),
        ],
      },
      endpoints: {
        id: ids.endpoint,
        ingressRules: [
          rule("tcp", 443, 443, "security_group", ids.task),
          rule("tcp", 443, 443, "security_group", ids.ingress),
        ],
        egressRules: [],
      },
      database: {
        id: ids.database,
        ingressRules: [rule("tcp", 5432, 5432, "security_group", ids.task)],
        egressRules: [],
      },
    },
    routeTable: { id: ids.routeTable, routes, defaultIpv4RouteCount: 0, defaultIpv6RouteCount: 0 },
    assignPublicIp: false,
    publicListener: false,
    providerEgress: false,
    endpoints: Object.fromEntries([
      ...["ecr.api", "ecr.dkr", "logs", "secretsmanager"].map((name, index) => [
        name,
        {
          id: `vpce-0000000${index + 1}`,
          serviceName: `com.amazonaws.us-west-2.${name}`,
          type: "Interface",
          privateDnsEnabled: true,
          subnetIds: ["subnet-00000001", "subnet-00000002"],
          securityGroupIds: [ids.endpoint],
          policySha256: String(index + 1).repeat(64),
        },
      ]),
      [
        "s3",
        {
          id: "vpce-00000005",
          serviceName: "com.amazonaws.us-west-2.s3",
          type: "Gateway",
          privateDnsEnabled: false,
          subnetIds: [],
          securityGroupIds: [],
          routeTableIds: [ids.routeTable],
          policySha256: "5".repeat(64),
        },
      ],
    ]),
  };
  const contract = {
    schemaVersion: 1,
    accountId: "075343201918",
    region: "us-west-2",
    clusterName: "risely-qm-pilot",
    serviceName: "ceo-canary",
    family: "risely-qm-pilot-ceo-canary",
    image: `075343201918.dkr.ecr.us-west-2.amazonaws.com/risely-qm-pilot-ceo-canary@sha256:${"a".repeat(64)}`,
    deploymentProfileRef: "deployment-profile:risely:ceo:v1",
    database: {
      arn: "arn:aws:rds:us-west-2:075343201918:db:risely-qm-pilot-core",
      identifier: "risely-qm-pilot-core",
      host,
      port: 5432,
      name: "qm",
      attachedSecurityGroupIds: [ids.database, ids.sharedDatabase].sort(),
    },
    environment: {
      ...CEO_CANARY_TASK_CONTRACT.environment,
      AWS_REGION: "us-west-2",
      CANARY_DATABASE_HOST: host,
      CANARY_DATABASE_PORT: "5432",
      CANARY_DATABASE_NAME: "qm",
      CANARY_DATABASE_SCHEMA: "risely_agent_runtime",
      CANARY_RUNTIME_DATABASE_USER: "risely_agent_runtime_runtime",
    },
    secrets: {
      CANARY_DATABASE_URL:
        "arn:aws:secretsmanager:us-west-2:075343201918:secret:risely/qm-pilot/CANARY_DATABASE_URL-AbCd12",
      CANARY_INGRESS_SECRET:
        "arn:aws:secretsmanager:us-west-2:075343201918:secret:risely/qm-pilot/CANARY_INGRESS_SECRET-AbCd12",
      DATABASE_CA_CERT:
        "arn:aws:secretsmanager:us-west-2:075343201918:secret:risely/qm-pilot/CANARY_DATABASE_CA_CERT-AbCd12",
    },
    iam: {
      taskRoleArn: "arn:aws:iam::075343201918:role/risely-qm-pilot-ceo-canary-task",
      executionRoleArn: "arn:aws:iam::075343201918:role/risely-qm-pilot-ceo-canary-execution",
      taskRoleDenyAllPolicyName: "risely-qm-pilot-ceo-canary-deny-all",
      deploymentPrincipalAvailable: false,
    },
    container: structuredClone(CEO_CANARY_TASK_CONTRACT.container),
    logging: {
      groupName: "/ecs/risely-qm-pilot-ceo-canary",
      region: "us-west-2",
      streamPrefix: "ceo-canary",
      mode: "non-blocking",
      maxBufferSize: "4m",
    },
    network,
    service: {
      desiredCount: 0,
      enableExecuteCommand: false,
      serviceRegistryArn: "arn:aws:servicediscovery:us-west-2:075343201918:service/srv-AbCd1234",
      loadBalancerCount: 0,
    },
  };
  return {
    contract,
    contractSha256: hash(contract),
    taskDefinitionArn: "arn:aws:ecs:us-west-2:075343201918:task-definition/risely-qm-pilot-ceo-canary:1",
    serviceArn: "arn:aws:ecs:us-west-2:075343201918:service/risely-qm-pilot/risely-qm-pilot-ceo-canary",
    clusterArn: "arn:aws:ecs:us-west-2:075343201918:cluster/risely-qm-pilot",
  };
};

const observationFor = (terraform) => ({
  taskDefinition: {
    arn: terraform.taskDefinitionArn,
    family: terraform.contract.family,
    taskRoleArn: terraform.contract.iam.taskRoleArn,
    executionRoleArn: terraform.contract.iam.executionRoleArn,
    cpu: "256",
    memory: "512",
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    runtimePlatform: { operatingSystemFamily: "LINUX", cpuArchitecture: "X86_64" },
    provenanceSha256: terraform.contractSha256,
    containerDefinitions: [
      {
        name: "ceo-canary",
        image: terraform.contract.image,
        essential: true,
        user: "node",
        privileged: false,
        readonlyRootFilesystem: true,
        portMappings: [{ containerPort: 8080, protocol: "tcp", appProtocol: "http" }],
        environment: Object.entries(terraform.contract.environment)
          .map(([name, value]) => ({ name, value: String(value) }))
          .sort((left, right) => left.name.localeCompare(right.name)),
        secrets: CEO_CANARY_TASK_CONTRACT.secretBindings.map(({ environmentName }) => ({
          name: environmentName,
          valueFrom: terraform.contract.secrets[environmentName],
        })),
        linuxParameters: { initProcessEnabled: true, capabilities: { add: [], drop: ["ALL"] } },
        healthCheck: {
          command: [
            "CMD-SHELL",
            "node -e \"fetch('http://127.0.0.1:8080/readyz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))\"",
          ],
          interval: 30,
          timeout: 5,
          retries: 3,
          startPeriod: 20,
        },
        logConfiguration: {
          logDriver: "awslogs",
          options: {
            "awslogs-group": "/ecs/risely-qm-pilot-ceo-canary",
            "awslogs-region": "us-west-2",
            "awslogs-stream-prefix": "ceo-canary",
            mode: "non-blocking",
            "max-buffer-size": "4m",
          },
        },
      },
    ],
  },
  service: {
    arn: terraform.serviceArn,
    name: "risely-qm-pilot-ceo-canary",
    clusterArn: terraform.clusterArn,
    taskDefinitionArn: terraform.taskDefinitionArn,
    desiredCount: 0,
    enableExecuteCommand: false,
    launchType: "FARGATE",
    assignPublicIp: false,
    subnetIds: terraform.contract.network.subnetIds,
    securityGroupIds: terraform.contract.network.securityGroupIds,
    serviceRegistryArn: terraform.contract.service.serviceRegistryArn,
    loadBalancerCount: 0,
    provenanceSha256: terraform.contractSha256,
  },
  network: structuredClone(terraform.contract.network),
  database: structuredClone(terraform.contract.database),
});

const verifierFor = async (terraform) => {
  const source = read("canary/deployment/task-definition.mjs")
    .replace(
      'import taskContract from "./ceo-canary-task-contract.json" with { type: "json" };',
      `const taskContract = ${JSON.stringify(CEO_CANARY_TASK_CONTRACT)};`,
    )
    .replace(
      'import { sealedCeoCanaryTerraformProvenance } from "./sealed-provenance.mjs";',
      `const sealedCeoCanaryTerraformProvenance = ${JSON.stringify(terraform)};`,
    );
  const module = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
  return module.assertCeoCanaryDeploymentProvenance;
};

test("production provenance is sealed to the observed inert deployment and callers cannot self-bless", () => {
  assert.equal(Object.isFrozen(sealedCeoCanaryTerraformProvenance), true);
  assert.equal(Object.isFrozen(sealedCeoCanaryTerraformProvenance.contract), true);
  assert.equal(Object.isFrozen(sealedCeoCanaryTerraformProvenance.contract.network), true);
  assert.equal(assertCeoCanaryDeploymentProvenance.length, 1);
  assert.deepEqual(
    assertCeoCanaryDeploymentProvenance(observationFor(sealedCeoCanaryTerraformProvenance)),
    sealedCeoCanaryTerraformProvenance,
  );
  assert.throws(() => {
    sealedCeoCanaryTerraformProvenance.contract.service.desiredCount = 1;
  }, TypeError);
  const probes = [
    {},
    { taskDefinition: {}, service: {}, network: {} },
    {
      taskDefinition: { image: "caller-selected@sha256:" + "a".repeat(64) },
      service: { desiredCount: 0 },
      network: { defaultRouteCount: 0 },
    },
  ];
  for (const observation of probes) {
    assert.throws(() => assertCeoCanaryDeploymentProvenance(observation, structuredClone(observation)));
  }
  let traps = 0;
  const hostile = new Proxy(
    {},
    {
      get() {
        traps += 1;
        throw new Error("observation read");
      },
      ownKeys() {
        traps += 1;
        throw new Error("observation enumerated");
      },
      getOwnPropertyDescriptor() {
        traps += 1;
        throw new Error("observation described");
      },
    },
  );
  assert.throws(() => assertCeoCanaryDeploymentProvenance(hostile), /deployment observation is invalid/);
  assert.equal(traps, 0);
  const nested = observationFor(sealedCeoCanaryTerraformProvenance);
  nested.network = hostile;
  assert.throws(() => assertCeoCanaryDeploymentProvenance(nested), /deployment observation.network is invalid/);
  assert.equal(traps, 0);
  let getters = 0;
  const accessor = observationFor(sealedCeoCanaryTerraformProvenance);
  Object.defineProperty(accessor.service, "desiredCount", {
    enumerable: true,
    get() {
      getters += 1;
      return 0;
    },
  });
  assert.throws(() => assertCeoCanaryDeploymentProvenance(accessor), /deployment observation.service is invalid/);
  assert.equal(getters, 0);
  for (const path of [["service"], ["network"], ["database"], ["network", "endpoints", "ecr.api"]]) {
    const polluted = observationFor(sealedCeoCanaryTerraformProvenance);
    let target = polluted;
    for (const key of path) target = target[key];
    Object.defineProperty(target, "__proto__", {
      value: { polluted: true },
      enumerable: true,
      configurable: true,
      writable: true,
    });
    assert.throws(() => assertCeoCanaryDeploymentProvenance(polluted), /invalid|does not match/);
    assert.equal(Object.hasOwn(Object.prototype, "polluted"), false);
  }
  for (const [key, value] of [
    [
      "toJSON",
      () => {
        throw new Error("callable hook invoked");
      },
    ],
    ["extraUndefined", undefined],
    ["extraSymbol", Symbol("hidden")],
    ["extraBigInt", 1n],
    ["extraNaN", Number.NaN],
    ["extraInfinity", Number.POSITIVE_INFINITY],
  ]) {
    const malformed = observationFor(sealedCeoCanaryTerraformProvenance);
    Object.defineProperty(malformed.service, key, { value, enumerable: true });
    assert.throws(() => assertCeoCanaryDeploymentProvenance(malformed), /deployment observation.service/);
  }
  let calls = 0;
  const callable = observationFor(sealedCeoCanaryTerraformProvenance);
  const validService = structuredClone(callable.service);
  callable.service.desiredCount = 99;
  Object.defineProperty(callable.service, "toJSON", {
    value() {
      calls += 1;
      return validService;
    },
    enumerable: true,
  });
  assert.throws(
    () => assertCeoCanaryDeploymentProvenance(callable),
    /deployment observation.service.toJSON is invalid/,
  );
  assert.equal(calls, 0);
});

test("closed task contract fixes production identity, database, health, and zero authority", () => {
  assert.deepEqual(
    {
      accountId: CEO_CANARY_TASK_CONTRACT.accountId,
      region: CEO_CANARY_TASK_CONTRACT.region,
      clusterName: CEO_CANARY_TASK_CONTRACT.clusterName,
      family: CEO_CANARY_TASK_CONTRACT.family,
      repository: CEO_CANARY_TASK_CONTRACT.ecrRepository,
      profileRef: CEO_CANARY_TASK_CONTRACT.deploymentProfileRef,
      database: CEO_CANARY_TASK_CONTRACT.database,
    },
    {
      accountId: "075343201918",
      region: "us-west-2",
      clusterName: "risely-qm-pilot",
      family: "risely-qm-pilot-ceo-canary",
      repository: "risely-qm-pilot-ceo-canary",
      profileRef: "deployment-profile:risely:ceo:v1",
      database: { name: "qm", port: 5432, schema: "risely_agent_runtime", runtimeUser: "risely_agent_runtime_runtime" },
    },
  );
  assert.equal(CEO_CANARY_TASK_CONTRACT.container.healthPath, "/readyz");
  assert.equal(CEO_CANARY_TASK_CONTRACT.container.user, "node");
  assert.equal(CEO_CANARY_TASK_CONTRACT.container.readOnlyRootFilesystem, true);
  assert.equal(CEO_CANARY_TASK_CONTRACT.container.privileged, false);
  assert.deepEqual(CEO_CANARY_TASK_CONTRACT.container.dropCapabilities, ["ALL"]);
  assert.deepEqual(CEO_CANARY_TASK_CONTRACT.secretBindings, [
    { environmentName: "CANARY_DATABASE_URL", secretName: "CANARY_DATABASE_URL" },
    { environmentName: "CANARY_INGRESS_SECRET", secretName: "CANARY_INGRESS_SECRET" },
    { environmentName: "DATABASE_CA_CERT", secretName: "CANARY_DATABASE_CA_CERT" },
  ]);
  assert.equal(CEO_CANARY_TASK_CONTRACT.service.desiredCount, 0);
  assert.equal(CEO_CANARY_TASK_CONTRACT.service.enableExecuteCommand, false);
  assert.deepEqual(CEO_CANARY_TASK_CONTRACT.network, {
    assignPublicIp: false,
    publicListener: false,
    providerEgress: false,
  });
  for (const name of Object.keys(CEO_CANARY_TASK_CONTRACT.environment)) {
    assert.doesNotMatch(name, /EVALUATION_WRITER|MIGRATION|PROVIDER_(?:KEY|TOKEN|SECRET)/);
  }
  assert.throws(() => {
    CEO_CANARY_TASK_CONTRACT.database.name = "command_center";
  }, TypeError);
});

test("generic deploy authority excludes every canary mutation and role path", () => {
  const main = read("infra/main.tf");
  const canary = read("infra/ceo-canary.tf");
  const tfvars = read("infra/terraform.tfvars");
  for (const statement of [
    "ManageStackTaskDefinitions",
    "PushDeploymentImages",
    "RollClusterServices",
    "ManageContractSecrets",
    "TailServiceLogs",
  ]) {
    const start =
      main.indexOf(`Sid    = "${statement}"`) >= 0
        ? main.indexOf(`Sid    = "${statement}"`)
        : main.indexOf(`Sid      = "${statement}"`);
    assert.notEqual(start, -1, statement);
    const block = main.slice(start, main.indexOf("\n      },", start) + 9);
    assert.match(block, /name != local\.ceo_canary_service_name|!startswith\(name, "CANARY_"\)/, statement);
  }
  assert.match(main, /task_role_arns[\s\S]*if name != local\.ceo_canary_service_name/);
  assert.match(main, /execution_role_arns[\s\S]*if name != local\.ceo_canary_service_name/);
  assert.doesNotMatch(main, /aws_iam_role\.ceo_canary_(?:task|execution)/);
  assert.doesNotMatch(tfvars, /ceo-canary-(?:task|execution)/);
  assert.match(canary, /resource "aws_iam_role" "ceo_canary_task"/);
  assert.match(canary, /resource "aws_iam_role" "ceo_canary_execution"/);
  assert.match(
    canary,
    /resource "aws_iam_role_policy" "ceo_canary_task_deny_all"[\s\S]*Effect\s+= "Deny"[\s\S]*Action\s+= "\*"[\s\S]*Resource = "\*"/,
  );
  assert.match(canary, /deploymentPrincipalAvailable = false/);
  assert.doesNotMatch(canary, /github_deploy|AssumeRoleWithWebIdentity|ceo_canary_deploy/);
});

test("database access is additive and leaves the shared security group byte shape intact", () => {
  const main = read("infra/main.tf");
  const canary = read("infra/ceo-canary.tf");
  assert.match(
    main,
    /resource "aws_security_group" "database" \{\n  name   = "\$\{var\.cluster_name\}-database"\n  vpc_id = aws_vpc\.this\.id\n  ingress \{\n    from_port       = 5432\n    to_port         = 5432\n    protocol        = "tcp"\n    security_groups = local\.service_security_groups\n  \}\n  tags = local\.tags\n\}/,
  );
  assert.match(main, /resource "aws_db_instance" "this"[\s\S]*port\s+= 5432/);
  assert.match(
    main,
    /vpc_security_group_ids\s+= \[aws_security_group\.database\.id, aws_security_group\.ceo_canary_database\.id\]/,
  );
  assert.match(
    canary,
    /resource "aws_security_group" "ceo_canary_database"[\s\S]*from_port\s+= local\.ceo_canary_contract\.database\.port[\s\S]*security_groups = \[aws_security_group\.ceo_canary\.id\]/,
  );
  assert.match(
    canary,
    /resource "aws_vpc_security_group_egress_rule" "ceo_canary_database"[\s\S]*referenced_security_group_id = aws_security_group\.ceo_canary_database\.id[\s\S]*from_port\s+= aws_db_instance\.this\.port/,
  );
  assert.doesNotMatch(
    canary,
    /resource "aws_vpc_security_group_egress_rule" "ceo_canary_database"[\s\S]*referenced_security_group_id = aws_security_group\.database\.id/,
  );
});

test("private endpoints are policy-bounded while preserving VPC-wide DNS clients", () => {
  const canary = read("infra/ceo-canary.tf");
  for (const service of ["ecr.api", "ecr.dkr", "logs", "secretsmanager"]) {
    assert.match(canary, new RegExp(service.replace(".", "\\.")));
  }
  assert.match(canary, /private_dns_enabled = true/);
  assert.match(canary, /security_groups = \[aws_security_group\.ceo_canary\.id, aws_security_group\.services\.id\]/);
  for (const action of [
    "secretsmanager:GetSecretValue",
    "logs:PutLogEvents",
    "ecr:GetAuthorizationToken",
    "ecr:BatchGetImage",
    "s3:GetObject",
  ]) {
    assert.match(canary, new RegExp(action.replace(":", "\\:")));
  }
  assert.match(canary, /prod-\$\{var\.region\}-starport-layer-bucket\/\*/);
  assert.doesNotMatch(canary, /aws_nat_gateway|assign_public_ip\s+= true|aws_lb_listener/);
  assert.match(canary, /destinationType == "ipv4_cidr" && route\.destination == "0\.0\.0\.0\/0"/);
  assert.match(canary, /destinationType == "ipv6_cidr" && route\.destination == "::\/0"/);
  assert.match(canary, /network\.routeTable\.defaultIpv4RouteCount == 0/);
  assert.match(canary, /network\.routeTable\.defaultIpv6RouteCount == 0/);
  assert.match(canary, /destinationType = "prefix_list"[\s\S]*targetType\s+= "vpc_endpoint"/);
  assert.match(canary, /providerEgress\s+= local\.ceo_canary_contract\.network\.providerEgress/);
});

test("Terraform emits a complete hashed provenance contract and creates dedicated runtime identities", () => {
  const main = read("infra/main.tf");
  const canary = read("infra/ceo-canary.tf");
  const outputs = read("infra/outputs.tf");
  const tfvars = read("infra/terraform.tfvars");
  assert.match(
    canary,
    /ceo_canary_task_provenance_sha256 = sha256\(jsonencode\(local\.ceo_canary_task_provenance_contract\)\)/,
  );
  for (const field of [
    "accountId",
    "region",
    "clusterName",
    "serviceName",
    "family",
    "image",
    "deploymentProfileRef",
    "database",
    "environment",
    "secrets",
    "iam",
    "container",
    "logging",
    "network",
    "service",
  ]) {
    assert.match(canary, new RegExp(`\\b${field}\\b`), field);
  }
  for (const outputField of ["contract", "contractSha256", "taskDefinitionArn", "serviceArn", "clusterArn"]) {
    assert.match(outputs, new RegExp(`\\b${outputField}\\b`), outputField);
  }
  assert.match(canary, /CeoCanaryProvenanceSha256 = local\.ceo_canary_task_provenance_sha256/g);
  assert.doesNotMatch(canary, /\bmoved\s*\{/);
  assert.match(canary, /resource "aws_ecs_task_definition" "ceo_canary"/);
  assert.match(canary, /resource "aws_ecs_service" "ceo_canary"/);
  assert.match(
    canary,
    /resource "aws_ecs_service" "ceo_canary"[\s\S]*desired_count\s+= local\.ceo_canary_contract\.service\.desiredCount[\s\S]*prevent_destroy = true/,
  );
  assert.match(canary, /healthPath/);
  assert.match(read("canary/deployment/ceo-canary-task-contract.json"), /"healthPath": "\/readyz"/);
  assert.match(
    main,
    /for_each\s+= \{ for name, service in var\.services : name => service if name != local\.ceo_canary_service_name \}/,
  );
  assert.match(tfvars, /"ceo-canary"\s*:/);
  for (const name of ["core", "web-ui", "admin", "portal", "auth", "gemini-compat"]) {
    assert.match(tfvars, new RegExp(`"${name}"\\s*:`));
  }
});

test("existing QM bootstrap architectures remain aligned with observed Terraform state", () => {
  const tfvars = read("infra/terraform.tfvars");
  for (const name of ["core", "web-ui", "admin", "portal", "auth"]) {
    assert.match(tfvars, new RegExp(`"${name}"\\s*:\\s*\\{[\\s\\S]*?"architecture"\\s*:\\s*"arm64"`));
  }
  assert.match(tfvars, /"gemini-compat"\s*:\s*\{[\s\S]*?"architecture"\s*:\s*"amd64"/);
});

test("sealed provenance accepts only exact normalized network and RDS observations", async () => {
  const terraform = provenanceFixture();
  const verify = await verifierFor(terraform);
  const observation = observationFor(terraform);
  assert.deepEqual(verify(observation), terraform);
  const mutations = [
    (value) =>
      value.network.securityGroups.task.egressRules.push(rule("tcp", 443, 443, "security_group", "sg-00000006")),
    (value) => {
      value.network.securityGroups.endpoints.ingressRules[0].fromPort = 0;
    },
    (value) =>
      value.network.securityGroups.database.ingressRules.push(rule("tcp", 5432, 5432, "security_group", "sg-00000006")),
    (value) => value.database.attachedSecurityGroupIds.push("sg-00000006"),
    (value) =>
      value.network.routeTable.routes.push({
        destinationType: "ipv4_cidr",
        destination: "0.0.0.0/0",
        targetType: "internet_gateway",
        targetId: "igw-00000001",
      }),
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(observation);
    mutate(changed);
    assert.throws(() => verify(changed), /does not match/);
  }
});

test("a rehashed sealed contract cannot authorize widened rules, extra RDS groups, or default routes", async () => {
  const mutations = [
    (contract) => {
      contract.network.securityGroups.task.egressRules[0].toPort = 65535;
    },
    (contract) => contract.database.attachedSecurityGroupIds.push("sg-00000006"),
    (contract) => {
      contract.network.routeTable.routes.push({
        destinationType: "ipv6_cidr",
        destination: "::/0",
        targetType: "internet_gateway",
        targetId: "igw-00000001",
      });
      contract.network.routeTable.defaultIpv6RouteCount = 1;
    },
  ];
  for (const mutate of mutations) {
    const terraform = provenanceFixture();
    mutate(terraform.contract);
    terraform.contractSha256 = hash(terraform.contract);
    const verify = await verifierFor(terraform);
    assert.throws(() => verify(observationFor(terraform)), /Terraform .* (?:does not match|invalid)/);
  }
});
