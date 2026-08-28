import { createHash } from "node:crypto";
import { types } from "node:util";
import taskContract from "./ceo-canary-task-contract.json" with { type: "json" };
import { sealedCeoCanaryTerraformProvenance } from "./sealed-provenance.mjs";

const SHA256 = /^[0-9a-f]{64}$/;
const AWS_ID = Object.freeze({
  subnet: /^subnet-[0-9a-f]{8,17}$/,
  securityGroup: /^sg-[0-9a-f]{8,17}$/,
  routeTable: /^rtb-[0-9a-f]{8,17}$/,
  endpoint: /^vpce-[0-9a-f]{8,17}$/,
  prefixList: /^pl-[0-9a-f]{8,17}$/,
});

function freeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const item of Object.values(value)) freeze(item);
  return Object.freeze(value);
}

function exactKeys(value, keys, name) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(`${name} is invalid`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${name} keys are invalid`);
  }
  return value;
}

function snapshot(value, name, ancestors = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "object") throw new Error(`${name} is invalid`);
  if (types.isProxy(value) || ancestors.has(value)) throw new Error(`${name} is invalid`);
  const nextAncestors = new Set(ancestors).add(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new Error(`${name} is invalid`);
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) throw new Error(`${name} is invalid`);
    const keys = Object.keys(descriptors).filter((key) => key !== "length");
    if (keys.length !== value.length) throw new Error(`${name} is invalid`);
    return Array.from({ length: value.length }, (_, index) => {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
        throw new Error(`${name} is invalid`);
      }
      return snapshot(descriptor.value, `${name}[${index}]`, nextAncestors);
    });
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${name} is invalid`);
  const result = {};
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!("value" in descriptor) || descriptor.enumerable !== true) throw new Error(`${name} is invalid`);
    Object.defineProperty(result, key, {
      value: snapshot(descriptor.value, `${name}.${key}`, nextAncestors),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return result;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonical(value[key])]),
  );
}

function digest(value) {
  return createHash("sha256")
    .update(JSON.stringify(canonical(value)))
    .digest("hex");
}

function exact(value, expected, name) {
  if (JSON.stringify(canonical(value)) !== JSON.stringify(canonical(expected)))
    throw new Error(`${name} does not match`);
}

function uniqueIds(values, pattern, name, expectedLength) {
  if (
    !Array.isArray(values) ||
    values.length !== expectedLength ||
    new Set(values).size !== values.length ||
    values.some((value) => typeof value !== "string" || !pattern.test(value))
  ) {
    throw new Error(`${name} are invalid`);
  }
  return [...values];
}

function exactStaticContract(contract) {
  for (const key of [
    "schemaVersion",
    "accountId",
    "region",
    "clusterName",
    "serviceName",
    "family",
    "deploymentProfileRef",
  ]) {
    if (contract[key] !== taskContract[key]) throw new Error(`Terraform contract ${key} is invalid`);
  }
  exactKeys(
    contract.database,
    ["arn", "identifier", "host", "port", "name", "attachedSecurityGroupIds"],
    "Terraform contract database",
  );
  const expectedImagePrefix = `${taskContract.accountId}.dkr.ecr.${taskContract.region}.amazonaws.com/${taskContract.ecrRepository}@sha256:`;
  if (
    typeof contract.image !== "string" ||
    !contract.image.startsWith(expectedImagePrefix) ||
    !SHA256.test(contract.image.slice(-64))
  ) {
    throw new Error("Terraform contract image is invalid");
  }
  const expectedDatabaseSuffix = `.${taskContract.region}.rds.amazonaws.com`;
  if (
    typeof contract.database.host !== "string" ||
    !contract.database.host.startsWith(`${taskContract.clusterName}-core.`) ||
    !contract.database.host.endsWith(expectedDatabaseSuffix) ||
    contract.database.arn !==
      `arn:aws:rds:${taskContract.region}:${taskContract.accountId}:db:${taskContract.clusterName}-core` ||
    contract.database.identifier !== `${taskContract.clusterName}-core` ||
    contract.database.port !== taskContract.database.port ||
    contract.database.name !== taskContract.database.name
  ) {
    throw new Error("Terraform contract database is invalid");
  }
  const expectedEnvironment = {
    ...taskContract.environment,
    AWS_REGION: taskContract.region,
    CANARY_DATABASE_HOST: contract.database.host,
    CANARY_DATABASE_PORT: String(taskContract.database.port),
    CANARY_DATABASE_NAME: taskContract.database.name,
    CANARY_DATABASE_SCHEMA: taskContract.database.schema,
    CANARY_RUNTIME_DATABASE_USER: taskContract.database.runtimeUser,
  };
  exactKeys(contract.environment, Object.keys(expectedEnvironment), "Terraform contract environment");
  exact(contract.environment, expectedEnvironment, "Terraform contract environment");
  const secretEnvironmentNames = taskContract.secretBindings.map(({ environmentName }) => environmentName);
  exactKeys(contract.secrets, secretEnvironmentNames, "Terraform contract secrets");
  for (const { environmentName, secretName } of taskContract.secretBindings) {
    const prefix = `arn:aws:secretsmanager:${taskContract.region}:${taskContract.accountId}:secret:${taskContract.secretsPrefix}${secretName}-`;
    if (
      typeof contract.secrets[environmentName] !== "string" ||
      !contract.secrets[environmentName].startsWith(prefix)
    ) {
      throw new Error("Terraform contract secret ARN is invalid");
    }
  }
  exactKeys(
    contract.iam,
    ["taskRoleArn", "executionRoleArn", "taskRoleDenyAllPolicyName", "deploymentPrincipalAvailable"],
    "Terraform contract IAM",
  );
  if (
    contract.iam.taskRoleArn !== `arn:aws:iam::${taskContract.accountId}:role/${taskContract.family}-task` ||
    contract.iam.executionRoleArn !== `arn:aws:iam::${taskContract.accountId}:role/${taskContract.family}-execution` ||
    contract.iam.taskRoleDenyAllPolicyName !== `${taskContract.family}-deny-all` ||
    contract.iam.deploymentPrincipalAvailable !== false
  ) {
    throw new Error("Terraform contract IAM is invalid");
  }
  exact(contract.container, taskContract.container, "Terraform contract container");
  exactKeys(
    contract.logging,
    ["groupName", "region", "streamPrefix", "mode", "maxBufferSize"],
    "Terraform contract logging",
  );
  exact(
    contract.logging,
    {
      groupName: `/ecs/${taskContract.family}`,
      region: taskContract.region,
      streamPrefix: taskContract.serviceName,
      mode: "non-blocking",
      maxBufferSize: "4m",
    },
    "Terraform contract logging",
  );
  return expectedEnvironment;
}

function exactNetwork(contract) {
  const network = exactKeys(
    contract.network,
    [
      "subnetIds",
      "securityGroupIds",
      "endpointSecurityGroupIds",
      "ingressSourceSecurityGroupId",
      "sharedDatabaseSecurityGroupId",
      "databaseSecurityGroupId",
      "securityGroups",
      "routeTable",
      "assignPublicIp",
      "publicListener",
      "providerEgress",
      "endpoints",
    ],
    "Terraform contract network",
  );
  const subnetIds = uniqueIds(network.subnetIds, AWS_ID.subnet, "private subnet IDs", 2);
  const securityGroupIds = uniqueIds(network.securityGroupIds, AWS_ID.securityGroup, "task security group IDs", 1);
  const endpointSecurityGroupIds = uniqueIds(
    network.endpointSecurityGroupIds,
    AWS_ID.securityGroup,
    "endpoint security group IDs",
    1,
  );
  for (const [name, value] of [
    ["ingress source security group", network.ingressSourceSecurityGroupId],
    ["shared database security group", network.sharedDatabaseSecurityGroupId],
    ["database security group", network.databaseSecurityGroupId],
  ]) {
    if (typeof value !== "string" || !AWS_ID.securityGroup.test(value)) throw new Error(`${name} is invalid`);
  }
  const securityIdentities = [
    ...securityGroupIds,
    ...endpointSecurityGroupIds,
    network.ingressSourceSecurityGroupId,
    network.sharedDatabaseSecurityGroupId,
    network.databaseSecurityGroupId,
  ];
  if (new Set(securityIdentities).size !== securityIdentities.length)
    throw new Error("security group identities collide");
  if (network.assignPublicIp !== false || network.publicListener !== false || network.providerEgress !== false) {
    throw new Error("Terraform contract network authority is invalid");
  }
  exactKeys(network.securityGroups, ["task", "endpoints", "database"], "Terraform security groups");
  const taskSecurityGroup = exactKeys(
    network.securityGroups.task,
    ["id", "ingressRules", "egressRules"],
    "Terraform task security group",
  );
  const endpointSecurityGroup = exactKeys(
    network.securityGroups.endpoints,
    ["id", "ingressRules", "egressRules"],
    "Terraform endpoint security group",
  );
  const databaseSecurityGroup = exactKeys(
    network.securityGroups.database,
    ["id", "ingressRules", "egressRules"],
    "Terraform database security group",
  );
  const rule = (protocol, fromPort, toPort, peerType, peerId) => ({ protocol, fromPort, toPort, peerType, peerId });
  exact(
    taskSecurityGroup,
    {
      id: securityGroupIds[0],
      ingressRules: [
        rule(
          "tcp",
          taskContract.container.port,
          taskContract.container.port,
          "security_group",
          network.ingressSourceSecurityGroupId,
        ),
      ],
      egressRules: [
        rule(
          "tcp",
          taskContract.database.port,
          taskContract.database.port,
          "security_group",
          network.databaseSecurityGroupId,
        ),
        rule("tcp", 443, 443, "security_group", endpointSecurityGroupIds[0]),
        rule("tcp", 443, 443, "prefix_list", network.routeTable.routes[1]?.destination),
      ],
    },
    "Terraform task security group",
  );
  exact(
    endpointSecurityGroup,
    {
      id: endpointSecurityGroupIds[0],
      ingressRules: [
        rule("tcp", 443, 443, "security_group", securityGroupIds[0]),
        rule("tcp", 443, 443, "security_group", network.ingressSourceSecurityGroupId),
      ],
      egressRules: [],
    },
    "Terraform endpoint security group",
  );
  exact(
    databaseSecurityGroup,
    {
      id: network.databaseSecurityGroupId,
      ingressRules: [
        rule("tcp", taskContract.database.port, taskContract.database.port, "security_group", securityGroupIds[0]),
      ],
      egressRules: [],
    },
    "Terraform database security group",
  );
  const routeTable = exactKeys(
    network.routeTable,
    ["id", "routes", "defaultIpv4RouteCount", "defaultIpv6RouteCount"],
    "Terraform route table",
  );
  if (typeof routeTable.id !== "string" || !AWS_ID.routeTable.test(routeTable.id)) {
    throw new Error("private route table is invalid");
  }
  exact(
    routeTable.routes,
    [
      {
        destinationType: "ipv4_cidr",
        destination: "10.42.0.0/16",
        targetType: "local",
        targetId: "local",
      },
      {
        destinationType: "prefix_list",
        destination: routeTable.routes[1]?.destination,
        targetType: "vpc_endpoint",
        targetId: routeTable.routes[1]?.targetId,
      },
    ],
    "Terraform private routes",
  );
  if (
    !AWS_ID.prefixList.test(routeTable.routes[1]?.destination) ||
    !AWS_ID.endpoint.test(routeTable.routes[1]?.targetId) ||
    routeTable.defaultIpv4RouteCount !==
      routeTable.routes.filter(
        ({ destinationType, destination }) => destinationType === "ipv4_cidr" && destination === "0.0.0.0/0",
      ).length ||
    routeTable.defaultIpv6RouteCount !==
      routeTable.routes.filter(
        ({ destinationType, destination }) => destinationType === "ipv6_cidr" && destination === "::/0",
      ).length ||
    routeTable.defaultIpv4RouteCount !== 0 ||
    routeTable.defaultIpv6RouteCount !== 0
  ) {
    throw new Error("Terraform route authority is invalid");
  }
  exactKeys(network.endpoints, ["ecr.api", "ecr.dkr", "logs", "secretsmanager", "s3"], "Terraform endpoints");
  const endpointIds = [];
  for (const name of ["ecr.api", "ecr.dkr", "logs", "secretsmanager"]) {
    const endpoint = exactKeys(
      network.endpoints[name],
      ["id", "serviceName", "type", "privateDnsEnabled", "subnetIds", "securityGroupIds", "policySha256"],
      `Terraform ${name} endpoint`,
    );
    if (
      !AWS_ID.endpoint.test(endpoint.id) ||
      endpoint.serviceName !== `com.amazonaws.${taskContract.region}.${name}` ||
      endpoint.type !== "Interface" ||
      endpoint.privateDnsEnabled !== true ||
      !SHA256.test(endpoint.policySha256)
    ) {
      throw new Error(`Terraform ${name} endpoint is invalid`);
    }
    exact(endpoint.subnetIds, subnetIds, `Terraform ${name} endpoint subnets`);
    exact(endpoint.securityGroupIds, endpointSecurityGroupIds, `Terraform ${name} endpoint security groups`);
    endpointIds.push(endpoint.id);
  }
  const s3 = exactKeys(
    network.endpoints.s3,
    [
      "id",
      "serviceName",
      "type",
      "privateDnsEnabled",
      "subnetIds",
      "securityGroupIds",
      "routeTableIds",
      "policySha256",
    ],
    "Terraform s3 endpoint",
  );
  if (
    !AWS_ID.endpoint.test(s3.id) ||
    s3.serviceName !== `com.amazonaws.${taskContract.region}.s3` ||
    s3.type !== "Gateway" ||
    s3.privateDnsEnabled !== false ||
    s3.subnetIds.length !== 0 ||
    s3.securityGroupIds.length !== 0 ||
    !SHA256.test(s3.policySha256)
  ) {
    throw new Error("Terraform s3 endpoint is invalid");
  }
  exact(s3.routeTableIds, [routeTable.id], "Terraform s3 route tables");
  if (s3.id !== routeTable.routes[1].targetId) throw new Error("Terraform s3 route target is invalid");
  endpointIds.push(s3.id);
  if (new Set(endpointIds).size !== endpointIds.length) throw new Error("endpoint identities collide");
}

function expectedTaskDefinition(terraform) {
  const contract = terraform.contract;
  const environment = Object.entries(contract.environment)
    .map(([name, value]) => ({ name, value: String(value) }))
    .sort((left, right) => left.name.localeCompare(right.name));
  return {
    arn: terraform.taskDefinitionArn,
    family: contract.family,
    taskRoleArn: contract.iam.taskRoleArn,
    executionRoleArn: contract.iam.executionRoleArn,
    cpu: String(contract.container.cpu),
    memory: String(contract.container.memory),
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    runtimePlatform: { operatingSystemFamily: "LINUX", cpuArchitecture: contract.container.architecture },
    provenanceSha256: terraform.contractSha256,
    containerDefinitions: [
      {
        name: contract.container.name,
        image: contract.image,
        essential: true,
        user: contract.container.user,
        privileged: contract.container.privileged,
        readonlyRootFilesystem: contract.container.readOnlyRootFilesystem,
        portMappings: [{ containerPort: contract.container.port, protocol: "tcp", appProtocol: "http" }],
        environment,
        secrets: taskContract.secretBindings.map(({ environmentName }) => ({
          name: environmentName,
          valueFrom: contract.secrets[environmentName],
        })),
        linuxParameters: {
          initProcessEnabled: true,
          capabilities: { add: [], drop: [...contract.container.dropCapabilities] },
        },
        healthCheck: {
          command: [
            "CMD-SHELL",
            `node -e \"fetch('http://127.0.0.1:${contract.container.port}${contract.container.healthPath}').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))\"`,
          ],
          interval: contract.container.healthIntervalSeconds,
          timeout: contract.container.healthTimeoutSeconds,
          retries: contract.container.healthRetries,
          startPeriod: contract.container.healthStartPeriodSeconds,
        },
        logConfiguration: {
          logDriver: "awslogs",
          options: {
            "awslogs-group": contract.logging.groupName,
            "awslogs-region": contract.logging.region,
            "awslogs-stream-prefix": contract.logging.streamPrefix,
            mode: contract.logging.mode,
            "max-buffer-size": contract.logging.maxBufferSize,
          },
        },
      },
    ],
  };
}

function expectedService(terraform) {
  const contract = terraform.contract;
  return {
    arn: terraform.serviceArn,
    name: contract.family,
    clusterArn: terraform.clusterArn,
    taskDefinitionArn: terraform.taskDefinitionArn,
    desiredCount: contract.service.desiredCount,
    enableExecuteCommand: contract.service.enableExecuteCommand,
    launchType: "FARGATE",
    assignPublicIp: contract.network.assignPublicIp,
    subnetIds: contract.network.subnetIds,
    securityGroupIds: contract.network.securityGroupIds,
    serviceRegistryArn: contract.service.serviceRegistryArn,
    loadBalancerCount: contract.service.loadBalancerCount,
    provenanceSha256: terraform.contractSha256,
  };
}

export const CEO_CANARY_TASK_CONTRACT = freeze(structuredClone(taskContract));

export function assertCeoCanaryDeploymentProvenance(observation) {
  if (sealedCeoCanaryTerraformProvenance === null) {
    throw new Error("sealed Terraform provenance is unavailable");
  }
  const observed = snapshot(observation, "deployment observation");
  exactKeys(observed, ["taskDefinition", "service", "network", "database"], "deployment observation");
  const terraform = sealedCeoCanaryTerraformProvenance;
  exactKeys(
    terraform,
    ["contract", "contractSha256", "taskDefinitionArn", "serviceArn", "clusterArn"],
    "Terraform provenance output",
  );
  exactKeys(
    terraform.contract,
    [
      "schemaVersion",
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
    ],
    "Terraform contract",
  );
  exactStaticContract(terraform.contract);
  exactNetwork(terraform.contract);
  exact(
    terraform.contract.database.attachedSecurityGroupIds,
    [
      terraform.contract.network.databaseSecurityGroupId,
      terraform.contract.network.sharedDatabaseSecurityGroupId,
    ].sort(),
    "Terraform RDS security group attachments",
  );
  exactKeys(
    terraform.contract.service,
    ["desiredCount", "enableExecuteCommand", "serviceRegistryArn", "loadBalancerCount"],
    "Terraform service contract",
  );
  if (
    terraform.contract.service.desiredCount !== 0 ||
    terraform.contract.service.enableExecuteCommand !== false ||
    terraform.contract.service.loadBalancerCount !== 0 ||
    typeof terraform.contract.service.serviceRegistryArn !== "string" ||
    !new RegExp(
      `^arn:aws:servicediscovery:${taskContract.region}:${taskContract.accountId}:service/srv-[A-Za-z0-9]+$`,
    ).test(terraform.contract.service.serviceRegistryArn)
  ) {
    throw new Error("Terraform service contract is invalid");
  }
  if (!SHA256.test(terraform.contractSha256) || digest(terraform.contract) !== terraform.contractSha256) {
    throw new Error("Terraform provenance digest is invalid");
  }
  const taskArnPrefix = `arn:aws:ecs:${taskContract.region}:${taskContract.accountId}:task-definition/${taskContract.family}:`;
  const serviceArnPrefix = `arn:aws:ecs:${taskContract.region}:${taskContract.accountId}:service/${taskContract.clusterName}/${taskContract.family}`;
  const clusterArn = `arn:aws:ecs:${taskContract.region}:${taskContract.accountId}:cluster/${taskContract.clusterName}`;
  if (
    typeof terraform.taskDefinitionArn !== "string" ||
    !new RegExp(`^${taskArnPrefix}[1-9][0-9]*$`).test(terraform.taskDefinitionArn) ||
    typeof terraform.serviceArn !== "string" ||
    terraform.serviceArn !== serviceArnPrefix ||
    terraform.clusterArn !== clusterArn
  ) {
    throw new Error("Terraform deployment identity is invalid");
  }
  exact(observed.taskDefinition, expectedTaskDefinition(terraform), "observed task definition");
  exact(observed.service, expectedService(terraform), "observed service");
  exact(observed.network, terraform.contract.network, "observed network");
  exact(observed.database, terraform.contract.database, "observed database");
  return freeze(structuredClone(terraform));
}
