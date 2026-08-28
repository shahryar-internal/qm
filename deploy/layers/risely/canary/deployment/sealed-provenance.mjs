const deepFreeze = (value) => {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
};

export const sealedCeoCanaryTerraformProvenance = deepFreeze({
  clusterArn: "arn:aws:ecs:us-west-2:075343201918:cluster/risely-qm-pilot",
  contract: {
    accountId: "075343201918",
    clusterName: "risely-qm-pilot",
    container: {
      architecture: "X86_64",
      cpu: 256,
      dropCapabilities: ["ALL"],
      healthIntervalSeconds: 30,
      healthPath: "/readyz",
      healthRetries: 3,
      healthStartPeriodSeconds: 20,
      healthTimeoutSeconds: 5,
      memory: 512,
      name: "ceo-canary",
      port: 8080,
      privileged: false,
      readOnlyRootFilesystem: true,
      user: "node",
    },
    database: {
      arn: "arn:aws:rds:us-west-2:075343201918:db:risely-qm-pilot-core",
      attachedSecurityGroupIds: ["sg-00e02761ad16d0493", "sg-0c4f6b16c2bc6f746"],
      host: "risely-qm-pilot-core.c3s2q4qo8kp7.us-west-2.rds.amazonaws.com",
      identifier: "risely-qm-pilot-core",
      name: "qm",
      port: 5432,
    },
    deploymentProfileRef: "deployment-profile:risely:ceo:v1",
    environment: {
      AWS_REGION: "us-west-2",
      CANARY_DATABASE_HOST: "risely-qm-pilot-core.c3s2q4qo8kp7.us-west-2.rds.amazonaws.com",
      CANARY_DATABASE_NAME: "qm",
      CANARY_DATABASE_PORT: "5432",
      CANARY_DATABASE_SCHEMA: "risely_agent_runtime",
      CANARY_DEPLOYMENT_PROFILE_REF: "deployment-profile:risely:ceo:v1",
      CANARY_INGRESS_AUDIENCE: "risely-ceo-canary",
      CANARY_INGRESS_ISSUER: "risely-ceo-canary-caller-v1",
      CANARY_INGRESS_KEY_ID: "ceo-canary-ingress-v1",
      CANARY_MUTATIONS_ENABLED: "0",
      CANARY_PROVIDER_EXECUTION_ENABLED: "0",
      CANARY_RUNTIME_DATABASE_USER: "risely_agent_runtime_runtime",
      NODE_ENV: "production",
      PORT: "8080",
    },
    family: "risely-qm-pilot-ceo-canary",
    iam: {
      deploymentPrincipalAvailable: false,
      executionRoleArn: "arn:aws:iam::075343201918:role/risely-qm-pilot-ceo-canary-execution",
      taskRoleArn: "arn:aws:iam::075343201918:role/risely-qm-pilot-ceo-canary-task",
      taskRoleDenyAllPolicyName: "risely-qm-pilot-ceo-canary-deny-all",
    },
    image:
      "075343201918.dkr.ecr.us-west-2.amazonaws.com/risely-qm-pilot-ceo-canary@sha256:fb9019d466839194d7d96fb983eb2ca1ce989b62384bd331ae3b68ed3d1bc3dd",
    logging: {
      groupName: "/ecs/risely-qm-pilot-ceo-canary",
      maxBufferSize: "4m",
      mode: "non-blocking",
      region: "us-west-2",
      streamPrefix: "ceo-canary",
    },
    network: {
      assignPublicIp: false,
      databaseSecurityGroupId: "sg-00e02761ad16d0493",
      endpointSecurityGroupIds: ["sg-0a6bc8bcfe6bc163b"],
      endpoints: {
        "ecr.api": {
          id: "vpce-06c29c03d214f16e1",
          policySha256: "472230573d2c92d69ac9a5eda63af1a31120c9f69103d6878ba682867d781967",
          privateDnsEnabled: true,
          securityGroupIds: ["sg-0a6bc8bcfe6bc163b"],
          serviceName: "com.amazonaws.us-west-2.ecr.api",
          subnetIds: ["subnet-0763bf159bdcce9ab", "subnet-0e0fa6b2b86f75bc4"],
          type: "Interface",
        },
        "ecr.dkr": {
          id: "vpce-0149ceea1b56aaf82",
          policySha256: "472230573d2c92d69ac9a5eda63af1a31120c9f69103d6878ba682867d781967",
          privateDnsEnabled: true,
          securityGroupIds: ["sg-0a6bc8bcfe6bc163b"],
          serviceName: "com.amazonaws.us-west-2.ecr.dkr",
          subnetIds: ["subnet-0763bf159bdcce9ab", "subnet-0e0fa6b2b86f75bc4"],
          type: "Interface",
        },
        logs: {
          id: "vpce-0a88394f64276ad66",
          policySha256: "7751b36ea475ea1f3be15f44efb58f8d84c1e87fe0b8c7c3973211b5e060c2b7",
          privateDnsEnabled: true,
          securityGroupIds: ["sg-0a6bc8bcfe6bc163b"],
          serviceName: "com.amazonaws.us-west-2.logs",
          subnetIds: ["subnet-0763bf159bdcce9ab", "subnet-0e0fa6b2b86f75bc4"],
          type: "Interface",
        },
        s3: {
          id: "vpce-095f4d14722c907ae",
          policySha256: "4d18ab551c5bf87d491b42b1c8bcf53996dd4821f16584e14f5744962323882f",
          privateDnsEnabled: false,
          routeTableIds: ["rtb-004e6904954a52499"],
          securityGroupIds: [],
          serviceName: "com.amazonaws.us-west-2.s3",
          subnetIds: [],
          type: "Gateway",
        },
        secretsmanager: {
          id: "vpce-04505503c2c532087",
          policySha256: "f30275d0eabfc06e010863ebe1651cc3db50d3af1c25b4a6800338060b644a2f",
          privateDnsEnabled: true,
          securityGroupIds: ["sg-0a6bc8bcfe6bc163b"],
          serviceName: "com.amazonaws.us-west-2.secretsmanager",
          subnetIds: ["subnet-0763bf159bdcce9ab", "subnet-0e0fa6b2b86f75bc4"],
          type: "Interface",
        },
      },
      ingressSourceSecurityGroupId: "sg-0333ca66229f3c028",
      providerEgress: false,
      publicListener: false,
      routeTable: {
        defaultIpv4RouteCount: 0,
        defaultIpv6RouteCount: 0,
        id: "rtb-004e6904954a52499",
        routes: [
          {
            destination: "10.42.0.0/16",
            destinationType: "ipv4_cidr",
            targetId: "local",
            targetType: "local",
          },
          {
            destination: "pl-68a54001",
            destinationType: "prefix_list",
            targetId: "vpce-095f4d14722c907ae",
            targetType: "vpc_endpoint",
          },
        ],
      },
      securityGroupIds: ["sg-07a0bbf0aeb27b737"],
      securityGroups: {
        database: {
          egressRules: [],
          id: "sg-00e02761ad16d0493",
          ingressRules: [
            {
              fromPort: 5432,
              peerId: "sg-07a0bbf0aeb27b737",
              peerType: "security_group",
              protocol: "tcp",
              toPort: 5432,
            },
          ],
        },
        endpoints: {
          egressRules: [],
          id: "sg-0a6bc8bcfe6bc163b",
          ingressRules: [
            {
              fromPort: 443,
              peerId: "sg-07a0bbf0aeb27b737",
              peerType: "security_group",
              protocol: "tcp",
              toPort: 443,
            },
            {
              fromPort: 443,
              peerId: "sg-0333ca66229f3c028",
              peerType: "security_group",
              protocol: "tcp",
              toPort: 443,
            },
          ],
        },
        task: {
          egressRules: [
            {
              fromPort: 5432,
              peerId: "sg-00e02761ad16d0493",
              peerType: "security_group",
              protocol: "tcp",
              toPort: 5432,
            },
            {
              fromPort: 443,
              peerId: "sg-0a6bc8bcfe6bc163b",
              peerType: "security_group",
              protocol: "tcp",
              toPort: 443,
            },
            {
              fromPort: 443,
              peerId: "pl-68a54001",
              peerType: "prefix_list",
              protocol: "tcp",
              toPort: 443,
            },
          ],
          id: "sg-07a0bbf0aeb27b737",
          ingressRules: [
            {
              fromPort: 8080,
              peerId: "sg-0333ca66229f3c028",
              peerType: "security_group",
              protocol: "tcp",
              toPort: 8080,
            },
          ],
        },
      },
      sharedDatabaseSecurityGroupId: "sg-0c4f6b16c2bc6f746",
      subnetIds: ["subnet-0763bf159bdcce9ab", "subnet-0e0fa6b2b86f75bc4"],
    },
    region: "us-west-2",
    schemaVersion: 1,
    secrets: {
      CANARY_DATABASE_URL:
        "arn:aws:secretsmanager:us-west-2:075343201918:secret:risely/qm-pilot/CANARY_DATABASE_URL-A7a3Lz",
      CANARY_INGRESS_SECRET:
        "arn:aws:secretsmanager:us-west-2:075343201918:secret:risely/qm-pilot/CANARY_INGRESS_SECRET-Q9qayA",
      DATABASE_CA_CERT:
        "arn:aws:secretsmanager:us-west-2:075343201918:secret:risely/qm-pilot/CANARY_DATABASE_CA_CERT-X54xRz",
    },
    service: {
      desiredCount: 0,
      enableExecuteCommand: false,
      loadBalancerCount: 0,
      serviceRegistryArn: "arn:aws:servicediscovery:us-west-2:075343201918:service/srv-icssuqvosuobe3qs",
    },
    serviceName: "ceo-canary",
  },
  contractSha256: "296cbb8211d4d55baf3c8db0498f8987ffd891330179bfbd52951ddc028a352f",
  serviceArn: "arn:aws:ecs:us-west-2:075343201918:service/risely-qm-pilot/risely-qm-pilot-ceo-canary",
  taskDefinitionArn: "arn:aws:ecs:us-west-2:075343201918:task-definition/risely-qm-pilot-ceo-canary:1",
});
