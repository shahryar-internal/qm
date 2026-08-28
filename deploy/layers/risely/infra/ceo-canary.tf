locals {
  ceo_canary_contract           = jsondecode(file("${path.module}/../canary/deployment/ceo-canary-task-contract.json"))
  ceo_canary_service_name       = local.ceo_canary_contract.serviceName
  ceo_canary_private_subnet_ids = values(aws_subnet.ceo_canary_private)[*].id
  ceo_canary_endpoint_services  = toset(["ecr.api", "ecr.dkr", "logs", "secretsmanager"])
  ceo_canary_generic_ecr_arns = [
    for name, repository in aws_ecr_repository.service : repository.arn if name != local.ceo_canary_service_name
  ]
  ceo_canary_generic_log_arns = flatten([
    for name, group in aws_cloudwatch_log_group.service : [group.arn, "${group.arn}:*"] if name != local.ceo_canary_service_name
  ])
  ceo_canary_generic_secret_arns = [
    for name, secret in aws_secretsmanager_secret.contract : secret.arn if !startswith(name, "CANARY_")
  ]
  ceo_canary_environment = merge(local.ceo_canary_contract.environment, {
    AWS_REGION                   = var.region
    CANARY_DATABASE_HOST         = aws_db_instance.this.address
    CANARY_DATABASE_PORT         = tostring(aws_db_instance.this.port)
    CANARY_DATABASE_NAME         = aws_db_instance.this.db_name
    CANARY_DATABASE_SCHEMA       = local.ceo_canary_contract.database.schema
    CANARY_RUNTIME_DATABASE_USER = local.ceo_canary_contract.database.runtimeUser
  })
  ceo_canary_secrets = {
    for binding in local.ceo_canary_contract.secretBindings : binding.environmentName => aws_secretsmanager_secret.contract[binding.secretName].arn
  }
  ceo_canary_container_definition = {
    name                   = local.ceo_canary_contract.container.name
    image                  = var.ceo_canary_runtime_image
    essential              = true
    user                   = local.ceo_canary_contract.container.user
    privileged             = local.ceo_canary_contract.container.privileged
    readonlyRootFilesystem = local.ceo_canary_contract.container.readOnlyRootFilesystem
    portMappings = [{
      containerPort = local.ceo_canary_contract.container.port
      protocol      = "tcp"
      appProtocol   = "http"
    }]
    environment = [
      for name in sort(keys(local.ceo_canary_environment)) : {
        name  = name
        value = tostring(local.ceo_canary_environment[name])
      }
    ]
    secrets = [
      for binding in local.ceo_canary_contract.secretBindings : {
        name      = binding.environmentName
        valueFrom = local.ceo_canary_secrets[binding.environmentName]
      }
    ]
    linuxParameters = {
      initProcessEnabled = true
      capabilities = {
        add  = []
        drop = local.ceo_canary_contract.container.dropCapabilities
      }
    }
    healthCheck = {
      command = [
        "CMD-SHELL",
        "node -e \"fetch('http://127.0.0.1:${local.ceo_canary_contract.container.port}${local.ceo_canary_contract.container.healthPath}').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))\"",
      ]
      interval    = local.ceo_canary_contract.container.healthIntervalSeconds
      timeout     = local.ceo_canary_contract.container.healthTimeoutSeconds
      retries     = local.ceo_canary_contract.container.healthRetries
      startPeriod = local.ceo_canary_contract.container.healthStartPeriodSeconds
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.service[local.ceo_canary_service_name].name
        awslogs-region        = var.region
        awslogs-stream-prefix = local.ceo_canary_service_name
        mode                  = "non-blocking"
        max-buffer-size       = "4m"
      }
    }
  }
}

check "ceo_canary_closed_contract" {
  assert {
    condition = (
      local.ceo_canary_contract.schemaVersion == 1 &&
      var.account_id == local.ceo_canary_contract.accountId &&
      var.region == local.ceo_canary_contract.region &&
      var.cluster_name == local.ceo_canary_contract.clusterName &&
      var.cloud_map_namespace == local.ceo_canary_contract.cloudMapNamespace &&
      var.secrets_prefix == local.ceo_canary_contract.secretsPrefix &&
      local.ceo_canary_contract.serviceName == "ceo-canary" &&
      local.ceo_canary_contract.family == "${var.cluster_name}-ceo-canary" &&
      local.ceo_canary_contract.ecrRepository == "${var.cluster_name}-ceo-canary" &&
      local.ceo_canary_contract.deploymentProfileRef == "deployment-profile:risely:ceo:v1" &&
      local.ceo_canary_contract.database.name == "qm" &&
      aws_db_instance.this.db_name == local.ceo_canary_contract.database.name &&
      aws_db_instance.this.port == local.ceo_canary_contract.database.port &&
      local.ceo_canary_contract.environment.CANARY_DEPLOYMENT_PROFILE_REF == local.ceo_canary_contract.deploymentProfileRef &&
      local.ceo_canary_contract.environment.CANARY_MUTATIONS_ENABLED == "0" &&
      local.ceo_canary_contract.environment.CANARY_PROVIDER_EXECUTION_ENABLED == "0" &&
      local.ceo_canary_contract.container.user == "node" &&
      local.ceo_canary_contract.container.readOnlyRootFilesystem &&
      !local.ceo_canary_contract.container.privileged &&
      local.ceo_canary_contract.container.dropCapabilities == ["ALL"] &&
      local.ceo_canary_contract.container.healthPath == "/readyz" &&
      local.ceo_canary_contract.service.desiredCount == 0 &&
      !local.ceo_canary_contract.service.enableExecuteCommand &&
      !local.ceo_canary_contract.network.assignPublicIp &&
      !local.ceo_canary_contract.network.publicListener &&
      !local.ceo_canary_contract.network.providerEgress &&
      local.ceo_canary_contract.secretBindings == [
        { environmentName = "CANARY_DATABASE_URL", secretName = "CANARY_DATABASE_URL" },
        { environmentName = "CANARY_INGRESS_SECRET", secretName = "CANARY_INGRESS_SECRET" },
        { environmentName = "DATABASE_CA_CERT", secretName = "CANARY_DATABASE_CA_CERT" }
      ]
    )
    error_message = "the CEO canary task contract must remain fixed to the inert Risely QM profile, database, secret, and network boundary"
  }
}

check "ceo_canary_service_input" {
  assert {
    condition = (
      contains(keys(var.services), local.ceo_canary_service_name) &&
      var.services[local.ceo_canary_service_name].ecs_service == "${var.cluster_name}-ceo-canary" &&
      var.services[local.ceo_canary_service_name].ecr_repository == "${var.cluster_name}-ceo-canary" &&
      var.services[local.ceo_canary_service_name].internal_port == local.ceo_canary_contract.container.port &&
      try(var.services[local.ceo_canary_service_name].task_role_arn, null) == null &&
      try(var.services[local.ceo_canary_service_name].execution_role_arn, null) == null
    )
    error_message = "the existing CEO canary service address must retain its exact stack-owned identity"
  }
}

check "ceo_canary_excluded_from_generic_runtime" {
  assert {
    condition = (
      !contains(keys(aws_ecs_task_definition.bootstrap), local.ceo_canary_service_name) &&
      !contains(keys(aws_ecs_service.service), local.ceo_canary_service_name)
    )
    error_message = "the dedicated CEO canary runtime must never inherit the generic QM task or service boundary"
  }
}

check "ceo_canary_image_provenance" {
  assert {
    condition = startswith(
      var.ceo_canary_runtime_image,
      "${var.account_id}.dkr.ecr.${var.region}.amazonaws.com/${var.services[local.ceo_canary_service_name].ecr_repository}@sha256:"
    )
    error_message = "ceo_canary_runtime_image must be a digest-pinned image from the stack-owned CEO canary ECR repository"
  }
}

check "ceo_canary_secret_inventory" {
  assert {
    condition = alltrue([
      for binding in local.ceo_canary_contract.secretBindings : contains(var.secret_names, binding.secretName)
    ])
    error_message = "the runtime database, ingress, and CA secret containers must exist"
  }
}

resource "aws_subnet" "ceo_canary_private" {
  for_each                = toset(local.azs)
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value
  cidr_block              = cidrsubnet(aws_vpc.this.cidr_block, 8, 128 + index(local.azs, each.value))
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${var.cluster_name}-ceo-canary-${each.value}" })
}

resource "aws_route_table" "ceo_canary_private" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.cluster_name}-ceo-canary-private" })
}

resource "aws_route_table_association" "ceo_canary_private" {
  for_each       = aws_subnet.ceo_canary_private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.ceo_canary_private.id
}

resource "aws_security_group" "ceo_canary" {
  name   = "${var.cluster_name}-ceo-canary"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port       = local.ceo_canary_contract.container.port
    to_port         = local.ceo_canary_contract.container.port
    protocol        = "tcp"
    security_groups = [aws_security_group.services.id]
  }
  tags = local.tags
}

resource "aws_security_group" "ceo_canary_endpoints" {
  name   = "${var.cluster_name}-ceo-canary-endpoints"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.ceo_canary.id, aws_security_group.services.id]
  }
  tags = local.tags
}

resource "aws_security_group" "ceo_canary_database" {
  name   = "${var.cluster_name}-ceo-canary-database"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port       = local.ceo_canary_contract.database.port
    to_port         = local.ceo_canary_contract.database.port
    protocol        = "tcp"
    security_groups = [aws_security_group.ceo_canary.id]
  }
  tags = local.tags
}

resource "aws_vpc_security_group_egress_rule" "ceo_canary_database" {
  security_group_id            = aws_security_group.ceo_canary.id
  referenced_security_group_id = aws_security_group.ceo_canary_database.id
  from_port                    = aws_db_instance.this.port
  to_port                      = aws_db_instance.this.port
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "ceo_canary_control_plane" {
  security_group_id            = aws_security_group.ceo_canary.id
  referenced_security_group_id = aws_security_group.ceo_canary_endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_endpoint" "ceo_canary_control_plane" {
  for_each            = local.ceo_canary_endpoint_services
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = local.ceo_canary_private_subnet_ids
  security_group_ids  = [aws_security_group.ceo_canary_endpoints.id]
  policy = each.value == "secretsmanager" ? jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
      Resource  = concat(local.ceo_canary_generic_secret_arns, values(local.ceo_canary_secrets), local.ceo_canary_db_operator_secret_arns)
    }]
    }) : each.value == "logs" ? jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]
      Resource  = concat(local.ceo_canary_generic_log_arns, [aws_cloudwatch_log_group.service[local.ceo_canary_service_name].arn, "${aws_cloudwatch_log_group.service[local.ceo_canary_service_name].arn}:*"], local.ceo_canary_db_operator_log_arns)
    }]
    }) : jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "ecr:GetAuthorizationToken"
        Resource  = "*"
      },
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
        Resource  = concat(local.ceo_canary_generic_ecr_arns, [aws_ecr_repository.service[local.ceo_canary_service_name].arn])
      },
    ]
  })
  tags = merge(local.tags, { Name = "${var.cluster_name}-ceo-canary-${replace(each.value, ".", "-")}" })
}

resource "aws_vpc_endpoint" "ceo_canary_s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.ceo_canary_private.id]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::prod-${var.region}-starport-layer-bucket/*"
    }]
  })
  tags = merge(local.tags, { Name = "${var.cluster_name}-ceo-canary-s3" })
}

resource "aws_vpc_security_group_egress_rule" "ceo_canary_ecr_layers" {
  security_group_id = aws_security_group.ceo_canary.id
  prefix_list_id    = aws_vpc_endpoint.ceo_canary_s3.prefix_list_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_iam_role" "ceo_canary_task" {
  name               = "${var.cluster_name}-ceo-canary-task"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  tags               = local.tags
}

resource "aws_iam_role_policy" "ceo_canary_task_deny_all" {
  name = "${var.cluster_name}-ceo-canary-deny-all"
  role = aws_iam_role.ceo_canary_task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "ceo_canary_execution" {
  name               = "${var.cluster_name}-ceo-canary-execution"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "ceo_canary_execution" {
  role       = aws_iam_role.ceo_canary_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ceo_canary_secrets" {
  role = aws_iam_role.ceo_canary_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = values(local.ceo_canary_secrets)
    }]
  })
}

locals {
  ceo_canary_expected_routes = [
    {
      destinationType = "ipv4_cidr"
      destination     = aws_vpc.this.cidr_block
      targetType      = "local"
      targetId        = "local"
    },
    {
      destinationType = "prefix_list"
      destination     = aws_vpc_endpoint.ceo_canary_s3.prefix_list_id
      targetType      = "vpc_endpoint"
      targetId        = aws_vpc_endpoint.ceo_canary_s3.id
    },
  ]
  ceo_canary_default_ipv4_route_count = length([
    for route in local.ceo_canary_expected_routes : route if route.destinationType == "ipv4_cidr" && route.destination == "0.0.0.0/0"
  ])
  ceo_canary_default_ipv6_route_count = length([
    for route in local.ceo_canary_expected_routes : route if route.destinationType == "ipv6_cidr" && route.destination == "::/0"
  ])
  ceo_canary_security_group_contract = {
    task = {
      id = aws_security_group.ceo_canary.id
      ingressRules = [{
        protocol = "tcp"
        fromPort = local.ceo_canary_contract.container.port
        toPort   = local.ceo_canary_contract.container.port
        peerType = "security_group"
        peerId   = aws_security_group.services.id
      }]
      egressRules = [
        {
          protocol = "tcp"
          fromPort = aws_db_instance.this.port
          toPort   = aws_db_instance.this.port
          peerType = "security_group"
          peerId   = aws_security_group.ceo_canary_database.id
        },
        {
          protocol = "tcp"
          fromPort = 443
          toPort   = 443
          peerType = "security_group"
          peerId   = aws_security_group.ceo_canary_endpoints.id
        },
        {
          protocol = "tcp"
          fromPort = 443
          toPort   = 443
          peerType = "prefix_list"
          peerId   = aws_vpc_endpoint.ceo_canary_s3.prefix_list_id
        },
      ]
    }
    endpoints = {
      id = aws_security_group.ceo_canary_endpoints.id
      ingressRules = [
        {
          protocol = "tcp"
          fromPort = 443
          toPort   = 443
          peerType = "security_group"
          peerId   = aws_security_group.ceo_canary.id
        },
        {
          protocol = "tcp"
          fromPort = 443
          toPort   = 443
          peerType = "security_group"
          peerId   = aws_security_group.services.id
        },
      ]
      egressRules = []
    }
    database = {
      id = aws_security_group.ceo_canary_database.id
      ingressRules = [{
        protocol = "tcp"
        fromPort = aws_db_instance.this.port
        toPort   = aws_db_instance.this.port
        peerType = "security_group"
        peerId   = aws_security_group.ceo_canary.id
      }]
      egressRules = []
    }
  }
  ceo_canary_task_provenance_contract = {
    schemaVersion        = local.ceo_canary_contract.schemaVersion
    accountId            = local.ceo_canary_contract.accountId
    region               = local.ceo_canary_contract.region
    clusterName          = local.ceo_canary_contract.clusterName
    serviceName          = local.ceo_canary_contract.serviceName
    family               = local.ceo_canary_contract.family
    image                = var.ceo_canary_runtime_image
    deploymentProfileRef = local.ceo_canary_contract.deploymentProfileRef
    database = {
      arn                      = aws_db_instance.this.arn
      identifier               = aws_db_instance.this.identifier
      host                     = aws_db_instance.this.address
      port                     = aws_db_instance.this.port
      name                     = aws_db_instance.this.db_name
      attachedSecurityGroupIds = sort(aws_db_instance.this.vpc_security_group_ids)
    }
    environment = local.ceo_canary_environment
    secrets     = local.ceo_canary_secrets
    iam = {
      taskRoleArn                  = aws_iam_role.ceo_canary_task.arn
      executionRoleArn             = aws_iam_role.ceo_canary_execution.arn
      taskRoleDenyAllPolicyName    = aws_iam_role_policy.ceo_canary_task_deny_all.name
      deploymentPrincipalAvailable = false
    }
    container = local.ceo_canary_contract.container
    logging = {
      groupName     = aws_cloudwatch_log_group.service[local.ceo_canary_service_name].name
      region        = var.region
      streamPrefix  = local.ceo_canary_service_name
      mode          = "non-blocking"
      maxBufferSize = "4m"
    }
    network = {
      subnetIds                     = sort(local.ceo_canary_private_subnet_ids)
      securityGroupIds              = [aws_security_group.ceo_canary.id]
      endpointSecurityGroupIds      = [aws_security_group.ceo_canary_endpoints.id]
      ingressSourceSecurityGroupId  = aws_security_group.services.id
      sharedDatabaseSecurityGroupId = aws_security_group.database.id
      databaseSecurityGroupId       = aws_security_group.ceo_canary_database.id
      securityGroups                = local.ceo_canary_security_group_contract
      routeTable = {
        id                    = aws_route_table.ceo_canary_private.id
        routes                = local.ceo_canary_expected_routes
        defaultIpv4RouteCount = local.ceo_canary_default_ipv4_route_count
        defaultIpv6RouteCount = local.ceo_canary_default_ipv6_route_count
      }
      assignPublicIp = local.ceo_canary_contract.network.assignPublicIp
      publicListener = local.ceo_canary_contract.network.publicListener
      providerEgress = local.ceo_canary_contract.network.providerEgress
      endpoints = merge(
        {
          for name, endpoint in aws_vpc_endpoint.ceo_canary_control_plane : name => {
            id                = endpoint.id
            serviceName       = endpoint.service_name
            type              = endpoint.vpc_endpoint_type
            privateDnsEnabled = endpoint.private_dns_enabled
            subnetIds         = sort(endpoint.subnet_ids)
            securityGroupIds  = sort(endpoint.security_group_ids)
            policySha256      = sha256(endpoint.policy)
          }
        },
        {
          s3 = {
            id                = aws_vpc_endpoint.ceo_canary_s3.id
            serviceName       = aws_vpc_endpoint.ceo_canary_s3.service_name
            type              = aws_vpc_endpoint.ceo_canary_s3.vpc_endpoint_type
            privateDnsEnabled = false
            subnetIds         = []
            securityGroupIds  = []
            routeTableIds     = sort(aws_vpc_endpoint.ceo_canary_s3.route_table_ids)
            policySha256      = sha256(aws_vpc_endpoint.ceo_canary_s3.policy)
          }
        }
      )
    }
    service = {
      desiredCount         = local.ceo_canary_contract.service.desiredCount
      enableExecuteCommand = local.ceo_canary_contract.service.enableExecuteCommand
      serviceRegistryArn   = aws_service_discovery_service.service[local.ceo_canary_service_name].arn
      loadBalancerCount    = 0
    }
  }
  ceo_canary_task_provenance_sha256 = sha256(jsonencode(local.ceo_canary_task_provenance_contract))
}

check "ceo_canary_provenance_uniqueness" {
  assert {
    condition = (
      length(local.ceo_canary_task_provenance_contract.network.subnetIds) == 2 &&
      length(distinct(local.ceo_canary_task_provenance_contract.network.subnetIds)) == 2 &&
      local.ceo_canary_task_provenance_contract.network.routeTable.defaultIpv4RouteCount == 0 &&
      local.ceo_canary_task_provenance_contract.network.routeTable.defaultIpv6RouteCount == 0 &&
      length(local.ceo_canary_task_provenance_contract.network.routeTable.routes) == 2 &&
      length(local.ceo_canary_task_provenance_contract.database.attachedSecurityGroupIds) == 2 &&
      toset(local.ceo_canary_task_provenance_contract.database.attachedSecurityGroupIds) == toset([aws_security_group.database.id, aws_security_group.ceo_canary_database.id]) &&
      length(distinct(concat(
        [for endpoint in values(local.ceo_canary_task_provenance_contract.network.endpoints) : endpoint.id],
        local.ceo_canary_task_provenance_contract.network.securityGroupIds,
        local.ceo_canary_task_provenance_contract.network.endpointSecurityGroupIds,
        [local.ceo_canary_task_provenance_contract.network.databaseSecurityGroupId, local.ceo_canary_task_provenance_contract.network.sharedDatabaseSecurityGroupId, local.ceo_canary_task_provenance_contract.network.ingressSourceSecurityGroupId]
      ))) == 10
    )
    error_message = "CEO canary provenance network identities must be present and pairwise unique"
  }
}

resource "aws_ecs_task_definition" "ceo_canary" {
  depends_on = [
    aws_iam_role_policy.ceo_canary_task_deny_all,
    aws_iam_role_policy.ceo_canary_secrets,
    aws_iam_role_policy_attachment.ceo_canary_execution,
  ]
  family                   = var.services[local.ceo_canary_service_name].ecs_service
  cpu                      = local.ceo_canary_contract.container.cpu
  memory                   = local.ceo_canary_contract.container.memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ceo_canary_execution.arn
  task_role_arn            = aws_iam_role.ceo_canary_task.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = local.ceo_canary_contract.container.architecture
  }
  container_definitions = jsonencode([local.ceo_canary_container_definition])
  tags = merge(local.tags, {
    CeoCanaryProvenanceSha256 = local.ceo_canary_task_provenance_sha256
  })
}

resource "aws_ecs_service" "ceo_canary" {
  depends_on = [
    aws_vpc_endpoint.ceo_canary_control_plane,
    aws_vpc_endpoint.ceo_canary_s3,
    aws_iam_role_policy.ceo_canary_secrets,
  ]
  name                   = var.services[local.ceo_canary_service_name].ecs_service
  cluster                = aws_ecs_cluster.this.id
  task_definition        = aws_ecs_task_definition.ceo_canary.arn
  desired_count          = local.ceo_canary_contract.service.desiredCount
  launch_type            = "FARGATE"
  enable_execute_command = local.ceo_canary_contract.service.enableExecuteCommand
  network_configuration {
    subnets          = local.ceo_canary_private_subnet_ids
    security_groups  = [aws_security_group.ceo_canary.id]
    assign_public_ip = local.ceo_canary_contract.network.assignPublicIp
  }
  service_registries {
    registry_arn = aws_service_discovery_service.service[local.ceo_canary_service_name].arn
  }
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  lifecycle {
    prevent_destroy = true
  }
  tags = merge(local.tags, {
    CeoCanaryProvenanceSha256 = local.ceo_canary_task_provenance_sha256
  })
}
