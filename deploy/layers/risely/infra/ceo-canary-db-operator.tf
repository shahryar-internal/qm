locals {
  ceo_canary_db_operator_contract = jsondecode(file("${path.module}/../canary/deployment/ceo-canary-db-operator-contract.json"))
  ceo_canary_db_operator_phases   = local.ceo_canary_db_operator_contract.phases
  ceo_canary_db_operator_environment = merge(local.ceo_canary_db_operator_contract.environment, {
    AWS_REGION                     = var.region
    CANARY_BOOTSTRAP_ADMIN_ROLE    = local.ceo_canary_db_operator_contract.database.bootstrapAdminUser
    CANARY_DATABASE_HOST           = aws_db_instance.this.address
    CANARY_DATABASE_NAME           = aws_db_instance.this.db_name
    CANARY_DATABASE_PORT           = tostring(aws_db_instance.this.port)
    CANARY_DATABASE_SCHEMA         = local.ceo_canary_db_operator_contract.database.schema
    CANARY_MIGRATION_DATABASE_USER = local.ceo_canary_db_operator_contract.database.migrationUser
    CANARY_OWNER_DATABASE_USER     = local.ceo_canary_db_operator_contract.database.ownerUser
    CANARY_RUNTIME_DATABASE_USER   = local.ceo_canary_db_operator_contract.database.runtimeUser
  })
  ceo_canary_db_operator_secrets = {
    for phase, contract in local.ceo_canary_db_operator_phases : phase => {
      for binding in contract.secretBindings : binding.environmentName => aws_secretsmanager_secret.contract[binding.secretName].arn
    }
  }
  ceo_canary_db_operator_secret_arns = distinct(flatten([
    for secrets in values(local.ceo_canary_db_operator_secrets) : values(secrets)
  ]))
  ceo_canary_db_operator_log_arns = flatten([
    for group in values(aws_cloudwatch_log_group.ceo_canary_db_operator) : [group.arn, "${group.arn}:*"]
  ])
  ceo_canary_db_operator_provenance = {
    schemaVersion = local.ceo_canary_db_operator_contract.schemaVersion
    accountId     = local.ceo_canary_db_operator_contract.accountId
    region        = local.ceo_canary_db_operator_contract.region
    clusterName   = local.ceo_canary_db_operator_contract.clusterName
    familyPrefix  = local.ceo_canary_db_operator_contract.familyPrefix
    image         = var.ceo_canary_db_operator_image
    database = {
      arn        = aws_db_instance.this.arn
      identifier = aws_db_instance.this.identifier
      host       = aws_db_instance.this.address
      port       = aws_db_instance.this.port
      name       = aws_db_instance.this.db_name
      schema     = local.ceo_canary_db_operator_contract.database.schema
    }
    environment = local.ceo_canary_db_operator_environment
    phases = {
      for phase, contract in local.ceo_canary_db_operator_phases : phase => {
        family           = "${local.ceo_canary_db_operator_contract.familyPrefix}-${phase}"
        readOnly         = contract.readOnly
        secrets          = local.ceo_canary_db_operator_secrets[phase]
        taskRoleArn      = aws_iam_role.ceo_canary_db_operator_task[phase].arn
        executionRoleArn = aws_iam_role.ceo_canary_db_operator_execution[phase].arn
        logGroupName     = aws_cloudwatch_log_group.ceo_canary_db_operator[phase].name
        entryPoint       = ["node", local.ceo_canary_db_operator_contract.container.entrypoint, phase]
      }
    }
    network = {
      subnetIds        = sort(local.ceo_canary_private_subnet_ids)
      securityGroupIds = [aws_security_group.ceo_canary.id]
      assignPublicIp   = false
      publicListener   = false
      providerEgress   = false
    }
    launch = local.ceo_canary_db_operator_contract.launch
  }
  ceo_canary_db_operator_provenance_sha256 = sha256(jsonencode(local.ceo_canary_db_operator_provenance))
}

check "ceo_canary_db_operator_closed_contract" {
  assert {
    condition = (
      local.ceo_canary_db_operator_contract.schemaVersion == 1 &&
      local.ceo_canary_db_operator_contract.accountId == var.account_id &&
      local.ceo_canary_db_operator_contract.region == var.region &&
      local.ceo_canary_db_operator_contract.clusterName == var.cluster_name &&
      local.ceo_canary_db_operator_contract.familyPrefix == "${var.cluster_name}-ceo-canary-db" &&
      local.ceo_canary_db_operator_contract.ecrRepository == var.services[local.ceo_canary_service_name].ecr_repository &&
      local.ceo_canary_db_operator_contract.database.name == "qm" &&
      local.ceo_canary_db_operator_contract.database.port == 5432 &&
      local.ceo_canary_db_operator_contract.database.schema == "risely_agent_runtime" &&
      local.ceo_canary_db_operator_contract.database.bootstrapAdminUser == var.db_username &&
      local.ceo_canary_db_operator_contract.database.ownerUser == "risely_agent_runtime_owner" &&
      local.ceo_canary_db_operator_contract.database.migrationUser == "risely_agent_runtime_migrator" &&
      local.ceo_canary_db_operator_contract.database.runtimeUser == "risely_agent_runtime_runtime" &&
      local.ceo_canary_db_operator_contract.database.evaluationWriterUser == "risely_agent_runtime_evaluation_writer" &&
      aws_db_instance.this.db_name == local.ceo_canary_db_operator_contract.database.name &&
      aws_db_instance.this.port == local.ceo_canary_db_operator_contract.database.port &&
      toset(keys(local.ceo_canary_db_operator_phases)) == toset(["inventory", "bootstrap", "provision", "migrate", "readiness"]) &&
      local.ceo_canary_db_operator_contract.phases.inventory.readOnly &&
      local.ceo_canary_db_operator_contract.phases.readiness.readOnly &&
      !local.ceo_canary_db_operator_contract.phases.bootstrap.readOnly &&
      !local.ceo_canary_db_operator_contract.phases.provision.readOnly &&
      !local.ceo_canary_db_operator_contract.phases.migrate.readOnly &&
      local.ceo_canary_db_operator_contract.container.user == "node" &&
      !local.ceo_canary_db_operator_contract.container.readOnlyRootFilesystem &&
      !local.ceo_canary_db_operator_contract.container.privileged &&
      local.ceo_canary_db_operator_contract.container.dropCapabilities == ["ALL"] &&
      local.ceo_canary_db_operator_contract.environment.CANARY_MUTATIONS_ENABLED == "0" &&
      local.ceo_canary_db_operator_contract.environment.CANARY_PROVIDER_EXECUTION_ENABLED == "0" &&
      !local.ceo_canary_db_operator_contract.network.assignPublicIp &&
      !local.ceo_canary_db_operator_contract.network.publicListener &&
      !local.ceo_canary_db_operator_contract.network.providerEgress &&
      !local.ceo_canary_db_operator_contract.launch.serviceCreated &&
      !local.ceo_canary_db_operator_contract.launch.scheduleCreated &&
      !local.ceo_canary_db_operator_contract.launch.deploymentPrincipalAvailable &&
      !local.ceo_canary_db_operator_contract.launch.executeCommandEnabled
    )
    error_message = "the one-off database operator must remain fixed to the inert same-QM lifecycle boundary"
  }
}

check "ceo_canary_db_operator_images_and_secrets" {
  assert {
    condition = (
      startswith(
        var.ceo_canary_db_operator_image,
        "${var.account_id}.dkr.ecr.${var.region}.amazonaws.com/${local.ceo_canary_db_operator_contract.ecrRepository}@sha256:"
      ) &&
      alltrue(flatten([
        for contract in values(local.ceo_canary_db_operator_phases) : [
          for binding in contract.secretBindings : contains(var.secret_names, binding.secretName)
        ]
      ])) &&
      toset(keys(local.ceo_canary_db_operator_secrets.inventory)) == toset(["CANARY_BOOTSTRAP_DATABASE_URL", "DATABASE_CA_CERT"]) &&
      toset(keys(local.ceo_canary_db_operator_secrets.bootstrap)) == toset(["CANARY_BOOTSTRAP_DATABASE_URL", "DATABASE_CA_CERT"]) &&
      toset(keys(local.ceo_canary_db_operator_secrets.provision)) == toset(["CANARY_BOOTSTRAP_DATABASE_URL", "CANARY_MIGRATION_DATABASE_URL", "CANARY_DATABASE_URL", "DATABASE_CA_CERT"]) &&
      toset(keys(local.ceo_canary_db_operator_secrets.migrate)) == toset(["CANARY_MIGRATION_DATABASE_URL", "DATABASE_CA_CERT"]) &&
      toset(keys(local.ceo_canary_db_operator_secrets.readiness)) == toset(["CANARY_DATABASE_URL", "DATABASE_CA_CERT"])
    )
    error_message = "each database operator phase must use a digest-pinned image and only its exact database credentials"
  }
}

resource "aws_cloudwatch_log_group" "ceo_canary_db_operator" {
  for_each          = local.ceo_canary_db_operator_phases
  name              = "/ecs/${local.ceo_canary_db_operator_contract.familyPrefix}-${each.key}"
  retention_in_days = 90
  tags              = local.tags
}

resource "aws_iam_role" "ceo_canary_db_operator_task" {
  for_each           = local.ceo_canary_db_operator_phases
  name               = "${local.ceo_canary_db_operator_contract.familyPrefix}-${each.key}-task"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  tags               = local.tags
}

resource "aws_iam_role_policy" "ceo_canary_db_operator_task_deny_all" {
  for_each = local.ceo_canary_db_operator_phases
  name     = "${local.ceo_canary_db_operator_contract.familyPrefix}-${each.key}-deny-all"
  role     = aws_iam_role.ceo_canary_db_operator_task[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "ceo_canary_db_operator_execution" {
  for_each           = local.ceo_canary_db_operator_phases
  name               = "${local.ceo_canary_db_operator_contract.familyPrefix}-${each.key}-execution"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "ceo_canary_db_operator_execution" {
  for_each   = local.ceo_canary_db_operator_phases
  role       = aws_iam_role.ceo_canary_db_operator_execution[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ceo_canary_db_operator_secrets" {
  for_each = local.ceo_canary_db_operator_phases
  role     = aws_iam_role.ceo_canary_db_operator_execution[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = values(local.ceo_canary_db_operator_secrets[each.key])
    }]
  })
}

resource "aws_ecs_task_definition" "ceo_canary_db_operator" {
  for_each = local.ceo_canary_db_operator_phases
  depends_on = [
    aws_iam_role_policy.ceo_canary_db_operator_task_deny_all,
    aws_iam_role_policy.ceo_canary_db_operator_secrets,
    aws_iam_role_policy_attachment.ceo_canary_db_operator_execution,
  ]
  family                   = "${local.ceo_canary_db_operator_contract.familyPrefix}-${each.key}"
  cpu                      = local.ceo_canary_db_operator_contract.container.cpu
  memory                   = local.ceo_canary_db_operator_contract.container.memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ceo_canary_db_operator_execution[each.key].arn
  task_role_arn            = aws_iam_role.ceo_canary_db_operator_task[each.key].arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = local.ceo_canary_db_operator_contract.container.architecture
  }
  container_definitions = jsonencode([{
    name                   = "${local.ceo_canary_db_operator_contract.container.namePrefix}-${each.key}"
    image                  = var.ceo_canary_db_operator_image
    essential              = true
    user                   = local.ceo_canary_db_operator_contract.container.user
    privileged             = local.ceo_canary_db_operator_contract.container.privileged
    readonlyRootFilesystem = local.ceo_canary_db_operator_contract.container.readOnlyRootFilesystem
    entryPoint             = ["node", local.ceo_canary_db_operator_contract.container.entrypoint, each.key]
    environment = [
      for name in sort(keys(local.ceo_canary_db_operator_environment)) : {
        name  = name
        value = tostring(local.ceo_canary_db_operator_environment[name])
      }
    ]
    secrets = [
      for binding in each.value.secretBindings : {
        name      = binding.environmentName
        valueFrom = local.ceo_canary_db_operator_secrets[each.key][binding.environmentName]
      }
    ]
    linuxParameters = {
      initProcessEnabled = true
      capabilities = {
        add  = []
        drop = local.ceo_canary_db_operator_contract.container.dropCapabilities
      }
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.ceo_canary_db_operator[each.key].name
        awslogs-region        = var.region
        awslogs-stream-prefix = each.key
        mode                  = "blocking"
      }
    }
  }])
  tags = merge(local.tags, {
    CeoCanaryDbOperatorProvenanceSha256 = local.ceo_canary_db_operator_provenance_sha256
    CeoCanaryDbOperatorPhase            = each.key
  })
}

check "ceo_canary_db_operator_has_no_automatic_launcher" {
  assert {
    condition = (
      length(aws_ecs_task_definition.ceo_canary_db_operator) == 5 &&
      local.ceo_canary_db_operator_contract.launch.serviceCreated == false &&
      local.ceo_canary_db_operator_contract.launch.scheduleCreated == false &&
      local.ceo_canary_db_operator_contract.launch.deploymentPrincipalAvailable == false
    )
    error_message = "database operator task definitions must remain inert without a service, schedule, or deployment principal"
  }
}
