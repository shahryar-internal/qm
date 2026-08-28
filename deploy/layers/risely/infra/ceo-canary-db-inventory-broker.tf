locals {
  ceo_canary_db_inventory_broker_name = "${local.ceo_canary_db_operator_contract.familyPrefix}-inventory-broker"
  ceo_canary_db_inventory_broker_arn  = "arn:aws:states:${var.region}:${data.aws_caller_identity.current.account_id}:stateMachine:${local.ceo_canary_db_inventory_broker_name}"
  ceo_canary_db_inventory_broker_enabled = (
    local.ceo_canary_db_operator_enabled &&
    contains(keys(local.ceo_canary_db_operator_phases), "inventory")
  )
  ceo_canary_db_inventory_broker_contract = local.ceo_canary_db_inventory_broker_enabled ? {
    schemaVersion  = 1
    phase          = "inventory"
    readOnly       = true
    stateMachine   = local.ceo_canary_db_inventory_broker_name
    taskDefinition = aws_ecs_task_definition.ceo_canary_db_operator["inventory"].arn
    clusterArn     = aws_ecs_cluster.this.arn
    platform       = "1.4.0"
    timeoutSeconds = 300
    network = {
      subnetIds        = sort(local.ceo_canary_private_subnet_ids)
      securityGroupIds = [aws_security_group.ceo_canary.id]
      assignPublicIp   = "DISABLED"
    }
    execution = {
      callerInputForwarded = false
      commandOverrides     = false
      environmentOverrides = false
      roleOverrides        = false
      executeCommand       = false
      automaticStart       = false
      invokerRoleCreated   = false
    }
  } : null
  ceo_canary_db_inventory_broker_contract_sha256 = local.ceo_canary_db_inventory_broker_enabled ? sha256(jsonencode(local.ceo_canary_db_inventory_broker_contract)) : null
}

resource "aws_iam_role" "ceo_canary_db_inventory_broker" {
  count = local.ceo_canary_db_inventory_broker_enabled ? 1 : 0
  name  = local.ceo_canary_db_inventory_broker_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "states.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = local.ceo_canary_db_inventory_broker_arn
        }
        StringEquals = {
          "aws:SourceAccount" = var.account_id
        }
      }
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "ceo_canary_db_inventory_broker" {
  count = local.ceo_canary_db_inventory_broker_enabled ? 1 : 0
  name  = "${local.ceo_canary_db_inventory_broker_name}-fixed-run"
  role  = aws_iam_role.ceo_canary_db_inventory_broker[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RunExactInventoryRevision"
        Effect   = "Allow"
        Action   = ["ecs:RunTask"]
        Resource = aws_ecs_task_definition.ceo_canary_db_operator["inventory"].arn
        Condition = {
          ArnEquals = {
            "ecs:cluster"         = aws_ecs_cluster.this.arn
            "ecs:task-definition" = aws_ecs_task_definition.ceo_canary_db_operator["inventory"].arn
          }
          Bool = {
            "ecs:auto-assign-public-ip" = "false"
          }
          StringEquals = {
            "ecs:enable-execute-command" = "false"
          }
          "ForAllValues:StringEquals" = {
            "ecs:subnet" = sort(local.ceo_canary_private_subnet_ids)
          }
          Null = {
            "ecs:subnet" = "false"
          }
        }
      },
      {
        Sid    = "PassExactInventoryRoles"
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [
          aws_iam_role.ceo_canary_db_operator_task["inventory"].arn,
          aws_iam_role.ceo_canary_db_operator_execution["inventory"].arn,
        ]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      },
      {
        Sid      = "ObserveBrokerTasks"
        Effect   = "Allow"
        Action   = ["ecs:DescribeTasks", "ecs:StopTask"]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "ecs:cluster" = aws_ecs_cluster.this.arn
          }
        }
      },
      {
        Sid    = "ObserveBrokerTaskEvents"
        Effect = "Allow"
        Action = ["events:PutTargets", "events:PutRule", "events:DescribeRule"]
        Resource = [
          "arn:aws:events:${var.region}:${data.aws_caller_identity.current.account_id}:rule/StepFunctionsGetEventsForECSTaskRule",
        ]
      },
    ]
  })
}

resource "aws_sfn_state_machine" "ceo_canary_db_inventory_broker" {
  count    = local.ceo_canary_db_inventory_broker_enabled ? 1 : 0
  name     = local.ceo_canary_db_inventory_broker_name
  role_arn = aws_iam_role.ceo_canary_db_inventory_broker[0].arn
  type     = "STANDARD"
  definition = jsonencode({
    StartAt = "Run exact inventory task"
    States = {
      "Run exact inventory task" = {
        Type       = "Task"
        Resource   = "arn:aws:states:::ecs:runTask.sync"
        InputPath  = null
        ResultPath = "$"
        Parameters = {
          Cluster              = aws_ecs_cluster.this.arn
          TaskDefinition       = aws_ecs_task_definition.ceo_canary_db_operator["inventory"].arn
          LaunchType           = "FARGATE"
          PlatformVersion      = "1.4.0"
          EnableExecuteCommand = false
          PropagateTags        = "TASK_DEFINITION"
          NetworkConfiguration = {
            AwsvpcConfiguration = {
              Subnets        = sort(local.ceo_canary_private_subnet_ids)
              SecurityGroups = [aws_security_group.ceo_canary.id]
              AssignPublicIp = "DISABLED"
            }
          }
        }
        TimeoutSeconds = 300
        Next           = "Verify inventory exit"
      }
      "Verify inventory exit" = {
        Type = "Choice"
        Choices = [{
          Variable      = "$.Containers[0].ExitCode"
          NumericEquals = 0
          Next          = "Inventory complete"
        }]
        Default = "Inventory failed"
      }
      "Inventory complete" = {
        Type = "Succeed"
      }
      "Inventory failed" = {
        Type  = "Fail"
        Error = "CeoCanaryDatabaseInventoryFailed"
      }
    }
  })
  tags = merge(local.tags, {
    CeoCanaryDbInventoryBrokerContractSha256 = local.ceo_canary_db_inventory_broker_contract_sha256
  })
}

check "ceo_canary_db_inventory_broker_is_read_only_and_inputless" {
  assert {
    condition = !local.ceo_canary_db_inventory_broker_enabled || (
      local.ceo_canary_db_operator_contract.phases.inventory.readOnly &&
      local.ceo_canary_db_inventory_broker_contract.phase == "inventory" &&
      !local.ceo_canary_db_inventory_broker_contract.execution.callerInputForwarded &&
      !local.ceo_canary_db_inventory_broker_contract.execution.commandOverrides &&
      !local.ceo_canary_db_inventory_broker_contract.execution.environmentOverrides &&
      !local.ceo_canary_db_inventory_broker_contract.execution.roleOverrides &&
      !local.ceo_canary_db_inventory_broker_contract.execution.executeCommand &&
      !local.ceo_canary_db_inventory_broker_contract.execution.automaticStart &&
      !local.ceo_canary_db_inventory_broker_contract.execution.invokerRoleCreated
    )
    error_message = "the inventory broker must remain a read-only, inputless, manually reviewed fixed task launch"
  }
}
