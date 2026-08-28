output "alb_hostname" { value = aws_lb.this.dns_name }
output "cloudfront_hostname" { value = aws_cloudfront_distribution.portal.domain_name }
output "cluster" { value = aws_ecs_cluster.this.name }
output "ceo_canary_database_host" { value = aws_db_instance.this.address }
output "ceo_canary_database_environment" {
  description = "CEO-canary database and profile environment derived directly from the existing Risely QM RDS resource."
  value = {
    CANARY_BOOTSTRAP_ADMIN_ROLE   = var.db_username
    CANARY_DATABASE_HOST          = aws_db_instance.this.address
    CANARY_DATABASE_PORT          = tostring(aws_db_instance.this.port)
    CANARY_DATABASE_NAME          = var.db_name
    CANARY_DEPLOYMENT_PROFILE_REF = local.ceo_canary_contract.deploymentProfileRef
  }
}
output "ceo_canary_task_provenance" {
  description = "Expected zero-service task provenance for independent comparison with a future deployed ECS revision."
  value = {
    contract          = local.ceo_canary_task_provenance_contract
    contractSha256    = local.ceo_canary_task_provenance_sha256
    taskDefinitionArn = aws_ecs_task_definition.ceo_canary.arn
    serviceArn        = "arn:aws:ecs:${var.region}:${data.aws_caller_identity.current.account_id}:service/${var.cluster_name}/${local.ceo_canary_contract.family}"
    clusterArn        = aws_ecs_cluster.this.arn
  }
}
output "ceo_canary_db_operator_provenance" {
  description = "Expected inert one-off database operator task provenance and fixed private RunTask network contract."
  value = {
    contract       = local.ceo_canary_db_operator_provenance
    contractSha256 = local.ceo_canary_db_operator_provenance_sha256
    taskDefinitionArns = {
      for phase, definition in aws_ecs_task_definition.ceo_canary_db_operator : phase => definition.arn
    }
    clusterArn = aws_ecs_cluster.this.arn
    runTaskNetwork = {
      subnetIds        = sort(local.ceo_canary_private_subnet_ids)
      securityGroupIds = [aws_security_group.ceo_canary.id]
      assignPublicIp   = "DISABLED"
    }
  }
}
output "deploy_role_arn" { value = aws_iam_role.github_deploy.arn }
output "task_execution_role_arn" { value = aws_iam_role.task_execution.arn }
output "task_role_arn" { value = aws_iam_role.task.arn }
output "core_task_role_arn" { value = aws_iam_role.core_task.arn }
output "microvm_build_role_arn" { value = aws_iam_role.microvm_build.arn }
output "microvm_execution_role_arn" { value = var.deploy_microvm_execution_role_arn }
output "object_store_bucket" { value = aws_s3_bucket.objects.bucket }
output "auth_smtp_username" {
  value     = aws_iam_access_key.auth_smtp.id
  sensitive = true
}
output "auth_smtp_password" {
  value     = aws_iam_access_key.auth_smtp.ses_smtp_password_v4
  sensitive = true
}
output "core_object_store_environment" {
  value = {
    SNAPSHOT_STORE = "s3"
    TRANSFER_STORE = "s3"
    S3_BUCKET      = aws_s3_bucket.objects.bucket
    S3_REGION      = var.region
  }
}
