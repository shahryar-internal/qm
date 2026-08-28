org_id                            = "risely"
account_id                        = "075343201918"
region                            = "us-west-2"
cluster_name                      = "risely-qm-pilot"
public_url                        = "https://d2arqymlq4fdoe.cloudfront.net"
cloud_map_namespace               = "risely-qm-pilot.internal"
secrets_prefix                    = "risely/qm-pilot/"
github_oidc_provider_arn          = "arn:aws:iam::075343201918:oidc-provider/token.actions.githubusercontent.com"
github_environment                = ""
object_store_bucket               = "qm-risely-1527ca86c933"
transfer_lifecycle_prefix         = "transfer/"
deploy_microvm_image              = "risely-qm-pilot-sandbox"
deploy_microvm_execution_role_arn = "arn:aws:iam::075343201918:role/risely-qm-pilot-microvm-exec"
github_repository                 = "Risely-AI/risely-agent-runtime"
github_ref                        = "refs/heads/codex/risely-slack-pilot"
certificate_arn                   = ""
db_deletion_protection            = true
services = {
  "core" : {
    "ecr_repository" : "risely-qm-pilot-core",
    "ecs_service" : "risely-qm-pilot-core",
    "cpu" : 2048,
    "memory" : 4096,
    "architecture" : "arm64",
    "internal_port" : 8080
  },
  "web-ui" : {
    "ecr_repository" : "risely-qm-pilot-web-ui",
    "ecs_service" : "risely-qm-pilot-web-ui",
    "cpu" : 512,
    "memory" : 1024,
    "architecture" : "arm64",
    "internal_port" : 8080
  },
  "admin" : {
    "ecr_repository" : "risely-qm-pilot-admin",
    "ecs_service" : "risely-qm-pilot-admin",
    "cpu" : 512,
    "memory" : 1024,
    "architecture" : "arm64",
    "internal_port" : 8080
  },
  "portal" : {
    "ecr_repository" : "risely-qm-pilot-portal",
    "ecs_service" : "risely-qm-pilot-portal",
    "cpu" : 512,
    "memory" : 1024,
    "architecture" : "arm64",
    "internal_port" : 8080
  },
  "auth" : {
    "ecr_repository" : "risely-qm-pilot-auth",
    "ecs_service" : "risely-qm-pilot-auth",
    "cpu" : 256,
    "memory" : 512,
    "architecture" : "arm64",
    "internal_port" : 8080
  },
  "gemini-compat" : {
    "ecr_repository" : "risely-qm-pilot-gemini-compat",
    "ecs_service" : "risely-qm-pilot-gemini-compat",
    "cpu" : 256,
    "memory" : 512,
    "architecture" : "amd64",
    "internal_port" : 8080
  },
  "ceo-canary" : {
    "ecr_repository" : "risely-qm-pilot-ceo-canary",
    "ecs_service" : "risely-qm-pilot-ceo-canary",
    "cpu" : 256,
    "memory" : 512,
    "architecture" : "amd64",
    "internal_port" : 8080
  }
}
secret_names = [
  "ADMIN_GRANTS",
  "ANTHROPIC_API_KEY",
  "AUTH_ALLOWED_EMAILS",
  "AUTH_CLIENT_SECRET",
  "AUTH_EMAIL_FROM",
  "AUTH_SIGNING_JWK",
  "AUTH_TOKEN_SECRET",
  "CAPABILITY_SECRET",
  "CANARY_DATABASE_URL",
  "CANARY_BOOTSTRAP_DATABASE_URL",
  "CANARY_DATABASE_CA_CERT",
  "CANARY_INGRESS_SECRET",
  "CANARY_MIGRATION_DATABASE_URL",
  "CONNECTOR_SECRET_KEY",
  "CORE_SIGNING_SECRET",
  "DATABASE_CA_CERT",
  "DATABASE_URL",
  "OPENROUTER_API_KEY",
  "PORTAL_IDENTITY_SECRET",
  "PORTAL_SESSION_SECRET",
  "PUBLIC_API_URL",
  "SKILL_SIGNING_SECRET",
  "SLACK_APP_TOKEN",
  "SLACK_BOT_TOKEN",
  "SMTP_HOST",
  "SMTP_PASSWORD",
  "SMTP_USERNAME"
]
