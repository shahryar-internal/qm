# Same-QM database operator runbook

## Status

The database-operator slice is absent by default. When `ceo_canary_db_operator_image` is unset, Terraform creates no operator log group, role, policy, task definition, service, schedule, launcher, deployment permission, or desired task count, and emits no operator provenance. Supplying a real immutable operator image enables exactly five inert, one-off ECS task definitions and their least-authority startup resources. Do not launch any phase until a reviewed Terraform state plan proves that all resources are additive, an independent reviewer approves the exact task revision and provenance output, and the operator confirms that the existing QM database backup and recovery controls are healthy.

The operator uses the existing Terraform-owned `risely-qm-pilot-core` RDS instance, database `qm`, and schema `risely_agent_runtime`. It has no Command Center database credential, network route, secret, import, query, or migration. It has no provider credential or action/evaluation writer credential.

## Image and secrets

Build `Dockerfile.db-operator` from the `canary` directory and provide its immutable stack-owned ECR digest as `ceo_canary_db_operator_image` only when the five definitions are intentionally being registered. This dedicated image copies only the eight reviewed same-QM lifecycle modules and installs only their PostgreSQL client dependency. The runtime image is a separate input and must not be substituted. A tag, foreign repository, placeholder digest, or runtime-image substitution is invalid operator evidence. The structural bootstrap embedded in the operator image must byte-match `migrations/bootstrap.sql`; the offline contract test enforces that equality.

Populate the following dedicated secret containers only after the task definitions and execution policies have passed state-plan review:

- `CANARY_BOOTSTRAP_DATABASE_URL`: exact `qm` database owner URL for the Terraform-derived RDS host, port 5432, and database `qm`.
- `CANARY_MIGRATION_DATABASE_URL`: exact migration-role URL with a canonical 32-byte base64url credential.
- `CANARY_DATABASE_URL`: exact runtime-role URL with a distinct canonical 32-byte base64url credential.
- `CANARY_DATABASE_CA_CERT`: the RDS trust bundle used with hostname verification.

The bootstrap, migration, and runtime credentials must all be distinct. Secrets are injected only into the phases that require them. Task roles deny every AWS action. Per-phase execution roles can read only the exact phase secrets required to start that task.

## Required order

Launch exactly one task at a time, wait for a successful exit, retain its task ARN and log stream as evidence, and do not use container overrides. Use only the cluster, task definition ARN, private subnet IDs, security-group ID, and `assignPublicIp=DISABLED` values emitted by `ceo_canary_db_operator_provenance`.

1. `inventory` opens a read-only transaction as the exact `qm` database owner and reports only the database identity, expected canary roles/schema, migration-catalog presence, and bounded hazard counts. It does not receive a canary data-reader credential and cannot execute bootstrap or migration code because its phase is compiled into the immutable ECS entrypoint.
2. `bootstrap` repeats the inventory, requires the canary schema and four roles to be absent, then runs the one-shot transactional structural bootstrap. Any preexisting canary object causes refusal.
3. `provision` requires the exact empty bootstrapped schema, derives the two canonical credentials from their fixed URLs, and invokes the transactional credential provisioner. It never prints credentials or password hashes.
4. `migrate` receives only the migration URL and CA, then executes migration v8 through the centralized full catalog and database-boundary verifier.
5. `readiness` receives only the runtime URL and CA, then runs the same production database readiness verifier used by the CEO canary runtime.

Stop immediately on any nonzero exit, unexpected inventory state, task-definition mismatch, network override, secret override, extra command argument, or absent completion marker. Do not skip, reorder, retry bootstrap, or use an interactive shell. Inventory, credential provisioning, and readiness are intentionally re-runnable; bootstrap and migration retain their strict existing database contracts.

## Network and launch boundary

The definitions reuse the dedicated canary private subnets, route table, endpoint set, task security group, and additive canary database security group. There is no public IP, NAT/default route, listener, provider egress, ECS Exec permission, or automatic launcher. Registering the definitions does not run them. A future narrowly reviewed operator principal may receive `ecs:RunTask` and exact `iam:PassRole` only after it also denies task-role, execution-role, command, environment, network, public-IP, and execute-command overrides. That principal is deliberately absent here.

## Offline validation

Run Terraform formatting and validation without a backend or provider access, the task-contract tests, and the isolated PostgreSQL 16 lifecycle. None of these commands may use an AWS, QM, or Command Center connection string. Live inventory is itself a live database action and is outside the validation authorized for this change.
