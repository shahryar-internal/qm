# Read-only database inventory broker

This source defines a future fixed AWS Step Functions broker for only the `inventory` database-operator task. It has not been planned, registered, or executed. It does not add a schedule, service, event rule, Lambda function, ordinary invoker role, or permission for the generic deployment role to start or modify an execution.

The broker exists because a direct `ecs:RunTask` principal cannot independently close every caller-controlled override. The state-machine definition discards caller input and fixes the exact inventory task-definition revision, cluster, Fargate platform, private subnets, task security group, disabled public IP, disabled ECS Exec, timeout, and zero container, environment, command, or role overrides. Its execution role can run only the exact inventory revision and pass only that revision's deny-all task role and phase-scoped execution role. No bootstrap, credential provision, migration, readiness, runtime, provider, evaluation-writer, or Command Center task is reachable from this definition.

Registration remains blocked until a fresh reviewer approves the complete Terraform plan, IAM policy, state-machine definition, activation evidence, and preservation of all generic QM resources. Registration alone is not inventory authorization.

Starting the inventory remains blocked until the exact bootstrap URL and CA secret containers are provisioned through a separately reviewed secret path, the existing QM backup and recovery state is re-attested, the registered task revision and source provenance are re-attested, the state-machine execution role has no out-of-band policies, and an independent operator approves one named execution. The operator must confirm no other inventory execution or database-operator task is active, provide an empty input object, retain the execution ARN, task ARN, stopped reason, exit code, and log stream, and stop on any nonzero or indeterminate result.

This broker is read-only by task contract, but it still connects to the production QM PostgreSQL instance. It must never receive a Command Center database URL, credential, route, schema, or query.
