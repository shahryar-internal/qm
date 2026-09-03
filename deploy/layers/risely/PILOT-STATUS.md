# Risely agent pilot status

Last verified: August 27, 2026

## Live pilot

- Web and sign-in: `https://d2arqymlq4fdoe.cloudfront.net`
- Admin: `https://d2arqymlq4fdoe.cloudfront.net/admin/onboarding`
- AWS account and region: `075343201918`, `us-west-2`
- Stack prefix: `risely-qm-pilot`
- Model: Google `gemini-3.7-flash` through the private `gemini-compat` service; `gemini-3.5-flash` remains registered for rollback
- Gemini gateway image: `sha256:df25432b2b6bb6ce8c6ecce1a171f8db33fd5396e99f4cc6a2300bb4aed05a2d`
- Portal image: Risely custom-provider gate override pinned to `sha256:eedc2a58d758344b383fd5680545f18f3392f1dbd6b653ef4bc62ea44cd7547f`
- Signed organization layer: version 8, digest prefix `a647a2065ef7`
- Shell governance: strict QM tool approval plus an empty organization command allowlist
- Database transport: Amazon RDS certificate chain and endpoint hostname verified with the official `us-west-2` CA bundle

The pilot is isolated from Command Center and existing Risely application databases. No Command Center connector, CRM connector, email connector, calendar connector, Notion connector, or production-data source is attached.

## CEO canary foundation

The CEO canary remains unapplied and is not part of the live pilot. Terraform now defines its first production-shaped, digest-pinned runtime revision behind private authenticated ingress. The service stays at desired count zero, receives no public address or listener, has no provider route, and cannot receive an evaluation-writer credential. Its task environment targets only the existing Terraform-managed Risely QM RDS resource and database `qm`; it never targets Command Center. The generic GitHub deploy role excludes the canary family, service, roles, ECR images, canary-prefixed secrets, and logs, while the task role carries an explicit deny-all policy. `DATABASE_CA_CERT` is injected from the dedicated `CANARY_DATABASE_CA_CERT` container, so the shared trust-anchor secret is not canary authority. No canary deployment principal exists. A dedicated additive RDS security group leaves the original shared rule unchanged. Exact normalized RDS attachment, security-group rule, endpoint-policy, and local/S3-prefix route provenance rejects extras, widening, and both default destinations. State-backed backend/workspace/lineage and no-replacement planning, external canary-role inventory, VPC-wide private-DNS compatibility QA, and independent sealing of exact Terraform output remain unavailable external blockers. Its sole initial database ancestry is version 8, with no v7 import, compatibility mode, or backfill path. Durable records are scoped by exact deployment-profile reference and digest. The production registry contains only the CEO profile; the synthetic second profile is test-only and confers no production authority. Its append-only evaluation ledger accepts only same-profile synthetic shadow releases from a dedicated evaluation-writer authority, while the runtime role is denied that routine. The writer remains `NOLOGIN` and has no production credential path, so release issuance is unavailable until separate provisioning and review. Every stored release is explicitly ineligible for provider execution.

Offline activation evidence is checksum-pinned, but it cannot satisfy the production PostgreSQL sentinel, deployed task-host provenance, IAM inventory, VPC-wide private-DNS QA, or authorized state-backed backend/workspace/lineage review requirements. The expected Terraform task contract is not deployment evidence. Every gate remains blocked, all newly managed CEO-canary services remain at desired count zero, and provider invocation remains disabled.

## Verified

- `npm test`: 16 passing tests
- `npm run check`: pass
- `npm run governance:lock`: pass, no change required
- `npm run public-chat:check`: authenticated public web/API turn passed on `gemini-3.7-flash`
- `npm exec qm -- check --live`: private live session smoke passed and live AWS state matches the directory in both directions
- `npm exec qm -- conformance`: pass
- `npm exec qm -- doctor`: AWS prerequisites ready
- Terraform format and validation: pass
- Chief of Staff live workflow: passed with all six goals graded from available evidence and no claimed action
- Sales Deal live workflow: two consecutive evidence-safe draft runs passed with no email, CRM update, proposal publication, or shell command
- Verified database TLS: a fresh core revision connected and reached healthy with `DATABASE_CA_CERT`; the database URL contains no `sslmode=no-verify` override
- Gemini gateway tests cover sequential tool replay and prove an upstream response-stream failure is contained without crashing the service

## Slack gate

Slack is not connected. `SLACK_BOT_TOKEN` and `SLACK_APP_TOKEN` are intentionally unset. To finish the Slack gate:

1. Run `npm run slack:render` and `npm run qm -- outputs`.
2. Open the generated Slack app creation URL, create it in the Risely workspace, and install it.
3. Create an app-level token with `connections:write`.
4. Enter the bot and app tokens in the authenticated QM Admin Slack card.
5. Invite Risely only to a dedicated private pilot channel and complete every check in `SLACK-PILOT.md`.

Do not open a pull request or add the bot to operating or customer channels until live Slack QA passes.

## Scheduled-loop gate

The live pilot's current `pg-boss` cron queue does not receive QM's RDS CA configuration. It refuses an unencrypted database connection and safely falls back to interval ticks. Interactive chat and manual workflows are unaffected. This unreleased private candidate merges the public scheduler successor `311bd82c5aceb4eb7ebe45029b9d3337d0be3b18`, which passes the existing verified CA configuration to `pg-boss` without changing connection-string TLS semantics and pins the required wiring order in a static regression test. Local custom-CA PostgreSQL coverage proves encrypted queue transport, multi-instance deduplication, restart replay, and cancellation, but this candidate has not been pushed, released, deployed, or tested against live RDS. Durable production automation loops remain gated on fresh review, official CI, a source-pinned private release, guarded deployment, and live RDS verification.

The committed Gemini 3.7 cost metadata uses Google's introductory `$0.75` input and `$3.75` output rates per million tokens through December 31, 2026. Review and update them to Google's published `$1.50` and `$7.50` rates before January 1, 2027.

## Known Terraform drift

A full Terraform plan reports replacement of five inert revision-1 bootstrap ECS task definitions because the stack was bootstrapped as ARM64 and the deployed QM services use AMD64. Do not apply that full plan casually. The live ECS services already run the correct immutable AMD64 revisions and `qm check --live` passes.

An unused `risely/qm-pilot/RESEND_API_KEY` secret remains in AWS outside Terraform state. It was not deleted. The pilot task and deploy roles no longer have access to it.
