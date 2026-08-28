# Risely CEO agent canary

This directory contains the provider-free foundation for a private, CEO-only agent canary. It is designed to render the same reviewed unit of work in QM, Slack, and Notion while keeping external effects separate from reasoning and presentation.

## Current safety state

- This branch contains no enabled CEO canary deployment or caller route.
- Command Center is a future allowlisted read-only context source. No Command Center write path is present.
- The public connector service is intentionally inert. It cannot open a live provider connection.
- The durable service rejects every workflow and action mutation before its corresponding store method. Authenticated ingress may still record replay-nonce state before route rejection. The service has no runtime enablement switch.
- No Gmail, Calendar, Notion, Clarify, Slack, or Brain credential is consumed here.
- No email, Slack message, Notion page, CRM change, campaign, or LinkedIn action can execute.
- The CEO canary service is outside QM plugin discovery so QM cannot inject its core signing secret.
- Terraform describes isolated canary roles and secret containers, but every newly managed ECS service starts with desired count zero.
- The sole initial database ancestry is version 8. It rejects versions 1–7 and has no v7 import, compatibility, or backfill path.
- Version 8 binds durable records to an exact deployment-profile reference and digest. The production registry remains CEO-only; its second profile is an inert test fixture, not an activation grant.
- The ordinary runtime role cannot insert evaluation records or execute the atomic evaluation routine. Its dedicated evaluation-writer role is `NOLOGIN`, has no production credential path, and remains unavailable pending separate provisioning and review.

## Modules

| Module                         | Responsibility                                                                           |
| ------------------------------ | ---------------------------------------------------------------------------------------- |
| `contracts`                    | Versioned workflow, evidence, proposal, approval, and receipt schemas                    |
| `actions`                      | Exact approval and one-attempt execution state machine                                   |
| `connectors`                   | Inert, opaque connection contracts and bounded provider projections                      |
| `evals`                        | Deterministic checks, independent signed judges, durable shadow releases, and repair     |
| `workflows`                    | Meeting lifecycle, stale-deal analysis, post-meeting analysis, and Gmail-draft proposals |
| `presentation`                 | Validated surface-neutral work cards                                                     |
| `slack`                        | Deterministic Block Kit rendering from trusted interaction references                    |
| `notion-templates`             | Structured artifact templates                                                            |
| `visuals` and `visual-preview` | QM, Slack, and Notion desktop/mobile review prototype                                    |
| `service/ceo-canary`           | Version-8 PostgreSQL integrity, profile isolation, evaluation ledger, audit, and ingress |
| `service/ceo-surface`          | Hard-disabled compiler for one immutable, evaluated, actionless CEO Slack DM             |

The generic QM changes needed for live Slack interactions and in-chat artifact rendering are specified in `QM-UPSTREAM-HOOKS.md`. They cannot be implemented in this private fork because core must remain byte-identical to upstream.

## Intended flow

1. A scheduler identifies one eligible calendar occurrence.
2. Reviewed adapters project bounded evidence from connected sources.
3. A workflow creates a versioned artifact without side effects.
4. Evaluation gates must persist an unexpired, provider-ineligible shadow release before presentation.
5. QM, Slack, and Notion render the same artifact and revision.
6. A human reviews one exact action proposal tied to their identity, credential owner, evidence, payload hash, and expiry.
7. A separately reviewed executor reserves the effect durably and records the provider receipt.

Steps 1, 2, 6, and 7 are deliberately not live in this foundation.

## Surface integration boundary

The checked-in Slack renderer produces valid Block Kit, but it is not connected to Slack delivery. A layer-owned shadow publisher may compile an actionless private CEO card with a fixed QM portal link. Sending remains blocked until authenticated evaluation, outbox, identity-resolution, target-pinning, durable receipt, and Slack-adapter contracts are independently reviewed and connected.

Custom buttons on the currently installed Risely Slack app require a small QM core extension. QM's current Socket Mode receiver registers only its existing action families, and a second receiver using the same app would make Slack distribute events nondeterministically between connections. The preferred end state is one typed action-provider hook in QM plus a typed web artifact-renderer hook. Until those exist, the prototype buttons are visual specifications rather than live controls.

## Local validation

From `deploy/layers/risely`:

```sh
npm test
terraform -chdir=infra fmt -check
terraform -chdir=infra validate
npm audit --audit-level=moderate
git diff --check
```

The exact bootstrap integration is skipped unless an operator explicitly enables its unique loopback-only PostgreSQL 16 container; it accepts no database URL and provisions the trusted bootstrap administrator as exact database-owner role `qm`. The full lifecycle integration is also opt-in and self-creates a unique TLS-enabled loopback PostgreSQL 16 container. It runs structural bootstrap, ordinary credential provisioning and rotation, migration and runtime authentication, the real version-8 migration wrapper, production runtime readiness, runtime evaluation-write denial, isolated evaluation-writer provisioning, signed quorum and atomic-release persistence, a representative store read, composite deployment-profile isolation, catalog self-attestation and cross-schema escape attacks, hostile retention refusal, and clean retention without accepting a caller database URL. Both suites remove their isolated resources and cannot target QM, Command Center, AWS, or an arbitrary RDS host.

To view the deterministic prototype, serve this directory locally and open `/visual-preview/`. The checked-in desktop and mobile captures are `visual-preview/desktop.png` and `visual-preview/mobile.png`.

## Live activation gates

1. Provision the dedicated `risely_agent_runtime` schema and roles inside the existing Risely QM database with the operator runbook.
2. Pass the self-created PostgreSQL 16 bootstrap and lifecycle suites before touching a persistent canary database.
3. Implement and independently review a durable connection resolver plus concrete provider adapters, including revocation and two-account isolation tests.
4. Implement and independently review a Slack-to-principal identity bridge. Service authentication alone is not human authorization.
5. Add the QM typed Slack action-provider and web artifact-renderer hooks, or limit the first shadow release to actionless CEO-private cards.
6. Wire Calendar and transcript reads in shadow mode and complete five duplicate-free meeting lifecycle runs.
7. Add Gmail draft creation only after exact proposal, account, effect, and provider-receipt tests pass. Sending remains a separate capability and review.
8. Keep CRM writes, bulk email, LinkedIn automation, and campaign execution disabled until each receives its own authority and safety review.

Secrets belong in the reviewed connection or AWS secret flow. Do not paste OAuth tokens or provider keys into source files, chat, fixtures, or local documentation.
