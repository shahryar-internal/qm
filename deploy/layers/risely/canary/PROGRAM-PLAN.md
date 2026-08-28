# Risely CEO agent program

## Objective

Build the complete CEO-only agent team without inheriting unsafe runtime behavior from prior prototypes. Meeting preparation, follow-up, deal movement, outreach, LinkedIn, demo customization, marketing, goals, and end-of-day reporting remain in scope. Release gates sequence authority; they do not remove features.

Command Center is a bounded read-only source. Risely Ops Staging and Shahryar Command Center are business-rule archaeology and sanitized fixture sources only. No old runtime, credential, approval, executor, database query, or scheduled job is called.

## Engineering team loop

Each lane passes through four distinct roles:

1. An author implements one bounded lane and publishes strict contracts and fixtures.
2. A different agent performs fresh-context adversarial review and attempts to break authority, identity, durability, replay, evidence, spend, and failure behavior.
3. A cross-lane reviewer verifies that adjacent producers and consumers agree without importing private internals.
4. The lead integrates, runs the affected and full deployment-layer suites, checks the repository boundary, and controls commits and deployment decisions.

Findings return to the original author. A lane is not complete until the independent reviewer returns GO on the repaired stable snapshot. Green tests are evidence, not approval.

The three parallel author lanes rotate reviews in a ring:

| Authored lane    | Adversarial reviewer | Cross-lane focus                                                             |
| ---------------- | -------------------- | ---------------------------------------------------------------------------- |
| Platform runtime | Revenue/source agent | Outbox, effects, budget, rate and account isolation                          |
| Chief of Staff   | Platform agent       | Scheduler durability, identity, evidence and Gmail draft authority           |
| Revenue/source   | Chief-of-Staff agent | Calendar/account context, customer evidence and unavailable-source semantics |

The next wave assigns marketing and surface integration to freed authors while the third agent performs integration review. No author self-approves.

## Shared contracts

Lane internals remain private and independently versioned. The integration boundary consumes each lane's public-index output and normalizes it into the same boundary vocabulary before cross-lane storage, evaluation, presentation or execution:

- `PrincipalBinding`: organization, deployment, CEO principal, surface identity, credential owner and audience.
- `EvidenceBundle`: immutable source references, hashes, observation times, trust labels and availability states.
- `WorkflowArtifact`: versioned reviewed work with one stable workflow identity and revision.
- `EvalRelease`: deterministic checks plus independently originated quality judges, exact artifact digest and zero-side-effect proof.
- `OutboxEvent`: immutable evaluated revision scheduled for one surface and audience.
- `PublicationEnvelope`: deterministic actionless presentation bound to the outbox event, principal, audience and artifact revision.

Action proposals and execution receipts remain lane-specific and inert until separate public adapters normalize their exact capability, target, payload, effect, credential, expiry and provider-result contracts.

No model emits Slack Block Kit, browser HTML, provider commands, credentials, authorization decisions, or executable payloads. Models propose typed work; deterministic code validates, evaluates, authorizes, renders and executes.

## Full product scope

### Chief of Staff

- Poll the CEO calendar and automatically detect eligible customer meetings.
- Schedule T-24 dossier, T-90 refresh and T-15 demo reminder work with move/cancel/recurrence deduplication.
- Combine Calendar, bounded Gmail context, Clarify, Brain, Notion and prior transcript evidence.
- Deliver a private briefing with account, attendee, positioning, outcome, risks and source links.
- Correlate the final transcript to the exact calendar occurrence.
- Produce what went well, what did not, decisions, commitments, owners and next steps.
- Prepare one exact Gmail draft proposal and a versioned proposal artifact without sending.
- Generate morning stale-deal follow-ups, goals-on-track analysis, goal-deck artifacts and employee end-of-day updates.

### Revenue and outreach

- Port deterministic ICP, Apollo, sequencing and suppression rules as reviewed configuration rather than old runtime calls.
- Prepare 100–200 daily email candidates across four bound inboxes with per-inbox budgets and suppression checks.
- Select the best 20 daily LinkedIn connection candidates from the evaluated outreach list.
- Correlate RB2B, Google Analytics and PostHog visitor intent without claiming identity beyond source confidence.
- Propose connection requests and accepted-connection DMs with exact account and recipient binding.
- Monitor stale deals and verified touches without treating unavailable sources as no activity.
- Keep CRM mutation, email send, LinkedIn execution and campaign launch disabled until their separate activation gates pass.

### Finance and invoicing

- Run a profile-scoped Mercury invoicing agent on explicit daily, weekly, or monthly QM schedules.
- Resolve each invoice from an approved billing record to one exact Mercury organization, customer, and destination account.
- Assign deterministic period-based invoice numbers so retries cannot create duplicate invoices.
- Create invoices sequentially with `sendEmailOption=DontSend`; never rely on Mercury's immediate-send default.
- Require a fresh one-use human approval bound to the exact customer, amount, line items, dates, invoice number, destination account, and rendered invoice before delivery.
- Poll the exact invoice status for reconciliation and surface unpaid, processing, paid, cancelled, short-payment, and overpayment states without treating a transaction memo as proof.
- Pin the official Mercury CLI and production API host, prohibit debug output and caller-selected base URLs, and prove the complete flow in Mercury's sandbox before production activation.
- Keep invoice cancellation, customer deletion, payment initiation, transfers, cards, recipients, and every other banking mutation outside this agent's authority.

### Demo customization

- Identify advancement-stage meetings and schedule T-3 preparation plus T-15 reminder work.
- Produce a reviewed demo specification, seeded-repository proposal and environment checklist.
- Never write a repository, inject an API key or claim a deployed demo until a dedicated builder executor returns a verified receipt.

### Marketing

- Produce a Friday weekly plan covering rotating advancement and admissions topics.
- Generate at least one daily draft from the approved plan using the versioned Shahryar voice rubric.
- Evaluate voice similarity, factual support, specificity, novelty, CTA quality, banned claims and source depth.
- Publish reviewed drafts to the private Notion workspace and Slack; social publishing remains a separately approved capability.

### Surfaces

- Use one Risely Slack app and one existing Socket Mode receiver.
- Deliver private CEO cards first; shared-channel publication requires a separate audience policy.
- Use opaque interaction references bound server-side to team, user, message, artifact, revision, proposal and expiry.
- Render the same artifact revision in Slack, QM and Notion with stable cross-links.
- Keep actionless delivery as the fallback until generic upstream QM Slack and web artifact hooks are released.

### Platform and operations

- Use the shared agent-runtime schema and dedicated roles inside the existing Risely QM database, with isolated migrations, retention and immutable audit.
- Reserve every external effect durably and reconcile ambiguous outcomes before retry.
- Route high-cost proposal generation through an independently reviewed worker; a consumer-plan login is not treated as an API or automated service entitlement.
- Enforce per-workflow budgets, rate limits, kill switches, connector revocation and two-account isolation.
- Provide runbooks, dashboards, delivery health, audit links, rollback and five consecutive duplicate-free shadow runs.

## Activation gates

| Gate                   | Enabled                                                                                       | Still disabled                                                      |
| ---------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| G0 reviewed foundation | Fixtures, schemas, evaluators, renderers                                                      | Provider traffic and deployment                                     |
| G1 read shadow         | Calendar, Gmail context, Brain, Clarify, Notion and transcript reads                          | All external writes                                                 |
| G2 surface shadow      | CEO-private actionless Slack/QM/Notion artifacts                                              | Buttons and provider effects                                        |
| G3 personal drafts     | Exact Gmail draft creation, private Notion publication and unsent Mercury invoice preparation | Email send, invoice delivery, CRM, LinkedIn, social and repo writes |
| G4 controlled actions  | Individually approved low-volume sends, invoice deliveries or connection requests             | Bulk unattended execution                                           |
| G5 scaled loops        | Daily budgets after measured canary success                                                   | Any capability without owner, suppression, rollback and audit       |

Promotion requires independent GO, live connector negative tests, correct provider receipts, no duplicate effects, kill-switch proof and explicit CEO activation. Disabling a capability never removes audit, outbox or outcome-unknown records.

## Workflow acceptance matrix

| Workflow               | Trigger and evidence                                                                                       | Reviewed output                                                               | Canary authority                      | Live proof required                                                                                     |
| ---------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Meeting preparation    | Exact eligible calendar occurrence plus available Gmail, Brain, Clarify, Notion and prior-meeting evidence | Cited dossier, positioning, desired outcome and risks                         | Read and private artifact delivery    | Five correctly timed, moved/cancelled-safe, duplicate-free shadow occurrences                           |
| Post-meeting follow-up | Final transcript bound to the exact completed occurrence                                                   | Analysis, commitments, next steps, email-draft proposal and proposal artifact | Draft proposal only until G3          | Correct sparse/missing/final transcript behavior and one exact Gmail draft receipt                      |
| Stale deals            | Verified newest touch across available account sources and stage threshold                                 | Ranked digest and per-deal follow-up proposal                                 | Read and draft proposal               | No unavailable source interpreted as no activity; threshold boundary fixtures match live shadow         |
| Goals and EOD          | Versioned goals, bounded reporting interval and cited work evidence                                        | On-track status, gaps, deck artifact and employee update                      | Private artifact delivery             | Every claim resolves to evidence and incomplete source coverage is visible                              |
| Daily outreach         | Approved ICP/campaign configuration, suppression state and evaluated candidates                            | 100–200 email candidates allocated to four bound inboxes                      | Preparation only through G3           | Budget, suppression, replay and two-account negative tests pass on shadow data                          |
| LinkedIn               | Evaluated outreach candidates or confidence-labelled visitor intent plus exact LinkedIn account            | Top 20 connection proposals and accepted-connection DM proposals              | No execution before G4                | Daily boundary, recipient/account binding, approval expiry and provider-receipt tests pass              |
| Demo customization     | Advancement-stage occurrence, account evidence and T-3 schedule                                            | Demo specification, seeded-repository proposal and T-15 runbook               | No repository or environment mutation | Builder receipt proves exact repository revision, configuration and secret-free output                  |
| Marketing              | Friday plan approval, versioned voice rubric and cited research                                            | Weekly plan and daily Shahryar-voice drafts                                   | Private Notion/Slack drafts only      | Voice, factuality, novelty, CTA, unsafe-claim and evaluator-independence gates pass                     |
| Mercury invoicing      | Approved billing record, exact customer/account binding and explicit QM billing schedule                   | Deterministic unsent invoice plus approval request and reconciliation status  | Prepare only through G3; send at G4   | Sandbox create/read/retry proof, one-use approval, duplicate denial and exact paid-state reconciliation |

For every row, source unavailability is a first-class state, revisions invalidate prior approvals, and an ambiguous external outcome is held for reconciliation rather than retried.

## Four-day build sequence

### Day 1

- Complete durable outbox/receipt and source adapter contracts.
- Implement the automatic meeting scheduler and bounded Google read vertical.
- Implement Brain, Clarify, Notion and transcript read normalization.
- Finish cross-lane contract fixtures and first adversarial rotation.

### Day 2

- Complete meeting dossier, refresh, post-meeting, Gmail-draft proposal, stale-deal and goals/EOD workflows.
- Complete CEO-private Slack identity and actionless delivery composition.
- Run provider-free end-to-end fixtures and second adversarial rotation.

### Day 3

- Complete outreach, LinkedIn, visitor-intent, demo and marketing state machines and evaluations.
- Prepare upstream QM Slack/web hook contribution material.
- Run full cross-workflow replay, rate, suppression, two-account and outcome-unknown tests.

### Day 4

- Provision only the reviewed dedicated canary resources.
- Connect live read adapters and run CEO-only shadow scenarios.
- Perform Slack/browser QA, operational drills and rollback proof.
- Activate only gates whose live evidence passes; retain the rest as complete but disabled capabilities.

The four-day objective is a functioning CEO shadow team with the full program represented in reviewed code and gated state machines. It is not permission to bypass provider consent, upstream repository rules, database isolation, external platform terms or independent live-activation review.
