# Revenue program boundary

This directory is the provider-free contract and durable prospective state layer for the CEO revenue program. It has no credentials, network clients, provider SDKs, queues, database access, receipt issuer, or execution path.

## Implemented now

- One fixed external deployment and CEO `PrincipalBinding` anchor, including Shahryar's exact Risely mailbox and Google credential owner, plus compile-time provider connection anchors that callers cannot replace
- Unresolved `ConnectionBinding` requirements for Apollo, Google, Notion, Clarify, Brain, LinkedIn, RB2B, PostHog, the demo repository, and the CEO Slack workspace, with no receipt mint in this package
- Typed correlation records from candidates, deals, meetings, acceptances, and artifacts to exact account, contact, meeting occurrence, provider, and present source records
- Read-only snapshots for all eleven Command Center Brain tools, Apollo, Clarify, Calendar, Gmail connection state, Notion, finalized transcripts, RB2B, Google Analytics, PostHog, and LinkedIn
- Closed provider-specific fact schemas and semantic-use policies tying Apollo evidence to candidate identity and content, Clarify evidence to stale-deal identity and content, LinkedIn and Notion evidence to accepted-profile DM content, Calendar evidence to a meeting schedule, and transcripts to exact artifact content
- Exact `available`, `none`, `unavailable`, and partial Brain semantics; Brain payload results remain opaque and unresolved and are never interpreted or used as action evidence
- Per-tool current Brain query subjects, exact `asOf`, an opaque result-state envelope, required response metadata, record citations, and provider-derived query references; any mixed tool status is partial
- Account-level-only visitor intent with bounded confidence-derived scores and exact RB2B, Google Analytics, and PostHog domain facts; visitor data can create only a private account research artifact and is causally excluded from email and LinkedIn proposals
- A combined daily Gmail proposal budget of 100–200 across cold and stale-deal drafts, with a combined maximum of 50 per inbox
- Stale drafts distributed to the least-used inbox and backed by the exact present touch record, timestamp fact, and citation
- Top-twenty LinkedIn connection selection from the selected daily email list, excluding accepted and suppressed identities
- Canonical email and LinkedIn-profile deduplication across suppression, ledger, stale, acceptance, and campaign inputs, with ledger identities derived from typed canonical recipients and exact subjects
- Meeting cancellation, movement, recurrence, original occurrence, prior start, prior and current event versions, prior and current schedule revisions, reminder ledger, and customization ledger modeling for the three-day demo workflow
- Cancellation cannot also claim a move: its prior and current start are identical, its move field is empty, and both lifecycle versions increase
- Private-CEO Notion artifacts pinned to the exact bound parent root
- Transcript artifacts bind the exact transcript record and complete fact-citation set, end time, finalization time, observed time, title, body, and summary; finalization must follow transcript end and precede observation, snapshot check, and trusted build time
- Provider-derived record, citation, Brain query, correlation, and proposal references with one global cross-namespace uniqueness check
- Proposal, idempotency, and prospective effect keys bound to provider account, credential owner, stable recipient, payload, local day, program, and revision
- Fixed deterministic and Luna evaluator origins with gate-specific criteria, exact artifact digests, evidence lineage, and nonreusable prospective run references
- Unresolved Slack approval requests bound to team, user, message, interaction, action, program and state revisions, payload hash, and expiry
- Prospective `outcome_unknown`, confirmed, and failed reconciliation vocabulary without a reconciliation mutation
- Uncommitted transition proposals with exact expected revisions and fences, bounded plain JSON, record hashes, and presentation totality

The built program contains unresolved proposals and no caller-controlled execution, live, enabled, or provider-effect fields. State initialization rejects such fields recursively and derives `safetyDisposition: hard_disabled`. A cloned or self-hashed program or state is not trusted. Raw evaluator and Slack approval receipts are rejected, including forged self-hashes. Evaluation and approval functions return unresolved transition proposals that require a future trusted durable compare-and-swap bridge; they do not commit state, record a pass, authorize an action, or change reconciliation state.

Command Center remains read-only. Gmail, LinkedIn, CRM, Notion, Slack, and demo-repository writes cannot run from this package.

## Integration boundary

Consumers import `index.mjs`. `createRevenueProgramBoundaryFixture` supplies the deterministic cross-lane fixture. `normalizeRevenueProgramInput` is the strict source boundary. `buildRevenueProgram` produces the complete prospective plan. `initializeRevenueProgramState` derives a branded, hard-disabled, uncommitted state proposal. `requestRevenueProgramEvaluation` and `requestRevenueProgramApproval` create unresolved transition proposals for future trusted bridges. `presentRevenueProgram` renders every proposal and source status without an action affordance.

Provider adapters must emit bounded records with the exact deployment, anchor, tenant, workspace, principal, credential-owner, provider-account, root, source-record, and evidence bindings. Record and citation references are derived from the bound provider, root, source, observation time, and exact facts rather than accepted as opaque caller identifiers. A source snapshot and its records must be fresh and belong to the canonical local goal day. `none`, `unavailable`, partial gaps, opaque Brain results, response receipts, and source-level hashes are never action evidence.

A future trusted bridge must persist programs and state records atomically in the dedicated canary schema inside the existing Risely QM database. Every transition proposal carries the exact expected revision and fence; the database transaction must compare and swap both and enforce uniqueness for program, request, proposal, idempotency, effect, evaluator-run, correlation, and stable-recipient keys. This package exposes no trusted-state or connection-receipt mint, so reconstructed records cannot currently re-enter a transition.

## Reproducible snapshot

`SNAPSHOT.sha256` freezes the reviewed tree hash. The hash covers relative path plus SHA-256 content digest for every file in `canary/revenue-program` and `test/revenue-program`, excluding `SNAPSHOT.sha256` itself. Run this from the repository root:

```sh
find deploy/layers/risely/canary/revenue-program deploy/layers/risely/test/revenue-program -type f ! -name SNAPSHOT.sha256 -print | LC_ALL=C sort | while IFS= read -r file; do digest=$(shasum -a 256 "$file" | awk '{print $1}'); relative=${file#deploy/layers/risely/}; printf '%s  %s\n' "$digest" "$relative"; done | shasum -a 256 | awk '{print $1}'
```

## Live blockers

Live reads still require separately reviewed adapters for Apollo, Google, Clarify, Notion, Brain, RB2B, Google Analytics, PostHog, and LinkedIn. Durable scheduling, reservation, transition compare-and-swap, connection binding, outbox, receipt, and reconciliation tables are not implemented here. Neither are Slack identity and signature resolution, trusted server time, evaluator receipt issuance, provider receipt verification, revocation, or end-to-end CEO shadow evidence.

Bulk email, LinkedIn connection or DM sending, CRM mutation, Notion publishing, Slack delivery, and demo-repository mutation require new dedicated executors. Activation cannot happen by changing a field in this package. Each executor needs least-privilege credentials, account and recipient binding, durable reservation and idempotency, expiry and revocation, outcome-unknown reconciliation, independent security review, and CEO-only canary evidence.
