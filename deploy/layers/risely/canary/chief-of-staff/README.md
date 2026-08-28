# Chief-of-Staff automatic meeting vertical

This directory is a credential-free, provider-bound implementation contract. It plans automatic CEO meeting work without making a network call, reading an environment token, writing a provider, delivering a message, or claiming that the current QM connection works headlessly.

The implemented vertical covers:

- fixed-host Calendar and Gmail read request plans;
- an unresolved provider execution proposal requesting at most 60 seconds of future broker authority;
- durable polling and reconciliation for T-24 dossier preparation, T-90 briefing refresh, and T-15 briefing delivery;
- stable recurring-instance identity, move reconciliation, explicit cancellation, and retry-safe job and outbox identities;
- evidence-bound meeting dossiers;
- exact or uniquely attributable untrusted transcript correlation plus an unresolved source-verification request;
- an inert post-meeting analysis input;
- a closed Gmail draft boundary that cannot produce a proposal without a future trusted source-verification broker;
- evidence-cited daily and periodic goals artifacts.

## Current QM keychain constraint

QM keeps connector credentials encrypted and owner-scoped in core. Core can refresh and access a connector token for an identified principal. The ordinary authorization path is attached to an authenticated user turn, conversation capability, or explicit keychain grant. An autonomous scheduler has no user turn and therefore has no legitimate principal-bound capability merely because the user connected Google in the web UI.

Strict posture makes this distinction important. A background job cannot reuse a browser cookie, manufacture a conversation grant, inject a refresh token through an environment variable, or ask the sandbox to materialize the CEO's connector credential. The existing user connection proves that the account can be connected; it does not create a durable authorization for unattended use.

## Smallest safe seam

The smallest upstream seam is a core-owned automation connector broker, not a raw-token endpoint.

1. The CEO creates or revokes a durable automation grant while authenticated in QM. The record binds the CEO principal, exact Google connection, allowed read operations, resource root, schedule, destination, and expiry.
2. The scheduler submits a signed job identity and the grant reference to a private core route.
3. Core verifies source identity, grant status, exact operation, audience, resource root, job idempotency, and rate limits.
4. Core retrieves and refreshes the keychain credential internally and performs the fixed-host provider request itself.
5. In one database transaction, core fences and reserves the exact organization, deployment, principal, credential owner, provider account subject, connection, job revision, schedule revision, operation, audience, destination, and request-plan hash against its monotonic server time.
6. Core returns only a bounded provider projection, evidence hash, and durable execution receipt. No access token, refresh token, authorization header, browser session, or keychain secret crosses the boundary.
7. Every attempt and result is durably audited against the principal, grant, connection, job, provider operation, request-plan hash, and response evidence hash.

`provider-boundary.mjs` emits only an unresolved execution proposal and fixed-host request plan. It makes no single-use, freshness, expiry, or replay-protection claim. It rejects caller-supplied issue, expiry, token, or execution fields. Its requested lifetime is only an input ceiling; a future broker must apply monotonic server time and durable single-use reservation. Until that reviewed broker exists, every plan states that provider execution is unavailable.

## Durable execution contract

The scheduler returns deterministic reconciliation data. A stable provider occurrence reference, not a movable start timestamp, identifies both recurring and non-recurring meetings. Missing events are never interpreted as deletions because paginated or temporarily unavailable Calendar results are not proof of cancellation. Only an explicit provider cancellation or an observed ineligible/moved revision cancels existing nonterminal work.

T-24, T-90, and T-15 work that is first observed late but before the meeting starts is marked `late_before_start` and becomes immediately eligible subject to its exact dependency job id and revision. Once the meeting has started, prep and briefing delivery are marked missed and no obsolete T-15 delivery is scheduled. Every durable claim must fence the job revision, and every outbox record must retain that fence plus the exact plan and authority lineage.

Production storage must implement the bound durable port as database transactions. Schedule reconciliation, job claims, job completion plus outbox append, outbox claims, acknowledgements, and expired-claim release cannot be backed only by process memory. Every method accepts and returns a distinct, bounded, exact envelope. Each request id is derived from the exact normalized authority and payload, including deployment, principal, operation, job, revision, and fence fields, and is rejected before adapter invocation if anything changes. Unknown fields and credential-, token-, secret-, authorization-, cookie-, password-, or API-key-shaped material fail before the adapter runs. Cancellation records retain the exact prior plan, schedule revision, job revision, and claim fence and can only be applied by fenced compare-and-swap. The current code supplies the interface and deterministic records but does not select or mutate a database.

Public claim requests contain only a fixed 60-second TTL intent. They do not accept a caller expiry or current time. Expired-claim release accepts no cutoff. Those three clock-sensitive methods remain unresolved and do not invoke the supplied adapter because this layer has no trusted database-clock receipt. A future reviewed store integration must calculate claim expiry and expiration eligibility from its server or database clock and return a broker-authenticated receipt before this contract can claim that durable state changed.

## Effect boundary

Calendar and Gmail context plans are reads. Pure correlation normalizes untrusted meeting and transcript objects and binds provider event and transcript identifiers, account subjects, exact occurrence and revision, event and transcript times, finalization time, evidence, participant identities and roles, and the workflow observation time. It emits only an unresolved request for `qm_core_source_verification_broker`; it does not mint trust or brand caller data. Analysis cannot predate transcript finality or workflow observation and must be generated within 24 hours.

A future core broker must mint an opaque, frozen, descriptor-safe `SourceVerificationReceipt` that binds its exact origin and instance, deployment, principal, credential owner, connection, Calendar account, meeting occurrence and revision, transcript provider account and revision, both evidence hashes, transcript content hash, correlation hash, verification-request hash, server verification time, and monotonic sequence. There is deliberately no public mint in this layer. Raw correlation results, fabricated receipts, proxies, accessors, and cloned receipt-shaped objects cannot cross the Gmail boundary.

Goals artifacts are generated only after a closed canonical local daily, Monday-to-Monday weekly, or calendar-quarter period. Directional status requires evidence observed inside that period. Earlier evidence must be explicitly typed as a baseline and cannot establish the current status by itself. All structured source and generated content stays outside presentation sinks and rejects Unicode default-ignorable, format-control, and bidirectional-control characters.

Gmail draft proposal creation remains unavailable until the trusted broker exists. A future implementation must derive recipients and evidence only from the verified receipt, require draft creation at or after transcript finality, analysis generation, broker verification, and the canonical current workflow time, and apply a bounded maximum delay. The canonical broker operations are `google.gmail.drafts.create` for automatic owner-mailbox drafts and `google.gmail.drafts.send` only after an exact one-use approval. Slack delivery, QM delivery, provider writes, and proposal publication remain outside this implementation until their separately reviewed executors are activated.

Chief-of-Staff scheduler and durable-port names are lane-private contracts, not the shared public vocabulary. Cross-lane composition uses the public integration adapter to produce canonical `PrincipalBinding`, `EvidenceBundle`, `WorkflowArtifact`, `EvalRelease`, `OutboxEvent`, and `PublicationEnvelope` values. Historical organization, deployment, principal, credential-owner, and audience aliases are accepted only by the private migration-ingress map; they do not become alternate public identities and are never emitted.
