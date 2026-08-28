# Mercury schedule authority handoff

## Decision

The candidate-to-proposal adapter must not be implemented against the current contracts.

QM does not issue a cryptographic schedule-fire receipt. Its durable cron record and fire log contain a fire key, thread reference, scheduled time, fired time, status, and optional session identifier, but no signature, signer identity, deployment-profile binding, schedule-definition digest, or run identifier. The scheduler also discards `TurnResult.runId`, and a synchronous turn result does not reliably expose it.

The deployment-profile v1 schema has no schedule-fire trust root. Its Ed25519 keys are judge-specific evaluation roots and cannot be reused as QM scheduler authority. A caller-supplied verifier or public key would let that caller mint its own authority. The route-scoped shadow-ingress HMAC is transport authentication, is not an immutable profile trust root, and does not attest cron state or durable run lineage.

Adding only a catalog entry or accepting a self-hashed, caller-labelled receipt would make the adapter look authoritative without establishing authority. The safe next change therefore requires an upstream QM signer and a deployment-profile version change.

## Required upstream QM contract

QM must produce a versioned `QmScheduleFireReceipt` from a signer whose public key is pinned in the consuming deployment profile. The private key must remain outside this repository and outside the Risely canary process. The signing key must be distinct from source-auth HMAC secrets, evaluation judge keys, and provider-effect proof keys.

The receipt must have exactly these fields:

```text
contractType = "qm-schedule-fire-receipt"
contractVersion = 1
digestRevision = "QmScheduleFireReceipt.sha256.v1"
signatureDomain = "qm.schedule-fire.v1"
authorityRef
issuerRef
keyId
algorithm = "Ed25519"
profileRef
profileSha256
scheduleRef
qmCronId
scheduleDefinitionSha256
cronRevisionSha256
fireMode = "scheduled"
fireKey
scheduledAt
firedAt
issuedAt
expiresAt
localOccurrence = { localDate, localTime, timeZone, utcOffset }
runId
sessionId
threadRef
runRequestSha256
receiptSha256
signature
```

All identifiers, timestamps, digests, nested keys, and the signature encoding must use strict bounded canonical forms. Unknown, missing, accessor-backed, proxy-backed, symbol, non-enumerable, inherited, or duplicate-semantic fields must be rejected before any application callback runs.

`receiptSha256` is SHA-256 over canonical JSON of every field except `receiptSha256` and `signature`. The Ed25519 signature is over the UTF-8 bytes of:

```text
qm.schedule-fire.v1\n<receiptSha256>
```

`fireKey` must equal QM's durable idempotency key for the exact calendar slot. `runId` must identify the durable run enqueued under that key. `runRequestSha256` must cover the canonical persisted run request, not rendered log text. `sessionId` and `threadRef` must equal the persisted run lineage. Manual `runNow` calls, interval schedules, webhook wakes, message-only deliveries, skipped fires, and fires without a durable run must not receive this receipt type.

QM must persist the claimed slot, run, receipt, and receipt outbox record atomically in its production Postgres authority. A worker must not be able to consume a provider-capable scheduled run unless that transaction committed. Duplicate delivery of the same slot must return the byte-identical receipt and the same run lineage. Conflicting reuse of a fire key must fail closed.

The transport that delivers the receipt is intentionally not specified here. No network route, secret name, or adapter port should be invented until the upstream contract and its durability boundary are reviewed.

## Schedule definition and disable semantics

The schedule definition hashed as `scheduleDefinitionSha256` must have exactly these fields:

```text
scheduleRef
cadence = daily | weekly | monthly
timeZone
localTime
weeklyDay
monthlyDay
activeFrom
activeUntil
```

`activeFrom` and `activeUntil` are inclusive local calendar dates in `timeZone`. Monthly days remain limited to 1 through 28. The definition hash uses canonical JSON and is independent of a deployment-profile digest so that pinning it in the profile does not create a hash cycle.

QM must calculate each slot with a calendar-aware scheduler. Before claiming a slot it must derive the local occurrence and verify all of the following against the stored immutable schedule revision:

- the local date is not before `activeFrom` and not after `activeUntil`;
- the local clock minute and daily, weekly, or monthly selector match;
- the local minute maps to exactly one UTC instant;
- the stored cron is enabled and not archived;
- the claimed revision and schedule-definition digest still match.

A nonexistent spring-forward minute produces no fire. A repeated fall-back minute is ineligible at both UTC instants rather than choosing one. This matches the current Mercury candidate compiler and prevents two invoice identities for one local occurrence.

Before QM would claim the first otherwise-matching slot whose local date is after `activeUntil`, it must atomically change the cron to disabled with reason `active_until_elapsed`. The transition must retain the last eligible scheduled instant, the first rejected scheduled instant, the prior and resulting cron revisions, and the schedule-definition digest. It must be durable and auditable. QM must never issue a schedule-fire receipt after this transition boundary. Re-enabling or changing the window creates a new schedule definition and revision; old receipts cannot authorize the new revision.

## Deployment-profile v2 requirement

The profile schema needs an exact `scheduleFirePolicy` field. A production value cannot be added until QM supplies the real public key and immutable cron identifier. Its shape is:

```text
policyRef
receiptContractVersion = 1
signatureDomain = "qm.schedule-fire.v1"
authorityRef
issuerRef
keyId
publicKey = { kty = "OKP", crv = "Ed25519", x }
maximumFireDelayMs
maximumReceiptLifetimeMs
allowedSchedules = [
  {
    scheduleRef
    qmCronId
    scheduleDefinitionSha256
    programRef
    provider = "mercury"
    providerOwnerRef
    environment = sandbox | production
  }
]
```

The public key, key ID, issuer, authority, cron ID, schedule definition, provider owner, and environment are profile-hashed data. Key rotation, cron replacement, schedule revision, provider-environment promotion, or authority replacement requires a new profile version and digest. Synthetic profiles must accept an explicitly supplied test public key and distinct schedule mapping; they must not inherit or manufacture the production root.

The profile contract must continue to require `activationMode="shadow"`, `providerExecutionAllowed=false`, and `maximumProviderGrantLifetimeMs=0`. Adding schedule authority must not activate provider execution.

## Provider-effect catalog v2 requirement

The catalog must move to a new immutable policy reference and include:

```text
capability = "mercury.invoices.create"
capabilityVersion = 1
provider = "mercury"
operation = "mercury.invoices.create"
authorizationMode = "approval-once"
ownershipMode = "owner-mercury-organization"
targetClass = "exact-scheduled-invoice-candidate"
maximumAttempts = 1
reconciliationRequired = true
```

Approval-once is required for both delivery modes because creating an unsent invoice is still a provider mutation. `send_after_approval` additionally binds `SendNow`; `prepare_only` binds `DontSend`. A later policy may distinguish these only through another reviewed capability version.

The Mercury proposal validator must require exact target and payload shapes. At minimum, the effect identity must bind:

- profile reference and digest;
- provider owner, environment, and fixed API base URL;
- candidate, batch, billing-record, invoice-payload, and CLI-plan digests;
- customer reference and provider customer ID;
- destination-account reference and provider destination-account ID;
- deterministic invoice number, delivery mode, and `sendEmailOption`;
- schedule reference, QM cron ID, schedule-definition digest, cron revision, scheduled instant, run ID, and schedule-fire receipt digest;
- CLI repository commit, release tag, archive digest, extracted binary digest, and executable name.

The validator must recompute the candidate and CLI bindings rather than accept duplicated caller assertions. No caller-selected host, executable, arguments, inherited process environment, credential reference, retry count, or reconciliation method is allowed.

## Candidate-to-proposal adapter

Only after the upstream receipt and profile v2 exist may `createMercuryInvoicingProgram` expose a branded adapter. The adapter takes a program-built batch, candidate reference, raw schedule-fire receipt, and proposal timestamps. It performs these checks in order:

1. Snapshot all inputs as canonical plain JSON without invoking accessors or proxy traps.
2. Validate the receipt's exact schema, self-hash, signature domain, Ed25519 signature, and pinned profile trust root.
3. Match profile, schedule mapping, provider owner, environment, schedule definition, cron revision, calendar occurrence, and fixed Mercury host.
4. Match the receipt's scheduled instant to `batch.occurrenceAt` and its `runId` to the proposal run.
5. Require `createdAt` to be no earlier than `issuedAt` and no later than `expiresAt`, and require proposal expiry not to exceed the receipt expiry or the profile approval lifetime.
6. Build the exact action proposal with `actor.surface="schedule"`, `capability="mercury.invoices.create"`, `provider="mercury"`, `subjectRef=candidateRef`, and deterministic identifiers derived from the receipt and candidate digests.
7. Pass the result through the profile-bound provider-effect policy suite.

The same receipt and candidate must produce the same proposal ID, semantic fingerprint, effect key, and proposal hash. Another candidate in the same batch, another fire, another cron revision, another environment, or another profile must produce a different effect identity. Durable attempt reservation remains the final replay barrier; the adapter does not reserve or execute anything.

The returned object must state all of the following and expose no invocation function:

```text
policyCatalogIntegrated = true
scheduleAuthorityVerified = true
executionAvailable = false
providerInvocationAllowed = false
credentialTransportAvailable = false
adapterAvailable = false
```

`createProviderEffectExecutionAuthority` must continue to throw. No Mercury binary, API credential, process spawn, provider request, reconciliation request, database write, or AWS call belongs in this change.

## Acceptance matrix

The implementing change must include focused and full layer tests covering:

- valid daily, weekly, and monthly synthetic receipts with explicitly generated test-only Ed25519 keys;
- deterministic replay and separation by candidate, fire, cron revision, environment, provider owner, and profile;
- valid inclusive `activeFrom` and `activeUntil` occurrences;
- rejection before `activeFrom`, after `activeUntil`, after receipt expiry, and when proposal expiry exceeds receipt authority;
- rejection of both UTC instants in a repeated fall-back local minute and absence of a spring-forward-gap fire;
- rejection of manual fires, interval fires, missing durable run IDs, mismatched run request hashes, and mismatched session or thread lineage;
- rejection of foreign keys, issuers, authorities, profiles, cron IDs, schedule definitions, billing records, candidates, owners, environments, hosts, CLI commits, archives, binaries, and plans;
- rejection after tampering every signed or effect-bound field, including a recomputed self-hash without a valid signature;
- accessor, proxy, symbol, inherited-property, non-enumerable-property, duplicate-semantic, oversized, and malformed-signature adversarial cases with zero getter or proxy-trap calls;
- catalog/profile digest mismatch and cross-profile branded-object rejection;
- continuing mechanical failure of provider-effect execution construction and absence of provider, credential, binary, database, or network calls.

An independent fresh-context security review must approve the upstream signer, atomic durability boundary, profile schema, policy catalog, adapter, and negative tests before merge.
