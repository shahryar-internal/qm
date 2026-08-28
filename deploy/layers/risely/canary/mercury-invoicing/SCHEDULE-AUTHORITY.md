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
cronStateRevision
runRequestTemplateSha256
scheduleState = "active"
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

The upstream boundary accepts at most 16 KiB of UTF-8 JSON bytes, not an already-parsed object. It must reject a byte-order mark, invalid UTF-8, duplicate keys at any depth, lone surrogates, non-integer numbers, and trailing data before constructing a value. Identifiers use `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`; digests are 64 lowercase hexadecimal characters; timestamps use exactly `YYYY-MM-DDTHH:mm:ss.sssZ`; `utcOffset` uses exactly `[+-](?:0\d|1[0-4]):[0-5]\d`; the Ed25519 JWK `x` is exactly 43 unpadded base64url characters; and the 64-byte signature is exactly 86 unpadded base64url characters. Unknown, missing, accessor-backed, proxy-backed, symbol, non-enumerable, inherited, or duplicate-semantic fields must be rejected before any application callback runs.

Canonical JSON means RFC 8785 JSON Canonicalization Scheme bytes. `receiptSha256` is SHA-256 over canonical bytes of every field except `receiptSha256` and `signature`. The Ed25519 signature is over the UTF-8 bytes of:

```text
qm.schedule-fire.v1\n<receiptSha256>
```

`fireKey` must equal QM's durable idempotency key for the exact calendar slot. `runId` must identify the durable run enqueued under that key. `runRequestSha256` must cover the RFC 8785 canonical persisted run request, not rendered log text. `runRequestTemplateSha256` must cover an exact `QmScheduleRunRequestTemplate.v1` projection that retains every request field and value except that `conversation.threadRef` and `idempotencyKey` are replaced by fixed domain markers. No other field may be removed or normalized. `sessionId` and `threadRef` must equal the persisted run lineage. Manual `runNow` calls, interval schedules, webhook wakes, message-only deliveries, skipped fires, and fires without a durable run must not receive this receipt type.

QM must preallocate the fresh durable session identity before enqueue and persist the claimed slot, session, run, receipt, and receipt outbox record atomically in its production Postgres authority. The run must reference that preallocated session, and the worker must use rather than replace it. A worker must not be able to consume a provider-capable scheduled run unless that transaction committed. Duplicate delivery of the same slot must return the byte-identical receipt and the same run and session lineage. Conflicting reuse of a fire key must fail closed.

The receipt is not bearer authority. The consuming server must select the canonical receipt bytes from the committed durable row using its authenticated ambient run identity, read the current durable run, session, attempt, and lease records, and obtain current time from a deployment-controlled trusted clock. None of the receipt, run identity, run record, session, attempt, lease token, or time inputs may come from an action-proposal request body. Verification must bind the committed receipt to the current run's ID, preallocated session, thread, canonical request digest, request-template digest, and fire key. It must also prove that the current handler owns the server-held lease token, the run status is `running`, the attempt and lease generation equal the durable record, and the lease has not expired at trusted current time. Only then may it mint a non-serializable, invocation-scoped authority carrying the attempt, lease-generation digest, and lease expiry but never the raw token. That authority must be branded to the deployment runtime scope, current server invocation, and current lease; it must be invalidated when the lease is lost and unusable by another request handler, retry, or reassigned worker even when the underlying signed receipt is copied.

The transport and invocation-context mechanism are intentionally not specified here. No network route, secret name, ambient-context implementation, or adapter port should be invented until the upstream contract, durable lookup, and invocation boundary are reviewed.

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

`activeFrom` and `activeUntil` are inclusive local calendar dates in `timeZone`. A daily schedule requires `weeklyDay=null` and `monthlyDay=null`; a weekly schedule requires a valid `weeklyDay` and `monthlyDay=null`; a monthly schedule requires `weeklyDay=null` and `monthlyDay` from 1 through 28. The definition hash uses RFC 8785 canonical JSON and is independent of a deployment-profile digest so that pinning it in the profile does not create a hash cycle.

`cronRevisionSha256` is SHA-256 over the RFC 8785 canonical bytes of this exact immutable projection:

```text
contractType = "qm-cron-configuration-revision"
contractVersion = 1
digestRevision = "QmCronConfigurationRevision.sha256.v1"
qmCronId
configurationGeneration
owner
ownerScopeId
createdBy
titleSha256
actionSha256
messageSha256
scheduleDefinitionSha256
runAs
destinationSha256
membersSha256
unattendedGrantsSha256
recipientConsentPolicySha256
runRequestTemplateSha256
```

`configurationGeneration` is a positive safe integer persisted with the cron and incremented atomically on every configuration edit or re-enable. Nullable configuration values hash as canonical `null`; arrays hash in their stored canonical order. Dynamic claim, last-fired, next-fire, and enabled-state fields are tracked by a separate monotonic state revision and are not in this projection. The generation therefore makes every configuration edit or re-enable produce a new `cronRevisionSha256`, even when the resulting values equal a prior revision.

QM must calculate each slot with a calendar-aware scheduler. Before claiming a slot it must derive the local occurrence and verify all of the following against the stored immutable schedule revision:

- the local date is not before `activeFrom` and not after `activeUntil`;
- the local clock minute and daily, weekly, or monthly selector match;
- the local minute maps to exactly one UTC instant;
- the stored cron is enabled and not archived;
- the claimed revision and schedule-definition digest still match.

A nonexistent spring-forward minute produces no fire. A repeated fall-back minute is ineligible at both UTC instants rather than choosing one. This matches the current Mercury candidate compiler and prevents two invoice identities for one local occurrence.

Before QM would claim the first otherwise-matching slot whose local date is after `activeUntil`, it must atomically change the cron to disabled with reason `active_until_elapsed`. The durable `QmScheduleDisableReceipt` has exactly these fields:

```text
contractType = "qm-schedule-disable-receipt"
contractVersion = 1
digestRevision = "QmScheduleDisableReceipt.sha256.v1"
signatureDomain = "qm.schedule-disable.v1"
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
reason = "active_until_elapsed"
lastEligibleScheduledAt
firstRejectedScheduledAt
disabledAt
priorStateRevision
resultingStateRevision
receiptSha256
signature
```

`lastEligibleScheduledAt` is a canonical timestamp or null. `firstRejectedScheduledAt <= disabledAt`, `lastEligibleScheduledAt < firstRejectedScheduledAt` when the former exists, and `resultingStateRevision = priorStateRevision + 1`. The receipt uses the same byte, shape, JWK, timestamp, digest, strict-parser, and 16 KiB rules as the fire receipt. Its `receiptSha256` excludes `receiptSha256` and `signature`; its signature is over `qm.schedule-disable.v1\n<receiptSha256>`. The disabled state update, receipt, and audit outbox record commit atomically. QM must never issue a schedule-fire receipt after this transition boundary. Re-enabling or changing the window creates a new immutable cron revision and deployment-profile mapping; old receipts cannot authorize the new revision.

## Deployment-profile v2 requirement

The profile schema needs an exact `scheduleFirePolicy` field. A production value cannot be added until QM supplies the real public key and immutable cron identifier. Its shape is:

```text
policyRef
receiptContractVersion = 1
signatureDomain = "qm.schedule-fire.v1"
disableReceiptContractVersion = 1
disableSignatureDomain = "qm.schedule-disable.v1"
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
    cronRevisionSha256
    runRequestTemplateSha256
    programRef
    provider = "mercury"
    providerOwnerRef
    environment = sandbox | production
  }
]
```

`allowedSchedules` is codepoint-sorted by `scheduleRef` and then `environment`; both the pair and every `qmCronId` must be unique. The public key, key ID, issuer, authority, cron ID, schedule definition, immutable cron revision, run-request template, provider owner, and environment are profile-hashed data. Key rotation, cron replacement, schedule revision, run-request change, provider-environment promotion, re-enable, or authority replacement requires a new profile version and digest. Synthetic profiles must accept an explicitly supplied test public key and distinct schedule mapping; they must not inherit or manufacture the production root.

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
providerContract = {
  hosts = {
    sandbox = "https://api-sandbox.mercury.com/api/v1/"
    production = "https://api.mercury.com/api/v1/"
  }
  cli = {
    repository = "https://github.com/MercuryTechnologies/mercury-cli"
    commit = "25cc254e78eddfbbd4f13cfc90a0beca930a2c0e"
    version = "0.11.8"
    releaseTag = "v0.11.8"
    checksumsAssetSha256 = "6ca71e169384a60c2838d562ab0fe4d797e12bec9fe50f2340e541caf7a16991"
    archiveName = "mercury_0.11.8_linux_amd64.tar.gz"
    archiveSha256 = "f39c3426edaf2750c04366d87c43c846fd50dd258056633fb2dbe633dc336a9c"
    binarySha256 = "3bb3a39a3676376998ea3a48034b7a636c5c31d7b7d08dca4c26cebd64520b8b"
    binaryFormat = "elf_x86_64_static_stripped"
    executable = "mercury"
  }
  planRevision = "MercuryCliCreatePlan.v1"
  plans = {
    sandbox = {
      apiBaseUrl = "https://api-sandbox.mercury.com/api/v1/"
      argv = ["--base-url", "https://api-sandbox.mercury.com/api/v1/", "--format", "json", "--format-error", "json", "invoices", "create"]
    }
    production = {
      apiBaseUrl = "https://api.mercury.com/api/v1/"
      argv = ["--base-url", "https://api.mercury.com/api/v1/", "--format", "json", "--format-error", "json", "invoices", "create"]
    }
  }
  stdinEncoding = "application/json"
  credentialTransport = "MERCURY_API_KEY_secret_environment_only"
  fixedEnvironment = { MERCURY_NO_UPDATE_CHECK = "1" }
  inheritedVariablesAllowed = false
  updateCheckDisabled = true
  debugAllowed = false
  oneProcessPerInvoice = true
}
```

Approval-once is required for both delivery modes because creating an unsent invoice is still a provider mutation. `send_after_approval` additionally binds `SendNow`; `prepare_only` binds `DontSend`. A later policy may distinguish these only through another reviewed capability version.

The Mercury proposal validator must require exact target and payload shapes. At minimum, the effect identity must bind:

- profile reference and digest;
- provider owner, environment, and fixed API base URL;
- candidate, batch, billing-record, invoice-payload, and CLI-plan digests;
- customer reference and provider customer ID;
- destination-account reference and provider destination-account ID;
- deterministic invoice number, delivery mode, and `sendEmailOption`;
- schedule reference, QM cron ID, schedule-definition digest, immutable cron revision, active state revision, scheduled instant, run ID, and schedule-fire receipt digest;
- CLI repository commit, release tag, archive digest, extracted binary digest, and executable name.

The entire `providerContract` projection is included in the catalog SHA pinned by the profile. The validator selects one exact catalog plan by the profile-pinned environment and recomputes the candidate and CLI bindings from that catalog projection rather than accepting duplicated caller assertions or mutable program constants. No caller-selected host, executable, arguments, inherited process environment, credential reference, retry count, or reconciliation method is allowed.

## Candidate-to-proposal adapter

Only after the upstream receipt, durable current-run lookup, trusted clock, and profile v2 exist may the server expose provider-free candidate-to-proposal compilation. The compiler takes only a program-built batch, candidate reference, and non-serializable current-invocation schedule authority. It does not accept receipt bytes, run identifiers, run records, or timestamps from the caller. It performs these checks in order:

1. Snapshot caller inputs as canonical plain JSON without invoking accessors or proxy traps.
2. Revalidate the current-invocation authority's runtime and invocation brands.
3. Match profile, schedule mapping, provider owner, environment, schedule definition, immutable cron revision, run-request template, calendar occurrence, and catalog-pinned Mercury host and CLI plan.
4. Match the committed receipt's scheduled instant to `batch.occurrenceAt` and its run, preallocated session, thread, request, request template, and fire key to the trusted current durable run.
5. Recheck that the current handler owns the durable running attempt and unexpired lease. Bind the attempt, lease-generation digest, and observed lease expiry only into `capturedState`, authority preconditions, proposal ID, and proposal hash. They must not enter target, payload, artifact references, semantic fingerprint, effect key, or prospective effect key.
6. Using trusted current time, require `scheduledAt <= firedAt <= issuedAt <= now < expiresAt`, `issuedAt-scheduledAt <= maximumFireDelayMs`, and `expiresAt-issuedAt <= maximumReceiptLifetimeMs`.
7. Derive proposal `createdAt` from receipt `issuedAt` and proposal `expiresAt` from the earliest of receipt `expiresAt`, lease expiry, and the profile approval-lifetime boundary. Caller time is never used.
8. Build the exact action proposal with `actor.surface="schedule"`, `capability="mercury.invoices.create"`, `provider="mercury"`, and `subjectRef=candidateRef`. Derive its semantic fingerprint and effect key only from the stable receipt and candidate effect projection. Derive its proposal ID and proposal hash from that stable projection plus the exact current attempt and lease snapshot.
9. Pass the result through the profile-bound provider-effect policy suite.

The same receipt and candidate must produce the same semantic fingerprint, effect key, and prospective effect key across retries, worker reassignment, lease renewal, and lease generations. Another candidate in the same batch, another fire, another cron revision, another environment, or another profile must produce a different effect identity. The same receipt, candidate, attempt, lease generation, and observed expiry snapshot must produce the same proposal ID and proposal hash; a changed attempt or lease snapshot must change only the proposal authority identity. Durable attempt reservation is keyed by the stable prospective effect key and must reject a later proposal for the same effect even when its proposal ID and hash differ. The compiler does not reserve or execute anything.

The returned object must state all of the following and expose no invocation function:

```text
policyCatalogIntegrated = true
scheduleAuthorityVerified = true
executionAvailable = false
providerInvocationAllowed = false
credentialTransportAvailable = false
candidateToProposalCompilerAvailable = true
providerInvocationAdapterAvailable = false
```

`createProviderEffectExecutionAuthority` must continue to throw. No Mercury binary, API credential, process spawn, provider request, reconciliation request, database write, or AWS call belongs in this change.

## Acceptance matrix

The implementing change must include focused and full layer tests covering:

- valid daily, weekly, and monthly synthetic receipts with explicitly generated test-only Ed25519 keys;
- stable semantic and prospective effect identity across retries, worker reassignment, heartbeat expiry changes, and lease generations, with proposal ID and hash separation for each authority snapshot;
- durable rejection of a second proposal carrying the same stable prospective effect key after an earlier attempt reserved or executed it;
- effect-identity separation by candidate, fire, cron revision, environment, provider owner, and profile;
- valid inclusive `activeFrom` and `activeUntil` occurrences;
- rejection before `activeFrom`, after `activeUntil`, after receipt expiry, and when proposal expiry exceeds receipt authority;
- rejection under a caller-supplied, stale, reversed, future, over-delay, over-lifetime, or substituted clock and proof that proposal timestamps are derived rather than accepted;
- rejection of both UTC instants in a repeated fall-back local minute and absence of a spring-forward-gap fire;
- rejection of manual fires, interval fires, missing durable run IDs, uncommitted or replaced sessions, mismatched run request or template hashes, mismatched session or thread lineage, copied receipts in another invocation, serialized or cross-handler authority brands, pending or terminal runs, stale or lost leases, wrong lease tokens, expired leases, reassigned workers, and retry-attempt substitution;
- rejection of foreign keys, issuers, authorities, profiles, cron IDs, schedule definitions, billing records, candidates, owners, environments, hosts, CLI commits, archives, binaries, and plans;
- rejection after tampering every signed or effect-bound field, including a recomputed self-hash without a valid signature;
- accessor, proxy, symbol, inherited-property, non-enumerable-property, duplicate-semantic, oversized, and malformed-signature adversarial cases with zero getter or proxy-trap calls;
- raw-byte rejection for invalid UTF-8, byte-order marks, duplicate JSON keys at every depth, lone surrogates, noncanonical timestamps, padded base64url, and bytes that do not round-trip to the exact canonical form;
- transaction failure injection before and after each slot, session, run, receipt, and outbox write; concurrent duplicate claims; proof that no worker consumes an uncommitted session or run; byte-identical redelivery; and conflicting fire-key rejection;
- the real durable `active_until_elapsed` state transition, disable-receipt self-hash and signature tampering, field and chronology substitutions, atomic signed audit record, concurrent transition attempts, same-values re-enable generation and revision change, and proof that no post-window receipt is issued;
- catalog/profile digest mismatch and cross-profile branded-object rejection;
- continuing mechanical failure of provider-effect execution construction and absence of provider, credential, binary, database, or network calls.

An independent fresh-context security review must approve the upstream signer, atomic durability boundary, profile schema, policy catalog, adapter, and negative tests before merge.
