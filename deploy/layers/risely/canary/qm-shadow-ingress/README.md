# Existing QM private shadow ingress

This slice reuses QM's existing Slack and authenticated web-chat ownership. It never opens another Slack connection and never exposes a public callback. The staged generic QM turn-observer hook and durable outbox send a normalized, signed digest to `POST /internal/v1/qm-shadow/observations` on the existing canary ingress after deployment-owned enrichment is wired.

The immutable `observedAt` remains bound into the run policy digest for audit. The durable run's `startedAt` is the canary's current acceptance time, so a delayed first delivery after a QM outage still passes the same-client database freshness check. Redelivery may use a fresh signed transport nonce, but the deterministic event/run identity and observation digest do not change.

The contract accepts only the exact selected deployment profile and either the profile's private Slack direct-message audience or private QM principal audience. Raw prompts, replies, files, tokens, and provider payloads are rejected by shape. Each accepted observation becomes a deterministic provider-free workflow run in the existing `qm` database's `risely_agent_runtime` schema. The signed nonce is durably consumed in `ingress_requests`; the deterministic run identity and stored content hash make a later QM redelivery idempotent and turn divergent reuse of an event identifier into a conflict.

`createQmShadowIngress` is profile-scoped rather than CEO-scoped. A future role receives a separate immutable deployment profile and runtime scope, which changes its durable run and session identities even when raw QM event identifiers coincide.

Provider invocation is structurally absent and the policy fixes the effect budget at zero. Production activation remains blocked on the generic upstream QM observer hook, verified QM-to-profile identity resolution, provisioned ingress signing material, live same-QM schema attestation, and private Slack and browser acceptance. The current service and Terraform deployment remain inert.

The production server does not register the observer unless `CANARY_QM_SHADOW_INGRESS_ENABLED=1` is explicitly deployed. The current task definition does not set that value.
