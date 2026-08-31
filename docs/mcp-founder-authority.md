# Founder analytics MCP authority

The founder analytics connector has two independent authorization layers. Its
encrypted MCP credential authenticates this QM instance to Command Center. A
short-lived Ed25519 envelope authorizes one exact human request from the
founder's personal Slack DM. A machine credential alone is never treated as
end-user authority.

This path is default-off. Configure all of the following values or none of
them; a partial configuration fails startup:

```text
QM_MCP_AUTHORITY_ISSUER=qm:prod
QM_MCP_AUTHORITY_ORGANIZATION_ID=<exact Command Center organization id>
QM_MCP_AUTHORITY_PRINCIPAL_ID=<exact Command Center founder principal id>
QM_MCP_AUTHORITY_SLACK_TEAM_ID=<exact T... workspace id>
QM_MCP_AUTHORITY_SLACK_USER_ID=<exact U... founder id>
QM_MCP_AUTHORITY_SLACK_DM_CHANNEL_ID=<exact D... personal-DM channel id>
QM_MCP_AUTHORITY_ED25519_PRIVATE_KEY=<base64 DER/PKCS8 Ed25519 private key>
QM_MCP_AUTHORITY_TTL_SECONDS=30
```

Provision the matching public key in Command Center as base64 DER/SPKI. Keep
the private key only in QM's secret store. The configured principal is the
Command Center principal placed in the signed envelope; the configured Slack
user is independently checked against the trusted human actor on every turn.
The authority issuer and public key are matched exactly by Command Center.
This version has one unidentified signing key, so rotate it by disabling the
connector, replacing both key halves, and re-enabling after a signed smoke
test; do not create an implicit overlapping key ring.

The QM MCP server record must pin the only allowed remote tool with these
closed contract fields in addition to its exact reviewed input schema:

```json
{
  "name": "analytics_query",
  "label": "Analyze account",
  "status": "Analyzing account",
  "readOnly": true,
  "requestAuthority": "qm.ed25519.founder-dm.v1",
  "nativeRenderer": "qm.analytics.card.v1",
  "inputSchema": {}
}
```

Replace the placeholder schema with the exact schema discovered and reviewed
from the analytics MCP server. QM refuses drift between the stored schema and
the live tool contract.

For a normal human Slack DM turn, QM derives the team, user, `D...` channel,
message timestamp, thread timestamp, and visible tool arguments from trusted
runtime state. It signs a fresh `jti`, canonical body hash, issue time, and
expiry, then injects `X-Risely-QM-Authority` only on the upstream `tools/call`
request. It never forwards model- or caller-supplied authority. Requests from
web, group channels, other users, other workspaces, other DMs, or calls through
the context-free MCP method fail closed.

The analytics server returns a closed `qm.analytics.card.v1` object in MCP
structured content. QM validates every field and the exact signed authority
echo, rejects remote Block Kit or action payloads, constructs Block Kit
locally, and queues it only to the current Slack destination with a receipt-
derived idempotency key. The model sees only the bounded text result; it cannot
choose a card destination or author Slack blocks.

Activation still requires independent review, the paired Command Center
successor and database migrations, exact issuer/key/identity agreement, a
dedicated least-privilege Auth0 client, the reviewed MCP server record, and
live founder-DM acceptance tests. No configuration in this repository is
deployment evidence.
