# Founder Notion read authority

The Command Center Notion connector has two independent authorization layers. Its encrypted MCP credential authenticates QM to Command Center. A fresh RS256 JWT authorizes one exact read requested by the configured founder in the configured personal Slack DM. Neither the machine credential nor a model-produced tool argument is end-user authority.

This path is default-off. The complete configuration may be staged while disabled, but every value is validated together and the signer, JWKS route, and hidden injection remain absent until `QM_NOTION_READ_AUTHORITY_ENABLED=true`.

```text
QM_NOTION_READ_AUTHORITY_ENABLED=false
QM_NOTION_READ_AUTHORITY_ISSUER=https://<QM PUBLIC_API_URL origin>/
QM_NOTION_READ_AUTHORITY_AUDIENCE=https://<Command Center authority audience>/
QM_NOTION_READ_AUTHORITY_KEY_ID=<exact active RSA key id>
QM_NOTION_READ_AUTHORITY_ORGANIZATION_ID=<exact Command Center organization id>
QM_NOTION_READ_AUTHORITY_ACTOR_PRINCIPAL_ID=<exact QM founder principal id>
QM_NOTION_READ_AUTHORITY_SLACK_TEAM_ID=<exact T... workspace id>
QM_NOTION_READ_AUTHORITY_SLACK_USER_ID=<exact U... founder id>
QM_NOTION_READ_AUTHORITY_SLACK_DM_CHANNEL_ID=<exact D... personal-DM channel id>
QM_NOTION_READ_AUTHORITY_RS256_PRIVATE_KEY=<base64 DER/PKCS8 2048-4096 bit RSA private key>
QM_NOTION_READ_AUTHORITY_TTL_SECONDS=30
PUBLIC_API_URL=https://<QM public API origin>
```

The issuer must be the canonical HTTPS root URL for the `PUBLIC_API_URL` origin. QM publishes only the matching public RSA key at `GET /.well-known/jwks.json`. The response contains exactly `kty`, `n`, `e`, `kid`, `alg=RS256`, and `use=sig`; the private key never enters an API response, audit event, MCP schema, or log. `GET /.well-known/notion-read-authority-readiness.json` exposes only the ready status, algorithm, authority contract name, and two tool names. It omits the issuer, audience, key ID, identity profile, and every callable signer method. Both routes return 404 while the signer is disabled.

Command Center must use the identical issuer, audience, organization, principal, Slack team, Slack user, and DM channel. Its JWKS URL is the issuer origin plus `/.well-known/jwks.json`. Keep `NOTION_AGENT_READ_ENABLED=false` there until both sides pass readiness and acceptance.

QM must register the dedicated Command Center `/api/mcp/notion/mcp` route. The server URL and OAuth audience are the same canonical HTTPS endpoint. The record must use client credentials, `tokenAudienceParameter=audience`, the sole scope `notion:read`, `readOnly=true`, and exactly the two tools below. The general Command Center, Brain, and analytics endpoints fail this contract before discovery.

```json
[
  {
    "name": "notion_search",
    "label": "Search Notion",
    "status": "Searching Notion",
    "readOnly": true,
    "requestAuthority": "qm.rs256.notion-read-founder-dm.v1",
    "inputSchema": {}
  },
  {
    "name": "notion_read_page",
    "label": "Read Notion page",
    "status": "Reading Notion page",
    "readOnly": true,
    "requestAuthority": "qm.rs256.notion-read-founder-dm.v1",
    "inputSchema": {}
  }
]
```

Replace each `inputSchema` placeholder with the complete schema in `test/fixtures/command-center-notion-m2m-tools-list.json`. That content-addressed fixture is pinned by contract version and SHA-256 in the adjacent `.source.json` file. Both schemas require `workflow` and `authorityEnvelope`, are closed with `additionalProperties=false`, and permit only the reviewed workflow enum. Search additionally requires `query` with 1–1000 characters; page read requires `pageId` with 1–128 characters. Discovery must advertise `readOnlyHint=true` and `destructiveHint=false`. QM refuses schema, safety-annotation, endpoint, OAuth, enablement, credential, or allowed-tool drift before dispatch. The Notion authority contract cannot be assigned to another tool name, a non-read-only tool, or a native renderer. There is no Notion create, append, update, delete, archive, share, permission, schema, property, block mutation, or write authority in this release.

QM removes `authorityEnvelope` from the schema shown to the model and validates model arguments against that reduced closed schema. A caller-supplied envelope or extra Slack context therefore fails before any `tools/call`. After MCP authentication, public DNS pinning, fresh discovery, and exact contract revalidation, QM derives the principal, team, user, DM channel, message timestamp, thread timestamp, and delivery target from trusted Slack turn state. It then mints a JWT with `typ=job-authority+jwt`, `alg=RS256`, the configured `kid`, `scope=notion:read`, a 10-60 second lifetime, a cryptographically random `jti` and request ID, and the SHA-256 of Command Center's canonical `notion-read-request/v1` body. Only then does QM inject the envelope into the outbound MCP arguments.

Every retry mints a new envelope and a new `jti`. QM never retries or reuses an authority token internally. Command Center atomically consumes the `jti` in its durable Redis replay fence, so reuse is denied across requests, process restarts, and QM restarts. QM rejects an MCP response that reflects the bearer credential or authority token and records only the existing tool/server outcome metadata, never arguments, tokens, query text, page IDs, or returned Notion content.

Before activation:

1. Keep both QM and Command Center flags false while provisioning the dedicated read-only Notion connection, dedicated `/api/mcp/notion/mcp` Auth0 client credential, RSA key, and exact MCP allowlist.
2. Start QM with the complete configuration and `QM_NOTION_READ_AUTHORITY_ENABLED=true`.
3. Fetch the QM JWKS endpoint without credentials. Confirm one active public key, the exact `kid`, `alg=RS256`, `use=sig`, and no private fields. Fetch the redacted readiness endpoint and confirm it contains no issuer, audience, key ID, identity, or callable signer field.
4. Run the Command Center Notion read doctor. It must accept that JWKS, its durable Redis replay probe, the exact owner/profile configuration, and the dedicated Notion bot/workspace/root attestation.
5. Enable Command Center and restart it.
6. From the configured founder DM, run one search and one page read. Confirm cited read output and no Notion write tool.
7. Retry after a forced transient failure and confirm the two envelopes have different `jti` values.
8. Replay an accepted envelope before and after restarts and confirm Command Center denies it before provider contact.
9. Try another user, team, channel, DM, tool, message, thread, and body and confirm each is denied without Notion content.

Rollback is fail-closed: set the QM flag false and restart QM, then set the Command Center flag false and restart Command Center. The JWKS endpoint becomes absent on QM, the hidden signer is not wired, and the Notion read tools cannot dispatch. No Notion write or database rollback exists in this release.
