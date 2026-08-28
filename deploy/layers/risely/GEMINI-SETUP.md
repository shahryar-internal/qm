# Gemini setup

The pilot uses Google Gemini through QM's encrypted OpenAI-compatible custom-provider registry. A private, stateless compatibility gateway normalizes QM's OpenAI requests and preserves Gemini tool-call continuity. It can reach only Google's fixed Gemini endpoint, has no public ingress, stores no key, and emits no request logs.

## Development credential

- Google Cloud project: `internal-agents-test-485307`
- API key display name: `risely-qm-dev-v2`
- API restriction: `generativelanguage.googleapis.com`
- Secret Manager secret: `risely-qm-gemini-api-key`
- Primary model: `gemini-3.7-flash`
- Rollback model: `gemini-3.5-flash`

The API key value is not stored in Git or this deployment directory.
The committed Gemini 3.7 cost metadata uses introductory pricing through
December 31, 2026 and must be reviewed before January 1, 2027.

## Before deploying

The Gemini key is deliberately not a deployment `.env` secret. QM must be
started first, then an authenticated Risely administrator registers the custom
provider through Admin. Do not run `qm check --live` until that registration is
complete because its real agent canary requires a working base model.

## Bootstrap order

1. Apply the isolated AWS infrastructure and run `npm exec qm -- up --yes`. Confirm the `gemini-compat` service is running before registering the provider. The core, Admin, and web surfaces may start without a provider because `modelProvider` is intentionally absent from `qm.config.jsonc`.
2. Sign in to the QM Admin surface with the configured Risely administrator.
3. Open **Model providers**, choose the OpenAI-compatible custom-provider
   option, and enter the non-secret fields from `gemini-provider.json`.
4. Retrieve `risely-qm-gemini-api-key` directly from Google Secret Manager and
   paste it into Admin's write-only key field. Do not print it, place it in a
   shell history, copy it into chat, or save it in this repository.
5. Save and validate the provider. QM stores the key encrypted in its own
   Postgres credential envelope.
6. Set the base model and web UI model list to `gemini-3.7-flash` in Admin.
7. Run `npm run public-chat:check` to send and verify one real message through
   the authenticated public web surface.
8. Run `npm exec qm -- check --live`, `npm exec qm -- conformance`, and the
   Slack acceptance checks in `SLACK-PILOT.md`.

There is no unauthenticated local registration helper. Custom-provider writes
must pass the normal QM Admin authentication and authorization boundary.

## Verify Google before deployment

Load the secret into the process environment without printing it, then run:

```bash
GEMINI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai npm run gemini:check
```

The command proves direct text generation and forced tool calling, and returns only the provider and model status. The deployed live check separately proves the private compatibility path and a complete model turn.
