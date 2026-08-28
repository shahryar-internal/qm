# QM deployment

This directory is one QM deployment: a config, a secret contract, and a
sandbox layer that customizes the agent without forking the core images. Commit
everything here except `.env`, which holds the secret values and is covered by
the scaffolded `.gitignore`.

## Where the documentation lives

- `package.json` pins the exact CLI version this directory is interpreted by,
  so every checkout resolves the same `qm`. `contract` in the config is only
  the coarse compatibility floor; this pin is the reproducible one. Upgrade it
  deliberately and re-run `qm check` afterwards.
- `qm.config.jsonc` describes what to run. Every field carries a comment
  explaining it, including the full list of services, so read the file itself
  before changing it. It is JSON with comments (the `tsconfig.json` dialect).
  That applies only to the config: `tool.json` files must stay strict JSON.
- `.env.example` is the secret catalog. It lists every secret the platform
  knows, what each one is for, what enables it, and the command that produces a
  value when one exists. The secrets the current config needs appear uncommented.
  `qm init` creates a gitignored `.env`, generates its local signing
  keys, and leaves provider credentials blank for you to fill in. Never write a
  secret value into any other file.
- `slack-app-manifest.yml` creates the optional qm bot app. Slack OIDC
  deployments also get `slack-sso-manifest.yml`. Run
  `npm exec qm -- slack render` after changing `publicUrl`, then
  `npm exec qm -- outputs` for creation links.

## Customizing the sandbox

`sandbox/` defines what the agent gets in its execution environment:

- A skill is `sandbox/skills/<id>/SKILL.md`: markdown with `name` and
  `description` frontmatter that teaches the agent a workflow and when to use it.
- A tool is `sandbox/tools/<id>/tool.json`: a descriptor whose minimal form is
  `{ "id": ..., "advertise": ..., "install": { "binary": ... } }`, with the
  executable next to it when the binary is not already in the base image.
- `sandbox/Dockerfile` is optional and only needed for system packages or
  runtimes.

The scaffold ships a working example, the `greet` skill and `example-tool`.
Copy its shape, then replace or delete it.

## The workflow

Run every command from this directory.

1. `npm exec qm -- check` validates the config and the sandbox layer and prints the
   secret names the config currently requires. It builds nothing, and when
   credential values are already present in `.env` it also verifies them
   against their providers, so run it after every edit.
2. `npm exec qm -- plan` reports what deployment would do
   without changing anything.
3. After the target prerequisites are complete, `npm exec qm -- up` brings the
   deployment up and prints the URLs. An AWS directory must first complete the
   edge and authenticated-portal steps in its AWS bootstrap section below.
   `--build-from <path to a QM checkout>` is reserved for contributors
   testing unreleased runtime code.
4. `npm exec qm -- status`, `npm exec qm -- logs [service]`, and
   `npm exec qm -- down` show
   what is running, tail logs, and stop the deployment.
5. `npm exec qm -- secrets push` uploads the `.env` values to the deploy target.
   The docker target reads `.env` directly and does not need it.

`npm exec qm -- help` lists everything else, including `sandbox build` and
`rollback`.

## Bootstrapping the AWS target

1. Replace the account and GitHub placeholders. The account must already have
   GitHub's IAM OIDC provider. Check it with
   `aws iam get-open-id-connect-provider --open-id-connect-provider-arn arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com`.
   If it is absent, an account administrator creates it once with
   `aws iam create-open-id-connect-provider --url https://token.actions.githubusercontent.com --client-id-list sts.amazonaws.com`.
2. Run `npm exec qm -- infra render`, review the result, then run
   `terraform -chdir=infra init && terraform -chdir=infra apply`. This creates
   inert ECS services, RDS, CloudFront, an ALB origin restricted to CloudFront,
   and the MicroVM roles. Set `publicUrl` to
   `https://<cloudfront_hostname>` and
   `env.core.AWS_PUBLIC_ORIGIN_URL` to `http://<alb_hostname>`.
3. Sign-in is handled by the built-in `auth` broker: set
   `env.auth.AUTH_ALLOWED_EMAIL_DOMAIN` (or leave it out and supply
   `AUTH_ALLOWED_EMAILS`), then run `npm exec qm -- setup` for the sender address
   and the Resend or SMTP credentials; the CLI generates the broker's keys and the
   portal's client credentials and wires `OIDC_*` itself. To use an external
   identity provider instead, drop `"auth"` from `services`, configure
   `env.portal` with the provider's OIDC endpoints and an `OIDC_ALLOWED_EMAILS`
   or `OIDC_ALLOWED_EMAIL_DOMAIN` tenant gate, and register
   `<publicUrl>/auth/callback` with the provider. Add optional services and their
   ECS/ECR entries now, then render and apply once more.
4. Run `npm run aws:image:build` to build the Lambda MicroVM guest image and
   record its immutable version and execution role in the config. This
   deployment-owned wrapper applies the reviewed aarch64 GitHub CLI fix to the
   pinned QM builder and always restores `node_modules` when it exits; do not
   bypass it with `npm exec qm -- infra build-image`.
5. Fill the gitignored `.env`, including the official regional Amazon RDS
   `us-west-2-bundle.pem` as `DATABASE_CA_CERT`, and run
   `npm exec qm -- secrets push`.
6. Run `npm exec qm -- doctor`, `npm exec qm -- plan`, and
   `npm exec qm -- up --yes`, in that order. This Risely deployment uses a
   custom Gemini provider, so complete the authenticated Admin registration in
   `GEMINI-SETUP.md` before running `npm exec qm -- check --live`.

To tear down this target, run `npm exec qm -- down`, then persist the destructive
lifecycle settings in Terraform state with `terraform -chdir=infra apply
-var='ecr_force_delete=true' -var='object_store_force_destroy=true'
-var='db_deletion_protection=false' -var='db_skip_final_snapshot=true'
-var='secret_recovery_window_days=0'`. Disabling database deletion protection
is a separate destructive decision: review that apply and its exact database
target before approving it. After that apply completes, run
`npm exec qm -- infra delete-task-definitions --yes`, then
`npm exec qm -- infra delete-image --yes`, then run `terraform -chdir=infra destroy
-var='ecr_force_delete=true' -var='object_store_force_destroy=true'
-var='db_deletion_protection=false' -var='db_skip_final_snapshot=true'
-var='secret_recovery_window_days=0'`.
Applying the settings before destroy lets Terraform remove deployed images,
versioned objects, Secrets Manager secrets without a recovery window, and the
database without a final snapshot. To retain a final RDS snapshot, keep
`db_deletion_protection=false` but omit only `db_skip_final_snapshot=true` from
both commands. Run the cleanup commands with
infrastructure-administrator credentials; the GitHub deploy role intentionally
cannot deregister or delete task definitions.
