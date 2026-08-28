FROM node:24.20.0-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS production-application
WORKDIR /app/canary/service/ceo-canary
RUN apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0
ENV NODE_ENV=production
ENV AWS_REGION=us-west-2 \
    CANARY_SECRETS_PREFIX=risely/qm-pilot/ \
    CANARY_DEPLOYMENT_PROFILE_REF=deployment-profile:risely:ceo:v1 \
    CANARY_DATABASE_SCHEMA=risely_agent_runtime \
    CANARY_DATABASE_NAME=qm \
    CANARY_DATABASE_PORT=5432 \
    CANARY_BOOTSTRAP_ADMIN_ROLE=qm \
    CANARY_OWNER_DATABASE_USER=risely_agent_runtime_owner \
    CANARY_RUNTIME_DATABASE_USER=risely_agent_runtime_runtime \
    CANARY_MIGRATION_DATABASE_USER=risely_agent_runtime_migrator \
    CANARY_INGRESS_ISSUER=risely-ceo-canary-caller-v1 \
    CANARY_INGRESS_AUDIENCE=risely-ceo-canary \
    CANARY_INGRESS_KEY_ID=ceo-canary-ingress-v1 \
    CANARY_MUTATIONS_ENABLED=0 \
    CANARY_PROVIDER_EXECUTION_ENABLED=0
COPY service/ceo-canary/package.json service/ceo-canary/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
RUN ln -s /app/canary/service/ceo-canary/node_modules /app/canary/node_modules
COPY service/ceo-canary/src ./src
COPY shared-contracts /app/canary/shared-contracts
COPY deployment-profiles/index.mjs deployment-profiles/contract.mjs deployment-profiles/provider-effect-policy.mjs /app/canary/deployment-profiles/
COPY deployment-profiles/profile-contract /app/canary/deployment-profiles/profile-contract
COPY provider-effects/index.mjs /app/canary/provider-effects/index.mjs
COPY runtime-scope /app/canary/runtime-scope
COPY contracts /app/canary/contracts
COPY chief-of-staff /app/canary/chief-of-staff
COPY evals/deterministic.mjs evals/fixtures.mjs evals/gates.mjs evals/index.mjs evals/judge.mjs evals/release-authority.mjs evals/repair-policy.mjs evals/replay.mjs evals/result-store.mjs /app/canary/evals/

FROM production-application AS test
COPY deployment-profiles/testing.mjs /app/canary/deployment-profiles/testing.mjs
COPY evals/testing.mjs evals/testing-result-store.mjs /app/canary/evals/
COPY presentation /app/canary/presentation
COPY slack /app/canary/slack
COPY service/ceo-surface/src /app/canary/service/ceo-surface/src

FROM production-application AS credential-operator
USER root
RUN apk add --no-cache postgresql16-client=16.15-r0
USER node
ENTRYPOINT ["node", "/app/canary/service/ceo-canary/src/provision-credentials.mjs"]

FROM production-application AS runtime
USER node
EXPOSE 8080
STOPSIGNAL SIGTERM
CMD ["node", "/app/canary/service/ceo-canary/src/server.mjs"]
