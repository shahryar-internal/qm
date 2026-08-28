FROM ghcr.io/yc-software/qm/portal@sha256:33aa80f67ddd9967d0f6b70cd3f2a060bc34b66b711d3940fb9bd047899972c0
USER root
COPY patch.mjs /tmp/patch.mjs
RUN node /tmp/patch.mjs && rm /tmp/patch.mjs
USER node
