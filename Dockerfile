# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# The demo app's image, and a test stage that is not part of it.
# `docker build --target test .` runs the unit suite. `docker build .` does not: the test stage is a
# sibling of the demo stage. The library is compiled in the build stage. The demo stage holds what runs
# (the compiled library, its two runtime dependencies, and the demo, whose server.ts Node runs as it is)
# plus the library sources and scripts/configure-iya-sts.ts, so that script runs inside this image.
# The iya-sts listener CA trust chain IS in the image: idpCa's file, demo/generated/idp-ca.pem, which
# the install script (scripts/configure-iya-sts.ts) wrote before the build. The key pair and both
# metadata documents are NOT: compose mounts demo/generated at /app/demo/generated, and the live
# sign-in mounts them one file each.
# 24.22.1: the 21 October 2026 security release, which fixes HTTP2Shell / Node2Shell (CVE-2026-111497).
FROM node:24.22.1-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages/saml2-sp-nodejs/package.json packages/saml2-sp-nodejs/
COPY demo/package.json demo/
RUN npm ci --workspaces --include-workspace-root --ignore-scripts
COPY packages/saml2-sp-nodejs/tsconfig.json packages/saml2-sp-nodejs/
COPY packages/saml2-sp-nodejs/src packages/saml2-sp-nodejs/src
RUN npm run build -w packages/saml2-sp-nodejs

# The unit suite. Not the demo image: nothing later copies this stage.
FROM build AS test
# scripts/trust-chain.test.ts makes a four-certificate chain with openssl.
RUN apk add --no-cache openssl
COPY packages/saml2-sp-nodejs/test packages/saml2-sp-nodejs/test
COPY demo/saml.json demo/
COPY scripts scripts
COPY VERSION VERSION
RUN npm test

FROM node:24.22.1-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/saml2-sp-nodejs/package.json packages/saml2-sp-nodejs/
COPY demo/package.json demo/
RUN npm ci --omit=dev --workspaces --include-workspace-root --ignore-scripts && npm cache clean --force
COPY --from=build /src/packages/saml2-sp-nodejs/dist packages/saml2-sp-nodejs/dist
# configure-iya-sts.ts imports the TypeScript sources. It runs in this image, not with node on the host.
COPY --from=build /src/packages/saml2-sp-nodejs/src packages/saml2-sp-nodejs/src
COPY scripts/redirects.mjs scripts/trust-chain.mjs scripts/configure-iya-sts.ts scripts/
# The demo, and with it idpCa's file: demo/generated/idp-ca.pem, the iya-sts listener CA trust chain
# scripts/configure-iya-sts.ts saved. The image trusts that iya-sts with no bind mount and no fetch.
# Rebuild after running the install script against a different iya-sts.
# .dockerignore admits that one file from demo/generated (never the key, the certificate or the
# metadata), and keeps out node_modules. A COPY of the demo DIRECTORY succeeds with or without the
# chain, so a fresh clone and CI still build; naming the file, or a glob that matches nothing, fails
# the build in both builders. It comes last, so a new chain rebuilds nothing else.
COPY demo demo
USER node
EXPOSE 3000
# PORT defaults to 3000 so a run that does not set it (the CI demo job) is still healthy.
# Compose passes PORT and overrides this. The shell form expands it; EXPOSE does not, so it stays 3000.
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:${PORT}/healthz >/dev/null || exit 1
CMD ["node", "demo/server.ts"]
