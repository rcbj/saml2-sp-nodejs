# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# The demo app's image. The library is compiled in the first stage; the second holds only what runs:
# the compiled library, its two runtime dependencies and the demo, whose server.ts Node runs as it is.
# The key pair, the metadata and the IdP's TLS root are NOT in the image: they are mounted at
# /app/demo/generated (docker-compose.yml), made on the host by the setup script.
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

FROM node:24.22.1-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/saml2-sp-nodejs/package.json packages/saml2-sp-nodejs/
COPY demo/package.json demo/
RUN npm ci --omit=dev --workspaces --include-workspace-root --ignore-scripts && npm cache clean --force
COPY --from=build /src/packages/saml2-sp-nodejs/dist packages/saml2-sp-nodejs/dist
COPY demo/server.ts demo/saml.json demo/
COPY demo/public demo/public
USER node
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:3000/healthz >/dev/null || exit 1
CMD ["node", "demo/server.ts"]
