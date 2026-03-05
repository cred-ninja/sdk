# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# Cred Dashboard — Docker image
#
# Build context: monorepo root (cred-ninja/sdk)
#
#   docker build -f packages/dashboard/Dockerfile -t cred-dashboard .
#
# Run:
#   docker run -d \
#     --name cred-dashboard \
#     -p 3456:3456 \
#     -v cred-vault:/app/data \
#     --env-file packages/dashboard/.env \
#     cred-dashboard
#
# NOTE: Once @credninja/oauth and @credninja/vault are published to npm,
# the multi-package build stages collapse to a single stage.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: build @credninja/oauth ──────────────────────────────────────────
FROM node:20-alpine AS build-oauth
WORKDIR /pkg/oauth
COPY packages/oauth/package*.json ./
RUN npm install
COPY packages/oauth/ ./
RUN npm run build

# ── Stage 2: build @credninja/vault ──────────────────────────────────────────
FROM node:20-alpine AS build-vault
WORKDIR /pkg/vault
COPY packages/vault/package*.json ./
RUN npm install
COPY packages/vault/ ./
RUN npm run build

# ── Stage 3: build the dashboard ─────────────────────────────────────────────
FROM node:20-alpine AS build-dashboard
WORKDIR /app

# Copy pre-built local packages
COPY --from=build-oauth /pkg/oauth /packages/oauth
COPY --from=build-vault /pkg/vault /packages/vault

# Install dashboard deps — rewrite file: paths to absolute paths inside image
COPY packages/dashboard/package*.json ./
RUN sed -i 's|file:../oauth|file:/packages/oauth|g' package.json && \
    sed -i 's|file:../vault|file:/packages/vault|g' package.json
RUN npm install

# Build
COPY packages/dashboard/src/ ./src/
COPY packages/dashboard/tsconfig.json ./
RUN npm run build

# ── Stage 4: production image ─────────────────────────────────────────────────
FROM node:20-alpine AS production
WORKDIR /app

COPY --from=build-oauth /pkg/oauth /packages/oauth
COPY --from=build-vault /pkg/vault /packages/vault
COPY --from=build-dashboard /app/dist ./dist
COPY --from=build-dashboard /app/package.json ./
COPY --from=build-dashboard /app/node_modules ./node_modules

# Vault data in a named volume — never baked into the image
VOLUME ["/app/data"]

EXPOSE 3456

ENV NODE_ENV=production

CMD ["node", "dist/index.js"]
