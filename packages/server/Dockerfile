# @credninja/server — production Docker image
#
# Build:  docker build -t cred-server .
# Run:    docker run -p 3456:3456 --env-file .env -v cred-data:/app/data cred-server
#
# Build context must be the repo root (so workspace deps resolve):
#   docker build -f packages/server/Dockerfile -t cred-server .

FROM node:26-alpine AS builder

WORKDIR /build

# Copy workspace root, the build helper, and every workspace package the
# server depends on (directly or through vault)
COPY package.json package-lock.json ./
COPY scripts/write-package-types.cjs scripts/
COPY packages/protocol/package.json packages/protocol/
COPY packages/attenuation/package.json packages/attenuation/
COPY packages/oauth/package.json packages/oauth/
COPY packages/tofu/package.json packages/tofu/
COPY packages/vault/package.json packages/vault/
COPY packages/guard/package.json packages/guard/
COPY packages/server/package.json packages/server/

# Install all workspace deps
RUN npm ci --workspace=packages/protocol --workspace=packages/attenuation --workspace=packages/oauth --workspace=packages/tofu --workspace=packages/vault --workspace=packages/guard --workspace=packages/server

# Copy source
COPY packages/protocol/ packages/protocol/
COPY packages/attenuation/ packages/attenuation/
COPY packages/oauth/ packages/oauth/
COPY packages/tofu/ packages/tofu/
COPY packages/vault/ packages/vault/
COPY packages/guard/ packages/guard/
COPY packages/server/ packages/server/

# Build in dependency order: protocol, attenuation, oauth and tofu have no
# workspace deps; vault needs protocol, attenuation and oauth; guard needs
# protocol; server needs all of them
RUN npm run build --workspace=packages/protocol && \
    npm run build --workspace=packages/attenuation && \
    npm run build --workspace=packages/oauth && \
    npm run build --workspace=packages/tofu && \
    npm run build --workspace=packages/vault && \
    npm run build --workspace=packages/guard && \
    npm run build --workspace=packages/server

# ── Production image ─────────────────────────────────────────────────────────

FROM node:26-alpine

WORKDIR /app

# Copy built artifacts + production deps
COPY --from=builder /build/package.json /build/package-lock.json ./
COPY --from=builder /build/packages/protocol/package.json packages/protocol/
COPY --from=builder /build/packages/protocol/dist/ packages/protocol/dist/
COPY --from=builder /build/packages/attenuation/package.json packages/attenuation/
COPY --from=builder /build/packages/attenuation/dist/ packages/attenuation/dist/
COPY --from=builder /build/packages/oauth/package.json packages/oauth/
COPY --from=builder /build/packages/oauth/dist/ packages/oauth/dist/
COPY --from=builder /build/packages/tofu/package.json packages/tofu/
COPY --from=builder /build/packages/tofu/dist/ packages/tofu/dist/
COPY --from=builder /build/packages/vault/package.json packages/vault/
COPY --from=builder /build/packages/vault/dist/ packages/vault/dist/
COPY --from=builder /build/packages/guard/package.json packages/guard/
COPY --from=builder /build/packages/guard/dist/ packages/guard/dist/
COPY --from=builder /build/packages/server/package.json packages/server/
COPY --from=builder /build/packages/server/dist/ packages/server/dist/

# Install production deps only
RUN npm ci --omit=dev --workspace=packages/protocol --workspace=packages/attenuation --workspace=packages/oauth --workspace=packages/tofu --workspace=packages/vault --workspace=packages/guard --workspace=packages/server

# Vault data directory (mount a volume here)
RUN mkdir -p /app/data
VOLUME /app/data

# Default env vars (override with --env-file or -e)
ENV HOST=0.0.0.0
ENV PORT=3456
ENV VAULT_PATH=/app/data/vault.json
ENV VAULT_STORAGE=file

EXPOSE 3456

WORKDIR /app/packages/server
CMD ["node", "dist/cli.js"]
