# @credninja/server — production Docker image
#
# Build:  docker build -t cred-server .
# Run:    docker run -p 3456:3456 --env-file .env -v cred-data:/app/data cred-server
#
# Build context must be the repo root (so workspace deps resolve):
#   docker build -f packages/server/Dockerfile -t cred-server .

FROM node:22-alpine AS builder

WORKDIR /build

# Copy workspace root + all packages needed for the build
COPY package.json package-lock.json ./
COPY packages/oauth/package.json packages/oauth/
COPY packages/vault/package.json packages/vault/
COPY packages/server/package.json packages/server/

# Install all workspace deps
RUN npm ci --workspace=packages/oauth --workspace=packages/vault --workspace=packages/server

# Copy source
COPY packages/oauth/ packages/oauth/
COPY packages/vault/ packages/vault/
COPY packages/server/ packages/server/

# Build all three packages (server depends on oauth + vault)
RUN npm run build --workspace=packages/oauth && \
    npm run build --workspace=packages/vault && \
    npm run build --workspace=packages/server

# ── Production image ─────────────────────────────────────────────────────────

FROM node:22-alpine

WORKDIR /app

# Copy built artifacts + production deps
COPY --from=builder /build/package.json /build/package-lock.json ./
COPY --from=builder /build/packages/oauth/package.json packages/oauth/
COPY --from=builder /build/packages/oauth/dist/ packages/oauth/dist/
COPY --from=builder /build/packages/vault/package.json packages/vault/
COPY --from=builder /build/packages/vault/dist/ packages/vault/dist/
COPY --from=builder /build/packages/server/package.json packages/server/
COPY --from=builder /build/packages/server/dist/ packages/server/dist/

# Install production deps only
RUN npm ci --omit=dev --workspace=packages/oauth --workspace=packages/vault --workspace=packages/server

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
