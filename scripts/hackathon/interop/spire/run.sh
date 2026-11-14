#!/usr/bin/env bash
# SPIRE main with WIT-SVIDs (experimental enable_wit_svids) against Cred, no Docker.
#   SPIRE_BIN=<dir with spire-server and spire-agent> ./run.sh [outdir]
# Build SPIRE: git clone https://github.com/spiffe/spire && cd spire &&
#   git checkout f722f5f0994ecc47ddd2ce9c805d262627529061 &&
#   GOTOOLCHAIN=auto go build -o <dir>/spire-server ./cmd/spire-server &&
#   GOTOOLCHAIN=auto go build -o <dir>/spire-agent ./cmd/spire-agent
# The WIT-SVID is fetched over the Workload API with go-spiffe v2.7.0
# (scripts/hackathon/interop/go-spiffe, mode "fetch").
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../../../.." && pwd)"
B="${SPIRE_BIN:?set SPIRE_BIN}"
out="${1:-$(mktemp -d)}"; mkdir -p "$out"
# Unix socket paths are limited to ~104 bytes on macOS: keep SPIRE's state short.
D=$(mktemp -d /tmp/crsp.XXXX)
td=domain-b.example
cat > "$D/server.conf" <<CONF
server {
  bind_address = "127.0.0.1"
  bind_port = "8081"
  socket_path = "$D/server.sock"
  trust_domain = "$td"
  data_dir = "$D/server-data"
  log_level = "INFO"
  experimental { enable_wit_svids = true }
}
plugins {
  DataStore "sql" { plugin_data { database_type = "sqlite3" connection_string = "$D/datastore.sqlite3" } }
  KeyManager "memory" { plugin_data {} }
  NodeAttestor "join_token" { plugin_data {} }
}
CONF
cat > "$D/agent.conf" <<CONF
agent {
  data_dir = "$D/agent-data"
  log_level = "INFO"
  server_address = "127.0.0.1"
  server_port = "8081"
  socket_path = "$D/agent.sock"
  trust_domain = "$td"
  insecure_bootstrap = true
  experimental { enable_wit_svids = true }
}
plugins {
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "memory" { plugin_data {} }
  WorkloadAttestor "unix" { plugin_data {} }
}
CONF
"$B/spire-server" run -config "$D/server.conf" > "$out/spire-server.log" 2>&1 & spid=$!
trap 'kill $spid ${apid:-} 2>/dev/null || true; rm -rf "$D"' EXIT
for _ in $(seq 1 40); do "$B/spire-server" healthcheck -socketPath "$D/server.sock" >/dev/null 2>&1 && break; sleep 0.5; done
echo "spire-server: $("$B/spire-server" --version 2>&1 | head -1)"
token=$("$B/spire-server" token generate -socketPath "$D/server.sock" -spiffeID "spiffe://$td/agent/local" | awk '{print $2}')
"$B/spire-agent" run -config "$D/agent.conf" -joinToken "$token" > "$out/spire-agent.log" 2>&1 & apid=$!
for _ in $(seq 1 40); do "$B/spire-agent" healthcheck -socketPath "$D/agent.sock" >/dev/null 2>&1 && break; sleep 0.5; done
"$B/spire-server" entry create -socketPath "$D/server.sock" -parentID "spiffe://$td/agent/local" \
  -spiffeID "spiffe://$td/ns/agents/sa/planner" -selector "unix:uid:$(id -u)" | grep -E 'SPIFFE ID|Selector'
grep -m1 'WIT key activated' "$out/spire-server.log" | sed 's/^/spire-server log: /'
# The workload fetches its WIT-SVID; retry while the agent syncs the new entry.
for _ in $(seq 1 30); do (cd "$root/scripts/hackathon/interop/go-spiffe" && go run . fetch "$D/agent.sock" "$out") && break; sleep 1; done
node -e 'const m=require(process.argv[1]);console.log("WIT header", Buffer.from(m.wit.split(".")[0],"base64url").toString())' "$out/svid.json"
# Out-of-band trust anchor: the operator's bundle export, loaded by Cred unchanged.
"$B/spire-server" bundle show -socketPath "$D/server.sock" -format spiffe > "$out/spire-bundle.json"
node -e 'const b=require(process.argv[1]);console.log("spire-server bundle show -format spiffe:",b.keys.map(k=>k.use).join(", "))' "$out/spire-bundle.json"
node "$root/scripts/hackathon/interop/final-hop.mjs" "$out/spire-bundle.json" "$td" "$out/svid.json" | grep -v '^\[cred\]'
