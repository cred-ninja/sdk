#!/usr/bin/env bash
# Cofide's WIMSE HTTP-signature PoC (cofide/wimse-s2s-httpsig-poc @ 7984a60) and its
# WIT issuer minispire v0.2.2 against Cred. Needs Go and a built Cred (npm run build).
# minispire must already be running on unix:///tmp/spire.sock. On Linux:
#   go run github.com/cofide/minispire/cmd@v0.2.2
# On macOS minispire v0.2.2 does not build (it reads SO_PEERCRED); see
# conformance/interop/cofide.md for the one-function peer-credential shim used there.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../../../.." && pwd)"
out="${1:-$(mktemp -d)}"; mkdir -p "$out"
(cd "$here" && go run . bundle "$out/minispire.wit-bundle.json")
# A: a minispire-issued WIT and key drive the final hop (WPT, then HTTP signature).
(cd "$here" && go run . mint > "$out/svid.json")
node "$root/scripts/hackathon/interop/final-hop.mjs" "$out/minispire.wit-bundle.json" example.com "$out/svid.json"
# B: Cofide's own client library calls a Cred agent route.
port=3481
sub=$(node -e 'const m=require(process.argv[1]);console.log(JSON.parse(Buffer.from(m.wit.split(".")[1],"base64url")).sub)' "$out/svid.json")
cat > "$out/cfg.json" <<JSON
{ "host": "127.0.0.1", "port": $port, "publicUrl": "http://127.0.0.1:$port",
  "trustDomains": { "example.com": { "witBundle": "./minispire.wit-bundle.json", "keyUse": "wit-svid" } },
  "user": "alice", "agents": [ { "name": "cofide-workload", "workload": "$sub", "allowedScopes": ["calendar.readonly"] } ] }
JSON
node "$root/scripts/hackathon/serve.mjs" --config "$out/cfg.json" > "$out/cred.log" 2>&1 & pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
sleep 3
(cd "$here" && go run . client "http://127.0.0.1:$port/api/v1/connections?user_id=alice")
grep 'identity refused' "$out/cred.log" || true
