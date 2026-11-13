#!/usr/bin/env bash
# wimsey (github.com/kanywst/wimsey, an independent Rust WIMSE implementation:
# WIT, WPT, RFC 9421 HTTP signatures) against Cred, both directions.
#   WIMSEY=<path to the wimsey binary> ./run.sh [outdir]
# Build wimsey: git clone https://github.com/kanywst/wimsey && cd wimsey &&
#   git checkout 56b070582f3e380c5006630698fb4ca808c08b04 && cargo build --release -p wimsey-cli
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../../../.." && pwd)"
W="${WIMSEY:?set WIMSEY to the wimsey binary}"
out="${1:-$(mktemp -d)}"; mkdir -p "$out"; cd "$out"
port=3491; base="http://127.0.0.1:$port"; td=domain-b.example
sub="spiffe://$td/ns/agents/sa/planner"
echo "wimsey: $("$W" --version 2>/dev/null || echo unknown)"

for alg in ES256 Ed25519; do
  echo; echo "=== wimsey -> Cred ($alg issuer and workload keys) ==="
  "$W" key generate --alg "$alg" --out "issuer-$alg.jwk"
  "$W" key public --in "issuer-$alg.jwk" --out "issuer-$alg.pub.jwk"
  "$W" key generate --alg "$alg" --out "pop-$alg.jwk"
  node -e 'const k=JSON.parse(require("fs").readFileSync(process.argv[1]));k.kid="wimsey-issuer-1";k.use="wit-svid";require("fs").writeFileSync(process.argv[2],JSON.stringify({keys:[k]},null,2))' "issuer-$alg.pub.jwk" "bundle-$alg.json"
  wit=$("$W" wit issue --issuer-key "issuer-$alg.jwk" --sub "$sub" --cnf-key "pop-$alg.jwk" --kid wimsey-issuer-1 --ttl 600)
  echo "WIT header: $(node -e 'console.log(Buffer.from(process.argv[1].split(".")[0],"base64url").toString())' "$wit")"
  cat > "cfg-$alg.json" <<JSON
{ "host": "127.0.0.1", "port": $port, "publicUrl": "$base",
  "trustDomains": { "$td": { "witBundle": "./bundle-$alg.json", "keyUse": "wit-svid" } },
  "user": "alice", "agents": [ { "name": "planner", "workload": "$sub", "allowedScopes": ["calendar.readonly"] } ] }
JSON
  node "$root/scripts/hackathon/serve.mjs" --config "cfg-$alg.json" --state "state-$alg" > "cred-$alg.log" 2>&1 & pid=$!
  trap 'kill $pid 2>/dev/null || true' EXIT
  for _ in $(seq 1 40); do curl -s -o /dev/null "$base/health" && break; sleep 0.25; done

  # 1. WIT + WPT made by wimsey.
  wpt=$("$W" wpt new --pop-key "pop-$alg.jwk" --wit "$wit" --aud "$base/api/v1/connections")
  echo "WIT + WPT (wimsey): $(curl -s -o /dev/null -w '%{http_code}' -H "Workload-Identity-Token: $wit" -H "Authorization: WPT $wpt" "$base/api/v1/connections?user_id=alice")"

  # 2. WIT + HTTP signature made by wimsey (GET with a query).
  sig=$("$W" httpsig sign --pop-key "pop-$alg.jwk" --method GET --authority "127.0.0.1:$port" --path /api/v1/connections --query user_id=alice --wit "$wit" --aud "$base/api/v1/connections")
  si=$(printf '%s\n' "$sig" | sed -n 's/^Signature-Input: //p'); sg=$(printf '%s\n' "$sig" | sed -n 's/^Signature: //p')
  echo "Signature-Input (wimsey): $si"
  echo "WIT + HTTP signature (wimsey), GET: $(curl -s -o /dev/null -w '%{http_code}' -H "Workload-Identity-Token: $wit" -H "Signature-Input: $si" -H "Signature: $sg" "$base/api/v1/connections?user_id=alice")"
  echo "  same request replayed: $(curl -s -o /dev/null -w '%{http_code}' -H "Workload-Identity-Token: $wit" -H "Signature-Input: $si" -H "Signature: $sg" "$base/api/v1/connections?user_id=alice")"

  # 3. POST with a body: wimsey adds and covers Content-Digest and Content-Type.
  printf '{"token_format":"handle","service":"google","user_id":"alice","scopes":["calendar.readonly"]}' > body.json
  sig=$("$W" httpsig sign --pop-key "pop-$alg.jwk" --method POST --authority "127.0.0.1:$port" --path /api/v1/delegate --header 'Content-Type: application/json' --body-file body.json --wit "$wit" --aud "$base/api/v1/delegate")
  si=$(printf '%s\n' "$sig" | sed -n 's/^Signature-Input: //p'); sg=$(printf '%s\n' "$sig" | sed -n 's/^Signature: //p')
  digest="sha-256=:$(openssl dgst -sha256 -binary body.json | base64):"
  resp=$(curl -s -w ' %{http_code}' -X POST -H 'Content-Type: application/json' -H "Content-Digest: $digest" -H "Workload-Identity-Token: $wit" -H "Signature-Input: $si" -H "Signature: $sg" --data-binary @body.json "$base/api/v1/delegate")
  echo "WIT + HTTP signature (wimsey), POST with body: $resp"
  echo "  (authenticated: the route then asks for the agent's DPoP proof, which is Cred's delegation protocol, not WIMSE)"

  # 4. A wimsey signature for one path, sent to another, is refused (@path is covered).
  sig=$("$W" httpsig sign --pop-key "pop-$alg.jwk" --method GET --authority "127.0.0.1:$port" --path /api/v1/connections --query user_id=alice --wit "$wit" --aud "$base/api/v1/connections")
  si=$(printf '%s\n' "$sig" | sed -n 's/^Signature-Input: //p'); sg=$(printf '%s\n' "$sig" | sed -n 's/^Signature: //p')
  echo "  wimsey signature for /api/v1/connections sent to /api/v1/providers: $(curl -s -o /dev/null -w '%{http_code}' -H "Workload-Identity-Token: $wit" -H "Signature-Input: $si" -H "Signature: $sg" "$base/api/v1/providers?user_id=alice")"
  grep 'identity refused' "cred-$alg.log" | sed 's/^/  cred log: /' || true
  kill $pid; wait $pid 2>/dev/null || true; trap - EXIT

  # 5. The full final hop with the wimsey-issued WIT and key (delegation, then a brokered read).
  node -e 'const fs=require("fs");fs.writeFileSync(process.argv[3],JSON.stringify({wit:process.argv[1],key:JSON.parse(fs.readFileSync(process.argv[2]))}))' "$wit" "pop-$alg.jwk" "svid-$alg.json"
  node "$root/scripts/hackathon/interop/final-hop.mjs" "bundle-$alg.json" "$td" "svid-$alg.json" | grep -v '^\[cred\]'
done

echo; echo "=== Cred -> wimsey (Cred's demo issuer and signer, wimsey verifies) ==="
eval "$(node "$here/cred-signed.mjs" "$out" "127.0.0.1:$port" /api/v1/connections user_id=alice "$base/api/v1/connections")"
"$W" httpsig verify --issuer-jwk "$out/cred-issuer.pub.jwk" --wit "$CRED_WIT" --method GET --authority "127.0.0.1:$port" --path /api/v1/connections --query user_id=alice --signature-input "$CRED_SI" --signature "$CRED_SIG" --aud "$base/api/v1/connections" && echo "wimsey httpsig verify of Cred's signature: OK"
"$W" wpt verify --issuer-jwk "$out/cred-issuer.pub.jwk" --wit "$CRED_WIT" --aud "$base/api/v1/connections" --proof "$CRED_WPT" 2>&1 && echo "wimsey wpt verify of Cred's WPT: OK" || true
