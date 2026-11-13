#!/usr/bin/env bash
# authgent's Transaction Token Service (github.com/authgent/authgent, Python)
# minting Txn-Tokens that Cred verifies on the final hop.
#   AUTHGENT=<path to the authgent-server executable> ./run.sh [outdir]
# Install: git clone https://github.com/authgent/authgent && cd authgent &&
#   git checkout 8341cf932c9816dc666f2a6577b6776bd6f3b978 &&
#   uv venv .venv --python 3.12 && VIRTUAL_ENV=.venv uv pip install -e server
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../../../.." && pwd)"
A="${AUTHGENT:?set AUTHGENT}"; py="$(dirname "$A")/python"
out="${1:-$(mktemp -d)}"; mkdir -p "$out"; cd "$out"
AUTHGENT_SERVER_URL=http://127.0.0.1:8765 AUTHGENT_TXN_TOKEN_TRUST_DOMAIN=domain-b.example \
  "$A" run --host 127.0.0.1 --port 8765 > authgent.log 2>&1 & pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
for _ in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:8765/.well-known/jwks.json && break; sleep 0.5; done
# Out of band: the Txn-Token Service's public keys, saved as a file Cred loads.
curl -s http://127.0.0.1:8765/.well-known/jwks.json > authgent-jwks.json
"$py" -I "$here/mint.py" 3 alice > txn-alice.json
"$py" -I "$here/mint.py" 1 bob | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s)[0]))' > txn-bob.txt
node -e 'const t=require(process.argv[1]);console.log("authgent Txn-Token header", Buffer.from(t[0].split(".")[0],"base64url").toString());console.log("authgent Txn-Token claims", Buffer.from(t[0].split(".")[1],"base64url").toString())' "$out/txn-alice.json"
node "$root/scripts/hackathon/interop/txn-final-hop.mjs" authgent-jwks.json txn-alice.json tctx.user txn-bob.txt | grep -v '^\[cred\]'
