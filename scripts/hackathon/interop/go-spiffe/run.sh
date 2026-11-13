#!/usr/bin/env bash
# go-spiffe v2.7.0 (experimental WIT-SVID) against Cred. Needs Go and a built Cred (npm run build).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../../../.." && pwd)"
out="${1:-$(mktemp -d)}"; mkdir -p "$out"
(cd "$here" && go run . issue "$out" domain-b.example /ns/agents/sa/planner)
node "$root/scripts/hackathon/interop/final-hop.mjs" "$out/bundle.json" domain-b.example "$out/svid.json"
# Reverse direction: go-spiffe validates a WIT from Cred's demo issuer.
read -r bundle wit < <(node --input-type=module -e "
import { witIssuer } from '$root/scripts/hackathon/lib/issuers.mjs';
const i = witIssuer('domain-b.example', '$out'); console.log(i.bundlePath, i.workload('/ns/agents/sa/planner').wit);")
(cd "$here" && go run . validate "$bundle" domain-b.example "$wit")
