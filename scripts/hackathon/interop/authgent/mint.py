# Mint Txn-Tokens from a local authgent server (RFC 8693 token exchange,
# requested_token_type txn_token). Usage: python mint.py <count> <user>

import json, sys, urllib.request, urllib.parse
B = "http://127.0.0.1:8765"
def post(path, data=None, js=None):
    if js is not None:
        req = urllib.request.Request(B + path, data=json.dumps(js).encode(), headers={"content-type": "application/json"})
    else:
        req = urllib.request.Request(B + path, data=urllib.parse.urlencode(data).encode())
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())
TE = "urn:ietf:params:oauth:grant-type:token-exchange"
parent = post("/register", js={"client_name": "domain-b-gateway", "grant_types": ["client_credentials"], "scope": "calendar.read"})
tts = post("/register", js={"client_name": "domain-b-tts-caller", "grant_types": ["client_credentials", TE], "scope": "calendar.read"})
sub_tok = post("/token", {"grant_type": "client_credentials", "client_id": parent["client_id"], "client_secret": parent["client_secret"], "scope": "calendar.read"})["access_token"]
out = []
for _ in range(int(sys.argv[1])):
    r = post("/token", {"grant_type": TE, "client_id": tts["client_id"], "client_secret": tts["client_secret"],
        "subject_token": sub_tok, "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "requested_token_type": "urn:ietf:params:oauth:token-type:txn_token", "audience": "domain-b.example",
        "scope": "calendar.read", "request_details": json.dumps({"user": sys.argv[2]})})
    out.append(r["access_token"])
print(json.dumps(out))
