"""The Python SDK as a WIMSE workload against a real Cred server.

Run by run.mjs, which starts Cred and writes this workload's WIT, key, agent
identity and Txn-Tokens into the directory named by argv[2]. Prints one
PASS/FAIL line per check and exits non-zero on any FAIL.
"""

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cred import AgentIdentity, Cred, CredError, create_wimse_http_signer

base_url, files = sys.argv[1], Path(sys.argv[2])
CALENDAR = "https://www.googleapis.com/calendar/v3/calendars/primary/events"


def workload(name, txns):
    pending = list(txns)
    signer = create_wimse_http_signer(
        wit=lambda: (files / f"{name}.wit").read_text().strip(),
        private_key=load_pem_private_key((files / f"{name}.key.pem").read_bytes(), password=None),
        alg="ES256",
        txn_token=lambda: pending.pop(0) if pending else None,
    )
    return Cred(base_url=base_url, sign_request=signer)


failed = 0


def check(name, ok, detail):
    global failed
    failed += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}\n      {detail}")


agent = AgentIdentity.from_export(json.loads((files / "planner.agent.json").read_text()))
txns = json.loads((files / "txns.json").read_text())

planner = workload("planner", txns["planner"])
handle = planner.delegate_handle(service="google", user_id="alice", scopes=["calendar.readonly"],
                                 app_client_id="local", agent_identity=agent)
check("Python SDK: WIT + HTTP signature + bound Txn-Token obtains a delegation handle",
      bool(handle.token), f"delegation {handle.delegation_id}, scopes {handle.scopes}")
used = planner.use(token=handle.token, url=CALENDAR, method="GET", agent_identity=agent)
check("Python SDK: the signed brokered read reaches the provider", used.status == 200 and used.ok,
      f"provider {used.status}: {used.body}")

try:
    planner.use(token=handle.token, url=CALENDAR, method="POST", body={"summary": "x"}, agent_identity=agent)
    check("Python SDK: a write under the read-only grant is refused", False, "accepted")
except CredError as err:
    check("Python SDK: a write under the read-only grant is refused", True, f"{err.status_code} {err.code}")

stranger = workload("stranger", txns["stranger"])
try:
    stranger.delegate_handle(service="google", user_id="alice", scopes=["calendar.readonly"],
                             app_client_id="local", agent_identity=agent)
    check("Python SDK: a workload mapped to another agent cannot use this agent's key", False, "accepted")
except CredError as err:
    check("Python SDK: a workload mapped to another agent cannot use this agent's key", True, f"{err.status_code} {err.code}: {err}")

sys.exit(1 if failed else 0)
