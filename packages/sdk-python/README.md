# cred-auth

Python SDK for Cred. OAuth2 credential delegation for AI agents. Supports both legacy short-lived access tokens and brokered delegation handles.

## Install

```bash
pip install cred-auth
```

## Quick Start

```python
import os
from cred import Cred, ConsentRequiredError

cred = Cred(
    agent_token=os.environ["CRED_AGENT_TOKEN"],
    base_url=os.environ["CRED_BASE_URL"],
)

try:
    result = cred.delegate(
        service="google",
        user_id="user_123",
        app_client_id="my_app_client_id",
        scopes=["calendar.readonly"],
    )
    print(result.access_token)
except ConsentRequiredError as e:
    # Redirect user to e.consent_url to complete OAuth consent
    print(f"Redirect user to: {e.consent_url}")
```

For brokered server-side use, issue the handle to the agent's own did:key. The handle is bound to that key: every request that uses it carries a DPoP proof (RFC 9449) signed by the agent, so a handle id copied out of a log is useless without the agent's private key. (This holds while the server requires DPoP, its default; a server run with `CRED_REQUIRE_DPOP=false` issues legacy Bearer-bound handles.)

```python
from cred import AgentIdentity, generate_agent_identity

identity = generate_agent_identity()  # persist with identity.export(); reload with AgentIdentity.from_export()

handle = cred.delegate_handle(
    service="google",
    user_id="user_123",
    app_client_id="my_app_client_id",
    scopes=["calendar.readonly"],
    agent_identity=identity,
)

events = cred.use(
    delegation_id=handle.delegation_id,
    url="https://www.googleapis.com/calendar/v3/calendars/primary/events",
    agent_identity=identity,
)
```

## API

### `Cred(agent_token, base_url)`

### `delegate(service, user_id, app_client_id, scopes=None) → DelegationResult`

Get a delegated access token for a service on behalf of a user.

Raises `ConsentRequiredError` (with `.consent_url`) if the user hasn't connected the service.

### `delegate_handle(service, user_id, app_client_id, scopes=None, agent_did=None, agent_identity=None) → DelegationHandleResult`

Get a brokered delegation handle for a service. The provider access token stays on the Cred server.

With `agent_identity`, the handle is issued to that identity's did:key (`agent_did` is set from it; passing a different `agent_did` raises `CredError`) and the request carries a `DPoP` proof of the key. A server that requires DPoP (the default) issues handles only this way.

### `use(delegation_id, url, method="GET", body=None, extra_headers=None, agent_identity=None) → BrokeredUseResult`

Broker an upstream API request through the Cred server with a delegation handle. The server enforces service URL allowlists, delegated scopes, and any configured Guard policies before forwarding.

Pass the same `agent_identity` the handle was issued to; the request then carries a `DPoP` proof that also commits to the handle (`ath`) and to this exact request (`cred_req`: URL, method, body and extra headers).

### `create_dpop_proof(identity, htm, htu, handle=None, request_body=None) → str`

Build a DPoP proof (compact JWS, `typ: dpop+jwt`, EdDSA) for one request, signed with the agent's Ed25519 key. `htu` is the request URL without query or fragment; `handle` adds `ath`, the base64url SHA-256 of the handle id. `request_body` adds `cred_req`, the base64url SHA-256 of the RFC 8785 (JCS) serialization of the whole JSON body sent, so the proof authorizes that one request; `use()` sets it for you. `canonical_json(value)` exposes the JCS serializer. The client methods above call this for you; make a new proof per request, since the server rejects a replayed `jti` or a proof older than two minutes.

### `get_user_connections(user_id, app_client_id=None) → list[Connection]`

List all active service connections for a user.

### `get_consent_url(service, user_id, app_client_id, scopes, redirect_uri) → str`

Build a consent URL. Pure URL construction, no HTTP call.

### `revoke(service, user_id, app_client_id=None) → None`

Revoke a user's connection to a service.

## Context Manager

```python
with Cred(agent_token=token, base_url=base_url) as cred:
    result = cred.delegate(service="github", user_id="u1", app_client_id="app1")
```

## Self-Hosted Server Mode

Point `base_url` at your own `@credninja/server` deployment when you want a separate credential broker instead of local-only usage.
