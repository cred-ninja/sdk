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

For brokered server-side use:

```python
handle = cred.delegate_handle(
    service="google",
    user_id="user_123",
    app_client_id="my_app_client_id",
    scopes=["calendar.readonly"],
)

events = cred.use(
    delegation_id=handle.delegation_id,
    url="https://www.googleapis.com/calendar/v3/calendars/primary/events",
)
```

## API

### `Cred(agent_token, base_url)`

### `delegate(service, user_id, app_client_id, scopes=None) → DelegationResult`

Get a delegated access token for a service on behalf of a user.

Raises `ConsentRequiredError` (with `.consent_url`) if the user hasn't connected the service.

### `delegate_handle(service, user_id, app_client_id, scopes=None) → DelegationHandleResult`

Get a brokered delegation handle for a service. The provider access token stays on the Cred server.

### `use(delegation_id, url, method="GET", body=None, extra_headers=None) → BrokeredUseResult`

Broker an upstream API request through the Cred server with a delegation handle. The server enforces service URL allowlists, delegated scopes, and any configured Guard policies before forwarding.

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
