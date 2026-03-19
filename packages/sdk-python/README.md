# cred-auth

Python SDK for Cred. OAuth2 credential delegation for AI agents. Tokens are brokered, never exposed.

## Install

```bash
pip install cred-auth
```

## Quick Start

```python
import os
from cred import Cred, ConsentRequiredError

cred = Cred(agent_token=os.environ["CRED_AGENT_TOKEN"])

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

## API

### `Cred(agent_token, base_url=...)`

### `delegate(service, user_id, app_client_id, scopes=None) → DelegationResult`

Get a delegated access token for a service on behalf of a user.

Raises `ConsentRequiredError` (with `.consent_url`) if the user hasn't connected the service.

### `get_user_connections(user_id, app_client_id=None) → list[Connection]`

List all active service connections for a user.

### `get_consent_url(service, user_id, app_client_id, scopes, redirect_uri) → str`

Build a consent URL. Pure URL construction, no HTTP call.

### `revoke(service, user_id, app_client_id=None) → None`

Revoke a user's connection to a service.

## Context Manager

```python
with Cred(agent_token=token) as cred:
    result = cred.delegate(service="github", user_id="u1", app_client_id="app1")
```

## Cred Cloud (Coming Soon)

Managed cloud delegation is coming. [Join the waitlist](https://cred.ninja/waitlist).
