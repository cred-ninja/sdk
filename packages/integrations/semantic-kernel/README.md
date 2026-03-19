# cred-semantic-kernel

Microsoft Semantic Kernel integration for Cred. OAuth2 credential delegation for AI agents.

## Install

```bash
pip install cred-semantic-kernel
```

## Quick Start

```python
import os
import semantic_kernel as sk
from cred_semantic_kernel import CredPlugin

kernel = sk.Kernel()

plugin = CredPlugin(
    agent_token=os.environ["CRED_AGENT_TOKEN"],
    user_id="user_123",
    app_client_id="my_app_client_id",
)

kernel.add_plugin(plugin, plugin_name="cred")
```

## Plugin Functions

The `cred` plugin exposes one kernel function:

### `delegate`

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | `string` | Service slug (e.g. `google`, `github`) |
| `scopes` | `string` | Comma-separated OAuth scopes to request |

`user_id` and `app_client_id` are pre-configured at construction time, not agent-controlled.

Returns a JSON string with `access_token`, `token_type`, `expires_in`, `service`, `scopes`, and `delegation_id`.

## Handling Consent

When the user hasn't connected the service, the `delegate` function raises `ConsentRequiredError`.
The error's `consent_url` attribute contains the URL to redirect the user.

```python
from cred import ConsentRequiredError

try:
    result = plugin.delegate(service="google", scopes="calendar.readonly")
except ConsentRequiredError as e:
    print(f"Redirect user to: {e.consent_url}")
```

## Cred Cloud (Coming Soon)

Managed cloud delegation is coming. [Join the waitlist](https://cred.ninja/waitlist).
