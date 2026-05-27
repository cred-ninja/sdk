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
    base_url=os.environ["CRED_BASE_URL"],
    user_id="user_123",
    app_client_id="my_app_client_id",
    token_format="handle",
)

kernel.add_plugin(plugin, plugin_name="cred")
```

## Plugin Functions

The `cred` plugin exposes two kernel functions:

### `delegate`

| Parameter | Type | Description |
|-----------|------|-------------|
| `service` | `string` | Service slug (e.g. `google`, `github`) |
| `scopes` | `string` | Comma-separated OAuth scopes to request |

`user_id` and `app_client_id` are pre-configured at construction time, not agent-controlled.

By default, `delegate` returns a legacy access token for backwards compatibility. Set `token_format="handle"` to return a brokered delegation handle instead, then call `use` to make allowed service API calls without exposing provider access tokens.

### `use`

| Parameter | Type | Description |
|-----------|------|-------------|
| `delegation_id` | `string` | Brokered handle returned by `delegate` |
| `url` | `string` | Full HTTPS API URL |
| `method` | `string` | HTTP method |
| `body` | `string` | Optional JSON body, or empty string |
| `extra_headers` | `string` | Optional JSON object of service-specific headers, or empty string |

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

## Brokered Server Mode

Point `CRED_BASE_URL` at your self-hosted `@credninja/server` deployment and set `token_format="handle"` when you want the agent to receive delegation handles instead of provider access tokens.
