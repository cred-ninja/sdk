# Python 2.0.0

This release updates `cred-auth`, `cred-langchain`, `cred-crewai`,
`cred-openai-agents`, `cred-autogen` and `cred-semantic-kernel` together for
the Cred 2.0 server. Upgrade the Python SDK and any Cred framework integrations
together; the integrations require `cred-auth>=2.0.0,<3.0.0`.

## Migration

- Brokered delegation requires the agent's signing identity. Pass
  `agent_identity` to `delegate_handle()` and use the returned `token`, with
  the same identity, in `use()`. A delegation id alone is no longer an
  exercise credential. The SDK creates a DPoP proof bound to the token and
  the exact request.
- Framework integrations using `token_format="handle"` also need an
  `agent_identity`. They retain the token internally and expose the delegation
  id to the model. Keep both the identity and token out of model prompts.
- Supply the actual `user_id` and explicit server `base_url`. Raw provider
  token delivery requires the deployment to enable that legacy mode.
- Follow the [server migration checklist](npm-2.0.0.md#migration-checklist)
  when upgrading the server, including consent, lifetimes, metering and audit
  storage requirements. Exercise a test-account delegation, use and revocation
  flow before moving production traffic.

```python
from cred import Cred, generate_agent_identity

identity = generate_agent_identity()
with Cred(agent_token=agent_token, base_url=server_url) as client:
    delegation = client.delegate_handle(
        service="github",
        user_id=user_id,
        app_client_id=app_client_id,
        scopes=["repo"],
        agent_identity=identity,
    )
    response = client.use(
        delegation.token,
        url="https://api.github.com/user/repos",
        agent_identity=identity,
    )
```

## Python compatibility

| Packages | Minimum Python |
|---|---|
| `cred-auth`, `cred-langchain` | 3.9 |
| `cred-crewai`, `cred-autogen`, `cred-openai-agents`, `cred-semantic-kernel` | 3.10 |

CrewAI, AutoGen and Semantic Kernel require Python 3.10 through their framework
dependencies. The OpenAI Agents integration also requires 3.10: the upstream
Agents package selected on Python 3.9 fails while evaluating its type annotations.
LangChain's public
initializer now postpones annotation evaluation so it imports on Python 3.9.
CI builds distributions and tests fresh wheel installs on Python 3.9, 3.10 and
3.12, selecting the packages compatible with each interpreter. It checks the
installed public exports and dependency consistency.

## Release verification

Run the Python unit tests and strict SDK typecheck, `npm run release:hygiene`,
and `bash scripts/smoke-python-wheels.sh` with each supported test interpreter
selected through `PYTHON`. Build a wheel and source distribution for each
package and run `twine check` on all twelve artifacts. Publish those exact
artifacts and compare their SHA256 digests with PyPI before verifying a fresh
registry installation. Fixture checks do not replace live-provider acceptance.
