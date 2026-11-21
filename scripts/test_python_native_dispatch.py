"""Native adapter contract tests; only the external HTTP transport is replaced.

Run against source or independently installed wheels. Select packages with
CRED_NATIVE_ADAPTERS=langchain,crewai,... (no missing-adapter skips).
"""
import asyncio
import json
import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cred import Cred, generate_agent_identity

ADAPTERS = os.environ.get(
    "CRED_NATIVE_ADAPTERS", "langchain,crewai,semantic-kernel,autogen,openai-agents"
).split(",")
BASE = "https://cred.example.test"
URL = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
TOKEN = "synthetic-delegation-secret"


def tools(adapter, client, identity, user="alice", token_format="handle"):
    common = dict(agent_token=None, base_url=None, cred=client, agent_identity=identity)
    if adapter == "langchain":
        from cred_langchain import CredToolkit
        return {t.name.removeprefix("cred_"): t for t in CredToolkit(
            user_id=user, token_format=token_format, **common
        ).get_tools()}
    if adapter == "crewai":
        from cred_crewai import CredTool, CredUseTool
        from crewai import Agent
        try:
            from crewai import BaseLLM
        except ImportError:
            from langchain_core.language_models.fake import FakeListLLM
            llm = FakeListLLM(responses=[])
        else:
            class OfflineLLM(BaseLLM):
                def call(self, *args, **kwargs):
                    raise AssertionError("Native tools must not call a model")
            llm = OfflineLLM(model="offline")

        delegate = CredTool(user_id=user, service="google", app_client_id="app",
                            scopes=["calendar.readonly"], token_format=token_format, **common)
        use = CredUseTool(user_id=user, **common)
        agent = Agent(role="test", goal="test", backstory="test",
                      llm=llm, tools=[delegate, use])
        assert agent.tools == [delegate, use]
        return {"delegate": delegate, "use": use}
    if adapter == "semantic-kernel":
        from cred_semantic_kernel import CredPlugin
        from semantic_kernel import Kernel
        kernel = Kernel()
        plugin = CredPlugin(user_id=user, app_client_id="app",
                            token_format=token_format, **common)
        kernel.add_plugin(plugin, plugin_name="cred")
        return {"delegate": (kernel, "delegate"), "use": (kernel, "use")}
    if adapter == "autogen":
        from cred_autogen import cred_delegate_tool, cred_use_tool
    elif adapter == "openai-agents":
        from cred_openai_agents import cred_delegate_tool, cred_use_tool
    else:
        raise AssertionError(adapter)
    return {
        "delegate": cred_delegate_tool(user_id=user, app_client_id="app",
                                       token_format=token_format, **common),
        "use": cred_use_tool(user_id=user, **common),
    }


async def invoke(adapter, tool, args):
    if adapter == "semantic-kernel":
        kernel, name = tool
        # Native provider selection uses service_slug, not reserved AI injection.
        if name == "use":
            # SK 1.0 marks empty-string defaults required in its metadata.
            # Supply the documented empty-string inputs rather than bypassing dispatch.
            args = {"body": "", "extra_headers": "", **args}
        result = await kernel.invoke(plugin_name="cred", function_name=name, **args)
        return str(result)
    if adapter == "autogen":
        from autogen_core import CancellationToken
        return await tool.run_json(args, CancellationToken())
    if adapter == "openai-agents":
        from agents import RunContextWrapper
        return await tool.on_invoke_tool(RunContextWrapper(context=None), json.dumps(args))
    if adapter == "crewai" and hasattr(tool, "to_structured_tool"):
        return tool.to_structured_tool().invoke(args)
    return tool.invoke(args)


def delegate_args(adapter):
    if adapter == "crewai":
        return {}
    if adapter == "semantic-kernel":
        return dict(service_slug="google", scopes="calendar.readonly")
    return dict(service="google", scopes=["calendar.readonly"],
                **({"app_client_id": "app"} if adapter == "langchain" else {}))


@pytest.fixture
def wire(monkeypatch):
    state = {"calls": [], "expires_in": 900}

    def handle(transport, request):
        state["calls"].append(request)
        if request.url.path == "/api/v1/delegate":
            body = json.loads(request.content)
            assert body["service"] == "google"
            assert body["user_id"] == "alice"
            assert body["appClientId"] == "app"
            assert body["scopes"] == ["calendar.readonly"]
            if body.get("token_format") == "handle":
                assert request.headers.get("DPoP")
                data = dict(access_token=TOKEN, token_type="DPoP", cnf={"jkt": "fixture"},
                            expires_in=state["expires_in"], service="google", user_id="alice",
                            scopes=["calendar.readonly"], delegation_id="native-handle")
            else:
                data = dict(access_token="synthetic-raw", token_type="Bearer", expires_in=900,
                            service="google", scopes=[], delegation_id="raw-handle")
            data["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=state["expires_in"])).isoformat()
        elif request.url.path == "/api/v1/use":
            assert request.headers["Authorization"] == "DPoP " + TOKEN
            assert request.headers.get("DPoP")
            assert json.loads(request.content) == {"url": URL, "method": "GET"}
            data = dict(status=200, ok=True, body={"items": []}, contentType="application/json")
        elif request.method == "GET":
            data = {"connections": []}
        elif request.method == "DELETE":
            return httpx.Response(204)
        else:
            raise AssertionError("Unexpected HTTP path")
        return httpx.Response(200, json=data)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle)
    return state


@pytest.mark.parametrize("adapter", ADAPTERS)
@pytest.mark.parametrize("authentication", ["bearer", "signer"])
def test_native_delegate_use_and_refusals(adapter, authentication, wire):
    async def flow():
        identity = generate_agent_identity()
        signed = []
        def signer(method, url, headers, body):
            signed.append((method, url, body))
            return {"X-Test-Signature": "synthetic-signature"}
        auth = {"sign_request": signer} if authentication == "signer" else {"agent_token": "synthetic-agent"}
        with Cred(base_url=BASE, **auth) as client:
            pair = tools(adapter, client, identity)
            output = await invoke(adapter, pair["delegate"], delegate_args(adapter))
            assert TOKEN not in output
            delegated = json.loads(output)
            assert "access_token" not in delegated
            assert "token" not in delegated
            assert delegated["delegation_id"] == "native-handle"
            args = dict(delegation_id=delegated["delegation_id"], url=URL, method="GET")
            output = await invoke(adapter, pair["use"], args)
            assert json.loads(output)["ok"] is True
            assert TOKEN not in output
            assert len(wire["calls"]) == 2
            if authentication == "signer":
                assert len(signed) == 2
                assert all(r.headers.get("X-Test-Signature") == "synthetic-signature" for r in wire["calls"])
            for wrong in ("missing", "server", "agent", "user"):
                other_client = Cred(agent_token="synthetic-agent", base_url=BASE + ("/other" if wrong == "server" else ""))
                try:
                    other = tools(adapter, other_client,
                                  generate_agent_identity() if wrong == "agent" else identity,
                                  user="bob" if wrong == "user" else "alice")
                    bad_args = dict(args, delegation_id="missing" if wrong == "missing" else "native-handle")
                    count = len(wire["calls"])
                    reason = "Unknown or expired" if wrong == "missing" else "different server, agent or user"
                    try:
                        refused = await invoke(adapter, other["use"], bad_args)
                    except Exception as error:
                        cause = error
                        while cause.__cause__ is not None:
                            cause = cause.__cause__
                        assert reason in str(cause)
                        assert TOKEN not in str(error)
                    else:
                        # OpenAI translates exceptions into model-visible tool errors.
                        assert "error" in refused.lower()
                        assert reason in refused
                        assert TOKEN not in refused
                    assert len(wire["calls"]) == count
                finally:
                    other_client.close()
            wire["expires_in"] = -1
            fresh = tools(adapter, client, identity)
            await invoke(adapter, fresh["delegate"], delegate_args(adapter))
            count = len(wire["calls"])
            try:
                refused = await invoke(adapter, fresh["use"], args)
            except Exception as error:
                cause = error
                while cause.__cause__ is not None:
                    cause = cause.__cause__
                assert "expired" in str(cause).lower()
            else:
                assert "expired" in refused.lower()
            assert len(wire["calls"]) == count
    asyncio.run(flow())


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_native_raw_compatibility(adapter, wire):
    async def flow():
        with Cred(agent_token="synthetic-agent", base_url=BASE) as client:
            pair = tools(adapter, client, None, token_format="raw")
            output = await invoke(adapter, pair["delegate"], delegate_args(adapter))
            assert "synthetic-raw" in output
            if adapter == "langchain":
                assert json.loads(await invoke(adapter, pair["status"], {})) == []
                assert json.loads(await invoke(adapter, pair["revoke"], {"service": "google"}))["revoked"] is True
                status, revoke = wire["calls"][-2:]
                assert (status.method, status.url.path) == ("GET", "/api/v1/connections")
                assert (revoke.method, revoke.url.path) == ("DELETE", "/api/v1/connections/google")
                assert status.url.params["user_id"] == revoke.url.params["user_id"] == "alice"
    asyncio.run(flow())
