import json
import urllib.error

import pytest

from soldb.cross_env.bridge_client import (
    BridgeClientError,
    CrossEnvBridgeClient,
    StylusBridgeIntegration,
)
from soldb.cross_env.protocol import ContractInfo, CrossEnvTrace, TraceResponse


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


class FakeErrorBody:
    def read(self):
        return json.dumps({"error_message": "bad"}).encode()

    def close(self):
        pass


def test_bridge_client_requests(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout):
        calls.append((req.full_url, req.get_method(), req.data))
        if req.full_url.endswith("/health"):
            return FakeResponse({"status": "healthy"})
        if req.full_url.endswith("/contracts"):
            return FakeResponse({"contracts": [{"address": "0x1", "environment": "stylus", "name": "S"}]})
        if req.full_url.endswith("/contract/0x1"):
            return FakeResponse({"address": "0x1", "environment": "stylus", "name": "S"})
        if req.full_url.endswith("/request-trace"):
            return FakeResponse({"request_id": "r", "status": "success", "trace": {"trace_id": "t"}})
        if req.full_url.endswith("/submit-trace"):
            return FakeResponse({"ok": True})
        if req.full_url.endswith("/trace/t"):
            return FakeResponse({"trace_id": "t"})
        return FakeResponse({"ok": True})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = CrossEnvBridgeClient("http://bridge/", timeout=1)

    assert client.health_check()["status"] == "healthy"
    assert client.is_available()
    assert client.register_evm_contract("0x1", "E", "debug") == {"ok": True}
    assert client.register_stylus_contract("0x2", "S", "lib") == {"ok": True}
    assert client.unregister_contract("0x2") == {"ok": True}
    assert client.get_contract("0x1").environment == "stylus"
    assert client.list_contracts()[0].name == "S"
    assert client.is_stylus_contract("0x1")
    assert not client.is_evm_contract("0x1")
    assert client.request_stylus_trace("0x1", "0xdead").trace.trace_id == "t"
    assert client.submit_trace(CrossEnvTrace(trace_id="t")) == {"ok": True}
    assert client.get_trace("t").trace_id == "t"
    assert calls[0][0] == "http://bridge/health"


def test_bridge_client_error_paths(monkeypatch):
    def http_error(req, timeout):
        raise urllib.error.HTTPError(
            req.full_url,
            500,
            "server error",
            {},
            FakeErrorBody(),
        )

    monkeypatch.setattr("urllib.request.urlopen", http_error)
    with pytest.raises(BridgeClientError, match="HTTP 500: bad"):
        CrossEnvBridgeClient().health_check()

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda req, timeout: (_ for _ in ()).throw(urllib.error.URLError("down")),
    )
    assert not CrossEnvBridgeClient().is_available()
    assert CrossEnvBridgeClient().get_contract("0x0") is None


def test_stylus_bridge_integration_cache_and_failures(monkeypatch):
    integration = StylusBridgeIntegration(enabled=False)
    assert not integration.connect()
    assert not integration.is_connected
    assert not integration.is_stylus_contract("abc")
    assert integration.get_contract_info("abc") is None

    class FakeClient:
        def __init__(self):
            self.contract = ContractInfo("0xabc", "stylus", "Stylus")

        def is_available(self):
            return True

        def get_contract(self, address):
            return self.contract

        def request_stylus_trace(self, **kwargs):
            return TraceResponse("r", "success", trace=CrossEnvTrace(trace_id="trace"))

        def register_contract(self, contract):
            self.contract = contract
            return {"ok": True}

    integration = StylusBridgeIntegration(enabled=True)
    integration._client = FakeClient()
    assert integration.connect()
    assert integration.is_stylus_contract("abc")
    assert integration.get_contract_info("0xabc").name == "Stylus"
    assert integration.request_trace("0xabc", "0x00").trace_id == "trace"
    assert integration.register_contract(ContractInfo("0xdef", "evm", "EVM"))
    integration.clear_cache()
    assert integration._contract_cache == {}
