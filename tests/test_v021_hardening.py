"""v0.2.1: request limits, tamper-evident audit, webhook retries, remote plugin IP fallback."""

import json
import socket
from argparse import Namespace
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from axg import audit
from axg.api import app
from axg.audit import FileAuditSink, WebhookAuditSink, verify_audit_chain
from axg.cli import cmd_verify_audit
from axg.limits import RateLimiter, rate_limiter
from axg.plugin_loader import PluginLoader, PluginLoadError
from tests.test_v02_security import decision_request


@pytest.fixture(autouse=True)
def fresh_rate_limiter():
    rate_limiter.reset()
    yield
    rate_limiter.reset()


# ── Request limits ───────────────────────────────────────────────────────────

def test_oversized_body_is_rejected_by_content_length(api_client, monkeypatch):
    monkeypatch.setenv("AXG_MAX_BODY_BYTES", "512")
    body = decision_request(payload={"blob": "x" * 2000}).model_dump(mode="json")
    response = api_client.post("/v1/decisions", json=body)
    assert response.status_code == 413


def test_oversized_chunked_body_is_rejected(api_client, monkeypatch):
    monkeypatch.setenv("AXG_MAX_BODY_BYTES", "512")

    def chunks():
        yield b'{"padding": "'
        for _ in range(10):
            yield b"x" * 100
        yield b'"}'

    response = api_client.post("/v1/decisions", content=chunks(), headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_non_http_scopes_pass_through():
    with TestClient(app) as client:  # lifespan scope goes through the middleware untouched
        assert client.get("/health").status_code == 200


def test_rate_limit_returns_429_with_retry_after(api_client, monkeypatch):
    monkeypatch.setenv("AXG_RATE_LIMIT_PER_MINUTE", "2")
    body = decision_request().model_dump(mode="json")
    assert api_client.post("/v1/decisions", json=body).status_code == 200
    assert api_client.post("/v1/decisions", json=body).status_code == 200
    limited = api_client.post("/v1/decisions", json=body)
    assert limited.status_code == 429
    assert 1 <= int(limited.headers["retry-after"]) <= 60


def test_rate_limit_window_and_disable(monkeypatch):
    limiter = RateLimiter()
    monkeypatch.setenv("AXG_RATE_LIMIT_PER_MINUTE", "1")
    with patch("axg.limits.time.time", return_value=120.0):
        assert limiter.check("a") is None
        assert limiter.check("a") == 60
        assert limiter.check("b") is None  # per caller
    with patch("axg.limits.time.time", return_value=180.0):
        assert limiter.check("a") is None  # new window

    monkeypatch.setenv("AXG_RATE_LIMIT_PER_MINUTE", "0")
    assert all(limiter.check("a") is None for _ in range(5))


# ── Tamper-evident audit log ─────────────────────────────────────────────────

async def _write(sink, n):
    for i in range(n):
        await sink.record({"execution_id": f"exec_{i}", "decision": "ALLOW", "amount": 1.5 * i, "note": "ação"})


@pytest.mark.asyncio
async def test_audit_chain_is_verifiable_and_resumes(tmp_path):
    path = tmp_path / "audit.jsonl"
    await _write(FileAuditSink(str(path)), 2)
    await _write(FileAuditSink(str(path)), 2)  # a new process continues the same chain

    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["prev_hash"] == audit.GENESIS_HASH
    assert all(lines[i]["prev_hash"] == lines[i - 1]["record_hash"] for i in range(1, 4))
    assert verify_audit_chain(str(path)) == (True, None)


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["edit", "delete", "reorder", "garbage"])
async def test_audit_chain_detects_tampering(tmp_path, tamper):
    path = tmp_path / "audit.jsonl"
    await _write(FileAuditSink(str(path)), 3)
    lines = path.read_text(encoding="utf-8").splitlines()

    if tamper == "edit":
        entry = json.loads(lines[1])
        entry["decision"] = "BLOCK"
        lines[1] = json.dumps(entry)
    elif tamper == "delete":
        del lines[1]
    elif tamper == "reorder":
        lines[1], lines[2] = lines[2], lines[1]
    else:
        lines[1] = "{not json"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert verify_audit_chain(str(path)) == (False, 2)


@pytest.mark.asyncio
async def test_audit_chain_starts_on_empty_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("\n", encoding="utf-8")
    await _write(FileAuditSink(str(path)), 1)
    assert verify_audit_chain(str(path)) == (True, None)


@pytest.mark.asyncio
async def test_cli_verify_audit(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    await _write(FileAuditSink(str(path)), 2)
    assert cmd_verify_audit(Namespace(file=str(path))) == 0

    path.write_text(path.read_text(encoding="utf-8").replace("ALLOW", "BLOCK", 1), encoding="utf-8")
    assert cmd_verify_audit(Namespace(file=str(path))) == 2
    assert cmd_verify_audit(Namespace(file=str(tmp_path / "missing.jsonl"))) == 1
    assert "BROKEN at line 1" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_webhook_sink_retries_then_succeeds(respx_mock, monkeypatch):
    async def no_sleep(_):
        return None

    monkeypatch.setattr(audit.anyio, "sleep", no_sleep)
    route = respx_mock.post("https://audit.example/hook").mock(
        side_effect=[httpx.Response(503), httpx.ConnectError("down"), httpx.Response(200)]
    )
    await WebhookAuditSink("https://audit.example/hook").record({"execution_id": "e1"})
    assert route.call_count == 3


# ── Remote plugins: fall back across validated addresses ─────────────────────

PLUGIN = {"plugin": "remote", "version": "1.0.0", "domain": "test", "rules": []}


def _dns(*ips):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ips]


@pytest.fixture
def remote_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_REMOTE_PLUGINS", "true")
    monkeypatch.setenv("AXG_REMOTE_PLUGIN_ALLOWLIST", "https://policies.example.com:8443")


@pytest.mark.asyncio
async def test_remote_plugin_falls_back_to_next_ip(remote_enabled, respx_mock):
    respx_mock.get("https://1.1.1.1:8443/rules.json").mock(side_effect=httpx.ConnectError("unreachable"))
    ok = respx_mock.get("https://8.8.8.8:8443/rules.json").respond(200, json=PLUGIN)

    with patch("socket.getaddrinfo", return_value=_dns("8.8.8.8", "1.1.1.1")):
        plugin = await PluginLoader().load("https://policies.example.com:8443/rules.json")

    assert plugin.plugin == "remote"
    assert ok.calls.last.request.headers["host"] == "policies.example.com:8443"


@pytest.mark.asyncio
async def test_remote_plugin_fails_when_every_ip_is_unreachable(remote_enabled, respx_mock):
    respx_mock.get("https://1.1.1.1:8443/rules.json").mock(side_effect=httpx.ConnectTimeout("t"))
    respx_mock.get("https://8.8.8.8:8443/rules.json").mock(side_effect=httpx.ConnectError("r"))

    with patch("socket.getaddrinfo", return_value=_dns("1.1.1.1", "8.8.8.8")):
        with pytest.raises(PluginLoadError, match="Failed to fetch remote plugin"):
            await PluginLoader().load("https://policies.example.com:8443/rules.json")


@pytest.mark.asyncio
async def test_cli_dispatches_verify_audit(tmp_path, monkeypatch):
    from axg.cli import async_main

    path = tmp_path / "audit.jsonl"
    await _write(FileAuditSink(str(path)), 1)
    monkeypatch.setattr("sys.argv", ["axg", "verify-audit", "--file", str(path)])
    with pytest.raises(SystemExit) as exit_info:
        await async_main()
    assert exit_info.value.code == 0


@pytest.mark.asyncio
async def test_client_disconnect_is_forwarded_to_the_app():
    from axg.limits import BodySizeLimitMiddleware

    seen = []

    async def app(scope, receive, send):
        seen.append(await receive())

    async def receive():
        return {"type": "http.disconnect"}

    await BodySizeLimitMiddleware(app)({"type": "http", "headers": []}, receive, None)
    assert seen == [{"type": "http.disconnect"}]
