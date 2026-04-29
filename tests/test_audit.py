import json
import logging
from unittest.mock import AsyncMock

import anyio
import httpx
import pytest

from axg.audit import AuditManager, FileAuditSink, WebhookAuditSink

@pytest.mark.anyio
async def test_file_audit_sink_success(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    sink = FileAuditSink(str(log_file))
    
    log = {"action": "allow", "amount": 100}
    await sink.record(log)
    
    # Read file
    content = log_file.read_text()
    written_log = json.loads(content.strip())
    assert written_log["action"] == "allow"
    assert "timestamp" in written_log

@pytest.mark.anyio
async def test_file_audit_sink_failure(tmp_path, monkeypatch, caplog):
    sink = FileAuditSink("/invalid/path/that/will/fail")
    with caplog.at_level(logging.ERROR):
        await sink.record({"test": "data"})
    assert "Failed to write to FileAuditSink" in caplog.text

@pytest.mark.anyio
async def test_webhook_audit_sink_success(monkeypatch):
    class MockResponse:
        def raise_for_status(self):
            pass

    async def mock_post(self, url, json, headers, timeout):
        assert url == "http://example.com"
        assert headers["Authorization"] == "Bearer test-token"
        assert json["action"] == "allow"
        assert "timestamp" in json
        return MockResponse()

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    sink = WebhookAuditSink("http://example.com", token="test-token")
    await sink.record({"action": "allow"})

@pytest.mark.anyio
async def test_webhook_audit_sink_failure(monkeypatch, caplog):
    async def mock_post(self, url, json, headers, timeout):
        raise httpx.RequestError("Network error")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    sink = WebhookAuditSink("http://example.com")
    with caplog.at_level(logging.ERROR):
        await sink.record({"test": "data"})
    
    assert "Failed to send to WebhookAuditSink" in caplog.text

@pytest.mark.anyio
async def test_webhook_audit_sink_http_error(monkeypatch, caplog):
    class MockResponse:
        def raise_for_status(self_resp):
            raise httpx.HTTPStatusError("500 Server Error", request=None, response=self_resp)

    async def mock_post(self, url, json, headers, timeout):
        return MockResponse()

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    sink = WebhookAuditSink("http://example.com")
    with caplog.at_level(logging.ERROR):
        await sink.record({"test": "data"})
    
    assert "Failed to send to WebhookAuditSink" in caplog.text

@pytest.mark.anyio
async def test_audit_manager(monkeypatch, tmp_path):
    log_file = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AXG_AUDIT_FILE", str(log_file))
    monkeypatch.setenv("AXG_AUDIT_WEBHOOK", "http://example.com/webhook")
    monkeypatch.setenv("AXG_AUDIT_WEBHOOK_TOKEN", "secret")
    
    manager = AuditManager()
    assert len(manager.sinks) == 2
    assert isinstance(manager.sinks[0], FileAuditSink)
    assert isinstance(manager.sinks[1], WebhookAuditSink)
    
    # Mock the sinks
    mock_sink1 = AsyncMock()
    mock_sink2 = AsyncMock()
    manager.sinks = [mock_sink1, mock_sink2]
    
    await manager.record_decision({"decision": "ALLOW"})
    
    mock_sink1.record.assert_called_once()
    mock_sink2.record.assert_called_once()
    
    # Ensure they got a copy of the dictionary
    passed_dict = mock_sink1.record.call_args[0][0]
    assert passed_dict["decision"] == "ALLOW"
