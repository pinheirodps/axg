from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Protocol

import httpx
import anyio

from axg.models import ExecutionRecord

logger = logging.getLogger(__name__)


class AuditSink(Protocol):
    async def record(self, decision_log: dict[str, Any]) -> None:
        """Records the decision log into the sink."""
        ...


class FileAuditSink:
    def __init__(self, file_path: str):
        self.file_path = file_path

    async def record(self, decision_log: dict[str, Any]) -> None:
        try:
            decision_log["timestamp"] = datetime.now(timezone.utc).isoformat()
            line = json.dumps(decision_log, sort_keys=True) + "\n"
            async with await anyio.open_file(self.file_path, mode="a", encoding="utf-8") as f:
                await f.write(line)
        except Exception as e:
            logger.error(f"Failed to write to FileAuditSink ({self.file_path}): {e}")


class WebhookAuditSink:
    def __init__(self, url: str, token: str | None = None):
        self.url = url
        self.token = token

    async def record(self, decision_log: dict[str, Any]) -> None:
        try:
            decision_log["timestamp"] = datetime.now(timezone.utc).isoformat()
            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            async with httpx.AsyncClient() as client:
                response = await client.post(self.url, json=decision_log, headers=headers, timeout=5.0)
                response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to send to WebhookAuditSink ({self.url}): {e}")


class AuditManager:
    def __init__(self):
        self.sinks: list[AuditSink] = []

        file_path = os.environ.get("AXG_AUDIT_FILE")
        if file_path:
            self.sinks.append(FileAuditSink(file_path))

        webhook_url = os.environ.get("AXG_AUDIT_WEBHOOK")
        if webhook_url:
            webhook_token = os.environ.get("AXG_AUDIT_WEBHOOK_TOKEN")
            self.sinks.append(WebhookAuditSink(webhook_url, webhook_token))

    async def record_decision(self, decision_log: dict[str, Any] | ExecutionRecord) -> None:
        if isinstance(decision_log, ExecutionRecord):
            log_dict = decision_log.model_dump()
        else:
            log_dict = decision_log.copy()
            
        for sink in self.sinks:
            await sink.record(log_dict.copy())


audit_manager = AuditManager()
