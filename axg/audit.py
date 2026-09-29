from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import anyio
import httpx

from axg.canonical import canonical_hash
from axg.models import ExecutionRecord

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64
WEBHOOK_ATTEMPTS = 3


class AuditSink(Protocol):
    async def record(self, decision_log: dict[str, Any]) -> None:
        """Records the decision log into the sink."""
        ...


def _chain_hash(entry: dict[str, Any]) -> str:
    """Hash of a chained entry: every field except record_hash itself (includes prev_hash)."""
    return canonical_hash({k: v for k, v in entry.items() if k != "record_hash"})


class FileAuditSink:
    """Append-only JSONL audit log with a hash chain.

    Each line carries ``prev_hash`` (the previous line's ``record_hash``) and ``record_hash``, so
    editing, deleting or reordering any record is detectable with ``verify_audit_chain``.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self._last_hash: str | None = None
        self._lock = anyio.Lock()

    async def _read_last_hash(self) -> str:
        path = anyio.Path(self.file_path)
        if not await path.exists():
            return GENESIS_HASH
        lines = [line for line in (await path.read_text(encoding="utf-8")).splitlines() if line.strip()]
        if not lines:
            return GENESIS_HASH
        return json.loads(lines[-1]).get("record_hash", GENESIS_HASH)

    async def record(self, decision_log: dict[str, Any]) -> None:
        try:
            async with self._lock:
                if self._last_hash is None:
                    self._last_hash = await self._read_last_hash()
                entry = dict(decision_log)
                entry["timestamp"] = datetime.now(timezone.utc).isoformat()
                entry["prev_hash"] = self._last_hash
                entry["record_hash"] = _chain_hash(entry)
                line = json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n"
                async with await anyio.open_file(self.file_path, mode="a", encoding="utf-8") as f:
                    await f.write(line)
                self._last_hash = entry["record_hash"]
        except Exception as e:
            logger.error(f"Failed to write to FileAuditSink ({self.file_path}): {e}")


def verify_audit_chain(file_path: str) -> tuple[bool, int | None]:
    """Verify a FileAuditSink log. Returns (True, None) or (False, 1-based line number of the first break)."""
    previous = GENESIS_HASH
    for number, line in enumerate(Path(file_path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, number
        if entry.get("prev_hash") != previous or entry.get("record_hash") != _chain_hash(entry):
            return False, number
        previous = entry["record_hash"]
    return True, None


class WebhookAuditSink:
    def __init__(self, url: str, token: str | None = None):
        self.url = url
        self.token = token

    async def record(self, decision_log: dict[str, Any]) -> None:
        decision_log["timestamp"] = datetime.now(timezone.utc).isoformat()
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        for attempt in range(1, WEBHOOK_ATTEMPTS + 1):
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(self.url, json=decision_log, headers=headers, timeout=5.0)
                    response.raise_for_status()
                return
            except Exception as e:
                if attempt == WEBHOOK_ATTEMPTS:
                    logger.error(f"Failed to send to WebhookAuditSink ({self.url}) after {attempt} attempts: {e}")
                    return
                await anyio.sleep(0.5 * attempt)


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
            log_dict = decision_log.model_dump(mode="json")
        else:
            log_dict = decision_log.copy()

        for sink in self.sinks:
            await sink.record(log_dict.copy())


audit_manager = AuditManager()
