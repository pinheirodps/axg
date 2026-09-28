import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from axg.api import app

TEST_API_KEY = "test-client-key"


def client_config(**overrides):
    config = {
        "client_id": "test-client",
        "key_sha256": hashlib.sha256(TEST_API_KEY.encode()).hexdigest(),
        "app_ids": ["*"],
        "permissions": ["*"],
    }
    config.update(overrides)
    return config


@pytest.fixture
def api_client(monkeypatch):
    """TestClient authenticated as a registered AXG client."""
    monkeypatch.setenv("AXG_CLIENTS", json.dumps([client_config()]))
    return TestClient(app, headers={"Authorization": f"Bearer {TEST_API_KEY}"})
