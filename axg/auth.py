"""Caller authentication for the AXG API.

A Passport is only as trustworthy as the caller that requested it, so every network caller
is identified by an API key and bound to the apps (Passport audiences) and permissions it may
assert for its agents.

Clients are configured through ``AXG_CLIENTS`` (JSON list); keys are stored as SHA-256 hashes:

    [{"client_id": "muai", "key_sha256": "<hex>", "app_ids": ["finnorte"], "permissions": ["*"]}]

``AXG_AUTH_MODE``: ``required`` (default) rejects unauthenticated calls with 401; ``optional``
(migration only) evaluates them but never returns ALLOW nor issues a Passport.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)

WILDCARD = "*"


class AuthConfigError(ValueError):
    """Raised when AXG_CLIENTS or AXG_AUTH_MODE is malformed."""


@dataclass(frozen=True)
class Caller:
    client_id: str
    authenticated: bool
    app_ids: frozenset[str]
    # None = the caller is trusted to assert its agents' permissions as-is
    permissions: frozenset[str] | None

    def may_act_for(self, app_id: str) -> bool:
        return WILDCARD in self.app_ids or app_id in self.app_ids

    def effective_permissions(self, requested: list[str]) -> list[str]:
        """Agent permissions capped by what this caller may grant."""
        if self.permissions is None or WILDCARD in self.permissions:
            return list(requested)
        return [p for p in requested if p in self.permissions]


# In-process use of the engine (library/embedded mode): the host application is the caller
TRUSTED_LOCAL = Caller("local", True, frozenset({WILDCARD}), None)
# Unauthenticated network caller in optional mode: evaluated, but never ALLOW, and it cannot
# vouch for any agent permission (claimed permissions must not turn a BLOCK into a CONFIRM)
ANONYMOUS = Caller("anonymous", False, frozenset({WILDCARD}), frozenset())


def auth_mode() -> str:
    mode = os.environ.get("AXG_AUTH_MODE", "required").strip().lower()
    if mode not in {"required", "optional"}:
        raise AuthConfigError(f"AXG_AUTH_MODE must be 'required' or 'optional', got '{mode}'")
    return mode


def _load_clients() -> list[dict]:
    raw = os.environ.get("AXG_CLIENTS", "").strip()
    if not raw:
        return []
    try:
        clients = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthConfigError("AXG_CLIENTS is not valid JSON") from exc
    if not isinstance(clients, list):
        raise AuthConfigError("AXG_CLIENTS must be a JSON list")
    for client in clients:
        if not isinstance(client, dict) or not client.get("client_id") or not client.get("key_sha256"):
            raise AuthConfigError("Each AXG client needs 'client_id' and 'key_sha256'")
    return clients


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def authenticate(api_key: str) -> Caller | None:
    """Return the Caller owning this API key, or None if it matches no client."""
    presented = hash_api_key(api_key)
    match = None
    # Compare against every client (constant-time per comparison, no early exit)
    for client in _load_clients():
        if hmac.compare_digest(presented, str(client["key_sha256"]).lower()):
            match = client
    if match is None:
        return None

    return Caller(
        client_id=str(match["client_id"]),
        authenticated=True,
        app_ids=frozenset(match.get("app_ids") or []),
        # Least privilege: a client without a permissions ceiling may grant its agents none
        permissions=frozenset(match.get("permissions") or []),
    )
