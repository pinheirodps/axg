from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from typing import Any, Dict, List, Optional, Protocol

import jwt
from jwt import PyJWKClient

from axg_python_sdk.canonical import canonical_hash


class AxgVerificationError(Exception):
    """Base error for AXG Passport verification failures."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def hash_payload(payload: Dict[str, Any]) -> str:
    """Canonical (RFC 8785-style) SHA-256 hash used by Passport v2; matches AXG core and the Node SDK."""
    return canonical_hash(payload)


def _legacy_hash_payload(payload: Dict[str, Any]) -> str:
    """Passport v1 hash (json.dumps with ASCII escaping). Kept only to verify v1 tokens."""
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class ReplayCache(Protocol):
    def check_and_store(self, jti: str, expires_at: int) -> bool:
        """Return True the first time a jti is seen (until it expires), False on replay."""


class InMemoryReplayCache:
    """Process-local replay protection. Use a shared store (e.g. Redis SET NX) across replicas."""

    def __init__(self) -> None:
        self._seen: Dict[str, int] = {}
        self._lock = threading.Lock()

    def check_and_store(self, jti: str, expires_at: int) -> bool:
        now = int(time.time())
        with self._lock:
            self._seen = {k: exp for k, exp in self._seen.items() if exp > now}
            if jti in self._seen:
                return False
            self._seen[jti] = expires_at
            return True


def verify_passport(
    token: str,
    payload: Dict[str, Any],
    app_id: str,
    tenant_id: Optional[str] = None,
    allowed_action_types: Optional[List[str]] = None,
    public_key: Optional[str] = None,
    jwks_url: Optional[str] = None,
    _signing_key: Any = None,
    replay_cache: Optional[ReplayCache] = None,
    jwks_client: Optional[PyJWKClient] = None,
) -> Dict[str, Any]:
    """
    Top-level utility for AXG Passport verification.

    Pass ``replay_cache`` to reject a Passport presented more than once (requires Passport v2).
    Pass a long-lived ``jwks_client`` to reuse cached keys instead of fetching the JWKS per call.
    """
    try:
        if public_key:
            signing_key = public_key
        elif _signing_key:
            signing_key = _signing_key
        else:
            if jwks_client is None:
                if not jwks_url:
                    raise ValueError("Either public_key or jwks_url must be provided.")
                jwks_client = PyJWKClient(jwks_url)
            signing_key = jwks_client.get_signing_key_from_jwt(token).key

        claims = jwt.decode(
            token, signing_key, algorithms=["RS256"], audience=app_id, issuer="axg-engine"
        )

        # 1. Decision Check
        if claims.get("decision") != "ALLOW":
            msg = f"Action not allowed by AXG decision: {claims.get('decision')}"
            raise AxgVerificationError(msg, "DECISION_NOT_ALLOWED")

        # 2. Tenant Check
        if tenant_id and claims.get("tenant_id") != tenant_id:
            msg = f"Tenant ID mismatch: expected {tenant_id}, got {claims.get('tenant_id')}"
            raise AxgVerificationError(msg, "TENANT_ID_MISMATCH")

        # 3. Action Type Check
        action_type = claims.get("action_type")
        if allowed_action_types and action_type not in allowed_action_types:
            msg = f"Action type mismatch: {action_type}"
            raise AxgVerificationError(msg, "ACTION_TYPE_MISMATCH")

        # 4. Payload Integrity check
        if "payload_hash" not in claims:
            raise AxgVerificationError(
                "Missing payload_hash claim in passport.", "MISSING_PAYLOAD_HASH"
            )

        expected_hash = hash_payload(payload) if claims.get("ver") == 2 else _legacy_hash_payload(payload)
        if claims.get("payload_hash") != expected_hash:
            raise AxgVerificationError(
                "Payload hash mismatch. Possible tampering detected.", "PAYLOAD_TAMPERED"
            )

        # 5. Replay protection (single use within the validity window)
        if replay_cache is not None:
            jti = claims.get("jti")
            if not jti:
                raise AxgVerificationError("Passport has no jti; replay protection needs Passport v2.", "MISSING_JTI")
            if not replay_cache.check_and_store(jti, int(claims["exp"])):
                raise AxgVerificationError("Passport was already used.", "PASSPORT_REPLAYED")

        return claims

    except jwt.PyJWTError as e:
        raise AxgVerificationError(f"JWT Verification failed: {e!s}", "JWT_ERROR") from e
    except Exception as e:
        if isinstance(e, AxgVerificationError):
            raise
        raise AxgVerificationError(
            f"Verification failed: {e!s}", "VERIFICATION_FAILED"
        ) from e


PASSPORT_META_KEY = "io.axg/passport"
PAYLOAD_META_KEY = "io.axg/actionable_payload"


def verify_mcp_tool_call(
    meta: Optional[Dict[str, Any]],
    tool_name: str,
    arguments: Dict[str, Any],
    app_id: str,
    tenant_id: Optional[str] = None,
    public_key: Optional[str] = None,
    jwks_url: Optional[str] = None,
    replay_cache: Optional[ReplayCache] = None,
    jwks_client: Optional[PyJWKClient] = None,
    ignored_arguments: tuple = ("axg",),
) -> Dict[str, Any]:
    """
    Verify, inside an MCP tool, that AXG authorized exactly this call.

    The AXG gateway/interceptor puts the Passport and the authorized actionable payload in the
    request ``params._meta``. The Passport must be valid for this tool (``action_type``) and payload,
    and every argument the tool received must be identical in the authorized payload (rules may add
    fields to the payload; they may never differ from the arguments).
    """
    meta = meta or {}
    passport = meta.get(PASSPORT_META_KEY)
    authorized = meta.get(PAYLOAD_META_KEY)
    if not passport or not isinstance(authorized, dict):
        raise AxgVerificationError("Tool call carries no AXG Passport.", "MISSING_PASSPORT")

    claims = verify_passport(
        passport,
        authorized,
        app_id,
        tenant_id=tenant_id,
        allowed_action_types=[tool_name],
        public_key=public_key,
        jwks_url=jwks_url,
        replay_cache=replay_cache,
        jwks_client=jwks_client,
    )

    for key, value in arguments.items():
        if key in ignored_arguments:
            continue
        if key not in authorized or authorized[key] != value:
            raise AxgVerificationError(
                f"Argument '{key}' differs from what AXG authorized.", "ARGUMENTS_MISMATCH"
            )
    return claims


class AxgClient:
    """
    Client for verifying AXG Passports in Python services.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.jwks_url = f"{self.base_url}/.well-known/jwks.json"
        # One client per AxgClient: PyJWKClient caches keys and refetches only on an unknown kid
        self._jwks_client = PyJWKClient(self.jwks_url)

    async def verify_passport(
        self,
        token: str,
        payload: Dict[str, Any],
        app_id: str,
        tenant_id: Optional[str] = None,
        allowed_action_types: Optional[List[str]] = None,
        public_key: Optional[str] = None,
        _signing_key: Any = None,
        replay_cache: Optional[ReplayCache] = None,
    ) -> Dict[str, Any]:
        """
        Verifies an AXG Decision Token (Passport) using the client's cached JWKS.
        Runs in a worker thread: fetching keys is blocking network I/O.
        """
        return await asyncio.to_thread(
            verify_passport,
            token,
            payload,
            app_id,
            tenant_id=tenant_id,
            allowed_action_types=allowed_action_types,
            public_key=public_key,
            _signing_key=_signing_key,
            replay_cache=replay_cache,
            jwks_client=self._jwks_client,
        )
