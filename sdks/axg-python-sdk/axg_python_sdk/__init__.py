from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

import jwt
from jwt import PyJWKClient


class AxgVerificationError(Exception):
    """Base error for AXG Passport verification failures."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def hash_payload(payload: Dict[str, Any]) -> str:
    """Deterministic SHA-256 hash matching AXG core."""
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def verify_passport(
    token: str,
    payload: Dict[str, Any],
    app_id: str,
    tenant_id: Optional[str] = None,
    allowed_action_types: Optional[List[str]] = None,
    public_key: Optional[str] = None,
    jwks_url: Optional[str] = None,
    _signing_key: Any = None,
) -> Dict[str, Any]:
    """
    Top-level utility for AXG Passport verification.
    """
    try:
        if public_key:
            signing_key = public_key
        elif _signing_key:
            signing_key = _signing_key
        else:
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

        if claims.get("payload_hash") != hash_payload(payload):
            raise AxgVerificationError(
                "Payload hash mismatch. Possible tampering detected.", "PAYLOAD_TAMPERED"
            )

        return claims

    except jwt.PyJWTError as e:
        raise AxgVerificationError(f"JWT Verification failed: {e!s}", "JWT_ERROR") from e
    except Exception as e:
        if isinstance(e, AxgVerificationError):
            raise
        raise AxgVerificationError(
            f"Verification failed: {e!s}", "VERIFICATION_FAILED"
        ) from e


class AxgClient:
    """
    Client for verifying AXG Passports in Python services.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.jwks_url = f"{self.base_url}/.well-known/jwks.json"

    async def verify_passport(
        self,
        token: str,
        payload: Dict[str, Any],
        app_id: str,
        tenant_id: Optional[str] = None,
        allowed_action_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Verifies an AXG Decision Token (Passport) using the client's JWKS.
        """
        return verify_passport(
            token,
            payload,
            app_id,
            tenant_id=tenant_id,
            allowed_action_types=allowed_action_types,
            jwks_url=self.jwks_url,
        )
