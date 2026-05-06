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


class AxgClient:
    """
    Client for verifying AXG Passports in Python services.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.jwks_url = f"{self.base_url}/.well-known/jwks.json"
        self._jwks_client = PyJWKClient(self.jwks_url)

    async def verify_passport(
        self,
        token: str,
        payload: Dict[str, Any],
        app_id: str,
        allowed_action_types: Optional[List[str]] = None,
        _signing_key: Any = None,  # Internal/Test injection
    ) -> Dict[str, Any]:
        """
        Verifies an AXG Decision Token (Passport).

        Performs cryptographic verification, expiration check, and payload integrity validation.
        """
        try:
            if _signing_key:
                signing_key = _signing_key
            else:
                # PyJWKClient.get_signing_key_from_jwt is NOT async by default in PyJWT
                signing_key = self._jwks_client.get_signing_key_from_jwt(token).key

            claims = jwt.decode(
                token, signing_key, algorithms=["RS256"], audience=app_id, issuer="axg-engine"
            )

            # 1. Decision Check
            if claims.get("decision") != "ALLOW":
                msg = f"Action not allowed by AXG decision: {claims.get('decision')}"
                raise AxgVerificationError(msg, "DECISION_NOT_ALLOWED")

            # 2. Action Type Check
            action_type = claims.get("action_type")
            if allowed_action_types and action_type not in allowed_action_types:
                msg = f"Action type mismatch: {action_type}"
                raise AxgVerificationError(msg, "ACTION_TYPE_MISMATCH")

            # 3. Payload Integrity check
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
