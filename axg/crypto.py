from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)

# Fallback in-memory keys if none are provided via env vars
_fallback_private_key = None
_fallback_public_key = None
KID = "axg-key-001"

def _generate_fallback_keys() -> tuple[str, str]:
    global _fallback_private_key, _fallback_public_key
    if _fallback_private_key and _fallback_public_key:
        return _fallback_private_key, _fallback_public_key

    logger.warning("Generating ephemeral RSA keys for AXG Passport. Keys will not persist across restarts.")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    _fallback_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    
    _fallback_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    return _fallback_private_key, _fallback_public_key

def get_private_key() -> str:
    key = os.environ.get("AXG_PRIVATE_KEY")
    if key:
        return key.replace("\\n", "\n")
    priv, _ = _generate_fallback_keys()
    return priv

def get_public_key() -> str:
    key = os.environ.get("AXG_PUBLIC_KEY")
    if key:
        return key.replace("\\n", "\n")
    
    priv_key_str = os.environ.get("AXG_PRIVATE_KEY")
    if priv_key_str:
        priv_key_str = priv_key_str.replace("\\n", "\n")
        private_key = serialization.load_pem_private_key(
            priv_key_str.encode("utf-8"),
            password=None,
            backend=default_backend()
        )
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    _, pub = _generate_fallback_keys()
    return pub

def hash_payload(payload: dict[str, Any]) -> str:
    """Creates a deterministic SHA-256 hash of the payload."""
    serialized = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

def sign_decision(
    execution_id: str,
    app_id: str,
    decision: str,
    action_type: str,
    actionable_payload: dict[str, Any],
    expires_in_minutes: int = 5
) -> str:
    """Generates a signed JWT Decision Token."""
    now = datetime.now(timezone.utc)
    
    claims = {
        "iss": "axg-engine",
        "sub": execution_id,
        "aud": app_id,
        "iat": now,
        "exp": now + timedelta(minutes=expires_in_minutes),
        "decision": decision,
        "action_type": action_type,
        "payload_hash": hash_payload(actionable_payload),
    }
    
    private_key = get_private_key()
    
    try:
        token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": KID})
        return token
    except Exception as e:
        logger.error(f"Failed to sign decision token: {e}")
        raise ValueError("Could not generate cryptographic decision token") from e
