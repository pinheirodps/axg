from __future__ import annotations

import hashlib
import json
import logging
import os
import base64
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)

def _int_to_base64url(val: int) -> str:
    """Converts an integer to base64url string as per RFC 7517/7518."""
    if val == 0:
        return "AA"
    byte_len = (val.bit_length() + 7) // 8
    der_bytes = val.to_bytes(byte_len, byteorder='big')
    return base64.urlsafe_b64encode(der_bytes).decode('ascii').rstrip('=')

class KeyManager:
    """
    Manages RSA keys for AXG Passport signing and verification.
    Follows SOLID by isolating key lifecycle and format conversion.
    """
    KID = "axg-key-001"
    
    def __init__(self):
        self.reload()

    def reload(self):
        """Reloads keys from environment or generates new ones. Useful for tests."""
        self._private_key_str = None
        self._public_key_str = None
        self._load_keys()

    def _load_keys(self):
        """Loads keys from environment or generates ephemeral ones (Fail-Safe)."""
        env_priv = os.environ.get("AXG_PRIVATE_KEY")
        env_pub = os.environ.get("AXG_PUBLIC_KEY")

        if env_priv:
            self._private_key_str = env_priv.replace("\\n", "\n")
            if env_pub:
                self._public_key_str = env_pub.replace("\\n", "\n")
            else:
                self._public_key_str = self._derive_public_key(self._private_key_str)
        else:
            self._generate_ephemeral_keys()

    def _derive_public_key(self, private_key_pem: str) -> str:
        """Derives public key from private key PEM."""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
            backend=default_backend()
        )
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def _generate_ephemeral_keys(self):
        """Generates temporary RSA keys for development/testing."""
        logger.warning("Generating ephemeral RSA keys for AXG Passport. Keys will not persist.")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        self._private_key_str = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")
        
        self._public_key_str = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    @property
    def private_key(self) -> str:
        return self._private_key_str

    @property
    def public_key(self) -> str:
        return self._public_key_str

    def get_jwks(self) -> Dict[str, Any]:
        """Returns the public key in JSON Web Key Set format."""
        try:
            public_key = serialization.load_pem_public_key(
                self.public_key.encode("utf-8"),
                backend=default_backend()
            )
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("Only RSA keys are supported for JWKS")

            numbers = public_key.public_numbers()
            
            return {
                "keys": [
                    {
                        "kty": "RSA",
                        "alg": "RS256",
                        "use": "sig",
                        "kid": self.KID,
                        "n": _int_to_base64url(numbers.n),
                        "e": _int_to_base64url(numbers.e),
                    }
                ]
            }
        except Exception as e:
            logger.error(f"Failed to generate JWKS: {e}")
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"Could not generate JWKS: {e}") from e

# Global instance for easy access, but designed for dependency injection if needed.
key_manager = KeyManager()

def get_private_key() -> str:
    return key_manager.private_key

def get_public_key() -> str:
    return key_manager.public_key

def get_jwks() -> Dict[str, Any]:
    return key_manager.get_jwks()

def hash_payload(payload: dict[str, Any]) -> str:
    """Creates a deterministic SHA-256 hash of the payload (DRY)."""
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
    """Generates a signed JWT Decision Token following RS256 standard."""
    now = datetime.now(timezone.utc)
    
    claims = {
        "iss": "axg-engine",
        "sub": execution_id,
        "aud": app_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_in_minutes)).timestamp()),
        "decision": decision,
        "action_type": action_type,
        "payload_hash": hash_payload(actionable_payload),
    }
    
    try:
        token = jwt.encode(
            claims, 
            key_manager.private_key, 
            algorithm="RS256", 
            headers={"kid": key_manager.KID}
        )
        return token
    except Exception as e:
        logger.error(f"Failed to sign decision token: {e}")
        raise ValueError("Could not generate cryptographic decision token") from e
