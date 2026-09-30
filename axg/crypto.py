from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from axg.canonical import canonical_hash
from axg.models import ApprovalChallenge, ApprovalTicketClaims, PassportApproval, PassportClaimsV2

logger = logging.getLogger(__name__)

PASSPORT_VERSION = 2
ISSUER = "axg-engine"
# JOSE typ of approval tickets: they must never be mistaken for a Passport
APPROVAL_TICKET_TYP = "axg-approval+jwt"


class KeyConfigError(RuntimeError):
    """Raised when signing keys are missing or invalid where they are mandatory."""


def _int_to_base64url(val: int) -> str:
    """Converts an integer to base64url string as per RFC 7517/7518."""
    if val == 0:
        return "AA"
    byte_len = (val.bit_length() + 7) // 8
    der_bytes = val.to_bytes(byte_len, byteorder='big')
    return base64.urlsafe_b64encode(der_bytes).decode('ascii').rstrip('=')


def _rsa_jwk(public_key_pem: str) -> Dict[str, str]:
    """Public JWK for an RSA PEM key, with an RFC 7638 thumbprint as kid."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"), backend=default_backend())
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Only RSA keys are supported for JWKS")
    numbers = public_key.public_numbers()
    e, n = _int_to_base64url(numbers.e), _int_to_base64url(numbers.n)
    # RFC 7638: SHA-256 over the required members in lexicographic order, no whitespace
    thumbprint_input = json.dumps({"e": e, "kty": "RSA", "n": n}, separators=(",", ":"), sort_keys=True)
    kid = base64.urlsafe_b64encode(hashlib.sha256(thumbprint_input.encode("ascii")).digest()).decode("ascii").rstrip("=")
    return {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": n, "e": e}


def _is_production() -> bool:
    return os.environ.get("AXG_ENV", "development").strip().lower() == "production"


class KeyManager:
    """
    Manages RSA keys for AXG Passport signing and verification.
    Follows SOLID by isolating key lifecycle and format conversion.
    """

    def __init__(self):
        self.reload()

    def reload(self):
        """Reloads keys from environment or generates new ones. Useful for tests."""
        self._private_key_str = None
        self._public_key_str = None
        self._load_keys()

    def _load_keys(self):
        """Loads keys from the environment; ephemeral keys only outside production (fail-closed)."""
        env_priv = os.environ.get("AXG_PRIVATE_KEY")
        env_pub = os.environ.get("AXG_PUBLIC_KEY")

        if env_priv:
            self._private_key_str = env_priv.replace("\\n", "\n")
            if env_pub:
                self._public_key_str = env_pub.replace("\\n", "\n")
            else:
                self._public_key_str = self._derive_public_key(self._private_key_str)
        elif _is_production():
            raise KeyConfigError("AXG_PRIVATE_KEY is required when AXG_ENV=production")
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

    @property
    def kid(self) -> str:
        """RFC 7638 thumbprint of the current signing key (changes when the key rotates)."""
        return _rsa_jwk(self.public_key)["kid"]

    def _previous_public_keys(self) -> list[str]:
        """Retired public keys kept in the JWKS so passports signed before a rotation still verify."""
        raw = os.environ.get("AXG_PREVIOUS_PUBLIC_KEYS", "").strip()
        if not raw:
            return []
        keys = json.loads(raw)
        if not isinstance(keys, list):
            raise ValueError("AXG_PREVIOUS_PUBLIC_KEYS must be a JSON list of PEM strings")
        return [k.replace("\\n", "\n") for k in keys]

    def verification_key(self, kid: str | None) -> str | None:
        """Public key (PEM) of a key this AXG signs or signed with, selected by its RFC 7638 kid."""
        for pem in (self.public_key, *self._previous_public_keys()):
            if _rsa_jwk(pem)["kid"] == kid:
                return pem
        return None

    def get_jwks(self) -> Dict[str, Any]:
        """Returns the current and retired public keys in JSON Web Key Set format."""
        try:
            keys = [_rsa_jwk(self.public_key)]
            keys += [_rsa_jwk(pem) for pem in self._previous_public_keys()]
            return {"keys": keys}
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
    """Deterministic SHA-256 of the canonical (RFC 8785-style) JSON payload (DRY)."""
    return canonical_hash(payload)

def sign_decision(
    *,
    execution_id: str,
    app_id: str,
    tenant_id: str,
    decision: str,
    action_type: str,
    actionable_payload: dict[str, Any],
    client_id: str,
    policy: str,
    expires_in_minutes: int = 5,
    jti: str | None = None,
    approval: PassportApproval | None = None,
) -> tuple[str, str]:
    """Issue a Passport v2 (RS256 JWT). Returns (token, jti).

    ``jti`` is fixed for Passports produced by an approval ticket (the ticket id), so one ticket
    can never yield two usable Passports: verifiers' replay caches reject the second.
    """
    now = datetime.now(timezone.utc)
    jti = jti or str(uuid.uuid4())

    claims = PassportClaimsV2(
        iss=ISSUER,
        sub=execution_id,
        aud=app_id,
        azp=client_id,
        iat=int(now.timestamp()),
        nbf=int(now.timestamp()),
        exp=int((now + timedelta(minutes=expires_in_minutes)).timestamp()),
        jti=jti,
        ver=PASSPORT_VERSION,
        tenant_id=tenant_id,
        decision=decision,
        action_type=action_type,
        policy=policy,
        payload_hash=hash_payload(actionable_payload),
        approval=approval,
    ).model_dump(exclude_none=True)

    try:
        token = jwt.encode(
            claims,
            key_manager.private_key,
            algorithm="RS256",
            headers={"kid": key_manager.kid}
        )
        return token, jti
    except Exception as e:
        logger.error(f"Failed to sign decision token: {e}")
        raise ValueError("Could not generate cryptographic decision token") from e


class ApprovalTicketError(ValueError):
    """The approval ticket is not one this AXG issued, or it is no longer valid."""


def sign_approval_ticket(
    *,
    execution_id: str,
    app_id: str,
    tenant_id: str,
    plugin_id: str,
    policy: str,
    decision: str,
    action_type: str,
    actionable_payload: dict[str, Any],
    client_id: str,
    required_role: str,
    user_id: str | None,
    agent_id: str | None,
    ttl_seconds: int,
) -> ApprovalChallenge:
    """Sign an approval ticket for a CONFIRM or SUGGEST decision (stateless: everything is in the token)."""
    now = datetime.now(timezone.utc)
    claims = ApprovalTicketClaims(
        sub=execution_id,
        aud=app_id,
        azp=client_id,
        iat=int(now.timestamp()),
        nbf=int(now.timestamp()),
        exp=int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        jti=str(uuid.uuid4()),
        tenant_id=tenant_id,
        plugin_id=plugin_id,
        policy=policy,
        decision=decision,
        action_type=action_type,
        payload_hash=hash_payload(actionable_payload),
        required_role=required_role,
        user_id=user_id,
        agent_id=agent_id,
    )
    token = jwt.encode(
        claims.model_dump(exclude_none=True),
        key_manager.private_key,
        algorithm="RS256",
        headers={"kid": key_manager.kid, "typ": APPROVAL_TICKET_TYP},
    )
    return ApprovalChallenge(ticket=token, ticket_id=claims.jti, required_role=required_role, expires_at=claims.exp)


def verify_approval_ticket(token: str) -> ApprovalTicketClaims:
    """Check that AXG issued this ticket (current or retired key) and that it is still valid."""
    try:
        header = jwt.get_unverified_header(token)
        if header.get("typ") != APPROVAL_TICKET_TYP:
            raise ApprovalTicketError("Not an approval ticket")
        key = key_manager.verification_key(header.get("kid"))
        if key is None:
            raise ApprovalTicketError("Unknown signing key")
        claims = jwt.decode(
            token, key, algorithms=["RS256"], issuer=ISSUER,
            options={"require": ["exp", "nbf", "jti"], "verify_aud": False},
        )
        return ApprovalTicketClaims.model_validate(claims)
    except ApprovalTicketError:
        raise
    except Exception as exc:
        raise ApprovalTicketError("Invalid or expired approval ticket") from exc

