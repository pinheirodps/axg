"""Signed context: facts that trusted services vouch for, so policies do not have to trust the caller.

A request's ``context`` is whatever the caller says. When a rule depends on a fact the caller could
misreport (a balance, a monthly total, an account status), the service that owns the fact signs it
as a short-lived JWT and the caller forwards it in ``signed_context``. AXG verifies each token and
exposes its facts to rules as ``verified.<provider>.<fact>``, a namespace callers cannot write to.

Providers are configured through ``AXG_CONTEXT_PROVIDERS`` (JSON list):

    [{"id": "ledger", "issuer": "https://ledger.internal", "jwks_url": "https://ledger.internal/jwks.json",
      "max_age_seconds": 300}]

``public_key`` (PEM) may replace ``jwks_url``. A token must be signed with an asymmetric algorithm
and carry ``iss`` (a configured issuer), ``aud`` (``AXG_CONTEXT_AUDIENCE``, default ``axg``), ``iat``,
``exp``, ``tenant_id`` (the request's tenant), an object ``context`` with the facts, and optionally
``sub`` (then it must be the request's ``user_id``).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

import jwt

logger = logging.getLogger(__name__)

# Asymmetric only: a shared secret would let anyone holding it vouch for facts
ALGORITHMS = ["RS256", "PS256", "ES256", "EdDSA"]
DEFAULT_MAX_AGE_SECONDS = 300
MAX_AGE_LIMIT_SECONDS = 86400
LEEWAY_SECONDS = 30
JWKS_TIMEOUT_SECONDS = 3
PROVIDER_ID = re.compile(r"^[a-z0-9_-]{1,64}$")
REQUIRED_CLAIMS = ["iss", "aud", "iat", "exp", "tenant_id", "context"]


class ContextConfigError(ValueError):
    """Raised when AXG_CONTEXT_PROVIDERS is malformed."""


@dataclass
class ContextProvider:
    id: str
    issuer: str
    max_age_seconds: int
    public_key: str | None = None
    jwks: jwt.PyJWKClient | None = None

    def signing_key(self, token: str) -> Any:
        return self.public_key or self.jwks.get_signing_key_from_jwt(token).key


@dataclass
class VerifiedContext:
    facts: dict[str, dict[str, Any]] = field(default_factory=dict)
    rejected: list[str] = field(default_factory=list)


def _provider(entry: Any) -> ContextProvider:
    if not isinstance(entry, dict):
        raise ContextConfigError("Each context provider must be a JSON object")
    provider_id, issuer = str(entry.get("id", "")), str(entry.get("issuer", "")).strip()
    if not PROVIDER_ID.match(provider_id):
        raise ContextConfigError("A context provider 'id' must be 1-64 characters of a-z, 0-9, '_' or '-'")
    if not issuer:
        raise ContextConfigError(f"Context provider '{provider_id}' needs an 'issuer'")
    max_age = entry.get("max_age_seconds", DEFAULT_MAX_AGE_SECONDS)
    if not isinstance(max_age, int) or not 1 <= max_age <= MAX_AGE_LIMIT_SECONDS:
        raise ContextConfigError(f"Context provider '{provider_id}': max_age_seconds must be 1 to {MAX_AGE_LIMIT_SECONDS}")
    public_key = str(entry.get("public_key") or "").replace("\\n", "\n") or None
    jwks_url = str(entry.get("jwks_url") or "").strip()
    if not public_key and not jwks_url:
        raise ContextConfigError(f"Context provider '{provider_id}' needs 'jwks_url' or 'public_key'")
    jwks = None if public_key else jwt.PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300, timeout=JWKS_TIMEOUT_SECONDS)
    return ContextProvider(provider_id, issuer, max_age, public_key, jwks)


# Keyed by the raw configuration, so JWKS caches survive between requests and reset when it changes
_providers_cache: dict[str, dict[str, ContextProvider]] = {}


def load_providers() -> dict[str, ContextProvider]:
    """Configured providers by issuer."""
    raw = os.environ.get("AXG_CONTEXT_PROVIDERS", "").strip()
    if not raw:
        return {}
    if raw not in _providers_cache:
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ContextConfigError("AXG_CONTEXT_PROVIDERS is not valid JSON") from exc
        if not isinstance(entries, list):
            raise ContextConfigError("AXG_CONTEXT_PROVIDERS must be a JSON list")
        providers = [_provider(entry) for entry in entries]
        by_issuer = {p.issuer: p for p in providers}
        if len(by_issuer) != len(providers) or len({p.id for p in providers}) != len(providers):
            raise ContextConfigError("Context provider ids and issuers must be unique")
        _providers_cache.clear()
        _providers_cache[raw] = by_issuer
    return _providers_cache[raw]


def _verify_token(token: str, providers: dict[str, ContextProvider], tenant_id: str, user_id: str | None,
                  audience: str) -> tuple[ContextProvider, dict[str, Any]]:
    """The provider and claims of a valid token; raises ValueError with a loggable reason otherwise."""
    try:
        issuer = jwt.decode(token, options={"verify_signature": False}).get("iss")
    except jwt.PyJWTError as exc:
        raise ValueError("malformed token") from exc
    provider = providers.get(issuer) if isinstance(issuer, str) else None
    if provider is None:
        raise ValueError("unknown issuer")
    try:
        claims = jwt.decode(
            token, provider.signing_key(token), algorithms=ALGORITHMS, audience=audience, issuer=provider.issuer,
            leeway=LEEWAY_SECONDS, options={"require": REQUIRED_CLAIMS},
        )
    except (jwt.PyJWTError, ValueError) as exc:
        raise ValueError(f"{provider.id}: {type(exc).__name__}") from exc
    if time.time() - claims["iat"] > provider.max_age_seconds + LEEWAY_SECONDS:
        raise ValueError(f"{provider.id}: too old")
    if claims["tenant_id"] != tenant_id:
        raise ValueError(f"{provider.id}: another tenant")
    if "sub" in claims and claims["sub"] != user_id:
        raise ValueError(f"{provider.id}: another user")
    if not isinstance(claims["context"], dict):
        raise ValueError(f"{provider.id}: context is not an object")
    return provider, claims


def verify_signed_context(tokens: list[str], tenant_id: str, user_id: str | None) -> VerifiedContext:
    """Verify every token; facts of valid ones by provider id, and why the others were rejected.

    Blocking (a JWKS may be fetched): the engine calls it off the event loop.
    """
    result = VerifiedContext()
    if not tokens:
        return result
    try:
        providers = load_providers()
    except ContextConfigError as exc:
        logger.error("AXG signed context disabled: %s", exc)
        result.rejected = ["provider configuration invalid"] * len(tokens)
        return result
    audience = os.environ.get("AXG_CONTEXT_AUDIENCE", "axg").strip() or "axg"
    for token in tokens:
        try:
            provider, claims = _verify_token(token, providers, tenant_id, user_id, audience)
        except ValueError as exc:
            result.rejected.append(str(exc))
            continue
        if provider.id in result.facts:
            result.rejected.append(f"{provider.id}: duplicate")
            continue
        result.facts[provider.id] = claims["context"]
    if result.rejected:
        logger.warning("AXG rejected signed context: %s", "; ".join(result.rejected))
    return result
