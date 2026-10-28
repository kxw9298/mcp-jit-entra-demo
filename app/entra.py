"""Microsoft Entra ID token validation.

Two kinds of token are checked here:

* Access tokens sent by the MCP client (Claude Code) as `Authorization: Bearer`.
  They must be issued by this tenant, for this API (audience), contain the
  `mcp.access` delegated scope, and be signed by a key from Entra's JWKS.
* ID tokens returned to the approval page after a user signs in.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import anyio
import jwt
from jwt import PyJWKClient

from mcp.server.auth.provider import AccessToken

from .config import SCOPE_NAME, Settings

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Principal:
    """The human the request is acting for."""

    oid: str
    name: str
    username: str
    tenant_id: str
    client_app: str | None = None  # the OAuth client that obtained the token (e.g. Azure CLI)

    @property
    def label(self) -> str:
        return f"{self.name} <{self.username}>" if self.username and self.username != self.name else self.name

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> "Principal":
        username = (
            claims.get("preferred_username")
            or claims.get("upn")
            or claims.get("email")
            or claims.get("unique_name", "").split("#")[-1]
            or ""
        )
        return cls(
            oid=claims["oid"],
            name=claims.get("name") or username or claims["oid"],
            username=username,
            tenant_id=claims.get("tid", ""),
            client_app=claims.get("azp") or claims.get("appid"),
        )


class EntraValidator:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._jwks = PyJWKClient(settings.jwks_uri, cache_keys=True, lifespan=3600)

    async def _signing_key(self, token: str):
        # PyJWKClient uses blocking urllib; keep it off the event loop.
        return await anyio.to_thread.run_sync(self._jwks.get_signing_key_from_jwt, token)

    async def validate_access_token(self, token: str) -> dict[str, Any]:
        key = await self._signing_key(token)
        claims = jwt.decode(
            token,
            key.key,
            algorithms=["RS256"],
            audience=self.settings.accepted_audiences,
            options={"require": ["exp", "iat", "iss", "aud", "oid", "tid"], "verify_iss": False},
            leeway=60,
        )
        if claims["iss"] not in self.settings.accepted_issuers:
            raise jwt.InvalidIssuerError(f"untrusted issuer {claims['iss']}")
        if claims["tid"] != self.settings.tenant_id:
            raise jwt.InvalidTokenError("token is from another tenant")
        if "scp" not in claims:
            # App-only tokens carry `roles`, not `scp`; this demo is for delegated (user) access only.
            raise jwt.InvalidTokenError("not a delegated user token (no scp claim)")
        return claims

    async def validate_id_token(self, token: str, nonce: str) -> dict[str, Any]:
        key = await self._signing_key(token)
        claims = jwt.decode(
            token,
            key.key,
            algorithms=["RS256"],
            audience=self.settings.client_id,
            issuer=self.settings.v2_issuer,
            options={"require": ["exp", "iat", "iss", "aud", "oid", "nonce"]},
            leeway=60,
        )
        if claims.get("nonce") != nonce:
            raise jwt.InvalidTokenError("nonce mismatch")
        if claims.get("tid") != self.settings.tenant_id:
            raise jwt.InvalidTokenError("user is from another tenant")
        return claims


class EntraTokenVerifier:
    """MCP SDK TokenVerifier backed by Entra ID."""

    def __init__(self, validator: EntraValidator):
        self.validator = validator
        self.settings = validator.settings

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = await self.validator.validate_access_token(token)
        except Exception as exc:  # any failure means "not authenticated"
            log.info("rejected bearer token: %s", exc)
            return None
        # Report scopes in full `api://<app>/mcp.access` form, matching what the
        # protected-resource metadata advertises and what AuthSettings requires.
        scopes = [f"{self.settings.app_id_uri}/{s}" for s in claims.get("scp", "").split()]
        return AccessToken(
            token=token,
            client_id=claims.get("azp") or claims.get("appid") or "unknown",
            scopes=scopes,
            expires_at=int(claims["exp"]),
            resource=self.settings.resource_url,
            subject=claims["oid"],
            claims=claims,
        )


__all__ = ["EntraTokenVerifier", "EntraValidator", "Principal", "SCOPE_NAME"]
