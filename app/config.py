"""Runtime settings, read from environment variables (see .env.example)."""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# Scope name exposed by the Entra app registration ("Expose an API").
SCOPE_NAME = "mcp.access"


@dataclass(frozen=True)
class Settings:
    tenant_id: str
    client_id: str
    app_id_uri: str
    public_base_url: str = "http://localhost:8000"
    authority: str = "https://login.microsoftonline.com"
    db_path: str = "/data/jit.db"
    policy_path: str = "policy.yaml"
    session_secret: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    extra_issuers: tuple[str, ...] = ()

    # ---- derived values -------------------------------------------------
    @property
    def resource_url(self) -> str:
        """The MCP endpoint; also the RFC 9728 protected-resource identifier."""
        return f"{self.public_base_url.rstrip('/')}/mcp"

    @property
    def redirect_uri(self) -> str:
        """Redirect URI for the approval page sign-in (register it in Entra)."""
        return f"{self.public_base_url.rstrip('/')}/auth/callback"

    @property
    def full_scope(self) -> str:
        return f"{self.app_id_uri}/{SCOPE_NAME}"

    @property
    def v2_issuer(self) -> str:
        return f"{self.authority.rstrip('/')}/{self.tenant_id}/v2.0"

    @property
    def accepted_issuers(self) -> list[str]:
        # Entra issues v1 tokens (sts.windows.net) unless the app manifest sets
        # requestedAccessTokenVersion=2, so accept both shapes for this tenant.
        return [self.v2_issuer, f"https://sts.windows.net/{self.tenant_id}/", *self.extra_issuers]

    @property
    def accepted_audiences(self) -> list[str]:
        # v1 tokens carry the App ID URI as aud, v2 tokens carry the client ID.
        return [self.app_id_uri, self.client_id]

    @property
    def authorize_endpoint(self) -> str:
        return f"{self.authority.rstrip('/')}/{self.tenant_id}/oauth2/v2.0/authorize"

    @property
    def token_endpoint(self) -> str:
        return f"{self.authority.rstrip('/')}/{self.tenant_id}/oauth2/v2.0/token"

    @property
    def jwks_uri(self) -> str:
        return f"{self.authority.rstrip('/')}/{self.tenant_id}/discovery/v2.0/keys"

    @property
    def allowed_hosts(self) -> list[str]:
        host = urlparse(self.public_base_url).hostname or "localhost"
        hosts = {host, "localhost", "127.0.0.1"}
        return sorted(f"{h}:*" for h in hosts) + sorted(hosts)

    @property
    def allowed_origins(self) -> list[str]:
        return [f"http://{h}" for h in self.allowed_hosts] + [f"https://{h}" for h in self.allowed_hosts]

    @property
    def secure_cookies(self) -> bool:
        return self.public_base_url.startswith("https://")


def load_settings() -> Settings:
    tenant = os.environ.get("ENTRA_TENANT_ID", "").strip()
    client = os.environ.get("ENTRA_CLIENT_ID", "").strip()
    if not tenant or not client:
        raise RuntimeError("ENTRA_TENANT_ID and ENTRA_CLIENT_ID must be set (copy .env.example to .env).")

    secret = os.environ.get("SESSION_SECRET", "").strip()
    if not secret:
        log.warning("SESSION_SECRET not set; using a random one (approval-page sign-ins reset on restart).")
        secret = secrets.token_urlsafe(32)

    extra = tuple(i.strip() for i in os.environ.get("ENTRA_EXTRA_ISSUERS", "").split(",") if i.strip())

    return Settings(
        tenant_id=tenant,
        client_id=client,
        app_id_uri=os.environ.get("ENTRA_APP_ID_URI", "").strip() or f"api://{client}",
        public_base_url=os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000").strip(),
        authority=os.environ.get("ENTRA_AUTHORITY", "https://login.microsoftonline.com").strip(),
        db_path=os.environ.get("DB_PATH", "/data/jit.db"),
        policy_path=os.environ.get("POLICY_FILE", "policy.yaml"),
        session_secret=secret,
        extra_issuers=extra,
    )
