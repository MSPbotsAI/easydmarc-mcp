from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Transport
    mcp_transport: Literal["stdio", "http"] = "stdio"
    mcp_http_port: int = 8080
    mcp_http_host: str = "0.0.0.0"

    # Auth mode:
    # "gateway" — production/SOP-compliant: token from HTTP header per request (no global state)
    # "env"     — local dev only: shared client_id/secret from env vars (not SOP-compliant)
    auth_mode: Literal["env", "gateway"] = "gateway"

    # EasyDMARC credentials (only required in env mode). These are the
    # long-lived client_id/client_secret pair from EasyDMARC's Account
    # Console (API Client management) — NOT a bearer token. EasyDMARC's
    # access tokens expire in ~5 minutes with no refresh, so this server
    # exchanges client_id/client_secret for a fresh token on every call
    # instead of accepting an already-issued token (see api_client.py).
    easydmarc_client_id: str | None = None
    easydmarc_client_secret: str | None = None
    # EasyDMARC serves the entire public API from api2.easydmarc.com — every
    # one of the 95 paths in the vendor's own OpenAPI document
    # (easydmarc/public-api-docs, specs/easydmarc-openapi.json) declares
    # `servers: https://api2.easydmarc.com`, including /auth/token. The
    # api.easydmarc.com host answers, but has none of these routes registered
    # and returns an Express 404 ("Cannot GET /v1/organizations") for all of
    # them — which this server previously surfaced as a not_found envelope.
    easydmarc_base_url: str = "https://api2.easydmarc.com"

    # Header names used to pass client_id/client_secret in gateway mode.
    # The client must include both headers on every /mcp request.
    easydmarc_client_id_header: str = "X-EasyDMARC-Client-Id"
    easydmarc_client_secret_header: str = "X-EasyDMARC-Client-Secret"

    @property
    def has_credentials(self) -> bool:
        """Returns True if the server can serve API calls.

        Gateway mode always returns True — each request carries its own
        credentials. Env mode requires both EASYDMARC_CLIENT_ID and
        EASYDMARC_CLIENT_SECRET to be set.
        """
        if self.auth_mode == "gateway":
            return True
        return bool(self.easydmarc_client_id and self.easydmarc_client_secret)


def get_settings() -> Settings:
    return Settings()
