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
    # "env"     — local dev only: shared token from EASYDMARC_API_TOKEN env var (not SOP-compliant)
    auth_mode: Literal["env", "gateway"] = "gateway"

    # EasyDMARC credentials (only required in env mode)
    easydmarc_api_token: str | None = None
    easydmarc_base_url: str = "https://api.easydmarc.com"

    # Header name used to pass the token in gateway mode.
    # The client must include this header on every /mcp request.
    easydmarc_auth_header: str = "X-EasyDMARC-Token"

    @property
    def has_credentials(self) -> bool:
        """Returns True if the server can serve API calls.

        Gateway mode always returns True — each request carries its own token.
        Env mode requires EASYDMARC_API_TOKEN to be set.
        """
        if self.auth_mode == "gateway":
            return True
        return self.easydmarc_api_token is not None


def get_settings() -> Settings:
    return Settings()
