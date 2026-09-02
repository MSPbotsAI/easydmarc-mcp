import contextvars
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .api_client import EasyDMARCClient
from .config import Settings

# Per-request credential isolation via contextvars.
# GatewayTokenMiddleware sets this before the MCP handler runs.
# Python asyncio copies context per task, so concurrent SSE connections are isolated.
#
# Holds (client_id, client_secret) — NOT a bearer token. EasyDMARC's own
# access tokens expire in ~5 minutes with no refresh (see api_client.py's
# EasyDMARCClient docstring), which doesn't fit the platform's "operator
# fills in credentials once, they're reused indefinitely" model. The
# client_id/client_secret pair is EasyDMARC's actual long-lived credential;
# EasyDMARCClient exchanges it for a fresh token on every call instead.
_gateway_creds_var: contextvars.ContextVar[tuple[str, str] | None] = contextvars.ContextVar(
    "easydmarc_gateway_creds", default=None
)


def get_client_from_context(settings: Settings) -> EasyDMARCClient | None:
    """Resolve the active EasyDMARCClient for the current request context."""
    if settings.auth_mode == "gateway":
        creds = _gateway_creds_var.get()
    else:
        creds = (
            (settings.easydmarc_client_id, settings.easydmarc_client_secret)
            if settings.easydmarc_client_id and settings.easydmarc_client_secret
            else None
        )

    if not creds:
        return None
    client_id, client_secret = creds
    return EasyDMARCClient(client_id, client_secret, settings.easydmarc_base_url)


class GatewayTokenMiddleware:
    """ASGI middleware.

    Reads the configured client-id/client-secret headers (default
    X-EasyDMARC-Client-Id / X-EasyDMARC-Client-Secret) from each request and
    stores the pair in the contextvar for the duration of that request.
    Returns 401 if either header is missing on /mcp requests.
    """

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        # Header lookup is case-insensitive in Starlette.
        client_id = request.headers.get(self.settings.easydmarc_client_id_header.lower())
        client_secret = request.headers.get(self.settings.easydmarc_client_secret_header.lower())
        if not client_id or not client_secret:
            required = [
                self.settings.easydmarc_client_id_header,
                self.settings.easydmarc_client_secret_header,
            ]
            response = JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": f"This server requires the {', '.join(required)} headers",
                    "required_headers": required,
                    "optional_headers": [],
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        ctx_token = _gateway_creds_var.set((client_id, client_secret))
        try:
            await self.app(scope, receive, send)
        finally:
            _gateway_creds_var.reset(ctx_token)


def create_mcp_server(settings: Settings) -> FastMCP:
    """Build the FastMCP server instance and register all EasyDMARC tools."""
    # DNS-rebinding protection is a browser-oriented safeguard that rejects
    # non-localhost Host headers with 421. Disable it so the server works
    # correctly behind a reverse proxy or docker network.
    mcp = FastMCP(
        name="easydmarc-mcp",
        instructions=(
            "EasyDMARC is an email authentication / anti-phishing platform: it "
            "monitors a domain's DMARC/SPF/DKIM/BIMI/MTA-STS/TLS-RPT DNS setup and "
            "aggregates the DMARC reports mailbox providers send back, so an MSP "
            "can see whether a client domain is protected against spoofing and "
            "fix misconfigurations. This server is a partner/MSP-tenant API: most "
            "calls are scoped to one client organization, so the typical flow is "
            "easydmarc_list_organizations to find the org_id, then "
            "easydmarc_list_domains(organization_id=...) to find a domain. Tool "
            "groups: easydmarc_*_domain(s) manage which domains are onboarded and "
            "their DMARC policy type; easydmarc_lookup_* run a live DNS lookup "
            "against a domain's current DMARC/SPF/DKIM/BIMI/MTA-STS/TLS-RPT "
            "records (point-in-time DNS check, not historical data); "
            "easydmarc_get_rua_* read aggregate (RUA) DMARC reports — volume, "
            "pass-rate, and raw report history already ingested by EasyDMARC; "
            "easydmarc_get_failure_reports/aggregates read forensic (RUF) "
            "failure reports naming specific senders/IPs that failed "
            "authentication. RUA/RUF tools are read-only history, not live "
            "checks. easydmarc_delete_domain is destructive and irreversible — "
            "requires confirm=true."
        ),
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    client_factory: Callable[[], EasyDMARCClient | None] = lambda: get_client_from_context(  # noqa: E731
        settings
    )

    if not settings.has_credentials:
        # Graceful degradation: register only a diagnostic tool when no credentials are available.
        @mcp.tool()
        async def easydmarc_test_connection() -> str:
            """Test EasyDMARC API connection.

            Shows configuration requirements when credentials are missing.
            """
            return (
                "Error: Missing EasyDMARC credentials.\n\n"
                "Set the required environment variables:\n"
                "  EASYDMARC_CLIENT_ID=your_client_id_here\n"
                "  EASYDMARC_CLIENT_SECRET=your_client_secret_here\n\n"
                "Or use gateway mode (per-request credentials):\n"
                "  AUTH_MODE=gateway\n"
                f"  Send headers: {settings.easydmarc_client_id_header}, "
                f"{settings.easydmarc_client_secret_header}"
            )

        return mcp

    from .tools import dns_lookup, domains, failure_reports, organizations, reports

    organizations.register(mcp, client_factory)
    domains.register(mcp, client_factory)
    dns_lookup.register(mcp, client_factory)
    reports.register(mcp, client_factory)
    failure_reports.register(mcp, client_factory)

    return mcp
