import asyncio
from typing import Any

import httpx

from ._json import error_envelope

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_MAX_BACKOFF_SECONDS = 20.0

# The token endpoint lives on a different host than the resource API itself
# — confirmed by the `servers` override on the /auth/token path in
# EasyDMARC's own OpenAPI spec (easydmarc/public-api-docs), not a guess.
_AUTH_URL = "https://api2.easydmarc.com/auth/token"

# One shared connection pool for the process lifetime. No credentials are
# ever stored on it — client_id/client_secret are passed per-call and used
# only to perform a fresh token exchange for that call (see
# EasyDMARCClient._login), and the resulting bearer token is attached
# per-request via a header rather than carried as client-level state. This
# makes sharing the pool across tenants/requests safe (see server.py's
# contextvar-based credential isolation, which is what actually keeps
# tenants apart).
_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True)
    return _http_client


# status_code -> (error code, retryable). status_code 0 means a network/
# connection-level failure (no response at all).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def _classify(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    return "invalid_argument", False


class EasyDMARCError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"EasyDMARC API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = _classify(self.status_code)
        return error_envelope(code, self.message, retryable)


class EasyDMARCClient:
    """Async httpx client wrapping the EasyDMARC public REST API (v1).

    Reuses the module-level connection pool (see _get_http_client) across
    every call made through this instance, rather than opening a new
    connection per request.

    Auth: EasyDMARC's `POST /auth/token` (client_credentials-shaped, per its
    own OpenAPI spec — `AuthTokenRequest`/`AuthTokenResponse`) exchanges a
    long-lived client_id/client_secret pair for a bearer access token good
    for `expires_in` seconds (300 in EasyDMARC's own documented example) —
    and `refresh_expires_in` is documented as *always 0*: EasyDMARC does not
    support refreshing a token, only re-requesting a new one. A ~5-minute
    token cannot be the thing an operator pastes into the platform once and
    reuses indefinitely (every tool call would 401 shortly after setup); the
    client_id/client_secret pair is the actual long-lived credential, so
    that's what this server accepts and stores. This client deliberately
    never caches the resulting token: every call performs a fresh exchange
    and discards it afterward, trading one extra HTTP round trip per call
    for full statelessness (same "re-login every call" pattern as
    oitvoip-mcp/ingrammicro-mcp/action1-mcp) — a cached token would also
    have to be keyed per-tenant to avoid leaking one tenant's token to
    another's request, which a stateless per-call exchange sidesteps
    entirely.
    """

    def __init__(self, client_id: str, client_secret: str, base_url: str):
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url.rstrip("/")

    async def _login(self) -> str:
        client = _get_http_client()
        try:
            resp = await client.post(
                _AUTH_URL,
                data={"client_id": self._client_id, "client_secret": self._client_secret},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
        except httpx.RequestError as e:
            raise EasyDMARCError(0, f"{e or type(e).__name__} (token exchange)") from e

        if resp.status_code >= 400:
            raise EasyDMARCError(resp.status_code, self._extract_error(resp))
        body = self._parse_body(resp)
        token = (body or {}).get("access_token") if isinstance(body, dict) else None
        if not token:
            raise EasyDMARCError(0, "Token exchange succeeded but response had no access_token")
        return token

    def _clean_params(self, params: dict | None) -> dict:
        if not params:
            return {}
        return {k: v for k, v in params.items() if v is not None}

    async def get(self, path: str, params: dict | None = None) -> Any:
        return await self._request("GET", path, params=params)

    async def post(self, path: str, params: dict | None = None, json_body: Any = None) -> Any:
        return await self._request("POST", path, params=params, json_body=json_body)

    async def patch(self, path: str, json_body: Any = None) -> Any:
        return await self._request("PATCH", path, json_body=json_body)

    async def delete(self, path: str, params: dict | None = None) -> Any:
        return await self._request("DELETE", path, params=params)

    async def _request(
        self, method: str, path: str, params: dict | None = None, json_body: Any = None
    ) -> Any:
        token = await self._login()
        client = _get_http_client()
        url = f"{self._base_url}{path}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        params = self._clean_params(params)

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = await client.request(
                    method, url, headers=headers, params=params, json=json_body
                )
            except httpx.RequestError as e:
                last_exc = e
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(min(2**attempt, _MAX_BACKOFF_SECONDS))
                    continue
                raise EasyDMARCError(0, f"{e or type(e).__name__} (url={url})") from e

            if resp.status_code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                delay = self._retry_delay(resp, attempt)
                await asyncio.sleep(delay)
                continue

            self._raise_for_status(resp)
            return self._parse_body(resp)

        # Unreachable in practice (loop always returns or raises above), but
        # keeps type checkers happy and guards against future edits.
        if last_exc:
            raise EasyDMARCError(0, f"{last_exc}") from last_exc
        raise EasyDMARCError(0, "request failed with no response")

    def _retry_delay(self, resp: httpx.Response, attempt: int) -> float:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), _MAX_BACKOFF_SECONDS)
            except ValueError:
                pass
        return min(2**attempt, _MAX_BACKOFF_SECONDS)

    def _parse_body(self, resp: httpx.Response) -> Any:
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw_response": resp.text}

    def _extract_error(self, resp: httpx.Response) -> str:
        try:
            detail = resp.json()
            if isinstance(detail, dict):
                return str(detail.get("message") or detail.get("error") or detail)
            return str(detail)
        except ValueError:
            return resp.text

    def _raise_for_status(self, resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            raise EasyDMARCError(resp.status_code, self._extract_error(resp))
