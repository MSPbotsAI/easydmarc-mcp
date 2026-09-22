"""tools/list snapshot + error-envelope mapping tests.

No network calls: tool enumeration goes through FastMCP's in-process
list_tools(), and the error-code mapping is tested directly against
EasyDMARCError, independent of any real HTTP request.
"""

import pytest

from easydmarc_mcp.api_client import EasyDMARCError
from easydmarc_mcp.config import Settings
from easydmarc_mcp.server import create_mcp_server

# name -> (required params, expected annotation hint set to True)
EXPECTED_TOOLS = {
    # organizations
    "easydmarc_list_organizations": (set(), {"readOnlyHint"}),
    "easydmarc_get_organization": ({"organization_id"}, {"readOnlyHint"}),
    # domains
    "easydmarc_list_domains": ({"organization_id"}, {"readOnlyHint"}),
    "easydmarc_get_domains_overview": (
        {"organization_id", "start_date", "end_date"},
        {"readOnlyHint"},
    ),
    "easydmarc_get_domain": ({"organization_id", "domain"}, {"readOnlyHint"}),
    "easydmarc_create_domain": ({"organization_id", "domain"}, set()),
    "easydmarc_update_domain": ({"domain"}, {"idempotentHint"}),
    "easydmarc_delete_domain": (
        {"organization_id", "domain"},
        {"destructiveHint", "idempotentHint"},
    ),
    "easydmarc_get_domain_setup": (
        {"organization_id", "domain", "record_type"},
        {"readOnlyHint"},
    ),
    "easydmarc_verify_domain_setup": ({"domain"}, set()),
    # dns lookup
    "easydmarc_lookup_dmarc": ({"domain"}, {"readOnlyHint"}),
    "easydmarc_lookup_spf": ({"domain"}, {"readOnlyHint"}),
    "easydmarc_lookup_spf_result": ({"domain"}, {"readOnlyHint"}),
    "easydmarc_lookup_dkim": ({"domain", "selectors"}, {"readOnlyHint"}),
    "easydmarc_lookup_bimi": ({"domain"}, {"readOnlyHint"}),
    "easydmarc_lookup_tls_rpt": ({"domain"}, {"readOnlyHint"}),
    "easydmarc_lookup_mta_sts": ({"domain"}, {"readOnlyHint"}),
    # rua reports
    "easydmarc_get_rua_reports": (
        {"organization_id", "domain_names", "report_type", "date_from", "date_to"},
        {"readOnlyHint"},
    ),
    "easydmarc_get_rua_report": ({"organization_id", "report_id"}, {"readOnlyHint"}),
    "easydmarc_get_rua_auth_pass_rates": (
        {"organization_id", "domains_with_report_types", "date_from", "date_to"},
        {"readOnlyHint"},
    ),
    "easydmarc_get_rua_volume": (
        {"organization_id", "domains_with_report_types", "date_from", "date_to"},
        {"readOnlyHint"},
    ),
    "easydmarc_get_rua_volume_history": (
        {"organization_id", "domains_with_report_types", "date_from", "date_to"},
        {"readOnlyHint"},
    ),
    # failure reports
    "easydmarc_get_failure_reports": ({"organization_id", "domains"}, {"readOnlyHint"}),
    "easydmarc_get_failure_report": (
        {"organization_id", "report_id"},
        {"readOnlyHint"},
    ),
    "easydmarc_get_failure_report_aggregates": (
        {"organization_id", "domains", "dimensions"},
        {"readOnlyHint"},
    ),
}

# Tools whose docstrings deliberately exceed the SOP's 500-char guideline
# (§2.2, a "should" not a hard rule) because they carry load-bearing
# disambiguation guidance an agent needs to pick the right tool.
_LONG_DESCRIPTION_EXCEPTIONS = {
    "easydmarc_get_domain_setup",
    "easydmarc_verify_domain_setup",
    "easydmarc_lookup_spf",
    "easydmarc_lookup_dkim",
    "easydmarc_get_rua_reports",
}


@pytest.mark.asyncio
async def test_tools_list_snapshot():
    mcp = create_mcp_server(Settings())
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert names == set(EXPECTED_TOOLS), f"unexpected tool set: {names}"
    # Keep the fleet-wide function-declaration budget in mind (see README
    # Known Gaps) — this MCP should stay well under it on its own.
    assert len(names) <= 30

    by_name = {t.name: t for t in tools}
    for name, (expected_required, expected_hints) in EXPECTED_TOOLS.items():
        tool = by_name[name]
        required = set(tool.inputSchema.get("required", []))
        assert required == expected_required, f"{name}: required={required}"

        description = tool.description or ""
        if name not in _LONG_DESCRIPTION_EXCEPTIONS:
            assert len(description) <= 500, f"{name}: description too long ({len(description)})"
        first_line = description.strip().splitlines()[0] if description.strip() else ""
        assert len(first_line) <= 100, f"{name}: first line too long: {first_line!r}"
        assert "GET /" not in description and "POST /" not in description, (
            f"{name}: leaked implementation detail"
        )

        annotations = tool.annotations
        actual_hints = set()
        if annotations is not None:
            for hint in ("readOnlyHint", "destructiveHint", "idempotentHint"):
                if getattr(annotations, hint, None) is True:
                    actual_hints.add(hint)
        assert actual_hints == expected_hints, f"{name}: hints={actual_hints}"


@pytest.mark.asyncio
async def test_service_instructions_present_and_bounded():
    mcp = create_mcp_server(Settings())
    assert mcp.instructions
    assert len(mcp.instructions) <= 1500


@pytest.mark.parametrize(
    "status_code,expected_code,expected_retryable",
    [
        (0, "upstream_error", True),
        (400, "invalid_argument", False),
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (422, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (503, "upstream_error", True),
    ],
)
def test_error_envelope_mapping(status_code, expected_code, expected_retryable):
    import json

    err = EasyDMARCError(status_code, "boom")
    envelope = json.loads(err.to_envelope())
    assert envelope["error"]["code"] == expected_code
    assert envelope["error"]["retryable"] is expected_retryable
    assert envelope["error"]["message"] == "boom"


@pytest.mark.asyncio
async def test_delete_domain_rejects_without_confirm():
    """Destructive confirm gate: calling without confirm=true must never
    reach the HTTP layer — verified via a stub client whose delete() would
    record a call if reached.
    """
    from mcp.server.fastmcp import FastMCP

    from easydmarc_mcp.tools import domains

    captured = {}

    class _StubClient:
        async def delete(self, path, params=None):
            captured["called"] = path
            return {"ok": True}

    mcp = FastMCP(name="test")
    domains.register(mcp, lambda: _StubClient())
    result = await mcp.call_tool(
        "easydmarc_delete_domain",
        {"organization_id": "org_1", "domain": "example.com", "confirm": False},
    )
    content = result[0] if isinstance(result, tuple) else result
    text = content[0].text if isinstance(content, list) else str(content)
    assert "invalid_argument" in text
    assert "called" not in captured


def test_base_url_points_at_the_host_that_serves_the_api():
    """Regression guard for the 404 that made every business tool unusable.

    EasyDMARC serves all 95 documented paths — including /auth/token — from
    api2.easydmarc.com. api.easydmarc.com resolves but has none of the
    routes registered and answers with an Express 404, which this server
    reported as a not_found envelope.
    """
    assert Settings().easydmarc_base_url == "https://api2.easydmarc.com"


@pytest.mark.asyncio
async def test_domains_overview_builds_expected_body():
    """The overview endpoint is a POST whose every input travels in the body.

    Also pins pageSize being sent explicitly: EasyDMARC's own default is 1
    record per page, so omitting it would silently truncate the census.
    """
    from mcp.server.fastmcp import FastMCP

    from easydmarc_mcp.tools import domains

    captured = {}

    class _StubClient:
        async def post(self, path, params=None, json_body=None):
            captured["path"] = path
            captured["body"] = json_body
            return {"data": [], "meta": {"total": 0}}

    mcp = FastMCP(name="test")
    domains.register(mcp, lambda: _StubClient())
    await mcp.call_tool(
        "easydmarc_get_domains_overview",
        {
            "organization_id": "org_1",
            "start_date": "08/01/2026",
            "end_date": "09/01/2026",
        },
    )
    assert captured["path"] == "/v1/domains/overview"
    assert captured["body"] == {
        "organizationId": "org_1",
        "page": 1,
        "pageSize": 20,
        "startDate": "08/01/2026",
        "endDate": "09/01/2026",
    }


@pytest.mark.asyncio
async def test_domains_overview_sends_only_the_documented_body_keys():
    """filters is the only genuinely optional key. startDate/endDate are
    required by EasyDMARC (422 "Start date is required" without them),
    despite its OpenAPI document typing them as plain optional strings.
    """
    from mcp.server.fastmcp import FastMCP

    from easydmarc_mcp.tools import domains

    captured = {}

    class _StubClient:
        async def post(self, path, params=None, json_body=None):
            captured["body"] = json_body
            return {"data": []}

    mcp = FastMCP(name="test")
    domains.register(mcp, lambda: _StubClient())
    await mcp.call_tool(
        "easydmarc_get_domains_overview",
        {"organization_id": "org_1", "start_date": "08/01/2026", "end_date": "09/01/2026"},
    )
    assert set(captured["body"]) == {
        "organizationId",
        "startDate",
        "endDate",
        "page",
        "pageSize",
    }


@pytest.mark.asyncio
async def test_rua_tools_all_send_organization_id():
    """Regression guard for the 422 that made every RUA tool unusable.

    EasyDMARC scopes all /v1/dmarc/rua/* endpoints to an organization and
    answers a request without organizationId with
    422 details=[{property: organizationId}] — regardless of how well-formed
    the rest of the body is. reports.py shipped without the field, so
    easydmarc_get_rua_volume (and its four siblings) failed on every call.
    """
    from mcp.server.fastmcp import FastMCP

    from easydmarc_mcp.tools import reports

    captured = {}

    class _StubClient:
        async def post(self, path, params=None, json_body=None):
            captured[path] = {"body": json_body, "params": params}
            return {"data": [], "meta": {"total": 0}}

        async def get(self, path, params=None):
            captured[path] = {"body": None, "params": params}
            return {"data": {}}

    dates = {"date_from": "2026-08-01T00:00:00.000Z", "date_to": "2026-09-01T00:00:00.000Z"}
    domains_with_types = [{"domainName": "example.com", "reportTypes": ["dmarc-capable"]}]
    calls = [
        ("easydmarc_get_rua_reports",
         {"organization_id": "org_1", "domain_names": ["example.com"],
          "report_type": "dmarc-capable", **dates}),
        ("easydmarc_get_rua_report", {"organization_id": "org_1", "report_id": "uuid-1"}),
        ("easydmarc_get_rua_auth_pass_rates",
         {"organization_id": "org_1", "domains_with_report_types": domains_with_types, **dates}),
        ("easydmarc_get_rua_volume",
         {"organization_id": "org_1", "domains_with_report_types": domains_with_types, **dates}),
        ("easydmarc_get_rua_volume_history",
         {"organization_id": "org_1", "domains_with_report_types": domains_with_types, **dates}),
    ]

    mcp = FastMCP(name="test")
    reports.register(mcp, lambda: _StubClient())
    for name, args in calls:
        captured.clear()
        await mcp.call_tool(name, args)
        assert len(captured) == 1, f"{name}: expected exactly one request, got {list(captured)}"
        path, sent = next(iter(captured.items()))
        # The single-report GET carries it as a query param, the four POSTs
        # in the body — either placement satisfies EasyDMARC.
        where = sent["body"] or sent["params"] or {}
        assert where.get("organizationId") == "org_1", f"{name}: no organizationId in {path}"


def test_error_message_keeps_easydmarc_validation_details():
    """A 422 body's `error` is the bare reason phrase, identical for every
    malformed request; only `details` says what was actually wrong. Folding
    it into the message is what turns an opaque envelope into something an
    agent can fix.
    """
    import httpx

    from easydmarc_mcp.api_client import EasyDMARCClient

    client = EasyDMARCClient("id", "secret", "https://api2.easydmarc.com")
    resp = httpx.Response(
        422,
        json={
            "statusCode": 422,
            "error": "Unprocessable Entity",
            "traceId": "t-1",
            "details": [{"property": "organizationId", "messages": ["Organization ID is required"]}],
        },
    )
    message = client._extract_error(resp)
    assert "Unprocessable Entity" in message
    assert "organizationId" in message
    assert "Organization ID is required" in message


def test_error_message_without_details_is_unchanged():
    import httpx

    from easydmarc_mcp.api_client import EasyDMARCClient

    client = EasyDMARCClient("id", "secret", "https://api2.easydmarc.com")
    resp = httpx.Response(404, json={"message": "Not Found"})
    assert client._extract_error(resp) == "Not Found"
