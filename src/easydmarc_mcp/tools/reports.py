"""Aggregate (RUA) DMARC report tools — read-only history already ingested
by EasyDMARC from mailbox providers, not live DNS checks.

Verified against EasyDMARC's own published OpenAPI spec
(github.com/easydmarc/public-api-docs, specs/easydmarc-openapi.json,
checked 2026-08-28). Scope note: the spec's rua/aggregations and
rua/properties endpoints are intentionally out of scope for this build —
they overlap with rua/auth-pass-rates and rua/volume for the same
underlying data, sliced differently; see README Known Gaps. The `filters`
advanced-query object (an EasyDMARC-defined operator DSL keyed by field
name — eq/ne/in/nin/gt/lt/etc.) is accepted as a raw passthrough dict
rather than fully modeled — EasyDMARC's own API validates it and returns a
structured 400 on a bad shape.
"""

from collections.abc import Callable
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import EasyDMARCClient, EasyDMARCError
from ._common import NO_TOKEN

_REPORT_TYPE_DESC = (
    '"dmarc-capable" — sender supports DMARC evaluation; "non-compliant" — '
    "failed DMARC and was not quarantined/rejected; \"threat-unknown\" — "
    'suspicious, not attributable to a known sender; "forwarded" — passed '
    "through an intermediary (mailing list, forwarder)."
)
_DATE_DESC = "ISO 8601 timestamp, e.g. \"2026-08-01T00:00:00.000Z\"."
_FILTERS_DESC = (
    "Optional advanced filter object, keyed by field name, each value "
    'shaped {"name": <field>, "type": "eq"|"ne"|"in"|"nin"|"nset"|"sw"|'
    '"ew"|"sin"|"range"|"gt"|"gte"|"lt"|"lte", "value": <match value>}. '
    "Not validated by this tool's schema — EasyDMARC's own API validates "
    "the shape and returns a structured error on a bad filter. Omit if you "
    "don't need filtering beyond domain/reportType/dateRange."
)
_DOMAINS_WITH_TYPES_DESC = (
    'Array of {"domainName": <fqdn>, "reportTypes": [<report type>, ...]} '
    "— one entry per domain, each with its own list of report types to "
    "include. reportTypes values: dmarc-capable, non-compliant, "
    "threat-unknown, forwarded. At least one entry required."
)

# The DMARC report field taxonomy shared by properties/groupByFields/
# orderFields across every RUA analytics endpoint below (verified against
# the OpenAPI spec's shared enum for these three parameters).
_RuaField = Literal[
    "uuid", "object_id", "temp_id", "dmarc_file", "report_id", "report_type",
    "explicit_report_type", "policy_domain", "start_date", "end_date", "report_date",
    "created_at", "updated_at", "count", "disposition", "country_code", "email",
    "header_from", "envelope_from", "envelope_to", "fo", "inbox_email", "location",
    "org_domain", "org_name", "pct", "policy_p", "policy_sp", "ptr", "ptr_group",
    "reason_comment", "reason_type", "sender_domain", "source_ip", "source_ip_str",
    "spf", "aspf", "spf_auth_root_domain", "spf_auth_domain", "spf_auth_scope",
    "spf_auth_result", "spf_auth_is_aligned", "spf_auth_is_ptr_aligned", "dkim", "adkim",
    "dkim_auth.root_domain", "dkim_auth.domain", "dkim_auth.selector", "dkim_auth.result",
    "dkim_auth.human_result", "dkim_auth.is_aligned", "dkim_auth.is_ptr_aligned",
    "dkim_results_length", "blacklisteds",
]  # fmt: skip


def register(mcp: FastMCP, client_factory: Callable[[], EasyDMARCClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_get_rua_reports(
        domain_names: Annotated[list[str], Field(description="Fully qualified domain names to include.")],
        report_type: Annotated[
            Literal["dmarc-capable", "non-compliant", "threat-unknown", "forwarded"],
            Field(description=_REPORT_TYPE_DESC),
        ],
        date_from: Annotated[str, Field(description=_DATE_DESC)],
        date_to: Annotated[str, Field(description=_DATE_DESC)],
        properties: Annotated[
            list[_RuaField] | None,
            Field(description="Optional subset of fields to return per report; omit for all fields."),
        ] = None,
        page: Annotated[int, Field(description="Page number, 1-based.", ge=1)] = 1,
        page_size: Annotated[
            int, Field(description="Records per page (max 10000).", ge=1, le=10000)
        ] = 1000,
        filters: Annotated[dict | None, Field(description=_FILTERS_DESC)] = None,
    ) -> str:
        """List raw parsed RUA (aggregate) DMARC reports for one or more
        domains, within a date range. Each row is one report entry (source
        IP + auth results), not a summary — for pre-aggregated pass-rate or
        volume numbers, use easydmarc_get_rua_auth_pass_rates or
        easydmarc_get_rua_volume instead, which are cheaper for "how well
        is this domain doing" style questions.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        body: dict = {
            "domainNames": domain_names,
            "reportType": report_type,
            "dateRange": {"from": date_from, "to": date_to},
            "filters": filters or {},
            "page": page,
            "pageSize": page_size,
        }
        if properties is not None:
            body["properties"] = properties
        try:
            result = await client.post("/v1/dmarc/rua/reports", json_body=body)
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_get_rua_report(
        report_id: Annotated[
            str, Field(description="UUID of the RUA report — resolve via easydmarc_get_rua_reports first.")
        ],
    ) -> str:
        """Get one parsed RUA (aggregate) DMARC report by its UUID —
        complete authentication results, policy info, and source details.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/v1/dmarc/rua/reports/{report_id}")
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_get_rua_auth_pass_rates(
        domains_with_report_types: Annotated[list[dict], Field(description=_DOMAINS_WITH_TYPES_DESC)],
        date_from: Annotated[str, Field(description=_DATE_DESC)],
        date_to: Annotated[str, Field(description=_DATE_DESC)],
        page: Annotated[int, Field(description="Page number, 1-based.", ge=1)] = 1,
        page_size: Annotated[
            int, Field(description="Records per page (max 100).", ge=1, le=100)
        ] = 100,
        filters: Annotated[dict | None, Field(description=_FILTERS_DESC)] = None,
    ) -> str:
        """Get SPF/DKIM authentication pass-rate percentages for domains
        over a date range — the standard "is this domain's DMARC
        compliance improving" report.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        body: dict = {
            "domainsWithReportTypes": domains_with_report_types,
            "dateRange": {"from": date_from, "to": date_to},
            "filters": filters or {},
            "page": page,
            "pageSize": page_size,
        }
        try:
            result = await client.post("/v1/dmarc/rua/auth-pass-rates", json_body=body)
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_get_rua_volume(
        domains_with_report_types: Annotated[list[dict], Field(description=_DOMAINS_WITH_TYPES_DESC)],
        date_from: Annotated[str, Field(description=_DATE_DESC)],
        date_to: Annotated[str, Field(description=_DATE_DESC)],
        group_by_fields: Annotated[
            list[_RuaField] | None,
            Field(description='Fields to group volume counts by (default ["policy_domain"]).'),
        ] = None,
        page: Annotated[int, Field(description="Page number, 1-based.", ge=1)] = 1,
        page_size: Annotated[
            int, Field(description="Records per page (max 100).", ge=1, le=100)
        ] = 100,
        filters: Annotated[dict | None, Field(description=_FILTERS_DESC)] = None,
    ) -> str:
        """Get total email volume for domains over a date range, grouped by
        a field (defaults to per-domain). Use for "how much mail did we get
        reports for" — not per-message detail, aggregate counts only.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        body: dict = {
            "domainsWithReportTypes": domains_with_report_types,
            "dateRange": {"from": date_from, "to": date_to},
            "filters": filters or {},
            "page": page,
            "pageSize": page_size,
        }
        if group_by_fields is not None:
            body["groupByFields"] = group_by_fields
        try:
            result = await client.post("/v1/dmarc/rua/volume", json_body=body)
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_get_rua_volume_history(
        domains_with_report_types: Annotated[list[dict], Field(description=_DOMAINS_WITH_TYPES_DESC)],
        date_from: Annotated[str, Field(description=_DATE_DESC)],
        date_to: Annotated[str, Field(description=_DATE_DESC)],
        period: Annotated[
            Literal["day", "week", "month"], Field(description="Time bucket size for the series.")
        ] = "day",
        group_by_fields: Annotated[
            list[_RuaField] | None,
            Field(description='Fields to group each period\'s volume by (default ["policy_domain"]).'),
        ] = None,
        page: Annotated[int, Field(description="Page number, 1-based.", ge=1)] = 1,
        page_size: Annotated[int, Field(description="Records per page.", ge=1)] = 100,
        filters: Annotated[dict | None, Field(description=_FILTERS_DESC)] = None,
    ) -> str:
        """Get email volume as a time series (day/week/month buckets) for
        domains over a date range — use for trend questions like "is
        volume from this sender increasing" rather than a single total.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        body: dict = {
            "domainsWithReportTypes": domains_with_report_types,
            "dateRange": {"from": date_from, "to": date_to},
            "period": period,
            "filters": filters or {},
            "page": page,
            "pageSize": page_size,
        }
        if group_by_fields is not None:
            body["groupByFields"] = group_by_fields
        try:
            result = await client.post("/v1/dmarc/rua/volume-history", json_body=body)
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()
