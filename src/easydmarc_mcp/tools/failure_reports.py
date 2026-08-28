"""Failure (RUF / forensic) DMARC report tools — read-only history of
individual messages that failed authentication, naming the specific
sender/IP involved. Complements the aggregate (RUA) reports in reports.py,
which summarize pass/fail counts without per-message detail.

Verified against EasyDMARC's own published OpenAPI spec
(github.com/easydmarc/public-api-docs, specs/easydmarc-openapi.json,
checked 2026-08-28). Binary download endpoints (raw .eml / attachment /
attachments-as-zip) are out of scope — this MCP returns JSON only, not file
downloads; see README Known Gaps.
"""

from collections.abc import Callable
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import EasyDMARCClient, EasyDMARCError
from ._common import NO_TOKEN

_ORG_ID_DESC = (
    'Organization ID, e.g. "org_6464de38ebf5b013b1928408" — resolve via '
    "easydmarc_list_organizations first, never guess one."
)
_DOMAINS_DESC = 'Domain name(s) to filter by, e.g. ["example.com", "test.com"] (at least one required).'
_SORT_FIELD = Literal[
    "report_id", "domain", "header_from", "from", "to", "subject", "date", "headers_eml",
    "report_domain", "report_from", "report_subject", "report_email_body",
    "report_email_body_urls", "report_date", "source_ip", "ptr", "ptr_group",
    "country_code", "created",
]  # fmt: skip


def register(mcp: FastMCP, client_factory: Callable[[], EasyDMARCClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_get_failure_reports(
        organization_id: Annotated[str, Field(description=_ORG_ID_DESC)],
        domains: Annotated[list[str], Field(description=_DOMAINS_DESC)],
        date_from: Annotated[
            str | None, Field(description="ISO 8601, filter reports from this date.")
        ] = None,
        date_to: Annotated[
            str | None, Field(description="ISO 8601, filter reports until this date.")
        ] = None,
        report_date: Annotated[
            str | None, Field(description="ISO 8601, filter to one exact report date.")
        ] = None,
        source_ip: Annotated[
            str | None, Field(description='Filter by source IPv4, e.g. "192.168.1.100".')
        ] = None,
        country_code: Annotated[str | None, Field(description='ISO 3166-1 alpha-2, e.g. "US".')] = None,
        reporter_domain: Annotated[
            str | None, Field(description="Filter by the reporting mail platform's domain.")
        ] = None,
        ptr: Annotated[str | None, Field(description='PTR record, or "Unknown".')] = None,
        ptr_group: Annotated[str | None, Field(description='PTR group, or "Unknown".')] = None,
        page: Annotated[int, Field(description="Page number, 1-based.", ge=1)] = 1,
        page_size: Annotated[int, Field(description="Items per page (max 1000).", ge=1, le=1000)] = 10,
        sort_field: Annotated[_SORT_FIELD, Field(description="Field to sort by.")] = "date",
        direction: Annotated[Literal["asc", "desc"], Field(description="Sort direction.")] = "desc",
    ) -> str:
        """List DMARC failure (RUF/forensic) reports — individual messages
        that failed authentication, each naming the sending IP/domain that
        sent it. For counts/breakdowns instead of a raw list, use
        easydmarc_get_failure_report_aggregates.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                "/v1/dmarc/failure-reports",
                params={
                    "organizationId": organization_id,
                    "domains": ",".join(domains),
                    "dateFrom": date_from,
                    "dateTo": date_to,
                    "reportDate": report_date,
                    "sourceIp": source_ip,
                    "countryCode": country_code,
                    "reporterDomain": reporter_domain,
                    "ptr": ptr,
                    "ptrGroup": ptr_group,
                    "page": page,
                    "pageSize": page_size,
                    "field": sort_field,
                    "direction": direction,
                },
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_get_failure_report(
        organization_id: Annotated[str, Field(description=_ORG_ID_DESC)],
        report_id: Annotated[
            str,
            Field(
                description=(
                    "MongoDB ObjectId of the failure report — resolve via "
                    "easydmarc_get_failure_reports first."
                )
            ),
        ],
        include: Annotated[
            list[Literal["rawHeaders", "emailBody", "addresses", "downloadUrls"]] | None,
            Field(description="Optional extra sections to include beyond the base record."),
        ] = None,
        redaction: Annotated[
            Literal["strict", "none"],
            Field(description='"strict" masks sensitive fields (default); "none" returns them raw.'),
        ] = "strict",
    ) -> str:
        """Get one DMARC failure (RUF/forensic) report's full detail by ID.
        `downloadUrls` (in include) returns links to the raw .eml/attachment
        files — this tool does not fetch those files itself, only the URLs.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                f"/v1/dmarc/failure-reports/{report_id}",
                params={
                    "organizationId": organization_id,
                    "include": ",".join(include) if include else None,
                    "redaction": redaction,
                },
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_get_failure_report_aggregates(
        organization_id: Annotated[str, Field(description=_ORG_ID_DESC)],
        domains: Annotated[list[str], Field(description=_DOMAINS_DESC)],
        dimensions: Annotated[
            list[Literal["reporter", "ptrGroup", "countryCode", "domain"]],
            Field(description="Which dimension(s) to break the counts down by (at least one required)."),
        ],
        date_from: Annotated[
            str | None, Field(description="ISO 8601, aggregate from this date.")
        ] = None,
        date_to: Annotated[
            str | None, Field(description="ISO 8601, aggregate until this date.")
        ] = None,
        reporter_domain: Annotated[
            str | None, Field(description="Filter by the reporting mail platform's domain.")
        ] = None,
        report_date: Annotated[
            str | None, Field(description="ISO 8601, filter to one exact report date.")
        ] = None,
        ptr: Annotated[str | None, Field(description='PTR record, or "Unknown".')] = None,
        ptr_group: Annotated[str | None, Field(description='PTR group, or "Unknown".')] = None,
        country_code: Annotated[str | None, Field(description='ISO 3166-1 alpha-2, e.g. "US".')] = None,
        source_ip: Annotated[
            str | None, Field(description='Filter by source IPv4, e.g. "192.168.1.100".')
        ] = None,
        has_attachments: Annotated[
            bool | None, Field(description="Filter to reports with/without attachments.")
        ] = None,
        top_n: Annotated[
            int, Field(description="Top results to return per dimension (max 100).", ge=1, le=100)
        ] = 10,
        min_count: Annotated[int, Field(description="Drop entries below this count.", ge=1)] = 1,
        sort_field: Annotated[
            Literal["count", "key"], Field(description="Sort aggregation rows by count or by key.")
        ] = "count",
        direction: Annotated[Literal["asc", "desc"], Field(description="Sort direction.")] = "desc",
    ) -> str:
        """Get failure-report counts broken down by dimension (top
        reporters, PTR groups, countries, or domains) — "who's sending us
        the most DMARC failures" style questions, without listing every
        individual report.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                "/v1/dmarc/failure-reports/aggregates",
                params={
                    "organizationId": organization_id,
                    "domains": ",".join(domains),
                    "dimensions": ",".join(dimensions),
                    "dateFrom": date_from,
                    "dateTo": date_to,
                    "reporterDomain": reporter_domain,
                    "reportDate": report_date,
                    "ptr": ptr,
                    "ptrGroup": ptr_group,
                    "countryCode": country_code,
                    "sourceIp": source_ip,
                    "hasAttachments": has_attachments,
                    "topN": top_n,
                    "minCount": min_count,
                    "field": sort_field,
                    "direction": direction,
                },
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()
