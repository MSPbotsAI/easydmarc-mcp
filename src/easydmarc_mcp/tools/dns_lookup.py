"""Live DNS lookup tools — point-in-time checks of a domain's current
DMARC/SPF/DKIM/BIMI/MTA-STS/TLS-RPT DNS records.

Verified against EasyDMARC's own published OpenAPI spec
(github.com/easydmarc/public-api-docs, specs/easydmarc-openapi.json,
checked 2026-08-28). These are live DNS resolutions, not historical report
data — for report history use the easydmarc_get_rua_*/failure_reports
tools instead. Scope note: EasyDMARC's DNS Lookup API also covers generic
A/AAAA/MX/NS/PTR/TXT/CNAME records and a newer "DNS Intelligence" batch-
check surface; those are intentionally out of scope here since they are
not EasyDMARC-specific (any DNS tool can resolve them) — this MCP only
covers the email-authentication-specific record types.
"""

from collections.abc import Callable
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import EasyDMARCClient, EasyDMARCError
from ._common import NO_TOKEN

_DOMAIN_DESC = 'Fully qualified domain name to look up, e.g. "example.com".'
_MAX_AGE_DESC = (
    "Cache freshness in milliseconds: 0 forces a fresh DNS fetch, -1 "
    "allows serving from cache regardless of age. Omit to use EasyDMARC's "
    "own default."
)


def register(mcp: FastMCP, client_factory: Callable[[], EasyDMARCClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_lookup_dmarc(
        domain: Annotated[str, Field(description=_DOMAIN_DESC)],
        recommended_rua: Annotated[
            str | None,
            Field(description="Optional RUA (aggregate report) address to compare the live record against."),
        ] = None,
        skip_our_addresses: Annotated[
            bool,
            Field(description="If true, don't flag EasyDMARC's own rua/ruf addresses as missing."),
        ] = False,
    ) -> str:
        """Live DNS lookup of a domain's current DMARC TXT record (does the
        record exist, is it valid, what policy does it declare). Point-in-
        time check, not report history — for compliance/pass-rate history
        use easydmarc_get_rua_auth_pass_rates instead.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                "/v1/dns-lookup/dmarc",
                params={
                    "domain": domain,
                    "recommendedRua": recommended_rua,
                    "skipOurAddresses": skip_our_addresses,
                },
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_lookup_spf(
        domain: Annotated[str, Field(description=_DOMAIN_DESC)],
        max_age_ms: Annotated[int | None, Field(description=_MAX_AGE_DESC)] = None,
    ) -> str:
        """Live DNS lookup and full parse of a domain's current SPF record
        — resolves the include/redirect/mx/a chain and returns each visited
        term. Does not accept a pre-built resume state (visitedTerms) for a
        continuation lookup — always resolves the chain fresh from the
        domain. For a simpler pass/fail + DNS-lookup-count-limit check
        only, use easydmarc_lookup_spf_result instead.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        body: dict = {"domain": domain}
        if max_age_ms is not None:
            body["maxAgeMs"] = max_age_ms
        try:
            result = await client.post("/v1/dns-lookup/spf", json_body=body)
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_lookup_spf_result(
        domain: Annotated[str, Field(description=_DOMAIN_DESC)],
        max_age_ms: Annotated[int | None, Field(description=_MAX_AGE_DESC)] = None,
    ) -> str:
        """Live SPF lookup summarized as a validation result — use this for
        "is this domain's SPF valid / under the 10-DNS-lookup limit" style
        questions. For the full resolved include-chain detail (every term
        and where it came from), use easydmarc_lookup_spf instead.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        body: dict = {"domain": domain}
        if max_age_ms is not None:
            body["maxAgeMs"] = max_age_ms
        try:
            result = await client.post("/v1/dns-lookup/spf/lookup-result", json_body=body)
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_lookup_dkim(
        domain: Annotated[str, Field(description=_DOMAIN_DESC)],
        selectors: Annotated[
            list[str],
            Field(
                description=(
                    'DKIM selector(s) to check, e.g. ["s1", "google"] — the '
                    "selector is the prefix before "
                    '"._domainkey." in the DKIM DNS record name, and is '
                    "chosen by the sending mail platform, not guessable "
                    "from the domain alone. Ask the user, or check their "
                    "email platform's DKIM setup instructions, if unknown."
                )
            ),
        ],
        max_age_ms: Annotated[int | None, Field(description=_MAX_AGE_DESC)] = None,
    ) -> str:
        """Live DNS lookup of a domain's DKIM record(s) for one or more
        selectors. A selector is required — there is no "look up all DKIM
        selectors" mode, since selectors aren't enumerable from DNS alone.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                "/v1/dns-lookup/dkim",
                params={"domain": domain, "selectors": selectors, "maxAgeMs": max_age_ms},
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_lookup_bimi(
        domain: Annotated[str, Field(description=_DOMAIN_DESC)],
        max_age_ms: Annotated[int | None, Field(description=_MAX_AGE_DESC)] = None,
    ) -> str:
        """Live DNS lookup of a domain's BIMI record (the brand logo shown
        next to authenticated email in supporting inboxes). BIMI requires
        DMARC enforcement to be in place first — a missing/invalid DMARC
        record is a common reason BIMI won't display even if this record
        looks correct.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                "/v1/dns-lookup/bimi", params={"domain": domain, "maxAgeMs": max_age_ms}
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_lookup_tls_rpt(
        domain: Annotated[str, Field(description=_DOMAIN_DESC)],
        max_age_ms: Annotated[int | None, Field(description=_MAX_AGE_DESC)] = None,
    ) -> str:
        """Live DNS lookup of a domain's TLS-RPT record (the `_smtp._tls`
        TXT record) — where SMTP TLS delivery failure reports get sent.
        Complements DMARC RUA/RUF reports by covering transport-layer (not
        authentication) delivery failures.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                "/v1/dns-lookup/tls-rpt", params={"domain": domain, "maxAgeMs": max_age_ms}
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_lookup_mta_sts(
        domain: Annotated[str, Field(description=_DOMAIN_DESC)],
        max_age_ms: Annotated[int | None, Field(description=_MAX_AGE_DESC)] = None,
    ) -> str:
        """Live DNS + HTTPS lookup of a domain's MTA-STS setup — resolves
        the `_mta-sts` TXT record AND fetches/validates the MTA-STS policy
        file it points to, confirming whether inbound mail to this domain
        is protected against TLS downgrade/interception.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                "/v1/dns-lookup/mta-sts", params={"domain": domain, "maxAgeMs": max_age_ms}
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()
