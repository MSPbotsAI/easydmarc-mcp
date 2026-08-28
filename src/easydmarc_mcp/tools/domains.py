"""Domain (onboarding/policy) tools.

Verified against EasyDMARC's own published OpenAPI spec
(github.com/easydmarc/public-api-docs, specs/easydmarc-openapi.json,
checked 2026-08-28). Domains are scoped by organization_id — resolve one
via easydmarc_list_organizations first.
"""

from collections.abc import Callable
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import EasyDMARCClient, EasyDMARCError
from ._common import CONFIRM_DESC, NO_TOKEN, confirm_gate

_ORG_ID_DESC = (
    'Organization ID, e.g. "org_68231dcfeb8e9f092a052b88" — resolve via '
    "easydmarc_list_organizations first, never guess one."
)
_DOMAIN_TYPE_DESC = (
    '"sending" — this domain sends mail and should be DMARC-enforced; '
    '"parked" — this domain never sends mail (should reject all mail via SPF/DMARC).'
)


def register(mcp: FastMCP, client_factory: Callable[[], EasyDMARCClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_list_domains(
        organization_id: Annotated[str, Field(description=_ORG_ID_DESC)],
        page: Annotated[int, Field(description="Page number, 1-based.", ge=1)] = 1,
        page_size: Annotated[
            int, Field(description="Items per page (max 100).", ge=1, le=100)
        ] = 20,
    ) -> str:
        """List domains onboarded to EasyDMARC for one organization."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                "/v1/domains",
                params={"organizationId": organization_id, "page": page, "pageSize": page_size},
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_get_domain(
        organization_id: Annotated[str, Field(description=_ORG_ID_DESC)],
        domain: Annotated[str, Field(description='Fully qualified domain name, e.g. "example.com".')],
    ) -> str:
        """Get one domain's onboarding details (type, group, status) by name."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                f"/v1/domains/{domain}", params={"organizationId": organization_id}
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool()
    async def easydmarc_create_domain(
        organization_id: Annotated[str, Field(description=_ORG_ID_DESC)],
        domain: Annotated[str, Field(description='Fully qualified domain name, e.g. "example.com".')],
        type: Annotated[Literal["sending", "parked"] | None, Field(description=_DOMAIN_TYPE_DESC)] = None,
        group_id: Annotated[
            str | None, Field(description="Optional domain group ID to place this domain in.")
        ] = None,
    ) -> str:
        """Onboard a new domain to EasyDMARC monitoring. Does not itself
        change any DNS record — after this, call easydmarc_get_domain_setup
        to get the DMARC record to publish.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        body: dict = {"organizationId": organization_id, "domain": domain}
        if type is not None:
            body["type"] = type
        if group_id is not None:
            body["groupId"] = group_id
        try:
            result = await client.post("/v1/domains", json_body=body)
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(idempotentHint=True))
    async def easydmarc_update_domain(
        domain: Annotated[
            str, Field(description='Fully qualified domain name to update, e.g. "example.com".')
        ],
        domain_name: Annotated[
            str | None, Field(description="New domain name value, if renaming.")
        ] = None,
        type: Annotated[Literal["sending", "parked"] | None, Field(description=_DOMAIN_TYPE_DESC)] = None,
        group_id: Annotated[str | None, Field(description="New domain group ID.")] = None,
    ) -> str:
        """Partially update a domain's type or group. Only the fields you
        pass are changed; omitted fields keep their current value. Unlike
        most other domain tools, this one is not organization-scoped by the
        API itself — the domain name alone identifies the resource.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        body: dict = {}
        if domain_name is not None:
            body["domainName"] = domain_name
        if type is not None:
            body["type"] = type
        if group_id is not None:
            body["groupId"] = group_id
        try:
            result = await client.patch(f"/v1/domains/{domain}", json_body=body)
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(destructiveHint=True, idempotentHint=True))
    async def easydmarc_delete_domain(
        organization_id: Annotated[str, Field(description=_ORG_ID_DESC)],
        domain: Annotated[
            str, Field(description='Fully qualified domain name to remove, e.g. "example.com".')
        ],
        confirm: Annotated[bool, Field(description=CONFIRM_DESC)] = False,
    ) -> str:
        """Remove a domain from EasyDMARC monitoring — stops report
        ingestion and DNS checks for it. Irreversible (historical reports
        already collected are not necessarily deleted, but monitoring
        stops). Requires confirm=true.
        """
        if (err := confirm_gate(confirm)) is not None:
            return err
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.delete(
                f"/v1/domains/{domain}", params={"organizationId": organization_id}
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_get_domain_setup(
        organization_id: Annotated[str, Field(description=_ORG_ID_DESC)],
        domain: Annotated[str, Field(description='Fully qualified domain name, e.g. "example.com".')],
        record_type: Annotated[
            Literal["CNAME", "TXT"],
            Field(description="Which DNS record format to return for onboarding."),
        ],
    ) -> str:
        """Get the DMARC DNS record EasyDMARC wants published for this
        domain (the value to add to the DNS provider). Use when a domain
        was just created via easydmarc_create_domain and needs its DMARC
        record set up, or to check what the expected record should look
        like. DNS propagation after publishing may take up to several hours
        — this tool only returns the expected record, it does not check
        whether it's live yet (for that, use easydmarc_lookup_dmarc).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                f"/v1/domains/{domain}/setup",
                params={"organizationId": organization_id, "type": record_type},
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool()
    async def easydmarc_verify_domain_setup(
        domain: Annotated[str, Field(description='Fully qualified domain name, e.g. "example.com".')],
        managed: Annotated[
            bool | None, Field(description="Whether DNS for this domain is managed by EasyDMARC.")
        ] = None,
        tags: Annotated[dict | None, Field(description="Optional free-form tags to attach.")] = None,
    ) -> str:
        """Trigger EasyDMARC to verify a domain's DMARC record is live in
        DNS. KNOWN LIMITATION: EasyDMARC's own API documentation marks this
        endpoint "Not available yet" as of the spec checked for this build
        (2026-08-28) — included for interface completeness, but expect it
        may 404/501 until EasyDMARC ships it. For an actual live DNS check
        today, use easydmarc_lookup_dmarc instead.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        body: dict = {}
        if managed is not None:
            body["managed"] = managed
        if tags is not None:
            body["tags"] = tags
        try:
            result = await client.post(f"/v1/domains/{domain}/setup", json_body=body)
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()
