"""Organization (partner-tenant) tools.

EasyDMARC's public API is a partner/MSP-tenant API: almost every other
resource (domains, failure reports) is scoped to one client organization
via an organizationId. These two read-only tools are the entry point for
finding that ID.
"""

from collections.abc import Callable
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import EasyDMARCClient, EasyDMARCError
from ._common import NO_TOKEN


def register(mcp: FastMCP, client_factory: Callable[[], EasyDMARCClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_list_organizations(
        page: Annotated[int, Field(description="Page number, 1-based.", ge=1)] = 1,
        limit: Annotated[
            int, Field(description="Items per page (max 100).", ge=1, le=100)
        ] = 10,
        order: Annotated[
            Literal["ASC", "DESC"] | None, Field(description="Sort direction by name.")
        ] = None,
    ) -> str:
        """List the client organizations under this partner account. Call
        this first to find an organization_id — nearly every other tool
        (domains, failure reports) needs one.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                "/v1/organizations", params={"page": page, "limit": limit, "order": order}
            )
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def easydmarc_get_organization(
        organization_id: Annotated[
            str,
            Field(
                description=(
                    'Organization ID, e.g. "org_68231dcfeb8e9f092a052b88" — '
                    "resolve via easydmarc_list_organizations first, never guess one."
                )
            ),
        ],
    ) -> str:
        """Get one client organization's details by ID."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/v1/organizations/{organization_id}")
            return dump_json_capped(result)
        except EasyDMARCError as e:
            return e.to_envelope()
