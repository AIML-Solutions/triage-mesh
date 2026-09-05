"""MCP client helper: each agent talks to exactly one first-party tool server."""

from __future__ import annotations

import json
from typing import Any

from mcp.client.client import Client


async def call_tool(mcp_url: str, tool: str, arguments: dict[str, Any]) -> Any:
    async with Client(mcp_url) as client:
        result = await client.call_tool(tool, arguments)
        if result.is_error:
            raise RuntimeError(f"tool {tool} failed: {result.content}")
        structured = result.structured_content
        if isinstance(structured, dict) and set(structured) == {"result"}:
            return structured["result"]  # SDK wraps scalar/list returns
        if structured is not None:
            return structured
        # Tools annotated with a bare dict return type get no output schema,
        # so the payload arrives as JSON text content instead.
        text = "".join(block.text for block in result.content if getattr(block, "text", None))
        return json.loads(text) if text else None
