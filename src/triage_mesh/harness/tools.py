"""MCP client helper: each agent talks to exactly one first-party tool server."""

from __future__ import annotations

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
        return structured
