"""MCP client side: each agent talks to exactly one first-party tool server,
and every call passes the policy engine first (deny-by-default, argument
constraints, per-task rate ceiling)."""

from __future__ import annotations

import json
from typing import Any

from mcp.client.client import Client

from triage_mesh.harness.policy import PolicyEngine, PolicyViolation


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


class Toolbelt:
    """One agent's policied view of its tool server, scoped to one task."""

    def __init__(self, agent: str, mcp_url: str, policy: PolicyEngine | None = None):
        self._agent = agent
        self._mcp_url = mcp_url
        self._policy = policy or PolicyEngine.load()
        self._calls = 0

    async def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        self._calls += 1
        if self._calls > self._policy.max_calls(self._agent):
            raise PolicyViolation(
                f"agent {self._agent!r} exceeded {self._policy.max_calls(self._agent)} calls per task"
            )
        self._policy.check(self._agent, tool, arguments)
        return await call_tool(self._mcp_url, tool, arguments)
