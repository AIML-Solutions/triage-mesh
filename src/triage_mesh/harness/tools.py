"""MCP client side: each agent talks to exactly one first-party tool server,
and every call passes the policy engine first (deny-by-default, argument
constraints, per-task rate ceiling)."""

from __future__ import annotations

import json
from typing import Any

import httpx
from mcp.client.client import Client
from mcp.client.streamable_http import streamable_http_client

from triage_mesh.harness.integrity import live_manifest_hash
from triage_mesh.harness.policy import PolicyEngine, PolicyViolation
from triage_mesh.harness.telemetry import get_tracer


async def verify_manifest(mcp_url: str, headers: dict[str, str] | None, expected: str) -> None:
    """Refuse to use a tool server whose advertised manifest drifted from its pin (T3)."""
    async with _client(mcp_url, headers) as client:
        actual = await live_manifest_hash(client)
    if actual != expected:
        raise PolicyViolation(
            f"tool manifest at {mcp_url} does not match its pin "
            f"(expected {expected[:12]}…, got {actual[:12]}…) — refusing all calls"
        )


def _client(mcp_url: str, headers: dict[str, str] | None) -> Client:
    if not headers:
        return Client(mcp_url)
    transport = streamable_http_client(mcp_url, http_client=httpx.AsyncClient(headers=headers))
    return Client(transport)


async def call_tool(
    mcp_url: str, tool: str, arguments: dict[str, Any], headers: dict[str, str] | None = None
) -> Any:
    async with _client(mcp_url, headers) as client:
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

    def __init__(
        self,
        agent: str,
        mcp_url: str,
        policy: PolicyEngine | None = None,
        audience: str | None = None,
    ):
        self._agent = agent
        self._mcp_url = mcp_url
        self._policy = policy or PolicyEngine.load()
        self._audience = audience
        self._calls = 0
        self._manifest_verified = False

    async def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        with get_tracer().start_as_current_span("tool.call") as span:
            span.set_attribute("agent.name", self._agent)
            span.set_attribute("tool.name", tool)
            self._calls += 1
            try:
                if self._calls > self._policy.max_calls(self._agent):
                    raise PolicyViolation(
                        f"agent {self._agent!r} exceeded "
                        f"{self._policy.max_calls(self._agent)} calls per task"
                    )
                self._policy.check(self._agent, tool, arguments)
            except PolicyViolation:
                span.set_attribute("policy.verdict", "denied")
                raise
            span.set_attribute("policy.verdict", "allowed")
            from triage_mesh.harness.auth import bearer_headers

            headers = bearer_headers(self._agent, self._audience) if self._audience else None
            expected = self._policy.expected_manifest(self._audience) if self._audience else None
            if expected and not self._manifest_verified:
                # Once per task: the server must still advertise exactly the pinned tools.
                await verify_manifest(self._mcp_url, headers, expected)
                self._manifest_verified = True
                span.set_attribute("tool.manifest", "verified")
            return await call_tool(self._mcp_url, tool, arguments, headers=headers)
