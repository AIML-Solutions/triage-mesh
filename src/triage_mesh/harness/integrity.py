"""Tool-manifest integrity pinning (threat T3: poisoned tool descriptions).

An MCP server's tool list — names, descriptions, input schemas — is text the
model reads. A compromised or swapped server can therefore inject
instructions through a tool description ("rug pull"). The mitigation: each
first-party server's manifest is hashed at pin time and recorded in
deploy/policies.yaml; the harness re-hashes the live manifest before an
agent's first call of a task and refuses to proceed on any drift.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from mcp.client.client import Client


def _tool_record(tool: Any) -> dict[str, Any]:
    schema = getattr(tool, "input_schema", None)
    if schema is None:
        schema = getattr(tool, "inputSchema", None)
    return {
        "name": tool.name,
        "description": tool.description or "",
        "input_schema": schema or {},
    }


def manifest_hash(tools: list[Any]) -> str:
    """Stable SHA-256 over the sorted (name, description, schema) triples."""
    records = sorted((_tool_record(t) for t in tools), key=lambda r: r["name"])
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def live_manifest_hash(client: Client) -> str:
    """Hash the manifest a live server actually advertises right now."""
    result = await client.list_tools(cache_mode="bypass")
    return manifest_hash(list(result.tools))
