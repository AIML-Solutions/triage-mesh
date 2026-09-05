"""Scanner agent: repo manifests in, typed DependencyInventory out."""

from __future__ import annotations

import os

from triage_mesh.harness.a2a_app import JsonTaskExecutor, make_card, serve_agent
from triage_mesh.harness.tools import Toolbelt
from triage_mesh.manifests import parse_manifest
from triage_mesh.schemas import DependencyInventory


def _mcp_url() -> str:
    return os.environ.get("MCP_URL", "http://127.0.0.1:7101/mcp")


async def handle(payload: dict) -> dict:
    repo_ref = str(payload["repo_ref"])
    belt = Toolbelt("scanner", _mcp_url())
    manifests: list[str] = await belt.call("list_manifests", {})
    packages = []
    for filename in manifests:
        content: str = await belt.call("read_manifest", {"filename": filename})
        packages.extend(parse_manifest(filename, content))
    inventory = DependencyInventory(repo_ref=repo_ref, manifests=manifests, packages=packages)
    return {
        "correlation_id": payload.get("correlation_id"),
        "inventory": inventory.model_dump(mode="json"),
    }


def main() -> None:
    card = make_card(
        name="scanner",
        description="Builds a typed dependency inventory from the repo's manifests.",
        skill="scan-dependencies",
        public_url=os.environ.get("PUBLIC_URL", "http://127.0.0.1:7201/"),
    )
    serve_agent(card, JsonTaskExecutor("scanner", handle), default_port=7201)


if __name__ == "__main__":
    main()
