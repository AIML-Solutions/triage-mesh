"""Intel agent: dependency inventory in, advisory bundles out (via vuln-intel)."""

from __future__ import annotations

import os

from triage_mesh.harness.a2a_app import JsonTaskExecutor, make_card, serve_agent
from triage_mesh.harness.tools import Toolbelt
from triage_mesh.schemas import AdvisoryBundle, DependencyInventory


def _mcp_url() -> str:
    return os.environ.get("MCP_URL", "http://127.0.0.1:7102/mcp")


async def handle(payload: dict) -> dict:
    inventory = DependencyInventory.model_validate(payload["inventory"])
    belt = Toolbelt("intel", _mcp_url(), audience="vuln-intel")
    bundles: list[dict] = []
    for package in inventory.packages:
        raw = await belt.call(
            "query_advisories",
            {
                "ecosystem": package.ecosystem.value,
                "name": package.name,
                "version": package.version,
            },
        )
        bundles.append(AdvisoryBundle.model_validate(raw).model_dump(mode="json"))
    return {"correlation_id": payload.get("correlation_id"), "bundles": bundles}


def main() -> None:
    card = make_card(
        name="intel",
        description="Fetches known vulnerability advisories for exact package coordinates.",
        skill="gather-advisories",
        public_url=os.environ.get("PUBLIC_URL", "http://127.0.0.1:7202/"),
    )
    serve_agent(card, JsonTaskExecutor("intel", handle), default_port=7202)


if __name__ == "__main__":
    main()
