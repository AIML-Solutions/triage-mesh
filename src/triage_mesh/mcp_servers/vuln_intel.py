"""vuln-intel MCP server: the mesh's only doorway to the outside world.

The tool schema is the exfiltration control (threat T6): queries are package
coordinates — validated enum + name + version — and nothing else can leave.
"""

from __future__ import annotations

import httpx
from mcp.server.mcpserver import MCPServer

from triage_mesh.mcp_servers.osv import fetch_advisories
from triage_mesh.schemas import Ecosystem, PackageCoordinate

server = MCPServer(
    name="vuln-intel",
    version="0.1.0",
    instructions="Query public vulnerability advisories (OSV) for exact package coordinates.",
)


@server.tool()
async def query_advisories(ecosystem: str, name: str, version: str) -> dict:
    """Fetch known advisories for one exact package coordinate from OSV.dev."""
    package = PackageCoordinate(ecosystem=Ecosystem(ecosystem), name=name, version=version)
    async with httpx.AsyncClient() as client:
        bundle = await fetch_advisories(client, package)
    return bundle.model_dump(mode="json")


def main() -> None:
    from triage_mesh.mcp_servers import serve

    serve(server, default_port=7102)


if __name__ == "__main__":
    main()
