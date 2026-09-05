"""repo-reader MCP server: read-only access to dependency manifests.

Capability surface is deliberately tiny (threat T2/T4): only known manifest
filenames, only under REPO_ROOT, nothing else readable.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from triage_mesh.manifests import PARSERS


def _repo_root() -> Path:
    return Path(os.environ.get("REPO_ROOT", "demo/seed-repo")).resolve()


server = MCPServer(
    name="repo-reader",
    version="0.1.0",
    instructions="Read-only access to the dependency manifests of the repo under assessment.",
)


@server.tool()
def list_manifests() -> list[str]:
    """List the dependency manifest files present in the repo under assessment."""
    root = _repo_root()
    return sorted(name for name in PARSERS if (root / name).is_file())


@server.tool()
def read_manifest(filename: str) -> str:
    """Read one known manifest file (requirements.txt or package-lock.json) verbatim."""
    if filename not in PARSERS:
        raise ValueError(f"not a recognized manifest: {filename!r}")
    path = _repo_root() / filename
    if not path.is_file():
        raise FileNotFoundError(f"manifest not present: {filename}")
    return path.read_text(encoding="utf-8", errors="replace")


def main() -> None:
    from triage_mesh.mcp_servers import serve

    serve(server, default_port=7101)


if __name__ == "__main__":
    main()
