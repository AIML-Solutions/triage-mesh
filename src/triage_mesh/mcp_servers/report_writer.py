"""report-writer MCP server: staging-only report persistence.

Structural enforcement of the human gate (threat T7): drafts land in STAGING_DIR
with status forced to PENDING_APPROVAL. There is no publish tool here — that
capability lives only in the orchestrator API.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from triage_mesh.schemas import RemediationReport, ReportStatus

server = MCPServer(
    name="report-writer",
    version="0.1.0",
    instructions="Persist draft remediation reports to the staging area, pending human approval.",
)


def _staging_dir() -> Path:
    path = Path(os.environ.get("STAGING_DIR", "staging"))
    path.mkdir(parents=True, exist_ok=True)
    return path


@server.tool()
def write_draft(report: dict) -> dict:
    """Validate and stage a remediation report draft. Always lands pending approval."""
    validated = RemediationReport.model_validate(report)
    validated.status = ReportStatus.PENDING_APPROVAL  # writer cannot publish, ever
    path = _staging_dir() / f"{validated.assessment_id}.json"
    path.write_text(validated.model_dump_json(indent=2), encoding="utf-8")
    return {"assessment_id": validated.assessment_id, "staged_at": str(path)}


def main() -> None:
    from triage_mesh.mcp_servers import serve

    serve(server, default_port=7103)


if __name__ == "__main__":
    main()
