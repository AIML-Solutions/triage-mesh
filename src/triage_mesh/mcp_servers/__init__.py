"""First-party MCP servers (v2 SDK, stateless streamable-HTTP transport)."""

import os

import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings


def serve(server: MCPServer, default_port: int) -> None:
    """Run an MCP server as a stateless HTTP service (container entrypoint).

    Stateless per the 2026-07-28 spec core: no sessions, every request
    self-contained. Host-header checks are relaxed here because services are
    addressed by compose/K8s DNS names; network reachability is constrained
    one layer down (compose networks / NetworkPolicies), and phase 2 adds JWTs.
    """
    from triage_mesh.harness.telemetry import setup_telemetry, traced_asgi

    setup_telemetry(server.name)
    app = server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        ),
    )
    from triage_mesh.harness.auth import ServiceAuthMiddleware

    uvicorn.run(
        traced_asgi(ServiceAuthMiddleware(app, audience=server.name)),
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", default_port)),
        log_level="info",
    )
