"""The generated NetworkPolicies must never drift from the declared topology."""

import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent


def test_networkpolicies_in_sync_with_topology():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_networkpolicies.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_every_agent_has_a_topology_edge_to_exactly_one_tool_server():
    config = yaml.safe_load((ROOT / "deploy" / "policies.yaml").read_text())
    edges = config["topology"]["edges"]
    for agent in config["agents"]:
        targets = edges.get(agent, [])
        assert len(targets) == 1 and targets[0].startswith("mcp-"), (
            f"agent {agent} must talk to exactly one first-party MCP server, got {targets}"
        )


def test_only_vuln_intel_has_internet_egress():
    services = yaml.safe_load((ROOT / "deploy" / "policies.yaml").read_text())["topology"]["services"]
    with_egress = [name for name, meta in services.items() if meta.get("internet_egress")]
    assert with_egress == ["mcp-vuln-intel"]
