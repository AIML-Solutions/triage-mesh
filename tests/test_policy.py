import pytest

from triage_mesh.harness.policy import PolicyEngine, PolicyViolation
from triage_mesh.harness.tools import Toolbelt

ENGINE = PolicyEngine.load("deploy/policies.yaml")


def test_allowed_calls_pass():
    ENGINE.check("scanner", "read_manifest", {"filename": "requirements.txt"})
    ENGINE.check(
        "intel",
        "query_advisories",
        {"ecosystem": "PyPI", "name": "requests", "version": "2.25.1"},
    )


def test_deny_by_default_unknown_agent_and_tool():
    with pytest.raises(PolicyViolation):
        ENGINE.check("orchestrator", "write_draft", {})
    with pytest.raises(PolicyViolation):
        ENGINE.check("scanner", "write_draft", {"report": {}})  # cross-role call


def test_enum_constraint_blocks_unknown_file():
    with pytest.raises(PolicyViolation):
        ENGINE.check("scanner", "read_manifest", {"filename": "secrets.env"})


def test_pattern_blocks_exfil_shaped_names():
    for bad in ["requests?d=hunter2", "a b", "x" * 300, "../../../etc/passwd"]:
        with pytest.raises(PolicyViolation):
            ENGINE.check(
                "intel",
                "query_advisories",
                {"ecosystem": "PyPI", "name": bad, "version": "1.0"},
            )


def test_unexpected_argument_rejected():
    with pytest.raises(PolicyViolation):
        ENGINE.check(
            "intel",
            "query_advisories",
            {
                "ecosystem": "PyPI",
                "name": "requests",
                "version": "1.0",
                "callback_url": "http://evil",
            },
        )


def test_payload_size_cap():
    with pytest.raises(PolicyViolation):
        ENGINE.check("assessor", "write_draft", {"report": {"blob": "x" * 2_000_000}})


async def test_rate_ceiling_per_task(monkeypatch):
    from triage_mesh.harness import tools as tools_module

    async def fake_call_tool(url, tool, args, headers=None):
        return "ok"

    monkeypatch.setattr(tools_module, "call_tool", fake_call_tool)
    belt = Toolbelt("scanner", "http://unused/mcp", policy=ENGINE)
    for _ in range(ENGINE.max_calls("scanner")):
        await belt.call("list_manifests", {})
    with pytest.raises(PolicyViolation):
        await belt.call("list_manifests", {})
