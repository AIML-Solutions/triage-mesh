from pathlib import Path

from triage_mesh.agents import assessor, intel, scanner
from triage_mesh.harness import tools
from triage_mesh.schemas import (
    AdvisoryBundle,
    DependencyInventory,
    Ecosystem,
    PackageCoordinate,
    ReportStatus,
    Severity,
)

SEED = Path(__file__).parent.parent / "demo" / "seed-repo"

PKG = {"ecosystem": "PyPI", "name": "requests", "version": "2.25.1"}
BUNDLE = AdvisoryBundle.model_validate(
    {
        "package": PKG,
        "advisories": [
            {
                "id": "GHSA-j8r2-6x86-q33q",
                "source": "osv",
                "summary": "header leak",
                "severity": "medium",
                "affected_package": PKG,
                "fixed_version": "2.31.0",
            }
        ],
        "sources_queried": ["osv"],
    }
)


async def test_scanner_handle_builds_inventory(monkeypatch):
    async def fake_call_tool(url, tool, args, headers=None):
        if tool == "list_manifests":
            return ["package-lock.json", "requirements.txt"]
        return (SEED / args["filename"]).read_text()

    monkeypatch.setattr(tools, "call_tool", fake_call_tool)
    result = await scanner.handle({"repo_ref": "seed", "correlation_id": "c1"})
    inventory = DependencyInventory.model_validate(result["inventory"])
    assert len(inventory.packages) == 6  # 4 PyPI + 2 npm
    assert result["correlation_id"] == "c1"


async def test_intel_handle_bundles_per_package(monkeypatch):
    calls = []

    async def fake_call_tool(url, tool, args, headers=None):
        calls.append(args)
        return BUNDLE.model_dump(mode="json")

    monkeypatch.setattr(tools, "call_tool", fake_call_tool)
    inventory = DependencyInventory(
        repo_ref="seed",
        manifests=["requirements.txt"],
        packages=[
            PackageCoordinate(ecosystem=Ecosystem.PYPI, name="requests", version="2.25.1"),
            PackageCoordinate(ecosystem=Ecosystem.PYPI, name="urllib3", version="1.26.4"),
        ],
    )
    result = await intel.handle({"inventory": inventory.model_dump(mode="json")})
    assert len(result["bundles"]) == 2
    assert calls[0] == {"ecosystem": "PyPI", "name": "requests", "version": "2.25.1"}


async def test_assessor_stages_pending_report(monkeypatch):
    staged = {}

    async def fake_call_tool(url, tool, args, headers=None):
        staged.update(args)
        return {"assessment_id": args["report"]["assessment_id"], "staged_at": "/staging/a1.json"}

    monkeypatch.setattr(tools, "call_tool", fake_call_tool)
    monkeypatch.setenv("MODEL_PROVIDER", "mock")
    inventory = DependencyInventory(
        repo_ref="seed", manifests=["requirements.txt"], packages=[BUNDLE.package]
    )
    result = await assessor.handle(
        {
            "assessment_id": "a1",
            "inventory": inventory.model_dump(mode="json"),
            "bundles": [BUNDLE.model_dump(mode="json")],
        }
    )
    report = result["report"]
    assert report["status"] == ReportStatus.PENDING_APPROVAL.value
    assert report["findings"][0]["advisory_id"] == "GHSA-j8r2-6x86-q33q"
    assert report["findings"][0]["severity"] == Severity.MEDIUM.value
    assert "2.31.0" in report["findings"][0]["recommended_action"]
    assert staged["report"]["assessment_id"] == "a1"
    assert result["staged_at"] == "/staging/a1.json"
