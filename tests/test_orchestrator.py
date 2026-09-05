import asyncio

import httpx

from triage_mesh.orchestrator import a2a, service
from triage_mesh.schemas import AssessmentState, ReportStatus

PKG = {"ecosystem": "PyPI", "name": "requests", "version": "2.25.1"}
INVENTORY = {"repo_ref": "seed", "manifests": ["requirements.txt"], "packages": [PKG]}
BUNDLE = {
    "package": PKG,
    "advisories": [
        {
            "id": "GHSA-1",
            "source": "osv",
            "severity": "high",
            "affected_package": PKG,
            "fixed_version": "2.31.0",
        }
    ],
    "sources_queried": ["osv"],
}


def fake_send_task(*, intel_fails: bool = False):
    async def _send(agent_url: str, payload: dict, deadline: float) -> dict:
        if "7201" in agent_url:  # scanner
            return {"inventory": INVENTORY, "correlation_id": payload["correlation_id"]}
        if "7202" in agent_url:  # intel
            if intel_fails:
                raise a2a.AgentTaskError("intel unreachable")
            return {"bundles": [BUNDLE]}
        # assessor: build a minimal valid report from its inputs
        findings = [
            {
                "package": b["package"],
                "advisory_id": a["id"],
                "severity": a["severity"],
                "exploitability_note": "in range",
                "recommended_action": "upgrade",
                "fixed_version": a.get("fixed_version"),
            }
            for b in payload["bundles"]
            for a in b["advisories"]
        ]
        return {
            "report": {
                "assessment_id": payload["assessment_id"],
                "repo_ref": "seed",
                "findings": findings,
                "summary": "test summary",
                "partial": payload["partial"],
                "status": "pending_approval",
            }
        }

    return _send


async def _client():
    transport = httpx.ASGITransport(app=service.app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def _wait_for_state(client, assessment_id, state, attempts=50):
    for _ in range(attempts):
        response = await client.get(f"/assessments/{assessment_id}")
        if response.json()["state"] == state:
            return response.json()
        await asyncio.sleep(0.01)
    raise AssertionError(f"never reached {state}: {response.json()}")


async def test_full_flow_publish(monkeypatch, tmp_path):
    monkeypatch.setattr(a2a, "send_task", fake_send_task())
    monkeypatch.setenv("PUBLISHED_DIR", str(tmp_path))
    async with await _client() as client:
        created = (await client.post("/assessments", json={"repo_ref": "seed"})).json()
        assessment_id = created["assessment_id"]

        # approving before the pipeline finishes must 409 (human gate integrity)
        early = await client.post(f"/assessments/{assessment_id}/approve")
        assert early.status_code == 409

        ready = await _wait_for_state(client, assessment_id, "pending_approval")
        assert ready["report"]["status"] == ReportStatus.PENDING_APPROVAL.value
        assert len(ready["report"]["findings"]) == 1

        approved = (await client.post(f"/assessments/{assessment_id}/approve")).json()
        assert approved["state"] == AssessmentState.PUBLISHED.value
        assert (tmp_path / f"{assessment_id}.json").exists()


async def test_intel_failure_degrades_to_partial(monkeypatch):
    monkeypatch.setattr(a2a, "send_task", fake_send_task(intel_fails=True))
    async with await _client() as client:
        created = (await client.post("/assessments", json={"repo_ref": "seed"})).json()
        ready = await _wait_for_state(client, created["assessment_id"], "pending_approval")
        assert ready["report"]["partial"] is True
        assert ready["report"]["findings"] == []


async def test_unknown_assessment_404(monkeypatch):
    async with await _client() as client:
        assert (await client.get("/assessments/nope")).status_code == 404
