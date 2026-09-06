import json

import httpx
import pytest
import respx

from triage_mesh.mcp_servers import osv, repo_reader, report_writer
from triage_mesh.schemas import (
    Ecosystem,
    PackageCoordinate,
    RemediationReport,
    ReportStatus,
    Severity,
)

PKG = PackageCoordinate(ecosystem=Ecosystem.PYPI, name="requests", version="2.25.1")

OSV_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-j8r2-6x86-q33q",
            "aliases": ["CVE-2023-32681"],
            "summary": "Unintended leak of Proxy-Authorization header",
            "database_specific": {"severity": "MODERATE"},
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "requests"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}],
                        }
                    ],
                }
            ],
            "references": [{"type": "ADVISORY", "url": "https://example.test/advisory"}],
        }
    ]
}


def test_osv_mapping():
    advisories = osv.osv_to_advisories(PKG, OSV_RESPONSE)
    assert len(advisories) == 1
    adv = advisories[0]
    assert adv.id == "GHSA-j8r2-6x86-q33q"
    assert adv.severity is Severity.MEDIUM  # MODERATE maps to medium
    assert adv.fixed_version == "2.31.0"
    assert "CVE-2023-32681" in adv.aliases


def test_osv_mapping_survives_junk():
    assert osv.osv_to_advisories(PKG, {"vulns": [{"no_id": True}, "garbage"]}) == []
    assert osv.osv_to_advisories(PKG, {}) == []


@respx.mock
async def test_fetch_advisories_retries_then_succeeds():
    route = respx.post(osv.OSV_QUERY_URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json=OSV_RESPONSE)]
    )
    osv._BACKOFF_SECONDS = 0.0
    async with httpx.AsyncClient() as client:
        bundle = await osv.fetch_advisories(client, PKG)
    assert route.call_count == 2
    assert bundle.sources_queried == ["osv"]
    assert bundle.advisories[0].fixed_version == "2.31.0"
    sent = json.loads(route.calls[0].request.content)
    assert set(sent) == {"package", "version"}  # coordinate-only egress (T6)


def test_repo_reader_rejects_unknown_files(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.25.1\n")
    (tmp_path / "secrets.env").write_text("KEY=hunter2\n")
    monkeypatch.setenv("REPO_ROOT", str(tmp_path))
    assert repo_reader.list_manifests() == ["requirements.txt"]
    assert "requests" in repo_reader.read_manifest("requirements.txt")
    with pytest.raises(ValueError):
        repo_reader.read_manifest("secrets.env")
    with pytest.raises(ValueError):
        repo_reader.read_manifest("../requirements.txt")


def test_report_writer_forces_pending_approval(tmp_path, monkeypatch):
    monkeypatch.setenv("STAGING_DIR", str(tmp_path))
    report = RemediationReport(
        assessment_id="a1",
        repo_ref="demo",
        findings=[],
        summary="clean",
        status=ReportStatus.PUBLISHED,  # writer must refuse to honor this
    )
    result = report_writer.write_draft(report.model_dump(mode="json"))
    staged = RemediationReport.model_validate_json((tmp_path / "a1.json").read_text())
    assert staged.status is ReportStatus.PENDING_APPROVAL
    assert result["assessment_id"] == "a1"
