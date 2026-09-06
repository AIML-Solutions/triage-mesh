import pytest
from pydantic import ValidationError

from triage_mesh.schemas import (
    Advisory,
    DependencyInventory,
    Ecosystem,
    PackageCoordinate,
    RemediationReport,
    ReportStatus,
    Severity,
)


def test_package_coordinate_roundtrip():
    pkg = PackageCoordinate(ecosystem=Ecosystem.PYPI, name="requests", version="2.25.1")
    assert PackageCoordinate.model_validate_json(pkg.model_dump_json()) == pkg


def test_extra_fields_rejected_everywhere():
    with pytest.raises(ValidationError):
        PackageCoordinate(ecosystem=Ecosystem.PYPI, name="requests", version="1.0", registry="evil")
    with pytest.raises(ValidationError):
        DependencyInventory(repo_ref="demo", manifests=[], packages=[], exfil_channel="dns")


def test_advisory_defaults_are_safe():
    adv = Advisory(
        id="GHSA-xxxx",
        source="osv",
        affected_package=PackageCoordinate(
            ecosystem=Ecosystem.NPM, name="lodash", version="4.17.15"
        ),
    )
    assert adv.severity is Severity.UNKNOWN
    assert adv.summary == ""


def test_report_starts_pending_approval():
    report = RemediationReport(assessment_id="a1", repo_ref="demo", findings=[], summary="clean")
    assert report.status is ReportStatus.PENDING_APPROVAL
