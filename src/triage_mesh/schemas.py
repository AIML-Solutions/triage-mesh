"""Boundary objects for every A2A artifact and MCP tool payload.

Every object that crosses a service boundary is defined here and validated on
both sides. `extra="forbid"` everywhere: an unexpected field is a rejected
message, not a warning (threat-model layer 4).
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


class Ecosystem(str, enum.Enum):
    PYPI = "PyPI"
    NPM = "npm"


class PackageCoordinate(StrictModel):
    """The only shape allowed to leave the mesh toward vuln intel APIs (threat T6)."""

    ecosystem: Ecosystem
    name: str = Field(min_length=1, max_length=214)
    version: str = Field(min_length=1, max_length=64)


class DependencyInventory(StrictModel):
    """Scanner output: what the repo depends on, and where that claim came from."""

    repo_ref: str
    manifests: list[str] = Field(description="Manifest paths the inventory was derived from")
    packages: list[PackageCoordinate]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Advisory(StrictModel):
    """One advisory as fetched from an intel source.

    `summary` and `details` are attacker-influenced text (threat T1): they are
    data to reason over, never instructions. Phase 2 wraps them in trust labels.
    """

    id: str
    source: str = Field(description="e.g. 'osv' or 'nvd'")
    aliases: list[str] = Field(default_factory=list)
    summary: str = ""
    severity: Severity = Severity.UNKNOWN
    affected_package: PackageCoordinate
    fixed_version: str | None = None
    references: list[str] = Field(default_factory=list)


class AdvisoryBundle(StrictModel):
    """Intel output: everything known about one package coordinate."""

    package: PackageCoordinate
    advisories: list[Advisory]
    sources_queried: list[str]
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Finding(StrictModel):
    """Assessor output: one advisory judged in the context of this repo."""

    package: PackageCoordinate
    advisory_id: str
    severity: Severity
    exploitability_note: str
    recommended_action: str
    fixed_version: str | None = None


class ReportStatus(str, enum.Enum):
    PENDING_APPROVAL = "pending_approval"
    PUBLISHED = "published"


class RemediationReport(StrictModel):
    """The human-gated end product. Only the orchestrator may flip its status."""

    assessment_id: str
    repo_ref: str
    findings: list[Finding]
    summary: str
    partial: bool = Field(
        default=False,
        description="True when intel or scanning degraded and the report says so",
    )
    status: ReportStatus = ReportStatus.PENDING_APPROVAL
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AssessmentState(str, enum.Enum):
    """Lifecycle of one assessment as tracked by the orchestrator."""

    PENDING = "pending"
    SCANNING = "scanning"
    GATHERING_INTEL = "gathering_intel"
    ASSESSING = "assessing"
    PENDING_APPROVAL = "pending_approval"
    PUBLISHED = "published"
    FAILED = "failed"
