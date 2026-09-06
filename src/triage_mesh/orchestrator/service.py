"""Orchestrator service.

Pipeline: scanner -> intel -> assessor, each behind a deadline. Intel failure
degrades the assessment to a partial report that says so; scanner failure
fails it. Publishing is this service's capability alone (threat T7): reports
stage as PENDING_APPROVAL and only POST /assessments/{id}/approve flips them.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from triage_mesh.harness.logging import get_logger, log
from triage_mesh.orchestrator import a2a
from triage_mesh.schemas import AssessmentState, RemediationReport, ReportStatus

logger = get_logger("orchestrator")


def _config() -> dict:
    return {
        "scanner_url": os.environ.get("SCANNER_URL", "http://127.0.0.1:7201"),
        "intel_url": os.environ.get("INTEL_URL", "http://127.0.0.1:7202"),
        "assessor_url": os.environ.get("ASSESSOR_URL", "http://127.0.0.1:7203"),
        "deadline": float(os.environ.get("TASK_DEADLINE_SECONDS", "120")),
        "published_dir": Path(os.environ.get("PUBLISHED_DIR", "published")),
    }


class Assessment:
    def __init__(self, assessment_id: str, repo_ref: str):
        self.id = assessment_id
        self.repo_ref = repo_ref
        self.state = AssessmentState.PENDING
        self.report: RemediationReport | None = None
        self.error: str | None = None


STORE: dict[str, Assessment] = {}


async def run_pipeline(assessment: Assessment) -> None:
    send_task = a2a.send_task  # late-bound so tests and middleware can swap it
    config = _config()
    correlation_id = assessment.id
    try:
        assessment.state = AssessmentState.SCANNING
        scan = await send_task(
            config["scanner_url"],
            {"repo_ref": assessment.repo_ref, "correlation_id": correlation_id},
            config["deadline"],
            audience="scanner",
        )
        inventory = scan["inventory"]

        assessment.state = AssessmentState.GATHERING_INTEL
        partial = False
        try:
            intel = await send_task(
                config["intel_url"],
                {"inventory": inventory, "correlation_id": correlation_id},
                config["deadline"],
                audience="intel",
            )
            bundles = intel["bundles"]
        except a2a.AgentTaskError as error:
            log(logger, "intel.degraded", correlation_id=correlation_id, error=str(error))
            bundles, partial = [], True

        assessment.state = AssessmentState.ASSESSING
        assessed = await send_task(
            config["assessor_url"],
            {
                "assessment_id": assessment.id,
                "inventory": inventory,
                "bundles": bundles,
                "partial": partial,
                "correlation_id": correlation_id,
            },
            config["deadline"],
            audience="assessor",
        )
        assessment.report = RemediationReport.model_validate(assessed["report"])
        assessment.state = AssessmentState.PENDING_APPROVAL
        log(
            logger,
            "assessment.ready",
            correlation_id=correlation_id,
            findings=len(assessment.report.findings),
            partial=partial,
        )
    except Exception as error:
        assessment.state = AssessmentState.FAILED
        assessment.error = str(error)
        log(logger, "assessment.failed", correlation_id=correlation_id, error=str(error))


class CreateAssessment(BaseModel):
    repo_ref: str


app = FastAPI(title="triage-mesh orchestrator", version="0.1.0")


@app.post("/assessments", status_code=202)
async def create_assessment(body: CreateAssessment) -> dict:
    assessment = Assessment(str(uuid.uuid4()), body.repo_ref)
    STORE[assessment.id] = assessment
    asyncio.get_running_loop().create_task(run_pipeline(assessment))
    log(logger, "assessment.created", correlation_id=assessment.id, repo_ref=body.repo_ref)
    return {"assessment_id": assessment.id, "state": assessment.state.value}


@app.get("/assessments/{assessment_id}")
async def get_assessment(assessment_id: str) -> dict:
    assessment = STORE.get(assessment_id)
    if assessment is None:
        raise HTTPException(404, "unknown assessment")
    return {
        "assessment_id": assessment.id,
        "state": assessment.state.value,
        "error": assessment.error,
        "report": assessment.report.model_dump(mode="json") if assessment.report else None,
    }


@app.post("/assessments/{assessment_id}/approve")
async def approve(assessment_id: str) -> dict:
    assessment = STORE.get(assessment_id)
    if assessment is None:
        raise HTTPException(404, "unknown assessment")
    if assessment.state is not AssessmentState.PENDING_APPROVAL or assessment.report is None:
        raise HTTPException(409, f"not awaiting approval (state: {assessment.state.value})")
    assessment.report.status = ReportStatus.PUBLISHED
    assessment.state = AssessmentState.PUBLISHED
    published_dir = _config()["published_dir"]
    published_dir.mkdir(parents=True, exist_ok=True)
    path = published_dir / f"{assessment.id}.json"
    path.write_text(assessment.report.model_dump_json(indent=2), encoding="utf-8")
    log(logger, "assessment.published", correlation_id=assessment.id, path=str(path))
    return {
        "assessment_id": assessment.id,
        "state": assessment.state.value,
        "published_at": str(path),
    }


def main() -> None:
    uvicorn.run(
        app,
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8080")),
        log_level="info",
    )


if __name__ == "__main__":
    main()
