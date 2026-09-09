#!/usr/bin/env python3
"""Record the flagship's tool-call trajectory as a multiclaw-harness run.

Runs the three agents in-process against the seed fixture with a fake tool
layer (no containers, no network, no tokens) and writes a run record in the
JSONL shape multiclaw-harness evaluates — so the flagship's behaviour is
regression-gated by AIML Solutions' own harness in CI.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import anyio

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from triage_mesh.agents import assessor, intel, scanner  # noqa: E402
from triage_mesh.harness import tools  # noqa: E402
from triage_mesh.manifests import PARSERS  # noqa: E402

SEED = ROOT / "demo" / "seed-repo"


def canned_bundle(args: dict) -> dict:
    package = {"ecosystem": args["ecosystem"], "name": args["name"], "version": args["version"]}
    return {
        "package": package,
        "advisories": [
            {
                "id": f"GHSA-fixture-{args['name']}",
                "source": "osv",
                "summary": "fixture advisory",
                "severity": "high",
                "affected_package": package,
                "fixed_version": "9.9.9",
            }
        ],
        "sources_queried": ["osv"],
    }


async def run() -> dict:
    trajectory: list[str] = []

    async def fake_call_tool(url, tool, args, headers=None):
        trajectory.append(tool)
        if tool == "list_manifests":
            return sorted(name for name in PARSERS if (SEED / name).is_file())
        if tool == "read_manifest":
            return (SEED / args["filename"]).read_text()
        if tool == "query_advisories":
            return canned_bundle(args)
        if tool == "write_draft":
            return {
                "assessment_id": args["report"]["assessment_id"],
                "staged_at": "staging/fixture.json",
            }
        raise RuntimeError(f"unexpected tool {tool}")

    async def no_verify(mcp_url, headers, expected):
        return None

    tools.call_tool = fake_call_tool
    tools.verify_manifest = no_verify

    started = time.monotonic()
    scan = await scanner.handle({"repo_ref": "demo/seed-repo", "correlation_id": "harness"})
    gathered = await intel.handle({"inventory": scan["inventory"], "correlation_id": "harness"})
    assessed = await assessor.handle(
        {
            "assessment_id": "harness",
            "inventory": scan["inventory"],
            "bundles": gathered["bundles"],
            "partial": False,
            "correlation_id": "harness",
        }
    )
    latency_ms = int((time.monotonic() - started) * 1000)
    report = assessed["report"]
    outcome = (
        f"Report status {report['status']} with {len(report['findings'])} findings across "
        f"{len(scan['inventory']['packages'])} packages; human approval required before "
        f"publication; partial={report['partial']}."
    )
    return {
        "case_id": "triage_mesh_seed_assessment",
        "tools": trajectory,
        "latency_ms": latency_ms,
        "estimated_cost_usd": 0.0,
        "outcome_text": outcome,
        "metadata": {
            "model": "mock",
            "provider": "MODEL_PROVIDER=mock",
            "fixture": "demo/seed-repo",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    record = anyio.run(run)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record) + "\n", encoding="utf-8")
    print(f"recorded {len(record['tools'])} tool calls -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
