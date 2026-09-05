"""OSV.dev client: package coordinate in, typed AdvisoryBundle out.

Everything OSV returns is untrusted text (threat T1); this module maps it into
typed Advisory objects and nothing else. Mapping is pure for testability.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from triage_mesh.schemas import Advisory, AdvisoryBundle, PackageCoordinate, Severity

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_RETRIES = 3
_BACKOFF_SECONDS = 1.0
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


async def post_with_retry(client: httpx.AsyncClient, url: str, payload: dict[str, Any]) -> httpx.Response:
    last_error: Exception | None = None
    for attempt in range(_RETRIES):
        try:
            response = await client.post(url, json=payload, timeout=15.0)
            if response.status_code in _RETRYABLE_STATUS:
                raise httpx.HTTPStatusError(
                    f"retryable status {response.status_code}",
                    request=response.request,
                    response=response,
                )
            response.raise_for_status()
            return response
        except (httpx.TransportError, httpx.HTTPStatusError) as error:
            if isinstance(error, httpx.HTTPStatusError) and error.response.status_code not in _RETRYABLE_STATUS:
                raise
            last_error = error
            await asyncio.sleep(_BACKOFF_SECONDS * 2**attempt)
    raise last_error  # type: ignore[misc]


def _severity_of(entry: dict[str, Any]) -> Severity:
    raw = str(entry.get("database_specific", {}).get("severity", "")).lower()
    if raw in ("critical", "high", "medium", "moderate", "low"):
        return Severity.MEDIUM if raw == "moderate" else Severity(raw)
    return Severity.UNKNOWN


def _fixed_version_of(entry: dict[str, Any], package: PackageCoordinate) -> str | None:
    for affected in entry.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != package.name.lower():
            continue
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                if "fixed" in event:
                    return str(event["fixed"])
    return None


def osv_to_advisories(package: PackageCoordinate, data: dict[str, Any]) -> list[Advisory]:
    advisories: list[Advisory] = []
    for entry in data.get("vulns", []):
        if not isinstance(entry, dict) or "id" not in entry:
            continue
        advisories.append(
            Advisory(
                id=str(entry["id"]),
                source="osv",
                aliases=[str(a) for a in entry.get("aliases", [])],
                summary=str(entry.get("summary", ""))[:2000],
                severity=_severity_of(entry),
                affected_package=package,
                fixed_version=_fixed_version_of(entry, package),
                references=[
                    str(ref.get("url", "")) for ref in entry.get("references", [])[:10]
                ],
            )
        )
    return advisories


async def fetch_advisories(client: httpx.AsyncClient, package: PackageCoordinate) -> AdvisoryBundle:
    payload = {
        "package": {"ecosystem": package.ecosystem.value, "name": package.name},
        "version": package.version,
    }
    response = await post_with_retry(client, OSV_QUERY_URL, payload)
    return AdvisoryBundle(
        package=package,
        advisories=osv_to_advisories(package, response.json()),
        sources_queried=["osv"],
    )
