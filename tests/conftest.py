import pytest

from triage_mesh.harness import tools


@pytest.fixture(autouse=True)
def _skip_manifest_verification(monkeypatch):
    """Unit tests fake the tool layer; manifest pins are exercised explicitly
    in tests/test_integrity.py and the red-team suite."""

    async def _ok(mcp_url, headers, expected):
        return None

    monkeypatch.setattr(tools, "verify_manifest", _ok)
