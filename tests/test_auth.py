import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from triage_mesh.harness import auth

SECRET = "test-secret"


@pytest.fixture
def mesh_secret(monkeypatch):
    monkeypatch.setenv("MESH_SECRET", SECRET)


def test_mint_verify_roundtrip(mesh_secret):
    token = auth.mint("scanner", "repo-reader")
    claims = auth.verify(token, "repo-reader")
    assert claims["iss"] == "scanner"


def test_audience_scoping_blocks_lateral_reuse(mesh_secret):
    token = auth.mint("scanner", "repo-reader")
    with pytest.raises(auth.AuthError):
        auth.verify(token, "vuln-intel")  # T5: credential is not portable


def test_tampered_token_rejected(mesh_secret):
    token = auth.mint("scanner", "repo-reader")
    with pytest.raises(auth.AuthError):
        auth.verify(token[:-2] + "xx", "repo-reader")


def _protected_app() -> Starlette:
    async def endpoint(request):
        return JSONResponse({"caller": request.scope.get("state", {}).get("service_caller")})

    app = Starlette(routes=[Route("/rpc", endpoint, methods=["GET", "POST"])])
    return auth.ServiceAuthMiddleware(app, audience="repo-reader")


async def _request(app, method, headers=None):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, "/rpc", headers=headers or {})


async def test_middleware_rejects_missing_and_wrong_tokens(mesh_secret):
    app = _protected_app()
    assert (await _request(app, "POST")).status_code == 401
    wrong = auth.bearer_headers("orchestrator", "vuln-intel")
    assert (await _request(app, "POST", wrong)).status_code == 401


async def test_middleware_accepts_valid_token_and_names_caller(mesh_secret):
    app = _protected_app()
    response = await _request(app, "POST", auth.bearer_headers("scanner", "repo-reader"))
    assert response.status_code == 200
    assert response.json()["caller"] == "scanner"


async def test_get_discovery_stays_open(mesh_secret):
    assert (await _request(_protected_app(), "GET")).status_code == 200


async def test_disabled_without_secret(monkeypatch):
    monkeypatch.delenv("MESH_SECRET", raising=False)
    assert (await _request(_protected_app(), "POST")).status_code == 200
