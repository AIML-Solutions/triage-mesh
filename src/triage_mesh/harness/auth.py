"""Pairwise service auth (threat T5): short-lived JWTs on every internal call.

HS256 with a deployment-wide MESH_SECRET, but audience-scoped: a token minted
for repo-reader does not authenticate to vuln-intel, so a compromised
container cannot reuse its credential laterally. Auth is enabled whenever
MESH_SECRET is set (compose/K8s always set it; bare dev runs may not).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import jwt

_TTL = timedelta(minutes=5)
_ALGORITHM = "HS256"


class AuthError(RuntimeError):
    pass


def enabled() -> bool:
    return bool(os.environ.get("MESH_SECRET"))


def _secret() -> str:
    secret = os.environ.get("MESH_SECRET")
    if not secret:
        raise AuthError("MESH_SECRET not configured")
    return secret


def mint(issuer: str, audience: str) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {"iss": issuer, "aud": audience, "iat": now, "exp": now + _TTL},
        _secret(),
        algorithm=_ALGORITHM,
    )


def verify(token: str, audience: str) -> dict:
    try:
        return jwt.decode(token, _secret(), algorithms=[_ALGORITHM], audience=audience)
    except jwt.PyJWTError as error:
        raise AuthError(f"token rejected: {error}") from error


def bearer_headers(issuer: str, audience: str) -> dict[str, str]:
    if not enabled():
        return {}
    return {"Authorization": f"Bearer {mint(issuer, audience)}"}


class ServiceAuthMiddleware:
    """ASGI middleware: POST requests must carry a valid audience-scoped token.

    GET stays open — agent cards are discovery metadata, and docs/health need
    no secret. All state changes and RPC go over POST in this system.
    """

    def __init__(self, app, audience: str):
        self._app = app
        self._audience = audience

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("method") == "POST" and enabled():
            headers = dict(scope.get("headers") or [])
            token = (headers.get(b"authorization") or b"").decode().removeprefix("Bearer ").strip()
            try:
                claims = verify(token, self._audience)
                scope.setdefault("state", {})["service_caller"] = claims.get("iss")
            except AuthError as error:
                await _reject(send, str(error))
                return
        await self._app(scope, receive, send)


async def _reject(send, detail: str) -> None:
    body = f'{{"detail": "unauthorized: {detail}"}}'.encode()
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})
