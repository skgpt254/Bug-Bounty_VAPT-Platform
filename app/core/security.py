"""
Access control for a self-hosted tool that can trigger outbound network
scans on command — if this app is ever reachable beyond localhost, an
unauthenticated `POST /api/programs/{id}/scan` is a way for a stranger to
make *your* IP send active traffic at *their* chosen target. Auth is
optional (blank APP_PASSWORD == trusted-loopback-only deployment, the
common case for a personal tool) but strongly recommended for anything
bound to a non-loopback interface.

Two surfaces:
  - JSON API: `X-API-Key: <APP_PASSWORD>` header, checked by `require_api_key`.
  - Dashboard: signed session cookie set by POST /login, checked by
    `require_dashboard_session`. Signing uses HMAC with SESSION_SECRET
    (auto-generated and persisted to .session_secret on first run if unset)
    so cookies survive process restarts without a server-side session store.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from pathlib import Path

from fastapi import Cookie, Header, HTTPException, Request
from fastapi.responses import RedirectResponse

from app.config import settings

SESSION_COOKIE = "bbvapt_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days

_SECRET_FILE = Path(".session_secret")


def _get_session_secret() -> str:
    if settings.session_secret:
        return settings.session_secret
    if _SECRET_FILE.exists():
        return _SECRET_FILE.read_text().strip()
    import secrets as _secrets
    generated = _secrets.token_hex(32)
    try:
        _SECRET_FILE.write_text(generated)
    except OSError:
        pass  # read-only filesystem etc. — falls back to a per-process secret
    return generated


def _sign(value: str) -> str:
    secret = _get_session_secret()
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def make_session_token() -> str:
    expiry = str(int(time.time()) + SESSION_MAX_AGE)
    return f"{expiry}.{_sign(expiry)}"


def verify_session_token(token: str) -> bool:
    try:
        expiry, sig = token.split(".", 1)
    except ValueError:
        return False
    if not hmac.compare_digest(sig, _sign(expiry)):
        return False
    return int(expiry) > time.time()


def auth_enabled() -> bool:
    return bool(settings.app_password)


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if not auth_enabled():
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, settings.app_password):
        raise HTTPException(401, "missing or invalid X-API-Key header")


async def require_dashboard_session(request: Request, bbvapt_session: str | None = Cookie(default=None)):
    """Use as a dependency on dashboard routes. Redirects to /login instead
    of raising, since these are browser-navigated HTML pages.
    """
    if not auth_enabled():
        return
    if not bbvapt_session or not verify_session_token(bbvapt_session):
        raise _RedirectToLogin(str(request.url.path))


class _RedirectToLogin(Exception):
    def __init__(self, next_path: str):
        self.next_path = next_path


class RateLimitMiddleware:
    """Minimal in-memory sliding-window limiter for mutating requests
    (POST/PATCH/DELETE). Not a substitute for a real reverse-proxy rate
    limiter in a multi-user deployment, but stops naive abuse/accidental
    hammering of scan-trigger endpoints out of the box.
    """

    def __init__(self, app, max_requests: int = 20, window_seconds: int = 60):
        self.app = app
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits: dict[str, list[float]] = {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PATCH", "DELETE"):
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        key = client[0] if client else "unknown"
        now = time.time()
        hits = [t for t in self._hits.get(key, []) if now - t < self.window]
        hits.append(now)
        self._hits[key] = hits

        if len(hits) > self.max_requests:
            await send({"type": "http.response.start", "status": 429,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body",
                        "body": b'{"detail":"rate limit exceeded, slow down"}'})
            return

        await self.app(scope, receive, send)
