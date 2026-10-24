import hashlib
import hmac
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from itsdangerous import BadSignature

from .dashboard import SESSION_COOKIE, _is_authenticated, _serializer, require_dashboard_auth
from .policy import Policy, PolicyStore, PolicyUpdate, ResetRequest, RevisionConflict


ASSETS = Path(__file__).resolve().parents[1] / "settings"
TEMPLATES = Path(__file__).resolve().parent / "templates"


def settings_router(settings, store: PolicyStore):
    router = APIRouter()

    @router.get("/settings", include_in_schema=False)
    @router.get("/settings/", include_in_schema=False)
    async def page(request: Request):
        if not _is_authenticated(request, settings):
            return RedirectResponse("/dashboard/login?next=/settings", status_code=303)
        if request.url.path == "/settings":
            return RedirectResponse("/settings/", status_code=308)
        return FileResponse(TEMPLATES / "settings.html", headers={"Cache-Control": "no-store"})

    @router.get("/settings/settings.css", include_in_schema=False)
    async def stylesheet():
        return FileResponse(ASSETS / "settings.css", headers={"Cache-Control": "no-store"})

    @router.get("/settings/settings.js", include_in_schema=False)
    async def javascript():
        return FileResponse(ASSETS / "settings.js", headers={"Cache-Control": "no-store"})

    def csrf(request):
        return hashlib.sha256(request.cookies.get(SESSION_COOKIE, "").encode()).hexdigest()

    def authorize_write(request):
        actor = require_dashboard_auth(request, settings)
        token = request.headers.get("x-csrf-token", "")
        # Custom header + signed, session-bound token; no cross-origin CORS allowance.
        try:
            payload = _serializer(settings).loads(token, max_age=settings.dashboard_session_max_age)
        except BadSignature:
            raise HTTPException(403, "Invalid CSRF token.") from None
        if not isinstance(payload, dict) or payload.get("purpose") != "settings-csrf" or not hmac.compare_digest(
            str(payload.get("session", "")), csrf(request)
        ):
            raise HTTPException(403, "Invalid CSRF token.")
        origin = request.headers.get("origin")
        if (origin is not None and origin != str(request.base_url).rstrip("/")) or request.headers.get(
            "sec-fetch-site", "same-origin"
        ) not in {"same-origin", "none"}:
            raise HTTPException(403, "Same-origin request required.")
        return actor

    def result(snapshot, request):
        return {
            **snapshot,
            "csrf_token": _serializer(settings).dumps({"purpose": "settings-csrf", "session": csrf(request)}),
            "defaults": Policy().model_dump(),
            "limits": {"request_bytes": settings.max_request_bytes,
                       "rate_requests": settings.rate_limit_requests,
                       "rate_window_seconds": settings.rate_limit_window_seconds},
        }

    @router.get("/waf-api/settings")
    async def read(request: Request):
        require_dashboard_auth(request, settings)
        return result(store.read(), request)

    @router.put("/waf-api/settings")
    async def update(request: Request, update: PolicyUpdate):
        actor = authorize_write(request)
        try:
            snapshot = store.update(update.policy, update.revision, actor)
        except RevisionConflict:
            raise HTTPException(409, "Settings changed in another session. Refresh and try again.") from None
        return result(snapshot, request)

    @router.post("/waf-api/settings/reset")
    async def reset(request: Request, update: ResetRequest):
        actor = authorize_write(request)
        try:
            snapshot = store.update(Policy(), update.revision, actor, "reset")
        except RevisionConflict:
            raise HTTPException(409, "Settings changed in another session. Refresh and try again.") from None
        return result(snapshot, request)

    # Reserve the management namespace: unsupported paths/methods never reach Flask.
    @router.api_route("/waf-api", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    @router.api_route("/waf-api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    async def unknown(request: Request, path: str = ""):
        require_dashboard_auth(request, settings)
        raise HTTPException(404, "Unknown WAF API endpoint.")

    return router
