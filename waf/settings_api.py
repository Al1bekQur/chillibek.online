import hashlib
import hmac
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from itsdangerous import BadSignature

from .dashboard import SESSION_COOKIE, _serializer, require_dashboard_auth
from .policy import Policy, PolicyStore, PolicyUpdate, ResetRequest, RevisionConflict


ASSETS = Path(__file__).resolve().parents[1] / "settings"


def settings_router(settings, store: PolicyStore):
    router = APIRouter()

    @router.get("/settings", include_in_schema=False)
    async def page_redirect():
        return RedirectResponse("/settings/", status_code=308)

    @router.get("/settings/", include_in_schema=False)
    async def page():
        return FileResponse(ASSETS / "index.html", headers={"Cache-Control": "no-store"})

    @router.get("/settings/settings.css", include_in_schema=False)
    async def stylesheet():
        return FileResponse(ASSETS / "settings.css")

    @router.get("/settings/settings.js", include_in_schema=False)
    async def javascript():
        return FileResponse(ASSETS / "settings.js")

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
        if request.headers.get("sec-fetch-site") == "cross-site":
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
    @router.api_route("/waf-api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    async def unknown(request: Request, path: str):
        require_dashboard_auth(request, settings)
        raise HTTPException(404, "Unknown WAF API endpoint.")

    return router
