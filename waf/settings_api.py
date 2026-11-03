import hashlib
import hmac
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from itsdangerous import BadSignature
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator

from .dashboard import SESSION_COOKIE, _is_authenticated, _serializer, require_dashboard_auth
from .policy import Policy, PolicyStore, PolicyUpdate, ResetRequest, RevisionConflict
from .enforcement import staff_policy
from .csp_policy import coverage


ASSETS = Path(__file__).resolve().parents[1] / "settings"
TEMPLATES = Path(__file__).resolve().parent / "templates"


class ManualBlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["ip", "account"]
    value: StrictStr = Field(min_length=1, max_length=80)
    duration_seconds: StrictInt = Field(ge=60, le=604800)
    reason: StrictStr = Field(min_length=1, max_length=200)

    @field_validator("value", "reason")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Value must not be blank.")
        return value.strip()


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
        policy = Policy.model_validate(snapshot["policy"])
        login_policy = staff_policy(policy, settings.allow_disabled_mode)
        blocks = store.active_blocks()
        for block in blocks:
            all_routes = block['manual'] and block['kind'] == 'ip' and policy.mode == 'block'
            block['enforced'] = all_routes or login_policy.mode == 'block' and (block['manual'] or login_policy.brute_force)
            block['scope'] = 'all backend routes' if all_routes else 'staff login'
        return {
            **snapshot,
            "csrf_token": _serializer(settings).dumps({"purpose": "settings-csrf", "session": csrf(request)}),
            "defaults": Policy().model_dump(mode='json'),
            "capabilities": {
                "allow_disabled_mode": settings.allow_disabled_mode,
                "production_login_guard_required": not settings.allow_disabled_mode,
            },
            "effective": {
                "mode": policy.mode,
                "login_abuse": (
                    "enforced_production" if not settings.allow_disabled_mode
                    else "disabled_test_only" if policy.mode == "disabled" or not policy.brute_force
                    else "enforced" if policy.mode == "block"
                    else "monitoring"
                ),
                "rate_limit_requests": min(policy.rate_limit_requests, settings.rate_limit_requests),
                "rate_limit_window_seconds": policy.rate_limit_window_seconds,
                "route_limit_requests": min(policy.route_limit_requests, settings.route_limit_requests),
                "route_limit_window_seconds": policy.route_limit_window_seconds,
                "request_size_bytes": min(policy.request_size_bytes, settings.max_request_bytes),
                "hard_request_size_bytes": settings.hard_max_request_bytes,
                "backend_body_size_bytes": getattr(request.app.state, 'backend_body_size_bytes', None),
            },
            "blocks": blocks,
            "block_history": store.block_history(),
            "csp_coverage": coverage(policy, settings),
        }

    @router.get("/waf-api/settings")
    async def read(request: Request):
        require_dashboard_auth(request, settings)
        snapshot = store.read()
        if not settings.allow_disabled_mode and (
            snapshot["policy"]["mode"] == "disabled" or not snapshot["policy"]["brute_force"]
        ):
            raise HTTPException(503, "Stored security policy violates mandatory production login protection.")
        return result(snapshot, request)

    @router.put("/waf-api/settings")
    async def update(request: Request, update: PolicyUpdate):
        actor = authorize_write(request)
        if update.policy.mode == "disabled" and not settings.allow_disabled_mode:
            raise HTTPException(422, "Disabled mode is restricted to isolated test environments.")
        if not settings.allow_disabled_mode and not update.policy.brute_force:
            raise HTTPException(422, "Login Abuse Protection cannot be disabled in production.")
        if update.policy.mode == "monitor" and not update.policy.event_logging:
            raise HTTPException(422, "Security Event Logging is required in Monitor mode.")
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

    @router.post("/waf-api/blocks")
    async def create_block(request: Request, block: ManualBlockRequest):
        actor = authorize_write(request)
        try:
            store.create_manual_block(
                block.kind, block.value, block.duration_seconds, block.reason.strip(), actor,
            )
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        return result(store.read(), request)

    @router.delete("/waf-api/blocks/{block_id}")
    async def remove_block(request: Request, block_id: str):
        actor = authorize_write(request)
        if not store.unblock(block_id, actor):
            raise HTTPException(404, "Active block not found.")
        return result(store.read(), request)

    # Reserve the management namespace: unsupported paths/methods never reach Flask.
    @router.api_route("/waf-api", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    @router.api_route("/waf-api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    async def unknown(request: Request, path: str = ""):
        require_dashboard_auth(request, settings)
        raise HTTPException(404, "Unknown WAF API endpoint.")

    return router
