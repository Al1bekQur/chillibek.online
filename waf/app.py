import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .config import WAFSettings
from .dashboard import dashboard_router, require_dashboard_auth
from .policy import Policy, PolicyStore
from .rules import inspect_headers, inspect_values
from .settings_api import settings_router


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}
INSPECTED_HEADERS = {"user-agent", "content-type", "accept", "referer"}


def create_app(settings: WAFSettings | None = None) -> FastAPI:
    settings = settings or WAFSettings()
    app = FastAPI(title="Chillibek WAF", version="0.2.0", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    store = PolicyStore(settings.policy_path or settings.log_path.parent / "policy.sqlite3")
    app.state.policy_store = store
    app.include_router(dashboard_router(settings))
    app.include_router(settings_router(settings, store))

    @app.middleware("http")
    async def management_security(request: Request, call_next):
        management = request.url.path.startswith(("/waf-api/", "/dashboard"))
        try:
            if management:
                # Authentication, authorization, login throttling and audit never depend on policy toggles.
                actor = None
                try:
                    actor = require_dashboard_auth(request, settings)
                except HTTPException:
                    pass
                if request.url.path == "/dashboard/login" and request.method == "POST" and store.over_limit(
                    "login", request.client.host if request.client else "unknown", 5, 60
                ):
                    store.audit(actor, "access", {"path": "/dashboard/login", "status": 429})
                    return JSONResponse({"detail": "Too many login attempts."}, status_code=429)
                # Authenticate before body validation, even for malformed mutation requests.
                if request.url.path.startswith("/waf-api/"):
                    try:
                        require_dashboard_auth(request, settings)
                    except HTTPException as error:
                        store.audit(None, "access", {"path": request.url.path[:240], "status": error.status_code})
                        return JSONResponse({"detail": error.detail}, status_code=error.status_code,
                                            headers={"Cache-Control": "no-store"})
            response = await call_next(request)
            if management:
                store.audit(actor, "access", {"path": request.url.path[:240], "method": request.method,
                                               "status": response.status_code})
                response.headers["Cache-Control"] = "no-store"
                response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response
        except (sqlite3.Error, OSError):
            return JSONResponse({"detail": "WAF policy storage unavailable."}, status_code=503,
                                headers={"Cache-Control": "no-store"})

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {
            "status": "ok",
            "component": "chillibek-waf",
            "upstream": settings.upstream_base_url,
        }

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    async def proxy(path: str, request: Request) -> Response:
        # One immutable snapshot per request; a committed update is used by the next request,
        # including requests handled by another worker using the same durable volume.
        policy = Policy.model_validate(store.read()["policy"])
        matched_rules, risk_score = [], 0
        block_status = 403
        if policy.rate_limiting and store.over_limit(
            "proxy", request.client.host if request.client else "unknown",
            settings.rate_limit_requests, settings.rate_limit_window_seconds,
        ):
            matched_rules.append("RATE-001")
            risk_score += settings.block_threshold
            block_status = 429
        if policy.suspicious_headers and inspect_headers(request.headers):
            matched_rules.append("HEADER-001")
            risk_score += settings.block_threshold
        if matched_rules and policy.mode == "block":
            _write_log(settings, request, "blocked", matched_rules, risk_score, block_status, policy)
            return JSONResponse({"success": False, "message": "Request blocked by WAF."}, status_code=block_status)

        chunks, size = [], 0
        oversized = False
        async for chunk in request.stream():
            size += len(chunk)
            if policy.request_size and size > settings.max_request_bytes:
                oversized = True
                if policy.mode == "block":
                    _write_log(settings, request, "blocked", ["SIZE-001"], 10, 413, policy)
                    return JSONResponse({"success": False, "message": "Request too large."}, status_code=413)
            chunks.append(chunk)
        body = b"".join(chunks)
        if oversized:
            matched_rules.append("SIZE-001")
            risk_score += 10
        enabled = {name for name in ("sql_injection", "xss", "path_traversal") if getattr(policy, name)}
        detected, score = inspect_values(_collect_inspection_values(path, request, body), enabled)
        matched_rules.extend(detected)
        risk_score += score
        if risk_score >= settings.block_threshold and policy.mode == "block":
            _write_log(settings, request, "blocked", matched_rules, risk_score, 403, policy)
            return JSONResponse({"success": False, "message": "Request blocked by WAF."}, status_code=403)

        upstream_url = _build_upstream_url(settings, path, request.url.query)
        headers = _forward_headers(request.headers)
        headers["x-forwarded-for"] = request.client.host if request.client else "unknown"
        headers["x-forwarded-proto"] = request.url.scheme
        headers["x-forwarded-host"] = request.headers.get("host", "")

        try:
            async with httpx.AsyncClient(
                timeout=settings.upstream_timeout_seconds,
                transport=settings.upstream_transport,
            ) as client:
                upstream_response = await client.request(
                    request.method,
                    upstream_url,
                    content=body,
                    headers=headers,
                )
        except httpx.HTTPError:
            _write_log(settings, request, "upstream_error", matched_rules, risk_score, 502, policy)
            return JSONResponse({"success": False, "message": "Upstream unavailable."}, status_code=502)

        response_headers = _response_headers(upstream_response.headers)
        _write_log(settings, request, "allowed", matched_rules, risk_score, upstream_response.status_code, policy)
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get("content-type"),
        )

    return app


def _collect_inspection_values(path: str, request: Request, body: bytes) -> list[str]:
    values = ["/" + path, request.url.query]
    for name, value in request.headers.items():
        if name.lower() in INSPECTED_HEADERS:
            values.append(value)
    content_type = request.headers.get("content-type", "")
    if body and _is_textual(content_type):
        values.append(body.decode("utf-8", errors="replace"))
    return values


def _is_textual(content_type: str) -> bool:
    lowered = content_type.lower()
    return (
        lowered.startswith("text/")
        or "json" in lowered
        or "xml" in lowered
        or "x-www-form-urlencoded" in lowered
    )


def _build_upstream_url(settings: WAFSettings, path: str, query: str) -> str:
    base = settings.upstream_base_url.rstrip("/")
    url = f"{base}/{path}"
    if query:
        url = f"{url}?{query}"
    return url


def _forward_headers(headers: Mapping[str, str]) -> dict[str, str]:
    forwarded = {}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in HOP_BY_HOP_HEADERS or lowered == "host" or lowered.startswith("x-forwarded-"):
            continue
        forwarded[name] = value
    return forwarded


def _response_headers(headers: httpx.Headers) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in HOP_BY_HOP_HEADERS | SENSITIVE_HEADERS
    }


def _write_log(
    settings: WAFSettings,
    request: Request,
    decision: str,
    matched_rules: list[str],
    risk_score: int,
    status_code: int,
    policy: Policy,
) -> None:
    if not policy.event_logging:
        return
    log_path: Path = settings.log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "path": request.url.path,
        "query_present": bool(request.url.query),
        "content_length": request.headers.get("content-length"),
        "matched_rules": matched_rules,
        "risk_score": risk_score,
        "decision": decision,
        "status_code": status_code,
    }
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, ensure_ascii=False) + "\n")


app = create_app()
