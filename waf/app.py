import asyncio
import json
import re
import secrets
import base64
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from .config import WAFSettings
from .dashboard import dashboard_router, require_dashboard_auth, _css, _javascript
from .policy import Policy, PolicyStore
from .rules import inspect_headers, inspect_values
from .parsing import request_values
from .protocol import ProtocolGuard
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

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        # Default validation errors echo rejected inputs, potentially secrets.
        return JSONResponse({'detail': [{'type': item['type'], 'loc': item['loc']} for item in error.errors()]}, status_code=422)

    @app.middleware("http")
    async def management_security(request: Request, call_next):
        management = request.url.path == "/waf-api" or request.url.path.startswith(("/waf-api/", "/dashboard", "/settings"))
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
                if request.url.path == "/waf-api" or request.url.path.startswith("/waf-api/"):
                    try:
                        require_dashboard_auth(request, settings)
                    except HTTPException as error:
                        store.audit(None, "access", {"path": safe_path(request.url.path), "status": error.status_code})
                        return JSONResponse({"detail": error.detail}, status_code=error.status_code,
                                            headers={"Cache-Control": "no-store"})
            response = await call_next(request)
            if management:
                store.audit(actor, "access", {"path": safe_path(request.url.path), "method": request.method,
                                               "status": response.status_code})
                response.headers["Cache-Control"] = "no-store"
                response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['Referrer-Policy'] = 'no-referrer'
            script_hash = base64.b64encode(hashlib.sha256(_javascript().encode()).digest()).decode()
            style_hash = base64.b64encode(hashlib.sha256(_css().encode()).digest()).decode()
            if management or request.url.path.startswith('/settings'):
                response.headers['Content-Security-Policy'] = ("default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
                    "form-action 'self'; script-src 'self' 'sha256-" + script_hash + "'; style-src 'self' 'sha256-" + style_hash + "'")
            if request.url.scheme == 'https':
                response.headers['Strict-Transport-Security'] = 'max-age=31536000'
            return response
        except (sqlite3.Error, OSError):
            return JSONResponse({"detail": "WAF policy storage unavailable."}, status_code=503,
                                headers={"Cache-Control": "no-store"})

    @app.get("/health")
    async def health() -> dict[str, str]:
        store.read()
        return {
            "status": "ok",
            "component": "chillibek-waf",
        }

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    async def proxy(path: str, request: Request) -> Response:
        # One immutable snapshot per request; a committed update is used by the next request,
        # including requests handled by another worker using the same durable volume.
        policy = Policy.model_validate(store.read()["policy"])
        matched_rules, risk_score = [], 0
        block_status = 403
        ip = request.client.host if request.client else "unknown"
        route = safe_path(request.url.path)
        if policy.rate_limiting and (store.over_limit(
            "proxy", ip, settings.rate_limit_requests, settings.rate_limit_window_seconds,
        ) or store.over_limit('route:' + route, ip, settings.route_limit_requests, settings.rate_limit_window_seconds)):
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
        enabled = {name for name in ("sql_injection", "xss", "path_traversal", "command_injection") if getattr(policy, name)}
        try:
            values = _collect_inspection_values(path, request, body)
        except (ValueError, UnicodeError, RecursionError):
            _write_log(settings, request, 'blocked', ['PARSE-001'], 0, 400, policy)
            return JSONResponse({'detail': 'Malformed request data.'}, status_code=400)
        detected, score = inspect_values(values, enabled)
        matched_rules.extend(detected)
        risk_score += score
        if risk_score >= settings.block_threshold and policy.mode == "block":
            _write_log(settings, request, "blocked", matched_rules, risk_score, 403, policy)
            return JSONResponse({"success": False, "message": "Request blocked by WAF."}, status_code=403)

        if policy.bot_detection:
            # 404s are counted from actual upstream outcomes, not User-Agent labels.
            if store.probe_blocked(ip, settings.bot_probe_limit):
                matched_rules.append('BOT-001')
                risk_score += settings.block_threshold
                if policy.mode == 'block':
                    _write_log(settings, request, 'blocked', matched_rules, risk_score, 429, policy)
                    return JSONResponse({'detail': 'Temporary probe limit.'}, status_code=429)
        login_keys = None
        if policy.brute_force and path == 'api/staff/login' and request.method == 'POST':
            try:
                account = json.loads(body).get('username', '')
            except (ValueError, AttributeError):
                account = ''
            login_keys = store.login_keys(ip, account[:80] if isinstance(account, str) else '')
            if store.login_locked(login_keys):
                matched_rules.append('BRUTE-001')
                risk_score += settings.block_threshold
                if policy.mode == 'block':
                    _write_log(settings, request, 'blocked', matched_rules, settings.block_threshold, 429, policy)
                    return JSONResponse({'detail': 'Too many login attempts.'}, status_code=429, headers={'Retry-After': '30'})

        upstream_url = _build_upstream_url(settings, path, request.url.query)
        headers = _forward_headers(request.headers)
        headers["x-forwarded-for"] = request.client.host if request.client else "unknown"
        headers["x-forwarded-proto"] = request.url.scheme
        headers["x-forwarded-host"] = request.headers.get("host", "")

        lease = 'proxy:' + secrets.token_hex(16)
        acquired = False
        if policy.rate_limiting:
            acquired = store.acquire(lease, ip, settings.max_concurrent_requests,
                                     settings.max_concurrent_per_ip, settings.request_timeout_seconds + 30)
            if not acquired:
                matched_rules.append('CONCURRENT-001')
                if policy.mode == 'block':
                    _write_log(settings, request, 'blocked', matched_rules, settings.block_threshold, 429, policy)
                    return JSONResponse({'detail': 'Too many concurrent requests.'}, status_code=429)
        try:
            async with httpx.AsyncClient(
                timeout=settings.upstream_timeout_seconds,
                transport=settings.upstream_transport,
            ) as client:
                upstream_response = await asyncio.wait_for(client.request(
                    request.method,
                    upstream_url,
                    content=body,
                    headers=headers,
                ), timeout=settings.request_timeout_seconds)
        except asyncio.TimeoutError:
            _write_log(settings, request, 'upstream_error', ['TIMEOUT-001'], 0, 504, policy)
            return JSONResponse({'detail': 'Upstream request timed out.'}, status_code=504)
        except httpx.HTTPError:
            _write_log(settings, request, "upstream_error", matched_rules, risk_score, 502, policy)
            return JSONResponse({"success": False, "message": "Upstream unavailable."}, status_code=502)
        finally:
            if acquired:
                store.release(lease)

        if login_keys:
            store.login_result(login_keys, upstream_response.status_code in {400, 401, 403})
            if upstream_response.status_code in {400, 401, 403}:
                matched_rules.append('BRUTE-FAIL-001')
        if policy.bot_detection and upstream_response.status_code == 404:
            store.over_limit('probes', ip, settings.bot_probe_limit, 60)
            matched_rules.append('BOT-PROBE-001')

        response_headers = _response_headers(upstream_response.headers)
        _write_log(settings, request, "allowed", matched_rules, risk_score, upstream_response.status_code, policy)
        response = Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get("content-type"),
        )
        if settings.forward_upstream_cookies:
            # The in-process WSGI adapter must preserve existing Flask sessions,
            # including multiple Set-Cookie headers. Cookie values are never logged.
            for cookie in upstream_response.headers.get_list("set-cookie"):
                response.headers.append("set-cookie", cookie)
        return response

    app.add_middleware(ProtocolGuard, settings=settings, store=store)
    return app


def safe_path(path):
    """Only known route templates enter logs/counter keys; never arbitrary path data."""
    if path in {'/api/menu', '/api/menu/add', '/api/staff/login', '/api/orders', '/api/orders/archive',
                '/dashboard', '/dashboard/login', '/dashboard/logout', '/settings', '/settings/',
                '/waf-api', '/waf-api/settings', '/waf-api/settings/reset'}:
        return path
    if re.fullmatch(r'/api/(?:orders|menu/(?:edit|delete))/[0-9]+', path):
        return re.sub(r'/[0-9]+$', '/:id', path)
    return '/[unrecognized]'


def _collect_inspection_values(path: str, request: Request, body: bytes) -> list[str]:
    values = request_values('/' + path, request.url.query, request.headers.get('content-type', ''), body)
    values.append(request.scope.get('raw_path', b'').decode('utf-8', 'replace'))
    for name, value in request.headers.items():
        if name.lower() in INSPECTED_HEADERS:
            values.append(value)
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
    connection_tokens = {value.strip().lower() for value in headers.get('connection', '').split(',')}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in HOP_BY_HOP_HEADERS | connection_tokens or lowered in {"host", "forwarded", "x-real-ip", "content-length"} or lowered.startswith("x-forwarded-"):
            continue
        forwarded[name] = value
    return forwarded


def _response_headers(headers: httpx.Headers) -> dict[str, str]:
    connection_tokens = {value.strip().lower() for value in headers.get('connection', '').split(',')}
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in HOP_BY_HOP_HEADERS | SENSITIVE_HEADERS | connection_tokens | {'content-length', 'content-encoding'}
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
        "path": safe_path(request.url.path),
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
