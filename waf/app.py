import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .config import WAFSettings
from .dashboard import dashboard_router
from .rules import inspect_values


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
    app = FastAPI(title="Chillibek WAF", version="0.1.0")
    app.state.settings = settings
    app.include_router(dashboard_router(settings))

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {
            "status": "ok",
            "component": "chillibek-waf",
            "upstream": settings.upstream_base_url,
        }

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    async def proxy(path: str, request: Request) -> Response:
        body = await request.body()
        if len(body) > settings.max_request_bytes:
            _write_log(settings, request, "blocked", ["SIZE-001"], 10, 413)
            return JSONResponse({"success": False, "message": "Request too large."}, status_code=413)

        inspected_values = _collect_inspection_values(path, request, body)
        matched_rules, risk_score = inspect_values(inspected_values)
        if risk_score >= settings.block_threshold:
            _write_log(settings, request, "blocked", matched_rules, risk_score, 403)
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
            _write_log(settings, request, "upstream_error", matched_rules, risk_score, 502)
            return JSONResponse({"success": False, "message": "Upstream unavailable."}, status_code=502)

        response_headers = _response_headers(upstream_response.headers)
        _write_log(settings, request, "allowed", matched_rules, risk_score, upstream_response.status_code)
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
        values.append(body[:8192].decode("utf-8", errors="replace"))
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
) -> None:
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
