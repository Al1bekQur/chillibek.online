from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request

from waf.app import create_app
from waf.config import WAFSettings


@pytest.fixture
async def upstream_server():
    upstream = FastAPI()
    captured = {}

    @upstream.get("/api/menu")
    async def menu(request: Request):
        captured["headers"] = dict(request.headers)
        return [{"id": 1, "name": "Synthetic item", "price": 1000}]

    @upstream.post("/api/orders")
    async def orders(request: Request):
        captured["headers"] = dict(request.headers)
        captured["body"] = await request.json()
        return {"success": True}

    transport = httpx.ASGITransport(app=upstream)
    yield transport, captured


@pytest.fixture
async def waf_client(tmp_path, upstream_server, monkeypatch):
    upstream_transport, captured = upstream_server
    settings = WAFSettings(
        upstream_base_url="http://upstream.test",
        max_request_bytes=1024,
        upstream_timeout_seconds=0.2,
        log_path=tmp_path / "waf.log",
        upstream_transport=upstream_transport,
    )
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://waf.test") as client:
        yield client, settings.log_path, captured


@pytest.mark.anyio
async def test_normal_menu_request_allowed(waf_client):
    client, _, _ = waf_client
    response = await client.get("/api/menu")
    assert response.status_code == 200
    assert response.json()[0]["name"] == "Synthetic item"


@pytest.mark.anyio
async def test_valid_json_post_forwarded(waf_client):
    client, _, captured = waf_client
    payload = {"table_number": "1", "items": [{"id": 1, "qty": 1}]}
    response = await client.post("/api/orders", json=payload)
    assert response.status_code == 200
    assert captured["body"] == payload


@pytest.mark.anyio
@pytest.mark.parametrize(
    "payload",
    [
        {"q": "' OR 1=1 --"},
        {"q": "<script>alert(1)</script>"},
        {"q": "../../etc/passwd"},
    ],
)
async def test_attack_payloads_blocked(waf_client, payload):
    client, _, _ = waf_client
    response = await client.post("/api/orders", json=payload)
    assert response.status_code == 403


@pytest.mark.anyio
async def test_oversized_request_rejected(waf_client):
    client, _, _ = waf_client
    response = await client.post(
        "/api/orders",
        content=b"x" * 1025,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


@pytest.mark.anyio
async def test_upstream_unavailable_handled_safely(tmp_path, monkeypatch):
    app = create_app(
        WAFSettings(
            upstream_base_url="http://127.0.0.1:59999",
            log_path=tmp_path / "waf.log",
            upstream_timeout_seconds=0.1,
        )
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://waf.test") as client:
        response = await client.get("/api/menu")
    assert response.status_code == 502
    assert response.json()["message"] == "Upstream unavailable."


@pytest.mark.anyio
async def test_authorization_header_not_written_to_logs(waf_client):
    client, log_path, _ = waf_client
    response = await client.get(
        "/api/menu",
        headers={"Authorization": "Bearer synthetic-secret-token", "Cookie": "session=secret"},
    )
    assert response.status_code == 200
    log_text = Path(log_path).read_text(encoding="utf-8")
    assert "synthetic-secret-token" not in log_text
    assert "authorization" not in log_text.lower()
    assert "cookie" not in log_text.lower()


@pytest.mark.anyio
async def test_health_endpoint(waf_client):
    client, _, _ = waf_client
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
