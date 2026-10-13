import json
import re
from datetime import datetime, timezone

import httpx
import pytest
from fastapi import FastAPI, Request
from werkzeug.security import generate_password_hash

from waf.app import create_app
from waf.config import WAFSettings


def write_event(log_path, **overrides):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": "127.0.0.1",
        "method": "GET",
        "path": "/api/menu",
        "query_present": False,
        "content_length": "0",
        "matched_rules": [],
        "risk_score": 0,
        "decision": "allowed",
        "status_code": 200,
    }
    event.update(overrides)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(event) + "\n")


@pytest.fixture
async def dashboard_client(tmp_path):
    upstream = FastAPI()
    captured = {"count": 0}

    @upstream.get("/{path:path}")
    async def upstream_catchall(path: str, request: Request):
        captured["count"] += 1
        return {"upstream_path": path}

    log_path = tmp_path / "waf.log"
    settings = WAFSettings(
        upstream_base_url="http://upstream.test",
        upstream_transport=httpx.ASGITransport(app=upstream),
        log_path=log_path,
        dashboard_username="analyst",
        dashboard_password_hash=generate_password_hash("synthetic-dashboard-password"),
        dashboard_session_secret="synthetic-dashboard-session-secret-32chars",
        dashboard_log_read_limit=10,
    )
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://waf.test", follow_redirects=False
    ) as client:
        yield client, log_path, captured


async def login(client):
    page = await client.get("/dashboard/login")
    assert page.status_code == 200
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = await client.post(
        "/dashboard/login",
        content=f"username=analyst&password=synthetic-dashboard-password&csrf_token={csrf}",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 303


@pytest.mark.anyio
async def test_dashboard_page_requires_auth(dashboard_client):
    client, _, captured = dashboard_client
    response = await client.get("/dashboard")
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard/login"
    assert captured["count"] == 0


@pytest.mark.anyio
async def test_dashboard_api_requires_auth(dashboard_client):
    client, _, captured = dashboard_client
    response = await client.get("/dashboard/api/summary")
    assert response.status_code == 401
    assert captured["count"] == 0


@pytest.mark.anyio
async def test_dashboard_login_and_summary_use_real_logs(dashboard_client):
    client, log_path, _ = dashboard_client
    write_event(log_path, decision="allowed", status_code=200)
    write_event(
        log_path,
        decision="blocked",
        status_code=403,
        matched_rules=["SQLI-001"],
        risk_score=6,
    )
    await login(client)
    summary = await client.get("/dashboard/api/summary")
    assert summary.status_code == 200
    body = summary.json()
    assert body["total_requests"] == 2
    assert body["allowed_requests"] == 1
    assert body["blocked_requests"] == 1
    assert body["attacks_by_category"] == {"sql_injection": 1}


@pytest.mark.anyio
async def test_dashboard_events_are_paginated_and_filterable(dashboard_client):
    client, log_path, _ = dashboard_client
    for index in range(12):
        write_event(
            log_path,
            path=f"/api/menu/{index}",
            decision="blocked" if index % 2 else "allowed",
            matched_rules=["XSS-001"] if index % 2 else [],
            risk_score=6 if index % 2 else 0,
        )
    await login(client)
    response = await client.get("/dashboard/api/events?decision=blocked&limit=3&offset=0")
    assert response.status_code == 200
    body = response.json()
    assert body["limit"] == 3
    assert body["total"] == 5
    assert len(body["events"]) == 3
    assert all(event["decision"] == "blocked" for event in body["events"])


@pytest.mark.anyio
async def test_dashboard_does_not_expose_sensitive_or_raw_attacker_data(dashboard_client):
    client, log_path, _ = dashboard_client
    write_event(
        log_path,
        path="/api/<script>alert(1)</script>",
        decision="blocked",
        status_code=403,
        matched_rules=["XSS-001"],
        risk_score=6,
    )
    await login(client)
    page = await client.get("/dashboard")
    assert page.status_code == 200
    assert "<script>alert(1)</script>" not in page.text
    events = await client.get("/dashboard/api/events")
    assert events.status_code == 200
    text = events.text.lower()
    assert "authorization" not in text
    assert "cookie" not in text
    assert "password" not in text


@pytest.mark.anyio
async def test_dashboard_rules_endpoint_is_read_only(dashboard_client):
    client, _, _ = dashboard_client
    await login(client)
    response = await client.get("/dashboard/api/rules")
    assert response.status_code == 200
    rules = response.json()["rules"]
    assert {rule["rule_id"] for rule in rules} >= {"SQLI-001", "XSS-001", "TRAV-001"}
