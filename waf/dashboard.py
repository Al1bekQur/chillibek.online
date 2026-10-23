from __future__ import annotations

import hmac
import hashlib
import json
import secrets
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.security import check_password_hash

from .config import WAFSettings
from .rules import RULES
from .policy import Policy


EXTRA_RULES = [
    {"rule_id": "RATE-001", "category": "rate_limiting", "score": 5,
     "description": "Per-client and per-route sliding-window limits with concurrency admission."},
    {"rule_id": "HEADER-001", "category": "suspicious_headers", "score": 5,
     "description": "Ambiguous framing, method overrides and header control bytes."},
    {"rule_id": "SIZE-001", "category": "request_size", "score": 10,
     "description": "Streaming request body size limit."},
    {'rule_id': 'BRUTE-001', 'category': 'brute_force', 'score': 5,
     'description': 'Shared per-account and per-IP escalating login lockouts.'},
    {'rule_id': 'BOT-001', 'category': 'bot_detection', 'score': 5,
     'description': 'Repeated missing-endpoint probing, independent of User-Agent.'},
]


SESSION_COOKIE = "chillibek_waf_session"
CSRF_COOKIE = "chillibek_waf_csrf"


def dashboard_router(settings: WAFSettings) -> APIRouter:
    router = APIRouter()

    @router.get("/dashboard/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> HTMLResponse:
        if _is_authenticated(request, settings):
            return RedirectResponse("/settings" if request.query_params.get("next") == "/settings" else "/dashboard", status_code=303)
        token = secrets.token_urlsafe(32)
        response = HTMLResponse(_login_html(_auth_configured(settings), token, request.query_params.get("next") == "/settings"))
        response.set_cookie(
            CSRF_COOKIE,
            token,
            httponly=True,
            samesite="strict",
            secure=settings.dashboard_secure_cookies,
            max_age=600,
        )
        return response

    @router.post("/dashboard/login")
    async def login(request: Request):
        form = parse_qs((await request.body()).decode("utf-8", errors="replace"))
        username = form.get("username", [""])[0][:80]
        password = form.get("password", [""])[0][:256]
        csrf_token = form.get("csrf_token", [""])[0][:128]
        csrf_cookie = request.cookies.get(CSRF_COOKIE, "")
        store = request.app.state.policy_store
        keys = store.login_keys('operator:' + (request.client.host if request.client else 'unknown'), 'operator:' + username)
        if store.login_locked(keys):
            raise HTTPException(429, 'Too many login attempts.', headers={'Retry-After':'30'})
        if not csrf_cookie or not hmac.compare_digest(csrf_cookie.encode(), csrf_token.encode()):
            store.login_result(keys, True)
            raise HTTPException(status_code=400, detail="Invalid login request.")
        if not _auth_configured(settings):
            raise HTTPException(status_code=503, detail="Dashboard authentication is not configured.")
        if not hmac.compare_digest(username.encode(), (settings.dashboard_username or "").encode()):
            store.login_result(keys, True)
            raise HTTPException(status_code=401, detail="Invalid username or password.")
        try:
            valid_password = check_password_hash(settings.dashboard_password_hash or "", password)
        except (TypeError, ValueError):
            valid_password = False
        if not valid_password:
            store.login_result(keys, True)
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        store.login_result(keys, False)
        serializer = _serializer(settings)
        destination = "/settings" if form.get("next", [""])[0] == "/settings" else "/dashboard"
        response = RedirectResponse(destination, status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            serializer.dumps({"username": username, "session_id": secrets.token_urlsafe(24)}),
            httponly=True,
            samesite="strict",
            secure=settings.dashboard_secure_cookies,
            max_age=settings.dashboard_session_max_age,
        )
        response.delete_cookie(CSRF_COOKIE)
        return response

    @router.post("/dashboard/logout")
    async def logout(request: Request):
        require_dashboard_auth(request, settings)
        form = parse_qs((await request.body()).decode('utf-8', errors='replace'))
        try:
            token = _serializer(settings).loads(form.get('csrf_token', [''])[0], max_age=settings.dashboard_session_max_age)
        except BadSignature:
            raise HTTPException(403, 'Invalid CSRF token.') from None
        expected = hashlib.sha256(request.cookies.get(SESSION_COOKIE, '').encode()).hexdigest()
        if not isinstance(token, dict) or token.get('purpose') != 'logout' or not hmac.compare_digest(str(token.get('session', '')), expected):
            raise HTTPException(403, 'Invalid CSRF token.')
        response = RedirectResponse("/dashboard/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE)
        return response

    @router.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        if not _is_authenticated(request, settings):
            return RedirectResponse("/dashboard/login", status_code=303)
        csrf = _serializer(settings).dumps({'purpose': 'logout', 'session': hashlib.sha256(request.cookies.get(SESSION_COOKIE, '').encode()).hexdigest()})
        return HTMLResponse(_dashboard_html(csrf))

    @router.get("/dashboard/api/summary")
    async def api_summary(
        request: Request,
        decision: str | None = Query(default=None, pattern="^(allowed|blocked|upstream_error)$"),
        path: str | None = Query(default=None, max_length=200),
        rule_id: str | None = Query(default=None, max_length=40),
        date_from: str | None = Query(default=None, max_length=40),
        date_to: str | None = Query(default=None, max_length=40),
    ) -> dict[str, Any]:
        require_dashboard_auth(request, settings)
        events = _filter_events(_read_events(settings), decision, path, rule_id, date_from, date_to)
        return _summary(events)

    @router.get("/dashboard/api/events")
    async def api_events(
        request: Request,
        decision: str | None = Query(default=None, pattern="^(allowed|blocked|upstream_error)$"),
        path: str | None = Query(default=None, max_length=200),
        rule_id: str | None = Query(default=None, max_length=40),
        date_from: str | None = Query(default=None, max_length=40),
        date_to: str | None = Query(default=None, max_length=40),
        limit: int = Query(default=25, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        require_dashboard_auth(request, settings)
        events = _filter_events(_read_events(settings), decision, path, rule_id, date_from, date_to)
        events.sort(key=lambda event: event.get("timestamp", ""), reverse=True)
        page = events[offset : offset + limit]
        return {"total": len(events), "limit": limit, "offset": offset, "events": page}

    @router.get("/dashboard/api/rules")
    async def api_rules(request: Request) -> dict[str, Any]:
        require_dashboard_auth(request, settings)
        policy = Policy.model_validate(request.app.state.policy_store.read()["policy"])
        return {
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "category": rule.category,
                    "score": rule.score,
                    "description": rule.description,
                    "enabled": getattr(policy, rule.category),
                }
                for rule in RULES
            ] + [{**rule, "enabled": getattr(policy, rule["category"])} for rule in EXTRA_RULES],
            "block_threshold": settings.block_threshold,
            "mode": policy.mode,
        }

    return router


def require_dashboard_auth(request: Request, settings: WAFSettings) -> str:
    if not _auth_configured(settings):
        raise HTTPException(status_code=503, detail="Dashboard authentication is not configured.")
    session = request.cookies.get(SESSION_COOKIE)
    if not session:
        raise HTTPException(status_code=401, detail="Dashboard authentication required.")
    try:
        payload = _serializer(settings).loads(session, max_age=settings.dashboard_session_max_age)
    except BadSignature:
        raise HTTPException(status_code=401, detail="Dashboard authentication required.") from None
    username = payload.get("username") if isinstance(payload, dict) else None
    if not isinstance(username, str) or not hmac.compare_digest(
        username.encode(), (settings.dashboard_username or "").encode()
    ):
        raise HTTPException(status_code=401, detail="Dashboard authentication required.")
    return username


def _auth_configured(settings: WAFSettings) -> bool:
    return bool(
        settings.dashboard_username
        and settings.dashboard_password_hash
        and settings.dashboard_session_secret
        and len(settings.dashboard_session_secret) >= 32
    )


def _is_authenticated(request: Request, settings: WAFSettings) -> bool:
    try:
        require_dashboard_auth(request, settings)
    except HTTPException:
        return False
    return True


def _serializer(settings: WAFSettings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.dashboard_session_secret, salt="waf-dashboard-v1")


def _read_events(settings: WAFSettings) -> list[dict[str, Any]]:
    path: Path = settings.log_path
    if not path.exists():
        return []
    lines = deque(maxlen=settings.dashboard_log_read_limit)
    with path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            lines.append(line)

    events: list[dict[str, Any]] = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        events.append(_sanitize_event(event))
    return events


def _sanitize_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": str(event.get("timestamp", ""))[:40],
        "method": str(event.get("method", ""))[:12],
        "path": str(event.get("path", ""))[:240],
        "query_present": bool(event.get("query_present", False)),
        "matched_rules": [
            str(rule_id)[:40] for rule_id in event.get("matched_rules", []) if isinstance(rule_id, str)
        ],
        "risk_score": _safe_int(event.get("risk_score")),
        "decision": str(event.get("decision", ""))[:40],
        "status_code": _safe_int(event.get("status_code")),
        "content_length": str(event.get("content_length", ""))[:40],
    }


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _filter_events(
    events: list[dict[str, Any]],
    decision: str | None,
    path: str | None,
    rule_id: str | None,
    date_from: str | None,
    date_to: str | None,
) -> list[dict[str, Any]]:
    start = _parse_datetime(date_from)
    end = _parse_datetime(date_to)
    filtered = []
    for event in events:
        event_time = _parse_datetime(event.get("timestamp"))
        if decision and event.get("decision") != decision:
            continue
        if path and path.lower() not in str(event.get("path", "")).lower():
            continue
        if rule_id and rule_id not in event.get("matched_rules", []):
            continue
        if start and event_time and event_time < start:
            continue
        if end and event_time and event_time > end:
            continue
        filtered.append(event)
    return filtered


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(events)
    allowed = sum(1 for event in events if event.get("decision") == "allowed")
    blocked = sum(1 for event in events if event.get("decision") == "blocked")
    attack_categories = Counter()
    rule_counts = Counter()
    activity = Counter()
    rule_category = {rule.rule_id: rule.category for rule in RULES}
    rule_category.update({rule["rule_id"]: rule["category"] for rule in EXTRA_RULES})
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=23)

    for event in events:
        for rule_id in event.get("matched_rules", []):
            rule_counts[rule_id] += 1
            attack_categories[rule_category.get(rule_id, "other")] += 1
        event_time = _parse_datetime(event.get("timestamp"))
        if event_time and event_time >= window_start:
            activity[event_time.strftime("%Y-%m-%dT%H:00:00Z")] += 1

    return {
        "total_requests": total,
        "allowed_requests": allowed,
        "blocked_requests": blocked,
        "block_rate": round((blocked / total) * 100, 2) if total else 0,
        "attacks_by_category": dict(attack_categories),
        "matched_rules": dict(rule_counts),
        "activity": _activity_series(activity, now),
    }


def _activity_series(activity: Counter, now: datetime) -> list[dict[str, Any]]:
    series = []
    base = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    for index in range(24):
        bucket = base + timedelta(hours=index)
        key = bucket.strftime("%Y-%m-%dT%H:00:00Z")
        series.append({"bucket": key, "count": activity.get(key, 0)})
    return series


def _login_html(configured: bool, csrf_token: str, settings_next: bool = False) -> str:
    notice = ""
    if not configured:
        notice = "<p class=\"notice\">Dashboard auth is not configured. Set WAF_DASHBOARD_USERNAME, WAF_DASHBOARD_PASSWORD_HASH and WAF_DASHBOARD_SESSION_SECRET.</p>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Chillibek WAF Login</title>
  <style>{_css()}</style>
</head>
<body class="login-body">
  <main class="login-panel">
    <div class="brand">CHILLIBEK WAF</div>
    <h1>Security Dashboard</h1>
    {notice}
    <form method="post" action="/dashboard/login">
      <input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
      <input type="hidden" name="next" value="{'/settings' if settings_next else '/dashboard'}">
      <label>Username<input name="username" autocomplete="username" required></label>
      <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>"""


def _dashboard_html(csrf_token) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Chillibek WAF Dashboard</title>
  <style>{_css()}</style>
</head>
<body>
  <header class="topbar">
    <div>
      <div class="brand">CHILLIBEK WAF</div>
      <h1>Security Dashboard</h1>
    </div>
    <a href="/settings">Security Settings</a>
    <form method="post" action="/dashboard/logout"><input type="hidden" name="csrf_token" value="{escape(csrf_token)}"><button class="ghost" type="submit">Logout</button></form>
  </header>
  <main>
    <section class="filters">
      <select id="decisionFilter">
        <option value="">All decisions</option>
        <option value="allowed">Allowed</option>
        <option value="blocked">Blocked</option>
        <option value="upstream_error">Upstream errors</option>
      </select>
      <input id="pathFilter" placeholder="Path contains">
      <input id="ruleFilter" placeholder="Rule ID">
      <input id="fromFilter" type="datetime-local">
      <input id="toFilter" type="datetime-local">
      <button id="refreshBtn" type="button">Refresh</button>
    </section>
    <section class="cards">
      <article><span>Total Requests</span><strong id="totalRequests">0</strong></article>
      <article><span>Allowed</span><strong id="allowedRequests">0</strong></article>
      <article><span>Blocked</span><strong id="blockedRequests">0</strong></article>
      <article><span>Block Rate</span><strong id="blockRate">0%</strong></article>
    </section>
    <section class="grid">
      <article class="panel"><h2>Request Activity</h2><canvas id="activityChart" width="900" height="260"></canvas></article>
      <article class="panel"><h2>Attack Categories</h2><div id="categoryList" class="metric-list"></div></article>
    </section>
    <section class="grid">
      <article class="panel wide"><h2>Recent Security Events</h2><div class="table-wrap"><table><thead><tr><th>Time</th><th>Decision</th><th>Method</th><th>Path</th><th>Status</th><th>Risk</th><th>Rules</th></tr></thead><tbody id="eventsBody"></tbody></table></div><div class="pager"><button id="prevPage">Prev</button><span id="pageInfo"></span><button id="nextPage">Next</button></div></article>
      <article class="panel"><h2>Detection Rules</h2><div id="rulesList" class="rules"></div></article>
    </section>
  </main>
  <script>{_javascript()}</script>
</body>
</html>"""


def _css() -> str:
    return """
:root { color-scheme: dark; --bg:#080d14; --panel:#101823; --panel2:#121f2d; --text:#e6edf5; --muted:#8aa0b5; --line:#203043; --accent:#39d98a; --danger:#ff5c7a; --warn:#ffc857; }
* { box-sizing:border-box; }
body { margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; background:var(--bg); color:var(--text); }
.topbar { display:flex; justify-content:space-between; align-items:center; padding:22px clamp(16px,4vw,42px); border-bottom:1px solid var(--line); background:#0b121c; gap:16px; }
.brand { color:var(--accent); font-weight:800; letter-spacing:.08em; font-size:12px; }
h1 { margin:4px 0 0; font-size:clamp(24px,4vw,36px); }
h2 { margin:0 0 14px; font-size:17px; }
main { padding:22px clamp(16px,4vw,42px) 42px; }
.filters { display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:10px; margin-bottom:18px; }
input, select, button { min-height:42px; border:1px solid var(--line); background:var(--panel); color:var(--text); border-radius:8px; padding:0 12px; }
button { cursor:pointer; background:#173222; border-color:#235d3b; font-weight:700; }
.ghost { background:transparent; border-color:var(--line); }
.cards { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin-bottom:14px; }
.cards article, .panel, .login-panel { background:linear-gradient(180deg,var(--panel),#0c141e); border:1px solid var(--line); border-radius:8px; padding:18px; }
.cards span { color:var(--muted); display:block; margin-bottom:8px; }
.cards strong { font-size:30px; }
.grid { display:grid; grid-template-columns:2fr 1fr; gap:14px; margin-top:14px; }
.wide { min-width:0; }
canvas { width:100%; max-height:260px; background:var(--panel2); border:1px solid var(--line); border-radius:8px; }
.metric-list, .rules { display:grid; gap:10px; }
.metric, .rule { padding:12px; background:var(--panel2); border:1px solid var(--line); border-radius:8px; }
.metric b, .rule b { color:var(--accent); }
.table-wrap { overflow:auto; border:1px solid var(--line); border-radius:8px; }
table { width:100%; border-collapse:collapse; min-width:760px; }
th, td { padding:11px 10px; border-bottom:1px solid var(--line); text-align:left; font-size:13px; vertical-align:top; }
th { color:var(--muted); background:#0d1722; }
.blocked { color:var(--danger); font-weight:800; }
.allowed { color:var(--accent); font-weight:800; }
.upstream_error { color:var(--warn); font-weight:800; }
.pager { display:flex; justify-content:flex-end; gap:10px; align-items:center; margin-top:12px; color:var(--muted); }
.login-body { min-height:100vh; display:grid; place-items:center; padding:18px; }
.login-panel { width:min(420px,100%); }
.login-panel h1 { margin-bottom:18px; }
.login-panel label { display:grid; gap:7px; margin:12px 0; color:var(--muted); }
.login-panel button { width:100%; margin-top:10px; }
.notice { color:var(--warn); line-height:1.45; }
@media (max-width: 900px) { .filters, .cards, .grid { grid-template-columns:1fr; } .topbar { align-items:flex-start; } }
"""


def _javascript() -> str:
    return """
let offset = 0;
const limit = 25;
const safeText = (value) => value == null ? '' : String(value);
function params() {
  const p = new URLSearchParams();
  for (const [id, key] of [['decisionFilter','decision'],['pathFilter','path'],['ruleFilter','rule_id'],['fromFilter','date_from'],['toFilter','date_to']]) {
    const value = document.getElementById(id).value;
    if (value) p.set(key, value);
  }
  return p;
}
async function loadDashboard() {
  const p = params();
  const summary = await fetch('/dashboard/api/summary?' + p.toString()).then(r => r.json());
  document.getElementById('totalRequests').textContent = summary.total_requests;
  document.getElementById('allowedRequests').textContent = summary.allowed_requests;
  document.getElementById('blockedRequests').textContent = summary.blocked_requests;
  document.getElementById('blockRate').textContent = summary.block_rate + '%';
  renderCategories(summary.attacks_by_category || {});
  renderChart(summary.activity || []);

  const eventParams = params();
  eventParams.set('limit', limit);
  eventParams.set('offset', offset);
  const events = await fetch('/dashboard/api/events?' + eventParams.toString()).then(r => r.json());
  renderEvents(events.events || []);
  document.getElementById('pageInfo').textContent = `${offset + 1}-${Math.min(offset + limit, events.total)} of ${events.total}`;
  document.getElementById('prevPage').disabled = offset === 0;
  document.getElementById('nextPage').disabled = offset + limit >= events.total;

  const rules = await fetch('/dashboard/api/rules').then(r => r.json());
  renderRules(rules.rules || [], rules.block_threshold, rules.mode);
}
function renderCategories(categories) {
  const box = document.getElementById('categoryList');
  box.replaceChildren();
  const entries = Object.entries(categories);
  if (!entries.length) entries.push(['none', 0]);
  for (const [name, count] of entries) {
    const row = document.createElement('div');
    row.className = 'metric';
    const b = document.createElement('b');
    b.textContent = safeText(count);
    row.append(b, document.createTextNode(' ' + safeText(name)));
    box.appendChild(row);
  }
}
function renderEvents(events) {
  const body = document.getElementById('eventsBody');
  body.replaceChildren();
  for (const event of events) {
    const tr = document.createElement('tr');
    for (const value of [event.timestamp, event.decision, event.method, event.path, event.status_code, event.risk_score, (event.matched_rules || []).join(', ')]) {
      const td = document.createElement('td');
      td.textContent = safeText(value);
      if (value === event.decision) td.className = safeText(event.decision);
      tr.appendChild(td);
    }
    body.appendChild(tr);
  }
}
function renderRules(rules, threshold, mode) {
  const box = document.getElementById('rulesList');
  box.replaceChildren();
  const intro = document.createElement('div');
  intro.className = 'metric';
  intro.textContent = 'Mode: ' + mode + ' | Block threshold: ' + threshold;
  box.appendChild(intro);
  for (const rule of rules) {
    const item = document.createElement('div');
    item.className = 'rule';
    const title = document.createElement('b');
    title.textContent = `${rule.rule_id} | ${rule.enabled ? 'ON' : 'OFF'} (${rule.category}, score ${rule.score})`;
    const desc = document.createElement('div');
    desc.textContent = rule.description;
    item.append(title, desc);
    box.appendChild(item);
  }
}
function renderChart(points) {
  const canvas = document.getElementById('activityChart');
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const max = Math.max(1, ...points.map(p => p.count));
  const pad = 28;
  const width = canvas.width - pad * 2;
  const height = canvas.height - pad * 2;
  ctx.strokeStyle = '#203043';
  ctx.beginPath();
  ctx.moveTo(pad, pad);
  ctx.lineTo(pad, pad + height);
  ctx.lineTo(pad + width, pad + height);
  ctx.stroke();
  ctx.fillStyle = '#39d98a';
  const bar = width / Math.max(points.length, 1);
  points.forEach((point, i) => {
    const h = (point.count / max) * (height - 8);
    ctx.fillRect(pad + i * bar + 2, pad + height - h, Math.max(3, bar - 4), h);
  });
}
document.getElementById('refreshBtn').addEventListener('click', () => { offset = 0; loadDashboard(); });
document.getElementById('prevPage').addEventListener('click', () => { offset = Math.max(0, offset - limit); loadDashboard(); });
document.getElementById('nextPage').addEventListener('click', () => { offset += limit; loadDashboard(); });
loadDashboard();
"""
