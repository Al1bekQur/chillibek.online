"""Synthetic requests only. No production network or databases."""
import json
import re
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, Request
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash

from waf.app import create_app
from waf.config import WAFSettings
from waf.dashboard import SESSION_COOKIE
from waf.policy import Policy, PolicyStore


@pytest.fixture
async def control(tmp_path, monkeypatch):
    monkeypatch.setattr('waf.policy.time', SimpleNamespace(time=lambda: 1800000000))
    upstream = FastAPI()
    captured = []

    @upstream.api_route('/{path:path}', methods=['GET', 'POST'])
    async def echo(path: str, request: Request):
        captured.append({'path': path, 'body': (await request.body()).decode(), 'headers': dict(request.headers)})
        return {'upstream': True}

    settings = WAFSettings(
        log_path=tmp_path / 'events.log', policy_path=tmp_path / 'policy.sqlite3',
        upstream_base_url='https://synthetic.test', upstream_transport=httpx.ASGITransport(app=upstream),
        max_request_bytes=256, rate_limit_requests=1000,
        dashboard_username='operator', dashboard_password_hash=generate_password_hash('synthetic-password'),
        dashboard_session_secret='synthetic-session-secret-at-least-32-characters',
    )
    app = create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://waf.test') as client:
        page = await client.get('/dashboard/login?next=/settings')
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text)[1]
        response = await client.post('/dashboard/login', data={
            'username': 'operator', 'password': 'synthetic-password', 'csrf_token': token, 'next': '/settings',
        })
        assert response.status_code == 303
        assert response.headers['location'] == '/settings'
        assert 'Secure' in response.headers.get_list('set-cookie')[0]
        yield client, app, settings, captured


async def update(client, **changes):
    snapshot = (await client.get('/waf-api/settings')).json()
    return await client.put('/waf-api/settings', json={
        'revision': snapshot['revision'], 'policy': {**snapshot['policy'], **changes},
    }, headers={'x-csrf-token': snapshot['csrf_token']})


@pytest.mark.anyio
@pytest.mark.parametrize('category,payload,rule', [
    ('sql_injection', "' OR 1=1 --", 'SQLI-001'),
    ('xss', '<script>alert(1)</script>', 'XSS-001'),
    ('path_traversal', '../../etc/passwd', 'TRAV-001'),
])
async def test_detection_switches_independent(control, category, payload, rule):
    client, _, settings, captured = control
    assert (await client.post('/api/orders', json={'synthetic': payload})).status_code == 403
    assert not captured
    response = await update(client, **{category: False})
    assert response.status_code == 200
    assert response.json()['policy'][category] is False
    assert (await client.post('/api/orders', json={'synthetic': payload})).status_code == 200
    event = json.loads(settings.log_path.read_text().splitlines()[-1])
    assert rule not in event['matched_rules']
    other = '<svg onload=alert(1)>' if category != 'xss' else "' OR 1=1 --"
    assert (await client.post('/api/orders', json={'synthetic': other})).status_code == 403
    assert (await update(client, **{category: True})).status_code == 200
    assert (await client.post('/api/orders', json={'synthetic': payload})).status_code == 403


@pytest.mark.anyio
async def test_persist_restart_and_other_worker_reload(control):
    client, _, settings, _ = control
    # A second already-running worker reads the same policy database.
    second = create_app(settings)
    response = await update(client, sql_injection=False)
    assert response.status_code == 200
    for app in (second, create_app(settings)):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://waf.test') as worker:
            assert (await worker.get('/api/menu', params={'q': "' OR 1=1 --"})).status_code == 200
        snapshot = app.state.policy_store.read()
        assert snapshot['policy']['sql_injection'] is False
        assert snapshot['updated_by'] == 'operator'
        assert snapshot['updated_at'] == response.json()['updated_at']
        assert snapshot['revision'] == response.json()['revision']


@pytest.mark.anyio
@pytest.mark.parametrize('changes', [
    {'sql_injection': 'false'}, {'xss': 0}, {'mode': 'off'}, {'extra_rule': True},
])
async def test_invalid_settings_rejected(control, changes):
    client, app, _, _ = control
    before = app.state.policy_store.read()
    assert (await update(client, **changes)).status_code == 422
    assert app.state.policy_store.read() == before


@pytest.mark.anyio
async def test_invalid_revision_malformed_json_and_unknown_fields(control):
    client, app, _, _ = control
    state = (await client.get('/waf-api/settings')).json()
    headers = {'x-csrf-token': state['csrf_token']}
    for body in [
        {'policy': state['policy']}, {'revision': True, 'policy': state['policy']},
        {'revision': 0, 'policy': {'xss': False}},
        {'revision': -1, 'policy': state['policy']},
        {'revision': 0, 'policy': state['policy'], 'extra': 1},
    ]:
        assert (await client.put('/waf-api/settings', json=body, headers=headers)).status_code == 422
    assert (await client.put('/waf-api/settings', content='{', headers={**headers, 'content-type': 'application/json'})).status_code == 422
    assert app.state.policy_store.read()['revision'] == 0


@pytest.mark.anyio
async def test_unauthorized_modifications_and_forged_role_rejected(control):
    client, app, settings, captured = control
    client.cookies.clear()
    for method, path in [('GET', '/waf-api/settings'), ('PUT', '/waf-api/settings'), ('POST', '/waf-api/settings/reset')]:
        response = await client.request(method, path, json={})
        assert response.status_code == 401
    serializer = URLSafeTimedSerializer(settings.dashboard_session_secret, salt='waf-dashboard-v1')
    client.cookies.set(SESSION_COOKIE, serializer.dumps({'username': 'restaurant-admin'}))
    assert (await client.put('/waf-api/settings', json={})).status_code == 401
    client.cookies.set(SESSION_COOKIE, 'forged-session')
    assert (await client.put('/waf-api/settings', json={})).status_code == 401
    assert not captured
    assert app.state.policy_store.read()['revision'] == 0


@pytest.mark.anyio
async def test_csrf_and_stale_revision_rejected(control):
    client, app, _, _ = control
    state = (await client.get('/waf-api/settings')).json()
    body = {'revision': state['revision'], 'policy': {**state['policy'], 'xss': False}}
    for headers in [{}, {'x-csrf-token': 'forged'}, {'x-csrf-token': state['csrf_token'], 'sec-fetch-site': 'cross-site'}]:
        assert (await client.put('/waf-api/settings', json=body, headers=headers)).status_code == 403
    assert (await update(client, xss=False)).status_code == 200
    assert (await client.put('/waf-api/settings', json=body, headers={'x-csrf-token': state['csrf_token']})).status_code == 409
    assert app.state.policy_store.read()['revision'] == 1


@pytest.mark.anyio
async def test_monitor_detects_without_blocking(control):
    client, _, settings, captured = control
    assert (await update(client, mode='monitor')).status_code == 200
    response = await client.post('/api/orders', json={'q': "' OR 1=1 -- <script>alert(1)</script> ../../etc/passwd"})
    assert response.status_code == 200
    assert captured
    event = json.loads(settings.log_path.read_text().splitlines()[-1])
    assert set(event['matched_rules']) == {'SQLI-001', 'XSS-001', 'TRAV-001'}
    assert event['decision'] == 'allowed'


@pytest.mark.anyio
async def test_size_toggle_and_monitor(control):
    client, _, settings, _ = control
    body = b'x' * (settings.max_request_bytes + 1)
    assert (await client.post('/api/orders', content=body)).status_code == 413
    assert (await update(client, request_size=False)).status_code == 200
    assert (await client.post('/api/orders', content=body)).status_code == 200
    assert (await update(client, request_size=True, mode='monitor')).status_code == 200
    assert (await client.post('/api/orders', content=body)).status_code == 200
    assert 'SIZE-001' in json.loads(settings.log_path.read_text().splitlines()[-1])['matched_rules']


@pytest.mark.anyio
@pytest.mark.parametrize('headers', [
    {'x-http-method-override': 'DELETE'}, {'x-method-override': 'PUT'},
    {'x-test': 'synthetic\x7fvalue'},
    {'transfer-encoding': 'chunked', 'content-length': '1'},
    [('content-length', '1'), ('content-length', '2')],
])
async def test_suspicious_headers_toggle(control, headers):
    client, _, settings, _ = control
    assert (await client.post('/api/orders', content='x', headers=headers)).status_code == 403
    assert (await update(client, suspicious_headers=False)).status_code == 200
    assert (await client.post('/api/orders', content='x', headers=headers)).status_code == 200
    event = json.loads(settings.log_path.read_text().splitlines()[-1])
    assert 'HEADER-001' not in event['matched_rules']
    assert (await update(client, suspicious_headers=True, mode='monitor')).status_code == 200
    assert (await client.post('/api/orders', content='x', headers=headers)).status_code == 200
    assert 'HEADER-001' in json.loads(settings.log_path.read_text().splitlines()[-1])['matched_rules']


@pytest.mark.anyio
async def test_rate_limit_toggle_shared_counter_and_monitor(control, monkeypatch):
    client, app, settings, _ = control
    monkeypatch.setattr('waf.policy.time', SimpleNamespace(time=lambda: 1800000000))
    smaller = replace(settings, rate_limit_requests=2)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(smaller)), base_url='https://waf.test') as limited:
        assert (await limited.get('/api/menu')).status_code == 200
        assert (await limited.get('/api/menu')).status_code == 200
        assert (await limited.get('/api/menu', headers={'x-forwarded-for': 'spoofed'})).status_code == 429
        assert (await update(client, rate_limiting=False)).status_code == 200
        assert (await limited.get('/api/menu')).status_code == 200
        assert (await update(client, rate_limiting=True, mode='monitor')).status_code == 200
        assert (await limited.get('/api/menu')).status_code == 200
        assert 'RATE-001' in json.loads(settings.log_path.read_text().splitlines()[-1])['matched_rules']
        monkeypatch.setattr('waf.policy.time', SimpleNamespace(time=lambda: 1800000060))
        assert (await update(client, mode='block')).status_code == 200
        assert (await limited.get('/api/menu')).status_code == 200


@pytest.mark.anyio
async def test_event_logging_off_preserves_audit_auth_and_dashboard(control):
    client, app, settings, _ = control
    assert (await update(client, event_logging=False, mode='monitor', **{name: False for name in (
        'sql_injection', 'xss', 'path_traversal', 'rate_limiting', 'suspicious_headers', 'request_size',
    )})).status_code == 200
    assert (await client.get('/api/menu')).status_code == 200
    assert not settings.log_path.exists()
    assert (await client.get('/dashboard')).status_code == 200
    rules = (await client.get('/dashboard/api/rules')).json()
    assert all(not rule['enabled'] for rule in rules['rules'])
    assert rules['mode'] == 'monitor'
    state = (await client.get('/waf-api/settings')).json()
    reset = await client.post('/waf-api/settings/reset', json={'revision': state['revision']}, headers={'x-csrf-token': state['csrf_token']})
    assert reset.status_code == 200
    assert reset.json()['policy'] == Policy().model_dump()
    with sqlite3.connect(settings.policy_path) as connection:
        actions = connection.execute('SELECT action, details FROM configuration_audit').fetchall()
    assert {action for action, _ in actions} >= {'update', 'reset', 'access'}
    assert 'synthetic-password' not in str(actions)
    assert 'csrf_token' not in str(actions)
    assert 'before' in next(detail for action, detail in actions if action == 'update')
    client.cookies.clear()
    assert (await client.put('/waf-api/settings', json={})).status_code == 401


@pytest.mark.anyio
async def test_storage_failure_never_acknowledged_as_success(control, monkeypatch):
    client, app, settings, _ = control
    state = (await client.get('/waf-api/settings')).json()
    original = app.state.policy_store.read()
    def fail(*args, **kwargs):
        raise sqlite3.OperationalError('synthetic disk full')
    # A failure writing the required audit must roll back the policy transaction.
    monkeypatch.setattr(app.state.policy_store, '_audit', fail)
    response = await client.put('/waf-api/settings', json={
        'revision': state['revision'], 'policy': {**state['policy'], 'xss': False},
    }, headers={'x-csrf-token': state['csrf_token']})
    assert response.status_code == 503
    assert PolicyStore(settings.policy_path).read() == original


@pytest.mark.anyio
async def test_public_static_page_and_assets_never_expose_fake_status(control):
    client, _, _, captured = control
    redirect = await client.get('/settings')
    assert redirect.status_code == 308
    assert redirect.headers['location'] == '/settings/'
    for path in ['/settings', '/settings/']:
        page = await client.get(path, follow_redirects=True)
        assert page.status_code == 200
        assert 'CHILLIBEK WAF — Security Settings' in page.text
        assert 'Waiting for the WAF backend' in page.text
        assert 'href="./settings.css"' in page.text
        assert 'src="./settings.js"' in page.text
    for path in ['/settings/settings.css', '/settings/settings.js']:
        assert (await client.get(path)).status_code == 200
    assert not captured


@pytest.mark.anyio
async def test_login_throttle_not_disabled_by_policy(control):
    client, _, _, _ = control
    assert (await update(client, rate_limiting=False, mode='monitor')).status_code == 200
    client.cookies.clear()
    # The fixture already made one login attempt in the same window.
    responses = [await client.post('/dashboard/login', content='username=synthetic') for _ in range(5)]
    assert responses[-1].status_code == 429


@pytest.mark.anyio
@pytest.mark.parametrize('stored', ['invalid-json', '{}', '{"mode":"monitor"}'])
async def test_corrupt_policy_fails_closed_without_restoring_defaults(control, stored):
    client, _, settings, captured = control
    with sqlite3.connect(settings.policy_path) as connection:
        connection.execute("UPDATE policy SET value=? WHERE id=1", (stored,))
    assert (await client.get('/waf-api/settings')).status_code == 503
    assert (await client.get('/api/menu')).status_code == 503
    assert not captured
    with sqlite3.connect(settings.policy_path) as connection:
        assert connection.execute('SELECT value FROM policy').fetchone()[0] == stored


@pytest.mark.anyio
@pytest.mark.parametrize('mode', ['block', 'monitor'])
async def test_real_flask_restaurant_through_existing_proxy(tmp_path, monkeypatch, mode):
    # Set import-time Flask state to synthetic storage, including when run by itself.
    monkeypatch.setenv('FLASK_SECRET_KEY', 'synthetic-flask-secret-at-least-32-characters')
    monkeypatch.setenv('DATABASE_PATH', str(tmp_path / 'import.sqlite3'))
    monkeypatch.setenv('DATABASE_URL', '')
    from backend.server import create_app as create_restaurant, get_db_connection
    restaurant = create_restaurant({
        'TESTING': True, 'SECRET_KEY': 'synthetic-flask-secret-at-least-32-characters',
        'DATABASE_PATH': str(tmp_path / 'restaurant.sqlite3'), 'DATABASE_URL': None,
        'CORS_ALLOWED_ORIGINS': ['https://chillibek.online'], 'RATELIMIT_STORAGE_URI': 'memory://',
    })
    with restaurant.app_context(), get_db_connection() as connection:
        connection.execute('INSERT INTO staff(username, password, role) VALUES (?, ?, ?)',
                           ('synthetic-waiter', generate_password_hash('synthetic-password'), 'waiter'))

    def bridge(request):
        # A local in-process transport, not an external HTTP request.
        with restaurant.test_client() as upstream:
            response = upstream.open(str(request.url.path), method=request.method,
                                     query_string=request.url.query.decode(), data=request.content,
                                     headers=dict(request.headers))
        return httpx.Response(response.status_code, content=response.data, headers=dict(response.headers))

    settings = WAFSettings(log_path=tmp_path / 'integration.log', upstream_transport=httpx.MockTransport(bridge))
    app = create_app(settings)
    # Direct internal policy setup avoids introducing any test-only public endpoint.
    app.state.policy_store.update(Policy(mode=mode, sql_injection=False, xss=False), 0, 'synthetic-operator')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://waf.test') as client:
        menu = await client.get('/api/menu', headers={'origin': 'https://chillibek.online'})
        assert menu.status_code == 200
        assert len(menu.json()) == 14
        assert menu.headers['access-control-allow-origin'] == 'https://chillibek.online'
        assert (await client.get('/api/orders')).status_code == 401
        login = await client.post('/api/staff/login', json={'username': 'synthetic-waiter', 'password': 'synthetic-password'})
        assert login.status_code == 200
        bearer = {'authorization': 'Bearer ' + login.json()['token']}
        order = await client.post('/api/orders', json={'table_number': '1', 'items': [{'id': 1, 'qty': 2, 'price': 1}], 'total_price': 1})
        assert order.status_code == 200
        orders = await client.get('/api/orders', headers=bearer)
        assert orders.status_code == 200
        assert orders.json()[0]['total_price'] == 4620
        assert (await client.post('/api/menu/add', headers=bearer, json={})).status_code == 403
        assert (await client.put('/waf-api/settings', headers=bearer, json={})).status_code == 503
    restaurant.config['DB_ENGINE'].dispose()
