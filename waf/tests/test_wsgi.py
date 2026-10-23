"""Synthetic staging of the exact WSGI -> existing WAF -> real Flask stack."""
import json
import re
import socket
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest
from flask import Flask, jsonify, request, session
from werkzeug.security import generate_password_hash
from werkzeug.test import Client
from werkzeug.wrappers import Response

from waf.config import WAFSettings
from waf.policy import Policy
from waf.wsgi import protect_wsgi


class StagingClient(Client):
    def open(self, *args, **kwargs):
        kwargs.setdefault('buffered', True)
        return super().open(*args, **kwargs)


@pytest.fixture
def staging(tmp_path, monkeypatch):
    monkeypatch.setenv('FLASK_SECRET_KEY', 'synthetic-flask-secret-at-least-32-characters')
    monkeypatch.setenv('DATABASE_PATH', str(tmp_path / 'import.sqlite3'))
    monkeypatch.setenv('DATABASE_URL', '')
    monkeypatch.setattr('waf.policy.time', SimpleNamespace(time=lambda: 1800000000))
    from backend.server import create_app, get_db_connection
    restaurant = create_app({
        'TESTING': True, 'SECRET_KEY': 'synthetic-flask-secret-at-least-32-characters',
        'DATABASE_URL': None, 'DATABASE_PATH': str(tmp_path / 'restaurant.sqlite3'),
        'CORS_ALLOWED_ORIGINS': ['https://chillibek.online'], 'RATELIMIT_STORAGE_URI': 'memory://',
    })
    with restaurant.app_context(), get_db_connection() as connection:
        for role in ['admin', 'waiter', 'chef']:
            connection.execute('INSERT INTO staff(username,password,role) VALUES (?,?,?)',
                               ('synthetic-' + role, generate_password_hash('synthetic-staff-password'), role))
    settings = WAFSettings(
        policy_path=tmp_path / 'policy.sqlite3', log_path=tmp_path / 'events.log',
        dashboard_username='waf-operator',
        dashboard_password_hash=generate_password_hash('synthetic-waf-password'),
        dashboard_session_secret='synthetic-waf-session-secret-at-least-32-characters',
    )
    wrapper = protect_wsgi(restaurant, settings)
    client = StagingClient(wrapper, Response)
    yield client, wrapper, settings, restaurant
    restaurant.config['DB_ENGINE'].dispose()


def admin_login(client):
    page = client.get('/dashboard/login?next=/settings', base_url='https://staging.test')
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text)[1]
    result = client.post('/dashboard/login', base_url='https://staging.test', data={
        'username': 'waf-operator', 'password': 'synthetic-waf-password', 'csrf_token': token, 'next': '/settings',
    })
    assert result.status_code == 303
    return result


def read(client):
    result = client.get('/waf-api/settings', base_url='https://staging.test')
    assert result.status_code == 200
    return result.json


def update(client, **changes):
    before = read(client)
    return client.put('/waf-api/settings', base_url='https://staging.test',
                      headers={'X-CSRF-Token': before['csrf_token']},
                      json={'revision': before['revision'], 'policy': {**before['policy'], **changes}})


@pytest.mark.parametrize('category,payload,rule', [
    ('sql_injection', "' OR 1=1 --", 'SQLI-001'),
    ('xss', '<script>alert(1)</script>', 'XSS-001'),
    ('path_traversal', '../../etc/passwd', 'TRAV-001'),
])
def test_live_rule_toggles_on_actual_flask_request(staging, category, payload, rule):
    client, _, settings, _ = staging
    assert client.get('/api/menu', query_string={'q': payload}).status_code == 403
    admin_login(client)
    assert update(client, **{category: False}).status_code == 200
    assert client.get('/api/menu', query_string={'q': payload}).status_code == 200
    assert rule not in json.loads(settings.log_path.read_text().splitlines()[-1])['matched_rules']
    other = '<svg onload=alert(1)>' if category != 'xss' else "' OR 1=1 --"
    assert client.get('/api/menu', query_string={'q': other}).status_code == 403
    assert update(client, **{category: True}).status_code == 200
    assert client.get('/api/menu', query_string={'q': payload}).status_code == 403


def test_no_network_or_loopback_upstream(staging, monkeypatch):
    client, wrapper, _, _ = staging
    # Windows initializes asyncio's wake-up pipe with a socket pair. Initialize
    # that runtime primitive first; forwarding itself must open no connection.
    assert wrapper.adapter is not None
    def forbidden(*args, **kwargs):
        raise AssertionError('The WSGI path must not open a network connection.')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    assert client.get('/api/menu').status_code == 200
    assert wrapper.waf.state.settings.upstream_base_url == 'http://wsgi.internal'


def test_restaurant_menu_order_and_staff_role_workflow(staging):
    client, _, _, _ = staging
    menu = client.get('/api/menu', headers={'Origin': 'https://chillibek.online'})
    assert menu.status_code == 200 and len(menu.json) == 14
    assert menu.headers['Access-Control-Allow-Origin'] == 'https://chillibek.online'
    assert client.get('/api/orders').status_code == 401
    tokens = {}
    for role in ['admin', 'waiter', 'chef']:
        login = client.post('/api/staff/login', json={'username': 'synthetic-' + role, 'password': 'synthetic-staff-password'})
        assert login.status_code == 200
        tokens[role] = {'Authorization': 'Bearer ' + login.json['token']}
    assert client.post('/api/orders', json={'table_number': '1', 'items': [{'id': 1, 'qty': 2, 'price': 1}], 'total_price': 1}).status_code == 200
    orders = client.get('/api/orders', headers=tokens['waiter'])
    assert orders.status_code == 200 and orders.json[0]['total_price'] == 4620
    order_id = orders.json[0]['id']
    assert client.put(f'/api/orders/{order_id}', json={'status': 'cooking'}, headers=tokens['chef']).status_code == 403
    assert client.put(f'/api/orders/{order_id}', json={'status': 'cooking'}, headers=tokens['waiter']).status_code == 200
    assert client.put(f'/api/orders/{order_id}', json={'status': 'ready'}, headers=tokens['chef']).status_code == 200
    assert client.put(f'/api/orders/{order_id}', json={'status': 'completed'}, headers=tokens['waiter']).status_code == 200
    assert client.get('/api/orders', headers=tokens['waiter']).json == []
    assert client.get('/api/orders/archive', headers=tokens['chef']).status_code == 403
    assert client.post('/api/menu/add', json={}, headers=tokens['waiter']).status_code == 403
    assert client.get('/waf-api/settings', headers=tokens['admin']).status_code == 401


def test_admin_auth_csrf_and_dashboard_real_events(staging):
    client, _, _, _ = staging
    assert client.get('/dashboard').status_code == 303
    assert client.get('/dashboard/api/events').status_code == 401
    assert client.put('/waf-api/settings', json={}).status_code == 401
    assert client.post('/waf-api/settings/reset', json={}).status_code == 401
    login = admin_login(client)
    assert any('Secure' in cookie and 'HttpOnly' in cookie for cookie in login.headers.getlist('Set-Cookie'))
    policy = read(client)
    assert client.put('/waf-api/settings', base_url='https://staging.test',
                      json={'revision': policy['revision'], 'policy': policy['policy']}).status_code == 403
    assert client.get('/api/menu?q=union+select+synthetic').status_code == 403
    dashboard = client.get('/dashboard', base_url='https://staging.test')
    assert dashboard.status_code == 200
    events = client.get('/dashboard/api/events', base_url='https://staging.test').json['events']
    assert any(event['decision'] == 'blocked' and 'SQLI-001' in event['matched_rules'] for event in events)
    assert client.get('/dashboard/api/summary', base_url='https://staging.test').json['blocked_requests'] >= 1


def test_restart_and_second_worker_share_live_policy(staging):
    client, _, settings, restaurant = staging
    second = protect_wsgi(restaurant, settings)
    admin_login(client)
    changed = update(client, sql_injection=False)
    assert changed.status_code == 200
    for wrapper in [second, protect_wsgi(restaurant, settings)]:
        other = StagingClient(wrapper, Response)
        assert other.get('/api/menu?q=union+select+synthetic').status_code == 200
        assert wrapper.waf.state.policy_store.read()['revision'] == changed.json['revision']


def test_size_header_and_monitor_controls(staging):
    _, _, settings, restaurant = staging
    wrapper = protect_wsgi(restaurant, replace(settings, max_request_bytes=256))
    client = StagingClient(wrapper, Response)
    assert client.get('/api/menu', data=b'x' * 257).status_code == 413
    admin_login(client)
    assert update(client, request_size=False).status_code == 200
    assert client.get('/api/menu', data=b'x' * 257).status_code == 200
    assert client.get('/api/menu', headers={'X-HTTP-Method-Override': 'DELETE'}).status_code == 403
    assert update(client, suspicious_headers=False).status_code == 200
    assert client.get('/api/menu', headers={'X-HTTP-Method-Override': 'DELETE'}).status_code == 200
    assert update(client, mode='monitor', suspicious_headers=True, request_size=True).status_code == 200
    assert client.get('/api/menu?q=union+select+synthetic', data=b'x' * 257,
                      headers={'X-HTTP-Method-Override': 'DELETE'}).status_code == 200
    event = json.loads(settings.log_path.read_text().splitlines()[-1])
    assert set(event['matched_rules']) >= {'SQLI-001', 'SIZE-001', 'HEADER-001'}


def test_logging_off_cannot_disable_audit_or_staff_auth(staging):
    client, _, settings, _ = staging
    admin_login(client)
    assert update(client, event_logging=False, mode='monitor').status_code == 200
    assert client.get('/api/menu').status_code == 200
    assert client.get('/api/orders').status_code == 401
    assert not settings.log_path.exists()
    with sqlite3.connect(settings.policy_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM configuration_audit WHERE action='update'").fetchone()[0] == 1
    state = read(client)
    reset = client.post('/waf-api/settings/reset', base_url='https://staging.test',
                        json={'revision': state['revision']}, headers={'X-CSRF-Token': state['csrf_token']})
    assert reset.status_code == 200 and reset.json['policy'] == Policy().model_dump()


def test_pythonanywhere_trusted_client_ip_and_per_client_rate_limit(staging):
    _, _, settings, restaurant = staging
    wrapper = protect_wsgi(restaurant, replace(settings, rate_limit_requests=1), trust_pythonanywhere_proxy=True)
    client = StagingClient(wrapper, Response)
    headers = {'X-Real-IP': '192.0.2.1', 'X-Forwarded-Proto': 'https', 'X-Forwarded-For': 'spoofed'}
    assert client.get('/api/menu', headers=headers).status_code == 200
    assert client.get('/api/menu', headers={**headers, 'X-Forwarded-For': 'another-spoof'}).status_code == 429
    assert client.get('/api/menu', headers={**headers, 'X-Real-IP': '192.0.2.2'}).status_code == 200
    assert client.get('/api/menu', headers={'X-Real-IP': 'not-an-ip'}).status_code == 503
    assert client.get('/api/menu').status_code == 503
    operator = StagingClient(wrapper, Response)
    # Rate limiting OFF is a real persisted policy change; use a separate operator client.
    wrapper.waf.state.policy_store.update(Policy(rate_limiting=False), 0, 'synthetic-operator')
    assert operator.get('/api/menu', headers=headers).status_code == 200


def test_generic_adapter_never_trusts_client_forwarding_headers(staging):
    _, _, settings, restaurant = staging
    wrapper = protect_wsgi(restaurant, replace(settings, rate_limit_requests=1))
    client = StagingClient(wrapper, Response)
    assert client.get('/api/menu', headers={'X-Real-IP': '192.0.2.5'}, environ_overrides={'REMOTE_ADDR': '198.51.100.1'}).status_code == 200
    assert client.get('/api/menu', headers={'X-Real-IP': '192.0.2.6', 'X-Forwarded-For': '198.51.100.2'},
                      environ_overrides={'REMOTE_ADDR': '198.51.100.1'}).status_code == 429


def test_existing_wsgi_cookie_sessions_survive_wrapper(tmp_path):
    # This application exists only inside the test. It is never exported or deployed.
    original = Flask('synthetic-cookie-app')
    original.secret_key = 'synthetic-existing-cookie-session-secret'
    @original.get('/existing-cookie')
    def cookie_session():
        session['visits'] = session.get('visits', 0) + 1
        response = jsonify(visits=session['visits'], host=request.host, scheme=request.scheme,
                           ip=request.remote_addr, query=request.args.get('q'))
        response.set_cookie('synthetic-extra', 'test-only')
        return response
    wrapper = protect_wsgi(original, WAFSettings(log_path=tmp_path / 'events.log'))
    client = StagingClient(wrapper, Response)
    first = client.get('/existing-cookie?q=%D1%82%D0%B5%D1%81%D1%82', base_url='https://staging.test',
                       environ_overrides={'REMOTE_ADDR': '198.51.100.7'})
    assert first.status_code == 200
    assert len(first.headers.getlist('Set-Cookie')) == 2
    assert first.json == {'visits': 1, 'host': 'staging.test', 'scheme': 'https', 'ip': '198.51.100.7', 'query': 'тест'}
    assert client.get('/existing-cookie', base_url='https://staging.test').json['visits'] == 2
    provider = StagingClient(protect_wsgi(original, WAFSettings(log_path=tmp_path / 'provider.log'),
                                         trust_pythonanywhere_proxy=True), Response)
    result = provider.get('/existing-cookie', base_url='https://staging.test',
                          headers={'X-Real-IP': '192.0.2.55', 'X-Forwarded-Proto': 'http'})
    assert result.status_code == 200
    assert result.json['scheme'] == 'https'
    assert result.json['ip'] == '192.0.2.55'


def test_flask_staff_login_limits_keep_distinct_real_clients(staging):
    _, _, settings, restaurant = staging
    client = StagingClient(protect_wsgi(restaurant, settings, trust_pythonanywhere_proxy=True), Response)
    first = {'X-Real-IP': '192.0.2.10', 'X-Forwarded-Proto': 'https'}
    payload = {'username': 'synthetic-unknown', 'password': 'synthetic-invalid'}
    responses = [client.post('/api/staff/login', json=payload, headers=first).status_code for _ in range(6)]
    assert responses == [401] * 5 + [429]
    # A distributed attack on the SAME account is now limited by Flask too.
    assert client.post('/api/staff/login', json=payload, headers={**first, 'X-Real-IP': '192.0.2.11'}).status_code == 429
    assert client.post('/api/staff/login', json={**payload, 'username':'synthetic-another'}, headers={**first, 'X-Real-IP': '192.0.2.12'}).status_code == 401


def test_disabled_proxy_rate_limit_cannot_disable_operator_login_throttle(staging):
    client, wrapper, _, _ = staging
    wrapper.waf.state.policy_store.update(Policy(rate_limiting=False, mode='monitor'), 0, 'synthetic-operator')
    results = [client.post('/dashboard/login', data={'username': 'synthetic-no-user'}).status_code for _ in range(6)]
    assert results == [400] * 5 + [429]


CONTROL_CASES = [
    ('mode', 'monitor', 403, 200),
    ('sql_injection', False, 403, 200),
    ('xss', False, 403, 200),
    ('path_traversal', False, 403, 200),
    ('command_injection', False, 403, 200),
    ('rate_limiting', False, 429, 200),
    ('suspicious_headers', False, 403, 200),
    ('request_size', False, 413, 200),
    ('event_logging', False, True, False),
]


def probe_control(client, settings, field):
    """Observe behavior of actual restaurant traffic, not just returned policy JSON."""
    options = {'environ_overrides': {'REMOTE_ADDR': '192.0.2.20'}}
    payloads = {'mode': "' OR 1=1 --", 'sql_injection': "' OR 1=1 --",
                'xss': '<script>alert(1)</script>', 'path_traversal': '../../etc/passwd', 'command_injection':'x; whoami'}
    if field in payloads:
        return client.get('/api/menu', query_string={'q': payloads[field]}, **options).status_code
    if field == 'rate_limiting':
        responses = [client.get('/api/menu', **options) for _ in range(settings.rate_limit_requests + 1)]
        return responses[-1].status_code
    if field == 'suspicious_headers':
        return client.get('/api/menu', headers={'X-HTTP-Method-Override': 'DELETE'}, **options).status_code
    if field == 'request_size':
        return client.get('/api/menu', data=b'x' * (settings.max_request_bytes + 1), **options).status_code
    previous = settings.log_path.read_bytes() if settings.log_path.exists() else b''
    assert client.get('/api/menu', **options).status_code == 200
    current = settings.log_path.read_bytes() if settings.log_path.exists() else b''
    return len(current) > len(previous)


def assert_independent_behavior(client, field, phase):
    options = {'environ_overrides': {'REMOTE_ADDR': f'198.51.100.{phase}'}}
    if field == 'mode':
        # Monitor changes enforcement, while all enabled detectors keep reporting.
        response = client.get('/api/menu', query_string={'q': "' OR 1=1 -- <script>alert(1)</script> ../../etc/passwd"}, **options)
        assert response.status_code == 200
        return
    if field == 'sql_injection':
        assert client.get('/api/menu', query_string={'q': '<script>alert(1)</script>'}, **options).status_code == 403
    else:
        assert client.get('/api/menu', query_string={'q': "' OR 1=1 --"}, **options).status_code == 403


@pytest.mark.parametrize('field,changed,enabled_result,changed_result', CONTROL_CASES, ids=[case[0] for case in CONTROL_CASES])
def test_every_control_hot_reload_persistence_and_independence(staging, field, changed, enabled_result, changed_result):
    _, _, original_settings, restaurant = staging
    settings = replace(original_settings, max_request_bytes=256,
                       rate_limit_requests=2 if field == 'rate_limiting' else 120)
    wrapper = protect_wsgi(restaurant, settings)
    client = StagingClient(wrapper, Response)
    existing_worker = protect_wsgi(restaurant, settings)
    assert existing_worker.waf.state.policy_store.read()['policy'] == Policy().model_dump()
    admin_login(client)
    baseline = read(client)['policy']
    assert probe_control(client, settings, field) == enabled_result
    result = update(client, **{field: changed})
    assert result.status_code == 200
    saved = result.json
    assert {key for key in baseline if baseline[key] != saved['policy'][key]} == {field}
    assert probe_control(client, settings, field) == changed_result
    assert_independent_behavior(client, field, 40)
    if field == 'mode':
        event = json.loads(settings.log_path.read_text().splitlines()[-1])
        assert set(event['matched_rules']) == {'SQLI-001', 'XSS-001', 'TRAV-001'}

    # A worker that already existed and a recreated service both read the exact
    # policy, revision, timestamp and actor committed by the settings API.
    for phase, current in enumerate([existing_worker, protect_wsgi(restaurant, settings)], 41):
        refreshed = StagingClient(current, Response)
        admin_login(refreshed)
        actual = read(refreshed)
        for key in ['policy', 'revision', 'updated_at', 'updated_by']:
            assert actual[key] == saved[key]
        assert refreshed.get('/settings/', base_url='https://staging.test').status_code == 200
        assert probe_control(refreshed, settings, field) == changed_result
        assert_independent_behavior(refreshed, field, phase)

    # Management safeguards are mandatory regardless of which control is changed.
    body = {'revision': saved['revision'], 'policy': saved['policy']}
    assert client.put('/waf-api/settings', base_url='https://staging.test', json=body).status_code == 403
    anonymous = StagingClient(wrapper, Response)
    assert anonymous.put('/waf-api/settings', base_url='https://staging.test', json=body).status_code == 401
    assert read(client)['policy'] == saved['policy']
    restored = update(client, **{field: baseline[field]})
    assert restored.status_code == 200 and restored.json['policy'] == baseline
    assert probe_control(client, settings, field) == enabled_result
    assert existing_worker.waf.state.policy_store.read()['policy'] == baseline
    with sqlite3.connect(settings.policy_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM configuration_audit WHERE action='update'").fetchone()[0] == 2
