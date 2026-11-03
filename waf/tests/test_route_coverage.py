"""Every restaurant route through the public WSGI -> WAF -> Flask pipeline.

Only tmp_path restaurant fixtures and disposable staff from test_wsgi are used.
Query probes exercise the WAF without committing malicious restaurant records.
"""
import json
from dataclasses import replace

import pytest
from werkzeug.wrappers import Response

from waf.enforcement import CONTEXT_KEY
from waf.policy import Policy
from waf.wsgi import protect_wsgi
from test_wsgi import staging, StagingClient, admin_login, read, update


# Mutations intentionally fail application validation or address nonexistent IDs.
# This lets identical probes be replayed without changing the fixture's menu.
ROUTES = [
    ('GET', '/api/menu', None, 200),
    ('HEAD', '/api/menu', None, 200),
    ('OPTIONS', '/api/menu', None, 200),
    ('POST', '/api/staff/login', {'username': 'synthetic-chef', 'password': 'incorrect-synthetic'}, 401),
    ('POST', '/api/menu/add', {}, 400),
    ('PUT', '/api/menu/edit/999999', {}, 400),
    ('DELETE', '/api/menu/delete/999999', None, 404),
    ('POST', '/api/orders', {}, 400),
    ('GET', '/api/orders', None, 200),
    ('GET', '/api/orders/archive', None, 200),
    ('PUT', '/api/orders/999999', {}, 400),
    ('DELETE', '/api/orders/999999', None, 404),
    ('GET', '/api/unknown', None, 404),
    ('PATCH', '/api/menu', {}, 405),
]
PAYLOADS = [
    ('sql_injection', "' OR 1=1 --", 'SQLI-001'),
    ('xss', '<script>alert(1)</script>', 'XSS-001'),
    ('path_traversal', '../../etc/passwd', 'TRAV-001'),
    ('command_injection', 'x; whoami', 'CMD-001'),
]


@pytest.fixture(autouse=True)
def enforce_real_flask_entry_boundary(staging):
    # Matrix cases must pass the trusted handoff, even though data is disposable.
    staging[3].testing = False


def set_policy(wrapper, **changes):
    store = wrapper.waf.state.policy_store
    state = store.read()
    return store.update(Policy(**{**state['policy'], **changes}), state['revision'], 'synthetic-coverage')


def token(client, role='admin'):
    response = client.post('/api/staff/login', json={
        'username': 'synthetic-' + role, 'password': 'synthetic-staff-password',
    })
    assert response.status_code == 200
    return response.json['token']


def send(client, route, bearer, ip='192.0.2.50', query=None):
    method, path, body, _ = route
    options = {'method': method, 'headers': {'Authorization': 'Bearer ' + bearer},
               'environ_overrides': {'REMOTE_ADDR': ip}, 'query_string': query}
    if body is not None:
        options['json'] = body
    return client.open(path, **options)


def event(settings):
    return json.loads(settings.log_path.read_text().splitlines()[-1])


@pytest.mark.parametrize('route', ROUTES, ids=lambda r: r[0] + ' ' + r[1])
def test_content_modules_on_off_monitor_every_route(staging, route):
    client, wrapper, settings, _ = staging
    bearer = token(client)
    set_policy(wrapper, brute_force=False, bot_detection=False, rate_limiting=False)
    for category, payload, rule in PAYLOADS:
        query = {'probe': payload}
        assert send(client, route, bearer, query=query).status_code == 403
        assert event(settings)['decision'] == 'blocked'
        assert rule in event(settings)['matched_rules']
        set_policy(wrapper, **{category: False})
        assert send(client, route, bearer, query=query).status_code == route[3]
        assert rule not in event(settings)['matched_rules']
        assert event(settings)['decision'] == 'allowed'
        set_policy(wrapper, **{category: True, 'mode': 'monitor'})
        assert send(client, route, bearer, query=query).status_code == route[3]
        assert event(settings)['decision'] == 'detected'
        assert rule in event(settings)['matched_rules']
        set_policy(wrapper, mode='block')


@pytest.mark.parametrize('route', ROUTES, ids=lambda r: r[0] + ' ' + r[1])
def test_rate_and_bot_modules_every_route(staging, route):
    client, wrapper, settings, _ = staging
    bearer = token(client)
    set_policy(wrapper, brute_force=False, rate_limit_requests=1, route_limit_requests=1)
    assert send(client, route, bearer).status_code == route[3]
    assert send(client, route, bearer).status_code == 429
    assert event(settings)['matched_rules'] == ['RATE-001']
    set_policy(wrapper, mode='monitor')
    assert send(client, route, bearer).status_code == route[3]
    assert event(settings)['decision'] == 'detected'
    assert 'RATE-001' in event(settings)['matched_rules']
    set_policy(wrapper, rate_limiting=False)
    assert send(client, route, bearer).status_code == route[3]
    assert send(client, route, bearer).status_code == route[3]
    set_policy(wrapper, mode='block', bot_detection_limit=2)
    for path in ['/synthetic-missing-a', '/synthetic-missing-b']:
        assert client.get(path, environ_overrides={'REMOTE_ADDR': '192.0.2.60'}).status_code == 404
    assert send(client, route, bearer, ip='192.0.2.60').status_code == 429
    assert 'BOT-001' in event(settings)['matched_rules']
    set_policy(wrapper, mode='monitor')
    assert send(client, route, bearer, ip='192.0.2.60').status_code == route[3]
    assert event(settings)['decision'] == 'detected'
    assert 'BOT-001' in event(settings)['matched_rules']
    set_policy(wrapper, bot_detection=False)
    assert send(client, route, bearer, ip='192.0.2.60').status_code == route[3]


@pytest.mark.parametrize('route', ROUTES, ids=lambda r: r[0] + ' ' + r[1])
def test_header_and_size_controls_every_route(staging, route):
    client, wrapper, settings, _ = staging
    bearer = token(client)
    set_policy(wrapper, brute_force=False, bot_detection=False, rate_limiting=False, request_size_bytes=1024)
    method, path, body, expected = route
    options = {'method': method, 'headers': {'Authorization': 'Bearer ' + bearer,
               'X-HTTP-Method-Override': 'DELETE'}, 'json': body}
    assert client.open(path, **options).status_code == 403
    assert event(settings)['matched_rules'] == ['HEADER-001']
    set_policy(wrapper, suspicious_headers=False)
    assert client.open(path, **options).status_code == expected
    assert 'HEADER-001' not in event(settings)['matched_rules']
    options['headers'].pop('X-HTTP-Method-Override')
    options.pop('json')
    data = json.dumps(body).encode() if body is not None else b''
    options['data'] = data + b' ' * (1025 - len(data))
    options['content_type'] = 'application/json' if body is not None else 'text/plain'
    assert client.open(path, **options).status_code == 413
    assert event(settings)['matched_rules'] == ['SIZE-001']
    set_policy(wrapper, request_size=False)
    assert client.open(path, **options).status_code == expected
    assert 'SIZE-001' not in event(settings)['matched_rules']
    set_policy(wrapper, request_size=True, mode='monitor')
    assert client.open(path, **options).status_code == expected
    assert event(settings)['decision'] == 'detected'
    assert 'SIZE-001' in event(settings)['matched_rules']


def test_matrix_covers_all_flask_rules_and_methods(staging):
    _, _, _, restaurant = staging
    covered = {(method, path) for method, path, _, _ in ROUTES}
    for rule in restaurant.url_map.iter_rules():
        if not rule.rule.startswith('/api/'):
            continue
        path = rule.rule.replace('<int:item_id>', '999999').replace('<int:order_id>', '999999')
        # OPTIONS and HEAD share the same central catch-all; test representatives.
        for method in rule.methods - {'HEAD', 'OPTIONS'}:
            assert (method, path) in covered


@pytest.mark.parametrize('role', ['admin', 'chef'])
def test_real_staff_login_off_monitor_on_and_audited_unblock(staging, role):
    client, wrapper, settings, _ = staging
    admin_login(client)
    assert update(client, login_max_attempts=2, rate_limiting=False).status_code == 200
    bad = {'username': 'synthetic-' + role, 'password': 'incorrect-synthetic'}
    for _ in range(2):
        assert client.post('/api/staff/login', json=bad).status_code == 401
    assert client.post('/api/staff/login', json=bad).status_code == 429
    assert event(settings)['decision'] == 'blocked'
    assert event(settings)['matched_rules'] == ['AUTH-001']
    assert update(client, brute_force=False).status_code == 200
    for _ in range(4):
        assert client.post('/api/staff/login', json=bad).status_code == 401
        assert not event(settings)['matched_rules']
    assert token(client, role)
    assert update(client, brute_force=True, mode='monitor').status_code == 200
    for _ in range(3):
        assert client.post('/api/staff/login', json=bad).status_code == 401
    assert event(settings)['decision'] == 'detected'
    assert 'AUTH-001' in event(settings)['matched_rules']
    state = read(client)
    block = next(b for b in state['blocks'] if b['kind'] == 'account')
    assert client.delete('/waf-api/blocks/' + block['id'], base_url='https://staging.test').status_code == 403
    removed = client.delete('/waf-api/blocks/' + block['id'], base_url='https://staging.test',
        headers={'X-CSRF-Token': state['csrf_token']})
    assert removed.status_code == 200
    assert any(b['action'] == 'security_unblock' and b['actor'] == 'waf-operator'
               for b in removed.json['block_history'])
    assert update(client, mode='block').status_code == 200
    assert token(client, role)


def test_production_monitor_keeps_bounded_staff_login(staging):
    _, _, settings, restaurant = staging
    wrapper = protect_wsgi(restaurant, replace(settings, allow_disabled_mode=False))
    client = StagingClient(wrapper, Response)
    admin_login(client)
    assert update(client, mode='monitor', login_max_attempts=2, rate_limiting=False).status_code == 200
    assert read(client)['effective']['login_abuse'] == 'enforced_production'
    bad = {'username': 'synthetic-chef', 'password': 'incorrect-synthetic'}
    assert [client.post('/api/staff/login', json=bad).status_code for _ in range(3)] == [401, 401, 429]
    assert client.get('/api/menu', query_string={'q': PAYLOADS[0][1]}).status_code == 200


def test_login_uses_admitted_snapshot_during_policy_change(staging):
    client, wrapper, _, restaurant = staging
    set_policy(wrapper, brute_force=False)
    seen = []
    @restaurant.before_request
    def change_after_waf_admission():
        from flask import request
        context = request.environ[CONTEXT_KEY]
        seen.append(context.revision)
        set_policy(wrapper, brute_force=True)
    bad = {'username': 'synthetic-admin', 'password': 'incorrect-synthetic'}
    assert client.post('/api/staff/login', json=bad).status_code == 401
    with wrapper.waf.state.policy_store.connect() as connection:
        assert connection.execute('SELECT COUNT(*) FROM login_counters').fetchone()[0] == 0
    assert seen == [1]
    assert client.post('/api/staff/login', json=bad).status_code == 401
    with wrapper.waf.state.policy_store.connect() as connection:
        assert connection.execute('SELECT COUNT(*) FROM login_counters').fetchone()[0] == 2


def test_raw_production_flask_cannot_bypass_waf_with_headers(staging):
    _, _, _, restaurant = staging
    restaurant.testing = False
    client = restaurant.test_client()
    assert client.get('/api/menu', headers={'X-WAF-Policy': 'disabled'}).status_code == 503


def test_single_hop_proxy_metadata_requires_explicit_trust(staging):
    _, _, settings, restaurant = staging
    wrapper = protect_wsgi(restaurant, replace(settings, trusted_proxy_ips=('192.0.2.10',)))
    client = StagingClient(wrapper, Response)
    proxy = {'environ_overrides': {'REMOTE_ADDR': '192.0.2.10'}}
    assert client.get('/api/menu', **proxy).status_code == 503
    response = client.get('/api/menu', headers={'X-Forwarded-For': '198.51.100.50',
        'X-Forwarded-Proto': 'https'}, **proxy)
    assert response.status_code == 200
    assert response.headers['Strict-Transport-Security'] == 'max-age=31536000'
    assert event(settings)['client_ip'] == '198.51.100.50'
    assert client.get('/api/menu', headers={'X-Forwarded-For': '198.51.100.50, 198.51.100.51',
        'X-Forwarded-Proto': 'https'}, **proxy).status_code == 503
    assert client.get('/api/menu', headers={'X-Forwarded-For': '198.51.100.50',
        'X-Forwarded-Proto': 'https'},
        environ_overrides={'REMOTE_ADDR': '198.51.100.70'}).status_code == 200
    assert event(settings)['client_ip'] == '198.51.100.70'


def test_off_preserves_auth_integrity_and_restaurant_data(staging):
    client, wrapper, _, restaurant = staging
    from sqlalchemy import text
    with restaurant.config['DB_ENGINE'].connect() as connection:
        before = {table: connection.execute(text('SELECT * FROM ' + table)).fetchall()
                  for table in ['staff', 'menu_items', 'orders']}
    set_policy(wrapper, mode='disabled', brute_force=False)
    assert client.get('/api/orders').status_code == 401
    chef = token(client, 'chef')
    assert client.post('/api/menu/add', headers={'Authorization': 'Bearer ' + chef}, json={}).status_code == 403
    assert client.post('/api/orders', json={'table_number': '1', 'items': []}).status_code == 400
    assert client.post('/api/staff/login', json={'username': 'synthetic-admin', 'password': 'incorrect-synthetic'}).status_code == 401
    assert client.get('/api/menu', headers={'Content-Encoding': 'gzip'}).status_code == 415
    with restaurant.config['DB_ENGINE'].connect() as connection:
        after = {table: connection.execute(text('SELECT * FROM ' + table)).fetchall()
                 for table in before}
    assert before == after


def test_hosting_capacity_denial_is_logged_independently_of_rate_switch(staging, monkeypatch):
    client, wrapper, settings, _ = staging
    set_policy(wrapper, rate_limiting=False)
    monkeypatch.setattr(wrapper.waf.state.policy_store, 'acquire', lambda *args: False)
    assert client.get('/api/menu').status_code == 429
    record = event(settings)
    assert record['decision'] == 'blocked'
    assert record['matched_rules'] == ['CAPACITY-001']
    assert record['enforcement'] == 'hosting'


def test_traffic_records_revision_decision_and_no_credentials(staging):
    client, wrapper, settings, _ = staging
    revision = set_policy(wrapper, mode='monitor')['revision']
    secret = 'synthetic-never-record-this-password'
    response = client.post('/api/staff/login', query_string={'probe': PAYLOADS[0][1]},
        json={'username': 'synthetic-admin', 'password': secret},
        headers={'Authorization': 'Bearer synthetic-never-record-this-token'})
    assert response.status_code == 401
    record = event(settings)
    assert record['decision'] == 'detected'
    assert record['policy_revision'] == revision
    assert record['policy_mode'] == 'monitor'
    assert record['status_code'] == 401
    data = settings.log_path.read_text()
    assert secret not in data and 'synthetic-never-record-this-token' not in data
    assert PAYLOADS[0][1] not in data
