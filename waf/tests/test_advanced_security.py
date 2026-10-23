"""Synthetic security regression suite. No network or production data."""
import asyncio
import json
import re
import sqlite3
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from werkzeug.security import generate_password_hash

from waf.app import create_app
from waf.config import WAFSettings
from waf.policy import Policy, PolicyStore
from waf.rules import inspect_values

CORPUS = json.loads(Path(__file__).with_name('security_corpus.json').read_text(encoding='utf-8'))


@pytest.mark.parametrize('case', CORPUS, ids=[f"{c['category']}-{i}" for i, c in enumerate(CORPUS)])
def test_labeled_corpus(case):
    rules, score = inspect_values([case['value']], {case['category']})
    assert bool(rules) == case['malicious']
    assert (score >= 5) == case['malicious']


@pytest.fixture
async def engine(tmp_path):
    captured = []
    upstream = FastAPI()

    @upstream.api_route('/{path:path}', methods=['GET', 'POST'])
    async def harmless(path: str, request: Request):
        captured.append(path)
        if path == 'api/staff/login':
            return JSONResponse({'detail': 'Synthetic failure'}, status_code=401)
        return JSONResponse({'synthetic': True}, status_code=200 if path.startswith('api/') else 404)

    settings = WAFSettings(log_path=tmp_path / 'events.log', policy_path=tmp_path / 'policy.sqlite3',
        upstream_transport=httpx.ASGITransport(app=upstream), rate_limit_requests=10000, route_limit_requests=10000,
        dashboard_username='synthetic-operator', dashboard_password_hash=generate_password_hash('synthetic-password'),
        dashboard_session_secret='synthetic-advanced-session-secret-at-least-32-characters')
    app = create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://staging.test') as client:
        yield client, app, settings, captured


def apply(app, **changes):
    store = app.state.policy_store
    before = store.read()
    return store.update(Policy(**{**before['policy'], **changes}), before['revision'], 'synthetic-operator')


@pytest.mark.anyio
@pytest.mark.parametrize('case', [c for c in CORPUS if c['malicious']])
async def test_attack_wire_variants_and_real_policy(engine, case):
    client, app, settings, captured = engine
    category, value = case['category'], case['value']
    expected = {'sql_injection':'SQLI-001', 'xss':'XSS-001', 'path_traversal':'TRAV-001', 'command_injection':'CMD-001'}[category]
    # Isolate each rule so another category cannot hide a disabled-module defect.
    apply(app, **{key: key == category for key in ['sql_injection','xss','path_traversal','command_injection']})
    for transformed in [value, quote(quote(value, safe=''), safe='')]:
        assert (await client.post('/api/orders', json={'nested': [{'text': transformed}]})).status_code == 403
        assert expected in json.loads(settings.log_path.read_text().splitlines()[-1])['matched_rules']
    # JSON unicode escapes must be parsed, not inspected as opaque backslashes.
    escaped = ''.join('\\u%04x' % ord(char) for char in value)
    assert (await client.post('/api/orders', content='{"value":"' + escaped + '"}', headers={'Content-Type':'application/json'})).status_code == 403
    assert not captured
    apply(app, mode='monitor')
    assert (await client.post('/api/orders', json={'text':value})).status_code == 200
    assert expected in json.loads(settings.log_path.read_text().splitlines()[-1])['matched_rules']
    apply(app, mode='block', **{category:False})
    assert (await client.post('/api/orders', json={'text':value})).status_code == 200
    assert expected not in json.loads(settings.log_path.read_text().splitlines()[-1])['matched_rules']
    restarted = create_app(settings)
    assert restarted.state.policy_store.read() == app.state.policy_store.read()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restarted), base_url='https://staging.test') as other:
        assert (await other.post('/api/orders', json={'text':value})).status_code == 200


@pytest.mark.anyio
async def test_form_and_multipart_parsing(engine):
    client, _, _, _ = engine
    assert (await client.post('/api/orders', data={'text': '<svg onload=alert(1)>'})).status_code == 403
    assert (await client.post('/api/orders', files={'text': (None, '<svg onload=alert(1)>')})).status_code == 403
    assert (await client.post('/api/orders', files={'text': (None, 'Fresh seasonal soup')})).status_code == 200
    assert (await client.post('/api/orders', content='{"x":' + '[' * 30 + '0' + ']' * 30 + '}', headers={'Content-Type':'application/json'})).status_code == 400


@pytest.mark.anyio
@pytest.mark.parametrize('headers,status', [
    ([(b'content-length',b'0'),(b'content-length',b'0')],400),
    ([(b'content-length',b'0'),(b'transfer-encoding',b'chunked')],400),
    ([(b'transfer-encoding',b'gzip, chunked')],400),
    ([(b'host',b'first'),(b'host',b'second')],400),
    ([(b'content-length',b'+0')],400),
    ([(b'content-length',b'1, 1')],400),
    ([(b'bad name',b'v')],400),
    ([(b'x-test',b'v\r\nInjected: yes')],400),
    ([(b'authorization',b'a'),(b'authorization',b'b')],400),
    ([(b'x-'+str(i).encode(),b'x') for i in range(81)],431),
    ([(b'x-large',b'x'*17000)],431),
    ([(b'content-encoding',b'gzip')],415),
])
async def test_protocol_safety_cannot_be_disabled(engine, headers, status):
    client, app, _, captured = engine
    apply(app, mode='monitor', suspicious_headers=False)
    response = await client.get('/api/menu', headers=headers)
    assert response.status_code == status
    assert not captured


@pytest.mark.anyio
async def test_hard_size_ceiling_and_length_mismatch(engine):
    _, app, settings, captured = engine
    apply(app, mode='monitor', request_size=False)
    small = create_app(replace(settings, hard_max_request_bytes=64))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=small), base_url='https://staging.test') as client:
        assert (await client.post('/api/orders', content=b'x'*65)).status_code == 413
        assert (await client.post('/api/orders', content=b'x', headers={'Content-Length':'2'})).status_code == 400
    assert not captured


def test_sliding_window_does_not_reset_at_clock_boundary(tmp_path, monkeypatch):
    clock = SimpleNamespace(time=lambda:59.9)
    monkeypatch.setattr('waf.policy.time', clock)
    store = PolicyStore(tmp_path/'policy.sqlite3')
    assert not store.over_limit('synthetic', '192.0.2.1', 1, 60)
    clock.time = lambda:60.1
    assert store.over_limit('synthetic', '192.0.2.1', 1, 60)
    clock.time = lambda:120.1
    assert not store.over_limit('synthetic', '192.0.2.1', 1, 60)


@pytest.mark.anyio
async def test_distributed_login_lock_toggle_monitor_persistence(engine):
    _, app, settings, _ = engine
    async def attempt(ip):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip,1234)), base_url='https://staging.test') as client:
            return await client.post('/api/staff/login', json={'username':'synthetic-target','password':'synthetic-never-log'})
    for i in range(5):
        assert (await attempt(f'192.0.2.{i}')).status_code == 401
    assert (await attempt('192.0.2.10')).status_code == 429
    apply(app, mode='monitor')
    assert (await attempt('192.0.2.11')).status_code == 401
    apply(app, mode='block', brute_force=False)
    assert (await attempt('192.0.2.12')).status_code == 401
    assert create_app(settings).state.policy_store.read()['policy']['brute_force'] is False
    assert 'synthetic-never-log' not in settings.log_path.read_text()


@pytest.mark.anyio
async def test_scanner_sequences_toggle_and_monitor(engine):
    client, app, settings, _ = engine
    for i in range(settings.bot_probe_limit):
        assert (await client.get('/synthetic-missing-' + str(i), headers={'User-Agent':'Ordinary Browser'})).status_code == 404
    assert (await client.get('/api/menu')).status_code == 429
    apply(app, mode='monitor')
    assert (await client.get('/api/menu')).status_code == 200
    assert 'BOT-001' in json.loads(settings.log_path.read_text().splitlines()[-1])['matched_rules']
    apply(app, mode='block', bot_detection=False)
    assert (await client.get('/api/menu')).status_code == 200
    assert create_app(settings).state.policy_store.read()['policy']['bot_detection'] is False


@pytest.mark.anyio
async def test_concurrency_and_wall_timeout(engine):
    _, _, settings, _ = engine
    started, release = asyncio.Event(), asyncio.Event()
    async def slow(request):
        started.set()
        await release.wait()
        return httpx.Response(200, json={'synthetic':True})
    app = create_app(replace(settings, upstream_transport=httpx.MockTransport(slow), max_concurrent_per_ip=1, request_timeout_seconds=0.1))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://staging.test') as client:
        first = asyncio.create_task(client.get('/api/menu'))
        await started.wait()
        assert (await client.get('/api/menu')).status_code == 429
        assert (await first).status_code == 504
        release.set()
        assert (await client.get('/api/menu')).status_code == 200


@pytest.mark.anyio
async def test_route_quotas_and_monitor_log(engine):
    _, _, settings, _ = engine
    app = create_app(replace(settings, route_limit_requests=2))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://staging.test') as client:
        assert (await client.get('/api/menu')).status_code == 200
        assert (await client.get('/api/menu')).status_code == 200
        assert (await client.get('/api/menu')).status_code == 429
        assert (await client.post('/api/orders', json={'table_number':'1'})).status_code == 200
        apply(app, mode='monitor')
        assert (await client.get('/api/menu')).status_code == 200
        assert 'RATE-001' in json.loads(settings.log_path.read_text().splitlines()[-1])['matched_rules']
        apply(app, mode='block', rate_limiting=False)
        assert (await client.get('/api/menu')).status_code == 200


@pytest.mark.anyio
async def test_body_timeout_safe_protocol_log_and_lease_cleanup(tmp_path):
    from waf.protocol import ProtocolGuard
    settings = WAFSettings(log_path=tmp_path/'events.log', body_timeout_seconds=0.01)
    store = PolicyStore(tmp_path/'policy.sqlite3')
    messages = []
    async def unreachable(scope, receive, send):
        raise AssertionError('Incomplete body must never reach the application')
    async def slow_receive():
        await asyncio.sleep(0.1)
        return {'type':'http.request', 'body':b'synthetic-password', 'more_body':True}
    async def send(message):
        messages.append(message)
    guard = ProtocolGuard(unreachable, settings, store)
    await guard({'type':'http', 'scheme':'https', 'method':'POST', 'path':'/synthetic-secret-path',
                 'headers':[], 'client':('192.0.2.1',123)}, slow_receive, send)
    assert messages[0]['status'] == 408
    log = settings.log_path.read_text()
    assert 'HTTP-001' in log and 'synthetic-password' not in log and 'synthetic-secret-path' not in log
    with store.connect() as connection:
        assert connection.execute('SELECT COUNT(*) FROM leases').fetchone()[0] == 0


@pytest.mark.anyio
async def test_unknown_path_and_query_secrets_never_enter_event_log(engine):
    client, _, settings, _ = engine
    await client.get('/synthetic-secret-token?password=synthetic-password')
    log = settings.log_path.read_text()
    assert 'synthetic-secret-token' not in log and 'synthetic-password' not in log
    assert '/[unrecognized]' in log


def test_expired_concurrency_leases_and_lockout_progression(tmp_path, monkeypatch):
    clock = SimpleNamespace(time=lambda:1800000000)
    monkeypatch.setattr('waf.policy.time', clock)
    store = PolicyStore(tmp_path/'policy.sqlite3')
    assert store.acquire('proxy:first', '192.0.2.1', 1, 1, 10)
    assert not store.acquire('proxy:second', '192.0.2.1', 1, 1, 10)
    clock.time = lambda:1800000011
    assert store.acquire('proxy:second', '192.0.2.1', 1, 1, 10)
    identities = store.login_keys('192.0.2.1', 'synthetic-target')
    for _ in range(5):
        store.login_result(identities, True)
    assert store.login_locked(identities)
    clock.time = lambda:1800000042
    assert not store.login_locked(identities)
    for _ in range(5):
        store.login_result(identities, True)
    with store.connect() as connection:
        assert connection.execute('SELECT locked_until FROM failures WHERE client=?', (identities[-1],)).fetchone()[0] == 1800000102


def test_unclosed_comment_input_has_bounded_processing_cost():
    import time
    started = time.perf_counter()
    inspect_values(['a/*' * 10000], {'sql_injection'})
    assert time.perf_counter() - started < 2.0


def test_missing_policy_row_fails_closed_after_restart(tmp_path):
    store = PolicyStore(tmp_path/'policy.sqlite3')
    store.read()
    with sqlite3.connect(store.path) as connection:
        connection.execute('DELETE FROM policy')
    for current in [store, PolicyStore(store.path)]:
        with pytest.raises(sqlite3.DatabaseError):
            current.read()
    with sqlite3.connect(store.path) as connection:
        assert connection.execute('SELECT COUNT(*) FROM policy').fetchone()[0] == 0


def test_exact_legacy_schema_upgraded_once_without_losing_disabled_rules(tmp_path):
    store = PolicyStore(tmp_path/'policy.sqlite3')
    original = store.read()
    legacy = {key:value for key,value in original['policy'].items() if key not in {'command_injection','brute_force','bot_detection'}}
    legacy['sql_injection'] = False
    with sqlite3.connect(store.path) as connection:
        connection.execute('UPDATE policy SET value=? WHERE id=1', (json.dumps(legacy),))
    upgraded = PolicyStore(store.path).read()
    assert upgraded['policy']['sql_injection'] is False
    assert upgraded['policy']['command_injection'] is True
    assert upgraded['revision'] == original['revision'] + 1
    assert store.read() == upgraded
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM configuration_audit WHERE action='schema_upgrade'").fetchone()[0] == 1


@pytest.mark.anyio
async def test_logout_csrf_safe_validation_and_security_headers(engine):
    client, _, settings, _ = engine
    page = await client.get('/dashboard/login')
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)[1]
    assert (await client.post('/dashboard/login', data={'username':'synthetic-operator','password':'synthetic-password','csrf_token':csrf})).status_code == 303
    assert (await client.post('/dashboard/logout')).status_code == 403
    page = await client.get('/dashboard')
    assert 'sha256-' in page.headers['content-security-policy']
    assert page.headers['strict-transport-security'] == 'max-age=31536000'
    state = (await client.get('/waf-api/settings')).json()
    body = {'revision':state['revision'], 'policy':{**state['policy'], 'sql_injection':'synthetic-sensitive-input'}}
    invalid = await client.put('/waf-api/settings', json=body, headers={'X-CSRF-Token':state['csrf_token']})
    assert invalid.status_code == 422 and 'synthetic-sensitive-input' not in invalid.text
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)[1]
    assert (await client.post('/dashboard/logout', data={'csrf_token':csrf})).status_code == 303
    assert (await client.get('/waf-api/settings')).status_code == 401
