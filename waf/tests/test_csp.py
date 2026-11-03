"""CSP through the actual WSGI -> WAF -> Flask stack; temporary data only."""
import json
import sqlite3
from dataclasses import replace

import pytest
from pydantic import ValidationError

from waf.csp_policy import CSPPolicy
from waf.policy import Policy, PolicyStore
from waf.wsgi import protect_wsgi
from waf.tests.test_wsgi import staging, StagingClient, admin_login, read, update
from werkzeug.wrappers import Response

BASE = 'https://staging.test'


@pytest.fixture
def hosted(staging):
    _, _, settings, restaurant = staging
    wrapper = protect_wsgi(restaurant, replace(settings, serve_frontend=True))
    return StagingClient(wrapper, Response), wrapper, settings


@pytest.mark.parametrize('mode,master,header', [
    ('enforce', 'block', 'Content-Security-Policy'),
    ('off', 'block', None),
    ('report-only', 'block', 'Content-Security-Policy-Report-Only'),
    ('enforce', 'monitor', 'Content-Security-Policy-Report-Only'),
    ('enforce', 'disabled', None),
])
def test_csp_modes_all_served_documents(hosted, mode, master, header):
    client, _, _ = hosted
    admin_login(client)
    data = read(client)
    assert update(client, mode=master, csp={**data['policy']['csp'], 'mode': mode}).status_code == 200
    for path in ['/', '/index.html', '/admin.html', '/kitchen.html', '/dashboard', '/settings/']:
        result = client.get(path, base_url=BASE)
        assert result.status_code == 200, path
        assert result.headers['X-Content-Type-Options'] == 'nosniff'
        assert ('Content-Security-Policy' in result.headers) == (header == 'Content-Security-Policy')
        assert ('Content-Security-Policy-Report-Only' in result.headers) == (header == 'Content-Security-Policy-Report-Only')
        if header:
            policy = result.headers[header]
            assert "script-src 'self'" in policy and "style-src 'self'" in policy
            assert "script-src-attr 'none'" in policy and "object-src 'none'" in policy
            assert "require-trusted-types-for 'script'" in policy
            assert 'report-uri /csp-report' in policy
            assert 'unsafe-inline' not in policy and 'unsafe-eval' not in policy
        if path.endswith('.html') or path == '/':
            assert 'data-api-base="/api"' in result.text
    assert client.get('/api/menu', base_url=BASE).status_code == 200
    assert client.get('/synthetic-missing', base_url=BASE).status_code == 404


def test_csp_disabled_frontend_coverage_and_request_rules_are_independent(staging):
    client, _, _, _ = staging
    admin_login(client)
    data = read(client)
    assert data['csp_coverage']['restaurant'] == 'not served (opt-in required)'
    assert data['csp_coverage']['github_pages'].startswith('NOT COVERED')
    assert data['csp_coverage']['live_deployment_verified'] is False
    assert update(client, csp={**data['policy']['csp'], 'mode': 'off'}).status_code == 200
    assert client.get('/api/menu?q=%3Cscript%3Ealert(1)%3C/script%3E', base_url=BASE).status_code == 403
    assert update(client, xss=False).status_code == 200
    assert client.get('/api/menu?q=%3Cscript%3Ealert(1)%3C/script%3E', base_url=BASE).status_code == 200
    assert 'Content-Security-Policy' not in client.get('/dashboard/login', base_url=BASE).headers


@pytest.mark.parametrize('source', ["'unsafe-inline'", "'unsafe-eval'", '*', 'https:', 'data:',
    'https://good.test;script-src *', 'https://good.test\nX:evil', 'https://good.test/path',
    'https://user:password@good.test', 'http://not-loopback.test', 'https://good.test:999999',
    'https://пример.рф', 'https://good.test?x', 'https://good.test#x', 'https://good.test\\evil',
    'https://good.test<evil', 'https://bad%20host', 'https://bad..host'])
def test_csp_rejects_unsafe_sources(source):
    with pytest.raises(ValidationError):
        CSPPolicy(script_src=["'self'", source])


def test_csp_auth_csrf_validation_persistence_and_schema_upgrade(hosted, staging):
    client, _, settings = hosted
    assert client.get('/dashboard/api/csp', base_url=BASE).status_code == 401
    assert client.put('/waf-api/settings', json={}, base_url=BASE).status_code == 401
    admin_login(client)
    data = read(client)
    changed = {**data['policy']['csp'], 'mode': 'report-only', 'trusted_types': False,
               'img_src': ["'self'", 'https://cdn.example.test']}
    assert client.put('/waf-api/settings', base_url=BASE, json={'revision': data['revision'],
        'policy': {**data['policy'], 'csp': changed}}).status_code == 403
    result = update(client, csp=changed)
    assert result.status_code == 200
    reopened = PolicyStore(settings.policy_path).read()
    assert reopened['policy']['csp']['mode'] == 'report-only'
    restarted = protect_wsgi(staging[3], replace(settings, serve_frontend=True))
    restarted_page = StagingClient(restarted, Response).get('/index.html', base_url=BASE)
    assert restarted_page.status_code == 200
    assert 'Content-Security-Policy-Report-Only' in restarted_page.headers
    assert 'require-trusted-types-for' not in client.get('/index.html', base_url=BASE).headers['Content-Security-Policy-Report-Only']
    assert update(client, csp={**changed, 'script_src': ["'none'"]}).status_code == 422
    assert update(client, csp={**changed, 'connect_src': ["'none'"]}).status_code == 422
    # Exact pre-CSP schema migrates once, retaining all prior operator choices.
    legacy = {**reopened['policy'], 'sql_injection': False, 'login_max_attempts': 17}
    del legacy['csp']
    with sqlite3.connect(settings.policy_path) as connection:
        connection.execute('UPDATE policy SET value=? WHERE id=1', (json.dumps(legacy),))
    upgraded = PolicyStore(settings.policy_path).read()
    assert upgraded['revision'] == reopened['revision'] + 1
    assert all(upgraded['policy'][key] == value for key, value in legacy.items())
    assert PolicyStore(settings.policy_path).read() == upgraded


def report(**changes):
    return {'csp-report': {'document-uri': BASE + '/index.html?secret=sensitive#private',
        'effective-directive': 'script-src-elem', 'disposition': 'enforce',
        'blocked-uri': 'https://evil.invalid/private?token=sensitive', 'script-sample': 'SECRET', **changes}}


def send(client, payload=None, **kwargs):
    return client.post('/csp-report', base_url=BASE, data=json.dumps(report() if payload is None else payload),
        content_type='application/csp-report', **kwargs)


def test_csp_report_privacy_formats_and_retention(hosted):
    client, wrapper, _ = hosted
    assert send(client).status_code == 204
    batch = [{'type': 'csp-violation', 'body': {'documentURL': BASE + '/admin.html',
        'effectiveDirective': 'script-src-attr', 'disposition': 'report', 'blockedURL': 'inline'}}]
    assert client.post('/csp-report', base_url=BASE, data=json.dumps(batch), content_type='application/reports+json').status_code == 204
    admin_login(client)
    assert 'id="cspReports"' in client.get('/dashboard', base_url=BASE).text
    result = client.get('/dashboard/api/csp', base_url=BASE)
    assert result.status_code == 200
    assert len(result.json['reports']) == 2
    assert {r['disposition'] for r in result.json['reports']} == {'enforce', 'report'}
    assert result.json['reports'][-1]['document_path'] == '/index.html'
    assert result.json['reports'][-1]['blocked_resource'] == 'external resource'
    assert all(secret not in result.text for secret in ['sensitive', 'SECRET', 'evil.invalid', 'script-sample'])
    store = wrapper.waf.state.policy_store
    store.record_csp_reports([{'directive': 'script-src', 'document_path': '/index.html',
        'blocked_resource': 'inline', 'disposition': 'enforce'}] * 1010, 0)
    assert len(store.csp_reports()) == 100
    with store.connect() as connection:
        assert connection.execute('SELECT COUNT(*) FROM csp_reports').fetchone()[0] == 1000


@pytest.mark.parametrize('payload', [[], None, {}, {'csp-report': []},
    report(**{'document-uri': 'https://foreign.test/index.html'}),
    report(**{'document-uri': BASE + '/private/secret'}), report(disposition='unknown'),
    report(**{'effective-directive': '<img onerror=alert(1)>'}),
    report(**{'blocked-uri': {'unexpected': True}}), report(**{'blocked-uri': 'http://['}),
])
def test_invalid_reports_controlled(hosted, payload):
    client, _, _ = hosted
    assert send(client, payload if payload is not None else {'csp-report': None}).status_code == 400


def test_report_hard_limits_and_origin_even_when_optional_modules_off(hosted):
    client, _, _ = hosted
    admin_login(client)
    assert update(client, mode='disabled', request_size=False, rate_limiting=False, csp={**read(client)['policy']['csp'], 'mode': 'off'}).status_code == 200
    assert send(client, headers={'Origin': 'https://foreign.test'}).status_code == 403
    assert client.post('/csp-report', base_url=BASE, data='x' * 8193, content_type='application/csp-report').status_code == 413
    assert client.post('/csp-report', base_url=BASE, json={}).status_code == 415
    # Three prior requests: framing-rejected oversized body never enters quota.
    for _ in range(28):
        assert send(client).status_code == 204
    assert send(client).status_code == 429


def test_protected_assets_have_no_inline_execution(hosted):
    client, _, _ = hosted
    for name in ['index', 'admin', 'kitchen']:
        page = client.get('/' + name + '.html', base_url=BASE)
        assert '<script>' not in page.text and '<style>' not in page.text
        import re
        assert not re.search(r'\son\w+\s*=', page.text)
        for ext, mime in [('js', 'javascript'), ('css', 'text/css')]:
            asset = client.get(f'/restaurant-{name}.{ext}', base_url=BASE)
            assert asset.status_code == 200 and mime in asset.content_type
    assert client.get('/restaurant-unknown.js', base_url=BASE).status_code == 404
