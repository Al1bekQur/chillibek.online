"""Audit A01/A02 regressions through WSGI -> WAF -> real production-mode Flask."""
import json
from urllib.parse import quote

import pytest

from test_wsgi import staging
from waf.parsing import InvalidInspectionInput
from waf.policy import Policy
from waf.rules import inspect_values


def apply(wrapper, **changes):
    store = wrapper.waf.state.policy_store
    state = store.read()
    return store.update(Policy(**{**state['policy'], **changes}), state['revision'], 'synthetic-regression')


@pytest.fixture(autouse=True)
def real_entry_boundary(staging):
    staging[3].testing = False
    apply(staging[1], rate_limiting=False, bot_detection=False)


def last_event(settings):
    return json.loads(settings.log_path.read_text(encoding='utf-8').splitlines()[-1])


@pytest.mark.parametrize('payload', [
    '<![audit]>', '<![bogus]><svg onload=alert(1)>', '<script>audit()</script>',
    quote(quote('<img src=x onerror=alert(1)>')), '&#60;svg onload=alert(1)&#62;',
    '＜script＞audit()＜/script＞', '<svg\x00 onload=alert(1)>',
])
def test_xss_block_monitor_off_and_logging(staging, payload, monkeypatch):
    client, wrapper, settings, _ = staging
    for method, path, body in [('GET', '/api/menu', None), ('POST', '/api/orders', {'probe': payload})]:
        apply(wrapper, mode='block', xss=True)
        options = {'query_string': {'probe': payload}} if body is None else {'json': body}
        response = client.open(path, method=method, **options)
        assert response.status_code == 403
        record = last_event(settings)
        assert record['decision'] == 'blocked' and 'XSS-001' in record['matched_rules']
        assert payload not in response.text and 'Traceback' not in response.text
        apply(wrapper, mode='monitor')
        assert client.open(path, method=method, **options).status_code == (200 if body is None else 400)
        assert last_event(settings)['decision'] == 'detected'
        assert 'XSS-001' in last_event(settings)['matched_rules']
        apply(wrapper, mode='block', xss=False)
        # OFF must skip this detector, not merely discard its verdict afterward.
        with monkeypatch.context() as local:
            local.setitem(__import__('waf.rules', fromlist=['DETECTORS']).DETECTORS, 'xss',
                          lambda _: pytest.fail('Disabled XSS detector was called'))
            assert client.open(path, method=method, **options).status_code == (200 if body is None else 400)
        assert 'XSS-001' not in last_event(settings)['matched_rules']
        assert last_event(settings)['decision'] == 'allowed'


def test_benign_unicode_incomplete_markup_and_nonstring_json(staging):
    client, _, _, _ = staging
    for value in ['Сырники 🧀 Қазақша', '2 < 3 & 4 > 1', '<![CDATA[menu]]>', '<!-- unfinished', 'é\u0301']:
        assert client.get('/api/menu', query_string={'text': value}).status_code == 200
    for value in [None, True, 4, 2.5, [], {}, [1, None, {'text': 'Soup'}]]:
        # These are valid JSON types, not text coerced into a detector.
        assert client.post('/api/orders', json={'items': value}).status_code == 400


@pytest.mark.parametrize('mode,xss', [('block', True), ('monitor', True), ('block', False), ('disabled', False)])
def test_invalid_unicode_is_controlled_input_integrity_error(staging, mode, xss):
    client, wrapper, settings, _ = staging
    apply(wrapper, mode=mode, xss=xss)
    for body in [b'{"text":"\\ud800"}', b'{"\\udfff":"value"}', b'{"text":"\xff"}']:
        response = client.post('/api/orders', data=body, content_type='application/json')
        assert response.status_code == 400
        assert response.json == {'detail': 'Malformed request data.'}
        record = last_event(settings)
        assert record['matched_rules'] == ['PARSE-001'] and record['decision'] == 'blocked'
        assert record['policy_revision'] == wrapper.waf.state.policy_store.read()['revision']


@pytest.mark.parametrize('values', [None, 5, 'not-a-sequence', [None], [5], [b'<script>'], [{}], ['\ud800']])
def test_detector_rejects_unexpected_internal_types_predictably(values):
    with pytest.raises(InvalidInspectionInput):
        inspect_values(values)


def test_numeric_bounds_all_payload_fields_and_routes(staging):
    client, wrapper, settings, restaurant = staging
    login = client.post('/api/staff/login', json={
        'username': 'synthetic-admin', 'password': 'synthetic-staff-password'})
    assert login.status_code == 200
    headers = {'Authorization': 'Bearer ' + login.json['token']}
    menu = {'category': 'snacks', 'name': 'Synthetic', 'description': 'Synthetic',
            'weight': '100g', 'price': 1000, 'image_url': 'https://images.unsplash.com/synthetic'}
    from sqlalchemy import text
    with restaurant.config['DB_ENGINE'].connect() as connection:
        before = {table: connection.execute(text('SELECT * FROM ' + table)).fetchall()
                  for table in ['staff', 'menu_items', 'orders']}
    for value in ['9' * 5000, '0' * 5000, '9' * 32, '1e5000', '²', '١', '-1', '1.5', True, None, [], {}, 1e100]:
        for field in ['id', 'qty', 'price']:
            item = {'id': 1, 'qty': 1, 'price': 1000}
            item[field] = value
            assert client.post('/api/orders', json={'table_number': '1', 'items': [item]}).status_code == 400
        assert client.post('/api/orders', json={'table_number': '1', 'items': [{'id': 1, 'qty': 1}],
                                             'total_price': value}).status_code == 400
        for path, method in [('/api/menu/add', 'POST'), ('/api/menu/edit/1', 'PUT')]:
            assert client.open(path, method=method, json={**menu, 'price': value}, headers=headers).status_code == 400
    for table in ['²', '١', '9' * 5000, [], None, True]:
        assert client.post('/api/orders', json={'table_number': table, 'items': [{'id': 1, 'qty': 1}]}).status_code == 400
    # Numeric URL converters run before Flask before_request, and SQL binding
    # has a signed 64-bit ceiling even when int() itself accepts the number.
    for value in ['9' * 5000, '9' * 32, str(2**63), '²']:
        for method, path in [('PUT', '/api/menu/edit/'), ('DELETE', '/api/menu/delete/'),
                             ('PUT', '/api/orders/'), ('DELETE', '/api/orders/')]:
            response = client.open(path + value, method=method, json={'status': 'cooking'}, headers=headers)
            assert response.status_code in {404, 405}  # Router may retain an OPTIONS method match.
            assert 'Traceback' not in response.text
    apply(wrapper, mode='disabled', xss=False)
    assert client.post('/api/orders', json={'table_number': '1', 'items': [{'id': 1, 'qty': '9' * 5000}]}).status_code == 400
    with restaurant.config['DB_ENGINE'].connect() as connection:
        assert before == {table: connection.execute(text('SELECT * FROM ' + table)).fetchall() for table in before}
    assert all(json.loads(line)['status_code'] != 500 for line in settings.log_path.read_text().splitlines())


def test_normal_numeric_strings_and_independent_security(staging):
    client, wrapper, _, _ = staging
    apply(wrapper, xss=False)
    assert client.get('/api/orders').status_code == 401
    assert client.get('/api/menu', query_string={'q': "' OR 1=1 --"}).status_code == 403
    assert client.post('/api/orders', json={'table_number': '01', 'items': [{'id': '0001', 'qty': '02'}]}).status_code == 200
    assert client.get('/api/menu', headers={'Content-Encoding': 'gzip'}).status_code == 415
