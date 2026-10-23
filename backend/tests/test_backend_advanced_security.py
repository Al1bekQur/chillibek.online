"""Application defenses remain enforceable without the WAF."""
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from backend.login_guard import admit, keys
from backend.db import create_db_engine, create_schema, login_attempts
from test_security import app, client, add_staff, login, auth, add_order


def test_persistent_distributed_login_limits_without_waf(app, monkeypatch):
    clock = SimpleNamespace(time=lambda:1800000000)
    monkeypatch.setattr('backend.login_guard.time', clock)
    # server may have been imported using the legacy module name by other tests.
    import sys
    if 'login_guard' in sys.modules:
        monkeypatch.setattr(sys.modules['login_guard'], 'time', clock)
    for index in range(5):
        client = app.test_client()
        response = client.post('/api/staff/login', json={'username':'synthetic-target','password':'never-log-this'},
                               environ_overrides={'REMOTE_ADDR':f'192.0.2.{index}'})
        assert response.status_code == 401
    client = app.test_client()
    response = client.post('/api/staff/login', json={'username':'synthetic-target','password':'never-log-this'},
                           environ_overrides={'REMOTE_ADDR':'192.0.2.20'})
    assert response.status_code == 429 and int(response.headers['Retry-After']) > 0
    # A fresh engine reads the same durable account state.
    restarted = create_db_engine(app.config['DATABASE_URL'])
    assert admit(restarted, keys('192.0.2.21', 'synthetic-target')) > 0
    clock.time = lambda:1800000031
    for i in range(5):
        assert admit(restarted, keys(f'198.51.100.{i}', 'synthetic-target')) == 0
    assert admit(restarted, keys('198.51.100.20', 'synthetic-target')) == 60
    with restarted.connect() as connection:
        rows = connection.execute(select(login_attempts)).all()
        assert 'synthetic-target' not in str(rows) and 'never-log-this' not in str(rows)
    restarted.dispose()


@pytest.mark.parametrize('url', ['http://127.0.0.1/a', 'http://[::1]/a', 'http://169.254.169.254/a',
    'http://localhost/a', 'http://user:password@example.test/a', 'javascript:alert(1)', 'http://10.0.0.1/a'])
def test_menu_url_validation_without_waf(app, client, url):
    add_staff(app, 'synthetic-admin', 'admin')
    token = login(client, 'synthetic-admin')
    payload = {'category':'snacks','name':'Synthetic','description':'Synthetic','weight':'100g','price':1000,'image_url':url}
    assert client.post('/api/menu/add', json=payload, headers=auth(token)).status_code == 400


def test_stored_html_remains_json_and_api_security_headers(app, client):
    add_staff(app, 'synthetic-admin', 'admin')
    token = login(client, 'synthetic-admin')
    payload = {'category':'snacks','name':'<svg onload=alert(1)>','description':'Synthetic','weight':'100g','price':1000,'image_url':'https://images.unsplash.com/synthetic'}
    assert client.post('/api/menu/add', json=payload, headers=auth(token)).status_code == 200
    menu = client.get('/api/menu', base_url='https://staging.test')
    assert menu.content_type == 'application/json'
    assert "default-src 'none'" in menu.headers['Content-Security-Policy']
    assert menu.headers['Strict-Transport-Security'] == 'max-age=31536000'
    # Plaintext is data; existing frontend escapeHtml is the rendering defense.
    assert any(row['name'] == payload['name'] for row in menu.json)


def test_staff_tokens_expire_and_tampering_cannot_escalate(app, client):
    from itsdangerous import URLSafeTimedSerializer
    add_staff(app, 'synthetic-waiter', 'waiter')
    token = login(client, 'synthetic-waiter')
    app.config['TOKEN_MAX_AGE'] = -1
    assert client.get('/api/orders', headers=auth(token)).status_code == 401
    app.config['TOKEN_MAX_AGE'] = 28800
    assert client.post('/api/menu/add', json={}, headers=auth(token)).status_code == 403
    assert client.get('/api/orders', headers=auth(token + 'tampered')).status_code == 401


def test_order_transition_rejects_state_changed_after_authorization(app, client, monkeypatch):
    import db
    from sqlalchemy import text
    add_staff(app, 'synthetic-waiter', 'waiter')
    token = login(client, 'synthetic-waiter')
    order_id = add_order(client)
    original = db.DatabaseConnection.execute
    def change_between_read_and_write(self, statement, parameters=None):
        result = original(self, statement, parameters)
        if statement == 'SELECT status FROM orders WHERE id = ?':
            previous = result.fetchone()
            # A separate committed transaction changes the state after the role
            # check's read, reproducing a stale transition without threads.
            with app.config['DB_ENGINE'].begin() as other:
                other.execute(text("UPDATE orders SET status='completed' WHERE id=:id"), {'id':order_id})
            return SimpleNamespace(fetchone=lambda:previous)
        return result
    monkeypatch.setattr(db.DatabaseConnection, 'execute', change_between_read_and_write)
    response = client.put(f'/api/orders/{order_id}', json={'status':'cooking'}, headers=auth(token))
    assert response.status_code == 409
    with app.config['DB_ENGINE'].connect() as connection:
        assert connection.execute(text('SELECT status FROM orders WHERE id=:id'), {'id':order_id}).scalar_one() == 'completed'
