import os
import sys
import tempfile
from pathlib import Path

import pytest
from werkzeug.security import check_password_hash, generate_password_hash


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
TEST_DATABASE = tempfile.TemporaryDirectory()
os.environ["FLASK_SECRET_KEY"] = "test-only-secret-key-never-use-outside-tests"
os.environ["DATABASE_PATH"] = str(Path(TEST_DATABASE.name) / "import-only.sqlite3")

from server import create_app, get_db_connection  # noqa: E402
import server as imported_server
imported_server.app.config['DB_ENGINE'].dispose()


@pytest.fixture
def app(tmp_path):
    instance = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-secret-key-never-use-outside-tests",
            "DATABASE_PATH": str(tmp_path / "test.sqlite3"),
            "CORS_ALLOWED_ORIGINS": ["https://chillibek.online"],
            "RATELIMIT_STORAGE_URI": "memory://",
        }
    )
    yield instance
    instance.config['DB_ENGINE'].dispose()


@pytest.fixture
def client(app):
    return app.test_client()


def add_staff(app, username, role, password="synthetic-test-password"):
    with app.app_context(), get_db_connection() as connection:
        connection.execute(
            "INSERT INTO staff (username, password, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )


def login(client, username):
    response = client.post(
        "/api/staff/login",
        json={"username": username, "password": "synthetic-test-password"},
    )
    assert response.status_code == 200
    return response.json["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def add_order(client):
    response = client.post(
        "/api/orders",
        json={"table_number": "1", "items": [{"id": 1, "qty": 1}]},
    )
    assert response.status_code == 200
    with client.application.app_context(), get_db_connection() as connection:
        return connection.execute("SELECT MAX(id) FROM orders").fetchone()[0]


def test_public_menu_and_protected_staff_endpoints(client):
    assert client.get("/api/menu").status_code == 200
    assert client.get("/api/orders").status_code == 401
    assert client.get("/api/orders/archive").status_code == 401
    assert client.post("/api/menu/add", json={}).status_code == 401
    assert client.get("/api/orders", headers=auth("invalid-token")).status_code == 401
    with client.application.app_context(), get_db_connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM staff").fetchone()[0] == 0


def test_login_hashes_legacy_password_without_exposing_it(app, client):
    with app.app_context(), get_db_connection() as connection:
        connection.execute(
            "INSERT INTO staff (username, password, role) VALUES (?, ?, ?)",
            ("legacy-user", "synthetic-legacy-password", "waiter"),
        )

    response = client.post(
        "/api/staff/login",
        json={"username": "LEGACY-USER", "password": "synthetic-legacy-password"},
    )
    assert response.status_code == 200
    assert response.json["success"] is True
    assert response.json["role"] == "waiter"
    assert "synthetic-legacy-password" not in response.get_data(as_text=True)
    with app.app_context(), get_db_connection() as connection:
        stored = connection.execute(
            "SELECT password FROM staff WHERE username = 'legacy-user'"
        ).fetchone()["password"]
    assert stored != "synthetic-legacy-password"
    assert check_password_hash(stored, "synthetic-legacy-password")


def test_login_rejects_malformed_json_and_bad_credentials(client):
    assert client.post(
        "/api/staff/login", data="{", content_type="application/json"
    ).status_code == 400
    response = client.post(
        "/api/staff/login",
        json={"username": "missing", "password": "wrong"},
    )
    assert response.status_code == 401
    assert response.json["success"] is False


def test_menu_management_requires_admin_and_validates_data(app, client):
    add_staff(app, "waiter-test", "waiter")
    add_staff(app, "chef-test", "chef")
    add_staff(app, "admin-test", "admin")
    waiter = login(client, "waiter-test")
    chef = login(client, "chef-test")
    admin = login(client, "admin-test")
    payload = {
        "category": "snacks",
        "name": "Test item",
        "description": "For automated tests",
        "weight": "100g",
        "price": "999",
        "image_url": "https://example.test/item.jpg",
    }
    assert client.post("/api/menu/add", json=payload, headers=auth(waiter)).status_code == 403
    assert client.post("/api/menu/add", json=payload, headers=auth(chef)).status_code == 403
    assert client.put(
        "/api/menu/edit/1", json=payload, headers=auth(waiter)
    ).status_code == 403
    assert client.delete("/api/menu/delete/1", headers=auth(chef)).status_code == 403
    assert client.post("/api/menu/add", json={**payload, "price": "-1"}, headers=auth(admin)).status_code == 400
    assert client.post("/api/menu/add", json={**payload, "category": "unknown"}, headers=auth(admin)).status_code == 400
    assert client.post("/api/menu/add", json=payload, headers=auth(admin)).json == {"success": True}

    new_item = next(item for item in client.get("/api/menu").json if item["name"] == "Test item")
    assert client.put(
        f"/api/menu/edit/{new_item['id']}",
        json={**payload, "name": "Updated item"},
        headers=auth(admin),
    ).json == {"success": True}
    assert client.delete(
        f"/api/menu/delete/{new_item['id']}", headers=auth(admin)
    ).json == {"success": True}


def test_authorization_uses_current_database_role(app, client):
    add_staff(app, "role-test", "waiter")
    token = login(client, "role-test")
    with app.app_context(), get_db_connection() as connection:
        connection.execute(
            "UPDATE staff SET role = 'chef' WHERE username = 'role-test'"
        )
    assert client.get("/api/orders/archive", headers=auth(token)).status_code == 403


def test_order_uses_database_prices_and_ignores_client_totals(app, client):
    add_staff(app, "waiter-test", "waiter")
    waiter = login(client, "waiter-test")
    response = client.post(
        "/api/orders",
        json={
            "table_number": "1",
            "items": [{"id": 1, "qty": 2, "name": "Forged name", "price": 1}],
            "total_price": 1,
        },
    )
    assert response.status_code == 200
    orders = client.get("/api/orders", headers=auth(waiter)).json
    assert len(orders) == 1
    assert orders[0]["total_price"] == 4620
    assert orders[0]["items"] == [
        {"id": 1, "name": "Сырники с ягодами", "price": 2100, "qty": 2}
    ]


@pytest.mark.parametrize(
    "payload",
    [
        {"table_number": "16", "items": [{"id": 1, "qty": 1}]},
        {"table_number": "1", "items": [{"id": -1, "qty": 1}]},
        {"table_number": "1", "items": [{"id": 1, "qty": 0}]},
        {"table_number": "1", "items": [{"id": 1, "qty": 100}]},
        {"table_number": "1", "items": [{"id": 99999, "qty": 1}]},
        {"table_number": "1", "items": []},
        {"table_number": "1", "items": [{"id": 1, "qty": True}]},
        {"table_number": "x", "items": [{"id": 1, "qty": 1}]},
    ],
)
def test_order_rejects_invalid_input(client, payload):
    assert client.post("/api/orders", json=payload).status_code == 400


def test_order_roles_and_valid_workflow(app, client):
    add_staff(app, "waiter-test", "waiter")
    add_staff(app, "chef-test", "chef")
    waiter = login(client, "waiter-test")
    chef = login(client, "chef-test")
    order_id = add_order(client)

    assert client.put(
        f"/api/orders/{order_id}", json={"status": "cooking"}, headers=auth(chef)
    ).status_code == 403
    assert client.put(
        f"/api/orders/{order_id}", json={"status": "ready"}, headers=auth(waiter)
    ).status_code == 403
    assert client.put(
        f"/api/orders/{order_id}", json={"status": ["ready"]}, headers=auth(waiter)
    ).status_code == 400
    assert client.put(
        f"/api/orders/{order_id}", json={"status": "cooking"}, headers=auth(waiter)
    ).json == {"success": True}
    assert client.put(
        f"/api/orders/{order_id}", json={"status": "ready"}, headers=auth(chef)
    ).json == {"success": True}
    assert client.put(
        f"/api/orders/{order_id}", json={"status": "completed"}, headers=auth(waiter)
    ).json == {"success": True}
    assert client.get("/api/orders", headers=auth(waiter)).json == []
    assert len(client.get("/api/orders/archive", headers=auth(waiter)).json) == 1
    assert client.get("/api/orders/archive", headers=auth(chef)).status_code == 403


def test_waiter_can_only_reject_pending_orders(app, client):
    add_staff(app, "waiter-test", "waiter")
    waiter = login(client, "waiter-test")
    order_id = add_order(client)
    assert client.delete(f"/api/orders/{order_id}", headers=auth(waiter)).status_code == 200

    order_id = add_order(client)
    assert client.put(
        f"/api/orders/{order_id}", json={"status": "cooking"}, headers=auth(waiter)
    ).status_code == 200
    assert client.delete(f"/api/orders/{order_id}", headers=auth(waiter)).status_code == 403


def test_cors_is_limited_and_security_headers_are_set(client):
    allowed = client.get("/api/menu", headers={"Origin": "https://chillibek.online"})
    denied = client.get("/api/menu", headers={"Origin": "https://attacker.example"})
    assert allowed.headers["Access-Control-Allow-Origin"] == "https://chillibek.online"
    assert "Access-Control-Allow-Origin" not in denied.headers
    assert allowed.headers["X-Content-Type-Options"] == "nosniff"
    assert allowed.headers["X-Frame-Options"] == "DENY"
    assert allowed.headers["Cache-Control"] == "no-store"


def test_login_rate_limit_is_enforced(client):
    responses = [
        client.post(
            "/api/staff/login",
            json={"username": "missing", "password": "wrong"},
        )
        for _ in range(6)
    ]
    assert [response.status_code for response in responses] == [401] * 5 + [429]


def test_cli_migrates_legacy_passwords_without_printing_values(app):
    with app.app_context(), get_db_connection() as connection:
        connection.execute(
            "INSERT INTO staff (username, password, role) VALUES (?, ?, ?)",
            ("legacy-user", "synthetic-legacy-password", "chef"),
        )
    result = app.test_cli_runner().invoke(args=["migrate-passwords"])
    assert result.exit_code == 0
    assert "Hashed 1 legacy password(s)." in result.output
    assert "synthetic-legacy-password" not in result.output
    with app.app_context(), get_db_connection() as connection:
        stored = connection.execute(
            "SELECT password FROM staff WHERE username = 'legacy-user'"
        ).fetchone()["password"]
    assert check_password_hash(stored, "synthetic-legacy-password")
