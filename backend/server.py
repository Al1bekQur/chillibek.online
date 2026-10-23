import hmac
import ipaddress
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from getpass import getpass
from pathlib import Path
from urllib.parse import urlsplit

import click
from dotenv import load_dotenv
from flask import Flask, abort, current_app, g, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.exc import IntegrityError

try:
    from . import login_guard
except ImportError:
    import login_guard

try:
    from .db import (
        create_db_engine,
        create_schema,
        database_url_from_path,
        seed_menu_if_empty,
        connection_scope,
    )
except ImportError:  # Supports `flask --app backend/server.py` and legacy test imports.
    from db import (
        create_db_engine,
        create_schema,
        database_url_from_path,
        seed_menu_if_empty,
        connection_scope,
    )


BASE_DIR = Path(__file__).resolve().parent
CATEGORIES = {"breakfasts", "salads", "soups", "main", "pizza", "snacks", "drinks"}
ROLES = {"admin", "waiter", "chef"}
ORDER_STATUSES = {"pending", "cooking", "ready", "completed"}
MENU_FIELDS = {"category", "name", "description", "weight", "price", "image_url"}
limiter = Limiter(key_func=get_remote_address, default_limits=[])

MENU_SEED = [
    ("breakfasts", "Сырники с ягодами", "Нежные сырники из фермерского творога со сметаной и свежими ягодами.", "220г", 2100, "https://images.unsplash.com/photo-1590137876181-2a5a7e340308?w=500&q=80"),
    ("breakfasts", "Английский завтрак", "Глазунья, бекон, фасоль, колбаски гриль, томаты, хрустящий тост.", "350г", 2800, "https://images.unsplash.com/photo-1533089860892-a7c6f0a88666?w=500&q=80"),
    ("salads", "Цезарь с курицей", "Хрустящий айсберг, сочная курица гриль, черри, перепелиные яйца, пармезан, соус цезарь.", "250г", 2600, "https://images.unsplash.com/photo-1550304943-4f24f54ddde9?w=500&q=80"),
    ("salads", "Греческий салат", "Свежие овощи, сыр фета, маслины, оливковое масло, орегано.", "220г", 2200, "https://images.unsplash.com/photo-1540189549336-e6e99c3679fe?w=500&q=80"),
    ("soups", "Рамен с курицей", "Пшеничная лапша, куриный бульон, яйцо нитамаго, нори.", "450г", 2450, "https://images.unsplash.com/photo-1569718212165-3a8278d5f624?w=500&q=80"),
    ("soups", "Том Ям с креветками", "Острый бульон, кокосовое молоко, тигровые креветки, рис.", "400г", 3200, "https://images.unsplash.com/photo-1548940740-2047263be975?w=500&q=80"),
    ("main", "Стейк Рибай", "Мраморная говядина зернового откорма, перечный соус.", "300г", 5800, "https://images.unsplash.com/photo-1544025162-d76694265947?w=500&q=80"),
    ("main", "Паста Карбонара", "Спагетти, бекон, сливки, желток, пармезан.", "350г", 2800, "https://images.unsplash.com/photo-1612874742237-6526221588e3?w=500&q=80"),
    ("pizza", "Маргарита", "Томатный соус, моцарелла, свежий базилик.", "400г", 2500, "https://images.unsplash.com/photo-1574071318508-1cdbab80d002?w=500&q=80"),
    ("pizza", "Пепперони", "Томатный соус, моцарелла, пикантная пепперони.", "450г", 2900, "https://images.unsplash.com/photo-1628840042765-356cda07504e?w=500&q=80"),
    ("snacks", "Хрустящие баклажаны", "Баклажаны во фритюре, томаты, сладкий чили.", "250г", 1900, "https://images.unsplash.com/photo-1592417817098-8f3d6eb19675?w=500&q=80"),
    ("snacks", "Сырные палочки", "Моцарелла в хрустящей панировке. Подается с ягодным соусом.", "180г", 1500, "https://images.unsplash.com/photo-1536510233921-8e5043fce771?w=500&q=80"),
    ("drinks", "Лимонад Маракуйя", "Пюре маракуйи, содовая, мята, лед.", "400мл", 1450, "https://images.unsplash.com/photo-1513558161293-cdaf765ed2fd?w=500&q=80"),
    ("drinks", "Матча-Латте", "Японская зеленая матча, нежное овсяное молоко, лед.", "350мл", 1600, "https://images.unsplash.com/photo-1536256263959-770b48d82b0a?w=500&q=80"),
]


@contextmanager
def get_db_connection():
    with connection_scope(current_app.config["DB_ENGINE"]) as connection:
        yield connection


def init_db():
    create_schema(current_app.config["DB_ENGINE"])
    seed_menu_if_empty(current_app.config["DB_ENGINE"], MENU_SEED)


def _token_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="staff-auth-v1")


def _json_object():
    data = request.get_json()
    if not isinstance(data, dict):
        abort(400, description="A JSON object is required.")
    return data


def _bounded_string(value, field, maximum, *, required=True):
    if not isinstance(value, str):
        abort(400, description=f"{field} must be text.")
    value = value.strip()
    if required and not value:
        abort(400, description=f"{field} is required.")
    if len(value) > maximum or any(ord(char) < 32 for char in value):
        abort(400, description=f"{field} is invalid.")
    return value


def _integer(value, field, minimum, maximum):
    if isinstance(value, bool):
        abort(400, description=f"{field} must be an integer.")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        number = int(value)
    else:
        abort(400, description=f"{field} must be an integer.")
    if not minimum <= number <= maximum:
        abort(400, description=f"{field} is outside the allowed range.")
    return number


def _menu_payload(data):
    if set(data) != MENU_FIELDS:
        abort(400, description="All menu fields are required.")
    category = _bounded_string(data["category"], "category", 32)
    if category not in CATEGORIES:
        abort(400, description="Unknown menu category.")

    image_url = _bounded_string(data["image_url"], "image_url", 2048)
    try:
        parsed_url = urlsplit(image_url)
    except ValueError:
        abort(400, description="image_url must be a valid HTTP or HTTPS URL.")
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname or parsed_url.username or parsed_url.password or '\\' in image_url:
        abort(400, description="image_url must be an HTTP or HTTPS URL.")
    # The application stores this URL for browser images; it NEVER fetches it.
    # Reject literal local destinations/credentials, without adding a DNS fetch.
    if parsed_url.hostname.lower() in {'localhost', 'metadata.google.internal'} or parsed_url.hostname.lower().endswith(('.localhost', '.local', '.internal')):
        abort(400, description='Local image destinations are not allowed.')
    try:
        address = ipaddress.ip_address(parsed_url.hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        abort(400, description='Local image destinations are not allowed.')

    return (
        category,
        _bounded_string(data["name"], "name", 120),
        _bounded_string(data["description"], "description", 1000),
        _bounded_string(data["weight"], "weight", 50),
        _integer(data["price"], "price", 1, 1_000_000),
        image_url,
    )


def require_roles(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            authorization = request.headers.get("Authorization", "")
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() != "bearer" or not token:
                abort(401, description="Authentication required.")
            try:
                payload = _token_serializer().loads(
                    token, max_age=current_app.config["TOKEN_MAX_AGE"]
                )
            except BadSignature:
                abort(401, description="Authentication required.")

            staff_id = payload.get("staff_id") if isinstance(payload, dict) else None
            if not isinstance(staff_id, int) or isinstance(staff_id, bool):
                abort(401, description="Authentication required.")
            with get_db_connection() as connection:
                user = connection.execute(
                    "SELECT id, username, role FROM staff WHERE id = ?", (staff_id,)
                ).fetchone()
            if user is None or user["role"] not in ROLES:
                abort(401, description="Authentication required.")
            if user["role"] not in allowed_roles:
                abort(403, description="Insufficient permissions.")
            g.staff = dict(user)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def create_app(test_config=None):
    load_dotenv(BASE_DIR / ".env")
    secret_key = os.getenv("FLASK_SECRET_KEY")
    database_url = os.getenv("DATABASE_URL")
    database_path = os.getenv("DATABASE_PATH", "instance/chillibek.sqlite3")

    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=secret_key,
        DATABASE_URL=database_url,
        DATABASE_PATH=database_path,
        TOKEN_MAX_AGE=8 * 60 * 60,
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,
        RATELIMIT_STORAGE_URI=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
        CORS_ALLOWED_ORIGINS=os.getenv("CORS_ALLOWED_ORIGINS", ""),
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["DATABASE_URL"]:
        configured_path = app.config["DATABASE_PATH"]
        if not Path(configured_path).is_absolute():
            configured_path = str(BASE_DIR / configured_path)
        app.config["DATABASE_PATH"] = configured_path
        app.config["DATABASE_URL"] = database_url_from_path(configured_path)
    app.config["DB_ENGINE"] = create_db_engine(app.config["DATABASE_URL"])
    if not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("Set FLASK_SECRET_KEY to a random value of at least 32 characters.")

    origins = app.config["CORS_ALLOWED_ORIGINS"]
    if isinstance(origins, str):
        origins = [origin.strip() for origin in origins.split(",") if origin.strip()]
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": origins,
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
                "max_age": 600,
            }
        },
    )
    limiter.init_app(app)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(409)
    @app.errorhandler(413)
    @app.errorhandler(415)
    @app.errorhandler(429)
    def handle_client_error(error):
        return jsonify({"success": False, "message": error.description}), error.code

    @app.errorhandler(500)
    def handle_server_error(_error):
        return jsonify({"success": False, "message": "Internal server error."}), 500

    @app.get("/api/menu")
    @limiter.limit("120 per minute")
    def get_menu():
        with get_db_connection() as connection:
            items = connection.execute("SELECT * FROM menu_items ORDER BY id").fetchall()
        return jsonify([dict(item) for item in items])

    @app.post("/api/staff/login")
    @limiter.limit("5 per minute")
    def staff_login():
        data = _json_object()
        if set(data) != {"username", "password"}:
            abort(400, description="Only username and password are accepted.")
        username = _bounded_string(data.get("username"), "username", 80).lower()
        password = data.get("password")
        if not isinstance(password, str) or not password or len(password) > 256:
            abort(400, description="A valid password is required.")
        identities = login_guard.keys(request.remote_addr or 'unknown', username)
        retry = login_guard.admit(app.config['DB_ENGINE'], identities)
        if retry:
            app.logger.warning('security_event=LOGIN_LIMIT rule_id=AUTH-001')
            return jsonify({'success': False, 'message': 'Too many login attempts.'}), 429, {'Retry-After': str(retry)}

        with get_db_connection() as connection:
            user = connection.execute(
                "SELECT id, password, role FROM staff WHERE LOWER(username) = ?",
                (username,),
            ).fetchone()
            if user is None or user["role"] not in ROLES:
                app.logger.warning('security_event=LOGIN_FAILURE rule_id=AUTH-FAIL-001')
                abort(401, description="Invalid username or password.")

            stored_password = user["password"]
            if stored_password.startswith(("scrypt:", "pbkdf2:")):
                try:
                    password_valid = check_password_hash(stored_password, password)
                except (TypeError, ValueError):
                    password_valid = False
            else:
                password_valid = hmac.compare_digest(
                    stored_password.encode("utf-8"), password.encode("utf-8")
                )
                if password_valid:
                    connection.execute(
                        "UPDATE staff SET password = ? WHERE id = ?",
                        (generate_password_hash(password), user["id"]),
                    )
            if not password_valid:
                app.logger.warning('security_event=LOGIN_FAILURE rule_id=AUTH-FAIL-001')
                abort(401, description="Invalid username or password.")

        login_guard.success(app.config['DB_ENGINE'], identities)
        token = _token_serializer().dumps({"staff_id": user["id"]})
        return jsonify({"success": True, "role": user["role"], "token": token})

    @app.post("/api/menu/add")
    @limiter.limit("30 per minute")
    @require_roles("admin")
    def add_menu_item():
        values = _menu_payload(_json_object())
        with get_db_connection() as connection:
            connection.execute(
                """
                INSERT INTO menu_items
                    (category, name, description, weight, price, image_url)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        return jsonify({"success": True})

    @app.put("/api/menu/edit/<int:item_id>")
    @limiter.limit("30 per minute")
    @require_roles("admin")
    def edit_menu_item(item_id):
        values = _menu_payload(_json_object())
        with get_db_connection() as connection:
            cursor = connection.execute(
                """
                UPDATE menu_items
                SET category = ?, name = ?, description = ?, weight = ?, price = ?, image_url = ?
                WHERE id = ?
                """,
                (*values, item_id),
            )
            if cursor.rowcount == 0:
                abort(404, description="Menu item not found.")
        return jsonify({"success": True})

    @app.delete("/api/menu/delete/<int:item_id>")
    @limiter.limit("30 per minute")
    @require_roles("admin")
    def delete_menu_item(item_id):
        with get_db_connection() as connection:
            cursor = connection.execute("DELETE FROM menu_items WHERE id = ?", (item_id,))
            if cursor.rowcount == 0:
                abort(404, description="Menu item not found.")
        return jsonify({"success": True})

    @app.post("/api/orders")
    @limiter.limit("20 per minute")
    def create_order():
        data = _json_object()
        if not {"table_number", "items"}.issubset(data) or not set(data).issubset(
            {"table_number", "items", "total_price"}
        ):
            abort(400, description="Only table_number, items, and total_price are accepted.")
        if "total_price" in data:
            _integer(data["total_price"], "total_price", 0, 5_500_000_000)
        table_number = _bounded_string(data.get("table_number"), "table_number", 2)
        if not table_number.isdigit() or not 1 <= int(table_number) <= 15:
            abort(400, description="table_number must be between 1 and 15.")
        items = data.get("items")
        if not isinstance(items, list) or not 1 <= len(items) <= 50:
            abort(400, description="Order must contain between 1 and 50 items.")

        quantities = {}
        for item in items:
            if not isinstance(item, dict):
                abort(400, description="Each order item must be an object.")
            if not {"id", "qty"}.issubset(item) or not set(item).issubset(
                {"id", "qty", "name", "price"}
            ):
                abort(400, description="Order items contain unsupported fields.")
            if "name" in item:
                _bounded_string(item["name"], "item name", 120)
            if "price" in item:
                _integer(item["price"], "item price", 1, 1_000_000)
            item_id = _integer(item.get("id"), "item id", 1, 2_147_483_647)
            quantity = _integer(item.get("qty"), "quantity", 1, 99)
            if item_id in quantities:
                abort(400, description="Duplicate menu item IDs are not allowed.")
            quantities[item_id] = quantity

        with get_db_connection() as connection:
            menu_ids = tuple(quantities)
            placeholders = ",".join("?" for _ in menu_ids)
            menu_items = connection.execute(
                f"SELECT id, name, price FROM menu_items WHERE id IN ({placeholders})",
                menu_ids,
            ).fetchall()
            menu_by_id = {row["id"]: row for row in menu_items}
            if len(menu_by_id) != len(quantities):
                abort(400, description="Order contains an unknown menu item.")

            order_items = []
            subtotal = 0
            for item_id, quantity in quantities.items():
                menu_item = menu_by_id[item_id]
                price = _integer(menu_item["price"], "menu price", 1, 1_000_000)
                subtotal += price * quantity
                order_items.append(
                    {
                        "id": item_id,
                        "name": menu_item["name"],
                        "price": price,
                        "qty": quantity,
                    }
                )
            total_price = subtotal + (subtotal * 10 + 50) // 100
            created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            connection.execute(
                """
                INSERT INTO orders (table_number, items_json, total_price, status, created_at)
                VALUES (?, ?, ?, 'pending', ?)
                """,
                (table_number, json.dumps(order_items, ensure_ascii=False), total_price, created_at),
            )
        return jsonify({"success": True})

    def _fetch_orders(query):
        with get_db_connection() as connection:
            rows = connection.execute(query).fetchall()
        orders = []
        for row in rows:
            order = dict(row)
            order["items"] = json.loads(order.pop("items_json"))
            orders.append(order)
        return orders

    @app.get("/api/orders")
    @limiter.limit("120 per minute")
    @require_roles("admin", "waiter", "chef")
    def get_orders():
        return jsonify(
            _fetch_orders("SELECT * FROM orders WHERE status != 'completed' ORDER BY id ASC")
        )

    @app.get("/api/orders/archive")
    @limiter.limit("60 per minute")
    @require_roles("admin", "waiter")
    def get_archive():
        return jsonify(
            _fetch_orders("SELECT * FROM orders WHERE status = 'completed' ORDER BY id DESC")
        )

    @app.put("/api/orders/<int:order_id>")
    @limiter.limit("30 per minute")
    @require_roles("admin", "waiter", "chef")
    def update_order_status(order_id):
        data = _json_object()
        if set(data) != {"status"}:
            abort(400, description="Only status may be updated.")
        status = data.get("status")
        if not isinstance(status, str) or status not in ORDER_STATUSES:
            abort(400, description="Invalid order status.")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with get_db_connection() as connection:
            order = connection.execute(
                "SELECT status FROM orders WHERE id = ?", (order_id,)
            ).fetchone()
            if order is None:
                abort(404, description="Order not found.")

            old_status = order["status"]
            allowed_transitions = {
                "waiter": {("pending", "cooking"), ("ready", "completed")},
                "chef": {("cooking", "ready")},
                "admin": {
                    ("pending", "cooking"),
                    ("cooking", "ready"),
                    ("ready", "completed"),
                },
            }
            if (old_status, status) not in allowed_transitions[g.staff["role"]]:
                abort(403, description="This role cannot perform that order transition.")

            if status == "cooking":
                cursor = connection.execute(
                    "UPDATE orders SET status = ?, approved_at = ? WHERE id = ? AND status = ?",
                    (status, now, order_id, old_status),
                )
            elif status == "ready":
                cursor = connection.execute(
                    "UPDATE orders SET status = ?, ready_at = ? WHERE id = ? AND status = ?",
                    (status, now, order_id, old_status),
                )
            else:
                cursor = connection.execute(
                    "UPDATE orders SET status = ? WHERE id = ? AND status = ?", (status, order_id, old_status)
                )
            if cursor.rowcount != 1:
                abort(409, description='Order changed; refresh and retry.')
        return jsonify({"success": True})

    @app.delete("/api/orders/<int:order_id>")
    @limiter.limit("20 per minute")
    @require_roles("admin", "waiter")
    def delete_order(order_id):
        with get_db_connection() as connection:
            order = connection.execute(
                "SELECT status FROM orders WHERE id = ?", (order_id,)
            ).fetchone()
            if order is None:
                abort(404, description="Order not found.")
            if g.staff["role"] == "waiter" and order["status"] != "pending":
                abort(403, description="Waiters may only reject pending orders.")
            cursor = connection.execute("DELETE FROM orders WHERE id = ? AND status = ?", (order_id, order['status']))
            if cursor.rowcount != 1:
                abort(409, description='Order changed; refresh and retry.')
        return jsonify({"success": True})

    @app.cli.command("create-admin")
    @click.argument("username")
    def create_admin(username):
        username = username.strip().lower()
        if not re.fullmatch(r"[a-z0-9_.-]{3,80}", username):
            raise click.ClickException("Username must be 3-80 characters: letters, digits, . _ or -.")
        password = getpass("New admin password (12+ characters): ")
        confirmation = getpass("Confirm password: ")
        if len(password) < 12 or password != confirmation:
            raise click.ClickException("Password must be 12+ characters and match confirmation.")
        with get_db_connection() as connection:
            try:
                connection.execute(
                    "INSERT INTO staff (username, password, role) VALUES (?, ?, 'admin')",
                    (username, generate_password_hash(password)),
                )
            except IntegrityError as error:
                raise click.ClickException("That username already exists.") from error
        click.echo("Admin account created.")

    @app.cli.command("create-staff")
    @click.argument("username")
    @click.argument("role", type=click.Choice(["waiter", "chef"]))
    def create_staff(username, role):
        username = username.strip().lower()
        if not re.fullmatch(r"[a-z0-9_.-]{3,80}", username):
            raise click.ClickException("Username must be 3-80 characters: letters, digits, . _ or -.")
        password = getpass("New staff password (12+ characters): ")
        confirmation = getpass("Confirm password: ")
        if len(password) < 12 or password != confirmation:
            raise click.ClickException("Password must be 12+ characters and match confirmation.")
        with get_db_connection() as connection:
            try:
                connection.execute(
                    "INSERT INTO staff (username, password, role) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), role),
                )
            except IntegrityError as error:
                raise click.ClickException("That username already exists.") from error
        click.echo("Staff account created.")

    @app.cli.command("migrate-passwords")
    def migrate_passwords():
        migrated = 0
        with get_db_connection() as connection:
            users = connection.execute("SELECT id, password FROM staff").fetchall()
            for user in users:
                if not user["password"].startswith(("scrypt:", "pbkdf2:")):
                    connection.execute(
                        "UPDATE staff SET password = ? WHERE id = ?",
                        (generate_password_hash(user["password"]), user["id"]),
                    )
                    migrated += 1
        click.echo(f"Hashed {migrated} legacy password(s). No password values were displayed.")

    with app.app_context():
        init_db()
    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_RUN_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_RUN_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
    )
