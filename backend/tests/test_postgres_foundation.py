import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from server import create_app, get_db_connection


def test_backend_accepts_sqlalchemy_database_url(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-secret-key-never-use-outside-tests",
            "DATABASE_URL": f"sqlite:///{(tmp_path / 'url-db.sqlite3').as_posix()}",
            "CORS_ALLOWED_ORIGINS": ["https://chillibek.online"],
            "RATELIMIT_STORAGE_URI": "memory://",
        }
    )
    with app.app_context(), get_db_connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM menu_items").fetchone()[0] == 14


def make_sqlite_source(path: Path, password: str):
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE menu_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            weight TEXT,
            price INTEGER NOT NULL,
            image_url TEXT
        );
        CREATE TABLE staff (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_number TEXT,
            items_json TEXT NOT NULL,
            total_price INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            approved_at TEXT,
            ready_at TEXT
        );
        """
    )
    connection.execute(
        "INSERT INTO menu_items (category, name, description, weight, price, image_url) VALUES (?, ?, ?, ?, ?, ?)",
        ("snacks", "Synthetic", "Synthetic", "100g", 1000, "https://example.test/item.jpg"),
    )
    connection.execute(
        "INSERT INTO staff (username, password, role) VALUES (?, ?, ?)",
        ("synthetic-admin", password, "admin"),
    )
    connection.commit()
    connection.close()


def test_import_tool_refuses_legacy_plaintext_staff_passwords(tmp_path):
    source = tmp_path / "legacy.sqlite3"
    target = tmp_path / "target.sqlite3"
    make_sqlite_source(source, "plaintext-password")
    result = subprocess.run(
        [
            sys.executable,
            "backend/tools/import_sqlite_to_postgres.py",
            "--sqlite-path",
            str(source),
            "--postgres-url",
            f"sqlite:///{target.as_posix()}",
        ],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Refusing to import legacy plaintext staff passwords" in result.stderr
    assert "plaintext-password" not in result.stderr


def test_import_tool_allows_hashed_or_reset_staff_data(tmp_path):
    source = tmp_path / "hashed.sqlite3"
    target = tmp_path / "target.sqlite3"
    make_sqlite_source(source, generate_password_hash("synthetic-password"))
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-secret-key-never-use-outside-tests",
            "DATABASE_URL": f"sqlite:///{target.as_posix()}",
            "RATELIMIT_STORAGE_URI": "memory://",
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            "backend/tools/import_sqlite_to_postgres.py",
            "--sqlite-path",
            str(source),
            "--postgres-url",
            f"sqlite:///{target.as_posix()}",
        ],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Import complete." in result.stdout
    assert "synthetic-password" not in result.stdout
