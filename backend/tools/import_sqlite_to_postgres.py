import argparse
import sqlite3
import sys
from pathlib import Path

from sqlalchemy import create_engine, text

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from backend.db import create_schema


HASH_PREFIXES = ("scrypt:", "pbkdf2:")


def main():
    parser = argparse.ArgumentParser(
        description="Import authorized Chillibek SQLite data into PostgreSQL without printing records."
    )
    parser.add_argument("--sqlite-path", required=True, help="Authorized local SQLite export path.")
    parser.add_argument("--postgres-url", required=True, help="Target PostgreSQL SQLAlchemy URL.")
    parser.add_argument(
        "--reset-staff",
        action="store_true",
        help="Skip staff password import so accounts can be recreated/reset safely.",
    )
    args = parser.parse_args()

    sqlite_path = Path(args.sqlite_path)
    if not sqlite_path.exists():
        raise SystemExit("SQLite source file does not exist.")

    source = sqlite3.connect(sqlite_path)
    source.row_factory = sqlite3.Row
    target = create_engine(args.postgres_url, future=True, pool_pre_ping=True)
    create_schema(target)

    staff_rows = source.execute("SELECT id, username, password, role FROM staff").fetchall()
    if not args.reset_staff:
        legacy = [row for row in staff_rows if not str(row["password"]).startswith(HASH_PREFIXES)]
        if legacy:
            raise SystemExit(
                "Refusing to import legacy plaintext staff passwords. "
                "Run a credential reset or use --reset-staff and recreate accounts."
            )

    with target.begin() as connection:
        for table in ("orders", "staff", "menu_items"):
            connection.execute(text(f"DELETE FROM {table}"))

        menu_rows = source.execute(
            "SELECT id, category, name, description, weight, price, image_url FROM menu_items"
        ).fetchall()
        for row in menu_rows:
            connection.execute(
                text(
                    """
                    INSERT INTO menu_items
                        (id, category, name, description, weight, price, image_url)
                    VALUES
                        (:id, :category, :name, :description, :weight, :price, :image_url)
                    """
                ),
                dict(row),
            )

        if not args.reset_staff:
            for row in staff_rows:
                connection.execute(
                    text(
                        """
                        INSERT INTO staff (id, username, password, role)
                        VALUES (:id, :username, :password, :role)
                        """
                    ),
                    dict(row),
                )

        order_rows = source.execute(
            """
            SELECT id, table_number, items_json, total_price, status, created_at, approved_at, ready_at
            FROM orders
            """
        ).fetchall()
        for row in order_rows:
            connection.execute(
                text(
                    """
                    INSERT INTO orders
                        (id, table_number, items_json, total_price, status, created_at, approved_at, ready_at)
                    VALUES
                        (:id, :table_number, :items_json, :total_price, :status, :created_at, :approved_at, :ready_at)
                    """
                ),
                dict(row),
            )

        if target.dialect.name == "postgresql":
            for table in ("menu_items", "staff", "orders"):
                connection.execute(
                    text(
                        """
                        SELECT setval(
                            pg_get_serial_sequence(:table_name, 'id'),
                            COALESCE((SELECT MAX(id) FROM %(table)s), 1),
                            true
                        )
                        """
                        % {"table": table}
                    ),
                    {"table_name": table},
                )

    print(
        "Import complete. Records were not printed. "
        "If --reset-staff was used, recreate staff accounts with rotated credentials."
    )


if __name__ == "__main__":
    main()
