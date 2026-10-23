import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import (
    CheckConstraint,
    Column,
    Integer,
    Float,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    func,
    select,
    text,
)
from sqlalchemy.engine import Connection, Engine


metadata = MetaData()

login_attempts = Table(
    'login_attempts', metadata,
    Column('identity', String(64), primary_key=True),
    Column('attempts', Integer, nullable=False),
    Column('level', Integer, nullable=False),
    Column('reset_at', Float, nullable=False),
    Column('locked_until', Float, nullable=False),
)

menu_items = Table(
    "menu_items",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("category", String(32), nullable=False),
    Column("name", String(120), nullable=False),
    Column("description", Text),
    Column("weight", String(50)),
    Column("price", Integer, nullable=False),
    Column("image_url", Text),
    CheckConstraint("price > 0", name="ck_menu_items_price_positive"),
)

staff = Table(
    "staff",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(80), nullable=False, unique=True),
    Column("password", Text, nullable=False),
    Column("role", String(20), nullable=False),
    CheckConstraint("role IN ('admin', 'waiter', 'chef')", name="ck_staff_role"),
)

orders = Table(
    "orders",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("table_number", String(2)),
    Column("items_json", Text, nullable=False),
    Column("total_price", Integer, nullable=False),
    Column("status", String(20), nullable=False, server_default="pending"),
    Column("created_at", String(32)),
    Column("approved_at", String(32)),
    Column("ready_at", String(32)),
    CheckConstraint(
        "status IN ('pending', 'cooking', 'ready', 'completed')",
        name="ck_orders_status",
    ),
    CheckConstraint("total_price >= 0", name="ck_orders_total_price_nonnegative"),
)


def database_url_from_path(database_path: str | Path) -> str:
    path = Path(database_path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path.as_posix()}"


def create_db_engine(database_url: str) -> Engine:
    kwargs: dict[str, Any] = {"future": True, "pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(database_url, **kwargs)


def create_schema(engine: Engine) -> None:
    metadata.create_all(engine)


def seed_menu_if_empty(engine: Engine, menu_seed: Iterable[tuple[Any, ...]]) -> None:
    with engine.begin() as connection:
        count = connection.execute(select(func.count()).select_from(menu_items)).scalar_one()
        if count == 0:
            connection.execute(
                menu_items.insert(),
                [
                    {
                        "category": row[0],
                        "name": row[1],
                        "description": row[2],
                        "weight": row[3],
                        "price": row[4],
                        "image_url": row[5],
                    }
                    for row in menu_seed
                ],
            )


@contextmanager
def connection_scope(engine: Engine):
    with engine.begin() as connection:
        yield DatabaseConnection(connection)


class DatabaseConnection:
    def __init__(self, connection: Connection):
        self.connection = connection

    def execute(self, statement: str, parameters: Any = None):
        sql, params = _prepare_statement(statement, parameters)
        result = self.connection.execute(text(sql), params)
        return ResultWrapper(result)

    def executemany(self, statement: str, parameters: list[tuple[Any, ...]]):
        sql, named_rows = _prepare_many(statement, parameters)
        return ResultWrapper(self.connection.execute(text(sql), named_rows))

    def executescript(self, script: str):
        result = None
        for statement in script.split(";"):
            statement = statement.strip()
            if statement:
                result = self.execute(statement)
        return result


class ResultWrapper:
    def __init__(self, result):
        self.result = result
        self.rowcount = result.rowcount

    def fetchone(self):
        row = self.result.fetchone()
        return RowWrapper(row) if row is not None else None

    def fetchall(self):
        return [RowWrapper(row) for row in self.result.fetchall()]


class RowWrapper:
    def __init__(self, row):
        self.row = row
        self.mapping = row._mapping
        self.values = list(self.mapping.values())

    def __getitem__(self, key):
        if isinstance(key, int):
            return self.values[key]
        return self.mapping[key]

    def __iter__(self):
        return iter(self.mapping)

    def keys(self):
        return self.mapping.keys()


def _prepare_statement(statement: str, parameters: Any = None) -> tuple[str, dict[str, Any]]:
    if parameters is None:
        return statement, {}
    if isinstance(parameters, dict):
        return statement, parameters
    if not isinstance(parameters, (tuple, list)):
        parameters = (parameters,)
    return _replace_qmarks(statement, parameters)


def _prepare_many(statement: str, rows: list[tuple[Any, ...]]):
    if not rows:
        return statement, []
    sql, _ = _replace_qmarks(statement, rows[0])
    named_rows = []
    for row in rows:
        _, params = _replace_qmarks(statement, row)
        named_rows.append(params)
    return sql, named_rows


def _replace_qmarks(statement: str, parameters: tuple[Any, ...] | list[Any]):
    params = {f"p{index}": value for index, value in enumerate(parameters)}
    index = 0

    def replace(_match):
        nonlocal index
        name = f":p{index}"
        index += 1
        return name

    sql = re.sub(r"\?", replace, statement)
    return sql, params
