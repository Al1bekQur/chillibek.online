"""Mandatory atomic login admission, independent of WAF toggles (SQLite/Postgres)."""
import hashlib
import time

from sqlalchemy import case, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

try:
    from .db import login_attempts as table
except ImportError:
    from db import login_attempts as table


def keys(ip, username):
    return [hashlib.sha256(value.encode('utf-8')).hexdigest()
            for value in ('ip:' + ip, 'account:' + username.strip().casefold())]


def admit(engine, identities):
    now = time.time()
    retry = 0
    with engine.begin() as connection:
        connection.execute(delete(table).where(table.c.reset_at < now - 1800))
        for identity in identities:
            insert = sqlite_insert if engine.dialect.name == 'sqlite' else pg_insert
            statement = insert(table).values(identity=identity, attempts=1, level=0, reset_at=now + 900, locked_until=0)
            expired = table.c.reset_at <= now
            statement = statement.on_conflict_do_update(index_elements=[table.c.identity], set_={
                'attempts': case((expired, 1), (table.c.locked_until > now, table.c.attempts), else_=table.c.attempts + 1),
                'level': case((expired, 0), else_=table.c.level),
                'reset_at': case((expired, now + 900), else_=table.c.reset_at),
                'locked_until': case((expired, 0), else_=table.c.locked_until),
            })
            connection.execute(statement)
            row = connection.execute(select(table).where(table.c.identity == identity)).mappings().one()
            if row['locked_until'] > now:
                retry = max(retry, int(row['locked_until'] - now) + 1)
            elif row['attempts'] > 5:
                seconds = min(900, 30 * 2 ** min(row['level'], 5))
                connection.execute(update(table).where(table.c.identity == identity).values(
                    attempts=0, level=row['level'] + 1, locked_until=now + seconds))
                retry = max(retry, seconds)
    return retry


def success(engine, identities):
    with engine.begin() as connection:
        connection.execute(delete(table).where(table.c.identity == identities[-1]))
