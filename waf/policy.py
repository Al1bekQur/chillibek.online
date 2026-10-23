"""Durable live policy, audit trail, sliding counters and cross-worker admission."""
import hashlib
import json
import sqlite3
import time
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    mode: Literal["block", "monitor"] = "block"
    sql_injection: StrictBool = True
    xss: StrictBool = True
    path_traversal: StrictBool = True
    rate_limiting: StrictBool = True
    suspicious_headers: StrictBool = True
    request_size: StrictBool = True
    event_logging: StrictBool = True
    command_injection: StrictBool = True
    brute_force: StrictBool = True
    bot_detection: StrictBool = True


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: StrictInt = Field(ge=0)
    policy: Policy

    @field_validator("policy", mode="before")
    @classmethod
    def complete_policy(cls, value):
        if not isinstance(value, dict) or set(value) != set(Policy.model_fields):
            raise ValueError("A complete policy with all supported fields is required.")
        return value


class ResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: StrictInt = Field(ge=0)


class RevisionConflict(Exception):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


class PolicyStore:
    def __init__(self, path: Path):
        self.path = path
        self._schema_lock = threading.Lock()
        self._initialized = False

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA synchronous=FULL")
            with self._schema_lock:
                if not self._initialized:
                    self._initialize(connection)
                    self._initialized = True
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self, connection):
        existed = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='policy'").fetchone() is not None
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS policy (
                id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL,
                revision INTEGER NOT NULL, updated_at TEXT, updated_by TEXT
            );
            CREATE TABLE IF NOT EXISTS configuration_audit (
                id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL,
                actor TEXT, action TEXT NOT NULL, details TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rate_windows (
                scope TEXT NOT NULL, client TEXT NOT NULL, bucket INTEGER NOT NULL,
                count INTEGER NOT NULL, PRIMARY KEY(scope, client)
            );
            CREATE TABLE IF NOT EXISTS traffic_events (
                scope TEXT NOT NULL, client TEXT NOT NULL, timestamp REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS traffic_lookup ON traffic_events(scope, client, timestamp);
            CREATE TABLE IF NOT EXISTS leases (
                token TEXT PRIMARY KEY, client TEXT NOT NULL, expires REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS failures (
                client TEXT PRIMARY KEY, count INTEGER NOT NULL, level INTEGER NOT NULL,
                expires REAL NOT NULL, locked_until REAL NOT NULL
            );
        """)
        if not existed:
            connection.execute('INSERT OR IGNORE INTO policy VALUES (1, ?, 0, NULL, NULL)', (Policy().model_dump_json(),))
        connection.commit()
        # Upgrade only the complete, validated previous schema. Partial or
        # corrupted policies must never be interpreted as an old version.
        row = connection.execute('SELECT value FROM policy WHERE id=1').fetchone()
        if row is None:
            raise sqlite3.DatabaseError('Stored WAF policy is missing.')
        raw = row[0]
        try:
            legacy = json.loads(raw)
            old_keys = set(Policy.model_fields) - {'command_injection', 'brute_force', 'bot_detection'}
            if isinstance(legacy, dict) and set(legacy) == old_keys:
                upgraded = Policy.model_validate(legacy)
                connection.execute('BEGIN IMMEDIATE')
                # Another worker may already have upgraded the row.
                changed = connection.execute('UPDATE policy SET value=?, revision=revision+1, updated_at=?, updated_by=? WHERE id=1 AND value=?',
                    (upgraded.model_dump_json(), now(), 'schema-migration', raw)).rowcount
                if changed:
                    self._audit(connection, 'schema-migration', 'schema_upgrade', {'added': ['command_injection', 'brute_force', 'bot_detection']})
                connection.commit()
        except ValueError:
            pass  # _snapshot rejects invalid storage without modifying it.

    def _snapshot(self, connection):
        row = connection.execute("SELECT * FROM policy WHERE id=1").fetchone()
        if row is None:
            raise sqlite3.DatabaseError('Stored WAF policy is missing.')
        # Never silently enable defaults when durable configuration is corrupted.
        try:
            stored = json.loads(row["value"])
            if not isinstance(stored, dict) or set(stored) != set(Policy.model_fields):
                raise ValueError("Stored policy is incomplete.")
            policy = Policy.model_validate(stored).model_dump()
        except ValueError:
            raise sqlite3.DatabaseError("Stored WAF policy is invalid.") from None
        return {
            "policy": policy,
            "revision": row["revision"], "updated_at": row["updated_at"],
            "updated_by": row["updated_by"],
        }

    def read(self):
        with self.connect() as connection:
            return self._snapshot(connection)

    def update(self, policy: Policy, revision: int, actor: str, action="update"):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            before = self._snapshot(connection)
            if before["revision"] != revision:
                raise RevisionConflict()
            connection.execute(
                "UPDATE policy SET value=?, revision=revision+1, updated_at=?, updated_by=? WHERE id=1",
                (policy.model_dump_json(), now(), actor),
            )
            after = self._snapshot(connection)
            self._audit(connection, actor, action, {"before": before, "after": after})
            return after

    def _audit(self, connection, actor, action, details):
        connection.execute(
            "INSERT INTO configuration_audit(timestamp, actor, action, details) VALUES (?, ?, ?, ?)",
            (now(), actor, action, json.dumps(details)),
        )

    def audit(self, actor, action, details):
        with self.connect() as connection:
            self._audit(connection, actor, action, details)

    def over_limit(self, scope, client, limit, window):
        current = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute('DELETE FROM traffic_events WHERE timestamp<=?', (current - max(3600, window),))
            count = connection.execute('SELECT COUNT(*) FROM traffic_events WHERE scope=? AND client=? AND timestamp>?',
                (scope, client, current - window)).fetchone()[0]
            if count >= limit:
                return True
            connection.execute('INSERT INTO traffic_events VALUES (?, ?, ?)', (scope, client, current))
            return False

    def acquire(self, token, client, total, per_client, ttl):
        current = time.time()
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            connection.execute('DELETE FROM leases WHERE expires<=?', (current,))
            rows = connection.execute('SELECT client FROM leases WHERE token LIKE ?', (token.split(':', 1)[0] + ':%',)).fetchall()
            if len(rows) >= total or sum(row[0] == client for row in rows) >= per_client:
                return False
            connection.execute('INSERT INTO leases VALUES (?, ?, ?)', (token, client, current + ttl))
            return True

    def release(self, token):
        with self.connect() as connection:
            connection.execute('DELETE FROM leases WHERE token=?', (token,))

    def probe_blocked(self, client, limit):
        with self.connect() as connection:
            return connection.execute('SELECT COUNT(*) FROM traffic_events WHERE scope=? AND client=? AND timestamp>?',
                ('probes', client, time.time() - 60)).fetchone()[0] >= limit

    @staticmethod
    def identity(value):
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def login_keys(self, ip, account):
        return [self.identity('ip:' + ip), self.identity('account:' + account.casefold().strip())]

    def login_locked(self, keys):
        with self.connect() as connection:
            return any(connection.execute('SELECT 1 FROM failures WHERE client=? AND locked_until>?',
                (key, time.time())).fetchone() for key in keys)

    def login_result(self, keys, failed):
        current = time.time()
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            connection.execute('DELETE FROM failures WHERE expires<=?', (current,))
            for key in keys:
                if not failed:
                    # Keep the IP history when other accounts are being attacked.
                    if key == keys[-1]:
                        connection.execute('DELETE FROM failures WHERE client=?', (key,))
                    continue
                row = connection.execute('SELECT * FROM failures WHERE client=?', (key,)).fetchone()
                count = (row['count'] if row else 0) + 1
                level = row['level'] if row else 0
                locked = row['locked_until'] if row else 0
                if count >= 5:
                    locked = current + min(900, 30 * 2 ** min(level, 5))
                    level += 1
                    count = 0
                connection.execute('INSERT OR REPLACE INTO failures VALUES (?, ?, ?, ?, ?)',
                    (key, count, level, current + 1800, locked))
