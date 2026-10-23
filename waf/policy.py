"""Durable live policy, mandatory audit trail and shared fixed-window counters."""
import json
import sqlite3
import time
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

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA synchronous=FULL")
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
            """)
            connection.execute(
                "INSERT OR IGNORE INTO policy VALUES (1, ?, 0, NULL, NULL)",
                (Policy().model_dump_json(),),
            )
            connection.commit()
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _snapshot(self, connection):
        row = connection.execute("SELECT * FROM policy WHERE id=1").fetchone()
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
        current = int(time.time())
        bucket = current // window
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            # Bounded retention; counters are shared by processes on this server.
            connection.execute("DELETE FROM rate_windows WHERE scope=? AND bucket < ?", (scope, bucket))
            connection.execute("""
                INSERT INTO rate_windows VALUES (?, ?, ?, 1)
                ON CONFLICT(scope, client) DO UPDATE SET
                    count=CASE WHEN bucket=excluded.bucket THEN count+1 ELSE 1 END,
                    bucket=excluded.bucket
            """, (scope, client, bucket))
            count = connection.execute(
                "SELECT count FROM rate_windows WHERE scope=? AND client=?", (scope, client)
            ).fetchone()[0]
            return count > limit
