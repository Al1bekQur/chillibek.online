"""Durable live policy, audit trail, sliding counters and cross-worker admission."""
import hashlib
import ipaddress
import json
import secrets
import sqlite3
import time
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator
from .csp_policy import CSPPolicy


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    mode: Literal["block", "monitor", "disabled"] = "block"
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
    csp: CSPPolicy = CSPPolicy()
    rate_limit_requests: StrictInt = Field(default=120, ge=1, le=10000)
    rate_limit_window_seconds: StrictInt = Field(default=60, ge=1, le=3600)
    route_limit_requests: StrictInt = Field(default=90, ge=1, le=5000)
    route_limit_window_seconds: StrictInt = Field(default=60, ge=1, le=3600)
    bot_detection_limit: StrictInt = Field(default=12, ge=1, le=1000)
    bot_detection_window_seconds: StrictInt = Field(default=60, ge=1, le=3600)
    request_size_bytes: StrictInt = Field(default=1_048_576, ge=1024, le=4_194_304)
    login_max_attempts: StrictInt = Field(default=5, ge=1, le=100)
    login_ip_max_attempts: StrictInt = Field(default=20, ge=1, le=1000)
    login_window_seconds: StrictInt = Field(default=900, ge=60, le=86400)
    login_initial_lockout_seconds: StrictInt = Field(default=30, ge=5, le=3600)
    login_lockout_multiplier: StrictInt = Field(default=2, ge=1, le=10)
    login_max_lockout_seconds: StrictInt = Field(default=900, ge=30, le=86400)

    @model_validator(mode="after")
    def validate_login_lockout_bounds(self):
        if self.login_max_lockout_seconds < self.login_initial_lockout_seconds:
            raise ValueError("Maximum lockout duration must be at least the initial duration.")
        return self


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
            CREATE TABLE IF NOT EXISTS login_counters (
                identity TEXT PRIMARY KEY, kind TEXT NOT NULL, attempts INTEGER NOT NULL,
                level INTEGER NOT NULL, window_ends REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS active_blocks (
                id TEXT PRIMARY KEY, identity TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL, identifier TEXT NOT NULL, reason TEXT NOT NULL,
                rule_id TEXT NOT NULL, attempts INTEGER NOT NULL,
                started_at REAL NOT NULL, expires_at REAL, manual INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS active_blocks_expiry ON active_blocks(expires_at);
            CREATE TABLE IF NOT EXISTS csp_reports (
                id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, directive TEXT NOT NULL,
                document_path TEXT NOT NULL, blocked_resource TEXT NOT NULL,
                disposition TEXT NOT NULL, receipt_revision INTEGER NOT NULL
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
            current_keys = set(Policy.model_fields)
            pre_csp_keys = current_keys - {'csp'}
            new_fields = {
                'bot_detection_limit', 'bot_detection_window_seconds',
                'rate_limit_requests', 'rate_limit_window_seconds', 'route_limit_requests',
                'route_limit_window_seconds', 'request_size_bytes', 'login_max_attempts',
                'login_ip_max_attempts', 'login_window_seconds',
                'login_initial_lockout_seconds', 'login_lockout_multiplier',
                'login_max_lockout_seconds',
            }
            previous_keys = pre_csp_keys - new_fields
            oldest_keys = previous_keys - {'command_injection', 'brute_force', 'bot_detection'}
            numeric_policy_keys = {
                'rate_limit_requests', 'rate_limit_window_seconds', 'route_limit_requests',
                'route_limit_window_seconds', 'request_size_bytes', 'login_max_attempts',
                'login_ip_max_attempts', 'login_window_seconds',
                'login_initial_lockout_seconds', 'login_lockout_multiplier',
                'login_max_lockout_seconds',
            }
            older_keys = oldest_keys - numeric_policy_keys
            legacy_keys = {
                frozenset(previous_keys), frozenset(previous_keys - numeric_policy_keys),
                frozenset(oldest_keys), frozenset(older_keys),
                frozenset(current_keys - {'command_injection', 'brute_force', 'bot_detection'}),
                frozenset(pre_csp_keys),
                frozenset(pre_csp_keys - {'command_injection', 'brute_force', 'bot_detection'}),
            }
            if isinstance(legacy, dict) and frozenset(legacy) in legacy_keys:
                upgraded = Policy.model_validate({**Policy().model_dump(), **legacy})
                connection.execute('BEGIN IMMEDIATE')
                # Another worker may already have upgraded the row.
                changed = connection.execute('UPDATE policy SET value=?, revision=revision+1, updated_at=?, updated_by=? WHERE id=1 AND value=?',
                    (upgraded.model_dump_json(), now(), 'schema-migration', raw)).rowcount
                if changed:
                    self._audit(connection, 'schema-migration', 'schema_upgrade', {
                        'added': sorted(current_keys - set(legacy)),
                    })
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
            policy = Policy.model_validate(stored).model_dump(mode='json')
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

    def record_csp_reports(self, reports, revision):
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            connection.executemany('INSERT INTO csp_reports(timestamp,directive,document_path,blocked_resource,disposition,receipt_revision) VALUES (?,?,?,?,?,?)',
                [(now(), r['directive'], r['document_path'], r['blocked_resource'], r['disposition'], revision) for r in reports])
            connection.execute('DELETE FROM csp_reports WHERE id NOT IN (SELECT id FROM csp_reports ORDER BY id DESC LIMIT 1000)')

    def csp_reports(self):
        with self.connect() as connection:
            return [dict(row) for row in connection.execute('SELECT * FROM csp_reports ORDER BY id DESC LIMIT 100')]

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

    def probe_blocked(self, client, limit, window=60):
        with self.connect() as connection:
            return connection.execute('SELECT COUNT(*) FROM traffic_events WHERE scope=? AND client=? AND timestamp>?',
                ('probes', client, time.time() - window)).fetchone()[0] >= limit

    @staticmethod
    def identity(value):
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def login_keys(self, ip, account):
        return [self.identity('ip:' + ip), self.identity('account:' + account.casefold().strip())]

    def login_locked(self, keys):
        current = time.time()
        with self.connect() as connection:
            return any(connection.execute(
                'SELECT 1 FROM failures WHERE client=? AND locked_until>?',
                (key, current),
            ).fetchone() for key in keys)

    def login_result(self, keys, failed):
        current = time.time()
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            connection.execute('DELETE FROM failures WHERE expires<=?', (current,))
            for key in keys:
                if not failed:
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
                connection.execute(
                    'INSERT OR REPLACE INTO failures VALUES (?, ?, ?, ?, ?)',
                    (key, count, level, current + 1800, locked),
                )

    def _expire_blocks(self, connection, current):
        expired = connection.execute(
            'SELECT * FROM active_blocks WHERE expires_at IS NOT NULL AND expires_at<=?',
            (current,),
        ).fetchall()
        for block in expired:
            connection.execute('DELETE FROM active_blocks WHERE id=?', (block['id'],))
            self._audit(connection, 'system', 'security_block_expired', {
                'kind': block['kind'], 'identifier': block['identifier'], 'reason': block['reason'],
                'rule_id': block['rule_id'], 'attempts': block['attempts'],
                'manual': bool(block['manual']), 'started_at': block['started_at'],
                'expires_at': block['expires_at'],
            })

    def _login_identities(self, ip, account):
        normalized_ip = str(ipaddress.ip_address(ip))
        normalized_account = account.casefold().strip()
        return [
            (self.identity('ip:' + normalized_ip), 'ip', normalized_ip),
            (self.identity('account:' + normalized_account), 'account', normalized_account),
        ]

    @staticmethod
    def _masked_account(account):
        return (account[:1] + '***') if account else '***'

    def login_admission(self, ip, account, policy):
        if policy.mode != 'block':
            return 0
        current = time.time()
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            self._expire_blocks(connection, current)
            identities = self._login_identities(ip, account)
            rows = connection.execute(
                'SELECT * FROM active_blocks WHERE identity IN (?, ?)',
                (identities[0][0], identities[1][0]),
            ).fetchall()
            retry = 0
            for block in rows:
                if block['manual'] or policy.brute_force:
                    if block['expires_at'] is None:
                        return -1
                    retry = max(retry, int(block['expires_at'] - current) + 1)
            return retry

    def record_login_failure(self, ip, account, policy):
        if not policy.brute_force or policy.mode == 'disabled':
            return False
        current = time.time()
        detected = False
        thresholds = {'ip': policy.login_ip_max_attempts, 'account': policy.login_max_attempts}
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            self._expire_blocks(connection, current)
            for identity, kind, value in self._login_identities(ip, account):
                row = connection.execute(
                    'SELECT * FROM login_counters WHERE identity=?', (identity,),
                ).fetchone()
                if row is None or row['window_ends'] <= current:
                    attempts, level, window_ends = 0, 0, current + policy.login_window_seconds
                else:
                    attempts, level, window_ends = row['attempts'], row['level'], row['window_ends']
                attempts += 1
                if attempts >= thresholds[kind]:
                    detected = True
                    if policy.mode == 'block':
                        duration = policy.login_initial_lockout_seconds
                        for _ in range(level):
                            if duration >= policy.login_max_lockout_seconds:
                                break
                            duration = min(
                                policy.login_max_lockout_seconds,
                                duration * policy.login_lockout_multiplier,
                            )
                        expires_at = current + duration
                        identifier = value if kind == 'ip' else self._masked_account(value)
                        block_id = secrets.token_urlsafe(18)
                        connection.execute(
                            'INSERT OR REPLACE INTO active_blocks '
                            '(id, identity, kind, identifier, reason, rule_id, attempts, started_at, expires_at, manual) '
                            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)',
                            (block_id, identity, kind, identifier, 'Repeated failed staff login',
                             'AUTH-001', attempts, current, expires_at),
                        )
                        self._audit(connection, 'system', 'security_block', {
                            'kind': kind, 'identifier': identifier,
                            'reason': 'Repeated failed staff login', 'rule_id': 'AUTH-001',
                            'attempts': attempts, 'manual': False,
                            'started_at': current, 'expires_at': expires_at,
                        })
                        attempts = 0
                        level += 1
                connection.execute(
                    'INSERT OR REPLACE INTO login_counters VALUES (?, ?, ?, ?, ?)',
                    (identity, kind, attempts, level, window_ends),
                )
            return detected

    def record_login_success(self, account):
        identity = self.identity('account:' + account.casefold().strip())
        with self.connect() as connection:
            connection.execute('DELETE FROM login_counters WHERE identity=?', (identity,))

    def create_manual_block(self, kind, value, duration_seconds, reason, actor):
        if kind == 'ip':
            normalized = str(ipaddress.ip_address(value))
            identifier = normalized
        elif kind == 'account':
            normalized = value.strip().casefold()
            if not normalized or len(normalized) > 80:
                raise ValueError('Account identifier must be 1 to 80 characters.')
            identifier = self._masked_account(normalized)
        else:
            raise ValueError('Unsupported block type.')
        identity = self.identity(kind + ':' + normalized)
        current = time.time()
        expires_at = current + duration_seconds
        block_id = secrets.token_urlsafe(18)
        details = {
            'kind': kind, 'identifier': identifier, 'reason': reason,
            'rule_id': 'MANUAL-001', 'attempts': 0, 'manual': True,
            'started_at': current, 'expires_at': expires_at,
        }
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            self._expire_blocks(connection, current)
            connection.execute(
                'INSERT OR REPLACE INTO active_blocks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)',
                (block_id, identity, kind, identifier, reason, 'MANUAL-001', 0, current, expires_at),
            )
            self._audit(connection, actor, 'security_block', details)
        return block_id

    def active_blocks(self):
        current = time.time()
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            self._expire_blocks(connection, current)
            rows = connection.execute('SELECT * FROM active_blocks ORDER BY started_at DESC').fetchall()
            return [{
                'id': row['id'], 'kind': row['kind'], 'identifier': row['identifier'],
                'reason': row['reason'], 'rule_id': row['rule_id'], 'attempts': row['attempts'],
                'started_at': datetime.fromtimestamp(row['started_at'], timezone.utc).isoformat(),
                'expires_at': datetime.fromtimestamp(row['expires_at'], timezone.utc).isoformat() if row['expires_at'] else None,
                'remaining_seconds': max(0, int(row['expires_at'] - current)) if row['expires_at'] else None,
                'manual': bool(row['manual']),
            } for row in rows]

    def unblock(self, block_id, actor):
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            row = connection.execute('SELECT * FROM active_blocks WHERE id=?', (block_id,)).fetchone()
            if row is None:
                return False
            connection.execute('DELETE FROM active_blocks WHERE id=?', (block_id,))
            connection.execute('DELETE FROM login_counters WHERE identity=?', (row['identity'],))
            self._audit(connection, actor, 'security_unblock', {
                'kind': row['kind'], 'identifier': row['identifier'], 'reason': row['reason'],
                'rule_id': row['rule_id'], 'attempts': row['attempts'],
                'manual': bool(row['manual']),
            })
            return True

    def blocked_ip(self, ip):
        try:
            identity = self.identity('ip:' + str(ipaddress.ip_address(ip)))
        except ValueError:
            return None
        current = time.time()
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            self._expire_blocks(connection, current)
            row = connection.execute(
                'SELECT * FROM active_blocks WHERE identity=?', (identity,),
            ).fetchone()
            if row and (row['manual'] or row['rule_id'] == 'AUTH-001'):
                block = dict(row)
                block['remaining_seconds'] = (
                    max(1, int(row['expires_at'] - current) + 1) if row['expires_at'] else None
                )
                return block
            return None

    def block_history(self, limit=50):
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT timestamp, actor, action, details FROM configuration_audit "
                "WHERE action IN ('security_block', 'security_unblock', 'security_block_expired') "
                "ORDER BY id DESC LIMIT ?", (limit,),
            ).fetchall()
            return [{
                'timestamp': row['timestamp'], 'actor': row['actor'],
                'action': row['action'], 'details': json.loads(row['details']),
            } for row in rows]
