"""SQLite storage (WAL). Small, synchronous and fast; every call holds one lock for its statement(s)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 2

# Audit rows older than this are deleted when the database is opened (GW-23).
AUDIT_RETENTION_DAYS = 365

# Additive, idempotent column migrations: (table, column, SQL type/default). Applied on every open
# with ALTER TABLE ... ADD COLUMN when the column is missing, so databases created by older versions
# pick them up. Only ever ADD nullable columns here; never rename or drop.
#   v2: users.totp_last_counter - last accepted TOTP time step (replay protection, GW-14)
#       users.oidc_issuer / users.oidc_subject - OIDC identity binding by (iss, sub) (GW-12)
MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("users", "totp_last_counter", "INTEGER"),
    ("users", "oidc_issuer", "TEXT"),
    ("users", "oidc_subject", "TEXT"),
)
POST_MIGRATION_SQL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_oidc ON users(oidc_issuer, oidc_subject)"
    " WHERE oidc_subject IS NOT NULL",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'user',
  auth_source TEXT NOT NULL DEFAULT 'local',
  password_hash TEXT,
  must_change_pw INTEGER NOT NULL DEFAULT 0,
  totp_secret TEXT,
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  profile_mode TEXT NOT NULL DEFAULT 'isolated',
  profile_path TEXT NOT NULL DEFAULT '',
  personal_hints TEXT NOT NULL DEFAULT '',
  prefs TEXT NOT NULL DEFAULT '{}',
  policy_overrides TEXT NOT NULL DEFAULT '{}',
  has_schedules INTEGER NOT NULL DEFAULT 0,
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until REAL NOT NULL DEFAULT 0,
  created_at REAL NOT NULL,
  last_login_at REAL
  -- later columns (totp_last_counter, oidc_issuer, oidc_subject) are added by MIGRATIONS in db.py
);
CREATE TABLE IF NOT EXISTS teams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  description TEXT NOT NULL DEFAULT '',
  policy TEXT NOT NULL DEFAULT '{}',
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS team_members (
  team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (team_id, user_id)
);
CREATE TABLE IF NOT EXISTS hints_docs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  description TEXT NOT NULL DEFAULT '',
  content TEXT NOT NULL DEFAULT '',
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS user_hints (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hints_id INTEGER NOT NULL REFERENCES hints_docs(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, hints_id)
);
CREATE TABLE IF NOT EXISTS team_hints (
  team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  hints_id INTEGER NOT NULL REFERENCES hints_docs(id) ON DELETE CASCADE,
  PRIMARY KEY (team_id, hints_id)
);
CREATE TABLE IF NOT EXISTS team_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  source TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  UNIQUE (team_id, kind, name)
);
CREATE TABLE IF NOT EXISTS auth_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  last_seen REAL NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL DEFAULT 'password'
);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_user ON auth_sessions(user_id);
CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  created_at REAL NOT NULL,
  last_used REAL,
  expires_at REAL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  user_id INTEGER,
  username TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '{}',
  ok INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oidc_states (
  state TEXT PRIMARY KEY, verifier TEXT NOT NULL, nonce TEXT NOT NULL, created_at REAL NOT NULL
);
"""

JSON_COLUMNS = {"prefs", "policy_overrides", "policy", "payload", "detail", "value"}


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)
            self._conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
            self._migrate()
        self.purge_audit()

    def _table_columns(self, table: str) -> set[str]:
        if table not in {t for t, _, _ in MIGRATIONS} | {"users"}:
            raise ValueError(f"unknown table {table!r}")
        # table is checked against the fixed MIGRATIONS allow-list above, never user input.
        return {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")}  # nosec B608

    def _migrate(self) -> None:
        """Apply MIGRATIONS idempotently (safe to run on every start, new or old databases)."""
        with self._lock:
            for table, column, decl in MIGRATIONS:
                if column not in self._table_columns(table):
                    # Identifiers and types come from the MIGRATIONS constant, never user input.
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")  # nosec B608
            for sql in POST_MIGRATION_SQL:
                self._conn.execute(sql)
            self._conn.execute("UPDATE meta SET value=? WHERE key='schema_version' AND CAST(value AS INTEGER) < ?",
                               (str(SCHEMA_VERSION), SCHEMA_VERSION))
            self._user_columns = frozenset(self._table_columns("users"))

    # -- helpers -----------------------------------------------------------------
    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        d = dict(row)
        for k in JSON_COLUMNS & d.keys():
            try:
                d[k] = json.loads(d[k]) if isinstance(d[k], str) else d[k]
            except (ValueError, TypeError):
                pass
        return d

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            return [self._row(r) for r in self._conn.execute(sql, tuple(params)).fetchall()]

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        with self._lock:
            return self._row(self._conn.execute(sql, tuple(params)).fetchone())

    def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            return cur.lastrowid if cur.lastrowid else cur.rowcount

    def execute_count(self, sql: str, params: Iterable[Any] = ()) -> int:
        """Run an UPDATE/DELETE and return the number of rows changed.

        (execute() may return a stale lastrowid for non-INSERT statements, so use this when the
        caller needs to know whether a conditional UPDATE matched.)"""
        with self._lock:
            return self._conn.execute(sql, tuple(params)).rowcount

    def transaction(self, statements: list[tuple[str, Iterable[Any]]]) -> None:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                for sql, params in statements:
                    self._conn.execute(sql, tuple(params))
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- settings (JSON values) ------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        r = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return r["value"] if r else default

    def set_setting(self, key: str, value: Any) -> None:
        self.execute("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                     (key, json.dumps(value)))

    # -- users ---------------------------------------------------------------------
    def user_by_name(self, username: str) -> dict | None:
        return self.one("SELECT * FROM users WHERE username=?", (username,))

    def user_by_id(self, uid: int) -> dict | None:
        return self.one("SELECT * FROM users WHERE id=?", (uid,))

    def users(self) -> list[dict]:
        return self.query("SELECT * FROM users ORDER BY username")

    # Folder names inside the profiles root that must never become a user's profile folder.
    RESERVED_USERNAMES = frozenset({"appdata", "workspace", "_system", "_deleted", "library", "backups", "logs"})

    def create_user(self, **fields: Any) -> int:
        if str(fields.get("username") or "").lower() in self.RESERVED_USERNAMES:
            raise ValueError(f"the username '{fields.get('username')}' is reserved")
        fields.setdefault("created_at", time.time())
        for k in ("prefs", "policy_overrides"):
            if k in fields and not isinstance(fields[k], str):
                fields[k] = json.dumps(fields[k])
        self._check_user_columns(fields)
        cols = ", ".join(fields)
        marks = ", ".join("?" for _ in fields)
        # Column names are checked against the users table's real columns (_check_user_columns);
        # all values are bound parameters.
        return self.execute(f"INSERT INTO users({cols}) VALUES({marks})", list(fields.values()))  # nosec B608

    def update_user(self, uid: int, **fields: Any) -> None:
        if not fields:
            return
        for k in ("prefs", "policy_overrides"):
            if k in fields and not isinstance(fields[k], str):
                fields[k] = json.dumps(fields[k])
        self._check_user_columns(fields)
        sets = ", ".join(f"{k}=?" for k in fields)
        # Column names are checked against the users table's real columns (_check_user_columns);
        # all values are bound parameters.
        self.execute(f"UPDATE users SET {sets} WHERE id=?", [*fields.values(), uid])  # nosec B608

    def _check_user_columns(self, fields: dict) -> None:
        """Allow-list the column names that create_user/update_user interpolate into SQL."""
        bad = set(fields) - (self._user_columns - {"id"})
        if bad:
            raise ValueError(f"unknown or read-only user field(s): {sorted(bad)}")

    def user_teams(self, uid: int) -> list[dict]:
        return self.query("SELECT t.* FROM teams t JOIN team_members m ON m.team_id=t.id WHERE m.user_id=? ORDER BY t.name", (uid,))

    # -- audit -----------------------------------------------------------------------
    def purge_audit(self, days: float = AUDIT_RETENTION_DAYS) -> int:
        """Delete audit rows older than `days` days; return how many were removed (GW-23)."""
        if days is None or days <= 0:
            return 0
        return self.execute_count("DELETE FROM audit WHERE ts < ?", (time.time() - 86400 * float(days),))

    def audit(self, action: str, *, user: dict | None = None, ip: str = "", target: str = "",
              detail: dict | None = None, ok: bool = True) -> None:
        self.execute(
            "INSERT INTO audit(ts, user_id, username, ip, action, target, detail, ok) VALUES(?,?,?,?,?,?,?,?)",
            (time.time(), user["id"] if user else None, user["username"] if user else "", ip, action, target,
             json.dumps(detail or {}, default=str), 1 if ok else 0))
