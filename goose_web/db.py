"""SQLite storage (WAL). Small, synchronous and fast; every call holds one lock for its statement(s)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from .policy import ANY, CHAT_LISTS, LEGACY_DEFAULT_POLICY

SCHEMA_VERSION = 6   # v3 (1.3.0): ip_blocks table; v4 (1.5.0): one team per user, least-privilege policies;
#                      v5 (1.14.0): guard_rulesets table (prompt guard, spec 018)
#                      v6 (1.15.0): chat_state table (composer queues and herd marks survive a restart, spec 019)
POLICY_MODEL = 2     # meta 'policy_model': 2 = spec 009 semantics (empty list = nothing, "*" = any)

# Audit rows older than this are deleted when the database is opened (GW-23).
AUDIT_RETENTION_DAYS = 365

# Additive, idempotent column migrations: (table, column, SQL type/default). Applied on every open
# with ALTER TABLE ... ADD COLUMN when the column is missing, so databases created by older versions
# pick them up. Only ever ADD nullable columns here; never rename or drop.
#   v2: users.totp_last_counter - last accepted TOTP time step (replay protection, GW-14)
#       users.oidc_issuer / users.oidc_subject - OIDC identity binding by (iss, sub) (GW-12)
#   v3: oidc_states.binding - hash of the pre-sign-in browser cookie the OIDC state is bound to (A-4)
MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("users", "totp_last_counter", "INTEGER"),
    ("users", "oidc_issuer", "TEXT"),
    ("users", "oidc_subject", "TEXT"),
    ("oidc_states", "binding", "TEXT"),
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
-- OIDC sign-ins of accounts with two-factor, waiting for the TOTP code (auth.begin_mfa, A-8)
CREATE TABLE IF NOT EXISTS mfa_pending (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  method TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
-- failed sign-ins per client address (IPv4, or IPv6 /64) and blocks (ipblock.py, spec 007)
CREATE TABLE IF NOT EXISTS ip_blocks (
  ip TEXT PRIMARY KEY,
  failures TEXT NOT NULL DEFAULT '[]',      -- JSON list of failure timestamps in the current run, newest last
  last_username TEXT NOT NULL DEFAULT '',
  blocked_at REAL NOT NULL DEFAULT 0,       -- 0 = not blocked
  blocked_until REAL NOT NULL DEFAULT 0,    -- 0 while blocked = until an administrator unblocks it
  updated_at REAL NOT NULL
);
-- prompt guard rule sets (guard.py, spec 018); builtin = key of a shipped default ('' = made by an admin)
CREATE TABLE IF NOT EXISTS guard_rulesets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  description TEXT NOT NULL DEFAULT '',
  rules TEXT NOT NULL DEFAULT '[]',
  builtin TEXT NOT NULL DEFAULT '',
  updated_at REAL NOT NULL
);
-- per-chat live state the gateway keeps for each profile (hub.py, spec 019): kind 'queue' = the composer queue
-- (JSON list of messages waiting for the run to end), kind 'mark' = the herd status not yet seen by the user
CREATE TABLE IF NOT EXISTS chat_state (
  profile TEXT NOT NULL,
  session_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  data TEXT NOT NULL DEFAULT '{}',
  updated_at REAL NOT NULL,
  PRIMARY KEY (profile, session_id, kind)
);
"""

JSON_COLUMNS = {"prefs", "policy_overrides", "policy", "payload", "detail", "value", "failures", "rules"}


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
            # SC-7: deleted rows (queued prompts, sessions, audit) are overwritten, not left in free pages
            self._conn.execute("PRAGMA secure_delete=ON")
            self._conn.executescript(SCHEMA)
            self._conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
            self._migrate()
        # No audit purge here (review 2026-11-12, D-4): it used the fixed 365 days at EVERY open, the command line
        # included, so a longer logs.audit_days (kept for compliance) lost its older rows at each start. The
        # gateway's maintenance loop (logjanitor) applies the configured retention.

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
            self._migrate_policy_model()
            self._seed_guard()
            self._conn.execute("UPDATE meta SET value=? WHERE key='schema_version' AND CAST(value AS INTEGER) < ?",
                               (str(SCHEMA_VERSION), SCHEMA_VERSION))
            self._user_columns = frozenset(self._table_columns("users"))

    def _migrate_policy_model(self) -> None:
        """One-shot move to the spec 009 policy model, so existing teams and users behave exactly as before:

        - each team policy is materialised over the 1.4 defaults, and its empty mode/provider/model lists (which
          meant "unrestricted") become ["*"];
        - empty mode/provider/model lists in user policy_overrides become ["*"] as well;
        - a user in several teams keeps the team with the lowest id (the dropped memberships are audited);
        - team_members gets a unique index on user_id (one team per user from now on).
        New databases run it too (nothing to convert) and only get the index."""
        row = self._conn.execute("SELECT value FROM meta WHERE key='policy_model'").fetchone()
        if row is not None and int(row[0] or 0) >= POLICY_MODEL:
            self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_team_members_user ON team_members(user_id)")
            return
        now = time.time()
        self._conn.execute("BEGIN")
        try:
            for tid, raw in self._conn.execute("SELECT id, policy FROM teams").fetchall():
                try:
                    stored = json.loads(raw or "{}")
                except ValueError:
                    stored = {}
                pol = {**LEGACY_DEFAULT_POLICY, **(stored if isinstance(stored, dict) else {})}
                for k in CHAT_LISTS:
                    if not pol.get(k):
                        pol[k] = [ANY]
                self._conn.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps(pol), tid))
            for uid, raw in self._conn.execute("SELECT id, policy_overrides FROM users").fetchall():
                try:
                    ov = json.loads(raw or "{}")
                except ValueError:
                    continue
                if not isinstance(ov, dict):
                    continue
                changed = False
                for k in CHAT_LISTS:
                    if k in ov and isinstance(ov[k], list) and not ov[k]:
                        ov[k] = [ANY]
                        changed = True
                if changed:
                    self._conn.execute("UPDATE users SET policy_overrides=? WHERE id=?", (json.dumps(ov), uid))
            dupes = self._conn.execute(
                "SELECT m.user_id, m.team_id, u.username FROM team_members m JOIN users u ON u.id=m.user_id "
                "WHERE m.team_id > (SELECT MIN(team_id) FROM team_members m2 WHERE m2.user_id=m.user_id)").fetchall()
            for uid, tid, uname in dupes:
                self._conn.execute("DELETE FROM team_members WHERE user_id=? AND team_id=?", (uid, tid))
                self._conn.execute(
                    "INSERT INTO audit(ts, user_id, username, ip, action, target, detail, ok) VALUES(?,?,?,?,?,?,?,1)",
                    (now, None, "", "", "team.migrate.membership", uname,
                     json.dumps({"droppedTeamId": tid, "reason": "one team per user (spec 009)"})))
            self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_team_members_user ON team_members(user_id)")
            self._conn.execute("INSERT INTO meta(key, value) VALUES('policy_model', ?) "
                               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(POLICY_MODEL),))
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def _seed_guard(self) -> None:
        """Spec 018: insert the shipped prompt-guard rule sets once (an admin may delete or edit them later; Admin >
        Prompt guard can restore them). Teams are not touched: their guard stays off until an admin turns it on.
        Security review 2026-11-11 (SA-5): a built-in set whose rules are still exactly an earlier shipped version
        (never edited) is upgraded to the current one on every start."""
        from .guard import DEFAULT_RULESETS, PREVIOUS_DEFAULT_RULES, rules_hash
        for rid, key, raw in self._conn.execute("SELECT id, builtin, rules FROM guard_rulesets WHERE builtin<>''"
                                                ).fetchall():
            rs = DEFAULT_RULESETS.get(key)
            try:
                h = rules_hash(json.loads(raw or "[]"))
            except ValueError:
                continue
            if rs and h in PREVIOUS_DEFAULT_RULES.get(key, set()) and h != rules_hash(rs["rules"]):
                self._conn.execute("UPDATE guard_rulesets SET description=?, rules=?, updated_at=? WHERE id=?",
                                   (rs["description"], json.dumps(rs["rules"]), time.time(), rid))
                self._conn.execute(
                    "INSERT INTO audit(ts, user_id, username, ip, action, target, detail, ok) VALUES(?,?,?,?,?,?,?,1)",
                    (time.time(), None, "", "", "guard.ruleset.upgrade", key,
                     json.dumps({"reason": "shipped default updated (security review 2026-11-11)"})))
        if self._conn.execute("SELECT 1 FROM meta WHERE key='guard_seeded'").fetchone():
            return
        now = time.time()
        for key, rs in DEFAULT_RULESETS.items():
            self._conn.execute("INSERT OR IGNORE INTO guard_rulesets(name, description, rules, builtin, updated_at) "
                               "VALUES(?,?,?,?,?)", (rs["name"], rs["description"], json.dumps(rs["rules"]), key, now))
        self._conn.execute("INSERT INTO meta(key, value) VALUES('guard_seeded', '1')")

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
    RESERVED_USERNAMES = frozenset({"appdata", "workspace", "_system", "_deleted", "_teams", "library", "backups",
                                    "logs"})

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
        # SC-3: a new account never inherits live state left under its name (a deleted user with the same name)
        self.execute("DELETE FROM chat_state WHERE profile=?", (str(fields.get("username") or "").lower(),))
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

    def update_prefs(self, uid: int, fn: Callable[[dict], dict | None]) -> dict | None:
        """Read-modify-write one user's prefs in a single transaction (1.18.2): ``fn`` gets the stored prefs (a fresh
        copy, read inside the transaction) and returns the new prefs, or None to write nothing. Returns what was
        written (or None). An exception from ``fn`` rolls back."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute("SELECT prefs FROM users WHERE id=?", (uid,)).fetchone()
                if row is None:
                    raise KeyError(uid)
                try:
                    cur = json.loads(row["prefs"] or "{}")
                except (TypeError, ValueError):
                    cur = {}
                new = fn(cur if isinstance(cur, dict) else {})
                if new is not None:
                    self._conn.execute("UPDATE users SET prefs=? WHERE id=?", (json.dumps(new), uid))
                self._conn.execute("COMMIT")
                return new
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def _check_user_columns(self, fields: dict) -> None:
        """Allow-list the column names that create_user/update_user interpolate into SQL."""
        bad = set(fields) - (self._user_columns - {"id"})
        if bad:
            raise ValueError(f"unknown or read-only user field(s): {sorted(bad)}")

    def user_teams(self, uid: int) -> list[dict]:
        """The user's team as a list of 0 or 1 rows (one team per user since spec 009)."""
        return self.query("SELECT t.* FROM teams t JOIN team_members m ON m.team_id=t.id WHERE m.user_id=? "
                          "ORDER BY t.id LIMIT 1", (uid,))

    def user_team(self, uid: int) -> dict | None:
        rows = self.user_teams(uid)
        return rows[0] if rows else None

    def set_user_team(self, uid: int, team_id: int | None) -> None:
        """Put a user in exactly one team (or none). Replaces any previous membership."""
        stmts: list[tuple[str, Iterable[Any]]] = [("DELETE FROM team_members WHERE user_id=?", (int(uid),))]
        if team_id:
            stmts.append(("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (int(team_id), int(uid))))
        self.transaction(stmts)

    # -- audit -----------------------------------------------------------------------
    def purge_audit(self, days: float = AUDIT_RETENTION_DAYS) -> int:
        """Delete audit rows older than `days` days; return how many were removed (GW-23)."""
        if days is None or days <= 0:
            return 0
        return self.execute_count("DELETE FROM audit WHERE ts < ?", (time.time() - 86400 * float(days),))

    # ---- per-chat live state (spec 019)
    def chat_state(self, profile: str) -> list[dict]:
        """Every chat_state row of a profile, `data` decoded (rows that do not decode are skipped)."""
        out = []
        for r in self.query("SELECT session_id, kind, data FROM chat_state WHERE profile=?", (profile,)):
            try:
                out.append({"session_id": r["session_id"], "kind": r["kind"], "data": json.loads(r["data"])})
            except (TypeError, ValueError):
                continue
        return out

    def set_chat_state(self, profile: str, session_id: str, kind: str, data: Any) -> None:
        """Store one row; data None (or empty) deletes it."""
        if data is None or data == [] or data == {}:
            self.execute("DELETE FROM chat_state WHERE profile=? AND session_id=? AND kind=?", (profile, session_id, kind))
            return
        self.execute("INSERT INTO chat_state(profile, session_id, kind, data, updated_at) VALUES(?,?,?,?,?) "
                     "ON CONFLICT(profile, session_id, kind) DO UPDATE SET data=excluded.data, "
                     "updated_at=excluded.updated_at",
                     (profile, session_id, kind, json.dumps(data, separators=(",", ":")), time.time()))

    def delete_chat_state(self, profile: str, session_id: str | None = None) -> None:
        if session_id is None:
            self.execute("DELETE FROM chat_state WHERE profile=?", (profile,))
        else:
            self.execute("DELETE FROM chat_state WHERE profile=? AND session_id=?", (profile, session_id))

    def sweep_chat_state(self, *, queue_age: float, mark_age: float, now: float | None = None) -> int:
        """SC-7: queued messages older than queue_age and herd marks older than mark_age seconds are deleted
        (maintenance loop; before 1.15.1 rows lived until the profile's next restore)."""
        now = time.time() if now is None else now
        with self._lock:
            cur = self._conn.execute("DELETE FROM chat_state WHERE (kind='queue' AND updated_at<?) OR "
                                     "(kind='mark' AND updated_at<?)", (now - queue_age, now - mark_age))
            return cur.rowcount or 0

    def chat_state_sessions(self, profile: str) -> set[str]:
        return {r["session_id"] for r in self.query("SELECT DISTINCT session_id FROM chat_state WHERE profile=?",
                                                     (profile,))}

    def audit(self, action: str, *, user: dict | None = None, ip: str = "", target: str = "",
              detail: dict | None = None, ok: bool = True) -> None:
        from . import activity
        activity.record(action, user=user, ip=ip, target=target, detail=detail, ok=ok)   # activity.jsonl too
        self.execute(
            "INSERT INTO audit(ts, user_id, username, ip, action, target, detail, ok) VALUES(?,?,?,?,?,?,?,?)",
            (time.time(), user["id"] if user else None, user["username"] if user else "", ip, action, target,
             json.dumps(detail or {}, default=str), 1 if ok else 0))
