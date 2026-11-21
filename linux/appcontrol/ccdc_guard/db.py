"""
SQLite state database wrapper.

Schema lives here; every other module imports get_conn() and uses it
directly with parameterised queries.
"""

import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = "/var/lib/ccdc-guard/state.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_entries (
    id        INTEGER PRIMARY KEY,
    path      TEXT UNIQUE NOT NULL,
    sha256    TEXT NOT NULL,
    size      INTEGER,
    source    TEXT NOT NULL,
    added_by  TEXT,
    added_at  TEXT,
    notes     TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
    id           INTEGER PRIMARY KEY,
    path         TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    action       TEXT NOT NULL,
    performed_by TEXT,
    performed_at TEXT,
    notes        TEXT
);

CREATE TABLE IF NOT EXISTS snapshots (
    id           INTEGER PRIMARY KEY,
    created_at   TEXT NOT NULL,
    description  TEXT,
    rules_content TEXT,
    trust_content TEXT,
    conf_content  TEXT
);

CREATE TABLE IF NOT EXISTS service_manifest (
    id           INTEGER PRIMARY KEY,
    service_name TEXT NOT NULL,
    exec_path    TEXT NOT NULL,
    was_trusted  INTEGER,
    auto_added   INTEGER,
    baseline_at  TEXT
);
"""


def _ensure_dir():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def get_conn():
    """Return an open sqlite3 connection with WAL mode and the schema applied."""
    _ensure_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# trust_entries helpers
# ---------------------------------------------------------------------------

def upsert_trust(conn, path, sha256, size, source, added_by="ccdc-guard", notes=""):
    conn.execute(
        """INSERT INTO trust_entries (path, sha256, size, source, added_by, added_at, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(path) DO UPDATE SET
               sha256=excluded.sha256,
               size=excluded.size,
               source=excluded.source,
               added_by=excluded.added_by,
               added_at=excluded.added_at,
               notes=excluded.notes""",
        (path, sha256, size, source, added_by, now_utc(), notes),
    )
    conn.commit()


def remove_trust(conn, path):
    conn.execute("DELETE FROM trust_entries WHERE path = ?", (path,))
    conn.commit()


def get_trust(conn, path):
    row = conn.execute(
        "SELECT * FROM trust_entries WHERE path = ?", (path,)
    ).fetchone()
    return dict(row) if row else None


def list_trust(conn):
    rows = conn.execute("SELECT * FROM trust_entries ORDER BY path").fetchall()
    return [dict(r) for r in rows]


def count_trust(conn):
    row = conn.execute(
        "SELECT source, COUNT(*) AS cnt FROM trust_entries GROUP BY source"
    ).fetchall()
    return {r["source"]: r["cnt"] for r in row}


# ---------------------------------------------------------------------------
# approvals helpers
# ---------------------------------------------------------------------------

def record_approval(conn, path, sha256, action, performed_by="ccdc-guard", notes=""):
    conn.execute(
        """INSERT INTO approvals (path, sha256, action, performed_by, performed_at, notes)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (path, sha256, action, performed_by, now_utc(), notes),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# snapshots helpers
# ---------------------------------------------------------------------------

def save_snapshot(conn, description, rules_content, trust_content, conf_content):
    conn.execute(
        """INSERT INTO snapshots (created_at, description, rules_content, trust_content, conf_content)
           VALUES (?, ?, ?, ?, ?)""",
        (now_utc(), description, rules_content, trust_content, conf_content),
    )
    conn.commit()


def latest_snapshot(conn):
    row = conn.execute(
        "SELECT * FROM snapshots ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# service_manifest helpers
# ---------------------------------------------------------------------------

def upsert_service_manifest(conn, service_name, exec_path, was_trusted, auto_added):
    conn.execute(
        """INSERT INTO service_manifest
               (service_name, exec_path, was_trusted, auto_added, baseline_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT DO NOTHING""",
        (service_name, exec_path, int(was_trusted), int(auto_added), now_utc()),
    )
    conn.commit()


def list_service_manifest(conn):
    rows = conn.execute("SELECT * FROM service_manifest").fetchall()
    return [dict(r) for r in rows]
