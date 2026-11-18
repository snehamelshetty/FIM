"""
database.py - SQLite storage.

SQLite is a full database stored in ONE file, built into Python (no server to
install). We keep four tables:

  watches   - the files/folders the user chose to monitor
  baseline  - the "known good" hash, size and timestamp of every monitored file
  events    - every detected change (created/modified/deleted/renamed/...)
  meta      - small settings (last scan time, admin password hash)
"""
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS watches (
    path TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    added_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS baseline (
    path TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime REAL NOT NULL,
    recorded_at TEXT NOT NULL,
    mac TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    path TEXT NOT NULL,
    old_path TEXT,
    old_hash TEXT,
    new_hash TEXT,
    severity TEXT NOT NULL,
    details TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    source TEXT NOT NULL DEFAULT 'scan',
    resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


class Database:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self):
        # A fresh connection per operation keeps us safe when the Watchdog
        # thread and the dashboard thread use the database at the same time.
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ----- watches -----
    def add_watch(self, path: str, kind: str) -> None:
        with self._connect() as c:
            c.execute("INSERT OR REPLACE INTO watches VALUES (?, ?, ?)", (path, kind, now_iso()))

    def remove_watch(self, path: str) -> None:
        with self._connect() as c:
            c.execute("DELETE FROM watches WHERE path = ?", (path,))

    def list_watches(self) -> list:
        with self._connect() as c:
            return [dict(r) for r in c.execute("SELECT * FROM watches ORDER BY path")]

    # ----- baseline -----
    def upsert_baseline(self, path, sha256, size, mtime, mac) -> None:
        with self._connect() as c:
            c.execute(
                "INSERT OR REPLACE INTO baseline VALUES (?, ?, ?, ?, ?, ?)",
                (path, sha256, size, mtime, now_iso(), mac),
            )

    def delete_baseline(self, path: str) -> None:
        with self._connect() as c:
            c.execute("DELETE FROM baseline WHERE path = ?", (path,))

    def delete_baseline_under(self, root: str, sep: str) -> None:
        prefix = root.rstrip(sep) + sep
        with self._connect() as c:
            c.execute(
                "DELETE FROM baseline WHERE path = ? OR substr(path, 1, ?) = ?",
                (root, len(prefix), prefix),
            )

    def clear_baseline(self) -> None:
        with self._connect() as c:
            c.execute("DELETE FROM baseline")

    def all_baseline(self) -> list:
        with self._connect() as c:
            return [dict(r) for r in c.execute("SELECT * FROM baseline ORDER BY path")]

    # ----- events -----
    def add_event(self, event_type, path, old_path, old_hash, new_hash,
                  severity, details, source) -> dict:
        ts = now_iso()
        with self._connect() as c:
            cur = c.execute(
                "INSERT INTO events (timestamp, event_type, path, old_path, old_hash,"
                " new_hash, severity, details, status, source)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)",
                (ts, event_type, path, old_path, old_hash, new_hash, severity, details, source),
            )
            row = c.execute("SELECT * FROM events WHERE id = ?", (cur.lastrowid,)).fetchone()
            return dict(row)

    def find_open_event(self, event_type, path, new_hash):
        # "IS" (instead of "=") also works when new_hash is NULL
        with self._connect() as c:
            row = c.execute(
                "SELECT * FROM events WHERE status='open' AND event_type=? AND path=? AND new_hash IS ?",
                (event_type, path, new_hash),
            ).fetchone()
            return dict(row) if row else None

    def get_event(self, event_id: int):
        with self._connect() as c:
            row = c.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
            return dict(row) if row else None

    def list_events(self, status=None, limit=None) -> list:
        sql, params = "SELECT * FROM events", []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY id DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        with self._connect() as c:
            return [dict(r) for r in c.execute(sql, params)]

    def open_events_for_paths(self, paths) -> list:
        paths = list(paths)
        marks = ",".join("?" * len(paths))
        with self._connect() as c:
            rows = c.execute(
                f"SELECT * FROM events WHERE status='open' AND (path IN ({marks}) OR old_path IN ({marks}))",
                paths + paths,
            )
            return [dict(r) for r in rows]

    def resolve_events(self, ids, status: str) -> int:
        ids = list(ids)
        if not ids:
            return 0
        marks = ",".join("?" * len(ids))
        with self._connect() as c:
            c.execute(
                f"UPDATE events SET status=?, resolved_at=? WHERE id IN ({marks})",
                [status, now_iso()] + ids,
            )
        return len(ids)

    # ----- meta -----
    def set_meta(self, key: str, value: str) -> None:
        with self._connect() as c:
            c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, str(value)))

    def get_meta(self, key: str, default=None):
        with self._connect() as c:
            row = c.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default
