"""
engine.py - one simple "front door" to the whole system.

The CLI, the dashboard and the tests all talk to FIMEngine, so none of them
need to know how the database or scanner work internally.
"""
from collections import Counter
from pathlib import Path

from fim import config
from fim.database import Database
from fim.hasher import sha256_of_file
from fim.scanner import IntegrityScanner
from fim.security import (hash_password, load_or_create_key, validate_new_password,
                          verify_password)
from fim.validators import validate_watch_path

STATUS_ICON = {
    "INTACT": "✅ INTACT", "MODIFIED": "⚠️ MODIFIED", "DELETED": "🗑️ DELETED",
    "CREATED": "🆕 CREATED (unapproved)", "RENAMED": "🔀 RENAMED",
    "BASELINE_TAMPERED": "🚨 BASELINE TAMPERED",
}
_PRIORITY = ["BASELINE_TAMPERED", "MODIFIED", "DELETED", "RENAMED", "CREATED"]


class FIMEngine:
    def __init__(self, data_dir=None):
        self.data_dir = Path(data_dir or config.DATA_DIR).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir = self.data_dir / "reports"
        self.key = load_or_create_key(self.data_dir / ".fim_secret.key")
        self.db = Database(self.data_dir / "fim.db")
        self.scanner = IntegrityScanner(self.db, self.key, self.data_dir)

    # ---- watch list
    def add_watch(self, raw_path: str) -> dict:
        path = validate_watch_path(raw_path, self.data_dir)
        kind = "file" if path.is_file() else "dir"
        watch = {"path": str(path), "kind": kind}
        self.db.add_watch(watch["path"], kind)
        watch["baselined_files"] = self.scanner.baseline_watch(watch)
        return watch

    def remove_watch(self, path: str) -> None:
        self.db.remove_watch(path)
        self.scanner.remove_watch_baseline(path)

    def watches(self) -> list:
        return self.db.list_watches()

    # ---- scanning / baseline
    def scan(self, source="scan"):
        return self.scanner.scan(source)

    def rebuild_baseline(self) -> int:
        return self.scanner.create_baseline()

    # ---- admin password (protects baseline approvals)
    def admin_password_set(self) -> bool:
        return self.db.get_meta("admin_hash") is not None

    def set_admin_password(self, password: str, current: str = None) -> None:
        validate_new_password(password)
        if self.admin_password_set() and not self.verify_admin(current or ""):
            raise PermissionError("Current admin password is wrong.")
        salt, digest = hash_password(password)
        self.db.set_meta("admin_salt", salt)
        self.db.set_meta("admin_hash", digest)

    def verify_admin(self, password: str) -> bool:
        salt, digest = self.db.get_meta("admin_salt"), self.db.get_meta("admin_hash")
        return bool(salt and digest and password and verify_password(password, salt, digest))

    def approve(self, event_id: int, password: str) -> int:
        if not self.verify_admin(password):
            raise PermissionError("Wrong admin password - baseline NOT changed.")
        return self.scanner.approve(event_id)

    def approve_all(self, password: str) -> int:
        if not self.verify_admin(password):
            raise PermissionError("Wrong admin password - baseline NOT changed.")
        return self.scanner.approve_all()

    # ---- views for the dashboard
    def file_status(self) -> list:
        """One row per monitored file with its current integrity status."""
        flags = {}
        for ev in self.db.list_events(status="open"):
            flags.setdefault(ev["path"], []).append(ev["event_type"])
            if ev["old_path"]:
                flags.setdefault(ev["old_path"], []).append("RENAMED")
        rows = []
        for base in self.db.all_baseline():
            kinds = flags.pop(base["path"], [])
            status = next((k for k in _PRIORITY if k in kinds), "INTACT")
            rows.append({"File": base["path"], "Status": STATUS_ICON[status],
                         "SHA-256 (baseline)": base["sha256"][:16] + "…", "Size (bytes)": base["size"],
                         "Baseline time": base["recorded_at"]})
        for path, kinds in flags.items():          # files not in the baseline (new/renamed targets)
            status = next((k for k in _PRIORITY if k in kinds), "CREATED")
            rows.append({"File": path, "Status": STATUS_ICON[status], "SHA-256 (baseline)": "—",
                         "Size (bytes)": None, "Baseline time": "—"})
        return rows

    def summary(self) -> dict:
        open_events = self.db.list_events(status="open")
        counts = Counter(e["event_type"] for e in open_events)
        statuses = self.file_status()
        return {
            "monitored_files": len(self.db.all_baseline()),
            "intact": sum(1 for r in statuses if r["Status"] == STATUS_ICON["INTACT"]),
            "open_alerts": len(open_events),
            "open_by_type": dict(counts),
            "total_events": len(self.db.list_events()),
            "last_scan": self.db.get_meta("last_scan", "never"),
        }

    def log_tail(self, lines: int = 100) -> str:
        log_file = self.data_dir / "logs" / "fim_activity.log"
        if not log_file.exists():
            return "(no log yet)"
        return "".join(log_file.read_text(encoding="utf-8", errors="replace").splitlines(True)[-lines:])
