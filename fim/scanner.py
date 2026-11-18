"""
scanner.py - the heart of the system (the integrity engine).

HOW DETECTION WORKS (simple version)
  1. BASELINE = a trusted snapshot:  {file path -> SHA-256, size, timestamp}
  2. SCAN     = take a fresh snapshot of the same files right now.
  3. COMPARE  the two snapshots:

        in baseline, missing now ............. DELETED
        not in baseline, exists now .......... CREATED
        in both, hash differs ................ MODIFIED
        missing path + new path, SAME hash ... RENAMED (same content, new name)
        baseline row has a bad signature ..... BASELINE_TAMPERED

We always re-hash file CONTENT. We do not trust timestamps, because attackers
can forge them ("timestomping").
"""
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from fim import config
from fim.alerts import raise_alert
from fim.database import Database
from fim.hasher import HashError, sha256_of_file
from fim.logging_setup import get_logger
from fim.security import compute_row_mac, verify_row_mac

logger = get_logger("scanner")

SEVERITY = {
    "BASELINE_TAMPERED": "CRITICAL",
    "MODIFIED": "HIGH",
    "DELETED": "HIGH",
    "CREATED": "MEDIUM",
    "RENAMED": "MEDIUM",
}


@dataclass
class ScanResult:
    events: list = field(default_factory=list)   # NEW events found in this scan
    files_scanned: int = 0
    baseline_files: int = 0
    duration: float = 0.0


class IntegrityScanner:
    def __init__(self, db: Database, key: bytes, data_dir):
        self.db = db
        self.key = key
        self.data_dir = Path(data_dir).resolve()
        self._lock = threading.RLock()       # only one scan/approval at a time
        self.alert_callbacks = []            # extra listeners (optional)

    # ------------------------------------------------------------------ files
    def _in_data_dir(self, path: Path) -> bool:
        p = str(path)
        d = str(self.data_dir)
        return p == d or p.startswith(d + os.sep)

    def is_excluded(self, path) -> bool:
        p = Path(path)
        name = p.name
        if p.suffix.lower() in config.EXCLUDED_SUFFIXES or name.endswith("~") or name.startswith(".#"):
            return True
        if any(part in config.EXCLUDED_DIR_NAMES for part in p.parts):
            return True
        return self._in_data_dir(p)

    def iter_files(self, watches=None):
        """Yield every monitored file that currently exists on disk."""
        seen = set()
        for watch in (watches if watches is not None else self.db.list_watches()):
            root = Path(watch["path"])
            if watch["kind"] == "file":
                candidates = [str(root)] if root.is_file() else []
            elif root.is_dir():
                candidates = []
                for dirpath, dirnames, filenames in os.walk(root):
                    dirnames[:] = [
                        d for d in dirnames
                        if d not in config.EXCLUDED_DIR_NAMES and not self._in_data_dir(Path(dirpath) / d)
                    ]
                    candidates.extend(os.path.join(dirpath, n) for n in filenames)
            else:
                candidates = []
            for c in candidates:
                if c not in seen and not self.is_excluded(c):
                    seen.add(c)
                    yield c

    def _snapshot(self, watches=None):
        """Hash every monitored file. Returns (snapshot dict, unreadable set)."""
        snap, unreadable = {}, set()
        for path in self.iter_files(watches):
            try:
                stat = os.stat(path)
                digest = sha256_of_file(path)
            except (HashError, OSError) as exc:
                # A file we cannot read must NOT be reported as "deleted".
                logger.warning("Could not read %s (%s) - skipped this round", path, exc)
                unreadable.add(path)
                continue
            snap[path] = {"sha256": digest, "size": stat.st_size, "mtime": stat.st_mtime}
        return snap, unreadable

    # --------------------------------------------------------------- baseline
    def _store(self, path: str, info: dict) -> None:
        mac = compute_row_mac(self.key, path, info["sha256"], info["size"], info["mtime"])
        self.db.upsert_baseline(path, info["sha256"], info["size"], info["mtime"], mac)

    def baseline_watch(self, watch: dict) -> int:
        """Record the current state of ONE watch as trusted (used when it is first added)."""
        with self._lock:
            snap, _ = self._snapshot([watch])
            for path, info in snap.items():
                self._store(path, info)
            logger.info("Baseline created for %s (%d files)", watch["path"], len(snap))
            return len(snap)

    def create_baseline(self) -> int:
        """Reset the baseline to the CURRENT state of everything monitored."""
        with self._lock:
            snap, _ = self._snapshot()
            self.db.clear_baseline()
            for path, info in snap.items():
                self._store(path, info)
            closed = self._close_all_open("baseline_reset")
            logger.info("Baseline rebuilt: %d files recorded, %d open alerts closed", len(snap), closed)
            return len(snap)

    def remove_watch_baseline(self, path: str) -> None:
        self.db.delete_baseline_under(path, os.sep)

    # ------------------------------------------------------------------- scan
    def _record(self, event_type, path, source, old_path=None, old_hash=None,
                new_hash=None, details=None):
        """Store an event + raise an alert, unless the same alert is already open."""
        if self.db.find_open_event(event_type, path, new_hash):
            return None
        event = self.db.add_event(event_type, path, old_path, old_hash, new_hash,
                                  SEVERITY[event_type], details, source)
        raise_alert(event, self.alert_callbacks)
        return event

    def scan(self, source: str = "scan") -> ScanResult:
        """Compare the disk with the baseline and report every difference."""
        with self._lock:
            started = time.time()
            baseline = {row["path"]: row for row in self.db.all_baseline()}
            snap, unreadable = self._snapshot()
            result = ScanResult(files_scanned=len(snap), baseline_files=len(baseline))
            events = result.events

            # 1) Is the baseline itself intact?
            trusted = {}
            for path, row in baseline.items():
                if verify_row_mac(self.key, row):
                    trusted[path] = row
                else:
                    ev = self._record("BASELINE_TAMPERED", path, source,
                                      details="Baseline record failed signature check")
                    if ev:
                        events.append(ev)

            # 2) Deleted / created candidates
            missing = [p for p in trusted if p not in snap and p not in unreadable]
            added = [p for p in snap if p not in baseline]

            # 3) Renames: a "missing" file and a "new" file with identical content
            added_by_hash = {}
            for p in added:
                added_by_hash.setdefault(snap[p]["sha256"], []).append(p)
            renamed_old, renamed_new = set(), set()
            for old in missing:
                candidates = added_by_hash.get(trusted[old]["sha256"])
                if candidates:
                    new = candidates.pop(0)
                    renamed_old.add(old)
                    renamed_new.add(new)
                    ev = self._record("RENAMED", new, source, old_path=old,
                                      old_hash=trusted[old]["sha256"], new_hash=snap[new]["sha256"],
                                      details="Same content, different path")
                    if ev:
                        events.append(ev)

            for old in missing:
                if old not in renamed_old:
                    ev = self._record("DELETED", old, source, old_hash=trusted[old]["sha256"],
                                      details="File no longer exists")
                    if ev:
                        events.append(ev)
            for new in added:
                if new not in renamed_new:
                    ev = self._record("CREATED", new, source, new_hash=snap[new]["sha256"],
                                      details="File is not in the baseline")
                    if ev:
                        events.append(ev)

            # 4) Content modified: same path, different SHA-256
            for path, row in trusted.items():
                if path in snap and snap[path]["sha256"] != row["sha256"]:
                    ev = self._record("MODIFIED", path, source, old_hash=row["sha256"],
                                      new_hash=snap[path]["sha256"],
                                      details=f"Size {row['size']} -> {snap[path]['size']} bytes")
                    if ev:
                        events.append(ev)

            # 5) If someone put things back the way they were, close the stale alerts
            self._auto_resolve(trusted, snap)

            result.duration = time.time() - started
            self.db.set_meta("last_scan", time.strftime("%Y-%m-%d %H:%M:%S"))
            self.db.set_meta("last_scan_files", str(result.files_scanned))
            logger.info("Scan finished (%s): %d files, %d new events, %.2fs",
                        source, result.files_scanned, len(events), result.duration)
            return result

    def _auto_resolve(self, trusted, snap) -> None:
        for ev in self.db.list_events(status="open"):
            path, kind = ev["path"], ev["event_type"]
            reverted = (
                (kind in ("MODIFIED", "DELETED") and path in trusted and path in snap
                 and snap[path]["sha256"] == trusted[path]["sha256"])
                or (kind == "CREATED" and path not in snap)
            )
            if reverted:
                self.db.resolve_events([ev["id"]], "reverted")
                logger.info("Event #%d (%s %s) auto-closed: file matches the baseline again",
                            ev["id"], kind, path)

    # --------------------------------------------------------------- approval
    def _sync_path(self, path: str) -> None:
        """Make the baseline match the disk for ONE path."""
        if os.path.isfile(path):
            info = {"sha256": sha256_of_file(path), "size": os.stat(path).st_size,
                    "mtime": os.stat(path).st_mtime}
            self._store(path, info)
        else:
            self.db.delete_baseline(path)

    def approve(self, event_id: int) -> int:
        """Accept a change as legitimate: update the baseline, close related alerts."""
        with self._lock:
            event = self.db.get_event(event_id)
            if not event:
                raise ValueError(f"Event #{event_id} does not exist.")
            if event["status"] != "open":
                raise ValueError(f"Event #{event_id} is already {event['status']}.")
            paths = {event["path"]} | ({event["old_path"]} if event["old_path"] else set())
            for p in paths:
                self._sync_path(p)
            ids = [e["id"] for e in self.db.open_events_for_paths(paths)]
            self.db.resolve_events(ids, "approved")
            logger.info("APPROVED baseline update: %s %s (%d alert(s) closed)",
                        event["event_type"], event["path"], len(ids))
            return len(ids)

    def approve_all(self) -> int:
        count = 0
        for ev in reversed(self.db.list_events(status="open")):
            current = self.db.get_event(ev["id"])
            if current and current["status"] == "open":
                count += self.approve(ev["id"])
        return count

    def _close_all_open(self, status: str) -> int:
        ids = [e["id"] for e in self.db.list_events(status="open")]
        return self.db.resolve_events(ids, status)
