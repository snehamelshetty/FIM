"""
monitor.py - real-time monitoring with Watchdog.

Watchdog asks the operating system to tell us the instant something happens in a
folder (file created, changed, deleted, moved). We do NOT trust the event details
blindly. Instead, any event simply says "something changed, please re-check", and
the scanner does a SHA-256 comparison against the baseline. That makes detection
reliable even though different editors/OSes emit very different event sequences.

Two things run together:
  1. Watchdog Observer  -> instant reaction (debounced by DEBOUNCE_SECONDS)
  2. Periodic scan loop -> safety net every SCAN_INTERVAL_SECONDS
"""
import os
import threading
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from fim import config
from fim.logging_setup import get_logger

logger = get_logger("monitor")

# Event types that only mean "somebody looked at the file", not "it changed".
_IGNORED_EVENT_TYPES = {"opened", "closed_no_write"}


class _ChangeHandler(FileSystemEventHandler):
    def __init__(self, watch_path: Path, is_file_watch: bool, trigger, scanner):
        self.watch_path = str(watch_path)
        self.is_file_watch = is_file_watch
        self.trigger = trigger
        self.scanner = scanner

    def _relevant(self, path) -> bool:
        if not path:
            return False
        path = os.fsdecode(path)
        if self.scanner.is_excluded(path):
            return False
        return path == self.watch_path if self.is_file_watch else True

    def on_any_event(self, event):
        if event.event_type in _IGNORED_EVENT_TYPES:
            return
        paths = [getattr(event, "src_path", None), getattr(event, "dest_path", None)]
        if any(self._relevant(p) for p in paths):
            logger.debug("Watchdog saw %s on %s", event.event_type, paths[0])
            self.trigger()


class RealTimeMonitor:
    def __init__(self, scanner, scan_interval=None, debounce=None):
        self.scanner = scanner
        self.scan_interval = scan_interval or config.SCAN_INTERVAL_SECONDS
        self.debounce = debounce if debounce is not None else config.DEBOUNCE_SECONDS
        self._observer = None
        self._timer = None
        self._timer_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._periodic_thread = None
        self.running = False

    # --- debounce: restart a short timer on every event; scan when it expires
    def _trigger(self):
        with self._timer_lock:
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(self.debounce, self._scan_safely, args=("realtime",))
            self._timer.daemon = True
            self._timer.start()

    def _scan_safely(self, source):
        try:
            self.scanner.scan(source=source)
        except Exception:
            logger.exception("Scan failed")   # never let a bad scan kill the monitor

    def _periodic_loop(self):
        while not self._stop_event.wait(self.scan_interval):
            self._scan_safely("periodic")

    # --- public controls
    def start(self) -> int:
        """Start watching everything in the watch list. Returns folders being observed."""
        if self.running:
            return 0
        watches = self.scanner.db.list_watches()
        self._observer = Observer()
        scheduled = set()
        for watch in watches:
            path = Path(watch["path"])
            is_file = watch["kind"] == "file"
            target = path.parent if is_file else path
            if not target.is_dir():
                logger.warning("Cannot watch %s (folder missing)", path)
                continue
            handler = _ChangeHandler(path, is_file, self._trigger, self.scanner)
            self._observer.schedule(handler, str(target), recursive=not is_file)
            scheduled.add(str(target))
        self._observer.daemon = True
        self._observer.start()
        self._stop_event.clear()
        self._periodic_thread = threading.Thread(target=self._periodic_loop, daemon=True)
        self._periodic_thread.start()
        self.running = True
        logger.info("Real-time monitoring STARTED (%d location(s), safety scan every %ss)",
                    len(scheduled), self.scan_interval)
        return len(scheduled)

    def stop(self) -> None:
        if not self.running:
            return
        self._stop_event.set()
        with self._timer_lock:
            if self._timer:
                self._timer.cancel()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        self.running = False
        logger.info("Real-time monitoring STOPPED")

    def restart(self) -> int:
        self.stop()
        return self.start()
