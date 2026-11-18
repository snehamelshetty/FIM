"""
config.py - central settings.

Keeping every setting in ONE file means you never have to hunt through the
code to change a folder name or a time interval.
"""
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Where the FIM stores its own data (database, logs, reports, secret key).
# You can override it with an environment variable: FIM_DATA_DIR=/some/path
DATA_DIR = Path(os.environ.get("FIM_DATA_DIR", PROJECT_ROOT / "fim_data")).resolve()

# Read big files in 64 KB pieces so we never load a whole file into RAM.
HASH_CHUNK_SIZE = 64 * 1024

# Safety-net scan: even if the real-time watcher misses something,
# a full scan runs this often (seconds).
SCAN_INTERVAL_SECONDS = 30

# Editors fire many events for one save. We wait this long after the LAST
# event before scanning ("debouncing").
DEBOUNCE_SECONDS = 1.0

# Things we never monitor (temporary / noisy files).
EXCLUDED_DIR_NAMES = {"__pycache__", ".git", ".venv", "node_modules"}
EXCLUDED_SUFFIXES = {".tmp", ".swp", ".swx", ".pyc", ".part", ".crdownload"}

# Minimum length for the admin password.
MIN_PASSWORD_LENGTH = 8
