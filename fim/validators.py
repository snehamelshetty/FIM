"""
validators.py - input validation.

NEVER trust input, even your own. We check every path before we monitor it.
"""
import os
from pathlib import Path


def validate_watch_path(raw: str, data_dir=None) -> Path:
    """Return a clean absolute Path, or raise ValueError with a friendly message."""
    if raw is None or not str(raw).strip():
        raise ValueError("Path is empty. Please type a file or folder path.")

    cleaned = str(raw).strip().strip('"').strip("'")
    if "\x00" in cleaned:
        raise ValueError("Path contains an invalid character.")

    path = Path(os.path.expanduser(cleaned))
    try:
        path = path.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise ValueError(f"Path does not exist: {cleaned}")

    if path == Path(path.anchor):
        raise ValueError("Refusing to monitor an entire drive/root. Pick a specific folder.")
    if not (path.is_file() or path.is_dir()):
        raise ValueError("Only regular files and folders can be monitored.")
    if not os.access(path, os.R_OK):
        raise ValueError(f"No read permission for: {path}")

    if data_dir is not None:
        data = Path(data_dir).resolve()
        if path == data or data in path.parents or path in data.parents:
            raise ValueError("You cannot monitor the FIM's own data folder (it would alert on itself).")
    return path
