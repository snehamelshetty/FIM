"""
hasher.py - SHA-256 hashing.

WHAT IS A HASH?
A hash function turns any file into a fixed-length "fingerprint"
(64 hex characters for SHA-256). Change even ONE bit of the file and the
fingerprint changes completely. That is how we detect tampering without
storing a copy of every file.
"""
import hashlib
from pathlib import Path

from fim.config import HASH_CHUNK_SIZE


class HashError(Exception):
    """Raised when a file cannot be hashed (missing, no permission, ...)."""


def sha256_of_file(path) -> str:
    """Return the SHA-256 fingerprint (hex string) of a file."""
    file_path = Path(path)
    digest = hashlib.sha256()
    try:
        with file_path.open("rb") as handle:
            # iter(callable, sentinel) keeps calling read() until it returns b"" (end of file)
            for chunk in iter(lambda: handle.read(HASH_CHUNK_SIZE), b""):
                digest.update(chunk)
    except FileNotFoundError as exc:
        raise HashError(f"File not found: {file_path}") from exc
    except PermissionError as exc:
        raise HashError(f"Permission denied: {file_path}") from exc
    except IsADirectoryError as exc:
        raise HashError(f"Is a directory, not a file: {file_path}") from exc
    except OSError as exc:
        raise HashError(f"Cannot read {file_path}: {exc}") from exc
    return digest.hexdigest()


def sha256_of_text(text: str) -> str:
    """Hash a string (handy for demos and tests)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
