"""
security.py - protecting the baseline itself.

PROBLEM: an attacker who modifies a file could ALSO edit our baseline database
so the new hash looks "normal". To defend against that we:

  1. Sign every baseline row with an HMAC (a keyed hash). Without the secret key
     the attacker cannot produce a valid signature -> we raise BASELINE_TAMPERED.
  2. Protect "approve baseline changes" with an admin password. We store only a
     salted PBKDF2 hash of the password, never the password itself.

LIMITATION (be honest in your portfolio!): if an attacker can read the key file
too, they can forge signatures. In production, keep the key off the monitored
machine (HSM / remote secrets store) and ship logs to a remote server.
"""
import hashlib
import hmac
import os
import secrets
from pathlib import Path

from fim.config import MIN_PASSWORD_LENGTH

PBKDF2_ITERATIONS = 200_000


# ---------- HMAC signing of baseline rows ----------
def load_or_create_key(key_file) -> bytes:
    key_file = Path(key_file)
    if key_file.exists():
        return bytes.fromhex(key_file.read_text().strip())
    key = secrets.token_bytes(32)
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text(key.hex())
    try:
        os.chmod(key_file, 0o600)  # owner-only (no effect on Windows, that's fine)
    except OSError:
        pass
    return key


def compute_row_mac(key: bytes, path: str, sha256: str, size: int, mtime: float) -> str:
    message = f"{path}|{sha256}|{size}|{mtime:.6f}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_row_mac(key: bytes, row: dict) -> bool:
    expected = compute_row_mac(key, row["path"], row["sha256"], row["size"], row["mtime"])
    # compare_digest avoids timing attacks
    return hmac.compare_digest(expected, row["mac"])


# ---------- admin password ----------
def hash_password(password: str, salt: bytes = None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    _, candidate = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(candidate, hash_hex)


def validate_new_password(password: str) -> None:
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
