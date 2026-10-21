"""Password hashing helpers used by the education platform."""

import base64
import hashlib
import secrets


def hash_password(password: str) -> str:
    """Create a salted PBKDF2 password hash suitable for database storage."""
    salt = secrets.token_bytes(32)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 100_000
    )
    salt_text = base64.b64encode(salt).decode("ascii")
    hash_text = base64.b64encode(password_hash).decode("ascii")
    return f"{salt_text}${hash_text}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Return whether a plain password matches a stored salted hash."""
    try:
        salt_text, hash_text = stored_hash.split("$", 1)
        salt = base64.b64decode(salt_text)
        expected_hash = base64.b64decode(hash_text)
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 100_000
        )
        return secrets.compare_digest(expected_hash, actual_hash)
    except (ValueError, TypeError):
        return False


def is_hashed_password(password: str) -> bool:
    """Identify the format used by hashes created by :func:`hash_password`."""
    return "$" in password and len(password.split("$")) == 2