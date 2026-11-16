"""Password/PIN hashing, token generation and constant-time comparison helpers."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)


def hash_secret(secret: str) -> str:
    """Argon2id hash of a password, PIN or shortcut code."""
    if not secret:
        raise ValueError("secret must not be empty")
    return _ph.hash(secret)


def verify_secret(hashed: str, secret: str) -> bool:
    try:
        return _ph.verify(hashed, secret)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def needs_rehash(hashed: str) -> bool:
    try:
        return _ph.check_needs_rehash(hashed)
    except InvalidHashError:
        return True


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_fingerprint(token: str) -> str:
    """Session tokens are stored as SHA-256 fingerprints, never in clear."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def password_strength_problem(pw: str) -> str | None:
    if len(pw) < 12:
        return "Password must be at least 12 characters."
    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ])
    if classes < 3:
        return "Password must mix at least three of: lower, upper, digit, symbol."
    return None
