"""Security primitives: hashing, tokens, password policy."""
import pytest

from backend import security


def test_argon2id_hash_verifies_and_is_not_plaintext():
    h = security.hash_secret("correct horse battery staple")
    assert h.startswith("$argon2id$"), h
    assert "correct horse" not in h
    assert security.verify_secret(h, "correct horse battery staple")
    assert not security.verify_secret(h, "wrong")


def test_same_secret_hashes_differently():
    a = security.hash_secret("samevalue")
    b = security.hash_secret("samevalue")
    assert a != b
    assert security.verify_secret(a, "samevalue") and security.verify_secret(b, "samevalue")


def test_verify_rejects_garbage_hash():
    assert security.verify_secret("not-a-hash", "x") is False
    assert security.verify_secret("", "x") is False


def test_hash_rejects_empty_secret():
    with pytest.raises(ValueError):
        security.hash_secret("")


def test_token_fingerprint_is_sha256_and_stable():
    t = security.new_token()
    fp = security.token_fingerprint(t)
    assert len(fp) == 64 and fp == security.token_fingerprint(t)
    assert fp != t


def test_new_tokens_are_unique():
    assert len({security.new_token() for _ in range(50)}) == 50


def test_password_policy():
    assert security.password_strength_problem("short") is not None
    assert security.password_strength_problem("alllowercaseonly") is not None
    assert security.password_strength_problem("Correct-Horse-9") is None


def test_constant_eq():
    assert security.constant_eq("abc", "abc")
    assert not security.constant_eq("abc", "abd")
