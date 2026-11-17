"""Tests for the explicit CORS origin allowlist."""
import pytest

from backend.config import parse_cors_origins


def test_empty_cors_allowlist_keeps_same_origin_default():
    assert parse_cors_origins(None) == []
    assert parse_cors_origins("") == []


def test_https_origins_are_trimmed_and_deduplicated():
    assert parse_cors_origins(
        " https://console.example.test ,https://console.example.test "
    ) == ["https://console.example.test"]


@pytest.mark.parametrize("raw", [
    "*",
    "https://example.test/path",
    "https://user:pass@example.test",
    "https://example.test?debug=1",
    "https://example.test#fragment",
    "http://console.example.test",
    "ftp://console.example.test",
    "not-a-url",
    "https://console.example.test:99999",
    "https://console.example.test:notaport",
])
def test_rejects_unsafe_or_invalid_origins(raw):
    with pytest.raises(ValueError):
        parse_cors_origins(raw)


@pytest.mark.parametrize("origin", [
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://[::1]:8080",
])
def test_allows_local_development_http_origins(origin):
    assert parse_cors_origins(origin) == [origin]
