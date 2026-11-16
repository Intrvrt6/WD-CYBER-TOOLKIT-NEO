"""Regressions for tool-version probing, the report's Tools section, and the
documented-but-previously-unenforced must_change_password gate."""
import pytest

from backend import capabilities
from backend.deps import require_stage2_fresh_password

NL = chr(10)


# ------------------------------------------------------- version extraction --
@pytest.mark.parametrize("stdout,stderr,expected", [
    # ASCII-art banners must not become the reported version (httpx/naabu/katana).
    # Naabu's real banner, which used to be reported verbatim as its "version".
    ("__" + NL + "___  ___  ___ _/ /  __ __" + NL + "/ _ \\/ _ \\/ _ \\/ _ \\/ // /" + NL, "", ""),
    # A golang banner that carries the version inline is still parsed.
    ("|_| |____|___/_/\\_\\" + chr(116) + "v1.4.0" + NL, "", "1.4.0"),
    # An option-parsing error is not a version (candump --help).
    ("candump: invalid option -- '-'" + NL + "candump - dump CAN bus traffic." + NL
     + "Usage: candump [options] <CAN interface>+" + NL, "", ""),
    # ANSI-coloured tool banner with a real version.
    (chr(27) + "[34mINF" + chr(27) + "[0m Current Version: v2.17.0" + NL, "", "2.17.0"),
    # A version printed on stderr is still found.
    ("", "Version: 2.7.0" + NL, "2.7.0"),
    # A plain tool line.
    ("nmap version 7.94SVN ( https://nmap.org )" + NL, "", "7.94"),
    # Usage text with no version: empty rather than dumping usage at the reader.
    ("usage: thing [-h]" + NL, "", ""),
])
def test_extract_version(stdout, stderr, expected):
    assert capabilities.extract_version(stdout, stderr) == expected


def test_extract_version_strips_prefix_and_ansi():
    raw = chr(27) + "[32mVersion:" + chr(27) + "[0m 12.3.1" + NL
    assert capabilities.extract_version(raw, "") == "12.3.1"


def test_cli_tools_never_reports_banner_or_error_as_version():
    """The live probe must yield a dotted version or None, never banner/usage text."""
    for name, info in capabilities.cli_tools().items():
        if not info.get("present"):
            continue
        v = info.get("version")
        if v is None:
            continue
        assert any(ch.isdigit() for ch in v), f"{name} -> {v!r}"
        low = v.lower()
        for bad in ("invalid option", "usage", "copyright", "unrecognized option"):
            assert bad not in low, f"{name} -> {v!r}"


def test_capabilities_marks_unknown_version_honestly():
    for name, info in capabilities.cli_tools().items():
        if info.get("present") and not info.get("version"):
            assert info.get("version_known") is False, name
            assert info.get("reason"), name


def test_capture_interfaces_are_plain_names():
    for iface in capabilities.capture_interfaces():
        assert "(" not in iface and ")" not in iface, iface


# ------------------------------------------------- must_change_password gate --
class _U:
    def __init__(self, must):
        self.must_change_password = must
        self.username = "u"
        self.role = "admin"


class _S:
    stage = 2


class _P:
    def __init__(self, must):
        self.user = _U(must)
        self.session = _S()


def test_fresh_password_gate_blocks_bootstrap_password():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        require_stage2_fresh_password(_P(True))
    assert exc.value.status_code == 428
    assert exc.value.detail["code"] == "PASSWORD_CHANGE_REQUIRED"


def test_fresh_password_gate_allows_rotated_password():
    assert require_stage2_fresh_password(_P(False)) is not None


def _unlocked(client, operator):
    """Two-stage login helper -> bearer token."""
    r = client.post("/api/auth/stage1", json={"username": operator["username"],
                                              "password": operator["password"],
                                              "shortcut": operator["shortcut"]})
    assert r.status_code == 200, r.text
    tok = r.json()["token"]
    r = client.post("/api/auth/stage2", json={"pin": operator["pin"]},
                    headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 200, r.text
    return tok


def test_rotation_is_enforced_on_authorize_and_execute(client, operator):
    """End to end: a bootstrap-password session cannot authorize or execute."""
    from backend import database
    tok = _unlocked(client, operator)
    hdr = {"authorization": f"Bearer {tok}"}

    client.post("/api/scope", json={"target": "127.0.0.1"}, headers=hdr)

    db = database.SessionLocal()
    try:
        user = db.query(database.User).first()
        assert user is not None
        user.must_change_password = True
        db.commit()
    finally:
        db.close()

    r = client.post("/api/authorizations",
                    json={"targets": ["127.0.0.1"], "ttl_minutes": 10}, headers=hdr)
    assert r.status_code == 428, r.text
    assert r.json()["detail"]["code"] == "PASSWORD_CHANGE_REQUIRED"

    r = client.post("/api/assessments",
                    json={"template": "network_pentest", "targets": ["127.0.0.1"],
                          "mode": "live"}, headers=hdr)
    assert r.status_code == 428, r.text

    # Rotating the password re-opens authorization.
    r = client.post("/api/auth/password",
                    json={"old_password": operator["password"],
                          "new_password": "Rotated-Pass-2026!x"}, headers=hdr)
    assert r.status_code == 200, r.text

    r = client.post("/api/authorizations",
                    json={"targets": ["127.0.0.1"], "ttl_minutes": 10}, headers=hdr)
    assert r.status_code == 200, r.text
    assert r.json()["id"]

    r = client.get("/api/auth/me", headers=hdr)
    assert r.json()["user"]["must_change_password"] is False
