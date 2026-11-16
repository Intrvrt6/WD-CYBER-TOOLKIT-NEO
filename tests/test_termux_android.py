"""Termux / Android compatibility tests.

These lock in the three bugs fixed for Android access:
  1. backend used to call `ip -br addr` unconditionally -> zero interfaces on Termux
  2. the APK defaulted to the emulator alias 10.0.2.2 -> offline on real phones
  3. install.sh mentioned Termux in prose but never acted on it
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from backend import platform_utils as P

ROOT = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ detection --
def test_platform_label_is_one_of_known_values():
    assert P.platform_label() in {"termux", "android", "wsl", "windows", "linux"}


def test_termux_detected_from_env(monkeypatch):
    monkeypatch.setenv("TERMUX_VERSION", "0.118.0")
    assert P.is_termux() is True
    assert P.is_android() is True
    assert P.platform_label() == "termux"


def test_termux_detected_from_prefix(monkeypatch):
    monkeypatch.delenv("TERMUX_VERSION", raising=False)
    monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")
    monkeypatch.setattr(P.os.path, "isdir", lambda p: p == P.TERMUX_PREFIX)
    assert P.is_termux() is True


def test_not_termux_on_plain_linux(monkeypatch):
    monkeypatch.delenv("TERMUX_VERSION", raising=False)
    monkeypatch.setenv("PREFIX", "/usr")
    monkeypatch.setattr(P.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(P, "is_wsl", lambda: False)
    assert P.is_termux() is False
    assert P.platform_label() == "linux"


# --------------------------------------------------------------- interface io --
def test_interfaces_returns_rows_on_this_host():
    rows = P.interfaces()
    assert isinstance(rows, list)
    for row in rows:
        assert set(row) >= {"name", "state", "addresses"}
        assert isinstance(row["addresses"], list)


def test_interface_fallback_survives_missing_iproute2(monkeypatch):
    """The Termux case: no `ip` binary at all, interfaces must still resolve."""
    monkeypatch.setattr(P, "has_iproute2", lambda: False)
    monkeypatch.setattr(P.shutil, "which", lambda name: None)
    rows = P.interfaces()
    # Either psutil or the ioctl fallback must produce something on Linux.
    if sys.platform.startswith("linux"):
        assert rows, "no fallback produced interfaces without iproute2"
        assert any(r["name"] for r in rows)


def test_ioctl_fallback_finds_loopback_on_linux():
    if not sys.platform.startswith("linux"):
        pytest.skip("POSIX-only path")
    rows = P._rows_from_ioctl()
    assert rows, "ioctl fallback returned nothing"
    names = {r["name"] for r in rows}
    assert "lo" in names
    lo = next(r for r in rows if r["name"] == "lo")
    assert "127.0.0.1" in lo["addresses"]


def test_interface_source_reports_a_usable_path(monkeypatch):
    assert P.interface_source() in {"ip", "ifconfig", "psutil", "ioctl", "none"}
    monkeypatch.setattr(P, "has_iproute2", lambda: False)
    monkeypatch.setattr(P.shutil, "which", lambda name: None)
    assert P.interface_source() in {"psutil", "ioctl", "none"}


# ------------------------------------------------------------------- LAN urls --
def test_lan_urls_put_loopback_first():
    urls = P.lan_urls(8000)
    assert urls[0] == "http://127.0.0.1:8000"


def test_lan_urls_shape_and_dedupe():
    urls = P.lan_urls(9001)
    assert all(re.fullmatch(r"http://[\w.\-:]+:\d+", u) for u in urls), urls
    assert len(urls) == len(set(urls))
    assert urls[0].endswith(":9001")


def test_primary_lan_ip_env_override(monkeypatch):
    monkeypatch.setenv("WD_PUBLIC_HOST", "192.168.7.9")
    assert P.primary_lan_ip() == "192.168.7.9"


def test_primary_lan_ip_never_loopback(monkeypatch):
    monkeypatch.delenv("WD_PUBLIC_HOST", raising=False)
    monkeypatch.setattr(P, "interfaces", lambda: [
        {"name": "lo", "state": "UP", "addresses": ["127.0.0.1"]},
    ])
    ip = P.primary_lan_ip()
    assert ip is None or not ip.startswith("127.")


def test_usable_ipv4_skips_loopback_and_linklocal():
    assert P._usable_ipv4(["127.0.0.1", "169.254.3.4", "10.1.2.3"]) == "10.1.2.3"
    assert P._usable_ipv4(["127.0.0.1/8", "::1"]) is None


# --------------------------------------------------------------- network info --
def test_network_info_payload_shape():
    info = P.network_info(8000)
    for key in ("platform", "is_termux", "is_android", "urls", "on_device_url",
                "lan_url", "primary_lan_ip", "interface_source", "port"):
        assert key in info, key
    assert info["on_device_url"].startswith("http://127.0.0.1:")
    assert info["port"] == 8000


def test_network_info_lan_url_matches_primary_ip():
    info = P.network_info(8000)
    if info["primary_lan_ip"]:
        assert info["lan_url"] and info["primary_lan_ip"] in info["lan_url"]
    else:
        assert info["lan_url"] is None


# ------------------------------------------------------------- capability notes --
def test_capability_notes_explain_missing_tools_on_android(monkeypatch):
    monkeypatch.setattr(P, "is_termux", lambda: True)
    monkeypatch.setattr(P, "is_android", lambda: True)
    monkeypatch.setattr(P, "has_iproute2", lambda: False)
    monkeypatch.setattr(P, "has_can_utils", lambda: False)
    notes = " ".join(P.capability_notes())
    assert "iproute2" in notes
    assert "can-utils" in notes


# --------------------------------------------------------------- requirement set --
def test_core_requirements_exist_and_exclude_heavy_builds():
    path = ROOT / "requirements-core.txt"
    assert path.is_file(), "requirements-core.txt missing"
    lines = [ln.strip() for ln in path.read_text().splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    names = {re.split(r"[<>=!\[]", ln, 1)[0].lower() for ln in lines}
    # Must carry the runtime the API needs.
    assert {"fastapi", "uvicorn", "sqlalchemy", "argon2-cffi", "httpx"} <= names
    # Must not force Android-hostile builds.
    for heavy in ("yara-python", "asyncua", "pymodbus", "python-can", "scapy"):
        assert heavy not in names, f"{heavy} should not be mandatory on Termux"


def test_core_requirements_is_a_subset_of_full():
    def names(p):
        return {re.split(r"[<>=!\[]", ln.strip(), 1)[0].lower()
                for ln in p.read_text().splitlines()
                if ln.strip() and not ln.strip().startswith("#")}
    core = names(ROOT / "requirements-core.txt")
    full = names(ROOT / "requirements.txt")
    assert core <= full, f"core has entries missing from full: {core - full}"


# ------------------------------------------------------------------- scripts --
@pytest.mark.parametrize("script", ["scripts/termux.sh", "scripts/install.sh",
                                    "scripts/run.sh"])
def test_shell_scripts_parse(script):
    path = ROOT / script
    assert path.is_file(), f"{script} missing"
    res = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
    assert res.returncode == 0, f"{script} syntax error: {res.stderr}"


def test_termux_installer_actually_installs_packages():
    body = (ROOT / "scripts/termux.sh").read_text()
    assert "pkg install" in body, "termux.sh must actually install packages"
    assert "requirements-core.txt" in body
    assert "termux-wake-lock" in body, "phone server needs a wake lock"
    assert "--check" in body and "--install" in body


def test_install_sh_branches_to_termux_instead_of_printing_advice():
    body = (ROOT / "scripts/install.sh").read_text()
    assert "termux.sh" in body, "install.sh must hand over to the Termux installer"
    assert "exec bash" in body


def test_run_sh_reports_phone_reachable_url():
    body = (ROOT / "scripts/run.sh").read_text()
    assert "lan_urls" in body, "run.sh must use the shared LAN URL helper"
    assert "this device" in body


# ----------------------------------------------------------------------- apk --
def test_apk_defaults_to_on_device_loopback():
    """The regression that made the APK show offline on a real phone."""
    src = (ROOT / "android/src/sh/testssl/wdneo/MainActivity.java").read_text()
    assert 'DEFAULT_SERVER = "http://127.0.0.1:8000"' in src
    # The emulator alias must exist but never be the default argument to getString.
    assert "EMULATOR_HOST_ALIAS" in src
    assert 'prefs.getString(K_SERVER, "http://10.0.2.2:8000")' not in src
    assert "getString(K_SERVER, DEFAULT_SERVER)" in src


def test_apk_has_detect_flow_using_network_endpoint():
    src = (ROOT / "android/src/sh/testssl/wdneo/MainActivity.java").read_text()
    assert "doDetect" in src
    assert "network()" in src
    layout = (ROOT / "android/res/layout/activity_main.xml").read_text()
    assert 'android:id="@+id/btn_detect"' in layout
    api = (ROOT / "android/src/sh/testssl/wdneo/core/WdApi.java").read_text()
    assert '"/api/network"' in api


def test_apk_async_helper_does_not_drop_values():
    """async() discarded its Job result, so value callbacks got null."""
    src = (ROOT / "android/src/sh/testssl/wdneo/MainActivity.java").read_text()
    assert "asyncValue" in src, "value-returning async helper missing"
    assert "UiValue" in src


def test_apk_manifest_allows_cleartext_for_lan_http():
    manifest = (ROOT / "android/AndroidManifest.xml").read_text()
    assert 'android:usesCleartextTraffic="true"' in manifest
    assert "android.permission.INTERNET" in manifest


# ------------------------------------------------------- release metadata -- #
def test_api_network_is_mounted_publicly():
    """The APK calls /api/network before it has a token, so it must not need one."""
    from backend.main import app
    spec = app.openapi()
    paths = spec["paths"]
    assert "/api/network" in paths, "GET /api/network is not mounted"
    op = paths["/api/network"]["get"]
    assert not op.get("security"), "public discovery endpoint declares a security requirement"
    assert "401" not in op["responses"], "public discovery endpoint documents a 401"


def test_changelog_has_an_entry_for_the_running_version():
    """Honesty guard: APP_VERSION must have a matching CHANGELOG heading.

    This is the repo's recurring defect -- a doc or report claiming something
    the tree does not do. A version bump without a changelog entry is exactly
    that, so it is asserted rather than remembered.
    """
    from backend import config
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert f"## {config.APP_VERSION}" in changelog, (
        f"APP_VERSION is {config.APP_VERSION} but CHANGELOG.md has no '## {config.APP_VERSION}' section")
