"""Static-file serving containment (path-traversal regression tests).

These exist because the SPA catch-all once served ``FRONTEND_DIR / path`` whenever
the result was a file, letting an unauthenticated GET read files outside
frontend/ (including database/bootstrap_credentials.txt).
"""
import pytest


@pytest.fixture(scope="module")
def static():
    from backend import main
    if not main.config.FRONTEND_DIR.exists():
        pytest.skip("no frontend directory present")
    return main._safe_static, main._FRONTEND_ROOT, main.config.FRONTEND_DIR


@pytest.mark.parametrize("path", ["index.html", "assets/app.js", "assets/app.css"])
def test_real_frontend_files_are_served(static, path):
    fn, _root, frontend = static
    hit = fn(path)
    assert hit is not None
    assert str(hit).startswith(str(frontend.resolve()))


@pytest.mark.parametrize("path", [
    "../README.md",
    "../../etc/passwd",
    "../database/bootstrap_credentials.txt",
    "../database/schema.sql",
    "../requirements.txt",
    "../backend/security.py",
    "assets/../../README.md",
    "..\\..\\boot.ini",
    "/etc/passwd",
    "",
    "\x00index.html",
])
def test_traversal_never_escapes_frontend(static, path):
    fn, root, _frontend = static
    hit = fn(path)
    assert hit is None or str(hit).startswith(str(root)), f"{path!r} escaped to {hit}"


def test_dot_segments_inside_frontend_are_still_allowed(static):
    fn, root, _frontend = static
    hit = fn("assets/../index.html")
    assert hit is not None and str(hit).startswith(str(root))


def test_http_cannot_leak_credentials(client, tmp_root):
    """The bootstrap file must never be reachable over unauthenticated HTTP."""
    from pathlib import Path
    cred = Path(tmp_root) / "database" / "bootstrap_credentials.txt"
    cred.write_text("Operator password : LEAK-ME-NOT\n", encoding="utf-8")
    for path in ("/../database/bootstrap_credentials.txt",
                 "/..%2fdatabase%2fbootstrap_credentials.txt",
                 "/database/bootstrap_credentials.txt"):
        body = client.get(path).text
        assert "LEAK-ME-NOT" not in body, f"credentials leaked via {path}"


def test_spa_fallback_returns_html_for_unknown_route(client):
    r = client.get("/some/deep/spa/route")
    assert r.status_code == 200
    assert "<html" in r.text.lower()


def test_assets_mount_is_intact(client):
    assert client.get("/assets/app.css").status_code == 200
    assert client.get("/assets/api.js").status_code == 200
