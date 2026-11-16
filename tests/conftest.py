import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# Environment must be set BEFORE `backend` is imported (collection time), so the
# temporary DB/report/evidence directories are used and no module reloading is
# needed. Reloading would create duplicate exception classes and break
# `pytest.raises(...)` identity checks.
# ---------------------------------------------------------------------------
TEST_CREDS = {
    "username": "WD-TEST-OPERATOR",
    "password": "Unit-Test-Pass-2026",
    "pin": "42424242",
    "shortcut": "WD-TESTSHORTCUT01",
}

_TMP = tempfile.mkdtemp(prefix="wd_neo_test_")
os.environ["WD_DATA_DIR"] = os.path.join(_TMP, "database")
os.environ["WD_EVIDENCE_DIR"] = os.path.join(_TMP, "evidence")
os.environ["WD_REPORT_DIR"] = os.path.join(_TMP, "reports")
os.environ["WD_DATABASE_URL"] = f"sqlite:///{os.path.join(_TMP, 'database', 'test.db')}"
os.environ["WD_ADMIN_USER"] = TEST_CREDS["username"]
os.environ["WD_ADMIN_PASSWORD"] = TEST_CREDS["password"]
os.environ["WD_ADMIN_PIN"] = TEST_CREDS["pin"]
os.environ["WD_SHORTCUT"] = TEST_CREDS["shortcut"]
os.environ["WD_RATE_LIMIT_ATTEMPTS"] = "100000"
os.environ["WD_FORCE_PASSWORD_CHANGE"] = "0"


@pytest.fixture(scope="session")
def tmp_root():
    return _TMP


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset every table and runtime flag so each test is independent."""
    from backend import database, runner
    database.init_db()
    s = database.SessionLocal()
    try:
        for table in reversed(database.Base.metadata.sorted_tables):
            s.execute(table.delete())
        s.commit()
    finally:
        s.close()
    runner.executor.reset()
    yield
    runner.executor.reset()


@pytest.fixture()
def db():
    from backend import database
    database.init_db()
    s = database.SessionLocal()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture()
def operator(db):
    """Create the single operator with known cleartext credentials."""
    from backend import authentication
    created = authentication.bootstrap(db)
    assert created is not None, "bootstrap must create the first operator"
    return dict(TEST_CREDS)


@pytest.fixture()
def client(operator):
    from fastapi.testclient import TestClient
    from backend.main import app
    with TestClient(app) as c:
        yield c
