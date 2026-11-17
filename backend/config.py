"""Central configuration for WD CYBER TOOLKIT NEO.

Every value can be overridden through environment variables or a .env file, so
the same code runs on Kali, Linux, Windows/WSL and Android/Termux without edits.

The .env file is loaded at IMPORT time (not later in the app lifespan) because
the values below are read into module constants during import; loading it
afterwards would leave the defaults in place and silently ignore the file.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(__file__).resolve().parent.parent


def load_dotenv(path: Path | None = None) -> None:
    """Minimal .env loader (no external dependency).

    Existing environment variables win, so an explicit `WD_X=... ./run.sh`
    always overrides the file.
    """
    env_path = path or BASE_DIR / ".env"
    if not env_path.exists():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


# Load before any constant below reads os.environ.
load_dotenv()

DATA_DIR = Path(os.environ.get("WD_DATA_DIR", BASE_DIR / "database"))
EVIDENCE_DIR = Path(os.environ.get("WD_EVIDENCE_DIR", BASE_DIR / "evidence"))
REPORT_DIR = Path(os.environ.get("WD_REPORT_DIR", BASE_DIR / "reports"))
FRONTEND_DIR = BASE_DIR / "frontend"
TEMPLATES_DIR = BASE_DIR / "templates"
SAMPLES_DIR = BASE_DIR / "samples"

DATABASE_URL = os.environ.get("WD_DATABASE_URL", f"sqlite:///{DATA_DIR / 'wd_cyber.db'}")
INSTANCE_NAME = os.environ.get("WD_INSTANCE_NAME", "WD CYBER TOOLKIT NEO")
APP_VERSION = "1.4.1"


def parse_cors_origins(raw: str | None) -> list[str]:
    """Parse an explicit CORS allowlist; same-origin is the empty-list default.

    Wildcards, URL paths, credentials and non-local plaintext HTTP origins are
    rejected. Local HTTP origins remain useful for a developer workstation.
    """
    origins: list[str] = []
    for item in (raw or "").split(","):
        origin = item.strip().rstrip("/")
        if not origin:
            continue
        if origin == "*":
            raise ValueError("WD_CORS_ORIGINS must not contain wildcard origins")
        try:
            parsed = urlsplit(origin)
            _ = parsed.port  # reject malformed/out-of-range ports at startup
        except ValueError as exc:
            raise ValueError(f"Invalid CORS origin: {item!r}") from exc
        if (parsed.scheme not in {"https", "http"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.path
                or parsed.query or parsed.fragment):
            raise ValueError(f"Invalid CORS origin: {item!r}")
        if parsed.scheme == "http" and parsed.hostname not in {
            "localhost", "127.0.0.1", "::1"
        }:
            raise ValueError("Non-local CORS origins must use HTTPS")
        origins.append(origin)
    return list(dict.fromkeys(origins))


CORS_ORIGINS = parse_cors_origins(os.environ.get("WD_CORS_ORIGINS", ""))

# --- session / authorization lifetime -------------------------------------
SESSION_TTL_MINUTES = int(os.environ.get("WD_SESSION_TTL_MINUTES", "480"))
AUTHZ_TTL_MINUTES = int(os.environ.get("WD_AUTHZ_TTL_MINUTES", "60"))
AUTHZ_MAX_TTL_MINUTES = int(os.environ.get("WD_AUTHZ_MAX_TTL_MINUTES", "720"))

# --- lockout / throttling -------------------------------------------------
MAX_LOGIN_FAILURES = int(os.environ.get("WD_MAX_LOGIN_FAILURES", "5"))
LOCKOUT_MINUTES = int(os.environ.get("WD_LOCKOUT_MINUTES", "15"))
RATE_LIMIT_ATTEMPTS = int(os.environ.get("WD_RATE_LIMIT_ATTEMPTS", "10"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("WD_RATE_LIMIT_WINDOW_SECONDS", "60"))

# --- bootstrap credentials (optional explicit provisioning) ----------------
BOOTSTRAP_USER = os.environ.get("WD_ADMIN_USER")
BOOTSTRAP_PASSWORD = os.environ.get("WD_ADMIN_PASSWORD")
BOOTSTRAP_PIN = os.environ.get("WD_ADMIN_PIN")
BOOTSTRAP_SHORTCUT = os.environ.get("WD_SHORTCUT")
FORCE_PASSWORD_CHANGE = os.environ.get("WD_FORCE_PASSWORD_CHANGE", "1") == "1"

# --- execution defaults ---------------------------------------------------
DEFAULT_CMD_TIMEOUT = int(os.environ.get("WD_CMD_TIMEOUT", "120"))
MAX_CMD_TIMEOUT = int(os.environ.get("WD_MAX_CMD_TIMEOUT", "600"))
LAB_BIND_HOST = os.environ.get("WD_LAB_BIND_HOST", "127.0.0.1")

# --- Artax AI (assistant) -------------------------------------------------
# Defaults to the bundle's own model endpoint; any OpenAI-compatible endpoint works.
ARTAX_ENABLED = os.environ.get("WD_ARTAX_ENABLED", "1") == "1"
ARTAX_BASE_URL = os.environ.get("WD_ARTAX_BASE_URL", "")
ARTAX_API_KEY = os.environ.get("WD_ARTAX_API_KEY", "")
ARTAX_MODEL = os.environ.get("WD_ARTAX_MODEL", "artax")
ARTAX_TIMEOUT = int(os.environ.get("WD_ARTAX_TIMEOUT", "120"))
ARTAX_MAX_CONTEXT_FINDINGS = int(os.environ.get("WD_ARTAX_MAX_CONTEXT_FINDINGS", "40"))


def ensure_dirs() -> None:
    for d in (DATA_DIR, EVIDENCE_DIR, REPORT_DIR):
        d.mkdir(parents=True, exist_ok=True)


def reload() -> None:
    """Re-read .env into this module's constants (used by `make env-reload`/tests)."""
    global DATA_DIR, EVIDENCE_DIR, REPORT_DIR, DATABASE_URL, INSTANCE_NAME, CORS_ORIGINS
    global SESSION_TTL_MINUTES, AUTHZ_TTL_MINUTES, AUTHZ_MAX_TTL_MINUTES
    global MAX_LOGIN_FAILURES, LOCKOUT_MINUTES, RATE_LIMIT_ATTEMPTS, RATE_LIMIT_WINDOW_SECONDS
    global DEFAULT_CMD_TIMEOUT, MAX_CMD_TIMEOUT, LAB_BIND_HOST
    global ARTAX_ENABLED, ARTAX_BASE_URL, ARTAX_API_KEY, ARTAX_MODEL, ARTAX_TIMEOUT
    global ARTAX_MAX_CONTEXT_FINDINGS
    global BOOTSTRAP_USER, BOOTSTRAP_PASSWORD, BOOTSTRAP_PIN, BOOTSTRAP_SHORTCUT
    global FORCE_PASSWORD_CHANGE

    load_dotenv()
    DATA_DIR = Path(os.environ.get("WD_DATA_DIR", BASE_DIR / "database"))
    EVIDENCE_DIR = Path(os.environ.get("WD_EVIDENCE_DIR", BASE_DIR / "evidence"))
    REPORT_DIR = Path(os.environ.get("WD_REPORT_DIR", BASE_DIR / "reports"))
    DATABASE_URL = os.environ.get("WD_DATABASE_URL", f"sqlite:///{DATA_DIR / 'wd_cyber.db'}")
    INSTANCE_NAME = os.environ.get("WD_INSTANCE_NAME", "WD CYBER TOOLKIT NEO")
    CORS_ORIGINS = parse_cors_origins(os.environ.get("WD_CORS_ORIGINS", ""))
    SESSION_TTL_MINUTES = int(os.environ.get("WD_SESSION_TTL_MINUTES", "480"))
    AUTHZ_TTL_MINUTES = int(os.environ.get("WD_AUTHZ_TTL_MINUTES", "60"))
    AUTHZ_MAX_TTL_MINUTES = int(os.environ.get("WD_AUTHZ_MAX_TTL_MINUTES", "720"))
    MAX_LOGIN_FAILURES = int(os.environ.get("WD_MAX_LOGIN_FAILURES", "5"))
    LOCKOUT_MINUTES = int(os.environ.get("WD_LOCKOUT_MINUTES", "15"))
    RATE_LIMIT_ATTEMPTS = int(os.environ.get("WD_RATE_LIMIT_ATTEMPTS", "10"))
    RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("WD_RATE_LIMIT_WINDOW_SECONDS", "60"))
    DEFAULT_CMD_TIMEOUT = int(os.environ.get("WD_CMD_TIMEOUT", "120"))
    MAX_CMD_TIMEOUT = int(os.environ.get("WD_MAX_CMD_TIMEOUT", "600"))
    LAB_BIND_HOST = os.environ.get("WD_LAB_BIND_HOST", "127.0.0.1")
    ARTAX_ENABLED = os.environ.get("WD_ARTAX_ENABLED", "1") == "1"
    ARTAX_BASE_URL = os.environ.get("WD_ARTAX_BASE_URL", "")
    ARTAX_API_KEY = os.environ.get("WD_ARTAX_API_KEY", "")
    ARTAX_MODEL = os.environ.get("WD_ARTAX_MODEL", "artax")
    ARTAX_TIMEOUT = int(os.environ.get("WD_ARTAX_TIMEOUT", "120"))
    ARTAX_MAX_CONTEXT_FINDINGS = int(os.environ.get("WD_ARTAX_MAX_CONTEXT_FINDINGS", "40"))
    BOOTSTRAP_USER = os.environ.get("WD_ADMIN_USER")
    BOOTSTRAP_PASSWORD = os.environ.get("WD_ADMIN_PASSWORD")
    BOOTSTRAP_PIN = os.environ.get("WD_ADMIN_PIN")
    BOOTSTRAP_SHORTCUT = os.environ.get("WD_SHORTCUT")
    FORCE_PASSWORD_CHANGE = os.environ.get("WD_FORCE_PASSWORD_CHANGE", "1") == "1"
