-- WD CYBER TOOLKIT NEO — reference SQLite schema
-- Generated from backend/database.py (SQLAlchemy). For PostgreSQL, run the app
-- once against WD_DATABASE_URL and SQLAlchemy will create the equivalent schema.
--
-- Regenerate with:
--   python3 -c "from backend.database import Base, engine; Base.metadata.create_all(engine)"

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
  id                   VARCHAR(32) PRIMARY KEY,
  username             VARCHAR(64) NOT NULL UNIQUE,
  role                 VARCHAR(32) DEFAULT 'operator',
  password_hash        TEXT NOT NULL,          -- Argon2id
  pin_hash             TEXT NOT NULL,          -- Argon2id (stage 2)
  must_change_password BOOLEAN DEFAULT 0,
  is_active            BOOLEAN DEFAULT 1,
  failed_count         INTEGER DEFAULT 0,
  locked_until         DATETIME,
  last_login_at        DATETIME,
  created_at           DATETIME
);

CREATE TABLE IF NOT EXISTS shortcuts (
  id         VARCHAR(32) PRIMARY KEY,
  code_hash  TEXT NOT NULL,                    -- Argon2id of the WD shortcut
  label      VARCHAR(120) DEFAULT 'operator',
  active     BOOLEAN DEFAULT 1,
  created_at DATETIME
);

CREATE TABLE IF NOT EXISTS sessions (
  id          VARCHAR(32) PRIMARY KEY,
  token_hash  VARCHAR(128) NOT NULL UNIQUE,    -- sha256(token), never the token
  user_id     VARCHAR(32) NOT NULL REFERENCES users(id),
  shortcut_id VARCHAR(32),
  stage       INTEGER DEFAULT 1,
  ip          VARCHAR(64)  DEFAULT '',
  user_agent  VARCHAR(256) DEFAULT '',
  created_at  DATETIME,
  expires_at  DATETIME NOT NULL,
  revoked     BOOLEAN DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_sessions_token ON sessions(token_hash);

CREATE TABLE IF NOT EXISTS scope_entries (
  id          VARCHAR(32) PRIMARY KEY,
  target      VARCHAR(255) NOT NULL,
  target_type VARCHAR(32) DEFAULT 'auto',      -- ip|cidr|domain|url|can|ics_endpoint
  description TEXT DEFAULT '',
  created_by  VARCHAR(64) DEFAULT '',
  active      BOOLEAN DEFAULT 1,
  created_at  DATETIME,
  CONSTRAINT uq_scope_target UNIQUE (target, target_type)
);

CREATE TABLE IF NOT EXISTS authorizations (
  id             VARCHAR(32) PRIMARY KEY,
  user_id        VARCHAR(32) NOT NULL,
  assessment_id  VARCHAR(32),
  scope_snapshot TEXT,                          -- JSON: per-target match at issue time
  targets        TEXT,                          -- JSON array
  confirmed      BOOLEAN DEFAULT 0,
  revoked        BOOLEAN DEFAULT 0,
  created_at     DATETIME,
  expires_at     DATETIME NOT NULL,
  note           TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS assessments (
  id          VARCHAR(32) PRIMARY KEY,
  name        VARCHAR(160) NOT NULL,
  template    VARCHAR(64) NOT NULL,
  module      VARCHAR(64) NOT NULL,
  mode        VARCHAR(16) DEFAULT 'lab',        -- live|lab
  intensity   VARCHAR(16) DEFAULT 'normal',
  targets     TEXT,                             -- JSON array
  params      TEXT,                             -- JSON object
  status      VARCHAR(24) DEFAULT 'created',
  operator    VARCHAR(64) DEFAULT '',
  authz_id    VARCHAR(32),
  risk_score  FLOAT,
  summary     TEXT,                             -- JSON: counts, duration, worst severity
  created_at  DATETIME,
  started_at  DATETIME,
  ended_at    DATETIME
);

CREATE TABLE IF NOT EXISTS findings (
  id              VARCHAR(32) PRIMARY KEY,
  assessment_id   VARCHAR(32) NOT NULL REFERENCES assessments(id),
  title           VARCHAR(255) NOT NULL,
  severity        VARCHAR(16) DEFAULT 'info',
  description     TEXT DEFAULT '',
  evidence_source VARCHAR(24) DEFAULT 'live',   -- live|lab|local|unavailable
  cvss_score      FLOAT,
  cvss_vector     VARCHAR(255),
  cwe             TEXT,                         -- JSON array
  remediation     TEXT DEFAULT '',
  asset           VARCHAR(255) DEFAULT '',
  evidence        TEXT,                         -- JSON array of evidence records
  check_id        VARCHAR(120) DEFAULT '',
  created_at      DATETIME
);
CREATE INDEX IF NOT EXISTS ix_findings_assessment ON findings(assessment_id);

CREATE TABLE IF NOT EXISTS audit_events (
  id        VARCHAR(32) PRIMARY KEY,
  seq       INTEGER NOT NULL,
  ts        DATETIME,
  actor     VARCHAR(64)  DEFAULT 'system',
  action    VARCHAR(80)  NOT NULL,
  target    VARCHAR(255) DEFAULT '',
  detail    TEXT,                               -- JSON object
  prev_hash VARCHAR(64) DEFAULT '',
  hash      VARCHAR(64) NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_seq ON audit_events(seq);

CREATE TABLE IF NOT EXISTS jobs (
  id            VARCHAR(32) PRIMARY KEY,
  assessment_id VARCHAR(32) NOT NULL,
  status        VARCHAR(24) DEFAULT 'queued',
  progress      INTEGER DEFAULT 0,
  log           TEXT,                            -- JSON array of {at,level,message}
  error         TEXT DEFAULT '',
  created_at    DATETIME,
  ended_at      DATETIME
);

CREATE TABLE IF NOT EXISTS artifacts (
  id            VARCHAR(32) PRIMARY KEY,
  assessment_id VARCHAR(32) NOT NULL,
  name          VARCHAR(255) NOT NULL,
  path          TEXT NOT NULL,
  kind          VARCHAR(32) DEFAULT 'file',
  size          INTEGER DEFAULT 0,
  sha256        VARCHAR(64) DEFAULT '',
  created_at    DATETIME
);

CREATE TABLE IF NOT EXISTS state_kv (
  key        VARCHAR(80) PRIMARY KEY,
  value      TEXT,                               -- JSON (e.g. emergency_stop)
  updated_at DATETIME
);
