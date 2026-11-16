"""SQLAlchemy models + engine/session factory for WD CYBER TOOLKIT NEO.

SQLite is the default single-file store. Point WD_DATABASE_URL at PostgreSQL
(e.g. postgresql+psycopg://user:pass@host:5432/wd) for multi-operator use;
the models and stores are dialect-agnostic.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from backend import config


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return uuid.uuid4().hex


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="operator")
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    pin_hash: Mapped[str] = mapped_column(Text, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Shortcut(Base):
    __tablename__ = "shortcuts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    code_hash: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str] = mapped_column(String(120), default="operator")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    user_id: Mapped[str] = mapped_column(String(32), ForeignKey("users.id"), nullable=False)
    shortcut_id: Mapped[str | None] = mapped_column(String(32))
    stage: Mapped[int] = mapped_column(Integer, default=1)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class ScopeEntry(Base):
    __tablename__ = "scope_entries"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), default="auto")
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("target", "target_type", name="uq_scope_target"),)


class Assessment(Base):
    __tablename__ = "assessments"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    template: Mapped[str] = mapped_column(String(64), nullable=False)
    module: Mapped[str] = mapped_column(String(64), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), default="lab")
    intensity: Mapped[str] = mapped_column(String(16), default="normal")
    targets: Mapped[Any] = mapped_column(JSON, default=list)
    params: Mapped[Any] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="created")
    operator: Mapped[str] = mapped_column(String(64), default="")
    authz_id: Mapped[str | None] = mapped_column(String(32))
    risk_score: Mapped[float | None] = mapped_column(Float)
    summary: Mapped[Any] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class Authorization(Base):
    __tablename__ = "authorizations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(32), nullable=False)
    assessment_id: Mapped[str | None] = mapped_column(String(32))
    scope_snapshot: Mapped[Any] = mapped_column(JSON, default=list)
    targets: Mapped[Any] = mapped_column(JSON, default=list)
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    note: Mapped[str] = mapped_column(Text, default="")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(String(32), ForeignKey("assessments.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    description: Mapped[str] = mapped_column(Text, default="")
    evidence_source: Mapped[str] = mapped_column(String(24), default="live")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    cwe: Mapped[Any] = mapped_column(JSON, default=list)
    remediation: Mapped[str] = mapped_column(Text, default="")
    asset: Mapped[str] = mapped_column(String(255), default="")
    evidence: Mapped[Any] = mapped_column(JSON, default=list)
    check_id: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    seq: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(64), default="system")
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    target: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[Any] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), nullable=False)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    log: Mapped[Any] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), default="file")
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class StateKV(Base):
    __tablename__ = "state_kv"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON, default=dict)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


config.ensure_dirs()
connect_args = {"check_same_thread": False} if config.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(config.DATABASE_URL, future=True, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def kv_get(db, key: str, default: Any = None) -> Any:
    """Read a JSON value, bypassing any stale identity-map copy.

    Sessions use expire_on_commit=False, so a previously loaded row would keep
    serving its old JSON payload after another write. `populate_existing`
    forces the freshest stored value, which matters for the emergency-stop flag.
    """
    from sqlalchemy import select
    row = db.execute(
        select(StateKV).where(StateKV.key == key).execution_options(populate_existing=True)
    ).scalar_one_or_none()
    return default if row is None else row.value


def kv_set(db, key: str, value: Any, commit: bool = True) -> None:
    """Persist a JSON value.

    A deep copy is assigned on every write: SQLAlchemy's plain JSON column does
    not track in-place mutation, so re-assigning the same dict object (the
    common "read, update, write back" pattern) would silently not persist.

    ``commit=False`` stages the change so a caller can commit it atomically with
    other writes (the audit chain appends its anchor that way).
    """
    import copy
    fresh = copy.deepcopy(value)
    row = db.get(StateKV, key)
    if row is None:
        db.add(StateKV(key=key, value=fresh, updated_at=utcnow()))
    else:
        row.value = fresh
        row.updated_at = utcnow()
    if commit:
        db.commit()
