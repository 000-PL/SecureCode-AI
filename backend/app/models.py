"""Database models."""
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .core.database import Base

LongText = Text().with_variant(mysql.LONGTEXT(), "mysql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(190), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(255), default="untitled")
    language: Mapped[str] = mapped_column(String(30), default="unknown")
    code: Mapped[str] = mapped_column(LongText)
    status: Mapped[str] = mapped_column(String(20), default="success")        # success | failed
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    kind: Mapped[str] = mapped_column(String(20), default="scan")             # scan | validation
    parent_scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    iteration: Mapped[int] = mapped_column(Integer, default=1)
    score: Mapped[int] = mapped_column(Integer, default=0)
    grade: Mapped[str] = mapped_column(String(2), default="-")
    rating: Mapped[str] = mapped_column(String(60), default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    counts: Mapped[dict] = mapped_column(JSON, default=dict)
    breakdown: Mapped[list] = mapped_column(JSON, default=list)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    lines_scanned: Mapped[int] = mapped_column(Integer, default=0)
    execution: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan", order_by="Finding.id")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(60))
    title: Mapped[str] = mapped_column(String(160))
    severity: Mapped[str] = mapped_column(String(10))
    cwe: Mapped[str] = mapped_column(String(20), default="")
    owasp: Mapped[str] = mapped_column(String(100), default="")
    line: Mapped[int] = mapped_column(Integer)
    snippet: Mapped[str] = mapped_column(Text, default="")
    message: Mapped[str] = mapped_column(Text, default="")
    cause: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    how_to_fix: Mapped[str] = mapped_column(Text, default="")
    fixable: Mapped[bool] = mapped_column(Boolean, default=False)
    fix: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    scan = relationship("Scan", back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(60))
    detail: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
