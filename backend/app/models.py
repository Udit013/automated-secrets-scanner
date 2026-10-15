import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    String, Integer, Float, Boolean, DateTime, Text, ForeignKey, JSON, UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def utcnow_naive() -> datetime:
    """Timezone-aware now, stored naive-UTC (SQLite has no tz support)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    source_type: Mapped[str] = mapped_column(String(20))  # github | upload | paste
    # GitHub URL, or a `paste:<digest>` label (pasted content is never stored).
    # Short in both cases, so it is safe to index; the diff and project views
    # look scans up by it.
    source_ref: Mapped[str] = mapped_column(String(300), index=True)
    scan_git_history: Mapped[bool] = mapped_column(Boolean, default=False)
    max_commits: Mapped[int] = mapped_column(Integer, default=100)
    min_entropy: Mapped[float] = mapped_column(Float, default=3.5)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)  # queued|running|completed|failed
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    progress: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    file_path: Mapped[str] = mapped_column(Text)
    line_number: Mapped[int] = mapped_column(Integer)
    secret_type: Mapped[str] = mapped_column(String(60), index=True)
    matched_string: Mapped[str] = mapped_column(Text)
    entropy: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(10), index=True)  # CRITICAL|HIGH|MEDIUM|LOW
    confidence: Mapped[str] = mapped_column(String(10))
    context: Mapped[str] = mapped_column(Text)
    commit_hash: Mapped[str | None] = mapped_column(String(40), nullable=True)
    remediation: Mapped[str] = mapped_column(Text, default="")
    is_in_history: Mapped[bool] = mapped_column(Boolean, default=False)

    # Exposure Risk Score (0-100) + transparent reasoning
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_factors: Mapped[list | None] = mapped_column(JSON, nullable=True)  # ["Critical severity", ...]
    occurrences: Mapped[int] = mapped_column(Integer, default=1)

    # Secret lifecycle (populated when git history is scanned)
    introduced_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    exposure_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    commits_affected: Mapped[int | None] = mapped_column(Integer, nullable=True)
    authors_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Credential identity across files, commits, and scans (HMAC; never the
    # raw secret). Null only for rows written before fingerprints existed.
    fingerprint: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(120))
    source_type: Mapped[str] = mapped_column(String(20))
    source_ref: Mapped[str] = mapped_column(Text)
    cron_expression: Mapped[str] = mapped_column(String(60))  # e.g. "0 9 * * 1"
    scan_git_history: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive)


CREDENTIAL_STATUSES = ("open", "rotated", "false_positive", "accepted_risk")


class CredentialState(Base):
    """
    Triage decision for one credential in one project. Keyed by fingerprint
    rather than by finding, so it carries over to every future scan and to
    every file and commit the credential appears in.
    """

    __tablename__ = "credential_states"
    __table_args__ = (UniqueConstraint("source_ref", "fingerprint", name="uq_credential_state"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    source_ref: Mapped[str] = mapped_column(String(300), index=True)
    fingerprint: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(20), default="open")
    note: Mapped[str] = mapped_column(Text, default="")
    # Accepted risks expire: past this date the credential counts as open
    # again, so a waiver can't silently outlive the reason for it.
    review_by: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive, onupdate=utcnow_naive)


class AppSetting(Base):
    """Small key/value store for install-level settings (e.g. the fingerprint key)."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(60), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
