import uuid
from datetime import datetime
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    source_type: Mapped[str] = mapped_column(String(20))  # github | upload | paste
    source_ref: Mapped[str] = mapped_column(Text)  # URL, filename, or "paste"
    scan_git_history: Mapped[bool] = mapped_column(Boolean, default=False)
    max_commits: Mapped[int] = mapped_column(Integer, default=100)
    min_entropy: Mapped[float] = mapped_column(Float, default=3.5)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|completed|failed
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    progress: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"))
    file_path: Mapped[str] = mapped_column(Text)
    line_number: Mapped[int] = mapped_column(Integer)
    secret_type: Mapped[str] = mapped_column(String(60))
    matched_string: Mapped[str] = mapped_column(Text)
    entropy: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(10))  # CRITICAL|HIGH|MEDIUM|LOW
    confidence: Mapped[str] = mapped_column(String(10))
    context: Mapped[str] = mapped_column(Text)
    commit_hash: Mapped[str | None] = mapped_column(String(40), nullable=True)
    remediation: Mapped[str] = mapped_column(Text, default="")
    is_in_history: Mapped[bool] = mapped_column(Boolean, default=False)

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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
