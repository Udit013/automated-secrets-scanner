import re

from apscheduler.triggers.cron import CronTrigger
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Literal, Optional, List
from datetime import datetime, timedelta, timezone

# Public API guardrails
MAX_PASTE_BYTES = 512 * 1024  # 512 KB of pasted code is plenty
_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}/?$"
)


class FindingOut(BaseModel):
    id: str
    scan_id: str
    file_path: str
    line_number: int
    secret_type: str
    matched_string: str
    entropy: float
    severity: str
    confidence: str
    context: str
    commit_hash: Optional[str]
    remediation: str
    is_in_history: bool

    risk_score: int = 0
    risk_factors: Optional[List[str]] = None
    occurrences: int = 1

    introduced_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    exposure_days: Optional[int] = None
    commits_affected: Optional[int] = None
    authors_count: Optional[int] = None

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: str
    source_type: str
    source_ref: str
    scan_git_history: bool
    max_commits: int
    min_entropy: float
    status: str
    total_findings: int
    files_scanned: int
    progress: int
    error_message: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]
    findings: List[FindingOut] = []

    model_config = {"from_attributes": True}


class ScanListItem(BaseModel):
    id: str
    source_type: str
    source_ref: str
    status: str
    total_findings: int
    files_scanned: int
    progress: int
    created_at: datetime
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True}


def _validate_source(source_type: str, source_ref: str) -> str:
    if not source_ref or not source_ref.strip():
        raise ValueError("source_ref must not be empty")
    if source_type == "github":
        candidate = source_ref.strip().removesuffix(".git")
        if not _GITHUB_URL_RE.match(candidate):
            raise ValueError(
                "source_ref must be a GitHub repository URL like "
                "https://github.com/owner/repo"
            )
        return candidate.rstrip("/")
    if len(source_ref.encode("utf-8", errors="ignore")) > MAX_PASTE_BYTES:
        raise ValueError(f"Pasted content exceeds {MAX_PASTE_BYTES // 1024} KB limit")
    return source_ref


class StartScanRequest(BaseModel):
    source_type: str = Field(..., pattern="^(github|paste)$")
    source_ref: str  # GitHub URL or raw code content
    scan_git_history: bool = False
    max_commits: int = Field(default=100, ge=1, le=1000)
    min_entropy: float = Field(default=3.5, ge=0.0, le=8.0)

    @model_validator(mode="after")
    def _check_source(self):
        self.source_ref = _validate_source(self.source_type, self.source_ref)
        return self


MIN_SCHEDULE_INTERVAL = timedelta(minutes=15)


def _validate_cron(expr: str) -> str:
    """
    Parse with the same trigger APScheduler will use, so a bad field value
    is a 422 here rather than a 500 at registration. Also enforce a floor
    on frequency: schedules run unattended against a public, unauthenticated
    API, and an every-minute scan with history would monopolise the server.
    """
    parts = expr.strip().split()
    if len(parts) != 5:
        raise ValueError("cron_expression must have exactly 5 fields")
    minute, hour, day, month, weekday = parts
    try:
        trigger = CronTrigger(
            minute=minute, hour=hour, day=day, month=month,
            day_of_week=weekday, timezone=timezone.utc,
        )
    except ValueError as e:
        raise ValueError(f"Invalid cron expression: {e}") from None

    # Sample upcoming fire times; the tightest gap is the effective interval.
    fire = trigger.get_next_fire_time(None, datetime.now(timezone.utc))
    for _ in range(24):
        if fire is None:
            break
        nxt = trigger.get_next_fire_time(fire, fire)
        if nxt is None:
            break
        if nxt - fire < MIN_SCHEDULE_INTERVAL:
            raise ValueError("Schedules may run at most once every 15 minutes")
        fire = nxt
    return " ".join(parts)


class ScheduleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    # Only repositories can be rescanned on a schedule; pasted content is
    # never stored, so there would be nothing to rescan.
    source_type: str = Field(..., pattern="^github$")
    source_ref: str
    cron_expression: str  # standard 5-field cron
    scan_git_history: bool = False

    @model_validator(mode="after")
    def _check_source(self):
        self.source_ref = _validate_source(self.source_type, self.source_ref)
        return self

    @field_validator("cron_expression")
    @classmethod
    def _check_cron(cls, v: str) -> str:
        return _validate_cron(v)


class ScheduleOut(BaseModel):
    id: str
    name: str
    source_type: str
    source_ref: str
    cron_expression: str
    scan_git_history: bool
    enabled: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    last_scan_id: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class StatsOut(BaseModel):
    total_scans: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    by_type: dict
    recent_scans: List[ScanListItem]
    findings_over_time: List[dict]  # [{date, count}]
    # Open credentials across the latest scan of every project — unlike the
    # counts above, de-duplicated and net of triage.
    exposure: Optional["ExposureOut"] = None


# ─── Differential scanning ──────────────────────────────────────────────────

class DiffFinding(BaseModel):
    secret_type: str
    severity: str
    file_path: str
    line_number: int
    risk_score: int = 0


class ScanDiffOut(BaseModel):
    has_baseline: bool
    baseline_scan_id: Optional[str] = None
    baseline_created_at: Optional[datetime] = None
    current_total: int = 0
    baseline_total: int = 0
    new_count: int = 0
    resolved_count: int = 0
    unchanged_count: int = 0
    net_change: int = 0  # current_total - baseline_total
    new_findings: List[DiffFinding] = []
    resolved_findings: List[DiffFinding] = []


# ─── Projects & credential inventory ────────────────────────────────────────

CredentialStatus = Literal["open", "rotated", "false_positive", "accepted_risk"]
MAX_REVIEW_WINDOW = timedelta(days=366)


class CredentialLocation(BaseModel):
    file_path: str
    line_number: int
    in_history: bool
    commit_hash: Optional[str] = None


class CredentialOut(BaseModel):
    fingerprint: str
    secret_type: str
    secret_types: List[str]
    severity: str
    risk_score: int
    risk_factors: List[str]
    masked_value: str
    status: str                       # effective: an expired accepted risk reads "open"
    stored_status: str
    review_overdue: bool
    review_by: Optional[datetime] = None
    note: str
    triaged_at: Optional[datetime] = None
    exposure: Literal["working_tree", "history_only"]
    first_seen: Optional[datetime] = None
    exposure_days: Optional[int] = None
    commits_affected: Optional[int] = None
    authors_count: Optional[int] = None
    location_count: int
    locations: List[CredentialLocation]
    remediation: str
    rotation_url: str


class CredentialSummary(BaseModel):
    total: int
    open: int
    open_by_severity: dict[str, int]
    open_history_only: int
    rotated: int
    accepted_risk: int
    false_positive: int
    review_overdue: int


class ProjectSchedule(BaseModel):
    id: str
    cron_expression: str
    enabled: bool
    next_run_at: Optional[datetime] = None


class ProjectOut(BaseModel):
    slug: str
    source_ref: str
    last_scan_id: Optional[str] = None
    last_scanned_at: Optional[datetime] = None
    files_scanned: int
    history_scanned: bool
    latest_status: Optional[str] = None
    latest_scan_id: Optional[str] = None
    summary: CredentialSummary
    schedule: Optional[ProjectSchedule] = None


class TrendPoint(BaseModel):
    scan_id: str
    completed_at: Optional[datetime] = None
    credentials: int
    open: int
    critical_open: int
    new: int
    removed: int


class ProjectDetailOut(ProjectOut):
    trend: List[TrendPoint]


class CredentialsOut(BaseModel):
    scan_id: Optional[str] = None
    credentials: List[CredentialOut]


class TriageRequest(BaseModel):
    status: CredentialStatus
    note: str = Field(default="", max_length=2000)
    # Required for accepted_risk, ignored otherwise: a waiver must expire.
    review_by: Optional[datetime] = None

    @model_validator(mode="after")
    def _check_review(self):
        if self.status != "accepted_risk":
            self.review_by = None
            return self
        if self.review_by is None:
            raise ValueError("Accepting a risk requires a review_by date")
        review = self.review_by
        if review.tzinfo is not None:  # stored naive-UTC, like every timestamp here
            review = review.astimezone(timezone.utc).replace(tzinfo=None)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if review <= now:
            raise ValueError("review_by must be in the future")
        if review > now + MAX_REVIEW_WINDOW:
            raise ValueError("review_by must be within a year")
        self.review_by = review
        return self


class ExposureOut(BaseModel):
    projects: int
    open: int
    open_history_only: int
    open_by_severity: dict[str, int]
    review_overdue: int


StatsOut.model_rebuild()
