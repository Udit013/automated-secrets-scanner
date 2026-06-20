from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


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


class StartScanRequest(BaseModel):
    source_type: str = Field(..., pattern="^(github|paste)$")
    source_ref: str  # GitHub URL or raw code content
    scan_git_history: bool = False
    max_commits: int = Field(default=100, ge=1, le=1000)
    min_entropy: float = Field(default=3.5, ge=0.0, le=8.0)


class ScheduleCreate(BaseModel):
    name: str
    source_type: str = Field(..., pattern="^(github|paste)$")
    source_ref: str
    cron_expression: str  # standard 5-field cron
    scan_git_history: bool = False


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
