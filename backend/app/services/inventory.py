"""
Credential inventory: turns per-line findings into a ledger of credentials.

A scanner reports lines. Engineers rotate credentials. One leaked key can
appear in several files, in the working tree and in history, across every
scan of a repository — this module collapses all of that into one entry per
credential, joins it with its triage state, and answers the questions that
matter: is it still exposed, since when, and what changed since last scan.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import CredentialState, Finding, Scan, ScanSchedule, utcnow_naive
from ..scanner.patterns import PATTERNS

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_ROTATION_URLS = {p.name: p.rotation_url for p in PATTERNS}
_GITHUB_RE = re.compile(r"^https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})$")
GITHUB_PREFIX = "https://github.com/"


# ─── Identity ────────────────────────────────────────────────────────────────

def project_slug(source_ref: str) -> Optional[str]:
    m = _GITHUB_RE.match(source_ref or "")
    return f"{m.group(1)}/{m.group(2)}" if m else None


def source_ref_for(owner: str, repo: str) -> str:
    return f"{GITHUB_PREFIX}{owner}/{repo}"


def credential_key(f: Finding) -> str:
    """Fingerprint, or a location-scoped stand-in for rows that predate them."""
    if f.fingerprint:
        return f.fingerprint
    digest = hashlib.sha256(f"{f.secret_type}|{f.matched_string}|{f.file_path}".encode()).hexdigest()
    return "l" + digest[:31]


def effective_status(state: Optional[CredentialState], now: Optional[datetime] = None) -> tuple[str, bool]:
    """Returns (status, review_overdue). An expired accepted risk counts as open."""
    if state is None:
        return "open", False
    if state.status == "accepted_risk" and state.review_by and state.review_by < (now or utcnow_naive()):
        return "open", True
    return state.status, False


# ─── Queries ─────────────────────────────────────────────────────────────────

async def latest_completed_scan(db: AsyncSession, source_ref: str, before: Optional[datetime] = None) -> Optional[Scan]:
    q = select(Scan).where(Scan.source_ref == source_ref, Scan.status == "completed")
    if before is not None:
        q = q.where(Scan.created_at < before)
    return (await db.execute(q.order_by(Scan.created_at.desc()).limit(1))).scalar_one_or_none()


async def scan_findings(db: AsyncSession, scan_id: str) -> list[Finding]:
    return list((await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all())


async def load_states(db: AsyncSession, source_ref: str) -> dict[str, CredentialState]:
    rows = (await db.execute(select(CredentialState).where(CredentialState.source_ref == source_ref))).scalars()
    return {r.fingerprint: r for r in rows}


async def first_seen_map(db: AsyncSession, source_ref: str) -> dict[str, datetime]:
    """Earliest completed scan of this project in which each credential appeared."""
    # Only the columns credential_key needs: this spans every scan of the project.
    rows = (
        await db.execute(
            select(Finding.fingerprint, Finding.secret_type, Finding.matched_string,
                   Finding.file_path, Scan.created_at)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.source_ref == source_ref, Scan.status == "completed")
            .order_by(Scan.created_at)
        )
    ).all()
    seen: dict[str, datetime] = {}
    for row in rows:
        seen.setdefault(credential_key(row), row.created_at)
    return seen


async def github_projects(db: AsyncSession) -> list[str]:
    refs = (
        await db.execute(select(Scan.source_ref).where(Scan.source_type == "github").distinct())
    ).scalars().all()
    return sorted(r for r in refs if project_slug(r))


# ─── Grouping ────────────────────────────────────────────────────────────────

def group_credentials(
    findings: Iterable[Finding],
    states: dict[str, CredentialState],
    first_seen: Optional[dict[str, datetime]] = None,
    now: Optional[datetime] = None,
) -> list[dict]:
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(credential_key(f), []).append(f)

    now = now or utcnow_naive()
    out = []
    for key, items in groups.items():
        lead = max(items, key=lambda f: (SEVERITY_RANK.get(f.severity, 0), f.risk_score or 0))
        state = states.get(key)
        status, overdue = effective_status(state, now)
        in_head = any(not f.is_in_history for f in items)
        introduced = [f.introduced_at for f in items if f.introduced_at]
        seen = (first_seen or {}).get(key)
        candidates = [d for d in [seen, min(introduced) if introduced else None] if d]
        locations = sorted(
            {(f.file_path, f.line_number, f.is_in_history, f.commit_hash) for f in items},
            key=lambda loc: (loc[2], loc[0], loc[1]),
        )
        out.append({
            "fingerprint": key,
            "secret_type": lead.secret_type,
            "secret_types": sorted({f.secret_type for f in items}),
            "severity": lead.severity,
            "risk_score": max(f.risk_score or 0 for f in items),
            "risk_factors": lead.risk_factors or [],
            "masked_value": lead.matched_string,
            "status": status,
            "stored_status": state.status if state else "open",
            "review_overdue": overdue,
            "review_by": state.review_by if state else None,
            "note": state.note if state else "",
            "triaged_at": state.updated_at if state else None,
            "exposure": "working_tree" if in_head else "history_only",
            "first_seen": min(candidates) if candidates else None,
            "exposure_days": max((f.exposure_days or 0) for f in items) or None,
            "commits_affected": max((f.commits_affected or 0) for f in items) or None,
            "authors_count": max((f.authors_count or 0) for f in items) or None,
            "location_count": len(locations),
            "locations": [
                {"file_path": p, "line_number": ln, "in_history": h, "commit_hash": c}
                for p, ln, h, c in locations
            ],
            "remediation": lead.remediation or "",
            "rotation_url": _ROTATION_URLS.get(lead.secret_type, ""),
        })

    status_rank = {"open": 0, "accepted_risk": 1, "rotated": 2, "false_positive": 3}
    out.sort(key=lambda c: (status_rank.get(c["status"], 9), -SEVERITY_RANK.get(c["severity"], 0), -c["risk_score"]))
    return out


def summarize(credentials: list[dict]) -> dict:
    open_ = [c for c in credentials if c["status"] == "open"]
    return {
        "total": len(credentials),
        "open": len(open_),
        "open_by_severity": {s: sum(1 for c in open_ if c["severity"] == s) for s in SEVERITY_RANK},
        "open_history_only": sum(1 for c in open_ if c["exposure"] == "history_only"),
        "rotated": sum(1 for c in credentials if c["status"] == "rotated"),
        "accepted_risk": sum(1 for c in credentials if c["status"] == "accepted_risk"),
        "false_positive": sum(1 for c in credentials if c["status"] == "false_positive"),
        "review_overdue": sum(1 for c in credentials if c["review_overdue"]),
    }


# ─── Composite views ─────────────────────────────────────────────────────────

async def project_inventory(
    db: AsyncSession, source_ref: str, with_first_seen: bool = True,
) -> tuple[Optional[Scan], list[dict]]:
    """
    The latest completed scan's credentials. `with_first_seen` walks every
    earlier scan of the project; summaries (stats, project lists) skip it
    because counts don't depend on it.
    """
    scan = await latest_completed_scan(db, source_ref)
    if scan is None:
        return None, []
    creds = group_credentials(
        await scan_findings(db, scan.id),
        await load_states(db, source_ref),
        await first_seen_map(db, source_ref) if with_first_seen else None,
    )
    return scan, creds


async def project_overview(db: AsyncSession, source_ref: str) -> dict:
    latest_any = (
        await db.execute(select(Scan).where(Scan.source_ref == source_ref).order_by(Scan.created_at.desc()).limit(1))
    ).scalar_one_or_none()
    scan, creds = await project_inventory(db, source_ref, with_first_seen=False)
    schedule = (
        await db.execute(select(ScanSchedule).where(ScanSchedule.source_ref == source_ref).limit(1))
    ).scalar_one_or_none()
    return {
        "slug": project_slug(source_ref),
        "source_ref": source_ref,
        "last_scan_id": scan.id if scan else None,
        "last_scanned_at": scan.completed_at if scan else None,
        "files_scanned": scan.files_scanned if scan else 0,
        "history_scanned": bool(scan and scan.scan_git_history),
        "latest_status": latest_any.status if latest_any else None,
        "latest_scan_id": latest_any.id if latest_any else None,
        "summary": summarize(creds),
        "schedule": (
            {"id": schedule.id, "cron_expression": schedule.cron_expression,
             "enabled": schedule.enabled, "next_run_at": schedule.next_run_at}
            if schedule else None
        ),
    }


async def project_trend(db: AsyncSession, source_ref: str, limit: int = 30) -> list[dict]:
    """Credentials per completed scan, oldest first, with what changed each time."""
    scans = list(reversed((
        await db.execute(
            select(Scan).where(Scan.source_ref == source_ref, Scan.status == "completed")
            .order_by(Scan.created_at.desc()).limit(limit)
        )
    ).scalars().all()))
    states = await load_states(db, source_ref)
    points, previous = [], set()
    for s in scans:
        creds = group_credentials(await scan_findings(db, s.id), states)
        keys = {c["fingerprint"] for c in creds}
        points.append({
            "scan_id": s.id,
            "completed_at": s.completed_at,
            "credentials": len(creds),
            "open": sum(1 for c in creds if c["status"] == "open"),
            "critical_open": sum(1 for c in creds if c["status"] == "open" and c["severity"] == "CRITICAL"),
            "new": len(keys - previous) if points else len(keys),
            "removed": len(previous - keys) if points else 0,
        })
        previous = keys
    return points


async def exposure_totals(db: AsyncSession) -> dict:
    """Open credentials across the latest scan of every GitHub project."""
    totals = {"projects": 0, "open": 0, "open_history_only": 0,
              "open_by_severity": {s: 0 for s in SEVERITY_RANK}, "review_overdue": 0}
    for ref in await github_projects(db):
        _, creds = await project_inventory(db, ref, with_first_seen=False)
        summary = summarize(creds)
        totals["projects"] += 1
        totals["open"] += summary["open"]
        totals["open_history_only"] += summary["open_history_only"]
        totals["review_overdue"] += summary["review_overdue"]
        for sev, n in summary["open_by_severity"].items():
            totals["open_by_severity"][sev] += n
    return totals


async def new_open_critical(db: AsyncSession, scan: Scan) -> list[dict]:
    """
    CRITICAL credentials in this scan that were absent from the previous scan
    of the same source and are not triaged away. Alerting on these instead
    of on every CRITICAL finding stops a scheduled scan from re-sending the
    same alert every run.
    """
    current = group_credentials(await scan_findings(db, scan.id), await load_states(db, scan.source_ref))
    previous_scan = await latest_completed_scan(db, scan.source_ref, before=scan.created_at)
    seen = set()
    if previous_scan is not None:
        seen = {credential_key(f) for f in await scan_findings(db, previous_scan.id)}
    return [c for c in current
            if c["severity"] == "CRITICAL" and c["status"] == "open" and c["fingerprint"] not in seen]
