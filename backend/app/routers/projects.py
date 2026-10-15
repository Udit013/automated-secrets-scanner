"""
Projects: every GitHub repository CipherWatch has scanned, viewed as a
ledger of credentials with persistent triage.
"""

import re
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import CredentialState, Finding, Scan
from ..schemas import CredentialsOut, CredentialOut, ProjectDetailOut, ProjectOut, TriageRequest
from ..services import inventory

router = APIRouter(prefix="/projects", tags=["projects"])

Owner = Annotated[str, Path(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")]
Repo = Annotated[str, Path(pattern=r"^[A-Za-z0-9._-]{1,100}$")]
_FINGERPRINT_RE = re.compile(r"^[0-9a-fl][0-9a-f]{31}$")


async def _require_project(db: AsyncSession, owner: str, repo: str) -> str:
    source_ref = inventory.source_ref_for(owner, repo)
    exists = (
        await db.execute(select(Scan.id).where(Scan.source_ref == source_ref).limit(1))
    ).scalar_one_or_none()
    if exists is None:
        raise HTTPException(404, "No scans exist for this repository yet")
    return source_ref


@router.get("", response_model=list[ProjectOut])
async def list_projects(db: Annotated[AsyncSession, Depends(get_db)]):
    projects = [await inventory.project_overview(db, ref) for ref in await inventory.github_projects(db)]
    # Most urgent first: open critical, then open high, then any open.
    projects.sort(key=lambda p: (
        -p["summary"]["open_by_severity"]["CRITICAL"],
        -p["summary"]["open_by_severity"]["HIGH"],
        -p["summary"]["open"],
        p["slug"],
    ))
    return projects


@router.get("/{owner}/{repo}", response_model=ProjectDetailOut)
async def get_project(owner: Owner, repo: Repo, db: Annotated[AsyncSession, Depends(get_db)]):
    source_ref = await _require_project(db, owner, repo)
    overview = await inventory.project_overview(db, source_ref)
    overview["trend"] = await inventory.project_trend(db, source_ref)
    return overview


@router.get("/{owner}/{repo}/credentials", response_model=CredentialsOut)
async def list_credentials(
    owner: Owner,
    repo: Repo,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: Optional[str] = Query(None, pattern="^(open|rotated|false_positive|accepted_risk)$"),
    severity: Optional[str] = Query(None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$"),
    exposure: Optional[str] = Query(None, pattern="^(working_tree|history_only)$"),
):
    source_ref = await _require_project(db, owner, repo)
    scan, creds = await inventory.project_inventory(db, source_ref)
    if status:
        creds = [c for c in creds if c["status"] == status]
    if severity:
        creds = [c for c in creds if c["severity"] == severity]
    if exposure:
        creds = [c for c in creds if c["exposure"] == exposure]
    return {"scan_id": scan.id if scan else None, "credentials": creds}


@router.put("/{owner}/{repo}/credentials/{fingerprint}", response_model=CredentialOut)
async def triage_credential(
    owner: Owner,
    repo: Repo,
    fingerprint: str,
    body: TriageRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not _FINGERPRINT_RE.match(fingerprint):
        raise HTTPException(422, "Malformed credential fingerprint")
    source_ref = await _require_project(db, owner, repo)

    # Only credentials this project has actually produced can be triaged —
    # otherwise the endpoint would accept arbitrary keys. Stored fingerprints
    # are an indexed lookup; "l…" keys stand in for rows written before
    # fingerprints existed and are recomputed from those rows.
    query = (
        select(Finding).join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.source_ref == source_ref, Scan.status == "completed")
    )
    query = query.where(
        Finding.fingerprint.is_(None) if fingerprint.startswith("l") else Finding.fingerprint == fingerprint
    )
    matching = [f for f in (await db.execute(query)).scalars().all()
                if inventory.credential_key(f) == fingerprint]
    if not matching:
        raise HTTPException(404, "Credential not found in this project")

    async def upsert() -> None:
        state = (
            await db.execute(
                select(CredentialState).where(
                    CredentialState.source_ref == source_ref, CredentialState.fingerprint == fingerprint
                )
            )
        ).scalar_one_or_none()
        if state is None:
            state = CredentialState(source_ref=source_ref, fingerprint=fingerprint)
            db.add(state)
        state.status = body.status
        state.note = body.note.strip()
        state.review_by = body.review_by
        await db.commit()

    try:
        await upsert()
    except IntegrityError:
        # Two first decisions raced on the unique (project, fingerprint) key;
        # the other one created the row, so update it instead.
        await db.rollback()
        await upsert()

    _, creds = await inventory.project_inventory(db, source_ref)
    for c in creds:
        if c["fingerprint"] == fingerprint:
            return c
    # Triaged a credential that only exists in an older scan: report it from there.
    states = await inventory.load_states(db, source_ref)
    return inventory.group_credentials(matching, states)[0]
