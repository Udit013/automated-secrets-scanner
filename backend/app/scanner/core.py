"""
Enhanced secrets scanning engine.
Combines regex pattern matching, Shannon entropy analysis, and semantic heuristics.
"""

import re
import math
import os
from dataclasses import dataclass
from typing import Optional, AsyncIterator
from pathlib import Path

from datetime import datetime

from .patterns import PATTERNS, is_placeholder, is_test_file, SecretPattern
from .risk import compute_risk_score


@dataclass
class Finding:
    file_path: str
    line_number: int
    secret_type: str
    matched_string: str
    entropy: float
    severity: str
    confidence: str
    context: str
    commit_hash: Optional[str] = None
    remediation: str = ""
    is_in_history: bool = False
    # Risk + lifecycle (lifecycle stays None unless git history is scanned)
    risk_score: int = 0
    risk_factors: Optional[list] = None
    occurrences: int = 1
    introduced_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    exposure_days: Optional[int] = None
    commits_affected: Optional[int] = None
    authors_count: Optional[int] = None


SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".cpp", ".c", ".h",
    ".cs", ".go", ".rb", ".php", ".swift", ".kt", ".rs", ".scala",
    ".yaml", ".yml", ".json", ".xml", ".conf", ".config", ".ini",
    ".env", ".properties", ".sh", ".bash", ".zsh", ".fish",
    ".tf", ".tfvars", ".toml", ".gradle", ".pom", ".lock",
}

IGNORE_DIRS = {
    ".git", "node_modules", "venv", "__pycache__", ".idea", ".vscode",
    "build", "dist", "target", ".next", ".nuxt", "coverage", ".pytest_cache",
}

MIN_ENTROPY = 3.5


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for ch in data:
        counts[ord(ch)] = counts.get(ord(ch), 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _mask(secret: str, show: int = 4) -> str:
    if len(secret) <= show * 2:
        return "*" * len(secret)
    return secret[:show] + "*" * (len(secret) - show * 2) + secret[-show:]


def _confidence(entropy: float, pattern_match: bool) -> str:
    if pattern_match and entropy > 4.5:
        return "HIGH"
    if pattern_match and entropy > 3.5:
        return "MEDIUM"
    if entropy > 5.0:
        return "MEDIUM"
    return "LOW"


def scan_text(
    content: str,
    file_path: str = "string",
    min_entropy: float = MIN_ENTROPY,
    commit_hash: Optional[str] = None,
    is_history: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    is_test = is_test_file(file_path)
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        # Skip comment-only lines (basic heuristic)
        # Never skip PEM headers which look like "-----BEGIN..."
        stripped = line.strip()
        is_comment = stripped.startswith(("#", "//", "<!--"))
        is_block_comment = stripped.startswith(("* ", "*/")) or stripped == "*"
        is_sql_comment = stripped.startswith("--") and not stripped.startswith("-----BEGIN")
        if is_comment or is_block_comment or is_sql_comment:
            continue

        for pattern in PATTERNS:
            for match in re.finditer(pattern.regex, line, re.IGNORECASE):
                # Use the full match as the secret; only override with a group
                # if a non-trivial capturing group is clearly longer (e.g., generic API key pattern)
                matched_text = match.group(0)
                groups = [g for g in (match.groups() or []) if g and len(g) > 20]
                if groups:
                    matched_text = max(groups, key=len)

                if is_placeholder(matched_text):
                    continue

                entropy = _shannon_entropy(matched_text)

                if not pattern.format_specific and entropy < min_entropy:
                    continue

                # Test files downgrade severity by one level
                severity = pattern.severity
                if is_test:
                    severity = _downgrade(severity)

                confidence = _confidence(entropy, True)

                score, score_factors = compute_risk_score(
                    severity,
                    is_in_history=is_history,
                    entropy=entropy,
                )

                findings.append(
                    Finding(
                        file_path=file_path,
                        line_number=line_num,
                        secret_type=pattern.name,
                        matched_string=_mask(matched_text),
                        entropy=round(entropy, 2),
                        severity=severity,
                        confidence=confidence,
                        context=line.strip()[:200],
                        commit_hash=commit_hash,
                        remediation=pattern.remediation,
                        is_in_history=is_history,
                        risk_score=score,
                        risk_factors=score_factors,
                    )
                )

    return findings


def _downgrade(severity: str) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    idx = order.index(severity)
    return order[min(idx + 1, len(order) - 1)]


def scan_file(file_path: str, min_entropy: float = MIN_ENTROPY) -> list[Finding]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return scan_text(content, file_path, min_entropy)
    except OSError:
        return []


def scan_directory(
    directory: str, min_entropy: float = MIN_ENTROPY
) -> tuple[list[Finding], int]:
    all_findings: list[Finding] = []
    files_scanned = 0

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in files:
            fpath = os.path.join(root, fname)
            ext = Path(fpath).suffix
            if ext in SCANNABLE_EXTENSIONS or fname.startswith(".env"):
                findings = scan_file(fpath, min_entropy)
                all_findings.extend(findings)
                files_scanned += 1

    return all_findings, files_scanned


async def scan_directory_streaming(
    directory: str, min_entropy: float = MIN_ENTROPY
) -> AsyncIterator[tuple[str, list[Finding], int, int]]:
    """
    Yields (file_path, findings, files_done, total_files) as each file is processed.
    """
    all_files = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in files:
            fpath = os.path.join(root, fname)
            ext = Path(fpath).suffix
            if ext in SCANNABLE_EXTENSIONS or fname.startswith(".env"):
                all_files.append(fpath)

    total = len(all_files)
    for i, fpath in enumerate(all_files, 1):
        findings = scan_file(fpath, min_entropy)
        yield fpath, findings, i, total


def scan_git_history(
    repo_path: str,
    max_commits: int = 100,
    min_entropy: float = MIN_ENTROPY,
) -> tuple[list[Finding], int]:
    """
    Walk git history and build a *lifecycle* for every distinct secret:
    when it was first introduced, when it was last seen, how many commits
    and authors it spans, and how long it was exposed.

    Findings are de-duplicated by (file_path, secret_type, matched_string)
    so a secret living across 9 commits surfaces once — with the full
    exposure picture — rather than nine times.
    """
    try:
        import git  # type: ignore
    except ImportError:
        return [], 0

    try:
        repo = git.Repo(repo_path)
    except Exception:
        return [], 0

    # key -> aggregated lifecycle record
    agg: dict[tuple, dict] = {}
    files_scanned = 0

    commits = list(repo.iter_commits("HEAD", max_count=max_commits))
    for commit in commits:
        commit_dt = commit.committed_datetime.replace(tzinfo=None)
        author = (commit.author.email or commit.author.name or "unknown").lower()
        short_sha = commit.hexsha[:8]
        try:
            for item in commit.tree.traverse():
                if item.type != "blob":
                    continue
                ext = Path(item.path).suffix
                if ext not in SCANNABLE_EXTENSIONS and not item.path.split("/")[-1].startswith(".env"):
                    continue
                try:
                    content = item.data_stream.read().decode("utf-8", errors="ignore")
                except Exception:
                    continue
                files_scanned += 1
                for f in scan_text(content, item.path, min_entropy,
                                   commit_hash=short_sha, is_history=True):
                    key = (f.file_path, f.secret_type, f.matched_string)
                    rec = agg.get(key)
                    if rec is None:
                        agg[key] = {
                            "finding": f,
                            "first_dt": commit_dt,
                            "last_dt": commit_dt,
                            "first_sha": short_sha,
                            "last_sha": short_sha,
                            "commits": {short_sha},
                            "authors": {author},
                        }
                    else:
                        rec["commits"].add(short_sha)
                        rec["authors"].add(author)
                        if commit_dt < rec["first_dt"]:
                            rec["first_dt"], rec["first_sha"] = commit_dt, short_sha
                        if commit_dt > rec["last_dt"]:
                            rec["last_dt"], rec["last_sha"] = commit_dt, short_sha
        except Exception:
            continue

    findings: list[Finding] = []
    for rec in agg.values():
        f: Finding = rec["finding"]
        exposure_days = max((rec["last_dt"] - rec["first_dt"]).days, 0)
        f.introduced_at = rec["first_dt"]
        f.last_seen_at = rec["last_dt"]
        f.exposure_days = exposure_days
        f.commits_affected = len(rec["commits"])
        f.authors_count = len(rec["authors"])
        f.occurrences = len(rec["commits"])
        f.commit_hash = rec["last_sha"]
        # Recompute risk now that lifecycle context is known
        f.risk_score, f.risk_factors = compute_risk_score(
            f.severity,
            is_in_history=True,
            occurrences=f.occurrences,
            exposure_days=exposure_days,
            authors_count=f.authors_count,
            entropy=f.entropy,
        )
        findings.append(f)

    return findings, files_scanned
