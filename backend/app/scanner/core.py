"""
Secrets scanning engine.
Combines regex pattern matching, Shannon entropy gating, and placeholder
filtering, and gives every detected credential a stable fingerprint.
"""

import hashlib
import hmac
import logging
import re
import math
import os
from dataclasses import dataclass
from typing import Optional
from pathlib import Path

from datetime import datetime

from .patterns import PATTERNS, is_placeholder, is_test_file, SecretPattern
from .risk import compute_risk_score

logger = logging.getLogger(__name__)


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
    # Stable identity of the credential (not the line): see fingerprint().
    fingerprint: Optional[str] = None


SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".cpp", ".c", ".h",
    ".cs", ".go", ".rb", ".php", ".swift", ".kt", ".rs", ".scala",
    ".yaml", ".yml", ".json", ".xml", ".conf", ".config", ".ini",
    ".env", ".properties", ".sh", ".bash", ".zsh", ".fish",
    ".tf", ".tfvars", ".toml", ".gradle", ".pom", ".lock",
    # Where private keys and leaked notebook outputs actually live.
    ".pem", ".key", ".cfg", ".ipynb",
}

# Files with no useful extension that routinely hold credentials. Matching by
# suffix alone misses them (Path(".npmrc").suffix is ""), which meant the
# npm and PyPI token patterns could never fire on the files those tokens use.
SCANNABLE_FILENAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".dockercfg",
    "Dockerfile", "credentials",
}

IGNORE_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", ".idea", ".vscode",
    "build", "dist", "target", ".next", ".nuxt", "coverage", ".pytest_cache",
    ".tox", ".mypy_cache", ".ruff_cache",
}


# Larger files are skipped: credentials live in source and config, and reading
# a huge generated file whole could exhaust a small instance's memory.
# (Lockfiles, the largest text files most repos have, fit comfortably.)
MAX_FILE_BYTES = 5 * 1024 * 1024


def is_scannable(name: str) -> bool:
    return (
        Path(name).suffix in SCANNABLE_EXTENSIONS
        or name in SCANNABLE_FILENAMES
        or name.startswith(".env")
    )

MIN_ENTROPY = 3.5

# Key for credential fingerprints. The server replaces it at startup with a
# per-install secret (configure_fingerprint_key); the CLI keeps this public
# default unless FINGERPRINT_KEY is set, so baselines stay stable across
# machines. Same key on both sides -> CLI and console fingerprints match.
DEFAULT_FINGERPRINT_KEY = b"cipherwatch-fingerprint-v1"
_fingerprint_key = DEFAULT_FINGERPRINT_KEY


def configure_fingerprint_key(key: bytes) -> None:
    global _fingerprint_key
    _fingerprint_key = key


def fingerprint_key_id() -> str:
    """Short, non-reversible label of the active key, so two fingerprint sets
    can be checked for comparability without revealing the key."""
    return hmac.new(_fingerprint_key, b"cipherwatch-key-id", hashlib.sha256).hexdigest()[:12]


def fingerprint(raw: str, pattern: SecretPattern, file_path: str, masked: str) -> str:
    """
    Identify a *credential* rather than a line, so one leaked key found in
    five files and forty commits is triaged — and rotated — once.

    Format-specific credentials are identified by value: an HMAC of the raw
    secret, which is never stored. Two kinds fall back to location instead:
    marker patterns, whose match is a fixed header shared by every key of
    that type; and generic patterns, whose values can be low-entropy enough
    (`Summer2024!`) that even a keyed hash of the value is better avoided.
    """
    if pattern.marker or not pattern.format_specific:
        material = f"loc\x00{pattern.name}\x00{file_path}\x00{masked}"
    else:
        material = f"val\x00{raw}"
    return hmac.new(_fingerprint_key, material.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


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

        line_findings: list[Finding] = []
        raw_secrets: list[str] = []

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

                raw_secrets.append(matched_text)
                masked = _mask(matched_text)
                line_findings.append(
                    Finding(
                        file_path=file_path,
                        line_number=line_num,
                        secret_type=pattern.name,
                        matched_string=masked,
                        entropy=round(entropy, 2),
                        severity=severity,
                        confidence=confidence,
                        context="",
                        commit_hash=commit_hash,
                        remediation=pattern.remediation,
                        is_in_history=is_history,
                        risk_score=score,
                        risk_factors=score_factors,
                        fingerprint=fingerprint(matched_text, pattern, file_path, masked),
                    )
                )

        if line_findings:
            # The source line is persisted and exported, so every secret
            # detected on it is masked — not just the one a finding is about.
            context = _mask_secrets_in(stripped, raw_secrets)[:200]
            for f in line_findings:
                f.context = context
            findings.extend(line_findings)

    return findings


def _mask_secrets_in(text: str, secrets: list[str]) -> str:
    # Longest first, so a secret that contains another is masked whole.
    for secret in sorted(set(secrets), key=len, reverse=True):
        text = text.replace(secret, _mask(secret))
    return text


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


def iter_scannable_files(directory: str):
    """
    Yield (absolute path, repo-relative POSIX path) for every scannable file.

    Relative paths matter: findings — and location-scoped fingerprints — must
    not depend on where the tree happens to be checked out, or a credential
    would look new every time it is scanned from a different temp directory.
    Symlinks are skipped so a scan never reads outside the tree.
    """
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in files:
            fpath = os.path.join(root, fname)
            if os.path.islink(fpath) or not is_scannable(fname):
                continue
            try:
                if os.path.getsize(fpath) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield fpath, Path(os.path.relpath(fpath, directory)).as_posix()


def scan_directory(
    directory: str, min_entropy: float = MIN_ENTROPY
) -> tuple[list[Finding], int]:
    all_findings: list[Finding] = []
    files_scanned = 0
    for fpath, rel in iter_scannable_files(directory):
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except OSError:
            continue
        all_findings.extend(scan_text(content, rel, min_entropy))
        files_scanned += 1
    return all_findings, files_scanned


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
        logger.error("GitPython is not installed — git-history scanning is unavailable")
        return [], 0

    try:
        repo = git.Repo(repo_path)
    except Exception:
        logger.warning("Could not open git repo at %s for history scan", repo_path, exc_info=True)
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
                parts = item.path.split("/")
                if not is_scannable(parts[-1]) or IGNORE_DIRS.intersection(parts[:-1]):
                    continue
                if item.size > MAX_FILE_BYTES:
                    continue
                try:
                    content = item.data_stream.read().decode("utf-8", errors="ignore")
                except Exception:
                    continue
                files_scanned += 1
                for f in scan_text(content, item.path, min_entropy,
                                   commit_hash=short_sha, is_history=True):
                    key = (f.file_path, f.secret_type, f.fingerprint)
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
