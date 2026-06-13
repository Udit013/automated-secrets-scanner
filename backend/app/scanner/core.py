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

from .patterns import PATTERNS, is_placeholder, is_test_file, SecretPattern


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
    try:
        import git  # type: ignore
    except ImportError:
        return [], 0

    try:
        repo = git.Repo(repo_path)
    except Exception:
        return [], 0

    all_findings: list[Finding] = []
    files_scanned = 0

    commits = list(repo.iter_commits("HEAD", max_count=max_commits))
    for commit in commits:
        try:
            for item in commit.tree.traverse():
                if item.type == "blob":
                    try:
                        content = item.data_stream.read().decode("utf-8", errors="ignore")
                        findings = scan_text(
                            content,
                            item.path,
                            min_entropy,
                            commit_hash=commit.hexsha[:8],
                            is_history=True,
                        )
                        all_findings.extend(findings)
                        files_scanned += 1
                    except Exception:
                        continue
        except Exception:
            continue

    return all_findings, files_scanned
