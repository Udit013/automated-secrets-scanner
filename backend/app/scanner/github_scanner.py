"""
GitHub repository scanner.
Downloads a repo as a zip archive (no git clone needed) via the GitHub API.
"""

import asyncio
import logging
import os
import re
import shutil
import tempfile
import zipfile
from typing import Optional

import httpx

from .core import scan_directory, scan_git_history, Finding
from ..config import settings

logger = logging.getLogger(__name__)


_GITHUB_REPO_RE = re.compile(
    r"github\.com[/:]([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)


def parse_github_url(url: str) -> Optional[tuple[str, str]]:
    m = _GITHUB_REPO_RE.search(url)
    if m:
        return m.group(1), m.group(2)
    return None


# The scan endpoint is public, so every resource a repository can consume is
# bounded: the archive is streamed to disk (never held in memory) up to a
# size cap, and zip bombs are rejected from the central directory before a
# single byte is decompressed.
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024        # compressed download
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024      # total uncompressed size
MAX_ARCHIVE_MEMBERS = 50_000


def _safe_extract(zf: zipfile.ZipFile, dest: str) -> None:
    """
    Extract a zip archive, rejecting it up front if it is oversized or has
    a "zip slip" entry — a member path (e.g. containing `../`) that would
    resolve outside `dest`. Everything is validated before extracting, so
    a bad archive never leaves a partial extraction behind.
    """
    infos = zf.infolist()
    if len(infos) > MAX_ARCHIVE_MEMBERS:
        raise ValueError(f"Repository archive has more than {MAX_ARCHIVE_MEMBERS:,} files")
    if sum(i.file_size for i in infos) > MAX_EXTRACTED_BYTES:
        raise ValueError(
            f"Repository is larger than {MAX_EXTRACTED_BYTES // (1024 * 1024)} MB uncompressed"
        )
    dest_real = os.path.realpath(dest)
    for info in infos:
        member_path = os.path.realpath(os.path.join(dest, info.filename))
        if member_path != dest_real and not member_path.startswith(dest_real + os.sep):
            raise ValueError(f"Unsafe path in archive entry: {info.filename!r}")
    zf.extractall(dest)


def _extract_archive(archive_path: str, dest: str) -> None:
    with zipfile.ZipFile(archive_path) as zf:
        _safe_extract(zf, dest)


async def _download_archive(url: str, headers: dict, dest_path: str) -> None:
    received = 0
    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
        async with client.stream("GET", url, headers=headers) as resp:
            resp.raise_for_status()
            with open(dest_path, "wb") as fh:
                async for chunk in resp.aiter_bytes():
                    received += len(chunk)
                    if received > MAX_ARCHIVE_BYTES:
                        raise ValueError(
                            f"Repository archive exceeds {MAX_ARCHIVE_BYTES // (1024 * 1024)} MB"
                        )
                    fh.write(chunk)


def _scan_history(owner: str, repo: str, max_commits: int, min_entropy: float):
    """Clone (depth-limited) and walk history. Blocking — run in a thread."""
    import git as gitlib  # type: ignore

    clone_dir = tempfile.mkdtemp(prefix="secrets_clone_")
    try:
        gitlib.Repo.clone_from(
            f"https://github.com/{owner}/{repo}.git",
            clone_dir,
            no_checkout=False,
            multi_options=[f"--depth={max_commits}"],
        )
        return scan_git_history(clone_dir, max_commits, min_entropy)
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)


async def scan_github_repo(
    repo_url: str,
    scan_git_history_flag: bool = False,
    max_commits: int = 100,
    min_entropy: float = 3.5,
    progress_callback=None,
) -> tuple[list[Finding], int]:
    parsed = parse_github_url(repo_url)
    if not parsed:
        raise ValueError(f"Invalid GitHub URL: {repo_url}")

    owner, repo = parsed
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

    tmpdir = tempfile.mkdtemp(prefix="secrets_scan_")
    archive_path = os.path.join(tmpdir, "repo.zip")
    src_dir = os.path.join(tmpdir, "src")
    try:
        await _download_archive(
            f"https://api.github.com/repos/{owner}/{repo}/zipball", headers, archive_path
        )

        if progress_callback:
            await progress_callback(10, "Downloaded repository archive")

        # Extraction and scanning are blocking (disk + CPU). Worker threads
        # keep the event loop free for other requests, health checks, and
        # this scan's own progress broadcasts.
        await asyncio.to_thread(_extract_archive, archive_path, src_dir)

        if progress_callback:
            await progress_callback(20, "Extracted repository")

        findings, files_scanned = await asyncio.to_thread(scan_directory, src_dir, min_entropy)

        if progress_callback:
            await progress_callback(80, f"Scanned {files_scanned} files")

        # Fix file paths to look like repo paths
        prefix_len = len(src_dir) + 1
        for f in findings:
            raw = f.file_path[prefix_len:]
            # Remove the top-level owner-repo-hash dir
            parts = raw.split(os.sep, 1)
            f.file_path = parts[1] if len(parts) > 1 else raw

        if scan_git_history_flag:
            if progress_callback:
                await progress_callback(85, "Scanning git history...")
            try:
                hist_findings, hist_files = await asyncio.to_thread(
                    _scan_history, owner, repo, max_commits, min_entropy
                )
                findings.extend(hist_findings)
                files_scanned += hist_files
            except Exception:
                # Git history is best-effort on top of the (already-returned)
                # current-tree results — log so failures are visible in
                # server logs without failing the whole scan.
                logger.warning(
                    "Git-history scan failed for %s/%s; returning current-tree findings only",
                    owner, repo, exc_info=True,
                )

        if progress_callback:
            await progress_callback(95, "Finalising results")

        return findings, files_scanned

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
