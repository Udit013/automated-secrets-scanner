"""
GitHub repository scanner.
Downloads a repo as a zip archive (no git clone needed) via the GitHub API.
"""

import io
import os
import re
import shutil
import tempfile
import zipfile
from typing import Optional

import httpx

from .core import scan_directory, scan_git_history, Finding
from ..config import settings


_GITHUB_REPO_RE = re.compile(
    r"github\.com[/:]([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)


def parse_github_url(url: str) -> Optional[tuple[str, str]]:
    m = _GITHUB_REPO_RE.search(url)
    if m:
        return m.group(1), m.group(2)
    return None


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
    try:
        zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            resp = await client.get(zip_url, headers=headers)
            resp.raise_for_status()

        if progress_callback:
            await progress_callback(10, "Downloaded repository archive")

        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            zf.extractall(tmpdir)

        if progress_callback:
            await progress_callback(20, "Extracted repository")

        findings, files_scanned = scan_directory(tmpdir, min_entropy)

        if progress_callback:
            await progress_callback(80, f"Scanned {files_scanned} files")

        # Fix file paths to look like repo paths
        prefix_len = len(tmpdir) + 1
        for f in findings:
            raw = f.file_path[prefix_len:]
            # Remove the top-level owner-repo-hash dir
            parts = raw.split(os.sep, 1)
            f.file_path = parts[1] if len(parts) > 1 else raw

        if scan_git_history_flag:
            if progress_callback:
                await progress_callback(85, "Scanning git history...")
            # For git history we need an actual clone; do a shallow clone via git if available
            try:
                import git as gitlib  # type: ignore
                clone_dir = tempfile.mkdtemp(prefix="secrets_clone_")
                try:
                    clone_kwargs = {"depth": max_commits} if not scan_git_history_flag else {}
                    gitlib.Repo.clone_from(
                        f"https://github.com/{owner}/{repo}.git",
                        clone_dir,
                        no_checkout=False,
                        multi_options=["--depth={}".format(max_commits)],
                    )
                    hist_findings, hist_files = scan_git_history(clone_dir, max_commits, min_entropy)
                    findings.extend(hist_findings)
                    files_scanned += hist_files
                finally:
                    shutil.rmtree(clone_dir, ignore_errors=True)
            except Exception:
                pass

        if progress_callback:
            await progress_callback(95, "Finalising results")

        return findings, files_scanned

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
