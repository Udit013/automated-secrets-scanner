"""
CipherWatch command-line scanner — the same engine as the web app, built for
pre-commit hooks and CI.

    python -m app.cli scan PATH [--history] [--format text|json|sarif]
                               [--fail-on high] [--baseline .cipherwatch-baseline.json]
    python -m app.cli baseline PATH [-o .cipherwatch-baseline.json]

Exit codes: 0 = no unbaselined findings at or above --fail-on,
            1 = findings at or above --fail-on, 2 = usage or I/O error.

A baseline records the fingerprints of credentials that were already present
and triaged, so CI fails only on *new* leaks. It stores no secret values —
only fingerprints, types, and locations — so it is safe to commit.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

# Only the pure scanner package is imported: the CLI needs GitPython for
# history and nothing from the web stack.
from .scanner.core import (
    DEFAULT_FINGERPRINT_KEY, Finding, configure_fingerprint_key, fingerprint_key_id, scan_directory, scan_git_history, scan_text,
)
from .scanner.sarif import build_sarif

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
BASELINE_VERSION = 1


def _scan(path: str, history: bool, max_commits: int, min_entropy: float) -> tuple[list[Finding], int]:
    target = Path(path)
    if target.is_file():
        content = target.read_text(encoding="utf-8", errors="ignore")
        return scan_text(content, target.name, min_entropy), 1
    if not target.is_dir():
        raise FileNotFoundError(f"path not found: {path}")
    findings, files = scan_directory(str(target), min_entropy)
    if history:
        hist, hist_files = scan_git_history(str(target), max_commits, min_entropy)
        findings += hist
        files += hist_files
    return findings, files


def _load_baseline(path: str | None) -> set[str]:
    if not path:
        return set()
    data = json.loads(Path(path).read_text())
    if data.get("version") != BASELINE_VERSION:
        raise ValueError(f"Unsupported baseline version in {path}")
    # A baseline made under another key would match nothing and report every
    # known credential as new; refuse it instead.
    recorded = data.get("key_id")
    if recorded and recorded != fingerprint_key_id():
        raise ValueError(
            f"{path} was created with a different FINGERPRINT_KEY "
            f"(key id {recorded}, current {fingerprint_key_id()}). Regenerate it or set the same key."
        )
    return {entry["fingerprint"] for entry in data.get("credentials", [])}


def _credentials(findings: list[Finding]) -> list[dict]:
    """One entry per credential, keeping its first location for humans."""
    seen: dict[str, dict] = {}
    for f in sorted(findings, key=lambda x: (x.is_in_history, x.file_path, x.line_number)):
        entry = seen.setdefault(f.fingerprint, {
            "fingerprint": f.fingerprint,
            "secret_type": f.secret_type,
            "severity": f.severity,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "in_history_only": f.is_in_history,
        })
        if not f.is_in_history:
            entry["in_history_only"] = False
    return list(seen.values())


def _print_text(findings: list[Finding], new_fps: set[str], files: int, stream) -> None:
    creds = _credentials(findings)
    new = [c for c in creds if c["fingerprint"] in new_fps]
    print(f"CipherWatch scanned {files} file(s): {len(creds)} credential(s), "
          f"{len(new)} not in baseline.", file=stream)
    for c in sorted(creds, key=lambda c: -SEVERITY_RANK[c["severity"].lower()]):
        tag = "NEW " if c["fingerprint"] in new_fps else "base"
        where = "history" if c["in_history_only"] else f"{c['file_path']}:{c['line_number']}"
        print(f"  [{tag}] {c['severity']:<8} {c['secret_type']:<30} {where}", file=stream)


def cmd_scan(args) -> int:
    findings, files = _scan(args.path, args.history, args.max_commits, args.min_entropy)
    baseline = _load_baseline(args.baseline)
    new = [f for f in findings if f.fingerprint not in baseline]
    new_fps = {f.fingerprint for f in new}

    # SARIF reports only what the baseline doesn't cover, so code scanning
    # shows actionable alerts rather than every accepted legacy finding.
    def sarif() -> str:
        scan = SimpleNamespace(id="cli", source_ref=str(Path(args.path).resolve().name))
        return json.dumps(build_sarif(scan, new), indent=2)

    if args.sarif:  # alongside the main output, so CI scans once
        Path(args.sarif).write_text(sarif() + "\n")

    if args.format == "sarif":
        out = sarif()
    elif args.format == "json":
        out = json.dumps({
            "files_scanned": files,
            "credentials": [dict(c, baselined=c["fingerprint"] not in new_fps) for c in _credentials(findings)],
        }, indent=2)
    else:
        out = None
        _print_text(findings, new_fps, files, sys.stdout)

    if out is not None:
        if args.output:
            Path(args.output).write_text(out + "\n")
        else:
            print(out)

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    blocking = [f for f in new if SEVERITY_RANK[f.severity.lower()] >= threshold]
    if blocking and args.format != "text":
        print(f"{len({f.fingerprint for f in blocking})} new credential(s) at or above "
              f"{args.fail_on}.", file=sys.stderr)
    return 1 if blocking else 0


def cmd_baseline(args) -> int:
    findings, _ = _scan(args.path, args.history, args.max_commits, args.min_entropy)
    creds = _credentials(findings)
    doc = {
        "version": BASELINE_VERSION,
        "key_id": fingerprint_key_id(),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "Credentials accepted as of generation. Review entries before committing; "
                "rotate anything real.",
        "credentials": sorted(
            ({k: c[k] for k in ("fingerprint", "secret_type", "file_path")} for c in creds),
            key=lambda c: (c["file_path"], c["secret_type"]),
        ),
    }
    Path(args.output).write_text(json.dumps(doc, indent=2) + "\n")
    print(f"Wrote {len(creds)} credential(s) to {args.output}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cipherwatch", description="Find leaked credentials.")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("path", help="Directory, file, or git repository to scan")
        p.add_argument("--history", action="store_true", help="Also scan git history")
        p.add_argument("--max-commits", type=int, default=100)
        p.add_argument("--min-entropy", type=float, default=3.5)

    scan = sub.add_parser("scan", help="Scan and report")
    common(scan)
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("-o", "--output", help="Write json/sarif output to a file")
    scan.add_argument("--sarif", metavar="FILE", help="Also write a SARIF report to FILE")
    scan.add_argument("--baseline", help="Ignore credentials listed in this baseline file")
    scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                      default="low", help="Exit 1 if any new credential is at least this severe")
    scan.set_defaults(func=cmd_scan)

    base = sub.add_parser("baseline", help="Record current credentials as accepted")
    common(base)
    base.add_argument("-o", "--output", default=".cipherwatch-baseline.json")
    base.set_defaults(func=cmd_baseline)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Same variable as the server: set it to the server's value and CLI
    # fingerprints match the console's ledger. Unset, a fixed public key is
    # used, which still keeps secrets out of baselines (fingerprints are
    # one-way) but makes them comparable across machines.
    key = os.environ.get("FINGERPRINT_KEY")
    configure_fingerprint_key(key.encode("utf-8") if key else DEFAULT_FINGERPRINT_KEY)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError, json.JSONDecodeError, OSError) as e:
        print(f"cipherwatch: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
