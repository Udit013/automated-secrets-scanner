"""
CipherWatch CLI entry point.

Runs the same detection engine as the web app (backend/app/scanner):

    python cli.py scan .                         # report, exit 1 on any finding
    python cli.py scan . --fail-on high --baseline .cipherwatch-baseline.json
    python cli.py scan . --format sarif -o cipherwatch.sarif
    python cli.py baseline .                     # accept what's there today

The pre-3.0 flags still work and are translated:
    -d DIR / -f FILE  ->  scan PATH
    -g REPO           ->  scan REPO --history
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

from app.cli import main  # noqa: E402

_LEGACY = {"-d": [], "--directory": [], "-f": [], "--file": [], "-g": ["--history"], "--git": ["--history"]}


def translate_legacy(argv: list[str]) -> list[str]:
    """Map the old single-command flags onto `scan`, so existing scripts keep working."""
    if not argv or argv[0] in ("scan", "baseline", "-h", "--help"):
        return argv
    out, rest, i = ["scan"], [], 0
    while i < len(argv):
        arg = argv[i]
        if arg in _LEGACY and i + 1 < len(argv):
            out.append(argv[i + 1])
            rest += _LEGACY[arg]
            i += 2
            continue
        if arg == "--format" and i + 1 < len(argv):
            fmt = {"console": "text"}.get(argv[i + 1], argv[i + 1])
            rest += ["--format", fmt]
            i += 2
            continue
        if arg in ("--stats", "--recursive", "--verbose"):  # always on / no longer needed
            i += 1
            continue
        rest.append(arg)
        i += 1
    return out + rest


if __name__ == "__main__":
    sys.exit(main(translate_legacy(sys.argv[1:])))
